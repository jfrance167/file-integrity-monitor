#!/usr/bin/env python3
"""Create and verify signed SHA-256 file-integrity baselines."""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import hmac
import json
import os
import stat
import sys
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Iterable, Sequence


BASELINE_VERSION = 2
DEFAULT_BASELINE_NAME = ".fim-baseline.json"
HASH_CHUNK_SIZE = 1024 * 1024
DEFAULT_EXCLUDES = (".git", "__pycache__", "*.pyc")


@dataclass(frozen=True)
class FileRecord:
    sha256: str
    size: int
    mode: int
    uid: int
    gid: int
    kind: str = "file"


@dataclass(frozen=True)
class ModifiedFile:
    path: str
    before_sha256: str
    after_sha256: str
    before_size: int
    after_size: int
    before_mode: int
    after_mode: int
    before_uid: int
    after_uid: int
    before_gid: int
    after_gid: int
    before_kind: str
    after_kind: str


@dataclass(frozen=True)
class ScanResult:
    files: dict[str, FileRecord]
    errors: dict[str, str]


@dataclass(frozen=True)
class Baseline:
    root: Path
    excludes: list[str]
    files: dict[str, FileRecord]
    signed: bool


@dataclass(frozen=True)
class Comparison:
    created: list[str]
    modified: list[ModifiedFile]
    deleted: list[str]
    errors: dict[str, str]

    @property
    def change_count(self) -> int:
        return len(self.created) + len(self.modified) + len(self.deleted)

    def to_dict(self) -> dict[str, object]:
        return {
            "change_count": self.change_count,
            "created": self.created,
            "modified": [asdict(item) for item in self.modified],
            "deleted": self.deleted,
            "errors": self.errors,
        }


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def resolve_directory(value: str | Path) -> Path:
    path = Path(value).expanduser().resolve()
    if not path.exists():
        raise ValueError(f"directory does not exist: {path}")
    if not path.is_dir():
        raise ValueError(f"path is not a directory: {path}")
    return path


def resolve_baseline_path(value: str | None, root: Path) -> Path:
    if value is None:
        return root / DEFAULT_BASELINE_NAME
    return Path(value).expanduser().resolve()


def relative_if_within(path: Path, root: Path) -> str | None:
    """Return a lexical relative path without following the final path symlink."""
    try:
        absolute_path = Path(os.path.abspath(path.expanduser()))
        return absolute_path.relative_to(root).as_posix()
    except ValueError:
        return None


def _glob_matches(path_parts: tuple[str, ...], pattern_parts: tuple[str, ...]) -> bool:
    @lru_cache(maxsize=None)
    def match(path_index: int, pattern_index: int) -> bool:
        if pattern_index == len(pattern_parts):
            return path_index == len(path_parts)
        pattern_part = pattern_parts[pattern_index]
        if pattern_part == "**":
            return match(path_index, pattern_index + 1) or (
                path_index < len(path_parts) and match(path_index + 1, pattern_index)
            )
        return (
            path_index < len(path_parts)
            and fnmatch.fnmatchcase(path_parts[path_index], pattern_part)
            and match(path_index + 1, pattern_index + 1)
        )

    return match(0, 0)


def is_excluded(relative_path: str, patterns: Iterable[str]) -> bool:
    normalized = relative_path.replace("\\", "/").strip("/")
    path_parts = tuple(part for part in normalized.split("/") if part)
    if os.name == "nt":
        path_parts = tuple(part.casefold() for part in path_parts)

    for raw_pattern in patterns:
        pattern = raw_pattern.replace("\\", "/").strip().strip("/")
        while pattern.startswith("./"):
            pattern = pattern[2:]
        if not pattern:
            continue
        pattern_parts = tuple(part for part in pattern.split("/") if part)
        if os.name == "nt":
            pattern_parts = tuple(part.casefold() for part in pattern_parts)
        if len(pattern_parts) == 1:
            if any(fnmatch.fnmatchcase(part, pattern_parts[0]) for part in path_parts):
                return True
        elif _glob_matches(path_parts, pattern_parts):
            return True
    return False


def metadata_from_stat(info: os.stat_result) -> tuple[int, int, int]:
    return (
        stat.S_IMODE(info.st_mode),
        int(getattr(info, "st_uid", 0)),
        int(getattr(info, "st_gid", 0)),
    )


def same_file(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def stable_attributes(info: os.stat_result) -> tuple[int, int, int, int, int]:
    mode, uid, gid = metadata_from_stat(info)
    return (info.st_size, info.st_mtime_ns, mode, uid, gid)


def hash_regular_file(path: Path) -> FileRecord:
    """Hash a regular file without following a last-component symlink."""
    for attempt in range(2):
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode):
            raise OSError(f"unsupported special file: {path}")

        flags = (
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        descriptor = os.open(path, flags | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or not same_file(before, opened):
                raise OSError(f"file type changed while opening: {path}")
            digest = hashlib.sha256()
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                for chunk in iter(lambda: stream.read(HASH_CHUNK_SIZE), b""):
                    digest.update(chunk)
            after = os.fstat(descriptor)
            path_after = path.lstat()
        finally:
            os.close(descriptor)

        stable = (
            same_file(opened, after)
            and same_file(after, path_after)
            and stable_attributes(opened) == stable_attributes(after)
            and stable_attributes(after) == stable_attributes(path_after)
        )
        if stable:
            mode, uid, gid = metadata_from_stat(after)
            return FileRecord(
                sha256=digest.hexdigest(),
                size=after.st_size,
                mode=mode,
                uid=uid,
                gid=gid,
            )
        if attempt == 0:
            continue
    raise OSError("file changed while it was being hashed")


def hash_symlink(path: Path) -> FileRecord:
    for attempt in range(2):
        before = path.lstat()
        if not stat.S_ISLNK(before.st_mode):
            raise OSError(f"file type changed while reading symlink: {path}")
        target = os.readlink(path)
        after = path.lstat()
        stable = same_file(before, after) and stable_attributes(
            before
        ) == stable_attributes(after)
        if stable:
            encoded_target = os.fsencode(target)
            digest = hashlib.sha256(b"symlink\0" + encoded_target).hexdigest()
            mode, uid, gid = metadata_from_stat(after)
            return FileRecord(
                sha256=digest,
                size=len(encoded_target),
                mode=mode,
                uid=uid,
                gid=gid,
                kind="symlink",
            )
        if attempt == 0:
            continue
    raise OSError("symlink changed while it was being read")


def hash_path(path: Path) -> FileRecord:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode):
        return hash_symlink(path)
    if not stat.S_ISREG(info.st_mode):
        raise OSError(f"unsupported special file: {path}")
    return hash_regular_file(path)


def discover_paths(root: Path, patterns: Sequence[str]) -> list[tuple[str, Path]]:
    discovered: list[tuple[str, Path]] = []

    def raise_walk_error(error: OSError) -> None:
        raise error

    for current, directory_names, file_names in os.walk(
        root, followlinks=False, onerror=raise_walk_error
    ):
        current_path = Path(current)
        retained_directories: list[str] = []
        for name in directory_names:
            path = current_path / name
            relative = path.relative_to(root).as_posix()
            if is_excluded(relative, patterns):
                continue
            try:
                is_link = stat.S_ISLNK(path.lstat().st_mode)
            except OSError:
                is_link = False
            if is_link:
                discovered.append((relative, path))
            else:
                retained_directories.append(name)
        directory_names[:] = retained_directories

        for name in file_names:
            path = current_path / name
            relative = path.relative_to(root).as_posix()
            if not is_excluded(relative, patterns):
                discovered.append((relative, path))
    return sorted(discovered, key=lambda item: item[0])


def scan_directory(
    root: Path,
    excludes: Sequence[str] = (),
    protected_paths: Sequence[Path] = (),
) -> ScanResult:
    patterns = [*DEFAULT_EXCLUDES, *excludes]
    for protected_path in protected_paths:
        relative = relative_if_within(protected_path, root)
        if relative:
            patterns.append(relative)

    files: dict[str, FileRecord] = {}
    errors: dict[str, str] = {}
    try:
        discovered = discover_paths(root, patterns)
    except OSError as exc:
        raise ValueError(f"could not enumerate {root}: {exc}") from exc
    for relative, path in discovered:
        try:
            files[relative] = hash_path(path)
        except OSError as exc:
            errors[relative] = str(exc)
    return ScanResult(files=files, errors=errors)


def baseline_document(
    root: Path, scan: ScanResult, excludes: Sequence[str]
) -> dict[str, object]:
    return {
        "version": BASELINE_VERSION,
        "algorithm": "sha256",
        "created_at": utc_now(),
        "root": str(root),
        "excludes": list(excludes),
        "files": {path: asdict(record) for path, record in scan.files.items()},
    }


def canonical_json(document: dict[str, object]) -> bytes:
    unsigned = {key: value for key, value in document.items() if key != "hmac"}
    return json.dumps(
        unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def valid_sha256(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )


def sign_document(document: dict[str, object], key: bytes) -> None:
    if not key:
        raise ValueError("HMAC key must not be empty")
    document["hmac"] = {
        "algorithm": "hmac-sha256",
        "digest": hmac.new(key, canonical_json(document), hashlib.sha256).hexdigest(),
    }


def verify_document_signature(document: dict[str, object], key: bytes | None) -> bool:
    signature = document.get("hmac")
    if signature is None:
        if key is not None:
            raise ValueError("an HMAC key was supplied, but the baseline is unsigned")
        return False
    if key is None:
        raise ValueError("baseline is HMAC-signed; supply --key-file to verify it")
    if not isinstance(signature, dict):
        raise ValueError("invalid HMAC metadata in baseline")
    algorithm = signature.get("algorithm")
    digest = signature.get("digest")
    if algorithm != "hmac-sha256" or not valid_sha256(digest):
        raise ValueError("invalid HMAC metadata in baseline")
    expected = hmac.new(key, canonical_json(document), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(digest, expected):
        raise ValueError("baseline HMAC verification failed")
    return True


def atomic_write_json(path: Path, document: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(document, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, path)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise


def create_baseline(
    root: Path,
    baseline_path: Path,
    excludes: Sequence[str] = (),
    force: bool = False,
    hmac_key: bytes | None = None,
    key_path: Path | None = None,
) -> dict[str, object]:
    if baseline_path.exists() and not force:
        raise ValueError(
            f"baseline already exists: {baseline_path}; use --force to replace it"
        )
    protected_paths = [baseline_path]
    if key_path is not None:
        protected_paths.append(key_path)
    scan = scan_directory(root, excludes=excludes, protected_paths=protected_paths)
    if scan.errors:
        paths = ", ".join(sorted(scan.errors))
        raise ValueError(f"baseline was not written because files could not be read: {paths}")
    document = baseline_document(root, scan, excludes)
    if hmac_key is not None:
        sign_document(document, hmac_key)
    atomic_write_json(baseline_path, document)
    return document


def load_baseline(path: Path, hmac_key: bytes | None = None) -> Baseline:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"could not read baseline {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"baseline is not valid JSON: {exc}") from exc

    if not isinstance(document, dict) or document.get("version") != BASELINE_VERSION:
        raise ValueError(f"unsupported or missing baseline version in {path}")
    signed = verify_document_signature(document, hmac_key)
    if document.get("algorithm") != "sha256" or not isinstance(
        document.get("files"), dict
    ):
        raise ValueError(f"invalid baseline structure in {path}")
    root_value = document.get("root")
    excludes_value = document.get("excludes", [])
    if not isinstance(root_value, str) or not isinstance(excludes_value, list) or not all(
        isinstance(item, str) for item in excludes_value
    ):
        raise ValueError(f"invalid baseline metadata in {path}")

    records: dict[str, FileRecord] = {}
    for relative, value in document["files"].items():
        if not isinstance(relative, str) or not isinstance(value, dict):
            raise ValueError(f"invalid file record in baseline {path}")
        digest = value.get("sha256")
        size = value.get("size")
        mode = value.get("mode")
        uid = value.get("uid")
        gid = value.get("gid")
        kind = value.get("kind", "file")
        if (
            not valid_sha256(digest)
            or not isinstance(size, int)
            or size < 0
            or not isinstance(mode, int)
            or mode < 0
            or not isinstance(uid, int)
            or uid < 0
            or not isinstance(gid, int)
            or gid < 0
            or kind not in {"file", "symlink"}
        ):
            raise ValueError(f"invalid baseline record for {relative!r}")
        records[relative] = FileRecord(
            sha256=digest, size=size, mode=mode, uid=uid, gid=gid, kind=kind
        )
    return Baseline(
        root=Path(root_value), excludes=excludes_value, files=records, signed=signed
    )


def compare_records(
    baseline: dict[str, FileRecord], current: ScanResult
) -> Comparison:
    baseline_paths = set(baseline)
    current_paths = set(current.files)
    created = sorted(current_paths - baseline_paths)
    deleted = sorted(baseline_paths - current_paths - set(current.errors))
    modified: list[ModifiedFile] = []
    for path in sorted(baseline_paths & current_paths):
        before = baseline[path]
        after = current.files[path]
        if before != after:
            modified.append(
                ModifiedFile(
                    path=path,
                    before_sha256=before.sha256,
                    after_sha256=after.sha256,
                    before_size=before.size,
                    after_size=after.size,
                    before_mode=before.mode,
                    after_mode=after.mode,
                    before_uid=before.uid,
                    after_uid=after.uid,
                    before_gid=before.gid,
                    after_gid=after.gid,
                    before_kind=before.kind,
                    after_kind=after.kind,
                )
            )
    return Comparison(
        created=created,
        modified=modified,
        deleted=deleted,
        errors=current.errors,
    )


def verify_directory(
    root: Path,
    baseline_path: Path,
    excludes: Sequence[str] = (),
    ignore_root: bool = False,
    hmac_key: bytes | None = None,
    key_path: Path | None = None,
) -> Comparison:
    baseline = load_baseline(baseline_path, hmac_key=hmac_key)
    expected_root = os.path.normcase(str(baseline.root.expanduser().resolve()))
    actual_root = os.path.normcase(str(root.resolve()))
    if not ignore_root and expected_root != actual_root:
        raise ValueError(
            f"baseline was created for {baseline.root}, not the requested root {root}; "
            "use --ignore-root only for an intentional relocation"
        )
    effective_excludes = [*baseline.excludes, *excludes]
    protected_paths = [baseline_path]
    if key_path is not None:
        protected_paths.append(key_path)
    current = scan_directory(
        root, excludes=effective_excludes, protected_paths=protected_paths
    )
    return compare_records(baseline.files, current)


def print_comparison(comparison: Comparison) -> None:
    print("File Integrity Monitor")
    print(f"Changes detected: {comparison.change_count}")
    print(f"Scan errors:      {len(comparison.errors)}")
    print("-" * 64)
    for path in comparison.created:
        print(f"[CREATED]  {path}")
    for item in comparison.modified:
        print(f"[MODIFIED] {item.path}")
    for path in comparison.deleted:
        print(f"[DELETED]  {path}")
    for path, message in sorted(comparison.errors.items()):
        print(f"[ERROR]    {path}: {message}")
    if comparison.change_count == 0 and not comparison.errors:
        print("No integrity changes detected.")


def read_key_file(path: Path) -> bytes:
    try:
        key = path.read_bytes()
    except OSError as exc:
        raise ValueError(f"could not read HMAC key file {path}: {exc}") from exc
    if not key:
        raise ValueError(f"HMAC key file is empty: {path}")
    return key


def run_demo(json_output: bool) -> int:
    with tempfile.TemporaryDirectory(
        prefix="fim-demo-", dir=Path.cwd()
    ) as temporary_directory:
        root = Path(temporary_directory)
        baseline_path = root / DEFAULT_BASELINE_NAME
        (root / "unchanged.txt").write_text("unchanged\n", encoding="utf-8")
        (root / "modified.txt").write_text("original\n", encoding="utf-8")
        (root / "deleted.txt").write_text("delete me\n", encoding="utf-8")
        create_baseline(root, baseline_path)
        (root / "modified.txt").write_text("changed\n", encoding="utf-8")
        (root / "deleted.txt").unlink()
        (root / "created.txt").write_text("new file\n", encoding="utf-8")
        comparison = verify_directory(root, baseline_path)

    if json_output:
        print(json.dumps(comparison.to_dict(), indent=2))
    else:
        print_comparison(comparison)
    expected = (
        comparison.created == ["created.txt"]
        and [item.path for item in comparison.modified] == ["modified.txt"]
        and comparison.deleted == ["deleted.txt"]
        and not comparison.errors
    )
    return 0 if expected else 2


def add_common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("root", help="directory to monitor")
    parser.add_argument(
        "--baseline",
        default=None,
        help=f"baseline JSON path (default: ROOT/{DEFAULT_BASELINE_NAME})",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="GLOB",
        help="exclude a relative path glob; repeat for multiple patterns",
    )
    parser.add_argument(
        "--key-file",
        help="file containing the secret key for HMAC baseline protection",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Detect file content and metadata changes with SHA-256."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    baseline_parser = subparsers.add_parser("baseline", help="create a baseline")
    add_common_arguments(baseline_parser)
    baseline_parser.add_argument(
        "--force", action="store_true", help="replace an existing baseline"
    )
    check_parser = subparsers.add_parser("check", help="compare files to a baseline")
    add_common_arguments(check_parser)
    check_parser.add_argument("--json", action="store_true", help="emit JSON output")
    check_parser.add_argument(
        "--fail-on-change",
        action="store_true",
        help="return exit code 1 if changes are detected",
    )
    check_parser.add_argument(
        "--ignore-root",
        action="store_true",
        help="verify an intentional copy or relocated mount of the baseline root",
    )
    demo_parser = subparsers.add_parser(
        "demo", help="prove detection using temporary files"
    )
    demo_parser.add_argument("--json", action="store_true", help="emit JSON output")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "demo":
        return run_demo(args.json)

    try:
        root = resolve_directory(args.root)
        baseline_path = resolve_baseline_path(args.baseline, root)
        key_path = Path(args.key_file).expanduser().resolve() if args.key_file else None
        hmac_key = read_key_file(key_path) if key_path is not None else None
        if args.command == "baseline":
            document = create_baseline(
                root,
                baseline_path,
                excludes=args.exclude,
                force=args.force,
                hmac_key=hmac_key,
                key_path=key_path,
            )
            print(f"Baseline created: {baseline_path}")
            print(f"Files recorded:   {len(document['files'])}")
            print(f"HMAC protected:   {'yes' if hmac_key is not None else 'no'}")
            return 0
        comparison = verify_directory(
            root,
            baseline_path,
            excludes=args.exclude,
            ignore_root=args.ignore_root,
            hmac_key=hmac_key,
            key_path=key_path,
        )
    except (OSError, ValueError) as exc:
        if getattr(args, "json", False):
            print(json.dumps({"error": str(exc)}))
        else:
            print(f"Error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(comparison.to_dict(), indent=2))
    else:
        print_comparison(comparison)
    if comparison.errors:
        return 2
    return 1 if comparison.change_count and args.fail_on_change else 0


if __name__ == "__main__":
    raise SystemExit(main())
