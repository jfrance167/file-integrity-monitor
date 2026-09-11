from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

import file_integrity_monitor as monitor  # noqa: E402


class FileIntegrityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory(
            prefix="fim-test-", dir=PROJECT_ROOT
        )
        self.root = Path(self.temporary_directory.name)
        self.baseline_path = self.root / ".fim-baseline.json"

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def write(self, relative: str, content: str) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def test_unchanged_directory_has_no_changes(self) -> None:
        self.write("important.txt", "original")
        monitor.create_baseline(self.root, self.baseline_path)
        comparison = monitor.verify_directory(self.root, self.baseline_path)
        self.assertEqual(comparison.change_count, 0)
        self.assertEqual(comparison.errors, {})

    def test_detects_created_modified_and_deleted_files(self) -> None:
        self.write("modified.txt", "before")
        deleted = self.write("deleted.txt", "remove")
        self.write("unchanged.txt", "same")
        monitor.create_baseline(self.root, self.baseline_path)

        self.write("modified.txt", "after")
        deleted.unlink()
        self.write("nested/created.txt", "new")
        comparison = monitor.verify_directory(self.root, self.baseline_path)

        self.assertEqual(comparison.created, ["nested/created.txt"])
        self.assertEqual([item.path for item in comparison.modified], ["modified.txt"])
        self.assertEqual(comparison.deleted, ["deleted.txt"])
        self.assertEqual(comparison.change_count, 3)

    def test_baseline_does_not_monitor_itself(self) -> None:
        self.write("file.txt", "content")
        monitor.create_baseline(self.root, self.baseline_path)
        document = json.loads(self.baseline_path.read_text(encoding="utf-8"))
        self.assertNotIn(".fim-baseline.json", document["files"])

    def test_exclusion_glob_is_applied(self) -> None:
        self.write("logs/ignored.log", "one")
        self.write("keep.txt", "one")
        monitor.create_baseline(
            self.root, self.baseline_path, excludes=["logs/**"]
        )
        self.write("logs/ignored.log", "two")
        comparison = monitor.verify_directory(self.root, self.baseline_path)
        self.assertEqual(comparison.change_count, 0)

    def test_default_git_exclusion_is_applied(self) -> None:
        self.write(".git/config", "one")
        scan = monitor.scan_directory(self.root)
        self.assertEqual(scan.files, {})

    def test_refuses_to_replace_baseline_without_force(self) -> None:
        self.write("file.txt", "content")
        monitor.create_baseline(self.root, self.baseline_path)
        with self.assertRaisesRegex(ValueError, "--force"):
            monitor.create_baseline(self.root, self.baseline_path)

    def test_force_replaces_baseline(self) -> None:
        self.write("file.txt", "before")
        monitor.create_baseline(self.root, self.baseline_path)
        self.write("file.txt", "after")
        monitor.create_baseline(self.root, self.baseline_path, force=True)
        comparison = monitor.verify_directory(self.root, self.baseline_path)
        self.assertEqual(comparison.change_count, 0)

    def test_rejects_invalid_baseline_hash(self) -> None:
        document = {
            "version": monitor.BASELINE_VERSION,
            "algorithm": "sha256",
            "root": str(self.root),
            "excludes": [],
            "files": {
                "file.txt": {
                    "sha256": "bad",
                    "size": 1,
                    "mode": 0o644,
                    "uid": 0,
                    "gid": 0,
                    "kind": "file",
                }
            },
        }
        self.baseline_path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "invalid baseline record"):
            monitor.load_baseline(self.baseline_path)

    def test_content_change_with_same_size_is_detected(self) -> None:
        self.write("same-size.txt", "AAAA")
        monitor.create_baseline(self.root, self.baseline_path)
        self.write("same-size.txt", "BBBB")
        comparison = monitor.verify_directory(self.root, self.baseline_path)
        self.assertEqual([item.path for item in comparison.modified], ["same-size.txt"])

    def test_rejects_baseline_created_for_another_root(self) -> None:
        self.write("file.txt", "content")
        monitor.create_baseline(self.root, self.baseline_path)
        other_root = self.root / "other"
        other_root.mkdir()
        with self.assertRaisesRegex(ValueError, "not the requested root"):
            monitor.verify_directory(other_root, self.baseline_path)

    def test_ignore_root_allows_intentional_relocation(self) -> None:
        self.write("file.txt", "content")
        monitor.create_baseline(self.root, self.baseline_path)
        other_root = self.root / "relocated"
        other_root.mkdir()
        (other_root / "file.txt").write_text("content", encoding="utf-8")
        comparison = monitor.verify_directory(
            other_root, self.baseline_path, ignore_root=True
        )
        self.assertEqual(comparison.change_count, 0)

    def test_globstar_matches_top_level_and_nested_directories(self) -> None:
        self.assertTrue(monitor.is_excluded("__pycache__", ["**/__pycache__/**"]))
        self.assertTrue(
            monitor.is_excluded("src/__pycache__/module.pyc", ["**/__pycache__/**"])
        )
        self.assertFalse(
            monitor.is_excluded("src/cache/module.pyc", ["**/__pycache__/**"])
        )

    @unittest.skipUnless(os.name == "nt", "Windows-specific case semantics")
    def test_exclusions_are_case_insensitive_on_windows(self) -> None:
        self.assertTrue(monitor.is_excluded("CACHE.PYC", ["*.pyc"]))

    @unittest.skipIf(os.name == "nt", "POSIX mode-bit behavior")
    def test_detects_permission_change(self) -> None:
        path = self.write("script.sh", "#!/bin/sh\n")
        path.chmod(0o600)
        monitor.create_baseline(self.root, self.baseline_path)
        path.chmod(0o700)
        comparison = monitor.verify_directory(self.root, self.baseline_path)
        self.assertEqual([item.path for item in comparison.modified], ["script.sh"])
        self.assertNotEqual(
            comparison.modified[0].before_mode,
            comparison.modified[0].after_mode,
        )

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO creation is unavailable")
    def test_special_file_is_reported_without_opening(self) -> None:
        fifo = self.root / "events.pipe"
        os.mkfifo(fifo)
        scan = monitor.scan_directory(self.root)
        self.assertIn("events.pipe", scan.errors)
        self.assertIn("unsupported special file", scan.errors["events.pipe"])

    def test_hmac_signed_baseline_verifies_and_rejects_tampering(self) -> None:
        self.write("important.txt", "trusted")
        key = b"test-key-that-is-not-stored-in-the-baseline"
        monitor.create_baseline(
            self.root, self.baseline_path, hmac_key=key
        )
        comparison = monitor.verify_directory(
            self.root, self.baseline_path, hmac_key=key
        )
        self.assertEqual(comparison.change_count, 0)

        document = json.loads(self.baseline_path.read_text(encoding="utf-8"))
        document["files"]["important.txt"]["size"] = 999
        self.baseline_path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "HMAC verification failed"):
            monitor.verify_directory(self.root, self.baseline_path, hmac_key=key)

    def test_signed_baseline_requires_key(self) -> None:
        self.write("important.txt", "trusted")
        monitor.create_baseline(
            self.root, self.baseline_path, hmac_key=b"secret"
        )
        with self.assertRaisesRegex(ValueError, "supply --key-file"):
            monitor.verify_directory(self.root, self.baseline_path)

    def test_wrong_hmac_key_is_rejected(self) -> None:
        self.write("important.txt", "trusted")
        monitor.create_baseline(
            self.root, self.baseline_path, hmac_key=b"correct"
        )
        with self.assertRaisesRegex(ValueError, "HMAC verification failed"):
            monitor.verify_directory(
                self.root, self.baseline_path, hmac_key=b"incorrect"
            )

    def test_metadata_is_stored_in_baseline(self) -> None:
        path = self.write("important.txt", "trusted")
        monitor.create_baseline(self.root, self.baseline_path)
        document = json.loads(self.baseline_path.read_text(encoding="utf-8"))
        record = document["files"]["important.txt"]
        info = path.stat()
        self.assertEqual(record["mode"], stat.S_IMODE(info.st_mode))
        self.assertIn("uid", record)
        self.assertIn("gid", record)


class CommandLineTests(unittest.TestCase):
    def test_demo_proves_all_three_change_types(self) -> None:
        output = StringIO()
        with redirect_stdout(output):
            exit_code = monitor.main(["demo", "--json"])
        document = json.loads(output.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(document["created"], ["created.txt"])
        self.assertEqual(document["deleted"], ["deleted.txt"])
        self.assertEqual(document["modified"][0]["path"], "modified.txt")

    def test_fail_on_change_returns_one(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="fim-test-", dir=PROJECT_ROOT
        ) as temporary_directory:
            root = Path(temporary_directory)
            baseline = root / "baseline.json"
            (root / "file.txt").write_text("before", encoding="utf-8")
            monitor.create_baseline(root, baseline)
            (root / "file.txt").write_text("after", encoding="utf-8")
            with redirect_stdout(StringIO()):
                exit_code = monitor.main(
                    [
                        "check",
                        str(root),
                        "--baseline",
                        str(baseline),
                        "--fail-on-change",
                    ]
                )
        self.assertEqual(exit_code, 1)

    def test_missing_directory_returns_two(self) -> None:
        with redirect_stderr(StringIO()):
            exit_code = monitor.main(
                ["baseline", "definitely-does-not-exist-for-fim-test"]
            )
        self.assertEqual(exit_code, 2)

    def test_default_baseline_is_created_inside_monitored_root(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="fim-test-", dir=PROJECT_ROOT
        ) as temporary_directory:
            root = Path(temporary_directory)
            (root / "file.txt").write_text("content", encoding="utf-8")
            with redirect_stdout(StringIO()):
                exit_code = monitor.main(["baseline", str(root)])
            self.assertEqual(exit_code, 0)
            self.assertTrue((root / monitor.DEFAULT_BASELINE_NAME).is_file())

    def test_cli_hmac_key_file_is_excluded_from_scan(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="fim-test-", dir=PROJECT_ROOT
        ) as temporary_directory:
            root = Path(temporary_directory)
            key_path = root / "fim.key"
            key_path.write_bytes(b"secret-key")
            (root / "file.txt").write_text("content", encoding="utf-8")
            with redirect_stdout(StringIO()):
                exit_code = monitor.main(
                    ["baseline", str(root), "--key-file", str(key_path)]
                )
            self.assertEqual(exit_code, 0)
            baseline = json.loads(
                (root / monitor.DEFAULT_BASELINE_NAME).read_text(encoding="utf-8")
            )
            self.assertNotIn("fim.key", baseline["files"])
            self.assertIn("hmac", baseline)


if __name__ == "__main__":
    unittest.main()
