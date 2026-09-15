# File Integrity Monitor

A defensive Python tool that creates SHA-256 baselines and detects file-content
and security-metadata changes. It is a practical security lab implemented only
with the Python standard library.

Use it only on directories and systems you own or are authorized to monitor.

## Security Notice

This repository is an educational defensive-security lab, not a production
endpoint-security product. Use it only on systems you own or are authorized to
monitor. Protect HMAC keys outside the monitored directory and repository, and
do not treat a clean result as proof that a system is uncompromised.

Do not deploy this project in production.

## What it does

- Recursively records SHA-256, size, modification time, file type, permissions,
  owner UID/GID, and filesystem identity
- Detects created, modified, and deleted paths
- Detects content or metadata changes even when file size stays the same
- Records symbolic-link targets without following them outside the monitored tree
- Rejects FIFOs, sockets, and devices rather than risking a blocking read
- Uses race-resistant file descriptors and `O_NOFOLLOW` where supported
- Supports directory-aware exclusion globs, including `**`
- Excludes Git metadata, Python caches, the baseline, and HMAC key by default
- Writes baselines atomically and refuses accidental overwrites
- Optionally authenticates baselines with HMAC-SHA-256
- Supports intentional relocation and offline-image analysis with `--ignore-root`
- Reports check timestamps and the exact reasons each file was marked modified
- Produces human-readable or JSON reports and automation-friendly exit codes
- Includes an end-to-end demonstration and automated test suite

## Prove it works

The demonstration creates real temporary files, records a baseline, modifies
one file, creates one, deletes one, and verifies all three changes:

```powershell
python file_integrity_monitor.py demo
python file_integrity_monitor.py demo --json
```

The temporary directory is automatically removed afterward.

## Monitor a directory

```powershell
python file_integrity_monitor.py baseline C:\Path\To\Folder
python file_integrity_monitor.py check C:\Path\To\Folder
```

By default, `.fim-baseline.json` is created inside the monitored root and is
automatically excluded. For stronger separation, use a protected location:

```powershell
python file_integrity_monitor.py baseline C:\Path\To\Folder `
  --baseline C:\Baselines\important-files.json

python file_integrity_monitor.py check C:\Path\To\Folder `
  --baseline C:\Baselines\important-files.json
```

An existing baseline is never replaced unless `--force` is supplied.

## Protect the baseline with HMAC

A normal JSON baseline can be replaced by anyone who can write to it. Generate
a random secret key, store it separately with restrictive permissions, and use
the same key for creation and verification:

```powershell
python -c "import secrets; open('C:\Baselines\fim.key','wb').write(secrets.token_bytes(32))"

python file_integrity_monitor.py baseline C:\Path\To\Folder `
  --baseline C:\Baselines\important-files.json `
  --key-file C:\Baselines\fim.key

python file_integrity_monitor.py check C:\Path\To\Folder `
  --baseline C:\Baselines\important-files.json `
  --key-file C:\Baselines\fim.key `
  --fail-on-change
```

Never commit the key or store it beside the baseline with the same access
permissions. A signed baseline cannot be checked without its key. Any change to
the signed baseline data causes verification to fail before files are compared;
formatting-only changes remain valid. Keys shorter than 32 bytes are rejected.

## Exclusions and relocated roots

Exclusions are relative to the monitored root. `*` matches within one path
component, while `**` can span directories:

```powershell
python file_integrity_monitor.py baseline C:\Path\To\Folder `
  --exclude "logs/**" --exclude "**/*.tmp"
```

Creation-time exclusions are stored and reused during checks. Additional
check-time exclusions reduce monitoring coverage and should be reviewed.

The monitor normally rejects a baseline created for a different absolute root.
For an intentional copy, container mount, or offline forensic image:

```powershell
python file_integrity_monitor.py check D:\MountedImage `
  --baseline C:\Baselines\important-files.json `
  --ignore-root
```

`--ignore-root` also ignores device and inode differences caused by relocation;
content and the remaining metadata are still checked.

To keep the original root check but ignore device/inode changes on a filesystem
with unstable file identities, use `--ignore-identity`.

Baseline format version 3 records filesystem identity and modification times.
Older baseline versions are deliberately rejected and must be recreated.

## Automation

Use `--json` for structured output and `--fail-on-change` to return exit code 1
when changes are detected.

- `0`: scan completed; no changes, or changes reported without `--fail-on-change`
- `1`: changes found with `--fail-on-change`
- `2`: invalid input, bad HMAC, unreadable/unsupported file, or scan error

## Run the tests

```powershell
python -W error -m unittest discover -s tests -v
```

GitHub Actions runs the suite on Python 3.10 and 3.13.

## Security considerations

- Keep the baseline and HMAC key under different, appropriately restricted
  access controls. HMAC authenticity is only as strong as key protection.
- `--ignore-root` should only be used when relocation is intentional.
- On Windows, UID/GID values provide limited information. Windows ACL auditing
  requires platform-specific APIs beyond this standard-library project.
- Extended attributes and alternate data streams are not monitored.
- Matching records do not establish who changed a file or why.
- This is a point-in-time learning tool, not an enterprise endpoint platform.
