# Security Policy

## Supported version

Only the latest commit on `main` is maintained.

## Intended use

This repository is an educational defensive-security monitor. It is not a
production endpoint agent. HMAC keys and baselines from real systems must stay
outside the repository and be protected according to their sensitivity.

## Reporting a security issue

Use GitHub private vulnerability reporting when available. Do not place
credentials, HMAC keys, private keys, or sensitive filesystem evidence in a
public issue. Revoke and rotate exposed secrets before repository cleanup.

## Maintainer checks

Before publishing, run `pre-commit run --all-files`, the documented test suite,
and GitHub secret scanning. Confirm that generated baselines remain ignored.
