# Changelog

All notable changes to this project are documented in this file.

## 1.2.2 - 2026-04-12

- Removed the remaining `sys.path` import shims from scanner and collector entrypoints by switching to package-aware imports and explicit local module loading.
- Fixed monitor state path normalization so watched projects, notifications, and dependency-check records treat `/var/...` and `/private/var/...` aliases consistently on macOS.
- Expanded regression coverage for collector loading, malicious checker module resolution, normalized project-path storage, and the associated end-to-end release flow.
- Verified the release with `python3.14 -m unittest tests.test_monitor tests.test_regressions tests.test_packaging tests.test_client_e2e tests.test_e2e_compromised_detection`, `python3.14 -m build`, and the lean end-to-end matrix run in `scripts/run_e2e_matrix.py`.

## 1.2.1 - 2026-04-11

- Hardened monitor request validation, service path handling, snapshot staging, and collector error reporting against path traversal, weak token handling, unsafe temp/log path usage, and malformed payloads.
- Reduced regex-related scanner risk in IoC and dependency parsing paths and tightened Shai-Hulud version matching so prereleases stay distinct while exact `v`-prefixed versions still match.
- Fixed hardening regressions by restoring legitimate temp-root monitor layouts and log access, and by updating snapshot tests to use valid SQLite fixtures under the stricter snapshot validation rules.
- Verified the release with `python3.14 -m unittest tests.test_monitor tests.test_regressions`, `python3.14 -m unittest tests.test_packaging`, `python3.14 -m build --outdir /tmp/orewatch-1.2.1-dist`, and `python3.14 -m twine check /tmp/orewatch-1.2.1-dist/*`.

## 1.2.0 - 2026-04-11

- Hardened monitor, scanner, collector, and snapshot paths against unsafe path handling, oversized inputs, unsafe URL usage, and malformed config payloads.
- Fixed release-blocking regressions introduced during hardening, including temp-root monitor support, deleted watched-project cleanup, and local `file://` snapshot application.
- Improved the macOS menu bar app to show the running OreWatch version in the dropdown header and tooltip.
- Expanded integration and installation documentation for Codex, Claude Code, Cursor, and local monitor usage.
- Refreshed test coverage for dependency source normalization, threaded dependency checks, temp-root monitor layouts, deleted watched projects, snapshot channel application, and menu bar version rendering.
