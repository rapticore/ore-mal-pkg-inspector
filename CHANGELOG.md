# Changelog

All notable changes to this project are documented in this file.

## 1.3.0 - 2026-05-15

- Added a first-class package update advisory surface across the monitor: best-effort latest-version lookups for npm, PyPI, Maven Central, RubyGems, Go module proxy, and crates.io, plus an OreWatch self-update detector that recognizes pipx, pip, and Homebrew installs (including custom Homebrew prefixes via formula sibling-path checks).
- Added durable advisory storage in a new `package_update_advisories` SQLite table with new/updated/resolved deltas, so update suggestions persist across monitor restarts and can be reviewed later.
- Exposed advisories across all monitor surfaces: `orewatch monitor package-updates [--check] [--project] [--limit] [--all] [--json]`, `GET /v1/package-updates`, `POST /v1/package-updates/check`, and the new MCP tools `orewatch_list_package_updates` and `orewatch_check_package_updates`.
- Wired daily scheduled and manual update checks into the singleton monitor with file-lock serialization, structured runtime state (`running`/`queued`/`success`/`warning`/`skipped`/`contended`/`failed`), and clean state reset on every early-return path so the menu bar never gets stuck in a phantom "running" status.
- Upgraded the macOS menu bar with a dedicated Package Updates section: count badge (`OW U2`, capped at `OW U9+`), last-check status, self-update indication, per-project update entries with reveal-manifest, copyable suggested commands, and a manual "Check for Package Updates" action.
- Reinforced the notify-only contract: OreWatch surfaces newer versions and copy-ready commands but never mutates manifests, lockfiles, or installed packages.
- Updated Homebrew install guidance across README and docs: clarified that `orewatch monitor menubar` requires PyObjC in the same Python environment as `orewatch`, with `brew update && brew reinstall rapticore/tap/orewatch` documented as the recovery path for older Homebrew installs missing `AppKit`. (Note: the tap formula itself does not yet bundle PyObjC; a follow-up tap change is needed to enable `orewatch monitor menubar` directly on Homebrew installs.)
- Verified the release with `python3.14 -m py_compile monitor/*.py`, `python3.14 -m pytest tests/test_monitor.py -q` (112 passed), `python3.14 -m pytest -q` (189 passed, 82 subtests passed), `python3.14 -m build`, and `python3.14 -m twine check`.

## 1.2.5 - 2026-05-11

- Added a manual threat-intelligence refresh path across CLI, local API, and the macOS menu bar so users can request an immediate update outside the scheduled cadence.
- Added user-global local malicious package names, including menu bar add/remove controls, API/CLI management, exact affected-version support, and automatic retirement once official threat intelligence catches up.
- Seeded the same local-threat overlay with the StepSecurity Mini Shai-Hulud npm package/version list from May 11, 2026 so newly reported compromised packages block immediately while upstream feeds lag.
- Improved menu bar findings so long compromised dependency manifest paths remain accessible via a full-path copy action and a reveal-manifest action.
- Hardened live update failures by serializing refreshes with a lock, tracking refresh runtime state, moving collector caches into monitor-owned per-refresh directories, cleaning stale staging, and clearing stale OSV extraction trees.
- Verified the release with `python3.14 -m json.tool package.json`, `python3.14 -m py_compile ...`, `PYTHONPATH=. pytest tests/`, `python3.14 -m build`, and `python3.14 -m twine check`.

## 1.2.4 - 2026-05-11

- Improved the macOS menu bar install error: when PyObjC is missing, OreWatch now suggests the documented `orewatch[mac-menubar]` pip extra and `pipx inject orewatch pyobjc-framework-Cocoa`, and explicitly calls out that Homebrew's isolated libexec virtualenv will not pick up a separate `pip install`.
- Accepted `orewatch menubar ...` as a top-level alias for `orewatch monitor menubar ...` so Homebrew console-script users don't have to remember the `monitor` subcommand.
- Verified the release with `python3.14 -m pytest tests/`, `python3.14 -m build`, and `python3.14 -m twine check`.

## 1.2.3 - 2026-05-11

- Fixed unbounded growth of `snapshots/live-updates/backups/` and `snapshots/backups/`: each live-update or snapshot-apply promotion previously copied the full prior threat-data tree (~300 MB) with no retention, accumulating tens of gigabytes on long-running monitors.
- Replaced full database copies with SHA-256 backup manifests (~1 KB each); the rollback path in the swap root is unchanged, so durability is preserved.
- Added retention controls under `live_updates`: `retain_backups` (default 30) and `staging_max_age_seconds` (default 3600), with on-demand application via `orewatch monitor cleanup [--keep-backups N] [--staging-max-age-seconds N]`.
- Orphaned `candidate-raw-*` and `candidate-final-*` staging directories left behind by interrupted promotions are now reaped automatically on the next promotion and on demand via `monitor cleanup`.
- Renamed the live-update report field `backup_dir` to `backup_manifest_path` to reflect that the artifact is now a manifest file, not a database tree.
- Verified the release with `python3.14 -m pytest tests/`, `python3.14 -m build`, and `python3.14 -m twine check`.

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
