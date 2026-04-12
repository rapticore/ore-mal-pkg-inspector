# Changelog

All notable changes to this project are documented in this file.

## 1.2.0 - 2026-04-11

- Hardened monitor, scanner, collector, and snapshot paths against unsafe path handling, oversized inputs, unsafe URL usage, and malformed config payloads.
- Fixed release-blocking regressions introduced during hardening, including temp-root monitor support, deleted watched-project cleanup, and local `file://` snapshot application.
- Improved the macOS menu bar app to show the running OreWatch version in the dropdown header and tooltip.
- Expanded integration and installation documentation for Codex, Claude Code, Cursor, and local monitor usage.
- Refreshed test coverage for dependency source normalization, threaded dependency checks, temp-root monitor layouts, deleted watched projects, snapshot channel application, and menu bar version rendering.

