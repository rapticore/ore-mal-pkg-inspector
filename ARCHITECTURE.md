# OreWatch - Technical Architecture

This document describes the current internal design of `OreWatch`.

**For end users**: see [README.md](README.md).  
**For contributors**: see [CONTRIBUTING.md](CONTRIBUTING.md).

## Overview

`OreWatch` is a Python 3.14+ malicious-package scanner for six ecosystems:

- npm
- PyPI
- Maven
- RubyGems
- Go
- Cargo

The scanner combines four main concerns:

1. Dependency discovery and parsing
2. Threat-data collection and database building
3. Report generation and IoC detection
4. Local background monitoring

Threat intelligence is stored in per-ecosystem SQLite databases under `collectors/final-data/`. Scan reports are emitted as project-specific JSON. Package findings include SARIF-style `physicalLocation` objects, but the overall report is not a full SARIF document.

## Repository Layout

```text
ore-mal-pkg-inspector/
├── malicious_package_scanner.py
├── logging_config.py
├── README.md
├── ARCHITECTURE.md
├── requirements.txt
├── scanner_engine.py
│
├── collectors/
│   ├── orchestrator.py
│   ├── build_unified_index.py
│   ├── db.py
│   ├── utils.py
│   ├── collect_openssf.py
│   ├── collect_osv.py
│   ├── collect_phylum.py
│   ├── collect_socketdev.py
│   ├── raw-data/
│   └── final-data/
│
├── scanners/
│   ├── supported_files.py
│   ├── ecosystem_detector.py
│   ├── dependency_parsers.py
│   ├── file_input_parser.py
│   ├── malicious_checker.py
│   ├── ioc_detector.py
│   └── report_generator.py
│
├── monitor/
│   ├── cli.py
│   ├── config.py
│   ├── notifier.py
│   ├── policy.py
│   ├── scheduler.py
│   ├── service.py
│   ├── snapshot_updater.py
│   ├── state.py
│   └── watcher.py
│
└── tests/
    ├── fixtures/manifests/
    ├── test_manifest_fixtures.py
    ├── test_monitor.py
    └── test_regressions.py
```

## Scan Flow

The scanner entry point is [`malicious_package_scanner.py`](malicious_package_scanner.py).

### 1. Argument handling

The CLI supports:

- directory scans
- single-file scans
- generic package lists with `--ecosystem`
- data refresh controls with `--latest-data`
- strict availability checks with `--strict-data`
- experimental source opt-in with `--include-experimental-sources`
- support introspection with `--list-supported-files`
- background monitoring with `monitor ...`

### 2. Threat-data readiness

Before package checking, the scanner calls `ensure_threat_data()`.

Current behavior:

- if `--ioc-only` is set, package threat-data setup is skipped
- if `--latest-data` is set, collection and rebuild always run
- otherwise, the scanner reuses local databases only if every expected ecosystem has usable metadata
- stale or pre-metadata databases are treated as needing refresh

The scanner derives per-request data status for the requested ecosystems:

- `complete`
- `partial`
- `failed`
- `not_applicable`

With `--strict-data`, the scan exits non-zero if any requested ecosystem is partial or failed.

### 3. Ecosystem detection and file discovery

`scanners/supported_files.py` is the single source of truth for supported manifests.

Each manifest entry defines:

- `filename`
- `ecosystem`
- `parser_id`

`scanners/ecosystem_detector.py` uses this registry for:

- auto-detecting ecosystems in a directory
- finding matching dependency files
- printing exact supported filenames through the CLI

This avoids drift between help text, parser dispatch, and auto-detection.

### 4. Dependency parsing

`scanners/dependency_parsers.py` dispatches by `parser_id`, not just by ecosystem.

That allows the scanner to support multiple formats per ecosystem with dedicated parsing logic, including:

- npm: `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`
- PyPI: `requirements.txt`, `setup.py`, `pyproject.toml`, `Pipfile`, `poetry.lock`
- Maven: `pom.xml`, `build.gradle`
- RubyGems: `Gemfile`, `Gemfile.lock`
- Go: `go.mod`, `go.sum`
- Cargo: `Cargo.toml`, `Cargo.lock`

Generic package lists still route through `scanners/file_input_parser.py` when the filename is not one of the registry-backed manifest names and the user supplies `--ecosystem`.

### 5. Package aggregation

The scanner aggregates packages by:

- ecosystem
- normalized package name
- version

This prevents collisions when the same package name and version appear in multiple ecosystems.

Aggregated package entries also collect all physical file locations that contributed the package finding.

### 6. Threat matching and IoC scanning

`scanners/malicious_checker.py` queries the per-ecosystem SQLite databases.

`scanners/ioc_detector.py` scans the project tree for attack indicators such as:

- malicious bundle files
- suspicious install hooks
- suspicious GitHub workflow patterns
- known malicious payload hashes

Package checks are skipped for ecosystems with no usable threat database unless `--strict-data` is set, in which case the scan fails instead.

### 7. Report generation

`scanners/report_generator.py` writes JSON reports with:

- scan metadata
- threat-data status metadata
- malicious package findings
- IoC findings

Top-level threat-data fields include:

- `data_status`
- `sources_used`
- `experimental_sources_used`
- `missing_ecosystems`

## Background Monitor

The background monitor uses the same scan engine as the foreground CLI.

### Runtime components

- `monitor/service.py` runs the long-lived process
- `monitor/state.py` stores watched projects, findings, notifications, and watcher snapshots
- `monitor/watcher.py` polls supported manifests plus IoC-sensitive files
- `monitor/scheduler.py` handles debounced file changes and periodic scan cadence
- `monitor/notifier.py` records notifications and emits desktop notifications when available
- `monitor/snapshot_updater.py` refreshes threat data from signed manifests or signed channel descriptors, or falls back to live collection
- `monitor/cli.py` exposes install, uninstall, start, stop, restart, status, watch, scan-now, and snapshot commands

### Runtime data

The monitor stores runtime artifacts in `.ore-monitor/`:

- `.ore-monitor/config.yaml`
- `.ore-monitor/state.db`
- `.ore-monitor/reports/`
- `.ore-monitor/services/`
- `.ore-monitor/snapshots/`
- `.ore-monitor/logs/monitor.log`

### Service installation

The monitor supports three runtime modes:

- `launchd` user agents on macOS
- `systemd --user` services on Linux
- repo-local background mode as a fallback when no native user service manager is available

The CLI writes repo-local templates first, then installs user-scoped service definitions when the selected manager supports it.

### Scan modes

The monitor uses two scan modes:

- `quick`: package-focused scan without full IoC traversal
- `full`: package scan plus IoC detection

Quick scans are triggered by generic manifest changes and periodic package sweeps. Full scans are triggered on a nightly cadence, manual requests, and higher-risk file changes such as workflow edits, `package.json` changes, and known payload-file creation.

### Findings lifecycle

Findings are fingerprinted and persisted so the monitor can distinguish:

- new findings
- escalated findings
- resolved findings

Notifications are emitted only for new or escalated findings by default, which avoids re-alerting developers on the same issue every cycle.

### Snapshot distribution

`monitor/snapshot_updater.py` supports two hosted update shapes:

- a direct signed `manifest.json`
- a signed channel descriptor that points at the current manifest URL

Published snapshots use a static-hosting-friendly layout with versioned assets under `versions/<version>/` and channel pointers under `channels/<channel>.json`.

Snapshot signing uses an offline private key and OpenSSL-backed RSA SHA-256 signatures. Verification uses only the public key configured in `.ore-monitor/config.yaml`.

Snapshot application stages and validates all files before replacing `collectors/final-data/`, and it restores the previous directory if the final swap fails.

## Threat Data Pipeline

Threat collection is orchestrated by [`collectors/orchestrator.py`](collectors/orchestrator.py).

### Source tiers

The orchestrator defines sources in `SOURCE_DEFINITIONS` with a tier and default behavior.

| Source | Tier | Default | Notes |
|--------|------|---------|-------|
| `openssf` | core | yes | Main malicious-package feed |
| `osv` | core | yes | Bulk malware entries filtered from OSV |
| `phylum` | experimental | no | Heuristic extraction from blog content |
| `socketdev` | disabled | no | Placeholder only |

Default refreshes use only the core sources. `--include-experimental` or `--include-experimental-sources` adds `phylum`. `socketdev` remains out of the default path.

### Raw-data stage

Collectors write normalized JSON files to `collectors/raw-data/`.

Each raw file includes:

- `source`
- `source_tier`
- `collected_at`
- `total_packages`
- `ecosystems`
- `packages`
- optional `error`

### Build stage

`collectors/build_unified_index.py` loads raw files, groups packages by ecosystem, deduplicates records, and writes SQLite databases.

The builder can load only a selected subset of sources, which lets the orchestrator keep source selection and database metadata aligned.

### Database metadata

`collectors/db.py` stores per-ecosystem metadata alongside package rows.

Important metadata keys:

- `data_status`
- `sources_used`
- `experimental_sources_used`
- `failed_sources`
- `last_successful_collect`

`collectors/orchestrator.py` uses these metadata keys to decide whether existing databases are reusable or stale.

## Database Model

Each ecosystem database is stored at:

- `collectors/final-data/unified_npm.db`
- `collectors/final-data/unified_pypi.db`
- `collectors/final-data/unified_rubygems.db`
- `collectors/final-data/unified_go.db`
- `collectors/final-data/unified_maven.db`
- `collectors/final-data/unified_cargo.db`

The package table stores merged threat records such as:

- package name
- versions
- severity
- sources
- vulnerability or malware identifiers
- description
- detected behaviors
- timestamps

Metadata tables store refresh and source-coverage state used by the scanner.

## Supported Manifest Registry

The manifest registry lives in [`scanners/supported_files.py`](scanners/supported_files.py).

This file is intentionally shared across:

- ecosystem detection
- directory file discovery
- parser dispatch
- fixture tests
- `--list-supported-files`

That registry-driven design is the main guardrail against the previous class of bugs where a file appeared supported in docs or detection logic but was parsed by the wrong handler.

## Tests

Two test modules provide regression coverage:

- [`tests/test_manifest_fixtures.py`](tests/test_manifest_fixtures.py)
- [`tests/test_regressions.py`](tests/test_regressions.py)

The fixture suite verifies that every registry-backed manifest has:

- a fixture file
- a working parser path
- consistent detector and parser behavior

The regression suite covers scanner and collector behavior such as:

- threat-data refresh decisions
- source selection defaults
- report metadata output
- multi-ecosystem package aggregation

Tests are offline and deterministic. They do not require live network access.

## Module Notes

### `malicious_package_scanner.py`

Main CLI orchestration. Handles threat-data readiness, scan mode selection, ecosystem filtering, and strict-data enforcement.

### `scanners/supported_files.py`

Single-source registry for supported manifests.

### `scanners/ecosystem_detector.py`

Directory walking and ecosystem detection based on the registry and skip-directory rules.

### `scanners/dependency_parsers.py`

Filename-aware dependency parsing routed through `parser_id`.

### `collectors/orchestrator.py`

Source selection, collection execution, database build decisions, and data-status summarization.

### `collectors/build_unified_index.py`

Raw-data loading and database construction.

### `collectors/db.py`

SQLite schema creation, inserts, metadata storage, and metadata reads.

### `scanners/report_generator.py`

JSON report emission and console summary output.

## Operational Notes

- The scanner is read-only against the target project.
- Collection requires network access; scanning with already-built databases does not.
- First-run behavior is intentionally strict about database completeness to avoid silent empty or stale scans.
- The repository still carries a disabled Socket.dev placeholder, but it is not part of the supported default data path.
