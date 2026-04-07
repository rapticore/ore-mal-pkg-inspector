# OreWatch

**Multi-Ecosystem Malicious Package Detection and Supply Chain Security Scanner**

![Python Version](https://img.shields.io/badge/python-3.14-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-active-success.svg)
![Ecosystems](https://img.shields.io/badge/ecosystems-6-orange.svg)

A production-grade security tool for detecting malicious packages and supply chain threats across npm, PyPI, Maven, RubyGems, Go, and Cargo ecosystems. Leverages automated threat intelligence collection from trusted security sources to identify compromised dependencies in your projects.

`OreWatch` is the product and PyPI package name. The current source repository path still uses `ore-mal-pkg-inspector`.

# Videos 

## Installation 

https://github.com/rapticore/ore-mal-pkg-inspector/issues/2#issue-4215016110

## OreWatch and Cursor

https://github.com/rapticore/ore-mal-pkg-inspector/issues/3#issue-4215017945

## OreWatch and CodeX

https://github.com/rapticore/ore-mal-pkg-inspector/issues/4#issue-4215019385

## OreWatch and Claude-Code

https://github.com/rapticore/ore-mal-pkg-inspector/issues/5#issue-4215021599


---

## Table of Contents

- [The Problem](#the-problem)
- [The Solution](#the-solution)
- [Key Features](#key-features)
- [Why OreWatch?](#why-orewatch)
- [Start Here](#start-here)
- [Quick Start](#quick-start)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [First Scan](#first-scan)
- [Usage](#usage)
  - [Basic Commands](#basic-commands)
  - [Advanced Usage](#advanced-usage)
  - [Command-Line Reference](#command-line-reference)
  - [Background Monitoring](#background-monitoring)
- [Adoption Guide](#adoption-guide)
- [Distribution](#distribution)
  - [Managed macOS Rollout](#managed-macos-rollout)
- [Logging & Debugging](#logging--debugging)
- [Output & Reports](#output--reports)
- [CI/CD Integration](#cicd-integration)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)
- [Contributing](#contributing)
- [Security Policy](#security-policy)
- [Roadmap](#roadmap)
- [License](#license)
- [Support](#support)
- [Acknowledgments](#acknowledgments)

---

## The Problem

**Supply chain attacks are now the primary threat vector for software compromise.** In 2024 alone, thousands of malicious packages were published to npm, PyPI, and other package registries, targeting developers with typosquatting, dependency confusion, and sophisticated malware campaigns like Shai-Hulud.

**The challenge:** Organizations and developers need to:
- Scan dependencies across multiple programming ecosystems
- Stay current with rapidly evolving threat intelligence from multiple sources
- Detect not just known malicious packages but also indicators of compromise (IoCs)
- Integrate security scanning into existing development workflows
- Respond quickly to newly discovered threats

**The gap:** Existing solutions are often:
- Limited to a single ecosystem (npm-only, PyPI-only, etc.)
- Reliant on manual threat list maintenance
- Lacking IoC detection capabilities
- Difficult to integrate into automated pipelines
- Proprietary black-box tools without transparency

---

## The Solution

**OreWatch** addresses these challenges by providing:

**Comprehensive Multi-Ecosystem Coverage:** Single tool for npm, PyPI, Maven, RubyGems, Go, and Cargo packages

**Automated Threat Intelligence:** Dynamically collects and merges data from trusted security research sources

**Active IoC Detection:** Identifies Shai-Hulud attack patterns and other malicious code indicators beyond package name matching

**CI/CD Ready:** Designed for seamless integration into GitHub Actions, GitLab CI, Jenkins, and other automation platforms

**Open Source and Transparent:** Complete visibility into detection logic, data sources, and scanning methodology

---

## Key Features

**Multi-Ecosystem Support**
Scans npm, PyPI, Maven, RubyGems, Go, and Cargo packages with automatic ecosystem detection from project structure.

**Unified Threat Intelligence Database**
Checks against dynamically collected malicious package databases from trusted security research sources.

**Automatic Ecosystem Detection**
Intelligently identifies ecosystems from directory structure, file names, and can scan multiple ecosystems in a single run.

**Indicators of Compromise (IoC) Detection**
Scans for Shai-Hulud attack patterns (original and 2.0 variants), malicious hooks, suspicious workflows, and known payload files.

**Shai-Hulud Integration**
Cross-references npm packages against the comprehensive Shai-Hulud affected packages list from OreNPMGuard.

**Structured JSON Reporting**
Generates machine-readable JSON reports with explicit threat-data metadata and SARIF-style file locations for findings.

**Flexible Input Formats**
Supports standard dependency files (package.json, requirements.txt, etc.) and generic package lists (text, JSON, YAML).

**Production-Ready Logging**
Configurable verbosity levels with `--verbose` and `--debug` flags for troubleshooting and audit trails.

**Safe and Fast**
Read-only operations with no modifications to your code, optimized for scanning large codebases efficiently.

---

## Why OreWatch?

**vs. Single-Ecosystem Tools**
Most security scanners focus on one package manager. OreWatch provides unified protection across six major ecosystems, essential for modern polyglot development environments.

**vs. Manual Threat Lists**
Static malicious package lists become outdated quickly. Our automated collectors fetch fresh threat intelligence daily from multiple authoritative sources.

**vs. Package-Name-Only Detection**
Checking package names alone misses sophisticated attacks. IoC detection identifies malicious code patterns even in packages not yet on blocklists.

**vs. Manual Security Audits**
Manual dependency reviews are time-consuming and error-prone. Automated scanning enables continuous security validation in every build.

**vs. Commercial Black-Box Tools**
Proprietary tools lack transparency in detection logic. As an open-source project, every detection rule and data source is auditable.

**Origin Story**
OreWatch was born from the development of [OreNPMGuard](https://github.com/rapticore/OreNPMGuard), a specialized scanner for Shai-Hulud npm attacks. During that project, we recognized the need for broader multi-ecosystem coverage beyond npm. In December 2025, we extracted and enhanced the multi-ecosystem detection capabilities into this standalone tool, maintaining OreNPMGuard's focus on npm while enabling OreWatch to serve the wider developer community across all major package ecosystems.

---

## Start Here

If you are adopting OreWatch for the first time, pick the smallest path that matches your workflow:

| I want to... | Use this path | Start with |
|--------------|---------------|------------|
| scan one repo right now | CLI scan | `orewatch /path/to/project` |
| protect local development in the background | singleton monitor | `orewatch monitor quickstart /path/to/project --client claude_code` |
| use OreWatch from Cursor, Claude Code, or Codex | MCP bridge | `orewatch monitor quickstart /path/to/project --client cursor` |
| integrate with VS Code, PyCharm, or Xcode | localhost API | `orewatch monitor quickstart /path/to/project --client vscode` |
| get visible macOS alerts and a native review surface | menu bar app | `orewatch monitor menubar` |
| validate builds in CI | one-off CLI scan | `orewatch . --strict-data` |

Recommended first-run sequence for most developers:

1. Install OreWatch with `pip install .` or the published package.
2. Run `orewatch monitor quickstart /path/to/project --client <your-client>`.
3. Verify the daemon with `orewatch monitor status`.
4. If you are on macOS, launch `orewatch monitor menubar` for notifications and a local UI.

If you want a shorter setup guide with copy-paste commands, use [docs/adoption-guide.md](docs/adoption-guide.md).

---

## Quick Start

### Prerequisites

- **Python 3.14 or higher**
- **pip** for installing dependencies
- **Git** for cloning the repository
- **Internet connection** for initial threat intelligence setup
- **OpenSSL** for signed snapshot key generation, publishing, and verification in monitor snapshot workflows

### Installation

**Release install for end users:**

```bash
# Recommended isolated install for developers
pipx install orewatch

# macOS Homebrew tap
brew install rapticore/tap/orewatch
```

**Source checkout for contributors:**

```bash
# Clone the repository
git clone https://github.com/rapticore/ore-mal-pkg-inspector.git
cd ore-mal-pkg-inspector

# Create and activate virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install the project and its CLI entry point
pip install .
```

_Note: If local threat data is missing or stale, package scans stage a live-update candidate and only promote it after anomaly gates pass. If the candidate looks suspicious, OreWatch keeps the last-known-good dataset active._

_Note: The `pipx` and Homebrew commands above are the recommended end-user install paths. The source-checkout flow below them remains the development and contributor path. See [Distribution](#distribution) for the release model details._

_Installed CLI:_ `orewatch`  
_Compatibility alias:_ `ore-mal-pkg-inspector`

### First Scan

**Scan a project directory:**

```bash
# Auto-detect ecosystem and scan current directory
orewatch .

# Scan specific project path
orewatch /path/to/your/project

# With verbose output to see progress
orewatch /path/to/your/project --verbose
```

**Expected output:**

```
Detected multiple ecosystems: npm, pypi
   Scanning all detected ecosystems...

   Scanning npm...
   Found 2 dependency file(s) for npm
      Parsing: package.json
      Parsing: package-lock.json

   Scanning pypi...
   Found 1 dependency file(s) for pypi
      Parsing: requirements.txt

Extracted 45 unique package(s) across 2 ecosystem(s)

Checking 45 package(s) against malicious databases...
   Checking 30 npm package(s)...
   Checking 15 pypi package(s)...

Scanning for Indicators of Compromise...

Generating report...

============================================================
SCAN REPORT SUMMARY
============================================================
Ecosystem: npm, pypi
Total Packages Scanned: 45
Malicious Packages Found: 0
IoCs Found: 0

✅ No malicious packages or IoCs detected

HTML report saved to: scan-output/malicious_packages_report_20251231_120000.html
JSON report saved to: scan-output/malicious_packages_report_20251231_120000.json
============================================================
```

If you want OreWatch to keep watching the project after this first scan, continue with [Background Monitoring](#background-monitoring) or jump straight to [docs/adoption-guide.md](docs/adoption-guide.md).

---

## Usage

### Basic Commands

**Scan Directory (Auto-detect ecosystem):**

```bash
# Current directory
orewatch .

# Specific directory
orewatch /home/user/projects/my-app

# With absolute path
orewatch ~/projects/backend-api
```

**Scan Specific Dependency Files:**

```bash
# Ecosystem auto-detected from filename
orewatch --file package.json
orewatch --file requirements.txt
orewatch --file pom.xml
orewatch --file Gemfile
orewatch --file go.mod
orewatch --file Cargo.toml
```

**Force Specific Ecosystem:**

```bash
# Override auto-detection
orewatch /path/to/project --ecosystem npm
orewatch /path/to/project --ecosystem pypi
orewatch /path/to/project --ecosystem maven
orewatch /path/to/project --ecosystem rubygems
orewatch /path/to/project --ecosystem go
orewatch /path/to/project --ecosystem cargo
```

**Scan Generic Package Lists:**

```bash
# Text file (one package per line) - must specify ecosystem
orewatch --file packages.txt --ecosystem pypi

# JSON file with package array
orewatch --file packages.json --ecosystem npm

# YAML file
orewatch --file packages.yaml --ecosystem npm
```

### Advanced Usage

**Custom Output Path:**

```bash
# Save to custom location
orewatch /path/to/project --output /tmp/scan_report.json

# Save to specific subdirectory
orewatch /path/to/project --output reports/security/$(date +%Y%m%d).json
```

**IoC Scanning Control:**

```bash
# Full scan (packages + IoCs) - default behavior
orewatch /path/to/project

# Skip IoC scanning for faster package-only checks
orewatch /path/to/project --no-ioc

# Only scan for IoCs, skip package database checking
orewatch /path/to/project --ioc-only
```

**Quiet Mode:**

```bash
# Generate report without console summary (useful for scripts)
orewatch /path/to/project --no-summary
```

**Threat Data Controls:**

```bash
# Force a staged live refresh of the default core sources before scanning
orewatch /path/to/project --latest-data

# Fail if any requested ecosystem only has partial or missing threat data
orewatch /path/to/project --strict-data

# Include experimental sources during collection
orewatch /path/to/project --latest-data --include-experimental-sources

# Print the exact dependency filenames the scanner recognizes
orewatch --list-supported-files
```

**Batch Scanning:**

```bash
# Scan multiple projects
for dir in ~/projects/*/; do
    echo "Scanning $dir"
    orewatch "$dir" --output "reports/$(basename $dir).json"
done
```

### Command-Line Reference

#### Scanner Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--file` | `-f` | Path to specific file to scan (skips directory detection) | None |
| `--ecosystem` | `-e` | Force ecosystem: `npm`, `pypi`, `maven`, `rubygems`, `go`, `cargo` | Auto-detect |
| `--output` | `-o` | Custom output path for the primary JSON report; OreWatch also writes a sibling HTML report | `scan-output/malicious_packages_report_{timestamp}.json` |
| `--no-summary` | | Skip printing report summary to console | False |
| `--no-ioc` | | Skip IoC (Indicators of Compromise) scanning | False |
| `--ioc-only` | | Only scan for IoCs, skip package checking | False |
| `--latest-data` | | Force a staged live refresh and anomaly-gated promotion before scanning | False |
| `--strict-data` | | Fail if any requested ecosystem has partial or missing threat data | False |
| `--include-experimental-sources` | | Include experimental collectors during threat-data refresh | False |
| `--list-supported-files` | | Print the exact supported dependency manifest filenames and exit | False |
| `--verbose` | `-v` | Show INFO level logs (progress messages) | False |
| `--debug` | | Show DEBUG level logs (detailed diagnostics) | False |

### Background Monitoring

The repository now includes a local background monitor that keeps threat data fresh, watches opted-in projects for manifest and workflow changes, runs debounced scans, and records notifications for new or escalated findings. Monitor-owned config and state are stored outside the repo in user-owned directories so a cloned repository cannot preseed monitor behavior.

OreWatch now treats the monitor as a per-user singleton. One daemon can watch many projects anywhere on disk and serve many concurrent Claude Code, Codex, Cursor, VS Code, JetBrains / PyCharm, and Xcode clients.

#### End-to-End Monitor Setup

**1. Install and bootstrap the singleton monitor**

```bash
# First project + first client
orewatch monitor quickstart /path/to/project --client claude_code
```

`monitor quickstart` is the recommended first-run flow. It:

- installs or refreshes the singleton monitor service
- starts the monitor if needed
- adds the target project to the watch list
- prints the bootstrap block for the selected client

If you prefer to install the monitor first and wire clients later:

```bash
orewatch monitor install
orewatch monitor install --ide-bootstrap
orewatch monitor install --service-manager launchd --no-start
```

**2. Verify the monitor is healthy**

```bash
orewatch monitor status
orewatch monitor connection-info
orewatch monitor doctor
```

Use these commands for slightly different jobs:

- `monitor status` shows whether the singleton daemon and API are running
- `monitor connection-info` prints the loopback API URL, token path, monitor home, and supported bootstrap clients
- `monitor doctor` prints the exact config, state DB, log, and shared threat-data paths

**3. Add every project you want the singleton to watch**

```bash
orewatch monitor watch add /path/to/project-a
orewatch monitor watch add /path/to/project-b
orewatch monitor watch list
orewatch monitor watch remove /path/to/project-b
```

One OreWatch daemon can watch all of these projects at once. You do not need a separate monitor per repository or per IDE workspace.

#### Client Integration Recipes

OreWatch supports two integration transports:

| Client | Transport | Bootstrap Command | Notes |
|--------|-----------|-------------------|-------|
| Claude Code | MCP | `orewatch monitor ide-bootstrap --client claude_code` | First-class MCP bridge |
| Codex | MCP | `orewatch monitor ide-bootstrap --client codex` | First-class MCP bridge |
| Cursor | MCP | `orewatch monitor ide-bootstrap --client cursor` | First-class MCP bridge |
| VS Code | Local API | `orewatch monitor ide-bootstrap --client vscode` | No bundled extension; use the localhost API |
| JetBrains / PyCharm | Local API | `orewatch monitor ide-bootstrap --client jetbrains` | No bundled plugin; use the localhost API |
| Xcode | Local API | `orewatch monitor ide-bootstrap --client xcode` | Best for findings/notifications and mixed-language repos |

The bootstrap commands print one of these shapes:

```json
{
  "mcpServers": {
    "orewatch": {
      "command": "/absolute/path/to/orewatch",
      "args": [
        "monitor",
        "mcp"
      ]
    }
  }
}
```

When `orewatch monitor ide-bootstrap --client <client>` can resolve the local console script, it now emits that absolute path instead of bare `orewatch`. If you have an older MCP config that still says `"command": "orewatch"`, regenerate it and replace the old entry.

```json
{
  "orewatch": {
    "baseUrl": "http://127.0.0.1:48736",
    "tokenPath": "/path/to/api.token"
  }
}
```

##### Cursor, Claude Code, and Codex

These clients all use the same local MCP bridge:

```bash
orewatch monitor mcp
```

Recommended setup:

1. Run `orewatch monitor quickstart /path/to/project --client cursor` once.
2. Copy the printed MCP block into Cursor, Claude Code, or Codex.
3. Open a watched project in that client.
4. Let the client call OreWatch over MCP for:
   - `orewatch_health`
   - `orewatch_check_dependency_add`
   - `orewatch_check_manifest`
   - `orewatch_override_dependency_add`
   - `orewatch_list_active_findings`
   - `orewatch_list_notifications`

Notes:

- `monitor mcp` is a stdio server. If you launch it manually, it will appear idle while waiting for an MCP client.
- The MCP bridge checks the local API on startup and can auto-start the singleton monitor once when `auto_start_on_client` is enabled.
- For reliable IDE startup, install the background monitor once with `monitor install` so the daemon is already available before the MCP bridge starts.

##### VS Code

VS Code integrations should use the singleton localhost API rather than the MCP bridge.

Recommended setup:

1. Run `orewatch monitor quickstart /path/to/project --client vscode`.
2. Copy the `baseUrl` and `tokenPath` from `orewatch monitor ide-bootstrap --client vscode`.
3. Wire those values into your local VS Code extension, task, or helper.
4. Call the API on dependency-add, manifest-save, and alert-refresh events.

Recommended API usage for a VS Code integration:

- call `POST /v1/check/dependency-add` before package-manager install/add flows
- call `POST /v1/check/manifest` when a supported manifest is saved or explicitly rechecked
- poll `GET /v1/findings/active` and `GET /v1/notifications` to surface background detections

##### JetBrains / PyCharm

JetBrains and PyCharm use the same localhost API contract as VS Code.

Recommended setup:

1. Run `orewatch monitor quickstart /path/to/project --client jetbrains`.
2. Copy the API block from `orewatch monitor ide-bootstrap --client jetbrains`.
3. Use the returned `baseUrl` and `tokenPath` in a JetBrains plugin, external tool, or local helper.
4. Surface both synchronous dependency decisions and stored background alerts inside the IDE.

Recommended API usage for a JetBrains integration:

- check dependency additions with `POST /v1/check/dependency-add`
- recheck `package.json`, `requirements.txt`, `pyproject.toml`, `pom.xml`, `Gemfile`, `go.mod`, `Cargo.toml`, and related supported manifests with `POST /v1/check/manifest`
- fetch `GET /v1/findings/active` and `GET /v1/notifications` for persistent alert panels or tool windows

##### Xcode

Xcode integrations should also use the singleton localhost API, but there is an important scope boundary: OreWatch does not yet parse native Apple dependency manifests such as `Package.resolved`, `Podfile.lock`, or `Cartfile`. Today, Xcode integration is best for:

- showing background findings and notifications in a helper, script, or companion app
- mixed-language repositories opened in Xcode that also contain supported manifests such as `package.json`, `pyproject.toml`, or `Cargo.toml`
- teams that want the macOS menu bar app and Notification Center alerts while working in Xcode

Recommended setup:

1. Run `orewatch monitor quickstart /path/to/project --client xcode`.
2. Copy the API block from `orewatch monitor ide-bootstrap --client xcode`.
3. Use the returned `baseUrl` and `tokenPath` from a build-phase script, a helper process, or a custom Xcode integration.
4. Poll `GET /v1/findings/active` and `GET /v1/notifications` for user-visible alerts.
5. If the Xcode workspace contains supported non-Apple manifests, call `POST /v1/check/manifest` for those files as part of your workflow.

Current integration status:

- Claude Code, Codex, and Cursor: first-class MCP bridge included in this repo
- VS Code: local API contract documented, but no first-party extension bundled yet
- JetBrains / PyCharm: local API contract documented, but no first-party plugin bundled yet
- Xcode: local API and menu bar integration documented, but no first-party Xcode extension and no native Apple manifest parser yet

#### When OreWatch Finds Something

When the background monitor detects a compromised package or IoC in a watched project, OreWatch:

- writes monitor-managed JSON and HTML reports under the singleton monitor `reports/` directory
- stores the active finding in the monitor state DB
- stores a notification entry with an actionable message
- emits a terminal warning if terminal notifications are enabled
- on macOS, prefers the singleton menu bar app as the popup channel when it is running
- keeps the newest attention-worthy alert pinned at the top of the menu bar dropdown for quick review
- otherwise falls back to a best-effort direct desktop notification if desktop notifications are enabled
- can send an optional webhook notification for remote or headless environments

Use the built-in CLI review surface to inspect those alerts:

```bash
orewatch monitor findings
orewatch monitor findings --project /path/to/project --min-severity high
orewatch monitor notifications
orewatch monitor notifications --project /path/to/project
```

The local API and MCP bridge expose the same data for IDEs and agents:

- API:
  - `GET /v1/findings/active`
  - `GET /v1/notifications`
- MCP:
  - `orewatch_list_active_findings`
  - `orewatch_list_notifications`

This is the supported path for IDEs, MCP clients, and coding agents to surface background detections after the original scan has finished.

#### Native macOS Menu Bar App

OreWatch now includes a macOS-native menu bar app for people who want a visible local UI instead of relying only on CLI commands, MCP polling, or best-effort Notification Center popups.

Install the optional Cocoa bindings once on macOS:

```bash
python3.14 -m pip install 'orewatch[mac-menubar]'
```

Then launch the menu bar app:

```bash
orewatch monitor menubar
```

By default, `monitor menubar` relaunches the app in the background and returns your shell prompt immediately. Use `orewatch monitor menubar --foreground` only when you explicitly want to keep it attached to the terminal for debugging.

The menu bar app attaches to the same singleton monitor. It does not start a second monitor instance. If the monitor is not already installed and running, the app will install/start it on first launch.

When desktop notifications are enabled on macOS, the singleton watcher now keeps one singleton menu bar app alive and uses it as the primary popup surface. That avoids relying only on a detached `osascript` invocation from the daemon and gives you a persistent native UI for new findings.

The current menu bar build is icon-first. The old `OW` shorthand and earlier OreWatch icon wording should be treated as legacy references; the app now prefers the bundled branded icon and only falls back to compact text or badges when macOS cannot render the image or needs an alert count.

What the macOS menu bar app gives you:

- a persistent menu bar status item that prefers the bundled branded icon, with compact text fallback or alert badges when needed
- a compact red/bold alert state for newly detected alerts that stays visible until you open the menu
- a live summary of active findings and highest severity
- recent notifications in a native dropdown menu
- native Notification Center popups for newly stored monitor alerts
- an `Add Workspace Folder...` action that enrolls a project into the singleton watcher and runs an initial quick scan
- built-in configuration toggles for desktop notifications, terminal notifications, menu bar keepalive, and menu-bar-driven popups
- one-click actions to open reports, monitor home, and the monitor log
- one-click actions to open the monitor config file and config folder
- menu actions to refresh, run quick/full scans, and start/restart/stop the singleton monitor

Recommended Mac flow:

1. Run `orewatch monitor quickstart /path/to/project --client claude_code` once.
2. Install the optional bindings with `python3.14 -m pip install 'orewatch[mac-menubar]'`.
3. Launch `orewatch monitor menubar`.
4. Keep the menu bar app running for a persistent native review surface while your IDEs and coding agents continue using MCP or the local API.

## Adoption Guide

For easier rollout, use the focused docs instead of reading the full README end to end:

- [docs/adoption-guide.md](docs/adoption-guide.md): shortest path for local developer adoption
- [docs/local-api.md](docs/local-api.md): exact localhost API and MCP contract
- [docs/e2e-testing.md](docs/e2e-testing.md): contributor and validation workflow

Recommended adoption order:

1. Start with one repo and one user.
2. Enable the singleton monitor with `monitor quickstart`.
3. Connect one client: Cursor, Claude Code, Codex, VS Code, PyCharm, or Xcode.
4. Confirm that findings appear in `orewatch monitor findings` and `orewatch monitor notifications`.
5. On macOS, add `monitor menubar` so users get a persistent review surface and popup delivery.
6. After local adoption is stable, add CI scans and optional webhooks.

#### Daily Operations

**Common operational commands:**

```bash
# Background service lifecycle
orewatch monitor start
orewatch monitor restart
orewatch monitor stop
orewatch monitor uninstall

# Run the daemon in the foreground
orewatch monitor run

# Launch the native macOS menu bar UI
orewatch monitor menubar

# Trigger immediate scans
orewatch monitor scan-now
orewatch monitor scan-now /path/to/project

# Review detections and alerts
orewatch monitor findings
orewatch monitor notifications
```

**Manual snapshot and signing actions:**

```bash
# Generate a signing keypair
orewatch monitor snapshot keygen /tmp/ore-keys

# Build and apply local threat-data snapshots
orewatch monitor snapshot build /tmp/ore-snapshot \
  --private-key /tmp/ore-keys/snapshot_signing_private.pem \
  --public-key /tmp/ore-keys/snapshot_signing_public.pem
orewatch monitor snapshot apply /tmp/ore-snapshot/manifest.json \
  --public-key /tmp/ore-keys/snapshot_signing_public.pem

# Publish a hosted snapshot channel
orewatch monitor snapshot publish /tmp/ore-snapshots \
  --base-url https://example.com/ore-snapshots \
  --channel stable \
  --private-key /tmp/ore-keys/snapshot_signing_private.pem \
  --public-key /tmp/ore-keys/snapshot_signing_public.pem
```

**Monitor behavior:**
- Quick scans are package-focused and run on a schedule and after generic manifest changes.
- Full scans include IoC detection and run nightly, on manual request, and after workflow or payload-file changes.
- On Linux, config defaults to `~/.config/orewatch/singleton/` and state defaults to `~/.local/state/orewatch/singleton/`.
- On macOS, config defaults to `~/Library/Application Support/OreWatch/singleton/` and state defaults to `~/Library/Application Support/OreWatch/State/singleton/`.
- Shared threat data now lives under the singleton state directory at `threat-data/final-data/`.
- `monitor doctor` prints the exact `config_path`, `state_db`, `log_file`, `final_data_dir`, and service-template directory for the singleton monitor.
- Per-project policy overrides can be stored in `.ore-monitor.yml` at the project root.
- `monitor install` now installs a user-level `launchd` or `systemd` service when available, and falls back to the local background mode otherwise.
- `monitor quickstart /path/to/project --client claude_code` is the easiest first-run flow for a local LLM agent setup.
- `--workspace-root /path/to/workspace` is still accepted for one release as a deprecated compatibility alias, but it no longer changes monitor identity, token location, or service naming.
- In `auto` mode, if native `launchd` or `systemd` setup fails, OreWatch now falls back to the local background mode instead of aborting setup.
- `monitor install --ide-bootstrap` prints copy-paste bootstrap snippets for Claude Code, Codex, Cursor, VS Code, JetBrains / PyCharm, and Xcode.
- `monitor connection-info` prints the loopback API base URL, token path, singleton monitor scope/home, and whether the daemon is already running.
- `monitor ide-bootstrap` prints the current MCP/API bootstrap snippets again without reinstalling anything.
- `monitor mcp` runs a local MCP bridge that exposes OreWatch dependency checks to Claude Code, Codex, and Cursor.
- `monitor findings` and `monitor notifications` provide the built-in review surface for background detections.
- `monitor menubar` launches a native macOS menu bar app backed by the singleton monitor and findings store.
- `monitor mcp` is a stdio server, so it will wait for an MCP client after startup. It now writes readiness and auto-start status to stderr, not stdout.
- For IDE or MCP-client startup, use `monitor install` so the background daemon is already available when the client launches `monitor mcp` or calls the API.
- `make test-e2e-clients` bootstraps the synthetic workspace and runs the cross-ecosystem MCP/API client matrix for Claude Code, Codex, and Cursor.
- Open-source/community installs default to anomaly-gated live updates from the upstream core feeds (`openssf` and `osv`). Candidate data is staged in the user-owned monitor state directory, checked for abnormal drops/removals, and only then promoted into the active databases.
- Managed/enterprise installs can instead use a signed channel descriptor or manifest configured in the user-owned monitor config file via `snapshots.channel_url` or `snapshots.manifest_url`, and the monitor verifies them with `snapshots.public_key_path`.
- Signed snapshot workflows currently require `openssl` on the local machine.
- Cross-ecosystem client integration testing guidance is documented in [docs/e2e-testing.md](docs/e2e-testing.md).

**Local integration surface:**
- OreWatch now exposes a localhost-only API on `127.0.0.1:48736` by default when the monitor daemon is running.
- The API uses a per-user bearer token stored in the monitor config directory at `api.token` with owner-only permissions.
- Direct requests to `127.0.0.1:48736` without `Authorization: Bearer <token>` will correctly return `401 Unauthorized`.
- Agent and IDE clients should discover the monitor via `orewatch monitor connection-info` rather than guessing paths, and should send the actual `project_path` they are operating on inside dependency-check requests.
- Claude Code, Codex, and Cursor can use the bundled MCP bridge, which exposes `orewatch_health`, `orewatch_check_dependency_add`, `orewatch_check_manifest`, `orewatch_override_dependency_add`, `orewatch_list_active_findings`, and `orewatch_list_notifications`.
- VS Code, JetBrains / PyCharm, and Xcode integrations should call the same localhost API for dependency-add checks, manifest rechecks, active findings, and recent notifications.
- The exact request and response shapes are documented in [docs/local-api.md](docs/local-api.md).

**Optional anomaly-gated live-update config:**

```yaml
live_updates:
  enabled: true
  mode: gated
  bootstrap_from_live: true
  block_on_core_source_failure: false
  max_drop_ratio: 0.40
  max_drop_absolute: 200
  max_removal_ratio: 0.25
  max_removal_absolute: 100
  warn_growth_ratio: 5.0
  warn_growth_absolute: 2000
```

Key behavior:
- Live candidates are built in a staging area first; they do not overwrite the active databases during collection.
- Large drops, ecosystem regressions, empty ecosystems, and mass removals block promotion.
- Core-source outages are warning-only by default for open-source live refreshes; ecosystem-level drops and removals still block bad promotions.
- Warning-only anomalies are recorded in status and reports but do not prevent promotion.
- Rejected candidates keep the last-known-good dataset active when one already exists.
- First-run bootstrap from live feeds is allowed if at least one core source succeeds and the candidate produces usable ecosystem data.

**Optional notification webhook config:**

```yaml
notifications:
  desktop: true
  terminal: true
  webhook_url: https://hooks.example.com/orewatch
  webhook_format: generic
  webhook_timeout_ms: 5000
  webhook_headers:
    Authorization: Bearer change-me
```

Set `webhook_format: slack` when targeting a Slack incoming webhook. In that mode OreWatch sends a simple `text` payload.

---

## Distribution

The project now has two distinct distribution surfaces:

1. **The CLI and monitor code**
2. **The threat-data snapshots consumed by the monitor**

They should be distributed separately.

### Recommended Package Distribution

**Best default for developers:** publish the scanner as a normal Python package to PyPI and recommend installation with `pipx`.

Why this is the best fit:
- The project is a Python CLI and background monitor, so a universal wheel plus source distribution is the most direct release artifact.
- `pipx` gives developers an isolated, user-level install without polluting project virtualenvs.
- CI can still install the same version with `pip install orewatch==<version>`.
- This keeps the CLI upgrade path simple while leaving threat-data updates to the signed snapshot channel.

**Recommended release shape:**
- Publish `sdist` and universal wheel artifacts to PyPI.
- Expose the `orewatch` console entry point.
- Keep `ore-mal-pkg-inspector` as a temporary compatibility alias.
- Document `pipx install orewatch` for local developer installs.
- Document `pip install orewatch==<version>` for CI and pinned automation.

**Available secondary channel:** the Homebrew tap is now live for macOS users who prefer Brew-managed installs:

```bash
brew install rapticore/tap/orewatch
```

Homebrew remains a convenience layer over the published PyPI release, not the primary release artifact.

**Best option for contributors:** keep the current source-checkout flow:

```bash
git clone https://github.com/rapticore/ore-mal-pkg-inspector.git
cd ore-mal-pkg-inspector
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

### Managed macOS Rollout

If you are rolling OreWatch out with Kandji, Jamf Pro, Intune, Munki, or another macOS software-distribution system, the recommended model is different from the developer `pipx` path.

Current product reality:

- today the repo ships a Python package, not a first-party notarized macOS installer package
- for managed fleets, the recommended artifact is a signed flat `.pkg` built around the published OreWatch wheel
- threat-data snapshots should still be distributed separately from the app/runtime package

Recommended enterprise rollout model:

1. **Device install**
   - deploy a signed `.pkg` that installs the OreWatch runtime and a stable `orewatch` CLI shim
   - optionally include the `mac-menubar` extra if you want the native menu bar app on managed Macs
2. **User activation**
   - run `orewatch monitor quickstart /path/to/project --client <client>` or an equivalent user-context bootstrap
   - this step is separate because OreWatch’s monitor is intentionally **per-user** and uses a user LaunchAgent plus user-owned config/token/state
3. **Ongoing updates**
   - update the runtime package on your normal software lifecycle
   - update threat-data snapshots independently through the signed snapshot channel or live-update path

Why this split matters:

- MDM tools are good at installing code onto the machine
- OreWatch’s monitor, API token, and launchd service are user-scoped, so they should be created in the logged-in user context rather than forced from a machine-scope package install

Recommended package shape for managed macOS:

- a dedicated runtime under a stable path such as `/Library/Application Support/OreWatch/runtime`
- a stable shim such as `/usr/local/bin/orewatch`
- versioned package metadata so MDM platforms can detect upgrades cleanly
- code signing, and notarization where your fleet policy expects it

Vendor-specific guidance:

- **Kandji**
  - use a Custom App with an **Installer Package (`.pkg`)**
  - prefer `.pkg` over `.dmg` or `.zip` for OreWatch because the runtime is not a drag-and-drop app
  - use Self Service or a user-facing onboarding step for first-time monitor activation
- **Jamf Pro**
  - upload the `.pkg` as a Package and deploy it with a Policy or Self Service
  - keep user activation separate from the machine package deployment unless you have a deliberate user-context bootstrap step
- **Microsoft Intune**
  - use a macOS LOB app with a signed `.pkg`
  - Intune is stricter than the other channels: it expects a real `.pkg`, signed with a `Developer ID Installer` certificate, and the package must contain a payload
- **Munki**
  - publish the `.pkg` plus pkg metadata and treat OreWatch like other managed macOS software
  - Munki is a good fit when you want a package repo and optional Self Service style adoption
- **Other systems**
  - any package distribution system that can deploy a normal macOS flat package and optionally run a user bootstrap step can carry OreWatch

For a fuller rollout playbook, see [docs/managed-rollout.md](docs/managed-rollout.md).

### Recommended Snapshot Distribution

Threat-data snapshots should not be bundled inside the Python package. They change on a different cadence and are already supported as signed hosted artifacts.

**Open-source/community default:** consume `openssf` and `osv` directly through the anomaly-gated live-update path.
**Enterprise default:** publish versioned signed snapshots to static HTTPS hosting and let clients refresh them independently.

Recommended hosting targets:
- GitHub Releases assets
- S3 or Cloudflare R2 behind HTTPS
- Any static CDN-backed bucket that serves immutable versioned files

Recommended snapshot layout:
- `versions/<version>/manifest.json`
- `versions/<version>/*.db`
- `channels/stable.json`

Recommended trust model:
- Keep the private signing key offline
- Ship only the public verification key with the client config or package
- Verify every channel descriptor and manifest before download/apply

### Recommended Overall Model

For a production release, the cleanest setup is:
- Distribute the application as a PyPI package
- Install locally with `pipx`
- Install in CI with `pip`
- Distribute threat data as signed snapshot channels over HTTPS
- Treat source checkout as a development path, not the primary end-user install

---

## Logging & Debugging

By default, the scanner shows only warnings, errors, and the final summary. For troubleshooting or detailed progress tracking, use the logging flags:

### Verbose Mode

**See progress messages and collection statistics:**

```bash
orewatch /path/to/project --verbose
```

**Output includes:**
- Ecosystem detection results
- File parsing progress
- Package extraction counts
- Database query details
- IoC scanning progress

**Example:**

```
INFO: Detected ecosystems: npm, pypi
INFO: Loaded database for npm: 15234 malicious packages
INFO: Loaded database for pypi: 8421 malicious packages
INFO: Extracted 45 packages from 3 files
INFO: Checking 30 npm packages against database...
INFO: Checking 15 pypi packages against database...
INFO: IoC scan complete: 0 indicators found
```

### Debug Mode

**See detailed diagnostic information for troubleshooting:**

```bash
orewatch /path/to/project --debug
```

**Output includes:**
- All INFO level messages
- File paths being scanned
- SQL query execution details
- Hash calculations
- Pattern matching results
- Internal state information

**Use cases:**
- Investigating why a package wasn't detected
- Debugging ecosystem auto-detection issues
- Reporting issues with detailed context
- Auditing scanner behavior

### Logging for Collectors

The threat intelligence collectors also support verbose and debug modes:

```bash
cd collectors

# See collection progress
python3 orchestrator.py --verbose

# Debug data source issues
python3 orchestrator.py --debug
```

**Note:** All logs go to stderr, keeping stdout clean for JSON report output. This enables piping scanner results to other tools without log message interference.

---

## Output & Reports

### Report Structure

Reports are saved to the `scan-output/` directory by default (or a custom path with `--output`). OreWatch writes a machine-readable JSON report and a styled HTML companion report with the same basename. The JSON artifact includes threat-data availability metadata and uses SARIF-style `physicalLocation` objects for package findings, but it is not a full SARIF 2.1.0 document.

**Example report:**

```json
{
  "scan_timestamp": "2025-12-31T12:00:00Z",
  "ecosystem": "npm",
  "scanned_path": "/path/to/project",
  "total_packages_scanned": 150,
  "data_status": "complete",
  "sources_used": ["openssf", "osv"],
  "experimental_sources_used": [],
  "missing_ecosystems": [],
  "malicious_packages_found": 2,
  "iocs_found": 3,
  "malicious_packages": [
    {
      "name": "malicious-pkg",
      "version": "1.0.0",
      "severity": "critical",
      "sources": ["threat-intel-db", "research-community"],
      "description": "Malicious code executes unauthorized operations",
      "detected_behaviors": ["malicious_code", "data_exfiltration"]
    }
  ],
  "iocs": [
    {
      "type": "malicious_bundle_js",
      "path": "node_modules/suspect-pkg/bundle.js",
      "hash": "46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09",
      "severity": "CRITICAL",
      "variant": "original",
      "description": "Known malicious payload file from Shai-Hulud attack"
    },
    {
      "type": "malicious_postinstall",
      "path": "package.json",
      "pattern": "node bundle.js",
      "severity": "CRITICAL",
      "variant": "original",
      "description": "Malicious postinstall hook executes payload"
    }
  ]
}
```

**Threat data fields:**
- `data_status`: `complete`, `partial`, `failed`, or `not_applicable`
- `sources_used`: sources that contributed usable threat data for the requested ecosystems
- `experimental_sources_used`: experimental sources included in the scan data
- `missing_ecosystems`: requested ecosystems that had no usable package-threat database
- `promotion_decision`: empty for existing-data scans, otherwise `promoted`, `bootstrapped`, or `rejected`
- `kept_last_known_good`: `true` when a live candidate was rejected but the previous active dataset remained usable
- `anomalies`: warning/block anomalies raised during a live refresh attempt

### Understanding Results

**Severity Levels:**
- **CRITICAL:** Known malicious code with active exploits or data exfiltration
- **HIGH:** Strong indicators of malicious intent or typosquatting
- **MEDIUM:** Suspicious patterns or potential vulnerabilities
- **LOW:** Minor concerns or informational findings

**Recommended Actions:**
1. **Critical/High findings:** Immediately remove affected packages and investigate impact
2. **Review IoCs:** Check if malicious code has executed (logs, network activity)
3. **Update dependencies:** Replace malicious packages with legitimate alternatives
4. **Scan again:** Verify remediation with follow-up scan
5. **Report:** Consider reporting to package registry maintainers

---

## CI/CD Integration

### GitHub Actions

**Basic Security Scan:**

```yaml
name: Security Scan - Malicious Packages
on: [push, pull_request]

jobs:
  malicious-package-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.14'

      - name: Install OreWatch
        run: |
          git clone https://github.com/rapticore/ore-mal-pkg-inspector.git scanner
          cd scanner
          pip install .

      - name: Scan for malicious packages
        run: |
          cd scanner
          orewatch ${{ github.workspace }} --latest-data

      - name: Upload scan report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: security-scan-report
          path: scanner/scan-output/
```

**Advanced with Failure on Detection:**

```yaml
      - name: Scan and fail on malicious packages
        run: |
          cd scanner
          orewatch ${{ github.workspace }} --latest-data --output report.json

          # Check if malicious packages were found
          MALICIOUS_COUNT=$(jq '.malicious_packages_found' report.json)
          IOC_COUNT=$(jq '.iocs_found' report.json)

          if [ "$MALICIOUS_COUNT" -gt 0 ] || [ "$IOC_COUNT" -gt 0 ]; then
            echo "🚨 SECURITY ALERT: Malicious packages or IoCs detected!"
            echo "Malicious packages: $MALICIOUS_COUNT"
            echo "IoCs found: $IOC_COUNT"
            exit 1
          fi
```

### GitLab CI

```yaml
malicious-package-scan:
  image: python:3.14
  stage: security
  before_script:
    - git clone https://github.com/rapticore/ore-mal-pkg-inspector.git scanner
    - cd scanner && pip install .
  script:
    - orewatch $CI_PROJECT_DIR --latest-data --strict-data --output scan-report.json
  artifacts:
    paths:
      - scan-report.json
    when: always
  allow_failure: false
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any

    stages {
        stage('Setup Scanner') {
            steps {
                sh '''
                    git clone https://github.com/rapticore/ore-mal-pkg-inspector.git scanner
                    cd scanner
                    python3 -m pip install .
                '''
            }
        }

        stage('Security Scan') {
            steps {
                sh '''
                    cd scanner
                    orewatch ${WORKSPACE} --latest-data
                '''
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'scanner/scan-output/*.json', fingerprint: true
        }
    }
}
```

### Pre-commit Hook

Add to `.git/hooks/pre-commit`:

```bash
#!/bin/bash

echo "Running malicious package scan..."

cd /path/to/ore-mal-pkg-inspector
orewatch $PROJECT_DIR --no-summary

if [ $? -ne 0 ]; then
    echo "❌ Malicious packages or IoCs detected! Commit blocked."
    echo "Review the scan report in scan-output/"
    exit 1
fi

echo "✅ Security scan passed"
```

---

## Troubleshooting

### Common Issues

#### "Database not found" Error

**Symptom:**
```
ERROR: No usable threat data available for requested ecosystems: npm
```

**Cause:** Threat-data collection failed, metadata is incomplete, or the requested ecosystems do not have usable local databases yet.

**Solution:**
```bash
# Force recollection and require a complete result for the requested ecosystems
orewatch /path/to/project --latest-data --strict-data
```

**Note:** If this persists, check network connectivity, filesystem permissions, and whether you intentionally requested experimental sources.

#### "No packages detected" Warning

**Symptom:**
```
WARNING: No packages detected in /path/to/project
```

**Possible causes and solutions:**

1. **Wrong directory:** Ensure you're scanning the correct project directory
   ```bash
   ls /path/to/project  # Verify package.json or requirements.txt exists
   ```

2. **Unsupported or unexpected manifest:** Print the exact supported filenames
   ```bash
   orewatch --list-supported-files
   ```

3. **File permissions:** Ensure files are readable
   ```bash
   ls -la /path/to/project/package.json
   ```

#### Connection Errors During Update

**Symptom:**
```
ERROR: Error downloading npm: <urlopen error [Errno -3] Temporary failure in name resolution>
```

**Solutions:**

1. **Check internet connection:**
   ```bash
   ping google.com
   ```

2. **Retry with timeout increase:** Edit `collectors/config.yaml`:
   ```yaml
   osv:
     timeout: 600  # Increase from default 300
   ```

3. **Use cached data:** If you have previously downloaded data:
   ```bash
   python3 orchestrator.py --skip-build  # Skip download, rebuild from cache
   ```

#### Permission Denied Errors

**Symptom:**
```
ERROR: Error creating directory collectors/raw-data: Permission denied
```

**Solution:**
```bash
# Ensure proper ownership
sudo chown -R $USER:$USER /path/to/ore-mal-pkg-inspector

# Or run from user-writable location
cd ~/
git clone https://github.com/rapticore/ore-mal-pkg-inspector.git
cd ore-mal-pkg-inspector
```

#### False Positives

**Symptom:** Legitimate package flagged as malicious.

**Steps:**

1. **Verify the finding:** Review the report details including severity and description

2. **Check version:** The flagged version may be specific:
   ```bash
   orewatch /path/to/project --verbose
   ```

3. **Report false positive:** If confirmed incorrect:
   - Open issue at https://github.com/rapticore/ore-mal-pkg-inspector/issues with details

#### Debug Mode for Investigation

**Enable detailed logging:**

```bash
# Scanner debug mode
orewatch /path/to/project --debug 2> debug.log

# Collector debug mode
cd collectors
python3 orchestrator.py --debug 2> collector-debug.log
```

**Review logs:** Check `debug.log` for detailed execution trace including:
- File paths scanned
- SQL queries executed
- Pattern matching results
- Error stack traces

---

## FAQ

### How often should I update threat intelligence?

**Recommendation:**
- **Production/CI environments:** Daily automated updates
- **Development workstations:** Weekly updates minimum
- **After security news:** Immediate update when new threats are announced

Malicious packages are published continuously. Daily updates ensure the latest protections.

### How do I update the threat intelligence data?

Run the scanner with the `--latest-data` flag to force an update:

```bash
orewatch /path/to/project --latest-data
```

For automated updates in CI/CD, schedule periodic scans with `--latest-data` flag (e.g., daily). Add `--include-experimental-sources` only if you explicitly want Phylum-derived data included in the rebuild.

**Note:** First-time scans automatically collect data, so manual updates are only needed to refresh existing databases.

### Where does the threat data come from?

The default databases are built from the project’s **core threat sources**:
- `openssf`
- `osv`

The scanner can also include the project’s **experimental** source set:
- `phylum` with `--include-experimental-sources`

`socketdev` is present in the repository as a disabled placeholder and is not part of the default collection path.

For technical details about data sources, collection, and processing, see [ARCHITECTURE.md](ARCHITECTURE.md).

### Does this tool modify my code or dependencies?

**No.** OreWatch performs read-only operations. It:
- ✅ Reads dependency files
- ✅ Queries threat databases
- ✅ Scans for file patterns
- ✅ Generates reports

It **never**:
- ❌ Modifies package files
- ❌ Installs or removes packages
- ❌ Changes project configuration
- ❌ Executes package code

### What if my package is flagged as malicious?

**Steps to take:**

1. **Verify the finding:** Check the report for details and severity
2. **Review the evidence:** Examine the description and detected behaviors
3. **Check versions:** Determine if specific versions are affected
4. **If legitimate:**
   - Report false positive to data source maintainers
   - Open issue on our GitHub with details
5. **If truly malicious:**
   - Immediately remove the package
   - Review recent code commits for damage
   - Check logs for suspicious activity
   - Update to safe alternative

### Can I use this offline?

**Partially.**

**Offline scanning:** ✅ Yes, once databases are initialized
```bash
# Online: Initial setup (one-time - runs automatically on first scan)
orewatch /path/to/project

# Offline: Subsequent scans work with local databases
orewatch /path/to/project
```

**Offline updates:** ❌ No, threat intelligence collection requires internet access to fetch from security sources.

**Airgapped environments:** You can:
1. Download databases on an internet-connected machine
2. Transfer the SQLite files into the singleton `final_data_dir` shown by `orewatch monitor doctor`
3. Run scans offline with potentially outdated data

### How does this compare to npm audit or pip-audit?

**Different purposes:**

**npm audit / pip-audit:**
- Focus on known CVE vulnerabilities
- Check package versions against advisory databases
- Maintained by package registry teams

**OreWatch:**
- Focuses on malicious packages (not just vulnerable ones)
- Detects typosquatting, malware, supply chain attacks
- Cross-ecosystem coverage
- IoC detection for active threats

**Best practice:** Use **both**:
```bash
# Check for vulnerabilities
npm audit
pip-audit

# Check for malicious packages
orewatch /path/to/project
```

### Does this work with private package registries?

**Dependency scanning:** ✅ Yes, the scanner reads your dependency files regardless of where packages come from.

**Threat intelligence:** ⚠️ Limited. Our databases cover public registries (npmjs.com, pypi.org, etc.). Malicious packages on private registries won't be detected unless you add custom threat data.

**Custom threat data:** You can extend the databases with your own malicious package lists. Contact us for guidance on this advanced use case.

### What's the performance impact?

**Scan time:**
- **Small projects** (< 50 packages): < 5 seconds
- **Medium projects** (50-500 packages): 5-30 seconds
- **Large projects** (500+ packages): 30-120 seconds

**Factors:**
- IoC scanning adds 10-50% overhead (disable with `--no-ioc` if not needed)
- First run may be slower as databases load into memory

**Optimization tips:**
```bash

# Scan specific files instead of entire directory
orewatch --file package.json
```

---

## Contributing

We welcome contributions! Whether you're reporting bugs, suggesting features, or contributing code, your help improves OreWatch for everyone.

**Report bugs or request features:**
- GitHub Issues: https://github.com/rapticore/ore-mal-pkg-inspector/issues

**Contribute code:**
- See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines on development setup, code style, testing, and pull request process

**Questions or discussions:**
- GitHub Discussions: https://github.com/rapticore/ore-mal-pkg-inspector/discussions

---

## Security Policy

Security is our top priority. OreWatch is a security tool, and we take vulnerabilities seriously.

### Reporting Security Vulnerabilities

**Do NOT open public GitHub issues for security vulnerabilities.**

Instead, report privately:

**Email:** security@rapticore.com

**Include:**
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if applicable)
- Your contact information for follow-up

### Response Timeline

- **Acknowledgment:** Within 48 hours
- **Initial assessment:** Within 7 days
- **Fix timeline:** Varies by severity
  - Critical: 7-14 days
  - High: 14-30 days
  - Medium/Low: 30-60 days

### Security Best Practices

When using OreWatch:

**Do:**
- ✅ Run with least privilege (no root/admin required)
- ✅ Update threat intelligence regularly
- ✅ Review scan reports promptly
- ✅ Integrate into CI/CD for continuous protection
- ✅ Keep the tool updated to the latest version

**Don't:**
- ❌ Ignore scan findings without investigation
- ❌ Disable IoC scanning in production environments
- ❌ Share database files from untrusted sources
- ❌ Run with elevated privileges unnecessarily

### Vulnerability Disclosure

We follow coordinated disclosure:
1. Vulnerability reported privately
2. Fix developed and tested
3. Security advisory published
4. Public disclosure after fix is available

### Security Hall of Fame

We recognize security researchers who responsibly disclose vulnerabilities:

*List will be maintained as reports are received*

---

### Community Requests

Vote on or suggest features:
- **GitHub Discussions:** https://github.com/rapticore/ore-mal-pkg-inspector/discussions
- **Feature Requests:** https://github.com/rapticore/ore-mal-pkg-inspector/issues

### Contributing to Roadmap

We prioritize features based on:
- Security impact
- Community demand
- Maintenance sustainability
- Alignment with project goals

To influence the roadmap:
1. Open a feature request with detailed use case
2. Participate in discussions
3. Contribute implementations (PRs welcome!)

---

## Roadmap

OreWatch is usable today for:

- local CLI scans across npm, PyPI, Maven, RubyGems, Go, and Cargo
- one per-user background monitor for many projects
- MCP integrations for Cursor, Claude Code, and Codex
- localhost API integrations for VS Code, JetBrains / PyCharm, and Xcode helpers
- macOS menu bar review and popup notifications

Near-term priorities:

- first-party VS Code and JetBrains / PyCharm integration examples or thin plugins
- stronger user-facing notification workflows beyond local popups
- clearer project policy management from CLI and UI
- richer monitor reporting and adoption docs

Mid-term priorities:

- broader project-scan workflows from the monitor and MCP surface
- better organization-level rollout guidance
- more robust external alert delivery and escalation channels
- deeper IDE-specific UX instead of API-only integration guidance

Known current boundary:

- Xcode integration is currently best for alert visibility and mixed-language repositories. OreWatch does not yet parse native Apple manifests such as `Package.resolved`, `Podfile.lock`, or `Cartfile`.

Longer-term direction:

- native Apple ecosystem manifest support
- stronger first-party editor integrations
- broader operating-system UX parity beyond the current macOS menu bar path

See [docs/roadmap.md](docs/roadmap.md) for the more adoption-focused roadmap view.

---

## License

MIT License

Copyright (c) 2025 Rapticore

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---

## Support

### Getting Help

**Documentation:** You're reading it! Start here for most questions.

**GitHub Discussions:** For questions, ideas, and community interaction:
- https://github.com/rapticore/ore-mal-pkg-inspector/discussions

**GitHub Issues:** For bug reports and feature requests:
- https://github.com/rapticore/ore-mal-pkg-inspector/issues

**Email:** For security vulnerabilities and private inquiries:
- contact@rapticore.com

### Professional Support

For organizations requiring:
- Custom integrations
- SLA-backed support
- Private deployment assistance
- Custom threat intelligence feeds

Contact: contact@rapticore.com

---

## Acknowledgments

### Project Origin

This project was extracted from the [OreNPMGuard](https://github.com/rapticore/OreNPMGuard) repository to maintain clear project focus while expanding capabilities.

**OreNPMGuard** (December 2025) specializes in Shai-Hulud npm attack detection with 738+ affected packages and deep IoC analysis. During its development, we recognized the need for broader multi-ecosystem protection, leading to the creation of OreWatch as a standalone tool serving the wider developer community across all major package ecosystems.


### Related Projects

- **[OreNPMGuard](https://github.com/rapticore/OreNPMGuard)** - Specialized Shai-Hulud npm scanner
---

**Built by Rapticore Security Research Team**

*Protecting software supply chains, one scan at a time.*
