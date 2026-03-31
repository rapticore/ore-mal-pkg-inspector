# OreWatch

**Multi-Ecosystem Malicious Package Detection and Supply Chain Security Scanner**

![Python Version](https://img.shields.io/badge/python-3.14-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-active-success.svg)
![Ecosystems](https://img.shields.io/badge/ecosystems-6-orange.svg)

A production-grade security tool for detecting malicious packages and supply chain threats across npm, PyPI, Maven, RubyGems, Go, and Cargo ecosystems. Leverages automated threat intelligence collection from trusted security sources to identify compromised dependencies in your projects.

`OreWatch` is the product and PyPI package name. The current source repository path still uses `ore-mal-pkg-inspector`.

---

## Table of Contents

- [The Problem](#the-problem)
- [The Solution](#the-solution)
- [Key Features](#key-features)
- [Why OreWatch?](#why-orewatch)
- [Quick Start](#quick-start)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [First Scan](#first-scan)
- [Usage](#usage)
  - [Basic Commands](#basic-commands)
  - [Advanced Usage](#advanced-usage)
  - [Command-Line Reference](#command-line-reference)
  - [Background Monitoring](#background-monitoring)
- [Distribution](#distribution)
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

## Quick Start

### Prerequisites

- **Python 3.14 or higher**
- **pip** for installing dependencies
- **Git** for cloning the repository
- **Internet connection** for initial threat intelligence setup
- **OpenSSL** for signed snapshot key generation, publishing, and verification in monitor snapshot workflows

### Installation

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

_Note: Threat intelligence data is collected automatically on first scan. Core sources are enabled by default; experimental sources are opt-in._

_Note: The commands above install the project from a source checkout. This is the current development and contributor path. See [Distribution](#distribution) for the recommended release model for end users and CI._

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

Full report saved to: scan-output/malicious_packages_report_20251231_120000.json
============================================================
```

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
# Force a full refresh of the default core sources before scanning
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
| `--output` | `-o` | Custom output path for JSON report | `scan-output/malicious_packages_report_{timestamp}.json` |
| `--no-summary` | | Skip printing report summary to console | False |
| `--no-ioc` | | Skip IoC (Indicators of Compromise) scanning | False |
| `--ioc-only` | | Only scan for IoCs, skip package checking | False |
| `--latest-data` | | Force recollection and rebuild of threat intelligence before scanning | False |
| `--strict-data` | | Fail if any requested ecosystem has partial or missing threat data | False |
| `--include-experimental-sources` | | Include experimental collectors during threat-data refresh | False |
| `--list-supported-files` | | Print the exact supported dependency manifest filenames and exit | False |
| `--verbose` | `-v` | Show INFO level logs (progress messages) | False |
| `--debug` | | Show DEBUG level logs (detailed diagnostics) | False |

### Background Monitoring

The repository now includes a local background monitor that runs inside the repo under `.ore-monitor/`. It keeps threat data fresh, watches opted-in projects for manifest and workflow changes, runs debounced scans, and records notifications for new or escalated findings.

**Initialize and inspect the monitor:**

```bash
orewatch monitor install
orewatch monitor install --service-manager launchd --no-start
orewatch monitor status
orewatch monitor doctor
```

**Manage watched projects:**

```bash
orewatch monitor watch add /path/to/project
orewatch monitor watch list
orewatch monitor watch remove /path/to/project
```

**Run the service:**

```bash
# Background
orewatch monitor start
orewatch monitor restart
orewatch monitor stop
orewatch monitor uninstall

# Foreground
orewatch monitor run
```

**Manual monitor actions:**

```bash
# Trigger immediate scans for all watched projects
orewatch monitor scan-now

# Trigger one watched project only
orewatch monitor scan-now /path/to/project

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
- New state is stored in `.ore-monitor/state.db`, reports in `.ore-monitor/reports/`, and service templates in `.ore-monitor/services/`.
- Per-project policy overrides can be stored in `.ore-monitor.yml` at the project root.
- `monitor install` now installs a user-level `launchd` or `systemd` service when available, and falls back to the repo-local background mode otherwise.
- Hosted updates use a signed channel descriptor or manifest configured under `.ore-monitor/config.yaml` in `snapshots.channel_url` or `snapshots.manifest_url`, and the monitor verifies them with `snapshots.public_key_path`.
- Signed snapshot workflows currently require `openssl` on the local machine.

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

**Recommended secondary channel:** add a Homebrew formula only after the PyPI package and console entry point are stable. Homebrew is a convenience layer, not the primary release artifact.

**Best option for contributors:** keep the current source-checkout flow:

```bash
git clone https://github.com/rapticore/ore-mal-pkg-inspector.git
cd ore-mal-pkg-inspector
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

### Recommended Snapshot Distribution

Threat-data snapshots should not be bundled inside the Python package. They change on a different cadence and are already supported as signed hosted artifacts.

**Best default:** publish versioned signed snapshots to static HTTPS hosting and let clients refresh them independently.

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

Reports are saved to the `scan-output/` directory by default (or a custom path with `--output`). The default report format is project-specific JSON. It includes threat-data availability metadata and uses SARIF-style `physicalLocation` objects for package findings, but it is not a full SARIF 2.1.0 document.

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
2. Transfer `collectors/final-data/*.db` files to airgapped environment
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

**Built with ❤️ for the open source community**

*Protecting software supply chains, one scan at a time.*
