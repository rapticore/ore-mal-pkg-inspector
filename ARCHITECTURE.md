# ore-mal-pkg-inspector - Technical Architecture

This document provides technical implementation details for developers and contributors who need to understand how ore-mal-pkg-inspector works internally.

**For end users**: See [README.md](README.md) for usage instructions.
**For contributors**: See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.

## Table of Contents

- [Overview](#overview)
- [Directory Structure](#directory-structure)
- [Scanning Flow](#scanning-flow)
- [Automatic Data Collection](#automatic-data-collection)
- [Database Schema](#database-schema)
- [Threat Intelligence Pipeline](#threat-intelligence-pipeline)
- [Data Sources](#data-sources)
- [Supported Ecosystems](#supported-ecosystems)
- [Collector Configuration](#collector-configuration)
- [Module Descriptions](#module-descriptions)

---

## Overview

ore-mal-pkg-inspector is a multi-ecosystem malicious package scanner built with Python 3.9+. It uses SQLite databases for threat intelligence storage, supports six package ecosystems, and provides SARIF-compliant JSON reports.

**Core Components:**
1. **Scanner**: Detects ecosystems, parses dependency files, checks against databases
2. **Collectors**: Fetch threat intelligence from various sources
3. **Database Builder**: Merges raw data into unified per-ecosystem SQLite databases
4. **Report Generator**: Creates JSON reports with findings

---

## Directory Structure

```
ore-mal-pkg-inspector/
├── malicious_package_scanner.py    # Main scanner entry point
├── logging_config.py                # Centralized logging configuration
│
├── collectors/                       # Threat intelligence collection
│   ├── orchestrator.py              # Automated collection workflow
│   ├── collect_openssf.py           # OpenSSF malicious-packages collector
│   ├── collect_osv.py               # OSV.dev bulk download collector
│   ├── collect_phylum.py            # Phylum blog scraper
│   ├── collect_socketdev.py         # Socket.dev API collector (placeholder)
│   ├── build_unified_index.py       # Merge raw data into SQLite databases
│   ├── db.py                        # Database operations and schema
│   ├── utils.py                     # Shared utility functions
│   ├── config.yaml                  # Data source configuration
│   │
│   ├── .cache/                      # Downloaded source data (gitignored)
│   │   └── openssf-malicious-packages/  # Git clone of OpenSSF repo
│   │
│   ├── raw-data/                    # Collected JSON data
│   │   ├── openssf.json             # ~220k packages from OpenSSF
│   │   ├── osv.json                 # MAL- prefixed entries from OSV.dev
│   │   ├── phylum.json              # Scraped from Phylum blog
│   │   └── socketdev.json           # Socket.dev data (if configured)
│   │
│   └── final-data/                  # Unified SQLite databases
│       ├── unified_npm.db           # npm malicious packages
│       ├── unified_pypi.db          # PyPI malicious packages
│       ├── unified_rubygems.db      # RubyGems malicious packages
│       ├── unified_go.db            # Go malicious packages
│       ├── unified_maven.db         # Maven malicious packages
│       └── unified_cargo.db         # Cargo malicious packages
│
├── scanners/                         # Scanning modules
│   ├── ecosystem_detector.py        # Auto-detect ecosystems from project
│   ├── dependency_parsers.py        # Parse dependency files
│   ├── file_input_parser.py         # Generic file format parser
│   ├── malicious_checker.py         # Check packages against databases
│   ├── ioc_detector.py              # IoC pattern detection
│   └── report_generator.py          # JSON/SARIF report generation
│
├── scan-output/                      # Generated scan reports (gitignored)
│   └── malicious_packages_report_YYYYMMDD_HHMMSS.json
│
├── requirements.txt                  # Python dependencies
├── README.md                         # User documentation
├── CONTRIBUTING.md                   # Contribution guidelines
├── ARCHITECTURE.md                   # This file
└── LICENSE                           # MIT License
```

---

## Scanning Flow

The scanner follows a six-stage pipeline:

```
┌─────────────────────────────────────────────────────────────┐
│ 1. Input Processing                                         │
│    • Parse command-line arguments (path, --file, --ecosystem)│
│    • Validate inputs and determine scan mode               │
│    • Initialize logging based on --verbose/--debug         │
└────────────────────┬────────────────────────────────────────┘
                     ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. Ecosystem Detection                                      │
│    Module: scanners/ecosystem_detector.py                  │
│    • Scan directory for dependency files                    │
│    • Match files against ecosystem patterns                │
│    • Identify ecosystems (npm, pypi, maven, etc.)           │
│    • Support multi-ecosystem projects                       │
└────────────────────┬────────────────────────────────────────┘
                     ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. Dependency Parsing                                       │
│    Module: scanners/dependency_parsers.py                  │
│    • Parse package.json, requirements.txt, pom.xml, etc.    │
│    • Extract package names and versions                     │
│    • Handle generic formats (text, JSON, YAML)              │
│    • Deduplicate packages across multiple files             │
└────────────────────┬────────────────────────────────────────┘
                     ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. Malicious Package Check                                  │
│    Module: scanners/malicious_checker.py                   │
│    • Load unified SQLite databases (collectors/final-data/) │
│    • Query packages against threat intelligence             │
│    • Cross-reference with Shai-Hulud list (npm only)        │
│    • Aggregate findings from multiple sources               │
└────────────────────┬────────────────────────────────────────┘
                     ▼
┌─────────────────────────────────────────────────────────────┐
│ 5. IoC Detection (Optional, skip with --no-ioc)            │
│    Module: scanners/ioc_detector.py                        │
│    • Scan for malicious file patterns (bundle.js, etc.)     │
│    • Check for suspicious hooks (postinstall, preinstall)   │
│    • Detect known payload hashes (SHA-256)                  │
│    • Identify malicious workflows (.github/workflows/)      │
│    • Detect Shai-Hulud original & 2.0 variants              │
└────────────────────┬────────────────────────────────────────┘
                     ▼
┌─────────────────────────────────────────────────────────────┐
│ 6. Report Generation                                        │
│    Module: scanners/report_generator.py                    │
│    • Build SARIF-compatible JSON report                     │
│    • Include malicious packages with metadata               │
│    • Include IoCs with severity and descriptions            │
│    • Print console summary (unless --no-summary)            │
│    • Save to scan-output/ directory (or custom --output)    │
└─────────────────────────────────────────────────────────────┘
```

**Execution Path Examples:**

```python
# Directory scan with auto-detection
1. Input: /path/to/project
2. Detect: Find package.json, requirements.txt → [npm, pypi]
3. Parse: Extract 30 npm packages, 15 pypi packages
4. Check: Query unified_npm.db, unified_pypi.db
5. IoC: Scan project directory for indicators
6. Report: Generate JSON report with findings

# File scan with explicit ecosystem
1. Input: --file requirements.txt --ecosystem pypi
2. Detect: Skipped (ecosystem forced)
3. Parse: Extract packages from requirements.txt
4. Check: Query unified_pypi.db
5. IoC: Skipped (no directory context)
6. Report: Generate JSON report
```

---

## Automatic Data Collection

The scanner automatically ensures threat intelligence databases exist before scanning, eliminating manual setup steps for end users.

### Overview

On each scan execution, the scanner checks for threat intelligence databases and automatically collects data if missing. This provides a seamless out-of-box experience while allowing users to force updates when needed.

### Implementation

**Entry point**: `ensure_threat_data()` in `malicious_package_scanner.py` (line ~223)

Called at the start of `main()` after logging setup:
```python
def main():
    # ... argument parsing ...
    setup_logging(args.verbose, args.debug)

    # Ensure threat intelligence databases exist
    ensure_threat_data(force_update=args.latest_data)

    # ... continue with scanning ...
```

**Collection logic**:
1. Checks if databases exist using `orchestrator.check_databases_exist()`
2. If `--latest-data` flag set: Forces collection regardless of existing databases
3. If databases missing: Automatically triggers collection with progress messages
4. If databases exist: Skips collection, proceeds directly to scanning

**Progress feedback**:
- First run (databases missing): Shows "Collecting data... (first run only)" message
- Force update (`--latest-data`): Shows "Collecting latest threat intelligence..." message
- Existing databases: Silent (< 1ms overhead), logs debug message only

### Execution Flow

```
Scanner main()
  ↓
Parse arguments (--latest-data flag)
  ↓
Setup logging
  ↓
ensure_threat_data(force_update=args.latest_data)
  ↓
Check: databases exist?
  ├─ Yes → Return immediately (< 1ms)
  └─ No  → Collect data (6-11 minutes)
       ↓
  orchestrator.collect_all_data(build_if_missing=True)
       ↓
  Show progress messages
       ↓
  Return success/failure
  ↓
Continue with scan
```

### Error Handling

**Graceful degradation**:
- If collection succeeds: Scan proceeds with fresh data
- If collection fails: Shows warning, scan proceeds with old/missing data
- Scanner never aborts due to collection failure

**Failure scenarios**:
1. **Network error**: Cannot fetch threat data → Warns, continues with cached databases
2. **No cached databases + failure**: Scan completes but finds no malicious packages
3. **Partial failure**: Some collectors succeed → Uses available data, warns about failures
4. **Permission error**: Cannot write databases → Error message with diagnostic info

### Database Locations

**Databases stored in**: `collectors/final-data/unified_*.db`

| Ecosystem | Database File | Typical Size |
|-----------|--------------|--------------|
| npm | `unified_npm.db` | 291 MB (~220k packages) |
| pypi | `unified_pypi.db` | 16 MB |
| rubygems | `unified_rubygems.db` | 1.2 MB |
| go | `unified_go.db` | 68 KB |
| cargo | `unified_cargo.db` | 60 KB |
| maven | `unified_maven.db` | 60 KB |

**Detection logic**: `check_databases_exist()` returns `True` if ANY database file exists.

### User-Facing Behavior

**First-time user (no databases)**:
```bash
$ python3 malicious_package_scanner.py /path/to/project

============================================================
Threat intelligence databases not found.
Collecting data from security sources...
This may take 10-15 minutes (first run only).
============================================================

Fetching from security sources...
[orchestrator progress messages]

✓ Threat data collection completed successfully
============================================================

Scanning project...
[scan results]
```

**Existing user (databases present)**:
```bash
$ python3 malicious_package_scanner.py /path/to/project

Scanning project...
[scan results - no collection delay]
```

**Force update**:
```bash
$ python3 malicious_package_scanner.py /path/to/project --latest-data

============================================================
Collecting latest threat intelligence data...
This may take 10-15 minutes depending on network speed.
============================================================
[collection + scan]
```

### Performance Impact

**Database existence check**: < 1ms (file stat operations only)

**First run**:
- Before: User manually runs collectors (~6-11 min) + scan (~30 sec)
- After: Scanner auto-runs collectors + scan (~6-11 min total)
- **Impact**: Same total time, better UX (one command)

**Subsequent runs**:
- Before: Scan only (~30 sec)
- After: Check + scan (~30 sec + 1ms)
- **Impact**: Negligible (~1ms overhead)

**With --latest-data**:
- Forces 6-11 minute collection before each scan
- Recommended for: Daily CI/CD runs, after security advisories
- Not recommended for: Pre-commit hooks, rapid iteration

### Design Rationale

**Why check on every scan?**
- Ensures databases exist even if manually deleted
- No user confusion about "database not found" errors
- < 1ms overhead is negligible

**Why --latest-data instead of auto-update?**
- Predictable performance (users control when updates happen)
- Avoids surprise 10-minute delays mid-development
- Explicit control for CI/CD scheduling

**Why graceful degradation on failure?**
- Network issues shouldn't block security scanning
- Better to scan with stale data than not scan at all
- User receives warning but workflow continues

---

## Database Schema

Each unified ecosystem database (`unified_npm.db`, `unified_pypi.db`, etc.) uses the same schema:

### `packages` Table

```sql
CREATE TABLE packages (
    name TEXT PRIMARY KEY,
    versions TEXT,              -- JSON array: ["1.0.0", "1.2.3"]
    severity TEXT,              -- "critical", "high", "medium", "low"
    sources TEXT,               -- JSON array: ["openssf", "osv", "shai-hulud"]
    vuln_ids TEXT,              -- JSON array: ["MAL-2025-1234", "GHSA-xxxx"]
    description TEXT,           -- Human-readable description
    detected_behaviors TEXT,    -- JSON array: ["malicious_code", "data_exfiltration"]
    first_seen TEXT,            -- ISO 8601 date: "2025-01-15"
    last_updated TEXT           -- ISO 8601 timestamp: "2025-12-31T12:00:00Z"
)
```

**Indexes:**
```sql
CREATE INDEX idx_severity ON packages(severity);
CREATE INDEX idx_name ON packages(name);
```

**Example Row:**

| name | versions | severity | sources | vuln_ids | description | detected_behaviors | first_seen | last_updated |
|------|----------|----------|---------|----------|-------------|--------------------|------------|--------------|
| malicious-pkg | ["1.0.0", "1.0.1"] | critical | ["openssf", "osv"] | ["MAL-2025-1234"] | Malicious code detected | ["malicious_code"] | 2025-01-15 | 2025-12-31T10:00:00Z |

**JSON Field Formats:**

```python
# versions
["1.0.0", "1.2.3", "*"]  # "*" means all versions

# sources
["openssf", "osv", "phylum", "shai-hulud"]

# vuln_ids
["MAL-2025-1234", "GHSA-xxxx-xxxx-xxxx", "SNYK-JS-PKG-1234567"]

# detected_behaviors
["malicious_code", "data_exfiltration", "cryptomining", "backdoor"]
```

---

## Threat Intelligence Pipeline

The threat intelligence collection and database building process:

```
┌─────────────────────────────────────────────────────────────┐
│ COLLECTION PHASE                                            │
└─────────────────────────────────────────────────────────────┘

Sources                      collectors/*.py          Raw Data
┌──────────────────┐       ┌────────────────┐      ┌──────────────┐
│ OpenSSF Repo     │──────▶│ collect_       │─────▶│ openssf.json │
│ (git clone)      │       │ openssf.py     │      │ ~220k pkgs   │
└──────────────────┘       └────────────────┘      └──────────────┘

┌──────────────────┐       ┌────────────────┐      ┌──────────────┐
│ OSV.dev          │──────▶│ collect_       │─────▶│ osv.json     │
│ (bulk download)  │       │ osv.py         │      │ MAL- entries │
└──────────────────┘       └────────────────┘      └──────────────┘

┌──────────────────┐       ┌────────────────┐      ┌──────────────┐
│ Phylum Blog      │──────▶│ collect_       │─────▶│ phylum.json  │
│ (RSS scraping)   │       │ phylum.py      │      │ Blog posts   │
└──────────────────┘       └────────────────┘      └──────────────┘

┌──────────────────┐       ┌────────────────┐      ┌──────────────┐
│ Socket.dev API   │──────▶│ collect_       │─────▶│ socketdev.   │
│ (if configured)  │       │ socketdev.py   │      │ json         │
└──────────────────┘       └────────────────┘      └──────────────┘

                            collectors/raw-data/

┌─────────────────────────────────────────────────────────────┐
│ MERGE & BUILD PHASE                                         │
└─────────────────────────────────────────────────────────────┘

Raw Data                build_unified_index.py      Databases
┌──────────────┐       ┌────────────────────┐      ┌────────────────┐
│ openssf.json │──┐    │ 1. Load all raw    │      │ unified_npm.db │
│ osv.json     │──┼───▶│    JSON files      │─────▶│ unified_pypi   │
│ phylum.json  │──┤    │ 2. Group by        │      │ unified_go     │
│ socketdev... │──┘    │    ecosystem       │      │ unified_rubygems
└──────────────┘       │ 3. Deduplicate     │      │ unified_maven  │
                       │ 4. Build SQLite    │      │ unified_cargo  │
                       └────────────────────┘      └────────────────┘

                                                collectors/final-data/
```

**Deduplication Logic:**

When multiple sources report the same package:
- **Merge versions**: Union of all reported versions
- **Highest severity**: Take the most severe rating
- **Combine sources**: Array of all source names
- **Combine vuln_ids**: Array of all vulnerability IDs
- **Latest timestamp**: Use most recent last_updated

**Example:**

```python
# Source 1 (OpenSSF):
{
  "name": "evil-pkg",
  "versions": ["1.0.0"],
  "severity": "high",
  "sources": ["openssf"],
  "vuln_ids": ["GHSA-1234"]
}

# Source 2 (OSV):
{
  "name": "evil-pkg",
  "versions": ["1.0.0", "1.0.1"],
  "severity": "critical",
  "sources": ["osv"],
  "vuln_ids": ["MAL-2025-5678"]
}

# Merged result in database:
{
  "name": "evil-pkg",
  "versions": ["1.0.0", "1.0.1"],  # Union
  "severity": "critical",           # Highest
  "sources": ["openssf", "osv"],    # Combined
  "vuln_ids": ["GHSA-1234", "MAL-2025-5678"]  # Combined
}
```

---

## Data Sources

Detailed information about each threat intelligence source:

### OpenSSF Malicious Packages

**Source**: https://github.com/ossf/malicious-packages

**Method**: Git clone repository

**Coverage**:
- ~220,000 malicious packages across multiple ecosystems
- npm, PyPI, RubyGems, Go, Maven, Cargo, NuGet

**Data Format**: OSV (Open Source Vulnerability) JSON format

**Update Frequency**: Daily (repository updated continuously)

**Reliability**: ✅ Production - Highly reliable, authoritative source

**Collector**: `collectors/collect_openssf.py`

**Sample Data Structure**:
```json
{
  "id": "MAL-2025-1234",
  "summary": "Malicious package with data exfiltration",
  "details": "Full description...",
  "affected": [{
    "package": {"ecosystem": "npm", "name": "evil-pkg"},
    "versions": ["1.0.0", "1.0.1"]
  }]
}
```

---

### OSV.dev

**Source**: https://osv-vulnerabilities.storage.googleapis.com

**Method**: Bulk download ZIP files per ecosystem

**Coverage**:
- All MAL- prefixed entries (malware indicators)
- npm, PyPI, Go, RubyGems, Maven, Cargo, NuGet

**Data Format**: OSV JSON format

**Update Frequency**: Daily (updated by Google OSV team)

**Reliability**: ✅ Production - Comprehensive, well-maintained

**Collector**: `collectors/collect_osv.py`

**Processing**:
- Downloads `{ecosystem}/all.zip` for each ecosystem
- Extracts JSON files
- Filters for entries with `id` starting with "MAL-"
- Parses affected packages, versions, CWEs, origins

**Sample Data**:
```json
{
  "id": "MAL-2025-5678",
  "summary": "Typosquatting attack",
  "affected": [{
    "package": {"ecosystem": "PyPI", "name": "reqeusts"},
    "versions": ["1.0.0"]
  }],
  "database_specific": {
    "cwes": [{"cweId": "CWE-506", "name": "Embedded Malicious Code"}]
  }
}
```

---

### Phylum.io Blog

**Source**: https://blog.phylum.io/feed/

**Method**: RSS feed scraping with regex extraction

**Coverage**:
- Limited (blog posts only)
- High-quality research findings
- Primarily npm and PyPI

**Data Format**: Custom extraction from blog content

**Update Frequency**: Weekly (as new blog posts published)

**Reliability**: ⚠️ Limited - Basic implementation, may have false positives

**Collector**: `collectors/collect_phylum.py`

**Extraction Method**:
- Fetch RSS feed XML
- Extract package names using regex patterns:
  - npm: `(@?[a-z0-9-_]+(?:/[a-z0-9-_]+)?)`
  - PyPI: `PyPI.*?([a-z0-9-_]+)`
- Create package records from mentions

**Limitations**:
- Simple regex may capture non-malicious package names
- No version information from blog posts
- Requires manual verification of findings

---

### Socket.dev

**Source**: https://api.socket.dev (API key required)

**Method**: API queries (placeholder implementation)

**Coverage**: N/A (not fully integrated)

**Data Format**: JSON API responses

**Update Frequency**: N/A

**Reliability**: ⏳ Placeholder - Requires API key, not operational

**Collector**: `collectors/collect_socketdev.py`

**Status**: Socket.dev does not provide a public API for bulk package queries. The collector is a placeholder that returns empty results with a note. Consider using their npm package scanner or web interface for individual package analysis.

---

### Shai-Hulud List (npm only)

**Source**: OreNPMGuard research (local configuration)

**Method**: Local JSON file (`shai-hulud-config.json`)

**Coverage**:
- 738+ npm packages affected by Shai-Hulud attacks
- Original (September 2025) and 2.0 (November 2025) variants

**Data Format**: Custom JSON configuration

**Update Frequency**: As needed when new Shai-Hulud packages discovered

**Reliability**: ✅ Production - Curated list from OreNPMGuard project

**Loader**: `scanners/malicious_checker.py`

**Sample Structure**:
```json
{
  "affected_packages": [
    "malicious-pkg-name",
    "@scope/another-pkg"
  ]
}
```

---

## Supported Ecosystems

Technical details for each supported package ecosystem:

### npm (Node.js / JavaScript)

**Dependency Files**:
- `package.json` - Primary dependency manifest
- `package-lock.json` - Locked dependency versions
- `yarn.lock` - Yarn package manager lockfile
- `npm-shrinkwrap.json` - npm lockfile for publishing

**Parser**: `scanners/dependency_parsers.py::parse_npm_file()`

**Detection Pattern**: `scanners/ecosystem_detector.py`

**Parsing Logic**:
```python
# Extract from package.json
{
  "dependencies": {"pkg": "^1.0.0"},
  "devDependencies": {"test-pkg": "^2.0.0"}
}
# Returns: [{"name": "pkg", "version": "^1.0.0"}, ...]
```

**Database**: `collectors/final-data/unified_npm.db`

**Special Features**:
- Shai-Hulud IoC detection
- Cross-reference with shai-hulud-config.json

---

### PyPI (Python)

**Dependency Files**:
- `requirements.txt` - pip requirements format
- `Pipfile` - Pipenv dependency file
- `pyproject.toml` - Modern Python project metadata (PEP 518)
- `setup.py` - setuptools configuration

**Parser**: `scanners/dependency_parsers.py::parse_pypi_file()`

**Detection Pattern**: `scanners/ecosystem_detector.py`

**Parsing Logic**:
```python
# requirements.txt
package-name==1.0.0
another-pkg>=2.0.0

# Returns: [{"name": "package-name", "version": "1.0.0"}, ...]
```

**Database**: `collectors/final-data/unified_pypi.db`

---

### Maven (Java)

**Dependency Files**:
- `pom.xml` - Maven project object model

**Parser**: `scanners/dependency_parsers.py::parse_maven_file()`

**Detection Pattern**: `scanners/ecosystem_detector.py`

**Parsing Logic**:
```xml
<dependency>
  <groupId>org.example</groupId>
  <artifactId>package-name</artifactId>
  <version>1.0.0</version>
</dependency>
```

**Package Name Format**: `groupId:artifactId` (e.g., `org.example:package-name`)

**Database**: `collectors/final-data/unified_maven.db`

---

### RubyGems (Ruby)

**Dependency Files**:
- `Gemfile` - Bundler dependency specification
- `Gemfile.lock` - Locked gem versions

**Parser**: `scanners/dependency_parsers.py::parse_rubygems_file()`

**Detection Pattern**: `scanners/ecosystem_detector.py`

**Parsing Logic**:
```ruby
# Gemfile
gem 'rails', '~> 7.0.0'
gem 'puma'

# Returns: [{"name": "rails", "version": "~> 7.0.0"}, ...]
```

**Database**: `collectors/final-data/unified_rubygems.db`

---

### Go

**Dependency Files**:
- `go.mod` - Go module definition
- `go.sum` - Go module checksums

**Parser**: `scanners/dependency_parsers.py::parse_go_file()`

**Detection Pattern**: `scanners/ecosystem_detector.py`

**Parsing Logic**:
```go
// go.mod
require (
    github.com/pkg/errors v0.9.1
    golang.org/x/text v0.3.7
)
```

**Package Name Format**: Full module path (e.g., `github.com/pkg/errors`)

**Database**: `collectors/final-data/unified_go.db`

---

### Cargo (Rust)

**Dependency Files**:
- `Cargo.toml` - Cargo package manifest
- `Cargo.lock` - Locked dependency versions

**Parser**: `scanners/dependency_parsers.py::parse_cargo_file()`

**Detection Pattern**: `scanners/ecosystem_detector.py`

**Parsing Logic**:
```toml
# Cargo.toml
[dependencies]
serde = "1.0"
tokio = { version = "1.0", features = ["full"] }
```

**Database**: `collectors/final-data/unified_cargo.db`

---

## Collector Configuration

The `collectors/config.yaml` file configures data source collectors:

```yaml
# OpenSSF Malicious Packages Collector
openssf:
  repo_url: https://github.com/ossf/malicious-packages.git
  local_path: .cache/openssf-malicious-packages  # Where to clone repo
  timeout: 300  # Git clone timeout in seconds

# OSV.dev Bulk Download Collector
osv:
  base_url: https://osv-vulnerabilities.storage.googleapis.com
  ecosystems:  # Must match OSV ecosystem names (case-sensitive)
    - npm
    - PyPI
    - Go
    - RubyGems
    - Maven
    - crates.io  # Cargo ecosystem in OSV
    - NuGet
  timeout: 300  # Download timeout per ecosystem

# Phylum.io Blog Scraper
phylum:
  blog_url: https://blog.phylum.io
  blog_feed: https://blog.phylum.io/feed/
  timeout: 30

# Socket.dev API Collector (placeholder)
socketdev:
  api_url: https://api.socket.dev
  api_key: ""  # Add your API key here
  timeout: 30
  min_risk_score: 80  # Minimum risk score to include (0-100)
```

**Configuration Loading**: `collectors/utils.py::load_config()`

**Validation**:
- Checks for required fields
- Provides defaults for optional fields
- Logs warnings for missing API keys

---

## Module Descriptions

### Scanner Modules (`scanners/`)

#### `ecosystem_detector.py`

**Purpose**: Auto-detect package ecosystems from project directory

**Key Functions**:
- `detect_ecosystems(directory)`: Scan directory, return list of detected ecosystems
- `detect_from_file(file_path)`: Detect ecosystem from single file

**Detection Strategy**:
```python
ECOSYSTEM_FILES = {
    'npm': ['package.json', 'package-lock.json', 'yarn.lock'],
    'pypi': ['requirements.txt', 'Pipfile', 'pyproject.toml', 'setup.py'],
    'maven': ['pom.xml'],
    'rubygems': ['Gemfile', 'Gemfile.lock'],
    'go': ['go.mod', 'go.sum'],
    'cargo': ['Cargo.toml', 'Cargo.lock']
}
```

#### `dependency_parsers.py`

**Purpose**: Parse dependency files and extract package information

**Key Functions**:
- `parse_dependency_file(file_path, ecosystem)`: Main parsing router
- `parse_npm_file(file_path)`: Parse package.json
- `parse_pypi_file(file_path)`: Parse requirements.txt, Pipfile, etc.
- `parse_maven_file(file_path)`: Parse pom.xml
- `parse_rubygems_file(file_path)`: Parse Gemfile
- `parse_go_file(file_path)`: Parse go.mod
- `parse_cargo_file(file_path)`: Parse Cargo.toml

**Return Format**:
```python
[
    {"name": "package-name", "version": "1.0.0"},
    {"name": "another-pkg", "version": "^2.0.0"}
]
```

#### `file_input_parser.py`

**Purpose**: Parse generic package lists (text, JSON, YAML)

**Key Functions**:
- `parse_generic_file(file_path, ecosystem)`: Parse non-standard formats

**Supported Formats**:
- **Text**: One package per line
- **JSON**: Array of package names or objects
- **YAML**: List of packages

#### `malicious_checker.py`

**Purpose**: Check packages against threat intelligence databases

**Key Functions**:
- `load_database(ecosystem)`: Load SQLite database for ecosystem
- `check_package(package_name, ecosystem)`: Query database for package
- `check_shai_hulud(package_name)`: Check Shai-Hulud list (npm only)

**Database Queries**:
```sql
SELECT * FROM packages WHERE name = ?
```

#### `ioc_detector.py`

**Purpose**: Detect Indicators of Compromise (Shai-Hulud patterns)

**Key Functions**:
- `scan_for_iocs(directory)`: Scan directory for all IoCs
- `check_malicious_files()`: Detect known payload files (bundle.js, etc.)
- `check_malicious_hooks()`: Detect suspicious npm scripts (postinstall)
- `check_malicious_workflows()`: Detect suspicious GitHub Actions
- `calculate_file_hash(file_path)`: Calculate SHA-256 hash

**Known Indicators**:
- **Files**: `bundle.js`, `setup_bun.js`, `bun_environment.js`
- **Hooks**: `"postinstall": "node bundle.js"`
- **Workflows**: `.github/workflows/shai-hulud-workflow.yml`
- **Hashes**: Known SHA-256 hashes of malicious payloads

#### `report_generator.py`

**Purpose**: Generate JSON/SARIF reports and console summaries

**Key Functions**:
- `generate_report(scan_results)`: Create JSON report
- `save_report(report, output_path)`: Save to file
- `print_report_summary(report)`: Print console summary

**Report Format**: SARIF-compatible JSON

### Collector Modules (`collectors/`)

#### `orchestrator.py`

**Purpose**: Automate collection workflow

**Key Functions**:
- `run_all_collectors(sources)`: Run selected or all collectors
- `run_collector(name, func, output_file)`: Run single collector
- `build_databases()`: Build unified SQLite databases
- `collect_all_data()`: Main entry point (collection + build)

**Command-line Options**:
```bash
--sources openssf osv    # Run specific collectors
--skip-build             # Collect only, don't build databases
--build-if-missing       # Build databases only if they don't exist
--verbose                # Show INFO logs
--debug                  # Show DEBUG logs
```

#### `build_unified_index.py`

**Purpose**: Merge raw JSON data into unified SQLite databases

**Key Functions**:
- `load_all_raw_data()`: Load all JSON files from raw-data/
- `merge_packages_by_ecosystem(raw_data_list)`: Group and deduplicate
- `build_unified_database(ecosystem, packages)`: Create SQLite database

**Merging Algorithm**:
1. Load all raw-data/*.json files
2. Group packages by ecosystem
3. For duplicate package names:
   - Union versions
   - Take highest severity
   - Combine sources and vuln_ids
   - Use latest timestamp
4. Create SQLite database with merged data

#### `db.py`

**Purpose**: Database operations and schema management

**Key Functions**:
- `create_database(db_path)`: Create SQLite database with schema
- `insert_packages(db_path, packages)`: Insert package records
- `query_package(db_path, package_name)`: Query by name

#### `utils.py`

**Purpose**: Shared utility functions

**Key Functions**:
- `fetch_json(url)`: HTTP GET with JSON parsing
- `fetch_text(url)`: HTTP GET text content
- `save_json(data, filepath)`: Save JSON with atomic write
- `load_json(filepath)`: Load JSON from file
- `get_timestamp()`: Current UTC timestamp (ISO 8601)
- `standardize_severity(severity)`: Normalize severity levels
- `normalize_ecosystem(ecosystem)`: Normalize ecosystem names
- `retry_with_backoff(func)`: Retry with exponential backoff

---

## Performance Considerations

**Scan Performance**:
- Small projects (< 50 packages): < 5 seconds
- Medium projects (50-500 packages): 5-30 seconds
- Large projects (500+ packages): 30-120 seconds

**Database Performance**:
- SQLite indexed queries: O(log n)
- First load: ~100-500ms (load database into memory)
- Subsequent queries: < 1ms per package

**Optimization Strategies**:
- Use `--no-ioc` to skip IoC scanning (faster package-only checks)
- Scan specific files instead of entire directories
- Database indexes on `name` and `severity` columns
- Connection pooling for batch queries

---

## Security Considerations

**Safe Operations**:
- All operations are read-only on user projects
- No code execution from scanned packages
- No network connections to untrusted sources during scans

**Threat Intelligence Integrity**:
- Git clone verification for OpenSSF
- HTTPS for all downloads
- Atomic file writes to prevent corruption

**Database Security**:
- SQLite databases are local-only
- No user input in SQL queries (parameterized queries only)
- Database files are read-only during scans

---

## Future Architecture Enhancements

**Planned Improvements**:
1. **Caching Layer**: In-memory cache for frequently queried packages
2. **Parallel Scanning**: Multi-threaded ecosystem scanning
3. **Incremental Updates**: Only fetch changed data from sources
4. **Custom Data Sources**: Plugin system for adding new sources
5. **API Mode**: HTTP API for programmatic access

For the full roadmap, see [README.md#roadmap](README.md#roadmap).

---

## References

- **OpenSSF Malicious Packages**: https://github.com/ossf/malicious-packages
- **OSV.dev**: https://osv.dev/
- **SARIF Specification**: https://sarifweb.azurewebsites.net/
- **SQLite Documentation**: https://www.sqlite.org/docs.html
- **PEP 8 Style Guide**: https://peps.python.org/pep-0008/

---

For usage instructions, see [README.md](README.md).
For contribution guidelines, see [CONTRIBUTING.md](CONTRIBUTING.md).
