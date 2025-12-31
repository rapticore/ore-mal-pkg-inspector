# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

OREMalPkgInspector is a multi-ecosystem malicious package scanner that detects compromised packages across npm, PyPI, Maven, RubyGems, Go, and Cargo ecosystems. The tool uses dynamically collected threat intelligence from multiple sources (OpenSSF, OSV.dev, Phylum, Socket.dev) and stores data in SQLite databases for fast lookup.

## Core Architecture

### Two-Phase Design

**Phase 1: Data Collection** (`collectors/`)
- Individual collectors fetch threat data from external sources
- Raw data stored as-is in `collectors/raw-data/*.json` for transparency
- Data merged and deduplicated into SQLite databases per ecosystem in `collectors/final-data/unified_*.db`
- Can be run independently via `collectors/run_all.sh` or `python3 orchestrator.py`

**Phase 2: Scanning** (`scanners/` and `malicious_package_scanner.py`)
- Detects ecosystem(s) from directory structure or file names
- Parses dependency files (package.json, requirements.txt, etc.)
- Checks packages against SQLite databases
- Detects Indicators of Compromise (IoCs) for known attack patterns (Shai-Hulud)
- Generates SARIF-compliant JSON reports with physical locations

### Data Flow

```
External Sources → Collectors → raw-data/*.json → build_unified_index.py →
final-data/unified_*.db → malicious_checker.py → Report
```

### Key Components

**Collectors** (`collectors/`)
- `collect_openssf.py` - OpenSSF malicious packages repository (~220k packages)
- `collect_osv.py` - OSV.dev bulk download (MAL- entries)
- `collect_phylum.py` - Phylum.io blog scraping
- `collect_socketdev.py` - Socket.dev API (placeholder, requires API key)
- `build_unified_index.py` - Merges raw data into SQLite databases
- `orchestrator.py` - Runs all collectors programmatically
- `db.py` - SQLite operations (schema, insert, query)

**Scanners** (`scanners/`)
- `ecosystem_detector.py` - Auto-detects ecosystems from files/directories
- `dependency_parsers.py` - Parses dependency files for each ecosystem
- `file_input_parser.py` - Generic file input parsing (JSON, YAML, text)
- `malicious_checker.py` - Checks packages against databases and Shai-Hulud list
- `ioc_detector.py` - Scans for Indicators of Compromise (malicious files, hooks, workflows)
- `report_generator.py` - Generates JSON reports with SARIF compliance

### SARIF Compliance

The scanner outputs SARIF-compliant physical locations for detected packages:
```json
{
  "physicalLocation": {
    "artifactLocation": {"uri": "relative/path/to/file"},
    "region": {
      "startLine": 1,
      "startColumn": 1,
      "endLine": 1,
      "endColumn": 1
    }
  }
}
```

Locations are aggregated by package name+version to avoid duplicates across multiple dependency files.

## Common Commands

### Running the Scanner

```bash
# Install dependencies first
pip install -r requirements.txt

# Auto-detect ecosystem and scan directory
python3 malicious_package_scanner.py /path/to/project

# Scan specific file (ecosystem auto-detected)
python3 malicious_package_scanner.py --file package.json

# Force specific ecosystem
python3 malicious_package_scanner.py /path/to/project --ecosystem npm

# Skip IoC scanning for faster execution
python3 malicious_package_scanner.py /path/to/project --no-ioc

# Only scan for IoCs (skip package checking)
python3 malicious_package_scanner.py /path/to/project --ioc-only

# Custom output path
python3 malicious_package_scanner.py /path/to/project --output custom-report.json
```

### Collecting Threat Intelligence

```bash
# Run all collectors and build databases
cd collectors
./run_all.sh

# Or use Python orchestrator
python3 orchestrator.py

# Run specific collectors only
python3 orchestrator.py --sources openssf osv

# Skip database building (only collect raw data)
python3 orchestrator.py --skip-build

# Build databases only if they don't exist
python3 orchestrator.py --build-if-missing
```

### Testing

```bash
# Test with example malicious package file
python3 malicious_package_scanner.py test-malicious-package.json

# Run orchestrator example
python3 example_orchestrator_usage.py
```

## Important Implementation Details

### Database Structure
- **SQLite databases** per ecosystem in `collectors/final-data/unified_*.db`
- Schema includes: packages, package_versions, package_sources, package_references, package_origins, metadata
- Normalized package names for case-insensitive lookups
- Multiple sources tracked per package with source attribution

### Shai-Hulud Integration (npm only)
- Downloads latest affected packages from GitHub: `https://raw.githubusercontent.com/rapticore/OreNPMGuard/main/affected_packages.yaml`
- Falls back to local `affected_packages.yaml` if download fails
- Cached to avoid repeated downloads during scan
- Merged with unified database results, avoiding duplicates

### Multi-Ecosystem Scanning
- If multiple ecosystems detected in directory, scanner processes all automatically
- Packages tagged with ecosystem during parsing
- Results aggregated and reported together
- Exit code 1 if any malicious packages or IoCs found

### Package Aggregation
The `aggregate_package_locations()` function merges packages by (name, version) and collects all SARIF physical locations to avoid duplicate reporting across multiple dependency files.

### Version Matching
- Version strings normalized (strip whitespace)
- Supports exact version matching
- Future: Could add semver range support

## Configuration

### Collector Configuration
Edit `collectors/config.yaml` to configure API keys and endpoints:
- Socket.dev requires API key (free tier available)
- OpenSSF can use GitHub token for higher rate limits (optional)
- OSV.dev and Phylum require no authentication

### Ecosystem Support
Supported ecosystems and their dependency files:
- **npm**: package.json, package-lock.json, yarn.lock, pnpm-lock.yaml
- **PyPI**: requirements.txt, setup.py, pyproject.toml, Pipfile, poetry.lock
- **Maven**: pom.xml, build.gradle
- **RubyGems**: Gemfile, Gemfile.lock
- **Go**: go.mod, go.sum
- **Cargo**: Cargo.toml, Cargo.lock

Detection happens in `ecosystem_detector.py` via `FILENAME_TO_ECOSYSTEM` mapping.

## Development Notes

### Design Principles
- Function-based implementation (avoid classes except where needed like MaliciousPackageChecker)
- SQLite for data storage (no external database required)
- Transparent data flow (raw data preserved)
- Fail gracefully (continue if some collectors fail)
- Ecosystem separation (one database per ecosystem)

### Adding New Collectors
1. Create `collectors/collect_newsource.py`
2. Implement `fetch_newsource_packages()` returning standardized format
3. Add to `orchestrator.py` collector registry
4. Update `run_all.sh` to include new collector

### Adding New Ecosystems
1. Add filename mappings to `ecosystem_detector.py`
2. Add parser logic to `dependency_parsers.py`
3. Update supported ecosystems in argument parser

### IoC Detection Patterns
Located in `scanners/ioc_detector.py`. Add new patterns by defining file hash matches, file path patterns, or content patterns for known malicious indicators.

## Exit Codes
- **0**: No malicious packages or IoCs detected
- **1**: Malicious packages or IoCs found, or error occurred
