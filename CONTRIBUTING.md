# Contributing to OreWatch

Thank you for your interest in OreWatch! This document provides guidelines for developers who want to contribute code, documentation, or other improvements to the project.

## Table of Contents

- [Reporting Bugs](#reporting-bugs)
- [Suggesting Features](#suggesting-features)
- [Pull Request Process](#pull-request-process)
- [Development Setup](#development-setup)
- [Code Style Guidelines](#code-style-guidelines)
- [Adding New Ecosystems](#adding-new-ecosystems)
- [Adding New Data Sources](#adding-new-data-sources)
- [Testing](#testing)
- [Code of Conduct](#code-of-conduct)

---

## Reporting Bugs

We appreciate detailed bug reports that help us improve the tool.

### Before Submitting

1. **Search existing issues**: Check if the bug is already reported at https://github.com/rapticore/ore-mal-pkg-inspector/issues
2. **Verify it's reproducible**: Try to reproduce the bug with the latest version

### Creating a Bug Report

Include the following information:

- **OreWatch version**: Check with `git describe --tags` or note your commit hash
- **Python version**: Output of `python3 --version`
- **Operating System**: Linux, macOS, Windows (with version)
- **Steps to reproduce**: Detailed steps that consistently reproduce the issue
- **Expected behavior**: What you expected to happen
- **Actual behavior**: What actually happened
- **Relevant logs**: Run with `--debug` flag and include relevant log output
- **Sample files**: If applicable, provide sample dependency files (anonymized if needed)

**Submit at**: https://github.com/rapticore/ore-mal-pkg-inspector/issues

---

## Suggesting Features

We welcome feature suggestions that align with the project's goals.

### Before Suggesting

1. **Check the roadmap**: Review [README.md#roadmap](README.md#roadmap) to see if it's already planned
2. **Search discussions**: Look for existing feature requests at https://github.com/rapticore/ore-mal-pkg-inspector/discussions

### Creating a Feature Request

Include:

- **Use case**: Describe the problem this feature would solve
- **Proposed solution**: How you envision the feature working
- **Alternatives considered**: Other approaches you've thought about
- **Impact**: Who would benefit from this feature
- **Implementation complexity**: If known, estimate the effort required

**Submit at**: https://github.com/rapticore/ore-mal-pkg-inspector/issues (use "Feature Request" label)

---

## Pull Request Process

### 1. Fork and Clone

```bash
git clone https://github.com/YOUR-USERNAME/ore-mal-pkg-inspector.git
cd ore-mal-pkg-inspector
```

### 2. Create a Feature Branch

```bash
git checkout -b feature/your-feature-name
```

Use descriptive branch names:
- `feature/nuget-support` - New features
- `fix/database-connection-error` - Bug fixes
- `docs/update-installation-guide` - Documentation
- `refactor/collector-module` - Code refactoring

### 3. Make Your Changes

Follow the guidelines in this document:
- Write clean, readable code
- Follow [Code Style Guidelines](#code-style-guidelines)
- Add docstrings to new functions
- Use logging instead of print statements
- Update documentation if adding user-facing features

### 4. Test Your Changes

```bash
# Test scanner functionality
orewatch /path/to/test/project --debug

# Test with various ecosystems
orewatch --file package.json
orewatch --file requirements.txt

# Test collectors
cd collectors
python3 orchestrator.py --sources openssf --verbose

# Test edge cases
orewatch nonexistent-path  # Should handle gracefully
orewatch --file invalid.json --ecosystem npm
```

### 5. Commit Your Changes

Write clear, descriptive commit messages:

```bash
git add .
git commit -m "Add support for NuGet ecosystem detection

- Implement NuGet package file parsing (packages.config, *.csproj)
- Add ecosystem detection for .NET projects
- Update documentation with NuGet examples"
```

**Commit message format:**
- First line: Brief summary (50 chars or less)
- Blank line
- Detailed description of changes (wrapped at 72 chars)
- Reference any related issues: "Fixes #123" or "Relates to #456"

### 6. Push and Create Pull Request

```bash
git push origin feature/your-feature-name
```

Then open a pull request on GitHub with:
- **Clear title**: Summarize the change
- **Description**: Explain what changed and why
- **Testing**: Describe how you tested the changes
- **Screenshots**: If UI/output changes, include before/after examples
- **Checklist**:
  - [ ] Code follows style guidelines
  - [ ] Documentation updated
  - [ ] Tests pass
  - [ ] Commit messages are clear

### 7. Code Review

- Respond to reviewer feedback promptly
- Make requested changes in new commits (don't force-push during review)
- Once approved, maintainers will merge your PR

---

## Development Setup

### Prerequisites

- Python 3.14 or higher
- Git
- Virtual environment (recommended)

### Setup Steps

```bash
# Clone repository
git clone https://github.com/rapticore/ore-mal-pkg-inspector.git
cd ore-mal-pkg-inspector

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install the project in editable mode
pip install -e .

# Verify installation
orewatch --help

# Note: First scan will auto-collect threat intelligence data
# Or manually collect for testing:
# cd collectors && python3 orchestrator.py && cd ..
```

### Development Workflow

```bash
# Activate virtual environment
source .venv/bin/activate

# Make changes to code
# ... edit files ...

# Test changes
orewatch /path/to/test/project --debug

# Run collectors if testing threat intelligence
cd collectors
python3 orchestrator.py --sources openssf --verbose
cd ..

# Commit and push
git add .
git commit -m "Description of changes"
git push origin your-branch-name
```

---

## Code Style Guidelines

### Python Style (PEP 8)

Follow [PEP 8](https://peps.python.org/pep-0008/) Python style guidelines:

- **Indentation**: 4 spaces (no tabs)
- **Line length**: 79 characters for code, 72 for docstrings/comments
- **Naming**:
  - Functions/variables: `snake_case`
  - Classes: `PascalCase`
  - Constants: `UPPER_SNAKE_CASE`
- **Imports**: Group in order: standard library, third-party, local
- **Whitespace**: Follow PEP 8 conventions

### Logging

**Always use logging, not print():**

```python
import logging

logger = logging.getLogger(__name__)

# Good ✅
logger.info("Loaded %d packages from database", package_count)
logger.error("Failed to parse %s: %s", filename, error)
logger.debug("Query executed: %s", sql_query)

# Bad ❌
print(f"Loaded {package_count} packages")
print("Error:", error)
```

**Logging levels:**
- `logger.debug()`: Detailed diagnostic information
- `logger.info()`: Progress and status updates
- `logger.warning()`: Something unexpected but not critical
- `logger.error()`: Error that needs attention

**Use parameter substitution** (not f-strings) for logging:
```python
# Good ✅
logger.info("Processing %s with %d items", filename, count)

# Bad ❌
logger.info(f"Processing {filename} with {count} items")
```

### Docstrings

Add docstrings to all functions:

```python
def parse_dependency_file(file_path, ecosystem):
    """
    Parse a dependency file and extract package information.

    Args:
        file_path (str): Absolute path to the dependency file
        ecosystem (str): Package ecosystem (npm, pypi, etc.)

    Returns:
        list: List of package dictionaries with 'name' and 'version' keys

    Raises:
        FileNotFoundError: If file_path does not exist
        ValueError: If ecosystem is not supported
    """
    # Implementation here
    pass
```

### Error Handling

Use specific exception types:

```python
# Good ✅
try:
    data = json.load(f)
except FileNotFoundError:
    logger.error("File not found: %s", file_path)
except json.JSONDecodeError as e:
    logger.error("Invalid JSON in %s: %s", file_path, e)
except Exception as e:
    logger.error("Unexpected error: %s", e)

# Bad ❌
try:
    data = json.load(f)
except:  # Too broad
    print("Error occurred")
```

### Comments

- Explain **why**, not **what** (code should be self-documenting)
- Update comments when code changes
- Use TODO comments for future improvements: `# TODO: Add support for X`

---

## Adding New Ecosystems

To add support for a new package ecosystem (e.g., NuGet, Composer, CocoaPods):

### 1. Update Ecosystem Detector

Edit `scanners/ecosystem_detector.py`:

```python
# Add detection patterns for new ecosystem
ECOSYSTEM_FILES = {
    'npm': ['package.json', 'package-lock.json', 'yarn.lock'],
    'pypi': ['requirements.txt', 'Pipfile', 'setup.py', 'pyproject.toml'],
    # ... existing ecosystems ...
    'nuget': ['packages.config', '*.csproj', '*.vbproj'],  # Add new
}
```

### 2. Add Parser Function

Edit `scanners/dependency_parsers.py`:

```python
def parse_nuget_file(file_path):
    """
    Parse NuGet dependency file.

    Args:
        file_path (str): Path to packages.config or .csproj

    Returns:
        list: List of {name, version} dictionaries
    """
    # Implement parsing logic
    # Handle packages.config (XML) or .csproj (XML with PackageReference)
    packages = []
    # ... parsing implementation ...
    return packages
```

Add to the parser routing logic:
```python
# In parse_dependency_file()
elif ecosystem == 'nuget':
    return parse_nuget_file(file_path)
```

### 3. Update Build Unified Index

Edit `collectors/build_unified_index.py`:

```python
# Add to ECOSYSTEMS list
ECOSYSTEMS = ['npm', 'pypi', 'rubygems', 'go', 'maven', 'cargo', 'nuget']
```

### 4. Add Data Source (if needed)

If OSV.dev or OpenSSF don't cover the new ecosystem:

Create `collectors/collect_newsource.py`:
```python
#!/usr/bin/env python3
"""
New Source Collector
Fetches malicious packages for [ecosystem] from [source]
"""

def fetch_newsource_packages():
    """
    Fetch packages from new source.

    Returns:
        dict: Standardized data structure with packages
    """
    # Implementation
    pass
```

Update `collectors/orchestrator.py` to include the new collector.

### 5. Test

```bash
# Test detection
orewatch /path/to/nuget/project --verbose

# Test parsing
orewatch --file packages.config --ecosystem nuget

# Test database building
cd collectors
python3 build_unified_index.py
```

### 6. Update Documentation

- Update README.md supported ecosystems section
- Add usage examples for new ecosystem
- Update ARCHITECTURE.md with technical details

---

## Adding New Data Sources

To integrate a new threat intelligence source:

### 1. Create Collector Module

Create `collectors/collect_newsource.py`:

```python
#!/usr/bin/env python3
"""
NewSource Collector
Fetches malicious package data from NewSource API/Feed
"""

import os
import sys
import logging

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import utils

logger = logging.getLogger(__name__)

def fetch_newsource_packages():
    """
    Fetch malicious packages from NewSource.

    Returns:
        dict: Standardized data structure with packages:
        {
            "source": "newsource",
            "collected_at": "2025-12-31T12:00:00Z",
            "total_packages": 100,
            "ecosystems": ["npm", "pypi"],
            "packages": [
                {
                    "name": "package-name",
                    "ecosystem": "npm",
                    "versions": ["1.0.0", "1.0.1"],
                    "severity": "critical",
                    "description": "...",
                    "detected_behaviors": ["malicious_code"],
                    "source_url": "https://..."
                }
            ]
        }
    """
    logger.info("Fetching from NewSource...")

    # Fetch data (API, scraping, download, etc.)
    packages = []

    # Transform to standardized format
    for item in raw_data:
        pkg = {
            "name": item["package_name"],
            "ecosystem": utils.normalize_ecosystem(item["ecosystem"]),
            "versions": item.get("affected_versions", []),
            "severity": utils.standardize_severity(item["severity"]),
            "description": item.get("description", ""),
            "detected_behaviors": item.get("behaviors", []),
            "source_url": item.get("url", "")
        }
        packages.append(pkg)

    result = {
        "source": "newsource",
        "collected_at": utils.get_timestamp(),
        "total_packages": len(packages),
        "ecosystems": list(set(p["ecosystem"] for p in packages if p["ecosystem"])),
        "packages": packages
    }

    return result
```

### 2. Add to Orchestrator

Edit `collectors/orchestrator.py`:

```python
# Add import
import collect_newsource

# Add to all_collectors dictionary
all_collectors = {
    'openssf': {...},
    'osv': {...},
    'phylum': {...},
    'socketdev': {...},
    'newsource': {  # Add new
        'name': 'NewSource',
        'func': collect_newsource.fetch_newsource_packages,
        'output': 'newsource.json'
    }
}
```

### 3. Add Configuration

Edit `collectors/config.yaml`:

```yaml
newsource:
  api_url: https://api.newsource.com
  api_key: ""  # Optional
  timeout: 30
```

### 4. Test Collector

```bash
cd collectors

# Test new collector
python3 collect_newsource.py

# Test integration with orchestrator
python3 orchestrator.py --sources newsource --verbose

# Test full build
python3 orchestrator.py
```

### 5. Document

- Add to ARCHITECTURE.md data sources section
- Include any API key requirements
- Document data format and limitations

---

## Testing

### Manual Testing

Before submitting a PR, test your changes:

**Scanner Tests:**
```bash
# Test basic scanning
orewatch /path/to/test/project --verbose

# Test ecosystem detection
orewatch /path/to/multi-lang-project

# Test file parsing
orewatch --file package.json
orewatch --file requirements.txt

# Test error handling
orewatch nonexistent-path
orewatch --file invalid.json --ecosystem npm

# Test debug mode
orewatch . --debug 2> debug.log
```

**Collector Tests:**
```bash
cd collectors

# Test specific collector
python3 collect_openssf.py

# Test orchestrator
python3 orchestrator.py --sources openssf --verbose

# Test database building
python3 build_unified_index.py
```

**Automatic Collection Tests:**
```bash
# Test first-run auto-collection (delete databases first)
rm collectors/final-data/*.db
orewatch test-malicious-package.json

# Test --latest-data flag
orewatch test-malicious-package.json --latest-data

# Test graceful failure (disconnect network or block internet)
# Should warn but continue with old data
orewatch . --latest-data

# Test with existing databases (should skip collection)
orewatch . --verbose
# Should show: DEBUG: Threat intelligence databases found
```

### Test Coverage

Ensure your changes handle:
- **Happy path**: Normal, expected usage
- **Edge cases**: Empty files, missing files, malformed data
- **Error cases**: Invalid input, network failures, permission errors
- **Multiple ecosystems**: If applicable

---

## Code of Conduct

### Our Standards

- **Be respectful and constructive** in all interactions
- **Welcome newcomers** and help them learn
- **Focus on what's best** for the project and community
- **Accept feedback gracefully** and provide it tactfully
- **Respect maintainer decisions** on project scope and direction

### Unacceptable Behavior

- Harassment, discrimination, or personal attacks
- Trolling, insulting comments, or sustained disruption
- Publishing others' private information
- Other conduct inappropriate for a professional setting

### Enforcement

Violations may result in:
1. Warning
2. Temporary ban from project interactions
3. Permanent ban from the project

Report issues to: security@rapticore.com

---

## Questions?

- **General questions**: https://github.com/rapticore/ore-mal-pkg-inspector/discussions
- **Bug reports**: https://github.com/rapticore/ore-mal-pkg-inspector/issues
- **Security issues**: security@rapticore.com

Thank you for contributing to OreWatch!
