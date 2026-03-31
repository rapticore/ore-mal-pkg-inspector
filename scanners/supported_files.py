#!/usr/bin/env python3
"""
Supported manifest registry shared across scanner modules.
"""

from typing import Dict, List, Optional


ECOSYSTEM_PRIORITY = ["npm", "pypi", "maven", "rubygems", "go", "cargo"]

SKIP_DIRS = [
    "node_modules",
    ".git",
    "__pycache__",
    "venv",
    "env",
    ".venv",
    ".next",
    "build",
    "dist",
    ".build",
    "target",
    "out",
    ".cache",
    ".idea",
    ".vscode",
    ".vs",
    "coverage",
    ".nyc_output",
    ".pytest_cache",
    "bin",
    "obj",
    ".gradle",
    ".mvn",
    "vendor",
    "bower_components",
]


SUPPORTED_MANIFESTS: List[Dict[str, str]] = [
    {"filename": "package.json", "ecosystem": "npm", "parser_id": "npm_package_json"},
    {"filename": "package-lock.json", "ecosystem": "npm", "parser_id": "npm_package_lock"},
    {"filename": "yarn.lock", "ecosystem": "npm", "parser_id": "yarn_lock"},
    {"filename": "pnpm-lock.yaml", "ecosystem": "npm", "parser_id": "pnpm_lock"},
    {"filename": "requirements.txt", "ecosystem": "pypi", "parser_id": "requirements_txt"},
    {"filename": "setup.py", "ecosystem": "pypi", "parser_id": "setup_py"},
    {"filename": "pyproject.toml", "ecosystem": "pypi", "parser_id": "pyproject_toml"},
    {"filename": "Pipfile", "ecosystem": "pypi", "parser_id": "pipfile"},
    {"filename": "poetry.lock", "ecosystem": "pypi", "parser_id": "poetry_lock"},
    {"filename": "pom.xml", "ecosystem": "maven", "parser_id": "pom_xml"},
    {"filename": "build.gradle", "ecosystem": "maven", "parser_id": "build_gradle"},
    {"filename": "Gemfile", "ecosystem": "rubygems", "parser_id": "gemfile"},
    {"filename": "Gemfile.lock", "ecosystem": "rubygems", "parser_id": "gemfile_lock"},
    {"filename": "go.mod", "ecosystem": "go", "parser_id": "go_mod"},
    {"filename": "go.sum", "ecosystem": "go", "parser_id": "go_sum"},
    {"filename": "Cargo.toml", "ecosystem": "cargo", "parser_id": "cargo_toml"},
    {"filename": "Cargo.lock", "ecosystem": "cargo", "parser_id": "cargo_lock"},
]


def build_filename_map() -> Dict[str, Dict[str, str]]:
    """Return a lookup of filename -> manifest metadata."""
    return {manifest["filename"]: manifest for manifest in SUPPORTED_MANIFESTS}


FILENAME_TO_MANIFEST = build_filename_map()
FILENAME_TO_ECOSYSTEM = {
    filename: manifest["ecosystem"]
    for filename, manifest in FILENAME_TO_MANIFEST.items()
}


def get_supported_manifest_filenames() -> List[str]:
    """Return the exact supported manifest filenames in registry order."""
    return [manifest["filename"] for manifest in SUPPORTED_MANIFESTS]


def get_manifest_for_filename(filename: str) -> Optional[Dict[str, str]]:
    """Return manifest metadata for a filename if it is supported."""
    return FILENAME_TO_MANIFEST.get(filename)


def get_supported_files_for_ecosystem(ecosystem: str) -> List[str]:
    """Return supported filenames for one ecosystem in registry order."""
    return [
        manifest["filename"]
        for manifest in SUPPORTED_MANIFESTS
        if manifest["ecosystem"] == ecosystem
    ]

