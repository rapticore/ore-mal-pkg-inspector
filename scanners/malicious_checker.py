#!/usr/bin/env python3
"""
Malicious Package Checker Module
Checks packages against unified malicious package databases (SQLite)
"""

import os
import re
import sys
import logging
import hashlib
import sqlite3
import urllib.error
import urllib.parse
import urllib.request
import yaml
from typing import List, Dict, Optional, Set
from pathlib import Path

# Add collectors directory to path for db module
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'collectors'))
import db

# Module logger
logger = logging.getLogger(__name__)
REMOTE_SHAI_HULUD_ENV = "OREWATCH_ENABLE_REMOTE_SHAI_HULUD_FEED"
REMOTE_SHAI_HULUD_SHA256_ENV = "OREWATCH_SHAI_HULUD_YAML_SHA256"


class MaliciousPackageChecker:
    """Checks packages against malicious package databases."""

    def __init__(
        self,
        collectors_dir: Optional[str] = None,
        final_data_dir: Optional[str] = None,
    ):
        """
        Initialize the checker.

        Args:
            collectors_dir: Path to collectors directory (defaults to relative path)
            final_data_dir: Optional explicit final-data directory override
        """
        if collectors_dir is None:
            # Default to collectors directory relative to this file
            script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            collectors_dir = os.path.join(script_dir, 'collectors')

        self.collectors_dir = collectors_dir
        self.final_data_dir = final_data_dir or os.path.join(collectors_dir, 'final-data')
        self._shai_hulud_cache = None  # Cache for Shai-Hulud affected packages
        self._shai_hulud_loaded = False
        self.github_yaml_url = "https://raw.githubusercontent.com/rapticore/OreNPMGuard/main/affected_packages.yaml"

    def close(self) -> None:
        """Release transient resources held by the checker."""
        return None

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def _get_db_connection(self, ecosystem: str):
        """
        Open a read-only database connection for one lookup pass.

        Args:
            ecosystem: Ecosystem name (npm, pypi, etc.)

        Returns:
            Database connection or None if not found
        """
        db_path = os.path.join(self.final_data_dir, f'unified_{ecosystem}.db')
        return db.open_database(db_path)

    def _check_packages_with_connection(
        self,
        conn,
        packages: List[Dict[str, str]],
        ecosystem: str,
    ) -> List[Dict]:
        """Run package lookups with one open SQLite connection."""
        malicious_found = []
        for pkg in packages:
            pkg_name = pkg.get('name', '')
            pkg_version = pkg.get('version', '')

            if not pkg_name:
                continue

            # RubyGems treats "-" and "_" interchangeably, so query both forms.
            result = None
            for candidate_name in self._lookup_names_for_ecosystem(ecosystem, pkg_name):
                result = db.check_package(conn, candidate_name, pkg_version)
                if result:
                    if result.get('name') != pkg_name:
                        result['matched_name'] = result.get('name')
                        result['name'] = pkg_name
                    break
            if result:
                result['ecosystem'] = ecosystem
                # Preserve SARIF locations from input package
                if 'locations' in pkg:
                    result['locations'] = pkg['locations']
                malicious_found.append(result)
        return malicious_found
    
    def _normalize_package_name(self, name: str) -> str:
        """
        Normalize package name for comparison (case-insensitive).
        
        Args:
            name: Package name
            
        Returns:
            Normalized package name
        """
        return name.lower().strip()
    
    def _normalize_version(self, version: str) -> str:
        """
        Normalize version string for comparison.
        
        Args:
            version: Version string
            
        Returns:
            Normalized version
        """
        normalized = version.strip()
        if normalized[:1] in {"v", "V"} and normalized[1:2].isdigit():
            normalized = normalized[1:]
        return normalized

    def _lookup_names_for_ecosystem(self, ecosystem: str, name: str) -> List[str]:
        """Return lookup name variants for one ecosystem."""
        candidates = [name]
        if ecosystem == "rubygems":
            alternate = name.replace("-", "_") if "-" in name else name.replace("_", "-")
            if alternate != name:
                candidates.append(alternate)
        return candidates
    
    def _load_shai_hulud_packages(self) -> Dict[str, Set[str]]:
        """
        Load Shai-Hulud affected packages from GitHub or local YAML file.
        Uses caching to avoid reloading.
        
        Returns:
            Dict mapping package names to sets of affected versions
        """
        # Return cached data if already loaded
        if self._shai_hulud_loaded and self._shai_hulud_cache is not None:
            return self._shai_hulud_cache
        
        # First try to download from GitHub
        config = self._download_affected_packages_yaml()
        
        # If download failed, try local file
        if config is None:
            config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'affected_packages.yaml')
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = yaml.safe_load(f)
                    logger.info("✅ Loaded local Shai-Hulud configuration with %d packages", len(config.get('affected_packages', [])))
            except (FileNotFoundError, yaml.YAMLError, KeyError) as e:
                logger.warning("⚠️  Could not load Shai-Hulud configuration: %s", e)
                self._shai_hulud_cache = {}
                self._shai_hulud_loaded = True
                return self._shai_hulud_cache
        
        # Validate schema before trusting the parsed YAML (CWE-502)
        if not isinstance(config, dict):
            logger.warning("Shai-Hulud config is not a dict; ignoring")
            self._shai_hulud_cache = {}
            self._shai_hulud_loaded = True
            return self._shai_hulud_cache

        affected_packages = config.get('affected_packages')
        if not isinstance(affected_packages, list):
            logger.warning("Shai-Hulud config 'affected_packages' is not a list; ignoring")
            self._shai_hulud_cache = {}
            self._shai_hulud_loaded = True
            return self._shai_hulud_cache

        # Parse the configuration and cache it
        packages = {}
        for pkg in affected_packages:
            if (
                not isinstance(pkg, dict)
                or not isinstance(pkg.get('name'), str)
                or not isinstance(pkg.get('versions'), list)
            ):
                logger.warning("Shai-Hulud config entry has invalid schema; skipping: %s", pkg)
                continue
            packages[pkg['name']] = set(pkg['versions'])
        
        self._shai_hulud_cache = packages
        self._shai_hulud_loaded = True
        return packages
    
    def _download_affected_packages_yaml(self) -> Optional[Dict]:
        """
        Download the latest affected packages YAML from GitHub.
        
        Returns:
            Parsed YAML config or None on error
        """
        if os.environ.get(REMOTE_SHAI_HULUD_ENV) != "1":
            return None

        expected_sha256 = os.environ.get(REMOTE_SHAI_HULUD_SHA256_ENV, "").strip().lower()
        if not expected_sha256:
            logger.warning(
                "Remote Shai-Hulud feed requested but %s is not set; refusing unverified download",
                REMOTE_SHAI_HULUD_SHA256_ENV,
            )
            return None

        try:
            parsed_url = urllib.parse.urlparse(self.github_yaml_url)
            if parsed_url.scheme not in ("http", "https"):
                raise ValueError(f"Unsupported URL scheme: {parsed_url.scheme!r} (only http/https allowed)")
            req = urllib.request.Request(
                self.github_yaml_url,
                headers={'User-Agent': 'OreNPMGuard-Scanner/1.0'}
            )

            max_download_size = 5 * 1024 * 1024  # 5 MB

            with urllib.request.urlopen(req, timeout=10) as response:
                # CWE-400: enforce download size limit
                content_length = response.headers.get('Content-Length')
                if content_length is not None and int(content_length) > max_download_size:
                    logger.warning(
                        "Remote Shai-Hulud feed too large (Content-Length: %s); refusing download",
                        content_length,
                    )
                    return None

                raw_content = response.read(max_download_size + 1)
                if len(raw_content) > max_download_size:
                    logger.warning(
                        "Remote Shai-Hulud feed exceeds %d byte limit; discarding",
                        max_download_size,
                    )
                    return None
                digest = hashlib.sha256(raw_content).hexdigest()
                if digest != expected_sha256:
                    logger.warning(
                        "Remote Shai-Hulud feed checksum mismatch: expected %s, got %s",
                        expected_sha256,
                        digest,
                    )
                    return None
                yaml_content = raw_content.decode('utf-8')
                config = yaml.safe_load(yaml_content)
                if not isinstance(config, dict):
                    logger.warning("Downloaded Shai-Hulud config is not a dict; ignoring")
                    return None
                return config
        except (urllib.error.URLError, urllib.error.HTTPError, yaml.YAMLError, KeyError) as e:
            # Silently fail - will fall back to local file
            return None
        except Exception:
            return None
    
    def _check_shai_hulud_packages(self, packages: List[Dict[str, str]]) -> List[Dict]:
        """
        Check packages against Shai-Hulud affected packages list.
        
        Args:
            packages: List of dicts with 'name' and optionally 'version'
            
        Returns:
            List of malicious packages found from Shai-Hulud list
        """
        malicious_found = []
        
        # Load Shai-Hulud affected packages
        affected_db = self._load_shai_hulud_packages()
        if not affected_db:
            return malicious_found
        
        # Check each package
        for pkg in packages:
            pkg_name = pkg.get('name', '')
            pkg_version = pkg.get('version', '')
            
            if not pkg_name:
                continue
            
            normalized_name = self._normalize_package_name(pkg_name)
            
            # Check if package is in Shai-Hulud affected list
            if normalized_name in affected_db:
                affected_versions = affected_db[normalized_name]
                
                # Check version match
                is_malicious = False
                matched_version = None
                
                if pkg_version:
                    # Clean version string (remove ^, ~, >=, etc.)
                    clean_version = re.sub(r'^[\^~>=<! ]+', '', pkg_version)
                    normalized_version = self._normalize_version(clean_version)
                    normalized_affected_versions = {
                        self._normalize_version(version)
                        for version in affected_versions
                    }
                    is_malicious = normalized_version in normalized_affected_versions
                    if is_malicious:
                        matched_version = clean_version
                else:
                    # No version specified - if package has any affected versions, flag it
                    if affected_versions:
                        is_malicious = True
                        matched_version = list(affected_versions)[0] if affected_versions else None
                
                if is_malicious:
                    # Create result entry
                    result = {
                        'name': pkg_name,
                        'version': pkg_version or matched_version,
                        'ecosystem': 'npm',
                        'matched_version': matched_version,
                        'severity': 'critical',
                        'sources': ['shai-hulud'],
                        'description': f'Shai-Hulud compromised package: {pkg_name}',
                        'detected_behaviors': ['supply_chain_attack', 'malicious_code'],
                        'affected_versions': list(affected_versions)
                        # source_details removed
                    }
                    # Preserve SARIF locations from input package
                    if 'locations' in pkg:
                        result['locations'] = pkg['locations']
                    malicious_found.append(result)
        
        return malicious_found
    
    def _match_version(self, package_version: str, malicious_package_data: Dict) -> bool:
        """
        Check if a package version matches malicious criteria.

        Uses both explicit version matching and semantic version range matching.

        Args:
            package_version: Version to check
            malicious_package_data: Full package data including versions and origins

        Returns:
            True if version matches
        """
        # Get explicit versions and origins
        malicious_versions = malicious_package_data.get('versions', [])
        origins = malicious_package_data.get('origins', [])

        normalized_pkg_version = self._normalize_version(package_version)

        # Check 1: Exact version match (legacy behavior)
        for mal_version in malicious_versions:
            normalized_mal_version = self._normalize_version(mal_version)

            # Exact match
            if normalized_pkg_version == normalized_mal_version:
                return True

            # Handle version ranges (basic support)
            # If package version is empty, check if any version is malicious
            if not normalized_pkg_version and normalized_mal_version:
                # Empty version means any version - be conservative
                continue

        # Check 2: Semantic version range match (new behavior)
        if origins and normalized_pkg_version:
            if db.check_ranges(origins, normalized_pkg_version):
                return True

        return False
    
    def check_packages(self, packages: List[Dict[str, str]], ecosystem: str,
                      include_shai_hulud: bool = True) -> List[Dict]:
        """
        Check a list of packages against the malicious database.

        Args:
            packages: List of dicts with 'name' and optionally 'version'
            ecosystem: Ecosystem name (npm, pypi, etc.)
            include_shai_hulud: Whether to also check against Shai-Hulud affected packages (npm only)

        Returns:
            List of malicious packages found with full metadata
        """
        malicious_found = []

        conn = self._get_db_connection(ecosystem)
        if conn is None:
            logger.warning("Database not found for ecosystem: %s", ecosystem)
        else:
            try:
                malicious_found.extend(
                    self._check_packages_with_connection(conn, packages, ecosystem)
                )
            except sqlite3.Error as exc:
                logger.warning(
                    "SQLite lookup failed for ecosystem %s; reopening read-only database once: %s",
                    ecosystem,
                    exc,
                )
                try:
                    conn.close()
                except Exception:
                    pass
                retry_conn = self._get_db_connection(ecosystem)
                if retry_conn is None:
                    logger.warning("Database disappeared for ecosystem: %s", ecosystem)
                else:
                    try:
                        malicious_found.extend(
                            self._check_packages_with_connection(retry_conn, packages, ecosystem)
                        )
                    finally:
                        retry_conn.close()
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

        # Also check against Shai-Hulud affected packages for npm ecosystem
        if include_shai_hulud and ecosystem == 'npm':
            shai_hulud_malicious = self._check_shai_hulud_packages(packages)

            # Merge results, avoiding duplicates
            existing_names = {(pkg['name'].lower(), pkg.get('version', '')) for pkg in malicious_found}
            for pkg in shai_hulud_malicious:
                key = (pkg['name'].lower(), pkg.get('version', ''))
                if key not in existing_names:
                    malicious_found.append(pkg)
                    existing_names.add(key)

        return malicious_found


def check_malicious_packages(packages: List[Dict[str, str]], ecosystem: str,
                            collectors_dir: Optional[str] = None,
                            final_data_dir: Optional[str] = None,
                            include_shai_hulud: bool = True) -> List[Dict]:
    """
    Convenience function to check packages.
    
    Args:
        packages: List of dicts with 'name' and optionally 'version'
        ecosystem: Ecosystem name (npm, pypi, etc.)
        collectors_dir: Optional path to collectors directory
        final_data_dir: Optional explicit final-data directory override
        include_shai_hulud: Whether to also check against Shai-Hulud affected packages (npm only)
        
    Returns:
        List of malicious packages found
    """
    checker = MaliciousPackageChecker(collectors_dir, final_data_dir=final_data_dir)
    return checker.check_packages(packages, ecosystem, include_shai_hulud=include_shai_hulud)
