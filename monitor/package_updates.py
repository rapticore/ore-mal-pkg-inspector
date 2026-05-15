#!/usr/bin/env python3
"""
Best-effort package update advisory checks for watched projects.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import logging
import os
import shutil
import sys
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Tuple

from packaging.version import InvalidVersion, Version

try:
    from defusedxml import ElementTree
except ImportError:  # pragma: no cover - dependency is declared in pyproject
    import xml.etree.ElementTree as ElementTree  # type: ignore

from monitor.api import resolve_exact_version
from scanners.dependency_parsers import parse_dependencies
from scanners.ecosystem_detector import find_dependency_files
from scanners.supported_files import ECOSYSTEM_PRIORITY


logger = logging.getLogger(__name__)
SELF_UPDATE_ECOSYSTEM = "orewatch"
LOCKFILE_NAMES = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "Gemfile.lock",
    "go.sum",
    "Cargo.lock",
}


def _normalize_version_for_compare(value: str) -> str:
    version = str(value or "").strip()
    if version.startswith("v") and len(version) > 1 and version[1].isdigit():
        return version[1:]
    return version


def is_newer_version(latest_version: str, current_version: str) -> bool:
    """Return True when latest_version is strictly newer than current_version."""
    try:
        return Version(_normalize_version_for_compare(latest_version)) > Version(
            _normalize_version_for_compare(current_version)
        )
    except InvalidVersion:
        return False


def advisory_fingerprint(
    ecosystem: str,
    package_name: str,
    current_version: str,
    manifest_path: str,
    source_type: str,
) -> str:
    """Return a stable fingerprint for one package-update advisory."""
    material = "\x1f".join(
        [
            str(ecosystem).lower().strip(),
            str(package_name).lower().strip(),
            str(current_version).strip(),
            os.path.realpath(str(manifest_path or "")),
            str(source_type).lower().strip(),
        ]
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _json_get(url: str, timeout_seconds: float) -> Dict[str, Any]:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "OreWatch package update checker",
        },
    )
    with urllib.request.urlopen(request, timeout=max(float(timeout_seconds), 1.0)) as response:
        return json.loads(response.read().decode("utf-8"))


def _text_get(url: str, timeout_seconds: float) -> str:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "OreWatch package update checker"},
    )
    with urllib.request.urlopen(request, timeout=max(float(timeout_seconds), 1.0)) as response:
        return response.read().decode("utf-8", errors="replace")


def _go_module_escape(module_path: str) -> str:
    escaped = []
    for ch in str(module_path or ""):
        if "A" <= ch <= "Z":
            escaped.append("!" + ch.lower())
        else:
            escaped.append(ch)
    return "".join(escaped)


class RegistryClient:
    """Small public-registry client with per-check in-memory caching."""

    def __init__(self, timeout_ms: int = 5000):
        self.timeout_seconds = max(int(timeout_ms), 1000) / 1000.0
        self._cache: Dict[Tuple[str, str], Dict[str, str]] = {}

    def latest(self, ecosystem: str, package_name: str) -> Dict[str, str]:
        """Return latest-version metadata or an error string."""
        key = (ecosystem, package_name.lower())
        if key not in self._cache:
            self._cache[key] = self._lookup_latest(ecosystem, package_name)
        return dict(self._cache[key])

    def _lookup_latest(self, ecosystem: str, package_name: str) -> Dict[str, str]:
        try:
            if ecosystem == "npm":
                return self._latest_npm(package_name)
            if ecosystem == "pypi":
                return self._latest_pypi(package_name)
            if ecosystem == "maven":
                return self._latest_maven(package_name)
            if ecosystem == "rubygems":
                return self._latest_rubygems(package_name)
            if ecosystem == "go":
                return self._latest_go(package_name)
            if ecosystem == "cargo":
                return self._latest_cargo(package_name)
            return {"latest_version": "", "error": f"Unsupported ecosystem: {ecosystem}"}
        except (OSError, urllib.error.URLError, urllib.error.HTTPError, ValueError, json.JSONDecodeError) as exc:
            logger.debug("Package update lookup failed for %s/%s: %s", ecosystem, package_name, exc)
            return {"latest_version": "", "error": str(exc)}

    def _latest_npm(self, package_name: str) -> Dict[str, str]:
        encoded = urllib.parse.quote(package_name, safe="")
        url = f"https://registry.npmjs.org/{encoded}"
        payload = _json_get(url, self.timeout_seconds)
        latest = str((payload.get("dist-tags", {}) or {}).get("latest", "")).strip()
        return {
            "latest_version": latest,
            "registry_url": url,
            "package_url": f"https://www.npmjs.com/package/{encoded}",
        }

    def _latest_pypi(self, package_name: str) -> Dict[str, str]:
        encoded = urllib.parse.quote(package_name, safe="")
        url = f"https://pypi.org/pypi/{encoded}/json"
        payload = _json_get(url, self.timeout_seconds)
        latest = str((payload.get("info", {}) or {}).get("version", "")).strip()
        return {
            "latest_version": latest,
            "registry_url": url,
            "package_url": f"https://pypi.org/project/{encoded}/",
        }

    def _latest_maven(self, package_name: str) -> Dict[str, str]:
        if ":" not in package_name:
            return {"latest_version": "", "error": "Maven package must be group:artifact"}
        group_id, artifact_id = package_name.split(":", 1)
        group_path = "/".join(part for part in group_id.split(".") if part)
        encoded_artifact = urllib.parse.quote(artifact_id, safe="")
        url = f"https://repo1.maven.org/maven2/{group_path}/{encoded_artifact}/maven-metadata.xml"
        metadata = _text_get(url, self.timeout_seconds)
        root = ElementTree.fromstring(metadata)
        release = root.findtext("./versioning/release") or root.findtext("./versioning/latest") or ""
        versions = [
            str(version.text or "").strip()
            for version in root.findall("./versioning/versions/version")
            if str(version.text or "").strip()
        ]
        latest = str(release).strip() or (versions[-1] if versions else "")
        return {
            "latest_version": latest,
            "registry_url": url,
            "package_url": f"https://central.sonatype.com/artifact/{group_id}/{artifact_id}",
        }

    def _latest_rubygems(self, package_name: str) -> Dict[str, str]:
        encoded = urllib.parse.quote(package_name, safe="")
        url = f"https://rubygems.org/api/v1/versions/{encoded}/latest.json"
        payload = _json_get(url, self.timeout_seconds)
        latest = str(payload.get("version", "")).strip()
        return {
            "latest_version": latest,
            "registry_url": url,
            "package_url": f"https://rubygems.org/gems/{encoded}",
        }

    def _latest_go(self, package_name: str) -> Dict[str, str]:
        encoded = urllib.parse.quote(_go_module_escape(package_name), safe="/!")
        url = f"https://proxy.golang.org/{encoded}/@latest"
        payload = _json_get(url, self.timeout_seconds)
        latest = str(payload.get("Version", "")).strip()
        return {
            "latest_version": latest,
            "registry_url": url,
            "package_url": f"https://pkg.go.dev/{package_name}",
        }

    def _latest_cargo(self, package_name: str) -> Dict[str, str]:
        encoded = urllib.parse.quote(package_name, safe="")
        url = f"https://crates.io/api/v1/crates/{encoded}"
        payload = _json_get(url, self.timeout_seconds)
        crate = payload.get("crate", {}) or {}
        latest = str(
            crate.get("max_stable_version")
            or crate.get("newest_version")
            or crate.get("max_version")
            or ""
        ).strip()
        return {
            "latest_version": latest,
            "registry_url": url,
            "package_url": f"https://crates.io/crates/{encoded}",
        }


def _source_type_for_file(path: str) -> str:
    return "lockfile" if os.path.basename(path) in LOCKFILE_NAMES else "manifest"


def _candidate_rank(candidate: Dict[str, str]) -> int:
    if not candidate.get("current_version"):
        return 0
    return 3 if candidate.get("source_type") == "lockfile" else 2


def _dependency_manifest_path(dependency: Dict[str, Any], fallback_path: str) -> str:
    location = dependency.get("physical_location") or {}
    artifact = (location.get("artifact_location") or {}) if isinstance(location, dict) else {}
    uri = str(artifact.get("uri", "") or "").strip()
    return os.path.realpath(uri or fallback_path)


def _update_command(ecosystem: str, package_name: str, latest_version: str) -> str:
    if ecosystem == "npm":
        return f"npm install {package_name}@{latest_version}"
    if ecosystem == "pypi":
        return f"python -m pip install --upgrade {package_name}=={latest_version}"
    if ecosystem == "maven":
        return f"Update {package_name} to {latest_version} in your Maven/Gradle manifest"
    if ecosystem == "rubygems":
        return f"bundle update {package_name}"
    if ecosystem == "go":
        return f"go get {package_name}@{latest_version} && go mod tidy"
    if ecosystem == "cargo":
        return f"cargo update -p {package_name}"
    return ""


def _path_components(path: str) -> List[str]:
    return [
        component.lower()
        for component in os.path.realpath(os.path.abspath(path)).split(os.sep)
        if component
    ]


def _is_orewatch_homebrew_cellar_path(path: str) -> bool:
    if not path:
        return False
    components = _path_components(path)
    return "cellar" in components and "orewatch" in components


def _has_homebrew_orewatch_formula_sibling(command_path: str) -> bool:
    if not command_path or os.path.basename(command_path) != "orewatch":
        return False
    prefix = os.path.dirname(os.path.dirname(os.path.abspath(command_path)))
    return os.path.exists(os.path.join(prefix, "Cellar", "orewatch")) or os.path.exists(
        os.path.join(prefix, "opt", "orewatch")
    )


def _is_orewatch_homebrew_install(command_path: str, executable: str) -> bool:
    return (
        _is_orewatch_homebrew_cellar_path(command_path)
        or _is_orewatch_homebrew_cellar_path(executable)
        or _has_homebrew_orewatch_formula_sibling(command_path)
    )


def _self_update_command() -> str:
    command_path = shutil.which("orewatch") or ""
    executable = sys.executable or ""
    if _is_orewatch_homebrew_install(command_path, executable):
        return "brew update && brew reinstall rapticore/tap/orewatch"
    combined = f"{command_path} {executable}".lower()
    if "pipx" in combined:
        return "pipx upgrade orewatch"
    return f"{shlex_quote(executable)} -m pip install --upgrade orewatch" if executable else "python -m pip install --upgrade orewatch"


def shlex_quote(value: str) -> str:
    """Local tiny quote helper to avoid importing shlex into menu-facing payloads."""
    if not value:
        return "''"
    safe = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_@%+=:,./-")
    if all(ch in safe for ch in value):
        return value
    return "'" + value.replace("'", "'\"'\"'") + "'"


def resolve_orewatch_version() -> str:
    """Return the installed OreWatch version, falling back to source metadata."""
    try:
        return importlib.metadata.version("orewatch")
    except importlib.metadata.PackageNotFoundError:
        pyproject_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "pyproject.toml",
        )
        try:
            with open(pyproject_path, "rb") as handle:
                pyproject = tomllib.load(handle)
            return str(pyproject.get("project", {}).get("version", "")).strip()
        except (OSError, tomllib.TOMLDecodeError):
            return ""


class PackageUpdateChecker:
    """Build update advisories for projects and OreWatch itself."""

    def __init__(self, timeout_ms: int = 5000):
        self.timeout_ms = int(timeout_ms)

    def check_project(self, project_path: str) -> Dict[str, Any]:
        """Return active package update advisories for one project path."""
        project_path = os.path.realpath(os.path.abspath(project_path))
        registry = RegistryClient(timeout_ms=self.timeout_ms)
        candidates = self._collect_project_candidates(project_path)
        advisories: List[Dict[str, Any]] = []
        errors: List[Dict[str, str]] = []
        for candidate in candidates:
            latest = registry.latest(candidate["ecosystem"], candidate["package_name"])
            latest_version = str(latest.get("latest_version", "")).strip()
            if not latest_version:
                errors.append(
                    {
                        "ecosystem": candidate["ecosystem"],
                        "package_name": candidate["package_name"],
                        "error": str(latest.get("error", "latest version unavailable")),
                    }
                )
                continue
            if not is_newer_version(latest_version, candidate["current_version"]):
                continue
            advisories.append(
                self._build_advisory(
                    project_path=project_path,
                    ecosystem=candidate["ecosystem"],
                    package_name=candidate["package_name"],
                    current_version=candidate["current_version"],
                    latest_version=latest_version,
                    manifest_path=candidate["manifest_path"],
                    source_type=candidate["source_type"],
                    registry_url=str(latest.get("registry_url", "")),
                    package_url=str(latest.get("package_url", "")),
                    update_command=_update_command(
                        candidate["ecosystem"],
                        candidate["package_name"],
                        latest_version,
                    ),
                )
            )
        return {
            "project_path": project_path,
            "advisories": advisories,
            "errors": errors,
            "checked_packages": len(candidates),
        }

    def check_self(self, monitor_home: str) -> Dict[str, Any]:
        """Return an OreWatch self-update advisory when a newer release exists."""
        current_version = resolve_orewatch_version()
        if not current_version:
            return {
                "project_path": os.path.realpath(monitor_home),
                "advisories": [],
                "errors": [{"ecosystem": SELF_UPDATE_ECOSYSTEM, "package_name": "orewatch", "error": "current version unavailable"}],
                "checked_packages": 0,
            }
        registry = RegistryClient(timeout_ms=self.timeout_ms)
        latest = registry.latest("pypi", "orewatch")
        latest_version = str(latest.get("latest_version", "")).strip()
        if not latest_version:
            return {
                "project_path": os.path.realpath(monitor_home),
                "advisories": [],
                "errors": [{"ecosystem": SELF_UPDATE_ECOSYSTEM, "package_name": "orewatch", "error": str(latest.get("error", "latest version unavailable"))}],
                "checked_packages": 1,
            }
        if not is_newer_version(latest_version, current_version):
            return {
                "project_path": os.path.realpath(monitor_home),
                "advisories": [],
                "errors": [],
                "checked_packages": 1,
            }
        advisory = self._build_advisory(
            project_path=os.path.realpath(monitor_home),
            ecosystem=SELF_UPDATE_ECOSYSTEM,
            package_name="orewatch",
            current_version=current_version,
            latest_version=latest_version,
            manifest_path="",
            source_type="self",
            registry_url=str(latest.get("registry_url", "")),
            package_url=str(latest.get("package_url", "")),
            update_command=_self_update_command(),
        )
        advisory["details"]["self_update"] = True
        return {
            "project_path": os.path.realpath(monitor_home),
            "advisories": [advisory],
            "errors": [],
            "checked_packages": 1,
        }

    def _collect_project_candidates(self, project_path: str) -> List[Dict[str, str]]:
        selected: Dict[Tuple[str, str], Dict[str, str]] = {}
        for ecosystem in ECOSYSTEM_PRIORITY:
            for dependency_file in find_dependency_files(project_path, ecosystem):
                source_type = _source_type_for_file(dependency_file)
                try:
                    dependencies = parse_dependencies(dependency_file, ecosystem)
                except Exception as exc:
                    logger.debug("Skipping unparseable dependency file %s: %s", dependency_file, exc)
                    continue
                for dependency in dependencies:
                    package_name = str(dependency.get("name", "") or "").strip()
                    if not package_name:
                        continue
                    raw_version = str(dependency.get("version", "") or "").strip()
                    current_version = resolve_exact_version(
                        requested_spec=raw_version,
                        resolved_version=raw_version,
                    )
                    if not current_version:
                        continue
                    candidate = {
                        "ecosystem": ecosystem,
                        "package_name": package_name,
                        "current_version": current_version,
                        "manifest_path": _dependency_manifest_path(dependency, dependency_file),
                        "source_type": source_type,
                    }
                    key = (ecosystem, package_name.lower())
                    existing = selected.get(key)
                    if existing is None or _candidate_rank(candidate) > _candidate_rank(existing):
                        selected[key] = candidate
        return sorted(
            selected.values(),
            key=lambda item: (item["ecosystem"], item["package_name"].lower()),
        )

    def _build_advisory(
        self,
        project_path: str,
        ecosystem: str,
        package_name: str,
        current_version: str,
        latest_version: str,
        manifest_path: str,
        source_type: str,
        registry_url: str,
        package_url: str,
        update_command: str,
    ) -> Dict[str, Any]:
        fingerprint = advisory_fingerprint(
            ecosystem,
            package_name,
            current_version,
            manifest_path,
            source_type,
        )
        return {
            "project_path": os.path.realpath(project_path),
            "fingerprint": fingerprint,
            "ecosystem": ecosystem,
            "package_name": package_name,
            "current_version": current_version,
            "latest_version": latest_version,
            "manifest_path": os.path.realpath(manifest_path) if manifest_path else "",
            "source_type": source_type,
            "registry_url": registry_url,
            "package_url": package_url,
            "update_command": update_command,
            "details": {
                "project_name": os.path.basename(os.path.realpath(project_path)) or project_path,
                "self_update": ecosystem == SELF_UPDATE_ECOSYSTEM,
            },
        }
