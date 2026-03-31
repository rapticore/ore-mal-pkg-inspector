#!/usr/bin/env python3
"""
Per-project policy handling and finding filtering.
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import Dict, List

import yaml


SEVERITY_RANK = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


DEFAULT_PROJECT_POLICY = {
    "severity_threshold": "low",
    "notify_on": ["malicious_package", "ioc"],
    "strict_data": False,
    "include_experimental_sources": False,
    "quick_scan_interval_seconds": 6 * 60 * 60,
    "full_scan_interval_seconds": 24 * 60 * 60,
    "ignored_fingerprints": [],
    "ignored_packages": [],
    "ignored_ioc_types": [],
}


def _merge_dicts(base: Dict, override: Dict) -> Dict:
    """Recursively merge dictionaries."""
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge_dicts(merged[key], value)
        else:
            merged[key] = value
    return merged


def severity_rank(severity: str) -> int:
    """Return an integer severity rank."""
    return SEVERITY_RANK.get((severity or "low").lower(), 0)


def load_project_policy(project_path: str, monitor_config: Dict) -> Dict:
    """Load the effective project policy."""
    defaults = _merge_dicts(DEFAULT_PROJECT_POLICY, monitor_config.get("defaults", {}))
    policy_path = os.path.join(project_path, ".ore-monitor.yml")
    if not os.path.exists(policy_path):
        return defaults

    with open(policy_path, "r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle) or {}

    return _merge_dicts(defaults, loaded)


def fingerprint_finding(finding_type: str, payload: Dict) -> str:
    """Create a stable fingerprint for one finding."""
    if finding_type == "malicious_package":
        canonical = {
            "finding_type": finding_type,
            "ecosystem": payload.get("ecosystem", ""),
            "name": payload.get("name", ""),
            "version": payload.get("version", ""),
        }
    else:
        canonical = {
            "finding_type": finding_type,
            "type": payload.get("type", ""),
            "path": payload.get("path", ""),
            "hash": payload.get("hash", ""),
            "pattern": payload.get("pattern", ""),
            "variant": payload.get("variant", ""),
            "url": payload.get("url", ""),
            "filename": payload.get("filename", ""),
        }

    digest = hashlib.sha256(
        json.dumps(canonical, sort_keys=True).encode("utf-8")
    ).hexdigest()
    return digest


def _build_title(finding_type: str, payload: Dict) -> str:
    """Build a concise finding title."""
    if finding_type == "malicious_package":
        version = payload.get("version")
        if version:
            return f"Malicious package {payload.get('name')}@{version}"
        return f"Malicious package {payload.get('name')}"
    return f"IoC {payload.get('type')} at {payload.get('path')}"


def build_tracked_findings(scan_result, project_policy: Dict) -> List[Dict]:
    """Convert a scan result into tracked finding records."""
    findings: List[Dict] = []
    threshold = severity_rank(project_policy.get("severity_threshold", "low"))
    ignored_fingerprints = set(project_policy.get("ignored_fingerprints", []))
    ignored_packages = set(project_policy.get("ignored_packages", []))
    ignored_ioc_types = set(project_policy.get("ignored_ioc_types", []))

    for pkg in scan_result.malicious_packages:
        payload = dict(pkg)
        payload.setdefault("ecosystem", pkg.get("ecosystem") or scan_result.ecosystem)
        if payload.get("name") in ignored_packages:
            continue
        severity = (payload.get("severity") or "high").lower()
        if severity_rank(severity) < threshold:
            continue
        fingerprint = fingerprint_finding("malicious_package", payload)
        if fingerprint in ignored_fingerprints:
            continue
        findings.append(
            {
                "fingerprint": fingerprint,
                "finding_type": "malicious_package",
                "severity": severity,
                "title": _build_title("malicious_package", payload),
                "payload": payload,
            }
        )

    for ioc in scan_result.iocs:
        payload = dict(ioc)
        if payload.get("type") in ignored_ioc_types:
            continue
        severity = (payload.get("severity") or "high").lower()
        if severity_rank(severity) < threshold:
            continue
        fingerprint = fingerprint_finding("ioc", payload)
        if fingerprint in ignored_fingerprints:
            continue
        findings.append(
            {
                "fingerprint": fingerprint,
                "finding_type": "ioc",
                "severity": severity,
                "title": _build_title("ioc", payload),
                "payload": payload,
            }
        )

    return findings
