#!/usr/bin/env python3
"""
Polling watcher for dependency and IoC-sensitive files.
"""

from __future__ import annotations

import os
from typing import Dict, List

from scanners.ioc_detector import SHAI_HULUD_IOCS
from scanners.supported_files import SKIP_DIRS, get_supported_manifest_filenames


MANIFEST_FILENAMES = set(get_supported_manifest_filenames())
IOC_WATCH_FILENAMES = set(SHAI_HULUD_IOCS["payload_files"]) | set(SHAI_HULUD_IOCS["data_files"])
WORKFLOW_PREFIX = os.path.join(".github", "workflows")


def categorize_path(relative_path: str) -> str:
    """Return the watcher category for one relative path."""
    normalized = relative_path.replace("\\", "/")
    basename = os.path.basename(relative_path)
    if basename in MANIFEST_FILENAMES:
        if basename == "package.json":
            return "manifest_with_ioc_risk"
        return "manifest"
    if normalized.startswith(".github/workflows/") and normalized.endswith((".yml", ".yaml")):
        return "workflow"
    if basename in IOC_WATCH_FILENAMES:
        return "ioc_payload"
    return ""


def take_project_snapshot(project_path: str) -> Dict[str, Dict]:
    """Build a polling snapshot for one project."""
    snapshot: Dict[str, Dict] = {}

    for root, dirs, files in os.walk(project_path):
        dirs[:] = [dirname for dirname in dirs if dirname not in SKIP_DIRS]
        for filename in files:
            absolute_path = os.path.join(root, filename)
            relative_path = os.path.relpath(absolute_path, project_path)
            category = categorize_path(relative_path)
            if not category:
                continue
            stat_info = os.stat(absolute_path)
            snapshot[relative_path] = {
                "category": category,
                "mtime": stat_info.st_mtime,
                "size": stat_info.st_size,
            }

    return snapshot


def detect_changes(previous: Dict[str, Dict], current: Dict[str, Dict]) -> List[Dict]:
    """Compare two snapshots and return changed paths."""
    changes: List[Dict] = []
    all_paths = set(previous) | set(current)
    for relative_path in sorted(all_paths):
        old = previous.get(relative_path)
        new = current.get(relative_path)
        if old is None and new is not None:
            changes.append(
                {
                    "relative_path": relative_path,
                    "category": new["category"],
                    "action": "created",
                }
            )
            continue
        if old is not None and new is None:
            changes.append(
                {
                    "relative_path": relative_path,
                    "category": old["category"],
                    "action": "deleted",
                }
            )
            continue
        if old and new and (
            old["mtime"] != new["mtime"] or old["size"] != new["size"]
        ):
            changes.append(
                {
                    "relative_path": relative_path,
                    "category": new["category"],
                    "action": "modified",
                }
            )

    return changes
