#!/usr/bin/env python3
"""
Scheduling helpers for periodic and event-driven scans.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List, Optional


def parse_timestamp(value: Optional[str]) -> Optional[datetime]:
    """Parse an ISO-8601 UTC timestamp."""
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def should_run(last_timestamp: Optional[str], interval_seconds: int, now: Optional[datetime] = None) -> bool:
    """Return True when the interval has elapsed."""
    now = now or datetime.now(timezone.utc)
    last_run = parse_timestamp(last_timestamp)
    if last_run is None:
        return True
    return (now - last_run).total_seconds() >= interval_seconds


def determine_periodic_scan_kind(project_record: Dict, project_policy: Dict, now: Optional[datetime] = None) -> Optional[str]:
    """Return the due periodic scan kind, if any."""
    now = now or datetime.now(timezone.utc)
    full_interval = int(project_policy.get("full_scan_interval_seconds", 24 * 60 * 60))
    quick_interval = int(project_policy.get("quick_scan_interval_seconds", 6 * 60 * 60))

    if should_run(project_record.get("last_full_scan_at"), full_interval, now):
        return "full"

    last_quick = project_record.get("last_quick_scan_at") or project_record.get("last_full_scan_at")
    if should_run(last_quick, quick_interval, now):
        return "quick"

    return None


def queue_change(
    pending_changes: Dict[str, Dict],
    project_path: str,
    changes: List[Dict],
    debounce_seconds: int,
    now_monotonic: float,
) -> None:
    """Queue a file-change batch for debounced execution."""
    entry = pending_changes.setdefault(
        project_path,
        {
            "deadline": now_monotonic + debounce_seconds,
            "categories": set(),
            "paths": set(),
            "changes": [],
        },
    )
    entry["deadline"] = now_monotonic + debounce_seconds
    for change in changes:
        entry["categories"].add(change["category"])
        entry["paths"].add(change["relative_path"])
        entry["changes"].append(change)


def consume_ready_changes(pending_changes: Dict[str, Dict], now_monotonic: float) -> List[Dict]:
    """Return debounced file-change jobs that are ready to run."""
    ready_jobs: List[Dict] = []
    ready_paths = [
        project_path
        for project_path, metadata in pending_changes.items()
        if metadata["deadline"] <= now_monotonic
    ]

    for project_path in ready_paths:
        metadata = pending_changes.pop(project_path)
        categories = metadata["categories"]
        if {"workflow", "ioc_payload", "manifest_with_ioc_risk"} & categories:
            scan_kind = "full"
        else:
            scan_kind = "quick"
        ready_jobs.append(
            {
                "project_path": project_path,
                "scan_kind": scan_kind,
                "reason": "file-change",
                "changed_paths": sorted(metadata["paths"]),
            }
        )

    return ready_jobs
