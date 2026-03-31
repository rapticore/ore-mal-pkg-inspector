#!/usr/bin/env python3
"""
Configuration helpers for the local monitor.
"""

from __future__ import annotations

import copy
import os
from typing import Any, Dict, Optional

import yaml


MONITOR_DIRNAME = ".ore-monitor"

DEFAULT_CONFIG: Dict[str, Any] = {
    "version": 1,
    "defaults": {
        "severity_threshold": "low",
        "notify_on": ["malicious_package", "ioc"],
        "strict_data": False,
        "include_experimental_sources": False,
        "quick_scan_interval_seconds": 6 * 60 * 60,
        "full_scan_interval_seconds": 24 * 60 * 60,
        "ignored_fingerprints": [],
        "ignored_packages": [],
        "ignored_ioc_types": [],
    },
    "service": {
        "service_manager": "auto",
        "loop_interval_seconds": 5,
        "watcher_poll_interval_seconds": 5,
        "debounce_seconds": 5,
    },
    "snapshots": {
        "channel_url": "",
        "manifest_url": "",
        "public_key_path": "",
        "channel_name": "stable",
        "refresh_interval_seconds": 6 * 60 * 60,
        "use_live_collection_fallback": True,
    },
    "notifications": {
        "desktop": True,
        "terminal": True,
        "notify_on_resolved": False,
    },
}


def get_repo_root(explicit_root: Optional[str] = None) -> str:
    """Return the repository root used by the monitor."""
    if explicit_root:
        return os.path.abspath(explicit_root)
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def get_monitor_home(repo_root: Optional[str] = None) -> str:
    """Return the monitor home directory within the repository."""
    return os.path.join(get_repo_root(repo_root), MONITOR_DIRNAME)


def get_monitor_paths(repo_root: Optional[str] = None) -> Dict[str, str]:
    """Return monitor-managed filesystem paths."""
    home = get_monitor_home(repo_root)
    return {
        "home": home,
        "config": os.path.join(home, "config.yaml"),
        "state_db": os.path.join(home, "state.db"),
        "pid": os.path.join(home, "run", "monitor.pid"),
        "reports": os.path.join(home, "reports"),
        "services": os.path.join(home, "services"),
        "snapshots": os.path.join(home, "snapshots"),
        "logs": os.path.join(home, "logs"),
        "log_file": os.path.join(home, "logs", "monitor.log"),
    }


def ensure_monitor_layout(repo_root: Optional[str] = None) -> Dict[str, str]:
    """Create the monitor directory layout if it does not exist."""
    paths = get_monitor_paths(repo_root)
    os.makedirs(paths["home"], exist_ok=True)
    os.makedirs(os.path.dirname(paths["pid"]), exist_ok=True)
    os.makedirs(paths["reports"], exist_ok=True)
    os.makedirs(paths["services"], exist_ok=True)
    os.makedirs(paths["snapshots"], exist_ok=True)
    os.makedirs(paths["logs"], exist_ok=True)
    return paths


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively merge dictionaries without mutating inputs."""
    merged = copy.deepcopy(base)
    for key, value in override.items():
        if (
            isinstance(value, dict)
            and isinstance(merged.get(key), dict)
        ):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def load_monitor_config(repo_root: Optional[str] = None) -> Dict[str, Any]:
    """Load and merge the monitor config with defaults."""
    paths = ensure_monitor_layout(repo_root)
    if not os.path.exists(paths["config"]):
        save_monitor_config(copy.deepcopy(DEFAULT_CONFIG), repo_root)
        return copy.deepcopy(DEFAULT_CONFIG)

    with open(paths["config"], "r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle) or {}

    return _deep_merge(DEFAULT_CONFIG, loaded)


def save_monitor_config(config: Dict[str, Any], repo_root: Optional[str] = None) -> str:
    """Persist the monitor config to disk."""
    paths = ensure_monitor_layout(repo_root)
    with open(paths["config"], "w", encoding="utf-8") as handle:
        yaml.safe_dump(config, handle, sort_keys=False)
    return paths["config"]
