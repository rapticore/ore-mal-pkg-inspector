#!/usr/bin/env python3
"""
Configuration helpers for the local monitor.
"""

from __future__ import annotations

import copy
import hashlib
import os
import sys
from typing import Any, Dict, Optional

import yaml


APP_NAME = "orewatch"
APP_DISPLAY_NAME = "OreWatch"
OREWATCH_CONFIG_HOME_ENV = "OREWATCH_CONFIG_HOME"
OREWATCH_STATE_HOME_ENV = "OREWATCH_STATE_HOME"
OWNER_ONLY_DIR_MODE = 0o700
OWNER_ONLY_FILE_MODE = 0o600

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
        "use_live_collection_fallback": False,
    },
    "notifications": {
        "desktop": True,
        "terminal": True,
        "notify_on_resolved": False,
    },
    "policy": {
        "allow_project_file": False,
        "allow_project_suppressions": False,
    },
}


def ensure_owner_only_permissions(path: str, mode: int) -> None:
    """Best-effort chmod for files and directories that store monitor state."""
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def ensure_not_symlink(path: str, description: str) -> None:
    """Refuse to use symlinked monitor-managed paths or parent components."""
    normalized = os.path.abspath(os.path.expanduser(path))
    current = os.path.sep if normalized.startswith(os.path.sep) else ""
    for component in [part for part in normalized.split(os.sep) if part]:
        current = os.path.join(current, component) if current else component
        if os.path.lexists(current) and os.path.islink(current):
            raise RuntimeError(f"Refusing to use symlinked {description}: {current}")


def get_repo_root(explicit_root: Optional[str] = None) -> str:
    """Return the repository root used by the monitor."""
    if explicit_root:
        return os.path.abspath(explicit_root)
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _safe_instance_name(repo_root: str) -> str:
    """Return a stable per-repository storage key."""
    normalized_root = os.path.abspath(repo_root)
    basename = os.path.basename(normalized_root.rstrip(os.sep)) or "repo"
    safe_basename = "".join(ch if ch.isalnum() or ch in "-_." else "-" for ch in basename)
    digest = hashlib.sha1(normalized_root.encode("utf-8")).hexdigest()[:12]
    return f"{safe_basename}-{digest}"


def _expand_base_path(path: str) -> str:
    expanded = os.path.abspath(os.path.expanduser(path))
    if os.path.lexists(expanded) and os.path.islink(expanded):
        raise RuntimeError(f"Refusing to use symlinked monitor root: {expanded}")
    return os.path.realpath(expanded)


def get_monitor_config_root() -> str:
    """Return the user-owned config root for monitor instances."""
    override = os.environ.get(OREWATCH_CONFIG_HOME_ENV)
    if override:
        return _expand_base_path(override)
    if sys.platform == "darwin":
        return os.path.join(
            os.path.expanduser("~/Library/Application Support"),
            APP_DISPLAY_NAME,
        )
    xdg_config_home = os.environ.get("XDG_CONFIG_HOME")
    if xdg_config_home:
        return os.path.join(_expand_base_path(xdg_config_home), APP_NAME)
    return os.path.join(os.path.expanduser("~/.config"), APP_NAME)


def get_monitor_state_root() -> str:
    """Return the user-owned state root for monitor instances."""
    override = os.environ.get(OREWATCH_STATE_HOME_ENV)
    if override:
        return _expand_base_path(override)
    if sys.platform == "darwin":
        return os.path.join(
            os.path.expanduser("~/Library/Application Support"),
            APP_DISPLAY_NAME,
            "State",
        )
    xdg_state_home = os.environ.get("XDG_STATE_HOME")
    if xdg_state_home:
        return os.path.join(_expand_base_path(xdg_state_home), APP_NAME)
    return os.path.join(os.path.expanduser("~/.local/state"), APP_NAME)


def get_monitor_home(repo_root: Optional[str] = None) -> str:
    """Return the user-owned state directory for one repository monitor instance."""
    return os.path.join(
        get_monitor_state_root(),
        "instances",
        _safe_instance_name(get_repo_root(repo_root)),
    )


def get_monitor_paths(repo_root: Optional[str] = None) -> Dict[str, str]:
    """Return monitor-managed filesystem paths."""
    normalized_repo_root = get_repo_root(repo_root)
    instance_name = _safe_instance_name(normalized_repo_root)
    config_home = os.path.join(get_monitor_config_root(), "instances", instance_name)
    state_home = get_monitor_home(normalized_repo_root)
    return {
        "config_home": config_home,
        "home": state_home,
        "state_home": state_home,
        "config": os.path.join(config_home, "config.yaml"),
        "state_db": os.path.join(state_home, "state.db"),
        "pid": os.path.join(state_home, "run", "monitor.pid"),
        "reports": os.path.join(state_home, "reports"),
        "services": os.path.join(config_home, "services"),
        "snapshots": os.path.join(state_home, "snapshots"),
        "logs": os.path.join(state_home, "logs"),
        "log_file": os.path.join(state_home, "logs", "monitor.log"),
        "repo_root": normalized_repo_root,
        "instance_name": instance_name,
    }


def ensure_monitor_layout(repo_root: Optional[str] = None) -> Dict[str, str]:
    """Create the user-owned monitor directory layout if it does not exist."""
    paths = get_monitor_paths(repo_root)
    for directory in (
        os.path.dirname(paths["config_home"]),
        paths["config_home"],
        paths["home"],
        os.path.dirname(paths["pid"]),
        paths["reports"],
        paths["services"],
        paths["snapshots"],
        paths["logs"],
    ):
        ensure_not_symlink(directory, "monitor directory")
        os.makedirs(directory, mode=OWNER_ONLY_DIR_MODE, exist_ok=True)
        ensure_owner_only_permissions(directory, OWNER_ONLY_DIR_MODE)
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
    ensure_not_symlink(paths["config"], "monitor config file")
    if not os.path.exists(paths["config"]):
        save_monitor_config(copy.deepcopy(DEFAULT_CONFIG), repo_root)
        return copy.deepcopy(DEFAULT_CONFIG)

    with open(paths["config"], "r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle) or {}

    return _deep_merge(DEFAULT_CONFIG, loaded)


def save_monitor_config(config: Dict[str, Any], repo_root: Optional[str] = None) -> str:
    """Persist the monitor config to disk."""
    paths = ensure_monitor_layout(repo_root)
    ensure_not_symlink(paths["config"], "monitor config file")
    with open(paths["config"], "w", encoding="utf-8") as handle:
        yaml.safe_dump(config, handle, sort_keys=False)
    ensure_owner_only_permissions(paths["config"], OWNER_ONLY_FILE_MODE)
    return paths["config"]
