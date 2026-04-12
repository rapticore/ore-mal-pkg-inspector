#!/usr/bin/env python3
"""
Configuration helpers for the local monitor.
"""

from __future__ import annotations

import copy
import hashlib
import os
import secrets
import socket
import sys
from typing import Any, Dict, Optional

import yaml

from collectors.live_update import DEFAULT_LIVE_UPDATE_CONFIG


APP_NAME = "orewatch"
APP_DISPLAY_NAME = "OreWatch"
OREWATCH_CONFIG_HOME_ENV = "OREWATCH_CONFIG_HOME"
OREWATCH_STATE_HOME_ENV = "OREWATCH_STATE_HOME"
SINGLETON_MONITOR_SCOPE = "singleton"
LEGACY_INSTANCES_DIRNAME = "instances"
OWNER_ONLY_DIR_MODE = 0o700
OWNER_ONLY_FILE_MODE = 0o600
API_PORT_BASE = 48000
API_PORT_RANGE = 10000

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
    "api": {
        "enabled": True,
        "host": "127.0.0.1",
        "port": 48736,
        "request_timeout_ms": 5000,
        "auto_start_on_client": True,
        "override_ttl_seconds": 600,
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
        "auto_launch_menubar": sys.platform == "darwin",
        "popup_via_menubar": sys.platform == "darwin",
        "notify_on_resolved": False,
        "webhook_url": "",
        "webhook_format": "generic",
        "webhook_timeout_ms": 5000,
        "webhook_headers": {},
    },
    "policy": {
        "allow_project_file": False,
        "allow_project_suppressions": False,
    },
    "live_updates": copy.deepcopy(DEFAULT_LIVE_UPDATE_CONFIG),
}


def allocate_api_port(host: str = "127.0.0.1") -> int:
    """Ask the OS for a currently available localhost port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as handle:
        handle.bind((host, 0))
        return int(handle.getsockname()[1])


def _default_api_port_for_instance(instance_name: str) -> int:
    """Return a stable, per-workspace default API port without binding a socket."""
    digest = hashlib.sha256(instance_name.encode("utf-8")).hexdigest()
    return API_PORT_BASE + (int(digest[:8], 16) % API_PORT_RANGE)


def ensure_owner_only_permissions(path: str, mode: int) -> None:
    """Best-effort chmod for files and directories that store monitor state."""
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def ensure_not_symlink(path: str, description: str) -> None:
    """Refuse to use a symlink for the requested monitor-managed path itself."""
    normalized = os.path.abspath(os.path.expanduser(path))
    if os.path.lexists(normalized) and os.path.islink(normalized):
        raise RuntimeError(f"Refusing to use symlinked {description}: {normalized}")


def get_repo_root(explicit_root: Optional[str] = None) -> str:
    """Return the package code root or an explicit compatibility workspace root."""
    if explicit_root:
        return os.path.abspath(explicit_root)
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _safe_instance_name(repo_root: str) -> str:
    """Return a stable per-repository storage key."""
    normalized_root = os.path.abspath(repo_root)
    basename = os.path.basename(normalized_root.rstrip(os.sep)) or "repo"
    safe_basename = "".join(ch if ch.isalnum() or ch in "-_." else "-" for ch in basename)
    digest = hashlib.sha256(normalized_root.encode("utf-8")).hexdigest()[:12]
    return f"{safe_basename}-{digest}"


def _path_is_within(base: str, candidate: str) -> bool:
    """Return True when *candidate* is equal to or nested under *base*."""
    return candidate == base or candidate.startswith(base + os.sep)


def _check_path_components_for_symlinks(path: str, allowed_root: str) -> None:
    """Walk each component of *path* and reject symlinks that escape *allowed_root*."""
    current = path
    checked: set[str] = set()
    while True:
        if current in checked:
            break
        checked.add(current)
        if os.path.islink(current):
            target_real = os.path.realpath(current)
            if not _path_is_within(allowed_root, target_real):
                raise RuntimeError(
                    f"Refusing to follow symlink that escapes {allowed_root}: {current} -> {target_real}"
                )
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent


def _expand_base_path(path: str) -> str:
    expanded = os.path.abspath(os.path.expanduser(path))
    if os.path.lexists(expanded) and os.path.islink(expanded):
        raise RuntimeError(f"Refusing to use symlinked monitor root: {expanded}")
    resolved = os.path.realpath(expanded)
    home_real = os.path.realpath(os.path.expanduser("~"))
    # Only apply the ancestor symlink walk to home-scoped paths. Explicit
    # overrides may legitimately live under system temp roots such as /tmp or
    # macOS /var -> /private/var aliases.
    if _path_is_within(home_real, expanded) or _path_is_within(home_real, resolved):
        _check_path_components_for_symlinks(expanded, home_real)
    return resolved


def _validate_path_within_user_home(path: str, description: str) -> str:
    """Ensure a resolved path is within the user's home directory."""
    resolved = os.path.realpath(os.path.abspath(os.path.expanduser(path)))
    home_real = os.path.realpath(os.path.expanduser("~"))
    if not _path_is_within(home_real, resolved):
        raise RuntimeError(
            f"Refusing to use {description} outside user home: {resolved}"
        )
    return resolved


def get_monitor_config_root() -> str:
    """Return the user-owned config root for monitor instances."""
    override = os.environ.get(OREWATCH_CONFIG_HOME_ENV)
    if override:
        return _expand_base_path(override)
    if sys.platform == "darwin":
        base = os.path.join(
            os.path.expanduser("~/Library/Application Support"),
            APP_DISPLAY_NAME,
        )
        return _validate_path_within_user_home(base, "config root")
    xdg_config_home = os.environ.get("XDG_CONFIG_HOME")
    if xdg_config_home:
        safe_base = _expand_base_path(xdg_config_home)
        result = os.path.join(safe_base, APP_NAME)
        return _validate_path_within_user_home(result, "XDG config root")
    default_path = os.path.join(os.path.expanduser("~/.config"), APP_NAME)
    return _validate_path_within_user_home(default_path, "config root")


def get_monitor_state_root() -> str:
    """Return the user-owned state root for monitor instances."""
    override = os.environ.get(OREWATCH_STATE_HOME_ENV)
    if override:
        return _expand_base_path(override)
    if sys.platform == "darwin":
        base = os.path.join(
            os.path.expanduser("~/Library/Application Support"),
            APP_DISPLAY_NAME,
            "State",
        )
        return _validate_path_within_user_home(base, "state root")
    xdg_state_home = os.environ.get("XDG_STATE_HOME")
    if xdg_state_home:
        safe_base = _expand_base_path(xdg_state_home)
        result = os.path.join(safe_base, APP_NAME)
        return _validate_path_within_user_home(result, "XDG state root")
    default_path = os.path.join(os.path.expanduser("~/.local/state"), APP_NAME)
    return _validate_path_within_user_home(default_path, "state root")


def get_monitor_home(repo_root: Optional[str] = None) -> str:
    """Return the user-owned singleton state directory."""
    del repo_root
    return os.path.join(get_monitor_state_root(), SINGLETON_MONITOR_SCOPE)


def get_singleton_final_data_dir() -> str:
    """Return the shared final-data directory for the singleton monitor."""
    return os.path.join(get_monitor_home(), "threat-data", "final-data")


def get_legacy_monitor_home(repo_root: Optional[str] = None) -> str:
    """Return the legacy per-workspace state directory."""
    return os.path.join(
        get_monitor_state_root(),
        LEGACY_INSTANCES_DIRNAME,
        _safe_instance_name(get_repo_root(repo_root)),
    )


def get_legacy_monitor_paths(repo_root: Optional[str] = None) -> Dict[str, str]:
    """Return legacy per-workspace filesystem paths."""
    normalized_repo_root = get_repo_root(repo_root)
    instance_name = _safe_instance_name(normalized_repo_root)
    config_home = os.path.join(get_monitor_config_root(), LEGACY_INSTANCES_DIRNAME, instance_name)
    state_home = get_legacy_monitor_home(normalized_repo_root)
    return {
        "config_home": config_home,
        "home": state_home,
        "state_home": state_home,
        "config": os.path.join(config_home, "config.yaml"),
        "api_token": os.path.join(config_home, "api.token"),
        "state_db": os.path.join(state_home, "state.db"),
        "pid": os.path.join(state_home, "run", "monitor.pid"),
        "lock": os.path.join(state_home, "run", "monitor.lock"),
        "menubar_pid": os.path.join(state_home, "run", "menubar.pid"),
        "menubar_lock": os.path.join(state_home, "run", "menubar.lock"),
        "reports": os.path.join(state_home, "reports"),
        "services": os.path.join(config_home, "services"),
        "snapshots": os.path.join(state_home, "snapshots"),
        "logs": os.path.join(state_home, "logs"),
        "log_file": os.path.join(state_home, "logs", "monitor.log"),
        "repo_root": normalized_repo_root,
        "instance_name": instance_name,
    }


def iter_legacy_monitor_paths() -> list[Dict[str, str]]:
    """Return existing legacy monitor instance paths without mutating them."""
    config_instances_root = os.path.join(get_monitor_config_root(), LEGACY_INSTANCES_DIRNAME)
    state_instances_root = os.path.join(get_monitor_state_root(), LEGACY_INSTANCES_DIRNAME)
    candidates = []
    instance_names = set()
    for root in (config_instances_root, state_instances_root):
        if not os.path.isdir(root):
            continue
        ensure_not_symlink(root, "legacy monitor instances root")
        for entry in os.listdir(root):
            instance_names.add(entry)

    for instance_name in sorted(instance_names):
        config_home = os.path.join(config_instances_root, instance_name)
        state_home = os.path.join(state_instances_root, instance_name)
        candidates.append(
            {
                "config_home": config_home,
                "state_home": state_home,
                "config": os.path.join(config_home, "config.yaml"),
                "state_db": os.path.join(state_home, "state.db"),
                "instance_name": instance_name,
            }
        )
    return candidates


def get_monitor_paths(repo_root: Optional[str] = None) -> Dict[str, str]:
    """Return singleton monitor-managed filesystem paths."""
    requested_workspace_root = get_repo_root(repo_root)
    config_home = os.path.join(get_monitor_config_root(), SINGLETON_MONITOR_SCOPE)
    state_home = get_monitor_home()
    threat_data_home = os.path.join(state_home, "threat-data")
    final_data_dir = os.path.join(threat_data_home, "final-data")
    return {
        "config_home": config_home,
        "home": state_home,
        "state_home": state_home,
        "config": os.path.join(config_home, "config.yaml"),
        "api_token": os.path.join(config_home, "api.token"),
        "state_db": os.path.join(state_home, "state.db"),
        "pid": os.path.join(state_home, "run", "monitor.pid"),
        "lock": os.path.join(state_home, "run", "monitor.lock"),
        "menubar_pid": os.path.join(state_home, "run", "menubar.pid"),
        "menubar_lock": os.path.join(state_home, "run", "menubar.lock"),
        "reports": os.path.join(state_home, "reports"),
        "services": os.path.join(config_home, "services"),
        "snapshots": os.path.join(state_home, "snapshots"),
        "logs": os.path.join(state_home, "logs"),
        "log_file": os.path.join(state_home, "logs", "monitor.log"),
        "repo_root": requested_workspace_root,
        "workspace_root": requested_workspace_root,
        "requested_workspace_root": requested_workspace_root,
        "instance_name": SINGLETON_MONITOR_SCOPE,
        "monitor_scope": SINGLETON_MONITOR_SCOPE,
        "monitor_home": state_home,
        "threat_data_home": threat_data_home,
        "final_data_dir": final_data_dir,
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
        paths["threat_data_home"],
        paths["final_data_dir"],
    ):
        ensure_not_symlink(directory, "monitor directory")
        os.makedirs(directory, mode=OWNER_ONLY_DIR_MODE, exist_ok=True)
        ensure_owner_only_permissions(directory, OWNER_ONLY_DIR_MODE)
    return paths


def _port_used_by_other_instance(config_root: str, instance_name: str, port: int) -> bool:
    """Return True when another workspace config already claims this API port."""
    instances_root = os.path.join(config_root, "instances")
    if not os.path.isdir(instances_root):
        return False
    for candidate_name in os.listdir(instances_root):
        if candidate_name == instance_name:
            continue
        candidate_path = os.path.join(instances_root, candidate_name, "config.yaml")
        if not os.path.exists(candidate_path):
            continue
        try:
            with open(candidate_path, "r", encoding="utf-8") as handle:
                candidate = yaml.safe_load(handle) or {}
        except OSError:
            continue
        try:
            candidate_port = int(candidate.get("api", {}).get("port", 0) or 0)
        except (TypeError, ValueError):
            candidate_port = 0
        if candidate_port == port:
            return True
    return False


def _normalize_api_port(
    config: Dict[str, Any],
    paths: Dict[str, str],
    loaded: Optional[Dict[str, Any]],
) -> tuple[Dict[str, Any], bool]:
    """Assign the singleton API port when config is missing or invalid."""
    loaded_port = loaded.get("api", {}).get("port") if loaded else None
    configured_port = config.get("api", {}).get("port")
    try:
        port = int(configured_port)
    except (TypeError, ValueError):
        port = 0

    needs_new_port = port <= 0 or loaded_port is None
    if not needs_new_port:
        return config, False

    normalized = copy.deepcopy(config)
    normalized.setdefault("api", {})["port"] = int(DEFAULT_CONFIG["api"]["port"])
    return normalized, True


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
        config = copy.deepcopy(DEFAULT_CONFIG)
        config, _ = _normalize_api_port(config, paths, loaded=None)
        save_monitor_config(config, repo_root)
        return config

    with open(paths["config"], "r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle) or {}

    merged = _deep_merge(DEFAULT_CONFIG, loaded)
    normalized, changed = _normalize_api_port(merged, paths, loaded=loaded)
    if changed:
        save_monitor_config(normalized, repo_root)
    return normalized


def save_monitor_config(config: Dict[str, Any], repo_root: Optional[str] = None) -> str:
    """Persist the monitor config to disk."""
    paths = ensure_monitor_layout(repo_root)
    ensure_not_symlink(paths["config"], "monitor config file")
    with open(paths["config"], "w", encoding="utf-8") as handle:
        yaml.safe_dump(config, handle, sort_keys=False)
    ensure_owner_only_permissions(paths["config"], OWNER_ONLY_FILE_MODE)
    return paths["config"]


def ensure_monitor_api_token(repo_root: Optional[str] = None) -> str:
    """Return the stable local API token for one monitor instance."""
    paths = ensure_monitor_layout(repo_root)
    token_path = paths["api_token"]
    ensure_not_symlink(token_path, "monitor api token")
    if os.path.exists(token_path):
        with open(token_path, "r", encoding="utf-8") as handle:
            token = handle.read().strip()
        if token:
            ensure_owner_only_permissions(token_path, OWNER_ONLY_FILE_MODE)
            return token

    # secrets.token_urlsafe(32) produces 32 random bytes (256 bits of entropy),
    # base64url-encoded to ~43 characters.  This exceeds the OWASP minimum of
    # 128 bits for session/API tokens.
    token = secrets.token_urlsafe(32)
    with open(token_path, "w", encoding="utf-8") as handle:
        handle.write(token)
    ensure_owner_only_permissions(token_path, OWNER_ONLY_FILE_MODE)
    return token


def load_monitor_api_token(repo_root: Optional[str] = None) -> str:
    """Load the monitor API token, generating it if needed."""
    return ensure_monitor_api_token(repo_root)
