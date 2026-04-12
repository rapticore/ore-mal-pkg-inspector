#!/usr/bin/env python3
"""
Background monitor service runtime.
"""

from __future__ import annotations

import errno
import fcntl
import logging
import os
import shlex
import shutil
import signal
import sqlite3
import subprocess
import sys
import time
from contextlib import closing
from datetime import datetime, timezone
from typing import Dict, List, Optional

from collectors.orchestrator import get_database_statuses
from logging_config import setup_logging
from monitor.api import LocalMonitorAPIServer
from monitor.api import build_override_expiry
from monitor.api import make_check_id
from monitor.api import make_override_id
from monitor.api import normalize_dependency_input
from monitor.api import normalize_source_input
from monitor.api import resolve_exact_version
from monitor.api import supported_health_payload
from monitor.api import SUPPORTED_CLIENT_TYPES
from monitor.api import validate_client_request
from monitor.config import allocate_api_port
from monitor.config import ensure_monitor_api_token
from monitor.config import ensure_monitor_layout
from monitor.config import get_repo_root
from monitor.config import iter_legacy_monitor_paths
from monitor.config import load_monitor_config
from monitor.config import SINGLETON_MONITOR_SCOPE
from monitor.config import OWNER_ONLY_FILE_MODE
from monitor.config import ensure_owner_only_permissions
from monitor.config import ensure_not_symlink
from monitor.config import save_monitor_config
from monitor.ide_bootstrap import ALL_BOOTSTRAP_CLIENTS
from monitor.ide_bootstrap import build_mcp_server_definition
from monitor.menubar import count_unacknowledged_alert_notifications
from monitor.menubar import latest_attention_notification
from monitor.menubar import notification_is_visible
from monitor.notifier import Notifier
from monitor.policy import build_tracked_findings, load_project_policy, severity_rank
from monitor.scheduler import consume_ready_changes, determine_periodic_scan_kind, queue_change
from monitor.snapshot_updater import SnapshotUpdater
from monitor.state import MonitorState
from monitor.watcher import detect_changes, take_project_snapshot
from scanner_engine import ScanRequest, run_scan
from scanner_engine import summarize_requested_data_status
from scanners.dependency_parsers import parse_dependencies
from scanners.malicious_checker import MaliciousPackageChecker
from scanners import report_generator
from scanners.supported_files import ECOSYSTEM_PRIORITY
from scanners.supported_files import get_manifest_for_filename
from scanners.supported_files import get_supported_files_for_ecosystem


logger = logging.getLogger(__name__)
LAUNCHD_MANAGER = "launchd"
SYSTEMD_MANAGER = "systemd"
BACKGROUND_MANAGER = "background"
AUTO_MANAGER = "auto"
SUPPORTED_SEVERITIES = ("low", "medium", "high", "critical")
UNINSTALL_COMMANDS = {
    "npm": "npm uninstall {name}",
    "pypi": "pip uninstall {name}",
    "maven": "Remove {name} from pom.xml and run: mvn dependency:purge-local-repository",
    "rubygems": "gem uninstall {name}",
    "go": "go mod edit -droprequire {name} && go mod tidy",
    "cargo": "cargo remove {name}",
}


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_pid(pid_path: str) -> Optional[int]:
    """Read a PID file if it exists."""
    if not os.path.exists(pid_path):
        return None
    ensure_not_symlink(pid_path, "monitor pid file")
    try:
        with open(pid_path, "r", encoding="utf-8") as handle:
            return int(handle.read().strip())
    except (OSError, ValueError):
        return None


def pid_is_running(pid: Optional[int]) -> bool:
    """Return True when a PID appears to be alive."""
    if not pid:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


class RuntimeLock:
    """Advisory singleton lock for the monitor daemon runtime."""

    def __init__(self, lock_path: str):
        self.lock_path = lock_path
        self.handle = None

    def acquire(self, blocking: bool = False) -> bool:
        """Try to acquire the runtime lock."""
        if self.handle is not None:
            return True

        ensure_not_symlink(self.lock_path, "monitor runtime lock file")
        handle = open(self.lock_path, "a+", encoding="utf-8")
        ensure_owner_only_permissions(self.lock_path, OWNER_ONLY_FILE_MODE)
        flags = fcntl.LOCK_EX
        if not blocking:
            flags |= fcntl.LOCK_NB
        try:
            fcntl.flock(handle.fileno(), flags)
        except OSError as exc:
            handle.close()
            if exc.errno in {errno.EACCES, errno.EAGAIN}:
                return False
            raise

        self.handle = handle
        self._write_metadata()
        return True

    def _write_metadata(self) -> None:
        """Write lightweight metadata for debugging the active owner."""
        if self.handle is None:
            return
        self.handle.seek(0)
        self.handle.truncate()
        self.handle.write(f"pid={os.getpid()}\nstarted_at={_utcnow()}\n")
        self.handle.flush()
        os.fsync(self.handle.fileno())

    def release(self) -> None:
        """Release the runtime lock."""
        if self.handle is None:
            return
        try:
            self.handle.seek(0)
            self.handle.truncate()
            self.handle.flush()
        except OSError:
            pass
        try:
            fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
        finally:
            self.handle.close()
            self.handle = None


def _slugify_path(project_path: str) -> str:
    basename = os.path.basename(project_path.rstrip(os.sep)) or "project"
    digest = abs(hash(os.path.abspath(project_path))) % 100000
    safe_basename = "".join(ch if ch.isalnum() or ch in "-_." else "-" for ch in basename)
    return f"{safe_basename}-{digest}"


def _service_identity() -> Dict[str, str]:
    launchd_label = "org.orewatch.monitor"
    systemd_unit = "orewatch-monitor.service"
    return {
        "launchd_label": launchd_label,
        "systemd_unit": systemd_unit,
        "digest": SINGLETON_MONITOR_SCOPE,
    }


def _monitor_runtime_command(
    subcommand: str,
    python_executable: str,
) -> List[str]:
    """Build the OreWatch monitor command for the singleton daemon."""
    return [
        str(python_executable),
        "-m",
        "malicious_package_scanner",
        "monitor",
        subcommand,
    ]


def render_launchd_plist(
    working_directory: str,
    python_executable: str,
    label: str,
    log_file: str,
) -> str:
    """Render a launchd plist template."""
    program_arguments = _monitor_runtime_command("run", python_executable)
    program_arguments_xml = "\n".join(
        f"    <string>{argument}</string>" for argument in program_arguments
    )
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{label}</string>
  <key>ProgramArguments</key>
  <array>
{program_arguments_xml}
  </array>
  <key>WorkingDirectory</key>
  <string>{working_directory}</string>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>{log_file}</string>
  <key>StandardErrorPath</key>
  <string>{log_file}</string>
</dict>
</plist>
"""


def render_systemd_service(
    working_directory: str,
    python_executable: str,
    log_file: str,
) -> str:
    """Render a systemd user service template."""
    exec_start = shlex.join(_monitor_runtime_command("run", python_executable))
    return f"""[Unit]
Description=OreWatch monitor
After=network-online.target

[Service]
Type=simple
WorkingDirectory={working_directory}
ExecStart={exec_start}
Restart=always
RestartSec=10
StandardOutput=append:{log_file}
StandardError=append:{log_file}

[Install]
WantedBy=default.target
"""


class MonitorService:
    """Background monitor service."""

    def __init__(self, repo_root: Optional[str] = None):
        self.code_root = get_repo_root()
        self.requested_workspace_root = get_repo_root(repo_root)
        self.repo_root = self.requested_workspace_root
        self.monitor_scope = SINGLETON_MONITOR_SCOPE
        self.paths = ensure_monitor_layout(self.requested_workspace_root)
        self.config = load_monitor_config(self.requested_workspace_root)
        self.api_token = ensure_monitor_api_token(self.requested_workspace_root)
        self.state = MonitorState(self.paths["state_db"])
        self._migrate_legacy_instances_if_needed()
        self.notifier = Notifier(self.state, self.config, paths=self.paths)
        self.updater = SnapshotUpdater(
            self.code_root,
            self.paths["final_data_dir"],
            self.config,
            self.state,
            paths=self.paths,
        )
        self.package_checker = MaliciousPackageChecker(
            final_data_dir=self.paths["final_data_dir"]
        )
        self.pending_changes: Dict[str, Dict] = {}
        self.stop_requested = False
        self.identity = _service_identity()
        self.api_server: Optional[LocalMonitorAPIServer] = None
        self.runtime_lock = RuntimeLock(self.paths["lock"])
        self._last_menubar_ensure_monotonic = 0.0
        self.logger = logger
        self._configure_logging()

    def _migrate_legacy_instances_if_needed(self) -> None:
        """Import watched projects from legacy per-workspace monitor instances once."""
        migration_key = "singleton_legacy_watch_migration_v1"
        if self.state.get_agent_state(migration_key):
            return

        imported = 0
        source_dbs = 0
        last_error = ""
        for candidate in iter_legacy_monitor_paths():
            state_db = candidate["state_db"]
            if not os.path.exists(state_db):
                continue
            source_dbs += 1
            try:
                ensure_not_symlink(state_db, "legacy monitor state database")
                with closing(sqlite3.connect(state_db)) as conn:
                    conn.row_factory = sqlite3.Row
                    rows = conn.execute("SELECT * FROM watched_projects").fetchall()
            except sqlite3.OperationalError as exc:
                last_error = str(exc)
                logger.warning("Skipping legacy monitor state %s: %s", state_db, exc)
                continue
            except OSError as exc:
                last_error = str(exc)
                logger.warning("Skipping legacy monitor state %s: %s", state_db, exc)
                continue

            for row in rows:
                self.state.import_watched_project(dict(row))
                imported += 1

        self.state.set_agent_state(migration_key, _utcnow())
        self.state.set_agent_state("singleton_legacy_watch_imported_count", str(imported))
        self.state.set_agent_state("singleton_legacy_state_db_count", str(source_dbs))
        if last_error:
            self.state.set_agent_state("singleton_legacy_watch_last_error", last_error)

    def close(self) -> None:
        """Release transient resources held by this service object."""
        if self.api_server is not None and self.api_server.listening:
            self.stop_api_server()
        self.runtime_lock.release()
        self.package_checker.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def _configure_logging(self) -> None:
        setup_logging(logging.INFO)
        root_logger = logging.getLogger()
        log_file = self.paths["log_file"]
        ensure_not_symlink(log_file, "monitor log file")
        if not any(
            isinstance(handler, logging.FileHandler)
            and getattr(handler, "baseFilename", "") == os.path.abspath(log_file)
            for handler in root_logger.handlers
        ):
            try:
                file_handler = logging.FileHandler(log_file)
            except OSError as exc:
                logger.warning(
                    "OreWatch could not open the monitor log file at %s; continuing without file logging: %s",
                    log_file,
                    exc,
                )
                return
            file_handler.setLevel(logging.INFO)
            file_handler.setFormatter(
                logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
            )
            root_logger.addHandler(file_handler)
        if os.path.exists(log_file):
            ensure_owner_only_permissions(log_file, OWNER_ONLY_FILE_MODE)

    def _api_config(self) -> Dict[str, object]:
        """Return the configured API block."""
        return self.config.get("api", {})

    def _api_base_url(self) -> str:
        """Return the current API base URL."""
        host = str(self._api_config().get("host", "127.0.0.1"))
        port = int(self._api_config().get("port", 48736))
        if self.api_server is not None and self.api_server.listening:
            return self.api_server.base_url
        return f"http://{host}:{port}"

    def _menubar_status(self) -> Dict[str, object]:
        """Return the singleton macOS menu bar app runtime status."""
        pid = read_pid(self.paths["menubar_pid"])
        return {
            "menubar_pid": pid,
            "menubar_running": pid_is_running(pid),
            "menubar_pid_path": self.paths["menubar_pid"],
            "menubar_lock_path": self.paths["menubar_lock"],
        }

    def _should_auto_launch_menubar(self) -> bool:
        notifications = self.config.get("notifications", {}) or {}
        return (
            sys.platform == "darwin"
            and bool(notifications.get("desktop", True))
            and bool(notifications.get("auto_launch_menubar", True))
        )

    def _ensure_menubar_running_if_configured(self, force: bool = False) -> None:
        """Keep the macOS menu bar companion alive when desktop popups are enabled."""
        if not self._should_auto_launch_menubar():
            return
        if not force and (time.monotonic() - self._last_menubar_ensure_monotonic) < 30:
            return
        self._last_menubar_ensure_monotonic = time.monotonic()
        try:
            from monitor.menubar import launch_menubar_app_detached

            result = launch_menubar_app_detached(
                refresh_seconds=15.0,
                workspace_root=self.requested_workspace_root,
            )
            status = "success" if result.get("success", True) else "failed"
            self.state.set_agent_state("menubar_last_launch_status", status)
            self.state.set_agent_state(
                "menubar_last_launch_message",
                str(result.get("message", "")),
            )
            self.state.set_agent_state("menubar_last_launch_at", _utcnow())
        except Exception as exc:
            self.state.set_agent_state("menubar_last_launch_status", "failed")
            self.state.set_agent_state("menubar_last_launch_message", str(exc))
            self.state.set_agent_state("menubar_last_launch_at", _utcnow())
            logger.warning("OreWatch could not ensure the macOS menu bar app is running: %s", exc)

    def _reassign_api_port(self) -> int:
        """Persist a new API port for the singleton monitor after a bind conflict."""
        host = str(self._api_config().get("host", "127.0.0.1"))
        port = allocate_api_port(host)
        self.config.setdefault("api", {})["port"] = port
        save_monitor_config(self.config)
        return port

    def start_api_server(self) -> Optional[str]:
        """Start the localhost API if enabled."""
        if not self._api_config().get("enabled", True):
            self.state.set_agent_state("api_enabled", "false")
            self.state.set_agent_state("api_listening", "false")
            return None
        if self.api_server is None:
            self.api_server = LocalMonitorAPIServer(
                self,
                host=str(self._api_config().get("host", "127.0.0.1")),
                port=int(self._api_config().get("port", 48736)),
                api_token=self.api_token,
            )
        try:
            base_url = self.api_server.start()
        except OSError as exc:
            if exc.errno not in {48, 98}:
                raise
            self.api_server = LocalMonitorAPIServer(
                self,
                host=str(self._api_config().get("host", "127.0.0.1")),
                port=self._reassign_api_port(),
                api_token=self.api_token,
            )
            base_url = self.api_server.start()
        self.state.set_agent_state("api_enabled", "true")
        self.state.set_agent_state("api_listening", "true")
        self.state.set_agent_state("api_base_url", base_url)
        self.state.set_agent_state("api_last_started_at", _utcnow())
        return base_url

    def stop_api_server(self) -> None:
        """Stop the localhost API if it is running."""
        if self.api_server is not None:
            self.api_server.stop()
        self.state.set_agent_state("api_listening", "false")

    def get_connection_info(self) -> Dict[str, object]:
        """Return client connection info for IDE and agent integrations."""
        status = self.get_status()
        return {
            "base_url": self._api_base_url(),
            "token_path": self.paths["api_token"],
            "running": status["running"],
            "api_listening": status.get("api_listening", False),
            "monitor_scope": self.monitor_scope,
            "monitor_home": self.paths["home"],
            "final_data_dir": self.updater.final_data_dir,
            "workspace_root": self.requested_workspace_root,
            "repo_root": self.requested_workspace_root,
            "installed_service_manager": status.get("installed_service_manager"),
            "auto_start_on_client": bool(self._api_config().get("auto_start_on_client", True)),
            "mcp_server": build_mcp_server_definition(),
            "supported_bootstrap_clients": list(ALL_BOOTSTRAP_CLIENTS),
        }

    def _serialize_finding(self, finding: Dict[str, object]) -> Dict[str, object]:
        """Return a client-facing representation of one active finding."""
        payload = dict(finding.get("payload", {}) or {})
        project_path = str(finding["project_path"])
        report_path = finding.get("last_report_path")
        serialized = {
            "fingerprint": finding["fingerprint"],
            "project_path": project_path,
            "project_name": os.path.basename(project_path) or project_path,
            "finding_type": finding["finding_type"],
            "severity": finding["severity"],
            "title": finding["title"],
            "first_seen_at": finding["first_seen_at"],
            "last_seen_at": finding["last_seen_at"],
            "resolved_at": finding.get("resolved_at"),
            "report_path": report_path,
            "payload": payload,
        }
        if report_path:
            report_path = str(report_path)
            if report_path.lower().endswith((".html", ".htm")):
                serialized["html_report_path"] = report_path
                serialized["json_report_path"] = report_generator.get_json_report_path(report_path)
            else:
                serialized["json_report_path"] = report_path
                serialized["html_report_path"] = report_generator.get_html_report_path(report_path)
        if finding["finding_type"] == "malicious_package":
            serialized["package_name"] = payload.get("name", "")
            serialized["package_version"] = payload.get("version", "")
            serialized["ecosystem"] = payload.get("ecosystem", "")
        elif finding["finding_type"] == "ioc":
            serialized["ioc_type"] = payload.get("type", "")
            serialized["path"] = payload.get("path") or payload.get("filename", "")
        return serialized

    def _serialize_notification(self, notification: Dict[str, object]) -> Dict[str, object]:
        """Return a client-facing representation of one notification."""
        project_path = str(notification["project_path"])
        return {
            **notification,
            "project_name": os.path.basename(project_path) or project_path,
        }

    def list_active_findings(
        self,
        project_path: Optional[str] = None,
        limit: int = 20,
        min_severity: Optional[str] = None,
    ) -> Dict[str, object]:
        """Return active findings for CLI, API, and MCP clients."""
        normalized_project = os.path.abspath(project_path) if project_path else None
        threshold = 0
        normalized_severity = ""
        if min_severity:
            normalized_severity = str(min_severity).strip().lower()
            if normalized_severity not in SUPPORTED_SEVERITIES:
                raise ValueError(
                    "Unsupported min_severity; expected one of: "
                    + ", ".join(SUPPORTED_SEVERITIES)
                )
            threshold = severity_rank(normalized_severity)

        findings = self.state.list_active_findings(project_path=normalized_project)
        if threshold:
            findings = [
                finding
                for finding in findings
                if severity_rank(str(finding.get("severity", "")).lower()) >= threshold
            ]

        highest = findings[0]["severity"] if findings else None
        limited = findings[: max(int(limit), 1)]
        return {
            "project_path": normalized_project,
            "count": len(findings),
            "returned": len(limited),
            "limit": max(int(limit), 1),
            "min_severity": normalized_severity or None,
            "highest_severity": highest,
            "findings": [self._serialize_finding(finding) for finding in limited],
        }

    def list_recent_notifications(
        self,
        project_path: Optional[str] = None,
        limit: int = 20,
    ) -> Dict[str, object]:
        """Return recent monitor notifications for CLI, API, and MCP clients."""
        normalized_project = os.path.abspath(project_path) if project_path else None
        notifications = self.state.list_recent_notifications(
            limit=max(int(limit), 1),
            project_path=normalized_project,
        )
        return {
            "project_path": normalized_project,
            "count": len(notifications),
            "returned": len(notifications),
            "limit": max(int(limit), 1),
            "notifications": [
                self._serialize_notification(notification) for notification in notifications
            ],
        }

    def add_watched_project(
        self,
        project_path: str,
        policy: Optional[Dict[str, object]] = None,
        initial_scan_kind: Optional[str] = None,
    ) -> Dict[str, object]:
        """Enroll one project in the singleton watcher and optionally scan it immediately."""
        normalized_path = os.path.abspath(project_path)
        if not os.path.isdir(normalized_path):
            raise FileNotFoundError(normalized_path)
        if initial_scan_kind and initial_scan_kind not in {"quick", "full"}:
            raise ValueError("initial_scan_kind must be 'quick', 'full', or omitted")

        self.state.add_watched_project(normalized_path, dict(policy or {}))
        self.state.replace_observed_files(normalized_path, take_project_snapshot(normalized_path))

        result: Dict[str, object] = {
            "success": True,
            "project_path": normalized_path,
            "message": f"Watching {normalized_path}",
        }
        if not initial_scan_kind:
            return result

        project = self.state.get_watched_project(normalized_path)
        if project is None:
            return result

        initial_scan = self._run_project_scan(
            project,
            initial_scan_kind,
            "workspace added from menu bar",
        )
        result["initial_scan"] = initial_scan
        result["message"] = (
            f"Watching {normalized_path}; initial {initial_scan_kind} scan: "
            f"{initial_scan.get('message', 'completed')}"
        )
        return result

    def set_notification_preference(self, key: str, enabled: bool) -> Dict[str, object]:
        """Persist one notification-related preference."""
        labels = {
            "desktop": "Desktop notifications",
            "terminal": "Terminal notifications",
            "auto_launch_menubar": "Auto-launch menu bar app",
            "popup_via_menubar": "Menu bar popups",
        }
        if key not in labels:
            raise ValueError(
                "Unsupported notification preference; expected one of: "
                + ", ".join(sorted(labels))
            )

        self.config.setdefault("notifications", {})[key] = bool(enabled)
        save_monitor_config(self.config)
        self.notifier.config = self.config
        if enabled and key in {"auto_launch_menubar", "popup_via_menubar"}:
            self._ensure_menubar_running_if_configured(force=True)

        return {
            "success": True,
            "key": key,
            "value": bool(enabled),
            "message": f"{labels[key]} {'enabled' if enabled else 'disabled'}",
        }

    def mark_alerts_reviewed(self, limit: int = 20) -> Dict[str, object]:
        """Advance the reviewed-alert cursor without deleting alert history."""
        max_notifications = max(int(limit), 1)
        last_live_promotion_at = self.state.get_agent_state("last_live_promotion_at") or ""
        last_live_promotion_status = self.state.get_agent_state("last_live_promotion_status") or ""
        notifications = self.list_recent_notifications(limit=max_notifications)["notifications"]
        try:
            acknowledged_notification_id = int(
                self.state.get_agent_state("menubar_last_acknowledged_notification_id", "0") or 0
            )
        except (TypeError, ValueError):
            acknowledged_notification_id = 0

        cleared_alert_count = count_unacknowledged_alert_notifications(
            notifications,
            acknowledged_notification_id,
            last_live_promotion_at=last_live_promotion_at,
            last_live_promotion_status=last_live_promotion_status,
        )
        newest_alert = latest_attention_notification(
            notifications,
            last_live_promotion_at=last_live_promotion_at,
            last_live_promotion_status=last_live_promotion_status,
        )
        target_notification_id = int(newest_alert.get("id", 0) or 0) if newest_alert else 0
        if cleared_alert_count <= 0 or target_notification_id <= acknowledged_notification_id:
            return {
                "success": True,
                "acknowledged_notification_id": acknowledged_notification_id,
                "cleared_alert_count": 0,
                "message": "No new alerts to clear",
            }

        self.state.set_agent_state(
            "menubar_last_acknowledged_notification_id",
            str(target_notification_id),
        )
        return {
            "success": True,
            "acknowledged_notification_id": target_notification_id,
            "cleared_alert_count": cleared_alert_count,
            "message": f"Marked {cleared_alert_count} alert(s) reviewed",
        }

    def _dependency_data_health(self, ecosystem: str) -> Dict[str, object]:
        """Return threat-data health for one ecosystem."""
        return self._threat_data_summary([ecosystem])["summary"]

    def _threat_data_summary(self, ecosystems: Optional[List[str]] = None) -> Dict[str, object]:
        """Return DB-backed threat-data status for one or more ecosystems."""
        requested_ecosystems = list(ecosystems or ECOSYSTEM_PRIORITY)
        database_statuses = get_database_statuses(
            ecosystems=requested_ecosystems,
            final_data_dir=self.updater.final_data_dir,
        )
        summary = summarize_requested_data_status(requested_ecosystems, database_statuses)
        suggestion = ""
        if summary["data_status"] != "complete":
            suggestion = (
                "Run threat data collection or copy the SQLite databases into the shared "
                "OreWatch singleton final-data directory"
            )
        return {
            "summary": summary,
            "database_statuses": database_statuses,
            "data_health_details": {
                "expected_path": self.updater.final_data_dir,
                "requested_ecosystems": requested_ecosystems,
                "available_databases": sorted(
                    ecosystem
                    for ecosystem, status in database_statuses.items()
                    if status.get("exists")
                ),
                "missing_ecosystems": list(summary.get("missing_ecosystems", [])),
                "usable_ecosystems": list(summary.get("usable_ecosystems", [])),
                "sources_used": list(summary.get("sources_used", [])),
                "experimental_sources_used": list(summary.get("experimental_sources_used", [])),
                "requested_statuses": dict(summary.get("requested_statuses", {})),
                "suggestion": suggestion,
            },
        }

    def _normalize_manifest_dependency(self, dependency: Dict[str, object]) -> Dict[str, object]:
        """Map parser output into the dependency-add request shape."""
        version = str(dependency.get("version", "") or "").strip()
        exact_version = resolve_exact_version(requested_spec=version, resolved_version="")
        normalized = normalize_dependency_input(
            {
                "name": dependency.get("name", ""),
                "requested_spec": version,
                "resolved_version": exact_version,
                "dev_dependency": False,
                "physical_location": dependency.get("physical_location"),
                "section": dependency.get("section"),
            }
        )
        return normalized

    def _manifest_dependencies(
        self,
        payload: Dict[str, object],
        ecosystem: str,
    ) -> List[Dict[str, object]]:
        """Return explicit or parsed manifest dependencies."""
        dependencies = payload.get("dependencies")
        if isinstance(dependencies, list) and dependencies:
            return [normalize_dependency_input(item) for item in dependencies]

        manifest_path = os.path.realpath(str(payload["manifest_path"]))
        if not os.path.exists(manifest_path):
            raise ValueError(f"manifest_path does not exist: {manifest_path}")
        if not os.path.isfile(manifest_path):
            raise ValueError(f"manifest_path is not a file: {manifest_path}")

        project_path = os.path.realpath(str(payload.get("project_path", "")))
        if project_path and not manifest_path.startswith(project_path + os.sep):
            raise ValueError(
                f"manifest_path '{manifest_path}' is not inside project_path '{project_path}'"
            )

        filename = os.path.basename(manifest_path)
        manifest = get_manifest_for_filename(filename)
        supported_filenames = get_supported_files_for_ecosystem(ecosystem)
        if manifest is None:
            expected = ", ".join(supported_filenames)
            raise ValueError(
                f"Unsupported manifest filename '{filename}' for ecosystem '{ecosystem}'; "
                f"expected one of: {expected}"
            )
        if manifest["ecosystem"] != ecosystem:
            expected = ", ".join(supported_filenames)
            raise ValueError(
                f"manifest_path filename '{filename}' does not match ecosystem '{ecosystem}'; "
                f"expected one of: {expected}"
            )

        try:
            parsed_dependencies = parse_dependencies(manifest_path, ecosystem)
        except Exception as exc:
            raise ValueError(f"Unable to parse manifest_path '{manifest_path}': {exc}") from exc
        return [self._normalize_manifest_dependency(item) for item in parsed_dependencies]

    def _evaluate_dependencies(
        self,
        dependencies: List[Dict[str, object]],
        ecosystem: str,
    ) -> Dict[str, object]:
        """Evaluate dependency safety for preflight add/install checks."""
        normalized_dependencies = []
        for item in dependencies:
            if "exact_version" in item and "requested_spec" in item and "resolved_version" in item:
                normalized_dependencies.append(dict(item))
            else:
                normalized_dependencies.append(normalize_dependency_input(item))
        threat_data = self._threat_data_summary([ecosystem])
        health = threat_data["summary"]
        data_health = str(health.get("data_status", "failed"))
        lookup_packages = [
            {"name": dependency["name"], "version": dependency["exact_version"]}
            for dependency in normalized_dependencies
            if dependency["name"]
        ]
        malicious_matches = self.package_checker.check_packages(lookup_packages, ecosystem)
        matches_by_name: Dict[str, List[Dict[str, object]]] = {}
        for match in malicious_matches:
            matches_by_name.setdefault(str(match.get("name", "")).lower(), []).append(match)

        results: List[Dict[str, object]] = []
        has_malicious = False
        unresolved_count = 0
        for dependency in normalized_dependencies:
            dependency_matches = matches_by_name.get(dependency["name"].lower(), [])
            if dependency_matches:
                match = dependency_matches[0]
                has_malicious = True
                safe_name = shlex.quote(dependency["name"])
                uninstall_cmd = UNINSTALL_COMMANDS.get(ecosystem, "").format(name=safe_name)
                results.append(
                    {
                        "name": dependency["name"],
                        "requested_spec": dependency["requested_spec"],
                        "resolved_version": dependency["resolved_version"],
                        "status": "malicious_match",
                        "severity": match.get("severity", "critical"),
                        "sources": match.get("sources", []),
                        "reason": match.get(
                            "description",
                            f"Matched malicious package intelligence for {dependency['name']}",
                        ),
                        "user_action_required": (
                            f"Do not install {dependency['name']}. "
                            f"If already installed, run: {uninstall_cmd}"
                        ),
                    }
                )
                continue

            if not dependency["exact_version"]:
                unresolved_count += 1
                results.append(
                    {
                        "name": dependency["name"],
                        "requested_spec": dependency["requested_spec"],
                        "resolved_version": dependency["resolved_version"],
                        "status": "unresolved_version",
                        "severity": "warning",
                        "sources": [],
                        "reason": "Exact dependency version could not be determined",
                    }
                )
                continue

            if data_health != "complete":
                results.append(
                    {
                        "name": dependency["name"],
                        "requested_spec": dependency["requested_spec"],
                        "resolved_version": dependency["resolved_version"] or dependency["exact_version"],
                        "status": "data_unhealthy",
                        "severity": "warning",
                        "sources": list(health.get("sources_used", [])),
                        "reason": f"Threat data is {data_health}; explicit override is required",
                    }
                )
                continue

            results.append(
                {
                    "name": dependency["name"],
                    "requested_spec": dependency["requested_spec"],
                    "resolved_version": dependency["resolved_version"] or dependency["exact_version"],
                    "status": "clean",
                    "severity": "none",
                    "sources": [],
                    "reason": "No malicious match found in current threat data",
                }
            )

        if has_malicious:
            decision = "override_required"
            monitor_message = (
                "One or more dependencies matched malicious package intelligence; "
                "do NOT install these packages — if already installed, uninstall them immediately"
            )
        elif data_health != "complete":
            decision = "override_required"
            monitor_message = f"Threat data is {data_health}; explicit override required"
        elif unresolved_count:
            decision = "override_required"
            monitor_message = "Exact dependency version could not be determined"
        else:
            decision = "allow"
            monitor_message = "All requested dependencies passed OreWatch checks"

        manifest_status = "clean"
        if has_malicious:
            manifest_status = "blocked"
        elif decision != "allow":
            manifest_status = "warning"

        return {
            "decision": decision,
            "data_health": data_health,
            "data_health_details": threat_data["data_health_details"],
            "results": results,
            "monitor_message": monitor_message,
            "override_allowed": True,
            "manifest_status": manifest_status,
            "normalized_dependencies": normalized_dependencies,
            "summary": health,
        }

    def build_health_payload(self) -> Dict[str, object]:
        """Return the client-facing health payload for the local API."""
        status = self.get_status()
        threat_data = self._threat_data_summary()
        payload = {
            **supported_health_payload(),
            "daemon_running": bool(status.get("running") or status.get("api_listening")),
            "api_listening": bool(status.get("api_listening")),
            "base_url": self._api_base_url(),
            "last_threat_refresh_at": status.get("last_threat_refresh_at"),
            "last_threat_refresh_status": status.get("last_threat_refresh_status"),
            "last_live_promotion_status": status.get("last_live_promotion_status"),
            "last_live_promotion_decision": status.get("last_live_promotion_decision"),
            "current_snapshot_version": status.get("current_snapshot_version"),
            "current_live_dataset_version": status.get("current_live_dataset_version"),
            "scan_blocked_reason": status.get("scan_blocked_reason"),
            "monitor_scope": self.monitor_scope,
            "monitor_home": self.paths["home"],
            "data_health": threat_data["summary"]["data_status"],
            "data_health_details": threat_data["data_health_details"],
            "database_statuses": threat_data["database_statuses"],
            "final_data_dir": self.updater.final_data_dir,
            "active_findings": status.get("active_findings", 0),
            "highest_active_severity": status.get("highest_active_severity"),
            "recent_notifications": status.get("recent_notifications", []),
        }
        return payload

    def handle_dependency_add_check(self, payload: Dict[str, object]) -> Dict[str, object]:
        """Handle a preflight dependency add/install request."""
        validate_client_request(payload, manifest=False)
        ecosystem = str(payload["ecosystem"])
        evaluation = self._evaluate_dependencies(list(payload["dependencies"]), ecosystem)
        check_id = make_check_id()
        source = normalize_source_input(payload.get("source"))
        self.state.record_dependency_check(
            check_id=check_id,
            client_type=str(payload["client_type"]),
            project_path=str(payload["project_path"]),
            ecosystem=ecosystem,
            package_manager=str(payload["package_manager"]),
            operation=str(payload["operation"]),
            dependencies=evaluation["normalized_dependencies"],
            decision=str(evaluation["decision"]),
            data_health=str(evaluation["data_health"]),
            results=list(evaluation["results"]),
            monitor_message=str(evaluation["monitor_message"]),
            source=source,
        )
        if evaluation["decision"] == "override_required":
            self.notifier.notify_dependency_blocked(
                project_path=str(payload["project_path"]),
                check_id=check_id,
                results=list(evaluation["results"]),
                source=source,
            )
        return {
            "check_id": check_id,
            "decision": evaluation["decision"],
            "data_health": evaluation["data_health"],
            "data_health_details": evaluation["data_health_details"],
            "results": evaluation["results"],
            "monitor_message": evaluation["monitor_message"],
            "override_allowed": evaluation["override_allowed"],
        }

    def handle_manifest_check(self, payload: Dict[str, object]) -> Dict[str, object]:
        """Handle a manifest-wide dependency advisory check."""
        validate_client_request(payload, manifest=True)
        ecosystem = str(payload["ecosystem"])
        dependencies = self._manifest_dependencies(payload, ecosystem)
        evaluation = self._evaluate_dependencies(dependencies, ecosystem)
        check_id = make_check_id()
        source = {
            "kind": "ide_action",
            "file_path": str(payload["manifest_path"]),
            "command": "",
        }
        self.state.record_dependency_check(
            check_id=check_id,
            client_type=str(payload["client_type"]),
            project_path=str(payload["project_path"]),
            ecosystem=ecosystem,
            package_manager=str(payload.get("package_manager", ecosystem)),
            operation="manifest_check",
            dependencies=evaluation["normalized_dependencies"],
            decision=str(evaluation["decision"]),
            data_health=str(evaluation["data_health"]),
            results=list(evaluation["results"]),
            monitor_message=str(evaluation["monitor_message"]),
            source=source,
        )
        if evaluation["decision"] == "override_required":
            self.notifier.notify_dependency_blocked(
                project_path=str(payload["project_path"]),
                check_id=check_id,
                results=list(evaluation["results"]),
                source=source,
            )
        return {
            "check_id": check_id,
            "decision": evaluation["decision"],
            "manifest_status": evaluation["manifest_status"],
            "data_health": evaluation["data_health"],
            "data_health_details": evaluation["data_health_details"],
            "results": evaluation["results"],
            "monitor_message": evaluation["monitor_message"],
            "override_allowed": evaluation["override_allowed"],
        }

    def handle_dependency_override(self, check_id: str, payload: Dict[str, object]) -> Dict[str, object]:
        """Handle a one-time dependency add override."""
        if not check_id:
            raise ValueError("check_id is required")
        existing = self.state.get_dependency_check(check_id)
        if existing is None:
            raise ValueError("Unknown check_id")
        client_type = payload.get("client_type")
        actor = str(payload.get("actor", "")).strip()
        reason = str(payload.get("reason", "")).strip()
        if client_type not in SUPPORTED_CLIENT_TYPES:
            raise ValueError("Unsupported client_type")
        if str(client_type) != existing["client_type"]:
            raise ValueError("client_type does not match the original check")
        if not actor:
            raise ValueError("actor is required")
        if not reason:
            raise ValueError("reason is required")
        override_id = make_override_id()
        expires_at = build_override_expiry(int(self._api_config().get("override_ttl_seconds", 600)))
        self.state.record_dependency_override(
            override_id=override_id,
            check_id=check_id,
            client_type=str(client_type),
            actor=actor,
            reason=reason,
            expires_at=expires_at,
        )
        return {
            "override_id": override_id,
            "expires_at": expires_at,
            "decision": "allow",
        }

    _ALLOWED_COMMANDS = frozenset({
        "launchctl",
        "systemctl",
        "systemd-run",
    })

    _ALLOWED_SUBCOMMANDS: Dict[str, set] = {
        "launchctl": {"load", "unload", "list", "print", "bootstrap", "bootout", "enable", "disable", "kickstart"},
        "systemctl": {"start", "stop", "restart", "enable", "disable", "status", "is-active", "is-enabled", "daemon-reload"},
        "systemd-run": set(),  # accepts various flags, no fixed subcommands
    }

    _SHELL_METACHARACTERS = frozenset(";&|`$(){}[]!#~<>\\'\"\n\r")

    def _run_command(self, command: List[str]) -> subprocess.CompletedProcess:
        """Run a subprocess command and capture output.

        Only commands whose base name is in _ALLOWED_COMMANDS are permitted.
        Subcommands are validated against _ALLOWED_SUBCOMMANDS.
        All command elements are checked for shell metacharacters.
        """
        if not command:
            raise ValueError("Empty command list")

        base_cmd = os.path.basename(command[0])
        if base_cmd not in self._ALLOWED_COMMANDS:
            raise ValueError(
                f"Command '{base_cmd}' is not in the allowed command set: "
                f"{sorted(self._ALLOWED_COMMANDS)}"
            )

        allowed_subs = self._ALLOWED_SUBCOMMANDS.get(base_cmd)
        if allowed_subs is not None and len(allowed_subs) > 0 and len(command) > 1:
            # Find the first non-flag argument after the base command
            for arg in command[1:]:
                if arg.startswith("-"):
                    continue
                if arg not in allowed_subs:
                    raise ValueError(
                        f"Subcommand '{arg}' is not allowed for '{base_cmd}'. "
                        f"Allowed: {sorted(allowed_subs)}"
                    )
                break

        for i, element in enumerate(command):
            if any(ch in element for ch in self._SHELL_METACHARACTERS):
                raise ValueError(
                    f"Command element at index {i} contains disallowed shell metacharacter"
                )

        return subprocess.run(
            command,
            check=False,
            text=True,
            capture_output=True,
        )

    def _configured_service_manager(self) -> str:
        return self.config.get("service", {}).get("service_manager", AUTO_MANAGER)

    def _detect_available_service_manager(self, preferred: Optional[str] = None) -> str:
        """Return the best supported service manager for this machine."""
        preferred = preferred or self._configured_service_manager()
        if preferred and preferred != AUTO_MANAGER:
            return preferred

        if sys.platform == "darwin" and shutil.which("launchctl"):
            return LAUNCHD_MANAGER
        if shutil.which("systemctl"):
            return SYSTEMD_MANAGER
        return BACKGROUND_MANAGER

    def _service_target_path(self, manager: str) -> Optional[str]:
        """Return the installed service definition path for one manager.

        Validates that the resolved path stays within the expected
        service-definition directory to prevent path traversal.
        """
        if manager == LAUNCHD_MANAGER:
            base_dir = os.path.realpath(os.path.expanduser(
                os.path.join("~", "Library", "LaunchAgents")
            ))
            result = os.path.realpath(os.path.join(
                base_dir,
                f"{self.identity['launchd_label']}.plist",
            ))
            if not result.startswith(base_dir + os.sep) and result != base_dir:
                raise ValueError(
                    f"Resolved service path '{result}' escapes '{base_dir}'"
                )
            return result
        if manager == SYSTEMD_MANAGER:
            base_dir = os.path.realpath(os.path.expanduser(
                os.path.join("~", ".config", "systemd", "user")
            ))
            result = os.path.realpath(os.path.join(
                base_dir,
                self.identity["systemd_unit"],
            ))
            if not result.startswith(base_dir + os.sep) and result != base_dir:
                raise ValueError(
                    f"Resolved service path '{result}' escapes '{base_dir}'"
                )
            return result
        return None

    def _local_template_paths(self) -> Dict[str, str]:
        return {
            LAUNCHD_MANAGER: os.path.join(self.paths["services"], "launchd.plist"),
            SYSTEMD_MANAGER: os.path.join(self.paths["services"], "systemd.service"),
        }

    def _write_service_templates(self) -> Dict[str, str]:
        """Write service templates for the singleton daemon."""
        template_paths = self._local_template_paths()
        with open(template_paths[LAUNCHD_MANAGER], "w", encoding="utf-8") as handle:
            handle.write(
                render_launchd_plist(
                    self.code_root,
                    sys.executable,
                    self.identity["launchd_label"],
                    self.paths["log_file"],
                )
            )
        with open(template_paths[SYSTEMD_MANAGER], "w", encoding="utf-8") as handle:
            handle.write(
                render_systemd_service(
                    self.code_root,
                    sys.executable,
                    self.paths["log_file"],
                )
            )
        return template_paths

    def _is_installed_manager(self, manager: str) -> bool:
        target_path = self._service_target_path(manager)
        return bool(target_path and os.path.exists(target_path))

    def _installed_service_manager(self) -> Optional[str]:
        """Return the installed service manager, if any."""
        for manager in (LAUNCHD_MANAGER, SYSTEMD_MANAGER):
            if self._is_installed_manager(manager):
                return manager
        return None

    def _launchd_domain(self) -> str:
        uid = getattr(os, "getuid", lambda: 0)()
        return f"gui/{uid}"

    def _launchd_service_name(self) -> str:
        return f"{self._launchd_domain()}/{self.identity['launchd_label']}"

    def _launchd_service_status(self, label: Optional[str] = None) -> Dict[str, object]:
        """Return parsed launchd runtime state for one label."""
        service_label = label or self.identity["launchd_label"]
        service_name = f"{self._launchd_domain()}/{service_label}"
        result = self._run_command(["launchctl", "print", service_name])
        output = "\n".join(
            part for part in (result.stdout.strip(), result.stderr.strip()) if part
        )
        state = ""
        pid: Optional[int] = None
        last_exit_code: Optional[int] = None
        active_count: Optional[int] = None
        if result.returncode == 0:
            for raw_line in output.splitlines():
                line = raw_line.strip()
                if line.startswith("state ="):
                    state = line.split("=", 1)[1].strip()
                elif line.startswith("pid ="):
                    value = line.split("=", 1)[1].strip()
                    try:
                        pid = int(value)
                    except ValueError:
                        pid = None
                elif line.startswith("last exit code ="):
                    value = line.split("=", 1)[1].strip()
                    try:
                        last_exit_code = int(value)
                    except ValueError:
                        last_exit_code = None
                elif line.startswith("active count ="):
                    value = line.split("=", 1)[1].strip()
                    try:
                        active_count = int(value)
                    except ValueError:
                        active_count = None
        return {
            "label": service_label,
            "service_name": service_name,
            "loaded": result.returncode == 0,
            "running": result.returncode == 0 and (state == "running" or pid is not None),
            "pid": pid,
            "state": state or None,
            "last_exit_code": last_exit_code,
            "active_count": active_count,
            "output": output,
        }

    def _legacy_launchd_agents(self) -> List[Dict[str, object]]:
        """Return stale legacy launchd agents from pre-singleton installs."""
        if sys.platform != "darwin":
            return []
        launch_agents_dir = os.path.expanduser(
            os.path.join("~", "Library", "LaunchAgents")
        )
        if not os.path.isdir(launch_agents_dir):
            return []
        ensure_not_symlink(launch_agents_dir, "launchd agents directory")
        prefix = f"{self.identity['launchd_label']}."
        entries: List[Dict[str, object]] = []
        for filename in sorted(os.listdir(launch_agents_dir)):
            if filename == f"{self.identity['launchd_label']}.plist":
                continue
            if not filename.startswith(prefix) or not filename.endswith(".plist"):
                continue
            path = os.path.join(launch_agents_dir, filename)
            ensure_not_symlink(path, "legacy launchd service definition")
            label = filename[:-6]
            status = self._launchd_service_status(label)
            entries.append(
                {
                    "label": label,
                    "service_name": status["service_name"],
                    "path": path,
                    "loaded": status["loaded"],
                    "running": status["running"],
                    "state": status["state"],
                    "last_exit_code": status["last_exit_code"],
                    "active_count": status["active_count"],
                }
            )
        return entries

    def _cleanup_legacy_launchd_agents(self) -> Dict[str, List[Dict[str, object]]]:
        """Unload and remove stale legacy launchd agents left behind by workspace installs."""
        removed: List[Dict[str, object]] = []
        failed: List[Dict[str, object]] = []
        for entry in self._legacy_launchd_agents():
            unload_message = ""
            if entry.get("loaded"):
                unload = self._run_command(["launchctl", "bootout", entry["service_name"]])
                unload_output = unload.stderr.strip() or unload.stdout.strip()
                unload_message = unload_output
                if unload.returncode != 0 and "No such process" not in unload_output:
                    failed.append(
                        {
                            "label": entry["label"],
                            "path": entry["path"],
                            "message": unload_output or "launchd bootout failed",
                        }
                    )
                    continue
            try:
                os.unlink(str(entry["path"]))
            except OSError as exc:
                failed.append(
                    {
                        "label": entry["label"],
                        "path": entry["path"],
                        "message": str(exc),
                    }
                )
                continue
            removed.append(
                {
                    "label": entry["label"],
                    "path": entry["path"],
                    "message": unload_message or "Removed legacy launchd agent",
                }
            )
        return {"removed": removed, "failed": failed}

    def _copy_service_file(self, manager: str) -> str:
        """Copy a generated service template into the user service location."""
        local_templates = self._write_service_templates()
        source_path = local_templates[manager]
        target_path = self._service_target_path(manager)
        if target_path is None:
            raise ValueError(f"No service target path for manager {manager}")
        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        shutil.copy2(source_path, target_path)
        return target_path

    def _install_manager_service(self, manager: str, auto_start: bool = True) -> Dict[str, object]:
        """Install and optionally start a user service."""
        legacy_cleanup = {"removed": [], "failed": []}
        if manager == LAUNCHD_MANAGER:
            legacy_cleanup = self._cleanup_legacy_launchd_agents()
        target_path = self._copy_service_file(manager)

        if manager == LAUNCHD_MANAGER:
            service_name = self._launchd_service_name()
            if auto_start:
                if self._service_loaded(LAUNCHD_MANAGER):
                    self._run_command(["launchctl", "bootout", service_name])
                bootstrap = self._run_command(
                    ["launchctl", "bootstrap", self._launchd_domain(), target_path]
                )
                if bootstrap.returncode != 0:
                    return {
                        "success": False,
                        "service_manager": manager,
                        "service_definition": target_path,
                        "message": bootstrap.stderr.strip() or bootstrap.stdout.strip() or "launchd bootstrap failed",
                    }
                self._run_command(["launchctl", "kickstart", "-k", service_name])
            if auto_start:
                message = "launchd service installed and started"
            else:
                message = "launchd service installed"
            return {
                "success": True,
                "service_manager": manager,
                "service_definition": target_path,
                "auto_started": auto_start,
                "legacy_services_removed": legacy_cleanup["removed"],
                "legacy_services_failed": legacy_cleanup["failed"],
                "message": message,
            }

        if manager == SYSTEMD_MANAGER:
            unit = self.identity["systemd_unit"]
            daemon_reload = self._run_command(["systemctl", "--user", "daemon-reload"])
            if daemon_reload.returncode != 0:
                return {
                    "success": False,
                    "service_manager": manager,
                    "service_definition": target_path,
                    "message": daemon_reload.stderr.strip() or daemon_reload.stdout.strip() or "systemd daemon-reload failed",
                }
            enable_cmd = ["systemctl", "--user", "enable"]
            if auto_start:
                enable_cmd.append("--now")
            enable_cmd.append(unit)
            enable = self._run_command(enable_cmd)
            if enable.returncode != 0:
                return {
                    "success": False,
                    "service_manager": manager,
                    "service_definition": target_path,
                    "message": enable.stderr.strip() or enable.stdout.strip() or "systemd enable failed",
                }
            return {
                "success": True,
                "service_manager": manager,
                "service_definition": target_path,
                "auto_started": auto_start,
                "legacy_services_removed": legacy_cleanup["removed"],
                "legacy_services_failed": legacy_cleanup["failed"],
                "message": "systemd user service installed and started" if auto_start else "systemd user service installed",
            }

        raise ValueError(f"Unsupported service manager {manager}")

    def install(
        self,
        service_manager: Optional[str] = None,
        auto_start: bool = True,
    ) -> Dict[str, object]:
        """Initialize monitor files and install the selected service manager."""
        ensure_monitor_layout()
        self.state.initialize()
        templates = self._write_service_templates()
        preferred_manager = service_manager or AUTO_MANAGER
        manager = self._detect_available_service_manager(service_manager)
        result: Dict[str, object] = {
            "config": self.paths["config"],
            "state_db": self.paths["state_db"],
            "launchd": templates[LAUNCHD_MANAGER],
            "systemd": templates[SYSTEMD_MANAGER],
            "service_manager": manager,
            "requested_service_manager": preferred_manager,
        }

        if manager == BACKGROUND_MANAGER:
            result.update(
                {
                    "success": True,
                    "message": "No native service manager detected; using local background mode",
                }
            )
            if auto_start:
                result.update(self._start_local_background())
            return result

        try:
            manager_result = self._install_manager_service(manager, auto_start=auto_start)
        except Exception as exc:
            manager_result = {
                "success": False,
                "service_manager": manager,
                "message": str(exc),
            }
        if not manager_result.get("success") and preferred_manager in (None, AUTO_MANAGER, "auto"):
            fallback_result = self._start_local_background() if auto_start else {
                "success": True,
                "message": "Using local background mode",
            }
            result.update(
                {
                    "service_manager": BACKGROUND_MANAGER,
                    "fallback_from_service_manager": manager,
                    "fallback_reason": manager_result.get("message", ""),
                    "service_definition": None,
                    "auto_started": auto_start,
                }
            )
            result.update(fallback_result)
            fallback_message = (
                f"{manager} service setup failed: {manager_result.get('message', 'unknown error')}. "
                f"Falling back to local background mode."
            )
            if fallback_result.get("success"):
                result["message"] = fallback_message
            else:
                result["message"] = (
                    f"{fallback_message} Background startup also failed: "
                    f"{fallback_result.get('message', 'unknown error')}"
                )
            return result
        if not manager_result.get("success"):
            result.update(manager_result)
            return result
        result.update(manager_result)
        return result

    def uninstall(self, service_manager: Optional[str] = None) -> Dict[str, object]:
        """Remove an installed service definition."""
        manager = service_manager or self._installed_service_manager() or self._detect_available_service_manager(
            service_manager
        )
        if manager == BACKGROUND_MANAGER:
            stop_result = self._stop_local_background()
            return {
                "success": stop_result.get("success", True),
                "service_manager": BACKGROUND_MANAGER,
                "message": "Background monitor is not installed as a native service",
            }

        target_path = self._service_target_path(manager)
        if not target_path or not os.path.exists(target_path):
            return {
                "success": True,
                "service_manager": manager,
                "message": "Service is not installed",
            }

        stop_result = self.stop(service_manager=manager)
        if not stop_result.get("success"):
            return stop_result

        if manager == SYSTEMD_MANAGER:
            self._run_command(["systemctl", "--user", "disable", self.identity["systemd_unit"]])
            self._run_command(["systemctl", "--user", "daemon-reload"])

        os.unlink(target_path)
        return {
            "success": True,
            "service_manager": manager,
            "service_definition": target_path,
            "message": "Service uninstalled",
        }

    def _service_loaded(self, manager: str) -> bool:
        """Return True when the service manager reports the service as loaded/running."""
        if manager == LAUNCHD_MANAGER:
            return bool(self._launchd_service_status()["loaded"])
        if manager == SYSTEMD_MANAGER:
            result = self._run_command(
                ["systemctl", "--user", "is-active", self.identity["systemd_unit"]]
            )
            return result.returncode == 0 and result.stdout.strip() == "active"
        if manager == BACKGROUND_MANAGER:
            return pid_is_running(read_pid(self.paths["pid"]))
        return False

    def get_status(self) -> Dict[str, object]:
        """Return service status details."""
        installed_manager = self._installed_service_manager()
        configured_manager = self._configured_service_manager()
        effective_manager = installed_manager or self._detect_available_service_manager(configured_manager)
        summary = self.state.get_summary()
        active_findings = self.list_active_findings(limit=3)
        recent_notifications = self.list_recent_notifications(limit=20)
        menubar_status = self._menubar_status()
        legacy_launchd_agents = self._legacy_launchd_agents()
        last_live_promotion_at = self.state.get_agent_state("last_live_promotion_at")
        last_live_promotion_status = self.state.get_agent_state("last_live_promotion_status")
        visible_recent_notifications = [
            notification
            for notification in recent_notifications["notifications"]
            if notification_is_visible(
                notification,
                last_live_promotion_at=last_live_promotion_at,
                last_live_promotion_status=last_live_promotion_status,
            )
        ][:3]

        status = {
            "monitor_scope": self.monitor_scope,
            "monitor_home": self.paths["home"],
            "runtime_lock_path": self.paths["lock"],
            "final_data_dir": self.updater.final_data_dir,
            "configured_service_manager": configured_manager,
            "effective_service_manager": effective_manager,
            "installed_service_manager": installed_manager,
            "running": False,
            "api_enabled": bool(self._api_config().get("enabled", True)),
            "api_listening": bool(self.api_server is not None and self.api_server.listening),
            "api_base_url": self._api_base_url(),
            "api_token_path": self.paths["api_token"],
            "pid": read_pid(self.paths["pid"]),
            "last_heartbeat_at": self.state.get_agent_state("last_heartbeat_at"),
            "last_threat_refresh_attempt_at": self.state.get_agent_state("last_threat_refresh_attempt_at"),
            "last_threat_refresh_at": self.state.get_agent_state("last_threat_refresh_at"),
            "last_threat_refresh_status": self.state.get_agent_state("last_threat_refresh_status"),
            "last_threat_refresh_message": self.state.get_agent_state("last_threat_refresh_message"),
            "last_live_promotion_at": last_live_promotion_at,
            "last_live_promotion_status": last_live_promotion_status,
            "last_live_promotion_decision": self.state.get_agent_state("last_live_promotion_decision"),
            "last_live_promotion_message": self.state.get_agent_state("last_live_promotion_message"),
            "scan_blocked_reason": self.state.get_agent_state("scan_blocked_reason"),
            "current_snapshot_version": self.state.get_agent_state("current_snapshot_version"),
            "current_snapshot_key_id": self.state.get_agent_state("current_snapshot_key_id"),
            "current_live_dataset_version": self.state.get_agent_state("current_live_dataset_version"),
            "active_findings": summary.get("active_findings", 0),
            "highest_active_severity": summary.get("highest_active_severity"),
            "active_findings_preview": active_findings["findings"],
            "recent_notifications": visible_recent_notifications,
            "menubar_last_launch_at": self.state.get_agent_state("menubar_last_launch_at"),
            "menubar_last_launch_status": self.state.get_agent_state("menubar_last_launch_status"),
            "menubar_last_launch_message": self.state.get_agent_state("menubar_last_launch_message"),
            "watch_summary": summary,
            "legacy_launchd_agents": legacy_launchd_agents,
            "legacy_service_count": len(legacy_launchd_agents),
            "legacy_running_services": sum(
                1 for entry in legacy_launchd_agents if entry.get("running")
            ),
        }
        status.update(menubar_status)

        for manager in (LAUNCHD_MANAGER, SYSTEMD_MANAGER):
            target_path = self._service_target_path(manager)
            status[f"{manager}_service_definition"] = target_path
            status[f"{manager}_installed"] = bool(target_path and os.path.exists(target_path))

        if installed_manager:
            status["running"] = self._service_loaded(installed_manager)
            status["service_definition"] = self._service_target_path(installed_manager)
            if installed_manager == LAUNCHD_MANAGER:
                launchd_status = self._launchd_service_status()
                status["running"] = bool(launchd_status["running"])
                status["pid"] = launchd_status["pid"] or status["pid"]
                status["launchd_service_loaded"] = bool(launchd_status["loaded"])
                status["launchd_pid"] = launchd_status["pid"]
                status["launchd_service_state"] = launchd_status["state"]
                status["launchd_last_exit_code"] = launchd_status["last_exit_code"]
                status["launchd_active_count"] = launchd_status["active_count"]
        else:
            status["running"] = pid_is_running(status["pid"])
            status["service_definition"] = None

        if not status["api_listening"]:
            status["api_listening"] = self.state.get_agent_state("api_listening") == "true"
        if not status["api_base_url"]:
            status["api_base_url"] = self.state.get_agent_state("api_base_url") or self._api_base_url()

        return status

    def doctor(self) -> Dict[str, object]:
        """Return detailed health information."""
        status = self.get_status()
        status.update(
            {
                "monitor_scope": self.monitor_scope,
                "monitor_home": self.paths["home"],
                "runtime_lock_path": self.paths["lock"],
                "final_data_dir": self.updater.final_data_dir,
                "config_path": self.paths["config"],
                "state_db": self.paths["state_db"],
                "log_file": self.paths["log_file"],
                "services_dir": self.paths["services"],
                "snapshot_channel_url": self.config.get("snapshots", {}).get("channel_url", ""),
                "snapshot_manifest_url": self.config.get("snapshots", {}).get("manifest_url", ""),
                "snapshot_public_key_path": self.config.get("snapshots", {}).get("public_key_path", ""),
                "live_updates": self.config.get("live_updates", {}),
                "recent_notifications": self.list_recent_notifications(limit=5)["notifications"],
                "active_findings_preview": self.list_active_findings(limit=5)["findings"],
            }
        )
        return status

    def _start_local_background(self) -> Dict[str, object]:
        """Start the singleton monitor daemon in the background."""
        pid = read_pid(self.paths["pid"])
        if pid_is_running(pid):
            return {"success": True, "message": "Monitor already running", "pid": pid}
        if not self._runtime_lock_available():
            return {
                "success": True,
                "message": "Monitor already running",
                "pid": read_pid(self.paths["pid"]),
            }

        command = _monitor_runtime_command("run", sys.executable)
        process = subprocess.Popen(
            command,
            cwd=self.code_root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )

        deadline = time.time() + 5
        while time.time() < deadline:
            started_pid = read_pid(self.paths["pid"])
            if pid_is_running(started_pid):
                return {"success": True, "message": "Monitor started", "pid": started_pid}
            time.sleep(0.1)

        return {
            "success": False,
            "message": "Monitor process launched but did not become ready",
            "pid": process.pid,
        }

    def _stop_local_background(self) -> Dict[str, object]:
        """Stop the singleton background daemon."""
        pid = read_pid(self.paths["pid"])
        if not pid_is_running(pid):
            if os.path.exists(self.paths["pid"]):
                os.unlink(self.paths["pid"])
            return {"success": True, "message": "Monitor is not running"}

        os.kill(pid, signal.SIGTERM)
        deadline = time.time() + 5
        while time.time() < deadline:
            if not pid_is_running(pid):
                if os.path.exists(self.paths["pid"]):
                    os.unlink(self.paths["pid"])
                return {"success": True, "message": "Monitor stopped"}
            time.sleep(0.1)

        return {"success": False, "message": f"Timed out waiting for pid {pid} to stop"}

    def start(self, service_manager: Optional[str] = None) -> Dict[str, object]:
        """Start the monitor using the installed or selected service manager."""
        manager = service_manager or self._installed_service_manager() or BACKGROUND_MANAGER
        if manager == BACKGROUND_MANAGER:
            return self._start_local_background()

        if manager == LAUNCHD_MANAGER:
            legacy_cleanup = self._cleanup_legacy_launchd_agents()
            target_path = self._service_target_path(manager)
            service_name = self._launchd_service_name()
            if not target_path or not os.path.exists(target_path):
                return {
                    "success": False,
                    "message": "launchd service is not installed",
                    "legacy_services_removed": legacy_cleanup["removed"],
                    "legacy_services_failed": legacy_cleanup["failed"],
                }
            if not self._service_loaded(manager):
                bootstrap = self._run_command(["launchctl", "bootstrap", self._launchd_domain(), target_path])
                if bootstrap.returncode != 0:
                    return {
                        "success": False,
                        "message": bootstrap.stderr.strip() or bootstrap.stdout.strip() or "launchd bootstrap failed",
                        "legacy_services_removed": legacy_cleanup["removed"],
                        "legacy_services_failed": legacy_cleanup["failed"],
                    }
            result = self._run_command(["launchctl", "kickstart", "-k", service_name])
            return {
                "success": result.returncode == 0,
                "service_manager": manager,
                "legacy_services_removed": legacy_cleanup["removed"],
                "legacy_services_failed": legacy_cleanup["failed"],
                "message": result.stderr.strip() or result.stdout.strip() or "launchd service started",
            }

        if manager == SYSTEMD_MANAGER:
            unit = self.identity["systemd_unit"]
            result = self._run_command(["systemctl", "--user", "start", unit])
            return {
                "success": result.returncode == 0,
                "service_manager": manager,
                "message": result.stderr.strip() or result.stdout.strip() or "systemd service started",
            }

        return {"success": False, "message": f"Unsupported service manager {manager}"}

    def stop(self, service_manager: Optional[str] = None) -> Dict[str, object]:
        """Stop the monitor using the installed or selected service manager."""
        manager = service_manager or self._installed_service_manager() or BACKGROUND_MANAGER
        if manager == BACKGROUND_MANAGER:
            return self._stop_local_background()

        if manager == LAUNCHD_MANAGER:
            service_name = self._launchd_service_name()
            result = self._run_command(["launchctl", "bootout", service_name])
            success = result.returncode == 0 or "No such process" in (result.stderr or result.stdout)
            return {
                "success": success,
                "service_manager": manager,
                "message": result.stderr.strip() or result.stdout.strip() or "launchd service stopped",
            }

        if manager == SYSTEMD_MANAGER:
            result = self._run_command(["systemctl", "--user", "stop", self.identity["systemd_unit"]])
            return {
                "success": result.returncode == 0,
                "service_manager": manager,
                "message": result.stderr.strip() or result.stdout.strip() or "systemd service stopped",
            }

        return {"success": False, "message": f"Unsupported service manager {manager}"}

    def restart(self, service_manager: Optional[str] = None) -> Dict[str, object]:
        """Restart the monitor using the installed or selected service manager."""
        manager = service_manager or self._installed_service_manager() or BACKGROUND_MANAGER
        if manager == BACKGROUND_MANAGER:
            stop_result = self._stop_local_background()
            if not stop_result.get("success"):
                return stop_result
            return self._start_local_background()

        if manager == LAUNCHD_MANAGER:
            legacy_cleanup = self._cleanup_legacy_launchd_agents()
            target_path = self._service_target_path(manager)
            service_name = self._launchd_service_name()
            if not target_path or not os.path.exists(target_path):
                return {
                    "success": False,
                    "message": "launchd service is not installed",
                    "legacy_services_removed": legacy_cleanup["removed"],
                    "legacy_services_failed": legacy_cleanup["failed"],
                }
            if not self._service_loaded(manager):
                bootstrap = self._run_command(["launchctl", "bootstrap", self._launchd_domain(), target_path])
                if bootstrap.returncode != 0:
                    return {
                        "success": False,
                        "message": bootstrap.stderr.strip() or bootstrap.stdout.strip() or "launchd bootstrap failed",
                        "legacy_services_removed": legacy_cleanup["removed"],
                        "legacy_services_failed": legacy_cleanup["failed"],
                    }
            result = self._run_command(["launchctl", "kickstart", "-k", service_name])
            return {
                "success": result.returncode == 0,
                "service_manager": manager,
                "legacy_services_removed": legacy_cleanup["removed"],
                "legacy_services_failed": legacy_cleanup["failed"],
                "message": result.stderr.strip() or result.stdout.strip() or "launchd service restarted",
            }

        if manager == SYSTEMD_MANAGER:
            result = self._run_command(["systemctl", "--user", "restart", self.identity["systemd_unit"]])
            return {
                "success": result.returncode == 0,
                "service_manager": manager,
                "message": result.stderr.strip() or result.stdout.strip() or "systemd service restarted",
            }

        return {"success": False, "message": f"Unsupported service manager {manager}"}

    def scan_now(self, project_path: Optional[str] = None, full: bool = True) -> List[Dict]:
        """Run an immediate scan for one watched project or all watched projects."""
        projects = self.state.list_watched_projects()
        if project_path:
            normalized = os.path.abspath(project_path)
            projects = [project for project in projects if project["path"] == normalized]
        results = []
        for project in projects:
            results.append(self._run_project_scan(project, "full" if full else "quick", "manual"))
        return results

    def _runtime_lock_available(self) -> bool:
        """Return True when no other OreWatch monitor daemon currently holds the lock."""
        probe = RuntimeLock(self.paths["lock"])
        acquired = probe.acquire(blocking=False)
        if acquired:
            probe.release()
        return acquired

    def _write_pid_file(self) -> None:
        ensure_not_symlink(self.paths["pid"], "monitor pid file")
        with open(self.paths["pid"], "w", encoding="utf-8") as handle:
            handle.write(str(os.getpid()))
        ensure_owner_only_permissions(self.paths["pid"], OWNER_ONLY_FILE_MODE)

    def _cleanup_pid_file(self) -> None:
        if os.path.exists(self.paths["pid"]):
            os.unlink(self.paths["pid"])

    def _handle_stop_signal(self, signum, _frame) -> None:
        logger.info("Received stop signal %s", signum)
        self.stop_requested = True

    def run_forever(self, max_loops: Optional[int] = None) -> None:
        """Run the monitor loop until stopped."""
        if not self.runtime_lock.acquire(blocking=False):
            existing_pid = read_pid(self.paths["pid"])
            if existing_pid and existing_pid != os.getpid():
                raise RuntimeError(f"Monitor already running with pid {existing_pid}")
            raise RuntimeError("Monitor already running")

        signal.signal(signal.SIGTERM, self._handle_stop_signal)
        signal.signal(signal.SIGINT, self._handle_stop_signal)
        self._write_pid_file()
        self.state.set_agent_state("last_started_at", _utcnow())
        self.start_api_server()
        self._ensure_menubar_running_if_configured(force=True)
        loops = 0

        try:
            while not self.stop_requested:
                self.run_iteration()
                loops += 1
                if max_loops is not None and loops >= max_loops:
                    break
                time.sleep(int(self.config.get("service", {}).get("loop_interval_seconds", 5)))
        finally:
            self.stop_api_server()
            self.state.set_agent_state("last_stopped_at", _utcnow())
            self._cleanup_pid_file()
            self.runtime_lock.release()

    def run_iteration(self) -> None:
        """Run one service loop iteration."""
        self.state.set_agent_state("last_heartbeat_at", _utcnow())
        self._ensure_menubar_running_if_configured()
        refresh_result = self.updater.refresh_if_due(force=False)
        if refresh_result.get("used_live_collection") and not refresh_result.get("skipped"):
            logger.info(
                "Threat data live refresh decision=%s success=%s kept_last_known_good=%s message=%s",
                refresh_result.get("promotion_decision", ""),
                bool(refresh_result.get("success")),
                bool(refresh_result.get("kept_last_known_good")),
                str(refresh_result.get("message", "")),
            )
        if not refresh_result.get("success"):
            message = refresh_result.get("message", "Threat data refresh failed")
            self.state.set_agent_state("scan_blocked_reason", message)
            logger.error("Threat data refresh failed; skipping scans: %s", message)
            return
        if (
            refresh_result.get("promotion_decision") == "rejected"
            and refresh_result.get("kept_last_known_good")
        ):
            self.state.add_notification(
                self.paths["home"],
                "live_update_anomaly",
                str(refresh_result.get("message", "Live update rejected; kept last-known-good data")),
            )
        self.state.set_agent_state("scan_blocked_reason", "")
        projects = self.state.list_watched_projects()

        for project in projects:
            self._poll_project(project)

        for job in consume_ready_changes(self.pending_changes, time.monotonic()):
            project = self.state.get_watched_project(job["project_path"])
            if project:
                self._run_project_scan(
                    project,
                    job["scan_kind"],
                    f"{job['reason']}: {', '.join(job['changed_paths'])}",
                )

        for project in projects:
            policy = self._get_effective_policy(project)
            scan_kind = determine_periodic_scan_kind(project, policy)
            if scan_kind:
                self._run_project_scan(project, scan_kind, "scheduled")

    def _poll_project(self, project: Dict) -> None:
        """Poll one project for file changes."""
        project_path = project["path"]
        if not os.path.isdir(project_path):
            logger.warning("Watched project no longer exists: %s", project_path)
            return

        previous = self.state.get_observed_files(project_path)
        current = take_project_snapshot(project_path)
        if not previous:
            self.state.replace_observed_files(project_path, current)
            return

        changes = detect_changes(previous, current)
        if not changes:
            return

        self.state.replace_observed_files(project_path, current)
        debounce_seconds = int(self.config.get("service", {}).get("debounce_seconds", 5))
        queue_change(
            self.pending_changes,
            project_path,
            changes,
            debounce_seconds,
            time.monotonic(),
        )

    def _get_effective_policy(self, project: Dict) -> Dict:
        """Return the merged project policy."""
        policy = load_project_policy(project["path"], self.config)
        policy.update(project.get("policy", {}))
        return policy

    def _build_report_path(self, project_path: str, scan_kind: str) -> str:
        """Build a monitor-managed report path for one project scan."""
        slug = _slugify_path(project_path)
        reports_base = os.path.realpath(self.paths["reports"])
        report_dir = os.path.realpath(os.path.join(reports_base, slug))
        if not report_dir.startswith(reports_base + os.sep) and report_dir != reports_base:
            raise ValueError(
                f"Report directory '{report_dir}' escapes the reports base '{reports_base}'"
            )
        os.makedirs(report_dir, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        result = os.path.realpath(os.path.join(report_dir, f"{scan_kind}_{timestamp}.json"))
        if not result.startswith(report_dir + os.sep) and result != report_dir:
            raise ValueError(
                f"Report path '{result}' escapes the report directory '{report_dir}'"
            )
        return result

    def _run_project_scan(self, project: Dict, scan_kind: str, reason: str):
        """Run one monitored project scan and update state."""
        policy = self._get_effective_policy(project)
        output_path = self._build_report_path(project["path"], scan_kind)
        request = ScanRequest(
            target_path=project["path"],
            output_path=output_path,
            scan_iocs=(scan_kind == "full"),
            scan_packages=True,
            force_latest_data=False,
            strict_data=bool(policy.get("strict_data", False)),
            include_experimental_sources=bool(policy.get("include_experimental_sources", False)),
            ensure_data=False,
            print_summary=False,
        )
        result = run_scan(request)
        display_report_path = result.report_path
        if result.report_path:
            html_report_path = report_generator.get_html_report_path(result.report_path)
            if os.path.exists(html_report_path):
                display_report_path = html_report_path
        tracked_findings = build_tracked_findings(result, policy)
        changes = self.state.upsert_findings(project["path"], tracked_findings, display_report_path)
        self.state.update_project_scan(
            project["path"],
            scan_kind,
            display_report_path,
            result.exit_code,
            result.message,
            reason,
        )
        self.notifier.notify_project_changes(
            project["path"],
            changes,
            policy,
            report_path=display_report_path,
        )
        logger.info(
            "Completed %s scan for %s: %s",
            scan_kind,
            project["path"],
            result.message,
        )
        return {
            "project_path": project["path"],
            "scan_kind": scan_kind,
            "exit_code": result.exit_code,
            "message": result.message,
            "report_path": display_report_path,
            "json_report_path": result.report_path,
            "html_report_path": (
                report_generator.get_html_report_path(result.report_path)
                if result.report_path
                else None
            ),
            "new_findings": len(changes["new_findings"]),
            "escalated_findings": len(changes["escalated_findings"]),
            "resolved_findings": len(changes["resolved_findings"]),
        }
