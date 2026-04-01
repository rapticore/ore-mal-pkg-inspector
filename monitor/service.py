#!/usr/bin/env python3
"""
Background monitor service runtime.
"""

from __future__ import annotations

import hashlib
import logging
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional

from logging_config import setup_logging
from monitor.config import ensure_monitor_layout, get_repo_root, load_monitor_config
from monitor.config import OWNER_ONLY_FILE_MODE
from monitor.config import ensure_owner_only_permissions
from monitor.config import ensure_not_symlink
from monitor.notifier import Notifier
from monitor.policy import build_tracked_findings, load_project_policy
from monitor.scheduler import consume_ready_changes, determine_periodic_scan_kind, queue_change
from monitor.snapshot_updater import SnapshotUpdater
from monitor.state import MonitorState
from monitor.watcher import detect_changes, take_project_snapshot
from scanner_engine import ScanRequest, run_scan


logger = logging.getLogger(__name__)
LAUNCHD_MANAGER = "launchd"
SYSTEMD_MANAGER = "systemd"
BACKGROUND_MANAGER = "background"
AUTO_MANAGER = "auto"


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


def _slugify_path(project_path: str) -> str:
    basename = os.path.basename(project_path.rstrip(os.sep)) or "project"
    digest = abs(hash(os.path.abspath(project_path))) % 100000
    safe_basename = "".join(ch if ch.isalnum() or ch in "-_." else "-" for ch in basename)
    return f"{safe_basename}-{digest}"


def _service_identity(repo_root: str) -> Dict[str, str]:
    digest = hashlib.sha1(os.path.abspath(repo_root).encode("utf-8")).hexdigest()[:10]
    launchd_label = f"org.orewatch.monitor.{digest}"
    systemd_unit = f"orewatch-monitor-{digest}.service"
    return {
        "launchd_label": launchd_label,
        "systemd_unit": systemd_unit,
        "digest": digest,
    }


def render_launchd_plist(
    repo_root: str,
    python_executable: str,
    label: str,
    log_file: str,
) -> str:
    """Render a launchd plist template."""
    script_path = os.path.join(repo_root, "malicious_package_scanner.py")
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{label}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{python_executable}</string>
    <string>{script_path}</string>
    <string>monitor</string>
    <string>run</string>
  </array>
  <key>WorkingDirectory</key>
  <string>{repo_root}</string>
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
    repo_root: str,
    python_executable: str,
    log_file: str,
) -> str:
    """Render a systemd user service template."""
    script_path = os.path.join(repo_root, "malicious_package_scanner.py")
    return f"""[Unit]
Description=OreWatch monitor
After=network-online.target

[Service]
Type=simple
WorkingDirectory={repo_root}
ExecStart={python_executable} {script_path} monitor run
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
        self.repo_root = get_repo_root(repo_root)
        self.paths = ensure_monitor_layout(self.repo_root)
        self.config = load_monitor_config(self.repo_root)
        self.state = MonitorState(self.paths["state_db"])
        self.notifier = Notifier(self.state, self.config)
        self.updater = SnapshotUpdater(self.repo_root, self.config, self.state)
        self.pending_changes: Dict[str, Dict] = {}
        self.stop_requested = False
        self.identity = _service_identity(self.repo_root)
        self._configure_logging()

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
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(logging.INFO)
            file_handler.setFormatter(
                logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
            )
            root_logger.addHandler(file_handler)
        if os.path.exists(log_file):
            ensure_owner_only_permissions(log_file, OWNER_ONLY_FILE_MODE)

    def _run_command(self, command: List[str]) -> subprocess.CompletedProcess:
        """Run a subprocess command and capture output."""
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
        """Return the installed service definition path for one manager."""
        if manager == LAUNCHD_MANAGER:
            return os.path.expanduser(
                os.path.join(
                    "~",
                    "Library",
                    "LaunchAgents",
                    f"{self.identity['launchd_label']}.plist",
                )
            )
        if manager == SYSTEMD_MANAGER:
            return os.path.expanduser(
                os.path.join(
                    "~",
                    ".config",
                    "systemd",
                    "user",
                    self.identity["systemd_unit"],
                )
            )
        return None

    def _local_template_paths(self) -> Dict[str, str]:
        return {
            LAUNCHD_MANAGER: os.path.join(self.paths["services"], "launchd.plist"),
            SYSTEMD_MANAGER: os.path.join(self.paths["services"], "systemd.service"),
        }

    def _write_service_templates(self) -> Dict[str, str]:
        """Write repo-local copies of service templates."""
        template_paths = self._local_template_paths()
        with open(template_paths[LAUNCHD_MANAGER], "w", encoding="utf-8") as handle:
            handle.write(
                render_launchd_plist(
                    self.repo_root,
                    sys.executable,
                    self.identity["launchd_label"],
                    self.paths["log_file"],
                )
            )
        with open(template_paths[SYSTEMD_MANAGER], "w", encoding="utf-8") as handle:
            handle.write(
                render_systemd_service(
                    self.repo_root,
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
                "message": "systemd user service installed and started" if auto_start else "systemd user service installed",
            }

        raise ValueError(f"Unsupported service manager {manager}")

    def install(
        self,
        service_manager: Optional[str] = None,
        auto_start: bool = True,
    ) -> Dict[str, object]:
        """Initialize monitor files and install the selected service manager."""
        ensure_monitor_layout(self.repo_root)
        self.state.initialize()
        templates = self._write_service_templates()
        manager = self._detect_available_service_manager(service_manager)
        result: Dict[str, object] = {
            "config": self.paths["config"],
            "state_db": self.paths["state_db"],
            "launchd": templates[LAUNCHD_MANAGER],
            "systemd": templates[SYSTEMD_MANAGER],
            "service_manager": manager,
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

        manager_result = self._install_manager_service(manager, auto_start=auto_start)
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
            result = self._run_command(["launchctl", "print", self._launchd_service_name()])
            return result.returncode == 0
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

        status = {
            "configured_service_manager": configured_manager,
            "effective_service_manager": effective_manager,
            "installed_service_manager": installed_manager,
            "running": False,
            "pid": read_pid(self.paths["pid"]),
            "last_heartbeat_at": self.state.get_agent_state("last_heartbeat_at"),
            "last_threat_refresh_attempt_at": self.state.get_agent_state("last_threat_refresh_attempt_at"),
            "last_threat_refresh_at": self.state.get_agent_state("last_threat_refresh_at"),
            "last_threat_refresh_status": self.state.get_agent_state("last_threat_refresh_status"),
            "last_threat_refresh_message": self.state.get_agent_state("last_threat_refresh_message"),
            "scan_blocked_reason": self.state.get_agent_state("scan_blocked_reason"),
            "current_snapshot_version": self.state.get_agent_state("current_snapshot_version"),
            "current_snapshot_key_id": self.state.get_agent_state("current_snapshot_key_id"),
            "watch_summary": summary,
        }

        for manager in (LAUNCHD_MANAGER, SYSTEMD_MANAGER):
            target_path = self._service_target_path(manager)
            status[f"{manager}_service_definition"] = target_path
            status[f"{manager}_installed"] = bool(target_path and os.path.exists(target_path))

        if installed_manager:
            status["running"] = self._service_loaded(installed_manager)
            status["service_definition"] = self._service_target_path(installed_manager)
        else:
            status["running"] = pid_is_running(status["pid"])
            status["service_definition"] = None

        return status

    def doctor(self) -> Dict[str, object]:
        """Return detailed health information."""
        status = self.get_status()
        status.update(
            {
                "config_path": self.paths["config"],
                "state_db": self.paths["state_db"],
                "log_file": self.paths["log_file"],
                "services_dir": self.paths["services"],
                "snapshot_channel_url": self.config.get("snapshots", {}).get("channel_url", ""),
                "snapshot_manifest_url": self.config.get("snapshots", {}).get("manifest_url", ""),
                "snapshot_public_key_path": self.config.get("snapshots", {}).get("public_key_path", ""),
                "recent_notifications": self.state.list_recent_notifications(limit=5),
            }
        )
        return status

    def _start_local_background(self) -> Dict[str, object]:
        """Start the repo-local monitor daemon in the background."""
        pid = read_pid(self.paths["pid"])
        if pid_is_running(pid):
            return {"success": True, "message": "Monitor already running", "pid": pid}

        script_path = os.path.join(self.repo_root, "malicious_package_scanner.py")
        process = subprocess.Popen(
            [
                sys.executable,
                script_path,
                "monitor",
                "run",
            ],
            cwd=self.repo_root,
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
        """Stop the repo-local background daemon."""
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
            target_path = self._service_target_path(manager)
            service_name = self._launchd_service_name()
            if not target_path or not os.path.exists(target_path):
                return {"success": False, "message": "launchd service is not installed"}
            if not self._service_loaded(manager):
                bootstrap = self._run_command(["launchctl", "bootstrap", self._launchd_domain(), target_path])
                if bootstrap.returncode != 0:
                    return {"success": False, "message": bootstrap.stderr.strip() or bootstrap.stdout.strip() or "launchd bootstrap failed"}
            result = self._run_command(["launchctl", "kickstart", "-k", service_name])
            return {
                "success": result.returncode == 0,
                "service_manager": manager,
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
            target_path = self._service_target_path(manager)
            service_name = self._launchd_service_name()
            if not target_path or not os.path.exists(target_path):
                return {"success": False, "message": "launchd service is not installed"}
            if not self._service_loaded(manager):
                bootstrap = self._run_command(["launchctl", "bootstrap", self._launchd_domain(), target_path])
                if bootstrap.returncode != 0:
                    return {"success": False, "message": bootstrap.stderr.strip() or bootstrap.stdout.strip() or "launchd bootstrap failed"}
            result = self._run_command(["launchctl", "kickstart", "-k", service_name])
            return {
                "success": result.returncode == 0,
                "service_manager": manager,
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
        existing_pid = read_pid(self.paths["pid"])
        if pid_is_running(existing_pid) and existing_pid != os.getpid():
            raise RuntimeError(f"Monitor already running with pid {existing_pid}")

        signal.signal(signal.SIGTERM, self._handle_stop_signal)
        signal.signal(signal.SIGINT, self._handle_stop_signal)
        self._write_pid_file()
        self.state.set_agent_state("last_started_at", _utcnow())
        loops = 0

        try:
            while not self.stop_requested:
                self.run_iteration()
                loops += 1
                if max_loops is not None and loops >= max_loops:
                    break
                time.sleep(int(self.config.get("service", {}).get("loop_interval_seconds", 5)))
        finally:
            self.state.set_agent_state("last_stopped_at", _utcnow())
            self._cleanup_pid_file()

    def run_iteration(self) -> None:
        """Run one service loop iteration."""
        self.state.set_agent_state("last_heartbeat_at", _utcnow())
        refresh_result = self.updater.refresh_if_due(force=False)
        if not refresh_result.get("success"):
            message = refresh_result.get("message", "Threat data refresh failed")
            self.state.set_agent_state("scan_blocked_reason", message)
            logger.error("Threat data refresh failed; skipping scans: %s", message)
            return
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
        report_dir = os.path.join(self.paths["reports"], slug)
        os.makedirs(report_dir, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        return os.path.join(report_dir, f"{scan_kind}_{timestamp}.json")

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
        tracked_findings = build_tracked_findings(result, policy)
        changes = self.state.upsert_findings(project["path"], tracked_findings, result.report_path)
        self.state.update_project_scan(
            project["path"],
            scan_kind,
            result.report_path,
            result.exit_code,
            result.message,
            reason,
        )
        self.notifier.notify_project_changes(project["path"], changes, policy)
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
            "report_path": result.report_path,
            "new_findings": len(changes["new_findings"]),
            "escalated_findings": len(changes["escalated_findings"]),
            "resolved_findings": len(changes["resolved_findings"]),
        }
