#!/usr/bin/env python3
"""
macOS menu bar app for OreWatch.
"""

from __future__ import annotations

import errno
import fcntl
import importlib.metadata
import logging
import os
import shutil
import subprocess
import sys
import threading
import tomllib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from monitor.config import OWNER_ONLY_FILE_MODE
from monitor.config import ensure_owner_only_permissions
from monitor.config import ensure_not_symlink
from monitor.config import get_monitor_paths


MAC_MENUBAR_OPTIONAL_DEPENDENCY = "pyobjc-framework-Cocoa"
MENUBAR_APPLE_NOTIFICATION_SCRIPT = (
    "on run argv\n"
    "set notificationTitle to item 1 of argv\n"
    "set notificationSubtitle to item 2 of argv\n"
    "set notificationMessage to item 3 of argv\n"
    "if notificationSubtitle is equal to \"\" then\n"
    "display notification notificationMessage with title notificationTitle\n"
    "else\n"
    "display notification notificationMessage with title notificationTitle subtitle notificationSubtitle\n"
    "end if\n"
    "end run"
)
logger = logging.getLogger(__name__)
ATTENTION_NOTIFICATION_KINDS = {"findings", "dependency_blocked", "live_update_anomaly"}
_ASSETS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets")
DEFAULT_STATUSBAR_ICON_CANDIDATE_PATHS = (
    os.path.join(_ASSETS_DIR, "rapticore-icon-128.png"),
    os.path.join(_ASSETS_DIR, "notification-icon.png"),
)


def _resolve_orewatch_version() -> str:
    """Return the installed OreWatch version, falling back to local source metadata."""
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


OREWATCH_VERSION = _resolve_orewatch_version()


def orewatch_version_label() -> str:
    """Return the menu-bar label for the current OreWatch version."""
    if OREWATCH_VERSION:
        return f"OreWatch v{OREWATCH_VERSION}"
    return "OreWatch"


@dataclass
class MenuBarSnapshot:
    """Data rendered into the menu bar UI."""

    running: bool
    api_listening: bool
    active_findings: int
    highest_active_severity: Optional[str]
    active_findings_preview: List[Dict[str, Any]]
    recent_notifications: List[Dict[str, Any]]
    monitor_home: str
    reports_dir: str
    log_file: str
    api_base_url: str
    watch_count: int
    last_live_promotion_at: str = ""
    last_live_promotion_status: str = ""
    last_action_message: str = ""


def _truncate(text: str, limit: int = 80) -> str:
    normalized = " ".join(str(text).split())
    if len(normalized) <= limit:
        return normalized
    return normalized[: max(limit - 3, 0)] + "..."


def _selector(method_name: str) -> str:
    """Convert a PyObjC method name into an Objective-C selector string."""
    return method_name.replace("_", ":")


def _read_pid(pid_path: str) -> Optional[int]:
    if not os.path.exists(pid_path):
        return None
    ensure_not_symlink(pid_path, "OreWatch menu bar pid file")
    try:
        with open(pid_path, "r", encoding="utf-8") as handle:
            return int(handle.read().strip())
    except (OSError, ValueError):
        return None


def _pid_is_running(pid: Optional[int]) -> bool:
    if not pid:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    try:
        result = subprocess.run(
            ["ps", "-o", "stat=", "-p", str(pid)],
            check=False,
            text=True,
            capture_output=True,
        )
    except OSError:
        return True
    if result.returncode != 0:
        return False
    process_state = (result.stdout or "").strip().upper()
    if "Z" in process_state:
        return False
    return True


class MenuBarRuntimeLock:
    """Singleton runtime lock for the menu bar app."""

    def __init__(self, lock_path: str):
        self.lock_path = lock_path
        self.handle = None

    def acquire(self) -> bool:
        if self.handle is not None:
            return True
        ensure_not_symlink(self.lock_path, "OreWatch menu bar runtime lock")
        handle = open(self.lock_path, "a+", encoding="utf-8")
        ensure_owner_only_permissions(self.lock_path, OWNER_ONLY_FILE_MODE)
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            handle.close()
            if exc.errno in {errno.EACCES, errno.EAGAIN}:
                return False
            raise
        self.handle = handle
        self.handle.seek(0)
        self.handle.truncate()
        self.handle.write(f"pid={os.getpid()}\n")
        self.handle.flush()
        return True

    def release(self) -> None:
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


def _runtime_paths(workspace_root: Optional[str] = None) -> Dict[str, str]:
    paths = get_monitor_paths(workspace_root)
    return {
        "pid": paths["menubar_pid"],
        "lock": paths["menubar_lock"],
    }


def menubar_runtime_status(workspace_root: Optional[str] = None) -> Dict[str, object]:
    paths = _runtime_paths(workspace_root)
    pid = _read_pid(paths["pid"])
    return {
        "pid": pid,
        "running": _pid_is_running(pid),
        "pid_path": paths["pid"],
        "lock_path": paths["lock"],
    }


def _attention_statusbar_color(AppKit):
    """Return the menu bar attention color."""
    if hasattr(AppKit.NSColor, "systemRedColor"):
        return AppKit.NSColor.systemRedColor()
    return AppKit.NSColor.redColor()


def _configure_statusbar_icon(image, Foundation, template: bool) -> None:
    """Apply common menu bar icon rendering options."""
    if hasattr(image, "setTemplate_"):
        image.setTemplate_(bool(template))
    if hasattr(image, "setSize_"):
        image.setSize_(Foundation.NSMakeSize(18.0, 18.0))


def _tinted_statusbar_icon(image, AppKit, Foundation):
    """Return a red-tinted copy of the status icon for urgent attention state."""
    if image is None:
        return None
    try:
        size = image.size()
        tinted = AppKit.NSImage.alloc().initWithSize_(size)
        tinted.lockFocus()
        rect = Foundation.NSMakeRect(0.0, 0.0, size.width, size.height)
        image.drawInRect_fromRect_operation_fraction_(
            rect,
            Foundation.NSMakeRect(0.0, 0.0, size.width, size.height),
            getattr(AppKit, "NSCompositingOperationSourceOver", getattr(AppKit, "NSCompositeSourceOver", 2)),
            1.0,
        )
        _attention_statusbar_color(AppKit).set()
        AppKit.NSRectFillUsingOperation(
            rect,
            getattr(AppKit, "NSCompositingOperationSourceAtop", getattr(AppKit, "NSCompositeSourceAtop", 3)),
        )
        tinted.unlockFocus()
        _configure_statusbar_icon(tinted, Foundation, template=False)
        return tinted
    except Exception:  # pragma: no cover - defensive UI fallback
        logger.exception("OreWatch could not tint the menu bar icon; falling back to the base icon")
        fallback = image.copy()
        _configure_statusbar_icon(fallback, Foundation, template=False)
        return fallback


def _load_statusbar_icon(AppKit, Foundation, attention: bool = False):
    """Load the bundled menu bar icon when available."""
    for icon_path in DEFAULT_STATUSBAR_ICON_CANDIDATE_PATHS:
        if not os.path.exists(icon_path):
            continue
        image = AppKit.NSImage.alloc().initWithContentsOfFile_(icon_path)
        if image is None:
            continue
        if attention:
            return _tinted_statusbar_icon(image, AppKit, Foundation)
        _configure_statusbar_icon(image, Foundation, template=True)
        return image
    return None


def notification_requires_attention(notification: Dict[str, Any]) -> bool:
    """Return True when a notification should keep the menu bar in alert state."""
    return str(notification.get("kind", "") or "") in ATTENTION_NOTIFICATION_KINDS


def _parse_utc_timestamp(value: Any) -> Optional[datetime]:
    raw_value = str(value or "").strip()
    if not raw_value:
        return None
    try:
        return datetime.strptime(raw_value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def notification_is_attention_active(
    notification: Dict[str, Any],
    last_live_promotion_at: str = "",
    last_live_promotion_status: str = "",
) -> bool:
    """Return True when an attention-worthy notification is still current."""
    if not notification_requires_attention(notification):
        return False
    return notification_is_visible(
        notification,
        last_live_promotion_at=last_live_promotion_at,
        last_live_promotion_status=last_live_promotion_status,
    )


def notification_is_visible(
    notification: Dict[str, Any],
    last_live_promotion_at: str = "",
    last_live_promotion_status: str = "",
) -> bool:
    """Return True when a notification should still be surfaced as current UI state."""
    if str(notification.get("kind", "") or "") != "live_update_anomaly":
        return True
    if str(last_live_promotion_status or "").strip().lower() != "success":
        return True
    promotion_at = _parse_utc_timestamp(last_live_promotion_at)
    created_at = _parse_utc_timestamp(notification.get("created_at", ""))
    if promotion_at is None or created_at is None:
        return True
    return created_at >= promotion_at


def count_unacknowledged_alert_notifications(
    notifications: List[Dict[str, Any]],
    acknowledged_notification_id: int,
    last_live_promotion_at: str = "",
    last_live_promotion_status: str = "",
) -> int:
    """Count attention-worthy notifications newer than the last acknowledged id."""
    return sum(
        1
        for notification in notifications
        if notification_is_attention_active(
            notification,
            last_live_promotion_at=last_live_promotion_at,
            last_live_promotion_status=last_live_promotion_status,
        )
        and int(notification.get("id", 0) or 0) > int(acknowledged_notification_id or 0)
    )


def latest_attention_notification(
    notifications: List[Dict[str, Any]],
    last_live_promotion_at: str = "",
    last_live_promotion_status: str = "",
) -> Optional[Dict[str, Any]]:
    """Return the newest attention-worthy notification from a newest-first list."""
    for notification in notifications:
        if notification_is_attention_active(
            notification,
            last_live_promotion_at=last_live_promotion_at,
            last_live_promotion_status=last_live_promotion_status,
        ):
            return notification
    return None


def latest_visible_notification(
    notifications: List[Dict[str, Any]],
    last_live_promotion_at: str = "",
    last_live_promotion_status: str = "",
) -> Optional[Dict[str, Any]]:
    """Return the newest notification that should still be surfaced in current UI state."""
    for notification in notifications:
        if notification_is_visible(
            notification,
            last_live_promotion_at=last_live_promotion_at,
            last_live_promotion_status=last_live_promotion_status,
        ):
            return notification
    return None


def format_notification_context(notification: Dict[str, Any]) -> str:
    """Render a compact context line for one notification."""
    parts: List[str] = []
    project_name = str(notification.get("project_name", "") or "").strip()
    created_at = str(notification.get("created_at", "") or "").strip()
    if project_name:
        parts.append(project_name)
    if created_at:
        parts.append(created_at.replace("T", " ").replace("Z", " UTC"))
    return " | ".join(parts)


def latest_alert_target_path(
    snapshot: MenuBarSnapshot,
    notification: Dict[str, Any],
) -> str:
    """Choose the best path to open for the newest alert."""
    project_path = str(notification.get("project_path", "") or "").strip()
    for finding in snapshot.active_findings_preview:
        if str(finding.get("project_path", "") or "").strip() != project_path:
            continue
        return str(
            finding.get("html_report_path")
            or finding.get("report_path")
            or finding.get("project_path")
            or snapshot.reports_dir
        )
    return project_path or snapshot.reports_dir


def build_menu_bar_title(
    snapshot: MenuBarSnapshot,
    attention_alert_count: int = 0,
) -> str:
    """Return a compact menu bar title."""
    if attention_alert_count > 0:
        return "OW!"
    if snapshot.active_findings > 0:
        return f"OW!{snapshot.active_findings}"
    if snapshot.running or snapshot.api_listening:
        return "OW"
    return "OW?"


def _attention_badge_label(attention_alert_count: int) -> str:
    """Render a compact persistent badge for unreviewed alerts."""
    count = max(int(attention_alert_count or 0), 0)
    if count <= 0:
        return ""
    if count == 1:
        return "!"
    if count > 9:
        return "!9+"
    return f"!{count}"


def build_menu_bar_button_title(
    snapshot: MenuBarSnapshot,
    attention_alert_count: int = 0,
    has_status_icon: bool = True,
) -> str:
    """Return the status-item title text, including text fallback when no icon is available."""
    if has_status_icon:
        return _attention_badge_label(attention_alert_count)
    return build_menu_bar_title(snapshot, attention_alert_count=attention_alert_count)


def _attention_badge_attributes(AppKit) -> Dict[str, Any]:
    """Return the status-item badge styling for alert state."""
    return {
        AppKit.NSForegroundColorAttributeName: _attention_statusbar_color(AppKit),
        AppKit.NSFontAttributeName: AppKit.NSFont.boldSystemFontOfSize_(
            AppKit.NSFont.systemFontSize()
        ),
    }


def build_menu_bar_tooltip(
    snapshot: MenuBarSnapshot,
    attention_alert_count: int = 0,
) -> str:
    """Return a tooltip summarizing current monitor state."""
    status = "running" if snapshot.running else "stopped"
    lines = [
        f"{orewatch_version_label()} monitor {status}",
        f"Watched projects: {snapshot.watch_count}",
        f"Active findings: {snapshot.active_findings}",
    ]
    newest_alert = latest_attention_notification(
        snapshot.recent_notifications,
        last_live_promotion_at=snapshot.last_live_promotion_at,
        last_live_promotion_status=snapshot.last_live_promotion_status,
    )
    if attention_alert_count > 0:
        lines.append(f"New alerts requiring review: {attention_alert_count}")
    if attention_alert_count > 0 and newest_alert is not None:
        lines.append(f"Latest alert: {_truncate(str(newest_alert.get('message', '')))}")
    if snapshot.highest_active_severity:
        lines.append(f"Highest severity: {snapshot.highest_active_severity}")
    if attention_alert_count > 0 and newest_alert is not None:
        pass
    elif snapshot.active_findings_preview:
        top = snapshot.active_findings_preview[0]
        lines.append(f"Top finding: {_truncate(str(top.get('title', '')))}")
    else:
        latest_notification = latest_visible_notification(
            snapshot.recent_notifications,
            last_live_promotion_at=snapshot.last_live_promotion_at,
            last_live_promotion_status=snapshot.last_live_promotion_status,
        )
        if latest_notification is not None:
            lines.append(
                f"Latest notification: {_truncate(str(latest_notification.get('message', '')))}"
            )
    return "\n".join(lines)


def build_popup_title(notification: Dict[str, Any]) -> str:
    kind = str(notification.get("kind", "") or "")
    if kind == "resolved":
        return "OreWatch resolved finding"
    if kind == "findings":
        return "OreWatch security alert"
    if kind == "live_update_anomaly":
        return "OreWatch threat data alert"
    return "OreWatch notification"


def _deliver_macos_notification(
    title: str,
    subtitle: str,
    message: str,
) -> bool:
    """Use AppleScript Notification Center delivery when available."""
    if not shutil.which("osascript"):
        return False
    # Sanitize inputs passed to osascript to prevent command injection via
    # crafted notification strings.  Strip control characters and limit length.
    def _sanitize(text: str, max_len: int = 256) -> str:
        cleaned = "".join(ch for ch in text if ch.isprintable())
        return cleaned[:max_len]

    title = _sanitize(title)
    subtitle = _sanitize(subtitle)
    message = _sanitize(message)
    result = subprocess.run(
        [
            "osascript",
            "-e",
            MENUBAR_APPLE_NOTIFICATION_SCRIPT,
            title,
            subtitle,
            message,
        ],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0


def notification_setting_labels() -> Dict[str, str]:
    return {
        "desktop": "Desktop notifications",
        "terminal": "Terminal notifications",
        "auto_launch_menubar": "Keep menu bar app running",
        "popup_via_menubar": "Show popups via menu bar",
    }


def collect_menu_bar_snapshot(
    service,
    findings_limit: int = 5,
    notifications_limit: int = 20,
    last_action_message: str = "",
) -> MenuBarSnapshot:
    """Collect the current singleton monitor state for the menu bar."""
    status = service.get_status()
    findings = service.list_active_findings(limit=findings_limit)
    notifications = service.list_recent_notifications(limit=notifications_limit)
    watch_summary = status.get("watch_summary", {}) or {}
    return MenuBarSnapshot(
        running=bool(status.get("running")),
        api_listening=bool(status.get("api_listening")),
        active_findings=int(status.get("active_findings", findings.get("count", 0)) or 0),
        highest_active_severity=status.get("highest_active_severity")
        or findings.get("highest_severity"),
        active_findings_preview=list(findings.get("findings", [])),
        recent_notifications=list(notifications.get("notifications", [])),
        monitor_home=str(status.get("monitor_home") or service.paths["home"]),
        reports_dir=str(service.paths["reports"]),
        log_file=str(service.paths["log_file"]),
        api_base_url=str(status.get("api_base_url") or service.get_connection_info()["base_url"]),
        watch_count=int(watch_summary.get("watched_projects", 0) or 0),
        last_live_promotion_at=str(status.get("last_live_promotion_at") or ""),
        last_live_promotion_status=str(status.get("last_live_promotion_status") or ""),
        last_action_message=last_action_message,
    )


def _load_pyobjc() -> tuple[Any, Any, Any]:
    """Import the macOS UI bindings on demand."""
    if sys.platform != "darwin":
        raise RuntimeError("OreWatch menu bar mode is only supported on macOS")
    try:
        import AppKit  # type: ignore
        import Foundation  # type: ignore
        import objc  # type: ignore
    except ImportError as exc:  # pragma: no cover - depends on local runtime
        raise RuntimeError(
            "OreWatch menu bar mode requires PyObjC. "
            f"Install the optional dependency with: pip install '{MAC_MENUBAR_OPTIONAL_DEPENDENCY}'"
        ) from exc
    return AppKit, Foundation, objc


def ensure_menubar_supported() -> None:
    """Fail fast if the current runtime cannot launch the macOS menu bar app."""
    _load_pyobjc()


def build_detached_menubar_command(
    refresh_seconds: float = 15.0,
    workspace_root: Optional[str] = None,
) -> List[str]:
    """Build the command used to relaunch the menu bar app in detached mode."""
    command = [
        sys.executable,
        "-m",
        "malicious_package_scanner",
        "monitor",
        "menubar",
        "--foreground",
        "--refresh-seconds",
        str(float(refresh_seconds)),
    ]
    if workspace_root:
        command.extend(["--workspace-root", os.path.abspath(workspace_root)])
    return command


def launch_menubar_app_detached(
    refresh_seconds: float = 15.0,
    workspace_root: Optional[str] = None,
) -> Dict[str, Any]:
    """Launch the menu bar app as a detached background process."""
    status = menubar_runtime_status(workspace_root)
    if status["running"]:
        return {
            "success": True,
            "pid": status["pid"],
            "message": f"OreWatch menu bar app already running (pid: {status['pid']})",
        }
    ensure_menubar_supported()
    command = build_detached_menubar_command(
        refresh_seconds=refresh_seconds,
        workspace_root=workspace_root,
    )
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        close_fds=True,
        cwd=os.getcwd(),
        env=os.environ.copy(),
    )
    return {
        "success": True,
        "pid": process.pid,
        "message": f"OreWatch menu bar app launched in background (pid: {process.pid})",
    }


def run_menubar_app(service, refresh_seconds: float = 15.0) -> int:
    """Run the native macOS menu bar app."""
    AppKit, Foundation, objc = _load_pyobjc()
    runtime_paths = _runtime_paths(service.requested_workspace_root)
    runtime_lock = MenuBarRuntimeLock(runtime_paths["lock"])
    if not runtime_lock.acquire():
        return 0

    ensure_not_symlink(runtime_paths["pid"], "OreWatch menu bar pid file")
    with open(runtime_paths["pid"], "w", encoding="utf-8") as handle:
        handle.write(str(os.getpid()))
    ensure_owner_only_permissions(runtime_paths["pid"], OWNER_ONLY_FILE_MODE)
    service.state.set_agent_state("menubar_pid", str(os.getpid()))
    service.state.set_agent_state("menubar_running", "true")

    class OreWatchMenuBarController(Foundation.NSObject):
        def initWithService_refreshSeconds_(self, service_obj, refresh_interval):
            self = objc.super(OreWatchMenuBarController, self).init()
            if self is None:
                return None
            self.service = service_obj
            self.refresh_seconds = max(float(refresh_interval), 5.0)
            self.last_action_message = ""
            self.action_payloads: Dict[int, Dict[str, Any]] = {}
            self.next_action_id = 1
            self.last_seen_notification_id = self._latest_notification_id()
            self.last_acknowledged_notification_id = self._notification_cursor_state(
                "menubar_last_acknowledged_notification_id"
            )
            self.last_attention_notification_id = max(
                self._notification_cursor_state("menubar_last_attention_notification_id"),
                self._latest_attention_notification_id(),
            )
            self.status_item = AppKit.NSStatusBar.systemStatusBar().statusItemWithLength_(
                AppKit.NSVariableStatusItemLength
            )
            self.status_icon = _load_statusbar_icon(AppKit, Foundation)
            self.attention_status_icon = _load_statusbar_icon(
                AppKit,
                Foundation,
                attention=True,
            )
            self.menu = AppKit.NSMenu.alloc().init()
            self.menu.setAutoenablesItems_(False)
            self.menu.setDelegate_(self)
            self.status_item.setMenu_(self.menu)
            self.notification_center = getattr(AppKit, "NSUserNotificationCenter", None)
            if self.notification_center is not None:
                self.notification_center = AppKit.NSUserNotificationCenter.defaultUserNotificationCenter()
                self.notification_center.setDelegate_(self)
            self._ensure_monitor_ready()
            self.refresh_(None)
            self.timer = Foundation.NSTimer.scheduledTimerWithTimeInterval_target_selector_userInfo_repeats_(
                self.refresh_seconds,
                self,
                _selector("refresh_"),
                None,
                True,
            )
            return self

        def _ensure_monitor_ready(self):
            status = self.service.get_status()
            if status.get("running") or status.get("api_listening"):
                return
            result = self.service.install(service_manager="auto", auto_start=True)
            self.last_action_message = str(result.get("message", "Started OreWatch monitor"))

        def _latest_notification_id(self) -> int:
            notifications = self.service.list_recent_notifications(limit=1).get("notifications", [])
            if not notifications:
                return 0
            return int(notifications[0].get("id", 0) or 0)

        def _notification_cursor_state(self, key: str) -> int:
            raw_value = self.service.state.get_agent_state(key, "0")
            try:
                return int(raw_value or 0)
            except (TypeError, ValueError):
                return 0

        def _latest_attention_notification_id(self) -> int:
            notifications = self.service.list_recent_notifications(limit=20).get("notifications", [])
            relevant_ids = [
                int(notification.get("id", 0) or 0)
                for notification in notifications
                if notification_is_attention_active(
                    notification,
                    last_live_promotion_at=self.service.state.get_agent_state("last_live_promotion_at"),
                    last_live_promotion_status=self.service.state.get_agent_state("last_live_promotion_status"),
                )
            ]
            if not relevant_ids:
                return 0
            return max(relevant_ids)

        def _attention_alert_count(self, snapshot: MenuBarSnapshot) -> int:
            count = count_unacknowledged_alert_notifications(
                snapshot.recent_notifications,
                self.last_acknowledged_notification_id,
                last_live_promotion_at=snapshot.last_live_promotion_at,
                last_live_promotion_status=snapshot.last_live_promotion_status,
            )
            if count > 0:
                return count
            newest_alert = latest_attention_notification(
                snapshot.recent_notifications,
                last_live_promotion_at=snapshot.last_live_promotion_at,
                last_live_promotion_status=snapshot.last_live_promotion_status,
            )
            if newest_alert and int(newest_alert.get("id", 0) or 0) > self.last_acknowledged_notification_id:
                return 1
            return 0

        def _deliver_new_notifications(self, snapshot: MenuBarSnapshot):
            new_notifications = [
                notification
                for notification in snapshot.recent_notifications
                if int(notification.get("id", 0) or 0) > self.last_seen_notification_id
            ]
            if not new_notifications:
                return
            for notification in sorted(
                new_notifications,
                key=lambda item: int(item.get("id", 0) or 0),
            ):
                if notification_requires_attention(notification):
                    self.last_attention_notification_id = max(
                        self.last_attention_notification_id,
                        int(notification.get("id", 0) or 0),
                    )
                self._show_popup(notification)
                self.last_seen_notification_id = max(
                    self.last_seen_notification_id,
                    int(notification.get("id", 0) or 0),
                )
            self.service.state.set_agent_state(
                "menubar_last_seen_notification_id",
                str(self.last_seen_notification_id),
            )
            self.service.state.set_agent_state(
                "menubar_last_attention_notification_id",
                str(self.last_attention_notification_id),
            )

        def _show_popup(self, notification: Dict[str, Any]):
            project_name = str(notification.get("project_name", "") or "").strip()
            title = build_popup_title(notification)
            message = _truncate(str(notification.get("message", "")), 220)
            if _deliver_macos_notification(title, project_name, message):
                logger.info(
                    "OreWatch delivered macOS notification for notification id %s via osascript",
                    notification.get("id", ""),
                )
                return

            center = getattr(self, "notification_center", None)
            if center is None:
                logger.warning(
                    "OreWatch could not deliver popup for notification id %s: no notification center available",
                    notification.get("id", ""),
                )
                return
            user_notification = AppKit.NSUserNotification.alloc().init()
            user_notification.setTitle_(title)
            if project_name:
                user_notification.setSubtitle_(project_name)
            user_notification.setInformativeText_(message)
            icon_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "assets", "notification-icon.png"
            )
            if os.path.exists(icon_path):
                icon = AppKit.NSImage.alloc().initWithContentsOfFile_(icon_path)
                if icon:
                    user_notification.setContentImage_(icon)
            if hasattr(AppKit, "NSUserNotificationDefaultSoundName"):
                user_notification.setSoundName_(AppKit.NSUserNotificationDefaultSoundName)
            center.deliverNotification_(user_notification)
            logger.info(
                "OreWatch delivered macOS notification for notification id %s via NSUserNotification",
                notification.get("id", ""),
            )

        def userNotificationCenter_shouldPresentNotification_(self, _center, _notification):
            return True

        def menuWillOpen_(self, _menu):
            return None

        def menuDidClose_(self, _menu):
            return None

        def _set_status_visuals(self, snapshot: MenuBarSnapshot):
            attention_alert_count = self._attention_alert_count(snapshot)
            title = build_menu_bar_title(snapshot, attention_alert_count=attention_alert_count)
            active_status_icon = self.status_icon
            if attention_alert_count > 0 and self.attention_status_icon is not None:
                active_status_icon = self.attention_status_icon
            button_title = build_menu_bar_button_title(
                snapshot,
                attention_alert_count=attention_alert_count,
                has_status_icon=active_status_icon is not None,
            )
            tooltip = build_menu_bar_tooltip(
                snapshot,
                attention_alert_count=attention_alert_count,
            )
            button = self.status_item.button()
            if button is not None:
                if hasattr(button, "setImage_"):
                    button.setImage_(active_status_icon)
                if active_status_icon is not None:
                    if hasattr(AppKit, "NSImageLeft"):
                        button.setImagePosition_(
                            AppKit.NSImageLeft if button_title else AppKit.NSImageOnly
                        )
                rendered_title = button_title or (title if active_status_icon is None else "")
                if (
                    attention_alert_count > 0
                    and rendered_title
                    and hasattr(button, "setAttributedTitle_")
                ):
                    attributed_title = Foundation.NSAttributedString.alloc().initWithString_attributes_(
                        rendered_title,
                        _attention_badge_attributes(AppKit),
                    )
                    button.setAttributedTitle_(attributed_title)
                    button.setTitle_("")
                else:
                    if hasattr(button, "setAttributedTitle_"):
                        empty_title = Foundation.NSAttributedString.alloc().initWithString_attributes_(
                            "",
                            {},
                        )
                        button.setAttributedTitle_(empty_title)
                    button.setTitle_(rendered_title)
                button.setToolTip_(tooltip)
                return
            self.status_item.setTitle_(title)
            self.status_item.setToolTip_(tooltip)

        def _next_action_id(self) -> int:
            current = self.next_action_id
            self.next_action_id += 1
            return current

        def _make_item(
            self,
            title: str,
            selector: Optional[str] = None,
            payload: Optional[Dict[str, Any]] = None,
            enabled: bool = True,
        ):
            item = AppKit.NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(
                title,
                selector,
                "",
            )
            item.setEnabled_(enabled)
            if selector:
                item.setTarget_(self)
                if payload is not None:
                    tag = self._next_action_id()
                    self.action_payloads[tag] = payload
                    item.setTag_(tag)
            return item

        def _make_toggle_item(
            self,
            title: str,
            selector: str,
            payload: Dict[str, Any],
            checked: bool,
            enabled: bool = True,
        ):
            item = self._make_item(title, selector, payload, enabled=enabled)
            on_value = getattr(AppKit, "NSControlStateValueOn", 1)
            off_value = getattr(AppKit, "NSControlStateValueOff", 0)
            item.setState_(on_value if checked else off_value)
            return item

        def _menu_payload(self, sender) -> Dict[str, Any]:
            return self.action_payloads.get(int(sender.tag()), {})

        def _open_path(self, path: str) -> None:
            if not path:
                return
            # Validate the path before opening to prevent path traversal.
            path = os.path.abspath(path)
            if "\x00" in path or os.path.islink(path):
                return
            workspace = AppKit.NSWorkspace.sharedWorkspace()
            if workspace.openFile_(path):
                return
            subprocess.run(["open", path], check=False)

        def _choose_directory(self) -> Optional[str]:
            panel = AppKit.NSOpenPanel.openPanel()
            panel.setCanChooseDirectories_(True)
            panel.setCanChooseFiles_(False)
            panel.setCanCreateDirectories_(False)
            panel.setAllowsMultipleSelection_(False)
            response = panel.runModal()
            ok_value = getattr(AppKit, "NSModalResponseOK", 1)
            if int(response) != int(ok_value):
                return None
            url = panel.URL()
            if url is None:
                return None
            return str(url.path())

        def _start_async_action(self, message: str, fn) -> None:
            self.last_action_message = message
            self.refresh_(None)

            def runner():
                try:
                    result = fn()
                    if isinstance(result, dict):
                        self.last_action_message = str(result.get("message", message))
                    else:
                        self.last_action_message = message
                except Exception as exc:  # pragma: no cover - defensive UI boundary
                    self.last_action_message = f"Action failed: {exc}"
                finally:
                    self.performSelectorOnMainThread_withObject_waitUntilDone_(
                        _selector("refresh_"),
                        None,
                        False,
                    )

            thread = threading.Thread(target=runner, daemon=True)
            thread.start()

        def refresh_(self, _sender):
            self.action_payloads = {}
            self.last_acknowledged_notification_id = max(
                self.last_acknowledged_notification_id,
                self._notification_cursor_state("menubar_last_acknowledged_notification_id"),
            )
            snapshot = collect_menu_bar_snapshot(
                self.service,
                last_action_message=self.last_action_message,
            )
            self._deliver_new_notifications(snapshot)
            self._set_status_visuals(snapshot)
            self.menu.removeAllItems()

            self.menu.addItem_(self._make_item(orewatch_version_label(), enabled=False))
            attention_alert_count = self._attention_alert_count(snapshot)
            newest_alert = latest_attention_notification(
                snapshot.recent_notifications,
                last_live_promotion_at=snapshot.last_live_promotion_at,
                last_live_promotion_status=snapshot.last_live_promotion_status,
            )
            if attention_alert_count > 0:
                self.menu.addItem_(
                    self._make_item(
                        f"NEW ALERTS REQUIRING REVIEW: {attention_alert_count}",
                        enabled=False,
                    )
                )
            if newest_alert is not None:
                newest_alert_target = latest_alert_target_path(snapshot, newest_alert)
                self.menu.addItem_(self._make_item("Latest alert", enabled=False))
                self.menu.addItem_(
                    self._make_item(
                        _truncate(str(newest_alert.get("message", "")), 90),
                        _selector("openFinding_"),
                        {"path": newest_alert_target},
                        enabled=bool(newest_alert_target),
                    )
                )
                newest_alert_context = format_notification_context(newest_alert)
                if newest_alert_context:
                    self.menu.addItem_(
                        self._make_item(_truncate(newest_alert_context, 90), enabled=False)
                    )
            if newest_alert is not None or attention_alert_count > 0:
                self.menu.addItem_(
                    self._make_item(
                        "Mark Alerts Reviewed",
                        _selector("markAlertsReviewed_"),
                        enabled=attention_alert_count > 0,
                    )
                )
                self.menu.addItem_(AppKit.NSMenuItem.separatorItem())
            running_status = "Running" if snapshot.running else "Stopped"
            self.menu.addItem_(self._make_item(f"Monitor: {running_status}", enabled=False))
            self.menu.addItem_(
                self._make_item(
                    f"Active findings: {snapshot.active_findings}"
                    + (
                        f" ({snapshot.highest_active_severity})"
                        if snapshot.highest_active_severity
                        else ""
                    ),
                    enabled=False,
                )
            )
            self.menu.addItem_(
                self._make_item(f"Watched projects: {snapshot.watch_count}", enabled=False)
            )
            if snapshot.last_action_message:
                self.menu.addItem_(
                    self._make_item(_truncate(snapshot.last_action_message, 90), enabled=False)
                )

            self.menu.addItem_(AppKit.NSMenuItem.separatorItem())
            if snapshot.recent_notifications:
                self.menu.addItem_(self._make_item("Recent notifications", enabled=False))
                for notification in snapshot.recent_notifications[:5]:
                    label = f"{notification.get('created_at', '')} {notification.get('message', '')}"
                    self.menu.addItem_(self._make_item(_truncate(label, 90), enabled=False))
            else:
                self.menu.addItem_(self._make_item("No recent notifications", enabled=False))

            self.menu.addItem_(AppKit.NSMenuItem.separatorItem())
            if snapshot.active_findings_preview:
                self.menu.addItem_(self._make_item("Active findings", enabled=False))
                for finding in snapshot.active_findings_preview:
                    label = f"[{str(finding.get('severity', 'unknown')).upper()}] {finding.get('title', 'Finding')}"
                    target_path = str(
                        finding.get("html_report_path")
                        or finding.get("report_path")
                        or finding.get("project_path")
                        or snapshot.reports_dir
                    )
                    self.menu.addItem_(
                        self._make_item(
                            _truncate(label, 90),
                            _selector("openFinding_"),
                            {"path": target_path},
                            enabled=bool(target_path),
                        )
                    )
            else:
                self.menu.addItem_(self._make_item("No active findings", enabled=False))

            self.menu.addItem_(AppKit.NSMenuItem.separatorItem())
            self.menu.addItem_(
                self._make_item("Add Workspace Folder...", _selector("addWatchedProject_"))
            )
            self.menu.addItem_(AppKit.NSMenuItem.separatorItem())
            self.menu.addItem_(
                self._make_item("Open Reports Folder", _selector("openReportsFolder_"))
            )
            self.menu.addItem_(
                self._make_item("Open Monitor Home", _selector("openMonitorHome_"))
            )
            self.menu.addItem_(
                self._make_item("Open Monitor Config", _selector("openMonitorConfig_"))
            )
            self.menu.addItem_(
                self._make_item("Open Config Folder", _selector("openConfigHome_"))
            )
            self.menu.addItem_(self._make_item("Open Monitor Log", _selector("openMonitorLog_")))
            self.menu.addItem_(AppKit.NSMenuItem.separatorItem())
            self.menu.addItem_(self._make_item("Configuration", enabled=False))
            notifications_config = self.service.config.get("notifications", {}) or {}
            for key, label in notification_setting_labels().items():
                self.menu.addItem_(
                    self._make_toggle_item(
                        label,
                        _selector("toggleNotificationSetting_"),
                        {"key": key, "label": label},
                        checked=bool(notifications_config.get(key, False)),
                    )
                )
            self.menu.addItem_(AppKit.NSMenuItem.separatorItem())
            self.menu.addItem_(self._make_item("Refresh Now", _selector("refresh_")))
            self.menu.addItem_(self._make_item("Run Quick Scan", _selector("runQuickScan_")))
            self.menu.addItem_(self._make_item("Run Full Scan", _selector("runFullScan_")))
            if snapshot.running:
                self.menu.addItem_(self._make_item("Restart Monitor", _selector("restartMonitor_")))
                self.menu.addItem_(self._make_item("Stop Monitor", _selector("stopMonitor_")))
            else:
                self.menu.addItem_(self._make_item("Start Monitor", _selector("startMonitor_")))
            self.menu.addItem_(AppKit.NSMenuItem.separatorItem())
            self.menu.addItem_(self._make_item("Quit OreWatch Menu Bar", _selector("quitApp_")))

        def openFinding_(self, sender):
            payload = self._menu_payload(sender)
            self._open_path(str(payload.get("path", "")))

        def openReportsFolder_(self, _sender):
            self._open_path(self.service.paths["reports"])

        def openMonitorHome_(self, _sender):
            self._open_path(self.service.paths["home"])

        def openMonitorLog_(self, _sender):
            self._open_path(self.service.paths["log_file"])

        def openMonitorConfig_(self, _sender):
            self._open_path(self.service.paths["config"])

        def openConfigHome_(self, _sender):
            self._open_path(self.service.paths["config_home"])

        def addWatchedProject_(self, _sender):
            path = self._choose_directory()
            if not path:
                self.last_action_message = "Add workspace cancelled"
                self.refresh_(None)
                return
            self._start_async_action(
                f"Watching {path}...",
                lambda: self.service.add_watched_project(path, initial_scan_kind="quick"),
            )

        def toggleNotificationSetting_(self, sender):
            payload = self._menu_payload(sender)
            key = str(payload.get("key", "")).strip()
            label = str(payload.get("label", key)).strip() or key
            current = bool((self.service.config.get("notifications", {}) or {}).get(key, False))
            self._start_async_action(
                f"{'Disabling' if current else 'Enabling'} {label.lower()}...",
                lambda: self.service.set_notification_preference(key, not current),
            )

        def runQuickScan_(self, _sender):
            self._start_async_action("Running quick scan...", lambda: self.service.scan_now(full=False))

        def runFullScan_(self, _sender):
            self._start_async_action("Running full scan...", lambda: self.service.scan_now(full=True))

        def markAlertsReviewed_(self, _sender):
            result = self.service.mark_alerts_reviewed()
            self.last_acknowledged_notification_id = int(
                result.get("acknowledged_notification_id", self.last_acknowledged_notification_id) or 0
            )
            self.last_action_message = str(result.get("message", "Marked alerts reviewed"))
            self.refresh_(None)

        def startMonitor_(self, _sender):
            self._start_async_action(
                "Starting monitor...",
                lambda: self.service.install(service_manager="auto", auto_start=True),
            )

        def restartMonitor_(self, _sender):
            self._start_async_action("Restarting monitor...", self.service.restart)

        def stopMonitor_(self, _sender):
            self._start_async_action("Stopping monitor...", self.service.stop)

        def quitApp_(self, _sender):
            if getattr(self, "timer", None) is not None:
                self.timer.invalidate()
            AppKit.NSApp.terminate_(None)

    app = AppKit.NSApplication.sharedApplication()
    app.setActivationPolicy_(AppKit.NSApplicationActivationPolicyAccessory)
    controller = OreWatchMenuBarController.alloc().initWithService_refreshSeconds_(
        service,
        refresh_seconds,
    )
    app.setDelegate_(controller)
    try:
        app.run()
        return 0
    finally:
        service.state.set_agent_state("menubar_running", "false")
        service.state.set_agent_state("menubar_pid", "")
        if os.path.exists(runtime_paths["pid"]):
            try:
                os.unlink(runtime_paths["pid"])
            except OSError:
                pass
        runtime_lock.release()
