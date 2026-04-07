#!/usr/bin/env python3
"""
Notification helpers for the background monitor.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import sys
import urllib.request
from typing import Dict


logger = logging.getLogger(__name__)
APPLE_NOTIFICATION_SCRIPT = (
    "on run argv\n"
    "set notificationTitle to item 1 of argv\n"
    "set notificationMessage to item 2 of argv\n"
    "display notification notificationMessage with title notificationTitle\n"
    "end run"
)
_ASSETS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets")
NOTIFICATION_ICON_PATH = os.path.join(_ASSETS_DIR, "notification-icon.png")


class Notifier:
    """Send and record monitor notifications."""

    def __init__(self, state, monitor_config: Dict, paths: Dict | None = None):
        self.state = state
        self.config = monitor_config
        self.paths = paths or {}

    def notify_project_changes(
        self,
        project_path: str,
        changes: Dict,
        project_policy: Dict,
        report_path: str | None = None,
    ) -> None:
        """Emit notifications for new or escalated findings."""
        notify_on = set(project_policy.get("notify_on", ["malicious_package", "ioc"]))
        new_findings = [
            finding
            for finding in changes.get("new_findings", [])
            if finding["finding_type"] in notify_on
        ]
        escalated_findings = [
            finding
            for finding in changes.get("escalated_findings", [])
            if finding["finding_type"] in notify_on
        ]
        resolved_findings = [
            finding
            for finding in changes.get("resolved_findings", [])
            if finding["finding_type"] in notify_on
        ]

        if not new_findings and not escalated_findings:
            if resolved_findings and self.config.get("notifications", {}).get("notify_on_resolved"):
                message = self._build_message(
                    project_path,
                    "resolved",
                    resolved_findings,
                    [],
                    report_path,
                )
                self._emit(
                    project_path,
                    "resolved",
                    message,
                    details=self._build_details(
                        project_path,
                        new_findings=[],
                        escalated_findings=[],
                        resolved_findings=resolved_findings,
                        report_path=report_path,
                    ),
                )
            return

        message = self._build_message(
            project_path,
            "findings",
            new_findings,
            escalated_findings,
            report_path,
            resolved_findings=resolved_findings,
        )
        self._emit(
            project_path,
            "findings",
            message,
            details=self._build_details(
                project_path,
                new_findings=new_findings,
                escalated_findings=escalated_findings,
                resolved_findings=resolved_findings,
                report_path=report_path,
            ),
        )

    def notify_dependency_blocked(
        self,
        project_path: str,
        check_id: str,
        results: list[Dict],
        source: Dict,
    ) -> None:
        """Emit notifications when a dependency add/install is blocked."""
        malicious = [r for r in results if r.get("status") == "malicious_match"]
        if not malicious:
            return

        project_name = os.path.basename(project_path) or project_path
        pkg_names = [str(r.get("name", "unknown")) for r in malicious]
        if len(pkg_names) <= 2:
            pkg_list = ", ".join(pkg_names)
        else:
            pkg_list = f"{pkg_names[0]}, {pkg_names[1]}, +{len(pkg_names) - 2} more"

        remediation_cmds = [
            str(r.get("user_action_required", ""))
            for r in malicious
            if r.get("user_action_required")
        ]
        if remediation_cmds:
            remediation_suffix = " — " + "; ".join(remediation_cmds[:2])
            if len(remediation_cmds) > 2:
                remediation_suffix += f"; +{len(remediation_cmds) - 2} more"
        else:
            remediation_suffix = ""
        message = (
            f"Blocked {len(malicious)} malicious package(s) in {project_name}: "
            f"{pkg_list}{remediation_suffix}"
        )

        highest_severity = "critical" if malicious else None
        details = {
            "project_path": project_path,
            "project_name": project_name,
            "check_id": check_id,
            "source": source,
            "highest_severity": highest_severity,
            "blocked_packages": [
                {
                    "name": str(r.get("name", "")),
                    "version": str(r.get("resolved_version", r.get("requested_spec", ""))),
                    "severity": str(r.get("severity", "critical")),
                    "reason": str(r.get("reason", "")),
                    "sources": list(r.get("sources", [])),
                }
                for r in malicious
            ],
        }

        self._emit(project_path, "dependency_blocked", message, details=details)

    def _finding_brief(self, finding: Dict) -> str:
        severity = str(finding.get("severity", "unknown")).upper()
        title = str(finding.get("title", "OreWatch finding")).strip()
        return f"{severity} {title}"

    def _build_message(
        self,
        project_path: str,
        kind: str,
        primary_findings: list[Dict],
        escalated_findings: list[Dict],
        report_path: str | None,
        resolved_findings: list[Dict] | None = None,
    ) -> str:
        project_name = os.path.basename(project_path) or project_path
        resolved_findings = resolved_findings or []
        if kind == "resolved":
            details = ", ".join(
                self._finding_brief(finding) for finding in resolved_findings[:2]
            )
            suffix = f"; {details}" if details else ""
            message = f"{len(resolved_findings)} finding(s) resolved in {project_name}{suffix}"
        else:
            message_parts = []
            if primary_findings:
                message_parts.append(f"{len(primary_findings)} new finding(s)")
            if escalated_findings:
                message_parts.append(f"{len(escalated_findings)} escalated finding(s)")
            if resolved_findings and self.config.get("notifications", {}).get("notify_on_resolved"):
                message_parts.append(f"{len(resolved_findings)} resolved")
            highlights = primary_findings + escalated_findings
            detail_items = [self._finding_brief(finding) for finding in highlights[:2]]
            if len(highlights) > 2:
                detail_items.append(f"+{len(highlights) - 2} more")
            details = ", ".join(detail_items)
            detail_suffix = f": {details}" if details else ""
            message = f"{', '.join(message_parts)} in {project_name}{detail_suffix}"
        if report_path:
            message = f"{message} (report: {report_path})"
        return message

    def _build_details(
        self,
        project_path: str,
        new_findings: list[Dict],
        escalated_findings: list[Dict],
        resolved_findings: list[Dict],
        report_path: str | None,
    ) -> Dict:
        all_findings = new_findings + escalated_findings + resolved_findings
        highest_severity = None
        if all_findings:
            highest_severity = sorted(
                (str(finding.get("severity", "low")).lower() for finding in all_findings),
                key=lambda severity: {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(severity, 0),
                reverse=True,
            )[0]
        return {
            "project_path": project_path,
            "project_name": os.path.basename(project_path) or project_path,
            "report_path": report_path,
            "highest_severity": highest_severity,
            "new_findings": list(new_findings),
            "escalated_findings": list(escalated_findings),
            "resolved_findings": list(resolved_findings),
        }

    def _emit(self, project_path: str, kind: str, message: str, details: Dict | None = None) -> None:
        """Emit a notification through the configured channels."""
        self.state.add_notification(project_path, kind, message)

        if self.config.get("notifications", {}).get("terminal", True):
            logger.warning("MONITOR: %s", message)

        if self.config.get("notifications", {}).get("desktop", True):
            self._emit_desktop("OreWatch", message)

        self._emit_webhook(kind, message, details or {})

    def _emit_webhook(self, kind: str, message: str, details: Dict) -> None:
        """Send a webhook notification when configured."""
        notifications_config = self.config.get("notifications", {})
        webhook_url = str(notifications_config.get("webhook_url", "") or "").strip()
        if not webhook_url:
            return

        webhook_format = str(notifications_config.get("webhook_format", "generic") or "generic").strip().lower()
        if webhook_format == "slack":
            payload = {"text": message}
        else:
            payload = {
                "event": f"orewatch.{kind}",
                "title": "OreWatch",
                "message": message,
                "details": details,
            }

        headers = {"Content-Type": "application/json"}
        configured_headers = notifications_config.get("webhook_headers", {}) or {}
        if isinstance(configured_headers, dict):
            headers.update({str(key): str(value) for key, value in configured_headers.items()})

        request = urllib.request.Request(
            webhook_url,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        timeout_ms = int(notifications_config.get("webhook_timeout_ms", 5000) or 5000)
        try:
            with urllib.request.urlopen(request, timeout=max(timeout_ms / 1000.0, 1)):
                return
        except Exception as exc:
            logger.warning("OreWatch webhook notification failed: %s", exc)

    def _emit_desktop(self, title: str, message: str) -> None:
        """Send a desktop notification when possible."""
        if self._prefer_menubar_popups() and self._menubar_running():
            logger.info("OreWatch menu bar app is running; skipping duplicate direct desktop popup")
            return

        if sys.platform == "darwin" and self._emit_desktop_pyobjc(title, message):
            return

        if shutil.which("osascript"):
            subprocess.run(
                ["osascript", "-e", APPLE_NOTIFICATION_SCRIPT, title, message],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return

        if shutil.which("notify-send"):
            icon_args = []
            if os.path.exists(NOTIFICATION_ICON_PATH):
                icon_args = ["-i", NOTIFICATION_ICON_PATH]
            subprocess.run(
                ["notify-send", *icon_args, title, message],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

    def _emit_desktop_pyobjc(self, title: str, message: str) -> bool:
        """Send a macOS notification with the Rapticore icon via PyObjC. Returns True on success."""
        try:
            import AppKit
            import Foundation
        except ImportError:
            return False

        try:
            notification = AppKit.NSUserNotification.alloc().init()
            notification.setTitle_(title)
            notification.setInformativeText_(message)

            if os.path.exists(NOTIFICATION_ICON_PATH):
                icon = AppKit.NSImage.alloc().initWithContentsOfFile_(NOTIFICATION_ICON_PATH)
                if icon:
                    notification.setContentImage_(icon)

            if hasattr(AppKit, "NSUserNotificationDefaultSoundName"):
                notification.setSoundName_(AppKit.NSUserNotificationDefaultSoundName)

            center = AppKit.NSUserNotificationCenter.defaultUserNotificationCenter()
            center.deliverNotification_(notification)
            return True
        except Exception as exc:
            logger.debug("PyObjC notification failed, falling back: %s", exc)
            return False

    def _prefer_menubar_popups(self) -> bool:
        notifications = self.config.get("notifications", {}) or {}
        return sys.platform == "darwin" and bool(notifications.get("popup_via_menubar", True))

    def _menubar_running(self) -> bool:
        pid_path = str(self.paths.get("menubar_pid", "") or "").strip()
        if not pid_path or not os.path.exists(pid_path):
            return False
        try:
            with open(pid_path, "r", encoding="utf-8") as handle:
                pid = int(handle.read().strip())
        except (OSError, ValueError):
            return False

        try:
            os.kill(pid, 0)
        except OSError:
            return False
        return True
