#!/usr/bin/env python3
"""
Notification helpers for the background monitor.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from typing import Dict


logger = logging.getLogger(__name__)
APPLE_NOTIFICATION_SCRIPT = (
    "on run argv\n"
    "set notificationTitle to item 1 of argv\n"
    "set notificationMessage to item 2 of argv\n"
    "display notification notificationMessage with title notificationTitle\n"
    "end run"
)


class Notifier:
    """Send and record monitor notifications."""

    def __init__(self, state, monitor_config: Dict):
        self.state = state
        self.config = monitor_config

    def notify_project_changes(
        self,
        project_path: str,
        changes: Dict,
        project_policy: Dict,
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
                message = (
                    f"{len(resolved_findings)} finding(s) resolved in "
                    f"{os.path.basename(project_path) or project_path}"
                )
                self._emit(project_path, "resolved", message)
            return

        message_parts = []
        if new_findings:
            message_parts.append(f"{len(new_findings)} new finding(s)")
        if escalated_findings:
            message_parts.append(f"{len(escalated_findings)} escalated finding(s)")
        if resolved_findings and self.config.get("notifications", {}).get("notify_on_resolved"):
            message_parts.append(f"{len(resolved_findings)} resolved")
        message = (
            ", ".join(message_parts)
            + f" in {os.path.basename(project_path) or project_path}"
        )
        self._emit(project_path, "findings", message)

    def _emit(self, project_path: str, kind: str, message: str) -> None:
        """Emit a notification through the configured channels."""
        self.state.add_notification(project_path, kind, message)

        if self.config.get("notifications", {}).get("terminal", True):
            logger.warning("MONITOR: %s", message)

        if self.config.get("notifications", {}).get("desktop", True):
            self._emit_desktop("OreWatch", message)

    def _emit_desktop(self, title: str, message: str) -> None:
        """Send a desktop notification when possible."""
        if shutil.which("osascript"):
            subprocess.run(
                ["osascript", "-e", APPLE_NOTIFICATION_SCRIPT, title, message],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return

        if shutil.which("notify-send"):
            subprocess.run(
                ["notify-send", title, message],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
