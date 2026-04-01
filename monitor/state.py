#!/usr/bin/env python3
"""
SQLite-backed state storage for the background monitor.
"""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional

from monitor.config import OWNER_ONLY_FILE_MODE
from monitor.config import ensure_owner_only_permissions
from monitor.config import ensure_not_symlink


SEVERITY_RANK = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def utcnow() -> str:
    """Return the current UTC timestamp."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class MonitorState:
    """Manage persisted monitor state."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        ensure_not_symlink(os.path.dirname(db_path), "monitor state directory")
        ensure_not_symlink(self.db_path, "monitor state database")
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.initialize()
        self._secure_state_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _secure_state_db(self) -> None:
        """Best-effort permission hardening for the state database."""
        if os.path.exists(self.db_path):
            ensure_owner_only_permissions(self.db_path, OWNER_ONLY_FILE_MODE)

    def initialize(self) -> None:
        """Create required tables."""
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS watched_projects (
                    path TEXT PRIMARY KEY,
                    policy_json TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_quick_scan_at TEXT,
                    last_full_scan_at TEXT,
                    last_event_at TEXT,
                    last_event_reason TEXT,
                    last_report_path TEXT,
                    last_scan_status TEXT,
                    last_scan_exit_code INTEGER
                );

                CREATE TABLE IF NOT EXISTS findings (
                    fingerprint TEXT PRIMARY KEY,
                    project_path TEXT NOT NULL,
                    finding_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    active INTEGER NOT NULL DEFAULT 1,
                    first_seen_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    resolved_at TEXT,
                    last_report_path TEXT
                );

                CREATE TABLE IF NOT EXISTS notifications (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_path TEXT NOT NULL,
                    finding_fingerprint TEXT,
                    kind TEXT NOT NULL,
                    message TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS agent_state (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS observed_files (
                    project_path TEXT NOT NULL,
                    relative_path TEXT NOT NULL,
                    category TEXT NOT NULL,
                    mtime REAL NOT NULL,
                    size INTEGER NOT NULL,
                    PRIMARY KEY (project_path, relative_path)
                );
                """
            )
        self._secure_state_db()

    def add_watched_project(self, project_path: str, policy: Optional[Dict] = None) -> None:
        """Register or update a watched project."""
        normalized_path = os.path.abspath(project_path)
        now = utcnow()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO watched_projects (
                    path, policy_json, enabled, created_at, updated_at
                ) VALUES (?, ?, 1, ?, ?)
                ON CONFLICT(path) DO UPDATE SET
                    policy_json = excluded.policy_json,
                    enabled = 1,
                    updated_at = excluded.updated_at
                """,
                (
                    normalized_path,
                    json.dumps(policy or {}, sort_keys=True),
                    now,
                    now,
                ),
            )

    def remove_watched_project(self, project_path: str) -> None:
        """Remove a watched project and its observed-file cache."""
        normalized_path = os.path.abspath(project_path)
        with self._connect() as conn:
            conn.execute("DELETE FROM watched_projects WHERE path = ?", (normalized_path,))
            conn.execute("DELETE FROM observed_files WHERE project_path = ?", (normalized_path,))

    def list_watched_projects(self) -> List[Dict]:
        """Return watched projects."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM watched_projects WHERE enabled = 1 ORDER BY path"
            ).fetchall()

        projects = []
        for row in rows:
            project = dict(row)
            project["policy"] = json.loads(project.pop("policy_json") or "{}")
            projects.append(project)
        return projects

    def get_watched_project(self, project_path: str) -> Optional[Dict]:
        """Return one watched project record."""
        normalized_path = os.path.abspath(project_path)
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM watched_projects WHERE path = ?",
                (normalized_path,),
            ).fetchone()
        if row is None:
            return None
        project = dict(row)
        project["policy"] = json.loads(project.pop("policy_json") or "{}")
        return project

    def update_project_scan(
        self,
        project_path: str,
        scan_kind: str,
        report_path: Optional[str],
        exit_code: int,
        status_message: str,
        event_reason: Optional[str] = None,
    ) -> None:
        """Persist last scan details."""
        normalized_path = os.path.abspath(project_path)
        now = utcnow()
        quick_value = now if scan_kind == "quick" else None
        full_value = now if scan_kind == "full" else None

        with self._connect() as conn:
            current = conn.execute(
                """
                SELECT last_quick_scan_at, last_full_scan_at
                FROM watched_projects WHERE path = ?
                """,
                (normalized_path,),
            ).fetchone()
            if current is None:
                return

            last_quick_scan_at = quick_value or current["last_quick_scan_at"]
            last_full_scan_at = full_value or current["last_full_scan_at"]

            conn.execute(
                """
                UPDATE watched_projects
                SET updated_at = ?,
                    last_quick_scan_at = ?,
                    last_full_scan_at = ?,
                    last_event_at = ?,
                    last_event_reason = ?,
                    last_report_path = ?,
                    last_scan_status = ?,
                    last_scan_exit_code = ?
                WHERE path = ?
                """,
                (
                    now,
                    last_quick_scan_at,
                    last_full_scan_at,
                    now if event_reason else None,
                    event_reason,
                    report_path,
                    status_message,
                    exit_code,
                    normalized_path,
                ),
            )

    def set_agent_state(self, key: str, value: str) -> None:
        """Set one agent-level state value."""
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO agent_state (key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (key, value),
            )

    def get_agent_state(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Fetch one agent-level state value."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT value FROM agent_state WHERE key = ?",
                (key,),
            ).fetchone()
        if row is None:
            return default
        return row["value"]

    def get_observed_files(self, project_path: str) -> Dict[str, Dict]:
        """Return the stored watcher snapshot for one project."""
        normalized_path = os.path.abspath(project_path)
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT relative_path, category, mtime, size
                FROM observed_files
                WHERE project_path = ?
                """,
                (normalized_path,),
            ).fetchall()
        return {
            row["relative_path"]: {
                "category": row["category"],
                "mtime": row["mtime"],
                "size": row["size"],
            }
            for row in rows
        }

    def replace_observed_files(self, project_path: str, snapshot: Dict[str, Dict]) -> None:
        """Replace the stored watcher snapshot for one project."""
        normalized_path = os.path.abspath(project_path)
        with self._connect() as conn:
            conn.execute(
                "DELETE FROM observed_files WHERE project_path = ?",
                (normalized_path,),
            )
            conn.executemany(
                """
                INSERT INTO observed_files (
                    project_path, relative_path, category, mtime, size
                ) VALUES (?, ?, ?, ?, ?)
                """,
                [
                    (
                        normalized_path,
                        relpath,
                        metadata["category"],
                        metadata["mtime"],
                        metadata["size"],
                    )
                    for relpath, metadata in snapshot.items()
                ],
            )

    def add_notification(
        self,
        project_path: str,
        kind: str,
        message: str,
        finding_fingerprint: Optional[str] = None,
    ) -> None:
        """Record a notification event."""
        normalized_path = os.path.abspath(project_path)
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO notifications (
                    project_path, finding_fingerprint, kind, message, created_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    normalized_path,
                    finding_fingerprint,
                    kind,
                    message,
                    utcnow(),
                ),
            )

    def list_recent_notifications(self, limit: int = 20) -> List[Dict]:
        """Return recent notifications."""
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM notifications
                ORDER BY created_at DESC, id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def list_active_findings(self, project_path: Optional[str] = None) -> List[Dict]:
        """Return active findings for one project or all projects."""
        query = "SELECT * FROM findings WHERE active = 1"
        params: Iterable = ()
        if project_path:
            query += " AND project_path = ?"
            params = (os.path.abspath(project_path),)
        query += " ORDER BY severity DESC, title ASC"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        findings = []
        for row in rows:
            finding = dict(row)
            finding["payload"] = json.loads(finding.pop("payload_json"))
            findings.append(finding)
        return findings

    def get_summary(self) -> Dict[str, int]:
        """Return high-level counts for status output."""
        with self._connect() as conn:
            watched = conn.execute(
                "SELECT COUNT(*) AS count FROM watched_projects WHERE enabled = 1"
            ).fetchone()["count"]
            active_findings = conn.execute(
                "SELECT COUNT(*) AS count FROM findings WHERE active = 1"
            ).fetchone()["count"]
            notifications = conn.execute(
                "SELECT COUNT(*) AS count FROM notifications"
            ).fetchone()["count"]
        return {
            "watched_projects": watched,
            "active_findings": active_findings,
            "notifications": notifications,
        }

    def upsert_findings(
        self,
        project_path: str,
        findings: List[Dict],
        report_path: Optional[str],
    ) -> Dict[str, List[Dict]]:
        """Upsert active findings and return new/resolved/escalated deltas."""
        normalized_path = os.path.abspath(project_path)
        now = utcnow()
        with self._connect() as conn:
            current_rows = conn.execute(
                """
                SELECT * FROM findings
                WHERE project_path = ? AND active = 1
                """,
                (normalized_path,),
            ).fetchall()
            current = {row["fingerprint"]: dict(row) for row in current_rows}
            incoming = {finding["fingerprint"]: finding for finding in findings}

            new_findings: List[Dict] = []
            escalated_findings: List[Dict] = []
            resolved_findings: List[Dict] = []

            for fingerprint, finding in incoming.items():
                payload_json = json.dumps(finding["payload"], sort_keys=True)
                existing = current.get(fingerprint)
                if existing is None:
                    conn.execute(
                        """
                        INSERT INTO findings (
                            fingerprint, project_path, finding_type, severity, title,
                            payload_json, active, first_seen_at, last_seen_at,
                            resolved_at, last_report_path
                        ) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, NULL, ?)
                        """,
                        (
                            fingerprint,
                            normalized_path,
                            finding["finding_type"],
                            finding["severity"],
                            finding["title"],
                            payload_json,
                            now,
                            now,
                            report_path,
                        ),
                    )
                    new_findings.append(finding)
                    continue

                previous_rank = SEVERITY_RANK.get(existing["severity"].lower(), 0)
                current_rank = SEVERITY_RANK.get(finding["severity"].lower(), 0)
                conn.execute(
                    """
                    UPDATE findings
                    SET severity = ?,
                        title = ?,
                        payload_json = ?,
                        active = 1,
                        last_seen_at = ?,
                        resolved_at = NULL,
                        last_report_path = ?
                    WHERE fingerprint = ?
                    """,
                    (
                        finding["severity"],
                        finding["title"],
                        payload_json,
                        now,
                        report_path,
                        fingerprint,
                    ),
                )
                if current_rank > previous_rank:
                    escalated_findings.append(finding)

            for fingerprint, existing in current.items():
                if fingerprint in incoming:
                    continue
                conn.execute(
                    """
                    UPDATE findings
                    SET active = 0,
                        resolved_at = ?,
                        last_seen_at = ?,
                        last_report_path = ?
                    WHERE fingerprint = ?
                    """,
                    (now, now, report_path, fingerprint),
                )
                existing["payload"] = json.loads(existing.pop("payload_json"))
                resolved_findings.append(existing)

        return {
            "new_findings": new_findings,
            "escalated_findings": escalated_findings,
            "resolved_findings": resolved_findings,
        }
