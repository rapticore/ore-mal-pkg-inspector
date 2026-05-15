#!/usr/bin/env python3
"""
SQLite-backed state storage for the background monitor.
"""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Dict, List, Optional

from monitor.config import OWNER_ONLY_FILE_MODE
from monitor.config import ensure_owner_only_permissions
from monitor.config import ensure_not_symlink


SEVERITY_RANK = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

DEFAULT_POLICY_JSON = "{}"


def _validate_project_path(path: str) -> str:
    """Normalize and validate a project path.

    Raises ValueError if the path contains null bytes or does not point
    to an existing directory.
    """
    if "\x00" in path:
        raise ValueError("Project path must not contain null bytes")
    normalized = os.path.realpath(os.path.abspath(path))
    if not os.path.isdir(normalized):
        raise ValueError(f"Project path is not an existing directory: {normalized}")
    return normalized


def _normalize_project_path(path: str) -> str:
    """Normalize a project path while rejecting obviously invalid values."""
    if "\x00" in path:
        raise ValueError("Project path must not contain null bytes")
    return os.path.realpath(os.path.abspath(path))


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

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

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
                    project_path TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    finding_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    active INTEGER NOT NULL DEFAULT 1,
                    first_seen_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    resolved_at TEXT,
                    last_report_path TEXT,
                    PRIMARY KEY (project_path, fingerprint)
                );

                CREATE TABLE IF NOT EXISTS notifications (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_path TEXT NOT NULL,
                    finding_fingerprint TEXT,
                    kind TEXT NOT NULL,
                    message TEXT NOT NULL,
                    details_json TEXT NOT NULL DEFAULT '{}',
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

                CREATE TABLE IF NOT EXISTS dependency_checks (
                    check_id TEXT PRIMARY KEY,
                    client_type TEXT NOT NULL,
                    project_path TEXT NOT NULL,
                    ecosystem TEXT NOT NULL,
                    package_manager TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    source_kind TEXT NOT NULL,
                    source_file_path TEXT,
                    source_command TEXT,
                    dependencies_json TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    data_health TEXT NOT NULL,
                    results_json TEXT NOT NULL,
                    monitor_message TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS dependency_overrides (
                    override_id TEXT PRIMARY KEY,
                    check_id TEXT NOT NULL,
                    client_type TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS local_threat_packages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ecosystem TEXT NOT NULL,
                    name TEXT NOT NULL,
                    name_normalized TEXT NOT NULL,
                    versions_json TEXT NOT NULL DEFAULT '[]',
                    reason TEXT NOT NULL,
                    source TEXT NOT NULL DEFAULT 'user',
                    source_url TEXT NOT NULL DEFAULT '',
                    active INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    retired_at TEXT,
                    retired_reason TEXT
                );

                CREATE UNIQUE INDEX IF NOT EXISTS idx_local_threat_packages_active
                ON local_threat_packages(ecosystem, name_normalized)
                WHERE active = 1;

                CREATE TABLE IF NOT EXISTS package_update_advisories (
                    project_path TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    ecosystem TEXT NOT NULL,
                    package_name TEXT NOT NULL,
                    current_version TEXT NOT NULL,
                    latest_version TEXT NOT NULL,
                    manifest_path TEXT NOT NULL DEFAULT '',
                    source_type TEXT NOT NULL DEFAULT '',
                    registry_url TEXT NOT NULL DEFAULT '',
                    package_url TEXT NOT NULL DEFAULT '',
                    update_command TEXT NOT NULL DEFAULT '',
                    details_json TEXT NOT NULL DEFAULT '{}',
                    active INTEGER NOT NULL DEFAULT 1,
                    first_seen_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    resolved_at TEXT,
                    PRIMARY KEY (project_path, fingerprint)
                );

                CREATE INDEX IF NOT EXISTS idx_package_update_advisories_active
                ON package_update_advisories(active, project_path);
                """
            )
            self._migrate_notifications(conn)
            self._migrate_findings_primary_key(conn)
            self._migrate_local_threat_packages(conn)
        self._secure_state_db()

    def _migrate_notifications(self, conn: sqlite3.Connection) -> None:
        """Add notification columns introduced after the initial table."""
        rows = conn.execute("PRAGMA table_info(notifications)").fetchall()
        existing_columns = {row["name"] for row in rows}
        if "details_json" not in existing_columns:
            conn.execute(
                "ALTER TABLE notifications "
                "ADD COLUMN details_json TEXT NOT NULL DEFAULT '{}'"
            )

    def _migrate_local_threat_packages(self, conn: sqlite3.Connection) -> None:
        """Add local-threat columns introduced after the initial table."""
        rows = conn.execute("PRAGMA table_info(local_threat_packages)").fetchall()
        existing_columns = {row["name"] for row in rows}
        if "versions_json" not in existing_columns:
            conn.execute(
                "ALTER TABLE local_threat_packages "
                "ADD COLUMN versions_json TEXT NOT NULL DEFAULT '[]'"
            )
        if "source" not in existing_columns:
            conn.execute(
                "ALTER TABLE local_threat_packages "
                "ADD COLUMN source TEXT NOT NULL DEFAULT 'user'"
            )
        if "source_url" not in existing_columns:
            conn.execute(
                "ALTER TABLE local_threat_packages "
                "ADD COLUMN source_url TEXT NOT NULL DEFAULT ''"
            )

    def _serialize_versions(self, versions: Optional[List[str]]) -> str:
        """Return stable JSON for an optional exact-version list."""
        clean_versions = sorted(
            {
                str(version or "").strip()
                for version in (versions or [])
                if str(version or "").strip()
            }
        )
        return json.dumps(clean_versions)

    def _deserialize_local_threat_row(self, row: sqlite3.Row) -> Dict:
        """Return one local-threat row with parsed versions."""
        entry = dict(row)
        try:
            versions = json.loads(entry.get("versions_json", "[]") or "[]")
        except json.JSONDecodeError:
            versions = []
        entry["versions"] = [str(version) for version in versions if str(version)]
        return entry

    def add_local_threat_package(
        self,
        ecosystem: str,
        name: str,
        reason: str = "",
        versions: Optional[List[str]] = None,
        source: str = "user",
        source_url: str = "",
    ) -> Dict:
        """Add or reactivate a user-managed malicious package name."""
        normalized_ecosystem = str(ecosystem or "").strip().lower()
        package_name = str(name or "").strip()
        if not normalized_ecosystem:
            raise ValueError("ecosystem is required")
        if not package_name:
            raise ValueError("package name is required")
        name_normalized = package_name.lower()
        now = utcnow()
        reason = str(reason or "").strip() or "Added locally by user"
        versions_json = self._serialize_versions(versions)
        source = str(source or "user").strip() or "user"
        source_url = str(source_url or "").strip()
        with self._connect() as conn:
            existing = conn.execute(
                """
                SELECT * FROM local_threat_packages
                WHERE ecosystem = ? AND name_normalized = ? AND active = 1
                """,
                (normalized_ecosystem, name_normalized),
            ).fetchone()
            if existing is not None:
                row = self._deserialize_local_threat_row(existing)
                if source == "user":
                    conn.execute(
                        """
                        UPDATE local_threat_packages
                        SET versions_json = ?, reason = ?, source = 'user', source_url = ''
                        WHERE id = ?
                        """,
                        (versions_json, reason, int(row["id"])),
                    )
                    updated = conn.execute(
                        "SELECT * FROM local_threat_packages WHERE id = ?",
                        (int(row["id"]),),
                    ).fetchone()
                    row = self._deserialize_local_threat_row(updated)
                row["already_exists"] = True
                return row

            conn.execute(
                """
                INSERT INTO local_threat_packages (
                    ecosystem, name, name_normalized, versions_json, reason,
                    source, source_url, active, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
                """,
                (
                    normalized_ecosystem,
                    package_name,
                    name_normalized,
                    versions_json,
                    reason,
                    source,
                    source_url,
                    now,
                ),
            )
            package_id = int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])
            row = conn.execute(
                "SELECT * FROM local_threat_packages WHERE id = ?",
                (package_id,),
            ).fetchone()
        result = self._deserialize_local_threat_row(row) if row is not None else {}
        result["already_exists"] = False
        return result

    def get_local_threat_package_history(
        self,
        ecosystem: str,
        name: str,
        source: Optional[str] = None,
    ) -> Optional[Dict]:
        """Return the newest local-threat row for a package, including retired rows."""
        query = """
            SELECT * FROM local_threat_packages
            WHERE ecosystem = ? AND name_normalized = ?
        """
        params: List[object] = [
            str(ecosystem or "").strip().lower(),
            str(name or "").strip().lower(),
        ]
        if source is not None:
            query += " AND source = ?"
            params.append(str(source or "").strip())
        query += " ORDER BY active DESC, id DESC LIMIT 1"
        with self._connect() as conn:
            row = conn.execute(query, tuple(params)).fetchone()
        return self._deserialize_local_threat_row(row) if row is not None else None

    def list_local_threat_packages(
        self,
        active_only: bool = True,
        ecosystem: Optional[str] = None,
    ) -> List[Dict]:
        """Return user-managed local malicious package names."""
        query = "SELECT * FROM local_threat_packages"
        clauses: List[str] = []
        params: List[object] = []
        if active_only:
            clauses.append("active = 1")
        if ecosystem:
            clauses.append("ecosystem = ?")
            params.append(str(ecosystem).strip().lower())
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY ecosystem ASC, name_normalized ASC, id ASC"
        with self._connect() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
        return [self._deserialize_local_threat_row(row) for row in rows]

    def retire_local_threat_package(
        self,
        package_id: int,
        reason: str = "Removed by user",
    ) -> Optional[Dict]:
        """Retire one local malicious package entry."""
        now = utcnow()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM local_threat_packages WHERE id = ?",
                (int(package_id),),
            ).fetchone()
            if row is None:
                return None
            conn.execute(
                """
                UPDATE local_threat_packages
                SET active = 0, retired_at = ?, retired_reason = ?
                WHERE id = ?
                """,
                (now, str(reason or "Removed by user"), int(package_id)),
            )
            updated = conn.execute(
                "SELECT * FROM local_threat_packages WHERE id = ?",
                (int(package_id),),
            ).fetchone()
        return self._deserialize_local_threat_row(updated) if updated is not None else None

    def retire_local_threat_packages(
        self,
        package_ids: List[int],
        reason: str,
    ) -> int:
        """Retire multiple local malicious package entries."""
        if not package_ids:
            return 0
        now = utcnow()
        with self._connect() as conn:
            cursor = conn.executemany(
                """
                UPDATE local_threat_packages
                SET active = 0, retired_at = ?, retired_reason = ?
                WHERE id = ? AND active = 1
                """,
                [(now, str(reason or "Retired"), int(package_id)) for package_id in package_ids],
            )
        return int(cursor.rowcount or 0)

    def _findings_primary_key_columns(self, conn: sqlite3.Connection) -> List[str]:
        """Return the ordered PRIMARY KEY columns for the findings table."""
        rows = conn.execute("PRAGMA table_info(findings)").fetchall()
        pk_columns = [
            (int(row["pk"]), str(row["name"]))
            for row in rows
            if int(row["pk"] or 0) > 0
        ]
        return [name for _position, name in sorted(pk_columns)]

    def _migrate_findings_primary_key(self, conn: sqlite3.Connection) -> None:
        """Upgrade legacy findings tables from a global fingerprint key to a per-project key."""
        pk_columns = self._findings_primary_key_columns(conn)
        if not pk_columns or pk_columns == ["project_path", "fingerprint"]:
            return
        if pk_columns != ["fingerprint"]:
            raise RuntimeError(
                "Unsupported findings table schema; expected PRIMARY KEY(fingerprint) "
                "or PRIMARY KEY(project_path, fingerprint)"
            )

        conn.executescript(
            """
            ALTER TABLE findings RENAME TO findings_legacy;

            CREATE TABLE findings (
                project_path TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                finding_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                resolved_at TEXT,
                last_report_path TEXT,
                PRIMARY KEY (project_path, fingerprint)
            );

            INSERT INTO findings (
                project_path,
                fingerprint,
                finding_type,
                severity,
                title,
                payload_json,
                active,
                first_seen_at,
                last_seen_at,
                resolved_at,
                last_report_path
            )
            SELECT
                project_path,
                fingerprint,
                finding_type,
                severity,
                title,
                payload_json,
                active,
                first_seen_at,
                last_seen_at,
                resolved_at,
                last_report_path
            FROM findings_legacy;

            DROP TABLE findings_legacy;
            """
        )

    def add_watched_project(self, project_path: str, policy: Optional[Dict] = None) -> None:
        """Register or update a watched project."""
        normalized_path = _validate_project_path(project_path)
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
        normalized_path = _normalize_project_path(project_path)
        with self._connect() as conn:
            conn.execute("DELETE FROM watched_projects WHERE path = ?", (normalized_path,))
            conn.execute("DELETE FROM observed_files WHERE project_path = ?", (normalized_path,))

    def import_watched_project(self, record: Dict) -> None:
        """Import one watched-project row, preferring the newest update time."""
        normalized_path = _normalize_project_path(str(record["path"]))
        policy_json = record.get("policy_json")
        if policy_json is None:
            policy_json = json.dumps(record.get("policy", {}), sort_keys=True)
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO watched_projects (
                    path, policy_json, enabled, created_at, updated_at,
                    last_quick_scan_at, last_full_scan_at, last_event_at,
                    last_event_reason, last_report_path, last_scan_status,
                    last_scan_exit_code
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(path) DO UPDATE SET
                    policy_json = excluded.policy_json,
                    enabled = excluded.enabled,
                    created_at = excluded.created_at,
                    updated_at = excluded.updated_at,
                    last_quick_scan_at = excluded.last_quick_scan_at,
                    last_full_scan_at = excluded.last_full_scan_at,
                    last_event_at = excluded.last_event_at,
                    last_event_reason = excluded.last_event_reason,
                    last_report_path = excluded.last_report_path,
                    last_scan_status = excluded.last_scan_status,
                    last_scan_exit_code = excluded.last_scan_exit_code
                WHERE excluded.updated_at > watched_projects.updated_at
                """,
                (
                    normalized_path,
                    str(policy_json or DEFAULT_POLICY_JSON),
                    int(record.get("enabled", 1)),
                    str(record.get("created_at") or utcnow()),
                    str(record.get("updated_at") or utcnow()),
                    record.get("last_quick_scan_at"),
                    record.get("last_full_scan_at"),
                    record.get("last_event_at"),
                    record.get("last_event_reason"),
                    record.get("last_report_path"),
                    record.get("last_scan_status"),
                    record.get("last_scan_exit_code"),
                ),
            )

    def list_watched_projects(self) -> List[Dict]:
        """Return watched projects."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM watched_projects WHERE enabled = 1 ORDER BY path"
            ).fetchall()

        projects = []
        for row in rows:
            project = dict(row)
            project["policy"] = json.loads(project.pop("policy_json") or DEFAULT_POLICY_JSON)
            projects.append(project)
        return projects

    def get_watched_project(self, project_path: str) -> Optional[Dict]:
        """Return one watched project record."""
        normalized_path = _normalize_project_path(project_path)
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM watched_projects WHERE path = ?",
                (normalized_path,),
            ).fetchone()
        if row is None:
            return None
        project = dict(row)
        project["policy"] = json.loads(project.pop("policy_json") or DEFAULT_POLICY_JSON)
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
        normalized_path = _normalize_project_path(project_path)
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
        normalized_path = _normalize_project_path(project_path)
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
        normalized_path = _normalize_project_path(project_path)
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
        details: Optional[Dict] = None,
    ) -> None:
        """Record a notification event."""
        normalized_path = _normalize_project_path(project_path)
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO notifications (
                    project_path, finding_fingerprint, kind, message, details_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    normalized_path,
                    finding_fingerprint,
                    kind,
                    message,
                    json.dumps(details or {}, sort_keys=True),
                    utcnow(),
                ),
            )

    def list_recent_notifications(
        self,
        limit: int = 20,
        project_path: Optional[str] = None,
    ) -> List[Dict]:
        """Return recent notifications."""
        query = """
            SELECT * FROM notifications
        """
        params: List[object] = []
        if project_path:
            query += " WHERE project_path = ?"
            params.append(_normalize_project_path(project_path))
        query += """
            ORDER BY created_at DESC, id DESC
            LIMIT ?
        """
        params.append(max(int(limit), 1))
        with self._connect() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
        notifications = []
        for row in rows:
            notification = dict(row)
            try:
                details = json.loads(notification.pop("details_json", "{}") or "{}")
            except json.JSONDecodeError:
                details = {}
            notification["details"] = details
            notifications.append(notification)
        return notifications

    def _deserialize_package_update_advisory(self, row: sqlite3.Row | Dict) -> Dict:
        """Return one package-update advisory row with parsed details."""
        advisory = dict(row)
        try:
            details = json.loads(advisory.pop("details_json", "{}") or "{}")
        except json.JSONDecodeError:
            details = {}
        advisory["details"] = details
        return advisory

    def upsert_package_update_advisories(
        self,
        project_path: str,
        advisories: List[Dict],
        resolve_missing: bool = True,
    ) -> Dict[str, List[Dict]]:
        """Upsert package update advisories and return new/updated/resolved deltas."""
        normalized_path = _normalize_project_path(project_path)
        now = utcnow()
        incoming = {str(advisory["fingerprint"]): dict(advisory) for advisory in advisories}
        new_advisories: List[Dict] = []
        updated_advisories: List[Dict] = []
        resolved_advisories: List[Dict] = []

        with self._connect() as conn:
            current_rows = conn.execute(
                """
                SELECT * FROM package_update_advisories
                WHERE project_path = ?
                """,
                (normalized_path,),
            ).fetchall()
            current = {row["fingerprint"]: dict(row) for row in current_rows}
            active_current = {
                row["fingerprint"]: dict(row)
                for row in current_rows
                if int(row["active"] or 0) == 1
            }

            for fingerprint, advisory in incoming.items():
                details_json = json.dumps(advisory.get("details", {}) or {}, sort_keys=True)
                row = current.get(fingerprint)
                params = (
                    normalized_path,
                    fingerprint,
                    str(advisory.get("ecosystem", "")),
                    str(advisory.get("package_name", "")),
                    str(advisory.get("current_version", "")),
                    str(advisory.get("latest_version", "")),
                    str(advisory.get("manifest_path", "")),
                    str(advisory.get("source_type", "")),
                    str(advisory.get("registry_url", "")),
                    str(advisory.get("package_url", "")),
                    str(advisory.get("update_command", "")),
                    details_json,
                    now,
                    now,
                )
                conn.execute(
                    """
                    INSERT INTO package_update_advisories (
                        project_path, fingerprint, ecosystem, package_name,
                        current_version, latest_version, manifest_path, source_type,
                        registry_url, package_url, update_command, details_json,
                        active, first_seen_at, last_seen_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                    ON CONFLICT(project_path, fingerprint) DO UPDATE SET
                        ecosystem = excluded.ecosystem,
                        package_name = excluded.package_name,
                        current_version = excluded.current_version,
                        latest_version = excluded.latest_version,
                        manifest_path = excluded.manifest_path,
                        source_type = excluded.source_type,
                        registry_url = excluded.registry_url,
                        package_url = excluded.package_url,
                        update_command = excluded.update_command,
                        details_json = excluded.details_json,
                        active = 1,
                        last_seen_at = excluded.last_seen_at,
                        resolved_at = NULL
                    """,
                    params,
                )
                saved = conn.execute(
                    """
                    SELECT * FROM package_update_advisories
                    WHERE project_path = ? AND fingerprint = ?
                    """,
                    (normalized_path, fingerprint),
                ).fetchone()
                serialized = self._deserialize_package_update_advisory(saved)
                if row is None or int(row.get("active", 0) or 0) == 0:
                    new_advisories.append(serialized)
                elif str(row.get("latest_version", "")) != str(advisory.get("latest_version", "")):
                    updated_advisories.append(serialized)

            if resolve_missing:
                for fingerprint, row in active_current.items():
                    if fingerprint in incoming:
                        continue
                    conn.execute(
                        """
                        UPDATE package_update_advisories
                        SET active = 0, resolved_at = ?, last_seen_at = ?
                        WHERE project_path = ? AND fingerprint = ?
                        """,
                        (now, now, normalized_path, fingerprint),
                    )
                    updated = dict(row)
                    updated["active"] = 0
                    updated["resolved_at"] = now
                    updated["last_seen_at"] = now
                    resolved_advisories.append(self._deserialize_package_update_advisory(updated))

        return {
            "new_advisories": new_advisories,
            "updated_advisories": updated_advisories,
            "resolved_advisories": resolved_advisories,
        }

    def list_package_update_advisories(
        self,
        project_path: Optional[str] = None,
        active_only: bool = True,
        limit: Optional[int] = None,
    ) -> List[Dict]:
        """Return package update advisories."""
        query = "SELECT * FROM package_update_advisories"
        clauses: List[str] = []
        params: List[object] = []
        if active_only:
            clauses.append("active = 1")
        if project_path:
            clauses.append("project_path = ?")
            params.append(_normalize_project_path(project_path))
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY project_path ASC, ecosystem ASC, package_name ASC, current_version ASC"
        if limit is not None:
            query += " LIMIT ?"
            params.append(max(int(limit), 1))
        with self._connect() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
        return [self._deserialize_package_update_advisory(row) for row in rows]

    def list_active_findings(
        self,
        project_path: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> List[Dict]:
        """Return active findings for one project or all projects."""
        query = "SELECT * FROM findings WHERE active = 1"
        params: List[object] = []
        if project_path:
            query += " AND project_path = ?"
            params.append(_normalize_project_path(project_path))
        query += (
            " ORDER BY CASE lower(severity)"
            " WHEN 'critical' THEN 4"
            " WHEN 'high' THEN 3"
            " WHEN 'medium' THEN 2"
            " WHEN 'low' THEN 1"
            " ELSE 0 END DESC, title ASC"
        )
        if limit is not None:
            query += " LIMIT ?"
            params.append(max(int(limit), 1))
        with self._connect() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
        findings = []
        for row in rows:
            finding = dict(row)
            finding["payload"] = json.loads(finding.pop("payload_json"))
            findings.append(finding)
        return findings

    def get_summary(self) -> Dict[str, object]:
        """Return high-level counts for status output."""
        with self._connect() as conn:
            watched = conn.execute(
                "SELECT COUNT(*) AS count FROM watched_projects WHERE enabled = 1"
            ).fetchone()["count"]
            active_findings = conn.execute(
                "SELECT COUNT(*) AS count FROM findings WHERE active = 1"
            ).fetchone()["count"]
            active_package_updates = conn.execute(
                "SELECT COUNT(*) AS count FROM package_update_advisories WHERE active = 1"
            ).fetchone()["count"]
            notifications = conn.execute(
                "SELECT COUNT(*) AS count FROM notifications"
            ).fetchone()["count"]
            dependency_checks = conn.execute(
                "SELECT COUNT(*) AS count FROM dependency_checks"
            ).fetchone()["count"]
            highest_active = conn.execute(
                """
                SELECT severity FROM findings
                WHERE active = 1
                ORDER BY CASE lower(severity)
                    WHEN 'critical' THEN 4
                    WHEN 'high' THEN 3
                    WHEN 'medium' THEN 2
                    WHEN 'low' THEN 1
                    ELSE 0 END DESC, title ASC
                LIMIT 1
                """
            ).fetchone()
        return {
            "watched_projects": watched,
            "active_findings": active_findings,
            "active_package_updates": active_package_updates,
            "highest_active_severity": highest_active["severity"] if highest_active else None,
            "notifications": notifications,
            "dependency_checks": dependency_checks,
        }

    def record_dependency_check(
        self,
        check_id: str,
        client_type: str,
        project_path: str,
        ecosystem: str,
        package_manager: str,
        operation: str,
        dependencies: List[Dict],
        decision: str,
        data_health: str,
        results: List[Dict],
        monitor_message: str,
        source: Optional[Dict] = None,
    ) -> None:
        """Persist a dependency add or manifest check request."""
        source = source or {}
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO dependency_checks (
                    check_id, client_type, project_path, ecosystem, package_manager,
                    operation, source_kind, source_file_path, source_command,
                    dependencies_json, decision, data_health, results_json,
                    monitor_message, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    check_id,
                    client_type,
                    _normalize_project_path(project_path),
                    ecosystem,
                    package_manager,
                    operation,
                    source.get("kind", ""),
                    source.get("file_path"),
                    source.get("command"),
                    json.dumps(dependencies, sort_keys=True),
                    decision,
                    data_health,
                    json.dumps(results, sort_keys=True),
                    monitor_message,
                    utcnow(),
                ),
            )

    def get_dependency_check(self, check_id: str) -> Optional[Dict]:
        """Return one stored dependency check."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM dependency_checks WHERE check_id = ?",
                (check_id,),
            ).fetchone()
        if row is None:
            return None
        check = dict(row)
        check["dependencies"] = json.loads(check.pop("dependencies_json"))
        check["results"] = json.loads(check.pop("results_json"))
        return check

    def record_dependency_override(
        self,
        override_id: str,
        check_id: str,
        client_type: str,
        actor: str,
        reason: str,
        expires_at: str,
    ) -> None:
        """Persist a one-time dependency add override."""
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO dependency_overrides (
                    override_id, check_id, client_type, actor, reason, expires_at, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    override_id,
                    check_id,
                    client_type,
                    actor,
                    reason,
                    expires_at,
                    utcnow(),
                ),
            )

    def get_dependency_override(self, override_id: str) -> Optional[Dict]:
        """Return one stored dependency override."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM dependency_overrides WHERE override_id = ?",
                (override_id,),
            ).fetchone()
        return dict(row) if row is not None else None

    def upsert_findings(
        self,
        project_path: str,
        findings: List[Dict],
        report_path: Optional[str],
    ) -> Dict[str, List[Dict]]:
        """Upsert active findings and return new/resolved/escalated deltas."""
        normalized_path = _normalize_project_path(project_path)
        now = utcnow()
        with self._connect() as conn:
            current_rows = conn.execute(
                """
                SELECT * FROM findings
                WHERE project_path = ?
                """,
                (normalized_path,),
            ).fetchall()
            current = {row["fingerprint"]: dict(row) for row in current_rows}
            active_current = {
                row["fingerprint"]: dict(row)
                for row in current_rows
                if int(row["active"] or 0) == 1
            }
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
                    WHERE project_path = ? AND fingerprint = ?
                    """,
                    (
                        finding["severity"],
                        finding["title"],
                        payload_json,
                        now,
                        report_path,
                        normalized_path,
                        fingerprint,
                    ),
                )
                if current_rank > previous_rank:
                    escalated_findings.append(finding)

            for fingerprint, existing in active_current.items():
                if fingerprint in incoming:
                    continue
                conn.execute(
                    """
                    UPDATE findings
                    SET active = 0,
                        resolved_at = ?,
                        last_seen_at = ?,
                        last_report_path = ?
                    WHERE project_path = ? AND fingerprint = ?
                    """,
                    (now, now, report_path, normalized_path, fingerprint),
                )
                existing["payload"] = json.loads(existing.pop("payload_json"))
                resolved_findings.append(existing)

        return {
            "new_findings": new_findings,
            "escalated_findings": escalated_findings,
            "resolved_findings": resolved_findings,
        }
