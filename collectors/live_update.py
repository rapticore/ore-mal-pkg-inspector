#!/usr/bin/env python3
"""
Anomaly-gated live update helpers for client endpoints.
"""

from __future__ import annotations

import copy
import json
import os
import shutil
import tempfile
from typing import Any, Dict, Optional, Tuple

try:
    from . import db
except ImportError:  # pragma: no cover - script-style collector imports
    import db


DEFAULT_LIVE_UPDATE_CONFIG: Dict[str, Any] = {
    "enabled": True,
    "mode": "gated",
    "bootstrap_from_live": True,
    "block_on_core_source_failure": False,
    "max_drop_ratio": 0.40,
    "max_drop_absolute": 200,
    "max_removal_ratio": 0.25,
    "max_removal_absolute": 100,
    "warn_growth_ratio": 5.0,
    "warn_growth_absolute": 2000,
    "warn_addition_ratio": 3.0,
    "warn_addition_absolute": 1000,
    "retain_accepted_history": 20,
    "retain_rejected_history": 5,
}


STATUS_RANK = {
    "failed": 0,
    "partial": 1,
    "complete": 2,
}


def merge_live_update_config(config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Merge overrides into the default live-update config."""
    merged = copy.deepcopy(DEFAULT_LIVE_UPDATE_CONFIG)
    if config:
        merged.update(config)
    return merged


def ensure_live_update_layout(promotion_root: str) -> Dict[str, str]:
    """Create and return the live-update staging/history layout."""
    paths = {
        "root": promotion_root,
        "staging": os.path.join(promotion_root, "staging"),
        "accepted": os.path.join(promotion_root, "history", "accepted"),
        "rejected": os.path.join(promotion_root, "history", "rejected"),
        "backups": os.path.join(promotion_root, "backups"),
        "current_summary": os.path.join(promotion_root, "current-summary.json"),
    }
    for key, path in paths.items():
        if key == "current_summary":
            continue
        os.makedirs(path, exist_ok=True)
    return paths


def _write_json(path: str, payload: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    temp_path = f"{path}.tmp"
    with open(temp_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
    os.replace(temp_path, path)


def _load_json(path: str) -> Optional[Dict[str, Any]]:
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _normalize_status(status: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    status = status or {}
    return {
        "exists": bool(status.get("exists")),
        "usable": bool(status.get("usable")),
        "data_status": status.get("data_status", "failed"),
        "sources_used": status.get("sources_used", []),
        "experimental_sources_used": status.get("experimental_sources_used", []),
        "last_successful_collect": status.get("last_successful_collect", ""),
        "total_packages": int(status.get("total_packages", 0) or 0),
        "metadata_ready": bool(status.get("metadata_ready", False)),
    }


def summarize_database_directory(
    final_data_dir: str,
    ecosystems: list[str],
    get_database_statuses_fn,
) -> Tuple[Dict[str, Any], Dict[str, set[str]]]:
    """Return per-ecosystem metadata plus package-name sets for one DB directory."""
    statuses = get_database_statuses_fn(ecosystems=ecosystems, final_data_dir=final_data_dir)
    summary: Dict[str, Any] = {}
    package_sets: Dict[str, set[str]] = {}

    for ecosystem in ecosystems:
        status = _normalize_status(statuses.get(ecosystem))
        db_path = os.path.join(final_data_dir, f"unified_{ecosystem}.db")
        names: set[str] = set()
        if os.path.exists(db_path):
            conn = db.open_database(db_path)
            if conn:
                try:
                    names = db.list_package_names(conn)
                finally:
                    conn.close()
        package_sets[ecosystem] = names
        status["package_name_count"] = len(names)
        summary[ecosystem] = status

    return summary, package_sets


def build_candidate_summary(
    attempt_id: str,
    selected_sources: list[str],
    source_results: Dict[str, Dict[str, Any]],
    build_summary: Dict[str, Any],
    final_data_dir: str,
    ecosystems: list[str],
    get_database_statuses_fn,
) -> Tuple[Dict[str, Any], Dict[str, set[str]]]:
    """Build the candidate dataset summary for one live refresh attempt."""
    ecosystem_summary, package_sets = summarize_database_directory(
        final_data_dir,
        ecosystems,
        get_database_statuses_fn,
    )
    source_counts = {
        source: {
            "success": bool(result.get("success")),
            "package_count": int(result.get("package_count", 0) or 0),
            "tier": result.get("tier", ""),
            "error": result.get("error", ""),
        }
        for source, result in source_results.items()
    }
    return {
        "attempt_id": attempt_id,
        "selected_sources": selected_sources,
        "build_success": bool(build_summary.get("success")),
        "build_results": build_summary.get("build_results", {}),
        "ecosystems": ecosystem_summary,
        "usable_ecosystems": [
            ecosystem
            for ecosystem, status in ecosystem_summary.items()
            if status.get("usable")
        ],
        "source_counts": source_counts,
    }, package_sets


def load_active_baseline(
    promotion_root: str,
    active_final_data_dir: str,
    ecosystems: list[str],
    get_database_statuses_fn,
) -> Tuple[Optional[Dict[str, Any]], Dict[str, Any], Dict[str, set[str]], Dict[str, Any]]:
    """Load the current accepted summary plus active DB metadata."""
    layout = ensure_live_update_layout(promotion_root)
    current_summary = _load_json(layout["current_summary"])
    ecosystem_summary, package_sets = summarize_database_directory(
        active_final_data_dir,
        ecosystems,
        get_database_statuses_fn,
    )
    source_counts = {}
    if current_summary:
        source_counts = (
            current_summary.get("candidate", {}).get("source_counts")
            or current_summary.get("source_counts")
            or {}
        )
    return current_summary, ecosystem_summary, package_sets, source_counts


def _add_anomaly(
    anomalies: list[Dict[str, Any]],
    severity: str,
    code: str,
    scope: str,
    name: str,
    message: str,
) -> None:
    anomalies.append(
        {
            "severity": severity,
            "code": code,
            "scope": scope,
            "name": name,
            "message": message,
        }
    )


def _percent_change(new_value: int, old_value: int) -> float:
    if old_value <= 0:
        return 0.0
    return (new_value - old_value) / old_value


def evaluate_candidate(
    attempt_id: str,
    timestamp: str,
    selected_sources: list[str],
    source_definitions: Dict[str, Dict[str, Any]],
    candidate_summary: Dict[str, Any],
    active_summary: Dict[str, Any],
    candidate_names: Dict[str, set[str]],
    active_names: Dict[str, set[str]],
    active_source_counts: Dict[str, Any],
    live_update_config: Dict[str, Any],
) -> Dict[str, Any]:
    """Evaluate one candidate dataset and return a promotion decision report."""
    config = merge_live_update_config(live_update_config)
    anomalies: list[Dict[str, Any]] = []
    diff: Dict[str, Any] = {"ecosystems": {}, "sources": {}}
    candidate_ecosystems = candidate_summary["ecosystems"]
    active_usable = any(status.get("usable") for status in active_summary.values())
    candidate_usable = any(status.get("usable") for status in candidate_ecosystems.values())
    core_sources = [
        source
        for source in selected_sources
        if source_definitions.get(source, {}).get("tier") == "core"
    ]

    for ecosystem, status in candidate_ecosystems.items():
        active_status = active_summary.get(ecosystem, _normalize_status(None))
        candidate_count = int(status.get("total_packages", 0) or 0)
        active_count = int(active_status.get("total_packages", 0) or 0)
        added = len(candidate_names.get(ecosystem, set()) - active_names.get(ecosystem, set()))
        removed = len(active_names.get(ecosystem, set()) - candidate_names.get(ecosystem, set()))
        diff["ecosystems"][ecosystem] = {
            "active_total_packages": active_count,
            "candidate_total_packages": candidate_count,
            "active_data_status": active_status.get("data_status", "failed"),
            "candidate_data_status": status.get("data_status", "failed"),
            "added_packages": added,
            "removed_packages": removed,
        }

    for source in selected_sources:
        candidate_source = candidate_summary["source_counts"].get(source, {})
        active_source = active_source_counts.get(source, {})
        diff["sources"][source] = {
            "active_package_count": int(active_source.get("package_count", 0) or 0),
            "candidate_package_count": int(candidate_source.get("package_count", 0) or 0),
            "candidate_success": bool(candidate_source.get("success")),
        }

    if not candidate_summary.get("build_success"):
        failed_builds = [
            ecosystem
            for ecosystem, success in candidate_summary.get("build_results", {}).items()
            if not success
        ]
        _add_anomaly(
            anomalies,
            "block",
            "candidate_build_failed",
            "global",
            "build",
            f"Candidate database build failed for: {', '.join(failed_builds) or 'unknown'}",
        )

    if not candidate_usable:
        _add_anomaly(
            anomalies,
            "block",
            "no_usable_candidate_data",
            "global",
            "candidate",
            "Candidate live update did not produce any usable ecosystems",
        )

    if active_usable:
        if config.get("block_on_core_source_failure", False):
            for source in core_sources:
                if not candidate_summary["source_counts"].get(source, {}).get("success"):
                    _add_anomaly(
                        anomalies,
                        "block",
                        "core_source_failed",
                        "source",
                        source,
                        f"Core source {source} failed during live refresh",
                    )
        else:
            for source in core_sources:
                if not candidate_summary["source_counts"].get(source, {}).get("success"):
                    _add_anomaly(
                        anomalies,
                        "warn",
                        "core_source_failed",
                        "source",
                        source,
                        f"Core source {source} failed during live refresh",
                    )

        for source in core_sources:
            active_source_count = int(active_source_counts.get(source, {}).get("package_count", 0) or 0)
            candidate_source = candidate_summary["source_counts"].get(source, {})
            if not candidate_source.get("success"):
                continue
            candidate_source_count = int(candidate_source.get("package_count", 0) or 0)
            drop = active_source_count - candidate_source_count
            if (
                active_source_count > 0
                and drop >= int(config.get("max_drop_absolute", 200))
                and (drop / active_source_count) > float(config.get("max_drop_ratio", 0.40))
            ):
                _add_anomaly(
                    anomalies,
                    "block",
                    "source_count_drop",
                    "source",
                    source,
                    (
                        f"Source {source} dropped from {active_source_count} to "
                        f"{candidate_source_count} packages"
                    ),
                )

        for ecosystem, status in candidate_ecosystems.items():
            active_status = active_summary.get(ecosystem, _normalize_status(None))
            active_count = int(active_status.get("total_packages", 0) or 0)
            candidate_count = int(status.get("total_packages", 0) or 0)
            active_name_count = len(active_names.get(ecosystem, set()))
            candidate_name_count = len(candidate_names.get(ecosystem, set()))
            removed = len(active_names.get(ecosystem, set()) - candidate_names.get(ecosystem, set()))
            added = len(candidate_names.get(ecosystem, set()) - active_names.get(ecosystem, set()))

            if (
                active_status.get("usable")
                and STATUS_RANK.get(status.get("data_status", "failed"), 0)
                < STATUS_RANK.get(active_status.get("data_status", "failed"), 0)
            ):
                _add_anomaly(
                    anomalies,
                    "warn" if status.get("usable") else "block",
                    "ecosystem_regressed",
                    "ecosystem",
                    ecosystem,
                    (
                        f"Ecosystem {ecosystem} regressed from "
                        f"{active_status.get('data_status')} to {status.get('data_status')}"
                    ),
                )

            if active_count > 0 and candidate_count == 0:
                _add_anomaly(
                    anomalies,
                    "block",
                    "ecosystem_emptied",
                    "ecosystem",
                    ecosystem,
                    f"Ecosystem {ecosystem} became empty during live refresh",
                )

            drop = active_count - candidate_count
            if (
                active_count > 0
                and drop >= int(config.get("max_drop_absolute", 200))
                and (drop / active_count) > float(config.get("max_drop_ratio", 0.40))
            ):
                _add_anomaly(
                    anomalies,
                    "block",
                    "ecosystem_count_drop",
                    "ecosystem",
                    ecosystem,
                    f"Ecosystem {ecosystem} dropped from {active_count} to {candidate_count} packages",
                )

            if (
                active_name_count > 0
                and removed >= int(config.get("max_removal_absolute", 100))
                and (removed / active_name_count) > float(config.get("max_removal_ratio", 0.25))
            ):
                _add_anomaly(
                    anomalies,
                    "block",
                    "ecosystem_mass_removal",
                    "ecosystem",
                    ecosystem,
                    (
                        f"Ecosystem {ecosystem} removed {removed} package names "
                        f"out of {active_name_count}"
                    ),
                )

            growth = candidate_count - active_count
            if (
                active_count > 0
                and growth >= int(config.get("warn_growth_absolute", 2000))
                and _percent_change(candidate_count, active_count) > float(config.get("warn_growth_ratio", 5.0))
            ):
                _add_anomaly(
                    anomalies,
                    "warn",
                    "ecosystem_growth_spike",
                    "ecosystem",
                    ecosystem,
                    f"Ecosystem {ecosystem} grew from {active_count} to {candidate_count} packages",
                )

            if (
                active_name_count > 0
                and added >= int(config.get("warn_addition_absolute", 1000))
                and (added / active_name_count) > float(config.get("warn_addition_ratio", 3.0))
            ):
                _add_anomaly(
                    anomalies,
                    "warn",
                    "ecosystem_addition_spike",
                    "ecosystem",
                    ecosystem,
                    (
                        f"Ecosystem {ecosystem} added {added} package names "
                        f"to a baseline of {active_name_count}"
                    ),
                )

    else:
        if not config.get("bootstrap_from_live", True):
            _add_anomaly(
                anomalies,
                "block",
                "bootstrap_disabled",
                "global",
                "bootstrap",
                "Live bootstrap is disabled and no active baseline exists",
            )
        if core_sources and not any(
            candidate_summary["source_counts"].get(source, {}).get("success")
            for source in core_sources
        ):
            _add_anomaly(
                anomalies,
                "block",
                "no_core_source_success",
                "global",
                "bootstrap",
                "No core source succeeded during initial live bootstrap",
            )

    blocking = [anomaly for anomaly in anomalies if anomaly["severity"] == "block"]
    if blocking:
        decision = "rejected"
        kept_last_known_good = active_usable
        message = (
            "Live threat-data candidate rejected by anomaly gates; "
            + ("kept last-known-good data" if kept_last_known_good else "no baseline available")
        )
    elif active_usable:
        decision = "promoted"
        kept_last_known_good = False
        message = "Live threat-data candidate promoted successfully"
    else:
        decision = "bootstrapped"
        kept_last_known_good = False
        message = "Live threat-data bootstrap promoted successfully"

    return {
        "attempt_id": attempt_id,
        "generated_at": timestamp,
        "decision": decision,
        "message": message,
        "kept_last_known_good": kept_last_known_good,
        "anomalies": anomalies,
        "active": {
            "ecosystems": active_summary,
            "source_counts": active_source_counts,
        },
        "candidate": candidate_summary,
        "diff": diff,
    }


def _prune_history(history_dir: str, keep: int) -> None:
    if keep <= 0 or not os.path.isdir(history_dir):
        return
    entries = sorted(
        (
            os.path.join(history_dir, entry)
            for entry in os.listdir(history_dir)
            if entry.endswith(".json")
        )
    )
    for entry in entries[:-keep]:
        os.unlink(entry)


def persist_promotion_report(
    promotion_root: str,
    report: Dict[str, Any],
    live_update_config: Dict[str, Any],
) -> str:
    """Persist one promotion report and update current-summary on acceptance."""
    config = merge_live_update_config(live_update_config)
    layout = ensure_live_update_layout(promotion_root)
    history_dir = layout["accepted"] if report["decision"] in {"promoted", "bootstrapped"} else layout["rejected"]
    report_path = os.path.join(history_dir, f"{report['attempt_id']}.json")
    _write_json(report_path, report)

    if report["decision"] in {"promoted", "bootstrapped"}:
        _write_json(layout["current_summary"], report)
        _prune_history(layout["accepted"], int(config.get("retain_accepted_history", 20)))
    else:
        _prune_history(layout["rejected"], int(config.get("retain_rejected_history", 5)))

    return report_path


def promote_candidate_directory(
    active_final_data_dir: str,
    candidate_final_data_dir: str,
    promotion_root: str,
    live_dataset_version: str,
) -> Optional[str]:
    """Promote one staged candidate DB directory into the active final-data path."""
    layout = ensure_live_update_layout(promotion_root)
    os.makedirs(os.path.dirname(active_final_data_dir), exist_ok=True)
    temp_swap_root = tempfile.mkdtemp(prefix="live-update-swap-", dir=layout["staging"])
    temporary_backup_dir = os.path.join(temp_swap_root, "previous-final-data")
    backup_dir = os.path.join(layout["backups"], live_dataset_version, "final-data")
    had_existing = os.path.exists(active_final_data_dir)

    try:
        if had_existing:
            os.replace(active_final_data_dir, temporary_backup_dir)

        try:
            os.replace(candidate_final_data_dir, active_final_data_dir)
        except Exception:
            if had_existing and os.path.exists(temporary_backup_dir) and not os.path.exists(active_final_data_dir):
                os.replace(temporary_backup_dir, active_final_data_dir)
            raise

        if had_existing and os.path.exists(temporary_backup_dir):
            os.makedirs(os.path.dirname(backup_dir), exist_ok=True)
            if os.path.exists(backup_dir):
                shutil.rmtree(backup_dir)
            shutil.copytree(temporary_backup_dir, backup_dir)
            return backup_dir
        return None
    finally:
        shutil.rmtree(temp_swap_root, ignore_errors=True)
