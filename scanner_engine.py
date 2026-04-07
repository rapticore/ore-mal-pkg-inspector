#!/usr/bin/env python3
"""
Reusable scan engine for one-off CLI runs and background monitoring.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from collectors.live_update import build_candidate_summary
from collectors.live_update import ensure_live_update_layout
from collectors.live_update import evaluate_candidate
from collectors.live_update import load_active_baseline
from collectors.live_update import merge_live_update_config
from collectors.live_update import persist_promotion_report
from collectors.live_update import promote_candidate_directory
from logging_config import get_logger
from scanners import dependency_parsers
from scanners import ecosystem_detector
from scanners import file_input_parser
from scanners import ioc_detector
from scanners import malicious_checker
from scanners import report_generator
from scanners.supported_files import ECOSYSTEM_PRIORITY, get_supported_files_for_ecosystem


logger = get_logger(__name__)
REFRESH_MODE_EXISTING_ONLY = "existing_only"
REFRESH_MODE_LIVE_GATED_IF_NEEDED = "live_gated_if_needed"
REFRESH_MODE_LIVE_GATED_FORCE = "live_gated_force"


@dataclass
class ScanRequest:
    """Configuration for a single scan run."""

    target_path: Optional[str] = None
    file_path: Optional[str] = None
    ecosystem: Optional[str] = None
    output_path: Optional[str] = None
    scan_iocs: bool = True
    scan_packages: bool = True
    force_latest_data: bool = False
    strict_data: bool = False
    include_experimental_sources: bool = False
    ensure_data: bool = True
    refresh_mode: str = REFRESH_MODE_LIVE_GATED_IF_NEEDED
    print_summary: bool = True


@dataclass
class ScanResult:
    """Stable result model for scan callers."""

    ecosystem: str
    scanned_path: str
    requested_ecosystems: List[str]
    packages: List[Dict]
    malicious_packages: List[Dict]
    iocs: List[Dict]
    report_path: Optional[str]
    data_metadata: Dict[str, object]
    threat_data_summary: Dict[str, object] = field(default_factory=dict)
    exit_code: int = 0
    message: str = ""

    @property
    def has_issues(self) -> bool:
        """Return True when the scan found malicious packages or IoCs."""
        return bool(self.malicious_packages) or bool(self.iocs)


def print_supported_files() -> None:
    """Print the exact manifest filenames recognized by the scanner."""
    print("Supported dependency files:")
    for ecosystem in ECOSYSTEM_PRIORITY:
        filenames = get_supported_files_for_ecosystem(ecosystem)
        if not filenames:
            continue
        print(f"  {ecosystem}: {', '.join(filenames)}")


def normalize_requested_ecosystems(ecosystem_value) -> List[str]:
    """Normalize a scanner ecosystem return value to a list."""
    if isinstance(ecosystem_value, list):
        return ecosystem_value
    if isinstance(ecosystem_value, str) and ecosystem_value:
        return [ecosystem_value]
    return []


def summarize_requested_data_status(
    requested_ecosystems: List[str],
    database_statuses: Optional[Dict[str, Dict]] = None,
) -> Dict[str, object]:
    """Summarize threat-data availability for the requested ecosystems."""
    database_statuses = database_statuses or {}
    requested_statuses = {
        ecosystem: database_statuses.get(
            ecosystem,
            {
                "usable": False,
                "data_status": "failed",
                "sources_used": [],
                "experimental_sources_used": [],
            },
        )
        for ecosystem in requested_ecosystems
    }

    usable_ecosystems = [
        ecosystem
        for ecosystem, status in requested_statuses.items()
        if status.get("usable")
    ]
    missing_ecosystems = [
        ecosystem
        for ecosystem, status in requested_statuses.items()
        if not status.get("usable")
    ]
    partial_ecosystems = [
        ecosystem
        for ecosystem, status in requested_statuses.items()
        if status.get("data_status") == "partial"
    ]

    sources_used = sorted(
        {
            source
            for status in requested_statuses.values()
            for source in status.get("sources_used", [])
        }
    )
    experimental_sources_used = sorted(
        {
            source
            for status in requested_statuses.values()
            for source in status.get("experimental_sources_used", [])
        }
    )

    if not requested_ecosystems:
        data_status = "not_applicable"
    elif not usable_ecosystems:
        data_status = "failed"
    elif missing_ecosystems or partial_ecosystems:
        data_status = "partial"
    else:
        data_status = "complete"

    return {
        "data_status": data_status,
        "sources_used": sources_used,
        "experimental_sources_used": experimental_sources_used,
        "missing_ecosystems": missing_ecosystems,
        "usable_ecosystems": usable_ecosystems,
        "requested_statuses": requested_statuses,
    }


def _augment_data_metadata(
    data_metadata: Dict[str, object],
    threat_data_summary: Dict[str, object],
) -> Dict[str, object]:
    """Attach live-refresh promotion metadata to report-facing data metadata."""
    enriched = dict(data_metadata)
    enriched["promotion_decision"] = threat_data_summary.get("promotion_decision", "")
    enriched["kept_last_known_good"] = bool(
        threat_data_summary.get("kept_last_known_good", False)
    )
    enriched["anomalies"] = threat_data_summary.get("anomalies", [])
    return enriched


def aggregate_package_locations(packages: List[Dict], scanned_path: str) -> List[Dict]:
    """
    Aggregate packages by ecosystem+name+version and collect file locations.
    """
    aggregated: Dict[tuple, Dict] = {}

    for pkg in packages:
        key = (pkg.get("ecosystem", ""), pkg["name"].lower(), pkg.get("version", ""))

        if key not in aggregated:
            aggregated[key] = {
                "name": pkg["name"],
                "version": pkg.get("version", ""),
                "section": pkg.get("section", ""),
                "ecosystem": pkg.get("ecosystem", ""),
                "locations": [],
            }

        if "physical_location" in pkg and pkg["physical_location"]:
            phys_loc = pkg["physical_location"]
            abs_path = phys_loc["artifact_location"]["uri"]
            rel_path = os.path.relpath(abs_path, scanned_path)
            location = {
                "physicalLocation": {
                    "artifactLocation": {"uri": rel_path},
                    "region": {
                        "startLine": phys_loc["region"]["start_line"],
                        "startColumn": phys_loc["region"]["start_column"],
                        "endLine": phys_loc["region"]["end_line"],
                        "endColumn": phys_loc["region"]["end_column"],
                    },
                }
            }
            if location not in aggregated[key]["locations"]:
                aggregated[key]["locations"].append(location)

    return list(aggregated.values())


def scan_directory(directory: str, ecosystem: Optional[str] = None, scan_iocs: bool = True) -> tuple:
    """
    Scan a directory for dependency files and optional IoCs.
    """
    iocs: List[Dict] = []
    if scan_iocs:
        iocs = ioc_detector.scan_for_iocs(directory)
        if iocs:
            logger.info("🕵️  Found %d Indicator(s) of Compromise", len(iocs))

    if not ecosystem:
        all_ecosystems = ecosystem_detector.detect_all_ecosystems_from_directory(directory)
        if not all_ecosystems:
            logger.error("❌ Could not detect ecosystem in directory: %s", directory)
            logger.error("Please specify ecosystem with --ecosystem option")
            return None, [], directory, iocs

        if len(all_ecosystems) == 1:
            ecosystem = all_ecosystems[0]
            logger.info("🔍 Detected ecosystem: %s", ecosystem)
        else:
            logger.info("🔍 Detected multiple ecosystems: %s", ", ".join(all_ecosystems))
            logger.info("   Scanning all detected ecosystems...")
            all_packages: List[Dict] = []
            for eco in all_ecosystems:
                logger.info("\n   Scanning %s...", eco)
                dep_files = ecosystem_detector.find_dependency_files(directory, eco)
                if dep_files:
                    logger.info("   📦 Found %d dependency file(s) for %s", len(dep_files), eco)
                    for dep_file in dep_files:
                        logger.debug("      Parsing: %s", os.path.relpath(dep_file, directory))
                        packages = dependency_parsers.parse_dependencies(dep_file, eco)
                        for pkg in packages:
                            pkg["ecosystem"] = eco
                        all_packages.extend(packages)

            unique_packages = aggregate_package_locations(all_packages, directory)
            logger.info(
                "\n✅ Extracted %d unique package(s) across %d ecosystem(s)",
                len(unique_packages),
                len(all_ecosystems),
            )
            return all_ecosystems, unique_packages, directory, iocs

    logger.info("🔍 Using ecosystem: %s", ecosystem)
    dep_files = ecosystem_detector.find_dependency_files(directory, ecosystem)

    if not dep_files:
        logger.warning("⚠️  No dependency files found for %s in %s", ecosystem, directory)
        return ecosystem, [], directory, iocs

    logger.info("📦 Found %d dependency file(s)", len(dep_files))
    all_packages: List[Dict] = []
    for dep_file in dep_files:
        logger.debug("   Parsing: %s", os.path.relpath(dep_file, directory))
        packages = dependency_parsers.parse_dependencies(dep_file, ecosystem)
        for pkg in packages:
            pkg["ecosystem"] = ecosystem
        all_packages.extend(packages)

    unique_packages = aggregate_package_locations(all_packages, directory)
    logger.info("✅ Extracted %d unique package(s)", len(unique_packages))
    return ecosystem, unique_packages, directory, iocs


def scan_file(file_path: str, ecosystem: Optional[str] = None, scan_iocs: bool = True) -> tuple:
    """
    Scan a file for packages and optional IoCs.
    """
    iocs: List[Dict] = []
    if scan_iocs:
        file_dir = os.path.dirname(file_path) if os.path.dirname(file_path) else "."
        iocs = ioc_detector.scan_for_iocs(file_dir)
        if iocs:
            logger.info("🕵️  Found %d Indicator(s) of Compromise", len(iocs))

    detected_ecosystem = ecosystem_detector.detect_ecosystem_from_filename(file_path)
    use_dependency_parser = detected_ecosystem is not None

    if not ecosystem:
        ecosystem = detected_ecosystem

    if not ecosystem and file_path.endswith(".json"):
        ecosystem = ecosystem_detector.detect_ecosystem_from_json_content(file_path)
        if ecosystem:
            use_dependency_parser = True
            logger.info("🔍 Detected ecosystem from file content: %s", ecosystem)

    if not ecosystem:
        logger.error("❌ Could not determine ecosystem for file: %s", file_path)
        logger.error("Please specify ecosystem with --ecosystem option")
        return None, [], file_path, iocs

    logger.info("🔍 Using ecosystem: %s", ecosystem)

    if use_dependency_parser:
        logger.info("📦 Parsing dependency file: %s", os.path.basename(file_path))
        packages = dependency_parsers.parse_dependencies(file_path, ecosystem)
        for pkg in packages:
            pkg["ecosystem"] = ecosystem
    else:
        logger.info("📄 Parsing generic file: %s", os.path.basename(file_path))
        packages = file_input_parser.parse_file_input(file_path)
        for pkg in packages:
            pkg["ecosystem"] = ecosystem

    file_dir = os.path.dirname(file_path) if os.path.dirname(file_path) else "."
    packages = aggregate_package_locations(packages, file_dir)
    logger.info("✅ Extracted %d package(s)", len(packages))
    return ecosystem, packages, file_path, iocs


def _load_orchestrator_helpers():
    """Import collector orchestrator helpers lazily."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    collectors_dir = os.path.join(script_dir, "collectors")
    if collectors_dir not in sys.path:
        sys.path.insert(0, collectors_dir)

    from orchestrator import collect_all_data
    from orchestrator import EXPECTED_ECOSYSTEMS
    from orchestrator import SOURCE_DEFINITIONS
    from orchestrator import build_databases
    from orchestrator import databases_need_refresh
    from orchestrator import get_database_statuses
    from orchestrator import run_all_collectors
    from orchestrator import resolve_sources

    return (
        collect_all_data,
        build_databases,
        databases_need_refresh,
        get_database_statuses,
        resolve_sources,
        run_all_collectors,
        EXPECTED_ECOSYSTEMS,
        SOURCE_DEFINITIONS,
    )


def _load_live_update_runtime():
    """Return the live-update state directory and effective config."""
    from monitor.config import ensure_monitor_layout
    from monitor.config import load_monitor_config

    paths = ensure_monitor_layout()
    config = load_monitor_config()
    promotion_root = os.path.join(paths["snapshots"], "live-updates")
    return (
        promotion_root,
        merge_live_update_config(config.get("live_updates", {})),
        paths["final_data_dir"],
    )


def _format_anomaly_summary(anomalies: List[Dict[str, object]]) -> str:
    if not anomalies:
        return ""
    top = anomalies[0]
    if len(anomalies) == 1:
        return str(top.get("message", "anomaly detected"))
    return f"{top.get('message', 'anomaly detected')} (+{len(anomalies) - 1} more)"


def _perform_gated_live_refresh(
    include_experimental_sources: bool,
    promotion_root: str,
    live_updates_config: Dict[str, object],
    active_final_data_dir: Optional[str] = None,
) -> Dict[str, object]:
    """Collect live threat data into a candidate set and promote it only if gates pass."""
    (
        _collect_all_data,
        build_databases,
        _databases_need_refresh,
        get_database_statuses,
        resolve_sources,
        run_all_collectors,
        expected_ecosystems,
        source_definitions,
    ) = _load_orchestrator_helpers()

    live_updates_config = merge_live_update_config(live_updates_config)
    layout = ensure_live_update_layout(promotion_root)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    attempt_id = (
        f"{timestamp.replace(':', '').replace('-', '')}-{os.getpid()}-{os.urandom(4).hex()}"
    )
    selected_sources = resolve_sources(include_experimental=include_experimental_sources)
    candidate_raw_dir = tempfile.mkdtemp(prefix="candidate-raw-", dir=layout["staging"])
    candidate_final_dir = tempfile.mkdtemp(prefix="candidate-final-", dir=layout["staging"])
    if active_final_data_dir is None:
        _runtime_promotion_root, _runtime_live_updates_config, active_final_data_dir = (
            _load_live_update_runtime()
        )

    try:
        collector_results = run_all_collectors(
            sources=selected_sources,
            include_experimental=include_experimental_sources,
            raw_data_dir=candidate_raw_dir,
        )
        build_summary = build_databases(
            selected_sources=selected_sources,
            source_results=collector_results,
            raw_data_dir=candidate_raw_dir,
            final_data_dir=candidate_final_dir,
        )
        candidate_summary, candidate_names = build_candidate_summary(
            attempt_id,
            selected_sources,
            collector_results,
            build_summary,
            candidate_final_dir,
            expected_ecosystems,
            get_database_statuses,
        )
        current_summary, active_summary, active_names, active_source_counts = load_active_baseline(
            promotion_root,
            active_final_data_dir,
            expected_ecosystems,
            get_database_statuses,
        )
        report = evaluate_candidate(
            attempt_id=attempt_id,
            timestamp=timestamp,
            selected_sources=selected_sources,
            source_definitions=source_definitions,
            candidate_summary=candidate_summary,
            active_summary=active_summary,
            candidate_names=candidate_names,
            active_names=active_names,
            active_source_counts=active_source_counts,
            live_update_config=live_updates_config,
        )

        live_dataset_version = f"{timestamp.replace(':', '').replace('-', '')}-{attempt_id}"
        report["live_dataset_version"] = live_dataset_version
        report["active_summary_path"] = layout["current_summary"] if os.path.exists(layout["current_summary"]) else ""
        report_path = ""

        active_database_statuses = get_database_statuses(final_data_dir=active_final_data_dir)
        if report["decision"] in {"promoted", "bootstrapped"}:
            try:
                backup_dir = promote_candidate_directory(
                    active_final_data_dir,
                    candidate_final_dir,
                    promotion_root,
                    live_dataset_version,
                )
            except Exception as exc:
                report["decision"] = "rejected"
                report["kept_last_known_good"] = True
                report["message"] = (
                    "Live threat-data promotion failed; kept last-known-good data. "
                    f"{exc}"
                )
                report["anomalies"].append(
                    {
                        "severity": "block",
                        "code": "promotion_failed",
                        "scope": "global",
                        "name": "promotion",
                        "message": str(exc),
                    }
                )
                report_path = persist_promotion_report(promotion_root, report, live_updates_config)
                return {
                    "success": any(status.get("usable") for status in active_database_statuses.values()),
                    "database_statuses": active_database_statuses,
                    "selected_sources": selected_sources,
                    "used_live_collection": True,
                    "refresh_required": False,
                    "promotion_decision": "rejected",
                    "kept_last_known_good": True,
                    "anomalies": report["anomalies"],
                    "candidate_summary_path": report_path,
                    "active_summary_path": layout["current_summary"] if os.path.exists(layout["current_summary"]) else "",
                    "live_dataset_version": current_summary.get("live_dataset_version", "") if current_summary else "",
                    "message": report["message"],
                }
            if backup_dir:
                report["backup_dir"] = backup_dir
            report_path = persist_promotion_report(promotion_root, report, live_updates_config)
            report["candidate_summary_path"] = report_path
            report["active_summary_path"] = layout["current_summary"]
            database_statuses = get_database_statuses(final_data_dir=active_final_data_dir)
            message = report["message"]
            if report["anomalies"]:
                message = f"{message}. {_format_anomaly_summary(report['anomalies'])}"
            return {
                "success": any(status.get("usable") for status in database_statuses.values()),
                "database_statuses": database_statuses,
                "selected_sources": selected_sources,
                "used_live_collection": True,
                "refresh_required": False,
                "promotion_decision": report["decision"],
                "kept_last_known_good": False,
                "anomalies": report["anomalies"],
                "candidate_summary_path": report_path,
                "active_summary_path": layout["current_summary"],
                "live_dataset_version": live_dataset_version,
                "message": message,
            }

        shutil.rmtree(candidate_final_dir, ignore_errors=True)
        report_path = persist_promotion_report(promotion_root, report, live_updates_config)
        has_active_baseline = any(status.get("usable") for status in active_database_statuses.values())
        message = report["message"]
        if report["anomalies"]:
            message = f"{message}. {_format_anomaly_summary(report['anomalies'])}"
        return {
            "success": has_active_baseline and report.get("kept_last_known_good", False),
            "database_statuses": active_database_statuses,
            "selected_sources": selected_sources,
            "used_live_collection": True,
            "refresh_required": not has_active_baseline,
            "promotion_decision": report["decision"],
            "kept_last_known_good": report.get("kept_last_known_good", False),
            "anomalies": report["anomalies"],
            "candidate_summary_path": report_path,
            "active_summary_path": layout["current_summary"] if os.path.exists(layout["current_summary"]) else "",
            "live_dataset_version": current_summary.get("live_dataset_version", "") if current_summary else "",
            "message": message,
        }
    finally:
        shutil.rmtree(candidate_raw_dir, ignore_errors=True)
        if os.path.exists(candidate_final_dir):
            shutil.rmtree(candidate_final_dir, ignore_errors=True)


def ensure_threat_data(
    force_update: bool = False,
    include_experimental_sources: bool = False,
    live_updates_config: Optional[Dict[str, object]] = None,
    promotion_root: Optional[str] = None,
    final_data_dir: Optional[str] = None,
) -> Dict[str, object]:
    """
    Ensure threat-intelligence databases exist and are fresh enough.
    """
    (
        _collect_all_data,
        _build_databases,
        databases_need_refresh,
        get_database_statuses,
        resolve_sources,
        _run_all_collectors,
        _expected_ecosystems,
        _source_definitions,
    ) = _load_orchestrator_helpers()
    runtime_promotion_root, runtime_live_updates_config, runtime_final_data_dir = (
        _load_live_update_runtime()
    )
    final_data_dir = final_data_dir or runtime_final_data_dir
    database_statuses = get_database_statuses(final_data_dir=final_data_dir)
    current_summary = {
        "success": any(status.get("usable") for status in database_statuses.values()),
        "database_statuses": database_statuses,
        "selected_sources": resolve_sources(
            include_experimental=include_experimental_sources
        ),
        "refresh_required": databases_need_refresh(
            include_experimental=include_experimental_sources,
            final_data_dir=final_data_dir,
        ),
        "used_live_collection": False,
        "promotion_decision": "",
        "kept_last_known_good": False,
        "anomalies": [],
    }

    if not force_update and not current_summary["refresh_required"]:
        logger.debug("Threat intelligence databases found")
        return current_summary

    promotion_root = promotion_root or runtime_promotion_root
    effective_live_updates_config = live_updates_config or runtime_live_updates_config

    if not effective_live_updates_config.get("enabled", True):
        current_summary["message"] = (
            "Live threat-data updates are disabled and no signed snapshot refresh was configured"
        )
        return current_summary

    print("=" * 60)
    if force_update:
        print("Collecting latest threat intelligence data...")
        print("Evaluating anomaly gates before promotion.")
        print("This may take 10-15 minutes depending on network speed.")
    else:
        print("Threat intelligence databases are missing or need refresh.")
        print("Collecting data from security sources...")
        print("Evaluating anomaly gates before promotion.")
        print("This may take 10-15 minutes (first run only).")
    print("=" * 60)
    print()

    summary = _perform_gated_live_refresh(
        include_experimental_sources=include_experimental_sources,
        promotion_root=promotion_root,
        live_updates_config=effective_live_updates_config,
        active_final_data_dir=final_data_dir,
    )

    if summary.get("success"):
        print()
        print("✓ Threat data refresh completed")
        print("=" * 60)
        print()
        return summary

    print()
    print("⚠ WARNING: Threat data refresh failed")
    print(summary.get("message", "No usable threat data available"))
    print("=" * 60)
    print()
    logger.warning("Live refresh failed or was rejected: %s", summary.get("message", ""))
    return summary


def get_current_threat_data_summary(
    include_experimental_sources: bool = False,
    final_data_dir: Optional[str] = None,
) -> Dict[str, object]:
    """Return current threat-data statuses without forcing collection."""
    (
        _collect_all_data,
        _build_databases,
        databases_need_refresh,
        get_database_statuses,
        resolve_sources,
        _run_all_collectors,
        _expected_ecosystems,
        _source_definitions,
    ) = _load_orchestrator_helpers()
    _runtime_promotion_root, _runtime_live_updates_config, runtime_final_data_dir = (
        _load_live_update_runtime()
    )
    final_data_dir = final_data_dir or runtime_final_data_dir
    database_statuses = get_database_statuses(final_data_dir=final_data_dir)
    return {
        "success": any(status.get("usable") for status in database_statuses.values()),
        "database_statuses": database_statuses,
        "selected_sources": resolve_sources(
            include_experimental=include_experimental_sources
        ),
        "refresh_required": databases_need_refresh(
            include_experimental=include_experimental_sources,
            final_data_dir=final_data_dir,
        ),
        "used_live_collection": False,
        "promotion_decision": "",
        "kept_last_known_good": False,
        "anomalies": [],
    }


def _generate_ioc_only_result(request: ScanRequest) -> ScanResult:
    """Run IoC-only scanning and generate a report."""
    if request.file_path:
        scanned_path = request.file_path
        if not os.path.exists(scanned_path):
            return ScanResult(
                ecosystem="unknown",
                scanned_path=scanned_path,
                requested_ecosystems=[],
                packages=[],
                malicious_packages=[],
                iocs=[],
                report_path=None,
                data_metadata={},
                exit_code=1,
                message=f"Path not found: {scanned_path}",
            )
        file_dir = os.path.dirname(scanned_path) if os.path.dirname(scanned_path) else "."
        iocs = ioc_detector.scan_for_iocs(file_dir) if request.scan_iocs else []
        ecosystem = "unknown"
    else:
        scanned_path = request.target_path or ""
        if not os.path.exists(scanned_path):
            return ScanResult(
                ecosystem="unknown",
                scanned_path=scanned_path,
                requested_ecosystems=[],
                packages=[],
                malicious_packages=[],
                iocs=[],
                report_path=None,
                data_metadata={},
                exit_code=1,
                message=f"Path not found: {scanned_path}",
            )
        if not os.path.isdir(scanned_path):
            return ScanResult(
                ecosystem="unknown",
                scanned_path=scanned_path,
                requested_ecosystems=[],
                packages=[],
                malicious_packages=[],
                iocs=[],
                report_path=None,
                data_metadata={},
                exit_code=1,
                message=f"Not a directory: {scanned_path}",
            )
        iocs = ioc_detector.scan_for_iocs(scanned_path) if request.scan_iocs else []
        ecosystem = ecosystem_detector.detect_ecosystem_from_directory(scanned_path) or "unknown"

    report_path = None
    if iocs:
        report_path = report_generator.generate_report(
            ecosystem=ecosystem,
            scanned_path=scanned_path,
            total_packages_scanned=0,
            malicious_packages=[],
            iocs=iocs,
            output_path=request.output_path,
            data_metadata={
                "data_status": "not_applicable",
                "sources_used": [],
                "experimental_sources_used": [],
                "missing_ecosystems": [],
            },
        )
        if request.print_summary:
            report_generator.print_report_summary(report_path)

    return ScanResult(
        ecosystem=ecosystem,
        scanned_path=scanned_path,
        requested_ecosystems=[],
        packages=[],
        malicious_packages=[],
        iocs=iocs,
        report_path=report_path,
        data_metadata={
            "data_status": "not_applicable",
            "sources_used": [],
            "experimental_sources_used": [],
            "missing_ecosystems": [],
        },
        exit_code=1 if iocs else 0,
        message="IoCs detected" if iocs else "No IoCs detected",
    )


def run_scan(request: ScanRequest) -> ScanResult:
    """
    Run a scan based on the supplied request.
    """
    if not request.target_path and not request.file_path:
        return ScanResult(
            ecosystem="unknown",
            scanned_path="",
            requested_ecosystems=[],
            packages=[],
            malicious_packages=[],
            iocs=[],
            report_path=None,
            data_metadata={},
            exit_code=1,
            message="Either target_path or file_path is required",
        )

    if request.file_path and request.target_path:
        return ScanResult(
            ecosystem="unknown",
            scanned_path=request.file_path,
            requested_ecosystems=[],
            packages=[],
            malicious_packages=[],
            iocs=[],
            report_path=None,
            data_metadata={},
            exit_code=1,
            message="Cannot specify both target_path and file_path",
        )

    if request.scan_iocs and not request.scan_packages:
        return _generate_ioc_only_result(request)

    threat_data_summary: Dict[str, object] = {
        "success": True,
        "database_statuses": {},
        "selected_sources": [],
    }
    runtime_final_data_dir: Optional[str] = None

    if request.scan_packages:
        _runtime_promotion_root, _runtime_live_updates_config, runtime_final_data_dir = (
            _load_live_update_runtime()
        )
        if request.refresh_mode == REFRESH_MODE_EXISTING_ONLY or not request.ensure_data:
            threat_data_summary = get_current_threat_data_summary(
                include_experimental_sources=request.include_experimental_sources,
                final_data_dir=runtime_final_data_dir,
            )
        else:
            threat_data_summary = ensure_threat_data(
                force_update=(
                    request.force_latest_data
                    or request.refresh_mode == REFRESH_MODE_LIVE_GATED_FORCE
                ),
                include_experimental_sources=request.include_experimental_sources,
                final_data_dir=runtime_final_data_dir,
            )

    if request.force_latest_data:
        refresh_error = None
        if threat_data_summary.get("refresh_required") and not threat_data_summary.get(
            "used_live_collection"
        ):
            refresh_error = threat_data_summary.get(
                "message",
                "Threat data refresh could not start",
            )
        elif threat_data_summary.get("used_live_collection") and not threat_data_summary.get(
            "success"
        ):
            refresh_error = threat_data_summary.get(
                "message",
                "Threat data refresh failed",
            )

        if refresh_error:
            scanned_target = request.file_path or request.target_path or ""
            return ScanResult(
                ecosystem="unknown",
                scanned_path=scanned_target,
                requested_ecosystems=[],
                packages=[],
                malicious_packages=[],
                iocs=[],
                report_path=None,
                data_metadata={},
                threat_data_summary=threat_data_summary,
                exit_code=2,
                message=refresh_error,
            )

    if request.file_path:
        if not os.path.exists(request.file_path):
            return ScanResult(
                ecosystem="unknown",
                scanned_path=request.file_path,
                requested_ecosystems=[],
                packages=[],
                malicious_packages=[],
                iocs=[],
                report_path=None,
                data_metadata={},
                threat_data_summary=threat_data_summary,
                exit_code=1,
                message=f"File not found: {request.file_path}",
            )
        ecosystem, packages, scanned_path, iocs = scan_file(
            request.file_path,
            request.ecosystem,
            scan_iocs=request.scan_iocs,
        )
    else:
        target_path = request.target_path or ""
        if not os.path.exists(target_path):
            return ScanResult(
                ecosystem="unknown",
                scanned_path=target_path,
                requested_ecosystems=[],
                packages=[],
                malicious_packages=[],
                iocs=[],
                report_path=None,
                data_metadata={},
                threat_data_summary=threat_data_summary,
                exit_code=1,
                message=f"Path not found: {target_path}",
            )
        if not os.path.isdir(target_path):
            return ScanResult(
                ecosystem="unknown",
                scanned_path=target_path,
                requested_ecosystems=[],
                packages=[],
                malicious_packages=[],
                iocs=[],
                report_path=None,
                data_metadata={},
                threat_data_summary=threat_data_summary,
                exit_code=1,
                message=f"Not a directory: {target_path}",
            )
        ecosystem, packages, scanned_path, iocs = scan_directory(
            target_path,
            request.ecosystem,
            scan_iocs=request.scan_iocs,
        )

    if not ecosystem:
        return ScanResult(
            ecosystem="unknown",
            scanned_path=scanned_path,
            requested_ecosystems=[],
            packages=packages,
            malicious_packages=[],
            iocs=iocs,
            report_path=None,
            data_metadata={},
            threat_data_summary=threat_data_summary,
            exit_code=1,
            message="Could not determine ecosystem",
        )

    requested_ecosystems = normalize_requested_ecosystems(ecosystem)
    data_metadata = summarize_requested_data_status(
        requested_ecosystems,
        threat_data_summary.get("database_statuses"),
    )
    data_metadata = _augment_data_metadata(data_metadata, threat_data_summary)

    if request.scan_packages and requested_ecosystems:
        if request.strict_data and data_metadata["data_status"] != "complete":
            partial_ecosystems = [
                eco
                for eco, status in data_metadata["requested_statuses"].items()
                if status.get("data_status") == "partial"
            ]
            message_bits = ["Strict data mode requires complete threat data"]
            if data_metadata["missing_ecosystems"]:
                message_bits.append(
                    "missing: " + ", ".join(data_metadata["missing_ecosystems"])
                )
            if partial_ecosystems:
                message_bits.append("partial: " + ", ".join(partial_ecosystems))
            return ScanResult(
                ecosystem=", ".join(requested_ecosystems),
                scanned_path=scanned_path,
                requested_ecosystems=requested_ecosystems,
                packages=packages,
                malicious_packages=[],
                iocs=iocs,
                report_path=None,
                data_metadata=data_metadata,
                threat_data_summary=threat_data_summary,
                exit_code=2,
                message="; ".join(message_bits),
            )

        if not data_metadata["usable_ecosystems"]:
            guidance = threat_data_summary.get("message")
            message = (
                "No usable threat data available for requested ecosystem(s): "
                + ", ".join(requested_ecosystems)
            )
            if guidance:
                message = f"{message}. {guidance}"
            return ScanResult(
                ecosystem=", ".join(requested_ecosystems),
                scanned_path=scanned_path,
                requested_ecosystems=requested_ecosystems,
                packages=packages,
                malicious_packages=[],
                iocs=iocs,
                report_path=None,
                data_metadata=data_metadata,
                threat_data_summary=threat_data_summary,
                exit_code=2,
                message=message,
            )

        if data_metadata["missing_ecosystems"]:
            logger.warning(
                "⚠️  Skipping package checks for ecosystem(s) with unavailable threat data: %s",
                ", ".join(data_metadata["missing_ecosystems"]),
            )

    if not packages and request.scan_packages and not iocs:
        return ScanResult(
            ecosystem=", ".join(requested_ecosystems) if requested_ecosystems else "unknown",
            scanned_path=scanned_path,
            requested_ecosystems=requested_ecosystems,
            packages=[],
            malicious_packages=[],
            iocs=iocs,
            report_path=None,
            data_metadata=data_metadata,
            threat_data_summary=threat_data_summary,
            exit_code=0,
            message="No packages found to scan",
        )

    malicious_packages: List[Dict] = []
    if request.scan_packages and packages:
        if isinstance(ecosystem, list):
            logger.info("\n🔍 Checking %d package(s) against malicious databases...", len(packages))
            packages_by_ecosystem: Dict[str, List[Dict]] = {}
            for pkg in packages:
                pkg_eco = pkg.get("ecosystem", ecosystem[0])
                packages_by_ecosystem.setdefault(pkg_eco, []).append(pkg)

            for eco in ecosystem:
                if eco not in data_metadata["usable_ecosystems"]:
                    continue
                eco_packages = packages_by_ecosystem.get(eco, [])
                if eco_packages:
                    logger.info("   Checking %d %s package(s)...", len(eco_packages), eco)
                    malicious = malicious_checker.check_malicious_packages(
                        eco_packages,
                        eco,
                        final_data_dir=runtime_final_data_dir,
                        include_shai_hulud=True,
                    )
                    malicious_packages.extend(malicious)
            ecosystem_str = ", ".join(ecosystem)
        else:
            ecosystem_str = ecosystem
            if ecosystem in data_metadata["usable_ecosystems"]:
                logger.info(
                    "\n🔍 Checking %d package(s) against malicious database...",
                    len(packages),
                )
                malicious_packages = malicious_checker.check_malicious_packages(
                    packages,
                    ecosystem,
                    final_data_dir=runtime_final_data_dir,
                    include_shai_hulud=True,
                )
    else:
        ecosystem_str = (
            ecosystem
            if isinstance(ecosystem, str)
            else ", ".join(ecosystem)
            if isinstance(ecosystem, list)
            else "unknown"
        )

    report_path = report_generator.generate_report(
        ecosystem=ecosystem_str,
        scanned_path=scanned_path,
        total_packages_scanned=len(packages) if packages else 0,
        malicious_packages=malicious_packages,
        iocs=iocs,
        output_path=request.output_path,
        data_metadata=data_metadata,
    )

    if request.print_summary:
        report_generator.print_report_summary(report_path)

    has_issues = bool(malicious_packages) or bool(iocs)
    if has_issues:
        if malicious_packages and iocs:
            message = (
                f"{len(malicious_packages)} malicious package(s) and {len(iocs)} IoC(s) detected"
            )
        elif malicious_packages:
            message = f"{len(malicious_packages)} malicious package(s) detected"
        else:
            message = f"{len(iocs)} IoC(s) detected"
    else:
        message = "No malicious packages or IoCs detected"

    return ScanResult(
        ecosystem=ecosystem_str,
        scanned_path=scanned_path,
        requested_ecosystems=requested_ecosystems,
        packages=packages,
        malicious_packages=malicious_packages,
        iocs=iocs,
        report_path=report_path,
        data_metadata=data_metadata,
        threat_data_summary=threat_data_summary,
        exit_code=1 if has_issues else 0,
        message=message,
    )
