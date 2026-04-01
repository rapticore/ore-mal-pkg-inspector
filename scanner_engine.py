#!/usr/bin/env python3
"""
Reusable scan engine for one-off CLI runs and background monitoring.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from logging_config import get_logger
from scanners import dependency_parsers
from scanners import ecosystem_detector
from scanners import file_input_parser
from scanners import ioc_detector
from scanners import malicious_checker
from scanners import report_generator
from scanners.supported_files import ECOSYSTEM_PRIORITY, get_supported_files_for_ecosystem


logger = get_logger(__name__)
ALLOW_UNVERIFIED_LIVE_COLLECTION_ENV = "OREWATCH_ALLOW_UNVERIFIED_LIVE_COLLECTION"


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
    allow_unverified_live_collection: bool = False
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
    from orchestrator import databases_need_refresh
    from orchestrator import get_database_statuses
    from orchestrator import resolve_sources

    return collect_all_data, databases_need_refresh, get_database_statuses, resolve_sources


def ensure_threat_data(
    force_update: bool = False,
    include_experimental_sources: bool = False,
    allow_unverified_live_collection: bool = False,
) -> Dict[str, object]:
    """
    Ensure threat-intelligence databases exist and are fresh enough.
    """
    collect_all_data, databases_need_refresh, get_database_statuses, resolve_sources = (
        _load_orchestrator_helpers()
    )
    database_statuses = get_database_statuses()
    current_summary = {
        "success": any(status.get("usable") for status in database_statuses.values()),
        "database_statuses": database_statuses,
        "selected_sources": resolve_sources(
            include_experimental=include_experimental_sources
        ),
        "used_live_collection": False,
    }
    allow_live_collection = allow_unverified_live_collection or (
        os.environ.get(ALLOW_UNVERIFIED_LIVE_COLLECTION_ENV) == "1"
    )

    if force_update:
        if not allow_live_collection:
            current_summary["message"] = (
                "Threat data refresh requires signed snapshots or explicit opt-in to "
                "unverified live collection via --allow-unverified-live-collection "
                f"or {ALLOW_UNVERIFIED_LIVE_COLLECTION_ENV}=1"
            )
            current_summary["refresh_required"] = True
            logger.warning(current_summary["message"])
            return current_summary
        print("=" * 60)
        print("Collecting latest threat intelligence data...")
        print("This may take 10-15 minutes depending on network speed.")
        print("=" * 60)
        print()
    elif not databases_need_refresh(include_experimental=include_experimental_sources):
        logger.debug("Threat intelligence databases found")
        return current_summary
    else:
        if not allow_live_collection:
            current_summary["message"] = (
                "Threat data is missing or outdated. Apply a signed snapshot or rerun "
                "with --latest-data --allow-unverified-live-collection to opt in to "
                "unverified live collector refresh."
            )
            current_summary["refresh_required"] = True
            logger.warning(current_summary["message"])
            return current_summary
        print("=" * 60)
        print("Threat intelligence databases are missing or need refresh.")
        print("Collecting data from security sources...")
        print("This may take 10-15 minutes (first run only).")
        print("=" * 60)
        print()

    summary = collect_all_data(
        build_if_missing=not force_update,
        include_experimental=include_experimental_sources,
    )
    summary["used_live_collection"] = True

    if summary.get("success"):
        print()
        print("✓ Threat data collection completed successfully")
        print("=" * 60)
        print()
        return summary

    print()
    print("⚠ WARNING: Threat data collection failed")
    print("Using currently available local threat data only.")
    print("=" * 60)
    print()
    logger.warning("Live collection failed; using current local threat data only")
    summary["message"] = "Unverified live threat-data collection failed"
    return summary


def get_current_threat_data_summary(
    include_experimental_sources: bool = False,
) -> Dict[str, object]:
    """Return current threat-data statuses without forcing collection."""
    _, databases_need_refresh, get_database_statuses, resolve_sources = _load_orchestrator_helpers()
    database_statuses = get_database_statuses()
    return {
        "success": any(status.get("usable") for status in database_statuses.values()),
        "database_statuses": database_statuses,
        "selected_sources": resolve_sources(
            include_experimental=include_experimental_sources
        ),
        "refresh_required": databases_need_refresh(
            include_experimental=include_experimental_sources
        ),
        "used_live_collection": False,
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

    if request.scan_packages:
        if request.ensure_data:
            threat_data_summary = ensure_threat_data(
                force_update=request.force_latest_data,
                include_experimental_sources=request.include_experimental_sources,
                allow_unverified_live_collection=request.allow_unverified_live_collection,
            )
        else:
            threat_data_summary = get_current_threat_data_summary(
                include_experimental_sources=request.include_experimental_sources
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
