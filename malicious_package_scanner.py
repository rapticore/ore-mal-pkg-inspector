#!/usr/bin/env python3
"""
Multi-Ecosystem Malicious Package Scanner
Scans packages from various ecosystems against unified malicious package databases
"""

import sys
import os
import argparse
import logging
from pathlib import Path
from typing import Optional

# Add scanners directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from logging_config import setup_logging, get_logger
from scanners import ecosystem_detector
from scanners import dependency_parsers
from scanners import file_input_parser
from scanners import malicious_checker
from scanners import report_generator
from scanners import ioc_detector

# Module logger
logger = get_logger(__name__)


def aggregate_package_locations(packages: list, scanned_path: str) -> list:
    """
    Aggregate packages by name+version, collecting all SARIF physicalLocations.
    Convert absolute paths to relative paths.

    Args:
        packages: List of package dicts with physical_location
        scanned_path: Base directory for relative path calculation

    Returns:
        List of unique packages with locations array (SARIF physicalLocation format)
    """
    aggregated = {}

    for pkg in packages:
        key = (pkg['name'].lower(), pkg.get('version', ''))

        if key not in aggregated:
            aggregated[key] = {
                'name': pkg['name'],
                'version': pkg.get('version', ''),
                'section': pkg.get('section', ''),
                'ecosystem': pkg.get('ecosystem', ''),
                'locations': []
            }

        # Add SARIF physical location if it exists
        if 'physical_location' in pkg and pkg['physical_location']:
            phys_loc = pkg['physical_location']

            # Convert absolute path to relative in artifactLocation.uri
            abs_path = phys_loc['artifact_location']['uri']
            rel_path = os.path.relpath(abs_path, scanned_path)

            # Create SARIF-compliant location with camelCase field names
            sarif_location = {
                'physicalLocation': {
                    'artifactLocation': {
                        'uri': rel_path
                    },
                    'region': {
                        'startLine': phys_loc['region']['start_line'],
                        'startColumn': phys_loc['region']['start_column'],
                        'endLine': phys_loc['region']['end_line'],
                        'endColumn': phys_loc['region']['end_column']
                    }
                }
            }

            # Avoid duplicate locations
            if sarif_location not in aggregated[key]['locations']:
                aggregated[key]['locations'].append(sarif_location)

    return list(aggregated.values())


def scan_directory(directory: str, ecosystem: Optional[str] = None, scan_iocs: bool = True) -> tuple:
    """
    Scan a directory for dependencies and check against malicious database.
    If multiple ecosystems are detected and no ecosystem is specified, scans all detected ecosystems.
    
    Args:
        directory: Path to directory to scan
        ecosystem: Optional ecosystem override
        
    Returns:
        Tuple of (ecosystem_or_list, packages_list, scanned_path, iocs_list)
        If multiple ecosystems, returns list of ecosystems and combined packages list
    """
    iocs = []
    if scan_iocs:
        iocs = ioc_detector.scan_for_iocs(directory)
        if iocs:
            logger.info("🕵️  Found %d Indicator(s) of Compromise", len(iocs))

    # Detect ecosystem(s) if not provided
    if not ecosystem:
        all_ecosystems = ecosystem_detector.detect_all_ecosystems_from_directory(directory)
        if not all_ecosystems:
            logger.error("❌ Could not detect ecosystem in directory: %s", directory)
            logger.error("Please specify ecosystem with --ecosystem option")
            return None, [], directory

        if len(all_ecosystems) == 1:
            ecosystem = all_ecosystems[0]
            logger.info("🔍 Detected ecosystem: %s", ecosystem)
        else:
            logger.info("🔍 Detected multiple ecosystems: %s", ', '.join(all_ecosystems))
            logger.info("   Scanning all detected ecosystems...")
            # Scan all ecosystems
            all_packages = []
            for eco in all_ecosystems:
                logger.info("\n   Scanning %s...", eco)
                dep_files = ecosystem_detector.find_dependency_files(directory, eco)
                if dep_files:
                    logger.info("   📦 Found %d dependency file(s) for %s", len(dep_files), eco)
                    for dep_file in dep_files:
                        logger.debug("      Parsing: %s", os.path.relpath(dep_file, directory))
                        packages = dependency_parsers.parse_dependencies(dep_file, eco)
                        # Tag packages with ecosystem
                        for pkg in packages:
                            pkg['ecosystem'] = eco
                        all_packages.extend(packages)

            # Aggregate packages by name+version and collect SARIF locations
            unique_packages = aggregate_package_locations(all_packages, directory)

            logger.info("\n✅ Extracted %d unique package(s) across %d ecosystem(s)", len(unique_packages), len(all_ecosystems))
            return all_ecosystems, unique_packages, directory, iocs

    # Single ecosystem scan
    logger.info("🔍 Using ecosystem: %s", ecosystem)

    # Find dependency files
    dep_files = ecosystem_detector.find_dependency_files(directory, ecosystem)

    if not dep_files:
        logger.warning("⚠️  No dependency files found for %s in %s", ecosystem, directory)
        return ecosystem, [], directory

    logger.info("📦 Found %d dependency file(s)", len(dep_files))

    # Parse dependencies from all files
    all_packages = []
    for dep_file in dep_files:
        logger.debug("   Parsing: %s", os.path.relpath(dep_file, directory))
        packages = dependency_parsers.parse_dependencies(dep_file, ecosystem)
        all_packages.extend(packages)

    # Aggregate packages by name+version and collect SARIF locations
    unique_packages = aggregate_package_locations(all_packages, directory)

    logger.info("✅ Extracted %d unique package(s)", len(unique_packages))

    return ecosystem, unique_packages, directory, iocs


def scan_file(file_path: str, ecosystem: Optional[str] = None, scan_iocs: bool = True) -> tuple:
    """
    Scan a file for packages and check against malicious database.
    
    Args:
        file_path: Path to file to scan
        ecosystem: Optional ecosystem override
        
    Returns:
        Tuple of (ecosystem, packages_list, scanned_path, iocs_list)
    """
    iocs = []
    if scan_iocs:
        # Scan IoCs in the directory containing the file
        file_dir = os.path.dirname(file_path) if os.path.dirname(file_path) else '.'
        iocs = ioc_detector.scan_for_iocs(file_dir)
        if iocs:
            logger.info("🕵️  Found %d Indicator(s) of Compromise", len(iocs))

    # Detect ecosystem from filename if not provided
    detected_ecosystem = ecosystem_detector.detect_ecosystem_from_filename(file_path)

    if not ecosystem:
        ecosystem = detected_ecosystem

    # Fallback: try content-based detection for JSON files
    if not ecosystem and file_path.endswith('.json'):
        ecosystem = ecosystem_detector.detect_ecosystem_from_json_content(file_path)
        if ecosystem:
            logger.info("🔍 Detected ecosystem from file content: %s", ecosystem)

    if not ecosystem:
        logger.error("❌ Could not determine ecosystem for file: %s", file_path)
        logger.error("Please specify ecosystem with --ecosystem option")
        return None, [], file_path

    logger.info("🔍 Using ecosystem: %s", ecosystem)

    # Parse based on ecosystem (use dependency parser when we know the ecosystem)
    if ecosystem:
        # Parse as dependency file
        logger.info("📦 Parsing dependency file: %s", os.path.basename(file_path))
        packages = dependency_parsers.parse_dependencies(file_path, ecosystem)
    else:
        # Parse as generic file input
        logger.info("📄 Parsing generic file: %s", os.path.basename(file_path))
        packages = file_input_parser.parse_file_input(file_path)

    # Aggregate packages and collect SARIF locations (using file's directory as base path)
    file_dir = os.path.dirname(file_path) if os.path.dirname(file_path) else '.'
    packages = aggregate_package_locations(packages, file_dir)

    logger.info("✅ Extracted %d package(s)", len(packages))

    return ecosystem, packages, file_path, iocs


def ensure_threat_data(force_update=False):
    """
    Ensure threat intelligence databases exist.
    Automatically collects data if missing or if force_update is True.

    Args:
        force_update (bool): Force data collection even if databases exist

    Returns:
        bool: True if databases exist after check, False otherwise
    """
    # Add collectors to path for imports
    script_dir = os.path.dirname(os.path.abspath(__file__))
    collectors_dir = os.path.join(script_dir, 'collectors')
    sys.path.insert(0, collectors_dir)

    from orchestrator import check_databases_exist, collect_all_data

    # Check if collection needed
    if force_update:
        print("=" * 60)
        print("Collecting latest threat intelligence data...")
        print("This may take 10-15 minutes depending on network speed.")
        print("=" * 60)
        print()
    elif check_databases_exist():
        logger.debug("Threat intelligence databases found")
        return True
    else:
        print("=" * 60)
        print("Threat intelligence databases not found.")
        print("Collecting data from security sources...")
        print("This may take 10-15 minutes (first run only).")
        print("=" * 60)
        print()

    # Run collection
    success = collect_all_data(build_if_missing=True)

    if success:
        print()
        print("✓ Threat data collection completed successfully")
        print("=" * 60)
        print()
        return True
    else:
        print()
        print("⚠ WARNING: Threat data collection failed")
        print("Continuing scan with existing/cached data...")
        print("=" * 60)
        print()
        logger.warning("Collection failed, proceeding with available data")
        return False


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Multi-Ecosystem Malicious Package Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Auto-detect ecosystem and scan directory
  %(prog)s /path/to/project

  # Scan directory with ecosystem override
  %(prog)s /path/to/project --ecosystem npm

  # Scan dependency file (ecosystem auto-detected)
  %(prog)s --file package.json
  %(prog)s --file requirements.txt

  # Scan generic file with ecosystem
  %(prog)s --file packages.txt --ecosystem pypi

  # Specify output report path
  %(prog)s /path/to/project --output report.json
        """
    )
    
    parser.add_argument(
        'path',
        nargs='?',
        help='Path to directory or file to scan'
    )
    
    parser.add_argument(
        '--file', '-f',
        dest='file_path',
        help='Path to file to scan (skips directory detection)'
    )
    
    parser.add_argument(
        '--ecosystem', '-e',
        choices=['npm', 'pypi', 'maven', 'rubygems', 'go', 'cargo'],
        help='Ecosystem to scan (npm, pypi, maven, rubygems, go, cargo)'
    )
    
    parser.add_argument(
        '--output', '-o',
        dest='output_path',
        help='Output path for report JSON file (default: auto-generated timestamped filename)'
    )
    
    parser.add_argument(
        '--no-summary',
        action='store_true',
        help='Skip printing report summary'
    )
    
    parser.add_argument(
        '--no-ioc',
        action='store_true',
        dest='no_ioc',
        help='Skip IoC (Indicators of Compromise) scanning for faster execution'
    )
    
    parser.add_argument(
        '--ioc-only',
        action='store_true',
        dest='ioc_only',
        help='Only scan for IoCs, skip package dependency checking'
    )

    parser.add_argument(
        '--latest-data',
        action='store_true',
        dest='latest_data',
        help='Force collection of latest threat intelligence before scanning (takes 10-15 minutes)'
    )

    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show INFO level logs to console (progress messages)'
    )

    parser.add_argument(
        '--debug',
        action='store_true',
        help='Show DEBUG level logs to console (detailed diagnostic info)'
    )

    args = parser.parse_args()

    # Setup logging based on arguments
    if args.debug:
        setup_logging(logging.DEBUG)
    elif args.verbose:
        setup_logging(logging.INFO)
    else:
        setup_logging(logging.WARNING)  # Default: only warnings and errors

    logger.debug("Logging initialized at %s level",
                 'DEBUG' if args.debug else ('INFO' if args.verbose else 'WARNING'))

    # Ensure threat intelligence databases exist
    ensure_threat_data(force_update=args.latest_data)

    # Validate arguments
    if not args.path and not args.file_path:
        parser.error("Either provide a path or use --file option")
    
    if args.path and args.file_path:
        parser.error("Cannot specify both path and --file option")
    
    # Determine scan mode
    scan_iocs = not args.no_ioc
    scan_packages = not args.ioc_only
    
    # Determine what to scan
    if args.ioc_only:
        # IoC-only mode - just scan for IoCs
        if args.file_path:
            scanned_path = args.file_path
            file_dir = os.path.dirname(args.file_path) if os.path.dirname(args.file_path) else '.'
            iocs = ioc_detector.scan_for_iocs(file_dir) if scan_iocs else []
            ecosystem = 'unknown'
        else:
            scanned_path = args.path
            if not os.path.exists(scanned_path):
                logger.error("❌ Path not found: %s", scanned_path)
                sys.exit(1)
            if not os.path.isdir(scanned_path):
                logger.error("❌ Not a directory: %s", scanned_path)
                sys.exit(1)
            iocs = ioc_detector.scan_for_iocs(scanned_path) if scan_iocs else []
            # Try to detect ecosystem for reporting
            ecosystem = ecosystem_detector.detect_ecosystem_from_directory(scanned_path) or 'unknown'

        packages = []

        if not iocs:
            print("✅ No IoCs detected!")
            sys.exit(0)
        
        print(f"🕵️  Found {len(iocs)} Indicator(s) of Compromise")
        
        # Generate report with only IoCs
        report_path = report_generator.generate_report(
            ecosystem=ecosystem,
            scanned_path=scanned_path,
            total_packages_scanned=0,
            malicious_packages=[],
            iocs=iocs,
            output_path=args.output_path
        )
        
        if not args.no_summary:
            report_generator.print_report_summary(report_path)
        
        print(f"\n🚨 {len(iocs)} IoC(s) detected!")
        sys.exit(1)
    
    # Normal scanning mode
    if args.file_path:
        # File input mode
        if not os.path.exists(args.file_path):
            logger.error("❌ File not found: %s", args.file_path)
            sys.exit(1)

        ecosystem, packages, scanned_path, iocs = scan_file(args.file_path, args.ecosystem, scan_iocs=scan_iocs)
    else:
        # Directory mode
        if not os.path.exists(args.path):
            logger.error("❌ Path not found: %s", args.path)
            sys.exit(1)

        if not os.path.isdir(args.path):
            logger.error("❌ Not a directory: %s", args.path)
            sys.exit(1)

        ecosystem, packages, scanned_path, iocs = scan_directory(args.path, args.ecosystem, scan_iocs=scan_iocs)

    if not ecosystem:
        sys.exit(1)

    if not packages and scan_packages:
        logger.warning("⚠️  No packages found to scan")
        if not iocs:
            sys.exit(0)
    
    # Handle multiple ecosystems
    malicious_packages = []
    if scan_packages and packages:
        if isinstance(ecosystem, list):
            # Multiple ecosystems detected - check each separately
            logger.info("\n🔍 Checking %d package(s) against malicious databases...", len(packages))
            all_malicious = []

            # Group packages by ecosystem
            packages_by_ecosystem = {}
            for pkg in packages:
                pkg_eco = pkg.get('ecosystem', ecosystem[0])  # Default to first ecosystem if not tagged
                if pkg_eco not in packages_by_ecosystem:
                    packages_by_ecosystem[pkg_eco] = []
                packages_by_ecosystem[pkg_eco].append(pkg)

            # Check each ecosystem
            for eco in ecosystem:
                eco_packages = packages_by_ecosystem.get(eco, [])
                if eco_packages:
                    logger.info("   Checking %d %s package(s)...", len(eco_packages), eco)
                    malicious = malicious_checker.check_malicious_packages(eco_packages, eco, include_shai_hulud=True)
                    all_malicious.extend(malicious)

            malicious_packages = all_malicious
            ecosystem_str = ', '.join(ecosystem)
        else:
            # Single ecosystem
            logger.info("\n🔍 Checking %d package(s) against malicious database...", len(packages))
            malicious_packages = malicious_checker.check_malicious_packages(packages, ecosystem, include_shai_hulud=True)
            ecosystem_str = ecosystem
    else:
        ecosystem_str = ecosystem if isinstance(ecosystem, str) else ', '.join(ecosystem) if isinstance(ecosystem, list) else 'unknown'

    # Generate report
    logger.info("\n📊 Generating report...")
    report_path = report_generator.generate_report(
        ecosystem=ecosystem_str,
        scanned_path=scanned_path,
        total_packages_scanned=len(packages) if packages else 0,
        malicious_packages=malicious_packages,
        iocs=iocs,
        output_path=args.output_path
    )
    
    # Print summary unless disabled
    if not args.no_summary:
        report_generator.print_report_summary(report_path)
    
    # Exit with error code if malicious packages or IoCs found
    has_issues = bool(malicious_packages) or bool(iocs)
    if malicious_packages:
        print(f"\n🚨 {len(malicious_packages)} malicious package(s) detected!")
    if iocs:
        print(f"\n🚨 {len(iocs)} IoC(s) detected!")
    if not has_issues:
        print(f"\n✅ No malicious packages or IoCs detected!")
    
    sys.exit(1 if has_issues else 0)


if __name__ == "__main__":
    main()

