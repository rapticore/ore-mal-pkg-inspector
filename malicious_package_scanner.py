#!/usr/bin/env python3
"""
Multi-Ecosystem Malicious Package Scanner
Scans packages from various ecosystems against unified malicious package databases.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys

from logging_config import setup_logging
from monitor.cli import run_monitor_cli
from scanner_engine import ScanRequest
from scanner_engine import aggregate_package_locations
from scanner_engine import ensure_threat_data
from scanner_engine import normalize_requested_ecosystems
from scanner_engine import print_supported_files
from scanner_engine import run_scan
from scanner_engine import scan_directory
from scanner_engine import scan_file
from scanner_engine import summarize_requested_data_status

MINIMUM_PYTHON = (3, 14)


def ensure_supported_python() -> None:
    """Fail fast when the interpreter is older than the supported runtime."""
    if sys.version_info < MINIMUM_PYTHON:
        version = ".".join(str(part) for part in MINIMUM_PYTHON)
        raise SystemExit(
            f"OreWatch requires Python {version}+; "
            f"found {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        )


def build_parser() -> argparse.ArgumentParser:
    """Build the primary scanner parser."""
    parser = argparse.ArgumentParser(
        description="Multi-Ecosystem Malicious Package Scanner",
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

  # Start the background monitor
  %(prog)s monitor install
  %(prog)s monitor start
        """,
    )

    parser.add_argument("path", nargs="?", help="Path to directory or file to scan")
    parser.add_argument(
        "--file",
        "-f",
        dest="file_path",
        help="Path to file to scan (skips directory detection)",
    )
    parser.add_argument(
        "--ecosystem",
        "-e",
        choices=["npm", "pypi", "maven", "rubygems", "go", "cargo"],
        help="Ecosystem to scan (npm, pypi, maven, rubygems, go, cargo)",
    )
    parser.add_argument(
        "--output",
        "-o",
        dest="output_path",
        help="Output path for report JSON file (default: auto-generated timestamped filename)",
    )
    parser.add_argument(
        "--no-summary",
        action="store_true",
        help="Skip printing report summary",
    )
    parser.add_argument(
        "--no-ioc",
        action="store_true",
        dest="no_ioc",
        help="Skip IoC (Indicators of Compromise) scanning for faster execution",
    )
    parser.add_argument(
        "--ioc-only",
        action="store_true",
        dest="ioc_only",
        help="Only scan for IoCs, skip package dependency checking",
    )
    parser.add_argument(
        "--latest-data",
        action="store_true",
        dest="latest_data",
        help="Force collection of latest threat intelligence before scanning (takes 10-15 minutes)",
    )
    parser.add_argument(
        "--strict-data",
        action="store_true",
        dest="strict_data",
        help="Fail if any requested ecosystem has missing or partial threat data",
    )
    parser.add_argument(
        "--include-experimental-sources",
        action="store_true",
        dest="include_experimental_sources",
        help="Include experimental threat sources during data collection",
    )
    parser.add_argument(
        "--list-supported-files",
        action="store_true",
        dest="list_supported_files",
        help="List the exact dependency manifest filenames recognized by the scanner and exit",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show INFO level logs to console (progress messages)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Show DEBUG level logs to console (detailed diagnostic info)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Main entry point."""
    ensure_supported_python()
    argv = list(argv) if argv is not None else sys.argv[1:]

    if argv and argv[0] == "monitor":
        return run_monitor_cli(argv[1:])

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_supported_files:
        print_supported_files()
        return 0

    if not args.path and not args.file_path:
        parser.error("Either provide a path or use --file option")

    if args.path and args.file_path:
        parser.error("Cannot specify both path and --file option")

    if args.debug:
        setup_logging(logging.DEBUG)
    elif args.verbose:
        setup_logging(logging.INFO)
    else:
        setup_logging(logging.WARNING)

    request = ScanRequest(
        target_path=args.path,
        file_path=args.file_path,
        ecosystem=args.ecosystem,
        output_path=args.output_path,
        scan_iocs=not args.no_ioc,
        scan_packages=not args.ioc_only,
        force_latest_data=args.latest_data,
        strict_data=args.strict_data,
        include_experimental_sources=args.include_experimental_sources,
        ensure_data=not args.ioc_only,
        print_summary=not args.no_summary,
    )
    result = run_scan(request)

    if result.exit_code == 1 and result.message:
        if result.has_issues:
            print(f"\n🚨 {result.message}!")
        elif not result.report_path and result.message != "No packages found to scan":
            print(result.message, file=sys.stderr)
    elif result.exit_code == 0:
        if result.message == "No packages found to scan":
            logging.getLogger(__name__).warning("⚠️  No packages found to scan")
        elif result.message:
            print(f"\n✅ {result.message}!")
    elif result.message:
        print(result.message, file=sys.stderr)

    return result.exit_code


if __name__ == "__main__":
    sys.exit(main())
