#!/usr/bin/env python3
"""
CLI for the local background monitor.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List

from monitor.config import get_repo_root
from monitor.service import MonitorService
from monitor.snapshot_updater import build_snapshot
from monitor.snapshot_updater import generate_keypair
from monitor.snapshot_updater import publish_snapshot


def _build_watch_policy(args) -> dict:
    policy = {}
    if getattr(args, "severity_threshold", None):
        policy["severity_threshold"] = args.severity_threshold
    if getattr(args, "strict_data", False):
        policy["strict_data"] = True
    if getattr(args, "include_experimental_sources", False):
        policy["include_experimental_sources"] = True
    if getattr(args, "notify_on", None):
        policy["notify_on"] = args.notify_on
    return policy


def build_monitor_parser() -> argparse.ArgumentParser:
    """Build the monitor subcommand parser."""
    parser = argparse.ArgumentParser(prog="malicious_package_scanner.py monitor")
    subparsers = parser.add_subparsers(dest="command", required=True)

    install_parser = subparsers.add_parser("install", help="Initialize local monitor files and install a user service")
    install_parser.add_argument(
        "--service-manager",
        choices=["auto", "launchd", "systemd", "background"],
        default="auto",
        help="Service manager to install (default: auto-detect)",
    )
    install_parser.add_argument(
        "--no-start",
        action="store_true",
        help="Install the service definition without starting it immediately",
    )
    subparsers.add_parser("start", help="Start the monitor in the background")
    run_parser = subparsers.add_parser("run", help="Run the monitor in the foreground")
    run_parser.add_argument("--max-loops", type=int, default=None, help=argparse.SUPPRESS)
    subparsers.add_parser("stop", help="Stop the background monitor")
    subparsers.add_parser("restart", help="Restart the installed monitor service")
    uninstall_parser = subparsers.add_parser("uninstall", help="Remove the installed monitor service")
    uninstall_parser.add_argument(
        "--service-manager",
        choices=["auto", "launchd", "systemd", "background"],
        default="auto",
        help="Service manager to uninstall (default: installed manager)",
    )
    subparsers.add_parser("status", help="Show monitor status")
    subparsers.add_parser("doctor", help="Show detailed monitor diagnostics")

    watch_parser = subparsers.add_parser("watch", help="Manage watched projects")
    watch_subparsers = watch_parser.add_subparsers(dest="watch_command", required=True)
    watch_add = watch_subparsers.add_parser("add", help="Add a watched project")
    watch_add.add_argument("path", help="Project directory to watch")
    watch_add.add_argument(
        "--severity-threshold",
        choices=["low", "medium", "high", "critical"],
        help="Minimum severity to track and notify",
    )
    watch_add.add_argument(
        "--strict-data",
        action="store_true",
        help="Fail scans for this project when threat data is partial or missing",
    )
    watch_add.add_argument(
        "--include-experimental-sources",
        action="store_true",
        help="Allow experimental threat-data sources for this project",
    )
    watch_add.add_argument(
        "--notify-on",
        nargs="+",
        choices=["malicious_package", "ioc"],
        help="Finding classes to notify on",
    )

    watch_remove = watch_subparsers.add_parser("remove", help="Remove a watched project")
    watch_remove.add_argument("path", help="Project directory to stop watching")
    watch_subparsers.add_parser("list", help="List watched projects")

    scan_now = subparsers.add_parser("scan-now", help="Run an immediate monitor scan")
    scan_now.add_argument("path", nargs="?", help="Specific watched project path")
    scan_now.add_argument(
        "--quick",
        action="store_true",
        help="Run a package-only quick scan instead of a full scan",
    )

    snapshot_parser = subparsers.add_parser("snapshot", help="Manage threat-data snapshots")
    snapshot_subparsers = snapshot_parser.add_subparsers(dest="snapshot_command", required=True)
    snapshot_keygen = snapshot_subparsers.add_parser("keygen", help="Generate a snapshot signing keypair")
    snapshot_keygen.add_argument("output_dir", help="Directory to write the PEM keypair into")
    snapshot_build = snapshot_subparsers.add_parser("build", help="Build a local snapshot")
    snapshot_build.add_argument("output_dir", help="Output directory for snapshot artifacts")
    snapshot_build.add_argument(
        "--private-key",
        default="",
        help="PEM private key used to sign the snapshot manifest",
    )
    snapshot_build.add_argument(
        "--public-key",
        default="",
        help="PEM public key paired with the signing private key",
    )
    snapshot_apply = snapshot_subparsers.add_parser("apply", help="Apply a snapshot manifest")
    snapshot_apply.add_argument("manifest", help="Manifest file path or URL")
    snapshot_apply.add_argument(
        "--public-key",
        default="",
        help="PEM public key used to verify the signed manifest or channel",
    )
    snapshot_publish = snapshot_subparsers.add_parser(
        "publish",
        help="Publish a static-hosting-friendly snapshot channel",
    )
    snapshot_publish.add_argument("output_dir", help="Output directory for published snapshot assets")
    snapshot_publish.add_argument(
        "--base-url",
        required=True,
        help="Public base URL that will host the published snapshot assets",
    )
    snapshot_publish.add_argument(
        "--channel",
        default="stable",
        help="Channel name to publish (default: stable)",
    )
    snapshot_publish.add_argument(
        "--private-key",
        default="",
        help="PEM private key used to sign the channel and manifest",
    )
    snapshot_publish.add_argument(
        "--public-key",
        default="",
        help="PEM public key paired with the signing private key",
    )

    return parser


def run_monitor_cli(argv: List[str]) -> int:
    """Execute the monitor CLI."""
    parser = build_monitor_parser()
    args = parser.parse_args(argv)
    service = MonitorService(get_repo_root())

    if args.command == "install":
        info = service.install(
            service_manager=args.service_manager,
            auto_start=not args.no_start,
        )
        print("Monitor initialized")
        print(json.dumps(info, indent=2))
        return 0 if info.get("success", True) else 1

    if args.command == "start":
        result = service.start()
        print(result["message"])
        return 0 if result.get("success") else 1

    if args.command == "run":
        service.install(service_manager="background", auto_start=False)
        service.run_forever(max_loops=args.max_loops)
        return 0

    if args.command == "stop":
        result = service.stop()
        print(result["message"])
        return 0 if result.get("success") else 1

    if args.command == "restart":
        result = service.restart()
        print(result["message"])
        return 0 if result.get("success") else 1

    if args.command == "uninstall":
        result = service.uninstall(service_manager=None if args.service_manager == "auto" else args.service_manager)
        print(result["message"])
        return 0 if result.get("success") else 1

    if args.command == "status":
        print(json.dumps(service.get_status(), indent=2))
        return 0

    if args.command == "doctor":
        print(json.dumps(service.doctor(), indent=2))
        return 0

    if args.command == "watch":
        if args.watch_command == "add":
            path = os.path.abspath(args.path)
            if not os.path.isdir(path):
                print(f"Project path not found or not a directory: {path}", file=sys.stderr)
                return 1
            service.state.add_watched_project(path, _build_watch_policy(args))
            service.state.replace_observed_files(path, {})
            print(f"Watching {path}")
            return 0

        if args.watch_command == "remove":
            path = os.path.abspath(args.path)
            service.state.remove_watched_project(path)
            print(f"Stopped watching {path}")
            return 0

        if args.watch_command == "list":
            print(json.dumps(service.state.list_watched_projects(), indent=2))
            return 0

    if args.command == "scan-now":
        results = service.scan_now(args.path, full=not args.quick)
        print(json.dumps(results, indent=2))
        if not results:
            return 1 if args.path else 0
        return max(result["exit_code"] for result in results)

    if args.command == "snapshot":
        if args.snapshot_command == "keygen":
            result = generate_keypair(os.path.abspath(args.output_dir))
            print(json.dumps(result, indent=2))
            return 0

        if args.snapshot_command == "build":
            source_db_dir = os.path.join(get_repo_root(), "collectors", "final-data")
            manifest_path = build_snapshot(
                source_db_dir,
                os.path.abspath(args.output_dir),
                private_key_path=args.private_key or None,
                public_key_path=args.public_key or None,
            )
            print(manifest_path)
            return 0

        if args.snapshot_command == "apply":
            result = service.updater.apply_snapshot(
                args.manifest,
                public_key_path=args.public_key or service.config.get("snapshots", {}).get("public_key_path", ""),
            )
            print(json.dumps(result, indent=2))
            return 0 if result.get("success") else 1

        if args.snapshot_command == "publish":
            source_db_dir = os.path.join(get_repo_root(), "collectors", "final-data")
            result = publish_snapshot(
                source_db_dir,
                os.path.abspath(args.output_dir),
                base_url=args.base_url,
                channel=args.channel,
                private_key_path=args.private_key or None,
                public_key_path=args.public_key or None,
            )
            print(json.dumps(result, indent=2))
            return 0

    parser.error("Unknown monitor command")
    return 1
