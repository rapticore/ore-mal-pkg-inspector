#!/usr/bin/env python3
"""
CLI for the local background monitor.
"""

from __future__ import annotations

import argparse
from collections import deque
import json
import os
import sys
from typing import Dict, List

from monitor.ide_bootstrap import ALL_BOOTSTRAP_CLIENTS
from monitor.ide_bootstrap import build_connection_hints
from monitor.ide_bootstrap import build_ide_bootstrap
from monitor.menubar import launch_menubar_app_detached
from monitor.menubar import run_menubar_app
from monitor.mcp_adapter import run_mcp_adapter
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


def _add_workspace_root_args(parser: argparse.ArgumentParser) -> None:
    """Accept a deprecated compatibility workspace root before or after a subcommand."""
    parser.add_argument(
        "--workspace-root",
        dest="workspace_root",
        default=argparse.SUPPRESS,
        help="Deprecated compatibility workspace root; the monitor itself is now per-user singleton-scoped",
    )
    parser.add_argument(
        "--project-root",
        dest="workspace_root",
        default=argparse.SUPPRESS,
        help=argparse.SUPPRESS,
    )


def _resolve_monitor_workspace_root(args) -> str:
    """Resolve a compatibility workspace root for legacy output fields."""
    explicit = getattr(args, "workspace_root", None)
    if explicit:
        return os.path.abspath(explicit)
    if getattr(args, "command", None) == "quickstart":
        target = getattr(args, "path", ".") or "."
        return os.path.abspath(target)
    return os.path.abspath(os.getcwd())


def _print_install_summary(info: Dict[str, object], connection_info: Dict[str, object]) -> None:
    print("OreWatch monitor installed")
    print(f"Service manager: {info.get('service_manager', 'unknown')}")
    print(f"Status: {info.get('message', 'Ready')}")
    print(f"Monitor scope: {connection_info['monitor_scope']}")
    print(f"Monitor home: {connection_info['monitor_home']}")
    print(f"API: {connection_info['base_url']}")
    print(f"Token: {connection_info['token_path']}")
    print(f"Config: {info.get('config')}")
    print(f"State DB: {info.get('state_db')}")
    print("")
    print("Next steps:")
    print("  orewatch monitor watch add /path/to/project")
    print("  orewatch monitor ide-bootstrap --client claude_code")


def _add_watched_project(service: MonitorService, project_path: str, policy: Dict[str, object]) -> str:
    normalized_path = os.path.abspath(project_path)
    if not os.path.isdir(normalized_path):
        raise FileNotFoundError(normalized_path)
    service.add_watched_project(normalized_path, policy, initial_scan_kind=None)
    return normalized_path


def _print_quickstart_summary(
    info: Dict[str, object],
    connection_info: Dict[str, object],
    watched_path: str,
    client: str,
) -> None:
    print("OreWatch quickstart complete")
    print(f"Project: {watched_path}")
    print(f"Monitor scope: {connection_info['monitor_scope']}")
    print(f"Monitor home: {connection_info['monitor_home']}")
    print(f"Service manager: {info.get('service_manager', 'unknown')}")
    print(f"Status: {info.get('message', 'Ready')}")
    print(f"API: {connection_info['base_url']}")
    print(f"Token: {connection_info['token_path']}")
    print("")
    print("What happened:")
    print("  1. Installed or refreshed the local OreWatch monitor")
    print(f"  2. Started watching {watched_path}")
    print("  3. Prepared IDE bootstrap config")
    print("")
    print("Recommended next step:")
    if client == "all":
        print("  Copy the bootstrap block for your IDE from the output below")
    else:
        print(f"  Copy the {client} bootstrap block from the output below")
    print("")


def _render_bootstrap_text(connection_info: Dict[str, object], client: str) -> str:
    hints = build_connection_hints(connection_info)
    bootstrap = build_ide_bootstrap(connection_info)
    selected_clients = ALL_BOOTSTRAP_CLIENTS if client == "all" else (client,)
    lines = [
        "OreWatch IDE bootstrap",
        f"Monitor scope: {connection_info['monitor_scope']}",
        f"Monitor home: {connection_info['monitor_home']}",
        f"API base URL: {connection_info['base_url']}",
        f"API token: {connection_info['token_path']}",
        f"MCP command: {hints['mcp_command_preview']}",
        "",
    ]
    for selected in selected_clients:
        entry = bootstrap[selected]
        lines.append(f"[{entry['label']}]")
        lines.append(entry["snippet"])
        for note in entry["notes"]:
            lines.append(f"- {note}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _print_bootstrap(connection_info: Dict[str, object], client: str, json_output: bool) -> None:
    if json_output:
        bootstrap = build_ide_bootstrap(connection_info)
        if client == "all":
            print(json.dumps(bootstrap, indent=2))
            return
        print(json.dumps(bootstrap[client], indent=2))
        return
    print(_render_bootstrap_text(connection_info, client), end="")


def _render_findings_text(payload: Dict[str, object]) -> str:
    findings = payload.get("findings", [])
    if not findings:
        return "No active findings.\n"

    lines = [
        f"Active findings: {payload.get('count', len(findings))}",
    ]
    if payload.get("highest_severity"):
        lines.append(f"Highest severity: {payload['highest_severity']}")
    if payload.get("project_path"):
        lines.append(f"Project: {payload['project_path']}")
    if payload.get("min_severity"):
        lines.append(f"Minimum severity: {payload['min_severity']}")
    lines.append("")
    for finding in findings:
        lines.append(f"[{finding['severity'].upper()}] {finding['title']}")
        lines.append(f"Project: {finding['project_path']}")
        lines.append(f"First seen: {finding['first_seen_at']}")
        lines.append(f"Last seen: {finding['last_seen_at']}")
        if finding.get("report_path"):
            lines.append(f"Report: {finding['report_path']}")
        if (
            finding.get("json_report_path")
            and finding.get("json_report_path") != finding.get("report_path")
        ):
            lines.append(f"JSON: {finding['json_report_path']}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _render_notifications_text(payload: Dict[str, object]) -> str:
    notifications = payload.get("notifications", [])
    if not notifications:
        return "No recent notifications.\n"

    lines = [f"Recent notifications: {payload.get('count', len(notifications))}"]
    if payload.get("project_path"):
        lines.append(f"Project: {payload['project_path']}")
    lines.append("")
    for notification in notifications:
        lines.append(
            f"{notification['created_at']} [{notification['kind']}] {notification['message']}"
        )
    return "\n".join(lines).rstrip() + "\n"


def _render_monitor_log_text(log_path: str, lines: int) -> str:
    if not os.path.exists(log_path):
        return f"Monitor log not found: {log_path}\n"

    max_lines = max(int(lines), 1)
    tail_lines = deque(maxlen=max_lines)
    with open(log_path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            tail_lines.append(line.rstrip("\n"))

    if not tail_lines:
        return f"Monitor log is empty: {log_path}\n"

    header = [
        f"Monitor log: {log_path}",
        f"Showing last {len(tail_lines)} line(s)",
        "",
    ]
    return "\n".join(header + list(tail_lines)).rstrip() + "\n"


def build_monitor_parser() -> argparse.ArgumentParser:
    """Build the monitor subcommand parser."""
    parser = argparse.ArgumentParser(prog="malicious_package_scanner.py monitor")
    _add_workspace_root_args(parser)
    subparsers = parser.add_subparsers(dest="command", required=True)

    install_parser = subparsers.add_parser("install", help="Initialize local monitor files and install a user service")
    _add_workspace_root_args(install_parser)
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
    install_parser.add_argument(
        "--ide-bootstrap",
        action="store_true",
        help="Print copy-paste IDE and MCP bootstrap snippets after install",
    )
    install_parser.add_argument(
        "--json",
        action="store_true",
        help="Print raw install metadata as JSON",
    )
    quickstart_parser = subparsers.add_parser(
        "quickstart",
        help="Install the monitor, watch a project, and print IDE bootstrap guidance",
    )
    _add_workspace_root_args(quickstart_parser)
    quickstart_parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Project directory to watch (default: current directory)",
    )
    quickstart_parser.add_argument(
        "--client",
        choices=("all", *ALL_BOOTSTRAP_CLIENTS),
        default="all",
        help="IDE or agent bootstrap to print (default: all)",
    )
    quickstart_parser.add_argument(
        "--service-manager",
        choices=["auto", "launchd", "systemd", "background"],
        default="auto",
        help="Service manager to install (default: auto-detect)",
    )
    quickstart_parser.add_argument(
        "--no-start",
        action="store_true",
        help="Install the service definition without starting it immediately",
    )
    quickstart_parser.add_argument(
        "--severity-threshold",
        choices=["low", "medium", "high", "critical"],
        help="Minimum severity to track and notify for the watched project",
    )
    quickstart_parser.add_argument(
        "--strict-data",
        action="store_true",
        help="Fail scans for this project when threat data is partial or missing",
    )
    quickstart_parser.add_argument(
        "--include-experimental-sources",
        action="store_true",
        help="Allow experimental threat-data sources for this project",
    )
    quickstart_parser.add_argument(
        "--notify-on",
        nargs="+",
        choices=["malicious_package", "ioc"],
        help="Finding classes to notify on",
    )
    quickstart_parser.add_argument(
        "--json",
        action="store_true",
        help="Print raw quickstart metadata as JSON",
    )
    start_parser = subparsers.add_parser("start", help="Start the monitor in the background")
    _add_workspace_root_args(start_parser)
    run_parser = subparsers.add_parser("run", help="Run the monitor in the foreground")
    _add_workspace_root_args(run_parser)
    run_parser.add_argument("--max-loops", type=int, default=None, help=argparse.SUPPRESS)
    stop_parser = subparsers.add_parser("stop", help="Stop the background monitor")
    _add_workspace_root_args(stop_parser)
    restart_parser = subparsers.add_parser("restart", help="Restart the installed monitor service")
    _add_workspace_root_args(restart_parser)
    uninstall_parser = subparsers.add_parser("uninstall", help="Remove the installed monitor service")
    _add_workspace_root_args(uninstall_parser)
    uninstall_parser.add_argument(
        "--service-manager",
        choices=["auto", "launchd", "systemd", "background"],
        default="auto",
        help="Service manager to uninstall (default: installed manager)",
    )
    connection_info_parser = subparsers.add_parser("connection-info", help="Show local API connection info for IDE and agent clients")
    _add_workspace_root_args(connection_info_parser)
    ide_bootstrap = subparsers.add_parser("ide-bootstrap", help="Print IDE and agent bootstrap snippets")
    _add_workspace_root_args(ide_bootstrap)
    ide_bootstrap.add_argument(
        "--client",
        choices=("all", *ALL_BOOTSTRAP_CLIENTS),
        default="all",
        help="Client bootstrap to print (default: all)",
    )
    ide_bootstrap.add_argument(
        "--json",
        action="store_true",
        help="Print bootstrap output as JSON",
    )
    mcp_parser = subparsers.add_parser(
        "mcp",
        help="Run the OreWatch MCP adapter over stdio and auto-start the local monitor if needed",
    )
    _add_workspace_root_args(mcp_parser)
    menubar_parser = subparsers.add_parser(
        "menubar",
        help="Run the native macOS OreWatch menu bar app",
    )
    _add_workspace_root_args(menubar_parser)
    menubar_parser.add_argument(
        "--refresh-seconds",
        type=float,
        default=15.0,
        help="Refresh the menu bar state every N seconds (default: 15)",
    )
    menubar_parser.add_argument(
        "--foreground",
        action="store_true",
        help="Keep the menu bar app attached to the terminal instead of relaunching it in the background",
    )
    status_parser = subparsers.add_parser("status", help="Show monitor status")
    _add_workspace_root_args(status_parser)
    doctor_parser = subparsers.add_parser("doctor", help="Show detailed monitor diagnostics")
    _add_workspace_root_args(doctor_parser)
    findings_parser = subparsers.add_parser("findings", help="List active monitored findings")
    _add_workspace_root_args(findings_parser)
    findings_parser.add_argument("--project", help="Filter findings to one watched project path")
    findings_parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Maximum findings to return (default: 20)",
    )
    findings_parser.add_argument(
        "--min-severity",
        choices=["low", "medium", "high", "critical"],
        help="Only show findings at or above this severity",
    )
    findings_parser.add_argument(
        "--json",
        action="store_true",
        help="Print findings as JSON",
    )
    notifications_parser = subparsers.add_parser(
        "notifications",
        help="List recent monitor notifications",
    )
    _add_workspace_root_args(notifications_parser)
    notifications_parser.add_argument("--project", help="Filter notifications to one watched project path")
    notifications_parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Maximum notifications to return (default: 20)",
    )
    notifications_parser.add_argument(
        "--json",
        action="store_true",
        help="Print notifications as JSON",
    )
    log_parser = subparsers.add_parser("log", help="Show recent monitor log lines")
    _add_workspace_root_args(log_parser)
    log_parser.add_argument(
        "--lines",
        type=int,
        default=100,
        help="Maximum log lines to print from the end of the monitor log (default: 100)",
    )
    clear_alerts_parser = subparsers.add_parser(
        "clear-alerts",
        help="Mark current alert notifications as reviewed without deleting history",
    )
    _add_workspace_root_args(clear_alerts_parser)
    clear_alerts_parser.add_argument(
        "--json",
        action="store_true",
        help="Print the result as JSON",
    )

    watch_parser = subparsers.add_parser("watch", help="Manage watched projects")
    _add_workspace_root_args(watch_parser)
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
    _add_workspace_root_args(scan_now)
    scan_now.add_argument("path", nargs="?", help="Specific watched project path")
    scan_now.add_argument(
        "--quick",
        action="store_true",
        help="Run a package-only quick scan instead of a full scan",
    )

    snapshot_parser = subparsers.add_parser("snapshot", help="Manage threat-data snapshots")
    _add_workspace_root_args(snapshot_parser)
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
    service = MonitorService(_resolve_monitor_workspace_root(args))

    if args.command == "install":
        info = service.install(
            service_manager=args.service_manager,
            auto_start=not args.no_start,
        )
        connection_info = service.get_connection_info()
        if args.json:
            payload = dict(info)
            payload["connection_info"] = connection_info
            print(json.dumps(payload, indent=2))
        else:
            _print_install_summary(info, connection_info)
            if args.ide_bootstrap:
                print("")
                _print_bootstrap(connection_info, "all", json_output=False)
        return 0 if info.get("success", True) else 1

    if args.command == "quickstart":
        info = service.install(
            service_manager=args.service_manager,
            auto_start=not args.no_start,
        )
        if not info.get("success", True):
            if args.json:
                print(json.dumps(info, indent=2))
            else:
                print(info.get("message", "Monitor install failed"), file=sys.stderr)
            return 1
        try:
            watched_path = _add_watched_project(service, args.path, _build_watch_policy(args))
        except FileNotFoundError:
            print(
                f"Project path not found or not a directory: {os.path.abspath(args.path)}",
                file=sys.stderr,
            )
            return 1
        connection_info = service.get_connection_info()
        if args.json:
            print(
                json.dumps(
                    {
                        "install": info,
                        "watched_path": watched_path,
                        "connection_info": connection_info,
                        "bootstrap": build_ide_bootstrap(connection_info)
                        if args.client == "all"
                        else build_ide_bootstrap(connection_info)[args.client],
                    },
                    indent=2,
                )
            )
        else:
            _print_quickstart_summary(info, connection_info, watched_path, args.client)
            _print_bootstrap(connection_info, args.client, json_output=False)
        return 0

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

    if args.command == "connection-info":
        print(json.dumps(service.get_connection_info(), indent=2))
        return 0

    if args.command == "ide-bootstrap":
        _print_bootstrap(service.get_connection_info(), args.client, args.json)
        return 0

    if args.command == "mcp":
        return run_mcp_adapter(service)

    if args.command == "menubar":
        if not args.foreground and sys.platform == "darwin":
            result = launch_menubar_app_detached(
                refresh_seconds=args.refresh_seconds,
                workspace_root=getattr(args, "workspace_root", None),
            )
            print(result["message"])
            return 0 if result.get("success", True) else 1
        return run_menubar_app(service, refresh_seconds=args.refresh_seconds)

    if args.command == "doctor":
        print(json.dumps(service.doctor(), indent=2))
        return 0

    if args.command == "findings":
        findings = service.list_active_findings(
            project_path=args.project,
            limit=args.limit,
            min_severity=args.min_severity,
        )
        if args.json:
            print(json.dumps(findings, indent=2))
        else:
            print(_render_findings_text(findings), end="")
        return 0

    if args.command == "notifications":
        notifications = service.list_recent_notifications(
            project_path=args.project,
            limit=args.limit,
        )
        if args.json:
            print(json.dumps(notifications, indent=2))
        else:
            print(_render_notifications_text(notifications), end="")
        return 0

    if args.command == "log":
        print(_render_monitor_log_text(service.paths["log_file"], args.lines), end="")
        return 0

    if args.command == "clear-alerts":
        result = service.mark_alerts_reviewed()
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(result["message"])
        return 0 if result.get("success", True) else 1

    if args.command == "watch":
        if args.watch_command == "add":
            try:
                path = _add_watched_project(service, args.path, _build_watch_policy(args))
            except FileNotFoundError:
                path = os.path.abspath(args.path)
                print(f"Project path not found or not a directory: {path}", file=sys.stderr)
                return 1
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
            source_db_dir = service.paths["final_data_dir"]
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
            source_db_dir = service.paths["final_data_dir"]
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
