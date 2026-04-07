#!/usr/bin/env python3
"""
Run local end-to-end OreWatch integration checks against a prepared workspace.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
from contextlib import contextmanager
from typing import Dict, Iterable, List

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from monitor.api import monitor_api_request
from monitor.api import wait_for_api
from monitor.config import save_monitor_config
from monitor.integration_matrix import build_dependency_add_request
from monitor.integration_matrix import get_integration_cases
from monitor.service import MonitorService
from scripts.orewatch_client import OreWatchMCPClient


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@contextmanager
def _temporary_monitor_env(config_root: str, state_root: str):
    previous = {
        "OREWATCH_CONFIG_HOME": os.environ.get("OREWATCH_CONFIG_HOME"),
        "OREWATCH_STATE_HOME": os.environ.get("OREWATCH_STATE_HOME"),
    }
    os.environ["OREWATCH_CONFIG_HOME"] = config_root
    os.environ["OREWATCH_STATE_HOME"] = state_root
    try:
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _read_workspace(workspace_dir: str) -> Dict[str, object]:
    manifest_path = os.path.join(os.path.abspath(workspace_dir), "workspace.json")
    with open(manifest_path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _start_monitor(runtime_repo: str, env: Dict[str, str], verbose: bool) -> subprocess.Popen:
    return subprocess.Popen(
        [sys.executable, "malicious_package_scanner.py", "monitor", "run"],
        cwd=runtime_repo,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=None if verbose else subprocess.DEVNULL,
        stderr=None if verbose else subprocess.DEVNULL,
        start_new_session=True,
    )


def _stop_process(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def run_matrix(workspace_dir: str, clients: Iterable[str], verbose: bool = False) -> Dict[str, object]:
    workspace = _read_workspace(workspace_dir)
    runtime_repo = str(workspace["runtime_repo"])
    config_root = str(workspace["config_root"])
    state_root = str(workspace["state_root"])
    cases = {case.ecosystem: case for case in get_integration_cases()}

    with _temporary_monitor_env(config_root, state_root):
        service = MonitorService(runtime_repo)
        service.config["api"]["port"] = _find_free_port()
        save_monitor_config(service.config, runtime_repo)
        base_url = service.get_connection_info()["base_url"]
        token = service.api_token
        env = os.environ.copy()

        monitor_process = _start_monitor(runtime_repo, env, verbose=verbose)
        try:
            if not wait_for_api(str(base_url), token, timeout_ms=10000):
                raise RuntimeError("Monitor API did not become ready")

            api_results: Dict[str, Dict[str, object]] = {}
            for ecosystem, project_info in workspace["projects"].items():
                case = cases[ecosystem]
                project_path = project_info["project_dir"]
                safe_response = monitor_api_request(
                    str(base_url),
                    token,
                    "POST",
                    "/v1/check/dependency-add",
                    payload=build_dependency_add_request(case, project_path, "safe", "codex"),
                )
                malicious_response = monitor_api_request(
                    str(base_url),
                    token,
                    "POST",
                    "/v1/check/dependency-add",
                    payload=build_dependency_add_request(case, project_path, "malicious", "codex"),
                )
                api_results[ecosystem] = {
                    "safe_decision": safe_response["decision"],
                    "malicious_decision": malicious_response["decision"],
                }

            with OreWatchMCPClient(
                command=[sys.executable, "malicious_package_scanner.py", "monitor", "mcp"],
                cwd=runtime_repo,
                env=env,
                stderr=None if verbose else subprocess.DEVNULL,
            ) as mcp_client:
                expected_tools = {
                    "orewatch_health",
                    "orewatch_check_dependency_add",
                    "orewatch_check_manifest",
                    "orewatch_override_dependency_add",
                }
                missing_tools = sorted(expected_tools.difference(mcp_client.tools))
                if missing_tools:
                    raise RuntimeError(f"MCP server did not advertise expected tools: {', '.join(missing_tools)}")
                mcp_results: Dict[str, Dict[str, Dict[str, object]]] = {}
                for client in clients:
                    client_results: Dict[str, Dict[str, object]] = {}
                    for ecosystem, project_info in workspace["projects"].items():
                        case = cases[ecosystem]
                        project_path = project_info["project_dir"]
                        safe_result = mcp_client.call_tool(
                            "orewatch_check_dependency_add",
                            build_dependency_add_request(case, project_path, "safe", client),
                        )
                        bad_result = mcp_client.call_tool(
                            "orewatch_check_dependency_add",
                            build_dependency_add_request(case, project_path, "malicious", client),
                        )
                        client_results[ecosystem] = {
                            "safe_decision": safe_result["decision"],
                            "malicious_decision": bad_result["decision"],
                        }
                    mcp_results[client] = client_results
        finally:
            _stop_process(monitor_process)

    summary = {
        "workspace": os.path.abspath(workspace_dir),
        "base_url": base_url,
        "api_results": api_results,
        "mcp_results": mcp_results,
    }

    failures: List[str] = []
    for ecosystem, result in api_results.items():
        if result["safe_decision"] != "allow":
            failures.append(f"API safe check failed for {ecosystem}")
        if result["malicious_decision"] != "override_required":
            failures.append(f"API malicious check failed for {ecosystem}")
    for client, client_results in mcp_results.items():
        for ecosystem, result in client_results.items():
            if result["safe_decision"] != "allow":
                failures.append(f"MCP safe check failed for {client}/{ecosystem}")
            if result["malicious_decision"] != "override_required":
                failures.append(f"MCP malicious check failed for {client}/{ecosystem}")

    summary["failures"] = failures
    summary["success"] = not failures
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Run OreWatch local end-to-end integration checks")
    parser.add_argument("workspace_dir", help="Workspace created by setup_e2e_workspace.py")
    parser.add_argument(
        "--clients",
        default="claude_code,codex,cursor",
        help="Comma-separated client types to exercise through the MCP bridge",
    )
    parser.add_argument("--verbose", action="store_true", help="Show subprocess output")
    args = parser.parse_args()

    clients = [client.strip() for client in args.clients.split(",") if client.strip()]
    summary = run_matrix(args.workspace_dir, clients=clients, verbose=args.verbose)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
