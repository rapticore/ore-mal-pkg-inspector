#!/usr/bin/env python3
"""
Create an isolated OreWatch end-to-end testing workspace.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from monitor.integration_matrix import build_synthetic_final_data_dir
from monitor.integration_matrix import integration_case_summary
from monitor.integration_matrix import render_manual_client_checklist
from monitor.integration_matrix import write_project_fixtures


def _ignore_copy(_src, names):
    ignored = {
        ".git",
        ".env",
        ".venv",
        "env",
        "build",
        "dist",
        ".claude",
        ".idea",
        "__pycache__",
        "docs",
        "scan-output",
        "scripts",
        "tests",
        "orewatch.egg-info",
        "ore_mal_pkg_inspector.egg-info",
    }
    if os.path.basename(_src) == "collectors":
        ignored.update({"final-data", "raw-data"})
    return {name for name in names if name in ignored}


def create_workspace(output_dir: str, force: bool = False) -> dict:
    output_dir = os.path.abspath(output_dir)
    if os.path.exists(output_dir):
        if not force:
            raise FileExistsError(f"Workspace already exists: {output_dir}")
        shutil.rmtree(output_dir)
    os.makedirs(output_dir, exist_ok=True)

    runtime_repo = os.path.join(output_dir, "orewatch-runtime")
    projects_root = os.path.join(output_dir, "projects")
    config_root = os.path.join(output_dir, "config-home")
    state_root = os.path.join(output_dir, "state-home")

    shutil.copytree(REPO_ROOT, runtime_repo, ignore=_ignore_copy, dirs_exist_ok=True)
    build_synthetic_final_data_dir(os.path.join(runtime_repo, "collectors", "final-data"))
    projects = write_project_fixtures(projects_root)

    checklist_path = os.path.join(output_dir, "client-checklist.md")
    with open(checklist_path, "w", encoding="utf-8") as handle:
        handle.write(render_manual_client_checklist(runtime_repo, projects_root))

    manifest = {
        "workspace": output_dir,
        "runtime_repo": runtime_repo,
        "projects_root": projects_root,
        "config_root": config_root,
        "state_root": state_root,
        "checklist_path": checklist_path,
        "monitor_command": (
            f"OREWATCH_CONFIG_HOME={config_root} "
            f"OREWATCH_STATE_HOME={state_root} "
            f"python3 {os.path.join(runtime_repo, 'malicious_package_scanner.py')} monitor run"
        ),
        "mcp_command": (
            f"OREWATCH_CONFIG_HOME={config_root} "
            f"OREWATCH_STATE_HOME={state_root} "
            f"python3 {os.path.join(runtime_repo, 'malicious_package_scanner.py')} monitor mcp"
        ),
        "projects": projects,
        "cases": integration_case_summary(),
    }
    manifest_path = os.path.join(output_dir, "workspace.json")
    with open(manifest_path, "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)
    manifest["manifest_path"] = manifest_path
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description="Create an OreWatch E2E workspace")
    parser.add_argument("output_dir", help="Directory to create the workspace in")
    parser.add_argument("--force", action="store_true", help="Overwrite an existing workspace")
    args = parser.parse_args()

    manifest = create_workspace(args.output_dir, force=args.force)
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
