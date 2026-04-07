#!/usr/bin/env python3
"""
Shared synthetic fixtures for client integration and end-to-end testing.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from typing import Dict, List

from collectors import db as collector_db


TIMESTAMP = "2026-04-02T00:00:00Z"
FIXTURE_SOURCE = "synthetic-e2e-fixture"


@dataclass(frozen=True)
class IntegrationCase:
    ecosystem: str
    package_manager: str
    project_dir: str
    manifest_filename: str
    command_template: str
    safe_dependency: Dict[str, object]
    malicious_dependency: Dict[str, object]
    unresolved_dependency: Dict[str, object]
    baseline_manifest: str


INTEGRATION_CASES: List[IntegrationCase] = [
    IntegrationCase(
        ecosystem="npm",
        package_manager="npm",
        project_dir="npm-demo",
        manifest_filename="package.json",
        command_template="npm install {name}@{version}",
        safe_dependency={
            "name": "orewatch-good-npm",
            "requested_spec": "2.0.0",
            "resolved_version": "2.0.0",
            "dev_dependency": False,
        },
        malicious_dependency={
            "name": "orewatch-bad-npm",
            "requested_spec": "1.0.0",
            "resolved_version": "1.0.0",
            "dev_dependency": False,
        },
        unresolved_dependency={
            "name": "orewatch-range-npm",
            "requested_spec": "^1.0.0",
            "resolved_version": "",
            "dev_dependency": False,
        },
        baseline_manifest=json.dumps(
            {
                "name": "orewatch-npm-demo",
                "version": "0.1.0",
                "private": True,
                "dependencies": {},
            },
            indent=2,
        )
        + "\n",
    ),
    IntegrationCase(
        ecosystem="pypi",
        package_manager="pip",
        project_dir="pypi-demo",
        manifest_filename="requirements.txt",
        command_template="pip install {name}=={version}",
        safe_dependency={
            "name": "orewatch-good-pypi",
            "requested_spec": "==2.0.0",
            "resolved_version": "2.0.0",
            "dev_dependency": False,
        },
        malicious_dependency={
            "name": "orewatch-bad-pypi",
            "requested_spec": "==1.0.0",
            "resolved_version": "1.0.0",
            "dev_dependency": False,
        },
        unresolved_dependency={
            "name": "orewatch-range-pypi",
            "requested_spec": ">=1.0.0",
            "resolved_version": "",
            "dev_dependency": False,
        },
        baseline_manifest="# OreWatch PyPI demo\n",
    ),
    IntegrationCase(
        ecosystem="maven",
        package_manager="maven",
        project_dir="maven-demo",
        manifest_filename="pom.xml",
        command_template="mvn dependency:get -Dartifact={name}:{version}",
        safe_dependency={
            "name": "com.orewatch:good-maven",
            "requested_spec": "2.0.0",
            "resolved_version": "2.0.0",
            "dev_dependency": False,
        },
        malicious_dependency={
            "name": "com.orewatch:bad-maven",
            "requested_spec": "1.0.0",
            "resolved_version": "1.0.0",
            "dev_dependency": False,
        },
        unresolved_dependency={
            "name": "com.orewatch:range-maven",
            "requested_spec": "[1.0.0,)",
            "resolved_version": "",
            "dev_dependency": False,
        },
        baseline_manifest="""<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.orewatch</groupId>
  <artifactId>maven-demo</artifactId>
  <version>0.1.0</version>
  <dependencies>
  </dependencies>
</project>
""",
    ),
    IntegrationCase(
        ecosystem="rubygems",
        package_manager="bundler",
        project_dir="rubygems-demo",
        manifest_filename="Gemfile",
        command_template="bundle add {name} --version {version}",
        safe_dependency={
            "name": "orewatch-good-ruby",
            "requested_spec": "2.0.0",
            "resolved_version": "2.0.0",
            "dev_dependency": False,
        },
        malicious_dependency={
            "name": "orewatch-bad-ruby",
            "requested_spec": "1.0.0",
            "resolved_version": "1.0.0",
            "dev_dependency": False,
        },
        unresolved_dependency={
            "name": "orewatch-range-ruby",
            "requested_spec": "~> 1.0.0",
            "resolved_version": "",
            "dev_dependency": False,
        },
        baseline_manifest='source "https://rubygems.org"\n\n',
    ),
    IntegrationCase(
        ecosystem="go",
        package_manager="go",
        project_dir="go-demo",
        manifest_filename="go.mod",
        command_template="go get {name}@{version}",
        safe_dependency={
            "name": "example.com/orewatch/good-go",
            "requested_spec": "v2.0.0",
            "resolved_version": "v2.0.0",
            "dev_dependency": False,
        },
        malicious_dependency={
            "name": "example.com/orewatch/bad-go",
            "requested_spec": "v1.0.0",
            "resolved_version": "v1.0.0",
            "dev_dependency": False,
        },
        unresolved_dependency={
            "name": "example.com/orewatch/range-go",
            "requested_spec": "latest",
            "resolved_version": "",
            "dev_dependency": False,
        },
        baseline_manifest="""module example.com/orewatch/go-demo

go 1.23.0
""",
    ),
    IntegrationCase(
        ecosystem="cargo",
        package_manager="cargo",
        project_dir="cargo-demo",
        manifest_filename="Cargo.toml",
        command_template="cargo add {name}@{version}",
        safe_dependency={
            "name": "orewatch-good-cargo",
            "requested_spec": "2.0.0",
            "resolved_version": "2.0.0",
            "dev_dependency": False,
        },
        malicious_dependency={
            "name": "orewatch-bad-cargo",
            "requested_spec": "1.0.0",
            "resolved_version": "1.0.0",
            "dev_dependency": False,
        },
        unresolved_dependency={
            "name": "orewatch-range-cargo",
            "requested_spec": "^1.0.0",
            "resolved_version": "",
            "dev_dependency": False,
        },
        baseline_manifest="""[package]
name = "orewatch-cargo-demo"
version = "0.1.0"
edition = "2021"

[dependencies]
""",
    ),
]


def get_integration_cases() -> List[IntegrationCase]:
    """Return the ordered cross-ecosystem integration cases."""
    return list(INTEGRATION_CASES)


def _fixture_package(case: IntegrationCase) -> Dict[str, object]:
    dependency = case.malicious_dependency
    version = str(dependency["resolved_version"] or dependency["requested_spec"]).lstrip("=")
    return {
        "name": str(dependency["name"]),
        "versions": [version],
        "sources": [FIXTURE_SOURCE],
        "severity": "critical",
        "description": f"Synthetic compromised dependency for {case.ecosystem} integration testing",
        "detected_behaviors": ["synthetic_fixture", "integration_test"],
    }


def build_synthetic_final_data_dir(final_data_dir: str) -> Dict[str, str]:
    """Build a complete per-ecosystem SQLite fixture set for integration testing."""
    os.makedirs(final_data_dir, exist_ok=True)
    created: Dict[str, str] = {}
    for case in INTEGRATION_CASES:
        db_path = os.path.join(final_data_dir, f"unified_{case.ecosystem}.db")
        if os.path.exists(db_path):
            os.remove(db_path)
        conn, temp_db_path = collector_db.create_database(db_path)
        packages = [_fixture_package(case)]
        collector_db.insert_packages(conn, packages)
        collector_db.insert_metadata(
            conn,
            ecosystem=case.ecosystem,
            packages=packages,
            timestamp=TIMESTAMP,
            extra_metadata={
                "data_status": "complete",
                "sources_used": [FIXTURE_SOURCE],
                "experimental_sources_used": [],
                "last_successful_collect": TIMESTAMP,
            },
        )
        collector_db.finalize_database(conn, temp_db_path, db_path)
        created[case.ecosystem] = db_path
    return created


def write_project_fixtures(projects_root: str) -> Dict[str, Dict[str, str]]:
    """Write one minimal test project per supported ecosystem."""
    manifest_map: Dict[str, Dict[str, str]] = {}
    os.makedirs(projects_root, exist_ok=True)
    for case in INTEGRATION_CASES:
        project_dir = os.path.join(projects_root, case.project_dir)
        os.makedirs(project_dir, exist_ok=True)
        manifest_path = os.path.join(project_dir, case.manifest_filename)
        with open(manifest_path, "w", encoding="utf-8") as handle:
            handle.write(case.baseline_manifest)
        manifest_map[case.ecosystem] = {
            "project_dir": project_dir,
            "manifest_path": manifest_path,
        }
    return manifest_map


def build_dependency_add_request(
    case: IntegrationCase,
    project_path: str,
    dependency_kind: str,
    client_type: str,
) -> Dict[str, object]:
    """Build a preflight dependency-add request payload."""
    dependency = getattr(case, f"{dependency_kind}_dependency")
    version = str(dependency["resolved_version"] or dependency["requested_spec"]).replace("==", "")
    return {
        "client_type": client_type,
        "project_path": project_path,
        "ecosystem": case.ecosystem,
        "package_manager": case.package_manager,
        "operation": "add",
        "dependencies": [dict(dependency)],
        "source": {
            "kind": "agent_command",
            "command": case.command_template.format(name=dependency["name"], version=version),
        },
    }


def build_manifest_check_request(
    case: IntegrationCase,
    project_path: str,
    manifest_path: str,
    dependency_kind: str,
    client_type: str,
) -> Dict[str, object]:
    """Build a manifest-check request payload."""
    dependency = getattr(case, f"{dependency_kind}_dependency")
    return {
        "client_type": client_type,
        "project_path": project_path,
        "ecosystem": case.ecosystem,
        "manifest_path": manifest_path,
        "dependencies": [dict(dependency)],
    }


def render_manual_client_checklist(runtime_repo_root: str, projects_root: str) -> str:
    """Render a Markdown checklist for manual Claude/Codex/Cursor validation."""
    lines = [
        "# OreWatch Client E2E Checklist",
        "",
        "Configure your client to use this MCP command:",
        "",
        "```bash",
        f"python3 {os.path.join(runtime_repo_root, 'malicious_package_scanner.py')} monitor mcp",
        "```",
        "",
        "Run the following prompts or dependency-add actions and verify the expected outcome.",
        "",
    ]
    for case in INTEGRATION_CASES:
        project_path = os.path.join(projects_root, case.project_dir)
        safe = case.safe_dependency
        bad = case.malicious_dependency
        lines.extend(
            [
                f"## {case.ecosystem}",
                "",
                f"- Project: `{project_path}`",
                f"- Safe add: `{safe['name']} {safe['resolved_version']}` -> expect `allow`",
                f"- Malicious add: `{bad['name']} {bad['resolved_version']}` -> expect `override_required`",
                f"- Suggested prompt: `Add dependency {bad['name']} {bad['resolved_version']} using {case.package_manager}. Check OreWatch first and tell me the decision before making changes.`",
                "",
            ]
        )
    return "\n".join(lines) + "\n"


def integration_case_summary() -> List[Dict[str, object]]:
    """Return a serializable summary of the synthetic integration matrix."""
    return [asdict(case) for case in INTEGRATION_CASES]
