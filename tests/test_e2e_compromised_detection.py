#!/usr/bin/env python3
"""
End-to-end tests: add a compromised package → detect → notify.

Covers the full lifecycle from injecting a known-malicious dependency into
a project manifest through scanner detection, state persistence, notification
emission, and resolution when the package is removed.
"""

from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
import urllib.parse
from unittest.mock import MagicMock, patch

from collectors import db as collector_db
from monitor.integration_matrix import (
    build_dependency_add_request,
    build_synthetic_final_data_dir,
    get_integration_cases,
    write_project_fixtures,
)
from monitor import api as monitor_api_module
from monitor.mcp_adapter import MCPBridge
from monitor.service import MonitorService
from scanner_engine import ScanRequest, run_scan


def _build_malicious_db(final_data_dir, ecosystem, packages, sources=None):
    """Create a synthetic malicious-package SQLite DB for one ecosystem."""
    os.makedirs(final_data_dir, exist_ok=True)
    db_path = os.path.join(final_data_dir, f"unified_{ecosystem}.db")
    if os.path.exists(db_path):
        os.remove(db_path)
    conn, temp_db_path = collector_db.create_database(db_path)
    collector_db.insert_packages(conn, packages)
    collector_db.insert_metadata(
        conn,
        ecosystem=ecosystem,
        packages=packages,
        timestamp="2026-04-04T00:00:00Z",
        extra_metadata={
            "data_status": "complete",
            "sources_used": sources or ["openssf", "osv"],
            "experimental_sources_used": [],
            "last_successful_collect": "2026-04-04T00:00:00Z",
        },
    )
    collector_db.finalize_database(conn, temp_db_path, db_path)
    return db_path


class TestE2ECompromisedPackageDetection(unittest.TestCase):
    """Full lifecycle: add compromised package → detect → notify → resolve."""

    def setUp(self):
        self._config_root = tempfile.TemporaryDirectory()
        self._state_root = tempfile.TemporaryDirectory()
        self._env_patch = patch.dict(
            os.environ,
            {
                "OREWATCH_CONFIG_HOME": self._config_root.name,
                "OREWATCH_STATE_HOME": self._state_root.name,
            },
            clear=False,
        )
        self._env_patch.start()

    def tearDown(self):
        self._env_patch.stop()
        self._config_root.cleanup()
        self._state_root.cleanup()

    def _build_service(self):
        repo_root = tempfile.TemporaryDirectory()
        self.addCleanup(repo_root.cleanup)
        service = MonitorService(repo_root.name)
        build_synthetic_final_data_dir(service.paths["final_data_dir"])
        projects = write_project_fixtures(os.path.join(repo_root.name, "projects"))
        # Disable desktop notifications for testing
        service.config.setdefault("notifications", {})["desktop"] = False
        service.config["notifications"]["terminal"] = False
        return service, projects

    # ------------------------------------------------------------------
    # 1. Dependency-add preflight: malicious package blocked
    # ------------------------------------------------------------------
    def test_malicious_dependency_add_is_blocked_and_notified(self):
        """Adding a known-malicious npm package returns override_required and creates a notification."""
        service, projects = self._build_service()
        npm_case = next(c for c in get_integration_cases() if c.ecosystem == "npm")
        project_path = projects["npm"]["project_dir"]

        with patch("scanners.malicious_checker.logger"):
            response = service.handle_dependency_add_check(
                build_dependency_add_request(npm_case, project_path, "malicious", "claude_code")
            )

        # Verify detection
        self.assertEqual(response["decision"], "override_required")
        self.assertEqual(len(response["results"]), 1)
        result = response["results"][0]
        self.assertEqual(result["status"], "malicious_match")
        self.assertEqual(result["severity"], "critical")
        self.assertEqual(result["name"], "orewatch-bad-npm")
        self.assertIn("Do not install", result["user_action_required"])

        # Verify notification was recorded
        notifications = service.state.list_recent_notifications(project_path=project_path)
        self.assertGreaterEqual(len(notifications), 1)
        latest = notifications[0]
        self.assertEqual(latest["kind"], "dependency_blocked")
        self.assertIn("orewatch-bad-npm", latest["message"])

    # ------------------------------------------------------------------
    # 2. Safe package is allowed
    # ------------------------------------------------------------------
    def test_safe_dependency_add_is_allowed(self):
        """Adding a clean package returns allow with no notification."""
        service, projects = self._build_service()
        npm_case = next(c for c in get_integration_cases() if c.ecosystem == "npm")
        project_path = projects["npm"]["project_dir"]

        with patch("scanners.malicious_checker.logger"):
            response = service.handle_dependency_add_check(
                build_dependency_add_request(npm_case, project_path, "safe", "claude_code")
            )

        self.assertEqual(response["decision"], "allow")
        self.assertEqual(response["results"][0]["status"], "clean")

        # No dependency_blocked notification for clean packages
        notifications = service.state.list_recent_notifications(project_path=project_path)
        blocked = [n for n in notifications if n["kind"] == "dependency_blocked"]
        self.assertEqual(len(blocked), 0)

    # ------------------------------------------------------------------
    # 3. Manifest-level scan detects compromised package in manifest file
    # ------------------------------------------------------------------
    def test_manifest_check_detects_malicious_package(self):
        """Scanning a manifest with a malicious dependency blocks the manifest via manifest parsing."""
        service, projects = self._build_service()
        project_path = projects["npm"]["project_dir"]
        manifest_path = projects["npm"]["manifest_path"]

        # Inject the malicious dependency into the manifest
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
        manifest["dependencies"]["orewatch-bad-npm"] = "1.0.0"
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

        with patch("scanners.malicious_checker.logger"):
            response = service.handle_manifest_check(
                {
                    "client_type": "claude_code",
                    "project_path": project_path,
                    "ecosystem": "npm",
                    "manifest_path": manifest_path,
                }
            )

        self.assertEqual(response["decision"], "override_required")
        self.assertEqual(response["manifest_status"], "blocked")
        malicious_results = [r for r in response["results"] if r["status"] == "malicious_match"]
        self.assertGreaterEqual(len(malicious_results), 1)
        self.assertEqual(malicious_results[0]["name"], "orewatch-bad-npm")

    # ------------------------------------------------------------------
    # 4. Findings state: upsert, retrieve, and resolve
    # ------------------------------------------------------------------
    def test_finding_lifecycle_new_then_resolved(self):
        """Findings appear as new, persist, then resolve when removed."""
        service, projects = self._build_service()
        project_path = projects["npm"]["project_dir"]

        # Step 1: Insert new finding
        changes = service.state.upsert_findings(
            project_path,
            [
                {
                    "fingerprint": "e2e-test-finding-1",
                    "finding_type": "malicious_package",
                    "severity": "critical",
                    "title": "Malicious package evil-lib@1.0.0",
                    "payload": {
                        "name": "evil-lib",
                        "version": "1.0.0",
                        "ecosystem": "npm",
                    },
                }
            ],
            os.path.join(project_path, "report.json"),
        )

        self.assertEqual(len(changes["new_findings"]), 1)
        self.assertEqual(changes["new_findings"][0]["payload"]["name"], "evil-lib")
        self.assertEqual(len(changes["escalated_findings"]), 0)
        self.assertEqual(len(changes["resolved_findings"]), 0)

        # Step 2: Verify active finding is retrievable
        active = service.list_active_findings(project_path=project_path)
        self.assertEqual(active["count"], 1)
        self.assertEqual(active["findings"][0]["package_name"], "evil-lib")
        self.assertEqual(active["findings"][0]["severity"], "critical")

        # Step 3: Remove the finding (simulate clean scan — empty findings list)
        resolve_changes = service.state.upsert_findings(
            project_path,
            [],
            os.path.join(project_path, "report-clean.json"),
        )

        self.assertEqual(len(resolve_changes["new_findings"]), 0)
        self.assertEqual(len(resolve_changes["resolved_findings"]), 1)
        self.assertEqual(resolve_changes["resolved_findings"][0]["fingerprint"], "e2e-test-finding-1")

        # Step 4: Active findings now empty
        active_after = service.list_active_findings(project_path=project_path)
        self.assertEqual(active_after["count"], 0)

    # ------------------------------------------------------------------
    # 5. Severity escalation triggers notification
    # ------------------------------------------------------------------
    def test_finding_severity_escalation(self):
        """A finding that escalates from medium to critical is reported as escalated."""
        service, projects = self._build_service()
        project_path = projects["pypi"]["project_dir"]

        # Insert at medium severity
        service.state.upsert_findings(
            project_path,
            [
                {
                    "fingerprint": "escalation-test-1",
                    "finding_type": "malicious_package",
                    "severity": "medium",
                    "title": "Suspicious package sketchy-lib@2.0.0",
                    "payload": {
                        "name": "sketchy-lib",
                        "version": "2.0.0",
                        "ecosystem": "pypi",
                    },
                }
            ],
            None,
        )

        # Escalate to critical
        changes = service.state.upsert_findings(
            project_path,
            [
                {
                    "fingerprint": "escalation-test-1",
                    "finding_type": "malicious_package",
                    "severity": "critical",
                    "title": "Malicious package sketchy-lib@2.0.0",
                    "payload": {
                        "name": "sketchy-lib",
                        "version": "2.0.0",
                        "ecosystem": "pypi",
                    },
                }
            ],
            None,
        )

        self.assertEqual(len(changes["escalated_findings"]), 1)
        self.assertEqual(changes["escalated_findings"][0]["severity"], "critical")
        self.assertEqual(len(changes["new_findings"]), 0)

    # ------------------------------------------------------------------
    # 6. Notification emission for new findings
    # ------------------------------------------------------------------
    def test_notifier_emits_for_new_findings(self):
        """The notifier records a notification when new findings are reported."""
        service, projects = self._build_service()
        project_path = projects["npm"]["project_dir"]

        changes = {
            "new_findings": [
                {
                    "fingerprint": "notify-test-1",
                    "finding_type": "malicious_package",
                    "severity": "critical",
                    "title": "Malicious package trojan-pkg@0.1.0",
                    "payload": {"name": "trojan-pkg", "version": "0.1.0", "ecosystem": "npm"},
                }
            ],
            "escalated_findings": [],
            "resolved_findings": [],
        }

        service.notifier.notify_project_changes(
            project_path,
            changes,
            {"notify_on": ["malicious_package"]},
            report_path="/tmp/fake-report.html",
        )

        notifications = service.list_recent_notifications(project_path=project_path)
        self.assertEqual(notifications["count"], 1)
        self.assertIn("trojan-pkg", notifications["notifications"][0]["message"])
        self.assertIn("1 new finding", notifications["notifications"][0]["message"])

    # ------------------------------------------------------------------
    # 7. Override flow: block → override → allow
    # ------------------------------------------------------------------
    def test_override_flow_block_then_allow(self):
        """A blocked dependency can be overridden with justification."""
        service, projects = self._build_service()
        npm_case = next(c for c in get_integration_cases() if c.ecosystem == "npm")
        project_path = projects["npm"]["project_dir"]

        with patch("scanners.malicious_checker.logger"):
            block_response = service.handle_dependency_add_check(
                build_dependency_add_request(npm_case, project_path, "malicious", "claude_code")
            )

        self.assertEqual(block_response["decision"], "override_required")
        check_id = block_response["check_id"]

        # Override with justification
        override_response = service.handle_dependency_override(
            check_id,
            {
                "client_type": "claude_code",
                "actor": "e2e-test-user",
                "reason": "Verified safe by security team for testing purposes",
            },
        )

        self.assertEqual(override_response["decision"], "allow")
        self.assertIn("override_id", override_response)
        self.assertIn("expires_at", override_response)

        # Verify override is persisted
        stored_override = service.state.get_dependency_override(override_response["override_id"])
        self.assertIsNotNone(stored_override)
        self.assertEqual(stored_override["actor"], "e2e-test-user")
        self.assertEqual(stored_override["check_id"], check_id)

    # ------------------------------------------------------------------
    # 8. Multi-ecosystem detection
    # ------------------------------------------------------------------
    def test_malicious_detection_across_all_ecosystems(self):
        """Compromised packages are detected in every supported ecosystem."""
        service, projects = self._build_service()

        with patch("scanners.malicious_checker.logger"):
            for case in get_integration_cases():
                project_path = projects[case.ecosystem]["project_dir"]
                with self.subTest(ecosystem=case.ecosystem):
                    response = service.handle_dependency_add_check(
                        build_dependency_add_request(case, project_path, "malicious", "claude_code")
                    )
                    self.assertEqual(
                        response["decision"],
                        "override_required",
                        f"{case.ecosystem}: expected override_required",
                    )
                    self.assertEqual(
                        response["results"][0]["status"],
                        "malicious_match",
                        f"{case.ecosystem}: expected malicious_match",
                    )
                    self.assertEqual(response["results"][0]["severity"], "critical")
                    self.assertEqual(response["data_health"], "complete")

    # ------------------------------------------------------------------
    # 9. MCP bridge end-to-end: dependency add → block → notification retrieval
    # ------------------------------------------------------------------
    def test_mcp_bridge_full_flow(self):
        """MCP bridge: real local API check → block → store finding → retrieve via MCP."""
        service, projects = self._build_service()
        npm_case = next(c for c in get_integration_cases() if c.ecosystem == "npm")
        project_path = projects["npm"]["project_dir"]
        bridge = MCPBridge(service)

        class DummyResponse:
            def __init__(self, payload):
                self._payload = payload

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self):
                return json.dumps(self._payload).encode("utf-8")

        def fake_urlopen(request, timeout=0):
            del timeout
            parsed = urllib.parse.urlparse(request.full_url)
            handler = monitor_api_module._MonitorAPIHandler.__new__(
                monitor_api_module._MonitorAPIHandler
            )
            handler.path = parsed.path + (f"?{parsed.query}" if parsed.query else "")
            header_items = {key: value for key, value in request.header_items()}
            body = request.data or b""
            if body and "Content-Length" not in header_items:
                header_items["Content-Length"] = str(len(body))
            handler.headers = header_items
            handler.rfile = io.BytesIO(body)
            handler.server = type(
                "FakeServer",
                (),
                {"service": service, "api_token": service.api_token},
            )()
            captured = {}

            def fake_write_json(status_code, payload):
                captured["status_code"] = status_code
                captured["payload"] = payload

            handler._write_json = fake_write_json
            method = request.get_method().upper()
            if method == "GET":
                handler.do_GET()
            elif method == "POST":
                handler.do_POST()
            else:
                raise AssertionError(f"Unexpected method: {method}")
            self.assertEqual(captured["status_code"], 200)
            return DummyResponse(captured["payload"])

        with patch("scanners.malicious_checker.logger"):
            with patch("monitor.api.urllib.request.urlopen", side_effect=fake_urlopen):
            # Step 1: Check malicious dependency via MCP over the real local API
                check_result = bridge.call_tool(
                    "orewatch_check_dependency_add",
                    build_dependency_add_request(npm_case, project_path, "malicious", "claude_code"),
                )
                self.assertEqual(check_result["decision"], "override_required")

                # Step 2: Simulate a background scan finding and emit the normal findings notification
                report_path = os.path.join(project_path, "report.html")
                changes = service.state.upsert_findings(
                    project_path,
                    [
                        {
                            "fingerprint": "mcp-e2e-finding",
                            "finding_type": "malicious_package",
                            "severity": "critical",
                            "title": "Malicious package orewatch-bad-npm@1.0.0",
                            "payload": {
                                "name": "orewatch-bad-npm",
                                "version": "1.0.0",
                                "ecosystem": "npm",
                            },
                        }
                    ],
                    report_path,
                )
                service.notifier.notify_project_changes(
                    project_path,
                    changes,
                    {"notify_on": ["malicious_package"]},
                    report_path=report_path,
                )

                # Step 3: Retrieve findings via MCP over the real local API path
                findings = bridge.call_tool(
                    "orewatch_list_active_findings",
                    {"project_path": project_path, "min_severity": "high"},
                )
                self.assertEqual(findings["count"], 1)
                self.assertEqual(findings["findings"][0]["package_name"], "orewatch-bad-npm")

                # Step 4: Retrieve notifications via MCP over the real local API path
                notifications = bridge.call_tool(
                    "orewatch_list_notifications",
                    {"project_path": project_path},
                )
                self.assertGreaterEqual(notifications["count"], 2)
                kinds = {item["kind"] for item in notifications["notifications"]}
                self.assertIn("dependency_blocked", kinds)
                self.assertIn("findings", kinds)

    # ------------------------------------------------------------------
    # 10. Webhook notification fires on malicious detection
    # ------------------------------------------------------------------
    def test_webhook_notification_fires_on_detection(self):
        """Webhook is called with correct payload when a malicious package is blocked."""
        service, projects = self._build_service()
        service.config["notifications"]["webhook_url"] = "https://hooks.example.com/orewatch"
        service.config["notifications"]["webhook_format"] = "generic"
        service.notifier.config = service.config
        npm_case = next(c for c in get_integration_cases() if c.ecosystem == "npm")
        project_path = projects["npm"]["project_dir"]

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.return_value.__enter__ = MagicMock()
            mock_urlopen.return_value.__exit__ = MagicMock(return_value=False)

            with patch("scanners.malicious_checker.logger"):
                response = service.handle_dependency_add_check(
                    build_dependency_add_request(npm_case, project_path, "malicious", "claude_code")
                )

        mock_urlopen.assert_called_once()
        self.assertEqual(response["decision"], "override_required")
        request_obj = mock_urlopen.call_args[0][0]
        self.assertEqual(request_obj.method, "POST")
        payload = json.loads(request_obj.data.decode("utf-8"))
        self.assertEqual(payload["event"], "orewatch.dependency_blocked")
        self.assertIn("orewatch-bad-npm", payload["message"])
        self.assertEqual(
            payload["details"]["blocked_packages"][0]["name"],
            "orewatch-bad-npm",
        )

    # ------------------------------------------------------------------
    # 11. Scanner engine → state → notification full pipeline
    # ------------------------------------------------------------------
    def test_scanner_engine_detects_malicious_in_project(self):
        """run_scan on a project with a malicious dependency flags it."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create project with malicious dependency
            project_dir = os.path.join(temp_dir, "test-project")
            os.makedirs(project_dir, exist_ok=True)
            package_json_path = os.path.join(project_dir, "package.json")
            with open(package_json_path, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "name": "test-project",
                        "version": "1.0.0",
                        "dependencies": {
                            "evil-scanner-test": "1.0.0",
                            "safe-package": "2.0.0",
                        },
                    },
                    f,
                    indent=2,
                )

            # Create malicious package database
            final_data_dir = os.path.join(temp_dir, "final-data")
            _build_malicious_db(
                final_data_dir,
                "npm",
                [
                    {
                        "name": "evil-scanner-test",
                        "versions": ["1.0.0"],
                        "sources": ["openssf", "osv"],
                        "severity": "critical",
                        "description": "Known malicious package used for E2E testing",
                        "detected_behaviors": ["data_exfiltration", "install_script"],
                    }
                ],
            )

            request = ScanRequest(
                target_path=project_dir,
                scan_iocs=False,
                scan_packages=True,
                ensure_data=False,
                print_summary=False,
            )

            with patch("scanners.malicious_checker.logger"):
                with patch(
                    "scanner_engine._load_live_update_runtime",
                    return_value=(temp_dir, {"enabled": True}, final_data_dir),
                ):
                    result = run_scan(request)

            self.assertEqual(result.ecosystem, "npm")
            self.assertEqual(result.exit_code, 1, "Expected exit code 1 for malicious detection")
            self.assertGreaterEqual(len(result.malicious_packages), 1)

            mal_pkg = next(
                (p for p in result.malicious_packages if p["name"] == "evil-scanner-test"),
                None,
            )
            self.assertIsNotNone(mal_pkg, "evil-scanner-test should be flagged")
            self.assertEqual(mal_pkg["severity"], "critical")
            self.assertIn("openssf", mal_pkg.get("sources", []))

    # ------------------------------------------------------------------
    # 12. Findings summary and state reporting
    # ------------------------------------------------------------------
    def test_state_summary_reflects_active_findings(self):
        """State summary correctly counts active findings and highest severity."""
        service, projects = self._build_service()
        project_path = projects["npm"]["project_dir"]

        # Start with no findings
        summary = service.state.get_summary()
        self.assertEqual(summary["active_findings"], 0)
        self.assertIsNone(summary["highest_active_severity"])

        # Add critical finding
        service.state.upsert_findings(
            project_path,
            [
                {
                    "fingerprint": "summary-test-1",
                    "finding_type": "malicious_package",
                    "severity": "critical",
                    "title": "Critical malicious package",
                    "payload": {"name": "bad-pkg", "ecosystem": "npm"},
                },
                {
                    "fingerprint": "summary-test-2",
                    "finding_type": "malicious_package",
                    "severity": "high",
                    "title": "High severity malicious package",
                    "payload": {"name": "sus-pkg", "ecosystem": "npm"},
                },
            ],
            None,
        )

        summary = service.state.get_summary()
        self.assertEqual(summary["active_findings"], 2)
        self.assertEqual(summary["highest_active_severity"], "critical")

    # ------------------------------------------------------------------
    # 13. Unresolved version detection
    # ------------------------------------------------------------------
    def test_unresolved_version_requires_override(self):
        """A dependency with an unresolvable version range requires override."""
        service, projects = self._build_service()
        npm_case = next(c for c in get_integration_cases() if c.ecosystem == "npm")
        project_path = projects["npm"]["project_dir"]

        with patch("scanners.malicious_checker.logger"):
            response = service.handle_dependency_add_check(
                build_dependency_add_request(npm_case, project_path, "unresolved", "claude_code")
            )

        self.assertEqual(response["decision"], "override_required")
        self.assertEqual(response["results"][0]["status"], "unresolved_version")

    # ------------------------------------------------------------------
    # 14. Manifest with mixed safe and malicious dependencies
    # ------------------------------------------------------------------
    def test_manifest_mixed_dependencies(self):
        """A manifest with both safe and malicious deps blocks overall, reporting each."""
        service, projects = self._build_service()
        npm_case = next(c for c in get_integration_cases() if c.ecosystem == "npm")
        project_path = projects["npm"]["project_dir"]
        manifest_path = projects["npm"]["manifest_path"]

        # Write manifest with both safe and malicious packages
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "name": "mixed-test",
                    "version": "1.0.0",
                    "dependencies": {
                        "orewatch-good-npm": "2.0.0",
                        "orewatch-bad-npm": "1.0.0",
                    },
                },
                f,
                indent=2,
            )

        with patch("scanners.malicious_checker.logger"):
            response = service.handle_manifest_check({
                "client_type": "claude_code",
                "project_path": project_path,
                "ecosystem": "npm",
                "manifest_path": manifest_path,
            })

        self.assertEqual(response["decision"], "override_required")
        self.assertEqual(response["manifest_status"], "blocked")

        statuses = {r["name"]: r["status"] for r in response["results"]}
        self.assertEqual(statuses["orewatch-bad-npm"], "malicious_match")
        self.assertEqual(statuses["orewatch-good-npm"], "clean")


if __name__ == "__main__":
    unittest.main()
