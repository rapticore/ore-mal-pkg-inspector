import os
import tempfile
import unittest
from unittest.mock import patch

from monitor.integration_matrix import build_dependency_add_request
from monitor.integration_matrix import build_manifest_check_request
from monitor.integration_matrix import build_synthetic_final_data_dir
from monitor.integration_matrix import get_integration_cases
from monitor.integration_matrix import write_project_fixtures
from monitor.mcp_adapter import MCPBridge
from monitor.service import MonitorService


CLIENT_ROTATION = [
    "claude_code",
    "codex",
    "cursor",
    "vscode",
    "jetbrains",
    "xcode",
]


class ClientIntegrationE2ETests(unittest.TestCase):
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
        return service, projects

    def test_fixture_writer_creates_projects_for_all_ecosystems(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            projects = write_project_fixtures(temp_dir)

            for case in get_integration_cases():
                with self.subTest(ecosystem=case.ecosystem):
                    self.assertTrue(os.path.isdir(projects[case.ecosystem]["project_dir"]))
                    self.assertTrue(os.path.exists(projects[case.ecosystem]["manifest_path"]))

    def test_dependency_add_decisions_cover_all_ecosystems(self):
        service, projects = self._build_service()

        with patch("scanners.malicious_checker.logger"):
            for index, case in enumerate(get_integration_cases()):
                client_type = CLIENT_ROTATION[index]
                project_path = projects[case.ecosystem]["project_dir"]
                with self.subTest(ecosystem=case.ecosystem, client_type=client_type, scenario="safe"):
                    safe_response = service.handle_dependency_add_check(
                        build_dependency_add_request(case, project_path, "safe", client_type)
                    )
                    self.assertEqual(safe_response["decision"], "allow")
                    self.assertEqual(safe_response["data_health"], "complete")
                    self.assertEqual(safe_response["results"][0]["status"], "clean")

                with self.subTest(ecosystem=case.ecosystem, client_type=client_type, scenario="malicious"):
                    bad_response = service.handle_dependency_add_check(
                        build_dependency_add_request(case, project_path, "malicious", client_type)
                    )
                    self.assertEqual(bad_response["decision"], "override_required")
                    self.assertEqual(bad_response["results"][0]["status"], "malicious_match")
                    self.assertEqual(bad_response["results"][0]["severity"], "critical")

                with self.subTest(ecosystem=case.ecosystem, client_type=client_type, scenario="unresolved"):
                    unresolved_response = service.handle_dependency_add_check(
                        build_dependency_add_request(case, project_path, "unresolved", client_type)
                    )
                    self.assertEqual(unresolved_response["decision"], "override_required")
                    self.assertEqual(
                        unresolved_response["results"][0]["status"],
                        "unresolved_version",
                    )

    def test_manifest_and_mcp_bridge_cover_all_ecosystems(self):
        service, projects = self._build_service()
        bridge = MCPBridge(service)

        def fake_api_request(base_url, token, method, path, payload=None, timeout_ms=5000):
            del base_url, token, timeout_ms
            if method == "GET" and path == "/v1/health":
                health = service.build_health_payload()
                health["daemon_running"] = True
                health["api_listening"] = True
                return health
            if method == "POST" and path == "/v1/check/dependency-add":
                return service.handle_dependency_add_check(payload)
            if method == "POST" and path == "/v1/check/manifest":
                return service.handle_manifest_check(payload)
            if method == "POST" and path.startswith("/v1/checks/") and path.endswith("/override"):
                check_id = path[len("/v1/checks/") : -len("/override")].strip("/")
                return service.handle_dependency_override(check_id, payload)
            raise AssertionError(f"Unexpected API request: {method} {path}")

        with patch("scanners.malicious_checker.logger"):
            with patch("monitor.mcp_adapter.wait_for_api", return_value=True):
                with patch("monitor.mcp_adapter.monitor_api_request", side_effect=fake_api_request):
                    for index, case in enumerate(get_integration_cases()):
                        project_path = projects[case.ecosystem]["project_dir"]
                        manifest_path = projects[case.ecosystem]["manifest_path"]
                        client_type = CLIENT_ROTATION[index]
                        with self.subTest(ecosystem=case.ecosystem, client_type=client_type, scenario="manifest"):
                            manifest_result = bridge.call_tool(
                                "orewatch_check_manifest",
                                build_manifest_check_request(
                                    case,
                                    project_path,
                                    manifest_path,
                                    "malicious",
                                    client_type,
                                ),
                            )
                            self.assertEqual(manifest_result["decision"], "override_required")
                            self.assertEqual(manifest_result["manifest_status"], "blocked")

                        with self.subTest(ecosystem=case.ecosystem, client_type=client_type, scenario="mcp_safe"):
                            safe_result = bridge.call_tool(
                                "orewatch_check_dependency_add",
                                build_dependency_add_request(case, project_path, "safe", client_type),
                            )
                            self.assertEqual(safe_result["decision"], "allow")

                        with self.subTest(ecosystem=case.ecosystem, client_type=client_type, scenario="mcp_override"):
                            bad_result = bridge.call_tool(
                                "orewatch_check_dependency_add",
                                build_dependency_add_request(case, project_path, "malicious", client_type),
                            )
                            override_result = bridge.call_tool(
                                "orewatch_override_dependency_add",
                                {
                                    "check_id": bad_result["check_id"],
                                    "client_type": client_type,
                                    "actor": "integration-test",
                                    "reason": f"Synthetic override for {case.ecosystem}",
                                },
                            )
                            self.assertEqual(bad_result["decision"], "override_required")
                            self.assertEqual(override_result["decision"], "allow")

    def test_background_findings_are_retrievable_over_mcp(self):
        service, projects = self._build_service()
        bridge = MCPBridge(service)
        project_path = projects["npm"]["project_dir"]
        service.config["notifications"]["desktop"] = False
        service.config["notifications"]["terminal"] = False
        changes = service.state.upsert_findings(
            project_path,
            [
                {
                    "fingerprint": "finding-1",
                    "finding_type": "malicious_package",
                    "severity": "critical",
                    "title": "Malicious package -gzip-ize@1.0.0",
                    "payload": {
                        "name": "-gzip-ize",
                        "version": "1.0.0",
                        "ecosystem": "npm",
                    },
                }
            ],
            os.path.join(project_path, "report.json"),
        )
        service.notifier.notify_project_changes(
            project_path,
            changes,
            {"notify_on": ["malicious_package"]},
            report_path=os.path.join(project_path, "report.json"),
        )

        def fake_api_request(base_url, token, method, path, payload=None, timeout_ms=5000):
            del base_url, token, payload, timeout_ms
            if method == "GET" and path.startswith("/v1/findings/active"):
                return service.list_active_findings(project_path=project_path, limit=20)
            if method == "GET" and path.startswith("/v1/notifications"):
                return service.list_recent_notifications(project_path=project_path, limit=20)
            raise AssertionError(f"Unexpected API request: {method} {path}")

        with patch("monitor.mcp_adapter.wait_for_api", return_value=True):
            with patch("monitor.mcp_adapter.monitor_api_request", side_effect=fake_api_request):
                findings = bridge.call_tool(
                    "orewatch_list_active_findings",
                    {"project_path": project_path, "min_severity": "high"},
                )
                notifications = bridge.call_tool(
                    "orewatch_list_notifications",
                    {"project_path": project_path},
                )

        self.assertEqual(findings["count"], 1)
        self.assertEqual(findings["findings"][0]["package_name"], "-gzip-ize")
        self.assertEqual(notifications["count"], 1)
        self.assertIn("-gzip-ize@1.0.0", notifications["notifications"][0]["message"])


if __name__ == "__main__":
    unittest.main()
