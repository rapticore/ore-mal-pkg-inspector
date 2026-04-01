import json
import os
import pathlib
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from monitor import notifier as monitor_notifier
from monitor import policy as monitor_policy
from monitor.service import MonitorService
from monitor.snapshot_updater import build_snapshot
from monitor.snapshot_updater import generate_keypair
from monitor.snapshot_updater import publish_snapshot
from monitor.watcher import detect_changes, take_project_snapshot
from scanners import report_generator
from scanner_engine import ScanResult


def _build_data_metadata():
    return {
        "data_status": "complete",
        "sources_used": ["openssf", "osv"],
        "experimental_sources_used": [],
        "missing_ecosystems": [],
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

    def test_install_creates_monitor_layout_and_service_files(self):
        with tempfile.TemporaryDirectory() as repo_root:
            service = MonitorService(repo_root)
            info = service.install(service_manager="background", auto_start=False)

            self.assertTrue(os.path.exists(info["config"]))
            self.assertTrue(os.path.exists(info["state_db"]))
            self.assertTrue(os.path.exists(info["launchd"]))
            self.assertTrue(os.path.exists(info["systemd"]))
            self.assertFalse(service.config["snapshots"]["use_live_collection_fallback"])

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
        notifier = monitor_notifier.Notifier(state, {"notifications": {"desktop": True, "terminal": False}})
        malicious_message = 'foo" & do shell script "curl evil.com" & "'

        with patch("monitor.notifier.shutil.which", side_effect=lambda cmd: "/usr/bin/osascript" if cmd == "osascript" else None):
            with patch("monitor.notifier.subprocess.run") as mocked_run:
                notifier._emit("/tmp/project", "findings", malicious_message)

        args = mocked_run.call_args.args[0]
        self.assertEqual(args[:3], ["osascript", "-e", monitor_notifier.APPLE_NOTIFICATION_SCRIPT])
        self.assertEqual(args[3:], ["OreWatch", malicious_message])
        self.assertNotIn(malicious_message, monitor_notifier.APPLE_NOTIFICATION_SCRIPT)

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

    def test_build_and_apply_snapshot_with_signature(self):
        with tempfile.TemporaryDirectory() as repo_root:
            keys = self._generate_keys(repo_root)
            final_data_dir = os.path.join(repo_root, "collectors", "final-data")
            os.makedirs(final_data_dir, exist_ok=True)
            db_path = os.path.join(final_data_dir, "unified_npm.db")
            with open(db_path, "wb") as handle:
                handle.write(b"original-db")

            snapshot_dir = os.path.join(repo_root, "snapshot-output")
            manifest_path = build_snapshot(
                final_data_dir,
                snapshot_dir,
                private_key_path=keys["private_key_path"],
                public_key_path=keys["public_key_path"],
            )

            with open(db_path, "wb") as handle:
                handle.write(b"mutated-db")

            service = MonitorService(repo_root)
            result = service.updater.apply_snapshot(
                manifest_path,
                public_key_path=keys["public_key_path"],
            )

            self.assertTrue(result["success"])
            with open(db_path, "rb") as handle:
                self.assertEqual(handle.read(), b"original-db")
            self.assertEqual(result["key_id"], keys["key_id"])

    def test_publish_snapshot_creates_channel_descriptor_and_apply_from_channel(self):
        with tempfile.TemporaryDirectory() as repo_root:
            keys = self._generate_keys(repo_root)
            final_data_dir = os.path.join(repo_root, "collectors", "final-data")
            os.makedirs(final_data_dir, exist_ok=True)
            db_path = os.path.join(final_data_dir, "unified_npm.db")
            with open(db_path, "wb") as handle:
                handle.write(b"channel-original")

            publish_dir = os.path.join(repo_root, "published")
            publish_result = publish_snapshot(
                final_data_dir,
                publish_dir,
                base_url=pathlib.Path(publish_dir).as_uri(),
                channel="stable",
                private_key_path=keys["private_key_path"],
                public_key_path=keys["public_key_path"],
            )

            with open(db_path, "wb") as handle:
                handle.write(b"channel-mutated")

            service = MonitorService(repo_root)
            result = service.updater.apply_snapshot(
                publish_result["channel_path"],
                public_key_path=keys["public_key_path"],
            )

            self.assertTrue(result["success"])
            self.assertEqual(result["channel"], "stable")
            self.assertEqual(result["key_id"], keys["key_id"])
            with open(db_path, "rb") as handle:
                self.assertEqual(handle.read(), b"channel-original")

    def test_apply_snapshot_rolls_back_when_directory_swap_fails(self):
        with tempfile.TemporaryDirectory() as repo_root:
            keys = self._generate_keys(repo_root)
            final_data_dir = os.path.join(repo_root, "collectors", "final-data")
            os.makedirs(final_data_dir, exist_ok=True)
            db_path = os.path.join(final_data_dir, "unified_npm.db")
            with open(db_path, "wb") as handle:
                handle.write(b"rollback-original")

            publish_dir = os.path.join(repo_root, "published")
            publish_result = publish_snapshot(
                final_data_dir,
                publish_dir,
                base_url=pathlib.Path(publish_dir).as_uri(),
                channel="stable",
                private_key_path=keys["private_key_path"],
                public_key_path=keys["public_key_path"],
            )

            with open(db_path, "wb") as handle:
                handle.write(b"rollback-mutated")

            service = MonitorService(repo_root)
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
            final_data_dir = os.path.join(repo_root, "collectors", "final-data")
            os.makedirs(final_data_dir, exist_ok=True)
            db_path = os.path.join(final_data_dir, "unified_npm.db")
            with open(db_path, "wb") as handle:
                handle.write(b"signed-db")

            snapshot_dir = os.path.join(repo_root, "snapshot-output")
            manifest_path = build_snapshot(
                final_data_dir,
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
            service.config["notifications"]["desktop"] = False
            service.config["notifications"]["terminal"] = False
            service.state.add_watched_project(project_dir, {})

            with patch.object(service.updater, "refresh_if_due", return_value={"success": True}):
                service.run_iteration()

                service.state.update_project_scan(project_dir, "full", None, 0, "primed")

                with open(package_json, "w", encoding="utf-8") as handle:
                    handle.write('{"name": "demo", "dependencies": {"badpkg": "1.0.0"}}\n')

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

                with patch("monitor.service.run_scan", return_value=fake_result) as mocked_scan:
                    service.run_iteration()

            mocked_scan.assert_called_once()
            active_findings = service.state.list_active_findings(project_dir)
            self.assertEqual(len(active_findings), 1)
            self.assertEqual(active_findings[0]["title"], "Malicious package badpkg@1.0.0")
            notifications = service.state.list_recent_notifications(limit=5)
            self.assertEqual(len(notifications), 1)

    def test_refresh_failure_does_not_advance_last_successful_refresh_time(self):
        with tempfile.TemporaryDirectory() as repo_root:
            service = MonitorService(repo_root)
            previous_success = "2026-03-31T00:00:00Z"
            service.state.set_agent_state("last_threat_refresh_at", previous_success)

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

    def test_run_iteration_skips_scans_when_refresh_fails(self):
        with tempfile.TemporaryDirectory() as repo_root:
            project_dir = os.path.join(repo_root, "project")
            os.makedirs(project_dir, exist_ok=True)

            service = MonitorService(repo_root)
            service.state.add_watched_project(project_dir, {})

            with patch.object(
                service.updater,
                "refresh_if_due",
                return_value={"success": False, "message": "refresh failed"},
            ):
                with patch.object(service, "_poll_project") as mocked_poll:
                    with patch.object(service, "_run_project_scan") as mocked_scan:
                        service.run_iteration()

            mocked_poll.assert_not_called()
            mocked_scan.assert_not_called()
            self.assertEqual(
                service.state.get_agent_state("scan_blocked_reason"),
                "refresh failed",
            )

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
