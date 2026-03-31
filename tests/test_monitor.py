import os
import pathlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from monitor.service import MonitorService
from monitor.snapshot_updater import build_snapshot
from monitor.snapshot_updater import generate_keypair
from monitor.snapshot_updater import publish_snapshot
from monitor.watcher import detect_changes, take_project_snapshot
from scanner_engine import ScanResult


def _build_data_metadata():
    return {
        "data_status": "complete",
        "sources_used": ["openssf", "osv"],
        "experimental_sources_used": [],
        "missing_ecosystems": [],
    }


class MonitorTests(unittest.TestCase):
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
