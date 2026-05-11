import io
import json
import os
import tempfile
import time
import unittest
from contextlib import redirect_stdout

from collectors.live_update import (
    DEFAULT_LIVE_UPDATE_CONFIG,
    cleanup_stale_staging,
    ensure_live_update_layout,
    promote_candidate_directory,
    prune_backup_dirs,
    write_backup_manifest,
)
from monitor.cli import run_monitor_cli
from monitor.service import _directory_size_bytes


def _make_db_file(path: str, content: bytes) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(content)


def _make_backup_dir(root: str, name: str, payload: bytes = b"x" * 1024) -> str:
    path = os.path.join(root, name, "final-data")
    os.makedirs(path)
    with open(os.path.join(path, "unified_npm.db"), "wb") as handle:
        handle.write(payload)
    return os.path.join(root, name)


class PruneBackupDirsTests(unittest.TestCase):
    def test_keep_most_recent_n(self):
        with tempfile.TemporaryDirectory() as root:
            for name in (
                "20260404T010000Z-aaa",
                "20260405T010000Z-bbb",
                "20260406T010000Z-ccc",
                "20260407T010000Z-ddd",
            ):
                _make_backup_dir(root, name)

            removed = prune_backup_dirs(root, keep=2)

            self.assertEqual(removed, 2)
            self.assertEqual(
                sorted(os.listdir(root)),
                ["20260406T010000Z-ccc", "20260407T010000Z-ddd"],
            )

    def test_keep_zero_purges_all(self):
        with tempfile.TemporaryDirectory() as root:
            _make_backup_dir(root, "20260404T010000Z-aaa")
            _make_backup_dir(root, "20260405T010000Z-bbb")

            removed = prune_backup_dirs(root, keep=0)

            self.assertEqual(removed, 2)
            self.assertEqual(os.listdir(root), [])

    def test_negative_keep_is_safe_noop(self):
        with tempfile.TemporaryDirectory() as root:
            _make_backup_dir(root, "20260404T010000Z-aaa")

            removed = prune_backup_dirs(root, keep=-1)

            self.assertEqual(removed, 0)
            self.assertEqual(os.listdir(root), ["20260404T010000Z-aaa"])

    def test_ignores_files_and_hidden_entries(self):
        with tempfile.TemporaryDirectory() as root:
            _make_backup_dir(root, "20260404T010000Z-aaa")
            _make_backup_dir(root, "20260405T010000Z-bbb")
            with open(os.path.join(root, "stray.txt"), "w") as handle:
                handle.write("ignore me")
            os.makedirs(os.path.join(root, ".hidden"))

            prune_backup_dirs(root, keep=1)

            remaining = sorted(os.listdir(root))
            self.assertIn("20260405T010000Z-bbb", remaining)
            self.assertIn("stray.txt", remaining)
            self.assertIn(".hidden", remaining)
            self.assertNotIn("20260404T010000Z-aaa", remaining)

    def test_missing_root_is_safe_noop(self):
        with tempfile.TemporaryDirectory() as root:
            removed = prune_backup_dirs(os.path.join(root, "does-not-exist"), keep=5)
            self.assertEqual(removed, 0)


class WriteBackupManifestTests(unittest.TestCase):
    def test_manifest_records_files_and_hashes(self):
        with tempfile.TemporaryDirectory() as workdir:
            source = os.path.join(workdir, "previous-final-data")
            os.makedirs(source)
            _make_db_file(os.path.join(source, "unified_npm.db"), b"npm-bytes")
            _make_db_file(os.path.join(source, "unified_pypi.db"), b"pypi")
            # Subdirectories should be skipped — manifest is one level deep.
            os.makedirs(os.path.join(source, "junk-subdir"))

            destination = os.path.join(workdir, "backups", "v-001")
            manifest_path = write_backup_manifest(source, destination, "v-001")

            self.assertTrue(manifest_path.endswith("manifest.json"))
            with open(manifest_path, "r", encoding="utf-8") as handle:
                manifest = json.load(handle)

            self.assertEqual(manifest["version"], "v-001")
            self.assertIn("created_at", manifest)
            filenames = [entry["filename"] for entry in manifest["files"]]
            self.assertEqual(filenames, ["unified_npm.db", "unified_pypi.db"])
            self.assertEqual(manifest["files"][0]["size"], len(b"npm-bytes"))
            # sha256 of b"npm-bytes" is deterministic; verify field is hex.
            self.assertEqual(len(manifest["files"][0]["sha256"]), 64)
            int(manifest["files"][0]["sha256"], 16)  # raises if not hex

    def test_manifest_is_tiny_compared_to_payload(self):
        with tempfile.TemporaryDirectory() as workdir:
            source = os.path.join(workdir, "src")
            os.makedirs(source)
            _make_db_file(os.path.join(source, "unified_npm.db"), b"x" * (5 * 1024 * 1024))

            destination = os.path.join(workdir, "backups", "v-1")
            manifest_path = write_backup_manifest(source, destination, "v-1")
            self.assertLess(os.path.getsize(manifest_path), 1024)


class CleanupStaleStagingTests(unittest.TestCase):
    def test_removes_old_candidate_directories(self):
        with tempfile.TemporaryDirectory() as staging:
            fresh = os.path.join(staging, "candidate-raw-fresh")
            stale = os.path.join(staging, "candidate-raw-stale")
            os.makedirs(fresh)
            os.makedirs(stale)
            old_time = time.time() - 7200  # 2 hours ago
            os.utime(stale, (old_time, old_time))

            removed = cleanup_stale_staging(staging, max_age_seconds=3600)

            self.assertEqual(removed, 1)
            self.assertTrue(os.path.exists(fresh))
            self.assertFalse(os.path.exists(stale))

    def test_ignores_non_candidate_entries(self):
        with tempfile.TemporaryDirectory() as staging:
            unrelated = os.path.join(staging, "live-update-swap-temp")
            os.makedirs(unrelated)
            os.utime(unrelated, (time.time() - 7200, time.time() - 7200))

            removed = cleanup_stale_staging(staging, max_age_seconds=3600)

            self.assertEqual(removed, 0)
            self.assertTrue(os.path.exists(unrelated))

    def test_negative_age_is_safe_noop(self):
        with tempfile.TemporaryDirectory() as staging:
            entry = os.path.join(staging, "candidate-raw-foo")
            os.makedirs(entry)
            removed = cleanup_stale_staging(staging, max_age_seconds=-1)
            self.assertEqual(removed, 0)
            self.assertTrue(os.path.exists(entry))


class PromoteCandidateDirectoryStorageTests(unittest.TestCase):
    def test_promotion_writes_manifest_not_full_copy(self):
        with tempfile.TemporaryDirectory() as workdir:
            active = os.path.join(workdir, "final-data")
            promotion_root = os.path.join(workdir, "live-updates")
            os.makedirs(active)
            _make_db_file(os.path.join(active, "unified_npm.db"), b"y" * (2 * 1024 * 1024))

            candidate = os.path.join(workdir, "candidate-final")
            os.makedirs(candidate)
            _make_db_file(os.path.join(candidate, "unified_npm.db"), b"z" * (2 * 1024 * 1024))

            manifest_path = promote_candidate_directory(
                active, candidate, promotion_root, "v-001"
            )

            self.assertIsNotNone(manifest_path)
            self.assertTrue(manifest_path.endswith("manifest.json"))
            backup_dir = os.path.dirname(manifest_path)
            self.assertLess(_directory_size_bytes(backup_dir), 4096)

    def test_promotion_prunes_old_backups(self):
        with tempfile.TemporaryDirectory() as workdir:
            promotion_root = os.path.join(workdir, "live-updates")
            layout = ensure_live_update_layout(promotion_root)
            # Pre-seed five old backup manifest directories.
            for idx in range(5):
                name = f"2026040{idx}T010000Z-old-{idx}"
                os.makedirs(os.path.join(layout["backups"], name))
                with open(
                    os.path.join(layout["backups"], name, "manifest.json"), "w"
                ) as handle:
                    json.dump({"version": name, "files": []}, handle)

            active = os.path.join(workdir, "final-data")
            os.makedirs(active)
            _make_db_file(os.path.join(active, "unified_npm.db"), b"a")
            candidate = os.path.join(workdir, "candidate-final")
            os.makedirs(candidate)
            _make_db_file(os.path.join(candidate, "unified_npm.db"), b"b")

            promote_candidate_directory(
                active,
                candidate,
                promotion_root,
                "20260410T010000Z-new",
                live_update_config={"retain_backups": 2},
            )

            remaining = sorted(os.listdir(layout["backups"]))
            self.assertEqual(len(remaining), 2)
            self.assertIn("20260410T010000Z-new", remaining)

    def test_promotion_clears_stale_staging(self):
        with tempfile.TemporaryDirectory() as workdir:
            promotion_root = os.path.join(workdir, "live-updates")
            layout = ensure_live_update_layout(promotion_root)
            stale = os.path.join(layout["staging"], "candidate-raw-stale")
            os.makedirs(stale)
            old_time = time.time() - 7200
            os.utime(stale, (old_time, old_time))

            active = os.path.join(workdir, "final-data")
            os.makedirs(active)
            _make_db_file(os.path.join(active, "unified_npm.db"), b"a")
            candidate = os.path.join(workdir, "candidate-final")
            os.makedirs(candidate)
            _make_db_file(os.path.join(candidate, "unified_npm.db"), b"b")

            promote_candidate_directory(
                active,
                candidate,
                promotion_root,
                "20260410T010000Z-new",
                live_update_config={
                    "retain_backups": 5,
                    "staging_max_age_seconds": 3600,
                },
            )

            self.assertFalse(os.path.exists(stale))


class MonitorServiceCleanupTests(unittest.TestCase):
    def test_cleanup_storage_prunes_and_reports_bytes_freed(self):
        from monitor.service import MonitorService

        with tempfile.TemporaryDirectory() as workdir:
            os.environ["OREWATCH_STATE_HOME"] = workdir
            os.environ["OREWATCH_CONFIG_HOME"] = workdir
            try:
                service = MonitorService(workdir)
                snapshots_root = service.paths["snapshots"]
                live_backups = os.path.join(snapshots_root, "live-updates", "backups")
                staging_root = os.path.join(snapshots_root, "live-updates", "staging")
                os.makedirs(live_backups)
                os.makedirs(staging_root)

                # Six large pseudo-backups; only most-recent 2 should survive.
                for idx in range(6):
                    name = f"20260{idx + 1:02d}01T010000Z-v{idx}"
                    _make_backup_dir(live_backups, name, payload=b"q" * (256 * 1024))

                stale_candidate = os.path.join(staging_root, "candidate-raw-stale")
                os.makedirs(stale_candidate)
                old_time = time.time() - 7200
                os.utime(stale_candidate, (old_time, old_time))

                result = service.cleanup_storage(
                    keep_backups=2, staging_max_age_seconds=3600
                )

                self.assertTrue(result["success"])
                self.assertEqual(result["keep_backups"], 2)
                self.assertEqual(result["backups_pruned"]["live_update_backups"], 4)
                self.assertEqual(result["staging_entries_removed"], 1)
                self.assertGreater(result["bytes_freed"], 0)
                self.assertEqual(len(os.listdir(live_backups)), 2)
                self.assertFalse(os.path.exists(stale_candidate))

                service.close()
            finally:
                os.environ.pop("OREWATCH_STATE_HOME", None)
                os.environ.pop("OREWATCH_CONFIG_HOME", None)


class CleanupCliTests(unittest.TestCase):
    def test_cleanup_cli_invokes_service_and_returns_zero(self):
        with tempfile.TemporaryDirectory() as workdir:
            os.environ["OREWATCH_STATE_HOME"] = workdir
            os.environ["OREWATCH_CONFIG_HOME"] = workdir
            try:
                buffer = io.StringIO()
                with redirect_stdout(buffer):
                    exit_code = run_monitor_cli(
                        [
                            "cleanup",
                            "--keep-backups",
                            "2",
                            "--staging-max-age-seconds",
                            "3600",
                        ]
                    )

                self.assertEqual(exit_code, 0)
                payload = json.loads(buffer.getvalue())
                self.assertTrue(payload["success"])
                self.assertEqual(payload["keep_backups"], 2)
                self.assertEqual(payload["staging_max_age_seconds"], 3600)
                self.assertIn("backups_pruned", payload)
                self.assertIn("bytes_freed", payload)
            finally:
                os.environ.pop("OREWATCH_STATE_HOME", None)
                os.environ.pop("OREWATCH_CONFIG_HOME", None)


class LiveUpdateDefaultsTests(unittest.TestCase):
    def test_retain_backups_and_staging_age_present_in_defaults(self):
        self.assertIn("retain_backups", DEFAULT_LIVE_UPDATE_CONFIG)
        self.assertIn("staging_max_age_seconds", DEFAULT_LIVE_UPDATE_CONFIG)
        self.assertGreaterEqual(DEFAULT_LIVE_UPDATE_CONFIG["retain_backups"], 1)
        self.assertGreaterEqual(DEFAULT_LIVE_UPDATE_CONFIG["staging_max_age_seconds"], 60)


if __name__ == "__main__":
    unittest.main()
