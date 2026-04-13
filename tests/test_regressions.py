import contextlib
import importlib
import io
import json
import os
import sys
import tempfile
import unittest
import zipfile
from unittest.mock import patch

import malicious_package_scanner as scanner
import scanner_engine as engine
from collectors import collect_openssf, collect_osv, collect_socketdev, db as collector_db, utils
from collectors.live_update import evaluate_candidate
from monitor.state import MonitorState
from scanner_engine import ScanResult
from scanner_engine import REFRESH_MODE_EXISTING_ONLY
from scanner_engine import REFRESH_MODE_LIVE_GATED_FORCE
from scanner_engine import REFRESH_MODE_LIVE_GATED_IF_NEEDED
from scanners import dependency_parsers, report_generator
from scanners.malicious_checker import MaliciousPackageChecker


REPO_ROOT = os.path.dirname(os.path.dirname(__file__))
COLLECTORS_DIR = os.path.join(REPO_ROOT, "collectors")


def _import_orchestrator():
    return importlib.import_module("collectors.orchestrator")


class ScannerRegressionTests(unittest.TestCase):
    def _build_packages(self, names, source="osv"):
        return [
            {
                "name": name,
                "versions": ["1.0.0"],
                "sources": [source],
                "severity": "critical",
                "description": f"Malicious package {name}",
                "detected_behaviors": ["malicious_code"],
            }
            for name in names
        ]

    def _write_database(self, final_data_dir, ecosystem, packages, sources=None):
        os.makedirs(final_data_dir, exist_ok=True)
        db_path = os.path.join(final_data_dir, f"unified_{ecosystem}.db")
        conn, temp_db_path = collector_db.create_database(db_path)
        collector_db.insert_packages(conn, packages)
        collector_db.insert_metadata(
            conn,
            ecosystem=ecosystem,
            packages=packages,
            timestamp="2026-04-02T00:00:00Z",
            extra_metadata={
                "data_status": "complete",
                "sources_used": sources or ["openssf", "osv"],
                "experimental_sources_used": [],
                "last_successful_collect": "2026-04-02T00:00:00Z",
            },
        )
        collector_db.finalize_database(conn, temp_db_path, db_path)

    def _create_temp_checker(self, temp_dir, ecosystem, packages):
        collectors_dir = os.path.join(temp_dir, "collectors")
        final_data_dir = os.path.join(collectors_dir, "final-data")
        os.makedirs(final_data_dir, exist_ok=True)
        db_path = os.path.join(final_data_dir, f"unified_{ecosystem}.db")

        conn, temp_db_path = collector_db.create_database(db_path)
        collector_db.insert_packages(conn, packages)
        collector_db.insert_metadata(
            conn,
            ecosystem=ecosystem,
            packages=packages,
            timestamp="2026-03-31T00:00:00Z",
        )
        collector_db.finalize_database(conn, temp_db_path, db_path)

        return MaliciousPackageChecker(collectors_dir=collectors_dir)

    def test_aggregate_package_locations_keeps_same_name_across_ecosystems(self):
        aggregated = scanner.aggregate_package_locations(
            [
                {"name": "requests", "version": "1.0.0", "ecosystem": "npm"},
                {"name": "requests", "version": "1.0.0", "ecosystem": "pypi"},
            ],
            ".",
        )

        self.assertEqual(len(aggregated), 2)
        self.assertEqual({pkg["ecosystem"] for pkg in aggregated}, {"npm", "pypi"})

    def test_aggregate_package_locations_skips_out_of_tree_locations(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            scanned_dir = os.path.join(temp_dir, "scanned")
            outside_dir = os.path.join(temp_dir, "outside")
            os.makedirs(scanned_dir, exist_ok=True)
            os.makedirs(outside_dir, exist_ok=True)

            inside_path = os.path.join(scanned_dir, "package.json")
            outside_path = os.path.join(outside_dir, "package.json")
            with open(inside_path, "w", encoding="utf-8") as handle:
                handle.write("{}\n")
            with open(outside_path, "w", encoding="utf-8") as handle:
                handle.write("{}\n")

            packages = [
                {
                    "name": "inside-pkg",
                    "version": "1.0.0",
                    "ecosystem": "npm",
                    "physical_location": {
                        "artifact_location": {"uri": inside_path},
                        "region": {
                            "start_line": 1,
                            "start_column": 1,
                            "end_line": 1,
                            "end_column": 10,
                        },
                    },
                },
                {
                    "name": "outside-pkg",
                    "version": "1.0.0",
                    "ecosystem": "npm",
                    "physical_location": {
                        "artifact_location": {"uri": outside_path},
                        "region": {
                            "start_line": 1,
                            "start_column": 1,
                            "end_line": 1,
                            "end_column": 10,
                        },
                    },
                },
            ]

            with self.assertLogs("scanner_engine", level="WARNING") as captured:
                aggregated = scanner.aggregate_package_locations(packages, scanned_dir)

        by_name = {pkg["name"]: pkg for pkg in aggregated}
        self.assertEqual(
            by_name["inside-pkg"]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "package.json",
        )
        self.assertEqual(by_name["outside-pkg"]["locations"], [])
        self.assertIn("Skipping package location outside scanned path", "\n".join(captured.output))

    def test_scan_directory_returns_four_tuple_when_ecosystem_missing(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertLogs("scanner_engine", level="ERROR") as captured:
                result = scanner.scan_directory(temp_dir, scan_iocs=False)

        self.assertEqual(len(result), 4)
        self.assertEqual(result[0], None)
        self.assertEqual(result[1], [])
        self.assertEqual(result[3], [])
        self.assertIn("Could not detect ecosystem in directory", "\n".join(captured.output))

    def test_scan_file_returns_four_tuple_when_ecosystem_missing(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as temp_file:
            temp_file.write("requests\n")
            temp_path = temp_file.name

        try:
            with self.assertLogs("scanner_engine", level="ERROR") as captured:
                result = scanner.scan_file(temp_path, scan_iocs=False)
        finally:
            os.unlink(temp_path)

        self.assertEqual(len(result), 4)
        self.assertEqual(result[0], None)
        self.assertEqual(result[1], [])
        self.assertEqual(result[3], [])
        self.assertIn("Could not determine ecosystem for file", "\n".join(captured.output))

    def test_scan_file_uses_generic_parser_for_explicit_ecosystem_package_lists(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as temp_file:
            temp_file.write("requests@2.32.0\nflask\n")
            temp_path = temp_file.name

        try:
            with self.assertLogs("scanner_engine", level="INFO"):
                ecosystem, packages, _, _ = scanner.scan_file(
                    temp_path,
                    ecosystem="pypi",
                    scan_iocs=False,
                )
        finally:
            os.unlink(temp_path)

        self.assertEqual(ecosystem, "pypi")
        self.assertEqual(
            [(pkg["name"], pkg["version"], pkg["ecosystem"]) for pkg in packages],
            [("requests", "2.32.0", "pypi"), ("flask", "", "pypi")],
        )

    def test_cli_ioc_only_disables_ensure_data(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as temp_file:
            temp_file.write("requests==2.32.0\n")
            temp_path = temp_file.name

        try:
            with patch("malicious_package_scanner.run_scan") as run_scan:
                run_scan.return_value = ScanResult(
                    ecosystem="pypi",
                    scanned_path=temp_path,
                    requested_ecosystems=["pypi"],
                    packages=[],
                    malicious_packages=[],
                    iocs=[],
                    report_path=None,
                    data_metadata={},
                    exit_code=0,
                    message="ok",
                )
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    scanner.main(["--file", temp_path, "--ecosystem", "pypi", "--ioc-only"])
        finally:
            os.unlink(temp_path)

        request = run_scan.call_args.args[0]
        self.assertFalse(request.ensure_data)
        self.assertEqual(request.refresh_mode, REFRESH_MODE_EXISTING_ONLY)

    def test_cli_uses_gated_refresh_mode_by_default(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as temp_file:
            temp_file.write("requests==2.32.0\n")
            temp_path = temp_file.name

        try:
            with patch("malicious_package_scanner.run_scan") as run_scan:
                run_scan.return_value = ScanResult(
                    ecosystem="pypi",
                    scanned_path=temp_path,
                    requested_ecosystems=["pypi"],
                    packages=[],
                    malicious_packages=[],
                    iocs=[],
                    report_path=None,
                    data_metadata={},
                    exit_code=0,
                    message="ok",
                )
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    scanner.main(["--file", temp_path, "--ecosystem", "pypi", "--no-ioc"])
        finally:
            os.unlink(temp_path)

        request = run_scan.call_args.args[0]
        self.assertTrue(request.ensure_data)
        self.assertEqual(request.refresh_mode, REFRESH_MODE_LIVE_GATED_IF_NEEDED)

    def test_cli_latest_data_uses_live_gated_force(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as temp_file:
            temp_file.write("requests==2.32.0\n")
            temp_path = temp_file.name

        try:
            with patch("malicious_package_scanner.run_scan") as run_scan:
                run_scan.return_value = ScanResult(
                    ecosystem="pypi",
                    scanned_path=temp_path,
                    requested_ecosystems=["pypi"],
                    packages=[],
                    malicious_packages=[],
                    iocs=[],
                    report_path=None,
                    data_metadata={},
                    exit_code=0,
                    message="ok",
                )
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    scanner.main(["--file", temp_path, "--ecosystem", "pypi", "--latest-data", "--no-ioc"])
        finally:
            os.unlink(temp_path)

        request = run_scan.call_args.args[0]
        self.assertEqual(request.refresh_mode, REFRESH_MODE_LIVE_GATED_FORCE)

    def test_ensure_threat_data_force_update_runs_gated_live_refresh(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch(
                "scanner_engine._load_live_update_runtime",
                return_value=(temp_dir, {"enabled": True}, temp_dir),
            ):
                with patch("scanner_engine._perform_gated_live_refresh") as gated_refresh:
                    gated_refresh.return_value = {
                        "success": True,
                        "database_statuses": {},
                        "used_live_collection": True,
                        "promotion_decision": "promoted",
                        "kept_last_known_good": False,
                        "anomalies": [],
                    }
                    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                        summary = scanner.ensure_threat_data(force_update=True)

        self.assertTrue(summary["success"])
        self.assertTrue(summary["used_live_collection"])
        gated_refresh.assert_called_once()

    def test_ensure_threat_data_uses_existing_database_statuses_when_ready(self):
        orchestrator = _import_orchestrator()
        ready_statuses = {
            "npm": {
                "usable": True,
                "data_status": "complete",
                "sources_used": ["openssf", "osv"],
                "experimental_sources_used": [],
                "metadata_ready": True,
                "exists": True,
            }
        }

        with patch.object(orchestrator, "databases_need_refresh", return_value=False):
            with patch.object(orchestrator, "get_database_statuses", return_value=ready_statuses):
                summary = scanner.ensure_threat_data(force_update=False)

        self.assertTrue(summary["success"])
        self.assertEqual(summary["database_statuses"], ready_statuses)

    def test_check_databases_exist_requires_all_expected_databases(self):
        orchestrator = _import_orchestrator()
        ecosystems = ["npm", "pypi", "rubygems", "go", "maven", "cargo"]

        with tempfile.TemporaryDirectory() as temp_dir:
            raw_dir = os.path.join(temp_dir, "raw-data")
            final_dir = os.path.join(temp_dir, "final-data")
            os.makedirs(raw_dir, exist_ok=True)
            os.makedirs(final_dir, exist_ok=True)

            with patch.object(orchestrator, "_get_directories", return_value=(raw_dir, final_dir)):
                open(os.path.join(final_dir, "unified_npm.db"), "w", encoding="utf-8").close()
                self.assertFalse(orchestrator.check_databases_exist())

                for ecosystem in ecosystems:
                    open(
                        os.path.join(final_dir, f"unified_{ecosystem}.db"),
                        "a",
                        encoding="utf-8",
                    ).close()

                self.assertTrue(orchestrator.check_databases_exist())

    def test_collectors_and_utils_no_longer_raise_logger_nameerror(self):
        with patch.object(collect_osv, "download_ecosystem_data", return_value=None):
            with self.assertLogs("collectors.collect_osv", level="INFO"):
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    result = collect_osv.fetch_osv_packages()

        self.assertEqual(result["source"], "osv")

        with self.assertLogs("collectors.collect_socketdev", level="INFO"):
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                socketdev_result = collect_socketdev.fetch_socketdev_packages()
        self.assertEqual(socketdev_result["source"], "socketdev")

        with tempfile.NamedTemporaryFile("w", delete=False) as temp_file:
            temp_path = temp_file.name

        try:
            with self.assertLogs("collectors.utils", level="ERROR"):
                self.assertFalse(utils.ensure_directory(os.path.join(temp_path, "child")))
        finally:
            os.unlink(temp_path)

    def test_default_source_selection_excludes_experimental_sources(self):
        orchestrator = _import_orchestrator()

        self.assertEqual(orchestrator.resolve_sources(), ["openssf", "osv"])
        self.assertEqual(
            orchestrator.resolve_sources(include_experimental=True),
            ["openssf", "osv", "phylum"],
        )

    def test_orchestrator_import_does_not_require_repo_root_on_sys_path(self):
        original_sys_path = list(sys.path)
        original_cwd = os.getcwd()
        original_module = sys.modules.pop("orchestrator", None)
        importlib.invalidate_caches()

        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                os.chdir(temp_dir)
                trimmed_sys_path = []
                for entry in original_sys_path:
                    resolved_entry = os.path.realpath(entry or original_cwd)
                    if resolved_entry in {REPO_ROOT, COLLECTORS_DIR}:
                        continue
                    trimmed_sys_path.append(entry)
                sys.path = [COLLECTORS_DIR] + trimmed_sys_path
                orchestrator = importlib.import_module("orchestrator")
                self.assertTrue(callable(orchestrator.setup_logging))
        finally:
            os.chdir(original_cwd)
            sys.path = original_sys_path
            sys.modules.pop("orchestrator", None)
            if original_module is not None:
                sys.modules["orchestrator"] = original_module

    def test_load_orchestrator_helpers_uses_collectors_package_without_sys_path_mutation(self):
        original_sys_path = list(sys.path)

        helpers = engine._load_orchestrator_helpers()

        self.assertEqual(sys.path, original_sys_path)
        self.assertEqual(helpers[0].__module__, "collectors.orchestrator")

    def test_build_databases_only_loads_successful_sources(self):
        orchestrator = _import_orchestrator()

        with patch.object(
            orchestrator.build_unified_index,
            "load_all_raw_data",
            return_value=[],
        ) as load_all_raw_data:
            with self.assertLogs("collectors.orchestrator", level="INFO"):
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    summary = orchestrator.build_databases(
                        selected_sources=["openssf", "osv"],
                        source_results={
                            "openssf": {"success": False},
                            "osv": {"success": True},
                        },
                    )

        self.assertFalse(summary["success"])
        load_all_raw_data.assert_called_once_with(["osv"], raw_data_dir=None)

    def test_gated_live_refresh_promotes_normal_candidate(self):
        orchestrator = _import_orchestrator()
        source_definitions = {
            "openssf": {"tier": "core"},
            "osv": {"tier": "core"},
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            active_final_dir = os.path.join(temp_dir, "active-final")
            promotion_root = os.path.join(temp_dir, "live-updates")
            active_packages = self._build_packages(["pkg-a", "pkg-b", "pkg-c"])
            candidate_packages = self._build_packages(["pkg-a", "pkg-b", "pkg-c", "pkg-d"])
            self._write_database(active_final_dir, "npm", active_packages)

            def fake_run_all_collectors(**_kwargs):
                return {
                    "openssf": {"success": True, "package_count": 4, "tier": "core", "error": ""},
                    "osv": {"success": True, "package_count": 4, "tier": "core", "error": ""},
                }

            def fake_build_databases(
                selected_sources=None,
                source_results=None,
                raw_data_dir=None,
                final_data_dir=None,
            ):
                self._write_database(final_data_dir, "npm", candidate_packages)
                return {
                    "success": True,
                    "database_statuses": orchestrator.get_database_statuses(
                        ecosystems=["npm"],
                        final_data_dir=final_data_dir,
                    ),
                    "build_results": {"npm": True},
                }

            helpers = (
                orchestrator.collect_all_data,
                fake_build_databases,
                orchestrator.databases_need_refresh,
                orchestrator.get_database_statuses,
                lambda include_experimental=False: ["openssf", "osv"],
                fake_run_all_collectors,
                ["npm"],
                source_definitions,
            )

            with patch("scanner_engine._load_orchestrator_helpers", return_value=helpers):
                summary = engine._perform_gated_live_refresh(
                    include_experimental_sources=False,
                    promotion_root=promotion_root,
                    live_updates_config={"enabled": True},
                    active_final_data_dir=active_final_dir,
                )

            self.assertTrue(summary["success"])
            self.assertEqual(summary["promotion_decision"], "promoted")
            self.assertFalse(summary["kept_last_known_good"])
            conn = collector_db.open_database(os.path.join(active_final_dir, "unified_npm.db"))
            try:
                self.assertEqual(len(collector_db.list_package_names(conn)), 4)
            finally:
                conn.close()
            self.assertTrue(os.path.exists(summary["active_summary_path"]))

    def test_gated_live_refresh_rejects_large_removal_and_keeps_last_known_good(self):
        orchestrator = _import_orchestrator()
        source_definitions = {
            "openssf": {"tier": "core"},
            "osv": {"tier": "core"},
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            active_final_dir = os.path.join(temp_dir, "active-final")
            promotion_root = os.path.join(temp_dir, "live-updates")
            active_packages = self._build_packages([f"pkg-{index}" for index in range(400)])
            candidate_packages = self._build_packages([f"pkg-{index}" for index in range(50)])
            self._write_database(active_final_dir, "npm", active_packages)

            def fake_run_all_collectors(**_kwargs):
                return {
                    "openssf": {"success": True, "package_count": 50, "tier": "core", "error": ""},
                    "osv": {"success": True, "package_count": 50, "tier": "core", "error": ""},
                }

            def fake_build_databases(
                selected_sources=None,
                source_results=None,
                raw_data_dir=None,
                final_data_dir=None,
            ):
                self._write_database(final_data_dir, "npm", candidate_packages)
                return {
                    "success": True,
                    "database_statuses": orchestrator.get_database_statuses(
                        ecosystems=["npm"],
                        final_data_dir=final_data_dir,
                    ),
                    "build_results": {"npm": True},
                }

            helpers = (
                orchestrator.collect_all_data,
                fake_build_databases,
                orchestrator.databases_need_refresh,
                orchestrator.get_database_statuses,
                lambda include_experimental=False: ["openssf", "osv"],
                fake_run_all_collectors,
                ["npm"],
                source_definitions,
            )

            with patch("scanner_engine._load_orchestrator_helpers", return_value=helpers):
                summary = engine._perform_gated_live_refresh(
                    include_experimental_sources=False,
                    promotion_root=promotion_root,
                    live_updates_config={"enabled": True},
                    active_final_data_dir=active_final_dir,
                )

            self.assertTrue(summary["success"])
            self.assertEqual(summary["promotion_decision"], "rejected")
            self.assertTrue(summary["kept_last_known_good"])
            self.assertTrue(summary["anomalies"])
            conn = collector_db.open_database(os.path.join(active_final_dir, "unified_npm.db"))
            try:
                self.assertEqual(len(collector_db.list_package_names(conn)), 400)
            finally:
                conn.close()

    def test_live_refresh_allows_partial_core_source_updates_by_default(self):
        report = evaluate_candidate(
            attempt_id="attempt-1",
            timestamp="2026-04-06T00:00:00Z",
            selected_sources=["openssf", "osv"],
            source_definitions={
                "openssf": {"tier": "core"},
                "osv": {"tier": "core"},
            },
            candidate_summary={
                "build_success": True,
                "build_results": {"npm": True},
                "ecosystems": {
                    "npm": {
                        "usable": True,
                        "data_status": "partial",
                        "total_packages": 100,
                    }
                },
                "source_counts": {
                    "openssf": {"success": False, "package_count": 0, "tier": "core", "error": "timeout"},
                    "osv": {"success": True, "package_count": 100, "tier": "core", "error": ""},
                },
            },
            active_summary={
                "npm": {
                    "usable": True,
                    "data_status": "complete",
                    "total_packages": 100,
                }
            },
            candidate_names={"npm": {"pkg-a", "pkg-b", "pkg-c"}},
            active_names={"npm": {"pkg-a", "pkg-b", "pkg-c"}},
            active_source_counts={
                "openssf": {"package_count": 500},
                "osv": {"package_count": 100},
            },
            live_update_config={},
        )

        self.assertEqual(report["decision"], "promoted")
        severities = {anomaly["code"]: anomaly["severity"] for anomaly in report["anomalies"]}
        self.assertEqual(severities["core_source_failed"], "warn")
        self.assertEqual(severities["ecosystem_regressed"], "warn")

    def test_pyproject_dependencies_are_parsed_from_real_pyproject_filename(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            pyproject_path = os.path.join(temp_dir, "pyproject.toml")
            with open(pyproject_path, "w", encoding="utf-8") as f:
                f.write(
                    "[project]\n"
                    "dependencies = [\n"
                    '  "requests>=2.31",\n'
                    '  "flask==3.0.0"\n'
                    "]\n"
                )

            packages = dependency_parsers.parse_dependencies(pyproject_path, "pypi")

        self.assertEqual(
            [(pkg["name"], pkg["version"]) for pkg in packages],
            [("requests", ""), ("flask", "3.0.0")],
        )

    def test_build_gradle_dependencies_are_parsed(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            gradle_path = os.path.join(temp_dir, "build.gradle")
            with open(gradle_path, "w", encoding="utf-8") as f:
                f.write(
                    'plugins { id "java" }\n'
                    'dependencies { implementation "org.slf4j:slf4j-api:2.0.13" }\n'
                )

            packages = dependency_parsers.parse_dependencies(gradle_path, "maven")

        self.assertEqual(
            [(pkg["name"], pkg["version"]) for pkg in packages],
            [("org.slf4j:slf4j-api", "2.0.13")],
        )

    def test_package_json_exact_versions_are_preserved_for_matching(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            package_json_path = os.path.join(temp_dir, "package.json")
            with open(package_json_path, "w", encoding="utf-8") as f:
                f.write(
                    "{\n"
                    '  "dependencies": {\n'
                    '    "debug": "4.3.1"\n'
                    "  },\n"
                    '  "devDependencies": {\n'
                    '    "eslint-config-prettier": "8.6.0",\n'
                    '    "eslint-plugin-prettier": "5.1.3"\n'
                    "  }\n"
                    "}\n"
                )

            packages = dependency_parsers.parse_npm_dependencies(package_json_path)

        self.assertEqual(
            [(pkg["name"], pkg["version"]) for pkg in packages],
            [
                ("debug", "4.3.1"),
                ("eslint-config-prettier", "8.6.0"),
                ("eslint-plugin-prettier", "5.1.3"),
            ],
        )

    def test_package_json_exact_version_does_not_false_positive_on_other_malicious_version(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            checker = self._create_temp_checker(
                temp_dir,
                "npm",
                [
                    {
                        "name": "debug",
                        "versions": ["4.4.2"],
                        "sources": ["osv"],
                        "severity": "critical",
                        "description": "Malicious debug release",
                        "detected_behaviors": ["malicious_code"],
                    }
                ],
            )

            results = checker.check_packages(
                [{"name": "debug", "version": "4.3.1"}],
                "npm",
                include_shai_hulud=False,
            )

        self.assertEqual(results, [])

    def test_unknown_requirement_version_is_conservatively_flagged(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            checker = self._create_temp_checker(
                temp_dir,
                "pypi",
                [
                    {
                        "name": "evilpkg",
                        "versions": ["1.0.0"],
                        "sources": ["osv"],
                        "severity": "critical",
                        "description": "Malicious release of evilpkg",
                        "detected_behaviors": ["malicious_code"],
                    }
                ],
            )

            results = checker.check_packages(
                [{"name": "evilpkg", "version": ""}],
                "pypi",
                include_shai_hulud=False,
            )

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["name"], "evilpkg")
        self.assertEqual(results[0]["matched_version"], "1.0.0")

    def test_shai_hulud_exact_versions_keep_prereleases_distinct_but_allow_leading_v(self):
        checker = MaliciousPackageChecker(collectors_dir=COLLECTORS_DIR)
        checker._shai_hulud_cache = {"pkg": {"1.2.3"}}
        checker._shai_hulud_loaded = True

        prerelease_results = checker._check_shai_hulud_packages(
            [{"name": "pkg", "version": "1.2.3-beta.1"}]
        )
        exact_results = checker._check_shai_hulud_packages(
            [{"name": "pkg", "version": "v1.2.3"}]
        )

        self.assertEqual(prerelease_results, [])
        self.assertEqual(len(exact_results), 1)
        self.assertEqual(exact_results[0]["matched_version"], "v1.2.3")

    def test_litellm_exact_requirement_stays_exact_while_range_becomes_unknown(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            requirements_path = os.path.join(temp_dir, "requirements.txt")
            with open(requirements_path, "w", encoding="utf-8") as f:
                f.write(
                    "litellm==1.52.3\n"
                    "fastapi~=0.115.0\n"
                    "openai>=1.40.0,<2\n"
                )

            packages = dependency_parsers.parse_dependencies(requirements_path, "pypi")

        self.assertEqual(
            [(pkg["name"], pkg["version"]) for pkg in packages],
            [("litellm", "1.52.3"), ("fastapi", ""), ("openai", "")],
        )

    def test_safe_zip_extract_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            zip_path = os.path.join(temp_dir, "bad.zip")
            extract_dir = os.path.join(temp_dir, "extract")
            os.makedirs(extract_dir, exist_ok=True)
            escape_target = os.path.join(temp_dir, "escape.txt")

            with zipfile.ZipFile(zip_path, "w") as zf:
                zf.writestr("../escape.txt", "owned")

            with zipfile.ZipFile(zip_path, "r") as zf:
                with self.assertRaises(ValueError):
                    collect_osv._safe_extract_zip(zf, extract_dir)

            self.assertFalse(os.path.exists(escape_target))

    def test_openssf_live_collection_runs_without_extra_opt_in(self):
        clone_result = type("CloneResult", (), {"returncode": 0, "stderr": ""})()
        with patch("collectors.collect_openssf.os.path.exists", return_value=False):
            with patch("collectors.collect_openssf.subprocess.run", return_value=clone_result) as mocked_run:
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    result = collect_openssf.clone_or_update_repo()

        self.assertEqual(result, collect_openssf.CACHE_DIR)
        mocked_run.assert_called_once()

    def test_openssf_cached_repo_updates_when_present(self):
        with patch("collectors.collect_openssf.os.path.exists", return_value=True):
            with patch("collectors.collect_openssf.subprocess.run") as mocked_run:
                with self.assertLogs("collectors.collect_openssf", level="INFO"):
                    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                        result = collect_openssf.clone_or_update_repo()

        self.assertEqual(result, collect_openssf.CACHE_DIR)
        mocked_run.assert_called_once()

    def test_malicious_checker_uses_repo_collectors_db_module(self):
        import scanners.malicious_checker as checker_module

        expected_path = os.path.realpath(os.path.join(COLLECTORS_DIR, "db.py"))
        actual_path = os.path.realpath(checker_module.db.__file__)

        self.assertEqual(actual_path, expected_path)

    def test_notifications_normalize_project_path_aliases(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            project_dir = os.path.join(temp_dir, "project")
            alias_root = os.path.join(temp_dir, "alias-root")
            alias_project = os.path.join(alias_root, "project")
            db_path = os.path.join(temp_dir, "state.db")
            os.makedirs(project_dir, exist_ok=True)
            os.symlink(temp_dir, alias_root)

            state = MonitorState(db_path)
            state.add_notification(alias_project, "dependency_blocked", "blocked message")

            notifications = state.list_recent_notifications(project_path=project_dir)

        self.assertEqual(len(notifications), 1)
        self.assertEqual(notifications[0]["project_path"], os.path.realpath(project_dir))

    def test_cargo_lock_dependencies_are_parsed(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            cargo_lock_path = os.path.join(temp_dir, "Cargo.lock")
            with open(cargo_lock_path, "w", encoding="utf-8") as f:
                f.write('[[package]]\nname = "serde"\nversion = "1.0.203"\n')

            packages = dependency_parsers.parse_dependencies(cargo_lock_path, "cargo")

        self.assertEqual(
            [(pkg["name"], pkg["version"]) for pkg in packages],
            [("serde", "1.0.203")],
        )

    def test_summarize_requested_data_status_marks_partial_when_any_ecosystem_unavailable(self):
        summary = scanner.summarize_requested_data_status(
            ["npm", "pypi"],
            {
                "npm": {
                    "usable": True,
                    "data_status": "complete",
                    "sources_used": ["openssf", "osv"],
                    "experimental_sources_used": [],
                },
                "pypi": {
                    "usable": False,
                    "data_status": "failed",
                    "sources_used": [],
                    "experimental_sources_used": [],
                },
            },
        )

        self.assertEqual(summary["data_status"], "partial")
        self.assertEqual(summary["missing_ecosystems"], ["pypi"])

    def test_generate_report_includes_threat_data_metadata(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = os.path.join(temp_dir, "report.json")
            report_generator.generate_report(
                ecosystem="npm",
                scanned_path=temp_dir,
                total_packages_scanned=1,
                malicious_packages=[],
                iocs=[],
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

            with open(report_path, "r", encoding="utf-8") as f:
                report = json.load(f)

        self.assertEqual(report["data_status"], "partial")
        self.assertEqual(report["sources_used"], ["openssf", "osv"])
        self.assertEqual(report["experimental_sources_used"], ["phylum"])
        self.assertEqual(report["missing_ecosystems"], ["pypi"])
        self.assertEqual(report["promotion_decision"], "rejected")
        self.assertTrue(report["kept_last_known_good"])
        self.assertEqual(report["anomalies"][0]["message"], "count drop")


if __name__ == "__main__":
    unittest.main()
