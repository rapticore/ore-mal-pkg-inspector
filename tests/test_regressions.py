import importlib
import json
import os
import sys
import tempfile
import unittest
import zipfile
from unittest.mock import patch

import malicious_package_scanner as scanner
from collectors import collect_openssf, collect_osv, collect_socketdev, db as collector_db, utils
from scanner_engine import ScanResult
from scanners import dependency_parsers, report_generator
from scanners.malicious_checker import MaliciousPackageChecker


REPO_ROOT = os.path.dirname(os.path.dirname(__file__))
COLLECTORS_DIR = os.path.join(REPO_ROOT, "collectors")


def _import_orchestrator():
    if COLLECTORS_DIR not in sys.path:
        sys.path.insert(0, COLLECTORS_DIR)
    return importlib.import_module("orchestrator")


class ScannerRegressionTests(unittest.TestCase):
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

    def test_scan_directory_returns_four_tuple_when_ecosystem_missing(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            result = scanner.scan_directory(temp_dir, scan_iocs=False)

        self.assertEqual(len(result), 4)
        self.assertEqual(result[0], None)
        self.assertEqual(result[1], [])
        self.assertEqual(result[3], [])

    def test_scan_file_returns_four_tuple_when_ecosystem_missing(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as temp_file:
            temp_file.write("requests\n")
            temp_path = temp_file.name

        try:
            result = scanner.scan_file(temp_path, scan_iocs=False)
        finally:
            os.unlink(temp_path)

        self.assertEqual(len(result), 4)
        self.assertEqual(result[0], None)
        self.assertEqual(result[1], [])
        self.assertEqual(result[3], [])

    def test_scan_file_uses_generic_parser_for_explicit_ecosystem_package_lists(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as temp_file:
            temp_file.write("requests@2.32.0\nflask\n")
            temp_path = temp_file.name

        try:
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

    def test_cli_defaults_to_existing_local_threat_data_only(self):
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
                scanner.main(["--file", temp_path, "--ecosystem", "pypi", "--no-ioc"])
        finally:
            os.unlink(temp_path)

        request = run_scan.call_args.args[0]
        self.assertFalse(request.ensure_data)
        self.assertFalse(request.allow_unverified_live_collection)

    def test_cli_requires_explicit_flag_for_unverified_live_collection(self):
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
                scanner.main(
                    [
                        "--file",
                        temp_path,
                        "--ecosystem",
                        "pypi",
                        "--no-ioc",
                        "--allow-unverified-live-collection",
                    ]
                )
        finally:
            os.unlink(temp_path)

        request = run_scan.call_args.args[0]
        self.assertTrue(request.ensure_data)
        self.assertTrue(request.allow_unverified_live_collection)

    def test_ensure_threat_data_force_update_requires_explicit_live_opt_in(self):
        orchestrator = _import_orchestrator()
        empty_statuses = {
            ecosystem: {
                "usable": False,
                "data_status": "failed",
                "sources_used": [],
                "experimental_sources_used": [],
                "metadata_ready": False,
                "exists": False,
            }
            for ecosystem in ["npm", "pypi", "rubygems", "go", "maven", "cargo"]
        }

        with patch.object(
            orchestrator,
            "collect_all_data",
            return_value={"success": True, "database_statuses": {}},
        ) as collect:
            with patch.object(orchestrator, "get_database_statuses", return_value=empty_statuses):
                summary = scanner.ensure_threat_data(force_update=True)

        self.assertFalse(summary["success"])
        self.assertTrue(summary["refresh_required"])
        self.assertIn("explicit opt-in", summary["message"])
        collect.assert_not_called()

    def test_ensure_threat_data_force_update_collects_when_explicitly_opted_in(self):
        orchestrator = _import_orchestrator()
        with patch.object(
            orchestrator,
            "collect_all_data",
            return_value={"success": True, "database_statuses": {}},
        ) as collect:
            summary = scanner.ensure_threat_data(
                force_update=True,
                allow_unverified_live_collection=True,
            )

        self.assertTrue(summary["success"])
        self.assertTrue(summary["used_live_collection"])
        collect.assert_called_once_with(
            build_if_missing=False,
            include_experimental=False,
        )

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
            result = collect_osv.fetch_osv_packages()

        self.assertEqual(result["source"], "osv")

        socketdev_result = collect_socketdev.fetch_socketdev_packages()
        self.assertEqual(socketdev_result["source"], "socketdev")

        with tempfile.NamedTemporaryFile("w", delete=False) as temp_file:
            temp_path = temp_file.name

        try:
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

    def test_build_databases_only_loads_successful_sources(self):
        orchestrator = _import_orchestrator()

        with patch.object(
            orchestrator.build_unified_index,
            "load_all_raw_data",
            return_value=[],
        ) as load_all_raw_data:
            summary = orchestrator.build_databases(
                selected_sources=["openssf", "osv"],
                source_results={
                    "openssf": {"success": False},
                    "osv": {"success": True},
                },
            )

        self.assertFalse(summary["success"])
        load_all_raw_data.assert_called_once_with(["osv"])

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

    def test_openssf_live_collection_requires_explicit_opt_in(self):
        with patch.dict(os.environ, {}, clear=False):
            with patch("collectors.collect_openssf.os.path.exists", return_value=False):
                with patch("collectors.collect_openssf.subprocess.run") as mocked_run:
                    result = collect_openssf.clone_or_update_repo()

        self.assertIsNone(result)
        mocked_run.assert_not_called()

    def test_openssf_cached_repo_is_ignored_without_explicit_opt_in(self):
        with patch.dict(os.environ, {}, clear=False):
            with patch("collectors.collect_openssf.os.path.exists", return_value=True):
                with patch("collectors.collect_openssf.subprocess.run") as mocked_run:
                    result = collect_openssf.clone_or_update_repo()

        self.assertIsNone(result)
        mocked_run.assert_not_called()

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
                },
            )

            with open(report_path, "r", encoding="utf-8") as f:
                report = json.load(f)

        self.assertEqual(report["data_status"], "partial")
        self.assertEqual(report["sources_used"], ["openssf", "osv"])
        self.assertEqual(report["experimental_sources_used"], ["phylum"])
        self.assertEqual(report["missing_ecosystems"], ["pypi"])


if __name__ == "__main__":
    unittest.main()
