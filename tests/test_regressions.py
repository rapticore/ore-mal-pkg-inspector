import importlib
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

import malicious_package_scanner as scanner
from collectors import collect_osv, collect_socketdev, utils
from scanners import dependency_parsers, report_generator


REPO_ROOT = os.path.dirname(os.path.dirname(__file__))
COLLECTORS_DIR = os.path.join(REPO_ROOT, "collectors")


def _import_orchestrator():
    if COLLECTORS_DIR not in sys.path:
        sys.path.insert(0, COLLECTORS_DIR)
    return importlib.import_module("orchestrator")


class ScannerRegressionTests(unittest.TestCase):
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

    def test_ensure_threat_data_force_update_always_rebuilds(self):
        orchestrator = _import_orchestrator()

        with patch.object(
            orchestrator,
            "collect_all_data",
            return_value={"success": True, "database_statuses": {}},
        ) as collect:
            with patch.object(orchestrator, "check_databases_exist", return_value=True):
                self.assertTrue(scanner.ensure_threat_data(force_update=True))

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
            [("requests", "2.31"), ("flask", "3.0.0")],
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
