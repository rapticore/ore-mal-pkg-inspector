import os
import unittest

from scanners import dependency_parsers, ecosystem_detector
from scanners.supported_files import SUPPORTED_MANIFESTS, get_supported_manifest_filenames


FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "manifests")


EXPECTED_PACKAGES = {
    "package.json": [("lodash", "4.17.21"), ("jest", "29.7.0")],
    "package-lock.json": [("lodash", "4.17.21")],
    "yarn.lock": [("lodash", "4.17.21")],
    "pnpm-lock.yaml": [("lodash", "4.17.21")],
    "requirements.txt": [("requests", "2.32.0"), ("flask", "3.0.0")],
    "setup.py": [("requests", "2.32.0")],
    "pyproject.toml": [("requests", "2.31"), ("flask", "3.0.0")],
    "Pipfile": [("requests", "2.32.0"), ("pytest", "8.3.3")],
    "poetry.lock": [("attrs", "24.2.0")],
    "pom.xml": [("org.slf4j:slf4j-api", "2.0.13")],
    "build.gradle": [("org.slf4j:slf4j-api", "2.0.13")],
    "Gemfile": [("rails", "7.1.3")],
    "Gemfile.lock": [("rails", "7.1.3")],
    "go.mod": [("github.com/stretchr/testify", "v1.9.0")],
    "go.sum": [("github.com/stretchr/testify", "v1.9.0")],
    "Cargo.toml": [("serde", "1.0.203")],
    "Cargo.lock": [("serde", "1.0.203")],
}


class ManifestFixtureTests(unittest.TestCase):
    def test_registry_and_detector_cover_same_filenames(self):
        self.assertEqual(
            sorted(get_supported_manifest_filenames()),
            sorted(EXPECTED_PACKAGES.keys()),
        )

        for manifest in SUPPORTED_MANIFESTS:
            with self.subTest(filename=manifest["filename"]):
                ecosystem = ecosystem_detector.detect_ecosystem_from_filename(
                    manifest["filename"]
                )
                self.assertEqual(ecosystem, manifest["ecosystem"])

    def test_each_supported_manifest_fixture_parses_expected_packages(self):
        for manifest in SUPPORTED_MANIFESTS:
            filename = manifest["filename"]
            fixture_path = os.path.join(FIXTURE_DIR, filename)
            with self.subTest(filename=filename):
                parsed = dependency_parsers.parse_dependencies(
                    fixture_path,
                    manifest["ecosystem"],
                )
                self.assertEqual(
                    [(pkg["name"], pkg["version"]) for pkg in parsed],
                    EXPECTED_PACKAGES[filename],
                )


if __name__ == "__main__":
    unittest.main()
