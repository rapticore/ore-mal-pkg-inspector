import pathlib
import tomllib
import unittest


class PackagingMetadataTests(unittest.TestCase):
    def test_pyproject_declares_supported_runtime_and_console_entrypoint(self):
        repo_root = pathlib.Path(__file__).resolve().parent.parent
        pyproject_path = repo_root / "pyproject.toml"

        with pyproject_path.open("rb") as handle:
            data = tomllib.load(handle)

        project = data["project"]
        self.assertEqual(project["name"], "orewatch")
        self.assertEqual(project["requires-python"], ">=3.14")
        self.assertEqual(
            project["scripts"]["orewatch"],
            "malicious_package_scanner:main",
        )
        self.assertEqual(
            project["scripts"]["ore-mal-pkg-inspector"],
            "malicious_package_scanner:main",
        )
        self.assertEqual(
            data["build-system"]["requires"],
            ["setuptools==80.9.0", "wheel==0.45.1"],
        )
        self.assertEqual(
            project["dependencies"],
            [
                "PyYAML==6.0.3",
                "requests==2.33.1",
                "beautifulsoup4==4.14.3",
                "packaging==26.0",
                "defusedxml==0.7.1",
            ],
        )
        self.assertEqual(
            data["tool"]["setuptools"]["package-data"]["scanners"],
            ["affected_packages.yaml"],
        )


if __name__ == "__main__":
    unittest.main()
