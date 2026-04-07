import contextlib
import io
import pathlib
import tomllib
import unittest

import malicious_package_scanner


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
            ["setuptools>=80", "wheel>=0.45"],
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
        self.assertEqual(
            data["tool"]["setuptools"]["package-data"]["monitor"],
            ["assets/*.png"],
        )

    def test_packaged_entrypoint_exposes_monitor_quickstart(self):
        stdout = io.StringIO()
        with self.assertRaises(SystemExit) as context:
            with contextlib.redirect_stdout(stdout):
                malicious_package_scanner.main(["monitor", "quickstart", "--help"])

        self.assertEqual(context.exception.code, 0)
        output = stdout.getvalue()
        self.assertIn("monitor quickstart", output)
        self.assertIn("--client", output)
        self.assertIn("--service-manager", output)


if __name__ == "__main__":
    unittest.main()
