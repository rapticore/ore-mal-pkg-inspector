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


if __name__ == "__main__":
    unittest.main()
