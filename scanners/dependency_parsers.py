#!/usr/bin/env python3
"""
Dependency Parsers Module
Parses dependency files for various package ecosystems
"""

import ast
import json
import os
import re
import tomllib
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Tuple

from packaging.requirements import InvalidRequirement, Requirement
from scanners.supported_files import get_manifest_for_filename


SKIPPED_REQUIREMENT_PREFIXES = (
    "-r",
    "--",
    "git+",
    "hg+",
    "svn+",
    "bzr+",
    "http://",
    "https://",
    "file:",
    "./",
    "../",
)

NON_VERSION_SPEC_PREFIXES = (
    "workspace:",
    "file:",
    "link:",
    "git+",
    "github:",
    "gitlab:",
    "http://",
    "https://",
)

EXACT_VERSION_RE = re.compile(
    r"^[vV]?\d+(?:\.\d+)*(?:[-+._]?[A-Za-z0-9]+(?:[-+._][A-Za-z0-9]+)*)?$"
)


def _make_physical_location(
    file_path: str,
    start_line: int,
    start_column: int,
    end_column: int,
    end_line: Optional[int] = None,
) -> Dict:
    """Build a SARIF-compatible physical location."""
    return {
        "artifact_location": {"uri": file_path},
        "region": {
            "start_line": start_line,
            "start_column": start_column,
            "end_line": end_line or start_line,
            "end_column": end_column,
        },
    }


def _build_package(
    name: str,
    version: str,
    section: str,
    file_path: Optional[str] = None,
    line_num: Optional[int] = None,
    line_text: Optional[str] = None,
) -> Dict[str, str]:
    """Build a package dictionary with optional SARIF location data."""
    pkg = {
        "name": name,
        "version": version,
        "section": section,
    }

    if file_path and line_num and line_text is not None:
        start_column = line_text.find(name) + 1
        if start_column <= 0:
            start_column = 1
        end_column = start_column + len(name)
        pkg["physical_location"] = _make_physical_location(
            file_path,
            line_num,
            start_column,
            end_column,
        )

    return pkg


def _extract_first_version(version_spec: str) -> str:
    """Extract the first usable version token from a version specifier."""
    spec = str(version_spec or "").strip().strip("\"'")
    if not spec or spec == "*":
        return ""

    if spec.startswith(NON_VERSION_SPEC_PREFIXES):
        return ""

    if spec.startswith("npm:"):
        _, _, aliased_version = spec[4:].rpartition("@")
        return _extract_first_version(aliased_version) if aliased_version else ""

    if spec.startswith(("^", "~")):
        return spec[1:].strip()

    match = re.search(r"(?:===|==|~=|!=|>=|<=|>|<)\s*([^,;\s]+)", spec)
    if match:
        return match.group(1).strip("\"'")

    if EXACT_VERSION_RE.fullmatch(spec):
        return spec

    return ""


def _extract_exact_requirement_version(specifier_text: str) -> str:
    """Return an exact pinned requirement version, or empty string for ranges/unknowns."""
    spec = str(specifier_text or "").strip()
    if not spec:
        return ""

    match = re.fullmatch(r"(?:===|==)\s*([^,;\s]+)", spec)
    if not match:
        return ""

    version = match.group(1).strip("\"'")
    return "" if "*" in version else version


def _parse_requirement_string(requirement_str: str) -> Optional[Tuple[str, str]]:
    """Parse a Python requirement string into package name and first version token."""
    candidate = requirement_str.strip()
    if not candidate or candidate.startswith("#"):
        return None

    if " #" in candidate:
        candidate = candidate.split(" #", 1)[0].rstrip()

    if candidate.startswith("-e "):
        candidate = candidate[3:].strip()

    if candidate.startswith(SKIPPED_REQUIREMENT_PREFIXES):
        egg_match = re.search(r"#egg=([A-Za-z0-9_.-]+)", candidate)
        if egg_match:
            return egg_match.group(1), ""
        return None

    try:
        requirement = Requirement(candidate)
        return requirement.name, _extract_exact_requirement_version(str(requirement.specifier))
    except InvalidRequirement:
        match = re.match(r"^([A-Za-z0-9_.-]+(?:\[[^\]]+\])?)(.*)$", candidate)
        if not match:
            return None

        pkg_name = re.sub(r"\[.*\]", "", match.group(1))
        version = _extract_exact_requirement_version(match.group(2))
        return pkg_name, version


def _load_toml_file(file_path: str) -> Optional[Dict]:
    """Load a TOML file."""
    try:
        with open(file_path, "rb") as f:
            return tomllib.load(f)
    except (FileNotFoundError, OSError, ValueError):
        return None


def _find_package_location_in_json(
    lines: List[str], pkg_name: str, section: str
) -> Optional[Dict]:
    """
    Search for package name within a JSON section and return SARIF location.

    Args:
        lines: List of file lines
        pkg_name: Package name to search for
        section: Section name (e.g., 'dependencies', 'devDependencies')

    Returns:
        Dict with start_line, start_column, end_line, end_column or None
    """
    in_section = False
    for i, line in enumerate(lines, start=1):
        if f'"{section}"' in line and "{" in line:
            in_section = True
            continue
        if in_section and "}" in line:
            in_section = False
            continue
        if in_section and f'"{pkg_name}"' in line:
            match = re.search(rf'"{re.escape(pkg_name)}"', line)
            if match:
                return {
                    "start_line": i,
                    "start_column": match.start() + 2,
                    "end_line": i,
                    "end_column": match.end() - 1,
                }
    return None


def _find_name_in_lines(
    lines: List[str], name: str, start_line: int = 1
) -> Tuple[Optional[int], Optional[str]]:
    """Find the first line containing a package name."""
    for line_num in range(start_line, len(lines) + 1):
        line = lines[line_num - 1]
        if name in line:
            return line_num, line.rstrip("\n")
    return None, None


def _find_toml_assignment_line(
    lines: List[str], key: str, start_line: int = 1
) -> Tuple[Optional[int], Optional[str]]:
    """Find a TOML assignment line for a given key."""
    pattern = re.compile(rf'^\s*["\']?{re.escape(key)}["\']?\s*=')
    for line_num in range(start_line, len(lines) + 1):
        line = lines[line_num - 1]
        if pattern.search(line):
            return line_num, line.rstrip("\n")
    return None, None


def parse_npm_dependencies(file_path: str) -> List[Dict[str, str]]:
    """
    Parse npm dependencies from package.json or package-lock.json.

    Args:
        file_path: Path to package.json or package-lock.json

    Returns:
        List of dicts with 'name' and 'version' keys
    """
    filename = os.path.basename(file_path)

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            package_data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

    if filename == "package-lock.json":
        return _parse_package_lock(package_data)

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except FileNotFoundError:
        lines = []

    return _parse_package_json(package_data, file_path, lines)


def _parse_package_json(
    package_data: dict, file_path: str, lines: List[str]
) -> List[Dict[str, str]]:
    """Parse package.json dependency sections with SARIF location tracking."""
    packages = []
    deps_sections = [
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ]

    for section in deps_sections:
        if section not in package_data:
            continue

        for pkg_name, version_spec in package_data[section].items():
            clean_version = _extract_first_version(str(version_spec))

            location = None
            if lines:
                location = _find_package_location_in_json(lines, pkg_name, section)

            pkg_dict = {
                "name": pkg_name,
                "version": clean_version,
                "section": section,
            }

            if location:
                pkg_dict["physical_location"] = _make_physical_location(
                    file_path,
                    location["start_line"],
                    location["start_column"],
                    location["end_column"],
                    end_line=location["end_line"],
                )

            packages.append(pkg_dict)

    return packages


def _parse_package_lock(package_data: dict) -> List[Dict[str, str]]:
    """Parse package-lock.json dependencies."""
    packages = []

    def extract_from_deps(deps: dict):
        if not deps:
            return

        for pkg_name, pkg_info in deps.items():
            if not isinstance(pkg_info, dict):
                continue

            version = pkg_info.get("version", "")
            if version:
                packages.append(
                    {
                        "name": pkg_name,
                        "version": version,
                        "section": "lockfile",
                    }
                )

            if "dependencies" in pkg_info:
                extract_from_deps(pkg_info["dependencies"])

    if "dependencies" in package_data:
        extract_from_deps(package_data["dependencies"])

    if "packages" in package_data:
        for pkg_path, pkg_info in package_data["packages"].items():
            if not pkg_path or not isinstance(pkg_info, dict):
                continue

            version = pkg_info.get("version", "")
            if not version:
                continue

            pkg_name = pkg_path
            if "node_modules/" in pkg_path:
                pkg_name = pkg_path.rsplit("node_modules/", 1)[1]
                if pkg_name.startswith("@"):
                    parts = pkg_name.split("/")
                    pkg_name = "/".join(parts[:2])
                else:
                    pkg_name = pkg_name.split("/", 1)[0]

            packages.append(
                {
                    "name": pkg_name,
                    "version": version,
                    "section": "packages",
                }
            )

    return packages


def _extract_yarn_package_name(selector: str) -> Optional[str]:
    """Extract a package name from a yarn.lock selector."""
    selector = selector.strip().strip("\"'")
    if not selector:
        return None

    selector = selector.split(",", 1)[0].strip()
    if selector.startswith("@"):
        parts = selector.split("@")
        if len(parts) >= 3:
            return f"@{parts[1]}"
        return selector

    if "@" in selector:
        return selector.split("@", 1)[0]

    return None


def parse_yarn_lock_dependencies(file_path: str) -> List[Dict[str, str]]:
    """Parse yarn.lock dependencies."""
    packages = []

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except FileNotFoundError:
        return packages

    current_name = None
    current_line_num = None
    current_line_text = None

    for line_num, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if not line[:1].isspace():
            current_name = None
            current_line_num = None
            current_line_text = None

            if stripped.endswith(":"):
                current_name = _extract_yarn_package_name(stripped[:-1])
                current_line_num = line_num
                current_line_text = line.rstrip("\n")
            continue

        if not current_name:
            continue

        match = re.match(r'^version\s+["\']([^"\']+)["\']', stripped)
        if not match:
            match = re.match(r'^version:\s*["\']?([^"\']+)["\']?', stripped)

        if match:
            packages.append(
                _build_package(
                    current_name,
                    match.group(1),
                    "lockfile",
                    file_path,
                    current_line_num,
                    current_line_text,
                )
            )
            current_name = None

    return packages


def _parse_pnpm_package_key(package_key: str) -> Optional[Tuple[str, str]]:
    """Parse a pnpm package key into package name and version."""
    key = package_key.strip().strip("\"'")
    if key.startswith("/"):
        key = key[1:]

    key = key.split("(", 1)[0]
    if not key:
        return None

    split_at = key.rfind("@")
    if split_at <= 0:
        return None

    name = key[:split_at]
    version = key[split_at + 1 :]
    if version.startswith("npm:"):
        version = version[4:]

    if not name or not version:
        return None

    return name, version


def parse_pnpm_lock_dependencies(file_path: str) -> List[Dict[str, str]]:
    """Parse pnpm-lock.yaml dependencies from the packages section."""
    packages = []

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except FileNotFoundError:
        return packages

    in_packages_section = False

    for line_num, line in enumerate(lines, start=1):
        stripped = line.rstrip("\n")
        if stripped.strip() == "packages:":
            in_packages_section = True
            continue

        if in_packages_section and stripped and not line.startswith("  "):
            break

        if not in_packages_section:
            continue

        match = re.match(r'^\s{2,}["\']?(/?[^"\']+?)["\']?:\s*$', stripped)
        if not match:
            continue

        parsed = _parse_pnpm_package_key(match.group(1))
        if not parsed:
            continue

        name, version = parsed
        packages.append(
            _build_package(name, version, "lockfile", file_path, line_num, stripped)
        )

    return packages


def parse_pypi_dependencies(file_path: str) -> List[Dict[str, str]]:
    """
    Parse PyPI dependencies from requirements.txt.

    Args:
        file_path: Path to requirements.txt

    Returns:
        List of dicts with 'name' and 'version' keys
    """
    packages = []

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except FileNotFoundError:
        return packages

    for line_num, line in enumerate(lines, start=1):
        stripped = line.strip()
        parsed = _parse_requirement_string(stripped)
        if not parsed:
            continue

        pkg_name, version = parsed
        packages.append(
            _build_package(
                pkg_name,
                version,
                "requirements",
                file_path,
                line_num,
                line.rstrip("\n"),
            )
        )

    return packages


def _is_setup_call(node: ast.AST) -> bool:
    """Check if an AST node is a setup() call."""
    if not isinstance(node, ast.Call):
        return False

    if isinstance(node.func, ast.Name):
        return node.func.id == "setup"
    if isinstance(node.func, ast.Attribute):
        return node.func.attr == "setup"
    return False


def _extract_setup_requirement_entries(
    node: ast.AST,
    constants: Dict[str, ast.AST],
) -> List[Tuple[str, Optional[int]]]:
    """Extract requirement strings from setup.py AST nodes."""
    if isinstance(node, ast.Name) and node.id in constants:
        return _extract_setup_requirement_entries(constants[node.id], constants)

    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        entries = []
        for elt in node.elts:
            entries.extend(_extract_setup_requirement_entries(elt, constants))
        return entries

    if isinstance(node, ast.Dict):
        entries = []
        for value in node.values:
            entries.extend(_extract_setup_requirement_entries(value, constants))
        return entries

    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [(node.value, getattr(node, "lineno", None))]

    return []


def parse_setup_py_dependencies(file_path: str) -> List[Dict[str, str]]:
    """Parse install_requires-style dependencies from setup.py."""
    packages = []

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except FileNotFoundError:
        return packages

    try:
        tree = ast.parse("".join(lines), filename=file_path)
    except SyntaxError:
        return packages

    constants: Dict[str, ast.AST] = {}
    section_names = {
        "install_requires": "install_requires",
        "extras_require": "extras_require",
        "setup_requires": "setup_requires",
        "tests_require": "tests_require",
    }
    extracted: List[Tuple[str, str, Optional[int]]] = []

    for node in tree.body:
        if isinstance(node, ast.Assign):
            targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
            for target in targets:
                constants[target] = node.value
                if target in section_names:
                    for requirement, line_num in _extract_setup_requirement_entries(
                        node.value, constants
                    ):
                        extracted.append((requirement, section_names[target], line_num))

        if isinstance(node, ast.Expr) and _is_setup_call(node.value):
            for keyword in node.value.keywords:
                if keyword.arg not in section_names:
                    continue

                for requirement, line_num in _extract_setup_requirement_entries(
                    keyword.value, constants
                ):
                    extracted.append(
                        (requirement, section_names[keyword.arg], line_num)
                    )

    for requirement, section, line_num in extracted:
        parsed = _parse_requirement_string(requirement)
        if not parsed:
            continue

        pkg_name, version = parsed
        line_text = None
        if line_num and 0 < line_num <= len(lines):
            line_text = lines[line_num - 1].rstrip("\n")

        packages.append(
            _build_package(
                pkg_name,
                version,
                section,
                file_path if line_num else None,
                line_num,
                line_text,
            )
        )

    return packages


def _find_maven_dependency_location(
    xml_lines: List[str], artifact_id: str
) -> Optional[Dict]:
    """
    Search for artifactId tag in XML and return SARIF location.

    Args:
        xml_lines: List of XML file lines
        artifact_id: Artifact ID to search for

    Returns:
        Dict with start_line, start_column, end_line, end_column or None
    """
    pattern = rf"<artifactId>({re.escape(artifact_id)})</artifactId>"
    for i, line in enumerate(xml_lines, start=1):
        match = re.search(pattern, line)
        if match:
            return {
                "start_line": i,
                "start_column": match.start(1) + 1,
                "end_line": i,
                "end_column": match.end(1) + 1,
            }
    return None


def parse_maven_dependencies(file_path: str) -> List[Dict[str, str]]:
    """
    Parse Maven dependencies from pom.xml.

    Args:
        file_path: Path to pom.xml

    Returns:
        List of dicts with 'name' (groupId:artifactId) and 'version' keys
    """
    packages = []

    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
    except (FileNotFoundError, ET.ParseError):
        return packages

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            xml_lines = f.readlines()
    except FileNotFoundError:
        xml_lines = []

    ns = {"maven": "http://maven.apache.org/POM/4.0.0"}
    if root.tag.startswith("{"):
        ns_uri = root.tag[1:].split("}")[0]
        ns = {"maven": ns_uri}

    dependencies = root.findall(".//maven:dependency", ns)
    if not dependencies:
        dependencies = root.findall(".//dependency")

    for dep in dependencies:
        group_id_elem = dep.find("maven:groupId", ns)
        if group_id_elem is None:
            group_id_elem = dep.find("groupId")
        artifact_id_elem = dep.find("maven:artifactId", ns)
        if artifact_id_elem is None:
            artifact_id_elem = dep.find("artifactId")
        version_elem = dep.find("maven:version", ns)
        if version_elem is None:
            version_elem = dep.find("version")

        if group_id_elem is None or artifact_id_elem is None:
            continue

        group_id = group_id_elem.text.strip() if group_id_elem.text else ""
        artifact_id = artifact_id_elem.text.strip() if artifact_id_elem.text else ""
        version = version_elem.text.strip() if version_elem is not None and version_elem.text else ""
        pkg_name = f"{group_id}:{artifact_id}"

        location = None
        if xml_lines and artifact_id:
            location = _find_maven_dependency_location(xml_lines, artifact_id)

        pkg_dict = {
            "name": pkg_name,
            "version": version,
            "section": "dependencies",
        }

        if location:
            pkg_dict["physical_location"] = _make_physical_location(
                file_path,
                location["start_line"],
                location["start_column"],
                location["end_column"],
                end_line=location["end_line"],
            )

        packages.append(pkg_dict)

    return packages


def parse_gradle_dependencies(file_path: str) -> List[Dict[str, str]]:
    """Parse Maven-style dependencies from build.gradle."""
    packages = []

    direct_pattern = re.compile(
        r"""
        \b(?:api|implementation|compileOnly|runtimeOnly|testImplementation|
            testCompileOnly|testRuntimeOnly|annotationProcessor|kapt)\b
        \s*(?:\(\s*)?["']
        ([^:"']+):([^:"']+):([^"')]+)
        ["']
        """,
        re.VERBOSE,
    )
    map_pattern = re.compile(
        r"""
        \b(?:api|implementation|compileOnly|runtimeOnly|testImplementation|
            testCompileOnly|testRuntimeOnly|annotationProcessor|kapt)\b
        .*?group:\s*["']([^"']+)["']
        .*?name:\s*["']([^"']+)["']
        .*?version:\s*["']([^"']+)["']
        """,
        re.VERBOSE,
    )

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except FileNotFoundError:
        return packages

    for line_num, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue

        match = direct_pattern.search(line) or map_pattern.search(line)
        if not match:
            continue

        group_id, artifact_id, version = match.groups()
        packages.append(
            _build_package(
                f"{group_id}:{artifact_id}",
                version.strip(),
                "dependencies",
                file_path,
                line_num,
                line.rstrip("\n"),
            )
        )

    return packages


def parse_rubygems_dependencies(file_path: str) -> List[Dict[str, str]]:
    """
    Parse RubyGems dependencies from Gemfile.

    Args:
        file_path: Path to Gemfile

    Returns:
        List of dicts with 'name' and 'version' keys
    """
    packages = []

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
    except FileNotFoundError:
        return packages

    gem_pattern = r'gem\s+["\']([^"\']+)["\'](?:\s*,\s*["\']([^"\']+)["\'])?'

    for match in re.finditer(gem_pattern, content):
        gem_name = match.group(1)
        gem_version = match.group(2) if match.group(2) else ""

        start_line = content[: match.start()].count("\n") + 1
        line_start_pos = content.rfind("\n", 0, match.start()) + 1
        line_text = content[line_start_pos : content.find("\n", line_start_pos)]
        if line_text == "":
            line_text = content[line_start_pos:]

        packages.append(
            _build_package(
                gem_name,
                gem_version,
                "gems",
                file_path,
                start_line,
                line_text,
            )
        )

    return packages


def parse_gemfile_lock_dependencies(file_path: str) -> List[Dict[str, str]]:
    """Parse dependencies from Gemfile.lock."""
    packages = []

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except FileNotFoundError:
        return packages

    in_specs = False

    for line_num, line in enumerate(lines, start=1):
        stripped = line.rstrip("\n")
        if stripped.strip() == "specs:":
            in_specs = True
            continue

        if in_specs and line and not line.startswith("    "):
            in_specs = False

        if not in_specs:
            continue

        match = re.match(r"^\s{4}([A-Za-z0-9_.-]+) \(([^)]+)\)", stripped)
        if not match:
            continue

        gem_name, gem_version = match.groups()
        packages.append(
            _build_package(
                gem_name,
                gem_version,
                "lockfile",
                file_path,
                line_num,
                stripped,
            )
        )

    return packages


def parse_go_dependencies(file_path: str) -> List[Dict[str, str]]:
    """
    Parse Go dependencies from go.mod.

    Args:
        file_path: Path to go.mod

    Returns:
        List of dicts with 'name' (module path) and 'version' keys
    """
    packages = []

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except FileNotFoundError:
        return packages

    in_require_block = False

    for line_num, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue

        if stripped.startswith("require"):
            in_require_block = True
            if "(" not in stripped:
                parts = stripped.split()
                if len(parts) >= 3:
                    packages.append(
                        _build_package(
                            parts[1],
                            parts[2],
                            "require",
                            file_path,
                            line_num,
                            line.rstrip("\n"),
                        )
                    )
                in_require_block = False
            continue

        if stripped == ")" and in_require_block:
            in_require_block = False
            continue

        if in_require_block:
            dependency_part = stripped.split("//", 1)[0].strip()
            parts = dependency_part.split()
            if len(parts) >= 2:
                packages.append(
                    _build_package(
                        parts[0],
                        parts[1],
                        "require",
                        file_path,
                        line_num,
                        line.rstrip("\n"),
                    )
                )

    return packages


def parse_go_sum_dependencies(file_path: str) -> List[Dict[str, str]]:
    """Parse dependencies from go.sum."""
    packages = []

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except FileNotFoundError:
        return packages

    for line_num, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        parts = stripped.split()
        if len(parts) < 2:
            continue

        version = parts[1].removesuffix("/go.mod")
        packages.append(
            _build_package(
                parts[0],
                version,
                "sum",
                file_path,
                line_num,
                line.rstrip("\n"),
            )
        )

    return packages


def parse_cargo_dependencies(file_path: str) -> List[Dict[str, str]]:
    """
    Parse Cargo dependencies from Cargo.toml.

    Args:
        file_path: Path to Cargo.toml

    Returns:
        List of dicts with 'name' and 'version' keys
    """
    packages = []

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except FileNotFoundError:
        return packages

    in_dependencies = False

    for line_num, line in enumerate(lines, start=1):
        stripped = line.strip()

        if stripped.startswith("[") and stripped.endswith("]"):
            section_name = stripped.strip("[]")
            in_dependencies = section_name.endswith("dependencies")
            continue

        if not in_dependencies or not stripped or stripped.startswith("#") or "=" not in stripped:
            continue

        parts = stripped.split("=", 1)
        pkg_name = parts[0].strip().strip("\"'")
        version_part = parts[1].strip()
        version = ""

        if version_part.startswith(("\"", "'")):
            version_match = re.search(r'["\']([^"\']+)["\']', version_part)
            if version_match:
                version = version_match.group(1)
        elif "{" in version_part:
            version_match = re.search(
                r'version\s*=\s*["\']([^"\']+)["\']',
                version_part,
            )
            if version_match:
                version = version_match.group(1)

        packages.append(
            _build_package(
                pkg_name,
                version,
                "dependencies",
                file_path,
                line_num,
                line.rstrip("\n"),
            )
        )

    return packages


def parse_cargo_lock_dependencies(file_path: str) -> List[Dict[str, str]]:
    """Parse dependencies from Cargo.lock."""
    packages = []

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except FileNotFoundError:
        return packages

    current_name = None
    current_version = None
    current_name_line = None
    current_name_text = None

    for line_num, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped == "[[package]]":
            if current_name and current_version:
                packages.append(
                    _build_package(
                        current_name,
                        current_version,
                        "lockfile",
                        file_path,
                        current_name_line,
                        current_name_text,
                    )
                )
            current_name = None
            current_version = None
            current_name_line = None
            current_name_text = None
            continue

        name_match = re.match(r'^name\s*=\s*["\']([^"\']+)["\']', stripped)
        if name_match:
            current_name = name_match.group(1)
            current_name_line = line_num
            current_name_text = line.rstrip("\n")
            continue

        version_match = re.match(r'^version\s*=\s*["\']([^"\']+)["\']', stripped)
        if version_match:
            current_version = version_match.group(1)

    if current_name and current_version:
        packages.append(
            _build_package(
                current_name,
                current_version,
                "lockfile",
                file_path,
                current_name_line,
                current_name_text,
            )
        )

    return packages


def _extract_poetry_version(spec) -> str:
    """Extract a usable version string from a poetry dependency spec."""
    if isinstance(spec, str):
        return _extract_first_version(spec)
    if isinstance(spec, dict):
        return _extract_first_version(spec.get("version", ""))
    return ""


def parse_pyproject_dependencies(file_path: str) -> List[Dict[str, str]]:
    """Parse Python dependencies from pyproject.toml."""
    packages = []

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except FileNotFoundError:
        return packages

    data = _load_toml_file(file_path)
    if not data:
        in_project_dependencies = False
        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("dependencies") and "[" in stripped:
                in_project_dependencies = True
            elif in_project_dependencies and "]" in stripped:
                in_project_dependencies = False

            if not in_project_dependencies:
                continue

            for requirement in re.findall(r'["\']([^"\']+)["\']', stripped):
                parsed = _parse_requirement_string(requirement)
                if not parsed:
                    continue
                pkg_name, version = parsed
                packages.append(
                    _build_package(
                        pkg_name,
                        version,
                        "project.dependencies",
                        file_path,
                        line_num,
                        line.rstrip("\n"),
                    )
                )
        return packages

    project = data.get("project", {})
    for requirement in project.get("dependencies", []):
        parsed = _parse_requirement_string(requirement)
        if not parsed:
            continue

        pkg_name, version = parsed
        line_num, line_text = _find_name_in_lines(lines, pkg_name)
        packages.append(
            _build_package(
                pkg_name,
                version,
                "project.dependencies",
                file_path if line_num else None,
                line_num,
                line_text,
            )
        )

    optional_dependencies = project.get("optional-dependencies", {})
    for group_name, requirements in optional_dependencies.items():
        for requirement in requirements:
            parsed = _parse_requirement_string(requirement)
            if not parsed:
                continue

            pkg_name, version = parsed
            line_num, line_text = _find_name_in_lines(lines, pkg_name)
            packages.append(
                _build_package(
                    pkg_name,
                    version,
                    f"project.optional-dependencies.{group_name}",
                    file_path if line_num else None,
                    line_num,
                    line_text,
                )
            )

    poetry = data.get("tool", {}).get("poetry", {})
    for name, spec in poetry.get("dependencies", {}).items():
        if name == "python":
            continue

        line_num, line_text = _find_toml_assignment_line(lines, name)
        packages.append(
            _build_package(
                name,
                _extract_poetry_version(spec),
                "tool.poetry.dependencies",
                file_path if line_num else None,
                line_num,
                line_text,
            )
        )

    for name, spec in poetry.get("dev-dependencies", {}).items():
        line_num, line_text = _find_toml_assignment_line(lines, name)
        packages.append(
            _build_package(
                name,
                _extract_poetry_version(spec),
                "tool.poetry.dev-dependencies",
                file_path if line_num else None,
                line_num,
                line_text,
            )
        )

    for group_name, group_data in poetry.get("group", {}).items():
        for name, spec in group_data.get("dependencies", {}).items():
            if name == "python":
                continue

            line_num, line_text = _find_toml_assignment_line(lines, name)
            packages.append(
                _build_package(
                    name,
                    _extract_poetry_version(spec),
                    f"tool.poetry.group.{group_name}.dependencies",
                    file_path if line_num else None,
                    line_num,
                    line_text,
                )
            )

    return packages


def _extract_pipfile_version(spec) -> str:
    """Extract a usable version string from a Pipfile dependency spec."""
    if isinstance(spec, str):
        return _extract_first_version(spec)
    if isinstance(spec, dict):
        return _extract_first_version(spec.get("version", ""))
    return ""


def parse_pipfile_dependencies(file_path: str) -> List[Dict[str, str]]:
    """Parse dependencies from Pipfile."""
    packages = []

    data = _load_toml_file(file_path)
    if not data:
        return packages

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except FileNotFoundError:
        lines = []

    for section_name in ("packages", "dev-packages"):
        for name, spec in data.get(section_name, {}).items():
            line_num, line_text = _find_toml_assignment_line(lines, name)
            packages.append(
                _build_package(
                    name,
                    _extract_pipfile_version(spec),
                    section_name,
                    file_path if line_num else None,
                    line_num,
                    line_text,
                )
            )

    return packages


def parse_poetry_lock_dependencies(file_path: str) -> List[Dict[str, str]]:
    """Parse dependencies from poetry.lock."""
    packages = []

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except FileNotFoundError:
        return packages

    current_name = None
    current_version = None
    current_name_line = None
    current_name_text = None

    for line_num, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped == "[[package]]":
            if current_name and current_version:
                packages.append(
                    _build_package(
                        current_name,
                        current_version,
                        "lockfile",
                        file_path,
                        current_name_line,
                        current_name_text,
                    )
                )
            current_name = None
            current_version = None
            current_name_line = None
            current_name_text = None
            continue

        name_match = re.match(r'^name\s*=\s*["\']([^"\']+)["\']', stripped)
        if name_match:
            current_name = name_match.group(1)
            current_name_line = line_num
            current_name_text = line.rstrip("\n")
            continue

        version_match = re.match(r'^version\s*=\s*["\']([^"\']+)["\']', stripped)
        if version_match:
            current_version = version_match.group(1)

    if current_name and current_version:
        packages.append(
            _build_package(
                current_name,
                current_version,
                "lockfile",
                file_path,
                current_name_line,
                current_name_text,
            )
        )

    return packages


def parse_dependencies(file_path: str, ecosystem: str) -> List[Dict[str, str]]:
    """
    Parse dependencies from a file based on its filename and ecosystem.

    Args:
        file_path: Path to dependency file
        ecosystem: Ecosystem name (npm, pypi, maven, etc.)

    Returns:
        List of dicts with 'name' and 'version' keys
    """
    filename = os.path.basename(file_path)
    parser_by_id = {
        "npm_package_json": parse_npm_dependencies,
        "npm_package_lock": parse_npm_dependencies,
        "yarn_lock": parse_yarn_lock_dependencies,
        "pnpm_lock": parse_pnpm_lock_dependencies,
        "requirements_txt": parse_pypi_dependencies,
        "setup_py": parse_setup_py_dependencies,
        "pyproject_toml": parse_pyproject_dependencies,
        "pipfile": parse_pipfile_dependencies,
        "poetry_lock": parse_poetry_lock_dependencies,
        "pom_xml": parse_maven_dependencies,
        "build_gradle": parse_gradle_dependencies,
        "gemfile": parse_rubygems_dependencies,
        "gemfile_lock": parse_gemfile_lock_dependencies,
        "go_mod": parse_go_dependencies,
        "go_sum": parse_go_sum_dependencies,
        "cargo_toml": parse_cargo_dependencies,
        "cargo_lock": parse_cargo_lock_dependencies,
    }
    manifest = get_manifest_for_filename(filename)
    if manifest:
        return parser_by_id[manifest["parser_id"]](file_path)

    ecosystem_parsers = {
        "npm": parse_npm_dependencies,
        "pypi": parse_pypi_dependencies,
        "maven": parse_maven_dependencies,
        "rubygems": parse_rubygems_dependencies,
        "go": parse_go_dependencies,
        "cargo": parse_cargo_dependencies,
    }

    parser = ecosystem_parsers.get(ecosystem)
    if parser:
        return parser(file_path)

    return []
