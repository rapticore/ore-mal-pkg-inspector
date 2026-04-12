#!/usr/bin/env python3
"""
Localhost API for IDE and agent integrations.
"""

from __future__ import annotations

import json
import re
import threading
import time
import uuid
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from collectors.orchestrator import get_database_statuses
from scanner_engine import summarize_requested_data_status
from scanners.supported_files import ECOSYSTEM_PRIORITY, SUPPORTED_MANIFESTS

if TYPE_CHECKING:
    from monitor.service import MonitorService


SUPPORTED_CLIENT_TYPES = {"claude_code", "codex", "cursor", "vscode", "jetbrains", "xcode"}
SUPPORTED_SOURCE_KINDS = ("agent_command", "ide_action")
SOURCE_KIND_ALIASES = {"file_path": "ide_action"}
DEPENDENCY_ALLOWED_FIELDS = {
    "name",
    "requested_spec",
    "resolved_version",
    "version",
    "dev_dependency",
    "physical_location",
    "section",
}
SOURCE_ALLOWED_FIELDS = {"kind", "command", "file_path"}
PACKAGE_MANAGERS_BY_ECOSYSTEM = {
    "npm": ["npm", "pnpm", "yarn"],
    "pypi": ["pip", "poetry", "pipenv"],
    "maven": ["maven", "gradle"],
    "rubygems": ["bundler", "gem"],
    "go": ["go"],
    "cargo": ["cargo"],
}
SUPPORTED_PACKAGE_MANAGERS = sorted(
    {
        package_manager
        for package_managers in PACKAGE_MANAGERS_BY_ECOSYSTEM.values()
        for package_manager in package_managers
    }
)
LITERAL_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._!+-]*$")
NON_EXACT_SPEC_TOKENS = (
    " ",
    ",",
    "|",
    "^",
    "~",
    ">",
    "<",
    "*",
    "workspace:",
    "file:",
    "git+",
    "http://",
    "https://",
    "latest",
    "next",
)


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _is_literal_version(value: str) -> bool:
    candidate = (value or "").strip()
    if not candidate:
        return False
    lowered = candidate.lower()
    if any(token in lowered for token in NON_EXACT_SPEC_TOKENS):
        return False
    return bool(LITERAL_VERSION_RE.match(candidate))


def resolve_exact_version(requested_spec: str = "", resolved_version: str = "") -> str:
    """Return an exact version when one is clearly known."""
    if _is_literal_version(resolved_version):
        return resolved_version.strip()

    spec = (requested_spec or "").strip()
    if not spec:
        return ""
    if spec.startswith("=="):
        spec = spec[2:].strip()
    elif spec.startswith("=") and not spec.startswith((">=", "<=", "=>", "=<")):
        spec = spec[1:].strip()

    if _is_literal_version(spec):
        return spec
    return ""


def normalize_dependency_input(dependency: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize one dependency payload from a client."""
    unknown_fields = sorted(set(dependency) - DEPENDENCY_ALLOWED_FIELDS)
    if unknown_fields:
        allowed = ", ".join(sorted(DEPENDENCY_ALLOWED_FIELDS))
        raise ValueError(
            f"Unsupported dependency field(s): {', '.join(unknown_fields)}; "
            f"allowed fields: {allowed}"
        )

    name = str(dependency.get("name", "")).strip()
    if not name:
        raise ValueError("Dependency name is required")

    version_alias = str(dependency.get("version", "") or "").strip()
    requested_spec = str(dependency.get("requested_spec", "") or "").strip()
    resolved_version = str(dependency.get("resolved_version", "") or "").strip()
    if version_alias and (requested_spec or resolved_version):
        raise ValueError(
            "Dependency version is ambiguous; use either version or "
            "requested_spec/resolved_version"
        )
    if version_alias:
        requested_spec = version_alias
        resolved_version = version_alias

    exact_version = resolve_exact_version(requested_spec=requested_spec, resolved_version=resolved_version)
    normalized = {
        "name": name,
        "requested_spec": requested_spec,
        "resolved_version": resolved_version,
        "dev_dependency": bool(dependency.get("dev_dependency", False)),
        "exact_version": exact_version,
    }
    if "physical_location" in dependency:
        normalized["physical_location"] = dependency["physical_location"]
    if "section" in dependency:
        normalized["section"] = dependency["section"]
    return normalized


def _validate_dependencies(dependencies: Any, required: bool) -> None:
    if dependencies is None:
        if required:
            raise ValueError("dependencies must be a non-empty array")
        return
    if not isinstance(dependencies, list):
        raise ValueError("dependencies must be an array")
    if required and not dependencies:
        raise ValueError("dependencies must be a non-empty array")
    for dependency in dependencies:
        if not isinstance(dependency, dict):
            raise ValueError("dependencies entries must be objects")
        normalize_dependency_input(dependency)


def normalize_source_input(source: Any) -> Dict[str, Any]:
    """Validate and normalize a dependency-check source payload."""
    if not isinstance(source, dict):
        raise ValueError("source is required")

    unknown_fields = sorted(set(source) - SOURCE_ALLOWED_FIELDS)
    if unknown_fields:
        allowed = ", ".join(sorted(SOURCE_ALLOWED_FIELDS))
        raise ValueError(
            f"Unsupported source field(s): {', '.join(unknown_fields)}; "
            f"allowed fields: {allowed}"
        )

    kind = str(source.get("kind", "")).strip()
    normalized_kind = SOURCE_KIND_ALIASES.get(kind, kind)
    file_path = str(source.get("file_path", "") or "").strip()
    command = str(source.get("command", "") or "").strip()

    if kind == "file_path" and not file_path:
        raise ValueError("source.file_path is required when source.kind is 'file_path'")

    if normalized_kind not in SUPPORTED_SOURCE_KINDS:
        expected = ", ".join(SUPPORTED_SOURCE_KINDS)
        raise ValueError(f"Unsupported source.kind '{kind}'; expected one of: {expected}")
    if normalized_kind == "agent_command" and not command:
        raise ValueError("source.command is required when source.kind is 'agent_command'")

    normalized = {"kind": normalized_kind}
    if file_path:
        normalized["file_path"] = file_path
    if command:
        normalized["command"] = command
    return normalized


def validate_client_request(payload: Dict[str, Any], manifest: bool = False) -> None:
    """Validate one request payload and raise ValueError on invalid input."""
    client_type = payload.get("client_type")
    if client_type not in SUPPORTED_CLIENT_TYPES:
        raise ValueError("Unsupported client_type")

    ecosystem = payload.get("ecosystem")
    if ecosystem not in PACKAGE_MANAGERS_BY_ECOSYSTEM:
        raise ValueError("Unsupported ecosystem")

    project_path = str(payload.get("project_path", "")).strip()
    if not project_path:
        raise ValueError("project_path is required")

    if manifest:
        if not str(payload.get("manifest_path", "")).strip():
            raise ValueError("manifest_path is required")
        _validate_dependencies(payload.get("dependencies"), required=False)
        return

    _validate_dependencies(payload.get("dependencies"), required=True)

    package_manager = payload.get("package_manager")
    if package_manager not in SUPPORTED_PACKAGE_MANAGERS:
        raise ValueError("Unsupported package_manager")
    if package_manager not in PACKAGE_MANAGERS_BY_ECOSYSTEM[ecosystem]:
        raise ValueError("package_manager does not match ecosystem")
    if payload.get("operation") not in {"add", "install", "update"}:
        raise ValueError("Unsupported operation")

    normalize_source_input(payload.get("source"))


def monitor_api_request(
    base_url: str,
    token: str,
    method: str,
    path: str,
    payload: Optional[Dict[str, Any]] = None,
    timeout_ms: int = 5000,
) -> Dict[str, Any]:
    """Call the local monitor HTTP API."""
    url = urllib.parse.urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    parsed_url = urllib.parse.urlparse(url)
    if parsed_url.scheme not in ("http", "https"):
        raise ValueError(f"Unsupported URL scheme: {parsed_url.scheme!r} (only http/https allowed)")
    body = None
    headers = {"Authorization": f"Bearer {token}"}
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=body, headers=headers, method=method.upper())
    try:
        with urllib.request.urlopen(request, timeout=max(timeout_ms / 1000.0, 1)) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        response_body = exc.read().decode("utf-8", errors="ignore")
        try:
            parsed = json.loads(response_body)
        except json.JSONDecodeError:
            parsed = {"error": response_body or exc.reason}
        raise RuntimeError(f"Monitor API error {exc.code}: {parsed.get('error', exc.reason)}") from exc


def wait_for_api(base_url: str, token: str, timeout_ms: int = 5000) -> bool:
    """Poll the health endpoint until the API becomes ready or times out."""
    deadline = time.time() + max(timeout_ms / 1000.0, 1)
    while time.time() < deadline:
        try:
            monitor_api_request(base_url, token, "GET", "/v1/health", timeout_ms=1000)
            return True
        except Exception:
            time.sleep(0.1)
    return False


class _MonitorAPIHandler(BaseHTTPRequestHandler):
    """Request handler bound to one monitor service instance."""

    server_version = "OreWatchLocalAPI/1.0"

    def _write_json(self, status_code: int, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    MAX_REQUEST_BODY_BYTES = 1_048_576  # 1 MB

    def _read_json_body(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length <= 0:
            return {}
        if length > self.MAX_REQUEST_BODY_BYTES:
            raise ValueError(f"Request body too large ({length} bytes)")
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError("Request body must be valid JSON") from exc

    def _authorize(self) -> bool:
        import hmac
        expected = f"Bearer {self.server.api_token}"
        provided = self.headers.get("Authorization", "")
        if not hmac.compare_digest(provided, expected):
            self._write_json(401, {"error": "Unauthorized"})
            return False
        return True

    def _parse_request_target(self) -> tuple[str, Dict[str, List[str]]]:
        parsed = urllib.parse.urlparse(self.path)
        return parsed.path, urllib.parse.parse_qs(parsed.query, keep_blank_values=False)

    def _query_value(
        self,
        query: Dict[str, List[str]],
        key: str,
    ) -> Optional[str]:
        values = query.get(key, [])
        if not values:
            return None
        value = str(values[0]).strip()
        return value or None

    def _query_limit(
        self,
        query: Dict[str, List[str]],
        default: int = 20,
    ) -> int:
        raw = self._query_value(query, "limit")
        if raw is None:
            return default
        try:
            value = int(raw)
        except ValueError as exc:
            raise ValueError("limit must be a positive integer") from exc
        if value <= 0:
            raise ValueError("limit must be a positive integer")
        return value

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        self.server.service.logger.debug("monitor api: " + format, *args)

    def do_GET(self) -> None:  # noqa: N802
        if not self._authorize():
            return
        try:
            route, query = self._parse_request_target()
            if route == "/v1/health":
                self._write_json(200, self.server.service.build_health_payload())
                return
            if route in {"/v1/findings", "/v1/findings/active"}:
                self._write_json(
                    200,
                    self.server.service.list_active_findings(
                        project_path=self._query_value(query, "project_path"),
                        limit=self._query_limit(query, default=20),
                        min_severity=self._query_value(query, "min_severity"),
                    ),
                )
                return
            if route == "/v1/notifications":
                self._write_json(
                    200,
                    self.server.service.list_recent_notifications(
                        project_path=self._query_value(query, "project_path"),
                        limit=self._query_limit(query, default=20),
                    ),
                )
                return
            self._write_json(404, {"error": "Not found"})
        except ValueError as exc:
            self._write_json(400, {"error": str(exc)})

    def do_POST(self) -> None:  # noqa: N802
        if not self._authorize():
            return
        try:
            payload = self._read_json_body()
            route, _query = self._parse_request_target()
            if route == "/v1/check/dependency-add":
                self._write_json(200, self.server.service.handle_dependency_add_check(payload))
                return
            if route == "/v1/check/manifest":
                self._write_json(200, self.server.service.handle_manifest_check(payload))
                return
            if route.startswith("/v1/checks/") and route.endswith("/override"):
                check_id = route[len("/v1/checks/") : -len("/override")].strip("/")
                if not check_id or "/" in check_id:
                    self._write_json(400, {"error": "Invalid check_id"})
                    return
                self._write_json(200, self.server.service.handle_dependency_override(check_id, payload))
                return
            self._write_json(404, {"error": "Not found"})
        except ValueError as exc:
            self._write_json(400, {"error": str(exc)})
        except Exception as exc:  # pragma: no cover - defensive API boundary
            self.server.service.logger.exception("Local API request failed")
            self._write_json(500, {"error": str(exc)})


class _MonitorHTTPServer(ThreadingHTTPServer):
    """Threading HTTP server carrying service context."""

    daemon_threads = True

    def __init__(self, server_address, handler_class, service: "MonitorService", api_token: str):
        super().__init__(server_address, handler_class)
        self.service = service
        self.api_token = api_token


class LocalMonitorAPIServer:
    """Own one localhost HTTP server for the monitor."""

    def __init__(self, service: "MonitorService", host: str, port: int, api_token: str):
        self.service = service
        self.host = host
        self.port = int(port)
        self.api_token = api_token
        self._server: Optional[_MonitorHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    @property
    def listening(self) -> bool:
        return self._server is not None and self._thread is not None and self._thread.is_alive()

    @property
    def base_url(self) -> str:
        port = self.port
        if self._server is not None:
            port = int(self._server.server_address[1])
        return f"http://{self.host}:{port}"

    def start(self) -> str:
        """Start the HTTP server if it is not already listening."""
        if self.listening:
            return self.base_url
        self._server = _MonitorHTTPServer((self.host, self.port), _MonitorAPIHandler, self.service, self.api_token)
        self.port = int(self._server.server_address[1])
        self._thread = threading.Thread(target=self._server.serve_forever, name="orewatch-api", daemon=True)
        self._thread.start()
        return self.base_url

    def stop(self) -> None:
        """Stop the server if it is running."""
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2)
        self._server = None
        self._thread = None


def make_check_id() -> str:
    """Return a stable-ish opaque check identifier."""
    return f"check-{uuid.uuid4().hex}"


def make_override_id() -> str:
    """Return an opaque override identifier."""
    return f"override-{uuid.uuid4().hex}"


def build_override_expiry(ttl_seconds: int) -> str:
    """Return the expiry timestamp for a one-time override."""
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=max(int(ttl_seconds), 1))
    return expires_at.strftime("%Y-%m-%dT%H:%M:%SZ")


def supported_manifest_filenames() -> List[str]:
    """Return the registry-backed supported manifest filenames."""
    return [manifest["filename"] for manifest in SUPPORTED_MANIFESTS]


def supported_health_payload() -> Dict[str, Any]:
    """Return static client-facing capability metadata."""
    return {
        "supported_ecosystems": list(ECOSYSTEM_PRIORITY),
        "supported_package_managers": SUPPORTED_PACKAGE_MANAGERS,
        "supported_client_types": sorted(SUPPORTED_CLIENT_TYPES),
        "supported_manifest_filenames": supported_manifest_filenames(),
    }
