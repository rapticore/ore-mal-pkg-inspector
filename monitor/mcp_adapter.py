#!/usr/bin/env python3
"""
Minimal MCP adapter for OreWatch's local monitor API.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.parse
from typing import Any, Dict, Optional

from monitor.api import monitor_api_request
from monitor.api import supported_health_payload
from monitor.api import wait_for_api
from monitor.api import SUPPORTED_SOURCE_KINDS
from monitor.config import load_monitor_api_token


PROTOCOL_VERSION = "2024-11-05"
STDIO_MODE_CONTENT_LENGTH = "content-length"
STDIO_MODE_NEWLINE = "newline"
_STDIO_MESSAGE_MODE = STDIO_MODE_CONTENT_LENGTH


DEPENDENCY_ITEM_SCHEMA = {
    "type": "object",
    "properties": {
        "name": {"type": "string"},
        "requested_spec": {"type": "string"},
        "resolved_version": {"type": "string"},
        "version": {"type": "string"},
        "dev_dependency": {"type": "boolean"},
    },
    "required": ["name"],
    "additionalProperties": False,
}

SOURCE_SCHEMA = {
    "type": "object",
    "properties": {
        "kind": {"type": "string", "enum": list(SUPPORTED_SOURCE_KINDS)},
        "command": {"type": "string"},
        "file_path": {"type": "string"},
    },
    "required": ["kind"],
    "additionalProperties": False,
}
SEVERITY_SCHEMA = {"type": "string", "enum": ["low", "medium", "high", "critical"]}


TOOLS = [
    {
        "name": "orewatch_health",
        "description": "Return OreWatch monitor health, supported ecosystems, and threat-data status.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    },
    {
        "name": "orewatch_check_dependency_add",
        "description": "Check whether a proposed dependency add/install/update is safe before proceeding.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "client_type": {"type": "string"},
                "project_path": {"type": "string"},
                "ecosystem": {"type": "string"},
                "package_manager": {"type": "string"},
                "operation": {"type": "string"},
                "dependencies": {
                    "type": "array",
                    "items": DEPENDENCY_ITEM_SCHEMA,
                    "minItems": 1,
                },
                "source": SOURCE_SCHEMA,
            },
            "required": [
                "client_type",
                "project_path",
                "ecosystem",
                "package_manager",
                "operation",
                "dependencies",
                "source",
            ],
            "additionalProperties": False,
        },
    },
    {
        "name": "orewatch_check_manifest",
        "description": "Check a full manifest dependency set and return advisory status.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "client_type": {"type": "string"},
                "project_path": {"type": "string"},
                "ecosystem": {"type": "string"},
                "manifest_path": {"type": "string"},
                "dependencies": {
                    "type": "array",
                    "items": DEPENDENCY_ITEM_SCHEMA,
                },
            },
            "required": [
                "client_type",
                "project_path",
                "ecosystem",
                "manifest_path",
            ],
            "additionalProperties": False,
        },
    },
    {
        "name": "orewatch_override_dependency_add",
        "description": "Record a one-time explicit override for a previously blocked dependency check.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "check_id": {"type": "string"},
                "client_type": {"type": "string"},
                "actor": {"type": "string"},
                "reason": {"type": "string"},
            },
            "required": ["check_id", "client_type", "actor", "reason"],
            "additionalProperties": False,
        },
    },
    {
        "name": "orewatch_list_active_findings",
        "description": "List active monitor findings detected by background scans.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project_path": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1},
                "min_severity": SEVERITY_SCHEMA,
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "orewatch_list_notifications",
        "description": "List recent OreWatch monitor notifications and alert messages.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project_path": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1},
            },
            "additionalProperties": False,
        },
    },
]


def _write_message(payload: Dict[str, Any]) -> None:
    body = json.dumps(payload).encode("utf-8")
    if _STDIO_MESSAGE_MODE == STDIO_MODE_NEWLINE:
        sys.stdout.write(body.decode("utf-8"))
        sys.stdout.write("\n")
        sys.stdout.flush()
        return
    sys.stdout.write(f"Content-Length: {len(body)}\r\n\r\n")
    sys.stdout.flush()
    sys.stdout.buffer.write(body)
    sys.stdout.buffer.flush()


def _read_message() -> Optional[Dict[str, Any]]:
    global _STDIO_MESSAGE_MODE
    first_line = sys.stdin.buffer.readline()
    if not first_line:
        return None

    stripped = first_line.strip()
    if stripped.startswith((b"{", b"[")):
        _STDIO_MESSAGE_MODE = STDIO_MODE_NEWLINE
        return json.loads(stripped.decode("utf-8"))

    _STDIO_MESSAGE_MODE = STDIO_MODE_CONTENT_LENGTH
    headers: Dict[str, str] = {}
    line = first_line
    while True:
        if line in (b"\r\n", b"\n"):
            break
        decoded = line.decode("utf-8").strip()
        if ":" in decoded:
            key, value = decoded.split(":", 1)
            headers[key.lower()] = value.strip()
        line = sys.stdin.buffer.readline()
        if not line:
            return None
    content_length = int(headers.get("content-length", "0") or 0)
    if content_length <= 0:
        return None
    body = sys.stdin.buffer.read(content_length)
    return json.loads(body.decode("utf-8"))


class MCPBridge:
    """Proxy MCP tool calls to the local OreWatch HTTP API."""

    def __init__(self, service):
        self.service = service
        self.token = load_monitor_api_token()
        self.base_url = service.get_connection_info()["base_url"]

    def ensure_api_ready(self) -> Dict[str, Any]:
        """Ensure the local monitor API is reachable and auto-start once if configured."""
        info = self.service.get_connection_info()
        self.base_url = str(info["base_url"])
        if wait_for_api(self.base_url, self.token, timeout_ms=1000):
            return {
                "ready": True,
                "started_monitor": False,
                "message": f"OreWatch monitor API available at {self.base_url}",
            }
        if info.get("auto_start_on_client"):
            start_result = self.service.start()
            info = self.service.get_connection_info()
            self.base_url = str(info["base_url"])
            if wait_for_api(self.base_url, self.token, timeout_ms=5000):
                return {
                    "ready": True,
                    "started_monitor": True,
                    "message": (
                        f"{start_result.get('message', 'Started OreWatch monitor')} "
                        f"(API: {self.base_url})"
                    ),
                }
            return {
                "ready": False,
                "started_monitor": True,
                "message": (
                    f"{start_result.get('message', 'Started OreWatch monitor')} "
                    f"but the local API did not become ready"
                ),
            }
        return {
            "ready": False,
            "started_monitor": False,
            "message": "OreWatch monitor API is unavailable and auto-start is disabled",
        }

    def _offline_health(self) -> Dict[str, Any]:
        return {
            **supported_health_payload(),
            "daemon_running": False,
            "api_listening": False,
            "base_url": self.base_url,
            "last_threat_refresh_at": None,
            "last_threat_refresh_status": "failed",
            "last_live_promotion_status": None,
            "last_live_promotion_decision": None,
            "current_snapshot_version": None,
            "current_live_dataset_version": None,
            "scan_blocked_reason": "OreWatch monitor API is unavailable",
            "data_health": "failed",
            "data_health_details": {
                "expected_path": self.service.updater.final_data_dir,
                "requested_ecosystems": [],
                "available_databases": [],
                "missing_ecosystems": [],
                "usable_ecosystems": [],
                "sources_used": [],
                "experimental_sources_used": [],
                "requested_statuses": {},
                "suggestion": "Start the OreWatch monitor API and ensure threat data is available",
            },
            "database_statuses": {},
            "final_data_dir": self.service.updater.final_data_dir,
        }

    def _offline_check(self) -> Dict[str, Any]:
        return {
            "check_id": "",
            "decision": "override_required",
            "data_health": "failed",
            "data_health_details": {
                "expected_path": self.service.updater.final_data_dir,
                "requested_ecosystems": [],
                "available_databases": [],
                "missing_ecosystems": [],
                "usable_ecosystems": [],
                "sources_used": [],
                "experimental_sources_used": [],
                "requested_statuses": {},
                "suggestion": "Start the OreWatch monitor API and ensure threat data is available",
            },
            "results": [],
            "monitor_message": "OreWatch monitor API is unavailable",
            "override_allowed": True,
        }

    def _offline_findings(self) -> Dict[str, Any]:
        return {
            "project_path": None,
            "count": 0,
            "returned": 0,
            "limit": 20,
            "min_severity": None,
            "highest_severity": None,
            "findings": [],
            "monitor_message": "OreWatch monitor API is unavailable",
        }

    def _offline_notifications(self) -> Dict[str, Any]:
        return {
            "project_path": None,
            "count": 0,
            "returned": 0,
            "limit": 20,
            "notifications": [],
            "monitor_message": "OreWatch monitor API is unavailable",
        }

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatch one MCP tool call."""
        if name == "orewatch_health":
            if not self.ensure_api_ready()["ready"]:
                return self._offline_health()
            return monitor_api_request(self.base_url, self.token, "GET", "/v1/health")

        if name == "orewatch_check_dependency_add":
            if not self.ensure_api_ready()["ready"]:
                return self._offline_check()
            return monitor_api_request(
                self.base_url,
                self.token,
                "POST",
                "/v1/check/dependency-add",
                payload=arguments,
            )

        if name == "orewatch_check_manifest":
            if not self.ensure_api_ready()["ready"]:
                response = self._offline_check()
                response["manifest_status"] = "warning"
                return response
            return monitor_api_request(
                self.base_url,
                self.token,
                "POST",
                "/v1/check/manifest",
                payload=arguments,
            )

        if name == "orewatch_override_dependency_add":
            if not self.ensure_api_ready()["ready"]:
                return {
                    "decision": "override_required",
                    "monitor_message": "OreWatch monitor API is unavailable",
                }
            check_id = str(arguments.get("check_id", "")).strip()
            if not check_id or "/" in check_id:
                raise ValueError("Invalid check_id")
            payload = dict(arguments)
            payload.pop("check_id", None)
            return monitor_api_request(
                self.base_url,
                self.token,
                "POST",
                f"/v1/checks/{urllib.parse.quote(check_id, safe='')}/override",
                payload=payload,
            )

        if name == "orewatch_list_active_findings":
            if not self.ensure_api_ready()["ready"]:
                return self._offline_findings()
            query = {}
            if arguments.get("project_path"):
                pp = str(arguments["project_path"])
                if "\x00" in pp:
                    raise ValueError("Invalid project_path: null bytes not allowed")
                pp = os.path.abspath(pp)
                if not os.path.isdir(pp):
                    raise ValueError(f"project_path is not a valid directory: {pp}")
                query["project_path"] = pp
            if arguments.get("limit"):
                query["limit"] = int(arguments["limit"])
            if arguments.get("min_severity"):
                query["min_severity"] = str(arguments["min_severity"])
            path = "/v1/findings/active"
            if query:
                path += "?" + urllib.parse.urlencode(query)
            return monitor_api_request(self.base_url, self.token, "GET", path)

        if name == "orewatch_list_notifications":
            if not self.ensure_api_ready()["ready"]:
                return self._offline_notifications()
            query = {}
            if arguments.get("project_path"):
                pp = str(arguments["project_path"])
                if "\x00" in pp:
                    raise ValueError("Invalid project_path: null bytes not allowed")
                pp = os.path.abspath(pp)
                if not os.path.isdir(pp):
                    raise ValueError(f"project_path is not a valid directory: {pp}")
                query["project_path"] = pp
            if arguments.get("limit"):
                query["limit"] = int(arguments["limit"])
            path = "/v1/notifications"
            if query:
                path += "?" + urllib.parse.urlencode(query)
            return monitor_api_request(self.base_url, self.token, "GET", path)

        raise ValueError(f"Unknown tool: {name}")


def _tool_result(result: Dict[str, Any], is_error: bool = False) -> Dict[str, Any]:
    return {
        "content": [
            {
                "type": "text",
                "text": json.dumps(result, indent=2, sort_keys=True),
            }
        ],
        "isError": is_error,
    }


def _write_status(message: str) -> None:
    """Write human-readable bridge status to stderr without polluting MCP stdout."""
    print(message, file=sys.stderr, flush=True)


def _should_write_startup_status() -> bool:
    """Only write startup hints for manual interactive use unless explicitly requested."""
    if os.environ.get("OREWATCH_MCP_VERBOSE_STARTUP", "").strip().lower() in {"1", "true", "yes", "on"}:
        return True
    return sys.stdin.isatty() and sys.stderr.isatty()


def run_mcp_adapter(service) -> int:
    """Run the OreWatch MCP adapter over stdio."""
    global _STDIO_MESSAGE_MODE
    _STDIO_MESSAGE_MODE = STDIO_MODE_CONTENT_LENGTH
    bridge = MCPBridge(service)
    if _should_write_startup_status():
        startup = bridge.ensure_api_ready()
        _write_status(startup["message"])
        _write_status("OreWatch MCP bridge ready on stdio")
    while True:
        message = _read_message()
        if message is None:
            return 0

        method = message.get("method")
        message_id = message.get("id")
        params = message.get("params", {})

        if method == "initialize":
            if message_id is not None:
                _write_message(
                    {
                        "jsonrpc": "2.0",
                        "id": message_id,
                        "result": {
                            "protocolVersion": PROTOCOL_VERSION,
                            "capabilities": {"tools": {}},
                            "serverInfo": {"name": "orewatch", "version": "1.0"},
                        },
                    }
                )
            continue

        if method == "notifications/initialized":
            continue

        if method == "tools/list":
            _write_message(
                {
                    "jsonrpc": "2.0",
                    "id": message_id,
                    "result": {"tools": TOOLS},
                }
            )
            continue

        if method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments", {})
            try:
                result = bridge.call_tool(str(tool_name), dict(arguments))
                _write_message(
                    {
                        "jsonrpc": "2.0",
                        "id": message_id,
                        "result": _tool_result(result),
                    }
                )
            except Exception as exc:
                _write_message(
                    {
                        "jsonrpc": "2.0",
                        "id": message_id,
                        "result": _tool_result({"error": str(exc)}, is_error=True),
                    }
                )
            continue

        if method == "ping":
            _write_message({"jsonrpc": "2.0", "id": message_id, "result": {}})
            continue

        if message_id is not None:
            _write_message(
                {
                    "jsonrpc": "2.0",
                    "id": message_id,
                    "error": {"code": -32601, "message": f"Unknown method: {method}"},
                }
            )
