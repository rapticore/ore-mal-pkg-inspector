#!/usr/bin/env python3
"""
Helpers for generating IDE and agent bootstrap snippets.
"""

from __future__ import annotations

import json
import shlex
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, List


CLIENT_LABELS = {
    "claude_code": "Claude Code",
    "codex": "Codex",
    "cursor": "Cursor",
    "vscode": "VS Code",
    "jetbrains": "JetBrains / PyCharm",
    "xcode": "Xcode",
}

MCP_CLIENTS = ("claude_code", "codex", "cursor")
API_CLIENTS = ("vscode", "jetbrains", "xcode")
ALL_BOOTSTRAP_CLIENTS = MCP_CLIENTS + API_CLIENTS


def _bundled_cli_script_path() -> str | None:
    """Return the packaged scanner entrypoint path when it is present."""
    script_path = Path(__file__).resolve().parent.parent / "malicious_package_scanner.py"
    if script_path.is_file():
        return str(script_path)
    return None


def resolve_cli_invocation(
    python_executable: str | None = None,
    prefer_console_script: bool = True,
) -> Dict[str, Any]:
    """Resolve the preferred local OreWatch invocation."""
    console_script = shutil.which("orewatch") if prefer_console_script else None
    if console_script:
        resolved_command = str(Path(console_script).absolute())
        return {
            "command": resolved_command,
            "args_prefix": [],
            "display": shlex.quote(resolved_command),
        }

    python_command = python_executable or sys.executable
    script_path = _bundled_cli_script_path()
    if script_path:
        return {
            "command": python_command,
            "args_prefix": [script_path],
            "display": f"{shlex.quote(python_command)} {shlex.quote(script_path)}",
        }
    return {
        "command": python_command,
        "args_prefix": ["-m", "malicious_package_scanner"],
        "display": f"{shlex.quote(python_command)} -m malicious_package_scanner",
    }


def build_mcp_server_definition() -> Dict[str, Any]:
    """Return the MCP server command definition for OreWatch."""
    invocation = resolve_cli_invocation()
    return {
        "command": invocation["command"],
        "args": invocation["args_prefix"] + ["monitor", "mcp"],
    }


def build_connection_hints(connection_info: Dict[str, Any]) -> Dict[str, Any]:
    """Return shared bootstrap hints for IDE and agent integrations."""
    mcp_server = build_mcp_server_definition()
    return {
        "base_url": str(connection_info["base_url"]),
        "token_path": str(connection_info["token_path"]),
        "mcp_server": mcp_server,
        "mcp_command_preview": " ".join(
            shlex.quote(part) for part in [mcp_server["command"], *mcp_server["args"]]
        ),
    }


def _json_block(payload: Dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True)


def build_ide_bootstrap(connection_info: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Return per-client bootstrap snippets and notes."""
    hints = build_connection_hints(connection_info)
    mcp_block = {
        "mcpServers": {
            "orewatch": hints["mcp_server"],
        }
    }
    api_block = {
        "orewatch": {
            "baseUrl": hints["base_url"],
            "tokenPath": hints["token_path"],
        }
    }
    return {
        "claude_code": {
            "label": CLIENT_LABELS["claude_code"],
            "mode": "mcp",
            "snippet_format": "json",
            "snippet": _json_block(mcp_block),
            "notes": [
                "Add this MCP server entry to your Claude Code MCP configuration.",
                "This connects Claude Code to the per-user OreWatch monitor singleton that can serve many projects and agents.",
                "Replace older MCP configs that still use bare `orewatch`; bootstrap now emits the absolute local OreWatch binary path when it can resolve one.",
            ],
        },
        "codex": {
            "label": CLIENT_LABELS["codex"],
            "mode": "mcp",
            "snippet_format": "json",
            "snippet": _json_block(mcp_block),
            "notes": [
                "Add this MCP server entry to your Codex MCP configuration.",
                "One per-user OreWatch monitor can serve many Codex and Claude/Cursor agents at once.",
                "Replace older MCP configs that still use bare `orewatch`; bootstrap now emits the absolute local OreWatch binary path when it can resolve one.",
            ],
        },
        "cursor": {
            "label": CLIENT_LABELS["cursor"],
            "mode": "mcp",
            "snippet_format": "json",
            "snippet": _json_block(mcp_block),
            "notes": [
                "Use this MCP server entry in Cursor's MCP settings.",
                "The same singleton OreWatch MCP bridge is used for Cursor, Claude Code, and Codex.",
                "Replace older MCP configs that still use bare `orewatch`; bootstrap now emits the absolute local OreWatch binary path when it can resolve one.",
            ],
        },
        "vscode": {
            "label": CLIENT_LABELS["vscode"],
            "mode": "api",
            "snippet_format": "json",
            "snippet": _json_block(api_block),
            "notes": [
                "No first-party VS Code extension is bundled in this repo yet.",
                "Use this singleton API connection info when wiring a local VS Code integration.",
            ],
        },
        "jetbrains": {
            "label": CLIENT_LABELS["jetbrains"],
            "mode": "api",
            "snippet_format": "json",
            "snippet": _json_block(api_block),
            "notes": [
                "No first-party JetBrains / PyCharm plugin is bundled in this repo yet.",
                "Use this singleton API connection info when wiring a local JetBrains integration.",
            ],
        },
        "xcode": {
            "label": CLIENT_LABELS["xcode"],
            "mode": "api",
            "snippet_format": "json",
            "snippet": _json_block(api_block),
            "notes": [
                "No first-party Xcode extension is bundled in this repo yet.",
                "Use this singleton API connection info from a local helper, build-phase script, or custom Xcode integration.",
            ],
        },
    }
