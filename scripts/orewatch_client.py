#!/usr/bin/env python3
"""
Reusable MCP client for OreWatch's `monitor mcp` server.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from typing import Any, Dict, List, Optional

from monitor.ide_bootstrap import resolve_cli_invocation


DEFAULT_PROTOCOL_VERSION = "2024-11-05"


def _write_message(handle, payload: Dict[str, Any]) -> None:
    body = json.dumps(payload).encode("utf-8")
    handle.write(f"Content-Length: {len(body)}\r\n\r\n".encode("utf-8"))
    handle.write(body)
    handle.flush()


def _read_message(handle) -> Dict[str, Any]:
    headers: Dict[str, str] = {}
    while True:
        line = handle.readline()
        if not line:
            raise RuntimeError("MCP process exited unexpectedly")
        if line in (b"\r\n", b"\n"):
            break
        decoded = line.decode("utf-8").strip()
        if ":" in decoded:
            key, value = decoded.split(":", 1)
            headers[key.lower()] = value.strip()
    content_length = int(headers.get("content-length", "0") or 0)
    body = handle.read(content_length)
    return json.loads(body.decode("utf-8"))


def _extract_text_result(response: Dict[str, Any]) -> Dict[str, Any]:
    if "error" in response:
        error = response["error"]
        raise RuntimeError(error.get("message", str(error)))
    result = response.get("result", {})
    if result.get("isError"):
        content = result.get("content", [])
        if content and content[0].get("type") == "text":
            raise RuntimeError(content[0].get("text", "MCP tool call failed"))
        raise RuntimeError("MCP tool call failed")
    content = result.get("content", [])
    if not content:
        return {}
    text = content[0].get("text", "")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {"text": text}


class OreWatchMCPClient:
    """Persistent MCP client session for OreWatch."""

    def __init__(
        self,
        command: List[str],
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        stderr=None,
    ):
        self.command = list(command)
        self.cwd = cwd
        self.env = env
        self.stderr = stderr
        self.process: Optional[subprocess.Popen] = None
        self._message_id = 1
        self.tools: Dict[str, Dict[str, Any]] = {}

    def __enter__(self) -> "OreWatchMCPClient":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def _next_id(self) -> int:
        current = self._message_id
        self._message_id += 1
        return current

    def start(self) -> None:
        """Start the MCP process and complete the standard lifecycle."""
        if self.process is not None and self.process.poll() is None:
            return
        self.process = subprocess.Popen(
            self.command,
            cwd=self.cwd,
            env=self.env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self.stderr,
        )
        self.initialize()

    def _request(self, method: str, params: Optional[Dict[str, Any]] = None, expect_response: bool = True) -> Dict[str, Any]:
        if self.process is None or self.process.stdin is None or self.process.stdout is None:
            raise RuntimeError("MCP process is not running")
        payload: Dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if expect_response:
            payload["id"] = self._next_id()
        if params is not None:
            payload["params"] = params
        _write_message(self.process.stdin, payload)
        if expect_response:
            return _read_message(self.process.stdout)
        return {}

    def initialize(self) -> Dict[str, Any]:
        """Perform initialize, initialized notification, and tools/list."""
        response = self._request(
            "initialize",
            {
                "protocolVersion": DEFAULT_PROTOCOL_VERSION,
                "clientInfo": {"name": "orewatch-client", "version": "1.0"},
                "capabilities": {},
            },
        )
        self._request("notifications/initialized", {}, expect_response=False)
        tools_response = self._request("tools/list", {})
        self.tools = {
            tool["name"]: tool
            for tool in tools_response.get("result", {}).get("tools", [])
        }
        return response.get("result", {})

    def call_tool(self, tool_name: str, arguments: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Call one MCP tool after validating that it exists."""
        if tool_name not in self.tools:
            raise ValueError(f"Tool not advertised by MCP server: {tool_name}")
        response = self._request(
            "tools/call",
            {"name": tool_name, "arguments": arguments or {}},
        )
        return _extract_text_result(response)

    def close(self) -> None:
        """Terminate the MCP process."""
        if self.process is None:
            return
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        if self.process.stdin is not None:
            self.process.stdin.close()
        if self.process.stdout is not None:
            self.process.stdout.close()
        if self.process.stderr not in (None, sys.stderr, sys.stdout, subprocess.DEVNULL):
            try:
                self.process.stderr.close()
            except Exception:
                pass
        self.process = None


def _default_command(repo_root: str) -> List[str]:
    del repo_root
    invocation = resolve_cli_invocation(
        python_executable=sys.executable,
        prefer_console_script=False,
    )
    return [
        str(invocation["command"]),
        *[str(part) for part in invocation["args_prefix"]],
        "monitor",
        "mcp",
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description="Call the OreWatch MCP server like a real MCP client")
    parser.add_argument(
        "--cwd",
        default=os.getcwd(),
        help="Workspace root passed to the OreWatch MCP server",
    )
    parser.add_argument("--tool", help="Tool to call after initialize/tools/list")
    parser.add_argument(
        "--arguments-json",
        default="{}",
        help="JSON object passed as the tool arguments",
    )
    parser.add_argument(
        "--list-tools",
        action="store_true",
        help="Print the advertised tool names and exit",
    )
    parser.add_argument(
        "--command",
        nargs=argparse.REMAINDER,
        help="Override the MCP command; default is the packaged OreWatch entrypoint or module running `monitor mcp`",
    )
    args = parser.parse_args()

    command = args.command if args.command else _default_command(args.cwd)
    with OreWatchMCPClient(command=command, cwd=args.cwd, stderr=sys.stderr) as client:
        if args.list_tools:
            print(json.dumps(sorted(client.tools.keys()), indent=2))
            return 0
        if not args.tool:
            parser.error("--tool is required unless --list-tools is used")
        arguments = json.loads(args.arguments_json)
        result = client.call_tool(args.tool, arguments)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
