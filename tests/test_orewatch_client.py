import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest


REPO_ROOT = os.path.dirname(os.path.dirname(__file__))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from scripts.orewatch_client import _default_command
from scripts.orewatch_client import OreWatchMCPClient


FAKE_SERVER = r"""
import json
import sys

state = {"initialized": False, "notified": False, "listed": False}

def write(payload):
    body = json.dumps(payload).encode("utf-8")
    sys.stdout.write(f"Content-Length: {len(body)}\r\n\r\n")
    sys.stdout.flush()
    sys.stdout.buffer.write(body)
    sys.stdout.buffer.flush()

def read():
    headers = {}
    while True:
        line = sys.stdin.buffer.readline()
        if not line:
            raise SystemExit(0)
        if line in (b"\r\n", b"\n"):
            break
        decoded = line.decode("utf-8").strip()
        if ":" in decoded:
            key, value = decoded.split(":", 1)
            headers[key.lower()] = value.strip()
    content_length = int(headers.get("content-length", "0") or 0)
    body = sys.stdin.buffer.read(content_length)
    return json.loads(body.decode("utf-8"))

while True:
    message = read()
    method = message.get("method")
    message_id = message.get("id")
    if method == "initialize":
        state["initialized"] = True
        write({
            "jsonrpc": "2.0",
            "id": message_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "fake", "version": "1.0"},
            },
        })
    elif method == "notifications/initialized":
        state["notified"] = True
    elif method == "tools/list":
        state["listed"] = True
        write({
            "jsonrpc": "2.0",
            "id": message_id,
            "result": {
                "tools": [
                    {
                        "name": "orewatch_health",
                        "description": "health",
                        "inputSchema": {"type": "object"},
                    }
                ]
            },
        })
    elif method == "tools/call":
        if not (state["initialized"] and state["notified"] and state["listed"]):
            write({
                "jsonrpc": "2.0",
                "id": message_id,
                "result": {
                    "content": [{"type": "text", "text": json.dumps({"error": "bad lifecycle"})}],
                    "isError": True,
                },
            })
            continue
        write({
            "jsonrpc": "2.0",
            "id": message_id,
            "result": {
                "content": [{"type": "text", "text": json.dumps({"decision": "allow"})}],
                "isError": False,
            },
        })
"""


class OreWatchClientTests(unittest.TestCase):
    def test_default_command_uses_singleton_mcp_without_repo_script_assumption(self):
        with tempfile.TemporaryDirectory() as workspace_root:
            command = _default_command(workspace_root)

        self.assertEqual(
            command[-2:],
            ["monitor", "mcp"],
        )
        self.assertNotIn(
            os.path.join(workspace_root, "malicious_package_scanner.py"),
            command,
        )

    def test_client_performs_full_mcp_lifecycle_before_calling_tool(self):
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as server_file:
            server_file.write(textwrap.dedent(FAKE_SERVER))
            server_path = server_file.name

        try:
            with OreWatchMCPClient([sys.executable, server_path], cwd=REPO_ROOT, stderr=subprocess.DEVNULL) as client:
                self.assertIn("orewatch_health", client.tools)
                result = client.call_tool("orewatch_health", {})
        finally:
            os.unlink(server_path)

        self.assertEqual(result["decision"], "allow")

    def test_client_rejects_tool_calls_that_were_not_advertised(self):
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as server_file:
            server_file.write(textwrap.dedent(FAKE_SERVER))
            server_path = server_file.name

        try:
            with OreWatchMCPClient([sys.executable, server_path], cwd=REPO_ROOT, stderr=subprocess.DEVNULL) as client:
                with self.assertRaisesRegex(ValueError, "Tool not advertised"):
                    client.call_tool("orewatch_check_dependency_add", {})
        finally:
            os.unlink(server_path)


if __name__ == "__main__":
    unittest.main()
