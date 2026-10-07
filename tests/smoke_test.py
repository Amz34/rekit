#!/usr/bin/env python3
"""Self-contained smoke test for rekit (CLI + MCP server).

Run:  python3 tests/smoke_test.py
Needs: no network. The MCP half needs the `mcp` package (pip install -r requirements-mcp.txt).
Every check runs for real - nothing is mocked inside rekit itself.
"""
import json
import socket
import subprocess
import sys
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REKIT = ROOT / "rekit.py"
SERVER = ROOT / "mcp_server.py"
TARGET = "/usr/bin/ls" if Path("/usr/bin/ls").exists() else "/bin/sh"


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def rekit(*args: str, timeout: int = 300) -> dict:
    out = subprocess.run([sys.executable, str(REKIT), *args, "--json"],
                         capture_output=True, text=True, timeout=timeout)
    if out.returncode != 0:
        raise AssertionError(f"rekit {args[0]} rc={out.returncode}: {out.stderr[-400:]}")
    return json.loads(out.stdout)


class TestCli(unittest.TestCase):
    def test_triage(self):
        d = rekit("triage", TARGET)
        for key in ("sha256", "size_bytes", "kind"):
            self.assertIn(key, d)
        self.assertEqual(len(d["sha256"]), 64)

    def test_strings(self):
        d = rekit("strings", TARGET)
        self.assertGreater(d["total_unique"], 0)

    def test_disasm(self):
        d = rekit("disasm", TARGET)
        self.assertIsInstance(d, dict)

    def test_iocs(self):
        d = rekit("iocs", TARGET)
        self.assertIn("counts", d)


class TestMcp(unittest.TestCase):
    def test_lists_re_tools(self):
        try:
            import mcp  # noqa: F401
        except ImportError:
            self.skipTest("mcp package not installed (pip install -r requirements-mcp.txt)")
        port = free_port()
        proc = subprocess.Popen([sys.executable, str(SERVER), "--http",
                                 "--host", "127.0.0.1", "--port", str(port)],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        url = f"http://127.0.0.1:{port}/mcp"

        def post(payload, session=None):
            headers = {"Content-Type": "application/json",
                       "Accept": "application/json, text/event-stream"}
            if session:
                headers["mcp-session-id"] = session
            req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                         headers=headers)
            with urllib.request.urlopen(req, timeout=15) as r:
                return r.status, r.read().decode(), r.headers.get("mcp-session-id")

        def payload_of(raw):
            """Streamable HTTP answers may arrive as SSE frames."""
            if "data:" in raw:
                raw = [ln[5:].strip() for ln in raw.splitlines() if ln.startswith("data:")][-1]
            return json.loads(raw)

        try:
            deadline = time.time() + 40
            session = None
            last = None
            while time.time() < deadline:          # wait for boot, then handshake
                try:
                    _, raw, session = post({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                            "params": {"protocolVersion": "2025-06-18",
                                                       "capabilities": {},
                                                       "clientInfo": {"name": "smoke",
                                                                      "version": "0"}}})
                    payload_of(raw)
                    break
                except Exception as exc:
                    last = exc
                    time.sleep(2)
            else:
                self.fail(f"MCP server never answered initialize: {last}")
            post({"jsonrpc": "2.0", "method": "notifications/initialized"}, session=session)
            status, raw, _ = post({"jsonrpc": "2.0", "id": 2, "method": "tools/list",
                                   "params": {}}, session=session)
            self.assertEqual(status, 200)
            tools = [t["name"] for t in payload_of(raw)["result"]["tools"]]
            self.assertGreaterEqual(len(tools), 10)
            self.assertTrue(all(n.startswith("re_") for n in tools), tools)
            for expected in ("re_triage", "re_strings", "re_iocs", "re_ghidra_decompile"):
                self.assertIn(expected, tools)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()


if __name__ == "__main__":
    unittest.main(verbosity=2)
