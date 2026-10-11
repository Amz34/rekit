#!/usr/bin/env python3
"""Assert the rekit MCP server actually exposes its tools over stdio.

Spawns `mcp-stdio.sh` (or `mcp_server.py` directly), performs a real MCP
handshake, and fails unless the expected tools are advertised. This is the
check that would have caught a silently empty tool list.

Exit 0 = all expected tools present. Exit 1 = mismatch (details on stderr).
"""
from __future__ import annotations

import asyncio
import os
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)

EXPECTED = {
    "re_health", "re_triage", "re_strings", "re_iocs", "re_disasm", "re_apk",
    "re_firmware", "re_js", "re_pcap", "re_ghidra_decompile", "re_capa",
    "re_floss", "re_yara",
}


async def check() -> int:
    launcher = os.path.join(REPO, "mcp-stdio.sh")
    if os.access(launcher, os.X_OK):
        params = StdioServerParameters(command="bash", args=[launcher])
    else:
        params = StdioServerParameters(command=sys.executable,
                                       args=[os.path.join(REPO, "mcp_server.py")])
    # The interpreter running this check already has `mcp`; hand it to the
    # launcher so mcp-stdio.sh does not have to guess and bail out.
    params.env = {
        **os.environ,
        "REKIT_BIN": os.path.join(REPO, "rekit.py"),
        "REKIT_PYTHON": sys.executable,
    }

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            init = await session.initialize()
            tools = {t.name for t in (await session.list_tools()).tools}
            print(f"server={init.serverInfo.name} version={init.serverInfo.version}")
            print(f"tools={len(tools)}: {', '.join(sorted(tools))}")
            missing = EXPECTED - tools
            if missing:
                print(f"FAIL missing tools: {sorted(missing)}", file=sys.stderr)
                return 1
            if len(tools) < len(EXPECTED):
                print("FAIL advertised fewer tools than expected", file=sys.stderr)
                return 1
            print(f"OK {len(tools)} tools advertised")
            return 0


if __name__ == "__main__":
    try:
        import mcp.server.fastmcp  # noqa: F401
    except ImportError as exc:
        import importlib.metadata as md
        try:
            ver = md.version("mcp")
        except Exception:
            ver = "not installed"
        print(f"the rekit MCP server needs mcp 1.x; found: {ver} ({exc})\n"
              f"fix: pip install -r requirements-mcp.txt", file=sys.stderr)
        raise SystemExit(2)
    raise SystemExit(asyncio.run(check()))
