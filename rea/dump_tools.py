#!/usr/bin/env python3
"""Dump REA's live MCP tool surface to JSON.

    python3 rea/dump_tools.py            # -> rea/tools.json

Feeds `rea/make_map.py`, which turns the dump into the capability map. Requires
the `mcp` package and a working `rea` install (see rea/README.md); GHIDRA_INSTALL_DIR
and JAVA_HOME are taken from the environment.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import pathlib
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

HERE = pathlib.Path(__file__).resolve().parent


async def dump(launcher: str, out: pathlib.Path) -> int:
    env = {k: v for k, v in os.environ.items() if k in
           ("PATH", "HOME", "JAVA_HOME", "GHIDRA_INSTALL_DIR", "REA_BIN", "LANG")}
    params = StdioServerParameters(command="bash", args=[launcher], env=env)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as s:
            init = await s.initialize()
            tools = (await s.list_tools()).tools
            try:
                prompts = [p.name for p in (await s.list_prompts()).prompts]
            except Exception:
                prompts = []
            doc = {
                "server": init.serverInfo.name,
                "version": init.serverInfo.version,
                "tool_count": len(tools),
                "prompt_count": len(prompts),
                "prompts": prompts,
                "tools": [{
                    "name": t.name,
                    "description": (t.description or "").strip(),
                    "required": (t.inputSchema or {}).get("required", []),
                    "properties": list(((t.inputSchema or {}).get("properties")) or {}),
                } for t in tools],
            }
    out.write_text(json.dumps(doc, indent=2) + "\n")
    print(f"wrote {out} ({len(tools)} tools, {len(prompts)} prompts)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--launcher", default=str(HERE / "rea-mcp.sh"))
    ap.add_argument("--out", default=str(HERE / "tools.json"))
    a = ap.parse_args()
    try:
        return asyncio.run(dump(a.launcher, pathlib.Path(a.out)))
    except Exception as e:                                    # pragma: no cover
        print(f"dump failed: {type(e).__name__}: {e}", file=sys.stderr)
        print("is rea installed and GHIDRA_INSTALL_DIR set?", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
