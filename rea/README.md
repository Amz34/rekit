# REA integration (optional agentic layer)

rekit is a toolkit. [REA](https://github.com/morluto/rea) (`rea-agents`) is an independent
agent-directed layer that drives the same local analysis engines - Ghidra, IDA, Hopper -
and returns results as **sha256-pinned evidence envelopes** (confidence, authority,
limitations) instead of loose text. This directory holds the glue for running REA as an MCP
server alongside rekit, plus the one patch older REA builds need on aarch64.

## Files

| File | Purpose |
| --- | --- |
| `rea-mcp.sh` | Launches `rea mcp` as a stdio MCP server with `JAVA_HOME` / `GHIDRA_INSTALL_DIR` set correctly. |
| `patch-arm64.py` | Allowlists aarch64 Linux in `rea-agents` <= 6.0.x, which hard-coded x64. `--check` / `--revert` supported. |

## Wiring it up

Add to your MCP client config (Claude Code, Codex, Cursor, OpenCode, Hermes, ...):

```json
{
  "mcpServers": {
    "rekit":  { "command": "/path/to/rekit/mcp-stdio.sh" },
    "rea":    { "command": "/path/to/rekit/rea/rea-mcp.sh" }
  }
}
```

Two servers, one Ghidra install. `rekit` gives fast, deterministic, read-only extraction
(13 tools); `rea` adds the deep agentic workflow (125 tools, 80 CLI commands). Both report
the same binary identity - see `docs/verification.md` for the cross-surface hash check.

## aarch64 status

`rea-agents` gates its Ghidra provider on a hard-coded platform check. On Linux aarch64
that check failed even when a working native decompiler was present, so REA refused to use
Ghidra on ARM hosts.

| `rea-agents` | Behaviour on Linux aarch64 | Action |
| --- | --- | --- |
| <= 6.0.x | Ghidra provider rejected: `architecture === "x64"` for Linux | run `patch-arm64.py` after every install |
| >= 6.1.0 | `NATIVE_PLATFORMS.linux` includes `arm64` -> `linux_arm_64` | nothing to do |

This gate was reported upstream and fixed in `rea-agents` 6.1.0; verify on your version:

```bash
python3 rea/patch-arm64.py --check     # prints: patched | already-stock | upstream-fix-present
```

The patch is idempotent, keeps a `.js.orig` backup and is wiped by `npm i -g rea-agents`,
so re-run `--check` after each upgrade. It only relaxes an allowlist - it never changes how
Ghidra or REA analyse a binary.

## Requirements

* Ghidra with a native decompiler for your host - see `docs/ghidra-arm64.md`.
* An MCP client, and JDK 21+ (`rea-mcp.sh` derives `JAVA_HOME` when it is unset).
* `npm i -g rea-agents`, then `rea mcp` must start cleanly on its own.
