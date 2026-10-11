# The stack

rekit is layered so every layer can be used and verified on its own. Nothing executes a
sample: each backend is a read-only parser or a read-only analysis binary.

```
                     +-------------------------------+
  CLI / scripts ---> |  rekit.py  (13 subcommands)   |
                     |  triage strings iocs disasm   |
                     |  apk firmware js pcap ghidra  |
                     |  capa floss yara r2           |
                     +---------------+---------------+                              
                                     |
                                     v
                     +-------------------------------+
                     |  read-only backends           |
                     |  readelf objdump radare2 jadx |
                     |  binwalk tshark YARA capa     |
                     |  FLOSS Ghidra headless        |
                     +-------------------------------+
                                     ^
                                     |
                     +-------------------------------+
  MCP clients  ----> |  mcp_server.py (13 tools re_*)|
  (stdio / HTTP)     |  FastMCP "re-connector"       |
                     +-------------------------------+
                                     ^
                                     |
                     +-------------------------------+
  agents       ----> |  REA (rea-agents, optional)   |
                     |  125 MCP tools / 80 CLI cmds  |
                     |  evidence envelopes (sha256)  |
                     +-------------------------------+
```

## Layer 1 - rekit CLI

Single file, no service, no state. Every subcommand prints JSON on `--json` and reports a
missing backend as `tool_missing` instead of guessing. This is the layer to script and to
put in CI.

## Layer 2 - rekit MCP server

`mcp_server.py` exposes the same work as 13 MCP tools (`re_triage`, `re_strings`,
`re_iocs`, `re_disasm`, `re_apk`, `re_firmware`, `re_js`, `re_pcap`,
`re_ghidra_decompile`, `re_capa`, `re_floss`, `re_yara`, `re_health`) over stdio or
HTTP. `re_health` probes all 18 backends and reports which are installed, so a client can
tell "clean file" from "no tool available" before trusting a result.

## Layer 3 - REA (optional)

[REA](https://github.com/morluto/rea) is an independent agent-directed layer that drives
Ghidra/IDA/Hopper and returns **sha256-pinned evidence envelopes** (confidence, authority,
limitations) rather than bare text. It is optional: rekit works without it. When present,
its 125 tools sit on the same Ghidra install that `rekit ghidra` uses, so both layers see
identical binaries - see `docs/verification.md` for the cross-surface hash check.

## Choosing a layer

| Need | Use |
| --- | --- |
| One-off triage in a shell / CI | `rekit.py` (CLI) |
| Let an LLM agent reason over a binary | `mcp_server.py` (13 tools) |
| Deep, multi-step analysis with evidence trail | REA (125 tools) |
| Anything that must not run the sample | all three - static only |
