# Changelog

## 1.1.0

The stack release: the optional agentic layer, the aarch64 decompiler path, and a suite that
actually exercises every lane against in-repo fixtures.

### Added

* `rea/` - run REA (`rea-agents`) as a second MCP server next to rekit:
  * `rea-mcp.sh` derives `JAVA_HOME` and requires `GHIDRA_INSTALL_DIR` instead of hard-coding
    machine paths.
  * `patch-arm64.py` - idempotent `--check` / `--revert` patch that allowlists aarch64 Linux
    in `rea-agents` <= 6.0.x (upstream, fixed in REA 6.1.0).
  * `rea/README.md` - wiring, the aarch64 status matrix, and the two-server config snippet.
* `docs/ghidra-arm64.md` - how to get a native aarch64 Ghidra decompiler, how to verify the
  ELF, and why Java-side analysis works while decompilation fails without it.
* `docs/stack.md` - the three layers (CLI, MCP server, agentic) and when to use which.
* `docs/verification.md` - the audit: what was tested, on what, and what was found.
* `tests/run_rekit_suite.sh` - 17-check end-to-end suite driven by in-repo fixtures, with
  `--quick` for CI and explicit `SKIP` when a backend is absent.
* `tests/mcp_tools_check.py` - real MCP handshake; fails unless all 13 tools are advertised.
* `tests/samples/` - small self-contained fixtures: `tiny.c`, `tiny2.c`, `tiny_asm.s`,
  `sample.js`, and a stdlib-only PCAP generator (DNS + HTTP + TLS SNI, no scapy/dpkt).

### Changed

* Suite fixtures are generated locally; no third-party binaries are vendored. PE/APK lanes
  are opt-in via `REKIT_PE_SAMPLE` / `REKIT_APK_SAMPLE`.

### Verified

* 13/13 rekit subcommands, 13/13 MCP tools, the headless Ghidra decompile on aarch64, and
  REA's 125-tool surface - see `docs/verification.md`.
