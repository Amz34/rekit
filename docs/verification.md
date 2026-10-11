# Verification

This document records what was actually tested, on what host, and what the results were.
Every number below came from running the stack - none of it is quoted from documentation.
Anything that could not be verified is listed under *Not covered*.

## Environment

| Item | Value |
| --- | --- |
| Host | Linux `aarch64` (Ampere A1, 2 cores, 11 GiB RAM) |
| OS | Ubuntu 24.04.4 LTS |
| Python | 3.11.15 (system) / 3.12.3 (rekit venv) |
| Java | OpenJDK 21.0.12.1 |
| Ghidra | 12.1.4 (headless, native aarch64 decompiler) |
| REA | `rea-agents` 4.1.0 |
| Date | 2026-10-11 |

## Method

Every claim is produced by execution, from the outside in: the suite drives the CLI, a
real MCP handshake drives the server, and REA is driven over its own stdio transport. The
fixtures are built from source in this repository, so the results are reproducible without
downloading third-party samples.

## Results

### 1. rekit CLI - 16 checks, 16 pass

```
== rekit suite 2026-10-11T10:48:03Z  quick=0 ==
triage_elf             rc=0       1s     5255 bytes
triage_elf_static      rc=0       0s     4069 bytes
triage_asm             rc=0       1s     1574 bytes
strings_elf            rc=0       0s      306 bytes
iocs_elf               rc=0       0s      318 bytes
js_scan                rc=0       0s      513 bytes
disasm_elf             rc=0       0s     5933 bytes
firmware_scan          rc=0       1s      438 bytes
yara_elf               rc=0       0s      127 bytes
pcap_summary           rc=0       1s     1025 bytes
apk_summary            rc=0       1s     2007 bytes
capa_pe                rc=0       1s      363 bytes
floss_pe               rc=0       2s      546 bytes
mcp_stdio_tools        rc=0       2s      207 bytes
rea_present            rc=0       4s        6 bytes
ghidra_decompile       rc=0      20s     2879 bytes
== suite complete: pass=16 fail=0 skip=0 ==
```

Every lane returns non-empty output; none of the 16 checks is a skip. In `--quick` mode the
same suite reports `pass=12 fail=0 skip=4`, because the four checks whose inputs or
backends are absent are reported as `SKIP` with the reason - never as a pass.

### 2. MCP surface - 13 of 13 tools

A real MCP handshake over the `mcp-stdio.sh` launcher:

```
server=re-connector version=1.30.0
tools=13: re_apk, re_capa, re_disasm, re_firmware, re_floss,
          re_ghidra_decompile, re_health, re_iocs, re_js,
          re_pcap, re_strings, re_triage, re_yara
OK 13 tools advertised
```

`re_health` probes 18 backends and reports which are present, so a client can distinguish
"nothing found" from "no tool installed" before trusting an empty result.

### 3. Headless decompilation on aarch64 - works

`ghidra_decompile` (20 s) decompiles the in-repo aarch64 fixture. On a larger target, a
`/usr/bin/ls` analysis produced **412 functions** after a ~39 s auto-analysis pass on the
2-core host - the cost is Ghidra's analysis, not the ARM build.

The native decompiler in use is a real aarch64 ELF built for this host:

```
ELF 64-bit LSB pie executable, ARM aarch64, dynamically linked, not stripped
size 4,100,768 bytes   BuildID 48e6bdead2959b05761177ffdee2d70811a2673f
```

### 4. REA agentic layer - 125 tools

```
rea 4.1.0  ->  mcp_tools=125   cli_commands=80   prompts=6
```

A full agent chain was driven over stdio against `/usr/bin/ls`:

| Step | Result |
| --- | --- |
| `open_binary` | 275 ms, `arch=arm64` |
| `list_procedures` | 38.9 s, 523 rows / 412 real functions |
| `procedure_pseudo_code` | pseudocode + sha256-pinned evidence envelope (`confidence=observed`, `authority=shipped-artifact`) |
| `close_binary` | 126 ms |

### 5. Cross-surface consistency - one binary, one identity

The same file must hash identically no matter which layer opened it:

```
sha256sum /usr/bin/ls     fd9344759be2490eb7f1053ac1bb52924bc54695c420a973b9875bb60863d427
rekit triage ... sha256   fd9344759be2490eb7f1053ac1bb52924bc54695c420a973b9875bb60863d427
REA open_binary sha256    fd9344759be2490eb7f1053ac1bb52924bc54695c420a973b9875bb60863d427
```

All three agree, so results from `rekit` and REA can be correlated in one report.

## Defects found during this audit

Testing the stack found real problems, including two in the test harness itself:

1. **TCP data-offset bug in the PCAP fixture generator.** The data-offset nibble was written
   into the wrong byte, so Wireshark reported *Bogus TCP header length* and never dissected
   HTTP/TLS. Fixed; the fixture now yields DNS, HTTP host/path and TLS SNI.
2. **Backend gate only checked `PATH`.** `capa` and `floss` are installed beside the
   interpreter, so five checks were skipped while their backends were present. The gate now
   mirrors rekit's own resolution (PATH, then next to the interpreter).
3. **Argument-order bug silently skipped five checks**, reported as
   `backend '120' not installed`. Fixed; those lanes now execute.
4. **REA refused Ghidra on aarch64** because of a hard-coded x64 platform check. Reported
   upstream and fixed in `rea-agents` 6.1.0; `rea/patch-arm64.py` covers older versions.
5. **No native aarch64 decompiler in the Ghidra release.** Java-side analysis worked while
   decompilation failed. Built and verified - see `docs/ghidra-arm64.md`.
6. **The MCP check could not distinguish "no `mcp` package" from "wrong `mcp` version".** A
   guard that only tested `import mcp` passed on `mcp` 2.0.0 (where `mcp.server.fastmcp` no
   longer exists) and then died with a bare *Connection refused* after a 40 s wait. Now every
   gate checks the capability the server actually needs and names the installed version - the
   same trap existed in `mcp-stdio.sh`, the suite's interpreter picker and the smoke test.

## Not covered

* **Dynamic or emulated execution.** Out of scope by design: every backend is static and
  read-only. Malware detonation belongs in an isolated sandbox, not here.
* **IDA and Hopper providers.** Both are absent on this host (proprietary, or macOS-only),
  so REA's multi-provider fallback was exercised only through Ghidra.
* **REA version drift.** Installed 4.1.0 was tested; upstream is ahead of it. `rea doctor`
  also reports client-registration entries for assistants that are not installed here -
  configuration drift, not a functional failure.
* **Timings are host-specific.** The 2-core host makes auto-analysis the dominant cost;
  treat the seconds above as orders of magnitude, not benchmarks.
