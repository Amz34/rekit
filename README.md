# rekit

[![ci](https://github.com/Amz34/rekit/actions/workflows/ci.yml/badge.svg)](https://github.com/Amz34/rekit/actions/workflows/ci.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![XERJ Corpus Hub contributor](https://hub.xerj.org/contributors/Amz34/badge.svg)](https://hub.xerj.org/contributors/Amz34)

**Read-only reverse-engineering toolkit — CLI and MCP server.**

`rekit` gives a terminal — and any MCP-speaking AI agent — a single safe front-end for
static analysis: file triage, strings, IOC extraction, disassembly, APK/DEX, firmware
images, JS bundles, PCAPs and headless Ghidra decompilation. It never executes a sample,
and it never invents a result.

![rekit — read-only static analysis toolkit: triage, strings, disassembly and headless Ghidra decompilation](assets/rekit-overview.jpg)

| Guarantee | How it works |
|---|---|
| **Read-only** | only analysis binaries are shelled out (`readelf`, `objdump`, `radare2`, `jadx`, `tshark`, Ghidra headless). A sample is never executed. |
| **Nothing faked** | a missing backend is reported as `{"tool_missing": "..."}` — never guessed, never silently skipped. |
| **Machine-readable** | every subcommand accepts `--json`, so an agent can parse it directly. |
| **Bounded** | every subprocess has a timeout; inputs are size-capped by `REKIT_MAX_BYTES` (default 3 GiB). |

## Subcommands

| command | what it does | backend (optional) |
|---|---|---|
| `triage` | sha256/md5, kind, sections, entropy, packer hints | `readelf` / `objdump` / `lief` |
| `strings` | strings + an "interesting" filter (URLs, keys, paths, JWTs) | pure Python |
| `iocs` | extract URLs, IPs, domains, keys, JWTs, wallets, onion addresses | pure Python |
| `disasm` | disassembly of a function/offset range | `radare2` or `objdump` |
| `apk` | APK/DEX: manifest, permissions, packer, string surface | `jadx` / `androguard` |
| `firmware` | firmware image signature scan (squashfs, ubifs, uboot, ELF…) | `binwalk` |
| `js` | JS bundle: endpoints, suspect secrets (redacted), obfuscation signals | pure Python |
| `pcap` | conversations, DNS, HTTP hosts, TLS SNI | `tshark` |
| `ghidra` | headless decompile to C (one function or all) | Ghidra `analyzeHeadless` |
| `capa` | capability / MITRE ATT&CK mapping | `capa` |
| `floss` | obfuscated and decoded strings | `floss` |
| `yara` | YARA scan, built-in ruleset or your own | `yara` |
| `r2` | raw radare2 escape hatch | `radare2` |

## Install

```bash
git clone https://github.com/Amz34/rekit.git && cd rekit
python3 rekit.py --help            # pure-stdlib CLI, no install needed
pip install -r requirements-mcp.txt   # only for the MCP server
```

Optional backends unlock the matching subcommands:

```bash
sudo apt-get install binutils radare2 binwalk tshark yara   # base set
pip install lief capstone androguard                        # richer parsing
# jadx / capa / floss / Ghidra: see their own install docs
```

Optional Python bindings are imported lazily — if they are absent, the subcommand still
runs with the fallback backend or reports `tool_missing`.

## Docker

The image speaks MCP over stdio, so any client can spawn it directly — this is also the
container Glama builds and introspects:

```bash
docker build -t rekit .
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"local","version":"1"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' | docker run -i --rm rekit
```

The server itself needs only Python and the pinned `mcp` package
(`requirements-mcp.txt`, `mcp>=1.0,<2` — the transport API it uses is 1.x).
The analysis backends stay out of the default image; `--build-arg
REKIT_FULL_TOOLCHAIN=1` bakes in `binutils`, `radare2`, `binwalk`, `tshark`,
`yara` and `flare-floss`. A backend that is not installed is reported as
`tool_missing`, never guessed.

## Usage

```bash
# triage a binary (JSON on every subcommand)
rekit triage /usr/bin/ls
# -> sha256, size_bytes, kind, arch, sections, entropy, packer hints

# strings, with an "interesting" bucket (URLs / keys / paths / JWTs)
rekit strings /usr/bin/ls | head

# extract indicators you can pivot on
rekit iocs sample.bin
# -> {"urls": [...], "ips": [...], "domains": [...], "jwts": [...], ...}

# disassemble a range, or a whole function
rekit disasm sample.bin --offset 0x1000 --length 64

# decompile with headless Ghidra
rekit ghidra ./sample.bin --preview 4000
```

Real output from the headless decompiler (aarch64 ELF, Ghidra 12.1.4, **356 lines of C**
written to `sample.bin.decompiled.c`):

```
186:int add(int a,int b)
197:/* ==== secret_check @ 001007f8 ==== */
199:int secret_check(char *s)
217:int main(int argc,char **argv)
```

## MCP server

`mcp_server.py` exposes the toolkit over MCP so an agent can call triage/strings/disasm/
Ghidra directly instead of shelling out. 13 tools:

`re_health`, `re_triage`, `re_strings`, `re_iocs`, `re_disasm`, `re_apk`, `re_firmware`,
`re_js`, `re_pcap`, `re_ghidra_decompile`, `re_capa`, `re_floss`, `re_yara`

Every tool is read-only: paths are validated inside `REKIT_WORK`, outputs are size-capped
and truncated with a `truncated: true` flag, and a missing backend returns `tool_missing`
rather than an error-free lie.

**stdio** (Claude Code, Codex, Cursor, opencode — anything that spawns a command):

```json
{ "mcpServers": { "rekit": { "command": "/path/to/rekit/mcp-stdio.sh" } } }
```

**streamable HTTP**:

```bash
python3 mcp_server.py --http --host 127.0.0.1 --port 8798   # endpoint: /mcp
```

Environment: `REKIT_BIN` (path to `rekit.py`), `REKIT_WORK` (job dir, default `~/rekit/work`),
`REKIT_MAX_BYTES` (default 3 GiB), `REKIT_TIMEOUT` (default 1800 s), `REKIT_GHIDRA_SCRIPTS`
(where the bundled Ghidra scripts live).

## Ghidra setup (optional)

```bash
export GHIDRA_INSTALL_DIR=/opt/ghidra_12.1.4_PUBLIC   # or anywhere analyzeHeadless lives
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-arm64   # auto-detected if unset
rekit ghidra ./sample.bin
```

`rekit ghidra` writes `<name>.decompiled.c` and reports `rc`, `c_lines` and the tail of
Ghidra's log, so a failed decompile is visible instead of looking empty. The bundled
`ghidra/DecompileAll.java` and `ghidra/ListFunctions.java` are used automatically.

Two hard-won details: Ghidra requires an **absolute** project path, and it **rejects any
path element starting with a dot** — so the default project dir is `~/rekit/ghidra_proj`,
not `~/.rekit/...` (passing a dotted path now fails with a clear message instead of a
Ghidra stack trace).

## Verified on

Full audit - method, evidence and known gaps - is in **[docs/verification.md](docs/verification.md)**.

| | |
|---|---|
| Architecture | aarch64 (ARM64) Linux, Ubuntu 24.04.4 |
| Python | 3.12 (venv) / 3.11 (system) |
| Ghidra | 12.1.4, JDK 21, native aarch64 decompiler |
| Agentic layer | `rea-agents` 4.1.0 - 125 MCP tools |
| Suite | `bash tests/run_rekit_suite.sh` → **16 checks: 16 pass, 0 fail, 0 skip** |
| MCP surface | 13/13 tools advertised over a real stdio handshake |
| Cross-surface | one binary, one sha256 - identical via `sha256sum`, `rekit triage` and REA |

On a host without the optional PE/APK fixtures or Ghidra, the same suite reports
`12 pass / 4 skip`, naming each missing input - a skip is never counted as a pass.

## The stack

rekit is the CLI/MCP layer. The optional agentic layer sits on the same Ghidra install:

* **[docs/stack.md](docs/stack.md)** - the three layers and when to use which.
* **[rea/README.md](rea/README.md)** - run REA as a second MCP server next to rekit.
* **[rea/agentic-re-map.md](rea/agentic-re-map.md)** - machine-readable map of all 125 REA
  tools, grouped by intent, with the golden chain and invariants. Regenerate it with
  `python3 rea/dump_tools.py && python3 rea/make_map.py`.
* **[docs/ghidra-arm64.md](docs/ghidra-arm64.md)** - the native aarch64 decompiler: why the
  release does not ship it, how to build it, and how to verify the ELF.

## Scope

Static analysis only. `rekit` does not run a sample, does not emulate it, and does not
detonate it — dynamic analysis belongs in a separate, network-isolated lane. If a backend
is missing the subcommand says so; it never substitutes a guess for a finding.

## License

MIT — see `LICENSE`.

---

**Try it in one line:**

```bash
git clone https://github.com/Amz34/rekit.git && cd rekit && python3 rekit.py triage /bin/ls --json
```

If it saves you time, a star helps others find it. Run the suite on your own host first -
if a lane reports `tool_missing`, or a check you expected is silently skipped, open an
issue with the suite log: the 16 checks above are the checklist.

Part of [my always-on agent stack](https://github.com/Amz34) · [Awesome Agent Infrastructure](https://github.com/Amz34/awesome-agent-infrastructure) (135 live-checked building blocks).
