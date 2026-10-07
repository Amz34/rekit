# rekit

**Read-only reverse-engineering toolkit — CLI and MCP server.**

`rekit` gives a terminal — and any MCP-speaking AI agent — a single safe front-end for
static analysis: file triage, strings, IOC extraction, disassembly, APK/DEX, firmware
images, JS bundles, PCAPs and headless Ghidra decompilation. It never executes a sample,
and it never invents a result.

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

| | |
|---|---|
| Architecture | aarch64 (ARM64) Linux, Ubuntu 24.04 |
| Python | 3.12 |
| Ghidra | 12.1.4, JDK 21 |
| Backends present | `readelf`, `objdump`, `radare2`, `binwalk`, `tshark`, `yara` |
| Smoke test | `python3 tests/smoke_test.py` → 4 CLI checks + 1 MCP check, all pass |

## Scope

Static analysis only. `rekit` does not run a sample, does not emulate it, and does not
detonate it — dynamic analysis belongs in a separate, network-isolated lane. If a backend
is missing the subcommand says so; it never substitutes a guess for a finding.

## License

MIT — see `LICENSE`.

---

Part of [my always-on agent stack](https://github.com/Amz34) · [Awesome Agent Infrastructure](https://github.com/Amz34/awesome-agent-infrastructure) (135 live-checked building blocks).
