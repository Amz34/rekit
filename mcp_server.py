#!/usr/bin/env python3
"""re-connector - MCP server exposing the local read-only RE toolkit (rekit).

Lane: static analysis only. Nothing from a sample is ever executed:
rekit shells out to read-only analysis binaries (radare2/objdump/readelf/jadx/
binwalk/tshark/Ghidra headless) and Python parsers (lief/capstone/androguard).

Transport: stdio (default, for Hermes mcp_servers) or --http --host --port.

SAFETY: never point this at a live host; samples are untrusted input.
Dynamic/emulated execution belongs to the sandbox lane (untrusted-code-sandbox-lane).
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from mcp.server.fastmcp import FastMCP

_HERE = Path(__file__).resolve().parent
REKIT = Path(os.environ.get("REKIT_BIN", str(_HERE / "rekit.py"))).expanduser()
RE_PY = Path(os.environ.get("REKIT_PYTHON", ""))
WORK = Path(os.environ.get("REKIT_WORK", "~/rekit/work")).expanduser()
MAX_BYTES = int(os.environ.get("REKIT_MAX_BYTES", str(3 << 30)))
TIMEOUT = int(os.environ.get("REKIT_TIMEOUT", "1800"))

mcp = FastMCP("re-connector")


def _python() -> str:
    return str(RE_PY) if RE_PY.exists() else sys.executable


def _guard(path: str) -> str:
    p = Path(path).expanduser()
    if not p.exists():
        raise ValueError(f"path does not exist: {p}")
    if p.is_dir():
        raise ValueError(f"expected a file, got a directory: {p}")
    size = p.stat().st_size
    if size > MAX_BYTES:
        raise ValueError(f"file too large: {size} bytes > {MAX_BYTES}")
    return str(p.resolve())


def _rekit(sub: str, *a, timeout: int = TIMEOUT) -> dict:
    cmd = [_python(), str(REKIT), sub, *a, "--json"]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           errors="replace")
    except subprocess.TimeoutExpired:
        return {"error": f"rekit {sub} timed out after {timeout}s"}
    out = (p.stdout or "").strip()
    if not out:
        return {"error": f"rekit {sub} produced no output", "rc": p.returncode,
                "stderr": (p.stderr or "")[-800:]}
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return {"raw": out[-4000:], "rc": p.returncode, "stderr": (p.stderr or "")[-400:]}


def _workdir() -> Path:
    d = WORK / time.strftime("%Y%m%d_%H%M%S")
    d.mkdir(parents=True, exist_ok=True)
    return d


@mcp.tool()
def re_health() -> dict:
    """Report which RE backends are available on this host (no sample needed)."""
    bins = ["radare2", "r2", "objdump", "readelf", "strings", "binwalk", "tshark",
            "jadx", "apktool", "yara", "gdb", "patchelf", "upx", "java", "node", "npx",
            "mitmproxy", "qemu-x86_64"]
    out = {
        "rekit": str(REKIT),
        "rekit_python": _python(),
        "rekit_python_exists": RE_PY.exists(),
        "workdir": str(WORK),
        "binaries": {b: bool(shutil.which(b)) for b in bins},
        "ghidra": {
            "env": os.environ.get("GHIDRA_INSTALL_DIR", ""),
            "found": next((str(Path(c)) for c in
                           [os.path.expanduser("~/ops/vendor/re/ghidra_12.1.4_PUBLIC"), "/opt/ghidra"]
                           if Path(c, "support", "analyzeHeadless").exists()), ""),
        },
    }
    rc = subprocess.run([_python(), "-c",
                         "import lief,capstone,androguard;print('py:lief,capstone,androguard ok')"],
                        capture_output=True, text=True)
    out["python_modules"] = (rc.stdout or rc.stderr).strip()[-300:]
    return out


@mcp.tool()
def re_triage(path: str) -> dict:
    """Hash, file type, sections+entropy, imports/exports, packer hints for any binary/APK."""
    return _rekit("triage", _guard(path), timeout=600)


@mcp.tool()
def re_strings(path: str, min_len: int = 6, top: int = 100, regex: str = "") -> dict:
    """Extract strings, flag security-relevant ones (URLs, keys, tokens), optional regex."""
    a = ["_", "--min-len", str(min_len), "--top", str(top)]
    if regex:
        a += ["--regex", regex]
    a[0] = _guard(path)
    return _rekit("strings", *a, timeout=600)


@mcp.tool()
def re_iocs(path: str, from_strings: bool = False, top: int = 60) -> dict:
    """Extract indicators of compromise: URLs, IPs, emails, JWTs, cloud keys, wallets, onion."""
    a = [_guard(path), "--top", str(top)]
    if from_strings:
        a.append("--from-strings")
    return _rekit("iocs", *a, timeout=600)


@mcp.tool()
def re_disasm(path: str, symbol: str = "", offset: str = "", count: int = 80) -> dict:
    """Disassemble a function (by symbol) or at an address (offset) via radare2/objdump."""
    a = [_guard(path), "--count", str(count)]
    if symbol:
        a += ["--symbol", symbol]
    if offset:
        a += ["--offset", offset]
    return _rekit("disasm", *a, timeout=600)


@mcp.tool()
def re_apk(path: str, decompile_java: bool = False) -> dict:
    """Android APK: package, permissions, exported components, native libs, packer; optional jadx."""
    a = [_guard(path)]
    if decompile_java:
        a += ["--jadx", "--out", str(_workdir() / "jadx_out")]
    else:
        a += ["--dex-strings"]
    return _rekit("apk", *a, timeout=1800)


@mcp.tool()
def re_firmware(path: str) -> dict:
    """Firmware/embedded image layout: filesystems, kernels, compressed blobs (binwalk)."""
    return _rekit("firmware", _guard(path), timeout=1800)


@mcp.tool()
def re_js(path: str, deobfuscate: bool = False) -> dict:
    """JavaScript bundle: endpoints, suspect secrets (redacted), obfuscation signals; optional webcrack."""
    a = [_guard(path)]
    if deobfuscate:
        a += ["--deobfuscate", "--out", str(_workdir() / "js_deob")]
    return _rekit("js", *a, timeout=1800)


@mcp.tool()
def re_pcap(path: str) -> dict:
    """Traffic summary from a capture: conversations, DNS names, HTTP hosts/URIs, TLS SNI."""
    return _rekit("pcap", _guard(path), timeout=900)


@mcp.tool()
def re_ghidra_decompile(path: str, preview_chars: int = 0) -> dict:
    """Headless Ghidra: full decompiler output for every function, written to an artifact dir."""
    out = _workdir() / (Path(path).name + ".decompiled.c")
    a = [_guard(path), "--out", str(out)]
    if preview_chars:
        a += ["--preview", str(preview_chars)]
    return _rekit("ghidra", *a, timeout=3600)


@mcp.tool()
def re_capa(path: str) -> dict:
    """Capability detection + MITRE ATT&CK technique mapping (capa; PE and ELF)."""
    return _rekit("capa", _guard(path), timeout=1800)


@mcp.tool()
def re_floss(path: str) -> dict:
    """Recover obfuscated/stack/decoded strings with FLARE FLOSS."""
    return _rekit("floss", _guard(path), timeout=1800)


@mcp.tool()
def re_yara(path: str, rules_file: str = "") -> dict:
    """YARA scan with a builtin malware-indicator ruleset, or your own rules file."""
    a = [_guard(path)]
    if rules_file:
        a += ["--rules", _guard(rules_file)]
    return _rekit("yara", *a, timeout=900)


def main():
    if "--http" in sys.argv:
        host = "127.0.0.1"
        port = 8798
        if "--host" in sys.argv:
            host = sys.argv[sys.argv.index("--host") + 1]
        if "--port" in sys.argv:
            port = int(sys.argv[sys.argv.index("--port") + 1])
        mcp.settings.host = host
        mcp.settings.port = port
        mcp.run(transport="streamable-http")
    else:
        mcp.run()


if __name__ == "__main__":
    main()
