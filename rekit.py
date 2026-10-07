#!/usr/bin/env python3
"""rekit - read-only reverse engineering toolkit (CLI + library).

Static triage for ELF/PE/Mach-O, APK/DEX, firmware images, JS bundles and PCAPs.
Every backend is optional: a missing tool is reported as tool_missing, never faked.

Usage:  rekit <command> <path> [--json] [options]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

JADX_DIR = os.environ.get("REKIT_JADX", os.path.expanduser("~/ops/vendor/re/jadx"))
R2 = shutil.which("radare2") or shutil.which("r2")
READELF = shutil.which("readelf")
OBJDUMP = shutil.which("objdump")
STRINGS = shutil.which("strings")
BINWALK = shutil.which("binwalk")
UNBL0B = shutil.which("unblob")
EXIFTOOL = shutil.which("exiftool")
TSHARK = shutil.which("tshark")
NODE = os.environ.get("REKIT_NODE") or (shutil.which("node") or "")
NPM = os.environ.get("REKIT_NPM") or (shutil.which("npm") or "")
APKTOOL = shutil.which("apktool")
GHIDRA_HOME = os.environ.get("GHIDRA_INSTALL_DIR", "")
JAVA_HOME = os.environ.get("JAVA_HOME", "")


def run(cmd, timeout=240, cwd=None, input_text=None):
    """Run a command, return (rc, stdout, stderr). Never raises on rc!=0."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           cwd=cwd, input=input_text, errors="replace")
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s"
    except FileNotFoundError:
        return 127, "", f"not found: {cmd[0]}"
    except Exception as e:  # pragma: no cover
        return 1, "", f"{type(e).__name__}: {e}"


def have(binary):
    return bool(binary and (shutil.which(binary) or Path(binary).exists()))


def sha256(path, limit=None):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def md5(path):
    h = hashlib.md5()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def file_kind(path):
    """Magic sniffing without external 'file' (ELF/PE/Mach-O/DEX/ZIP/AR/GZIP...)."""
    with open(path, "rb") as fh:
        head = fh.read(4096)
    if head[:4] == b"\x7fELF":
        cls = {1: "ELF32", 2: "ELF64"}.get(head[4], "ELF?")
        endian = {1: "LE", 2: "BE"}.get(head[5], "?")
        etype = {1: "relocatable", 2: "executable", 3: "shared-object",
                 4: "core"}.get(head[16], "?")
        return f"{cls} {endian} {etype}"
    if head[:2] == b"MZ":
        return "PE/DOS (MZ)"
    if head[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf",
                    b"\xcf\xfa\xed\xfe"):
        return "Mach-O"
    if head[:4] == b"dex\n":
        return f"DEX ({head[4:7].decode('ascii', 'replace')})"
    if head[:4] == b"PK\x03\x04":
        with open(path, "rb") as fh:
            blob = fh.read(1 << 18)
        if b"AndroidManifest.xml" in blob:
            return "APK (ZIP w/ AndroidManifest)"
        if b"classes.dex" in blob:
            return "JAR/ZIP containing DEX"
        if b"[Content_Types].xml" in blob:
            return "OOXML/ZIP (docx/xlsx/pptx)"
        return "ZIP"
    if head[:8] == b"!<arch>\n":
        return "ar archive (deb/lib)"
    if head[:2] == b"\x1f\x8b":
        return "gzip"
    if head[:4] == b"\x28\xb5\x2f\xfd":
        return "zstd"
    if head[:6] == b"7z\xbc\xaf\x27\x1c":
        return "7z"
    if head[:5] == b"Rar!\x1a":
        return "rar"
    if head[:4] == b"\x00\x00\x00\x00" or head[:4] == b"\x00\x00\x00\x01":
        return "MP4/ISO-BMFF"
    if head[:256].lstrip().startswith((b"<?xml", b"<!DOCTYPE", b"<html", b"<!DOCTYPE html")):
        return "XML/HTML"
    if head[:2] == b"#!":
        return "script (shebang)"
    try:
        head[:512].decode("utf-8")
        return "text/unknown"
    except UnicodeDecodeError:
        return "binary/unknown"


def json_out(obj, as_json):
    if as_json:
        print(json.dumps(obj, indent=2, default=str))
    else:
        print(pretty(obj))
    return 0


def pretty(obj, indent=0):
    pad = "  " * indent
    out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (dict, list)) and v:
                out.append(f"{pad}{k}:")
                out.append(pretty(v, indent + 1))
            else:
                out.append(f"{pad}{k}: {v}")
    elif isinstance(obj, list):
        for v in obj[:60]:
            if isinstance(v, (dict, list)):
                out.append(pretty(v, indent + 1))
            else:
                out.append(f"{pad}- {v}")
        if len(obj) > 60:
            out.append(f"{pad}... (+{len(obj) - 60} more)")
    else:
        out.append(f"{pad}{obj}")
    return "\n".join(out)
# ---------------------------------------------------------------- binary triage
def fmt_sections(path):
    """Section table + entropy via LIEF, falling back to readelf."""
    out = {"source": None, "sections": []}
    try:
        import lief  # type: ignore
        b = lief.parse(path)
        if b is not None:
            out["source"] = "lief"
            for s in b.sections:
                try:
                    raw = bytes(s.content)
                    ent = round(entropy(raw), 2)
                except Exception:
                    ent = None
                out["sections"].append({
                    "name": s.name,
                    "size": s.size,
                    "vaddr": hex(getattr(s, "virtual_address", 0)),
                    "entropy": ent,
                    "flags": str(getattr(s, "flags", "")),
                })
            out["format"] = str(getattr(b, "format", "")) if hasattr(b, "format") else type(b).__name__
            return out
    except ImportError:
        out["note"] = "python-lief not installed"
    except Exception as e:
        out["note"] = f"lief failed: {e}"
    if READELF:
        rc, so, se = run([READELF, "-S", "-W", path])
        out["source"] = "readelf" if rc == 0 else None
        for line in so.splitlines():
            m = re.match(r"\s*\[\s*\d+\]\s+(\S+)\s+(\S+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)", line)
            if m:
                out["sections"].append({"name": m.group(1), "type": m.group(2),
                                        "size": int(m.group(5), 16)})
    return out


def fmt_imports(path):
    """Imports + linked libraries."""
    res = {"libraries": [], "imports": [], "exports": []}
    try:
        import lief  # type: ignore
        b = lief.parse(path)
        if b is not None:
            try:
                res["libraries"] = list(b.libraries)
            except Exception:
                pass
            try:
                res["imports"] = sorted({e.name for e in b.imported_symbols if e.name})
            except Exception:
                pass
            try:
                res["exports"] = sorted({e.name for e in b.exported_symbols if e.name})
            except Exception:
                pass
            if res["imports"] or res["exports"]:
                return res
    except Exception:
        pass
    if READELF:
        rc, so, _ = run([READELF, "-d", "-W", path])
        if rc == 0:
            res["libraries"] = re.findall(r"Shared library: \[([^\]]+)\]", so)
        rc, so, _ = run([READELF, "--dyn-syms", "-W", path])
        if rc == 0:
            for line in so.splitlines():
                m = re.search(r"\b(UND|GLOBAL DEFAULT\s+UND)\b.*?(\S+)$", line)
                if m:
                    res["imports"].append(m.group(2))
            res["imports"] = sorted(set(res["imports"]))
    return res


def elf_headers(path):
    if not READELF:
        return {"tool_missing": "readelf"}
    rc, so, _ = run([READELF, "-h", "-W", path])
    info = {}
    for k, pat in (("type", r"Type:\s+(.+)"), ("machine", r"Machine:\s+(.+)"),
                   ("entry", r"Entry point address:\s+(\S+)"),
                   ("interp", r"Requesting program interpreter: ([^\]]+)")):
        m = re.search(pat, so)
        if m:
            info[k] = m.group(1).strip()
    rc2, so2, _ = run([READELF, "-l", "-W", path])
    if "GNU_STACK" in so2:
        info["nx"] = "no RWE on GNU_STACK" if "RWE" not in so2.split("GNU_STACK")[1][:200] else "STACK IS EXECUTABLE"
    if "GNU_RELRO" in so2:
        info["relro"] = "present"
    return info


def packed_hints(path, sections):
    hints = []
    names = [s.get("name", "") for s in sections]
    if any(n.startswith("UPX") for n in names):
        hints.append("UPX packed (UPX0/UPX1 section names)")
    if any(n in (".aspack", "ASPack") for n in names):
        hints.append("ASPack")
    if any(n in (".themida", ".vmp0", ".vmp1") for n in names):
        hints.append("Themida/VMProtect-style protection")
    if any(n in (".enigma1", ".enigma2") for n in names):
        hints.append("Enigma protector")
    if "pyinstaller" in path.lower() or any("pyi-" in n for n in names):
        hints.append("PyInstaller bundle")
    return hints


def cmd_triage(args):
    path = args.path
    if not Path(path).is_file():
        return json_out({"error": f"not a file: {path}"}, args.json)
    st = os.stat(path)
    kind = file_kind(path)
    res = {
        "path": str(Path(path).resolve()),
        "size_bytes": st.st_size,
        "kind": kind,
        "sha256": sha256(path),
        "md5": md5(path),
        "whole_file_entropy": round(entropy(open(path, "rb").read(min(st.st_size, 4 << 20))), 2),
    }
    secs = fmt_sections(path)
    res["section_source"] = secs.get("source")
    res["sections"] = secs.get("sections", [])
    hi = [s for s in res["sections"] if isinstance(s.get("entropy"), (int, float)) and s["entropy"] > 7.2]
    res["high_entropy_sections"] = [s["name"] for s in hi]
    if kind.startswith("ELF"):
        res["elf"] = elf_headers(path)
        imp = fmt_imports(path)
        res["needed_libraries"] = imp.get("libraries", [])
        res["imports_count"] = len(imp.get("imports", []))
        res["imports_sample"] = imp.get("imports", [])[:40]
        res["exports_count"] = len(imp.get("exports", []))
        if "pyinstaller" in kind.lower():
            pass
    elif kind.startswith("PE"):
        try:
            import lief  # type: ignore
            b = lief.parse(path)
            res["pe"] = {"machine": str(b.header.machine), "dlls": list(b.libraries),
                         "timestamp": str(b.header.time_date_stamps)}
        except Exception as e:
            res["pe_note"] = f"lief unavailable: {e}"
    elif kind.startswith("Mach-O"):
        rc, so, _ = run([STRINGS or "strings", "-n", "6", path])
        res["slice_note"] = "Mach-O detected; use disasm/ghidra for full analysis"
    elif kind.startswith("APK") or "DEX" in kind:
        res["android"] = apk_summary(path)
    res["packer_hints"] = packed_hints(path, res["sections"])
    res["tools"] = {k: bool(v) for k, v in (("radare2", R2), ("binwalk", BINWALK),
                                            ("jadx", Path(JADX_DIR, "bin", "jadx").exists()),
                                            ("ghidra", bool(GHIDRA_HOME)), ("tshark", TSHARK),
                                            ("node", NODE))}
    return json_out(res, args.json)


# ------------------------------------------------------------------- strings/ioc
def cmd_strings(args):
    path = args.path
    min_len = args.min_len
    if STRINGS:
        rc, so, _ = run([STRINGS, "-n", str(min_len), "-a", path], timeout=180)
        lines = so.splitlines() if rc == 0 else []
        src = "strings"
    else:
        lines, src = _py_strings(path, min_len), "python"
    uniq = list(dict.fromkeys(l.strip() for l in lines if l.strip()))
    interesting = [s for s in uniq if _interesting(s)][: args.top]
    res = {"path": path, "source": src, "total_unique": len(uniq),
           "interesting_count": len(interesting), "interesting": interesting}
    if args.regex:
        pat = re.compile(args.regex, re.I)
        res["regex_matches"] = [s for s in uniq if pat.search(s)][: args.top]
    return json_out(res, args.json)


def _py_strings(path, min_len=4):
    data = Path(path).read_bytes()
    return [m.group().decode("utf-8", "replace")
            for m in re.finditer(rb"[ -~]{%d,}" % min_len, data)]


INTERESTING = re.compile(
    r"(https?://|ftp://|/api/|/v\d/|token|secret|api[_-]?key|password|passwd|BEGIN [A-Z ]*PRIVATE KEY|"
    r"AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{10,}\.|mongodb://|postgres://|mysql://|redis://|"
    r"-----BEGIN CERTIFICATE|Bearer |aws_|S3_|firebaseio|amazonaws\.com|\.onion|"
    r"eval\(|atob\(|fromCharCode|debug|root:|admin:|flag\{)", re.I)


def _interesting(s):
    return bool(INTERESTING.search(s))


IOC_PATTERNS = {
    "url": re.compile(r"https?://[^\s\"'<>\\]{4,200}"),
    "ip": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "email": re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.]{2,}\b"),
    "btc": re.compile(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}\b"),
    "eth": re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b"),
    "aws_key": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "private_key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "onion": re.compile(r"\b[a-z2-7]{16}\.onion\b"),
    "registry_path": re.compile(r"\b(?:HKEY_LOCAL_MACHINE|HKLM|HKCU)\\[^\s\"']{3,120}", re.I),
}
def cmd_iocs(args):
    path = args.path
    raw = Path(path).read_bytes()[: args.max_bytes]
    text = raw.decode("utf-8", "replace")
    if args.from_strings and STRINGS:
        rc, so, _ = run([STRINGS, "-n", "5", "-a", path], timeout=180)
        text = so if rc == 0 else text
    res = {"path": path, "scanned_bytes": len(raw), "counts": {}, "iocs": {}}
    for name, pat in IOC_PATTERNS.items():
        hits = list(dict.fromkeys(m.group() for m in pat.finditer(text)))
        # filter obvious noise
        if name == "ip":
            hits = [h for h in hits if not h.startswith(("0.", "255.", "127.0.0.1"))]
        if name == "email":
            hits = [h for h in hits if not h.lower().endswith((".png", ".jpg", ".gif", ".css", ".js"))]
        if hits:
            res["iocs"][name] = hits[: args.top]
            res["counts"][name] = len(hits)
    return json_out(res, args.json)


def cmd_disasm(args):
    path = args.path
    res = {"path": path, "backend": None, "instructions": []}
    if R2:
        cmd = ["aaa"] if not args.quick else ["aa"]
        if args.symbol:
            cmd.append(f"s {args.symbol}")
            cmd.append(f"pdf {args.count}")
        elif args.offset:
            cmd.append(f"s {args.offset}")
            cmd.append(f"pd {args.count}")
        else:
            cmd.append(f"pd {args.count} @ entry0")
        rc, so, se = run([R2, "-q", "-A", "-c", ";".join(cmd), "-c", "q", path],
                         timeout=args.timeout)
        if rc == 0 and so.strip():
            res["backend"] = "radare2"
            res["instructions"] = [l for l in so.splitlines() if l.strip()][: args.count]
            return json_out(res, args.json)
        res["r2_error"] = (se or so)[:600]
    if OBJDUMP:
        cmd = [OBJDUMP, "-d", "--no-show-raw-insn"]
        if args.symbol:
            cmd.append(f"--disassemble={args.symbol}")
        cmd.append(path)
        rc, so, _ = run(cmd, timeout=args.timeout)
        if rc == 0:
            res["backend"] = "objdump"
            res["instructions"] = [l.rstrip() for l in so.splitlines() if l.strip()][-args.count:]
            return json_out(res, args.json)
    res["error"] = "no disassembler available (need radare2 or objdump)"
    return json_out(res, args.json)


def _dex_in_zip(path):
    import zipfile
    try:
        with zipfile.ZipFile(path) as z:
            return sorted(n for n in z.namelist() if n.endswith(".dex"))
    except Exception:
        return []


def apk_summary(path, deep=False):
    """Static APK facts: permissions, exported components, packer, native libs."""
    out = {"apk": True, "dex_files": _dex_in_zip(path)}
    try:
        import zipfile
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
        out["file_count"] = len(names)
        out["libs"] = sorted({n.split("/")[1] for n in names
                              if n.startswith("lib/") and n.count("/") > 2})
        out["has_assets"] = any(n.startswith("assets/") for n in names)
        out["native_libs"] = [n for n in names if n.startswith("lib/") and n.endswith(".so")]
    except Exception as e:
        out["zip_error"] = str(e)
    try:
        from androguard.core.apk import APK  # type: ignore
        a = APK(path)
        out["package"] = a.get_package()
        out["app_name"] = a.get_app_name()
        out["version"] = f"{a.get_androidversion_name()} ({a.get_androidversion_code()})"
        out["min_sdk"] = a.get_min_sdk_version()
        out["target_sdk"] = a.get_target_sdk_version()
        perms = a.get_permissions()
        out["permissions_count"] = len(perms)
        out["permissions_dangerous"] = sorted(p for p in perms if any(
            k in p for k in ("SMS", "CALL", "RECORD_AUDIO", "CAMERA", "LOCATION",
                             "CONTACTS", "PHONE_STATE", "INSTALL_PACKAGES",
                             "SYSTEM_ALERT_WINDOW", "ACCESSIBILITY", "QUERY_ALL_PACKAGES",
                             "MANAGE_EXTERNAL_STORAGE", "READ_LOGS", "REQUEST_INSTALL")))
        act = a.get_activities()
        try:
            acts = [x.get_name() for x in act]
        except Exception:
            acts = list(act)
        per = [x for x in a.get_permissions()]
        exported = []
        for tag in ("activity", "service", "receiver", "provider"):
            try:
                for item in a.get_element(tag) or []:
                    if item.get("android:exported") == "true" or (
                            item.get("android:exported") is None and item.get("android:name", "").find(".") >= 0
                            and "intent-filter" in str(item).lower()):
                        name = item.get("android:name")
                        if name:
                            exported.append(f"{tag}:{name}")
            except Exception:
                pass
        out["activities_count"] = len(acts)
        out["exported_components"] = exported[:40]
        out["permissions_sample"] = per[:25]
    except ImportError:
        out["androguard"] = "not installed"
    except Exception as e:
        out["androguard_error"] = f"{type(e).__name__}: {e}"[:300]
    if shutil.which("apkid"):
        rc, so, se = run(["apkid", "-j", path], timeout=120)
        try:
            import json as _j
            out["apkid"] = _j.loads(so)
        except Exception:
            out["apkid_raw"] = (so or se)[:400]
    else:
        try:
            rc, so, se = run([sys.executable, "-m", "apkid", "-j", path], timeout=120)
            if rc == 0 and so.strip():
                import json as _j
                out["apkid"] = _j.loads(so)
        except Exception:
            pass
    return out


def cmd_apk(args):
    if not Path(args.path).is_file():
        return json_out({"error": f"not a file: {args.path}"}, args.json)
    res = apk_summary(args.path, deep=True)
    if args.jadx:
        outdir = Path(args.out or (Path(args.path).stem + "_jadx"))
        jadx = Path(JADX_DIR, "bin", "jadx")
        if jadx.exists():
            rc, so, se = run([str(jadx), "-d", str(outdir), "--no-res", args.path],
                             timeout=args.timeout)
            res["jadx"] = {"outdir": str(outdir.resolve()), "rc": rc,
                           "stderr_tail": se[-400:] if rc != 0 else "",
                           "java_files": sum(1 for _ in outdir.rglob("*.java")) if outdir.exists() else 0}
        else:
            res["jadx"] = {"tool_missing": str(jadx)}
    if args.dex_strings:
        if STRINGS:
            rc, so, _ = run([STRINGS, "-n", "6", "-a", args.path], timeout=180)
            lines = list(dict.fromkeys(so.splitlines()))
            res["interesting_strings"] = [s for s in lines if _interesting(s)][:60]
    return json_out(res, args.json)


def cmd_firmware(args):
    res = {"path": args.path, "signatures": [], "backend": None}
    if BINWALK:
        rc, so, se = run([BINWALK, "--signature", args.path], timeout=args.timeout)
        if rc == 0:
            res["backend"] = "binwalk"
            res["signatures"] = [l.rstrip() for l in so.splitlines() if l.strip()][:120]
            res["signature_count"] = len(res["signatures"])
            return json_out(res, args.json)
        res["binwalk_error"] = se[:400]
    rc, so, _ = run(["python3", "-c",
                     "import binwalk,sys;print(binwalk.__version__)"], timeout=30)
    res["error"] = "binwalk CLI unavailable"
    return json_out(res, args.json)


JS_SECRETS = re.compile(
    r"(?i)(api[_-]?key|secret|token|passwd|password|authorization|bearer|firebase|"
    r"client[_-]?secret|private[_-]?key)\s*[:=]\s*[\"']([^\"']{6,160})[\"']")


def cmd_js(args):
    path = Path(args.path)
    res = {"path": str(path.resolve()), "size": path.stat().st_size if path.exists() else 0}
    text = path.read_text(errors="replace") if path.is_file() else ""
    res["endpoints"] = sorted(set(IOC_PATTERNS["url"].findall(text)))[:60]
    res["secrets_suspect"] = [f"{m.group(1)} = <redacted len={len(m.group(2))}>"
                              for m in JS_SECRETS.finditer(text)][:30]
    res["obfuscation"] = {
        "has_eval": bool(re.search(r"\beval\s*\(", text)),
        "has_atob": bool(re.search(r"\batob\s*\(", text)),
        "has_fromcharcode": "fromCharCode" in text,
        "hex_escapes": len(re.findall(r"\\x[0-9a-fA-F]{2}", text)),
        "unicode_escapes": len(re.findall(r"\\u[0-9a-fA-F]{4}", text)),
        "minified_line_len": max((len(l) for l in text.splitlines()), default=0),
    }
    if args.deobfuscate:
        if have(NODE) and have(NPM):
            outdir = Path(args.out or (path.parent / (path.stem + "_deob")))
            rc, so, se = run([NPM, "exec", "--yes", "--", "webcrack", str(path),
                              "-o", str(outdir)], timeout=args.timeout)
            res["webcrack"] = {"outdir": str(outdir.resolve()), "rc": rc,
                               "files": sum(1 for _ in outdir.rglob("*")) if outdir.exists() else 0,
                               "stderr": se[-300:] if rc else ""}
        else:
            res["webcrack"] = {"tool_missing": "node/npm"}
    return json_out(res, args.json)


def cmd_pcap(args):
    if not TSHARK:
        return json_out({"error": "tshark missing (apt install tshark)"}, args.json)
    res = {"path": args.path}
    rc, so, _ = run([TSHARK, "-r", args.path, "-q", "-z", "conv,ip"], timeout=args.timeout)
    res["conversations"] = [l.rstrip() for l in so.splitlines() if l.strip()][:80]
    rc, so, _ = run([TSHARK, "-r", args.path, "-T", "fields", "-e", "dns.qry.name"], timeout=args.timeout)
    res["dns"] = sorted({l.strip() for l in so.splitlines() if l.strip()})[:80]
    rc, so, _ = run([TSHARK, "-r", args.path, "-T", "fields", "-e", "http.host",
                     "-e", "http.request.uri"], timeout=args.timeout)
    res["http"] = [l.strip() for l in so.splitlines() if l.strip()][:80]
    rc, so, _ = run([TSHARK, "-r", args.path, "-T", "fields", "-e", "tls.handshake.extensions_server_name"],
                    timeout=args.timeout)
    res["tls_sni"] = sorted({l.strip() for l in so.splitlines() if l.strip()})[:80]
    try:
        res["size_bytes"] = Path(args.path).stat().st_size
    except Exception:
        pass
    return json_out(res, args.json)
# ------------------------------------------------------------------ ghidra / capa
def ghidra_home():
    """Locate a Ghidra install: GHIDRA_INSTALL_DIR / GHIDRA_HOME first, then common spots."""
    import glob as _glob
    cands = [GHIDRA_HOME, os.environ.get("GHIDRA_INSTALL_DIR"),
             "/opt/ghidra", os.path.expanduser("~/ghidra")]
    for pat in ("/opt/ghidra_*_PUBLIC", "/opt/ghidra*",
                os.path.expanduser("~/tools/ghidra_*_PUBLIC"),
                os.path.expanduser("~/*/ghidra_*_PUBLIC"),
                os.path.expanduser("~/*/*/ghidra_*_PUBLIC"),
                os.path.expanduser("~/*/*/*/ghidra_*_PUBLIC"),
                os.path.expanduser("~/.rekit/ghidra_*_PUBLIC")):
        cands += sorted(_glob.glob(pat), reverse=True)
    for cand in cands:
        if cand and Path(cand, "support", "analyzeHeadless").exists():
            return cand
    return ""


def cmd_ghidra(args):
    home = ghidra_home()
    if not home:
        return json_out({"error": "Ghidra not found (set GHIDRA_INSTALL_DIR)"}, args.json)
    headless = Path(home, "support", "analyzeHeadless")
    proj = Path(args.project_dir or "~/rekit/ghidra_proj").expanduser()
    if not proj.is_absolute():
        proj = proj.resolve()
    bad = [p for p in proj.parts[1:] if p.startswith(".")]
    if bad:
        return json_out({"error": "Ghidra rejects project paths with a '.' element "
                                  f"({proj}); use e.g. ~/rekit/ghidra_proj"}, args.json)
    proj.mkdir(parents=True, exist_ok=True)
    out_c = Path(args.out or (Path(args.path).name + ".decompiled.c")).resolve()
    here = Path(__file__).resolve().parent
    _sp = os.environ.get("REKIT_GHIDRA_SCRIPTS", "").strip()
    script_path = Path(_sp) if _sp else None
    if script_path is None or not script_path.is_dir():
        script_path = here / "ghidra" if (here / "ghidra" / "DecompileAll.java").exists() else here
    env = dict(os.environ)
    if not env.get("JAVA_HOME"):
        import glob as _glob
        jvms = [j for j in sorted(_glob.glob("/usr/lib/jvm/java-*-openjdk-*"))
                if Path(j, "bin", "javac").exists()]
        if jvms:
            env["JAVA_HOME"] = jvms[-1]
    cmd = [str(headless), str(proj), "rekit", "-import", str(Path(args.path).resolve()),
           "-overwrite", "-scriptPath", str(script_path),
           "-postScript", "DecompileAll.java", str(out_c)]
    if args.functions:
        cmd += ["-postScript", "ListFunctions.java"]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=args.timeout,
                           env=env, errors="replace")
        rc, so, se = p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        rc, so, se = 124, "", f"timeout after {args.timeout}s"
    res = {"backend": "ghidra-headless", "ghidra": home, "rc": rc,
           "c_output": str(out_c) if out_c.exists() else None,
           "c_lines": sum(1 for _ in open(out_c, errors="replace")) if out_c.exists() else 0,
           "stdout_tail": so[-500:], "stderr_tail": se[-800:]}
    if out_c.exists() and args.preview:
        with open(out_c, errors="replace") as fh:
            res["preview"] = fh.read(args.preview)
    return json_out(res, args.json)


def cmd_capa(args):
    capa = shutil.which("capa") or str(Path(sys.executable).parent / "capa")
    if not Path(capa).exists():
        return json_out({"error": "capa not installed (pip install flare-capa)"}, args.json)
    rc, so, se = run([capa, "-q", args.path], timeout=args.timeout)
    lines = [l.rstrip() for l in so.splitlines() if l.strip()]
    rules = [l for l in lines if re.match(r"^\s*[A-Za-z][\w /().,-]{3,}$", l)]
    mitre = sorted({m for l in lines for m in re.findall(r"(T\d{4}(?:\.\d{3})?)", l)})
    res = {"backend": "capa", "rc": rc, "matched_capability_lines": rules[:120],
           "mitre_techniques": mitre, "stderr_tail": se[-300:] if rc else ""}
    return json_out(res, args.json)


def cmd_floss(args):
    floss = shutil.which("floss") or str(Path(sys.executable).parent / "floss")
    if not Path(floss).exists():
        return json_out({"error": "floss not installed (pip install flare-floss)"}, args.json)
    rc, so, se = run([floss, "-q", "--no-static-strings", args.path], timeout=args.timeout)
    decoded = [l.rstrip() for l in so.splitlines() if l.strip()]
    res = {"backend": "flare-floss", "rc": rc, "decoded_count": len(decoded),
           "decoded_sample": decoded[:100], "stderr_tail": se[-400:] if rc else ""}
    if rc != 0:
        res["note"] = "floss supports PE/ELF(x86) best; some formats unsupported"
    return json_out(res, args.json)


BUILTIN_YARA = r"""
rule rekit_upx_packer { meta: author="rekit" strings: $a="UPX0" $b="UPX1" condition: 2 of them }
rule rekit_ransom_note {
  meta: author="rekit" strings: $a="your files have been encrypted" nocase
  $b="all your files" nocase $c="decrypt" nocase $d="bitcoin" nocase
  condition: 2 of them
}
rule rekit_creds_dump_tools {
  meta: author="rekit" strings: $a="sekurlsa" nocase $b="lsass" nocase $c="mimikatz" nocase $d="wce.exe" nocase
  condition: any of them
}
rule rekit_shell_spawn { meta: author="rekit" strings: $a="/bin/sh -c" $b="cmd.exe /c" nocase condition: any of them }
rule rekit_reverse_shell_hint {
  meta: author="rekit" strings: $a="socket" $b="connect" $c="dup2" condition: all of them
}
rule rekit_b64_blob_in_js { meta: author="rekit" strings: $a="atob(" $b="eval(" condition: all of them }
"""


def cmd_yara(args):
    res = {"path": args.path, "rules_file": args.rules, "matches": []}
    try:
        import yara  # type: ignore
    except ImportError:
        return json_out({"error": "yara-python not installed"}, args.json)
    if args.rules:
        rules = yara.compile(filepath=args.rules)
    else:
        rules = yara.compile(source=BUILTIN_YARA)
    try:
        matches = rules.match(args.path, timeout=120)
        res["matches"] = [{"rule": m.rule, "tags": m.tags,
                           "strings": [f"{s.identifier}@{s.instances[0].offset}" for s in m.strings][:20]}
                          for m in matches]
        res["match_count"] = len(matches)
    except Exception as e:
        res["error"] = f"{type(e).__name__}: {e}"[:300]
    return json_out(res, args.json)


def cmd_r2(args):
    """Raw radare2 escape hatch (read-only analysis commands)."""
    if not R2:
        return json_out({"error": "radare2 not installed"}, args.json)
    res = {"backend": "radare2", "path": args.path, "results": []}
    cmd = ([args.cmd] if args.cmd else []) + (["q"] if "q" not in args.cmd else [])
    rc, so, se = run([R2, "-q", "-A", "-c", ";".join(cmd), args.path], timeout=args.timeout)
    res["rc"] = rc
    res["out"] = so[:6000]
    if rc != 0:
        res["err"] = se[:600]
    return json_out(res, args.json)


# ------------------------------------------------------------------------ main
def build_parser():
    p = argparse.ArgumentParser(prog="rekit", description="read-only RE toolkit")
    sub = p.add_subparsers(dest="command", required=True)

    def common(sp):
        sp.add_argument("--json", action="store_true", help="machine-readable output")
        return sp

    sp = common(sub.add_parser("triage", help="hash/type/sections/entropy/packer hints"))
    sp.add_argument("path")
    sp.set_defaults(func=cmd_triage)

    sp = common(sub.add_parser("strings", help="strings + interesting-string filter"))
    sp.add_argument("path")
    sp.add_argument("--min-len", type=int, default=6)
    sp.add_argument("--top", type=int, default=80)
    sp.add_argument("--regex", default="")
    sp.set_defaults(func=cmd_strings)

    sp = common(sub.add_parser("iocs", help="extract URLs/IPs/keys/JWTs/etc"))
    sp.add_argument("path")
    sp.add_argument("--max-bytes", type=int, default=64 << 20)
    sp.add_argument("--top", type=int, default=60)
    sp.add_argument("--from-strings", action="store_true")
    sp.set_defaults(func=cmd_iocs)

    sp = common(sub.add_parser("disasm", help="disassembly via radare2/objdump"))
    sp.add_argument("path")
    sp.add_argument("--symbol", default="")
    sp.add_argument("--offset", default="")
    sp.add_argument("--count", type=int, default=60)
    sp.add_argument("--quick", action="store_true")
    sp.add_argument("--timeout", type=int, default=300)
    sp.set_defaults(func=cmd_disasm)

    sp = common(sub.add_parser("apk", help="APK/DEX manifest, permissions, packer, jadx"))
    sp.add_argument("path")
    sp.add_argument("--jadx", action="store_true")
    sp.add_argument("--dex-strings", action="store_true")
    sp.add_argument("--out", default="")
    sp.add_argument("--timeout", type=int, default=900)
    sp.set_defaults(func=cmd_apk)

    sp = common(sub.add_parser("firmware", help="firmware image signature scan"))
    sp.add_argument("path")
    sp.add_argument("--timeout", type=int, default=600)
    sp.set_defaults(func=cmd_firmware)

    sp = common(sub.add_parser("js", help="JS bundle endpoints/secrets/deobfuscate"))
    sp.add_argument("path")
    sp.add_argument("--deobfuscate", action="store_true")
    sp.add_argument("--out", default="")
    sp.add_argument("--timeout", type=int, default=600)
    sp.set_defaults(func=cmd_js)

    sp = common(sub.add_parser("pcap", help="pcap summary: conv/dns/http/sni"))
    sp.add_argument("path")
    sp.add_argument("--timeout", type=int, default=300)
    sp.set_defaults(func=cmd_pcap)

    sp = common(sub.add_parser("ghidra", help="headless decompile to C"))
    sp.add_argument("path")
    sp.add_argument("--out", default="")
    sp.add_argument("--project-dir", default="")
    sp.add_argument("--functions", action="store_true")
    sp.add_argument("--preview", type=int, default=0)
    sp.add_argument("--timeout", type=int, default=1800)
    sp.set_defaults(func=cmd_ghidra)

    sp = common(sub.add_parser("capa", help="capability/MITRE mapping (PE/ELF)"))
    sp.add_argument("path")
    sp.add_argument("--timeout", type=int, default=900)
    sp.set_defaults(func=cmd_capa)

    sp = common(sub.add_parser("floss", help="obfuscated/decoded strings"))
    sp.add_argument("path")
    sp.add_argument("--timeout", type=int, default=900)
    sp.set_defaults(func=cmd_floss)

    sp = common(sub.add_parser("yara", help="yara scan (builtin or --rules)"))
    sp.add_argument("path")
    sp.add_argument("--rules", default="")
    sp.set_defaults(func=cmd_yara)

    sp = common(sub.add_parser("r2", help="raw radare2 command escape hatch"))
    sp.add_argument("path")
    sp.add_argument("cmd", nargs="?", default="iI;iz;ii")
    sp.add_argument("--timeout", type=int, default=300)
    sp.set_defaults(func=cmd_r2)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.func(args) or 0
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
