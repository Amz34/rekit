#!/usr/bin/env python3
"""Allow REA (rea-agents) to run on aarch64 Linux hosts.

Background
----------
`rea-agents` <= 6.0.x hard-coded an x64-only check for Linux hosts in
``dist/ghidra/GhidraInstallation.js``::

    passed: ((platform === "linux" || platform === "win32") &&
        architecture === "x64") || ...

That rejects an aarch64 host even when Ghidra's native arm64 decompiler
(``Ghidra/Features/Decompiler/os/linux_arm_64/decompile``) is present and
working. This script rewrites the check to allow ``arm64`` on Linux.

Status
------
Fixed upstream after we reported it (morluto/rea issue #1131). ``rea-agents``
>= 6.1.0 ships an explicit platform map - ``linux: { x64: "linux_x86_64",
arm64: "linux_arm_64" }`` - so this patch is a no-op there and only useful for
pinned pre-6.1.0 installs. Run with ``--check`` first; it will tell you.

Note: ``node_modules`` is replaced on every npm upgrade, so a patched 4.x/5.x
install needs re-patching after each install.

Usage
-----
    python3 patch-arm64.py --check          # report only (exit 0 if usable)
    python3 patch-arm64.py                  # apply (idempotent, keeps .orig backup)
    python3 patch-arm64.py --revert         # restore the stock file
    python3 patch-arm64.py --root /path/to/node_modules/rea-agents
"""
from __future__ import annotations

import argparse
import pathlib
import shutil
import subprocess
import sys

OLD_ARCH = """        passed: ((platform === "linux" || platform === "win32") &&
            architecture === "x64") ||
            (platform === "darwin" &&
                (architecture === "x64" || architecture === "arm64")),"""

NEW_ARCH = """        passed: (platform === "win32" && architecture === "x64") ||
            (platform === "linux" &&
                (architecture === "x64" || architecture === "arm64")) ||
            (platform === "darwin" &&
                (architecture === "x64" || architecture === "arm64")),"""

OLD_REMEDIATION = '        remediation: "Use x64 on Linux or Windows, or x64/arm64 on macOS.",'
NEW_REMEDIATION = ('        remediation: "Use x64 on Windows, x64/arm64 on Linux '
                   '(native decompiler required) or macOS.",')

# Present in >= 6.1.0, where upstream already allows arm64 on Linux.
UPSTREAM_FIX_MARKER = 'arm64: "linux_arm_64"'


def npm_global_root() -> pathlib.Path:
    for cmd in (["npm", "root", "-g"],):
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if out.returncode == 0 and out.stdout.strip():
                return pathlib.Path(out.stdout.strip())
        except (OSError, subprocess.SubprocessError):
            pass
    return pathlib.Path.home() / ".local/lib/node_modules"


def target_files(root: pathlib.Path) -> list[pathlib.Path]:
    base = root if root.name == "rea-agents" else root / "rea-agents"
    return sorted(base.glob("dist/ghidra/GhidraInstallation.js"))


def patch(path: pathlib.Path, revert: bool = False) -> str:
    text = path.read_text()
    if UPSTREAM_FIX_MARKER in text and not revert:
        return "upstream-fixed"
    if revert:
        if NEW_ARCH not in text:
            return "already-stock"
        pairs = [(NEW_ARCH, OLD_ARCH), (NEW_REMEDIATION, OLD_REMEDIATION)]
    else:
        if OLD_ARCH not in text:
            return "already-patched" if NEW_ARCH in text else "PATTERN-NOT-FOUND"
        pairs = [(OLD_ARCH, NEW_ARCH), (OLD_REMEDIATION, NEW_REMEDIATION)]
    backup = path.with_suffix(path.suffix + ".orig")
    if not revert and not backup.exists():
        shutil.copy2(path, backup)
    for old, new in pairs:
        text = text.replace(old, new)
    path.write_text(text)
    return "reverted" if revert else "patched"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", type=pathlib.Path, default=None,
                    help="npm global node_modules dir (default: autodetect)")
    ap.add_argument("--revert", action="store_true", help="restore the stock check")
    ap.add_argument("--check", action="store_true", help="report status, change nothing")
    args = ap.parse_args()

    root = args.root or npm_global_root()
    files = target_files(root)
    if not files:
        print(f"rea-agents not found under {root} - install it: npm i -g rea-agents")
        return 1

    rc = 0
    for path in files:
        if args.check:
            text = path.read_text()
            if UPSTREAM_FIX_MARKER in text:
                status = "upstream-fixed (arm64 supported natively, patch not needed)"
            elif NEW_ARCH in text:
                status = "patched"
            elif OLD_ARCH in text:
                status = "UNPATCHED (arm64 Linux will be rejected)"
                rc = 1
            else:
                status = "unknown layout - inspect manually"
                rc = 1
            print(f"{path}\n  {status}")
            continue
        status = patch(path, revert=args.revert)
        print(f"{status:12} {path}")
        if status == "PATTERN-NOT-FOUND":
            rc = 1
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
