#!/usr/bin/env bash
# rekit end-to-end suite.
#
# Runs every subcommand against real, in-repo fixtures (aarch64 ELF + hand-written
# assembly), records pass/fail with timing, and SKIPS cleanly when an optional
# backend is not installed. A skipped check is reported as SKIP, never as PASS:
# a missing backend must never look like a green test.
#
#   ./tests/run_rekit_suite.sh            # everything the host can run
#   ./tests/run_rekit_suite.sh --quick    # backend-light subset (CI-safe)
#
# Env overrides: REKIT_PYTHON, REKIT_HOME, OUT, REKIT_APK_SAMPLE, REKIT_PE_SAMPLE
set -uo pipefail

QUICK=0
[ "${1:-}" = "--quick" ] && QUICK=1

SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REKIT_HOME="${REKIT_HOME:-$(dirname "$SELF")}"
PY="${REKIT_PYTHON:-$(command -v python3)}"
REKIT="$REKIT_HOME/rekit.py"
SAMPLES="$SELF/samples"
OUT="${OUT:-$SELF/out}"
mkdir -p "$OUT"
LOG="$OUT/rekit_suite.log"
: > "$LOG"

PASS=0; FAIL=0; SKIP=0

have() {                      # backend available on PATH, or beside the interpreter
  command -v "$1" >/dev/null 2>&1 && return 0
  local py="${REKIT_PYTHON:-$PY}"
  [ -n "$py" ] && [ -x "$(dirname "$py")/$1" ] && return 0
  return 1
}

run() {                       # run <label> <timeout> <cmd...>
  local label="$1" tmo="$2"; shift 2
  local t0 t1 rc size
  t0=$(date +%s)
  timeout "$tmo" "$@" > "$OUT/$label.out" 2> "$OUT/$label.err"
  rc=$?
  t1=$(date +%s)
  size=$(wc -c < "$OUT/$label.out")
  if [ "$rc" -eq 0 ]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); fi
  printf '%-22s rc=%-4s %4ss %8s bytes\n' "$label" "$rc" "$((t1-t0))" "$size" | tee -a "$LOG"
}

skip() {                      # skip <label> <reason>
  SKIP=$((SKIP+1))
  printf '%-22s SKIP  %s\n' "$1" "$2" | tee -a "$LOG"
}

need() {                      # need <label> <timeout> <binary> <cmd...>
  local label="$1" tmo="$2" bin="$3"; shift 3
  if have "$bin"; then run "$label" "$tmo" "$@"; else skip "$label" "backend '$bin' not installed"; fi
}

echo "== rekit suite $(date -u +%FT%TZ)  quick=$QUICK ==" | tee -a "$LOG"

# --- core: no external backend required -------------------------------------
run triage_elf        120 "$PY" "$REKIT" triage  "$SAMPLES/tiny" --json
run triage_elf_static 120 "$PY" "$REKIT" triage  "$SAMPLES/tiny_static" --json
run triage_asm        120 "$PY" "$REKIT" triage  "$SAMPLES/tiny_asm" --json
run strings_elf       120 "$PY" "$REKIT" strings "$SAMPLES/tiny" --top 40 --json
run iocs_elf          120 "$PY" "$REKIT" iocs    "$SAMPLES/tiny" --json
run js_scan           120 "$PY" "$REKIT" js      "$SAMPLES/sample.js" --json

# --- backend-gated ----------------------------------------------------------
need disasm_elf       120 objdump "$PY" "$REKIT" disasm "$SAMPLES/tiny" --symbol main --count 25 --json
need firmware_scan    300 binwalk "$PY" "$REKIT" firmware "$SAMPLES/tiny" --json
need yara_elf         180 yara    "$PY" "$REKIT" yara "$SAMPLES/tiny" --json

if have tshark; then
  [ -s "$SAMPLES/test.pcap" ] || python3 "$SAMPLES/make_test_pcap.py" "$SAMPLES/test.pcap" >/dev/null 2>&1
  run pcap_summary    180 "$PY" "$REKIT" pcap "$SAMPLES/test.pcap" --json
else
  skip pcap_summary "backend 'tshark' not installed"
fi

if [ -n "${REKIT_APK_SAMPLE:-}" ] && [ -s "${REKIT_APK_SAMPLE:-}" ]; then
  run apk_summary     420 "$PY" "$REKIT" apk "$REKIT_APK_SAMPLE" --json
else
  skip apk_summary "set REKIT_APK_SAMPLE=/path/to/app.apk to enable"
fi

if [ -n "${REKIT_PE_SAMPLE:-}" ] && [ -s "${REKIT_PE_SAMPLE:-}" ]; then
  need capa_pe        900 capa  "$PY" "$REKIT" capa  "$REKIT_PE_SAMPLE" --json
  need floss_pe       900 floss "$PY" "$REKIT" floss "$REKIT_PE_SAMPLE" --json
else
  skip capa_pe  "set REKIT_PE_SAMPLE=/path/to/sample.exe to enable"
  skip floss_pe "set REKIT_PE_SAMPLE=/path/to/sample.exe to enable"
fi

# --- MCP surface ------------------------------------------------------------
# The check must run on an interpreter that actually has the `mcp` package,
# which is not necessarily the one rekit itself runs on.
MCP_PY=""
for cand in "${REKIT_MCP_PYTHON:-}" "$PY" "$(command -v python3 || true)" "$REKIT_HOME/.venv/bin/python"; do
  if [ -n "$cand" ] && [ -x "$cand" ] && "$cand" -c "import mcp.server.fastmcp" >/dev/null 2>&1; then MCP_PY="$cand"; break; fi
done
if [ -n "$MCP_PY" ]; then
  run mcp_stdio_tools 180 env REKIT_PYTHON="$MCP_PY" "$MCP_PY" "$REKIT_HOME/tests/mcp_tools_check.py"
else
  skip mcp_stdio_tools "no python with the 'mcp' package found"
fi

# --- optional agentic layer (REA) -------------------------------------------
if have rea; then
  run rea_present 120 rea --version
else
  skip rea_present "rea (rea-agents) not installed - optional agentic layer"
fi

# --- flagship: headless Ghidra on aarch64 -----------------------------------
if [ "$QUICK" -eq 0 ] && [ -n "${GHIDRA_INSTALL_DIR:-}" ]; then
  run ghidra_decompile 600 "$PY" "$REKIT" ghidra "$SAMPLES/tiny" --preview 2000
else
  skip ghidra_decompile "set GHIDRA_INSTALL_DIR to enable (flagship check)"
fi

echo "== suite complete: pass=$PASS fail=$FAIL skip=$SKIP ==" | tee -a "$LOG"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
