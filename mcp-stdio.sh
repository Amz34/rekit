#!/usr/bin/env bash
# rekit MCP stdio bridge - for MCP clients that speak stdio instead of HTTP.
# Point any client (Claude Code, Codex, Cursor, OpenCode, Hermes) at this script:
#   command: /path/to/rekit/mcp-stdio.sh
# Needs the `mcp` package (pip install -r requirements-mcp.txt); this script finds an
# interpreter that has it, or refuses with the exact fix instead of a Python traceback.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export REKIT_BIN="${REKIT_BIN:-$HERE/rekit.py}"
export REKIT_WORK="${REKIT_WORK:-$HOME/rekit/work}"

need() {
  echo "  fix: pip install -r requirements-mcp.txt  (or set REKIT_PYTHON=/path/to/python)" >&2
}

if [ -n "${REKIT_PYTHON:-}" ]; then
  PY="$REKIT_PYTHON"
  if ! "$PY" -c 'import mcp' >/dev/null 2>&1; then
    echo "mcp-stdio: REKIT_PYTHON=$PY cannot import the 'mcp' package." >&2
    need
    exit 3
  fi
else
  PY=""
  for cand in "$HERE/.venv/bin/python" "$(command -v python3 || true)"; do
    if [ -n "$cand" ] && [ -x "$cand" ] && "$cand" -c 'import mcp' >/dev/null 2>&1; then
      PY="$cand"
      break
    fi
  done
  if [ -z "$PY" ]; then
    echo "mcp-stdio: no Python with the 'mcp' package found." >&2
    need
    exit 3
  fi
fi

exec "$PY" "$HERE/mcp_server.py" "$@"
