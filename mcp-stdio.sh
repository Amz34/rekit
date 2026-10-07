#!/usr/bin/env bash
# rekit MCP stdio bridge - for MCP clients that speak stdio instead of HTTP.
# Point any client (Claude Code, Codex, Cursor, opencode, Hermes) at this script:
#   command: /path/to/rekit/mcp-stdio.sh
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export REKIT_BIN="${REKIT_BIN:-$HERE/rekit.py}"
export REKIT_WORK="${REKIT_WORK:-$HOME/.rekit/work}"
exec "${REKIT_PYTHON:-python3}" "$HERE/mcp_server.py" "$@"
