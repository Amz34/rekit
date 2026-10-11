#!/usr/bin/env bash
# Launch the REA (reverse-engineering agent) tool-set as an MCP stdio server.
#
# Point any MCP client at this script:
#   command: /path/to/rekit/rea/rea-mcp.sh
#
# Requirements
#   rea     npm i -g rea-agents
#   Ghidra  exported as GHIDRA_INSTALL_DIR (REA drives Ghidra headless)
#   JDK     21+ on PATH, or JAVA_HOME set
set -euo pipefail

: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR to your Ghidra install (e.g. /opt/ghidra_12.1.4_PUBLIC)}"

if [ -z "${JAVA_HOME:-}" ]; then
  if java_bin="$(command -v java)"; then
    JAVA_HOME="$(dirname "$(dirname "$(readlink -f "$java_bin")")")"
  else
    echo "rea-mcp: no java on PATH and JAVA_HOME unset (REA needs JDK 21+)" >&2
    exit 3
  fi
fi
export JAVA_HOME
export PATH="$JAVA_HOME/bin:$PATH"

REA_BIN="${REA_BIN:-$(command -v rea || true)}"
if [ -z "$REA_BIN" ] || [ ! -x "$REA_BIN" ]; then
  echo "rea-mcp: 'rea' not found. Install it with:  npm i -g rea-agents" >&2
  exit 3
fi

printf 'rea-mcp: rea=%s java=%s ghidra=%s\n' \
  "$REA_BIN" "$("$JAVA_HOME/bin/java" -version 2>&1 | head -1)" "$GHIDRA_INSTALL_DIR" >&2

exec "$REA_BIN" mcp
