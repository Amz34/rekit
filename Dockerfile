# rekit -- read-only reverse-engineering MCP server (stdio).
#
# Glama builds this image and speaks MCP over stdio. Introspection (initialize +
# tools/list) needs only Python and the `mcp` package. The analysis backends are
# deliberately OPTIONAL: rekit reports a missing tool as {"status":"tool_missing"}
# instead of faking a result, so the container is honest even when lean.
#
#   lean (default)   : docker build -t rekit .
#   full toolchain   : docker build --build-arg REKIT_FULL_TOOLCHAIN=1 -t rekit .
FROM python:3.12-slim

ARG REKIT_FULL_TOOLCHAIN=0
ARG DEBIAN_FRONTEND=noninteractive

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    REKIT_BIN=/app/rekit.py \
    REKIT_WORK=/work

WORKDIR /app

# Base: file/binutils give objdump+readelf, the two backends rekit uses most.
# Full: radare2 (r2), yara, tshark (pcap) and a JRE for jadx, plus the two
# pure-python extractors (binwalk, flare-floss).
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates file binutils \
 && if [ "$REKIT_FULL_TOOLCHAIN" = "1" ]; then \
        apt-get install -y --no-install-recommends radare2 yara tshark default-jre-headless \
        && pip install binwalk flare-floss; \
    fi \
 && rm -rf /var/lib/apt/lists/*

COPY requirements-mcp.txt /app/requirements-mcp.txt
RUN pip install -r /app/requirements-mcp.txt

COPY . /app
RUN mkdir -p /work

# stdio transport: the MCP client spawns the container and speaks JSON-RPC on stdin/stdout.
ENTRYPOINT ["python", "/app/mcp_server.py"]
