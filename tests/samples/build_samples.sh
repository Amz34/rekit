#!/usr/bin/env bash
# Rebuild the in-repo fixtures from source.
#
# Host-independent: tiny/tiny2/tiny_static and test.pcap build anywhere.
# tiny_asm is aarch64 assembly, so it is only rebuilt when an aarch64 toolchain
# is present (native aarch64 host, or aarch64-linux-gnu-gcc). The committed
# binary stays in place otherwise - the suite still tests it.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
CC="${CC:-cc}"

$CC -O0 -g -o tiny tiny.c
$CC -O2 -g -o tiny2 tiny2.c
$CC -O2 -static -g -o tiny_static tiny.c
python3 make_test_pcap.py test.pcap

asm_cc=""
if [ "${BUILD_ASM:-1}" = "1" ]; then
  if [ "$(uname -m)" = "aarch64" ] || [ "$(uname -m)" = "arm64" ]; then
    asm_cc="$CC"
  elif command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then
    asm_cc="aarch64-linux-gnu-gcc"
  fi
fi

if [ -n "$asm_cc" ]; then
  "$asm_cc" -nostdlib -static -o tiny_asm tiny_asm.s
  echo "built tiny_asm with $asm_cc"
else
  echo "skip tiny_asm: aarch64 toolchain not available on $(uname -m)"
  echo "  (tiny_asm.s is aarch64 asm; the committed binary is still used by the suite)"
fi

ls -l tiny tiny2 tiny_static test.pcap 2>/dev/null || true
