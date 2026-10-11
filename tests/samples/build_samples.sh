#!/usr/bin/env bash
# Rebuild the in-repo fixtures from source (aarch64 or x86_64).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
CC="${CC:-cc}"

$CC -O0 -g -o tiny tiny.c
$CC -O2 -g -o tiny2 tiny2.c
$CC -nostdlib -static -o tiny_asm tiny_asm.s
$CC -O2 -static -g -o tiny_static tiny.c

python3 make_test_pcap.py test.pcap
ls -l tiny tiny2 tiny_asm tiny_static test.pcap
