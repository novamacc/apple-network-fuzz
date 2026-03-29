#!/bin/bash
# build.sh - Build mDNSResponder/DNS fuzzer
set -e
cd "$(dirname "$0")"

COMMON="-framework Foundation -framework CoreFoundation -framework CFNetwork -lresolv"

echo "=== mDNS/DNS Protocol Fuzzer ==="
echo ""

echo "[1/3] Building seed generator..."
clang $COMMON -O2 -o seed_mdns seed_mdns.m 2>&1
echo "      Done."

echo "[2/3] Generating seed corpus..."
mkdir -p corpus crashes
./seed_mdns corpus/
echo ""

echo "[3/3] Building fuzzer (ASAN + UBSan + libFuzzer)..."
clang $COMMON \
    -fsanitize=fuzzer,address,undefined \
    -fno-sanitize-recover=undefined \
    -g -O1 \
    -o fuzz_mdns fuzz_mdns.m 2>&1
echo "      Done."

echo ""
echo "=== BUILD COMPLETE ==="
echo "Corpus seeds: $(ls corpus/ | wc -l | tr -d ' ') files"
echo "Run: ./fuzz_mdns corpus/ -max_len=4096 -timeout=5 -artifact_prefix=crashes/"
