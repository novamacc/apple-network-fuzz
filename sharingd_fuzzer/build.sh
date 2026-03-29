#!/bin/bash
# build.sh — Build sharingd/AirDrop proximity fuzzer
set -e
cd "$(dirname "$0")"

COMMON="-framework Foundation -framework CoreFoundation -framework Security -framework CoreGraphics -framework ImageIO"

echo "=== sharingd/AirDrop Proximity Fuzzer ==="
echo ""

echo "[1/3] Building seed generator..."
clang $COMMON -O2 -o seed_sharingd seed_sharingd.m 2>&1
echo "      Done."

echo "[2/3] Generating seed corpus..."
mkdir -p corpus crashes
./seed_sharingd corpus/
echo ""

echo "[3/3] Building fuzzer (ASAN + UBSan + libFuzzer)..."
clang $COMMON \
    -fsanitize=fuzzer,address,undefined \
    -fno-sanitize-recover=undefined \
    -g -O1 \
    -o fuzz_sharingd fuzz_sharingd.m 2>&1
echo "      Done."

echo ""
echo "=== BUILD COMPLETE ==="
SEED_COUNT=$(ls corpus/ | wc -l | tr -d ' ')
echo "Corpus seeds: $SEED_COUNT files (8 paths)"
echo ""
echo "Run:"
echo "  Quick:     ./fuzz_sharingd corpus/ -max_len=65536 -timeout=10 -max_total_time=120 -artifact_prefix=crashes/"
echo "  Overnight: ./fuzz_sharingd corpus/ -max_len=65536 -timeout=10 -jobs=8 -workers=4 -artifact_prefix=crashes/"
