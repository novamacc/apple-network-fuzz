#!/bin/bash
# build.sh - Build sharingd/AirDrop proximity fuzzer
# Handles both libFuzzer (local Xcode) and standalone harness (GitHub Actions CI)
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

echo "[3/3] Building fuzzer..."
if clang -fsanitize=fuzzer -x c -c /dev/null -o /dev/null 2>/dev/null; then
    echo "      libFuzzer available - building with -fsanitize=fuzzer"
    clang $COMMON \
        -fsanitize=fuzzer,address,undefined \
        -fno-sanitize-recover=undefined \
        -g -O1 \
        -o fuzz_sharingd fuzz_sharingd.m 2>&1
else
    echo "      libFuzzer NOT available - building with standalone harness"
    clang $COMMON \
        -fsanitize=address,undefined \
        -fno-sanitize-recover=undefined \
        -g -O1 \
        -c -o fuzz_sharingd.o fuzz_sharingd.m
    clang -fsanitize=address,undefined -g -O1 \
        -c -o standalone_harness.o ../standalone_harness.c
    clang $COMMON \
        -fsanitize=address,undefined \
        -g -O1 \
        -o fuzz_sharingd fuzz_sharingd.o standalone_harness.o
    rm -f fuzz_sharingd.o standalone_harness.o
fi
echo "      Done."

echo ""
echo "=== BUILD COMPLETE ==="
SEED_COUNT=$(ls corpus/ | wc -l | tr -d ' ')
echo "Corpus seeds: $SEED_COUNT files (8 paths)"
echo ""
echo "Run:"
echo "  Quick:     ./fuzz_sharingd corpus/ -max_len=65536 -timeout=10 -max_total_time=120 -artifact_prefix=crashes/"
echo "  Overnight: ./fuzz_sharingd corpus/ -max_len=65536 -timeout=10 -jobs=8 -workers=4 -artifact_prefix=crashes/"
