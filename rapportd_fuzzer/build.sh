#!/bin/bash
# build.sh - Build rapportd Continuity protocol fuzzer
# Handles both libFuzzer (local Xcode) and standalone harness (GitHub Actions CI)
set -e
cd "$(dirname "$0")"

COMMON="-framework Foundation -framework CoreFoundation -framework MultipeerConnectivity"

echo "=== rapportd Continuity Protocol Fuzzer ==="
echo ""

echo "[1/2] Creating seed corpus..."
mkdir -p corpus crashes
# Generate minimal seeds inline
cat > /tmp/gen_rapportd_seeds.m << 'SEEDEOF'
#import <Foundation/Foundation.h>
#include <sys/stat.h>
static void ws(const char *dir, const char *name, uint8_t path, NSData *d) {
    NSMutableData *full = [NSMutableData dataWithBytes:&path length:1];
    [full appendData:d];
    NSString *p = [NSString stringWithFormat:@"%s/%s", dir, name];
    [full writeToFile:p atomically:YES];
    printf("  [+] %s (%lu bytes)\n", name, (unsigned long)full.length);
}
int main(int argc, char *argv[]) {
    @autoreleasepool {
        const char *dir = argc > 1 ? argv[1] : "corpus";
        mkdir(dir, 0755);
        // OPACK seed
        uint8_t opack[] = {0x70, 0x31, 0x6E, 0x06, 0x2A, 0x02};
        ws(dir, "opack.bin", 0, [NSData dataWithBytes:opack length:sizeof(opack)]);
        // Handoff seed (archived dict)
        NSDictionary *h = @{@"activityType": @"com.apple.safari", @"title": @"Test"};
        NSData *hd = [NSKeyedArchiver archivedDataWithRootObject:h requiringSecureCoding:NO error:nil];
        if (hd) ws(dir, "handoff.bin", 1, hd);
        // TLV seed
        uint8_t tlv[] = {0x00,0x01,0x00,0x04,'T','e','s','t', 0x00,0x02,0x00,0x03,'M','a','c'};
        ws(dir, "identity_tlv.bin", 2, [NSData dataWithBytes:tlv length:sizeof(tlv)]);
        // Clipboard plist
        NSDictionary *cb = @{@"public.utf8-plain-text": [@"Hello" dataUsingEncoding:NSUTF8StringEncoding]};
        NSData *cbd = [NSPropertyListSerialization dataWithPropertyList:cb format:NSPropertyListBinaryFormat_v1_0 options:0 error:nil];
        if (cbd) ws(dir, "clipboard.bin", 3, cbd);
        // Control events
        uint8_t ev[] = {0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x08, 0x00,0x00,0x01,0x00,0x00,0x00,0x02,0x00};
        ws(dir, "control_events.bin", 4, [NSData dataWithBytes:ev length:sizeof(ev)]);
        // AirPlay plist
        NSDictionary *ap = @{@"deviceid": @"AA:BB:CC:DD:EE:FF", @"model": @"AppleTV", @"features": @(0x1234)};
        NSData *apd = [NSPropertyListSerialization dataWithPropertyList:ap format:NSPropertyListBinaryFormat_v1_0 options:0 error:nil];
        if (apd) ws(dir, "airplay.bin", 5, apd);
        printf("[+] rapportd seeds generated\n");
        return 0;
    }
}
SEEDEOF
clang -framework Foundation -O2 -o /tmp/gen_rapport_seeds /tmp/gen_rapportd_seeds.m 2>&1
/tmp/gen_rapport_seeds corpus/
rm -f /tmp/gen_rapport_seeds /tmp/gen_rapportd_seeds.m
echo "      Done."

echo "[2/2] Building fuzzer..."
if echo 'int LLVMFuzzerTestOneInput(const char *d, long s){return 0;}' | clang  -x c - -o /dev/null 2>/dev/null; then
    echo "      libFuzzer available - building with "
    clang $COMMON \
        -fsanitize=address,undefined \
        -fno-sanitize-recover=undefined \
        -g -O1 \
        -o fuzz_rapportd fuzz_rapportd.m 2>&1
else
    echo "      libFuzzer NOT available - building with standalone harness"
    clang $COMMON \
        -fsanitize=address,undefined \
        -fno-sanitize-recover=undefined \
        -g -O1 \
        -c -o fuzz_rapportd.o fuzz_rapportd.m
    clang -fsanitize=address,undefined -g -O1 \
        -c -o standalone_harness.o ../standalone_harness.c
    clang $COMMON \
        -fsanitize=address,undefined \
        -g -O1 \
        -o fuzz_rapportd fuzz_rapportd.o standalone_harness.o
    rm -f fuzz_rapportd.o standalone_harness.o
fi
echo "      Done."

echo ""
echo "=== BUILD COMPLETE ==="
echo "Corpus seeds: $(ls corpus/ | wc -l | tr -d ' ') files"
echo "Run: ./fuzz_rapportd corpus/ -max_len=65536 -timeout=10 -artifact_prefix=crashes/"
