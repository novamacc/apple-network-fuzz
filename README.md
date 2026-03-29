# apple-network-fuzz

Continuous fuzzing of Apple network/proximity frameworks on macOS using libFuzzer with AddressSanitizer and UndefinedBehaviorSanitizer.

## Fuzzers

| Fuzzer | Target | Protocols | Zero-Click Vectors |
|--------|--------|-----------|-------------------|
| `bluetooth_exploit` | IOBluetooth + CoreBluetooth | SDP, BLE advertisements, Apple Continuity, GATT ATT, HCI events | Nearby BLE devices (no pairing) |
| `mdns_fuzzer` | mDNSResponder + libresolv | DNS responses, mDNS/Bonjour, name compression, DNSSEC, EDNS0, TXT records | Network-adjacent DNS |
| `sharingd_fuzzer` | sharingd (AirDrop) | AirDrop Discover/Ask plists, BLE NearbyInfo, DER certificates, clipboard | AirDrop, Universal Clipboard |
| `rapportd_fuzzer` | rapportd (Continuity) | OPACK, Handoff, identity TLV, clipboard, Universal Control, AirPlay | Nearby Apple devices |

## CI

Runs on `macos-15` every 4 hours via GitHub Actions. Each fuzzer runs for ~5 hours with 3 parallel workers. Crash artifacts are uploaded automatically.

## Local Build

```bash
cd bluetooth_exploit && ./build.sh
./fuzz_bluetooth corpus/ -max_len=4096 -timeout=5 -jobs=4 -workers=4
```
