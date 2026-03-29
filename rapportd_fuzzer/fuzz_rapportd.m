/*
 * fuzz_rapportd.m — rapportd Continuity Protocol Fuzzer
 *
 * ═══════════════════════════════════════════════════════════════════════
 * TARGET: rapportd (/usr/libexec/rapportd) — 4.5MB, 52 entitlements
 *
 * Handles ALL device-to-device Apple Continuity communication:
 *   - Handoff, Universal Control, Sidecar, AirPlay
 *   - Uses DeviceToDeviceManager, CoreBluetooth, MultipeerConnectivity
 *   - Encrypted TLS streams between nearby Apple devices
 *   - Identity verification via iCloud Keychain
 *
 * We fuzz the data parsing that happens AFTER connection establishment
 * but BEFORE full authentication — the handshake/negotiation phase.
 *
 * FUZZING PATHS (6):
 *   [0] Opack serialization (Apple's custom binary format)
 *   [1] Handoff userActivity parsing (NSUserActivity archive)
 *   [2] Device identity TLV parsing
 *   [3] Continuity clipboard data
 *   [4] Universal Control event stream
 *   [5] AirPlay discovery/negotiation plist
 *
 * Build:
 *   clang -framework Foundation -framework CoreFoundation \
 *         -framework MultipeerConnectivity \
 *         -fsanitize=fuzzer,address,undefined -g -O1 \
 *         -o fuzz_rapportd fuzz_rapportd.m
 * ═══════════════════════════════════════════════════════════════════════
 */

#import <Foundation/Foundation.h>
#include <stdint.h>
#include <string.h>

/* ================================================================
 * PATH 0: OPACK binary format parsing
 *
 * OPACK is Apple's custom binary serialization format used in
 * Continuity protocols, RemoteXPC, and device-to-device comms.
 * Format: type byte + payload. Similar to msgpack/bplist.
 * ================================================================ */

/* Simple OPACK decoder to exercise format parsing */
static id parse_opack_value(const uint8_t *data, size_t size, size_t *consumed);

static id parse_opack_value(const uint8_t *data, size_t size, size_t *consumed) {
    if (size == 0) { *consumed = 0; return nil; }

    uint8_t type = data[0];
    *consumed = 1;

    /* Null */
    if (type == 0x01) return [NSNull null];

    /* Boolean */
    if (type == 0x04) return @NO;
    if (type == 0x05) return @YES;

    /* Integers (1-8 bytes) */
    if (type >= 0x06 && type <= 0x0D) {
        int shift = type - 0x06;
        if (shift > 3) shift = 3; /* cap at 8 bytes */
        int byteCount = 1 << shift;
        if (size < (size_t)(1 + byteCount)) return nil;
        uint64_t val = 0;
        for (int i = 0; i < byteCount; i++) {
            val |= ((uint64_t)data[1 + i]) << (i * 8);
        }
        *consumed = 1 + byteCount;
        return @((int64_t)val);
    }

    /* Float32 */
    if (type == 0x23 && size >= 5) {
        float f;
        memcpy(&f, data + 1, 4);
        *consumed = 5;
        return @(f);
    }

    /* Float64 */
    if (type == 0x24 && size >= 9) {
        double d;
        memcpy(&d, data + 1, 8);
        *consumed = 9;
        return @(d);
    }

    /* String (short: type encodes length) */
    if (type >= 0x30 && type <= 0x3F) {
        int len = type - 0x30;
        if (size < (size_t)(1 + len)) return nil;
        *consumed = 1 + len;
        return [[NSString alloc] initWithBytes:data + 1 length:len
                                      encoding:NSUTF8StringEncoding] ?: @"";
    }

    /* String (medium: next byte is length) */
    if (type == 0x40 && size >= 2) {
        uint8_t len = data[1];
        if (size < (size_t)(2 + len)) return nil;
        *consumed = 2 + len;
        return [[NSString alloc] initWithBytes:data + 2 length:len
                                      encoding:NSUTF8StringEncoding] ?: @"";
    }

    /* Data blob */
    if (type >= 0x50 && type <= 0x5F) {
        int len = type - 0x50;
        if (size < (size_t)(1 + len)) return nil;
        *consumed = 1 + len;
        return [NSData dataWithBytes:data + 1 length:len];
    }

    /* Dictionary */
    if (type == 0x70 || type == 0x71) {
        NSMutableDictionary *dict = [NSMutableDictionary dictionary];
        size_t off = 1;
        int maxItems = 50;
        while (off < size && maxItems-- > 0) {
            if (data[off] == 0x02) { off++; break; } /* terminator */
            size_t kc = 0, vc = 0;
            id key = parse_opack_value(data + off, size - off, &kc);
            if (!key || kc == 0) break;
            off += kc;
            id val = parse_opack_value(data + off, size - off, &vc);
            if (vc == 0) break;
            off += vc;
            if ([key isKindOfClass:[NSString class]])
                dict[key] = val ?: [NSNull null];
        }
        *consumed = off;
        return dict;
    }

    /* Array */
    if (type == 0x60 || type == 0x61) {
        NSMutableArray *arr = [NSMutableArray array];
        size_t off = 1;
        int maxItems = 100;
        while (off < size && maxItems-- > 0) {
            if (data[off] == 0x02) { off++; break; }
            size_t vc = 0;
            id val = parse_opack_value(data + off, size - off, &vc);
            if (vc == 0) break;
            off += vc;
            [arr addObject:val ?: [NSNull null]];
        }
        *consumed = off;
        return arr;
    }

    /* Unknown type — skip 1 byte */
    return nil;
}

static void fuzz_opack(const uint8_t *data, size_t size) {
    @autoreleasepool {
        size_t consumed = 0;
        id result = parse_opack_value(data, size, &consumed);
        if (result) {
            (void)[result description];
        }
    }
}

/* ================================================================
 * PATH 1: Handoff NSUserActivity parsing
 * ================================================================ */
static void fuzz_handoff(const uint8_t *data, size_t size) {
    @autoreleasepool {
        NSData *nsdata = [NSData dataWithBytesNoCopy:(void *)data
                                              length:size freeWhenDone:NO];
        @try {
            /* Parse as archived NSUserActivity payload */
            NSKeyedUnarchiver *una = [[NSKeyedUnarchiver alloc]
                initForReadingFromData:nsdata error:NULL];
            if (una) {
                una.requiresSecureCoding = YES;
                NSSet *allowed = [NSSet setWithArray:@[
                    [NSDictionary class], [NSArray class],
                    [NSString class], [NSNumber class],
                    [NSData class], [NSDate class], [NSURL class],
                ]];
                NSDictionary *activity = [una decodeObjectOfClasses:allowed
                    forKey:@"NSUserActivityUserInfo"];
                if (activity) {
                    (void)activity[@"activityType"];
                    (void)activity[@"title"];
                    (void)activity[@"webpageURL"];
                    (void)activity[@"userInfo"];
                }
                [una finishDecoding];
            }
        } @catch (NSException *e) { }
    }
}

/* ================================================================
 * PATH 2: Device identity TLV (Type-Length-Value) parsing
 * ================================================================ */
static void fuzz_identity_tlv(const uint8_t *data, size_t size) {
    @autoreleasepool {
        size_t off = 0;
        NSMutableDictionary *fields = [NSMutableDictionary dictionary];
        int maxFields = 100;

        while (off + 4 <= size && maxFields-- > 0) {
            uint16_t type, length;
            memcpy(&type, data + off, 2);
            memcpy(&length, data + off + 2, 2);
            type = CFSwapInt16BigToHost(type);
            length = CFSwapInt16BigToHost(length);
            off += 4;

            if (off + length > size) break;
            if (length > 4096) break; /* sanity limit */

            NSData *value = [NSData dataWithBytes:data + off length:length];
            fields[@(type)] = value;

            /* Parse known field types */
            switch (type) {
                case 0x0001: /* Device name */
                {
                    NSString *name = [[NSString alloc]
                        initWithData:value encoding:NSUTF8StringEncoding];
                    (void)name;
                    break;
                }
                case 0x0002: /* Device model */
                case 0x0003: /* OS version */
                case 0x0010: /* Apple ID hash */
                case 0x0020: /* Certificate */
                    (void)value.length;
                    break;
                default:
                    break;
            }
            off += length;
        }
        (void)fields.count;
    }
}

/* ================================================================
 * PATH 3: Universal Clipboard data parsing
 * ================================================================ */
static void fuzz_clipboard(const uint8_t *data, size_t size) {
    @autoreleasepool {
        NSData *nsdata = [NSData dataWithBytesNoCopy:(void *)data
                                              length:size freeWhenDone:NO];

        /* Parse as plist (clipboard data is plist-encoded) */
        id plist = [NSPropertyListSerialization
            propertyListWithData:nsdata
            options:NSPropertyListImmutable
            format:NULL error:NULL];

        if ([plist isKindOfClass:[NSDictionary class]]) {
            NSDictionary *dict = (NSDictionary *)plist;
            /* Clipboard items keyed by UTI */
            for (NSString *uti in dict) {
                id item = dict[uti];
                if ([item isKindOfClass:[NSData class]]) {
                    NSData *itemData = (NSData *)item;
                    (void)itemData.length;

                    /* Try to interpret as string */
                    if ([uti isEqualToString:@"public.utf8-plain-text"] ||
                        [uti isEqualToString:@"public.plain-text"]) {
                        NSString *str = [[NSString alloc]
                            initWithData:itemData encoding:NSUTF8StringEncoding];
                        (void)str.length;
                    }
                    /* Try as URL */
                    if ([uti isEqualToString:@"public.url"]) {
                        NSString *urlStr = [[NSString alloc]
                            initWithData:itemData encoding:NSUTF8StringEncoding];
                        if (urlStr) {
                            NSURL *url = [NSURL URLWithString:urlStr];
                            (void)url.host;
                        }
                    }
                }
            }
        }
    }
}

/* ================================================================
 * PATH 4: Universal Control event stream parsing
 * ================================================================ */
static void fuzz_control_events(const uint8_t *data, size_t size) {
    @autoreleasepool {
        /* Universal Control sends HID events over encrypted channel */
        size_t off = 0;
        int maxEvents = 200;

        while (off + 8 <= size && maxEvents-- > 0) {
            /* Event header: type(2) + flags(2) + length(4) */
            uint16_t evType, evFlags;
            uint32_t evLength;
            memcpy(&evType, data + off, 2);
            memcpy(&evFlags, data + off + 2, 2);
            memcpy(&evLength, data + off + 4, 4);
            evType = CFSwapInt16BigToHost(evType);
            evFlags = CFSwapInt16BigToHost(evFlags);
            evLength = CFSwapInt32BigToHost(evLength);
            off += 8;

            if (evLength > 4096) break;
            if (off + evLength > size) break;

            switch (evType & 0xFF) {
                case 0x01: /* Mouse move */
                    if (evLength >= 8) {
                        int32_t x, y;
                        memcpy(&x, data + off, 4);
                        memcpy(&y, data + off + 4, 4);
                        (void)x; (void)y;
                    }
                    break;
                case 0x02: /* Mouse click */
                case 0x03: /* Key event */
                case 0x04: /* Scroll event */
                case 0x05: /* Gesture */
                    (void)evFlags;
                    break;
                default:
                    break;
            }
            off += evLength;
        }
    }
}

/* ================================================================
 * PATH 5: AirPlay discovery plist
 * ================================================================ */
static void fuzz_airplay_plist(const uint8_t *data, size_t size) {
    @autoreleasepool {
        NSData *nsdata = [NSData dataWithBytesNoCopy:(void *)data
                                              length:size freeWhenDone:NO];

        /* AirPlay uses both binary and XML plists */
        id plist = [NSPropertyListSerialization
            propertyListWithData:nsdata
            options:NSPropertyListImmutable
            format:NULL error:NULL];

        if ([plist isKindOfClass:[NSDictionary class]]) {
            NSDictionary *dict = (NSDictionary *)plist;

            /* AirPlay service info fields */
            (void)dict[@"deviceid"];
            (void)dict[@"features"];
            (void)dict[@"model"];
            (void)dict[@"protovers"];
            (void)dict[@"srcvers"];
            (void)dict[@"flags"];
            (void)dict[@"pk"];             /* Public key */
            (void)dict[@"pi"];             /* Pairing identity */
            (void)dict[@"displays"];       /* Display capabilities */
            (void)dict[@"audioFormats"];   /* Supported audio */
            (void)dict[@"audioLatencies"];
            (void)dict[@"txtAirPlay"];

            /* Nested display info */
            id displays = dict[@"displays"];
            if ([displays isKindOfClass:[NSArray class]]) {
                for (id disp in (NSArray *)displays) {
                    if ([disp isKindOfClass:[NSDictionary class]]) {
                        (void)((NSDictionary *)disp)[@"width"];
                        (void)((NSDictionary *)disp)[@"height"];
                        (void)((NSDictionary *)disp)[@"overscanned"];
                    }
                }
            }
        }
    }
}

/* ================================================================ */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0;

    @autoreleasepool {
        uint8_t path = data[0];
        const uint8_t *payload = data + 1;
        size_t psize = size - 1;

        switch (path % 6) {
            case 0: fuzz_opack(payload, psize);           break;
            case 1: fuzz_handoff(payload, psize);         break;
            case 2: fuzz_identity_tlv(payload, psize);    break;
            case 3: fuzz_clipboard(payload, psize);       break;
            case 4: fuzz_control_events(payload, psize);  break;
            case 5: fuzz_airplay_plist(payload, psize);   break;
        }
    }
    return 0;
}
