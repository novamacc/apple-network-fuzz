/*
 * fuzz_sharingd.m — God-Level sharingd/AirDrop/Nearby Proximity Fuzzer
 *
 * ═══════════════════════════════════════════════════════════════════════
 * TARGET: sharingd (/usr/libexec/sharingd) — 19MB, 70+ entitlements
 *
 * ZERO-CLICK WIRELESS PROXIMITY ATTACK SURFACE:
 *   sharingd handles ALL proximity-based sharing on macOS/iOS:
 *   - AirDrop (Discover, Ask, Upload — HTTP over AWDL)
 *   - BLE Nearby (service advertisements, NearbyInfo frames)
 *   - Bonjour TXT records (service metadata)
 *   - Handoff / Universal Clipboard
 *   - Password sharing
 *   - Wi-Fi password sharing
 *
 * ATTACK MODEL:
 *   Attacker sends malformed wireless packets to victim's device.
 *   sharingd parses them without user interaction (zero-click).
 *   If AirDrop is set to "Everyone" or "Contacts Only" (+ known contact),
 *   parsing happens BEFORE any user prompt.
 *
 * FUZZING PATHS (8):
 *   [1] AirDrop Discover plist  — Sender identity + capabilities
 *   [2] AirDrop Ask plist       — File metadata + icons + senderRecordData
 *   [3] Bonjour TXT record      — Service advertisement metadata
 *   [4] BLE NearbyInfo frame    — Proximity detection frame
 *   [5] AirDrop senderRecordData — DER certificate + identity validation
 *   [6] AirDrop file icon       — JPEG/PNG icon data embedded in plist
 *   [7] Universal Clipboard     — Pasteboard data over proximity link
 *   [8] Wi-Fi Password share    — Password sharing plist
 *
 * Build:
 *   clang -framework Foundation -framework CoreFoundation \
 *         -framework Security -framework CoreGraphics \
 *         -fsanitize=fuzzer,address,undefined -g -O1 \
 *         -o fuzz_sharingd fuzz_sharingd.m
 * ═══════════════════════════════════════════════════════════════════════
 */

#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>
#import <ImageIO/ImageIO.h>
#import <Security/Security.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ================================================================
 * PATH 1: AirDrop Discover Request Plist
 *
 * When AirDrop discovers a nearby device, it sends an HTTP POST
 * with a plist body to /Discover. sharingd parses this before
 * showing any UI to the user.
 *
 * Keys: SenderComputerName, SenderModelName, SenderID,
 *        BundleID, ConvertMediaFormats, senderRecordData,
 *        SenderCapabilities, Flags
 * ================================================================ */
static void fuzz_discover_plist(const uint8_t *data, size_t size) {
    @autoreleasepool {
        /* Try to parse as binary plist */
        NSData *nsdata = [NSData dataWithBytesNoCopy:(void *)data
                                              length:size
                                        freeWhenDone:NO];

        /* Binary plist deserialization */
        NSError *err = nil;
        id plist = [NSPropertyListSerialization propertyListWithData:nsdata
                        options:NSPropertyListMutableContainersAndLeaves
                        format:NULL error:&err];

        if (plist && [plist isKindOfClass:[NSDictionary class]]) {
            NSDictionary *dict = (NSDictionary *)plist;

            /* Extract fields sharingd would process */
            id computerName = dict[@"SenderComputerName"];
            id modelName = dict[@"SenderModelName"];
            id senderID = dict[@"SenderID"];
            id recordData = dict[@"senderRecordData"];
            id flags = dict[@"Flags"];
            id capabilities = dict[@"SenderCapabilities"];

            /* Exercise string processing paths */
            if ([computerName isKindOfClass:[NSString class]]) {
                (void)[(NSString *)computerName length];
                (void)[(NSString *)computerName UTF8String];
            }
            if ([senderID isKindOfClass:[NSString class]]) {
                (void)[[NSUUID alloc] initWithUUIDString:(NSString *)senderID];
            }
            if ([recordData isKindOfClass:[NSData class]]) {
                SecCertificateRef cert = SecCertificateCreateWithData(
                    NULL, (__bridge CFDataRef)(NSData *)recordData);
                if (cert) {
                    CFStringRef summary = SecCertificateCopySubjectSummary(cert);
                    if (summary) CFRelease(summary);
                    SecKeyRef pubKey = SecCertificateCopyKey(cert);
                    if (pubKey) CFRelease(pubKey);
                    CFRelease(cert);
                }
            }
            if ([flags isKindOfClass:[NSNumber class]])
                (void)[(NSNumber *)flags unsignedIntValue];
            if ([capabilities isKindOfClass:[NSNumber class]])
                (void)[(NSNumber *)capabilities unsignedLongLongValue];
        }

        /* Also try XML plist (sharingd uses both) */
        plist = [NSPropertyListSerialization propertyListWithData:nsdata
                    options:NSPropertyListImmutable format:NULL error:NULL];
    }
}

/* ================================================================
 * PATH 2: AirDrop Ask Request Plist
 *
 * When a sender wants to share files, it POSTs to /Ask with
 * file metadata. This includes file icons (JPEG/PNG data),
 * file names, bundle IDs, and more.
 * ================================================================ */
static void fuzz_ask_plist(const uint8_t *data, size_t size) {
    @autoreleasepool {
        NSData *nsdata = [NSData dataWithBytesNoCopy:(void *)data
                                              length:size
                                        freeWhenDone:NO];

        NSError *err = nil;
        id plist = [NSPropertyListSerialization propertyListWithData:nsdata
                        options:NSPropertyListMutableContainersAndLeaves
                        format:NULL error:&err];

        if (plist && [plist isKindOfClass:[NSDictionary class]]) {
            NSDictionary *dict = (NSDictionary *)plist;

            /* File metadata */
            NSArray *files = dict[@"Files"];
            if ([files isKindOfClass:[NSArray class]]) {
                for (id fileObj in files) {
                    if (![fileObj isKindOfClass:[NSDictionary class]]) continue;
                    NSDictionary *file = (NSDictionary *)fileObj;

                    id fileName = file[@"FileName"];
                    id fileType = file[@"FileType"];
                    id fileSize = file[@"FileBomPath"];
                    id fileIcon = file[@"FileIcon"];

                    if ([fileName isKindOfClass:[NSString class]])
                        (void)[(NSString *)fileName pathExtension];
                    if ([fileType isKindOfClass:[NSString class]])
                        (void)[(NSString *)fileType UTF8String];
                    if ([fileSize isKindOfClass:[NSNumber class]])
                        (void)[(NSNumber *)fileSize unsignedLongLongValue];
                    else if ([fileSize isKindOfClass:[NSString class]])
                        (void)[(NSString *)fileSize UTF8String];

                    /* File icon is JPEG/PNG data — parse it */
                    if ([fileIcon isKindOfClass:[NSData class]]) {
                        CGDataProviderRef provider = CGDataProviderCreateWithCFData(
                            (__bridge CFDataRef)(NSData *)fileIcon);
                        if (provider) {
                            CGImageRef img = CGImageCreateWithJPEGDataProvider(
                                provider, NULL, false,
                                kCGRenderingIntentDefault);
                            if (!img) {
                                img = CGImageCreateWithPNGDataProvider(
                                    provider, NULL, false,
                                    kCGRenderingIntentDefault);
                            }
                            if (img) {
                                (void)CGImageGetWidth(img);
                                (void)CGImageGetHeight(img);
                                CGImageRelease(img);
                            }
                            CGDataProviderRelease(provider);
                        }
                    }
                }
            }

            /* Sender bundle ID */
            id bundleID = dict[@"BundleID"];
            if ([bundleID isKindOfClass:[NSString class]])
                (void)[(NSString *)bundleID UTF8String];

            /* Convert media formats */
            id convert = dict[@"ConvertMediaFormats"];
            if ([convert isKindOfClass:[NSNumber class]])
                (void)[(NSNumber *)convert boolValue];

            /* Small file icon (embedded in top-level) */
            NSData *smallIcon = dict[@"smallFileIcon"];
            if (smallIcon && [smallIcon isKindOfClass:[NSData class]]) {
                CGDataProviderRef p = CGDataProviderCreateWithCFData(
                    (__bridge CFDataRef)smallIcon);
                if (p) {
                    CGImageRef img = CGImageCreateWithJPEGDataProvider(
                        p, NULL, false, kCGRenderingIntentDefault);
                    if (img) CGImageRelease(img);
                    CGDataProviderRelease(p);
                }
            }
        }
    }
}

/* ================================================================
 * PATH 3: Bonjour TXT Record
 *
 * AirDrop advertises via Bonjour (_airdrop._tcp) with TXT records
 * containing device information. TXT records are key-value pairs
 * with a specific binary format: length-byte + key=value pairs.
 * ================================================================ */
static void fuzz_txt_record(const uint8_t *data, size_t size) {
    @autoreleasepool {
        /* TXT record is: [len][key=value][len][key=value]... */
        size_t off = 0;
        NSMutableDictionary *parsed = [NSMutableDictionary dictionary];

        while (off < size) {
            uint8_t len = data[off++];
            if (off + len > size) break;

            NSData *entry = [NSData dataWithBytes:data + off length:len];
            NSString *str = [[NSString alloc] initWithData:entry
                                                  encoding:NSUTF8StringEncoding];
            if (str) {
                NSRange eq = [str rangeOfString:@"="];
                if (eq.location != NSNotFound) {
                    NSString *key = [str substringToIndex:eq.location];
                    NSString *val = [str substringFromIndex:eq.location + 1];
                    parsed[key] = val;
                }
            }
            off += len;
        }

        /* Exercise the parsed values like sharingd would */
        NSString *flags = parsed[@"flags"];
        if (flags) {
            unsigned long val = strtoul(flags.UTF8String, NULL, 16);
            (void)(val & 0xFF);  /* discoverable mode */
            (void)((val >> 8) & 0xFF);  /* supports features */
        }

        /* Also parse via Apple's TXTRecordDictionary API */
        NSData *recordData = [NSData dataWithBytesNoCopy:(void *)data
                                                  length:size
                                            freeWhenDone:NO];
        NSDictionary *txtDict = [NSNetService dictionaryFromTXTRecordData:recordData];
        if (txtDict) {
            for (NSString *key in txtDict) {
                NSData *val = txtDict[key];
                if ([val isKindOfClass:[NSData class]]) {
                    (void)[[NSString alloc] initWithData:val
                                               encoding:NSUTF8StringEncoding];
                }
            }
        }
    }
}

/* ================================================================
 * PATH 4: BLE NearbyInfo Frame
 *
 * NearbyInfo is a BLE advertisement frame that sharingd parses
 * from ANY nearby device. Format:
 *   byte 0:     Frame type (0x10 = NearbyInfo)
 *   byte 1:     Status flags + action type
 *   bytes 2-4:  Wi-Fi SSID hash (3 bytes)
 *   bytes 5-7:  DSID hash (3 bytes)
 *   bytes 8+:   Variable: session ID, message ID, service data
 * ================================================================ */
static void fuzz_nearby_frame(const uint8_t *data, size_t size) {
    @autoreleasepool {
        if (size < 2) return;

        uint8_t frameType = data[0];
        uint8_t statusFlags = data[1];

        /* Parse action code */
        uint8_t actionCode = statusFlags & 0x0F;
        BOOL isActive = (statusFlags >> 4) & 1;

        /* Parse hashes */
        NSMutableData *ssidHash = [NSMutableData data];
        NSMutableData *dsidHash = [NSMutableData data];

        if (size >= 5) [ssidHash appendBytes:data + 2 length:3];
        if (size >= 8) [dsidHash appendBytes:data + 5 length:3];

        /* Variable-length service data */
        if (size > 8) {
            NSData *serviceData = [NSData dataWithBytes:data + 8
                                                 length:size - 8];

            /* Service data may contain embedded plists */
            id plist = [NSPropertyListSerialization
                propertyListWithData:serviceData
                options:NSPropertyListImmutable
                format:NULL error:NULL];

            if (plist) {
                /* sharingd uses service data for feature negotiation */
                if ([plist isKindOfClass:[NSDictionary class]]) {
                    NSDictionary *d = (NSDictionary *)plist;
                    for (NSString *key in d) {
                        (void)[d[key] description];
                    }
                }
            }
        }

        /* Construct a NearbyInfo-like advertisement */
        NSMutableDictionary *adv = [NSMutableDictionary dictionary];
        adv[@"type"] = @(frameType);
        adv[@"action"] = @(actionCode);
        adv[@"active"] = @(isActive);
        adv[@"ssidHash"] = ssidHash;
        adv[@"dsidHash"] = dsidHash;

        /* Serialize back to trigger plist round-trip bugs */
        NSData *serialized = [NSPropertyListSerialization
            dataWithPropertyList:adv
            format:NSPropertyListBinaryFormat_v1_0
            options:0 error:NULL];
        if (serialized) {
            (void)[NSPropertyListSerialization
                propertyListWithData:serialized
                options:0 format:NULL error:NULL];
        }
    }
}

/* ================================================================
 * PATH 5: DER Certificate (senderRecordData)
 *
 * AirDrop includes an Apple ID validation record as DER-encoded
 * certificate data. sharingd parses it to verify sender identity.
 * Malformed certificates exercise Security.framework parsers.
 * ================================================================ */
static void fuzz_sender_certificate(const uint8_t *data, size_t size) {
    @autoreleasepool {
        NSData *nsdata = [NSData dataWithBytesNoCopy:(void *)data
                                              length:size
                                        freeWhenDone:NO];

        /* Parse as DER certificate */
        SecCertificateRef cert = SecCertificateCreateWithData(
            NULL, (__bridge CFDataRef)nsdata);

        if (cert) {
            /* Extract properties */
            CFStringRef summary = SecCertificateCopySubjectSummary(cert);
            if (summary) CFRelease(summary);

            CFDataRef serial = SecCertificateCopySerialNumberData(cert, NULL);
            if (serial) CFRelease(serial);

            SecKeyRef pubKey = SecCertificateCopyKey(cert);
            if (pubKey) {
                CFDictionaryRef attrs = SecKeyCopyAttributes(pubKey);
                if (attrs) CFRelease(attrs);
                CFRelease(pubKey);
            }

            /* Try to create trust object */
            SecPolicyRef policy = SecPolicyCreateBasicX509();
            if (policy) {
                SecTrustRef trust = NULL;
                OSStatus st = SecTrustCreateWithCertificates(cert, policy, &trust);
                if (st == errSecSuccess && trust) {
                    /* Evaluate trust (exercises full chain validation) */
                    CFErrorRef trustErr = NULL;
                    bool trusted = SecTrustEvaluateWithError(trust, &trustErr);
                    (void)trusted;
                    if (trustErr) CFRelease(trustErr);
                    CFRelease(trust);
                }
                CFRelease(policy);
            }

            CFRelease(cert);
        }

        /* Also try parsing as PKCS12 */
        CFArrayRef items = NULL;
        NSDictionary *opts = @{
            (__bridge NSString *)kSecImportExportPassphrase: @""
        };
        SecPKCS12Import((__bridge CFDataRef)nsdata,
                        (__bridge CFDictionaryRef)opts, &items);
        if (items) CFRelease(items);

        /* Try parsing as CMS/PKCS7 */
        CMSDecoderRef decoder = NULL;
        if (CMSDecoderCreate(&decoder) == errSecSuccess && decoder) {
            CMSDecoderUpdateMessage(decoder, data, size);
            CMSDecoderFinalizeMessage(decoder);

            size_t numSigners = 0;
            CMSDecoderGetNumSigners(decoder, &numSigners);

            CFDataRef content = NULL;
            CMSDecoderCopyContent(decoder, &content);
            if (content) CFRelease(content);

            CFRelease(decoder);
        }
    }
}

/* ================================================================
 * PATH 6: Embedded Image/Icon Data
 *
 * AirDrop Ask requests include JPEG/PNG icon data inline.
 * sharingd renders these for the accept/reject UI.
 * ================================================================ */
static void fuzz_icon_image(const uint8_t *data, size_t size) {
    @autoreleasepool {
        NSData *nsdata = [NSData dataWithBytesNoCopy:(void *)data
                                              length:size
                                        freeWhenDone:NO];

        /* Try CGImage creation (JPEG, PNG, BMP, GIF, TIFF...) */
        CGDataProviderRef provider = CGDataProviderCreateWithCFData(
            (__bridge CFDataRef)nsdata);
        if (!provider) return;

        /* JPEG */
        CGImageRef img = CGImageCreateWithJPEGDataProvider(
            provider, NULL, false, kCGRenderingIntentDefault);
        if (img) {
            (void)CGImageGetWidth(img);
            (void)CGImageGetHeight(img);
            (void)CGImageGetBytesPerRow(img);
            (void)CGImageGetBitsPerComponent(img);

            /* Force decode by getting pixel data */
            CFDataRef pixelData = CGDataProviderCopyData(
                CGImageGetDataProvider(img));
            if (pixelData) CFRelease(pixelData);

            CGImageRelease(img);
        }

        /* PNG */
        img = CGImageCreateWithPNGDataProvider(
            provider, NULL, false, kCGRenderingIntentDefault);
        if (img) {
            CFDataRef pixelData = CGDataProviderCopyData(
                CGImageGetDataProvider(img));
            if (pixelData) CFRelease(pixelData);
            CGImageRelease(img);
        }

        /* CGImageSource for format-agnostic parsing */
        CGImageSourceRef src = CGImageSourceCreateWithData(
            (__bridge CFDataRef)nsdata, NULL);
        if (src) {
            size_t count = CGImageSourceGetCount(src);
            if (count > 0 && count < 100) {
                for (size_t i = 0; i < count && i < 5; i++) {
                    CGImageRef frame = CGImageSourceCreateImageAtIndex(
                        src, i, NULL);
                    if (frame) CGImageRelease(frame);

                    CFDictionaryRef props = CGImageSourceCopyPropertiesAtIndex(
                        src, i, NULL);
                    if (props) CFRelease(props);
                }
            }
            CFRelease(src);
        }

        CGDataProviderRelease(provider);
    }
}

/* ================================================================
 * PATH 7: Universal Clipboard / Handoff Data
 *
 * Handoff data is serialized as NSKeyedArchiver plist.
 * Universal Clipboard sends pasteboard contents over BLE/WiFi.
 * ================================================================ */
static void fuzz_clipboard_data(const uint8_t *data, size_t size) {
    @autoreleasepool {
        NSData *nsdata = [NSData dataWithBytesNoCopy:(void *)data
                                              length:size
                                        freeWhenDone:NO];

        @try {
            /* NSKeyedUnarchiver — same attack as iMessage */
            NSKeyedUnarchiver *unarchiver = [[NSKeyedUnarchiver alloc]
                initForReadingFromData:nsdata error:NULL];
            if (unarchiver) {
                unarchiver.requiresSecureCoding = NO;
                @try {
                    id obj = [unarchiver decodeObjectForKey:NSKeyedArchiveRootObjectKey];
                    (void)obj;
                } @catch (NSException *inner) {}
                @try {
                    [unarchiver finishDecoding];
                } @catch (NSException *inner) {}
            }
        } @catch (NSException *e) {
            /* Expected for malformed data */
        }

        /* Also try as a raw plist (clipboard metadata) */
        @try {
            id plist = [NSPropertyListSerialization
                propertyListWithData:nsdata
                options:NSPropertyListImmutable
                format:NULL error:NULL];
            if (plist && [plist isKindOfClass:[NSDictionary class]]) {
                NSDictionary *d = (NSDictionary *)plist;

                id type = d[@"Type"];
                id content = d[@"Content"];
                id source = d[@"SourceDeviceID"];
                id seq = d[@"SequenceNumber"];

                if ([type isKindOfClass:[NSString class]])
                    (void)[(NSString *)type UTF8String];
                if ([content isKindOfClass:[NSData class]])
                    (void)[(NSData *)content length];
                if ([source isKindOfClass:[NSString class]])
                    (void)[[NSUUID alloc] initWithUUIDString:(NSString *)source];
                if ([seq isKindOfClass:[NSNumber class]])
                    (void)[(NSNumber *)seq unsignedLongLongValue];
            }
        } @catch (NSException *e) {}
    }
}

/* ================================================================
 * PATH 8: Wi-Fi Password Sharing Plist
 *
 * When sharing Wi-Fi passwords, sharingd exchanges plists
 * containing SSID, PSK material, and device identity info.
 * ================================================================ */
static void fuzz_wifi_password(const uint8_t *data, size_t size) {
    @autoreleasepool {
        NSData *nsdata = [NSData dataWithBytesNoCopy:(void *)data
                                              length:size
                                        freeWhenDone:NO];

        id plist = [NSPropertyListSerialization
            propertyListWithData:nsdata
            options:NSPropertyListMutableContainersAndLeaves
            format:NULL error:NULL];

        if (plist && [plist isKindOfClass:[NSDictionary class]]) {
            NSDictionary *d = (NSDictionary *)plist;

            id ssid = d[@"SSID"];
            id psk = d[@"PSK"];
            id security = d[@"SecurityType"];
            id phone = d[@"PhoneNumber"];
            id email = d[@"AppleID"];
            id contactHash = d[@"ContactHash"];

            if ([ssid isKindOfClass:[NSString class]])
                (void)[(NSString *)ssid UTF8String];
            if ([psk isKindOfClass:[NSData class]])
                (void)[(NSData *)psk length];
            if ([security isKindOfClass:[NSString class]])
                (void)[(NSString *)security UTF8String];
            if ([phone isKindOfClass:[NSString class]])
                (void)[(NSString *)phone UTF8String];
            if ([email isKindOfClass:[NSString class]])
                (void)[(NSString *)email UTF8String];
            if ([contactHash isKindOfClass:[NSData class]])
                (void)[(NSData *)contactHash length];

            /* Nested device info */
            id device = d[@"DeviceInfo"];
            if ([device isKindOfClass:[NSDictionary class]]) {
                for (NSString *key in (NSDictionary *)device) {
                    if ([key isKindOfClass:[NSString class]])
                        (void)[[(NSDictionary *)device objectForKey:key] description];
                }
            }
        }
    }
}

/* ================================================================
 * LLVMFuzzerTestOneInput — libFuzzer entry point
 *
 * Input structure:
 *   byte 0:    path selector (8 paths)
 *   bytes 1+:  fuzz payload
 * ================================================================ */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0;

    uint8_t path = data[0];
    const uint8_t *payload = data + 1;
    size_t psize = size - 1;

    switch (path % 8) {
        case 0: fuzz_discover_plist(payload, psize);      break;
        case 1: fuzz_ask_plist(payload, psize);            break;
        case 2: fuzz_txt_record(payload, psize);           break;
        case 3: fuzz_nearby_frame(payload, psize);         break;
        case 4: fuzz_sender_certificate(payload, psize);   break;
        case 5: fuzz_icon_image(payload, psize);           break;
        case 6: fuzz_clipboard_data(payload, psize);       break;
        case 7: fuzz_wifi_password(payload, psize);        break;
    }

    return 0;
}
