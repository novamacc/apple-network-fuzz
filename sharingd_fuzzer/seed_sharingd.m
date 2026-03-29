/*
 * seed_sharingd.m — Generate seeds for all 8 sharingd fuzzing paths
 *
 * Build: clang -framework Foundation -framework Security -o seed_sharingd seed_sharingd.m
 * Run:   ./seed_sharingd corpus/
 */
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>

static void write_seed(const char *dir, const char *name,
                       uint8_t path_id, NSData *payload) {
    char filepath[256];
    snprintf(filepath, sizeof(filepath), "%s/%s", dir, name);

    NSMutableData *full = [NSMutableData dataWithBytes:&path_id length:1];
    [full appendData:payload];

    [full writeToFile:[NSString stringWithUTF8String:filepath] atomically:YES];
    printf("  [+] %-42s (%5lu bytes, path=%d)\n", name,
           (unsigned long)full.length, path_id);
}

int main(int argc, char *argv[]) {
    @autoreleasepool {
        const char *dir = argc > 1 ? argv[1] : "corpus";
        mkdir(dir, 0755);
        printf("[*] Generating sharingd/AirDrop seeds in %s/\n\n", dir);

        /* PATH 0: AirDrop Discover plist */
        {
            NSDictionary *discover = @{
                @"SenderComputerName": @"Attacker-MacBook",
                @"SenderModelName": @"MacBookPro18,1",
                @"SenderID": [[NSUUID UUID] UUIDString],
                @"BundleID": @"com.apple.AirDrop",
                @"Flags": @(0x0B),
                @"SenderCapabilities": @(0x1FF),
                @"ConvertMediaFormats": @YES,
            };
            NSData *plist = [NSPropertyListSerialization
                dataWithPropertyList:discover
                format:NSPropertyListBinaryFormat_v1_0 options:0 error:NULL];
            write_seed(dir, "discover_basic.bin", 0, plist);

            /* With senderRecordData (empty cert-like data) */
            NSMutableDictionary *discover2 = [discover mutableCopy];
            uint8_t fakeCert[] = { 0x30, 0x82, 0x01, 0x00, /* DER SEQUENCE */
                0x30, 0x81, 0xA0, /* TBS Certificate */
                0xA0, 0x03, 0x02, 0x01, 0x02, /* Version 3 */
                0x02, 0x01, 0x01 }; /* Serial 1 */
            discover2[@"senderRecordData"] = [NSData dataWithBytes:fakeCert
                                                           length:sizeof(fakeCert)];
            plist = [NSPropertyListSerialization
                dataWithPropertyList:discover2
                format:NSPropertyListBinaryFormat_v1_0 options:0 error:NULL];
            write_seed(dir, "discover_with_cert.bin", 0, plist);
        }

        /* PATH 1: AirDrop Ask plist */
        {
            /* Minimal JPEG header for icon */
            uint8_t jpeg[] = { 0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10,
                'J','F','I','F', 0x00, 0x01, 0x01, 0x00, 0x00, 0x01,
                0x00, 0x01, 0x00, 0x00, 0xFF, 0xD9 };

            NSDictionary *ask = @{
                @"SenderComputerName": @"Attacker",
                @"SenderID": [[NSUUID UUID] UUIDString],
                @"BundleID": @"com.apple.sharingd",
                @"ConvertMediaFormats": @YES,
                @"Files": @[
                    @{
                        @"FileName": @"evil.png",
                        @"FileType": @"public.png",
                        @"FileBomPath": @"/tmp/airdrop/evil.png",
                        @"FileIcon": [NSData dataWithBytes:jpeg length:sizeof(jpeg)],
                        @"FileIsDirectory": @NO,
                    }
                ],
                @"smallFileIcon": [NSData dataWithBytes:jpeg length:sizeof(jpeg)],
            };
            NSData *plist = [NSPropertyListSerialization
                dataWithPropertyList:ask
                format:NSPropertyListBinaryFormat_v1_0 options:0 error:NULL];
            write_seed(dir, "ask_with_icon.bin", 1, plist);

            /* Multiple files */
            NSMutableDictionary *ask2 = [ask mutableCopy];
            NSMutableArray *files = [NSMutableArray array];
            for (int i = 0; i < 10; i++) {
                [files addObject:@{
                    @"FileName": [NSString stringWithFormat:@"file_%d.dat", i],
                    @"FileType": @"public.data",
                    @"FileBomPath": [NSString stringWithFormat:@"/tmp/f%d", i],
                }];
            }
            ask2[@"Files"] = files;
            plist = [NSPropertyListSerialization
                dataWithPropertyList:ask2
                format:NSPropertyListBinaryFormat_v1_0 options:0 error:NULL];
            write_seed(dir, "ask_many_files.bin", 1, plist);
        }

        /* PATH 2: Bonjour TXT record */
        {
            NSMutableData *txt = [NSMutableData data];
            NSArray *entries = @[@"flags=0x18B", @"dk=12",
                @"cn=Attacker", @"model=MacBookPro"];
            for (NSString *e in entries) {
                uint8_t len = (uint8_t)e.length;
                [txt appendBytes:&len length:1];
                [txt appendData:[e dataUsingEncoding:NSUTF8StringEncoding]];
            }
            write_seed(dir, "txt_airdrop.bin", 2, txt);
        }

        /* PATH 3: BLE NearbyInfo frame */
        {
            uint8_t frame[] = {
                0x10,       /* Frame type: NearbyInfo */
                0x05,       /* Status: active, AirDrop */
                0xAB, 0xCD, 0xEF, /* SSID hash */
                0x12, 0x34, 0x56, /* DSID hash */
                0x78, 0x9A, 0xBC, 0xDE, /* Extra service data */
            };
            write_seed(dir, "nearby_frame.bin", 3,
                [NSData dataWithBytes:frame length:sizeof(frame)]);

            /* NearbyInfo with embedded plist */
            NSDictionary *svcData = @{
                @"v": @(1),
                @"cap": @(0xFF),
                @"sid": [NSData dataWithBytes:"\x01\x02\x03\x04" length:4],
            };
            NSData *svcPlist = [NSPropertyListSerialization
                dataWithPropertyList:svcData
                format:NSPropertyListBinaryFormat_v1_0 options:0 error:NULL];
            NSMutableData *frame2 = [NSMutableData dataWithBytes:frame length:8];
            [frame2 appendData:svcPlist];
            write_seed(dir, "nearby_with_plist.bin", 3, frame2);
        }

        /* PATH 4: DER Certificate */
        {
            /* Self-signed certificate */
            uint8_t cert[] = {
                0x30, 0x82, 0x01, 0x22, /* SEQUENCE */
                0x30, 0x82, 0x00, 0xCB, /* TBS Certificate */
                0xA0, 0x03, 0x02, 0x01, 0x02, /* Version 3 */
                0x02, 0x01, 0x01,              /* Serial 1 */
                0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86,
                0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, /* SHA256withRSA */
                0x30, 0x12, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03,
                0x55, 0x04, 0x03, 0x0C, 0x07, 'A','t','t','a','c','k','r', /* CN=Attackr */
            };
            write_seed(dir, "cert_basic.bin", 4,
                [NSData dataWithBytes:cert length:sizeof(cert)]);
        }

        /* PATH 5: JPEG icon */
        {
            uint8_t jpeg[] = {
                0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10,
                'J','F','I','F', 0x00, 0x01, 0x01, 0x00,
                0x00, 0x48, 0x00, 0x48, 0x00, 0x00,
                /* SOF0 - 1x1 pixel RGB */
                0xFF, 0xC0, 0x00, 0x0B, 0x08,
                0x00, 0x01, 0x00, 0x01, 0x01, 0x01, 0x11, 0x00,
                0xFF, 0xD9
            };
            write_seed(dir, "icon_jpeg.bin", 5,
                [NSData dataWithBytes:jpeg length:sizeof(jpeg)]);

            /* PNG */
            uint8_t png[] = {
                0x89, 'P','N','G', 0x0D, 0x0A, 0x1A, 0x0A, /* PNG signature */
                0x00, 0x00, 0x00, 0x0D, 'I','H','D','R',   /* IHDR chunk */
                0x00, 0x00, 0x00, 0x01, /* width=1 */
                0x00, 0x00, 0x00, 0x01, /* height=1 */
                0x08, 0x02, 0x00, 0x00, 0x00, /* 8bit RGB */
                0x90, 0x77, 0x53, 0xDE, /* CRC */
            };
            write_seed(dir, "icon_png.bin", 5,
                [NSData dataWithBytes:png length:sizeof(png)]);
        }

        /* PATH 6: Handoff/Clipboard NSKeyedArchiver */
        {
            NSMutableDictionary *clipboard = [NSMutableDictionary dictionary];
            clipboard[@"Type"] = @"public.utf8-plain-text";
            clipboard[@"Content"] = [@"Hello from AirDrop fuzzer!"
                                     dataUsingEncoding:NSUTF8StringEncoding];
            clipboard[@"SourceDeviceID"] = [[NSUUID UUID] UUIDString];
            clipboard[@"SequenceNumber"] = @(42);

            NSData *archived = [NSKeyedArchiver
                archivedDataWithRootObject:clipboard
                requiringSecureCoding:NO error:NULL];
            if (archived) write_seed(dir, "clipboard_archive.bin", 6, archived);

            /* Also raw plist */
            NSData *plist = [NSPropertyListSerialization
                dataWithPropertyList:clipboard
                format:NSPropertyListBinaryFormat_v1_0 options:0 error:NULL];
            write_seed(dir, "clipboard_plist.bin", 6, plist);
        }

        /* PATH 7: Wi-Fi Password plist */
        {
            NSDictionary *wifi = @{
                @"SSID": @"AttackerNetwork",
                @"PSK": [@"password123" dataUsingEncoding:NSUTF8StringEncoding],
                @"SecurityType": @"WPA2",
                @"PhoneNumber": @"+15551234567",
                @"AppleID": @"attacker@icloud.com",
                @"ContactHash": [NSData dataWithBytes:
                    "\x01\x02\x03\x04\x05\x06\x07\x08"
                    "\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10"
                    "\x11\x12\x13\x14\x15\x16\x17\x18"
                    "\x19\x1A\x1B\x1C\x1D\x1E\x1F\x20" length:32],
                @"DeviceInfo": @{
                    @"Model": @"MacBookPro18,1",
                    @"Name": @"Attacker's MacBook",
                    @"OS": @"macOS 26.4",
                },
            };
            NSData *plist = [NSPropertyListSerialization
                dataWithPropertyList:wifi
                format:NSPropertyListBinaryFormat_v1_0 options:0 error:NULL];
            write_seed(dir, "wifi_password.bin", 7, plist);
        }

        printf("\n[+] Seeds generated for all 8 paths.\n");
        return 0;
    }
}
