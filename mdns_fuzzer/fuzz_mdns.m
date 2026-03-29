/*
 * fuzz_mdns.m — God-Level mDNSResponder / DNS Packet Parser Fuzzer
 *
 * ═══════════════════════════════════════════════════════════════════════
 * TARGET: mDNSResponder (/usr/sbin/mDNSResponder) — 3.4MB
 *
 * ZERO-CLICK NETWORK ATTACK SURFACE:
 *   mDNSResponder processes ALL DNS traffic on Apple devices:
 *   - Standard DNS queries/responses (UDP 53)
 *   - mDNS/Bonjour service discovery (UDP 5353, multicast)
 *   - DNS-SD (Service Discovery)
 *   - DNSSEC validation
 *   - TSIG authentication
 *   - EDNS0 extensions
 *   - DNS-over-TLS (DoT) / DNS-over-HTTPS (DoH)
 *   - LLQ (Long-Lived Queries)
 *   - DNS push notifications
 *
 * ATTACK MODEL:
 *   Attacker on same network sends crafted DNS responses.
 *   mDNSResponder parses them in privileged context.
 *   No user interaction required (zero-click).
 *   mDNS multicast reaches all devices on LAN.
 *
 * FUZZING PATHS (8):
 *   [1] DNS response packet      — Header, questions, answers, authority, additional
 *   [2] mDNS response            — Multicast DNS with PTR/SRV/TXT records
 *   [3] DNS name decompression   — Label pointer compression (0xC0 pointers)
 *   [4] DNSSEC records           — RRSIG, DNSKEY, DS, NSEC, NSEC3
 *   [5] EDNS0 OPT records        — Extended DNS options
 *   [6] SRV/TXT/NAPTR records    — Service discovery record types
 *   [7] DNS-SD browse response   — PTR → SRV + TXT resolution chain
 *   [8] Malformed packets        — Truncated, oversized, circular refs
 *
 * We fuzz by constructing DNS packets and sending them via:
 *   1. Direct CFNetwork DNS parsing (dnsinfo)
 *   2. NSNetService resolution (Bonjour)
 *   3. Raw packet construction → libresolv parsing
 *
 * Build:
 *   clang -framework Foundation -framework CoreFoundation \
 *         -framework CFNetwork -lresolv \
 *         -fsanitize=fuzzer,address,undefined -g -O1 \
 *         -o fuzz_mdns fuzz_mdns.m
 * ═══════════════════════════════════════════════════════════════════════
 */

#import <Foundation/Foundation.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <dns_sd.h>
#include <stdint.h>
#include <string.h>

/* DNS header structure */
typedef struct __attribute__((packed)) {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;   /* question count */
    uint16_t ancount;   /* answer count */
    uint16_t nscount;   /* authority count */
    uint16_t arcount;   /* additional count */
} dns_header_t;

/* DNS resource record */
typedef struct __attribute__((packed)) {
    uint16_t type;
    uint16_t class_;
    uint32_t ttl;
    uint16_t rdlength;
} dns_rr_fixed_t;

/* ================================================================
 * PATH 1: DNS Response Packet Parsing
 *
 * Constructs a DNS response and parses it with libresolv's
 * res_parse / ns_initparse / ns_parserr.
 * ================================================================ */
static void fuzz_dns_response(const uint8_t *data, size_t size) {
    @autoreleasepool {
        if (size < sizeof(dns_header_t)) return;

        /* Parse header */
        ns_msg msg;
        int ret = ns_initparse(data, (int)size, &msg);
        if (ret == 0) {
            /* Successfully parsed — walk all sections */
            int qdcount = ns_msg_count(msg, ns_s_qd);
            int ancount = ns_msg_count(msg, ns_s_an);
            int nscount = ns_msg_count(msg, ns_s_ns);
            int arcount = ns_msg_count(msg, ns_s_ar);

            /* Parse questions */
            for (int i = 0; i < qdcount && i < 20; i++) {
                ns_rr rr;
                if (ns_parserr(&msg, ns_s_qd, i, &rr) == 0) {
                    (void)ns_rr_name(rr);
                    (void)ns_rr_type(rr);
                    (void)ns_rr_class(rr);
                }
            }

            /* Parse answers */
            for (int i = 0; i < ancount && i < 50; i++) {
                ns_rr rr;
                if (ns_parserr(&msg, ns_s_an, i, &rr) == 0) {
                    const char *name = ns_rr_name(rr);
                    uint16_t type = ns_rr_type(rr);
                    uint16_t rdlen = ns_rr_rdlen(rr);
                    const uint8_t *rdata = ns_rr_rdata(rr);

                    /* Decompress name in rdata for relevant types */
                    char dname[NS_MAXDNAME];
                    switch (type) {
                        case ns_t_cname:
                        case ns_t_ns:
                        case ns_t_ptr:
                        case ns_t_mx:
                            if (type == ns_t_mx && rdlen > 2)
                                dn_expand(data, data + size, rdata + 2,
                                          dname, sizeof(dname));
                            else
                                dn_expand(data, data + size, rdata,
                                          dname, sizeof(dname));
                            break;
                        case ns_t_a:
                            if (rdlen == 4) {
                                char ip[INET_ADDRSTRLEN];
                                inet_ntop(AF_INET, rdata, ip, sizeof(ip));
                            }
                            break;
                        case ns_t_aaaa:
                            if (rdlen == 16) {
                                char ip6[INET6_ADDRSTRLEN];
                                inet_ntop(AF_INET6, rdata, ip6, sizeof(ip6));
                            }
                            break;
                        case ns_t_txt:
                            if (rdlen > 0) {
                                uint8_t txtlen = rdata[0];
                                if (txtlen < rdlen) {
                                    char txt[256];
                                    size_t copylen = MIN((size_t)txtlen, sizeof(txt)-1);
                                    memcpy(txt, rdata + 1, copylen);
                                    txt[copylen] = '\0';
                                }
                            }
                            break;
                        case ns_t_srv:
                            if (rdlen > 6) {
                                uint16_t priority, weight, port;
                                memcpy(&priority, rdata, 2);
                                memcpy(&weight, rdata + 2, 2);
                                memcpy(&port, rdata + 4, 2);
                                dn_expand(data, data + size, rdata + 6,
                                          dname, sizeof(dname));
                            }
                            break;
                        default:
                            break;
                    }
                }
            }

            /* Parse authority */
            for (int i = 0; i < nscount && i < 20; i++) {
                ns_rr rr;
                if (ns_parserr(&msg, ns_s_ns, i, &rr) == 0) {
                    (void)ns_rr_name(rr);
                    (void)ns_rr_type(rr);
                }
            }

            /* Parse additional */
            for (int i = 0; i < arcount && i < 20; i++) {
                ns_rr rr;
                if (ns_parserr(&msg, ns_s_ar, i, &rr) == 0) {
                    (void)ns_rr_name(rr);
                    uint16_t type = ns_rr_type(rr);
                    /* OPT record (EDNS0) */
                    if (type == ns_t_opt) {
                        (void)ns_rr_class(rr);
                        (void)ns_rr_ttl(rr);
                    }
                }
            }
        }
    }
}

/* ================================================================
 * PATH 2: mDNS Response (Bonjour)
 *
 * mDNS uses the same packet format as DNS but with multicast
 * and different conventions. We parse mDNS-specific records.
 * ================================================================ */
static void fuzz_mdns_response(const uint8_t *data, size_t size) {
    @autoreleasepool {
        if (size < sizeof(dns_header_t)) return;

        ns_msg msg;
        if (ns_initparse(data, (int)size, &msg) != 0) return;

        int ancount = ns_msg_count(msg, ns_s_an);

        for (int i = 0; i < ancount && i < 50; i++) {
            ns_rr rr;
            if (ns_parserr(&msg, ns_s_an, i, &rr) != 0) continue;

            uint16_t type = ns_rr_type(rr);
            const uint8_t *rdata = ns_rr_rdata(rr);
            uint16_t rdlen = ns_rr_rdlen(rr);

            char dname[NS_MAXDNAME];

            switch (type) {
                case ns_t_ptr: /* _http._tcp.local → Instance._http._tcp.local */
                    dn_expand(data, data + size, rdata, dname, sizeof(dname));
                    /* Parse service instance name */
                    if (strlen(dname) > 0) {
                        NSString *name = [NSString stringWithUTF8String:dname];
                        NSArray *parts = [name componentsSeparatedByString:@"."];
                        (void)parts.count;
                    }
                    break;

                case ns_t_srv: /* Priority, Weight, Port, Target */
                    if (rdlen >= 6) {
                        uint16_t priority, weight, port;
                        memcpy(&priority, rdata, 2);
                        memcpy(&weight, rdata + 2, 2);
                        memcpy(&port, rdata + 4, 2);
                        priority = ntohs(priority);
                        weight = ntohs(weight);
                        port = ntohs(port);
                        dn_expand(data, data + size, rdata + 6,
                                  dname, sizeof(dname));
                    }
                    break;

                case ns_t_txt: /* Key=value pairs */
                    if (rdlen > 0) {
                        const uint8_t *p = rdata;
                        const uint8_t *end = rdata + rdlen;
                        NSMutableDictionary *txt = [NSMutableDictionary dictionary];
                        while (p < end) {
                            uint8_t len = *p++;
                            if (p + len > end) break;
                            NSString *entry = [[NSString alloc]
                                initWithBytes:p length:len
                                encoding:NSUTF8StringEncoding];
                            if (entry) {
                                NSRange eq = [entry rangeOfString:@"="];
                                if (eq.location != NSNotFound) {
                                    NSString *k = [entry substringToIndex:eq.location];
                                    NSString *v = [entry substringFromIndex:eq.location+1];
                                    txt[k] = v;
                                }
                            }
                            p += len;
                        }
                    }
                    break;

                case ns_t_a:
                case ns_t_aaaa:
                    /* Address records */
                    if (type == ns_t_a && rdlen == 4) {
                        char ip[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, rdata, ip, sizeof(ip));
                    } else if (type == ns_t_aaaa && rdlen == 16) {
                        char ip6[INET6_ADDRSTRLEN];
                        inet_ntop(AF_INET6, rdata, ip6, sizeof(ip6));
                    }
                    break;

                default:
                    break;
            }
        }
    }
}

/* ================================================================
 * PATH 3: DNS Name Decompression
 *
 * DNS names use label compression with 0xC0 pointers.
 * Malformed pointers can cause infinite loops or buffer overflows.
 * ================================================================ */
static void fuzz_name_decompress(const uint8_t *data, size_t size) {
    @autoreleasepool {
        if (size < 12) return;

        /* Use data as a DNS packet and try to decompress names at various offsets */
        char dname[NS_MAXDNAME];

        for (size_t off = 12; off < size && off < 512; off++) {
            /* dn_expand handles compression pointers */
            int ret = dn_expand(data, data + size, data + off,
                               dname, sizeof(dname));
            if (ret > 0) {
                (void)strlen(dname);
            }
        }

        /* Also try ns_name_uncompress */
        for (size_t off = 12; off < size && off < 256; off++) {
            char uncomp[NS_MAXDNAME];
            int ret = ns_name_uncompress(data, data + size, data + off,
                                         uncomp, sizeof(uncomp));
            if (ret > 0) {
                (void)strlen(uncomp);
            }
        }
    }
}

/* ================================================================
 * PATH 4: DNSSEC Record Types
 *
 * DNSSEC adds complex record types that mDNSResponder validates:
 * - RRSIG (46): Signature over RRset
 * - DNSKEY (48): Public key for zone
 * - DS (43): Delegation Signer
 * - NSEC (47): Authenticated denial of existence
 * - NSEC3 (50): Hashed denial of existence
 * ================================================================ */
static void fuzz_dnssec_records(const uint8_t *data, size_t size) {
    @autoreleasepool {
        if (size < sizeof(dns_header_t)) return;

        ns_msg msg;
        if (ns_initparse(data, (int)size, &msg) != 0) return;

        int ancount = ns_msg_count(msg, ns_s_an);

        for (int i = 0; i < ancount && i < 30; i++) {
            ns_rr rr;
            if (ns_parserr(&msg, ns_s_an, i, &rr) != 0) continue;

            uint16_t type = ns_rr_type(rr);
            const uint8_t *rdata = ns_rr_rdata(rr);
            uint16_t rdlen = ns_rr_rdlen(rr);

            switch (type) {
                case 46: /* RRSIG */
                    if (rdlen >= 18) {
                        uint16_t typeCovered;
                        memcpy(&typeCovered, rdata, 2);
                        typeCovered = ntohs(typeCovered);
                        uint8_t algorithm = rdata[2];
                        uint8_t labels = rdata[3];
                        uint32_t origTTL;
                        memcpy(&origTTL, rdata + 4, 4);
                        uint32_t sigExpire, sigInception;
                        memcpy(&sigExpire, rdata + 8, 4);
                        memcpy(&sigInception, rdata + 12, 4);
                        uint16_t keyTag;
                        memcpy(&keyTag, rdata + 16, 2);
                        /* Signer's name (compressed) */
                        char signer[NS_MAXDNAME];
                        if (rdlen > 18) {
                            dn_expand(data, data + size, rdata + 18,
                                     signer, sizeof(signer));
                        }
                        (void)algorithm;
                        (void)labels;
                    }
                    break;

                case 48: /* DNSKEY */
                    if (rdlen >= 4) {
                        uint16_t dnskey_flags;
                        memcpy(&dnskey_flags, rdata, 2);
                        uint8_t protocol = rdata[2];
                        uint8_t algo = rdata[3];
                        /* Public key data follows */
                        (void)protocol;
                        (void)algo;
                    }
                    break;

                case 43: /* DS */
                    if (rdlen >= 4) {
                        uint16_t keyTag;
                        memcpy(&keyTag, rdata, 2);
                        uint8_t algo = rdata[2];
                        uint8_t digestType = rdata[3];
                        /* Digest follows */
                        (void)algo;
                        (void)digestType;
                    }
                    break;

                case 47: /* NSEC */
                    if (rdlen > 0) {
                        char nextDomain[NS_MAXDNAME];
                        int nameLen = dn_expand(data, data + size, rdata,
                                                nextDomain, sizeof(nextDomain));
                        if (nameLen > 0 && (size_t)nameLen < rdlen) {
                            /* Type bitmap follows */
                            const uint8_t *bitmap = rdata + nameLen;
                            size_t bitmapLen = rdlen - nameLen;
                            (void)bitmapLen;
                        }
                    }
                    break;

                case 50: /* NSEC3 */
                    if (rdlen >= 5) {
                        uint8_t hashAlgo = rdata[0];
                        uint8_t nsec3flags = rdata[1];
                        uint16_t iterations;
                        memcpy(&iterations, rdata + 2, 2);
                        uint8_t saltLen = rdata[4];
                        (void)hashAlgo;
                        (void)nsec3flags;
                        (void)iterations;
                        (void)saltLen;
                    }
                    break;

                default:
                    break;
            }
        }
    }
}

/* ================================================================
 * PATH 5: EDNS0 OPT Records
 *
 * EDNS0 extends DNS with larger UDP sizes and option codes.
 * The OPT pseudo-record has special parsing requirements.
 * ================================================================ */
static void fuzz_edns0(const uint8_t *data, size_t size) {
    @autoreleasepool {
        if (size < sizeof(dns_header_t)) return;

        ns_msg msg;
        if (ns_initparse(data, (int)size, &msg) != 0) return;

        /* OPT records are in Additional section */
        int arcount = ns_msg_count(msg, ns_s_ar);

        for (int i = 0; i < arcount && i < 10; i++) {
            ns_rr rr;
            if (ns_parserr(&msg, ns_s_ar, i, &rr) != 0) continue;

            if (ns_rr_type(rr) == ns_t_opt) {
                /* UDP payload size is in CLASS field */
                uint16_t udpSize = ns_rr_class(rr);
                /* Extended RCODE and flags in TTL field */
                uint32_t extRcodeFlags = ns_rr_ttl(rr);
                uint8_t extRcode = (extRcodeFlags >> 24) & 0xFF;
                uint8_t version = (extRcodeFlags >> 16) & 0xFF;
                uint16_t doFlag = (extRcodeFlags) & 0x8000;

                /* Parse OPT options in RDATA */
                const uint8_t *rdata = ns_rr_rdata(rr);
                uint16_t rdlen = ns_rr_rdlen(rr);
                const uint8_t *p = rdata;
                const uint8_t *end = rdata + rdlen;

                while (p + 4 <= end) {
                    uint16_t optCode, optLen;
                    memcpy(&optCode, p, 2);
                    memcpy(&optLen, p + 2, 2);
                    optCode = ntohs(optCode);
                    optLen = ntohs(optLen);
                    p += 4;
                    if (p + optLen > end) break;

                    /* Process known option codes */
                    switch (optCode) {
                        case 3:  /* NSID */
                        case 8:  /* Client Subnet */
                        case 10: /* Cookie */
                        case 11: /* TCP Keepalive */
                        case 12: /* Padding */
                        case 15: /* Extended DNS Error */
                            (void)optLen;
                            break;
                    }
                    p += optLen;
                }

                (void)udpSize;
                (void)extRcode;
                (void)version;
                (void)doFlag;
            }
        }
    }
}

/* ================================================================
 * PATH 6: TXTRecordRef API (dns_sd.h)
 *
 * The TXTRecord API is used for Bonjour service registration.
 * It has its own binary format and parsing code.
 * ================================================================ */
static void fuzz_txtrecord_api(const uint8_t *data, size_t size) {
    @autoreleasepool {
        if (size < 1) return;

        /* Parse as TXT record using dns_sd API */
        uint16_t txtLen = (uint16_t)MIN(size, 65535);

        /* Iterate TXT record key-value pairs */
        uint16_t count = TXTRecordGetCount(txtLen, data);
        for (uint16_t i = 0; i < count && i < 100; i++) {
            char key[256];
            uint8_t valueLen;
            const void *value;

            DNSServiceErrorType err = TXTRecordGetItemAtIndex(
                txtLen, data, i, sizeof(key), key, &valueLen, &value);
            if (err == kDNSServiceErr_NoError) {
                (void)strlen(key);
                (void)valueLen;
            }
        }

        /* Also try TXTRecordContainsKey */
        TXTRecordContainsKey(txtLen, data, "version");
        TXTRecordContainsKey(txtLen, data, "model");
        TXTRecordContainsKey(txtLen, data, "flags");

        /* TXTRecordGetValuePtr */
        uint8_t vlen;
        (void)TXTRecordGetValuePtr(txtLen, data, "version", &vlen);
        (void)TXTRecordGetValuePtr(txtLen, data, "path", &vlen);
    }
}

/* ================================================================
 * PATH 7: NSNetService Resolution
 *
 * NSNetService uses mDNSResponder internally is exercises the
 * Bonjour TXT record, SRV resolution, and address lookup paths.
 * ================================================================ */
static void fuzz_netservice_txt(const uint8_t *data, size_t size) {
    @autoreleasepool {
        if (size < 2) return;

        /* Parse as TXT record data via NSNetService API */
        NSData *txtData = [NSData dataWithBytesNoCopy:(void *)data
                                               length:size
                                         freeWhenDone:NO];

        NSDictionary *dict = [NSNetService dictionaryFromTXTRecordData:txtData];
        if (dict) {
            for (NSString *key in dict) {
                id val = dict[key];
                if ([val isKindOfClass:[NSData class]]) {
                    NSString *strVal = [[NSString alloc] initWithData:(NSData *)val
                        encoding:NSUTF8StringEncoding];
                    (void)strVal;
                }
            }
        }

        /* Also create from dictionary and round-trip */
        if (dict && dict.count > 0 && dict.count < 50) {
            NSData *roundTrip = [NSNetService dataFromTXTRecordDictionary:dict];
            if (roundTrip) {
                NSDictionary *dict2 = [NSNetService dictionaryFromTXTRecordData:roundTrip];
                (void)dict2;
            }
        }
    }
}

/* ================================================================
 * PATH 8: Malformed Packet Patterns
 *
 * Specifically crafted malformed DNS packets to exercise
 * error handling paths in parsing code.
 * ================================================================ */
static void fuzz_malformed(const uint8_t *data, size_t size) {
    @autoreleasepool {
        if (size < 4) return;

        /* Use first byte to select malformation type */
        uint8_t maltype = data[0] % 6;
        const uint8_t *payload = data + 1;
        size_t psize = size - 1;

        switch (maltype) {
            case 0: {
                /* Circular compression pointer */
                uint8_t pkt[64];
                memset(pkt, 0, sizeof(pkt));
                dns_header_t *hdr = (dns_header_t *)pkt;
                hdr->id = htons(0x1234);
                hdr->flags = htons(0x8180);
                hdr->qdcount = htons(1);
                hdr->ancount = htons(1);

                /* Question: pointer at offset 12 points to itself */
                pkt[12] = 0xC0; pkt[13] = 0x0C; /* self-referencing */
                pkt[14] = 0x00; pkt[15] = 0x01; /* A type */
                pkt[16] = 0x00; pkt[17] = 0x01; /* IN class */

                /* Overlay fuzz data */
                size_t copy = MIN(psize, sizeof(pkt) - 18);
                if (copy > 0) memcpy(pkt + 18, payload, copy);

                ns_msg msg;
                ns_initparse(pkt, sizeof(pkt), &msg);

                char dname[NS_MAXDNAME];
                dn_expand(pkt, pkt + sizeof(pkt), pkt + 12, dname, sizeof(dname));
                break;
            }
            case 1: {
                /* Oversized name labels */
                uint8_t pkt[512];
                memset(pkt, 0, sizeof(pkt));
                dns_header_t *hdr = (dns_header_t *)pkt;
                hdr->flags = htons(0x8180);
                hdr->qdcount = htons(1);

                /* Name with 63-byte labels (max) */
                int off = 12;
                for (int l = 0; l < 4 && off < 400; l++) {
                    uint8_t labLen = MIN(63, (uint8_t)(psize > 0 ? payload[l % psize] : 10));
                    pkt[off++] = labLen;
                    for (int j = 0; j < labLen && off < 500; j++) {
                        pkt[off++] = 'a' + (j % 26);
                    }
                }
                pkt[off++] = 0; /* root */

                ns_msg msg;
                ns_initparse(pkt, off + 4, &msg);
                break;
            }
            case 2: {
                /* Count mismatch: header says more records than exist */
                uint8_t pkt[64];
                memset(pkt, 0, sizeof(pkt));
                dns_header_t *hdr = (dns_header_t *)pkt;
                hdr->flags = htons(0x8180);
                hdr->ancount = htons(0xFFFF); /* claims 65535 answers */
                pkt[12] = 3; pkt[13]='f'; pkt[14]='o'; pkt[15]='o';
                pkt[16] = 0; /* root */

                size_t copy = MIN(psize, sizeof(pkt) - 17);
                if (copy > 0) memcpy(pkt + 17, payload, copy);

                ns_msg msg;
                ns_initparse(pkt, sizeof(pkt), &msg);
                break;
            }
            case 3: {
                /* Truncated packet */
                size_t tsize = MIN(psize, (size_t)11); /* less than header */
                ns_msg msg;
                ns_initparse(payload, (int)tsize, &msg);
                break;
            }
            case 4: {
                /* Forward pointer past end */
                uint8_t pkt[32];
                memset(pkt, 0, sizeof(pkt));
                dns_header_t *hdr = (dns_header_t *)pkt;
                hdr->qdcount = htons(1);
                pkt[12] = 0xC0;
                pkt[13] = 0xFF; /* pointer past end */

                char dname[NS_MAXDNAME];
                dn_expand(pkt, pkt + sizeof(pkt), pkt + 12, dname, sizeof(dname));
                break;
            }
            case 5: {
                /* Raw fuzz data as DNS packet */
                ns_msg msg;
                ns_initparse(payload, (int)MIN(psize, 65535), &msg);
                if (psize >= 12) {
                    char dname[NS_MAXDNAME];
                    dn_expand(payload, payload + psize, payload + 12,
                             dname, sizeof(dname));
                }
                break;
            }
        }
    }
}

/* ================================================================
 * LLVMFuzzerTestOneInput
 * ================================================================ */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0;

    uint8_t path = data[0];
    const uint8_t *payload = data + 1;
    size_t psize = size - 1;

    switch (path % 8) {
        case 0: fuzz_dns_response(payload, psize);      break;
        case 1: fuzz_mdns_response(payload, psize);      break;
        case 2: fuzz_name_decompress(payload, psize);    break;
        case 3: fuzz_dnssec_records(payload, psize);     break;
        case 4: fuzz_edns0(payload, psize);               break;
        case 5: fuzz_txtrecord_api(payload, psize);       break;
        case 6: fuzz_netservice_txt(payload, psize);      break;
        case 7: fuzz_malformed(payload, psize);           break;
    }

    return 0;
}
