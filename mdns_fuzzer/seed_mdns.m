/*
 * seed_mdns.m — Generate seeds for 8 DNS/mDNS fuzzing paths
 *
 * Build: clang -framework Foundation -lresolv -o seed_mdns seed_mdns.m
 * Run:   ./seed_mdns corpus/
 */
#import <Foundation/Foundation.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <dns_sd.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>

typedef struct __attribute__((packed)) {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} dns_hdr_t;

static void write_seed(const char *dir, const char *name,
                       uint8_t path, const uint8_t *buf, size_t len) {
    char path_str[512];
    snprintf(path_str, sizeof(path_str), "%s/%s", dir, name);
    NSMutableData *d = [NSMutableData dataWithBytes:&path length:1];
    [d appendBytes:buf length:len];
    [d writeToFile:[NSString stringWithUTF8String:path_str] atomically:YES];
    printf("  [+] %-44s (%5lu bytes, path=%d)\n", name, (unsigned long)d.length, path);
}

/* Encode a DNS name into wire format */
static int encode_name(uint8_t *buf, int max, const char *name) {
    int off = 0;
    const char *p = name;
    while (*p && off < max - 2) {
        const char *dot = strchr(p, '.');
        int labLen = dot ? (int)(dot - p) : (int)strlen(p);
        if (labLen > 63) labLen = 63;
        buf[off++] = (uint8_t)labLen;
        memcpy(buf + off, p, labLen);
        off += labLen;
        p += labLen;
        if (*p == '.') p++;
    }
    buf[off++] = 0; /* root */
    return off;
}

/* Build a DNS response with given records */
static NSData *build_dns_response(const char *qname, uint16_t qtype,
                                   const uint8_t *rdata, uint16_t rdlen,
                                   uint16_t rtype) {
    uint8_t pkt[4096];
    memset(pkt, 0, sizeof(pkt));

    dns_hdr_t *hdr = (dns_hdr_t *)pkt;
    hdr->id = htons(0xABCD);
    hdr->flags = htons(0x8180); /* QR=1, AA=1, RD=1, RA=1 */
    hdr->qdcount = htons(1);
    hdr->ancount = htons(1);

    int off = sizeof(dns_hdr_t);

    /* Question section */
    off += encode_name(pkt + off, sizeof(pkt) - off, qname);
    *(uint16_t *)(pkt + off) = htons(qtype); off += 2;
    *(uint16_t *)(pkt + off) = htons(1);     off += 2; /* IN class */

    /* Answer: use compression pointer to question name */
    pkt[off++] = 0xC0; pkt[off++] = 0x0C; /* pointer to offset 12 */
    *(uint16_t *)(pkt + off) = htons(rtype); off += 2;
    *(uint16_t *)(pkt + off) = htons(1);     off += 2; /* IN */
    *(uint32_t *)(pkt + off) = htonl(300);   off += 4; /* TTL */
    *(uint16_t *)(pkt + off) = htons(rdlen); off += 2;
    memcpy(pkt + off, rdata, rdlen);         off += rdlen;

    return [NSData dataWithBytes:pkt length:off];
}

int main(int argc, char *argv[]) {
    @autoreleasepool {
        const char *dir = argc > 1 ? argv[1] : "corpus";
        mkdir(dir, 0755);
        printf("[*] Generating DNS/mDNS seeds in %s/\n\n", dir);

        /* PATH 0: A record response */
        {
            uint8_t ip[] = {192, 168, 1, 100};
            NSData *pkt = build_dns_response("example.com", 1, ip, 4, 1);
            write_seed(dir, "dns_a_record.bin", 0,
                      (const uint8_t *)pkt.bytes, pkt.length);
        }

        /* PATH 0: AAAA record */
        {
            uint8_t ip6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0, 0, 1};
            NSData *pkt = build_dns_response("example.com", 28, ip6, 16, 28);
            write_seed(dir, "dns_aaaa_record.bin", 0,
                      (const uint8_t *)pkt.bytes, pkt.length);
        }

        /* PATH 0: CNAME + MX */
        {
            uint8_t rdata[256];
            int off = 0;
            off += encode_name(rdata + off, sizeof(rdata) - off, "www.example.com");
            NSData *pkt = build_dns_response("alias.example.com", 5, rdata, off, 5);
            write_seed(dir, "dns_cname.bin", 0,
                      (const uint8_t *)pkt.bytes, pkt.length);
        }

        /* PATH 1: mDNS PTR response */
        {
            uint8_t rdata[256];
            int off = encode_name(rdata, sizeof(rdata), "My Printer._ipp._tcp.local");
            NSData *pkt = build_dns_response("_ipp._tcp.local", 12, rdata, off, 12);
            write_seed(dir, "mdns_ptr.bin", 1,
                      (const uint8_t *)pkt.bytes, pkt.length);
        }

        /* PATH 1: SRV record */
        {
            uint8_t rdata[256];
            *(uint16_t *)(rdata) = htons(0);   /* priority */
            *(uint16_t *)(rdata + 2) = htons(0); /* weight */
            *(uint16_t *)(rdata + 4) = htons(631); /* port */
            int off = 6 + encode_name(rdata + 6, sizeof(rdata) - 6, "printer.local");
            NSData *pkt = build_dns_response("My Printer._ipp._tcp.local", 33,
                                              rdata, off, 33);
            write_seed(dir, "mdns_srv.bin", 1,
                      (const uint8_t *)pkt.bytes, pkt.length);
        }

        /* PATH 2: Name compression test */
        {
            uint8_t pkt[128];
            memset(pkt, 0, sizeof(pkt));
            dns_hdr_t *hdr = (dns_hdr_t *)pkt;
            hdr->flags = htons(0x8180);
            hdr->qdcount = htons(1);
            hdr->ancount = htons(1);

            int off = sizeof(dns_hdr_t);
            off += encode_name(pkt + off, sizeof(pkt) - off, "www.example.com");
            *(uint16_t *)(pkt + off) = htons(1); off += 2;
            *(uint16_t *)(pkt + off) = htons(1); off += 2;
            /* Answer: CNAME with pointer to different part */
            pkt[off++] = 0xC0; pkt[off++] = 16; /* ptr to example.com */
            *(uint16_t *)(pkt + off) = htons(5); off += 2; /* CNAME */
            *(uint16_t *)(pkt + off) = htons(1); off += 2;
            *(uint32_t *)(pkt + off) = htonl(60); off += 4;
            int rdlenOff = off;
            off += 2;
            int nameStart = off;
            off += encode_name(pkt + off, sizeof(pkt) - off, "cdn.example.com");
            *(uint16_t *)(pkt + rdlenOff) = htons(off - nameStart);

            write_seed(dir, "name_compress.bin", 2, pkt, off);
        }

        /* PATH 3: DNSSEC RRSIG */
        {
            uint8_t pkt[512];
            memset(pkt, 0, sizeof(pkt));
            dns_hdr_t *hdr = (dns_hdr_t *)pkt;
            hdr->flags = htons(0x8580); /* AA, AD flags */
            hdr->qdcount = htons(1);
            hdr->ancount = htons(1);

            int off = sizeof(dns_hdr_t);
            off += encode_name(pkt + off, sizeof(pkt) - off, "example.com");
            *(uint16_t *)(pkt + off) = htons(46); off += 2; /* RRSIG */
            *(uint16_t *)(pkt + off) = htons(1);  off += 2;
            /* Answer */
            pkt[off++] = 0xC0; pkt[off++] = 0x0C;
            *(uint16_t *)(pkt + off) = htons(46); off += 2;
            *(uint16_t *)(pkt + off) = htons(1);  off += 2;
            *(uint32_t *)(pkt + off) = htonl(3600); off += 4;
            /* RRSIG RDATA */
            int rdlenOff = off; off += 2;
            int rdataStart = off;
            *(uint16_t *)(pkt + off) = htons(1); off += 2; /* type covered: A */
            pkt[off++] = 8;  /* algorithm: RSA/SHA-256 */
            pkt[off++] = 2;  /* labels */
            *(uint32_t *)(pkt + off) = htonl(3600); off += 4;
            *(uint32_t *)(pkt + off) = htonl(0x65800000); off += 4; /* expiration */
            *(uint32_t *)(pkt + off) = htonl(0x65700000); off += 4; /* inception */
            *(uint16_t *)(pkt + off) = htons(12345); off += 2; /* key tag */
            off += encode_name(pkt + off, sizeof(pkt) - off, "example.com"); /* signer */
            /* Fake signature */
            for (int i = 0; i < 64; i++) pkt[off++] = (uint8_t)i;
            *(uint16_t *)(pkt + rdlenOff) = htons(off - rdataStart);

            write_seed(dir, "dnssec_rrsig.bin", 3, pkt, off);
        }

        /* PATH 4: EDNS0 OPT record */
        {
            uint8_t pkt[128];
            memset(pkt, 0, sizeof(pkt));
            dns_hdr_t *hdr = (dns_hdr_t *)pkt;
            hdr->flags = htons(0x8180);
            hdr->qdcount = htons(1);
            hdr->arcount = htons(1); /* OPT in additional */

            int off = sizeof(dns_hdr_t);
            off += encode_name(pkt + off, sizeof(pkt) - off, "example.com");
            *(uint16_t *)(pkt + off) = htons(1); off += 2;
            *(uint16_t *)(pkt + off) = htons(1); off += 2;

            /* OPT pseudo-record */
            pkt[off++] = 0; /* empty name (root) */
            *(uint16_t *)(pkt + off) = htons(41); off += 2; /* OPT type */
            *(uint16_t *)(pkt + off) = htons(4096); off += 2; /* UDP size */
            *(uint32_t *)(pkt + off) = htonl(0x00008000); off += 4; /* DNSSEC OK */
            /* OPT options: NSID + Cookie */
            uint8_t optData[] = {
                0x00, 0x03, 0x00, 0x04, 'n', 's', 'i', 'd',  /* NSID */
                0x00, 0x0A, 0x00, 0x08, 0x01, 0x02, 0x03, 0x04,
                0x05, 0x06, 0x07, 0x08,  /* Cookie */
            };
            *(uint16_t *)(pkt + off) = htons(sizeof(optData)); off += 2;
            memcpy(pkt + off, optData, sizeof(optData)); off += sizeof(optData);

            write_seed(dir, "edns0_opt.bin", 4, pkt, off);
        }

        /* PATH 5: TXT record data */
        {
            uint8_t txt[] = "\x07version=1\x09model=Mac\x0bflags=0x42";
            write_seed(dir, "txt_record.bin", 5, txt, sizeof(txt) - 1);
        }

        /* PATH 6: NSNetService TXT */
        {
            NSDictionary *dict = @{
                @"version": [@"1.0" dataUsingEncoding:NSUTF8StringEncoding],
                @"model": [@"MacBook" dataUsingEncoding:NSUTF8StringEncoding],
                @"features": [@"0x1234" dataUsingEncoding:NSUTF8StringEncoding],
            };
            NSData *txtData = [NSNetService dataFromTXTRecordDictionary:dict];
            write_seed(dir, "netservice_txt.bin", 6,
                      (const uint8_t *)txtData.bytes, txtData.length);
        }

        /* PATH 7: Malformed packets */
        {
            /* Self-referencing name pointer */
            uint8_t mal1[] = {
                0xAB, 0xCD, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
                0x00, 0x00, 0x00, 0x00,
                0xC0, 0x0C, /* self-reference */
                0x00, 0x01, 0x00, 0x01,
            };
            write_seed(dir, "malformed_selfref.bin", 7, mal1, sizeof(mal1));

            /* Truncated header */
            uint8_t mal2[] = {0xAB, 0xCD, 0x81, 0x80, 0xFF, 0xFF};
            write_seed(dir, "malformed_truncated.bin", 7, mal2, sizeof(mal2));
        }

        printf("\n[+] DNS/mDNS seeds generated for 8 paths.\n");
        return 0;
    }
}
