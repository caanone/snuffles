#include "dissect.h"
#include "test_common.h"
#include <stdlib.h>
#include <string.h>

/* ── packet builders ─────────────────────────────────────────── */

static size_t put(uint8_t *dst, size_t off, const void *src, size_t n) {
    memcpy(dst + off, src, n);
    return off + n;
}

static size_t eth_hdr(uint8_t *b, uint16_t ethertype) {
    memset(b, 0xAA, 6);
    memset(b + 6, 0xBB, 6);
    b[12] = (uint8_t)(ethertype >> 8);
    b[13] = (uint8_t)ethertype;
    return 14;
}

static size_t ipv4_hdr(uint8_t *b, size_t off, uint8_t proto, uint16_t payload_len) {
    uint8_t h[20] = {0};
    h[0] = 0x45;                        /* v4, IHL 5 */
    uint16_t tot = (uint16_t)(20 + payload_len);
    h[2] = (uint8_t)(tot >> 8); h[3] = (uint8_t)tot;
    h[8] = 64;                          /* TTL */
    h[9] = proto;
    h[12] = 10; h[13] = 0; h[14] = 0; h[15] = 1;    /* 10.0.0.1 */
    h[16] = 8;  h[17] = 8; h[18] = 8;  h[19] = 8;   /* 8.8.8.8 */
    return put(b, off, h, 20);
}

static size_t tcp_hdr(uint8_t *b, size_t off, uint16_t sp, uint16_t dp, uint8_t flags) {
    uint8_t h[20] = {0};
    h[0] = (uint8_t)(sp >> 8); h[1] = (uint8_t)sp;
    h[2] = (uint8_t)(dp >> 8); h[3] = (uint8_t)dp;
    h[12] = 5 << 4;                     /* data offset 20 */
    h[13] = flags;
    return put(b, off, h, 20);
}

static size_t udp_hdr(uint8_t *b, size_t off, uint16_t sp, uint16_t dp, uint16_t len) {
    uint8_t h[8] = {0};
    h[0] = (uint8_t)(sp >> 8); h[1] = (uint8_t)sp;
    h[2] = (uint8_t)(dp >> 8); h[3] = (uint8_t)dp;
    uint16_t ul = (uint16_t)(8 + len);
    h[4] = (uint8_t)(ul >> 8); h[5] = (uint8_t)ul;
    return put(b, off, h, 8);
}

static int info_is_clean(const pkt_summary_t *s) {
    for (const char *p = s->info; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c < 0x20 || c >= 0x7f) return 0;
    }
    return 1;
}

int main(void) {
    uint8_t pkt[1600];
    pkt_summary_t out;

    /* ── TCP SYN dissects correctly ─────────────────────────── */
    size_t off = eth_hdr(pkt, 0x0800);
    off = ipv4_hdr(pkt, off, 6, 20);
    off = tcp_hdr(pkt, off, 40000, 443, 0x02);
    dissect_packet(pkt, (uint32_t)off, 1, &out);
    CHECK(strcmp(out.src_ip, "10.0.0.1") == 0);
    CHECK(strcmp(out.dst_ip, "8.8.8.8") == 0);
    CHECK(out.src_port == 40000 && out.dst_port == 443);
    CHECK(out.l4_proto == PROTO_TCP);
    CHECK(out.tcp_flags == 0x02);
    CHECK(out.ip_ttl == 64);
    CHECK(out.l7_off == 14 + 20 + 20);
    CHECK(out.l7_len == 0);

    /* ── l7_off/l7_len locate the TCP payload ───────────────── */
    {
        static const char pay[] = "hello payload";
        size_t o = eth_hdr(pkt, 0x0800);
        o = ipv4_hdr(pkt, o, 6, (uint16_t)(20 + sizeof(pay) - 1));
        o = tcp_hdr(pkt, o, 40000, 9999, 0x18);
        o = put(pkt, o, pay, sizeof(pay) - 1);
        dissect_packet(pkt, (uint32_t)o, 1, &out);
        CHECK(out.l7_off == 14 + 20 + 20);
        CHECK(out.l7_len == sizeof(pay) - 1);
        CHECK(out.l7_off + out.l7_len <= (uint32_t)o);
        CHECK(memcmp(pkt + out.l7_off, pay, out.l7_len) == 0);

        /* truncation keeps the invariant l7_off + l7_len <= caplen */
        for (uint32_t len = 0; len <= (uint32_t)o; len++) {
            dissect_packet(pkt, len, 1, &out);
            CHECK(out.l7_off + out.l7_len <= len);
        }
    }

    /* ── truncation sweep: every prefix must be safe and quiet ─ */
    for (uint32_t len = 0; len <= (uint32_t)off; len++) {
        dissect_packet(pkt, len, 1, &out);
        CHECK(info_is_clean(&out));
    }

    /* ── DNS query ──────────────────────────────────────────── */
    {
        static const uint8_t dns[] = {
            0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0,
            7, 'e','x','a','m','p','l','e', 3, 'c','o','m', 0,
            0, 1, 0, 1
        };
        size_t o = eth_hdr(pkt, 0x0800);
        o = ipv4_hdr(pkt, o, 17, (uint16_t)(8 + sizeof(dns)));
        o = udp_hdr(pkt, o, 5353, 53, (uint16_t)sizeof(dns));
        o = put(pkt, o, dns, sizeof(dns));
        dissect_packet(pkt, (uint32_t)o, 1, &out);
        CHECK(out.l7_proto == PROTO_DNS);
        CHECK(strstr(out.info, "example.com") != NULL);
        for (uint32_t len = 0; len <= (uint32_t)o; len++) {
            dissect_packet(pkt, len, 1, &out);
            CHECK(info_is_clean(&out));
        }
    }

    /* ── HTTP with embedded terminal escapes is sanitized ───── */
    {
        static const char http[] = "GET /\x1b[2Jevil\x07\xc3\xa9 HTTP/1.1\r\n\r\n";
        size_t o = eth_hdr(pkt, 0x0800);
        o = ipv4_hdr(pkt, o, 6, (uint16_t)(20 + sizeof(http) - 1));
        o = tcp_hdr(pkt, o, 40000, 80, 0x18);
        o = put(pkt, o, http, sizeof(http) - 1);
        dissect_packet(pkt, (uint32_t)o, 1, &out);
        CHECK(out.l7_proto == PROTO_HTTP);
        CHECK(info_is_clean(&out));
        CHECK(strchr(out.info, 0x1b) == NULL);
    }

    /* ── lying IHL / data-offset must not crash ─────────────── */
    {
        size_t o = eth_hdr(pkt, 0x0800);
        o = ipv4_hdr(pkt, o, 6, 20);
        o = tcp_hdr(pkt, o, 1, 2, 0);
        pkt[14] = 0x4F;            /* IHL = 60 bytes, packet is shorter */
        dissect_packet(pkt, (uint32_t)o, 1, &out);
        pkt[14] = 0x45;
        pkt[14 + 20 + 12] = 0xF0;  /* TCP data offset = 60 */
        dissect_packet(pkt, (uint32_t)o, 1, &out);
    }

    /* ── raw-IP datalinks (raw backend paths) ───────────────── */
    {
        size_t o = ipv4_hdr(pkt, 0, 6, 20);
        o = tcp_hdr(pkt, o, 1234, 80, 0x02);
        dissect_packet(pkt, (uint32_t)o, 228, &out);
        CHECK(out.src_port == 1234);
        for (uint32_t len = 0; len <= (uint32_t)o; len++)
            dissect_packet(pkt, len, 228, &out);
    }

    /* ── DNS response: answer IP and rcode surfaced ─────────── */
    {
        static const uint8_t dnsr[] = {
            0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0,
            7, 'e','x','a','m','p','l','e', 3, 'c','o','m', 0,
            0, 1, 0, 1,
            0xC0, 0x0C,                /* name: pointer to question */
            0, 1, 0, 1,                /* type A, class IN */
            0, 0, 0, 60,               /* TTL */
            0, 4, 93, 184, 216, 34     /* rdlength 4 + A rdata */
        };
        size_t o = eth_hdr(pkt, 0x0800);
        o = ipv4_hdr(pkt, o, 17, (uint16_t)(8 + sizeof(dnsr)));
        o = udp_hdr(pkt, o, 53, 5353, (uint16_t)sizeof(dnsr));
        o = put(pkt, o, dnsr, sizeof(dnsr));
        dissect_packet(pkt, (uint32_t)o, 1, &out);
        CHECK(out.l7_proto == PROTO_DNS);
        CHECK(strstr(out.info, "93.184.216.34") != NULL);
        for (uint32_t len = 0; len <= (uint32_t)o; len++) {
            dissect_packet(pkt, len, 1, &out);
            CHECK(info_is_clean(&out));
        }

        /* NXDOMAIN */
        uint8_t nx[sizeof(dnsr)];
        memcpy(nx, dnsr, sizeof(dnsr));
        nx[3] = 0x83;                  /* rcode 3 */
        nx[7] = 0;                     /* ancount 0 */
        o = eth_hdr(pkt, 0x0800);
        o = ipv4_hdr(pkt, o, 17, (uint16_t)(8 + sizeof(nx)));
        o = udp_hdr(pkt, o, 53, 5353, (uint16_t)sizeof(nx));
        o = put(pkt, o, nx, sizeof(nx));
        dissect_packet(pkt, (uint32_t)o, 1, &out);
        CHECK(strstr(out.info, "NXDOMAIN") != NULL);
    }

    /* ── IPv4 non-first fragment: no L4 parse ───────────────── */
    {
        size_t o = eth_hdr(pkt, 0x0800);
        o = ipv4_hdr(pkt, o, 6, 20);
        o = tcp_hdr(pkt, o, 40000, 443, 0x02);
        pkt[14 + 6] = 0x00; pkt[14 + 7] = 0xB9;   /* frag offset 185 */
        dissect_packet(pkt, (uint32_t)o, 1, &out);
        CHECK(out.l4_proto == PROTO_UNKNOWN);
        CHECK(out.src_port == 0);
        CHECK(strstr(out.info, "fragment") != NULL);
    }

    /* ── IPv6 with hop-by-hop extension header, then TCP ────── */
    {
        uint8_t v6[40] = {0x60};
        v6[6] = 0;      /* next: hop-by-hop */
        v6[7] = 64;
        v6[9] = 1;      /* src ::1-ish */
        v6[39] = 2;
        size_t o = eth_hdr(pkt, 0x86DD);
        o = put(pkt, o, v6, 40);
        uint8_t hbh[8] = { 6, 0 };   /* next: TCP, len 0 => 8 bytes */
        o = put(pkt, o, hbh, 8);
        o = tcp_hdr(pkt, o, 1234, 443, 0x02);
        dissect_packet(pkt, (uint32_t)o, 1, &out);
        CHECK(out.l4_proto == PROTO_TCP);
        CHECK(out.src_port == 1234 && out.dst_port == 443);
        CHECK(out.l7_off == 14 + 40 + 8 + 20);
        CHECK(out.l7_len == 0);

        /* payload lands past the extension chain */
        static const uint8_t v6pay[4] = { 'a', 'b', 'c', 'd' };
        size_t o2 = put(pkt, o, v6pay, sizeof(v6pay));
        dissect_packet(pkt, (uint32_t)o2, 1, &out);
        CHECK(out.l7_off == 14 + 40 + 8 + 20);
        CHECK(out.l7_len == sizeof(v6pay));
        CHECK(memcmp(pkt + out.l7_off, v6pay, sizeof(v6pay)) == 0);

        for (uint32_t len = 0; len <= (uint32_t)o2; len++) {
            dissect_packet(pkt, len, 1, &out);
            CHECK(info_is_clean(&out));
            CHECK(out.l7_off + out.l7_len <= len);
        }
    }

    /* ── IPv6 non-first fragment stops before L4 ────────────── */
    {
        uint8_t v6[40] = {0x60};
        v6[6] = 44;     /* next: fragment header */
        v6[7] = 64;
        size_t o = eth_hdr(pkt, 0x86DD);
        o = put(pkt, o, v6, 40);
        uint8_t frag[8] = { 6, 0, 0x05, 0xA8 };   /* offset != 0 */
        o = put(pkt, o, frag, 8);
        o = tcp_hdr(pkt, o, 999, 999, 0);         /* garbage beyond */
        dissect_packet(pkt, (uint32_t)o, 1, &out);
        CHECK(out.l4_proto == PROTO_UNKNOWN);
        CHECK(out.src_port == 0);
        CHECK(strstr(out.info, "fragment") != NULL);
    }

    /* ── Linux cooked capture (DLT_LINUX_SLL / SLL2) ────────── */
    {
        uint8_t sll[16] = {0};
        sll[14] = 0x08; sll[15] = 0x00;           /* EtherType IPv4 */
        size_t o = put(pkt, 0, sll, 16);
        o = ipv4_hdr(pkt, o, 6, 20);
        o = tcp_hdr(pkt, o, 5555, 80, 0x02);
        dissect_packet(pkt, (uint32_t)o, 113, &out);
        CHECK(out.l4_proto == PROTO_TCP);
        CHECK(out.src_port == 5555);
        for (uint32_t len = 0; len <= (uint32_t)o; len++)
            dissect_packet(pkt, len, 113, &out);

        uint8_t sll2[20] = {0x08, 0x00};          /* EtherType first */
        o = put(pkt, 0, sll2, 20);
        o = ipv4_hdr(pkt, o, 17, 8);
        o = udp_hdr(pkt, o, 68, 67, 0);
        dissect_packet(pkt, (uint32_t)o, 276, &out);
        CHECK(out.l4_proto == PROTO_UDP);
        CHECK(out.src_port == 68);
    }

    /* ── DLT_NULL loopback framing (both byte orders) ───────── */
    {
        uint8_t nullhdr[4] = { 2, 0, 0, 0 };      /* AF_INET little-endian */
        size_t o = put(pkt, 0, nullhdr, 4);
        o = ipv4_hdr(pkt, o, 6, 20);
        o = tcp_hdr(pkt, o, 4242, 22, 0x10);
        dissect_packet(pkt, (uint32_t)o, 0, &out);
        CHECK(out.l4_proto == PROTO_TCP);
        CHECK(out.src_port == 4242);

        uint8_t swapped[4] = { 0, 0, 0, 2 };      /* big-endian host / LOOP */
        put(pkt, 0, swapped, 4);
        dissect_packet(pkt, (uint32_t)o, 0, &out);
        CHECK(out.l4_proto == PROTO_TCP);
        for (uint32_t len = 0; len <= (uint32_t)o; len++)
            dissect_packet(pkt, len, 0, &out);
    }

    /* ── DHCP DISCOVER (and OFFER with yiaddr) ──────────────── */
    {
        uint8_t dhcp[244];
        memset(dhcp, 0, sizeof(dhcp));
        dhcp[0] = 1;                   /* op: BOOTREQUEST */
        dhcp[1] = 1; dhcp[2] = 6;      /* htype ethernet, hlen 6 */
        dhcp[236] = 0x63; dhcp[237] = 0x82;   /* magic cookie */
        dhcp[238] = 0x53; dhcp[239] = 0x63;
        dhcp[240] = 53; dhcp[241] = 1; dhcp[242] = 1;   /* opt 53: DISCOVER */
        dhcp[243] = 255;               /* end */
        size_t o = eth_hdr(pkt, 0x0800);
        o = ipv4_hdr(pkt, o, 17, (uint16_t)(8 + sizeof(dhcp)));
        o = udp_hdr(pkt, o, 68, 67, (uint16_t)sizeof(dhcp));
        o = put(pkt, o, dhcp, sizeof(dhcp));
        dissect_packet(pkt, (uint32_t)o, 1, &out);
        CHECK(out.l7_proto == PROTO_DHCP);
        CHECK(strcmp(out.protocol, "DHCP") == 0);
        CHECK(strstr(out.info, "DHCP DISCOVER") != NULL);
        for (uint32_t len = 0; len <= (uint32_t)o; len++) {
            dissect_packet(pkt, len, 1, &out);
            CHECK(info_is_clean(&out));
        }

        /* OFFER: op reply, yiaddr set, server -> client ports */
        dhcp[0] = 2;
        dhcp[16] = 10; dhcp[17] = 0; dhcp[18] = 0; dhcp[19] = 42;
        dhcp[242] = 2;
        o = eth_hdr(pkt, 0x0800);
        o = ipv4_hdr(pkt, o, 17, (uint16_t)(8 + sizeof(dhcp)));
        o = udp_hdr(pkt, o, 67, 68, (uint16_t)sizeof(dhcp));
        o = put(pkt, o, dhcp, sizeof(dhcp));
        dissect_packet(pkt, (uint32_t)o, 1, &out);
        CHECK(out.l7_proto == PROTO_DHCP);
        CHECK(strstr(out.info, "DHCP OFFER") != NULL);
        CHECK(strstr(out.info, "10.0.0.42") != NULL);
        for (uint32_t len = 0; len <= (uint32_t)o; len++) {
            dissect_packet(pkt, len, 1, &out);
            CHECK(info_is_clean(&out));
        }
    }

    /* ── NTP client (mode 3, v4) ────────────────────────────── */
    {
        uint8_t ntp[48];
        memset(ntp, 0, sizeof(ntp));
        ntp[0] = (0 << 6) | (4 << 3) | 3;   /* LI 0, VN 4, mode client */
        size_t o = eth_hdr(pkt, 0x0800);
        o = ipv4_hdr(pkt, o, 17, (uint16_t)(8 + sizeof(ntp)));
        o = udp_hdr(pkt, o, 50123, 123, (uint16_t)sizeof(ntp));
        o = put(pkt, o, ntp, sizeof(ntp));
        dissect_packet(pkt, (uint32_t)o, 1, &out);
        CHECK(out.l7_proto == PROTO_NTP);
        CHECK(strcmp(out.protocol, "NTP") == 0);
        CHECK(strstr(out.info, "NTP client v4") != NULL);
        for (uint32_t len = 0; len <= (uint32_t)o; len++) {
            dissect_packet(pkt, len, 1, &out);
            CHECK(info_is_clean(&out));
        }

        /* server reply: mode 4, stratum 2 */
        ntp[0] = (0 << 6) | (4 << 3) | 4;
        ntp[1] = 2;
        o = eth_hdr(pkt, 0x0800);
        o = ipv4_hdr(pkt, o, 17, (uint16_t)(8 + sizeof(ntp)));
        o = udp_hdr(pkt, o, 123, 50123, (uint16_t)sizeof(ntp));
        o = put(pkt, o, ntp, sizeof(ntp));
        dissect_packet(pkt, (uint32_t)o, 1, &out);
        CHECK(out.l7_proto == PROTO_NTP);
        CHECK(strstr(out.info, "NTP server v4 stratum 2") != NULL);
    }

    /* ── mDNS query: DNS bytes on port 5353, relabeled ──────── */
    {
        static const uint8_t dns[] = {
            0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0,
            7, 'e','x','a','m','p','l','e', 3, 'c','o','m', 0,
            0, 1, 0, 1
        };
        size_t o = eth_hdr(pkt, 0x0800);
        o = ipv4_hdr(pkt, o, 17, (uint16_t)(8 + sizeof(dns)));
        o = udp_hdr(pkt, o, 5353, 5353, (uint16_t)sizeof(dns));
        o = put(pkt, o, dns, sizeof(dns));
        dissect_packet(pkt, (uint32_t)o, 1, &out);
        CHECK(out.l7_proto == PROTO_MDNS);
        CHECK(out.highest_proto == PROTO_MDNS);
        CHECK(strcmp(out.protocol, "mDNS") == 0);
        CHECK(strstr(out.info, "example.com") != NULL);
        for (uint32_t len = 0; len <= (uint32_t)o; len++) {
            dissect_packet(pkt, len, 1, &out);
            CHECK(info_is_clean(&out));
        }
    }

    /* ── QUIC Initial long header on UDP 443 ────────────────── */
    {
        uint8_t quic[16];
        memset(quic, 0, sizeof(quic));
        quic[0] = 0xC0;                /* long header, type 0 = Initial */
        quic[4] = 0x01;                /* version 0x00000001 */
        size_t o = eth_hdr(pkt, 0x0800);
        o = ipv4_hdr(pkt, o, 17, (uint16_t)(8 + sizeof(quic)));
        o = udp_hdr(pkt, o, 51000, 443, (uint16_t)sizeof(quic));
        o = put(pkt, o, quic, sizeof(quic));
        dissect_packet(pkt, (uint32_t)o, 1, &out);
        CHECK(out.l7_proto == PROTO_QUIC);
        CHECK(strcmp(out.protocol, "QUIC") == 0);
        CHECK(strstr(out.info, "QUIC Initial v1") != NULL);
        for (uint32_t len = 0; len <= (uint32_t)o; len++) {
            dissect_packet(pkt, len, 1, &out);
            CHECK(info_is_clean(&out));
        }

        /* short header (top bit clear) must stay plain UDP */
        pkt[o - sizeof(quic)] = 0x40;
        dissect_packet(pkt, (uint32_t)o, 1, &out);
        CHECK(out.l7_proto == PROTO_UNKNOWN);
        CHECK(strcmp(out.protocol, "UDP") == 0);
    }

    /* ── random garbage sweep (mini-fuzz, deterministic) ────── */
    {
        unsigned seed = 42;
        for (int i = 0; i < 20000; i++) {
            seed = seed * 1103515245u + 12345u;
            uint32_t len = (seed >> 16) % 256;
            for (uint32_t j = 0; j < len; j++) {
                seed = seed * 1103515245u + 12345u;
                pkt[j] = (uint8_t)(seed >> 24);
            }
            dissect_packet(pkt, len, 1, &out);
            CHECK(info_is_clean(&out));
        }
    }

    TEST_MAIN_END();
}
