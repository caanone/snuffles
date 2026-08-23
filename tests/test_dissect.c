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
