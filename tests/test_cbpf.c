#include "cbpf.h"
#include "test_common.h"
#include <string.h>
#include <stdint.h>

/* ── minimal classic-BPF interpreter ─────────────────────────── */

static uint32_t bpf_run(const cbpf_insn_t *p, int n,
                        const uint8_t *pkt, uint32_t len) {
    uint32_t A = 0, X = 0;
    for (int i = 0; i < n && i >= 0; i++) {
        const cbpf_insn_t *o = &p[i];
        switch (o->code) {
            case 0x20: if (o->k + 4 > len) return 0;
                       A = ((uint32_t)pkt[o->k] << 24) | ((uint32_t)pkt[o->k+1] << 16) |
                           ((uint32_t)pkt[o->k+2] << 8) | pkt[o->k+3];
                       break;
            case 0x28: if (o->k + 2 > len) return 0;
                       A = ((uint32_t)pkt[o->k] << 8) | pkt[o->k+1];
                       break;
            case 0x30: if (o->k + 1 > len) return 0;
                       A = pkt[o->k];
                       break;
            case 0x48: if (X + o->k + 2 > len) return 0;
                       A = ((uint32_t)pkt[X+o->k] << 8) | pkt[X+o->k+1];
                       break;
            case 0xb1: if (o->k + 1 > len) return 0;
                       X = (uint32_t)(pkt[o->k] & 0x0F) * 4;
                       break;
            case 0x15: i += (A == o->k) ? o->jt : o->jf; break;
            case 0x45: i += (A & o->k) ? o->jt : o->jf; break;
            case 0x06: return o->k;
            default:   return 0;
        }
    }
    return 0;
}

/* ── packet builders (Ethernet + IPv4) ───────────────────────── */

static uint32_t build(uint8_t *b, uint8_t proto, const uint8_t src[4],
                      const uint8_t dst[4], uint16_t sp, uint16_t dp,
                      uint16_t frag) {
    memset(b, 0, 60);
    b[12] = 0x08; b[13] = 0x00;
    b[14] = 0x45;
    b[20] = (uint8_t)(frag >> 8); b[21] = (uint8_t)frag;
    b[22] = 64; b[23] = proto;
    memcpy(b + 26, src, 4);
    memcpy(b + 30, dst, 4);
    b[34] = (uint8_t)(sp >> 8); b[35] = (uint8_t)sp;
    b[36] = (uint8_t)(dp >> 8); b[37] = (uint8_t)dp;
    return 60;
}

static const uint8_t IP_A[4] = {10, 0, 0, 1};
static const uint8_t IP_B[4] = {8, 8, 8, 8};

static int match(const char *expr, const uint8_t *pkt, uint32_t len) {
    cbpf_insn_t insns[CBPF_MAX_INSNS];
    char err[128];
    int n = cbpf_compile(expr, insns, CBPF_MAX_INSNS, err, sizeof(err));
    if (n < 0) return -1;
    return bpf_run(insns, n, pkt, len) != 0;
}

int main(void) {
    uint8_t tcp443[60], udp53[60], icmp[60], frag[60], arp[60];
    uint32_t L = build(tcp443, 6, IP_A, IP_B, 40000, 443, 0);
    build(udp53, 17, IP_A, IP_B, 5353, 53, 0);
    build(icmp, 1, IP_A, IP_B, 0, 0, 0);
    build(frag, 6, IP_A, IP_B, 40000, 443, 0x00B9);   /* non-first fragment */
    memset(arp, 0, 60);
    arp[12] = 0x08; arp[13] = 0x06;

    /* protocols */
    CHECK(match("tcp", tcp443, L) == 1);
    CHECK(match("tcp", udp53, L) == 0);
    CHECK(match("udp", udp53, L) == 1);
    CHECK(match("icmp", icmp, L) == 1);
    CHECK(match("ip", arp, L) == 0);
    CHECK(match("arp", arp, L) == 1);
    CHECK(match("arp", tcp443, L) == 0);

    /* ports (either side), incl. proto and fragment guards */
    CHECK(match("port 443", tcp443, L) == 1);
    CHECK(match("port 40000", tcp443, L) == 1);
    CHECK(match("port 80", tcp443, L) == 0);
    CHECK(match("port 443", icmp, L) == 0);     /* ICMP has no ports */
    CHECK(match("port 443", frag, L) == 0);     /* fragment: no L4 header */
    CHECK(match("src port 40000", tcp443, L) == 1);
    CHECK(match("src port 443", tcp443, L) == 0);
    CHECK(match("dst port 443", tcp443, L) == 1);

    /* hosts */
    CHECK(match("host 10.0.0.1", tcp443, L) == 1);
    CHECK(match("host 8.8.8.8", tcp443, L) == 1);
    CHECK(match("host 1.2.3.4", tcp443, L) == 0);
    CHECK(match("src host 10.0.0.1", tcp443, L) == 1);
    CHECK(match("src host 8.8.8.8", tcp443, L) == 0);
    CHECK(match("dst host 8.8.8.8", tcp443, L) == 1);

    /* conjunctions, implicit and explicit */
    CHECK(match("tcp port 443", tcp443, L) == 1);
    CHECK(match("tcp port 443", udp53, L) == 0);
    CHECK(match("udp and port 53", udp53, L) == 1);
    CHECK(match("tcp and host 8.8.8.8 and port 443", tcp443, L) == 1);
    CHECK(match("tcp and host 1.1.1.1 and port 443", tcp443, L) == 0);

    /* unsupported / invalid syntax must fail to compile */
    CHECK(match("tcp or udp", tcp443, L) == -1);
    CHECK(match("not tcp", tcp443, L) == -1);
    CHECK(match("port 99999", tcp443, L) == -1);
    CHECK(match("host banana", tcp443, L) == -1);
    CHECK(match("vlan 5", tcp443, L) == -1);
    CHECK(match("", tcp443, L) == -1);
    CHECK(match("tcp and arp", tcp443, L) == -1);   /* conflicting protocols */

    TEST_MAIN_END();
}
