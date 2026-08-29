#include "filter.h"
#include "test_common.h"
#include <string.h>

static void set_v4(uint8_t *addr, const char *dotted) {
    unsigned a = 0, b = 0, c = 0, d = 0;
    memset(addr, 0, 16);
    if (sscanf(dotted, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
        addr[0] = (uint8_t)a; addr[1] = (uint8_t)b;
        addr[2] = (uint8_t)c; addr[3] = (uint8_t)d;
    }
}

/* text columns plus the binary pair, as the dissector would leave them
 * after summary_format() */
static pkt_summary_t mk(const char *si, const char *di, int sp, int dp) {
    pkt_summary_t p;
    memset(&p, 0, sizeof(p));
    snprintf(p.src_ip, sizeof(p.src_ip), "%s", si);
    snprintf(p.dst_ip, sizeof(p.dst_ip), "%s", di);
    set_v4(p.src_addr, si);
    set_v4(p.dst_addr, di);
    p.addr_family = 4;
    p.src_port = (uint16_t)sp;
    p.dst_port = (uint16_t)dp;
    p.l4_proto = PROTO_TCP;
    p.highest_proto = PROTO_TCP;
    snprintf(p.protocol, sizeof(p.protocol), "TCP");
    return p;
}

static int eval(const char *expr, const pkt_summary_t *p) {
    display_filter_t f;
    if (filter_compile(expr, &f) != 0) return -1;
    return filter_eval(&f, p) ? 1 : 0;
}

static int compiles(const char *expr) {
    display_filter_t f;
    return filter_compile(expr, &f) == 0;
}

int main(void) {
    pkt_summary_t a = mk("10.0.0.5", "8.8.8.8", 40000, 443);

    /* port as a field with operators */
    CHECK(eval("port == 443", &a) == 1);
    CHECK(eval("port == 80", &a) == 0);
    CHECK(eval("port 443", &a) == 1);
    CHECK(eval("port > 30000", &a) == 1);

    /* != means "neither side matches" on either-side fields */
    CHECK(eval("port != 443", &a) == 0);
    CHECK(eval("port != 53", &a) == 1);
    CHECK(eval("ip != 10.0.0.5", &a) == 0);
    CHECK(eval("ip != 1.2.3.4", &a) == 1);

    /* CIDR honors the operator */
    CHECK(eval("ip == 10.0.0.0/8", &a) == 1);
    CHECK(eval("ip != 10.0.0.0/8", &a) == 0);
    CHECK(eval("ip != 192.168.0.0/16", &a) == 1);
    CHECK(eval("src_ip == 10.0.0.0/8", &a) == 1);
    CHECK(eval("src_ip != 10.0.0.0/8", &a) == 0);
    CHECK(eval("dst_ip == 8.8.8.0/24", &a) == 1);

    /* port ranges honor the operator */
    CHECK(eval("port 80-500", &a) == 1);
    CHECK(eval("port != 80-500", &a) == 0);
    CHECK(eval("port != 1-100", &a) == 1);
    CHECK(eval("src_port == 30000-50000", &a) == 1);

    /* bare vlan quick filter */
    CHECK(eval("vlan", &a) == 0);
    a.vlan_id = 7;
    CHECK(eval("vlan", &a) == 1);
    CHECK(eval("vlan == 7", &a) == 1);
    a.vlan_id = 0;

    /* new UDP L7 shorthands compile and match (eval == -1 on
     * compile failure, so these also cover is_proto_shorthand) */
    {
        pkt_summary_t q = mk("10.0.0.5", "8.8.8.8", 51000, 443);
        q.l4_proto = PROTO_UDP;
        q.l7_proto = PROTO_QUIC;
        q.highest_proto = PROTO_QUIC;
        snprintf(q.protocol, sizeof(q.protocol), "QUIC");
        CHECK(eval("quic", &q) == 1);
        CHECK(eval("dhcp", &q) == 0);
        q.l7_proto = PROTO_MDNS; q.highest_proto = PROTO_MDNS;
        snprintf(q.protocol, sizeof(q.protocol), "mDNS");
        CHECK(eval("mdns", &q) == 1);
        q.l7_proto = PROTO_DHCP; q.highest_proto = PROTO_DHCP;
        snprintf(q.protocol, sizeof(q.protocol), "DHCP");
        CHECK(eval("dhcp", &q) == 1);
        q.l7_proto = PROTO_NTP; q.highest_proto = PROTO_NTP;
        snprintf(q.protocol, sizeof(q.protocol), "NTP");
        CHECK(eval("ntp", &q) == 1);
        CHECK(eval("quic", &q) == 0);
    }

    /* malformed CIDR / ranges are compile errors, not match-all */
    CHECK(!compiles("ip == 10.0.0.0/abc"));
    CHECK(!compiles("ip == 10.0.0.0/33"));
    CHECK(!compiles("port == 90-80"));

    /* precedence and combinators */
    CHECK(eval("(tcp or udp) && port 443", &a) == 1);
    CHECK(eval("not tcp", &a) == 0);
    CHECK(eval("!icmp && ip == 10.0.0.0/8", &a) == 1);
    CHECK(eval("tcp and udp", &a) == 0);
    CHECK(eval("tcp or udp", &a) == 1);

    /* oversized expression fails cleanly (no OOB token read) */
    {
        char big[4096] = "tcp";
        for (int i = 0; i < 60; i++) strcat(big, " and tcp");
        display_filter_t f;
        filter_compile(big, &f);   /* result irrelevant; must not crash */
    }

    /* a record straight from the ring: text columns pending, everything
     * decided on the binary fields, text produced on demand for the
     * predicates that need it */
    {
        pkt_summary_t r;
        memset(&r, 0, sizeof(r));
        r.text_pending = 1;
        set_v4(r.src_addr, "10.0.0.5");
        set_v4(r.dst_addr, "8.8.8.8");
        r.addr_family = 4;
        r.src_port = 40000; r.dst_port = 443;
        r.tcp_flags = 0x02;
        r.l3_proto = PROTO_IPV4;
        r.l4_proto = r.highest_proto = PROTO_TCP;
        r.proto_label = proto_label_of(PROTO_TCP);
        r.info_kind = INFO_TCP;
        r.has_mac = 1;
        memset(r.src_mac_raw, 0xab, 6);
        CHECK(eval("ip == 10.0.0.5", &r) == 1);
        CHECK(eval("src_ip == 10.0.0.5", &r) == 1);
        CHECK(eval("dst_ip == 10.0.0.5", &r) == 0);
        CHECK(eval("ip != 10.0.0.5", &r) == 0);
        CHECK(eval("10.0.0.0/8", &r) == 1);
        CHECK(eval("dst_ip == 8.8.8.0/24", &r) == 1);
        CHECK(eval("src_ip == 8.8.8.0/24", &r) == 0);
        CHECK(eval("proto == tcp", &r) == 1);
        CHECK(eval("tcp", &r) == 1);
        CHECK(eval("src_mac == ab:ab:ab:ab:ab:ab", &r) == 1);
        CHECK(eval("src_mac == AB:AB:AB:AB:AB:AB", &r) == 1);
        CHECK(eval("dst_mac == ab:ab:ab:ab:ab:ab", &r) == 0);
        CHECK(eval("info contains \"[S]\"", &r) == 1);
        CHECK(eval("info contains \"40000 -> 443\"", &r) == 1);
        CHECK(eval("info contains \"[SA]\"", &r) == 0);
        /* ordering operators on IP text still work */
        CHECK(eval("src_ip > 10.0.0.4", &r) == 1);
        CHECK(eval("src_ip contains 0.0.5", &r) == 1);
        /* evaluation never writes to the caller's record */
        CHECK(r.text_pending == 1 && r.info[0] == 0 && r.src_ip[0] == 0);

        /* IPv6 literal against a v6 pair (any spelling of the literal) */
        pkt_summary_t r6 = r;
        static const uint8_t a6[16] = { 0xfe, 0x80, 0,0,0,0,0,0, 0,0,0,0,0,0,0, 1 };
        memcpy(r6.src_addr, a6, 16);
        memset(r6.dst_addr, 0, 16); r6.dst_addr[15] = 1;
        r6.addr_family = 6;
        CHECK(eval("src_ip == fe80::1", &r6) == 1);
        CHECK(eval("src_ip == FE80:0:0:0:0:0:0:1", &r6) == 1);
        CHECK(eval("dst_ip == ::1", &r6) == 1);
        CHECK(eval("src_ip == fe80::2", &r6) == 0);
        CHECK(eval("ip == 10.0.0.0/8", &r6) == 0);

        /* no IP at all: address predicates are false, the rest works */
        pkt_summary_t rn = r;
        rn.addr_family = 0;
        rn.l3_proto = PROTO_ARP; rn.highest_proto = PROTO_ETH;
        rn.l4_proto = PROTO_UNKNOWN;
        rn.proto_label = proto_label_of(PROTO_ETH);
        rn.info_kind = INFO_ETH;
        CHECK(eval("ip == 10.0.0.5", &rn) == 0);
        CHECK(eval("10.0.0.0/8", &rn) == 0);
        CHECK(eval("ip != 10.0.0.5", &rn) == 1);
        CHECK(eval("info contains ab:ab:ab", &rn) == 1);
    }

    /* empty and NULL are match-all */
    CHECK(eval("", &a) == 1);
    {
        display_filter_t f;
        CHECK(filter_compile(NULL, &f) == 0);
        CHECK(filter_eval(&f, &a));
    }

    TEST_MAIN_END();
}
