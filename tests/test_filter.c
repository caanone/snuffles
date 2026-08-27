#include "filter.h"
#include "test_common.h"
#include <string.h>

static pkt_summary_t mk(const char *si, const char *di, int sp, int dp) {
    pkt_summary_t p;
    memset(&p, 0, sizeof(p));
    snprintf(p.src_ip, sizeof(p.src_ip), "%s", si);
    snprintf(p.dst_ip, sizeof(p.dst_ip), "%s", di);
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

    /* empty and NULL are match-all */
    CHECK(eval("", &a) == 1);
    {
        display_filter_t f;
        CHECK(filter_compile(NULL, &f) == 0);
        CHECK(filter_eval(&f, &a));
    }

    TEST_MAIN_END();
}
