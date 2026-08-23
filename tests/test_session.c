#include "session.h"
#include "test_common.h"
#include <stdlib.h>
#include <string.h>

static pkt_summary_t mk(const char *si, const char *di, int sp, int dp,
                        uint8_t flags, long ts) {
    pkt_summary_t p;
    memset(&p, 0, sizeof(p));
    snprintf(p.src_ip, sizeof(p.src_ip), "%s", si);
    snprintf(p.dst_ip, sizeof(p.dst_ip), "%s", di);
    p.src_port = (uint16_t)sp;
    p.dst_port = (uint16_t)dp;
    p.l4_proto = PROTO_TCP;
    p.tcp_flags = flags;
    p.ts.tv_sec = ts;
    p.length = 100;
    return p;
}

#define TF_FIN 0x01
#define TF_SYN 0x02
#define TF_RST 0x04
#define TF_ACK 0x10

int main(void) {
    session_table_t *st = session_table_create(64);
    CHECK(st != NULL);

    /* both directions of a flow map to the same session */
    pkt_summary_t fwd = mk("10.0.0.1", "8.8.8.8", 40000, 443, TF_SYN, 1);
    pkt_summary_t rev = mk("8.8.8.8", "10.0.0.1", 443, 40000, TF_SYN | TF_ACK, 2);
    uint32_t id1 = session_table_update(st, &fwd);
    uint32_t id2 = session_table_update(st, &rev);
    CHECK(id1 != 0);
    CHECK(id1 == id2);
    CHECK(session_table_count(st) == 1);

    /* a different 5-tuple gets a different session */
    pkt_summary_t other = mk("10.0.0.1", "8.8.8.8", 40001, 443, TF_SYN, 3);
    uint32_t id3 = session_table_update(st, &other);
    CHECK(id3 != 0 && id3 != id1);
    CHECK(session_table_count(st) == 2);

    /* packets without IPs are untracked */
    pkt_summary_t noip = mk("", "", 0, 0, 0, 4);
    CHECK(session_table_update(st, &noip) == 0);

    /* TCP state machine: SYN -> SYN/ACK -> ACK = EST, then FIN x2 = CLOSED */
    {
        uint32_t n;
        session_entry_t *snap = session_table_snapshot(st, &n, SORT_RECENT);
        CHECK(snap != NULL && n == 2);
        const session_entry_t *e = NULL;
        for (uint32_t i = 0; i < n; i++)
            if (snap[i].id == id1) e = &snap[i];
        CHECK(e && e->tcp_state == SESS_ESTABLISHED);   /* SYN, then SYN|ACK */
        free(snap);
    }
    pkt_summary_t fin1 = mk("10.0.0.1", "8.8.8.8", 40000, 443, TF_FIN | TF_ACK, 5);
    pkt_summary_t fin2 = mk("8.8.8.8", "10.0.0.1", 443, 40000, TF_FIN | TF_ACK, 6);
    session_table_update(st, &fin1);
    session_table_update(st, &fin2);
    {
        uint32_t n;
        session_entry_t *snap = session_table_snapshot(st, &n, SORT_BYTES);
        const session_entry_t *e = NULL;
        for (uint32_t i = 0; i < n; i++)
            if (snap[i].id == id1) e = &snap[i];
        CHECK(e && e->tcp_state == SESS_CLOSED);
        /* per-direction counters */
        CHECK(e && e->pkts_a_to_b + e->pkts_b_to_a == 4);

        /* snapshot returns copies: mutating it must not affect the table */
        snap[0].pkts_a_to_b = 999999;
        free(snap);
        uint32_t n2;
        session_entry_t *snap2 = session_table_snapshot(st, &n2, SORT_BYTES);
        CHECK(snap2 && snap2[0].pkts_a_to_b != 999999);
        free(snap2);
    }

    /* RST */
    pkt_summary_t rst = mk("10.0.0.1", "8.8.8.8", 40001, 443, TF_RST, 7);
    session_table_update(st, &rst);

    /* eviction respects the cap */
    st->max_sessions = 4;
    for (int i = 0; i < 10; i++) {
        pkt_summary_t p = mk("192.168.1.1", "192.168.1.2", 1000 + i, 80, TF_SYN,
                             100 + i);
        CHECK(session_table_update(st, &p) != 0);
        CHECK(session_table_count(st) <= 4);
    }

    /* clear */
    session_table_clear(st);
    CHECK(session_table_count(st) == 0);
    {
        uint32_t n = 123;
        session_entry_t *snap = session_table_snapshot(st, &n, SORT_BYTES);
        CHECK(snap == NULL && n == 0);
    }

    session_table_destroy(st);
    TEST_MAIN_END();
}
