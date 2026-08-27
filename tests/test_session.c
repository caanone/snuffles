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
    uint32_t id1 = session_table_update(st, &fwd, NULL, 0);
    uint32_t id2 = session_table_update(st, &rev, NULL, 0);
    CHECK(id1 != 0);
    CHECK(id1 == id2);
    CHECK(session_table_count(st) == 1);

    /* a different 5-tuple gets a different session */
    pkt_summary_t other = mk("10.0.0.1", "8.8.8.8", 40001, 443, TF_SYN, 3);
    uint32_t id3 = session_table_update(st, &other, NULL, 0);
    CHECK(id3 != 0 && id3 != id1);
    CHECK(session_table_count(st) == 2);

    /* packets without IPs are untracked */
    pkt_summary_t noip = mk("", "", 0, 0, 0, 4);
    CHECK(session_table_update(st, &noip, NULL, 0) == 0);

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
    session_table_update(st, &fin1, NULL, 0);
    session_table_update(st, &fin2, NULL, 0);
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
    session_table_update(st, &rst, NULL, 0);

    /* eviction respects the cap */
    st->max_sessions = 4;
    for (int i = 0; i < 10; i++) {
        pkt_summary_t p = mk("192.168.1.1", "192.168.1.2", 1000 + i, 80, TF_SYN,
                             100 + i);
        CHECK(session_table_update(st, &p, NULL, 0) != 0);
        CHECK(session_table_count(st) <= 4);
    }

    /* LRU eviction order: touching an old session protects it */
    session_table_clear(st);
    st->max_sessions = 3;
    pkt_summary_t sa = mk("1.1.1.1", "2.2.2.2", 100, 80, TF_SYN, 10);
    pkt_summary_t sb = mk("1.1.1.1", "2.2.2.2", 101, 80, TF_SYN, 11);
    pkt_summary_t sc = mk("1.1.1.1", "2.2.2.2", 102, 80, TF_SYN, 12);
    uint32_t ida = session_table_update(st, &sa, NULL, 0);
    uint32_t idb = session_table_update(st, &sb, NULL, 0);
    uint32_t idc = session_table_update(st, &sc, NULL, 0);
    session_table_update(st, &sa, NULL, 0);   /* touch A: B becomes LRU */
    pkt_summary_t sd = mk("1.1.1.1", "2.2.2.2", 103, 80, TF_SYN, 14);
    uint32_t idd = session_table_update(st, &sd, NULL, 0);
    CHECK(session_table_count(st) == 3);
    {
        uint32_t n;
        session_entry_t *snap = session_table_snapshot(st, &n, SORT_BYTES);
        CHECK(snap && n == 3);
        int hasA=0, hasB=0, hasC=0, hasD=0;
        for (uint32_t i = 0; i < n; i++) {
            if (snap[i].id == ida) hasA=1;
            if (snap[i].id == idb) hasB=1;
            if (snap[i].id == idc) hasC=1;
            if (snap[i].id == idd) hasD=1;
        }
        CHECK(hasA && hasC && hasD && !hasB);   /* untouched B was evicted */
        free(snap);
    }
    st->max_sessions = SESSION_DEFAULT_MAX;

    /* clear */
    session_table_clear(st);
    CHECK(session_table_count(st) == 0);
    {
        uint32_t n = 123;
        session_entry_t *snap = session_table_snapshot(st, &n, SORT_BYTES);
        CHECK(snap == NULL && n == 0);
    }

    session_table_destroy(st);

    /* ── TCP stream reassembly ──────────────────────────────── */
    {
        session_table_t *rt = session_table_create(64);
        CHECK(rt != NULL);
        session_table_enable_reasm(rt, 16 * 1024 * 1024);

        /* in-order segments accumulate per direction independently
         * (strcmp: "10.0.0.1" < "8.8.8.8", so side A = 10.0.0.1) */
        pkt_summary_t p;
        p = mk("10.0.0.1", "8.8.8.8", 40000, 443, TF_ACK, 1);
        p.tcp_seq = 1000;
        uint32_t sid = session_table_update(rt, &p, (const uint8_t *)"hello", 5);
        CHECK(sid != 0);
        p = mk("8.8.8.8", "10.0.0.1", 443, 40000, TF_ACK, 2);
        p.tcp_seq = 9000;
        session_table_update(rt, &p, (const uint8_t *)"WORLD!", 6);
        p = mk("10.0.0.1", "8.8.8.8", 40000, 443, TF_ACK, 3);
        p.tcp_seq = 1005;
        session_table_update(rt, &p, (const uint8_t *)" there", 6);

        uint8_t buf[SESSION_STREAM_CAP];
        uint32_t got = session_stream_copy(rt, sid, 0, buf, sizeof(buf));
        CHECK(got == 11 && memcmp(buf, "hello there", 11) == 0);
        got = session_stream_copy(rt, sid, 1, buf, sizeof(buf));
        CHECK(got == 6 && memcmp(buf, "WORLD!", 6) == 0);

        /* retransmitted segment does not duplicate */
        p = mk("10.0.0.1", "8.8.8.8", 40000, 443, TF_ACK, 4);
        p.tcp_seq = 1005;
        session_table_update(rt, &p, (const uint8_t *)" there", 6);
        CHECK(session_stream_copy(rt, sid, 0, buf, sizeof(buf)) == 11);

        /* gap resyncs: later bytes still captured, gaps counted */
        p = mk("10.0.0.1", "8.8.8.8", 40000, 443, TF_ACK, 5);
        p.tcp_seq = 2000;
        session_table_update(rt, &p, (const uint8_t *)"after-gap", 9);
        got = session_stream_copy(rt, sid, 0, buf, sizeof(buf));
        CHECK(got == 20 && memcmp(buf + 11, "after-gap", 9) == 0);
        {
            uint32_t n;
            session_entry_t *snap = session_table_snapshot(rt, &n, SORT_RECENT);
            CHECK(snap && n == 1);
            CHECK(snap[0].gaps == 1);
            /* snapshot copies never carry live stream pointers */
            CHECK(snap[0].stream_a == NULL && snap[0].stream_b == NULL);
            free(snap);
        }

        /* per-direction cap: feed > SESSION_STREAM_CAP, length stays capped */
        {
            uint8_t big[1000];
            memset(big, 'x', sizeof(big));
            uint32_t seq = 2009;   /* continues right after "after-gap" */
            for (int i = 0; i < 40; i++) {   /* 40 KB > 16 KB cap */
                p = mk("10.0.0.1", "8.8.8.8", 40000, 443, TF_ACK, 10 + i);
                p.tcp_seq = seq;
                session_table_update(rt, &p, big, sizeof(big));
                seq += sizeof(big);
            }
            uint8_t *cb = malloc(SESSION_STREAM_CAP + 16);
            CHECK(cb != NULL);
            got = session_stream_copy(rt, sid, 0, cb, SESSION_STREAM_CAP + 16);
            CHECK(got == SESSION_STREAM_CAP);
            free(cb);
        }

        /* clear frees the buffers and refunds the budget */
        CHECK(rt->reasm_used > 0);
        session_table_clear(rt);
        CHECK(rt->reasm_used == 0);
        CHECK(session_stream_copy(rt, sid, 0, buf, sizeof(buf)) == 0);

        session_table_destroy(rt);
    }

    TEST_MAIN_END();
}
