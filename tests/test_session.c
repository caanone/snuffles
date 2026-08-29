#include "session.h"
#include "test_common.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Summaries the way dissect_packet() hands them over: strings for display
 * plus the binary address pair the session table keys on. */
static void set_v4(uint8_t *addr, const char *dotted) {
    unsigned a = 0, b = 0, c = 0, d = 0;
    memset(addr, 0, 16);
    if (sscanf(dotted, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
        addr[0] = (uint8_t)a; addr[1] = (uint8_t)b;
        addr[2] = (uint8_t)c; addr[3] = (uint8_t)d;
    }
}

static pkt_summary_t mk(const char *si, const char *di, int sp, int dp,
                        uint8_t flags, long ts) {
    pkt_summary_t p;
    memset(&p, 0, sizeof(p));
    snprintf(p.src_ip, sizeof(p.src_ip), "%s", si);
    snprintf(p.dst_ip, sizeof(p.dst_ip), "%s", di);
    if (si[0] && di[0]) {
        set_v4(p.src_addr, si);
        set_v4(p.dst_addr, di);
        p.addr_family = 4;
    }
    p.src_port = (uint16_t)sp;
    p.dst_port = (uint16_t)dp;
    p.l4_proto = PROTO_TCP;
    p.tcp_flags = flags;
    p.ts.tv_sec = ts;
    p.length = 100;
    return p;
}

static pkt_summary_t mk6(const uint8_t *sa, const char *si,
                         const uint8_t *da, const char *di,
                         int sp, int dp, uint8_t flags, long ts) {
    pkt_summary_t p = mk("", "", sp, dp, flags, ts);
    snprintf(p.src_ip, sizeof(p.src_ip), "%s", si);
    snprintf(p.dst_ip, sizeof(p.dst_ip), "%s", di);
    memcpy(p.src_addr, sa, 16);
    memcpy(p.dst_addr, da, 16);
    p.addr_family = 6;
    return p;
}

static const session_entry_t *find_id(const session_entry_t *snap, uint32_t n,
                                      uint32_t id) {
    for (uint32_t i = 0; i < n; i++)
        if (snap[i].id == id) return &snap[i];
    return NULL;
}

static double now_s(void) {
    return (double)clock() / (double)CLOCKS_PER_SEC;
}

#define TF_FIN 0x01
#define TF_SYN 0x02
#define TF_RST 0x04
#define TF_ACK 0x10

int main(void) {
    session_table_t *st = session_table_create(64);
    CHECK(st != NULL);
    /* the bucket argument is a minimum: sized for the default cap */
    CHECK(st->bucket_count >= 2 * SESSION_DEFAULT_MAX);
    CHECK((st->bucket_count & (st->bucket_count - 1)) == 0);
    CHECK(st->pool_cap == SESSION_DEFAULT_MAX);

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

    /* same ports, different protocol: separate session */
    {
        pkt_summary_t u = mk("10.0.0.1", "8.8.8.8", 40000, 443, 0, 3);
        u.l4_proto = PROTO_UDP;
        uint32_t idu = session_table_update(st, &u, NULL, 0);
        CHECK(idu != 0 && idu != id1);
        CHECK(session_table_count(st) == 3);
    }

    /* packets without IPs are untracked */
    pkt_summary_t noip = mk("", "", 0, 0, 0, 4);
    CHECK(session_table_update(st, &noip, NULL, 0) == 0);

    /* display fields: side A is the lower binary address (8.8.8.8 < 10.0.0.1
     * as bytes, although "10..." < "8..." as strings) */
    {
        uint32_t n;
        session_entry_t *snap = session_table_snapshot(st, &n, SORT_RECENT);
        const session_entry_t *e = find_id(snap, n, id1);
        CHECK(e != NULL);
        CHECK(e && strcmp(e->key.ip_a, "8.8.8.8") == 0);
        CHECK(e && strcmp(e->key.ip_b, "10.0.0.1") == 0);
        CHECK(e && e->key.port_a == 443 && e->key.port_b == 40000);
        CHECK(e && e->key.proto == PROTO_TCP);
        CHECK(e && e->bkey.family == 4);
        /* per-direction counters follow the canonical sides */
        CHECK(e && e->pkts_b_to_a == 1 && e->pkts_a_to_b == 1);
        CHECK(e && e->tcp_state == SESS_ESTABLISHED);   /* SYN, then SYN|ACK */
        free(snap);
    }

    /* non-first IP fragments carry no L4 header: never a session */
    {
        uint32_t before = session_table_count(st);
        pkt_summary_t fr = mk("10.0.0.1", "8.8.8.8", 0, 0, 0, 4);
        fr.l4_proto = PROTO_UNKNOWN;
        fr.ip_frag_off = 0x00B9;                 /* offset 185, MF clear */
        CHECK(session_table_update(st, &fr, NULL, 0) == 0);
        fr.ip_frag_off = 0x2005;                 /* MF set, offset 5 */
        CHECK(session_table_update(st, &fr, NULL, 0) == 0);
        CHECK(session_table_count(st) == before);
        /* the FIRST fragment (offset 0, MF set) is a normal packet */
        pkt_summary_t f0 = mk("10.0.0.1", "8.8.8.8", 40000, 443, TF_ACK, 4);
        f0.ip_frag_off = 0x2000;
        CHECK(session_table_update(st, &f0, NULL, 0) == id1);
        CHECK(session_table_count(st) == before);
    }

    /* IPv6: both directions canonicalize to one session; an IPv6 address
     * whose first 4 bytes equal an IPv4 address is a different key */
    {
        static const uint8_t a6[16] = { 0x20,0x01,0x0d,0xb8, 0,0,0,0, 0,0,0,0, 0,0,0,1 };
        static const uint8_t b6[16] = { 0x20,0x01,0x0d,0xb8, 0,0,0,0, 0,0,0,0, 0,0,0,2 };
        static const uint8_t c6[16] = { 10,0,0,1, 0,0,0,0, 0,0,0,0, 0,0,0,0 };
        static const uint8_t d6[16] = { 8,8,8,8,  0,0,0,0, 0,0,0,0, 0,0,0,0 };
        pkt_summary_t p6  = mk6(b6, "2001:db8::2", a6, "2001:db8::1", 5555, 80, TF_SYN, 5);
        pkt_summary_t p6r = mk6(a6, "2001:db8::1", b6, "2001:db8::2", 80, 5555, TF_SYN | TF_ACK, 6);
        uint32_t i6 = session_table_update(st, &p6, NULL, 0);
        CHECK(i6 != 0);
        CHECK(session_table_update(st, &p6r, NULL, 0) == i6);
        uint32_t n;
        session_entry_t *snap = session_table_snapshot(st, &n, SORT_RECENT);
        const session_entry_t *e = find_id(snap, n, i6);
        CHECK(e && e->bkey.family == 6);
        CHECK(e && strcmp(e->key.ip_a, "2001:db8::1") == 0 && e->key.port_a == 80);
        CHECK(e && strcmp(e->key.ip_b, "2001:db8::2") == 0 && e->key.port_b == 5555);
        free(snap);
        /* v6 key with the v4 bytes of session id1 in front */
        pkt_summary_t px = mk6(c6, "a00:1::", d6, "808:808::", 40000, 443, TF_SYN, 7);
        uint32_t ix = session_table_update(st, &px, NULL, 0);
        CHECK(ix != 0 && ix != id1);
    }

    /* TCP state machine: EST, then FIN x2 = CLOSED */
    pkt_summary_t fin1 = mk("10.0.0.1", "8.8.8.8", 40000, 443, TF_FIN | TF_ACK, 5);
    pkt_summary_t fin2 = mk("8.8.8.8", "10.0.0.1", 443, 40000, TF_FIN | TF_ACK, 6);
    session_table_update(st, &fin1, NULL, 0);
    session_table_update(st, &fin2, NULL, 0);
    {
        uint32_t n;
        session_entry_t *snap = session_table_snapshot(st, &n, SORT_BYTES);
        const session_entry_t *e = find_id(snap, n, id1);
        CHECK(e && e->tcp_state == SESS_CLOSED);
        /* per-direction counters (SYN, SYN|ACK, first-fragment ACK, 2 FIN) */
        CHECK(e && e->pkts_a_to_b + e->pkts_b_to_a == 5);

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

    /* eviction respects the cap (one eviction per insert: start empty) */
    session_table_clear(st);
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
        CHECK(find_id(snap, n, ida) && find_id(snap, n, idc) &&
              find_id(snap, n, idd) && !find_id(snap, n, idb));
        free(snap);
    }
    /* the evicted entry went through the free list and was recycled for
     * D: three pool slots in use, nothing on the heap */
    CHECK(st->pool_used == 3 && st->free_list == NULL);
    st->max_sessions = SESSION_DEFAULT_MAX;

    /* clear */
    session_table_clear(st);
    CHECK(session_table_count(st) == 0);
    CHECK(st->pool_used == 0 && st->free_list == NULL);
    {
        uint32_t n = 123;
        session_entry_t *snap = session_table_snapshot(st, &n, SORT_BYTES);
        CHECK(snap == NULL && n == 0);
    }

    /* ── eviction at scale: O(1) per insert, strict LRU order ─── */
    {
        const uint32_t cap = SESSION_DEFAULT_MAX, total = 2 * cap;
        pkt_summary_t p = mk("10.1.0.0", "10.2.0.0", 1, 80, TF_SYN, 1);
        uint32_t first_id = 0, mid_id = 0;
        double t0 = now_s();
        for (uint32_t i = 0; i < total; i++) {
            /* distinct source address per flow */
            p.src_addr[1] = (uint8_t)(i >> 16);
            p.src_addr[2] = (uint8_t)(i >> 8);
            p.src_addr[3] = (uint8_t)i;
            p.ts.tv_sec = (long)i;
            uint32_t id = session_table_update(st, &p, NULL, 0);
            CHECK(id != 0);
            if (i == 0)   first_id = id;
            if (i == cap) mid_id = id;
        }
        double dt = now_s() - t0;
        printf("%u inserts into a %u-session cap: %.0f ms (%.0f ns/insert)\n",
               total, cap, dt * 1e3, dt * 1e9 / total);
        /* Wall-clock bound: 20 ms natively on x86-64, but the sanitized
         * arm64 CI runner needs ~4.3 s (21 us/insert under ASan/UBSan), so
         * only enforce it in unsanitized builds. */
#if !defined(__SANITIZE_ADDRESS__) && !(defined(__has_feature) && __has_feature(address_sanitizer))
        CHECK(dt < 2.0);
#endif
        CHECK(session_table_count(st) == cap);
        CHECK(st->pool_used == cap);            /* no growth past the pool */
        /* the first half was evicted in order; the second half is resident */
        uint32_t n;
        session_entry_t *snap = session_table_snapshot(st, &n, SORT_RECENT);
        CHECK(snap && n == cap);
        CHECK(!find_id(snap, n, first_id));
        CHECK(find_id(snap, n, mid_id) != NULL);
        CHECK(snap && snap[0].id == mid_id + cap - 1);      /* most recent */
        CHECK(snap && snap[n - 1].id == mid_id);            /* oldest */
        free(snap);
        /* every resident flow is still found under its id */
        for (uint32_t i = cap; i < total; i += 997) {
            p.src_addr[1] = (uint8_t)(i >> 16);
            p.src_addr[2] = (uint8_t)(i >> 8);
            p.src_addr[3] = (uint8_t)i;
            CHECK(session_table_update(st, &p, NULL, 0) == mid_id + (i - cap));
        }
        CHECK(session_table_count(st) == cap);
        session_table_clear(st);
    }

    session_table_destroy(st);

    /* ── TCP stream reassembly ──────────────────────────────── */
    {
        session_table_t *rt = session_table_create(64);
        CHECK(rt != NULL);
        session_table_enable_reasm(rt, 16 * 1024 * 1024);

        /* in-order segments accumulate per direction independently
         * (side A = 8.8.8.8, the lower binary address; so 10.0.0.1's
         * bytes are direction 1) */
        pkt_summary_t p;
        /* mk() sets length=100; reassembly derives the wire payload from
         * length - l7_off, so make each summary self-consistent */
        p = mk("10.0.0.1", "8.8.8.8", 40000, 443, TF_ACK, 1);
        p.tcp_seq = 1000; p.length = 5;
        uint32_t sid = session_table_update(rt, &p, (const uint8_t *)"hello", 5);
        CHECK(sid != 0);
        p = mk("8.8.8.8", "10.0.0.1", 443, 40000, TF_ACK, 2);
        p.tcp_seq = 9000; p.length = 6;
        session_table_update(rt, &p, (const uint8_t *)"WORLD!", 6);
        p = mk("10.0.0.1", "8.8.8.8", 40000, 443, TF_ACK, 3);
        p.tcp_seq = 1005; p.length = 6;
        session_table_update(rt, &p, (const uint8_t *)" there", 6);

        uint8_t buf[SESSION_STREAM_CAP];
        uint32_t got = session_stream_copy(rt, sid, 1, buf, sizeof(buf));
        CHECK(got == 11 && memcmp(buf, "hello there", 11) == 0);
        got = session_stream_copy(rt, sid, 0, buf, sizeof(buf));
        CHECK(got == 6 && memcmp(buf, "WORLD!", 6) == 0);
        {
            uint8_t oa[64], ob[64];
            uint32_t la, lb;
            session_streams_copy(rt, sid, oa, ob, sizeof(oa), &la, &lb);
            CHECK(la == 6 && lb == 11);
            CHECK(memcmp(oa, "WORLD!", 6) == 0 && memcmp(ob, "hello there", 11) == 0);
        }

        /* retransmitted segment does not duplicate */
        p = mk("10.0.0.1", "8.8.8.8", 40000, 443, TF_ACK, 4);
        p.tcp_seq = 1005; p.length = 6;
        session_table_update(rt, &p, (const uint8_t *)" there", 6);
        CHECK(session_stream_copy(rt, sid, 1, buf, sizeof(buf)) == 11);

        /* gap resyncs: later bytes still captured, gaps counted */
        p = mk("10.0.0.1", "8.8.8.8", 40000, 443, TF_ACK, 5);
        p.tcp_seq = 2000; p.length = 9;
        session_table_update(rt, &p, (const uint8_t *)"after-gap", 9);
        got = session_stream_copy(rt, sid, 1, buf, sizeof(buf));
        CHECK(got == 20 && memcmp(buf + 11, "after-gap", 9) == 0);
        {
            uint32_t n;
            session_entry_t *snap = session_table_snapshot(rt, &n, SORT_RECENT);
            CHECK(snap && n == 1);
            CHECK(snap[0].gaps == 1);
            /* snapshot copies never carry live stream pointers */
            CHECK(snap[0].stream_a == NULL && snap[0].stream_b == NULL);
            CHECK(snap[0].hold_prev == NULL && snap[0].hold_next == NULL);
            free(snap);
        }

        /* per-direction cap: feed > SESSION_STREAM_CAP, length stays capped */
        {
            uint8_t big[1000];
            memset(big, 'x', sizeof(big));
            uint32_t seq = 2009;   /* continues right after "after-gap" */
            for (int i = 0; i < 40; i++) {   /* 40 KB > 16 KB cap */
                p = mk("10.0.0.1", "8.8.8.8", 40000, 443, TF_ACK, 10 + i);
                p.tcp_seq = seq; p.length = sizeof(big);
                session_table_update(rt, &p, big, sizeof(big));
                seq += sizeof(big);
            }
            uint8_t *cb = malloc(SESSION_STREAM_CAP + 16);
            CHECK(cb != NULL);
            got = session_stream_copy(rt, sid, 1, cb, SESSION_STREAM_CAP + 16);
            CHECK(got == SESSION_STREAM_CAP);
            free(cb);
        }

        /* snaplen truncation: wire length exceeds the captured payload;
         * next_seq must advance by the WIRE length so the following
         * in-order segment is not miscounted as a gap */
        {
            session_table_t *tt = session_table_create(64);
            session_table_enable_reasm(tt, 1 << 20);
            pkt_summary_t q = mk("10.0.0.1", "8.8.8.8", 50000, 80, TF_ACK, 1);
            q.tcp_seq = 100; q.l7_off = 54; q.length = 54 + 1000;
            uint32_t tid = session_table_update(tt, &q,
                                                (const uint8_t *)"trunc", 5);
            q = mk("10.0.0.1", "8.8.8.8", 50000, 80, TF_ACK, 2);
            q.tcp_seq = 1100; q.l7_off = 54; q.length = 54 + 1000;
            session_table_update(tt, &q, (const uint8_t *)"cated", 5);
            uint32_t n;
            session_entry_t *ts = session_table_snapshot(tt, &n, SORT_RECENT);
            CHECK(ts && n == 1 && ts[0].id == tid);
            CHECK(ts[0].gaps == 0);   /* truncation is not packet loss */
            free(ts);
            uint8_t tb[32];
            CHECK(session_stream_copy(tt, tid, 1, tb, sizeof(tb)) == 10);
            CHECK(memcmp(tb, "trunccated", 10) == 0);
            session_table_destroy(tt);
        }

        /* clear frees the buffers and refunds the budget */
        CHECK(rt->reasm_used > 0);
        session_table_clear(rt);
        CHECK(rt->reasm_used == 0);
        CHECK(rt->buf_alloc == 0 && rt->buf_free == NULL);
        CHECK(session_stream_copy(rt, sid, 0, buf, sizeof(buf)) == 0);

        session_table_destroy(rt);
    }

    /* ── stream buffer lifecycle: budget of exactly two buffers ── */
    {
        session_table_t *bt = session_table_create(64);
        CHECK(bt != NULL);
        session_table_enable_reasm(bt, 2 * SESSION_STREAM_CAP);
        CHECK(bt->buf_max == 2);
        CHECK(bt->reasm_idle_sec == SESSION_REASM_IDLE_DEFAULT);
        pkt_summary_t p;
        uint8_t out[64];

        /* X (port 1001) and Y (port 1002) each take one buffer */
        p = mk("10.0.0.1", "10.0.0.2", 1001, 80, TF_ACK, 100);
        p.tcp_seq = 1; p.length = 4;
        uint32_t x = session_table_update(bt, &p, (const uint8_t *)"XXXX", 4);
        p = mk("10.0.0.1", "10.0.0.2", 1002, 80, TF_ACK, 101);
        p.tcp_seq = 1; p.length = 4;
        uint32_t y = session_table_update(bt, &p, (const uint8_t *)"YYYY", 4);
        CHECK(x && y && x != y);
        CHECK(bt->reasm_used == 2 * SESSION_STREAM_CAP && bt->buf_alloc == 2);

        /* budget exhausted, nobody closed or idle: Z takes the buffer of
         * the oldest holder (X); Y keeps its bytes */
        p = mk("10.0.0.1", "10.0.0.2", 1003, 80, TF_ACK, 102);
        p.tcp_seq = 1; p.length = 4;
        uint32_t z = session_table_update(bt, &p, (const uint8_t *)"ZZZZ", 4);
        CHECK(z != 0);
        CHECK(session_stream_copy(bt, z, 0, out, sizeof(out)) == 4);
        CHECK(session_stream_copy(bt, x, 0, out, sizeof(out)) == 0);
        CHECK(session_stream_copy(bt, y, 0, out, sizeof(out)) == 4);
        CHECK(bt->reasm_used == 2 * SESSION_STREAM_CAP && bt->buf_alloc == 2);

        /* Y closes (FIN both ways): it is now the first reclaim candidate
         * even though Z has been quiet for longer; until then its stream
         * stays readable */
        p = mk("10.0.0.1", "10.0.0.2", 1002, 80, TF_FIN | TF_ACK, 103);
        p.tcp_seq = 5; p.length = 0;
        session_table_update(bt, &p, NULL, 0);
        p = mk("10.0.0.2", "10.0.0.1", 80, 1002, TF_FIN | TF_ACK, 104);
        p.tcp_seq = 1; p.length = 0;
        session_table_update(bt, &p, NULL, 0);
        {
            uint32_t n;
            session_entry_t *snap = session_table_snapshot(bt, &n, SORT_RECENT);
            const session_entry_t *e = find_id(snap, n, y);
            CHECK(e && e->tcp_state == SESS_CLOSED);
            free(snap);
        }
        CHECK(session_stream_copy(bt, y, 0, out, sizeof(out)) == 4);
        CHECK(bt->hold_closed.head != NULL && bt->hold_closed.head->id == y);

        /* new session W takes the closed session's buffer, not Z's */
        p = mk("10.0.0.1", "10.0.0.2", 1004, 80, TF_ACK, 105);
        p.tcp_seq = 1; p.length = 4;
        uint32_t w = session_table_update(bt, &p, (const uint8_t *)"WWWW", 4);
        CHECK(session_stream_copy(bt, w, 0, out, sizeof(out)) == 4);
        CHECK(memcmp(out, "WWWW", 4) == 0);
        CHECK(session_stream_copy(bt, y, 0, out, sizeof(out)) == 0);
        CHECK(session_stream_copy(bt, z, 0, out, sizeof(out)) == 4);
        CHECK(bt->buf_alloc == 2);                  /* reused, not malloc'd */
        CHECK(bt->hold_closed.head == NULL);

        /* RST is a close too */
        p = mk("10.0.0.1", "10.0.0.2", 1004, 80, TF_RST, 106);
        p.tcp_seq = 5; p.length = 0;
        session_table_update(bt, &p, NULL, 0);
        CHECK(bt->hold_closed.head != NULL && bt->hold_closed.head->id == w);

        /* idle: Z's last packet was at t=102; a packet at t=102+60 from any
         * flow releases Z's buffer back to the pool (budget refunded) */
        p = mk("10.0.0.1", "10.0.0.2", 1005, 80, TF_SYN, 162);
        p.tcp_seq = 0; p.length = 0;
        session_table_update(bt, &p, NULL, 0);
        CHECK(session_stream_copy(bt, z, 0, out, sizeof(out)) == 0);
        CHECK(bt->reasm_used == SESSION_STREAM_CAP);   /* only W holds */
        CHECK(bt->buf_free != NULL);
        /* W (closed at t=106) goes idle at t=166 */
        p.ts.tv_sec = 166;
        session_table_update(bt, &p, NULL, 0);
        CHECK(bt->reasm_used == 0);
        CHECK(bt->hold_closed.head == NULL && bt->hold_active.head == NULL);
        /* and the pooled buffers serve the next flow without a malloc */
        p = mk("10.0.0.1", "10.0.0.2", 1006, 80, TF_ACK, 170);
        p.tcp_seq = 1; p.length = 4;
        uint32_t v = session_table_update(bt, &p, (const uint8_t *)"VVVV", 4);
        CHECK(session_stream_copy(bt, v, 0, out, sizeof(out)) == 4);
        CHECK(bt->buf_alloc == 2 && bt->reasm_used == SESSION_STREAM_CAP);

        /* a holder that keeps talking is never idle-released */
        for (long t = 171; t < 400; t += 30) {
            p = mk("10.0.0.1", "10.0.0.2", 1006, 80, TF_ACK, t);
            p.tcp_seq = 5; p.length = 0;
            session_table_update(bt, &p, NULL, 0);
        }
        CHECK(session_stream_copy(bt, v, 0, out, sizeof(out)) == 4);

        /* idle timeout 0 disables the sweep */
        bt->reasm_idle_sec = 0;
        p = mk("10.0.0.1", "10.0.0.2", 1007, 80, TF_SYN, 9999);
        session_table_update(bt, &p, NULL, 0);
        CHECK(session_stream_copy(bt, v, 0, out, sizeof(out)) == 4);

        /* eviction of a holder refunds its buffers: cap the table at one
         * entry and push enough new flows through to evict V */
        bt->max_sessions = 1;
        p = mk("10.0.0.9", "10.0.0.2", 1008, 80, TF_SYN, 9999);
        for (int i = 0; i < 20; i++) {
            p.src_port++;
            session_table_update(bt, &p, NULL, 0);
        }
        CHECK(bt->reasm_used == 0);
        CHECK(session_stream_copy(bt, v, 0, out, sizeof(out)) == 0);

        session_table_destroy(bt);
    }

    TEST_MAIN_END();
}
