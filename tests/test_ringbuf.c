#include "ringbuf.h"
#include "test_common.h"
#include <pthread.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifndef _WIN32
  #include <unistd.h>
  #include <sys/select.h>
#endif

/* ── single-thread semantics ─────────────────────────────────── */

static void push(ringbuf_t *rb, uint8_t fill) {
    pkt_record_t *r = ringbuf_producer_next(rb, 32);
    CHECK(r->raw_len == 32);
    memset(r->raw_data, fill, 32);
    r->summary.length = fill;
    ringbuf_producer_commit(rb);
}

static void test_basic(void) {
    ringbuf_t *rb = ringbuf_create(8, 64, 0);
    CHECK(rb != NULL);
    CHECK(ringbuf_count(rb) == 0);

    for (int i = 0; i < 5; i++) push(rb, (uint8_t)i);
    CHECK(ringbuf_count(rb) == 5);
    CHECK(ringbuf_total(rb) == 5);

    pkt_record_t rec;
    uint8_t data[64];
    for (uint32_t i = 0; i < 5; i++) {
        CHECK(ringbuf_read(rb, i, &rec, data) == 1);
        CHECK(rec.seq_num == i);
        CHECK(rec.summary.length == i);
        CHECK(data[0] == (uint8_t)i);
    }
    CHECK(ringbuf_read(rb, 5, &rec, data) == 0);   /* out of range */

    /* wrap: 10 more pushes, capacity 8 */
    for (int i = 5; i < 15; i++) push(rb, (uint8_t)i);
    CHECK(ringbuf_count(rb) == 8);
    CHECK(ringbuf_total(rb) == 15);
    CHECK(ringbuf_oldest(rb) == 7);
    CHECK(ringbuf_read(rb, 0, &rec, NULL) == 1);
    CHECK(rec.seq_num == 7);
    CHECK(rec.raw_data == NULL);                   /* summary-only read */

    /* clear raises the floor without touching producer counters */
    ringbuf_clear(rb);
    CHECK(ringbuf_count(rb) == 0);
    CHECK(ringbuf_total(rb) == 15);
    push(rb, 99);
    CHECK(ringbuf_count(rb) == 1);
    CHECK(ringbuf_read(rb, 0, &rec, data) == 1);
    CHECK(rec.seq_num == 15);
    CHECK(data[0] == 99);

    ringbuf_destroy(rb);
}

/* ── payload arena ───────────────────────────────────────────── */

/* Push one record of len bytes filled with fill, summary.length = len. */
static void push_len(ringbuf_t *rb, uint32_t len, uint8_t fill) {
    pkt_record_t *r = ringbuf_producer_next(rb, len);
    memset(r->raw_data, fill, r->raw_len);
    r->summary.length = len;
    ringbuf_producer_commit(rb);
}

/* Read sequence seq with payload; returns raw_len, -1 on failure, and
 * checks every returned byte equals fill. */
static int read_check(ringbuf_t *rb, uint64_t seq, uint8_t fill,
                      uint8_t *data, uint32_t datalen) {
    pkt_record_t rec;
    memset(data, 0xee, datalen);
    if (!ringbuf_read_seq(rb, seq, &rec, data)) return -1;
    CHECK(rec.raw_data == data);
    for (uint32_t i = 0; i < rec.raw_len; i++)
        if (data[i] != fill) { CHECK(!"payload bytes"); break; }
    return (int)rec.raw_len;
}

static void test_arena(void) {
    /* sizing: 0 derives capacity x min(snaplen, 2048); explicit sizes are
     * raised to snaplen; a grant never exceeds snaplen */
    ringbuf_t *rb = ringbuf_create(8, 64, 0);
    CHECK(rb->arena_size == 8 * 64);
    ringbuf_destroy(rb);
    rb = ringbuf_create(8, 4000, 0);
    CHECK(rb->arena_size == 8 * 2048);
    ringbuf_destroy(rb);
    rb = ringbuf_create(8, 4000, 100);
    CHECK(rb->arena_size == 4000);
    pkt_record_t *r = ringbuf_producer_next(rb, 65535);
    CHECK(r->raw_len == 4000);
    CHECK(r->raw_data == rb->arena);
    ringbuf_producer_commit(rb);
    r = ringbuf_producer_next(rb, 1);          /* tail full: wraps to 0 */
    CHECK(r->raw_data == rb->arena);
    CHECK(r->data_pos == 4000);
    ringbuf_producer_commit(rb);
    ringbuf_destroy(rb);

    /* wrap-around with mixed sizes: 8 slots, 1024-byte arena, 200-byte
     * packets. Positions 0,200,400,600,800 fit; the sixth does not fit in
     * the 24-byte tail, so it starts a new lap at position 1024 (offset
     * 0), then 1224, 1424; cursor 1624. A payload at P is intact while
     * cursor - P <= 1024: packets 3..7 (P = 600, 800, 1024, 1224, 1424),
     * and packets 0..2 have been overlapped by the new lap. */
    rb = ringbuf_create(8, 256, 1024);
    CHECK(rb->arena_size == 1024);
    for (uint8_t i = 0; i < 8; i++) push_len(rb, 200, (uint8_t)(0x10 + i));
    CHECK(atomic_load(&rb->arena_pos) == 1624);
    uint8_t data[256];
    for (uint64_t i = 0; i < 8; i++) {
        int n = read_check(rb, i, (uint8_t)(0x10 + i), data, sizeof(data));
        CHECK(n == (i < 3 ? 0 : 200));
    }
    /* summary-only reads report the same availability */
    pkt_record_t rec;
    CHECK(ringbuf_read(rb, 0, &rec, NULL) && rec.raw_len == 0 &&
          rec.summary.length == 200 && rec.raw_data == NULL);
    CHECK(ringbuf_read(rb, 3, &rec, NULL) && rec.raw_len == 200);
    CHECK(ringbuf_read_seq(rb, 3, &rec, data) && rec.raw_len == 200 &&
          data[199] == 0x13);

    /* a 256-byte packet: the tail (offset 600, 424 free) fits it, so it
     * takes position 1624 = offsets [600, 856): all of packet 3's bytes
     * and the first 56 of packet 4's. Cursor 1880: packet 4 (P = 800,
     * 1080 > 1024) is reclaimed too — a partial overlap is enough —
     * packet 5 (P = 1024, 856) is intact. Sequence 0 left the ring. */
    push_len(rb, 256, 0xaa);
    CHECK(ringbuf_oldest(rb) == 1);
    CHECK(read_check(rb, 3, 0x13, data, sizeof(data)) == 0);
    CHECK(read_check(rb, 4, 0x14, data, sizeof(data)) == 0);
    CHECK(read_check(rb, 5, 0x15, data, sizeof(data)) == 200);
    CHECK(read_check(rb, 8, 0xaa, data, sizeof(data)) == 256);
    /* zero-length records are always "intact" and never touch the arena */
    uint64_t before = atomic_load(&rb->arena_pos);
    push_len(rb, 0, 0);
    CHECK(atomic_load(&rb->arena_pos) == before);
    CHECK(read_check(rb, 9, 0, data, sizeof(data)) == 0);
    CHECK(read_check(rb, 8, 0xaa, data, sizeof(data)) == 256);
    ringbuf_destroy(rb);

    /* tiny arena: every packet evicts the previous one */
    rb = ringbuf_create(16, 100, 100);
    for (uint8_t i = 0; i < 16; i++) push_len(rb, 100, i);
    for (uint64_t i = 0; i < 16; i++)
        CHECK(read_check(rb, i, (uint8_t)i, data, sizeof(data)) == (i == 15 ? 100 : 0));
    ringbuf_destroy(rb);
}

/* Concurrent: random sizes into a small arena that laps many times per
 * ring lap. Every payload the reader gets back must be whole (all bytes
 * carry the record's fill), never a torn or overwritten one; records
 * whose bytes were reclaimed come back with raw_len 0 and a good summary. */
#define ARENA_N 400000ULL

static ringbuf_t *g_arb;

static void *arena_producer(void *arg) {
    (void)arg;
    unsigned seed = 777;
    for (uint64_t s = 0; s < ARENA_N; s++) {
        seed = seed * 1103515245u + 12345u;
        uint32_t len = 1 + (seed >> 16) % 256;       /* 1..256 */
        pkt_record_t *r = ringbuf_producer_next(g_arb, len);
        uint8_t v = (uint8_t)(s * 7 + 1);
        memset(r->raw_data, v, r->raw_len);
        r->summary.length = len;
        r->summary.src_port = v;
        ringbuf_producer_commit(g_arb);
    }
    return NULL;
}

static void test_arena_stress(void) {
    g_arb = ringbuf_create(64, 256, 2048);   /* ~8 packets' worth of bytes */
    CHECK(g_arb != NULL);

    pthread_t t;
    pthread_create(&t, NULL, arena_producer, NULL);

    uint64_t torn = 0, ok = 0, whole = 0, reclaimed = 0, shortlen = 0;
    uint8_t data[256];
    pkt_record_t rec;
    unsigned seed = 4242;
    while (ringbuf_total(g_arb) < ARENA_N) {
        uint32_t c = ringbuf_count(g_arb);
        if (!c) continue;
        seed = seed * 1103515245u + 12345u;
        uint32_t idx = (seed >> 16) % c;
        if (!ringbuf_read(g_arb, idx, &rec, data)) continue;
        ok++;
        uint8_t v = (uint8_t)(rec.seq_num * 7 + 1);
        if (rec.summary.src_port != v) torn++;
        if (rec.raw_len == 0) { reclaimed++; continue; }
        if (rec.raw_len != rec.summary.length) shortlen++;
        whole++;
        for (uint32_t i = 0; i < rec.raw_len; i++)
            if (data[i] != v) { torn++; break; }
    }
    pthread_join(t, NULL);

    printf("arena stress: reads=%llu whole=%llu reclaimed=%llu torn=%llu\n",
           (unsigned long long)ok, (unsigned long long)whole,
           (unsigned long long)reclaimed, (unsigned long long)torn);
    CHECK(torn == 0);
    CHECK(shortlen == 0);
    CHECK(whole > 100);        /* recent records still carry their bytes */
    CHECK(reclaimed > 100);    /* ...and the arena really did lap */
    ringbuf_destroy(g_arb);
}

/* ── concurrent seqlock stress ───────────────────────────────── */

#define STRESS_N 1000000ULL

static ringbuf_t *g_rb;

static void *producer(void *arg) {
    (void)arg;
    for (uint64_t s = 0; s < STRESS_N; s++) {
        pkt_record_t *r = ringbuf_producer_next(g_rb, 64);
        uint8_t v = (uint8_t)(s ^ (s >> 8));
        memset(r->raw_data, v, 64);
        r->summary.length = (uint32_t)s;
        r->summary.src_port = v;
        ringbuf_producer_commit(g_rb);
    }
    return NULL;
}

static void test_stress(void) {
    /* arena = one ring lap of 64-byte payloads plus one packet: the
     * producer claims the bytes of the record it is about to overwrite
     * (which no reader can validate) and nothing older, so a validated
     * read must always find its payload — the reclaim bound is tight to
     * within the one allocation in flight, never early. */
    g_rb = ringbuf_create(64, 64, 65 * 64);
    CHECK(g_rb != NULL);
    CHECK(g_rb->arena_size == 65 * 64);

    pthread_t t;
    pthread_create(&t, NULL, producer, NULL);

    uint64_t torn = 0, ok = 0, reclaimed = 0;
    uint8_t data[64];
    pkt_record_t rec;
    unsigned seed = 12345;

    while (ringbuf_total(g_rb) < STRESS_N) {
        uint32_t c = ringbuf_count(g_rb);
        if (!c) continue;
        seed = seed * 1103515245u + 12345u;
        uint32_t idx = (seed >> 16) % c;
        if (ringbuf_read(g_rb, idx, &rec, data)) {
            ok++;
            uint8_t v = (uint8_t)(rec.seq_num ^ (rec.seq_num >> 8));
            if (rec.summary.length != (uint32_t)rec.seq_num ||
                rec.summary.src_port != v)
                torn++;
            if (rec.raw_len != 64) { reclaimed++; continue; }
            for (int i = 0; i < 64; i++)
                if (data[i] != v) { torn++; break; }
        }
    }
    pthread_join(t, NULL);

    CHECK(torn == 0);
    CHECK(reclaimed == 0);
    CHECK(ok > 1000);   /* the reader actually exercised the seqlock */
    ringbuf_destroy(g_rb);
}

/* ── wakeup handshake ────────────────────────────────────────── */

#define WAKE_N     100000ULL
#define WAKE_PAUSE 10          /* producer naps this many times */

static void wake_nap(void) {
#ifdef _WIN32
    Sleep(2);
#else
    struct timespec nap = { 0, 2000000 };   /* 2 ms */
    nanosleep(&nap, NULL);
#endif
}

/* Block on the wakeup channel (pipe on POSIX, auto-reset event on
 * Windows) for at most ms. Returns 1 if woken, 0 on timeout. */
static int wake_block(ringbuf_t *rb, int ms) {
#ifdef _WIN32
    return WaitForSingleObject(rb->waiters[0].event, (DWORD)ms) == WAIT_OBJECT_0;
#else
    int fd = ringbuf_get_notify_fd(rb);
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(fd, &fds);
    struct timeval tv = { .tv_sec = ms / 1000, .tv_usec = (ms % 1000) * 1000 };
    return select(fd + 1, &fds, NULL, NULL, &tv) > 0;
#endif
}

/* Consume one pending wakeup without blocking: 1 if there was one (one
 * pipe byte / the event was signalled), 0 if the channel was quiet. */
static int wake_take(ringbuf_t *rb) {
#ifdef _WIN32
    return WaitForSingleObject(rb->waiters[0].event, 0) == WAIT_OBJECT_0;
#else
    char c;
    return read(ringbuf_get_notify_fd(rb), &c, 1) == 1;
#endif
}

static void *wake_producer(void *arg) {
    (void)arg;
    for (uint64_t s = 0; s < WAKE_N; s++) {
        /* Nap now and then so the consumer drains the ring and actually
         * blocks: those are the wakeups that must not be lost. */
        if (s && s % (WAKE_N / WAKE_PAUSE) == 0)
            wake_nap();
        pkt_record_t *r = ringbuf_producer_next(g_rb, 0);
        r->summary.length = (uint32_t)s;
        ringbuf_producer_commit(g_rb);
    }
    return NULL;
}

/* Consumer runs the documented protocol: announce, re-check, block on the
 * pipe. Every record it reads must be intact, every record it misses must
 * have been lapped, and no wait may hit the (generous) timeout: a timeout
 * means a commit landed while we were blocked and nobody woke us. */
static void test_wakeup(void) {
    g_rb = ringbuf_create(1024, 16, 0);
    CHECK(g_rb != NULL);
#ifndef _WIN32
    CHECK(ringbuf_get_notify_fd(g_rb) >= 0);
#endif

    pthread_t t;
    pthread_create(&t, NULL, wake_producer, NULL);

    uint64_t last = 0, seen = 0, lapped = 0, bad = 0;
    uint64_t waits = 0, blocks = 0, timeouts = 0;
    pkt_record_t rec;
    while (last < WAKE_N) {
        if (ringbuf_total(g_rb) <= last) {
            ringbuf_consumer_will_wait(g_rb);
            waits++;
            if (ringbuf_total(g_rb) <= last) {
                blocks++;
                if (!wake_block(g_rb, 2000)) timeouts++;
            }
        }
        ringbuf_drain_notify(g_rb);

        uint64_t total = ringbuf_total(g_rb);
        while (last < total) {
            uint64_t oldest = ringbuf_oldest(g_rb);
            if (last < oldest) { lapped += oldest - last; last = oldest; continue; }
            /* The index is relative to a moving floor: a read can come
             * back valid but for a later record, or fail because the slot
             * was just overwritten. Either way re-evaluate the floor. */
            if (!ringbuf_read(g_rb, (uint32_t)(last - oldest), &rec, NULL) ||
                rec.seq_num != last)
                continue;
            seen++;
            if (rec.summary.length != (uint32_t)last) bad++;
            last++;
        }
    }
    pthread_join(t, NULL);

    uint64_t sent = ringbuf_notify_sent(g_rb);
    printf("wakeup: seen=%llu lapped=%llu waits=%llu blocks=%llu "
           "timeouts=%llu wakeups=%llu\n",
           (unsigned long long)seen, (unsigned long long)lapped,
           (unsigned long long)waits, (unsigned long long)blocks,
           (unsigned long long)timeouts, (unsigned long long)sent);
    CHECK(bad == 0);
    CHECK(seen + lapped == WAKE_N);
    CHECK(timeouts == 0);          /* no lost wakeup */
    CHECK(blocks > 0);             /* the consumer really blocked */
    CHECK(sent > 0);               /* ...and was woken through the pipe */
    CHECK(sent <= waits);          /* at most one wakeup per announcement */
    ringbuf_destroy(g_rb);
}

/* A consumer that never announces a wait must cost the producer no
 * syscalls at all; one announcement buys exactly one pipe byte. */
static void test_wakeup_quiet(void) {
    ringbuf_t *rb = ringbuf_create(64, 16, 0);
    CHECK(rb != NULL);

    for (uint64_t s = 0; s < WAKE_N; s++) {
        (void)ringbuf_producer_next(rb, 0);
        ringbuf_producer_commit(rb);
    }
    CHECK(ringbuf_total(rb) == WAKE_N);
    CHECK(ringbuf_notify_sent(rb) == 0);
    CHECK(!wake_take(rb));                        /* channel quiet */

    ringbuf_consumer_will_wait(rb);
    for (uint64_t s = 0; s < WAKE_N; s++) {
        (void)ringbuf_producer_next(rb, 0);
        ringbuf_producer_commit(rb);
    }
    CHECK(ringbuf_notify_sent(rb) == 1);
    CHECK(wake_take(rb));                         /* exactly one wakeup */
    CHECK(!wake_take(rb));

    ringbuf_drain_notify(rb);                     /* withdraws the flag */
    for (int i = 0; i < 1000; i++) {
        (void)ringbuf_producer_next(rb, 0);
        ringbuf_producer_commit(rb);
    }
    CHECK(ringbuf_notify_sent(rb) == 1);
    ringbuf_destroy(rb);
}

/* Take one wakeup from waiter slot id without blocking. */
static int wake_take_slot(ringbuf_t *rb, int id) {
#ifdef _WIN32
    return WaitForSingleObject(rb->waiters[id].event, 0) == WAIT_OBJECT_0;
#else
    char c;
    return read(ringbuf_waiter_fd(rb, id), &c, 1) == 1;
#endif
}

/* Two blocking consumers (headless printer + output thread): each gets
 * its own wakeup, a slot that did not announce gets none, and the
 * producer's per-commit check stays a single counter. */
static void test_waiters(void) {
    ringbuf_t *rb = ringbuf_create(64, 64, 0);
    CHECK(rb != NULL);
    int w1 = ringbuf_waiter_add(rb);
    CHECK(w1 == 1);
    CHECK(atomic_load(&rb->nwaiters) == 2);

    /* both announce: one commit wakes both, once each */
    ringbuf_consumer_will_wait(rb);
    ringbuf_waiter_will_wait(rb, w1);
    CHECK(atomic_load(&rb->nwaiting) == 2);
    push(rb, 1);
    CHECK(ringbuf_notify_sent(rb) == 2);
    CHECK(atomic_load(&rb->nwaiting) == 0);
    push(rb, 2);
    CHECK(ringbuf_notify_sent(rb) == 2);          /* claimed: no repeat */
    CHECK(wake_take(rb));
    CHECK(!wake_take(rb));
    CHECK(wake_take_slot(rb, w1));
    CHECK(!wake_take_slot(rb, w1));
    ringbuf_drain_notify(rb);
    ringbuf_waiter_drain(rb, w1);

    /* only the second slot announces */
    ringbuf_waiter_will_wait(rb, w1);
    ringbuf_waiter_will_wait(rb, w1);             /* repeat: counted once */
    CHECK(atomic_load(&rb->nwaiting) == 1);
    push(rb, 3);
    CHECK(ringbuf_notify_sent(rb) == 3);
    CHECK(!wake_take(rb));
    CHECK(wake_take_slot(rb, w1));
    ringbuf_waiter_drain(rb, w1);

    /* an announcement withdrawn by drain costs nothing */
    ringbuf_waiter_will_wait(rb, w1);
    ringbuf_waiter_drain(rb, w1);
    CHECK(atomic_load(&rb->nwaiting) == 0);
    push(rb, 4);
    CHECK(ringbuf_notify_sent(rb) == 3);
    CHECK(!wake_take_slot(rb, w1));

    /* slots are finite */
    CHECK(ringbuf_waiter_add(rb) == 2);
    CHECK(ringbuf_waiter_add(rb) == 3);
    CHECK(ringbuf_waiter_add(rb) == -1);
    ringbuf_destroy(rb);
}

/* ── consumer position / producer back-pressure ──────────────── */

static void test_backpressure_basic(void) {
    ringbuf_t *rb = ringbuf_create(8, 64, 0);
    CHECK(rb != NULL);

    /* no consumer attached: never blocks, even after wrapping */
    CHECK(ringbuf_consumer_seq(rb) == RINGBUF_NO_CONSUMER);
    for (int i = 0; i < 20; i++) {
        CHECK(ringbuf_producer_may_write(rb) == 1);
        push(rb, (uint8_t)i);
    }

    /* attach at 0: capacity 8 leaves 6 records of headroom (one slot of
     * slack for the record being overwritten) */
    ringbuf_destroy(rb);
    rb = ringbuf_create(8, 64, 0);
    ringbuf_consumer_attach(rb);
    CHECK(ringbuf_consumer_seq(rb) == 0);
    for (int i = 0; i < 6; i++) {
        CHECK(ringbuf_producer_may_write(rb) == 1);
        push(rb, (uint8_t)i);
    }
    CHECK(ringbuf_total(rb) == 6);
    CHECK(ringbuf_producer_may_write(rb) == 1);    /* 6 < 7 */
    push(rb, 6);
    CHECK(ringbuf_producer_may_write(rb) == 0);    /* 7 < 7 fails */

    /* every unread record is still intact */
    pkt_record_t rec;
    for (uint64_t s = 0; s < 7; s++) {
        CHECK(ringbuf_read_seq(rb, s, &rec, NULL) == 1);
        CHECK(rec.summary.length == s);
    }

    /* consumer advances: one record of room per published sequence */
    ringbuf_consumer_publish(rb, 1);
    CHECK(ringbuf_producer_may_write(rb) == 1);
    push(rb, 7);
    CHECK(ringbuf_producer_may_write(rb) == 0);
    ringbuf_consumer_publish(rb, 7);
    CHECK(ringbuf_producer_may_write(rb) == 1);
    /* a consumer that is fully caught up never blocks the producer */
    ringbuf_consumer_publish(rb, ringbuf_total(rb));
    CHECK(ringbuf_producer_may_write(rb) == 1);

    /* a second attached slot: the slowest one holds the producer */
    int w1 = ringbuf_waiter_add(rb);
    CHECK(w1 == 1);
    ringbuf_waiter_attach(rb, w1);              /* at 0: 8 unread already */
    CHECK(ringbuf_producer_may_write(rb) == 0);
    ringbuf_waiter_publish(rb, w1, ringbuf_total(rb) - 6);
    CHECK(ringbuf_producer_may_write(rb) == 1); /* 6 < 7 */
    ringbuf_waiter_publish(rb, w1, ringbuf_total(rb) - 7);
    CHECK(ringbuf_producer_may_write(rb) == 0);
    ringbuf_consumer_publish(rb, ringbuf_total(rb) - 7);
    ringbuf_waiter_publish(rb, w1, ringbuf_total(rb));
    CHECK(ringbuf_producer_may_write(rb) == 0); /* slot 0 now the slow one */
    ringbuf_destroy(rb);
}

/* A producer that honours may_write and a deliberately slow consumer that
 * publishes its position: every record must be read intact, in order,
 * with no misses — the property the offline replay relies on. */
#define BP_N   50000ULL
#define BP_CAP 32u

static void *bp_producer(void *arg) {
    ringbuf_t *rb = (ringbuf_t *)arg;
    for (uint64_t s = 0; s < BP_N; s++) {
        while (!ringbuf_producer_may_write(rb))
            sched_yield();
        pkt_record_t *r = ringbuf_producer_next(rb, 8);
        r->summary.length = (uint32_t)s;
        memset(r->raw_data, (int)(s & 0xff), 8);
        ringbuf_producer_commit(rb);
    }
    return NULL;
}

static void test_backpressure_threads(void) {
    ringbuf_t *rb = ringbuf_create(BP_CAP, 64, 0);
    CHECK(rb != NULL);
    ringbuf_consumer_attach(rb);

    pthread_t prod;
    pthread_create(&prod, NULL, bp_producer, rb);

    uint64_t next = 0, misses = 0, bad = 0, max_lag = 0;
    uint8_t data[64];
    while (next < BP_N) {
        uint64_t total = ringbuf_total(rb);
        if (total <= next) { sched_yield(); continue; }
        if (total - next > max_lag) max_lag = total - next;
        pkt_record_t rec;
        if (!ringbuf_read_seq(rb, next, &rec, data)) {
            misses++;
        } else if (rec.summary.length != (uint32_t)next ||
                   data[0] != (uint8_t)(next & 0xff)) {
            bad++;
        }
        next++;
        ringbuf_consumer_publish(rb, next);
        if (next % 97 == 0) wake_nap();    /* slow consumer: ring fills */
    }
    pthread_join(prod, NULL);

    CHECK(misses == 0);
    CHECK(bad == 0);
    CHECK(max_lag <= BP_CAP - 1);          /* producer never lapped us */
    CHECK(ringbuf_total(rb) == BP_N);
    ringbuf_destroy(rb);
}

int main(void) {
    test_basic();
    test_arena();
    test_stress();
    test_arena_stress();
    test_wakeup();
    test_wakeup_quiet();
    test_waiters();
    test_backpressure_basic();
    test_backpressure_threads();
    TEST_MAIN_END();
}
