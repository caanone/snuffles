#include "ringbuf.h"
#include "test_common.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/select.h>

/* ── single-thread semantics ─────────────────────────────────── */

static void push(ringbuf_t *rb, uint8_t fill) {
    pkt_record_t *r = ringbuf_producer_next(rb);
    memset(r->raw_data, fill, 32);
    r->raw_len = 32;
    r->summary.length = fill;
    ringbuf_producer_commit(rb);
}

static void test_basic(void) {
    ringbuf_t *rb = ringbuf_create(8, 64);
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

/* ── concurrent seqlock stress ───────────────────────────────── */

#define STRESS_N 1000000ULL

static ringbuf_t *g_rb;

static void *producer(void *arg) {
    (void)arg;
    for (uint64_t s = 0; s < STRESS_N; s++) {
        pkt_record_t *r = ringbuf_producer_next(g_rb);
        uint8_t v = (uint8_t)(s ^ (s >> 8));
        memset(r->raw_data, v, 64);
        r->raw_len = 64;
        r->summary.length = (uint32_t)s;
        r->summary.src_port = v;
        ringbuf_producer_commit(g_rb);
    }
    return NULL;
}

static void test_stress(void) {
    g_rb = ringbuf_create(64, 64);
    CHECK(g_rb != NULL);

    pthread_t t;
    pthread_create(&t, NULL, producer, NULL);

    uint64_t torn = 0, ok = 0;
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
            for (int i = 0; i < 64; i++)
                if (data[i] != v) { torn++; break; }
        }
    }
    pthread_join(t, NULL);

    CHECK(torn == 0);
    CHECK(ok > 1000);   /* the reader actually exercised the seqlock */
    ringbuf_destroy(g_rb);
}

/* ── wakeup handshake ────────────────────────────────────────── */

#define WAKE_N     100000ULL
#define WAKE_PAUSE 10          /* producer naps this many times */

static void *wake_producer(void *arg) {
    (void)arg;
    for (uint64_t s = 0; s < WAKE_N; s++) {
        /* Nap now and then so the consumer drains the ring and actually
         * blocks: those are the wakeups that must not be lost. */
        if (s && s % (WAKE_N / WAKE_PAUSE) == 0) {
            struct timespec nap = { 0, 2000000 };   /* 2 ms */
            nanosleep(&nap, NULL);
        }
        pkt_record_t *r = ringbuf_producer_next(g_rb);
        r->summary.length = (uint32_t)s;
        r->raw_len = 0;
        ringbuf_producer_commit(g_rb);
    }
    return NULL;
}

/* Consumer runs the documented protocol: announce, re-check, block on the
 * pipe. Every record it reads must be intact, every record it misses must
 * have been lapped, and no wait may hit the (generous) timeout: a timeout
 * means a commit landed while we were blocked and nobody woke us. */
static void test_wakeup(void) {
    g_rb = ringbuf_create(1024, 16);
    CHECK(g_rb != NULL);
    int fd = ringbuf_get_notify_fd(g_rb);
    CHECK(fd >= 0);

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
                fd_set fds;
                FD_ZERO(&fds);
                FD_SET(fd, &fds);
                struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
                blocks++;
                if (select(fd + 1, &fds, NULL, NULL, &tv) == 0) timeouts++;
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
    ringbuf_t *rb = ringbuf_create(64, 16);
    CHECK(rb != NULL);
    int fd = ringbuf_get_notify_fd(rb);
    char buf[16];

    for (uint64_t s = 0; s < WAKE_N; s++) {
        pkt_record_t *r = ringbuf_producer_next(rb);
        r->raw_len = 0;
        ringbuf_producer_commit(rb);
    }
    CHECK(ringbuf_total(rb) == WAKE_N);
    CHECK(ringbuf_notify_sent(rb) == 0);
    CHECK(read(fd, buf, sizeof(buf)) < 0);        /* pipe empty (EAGAIN) */

    ringbuf_consumer_will_wait(rb);
    for (uint64_t s = 0; s < WAKE_N; s++) {
        pkt_record_t *r = ringbuf_producer_next(rb);
        r->raw_len = 0;
        ringbuf_producer_commit(rb);
    }
    CHECK(ringbuf_notify_sent(rb) == 1);
    CHECK(read(fd, buf, sizeof(buf)) == 1);       /* exactly one byte */
    CHECK(read(fd, buf, sizeof(buf)) < 0);

    ringbuf_drain_notify(rb);                     /* withdraws the flag */
    for (int i = 0; i < 1000; i++) {
        pkt_record_t *r = ringbuf_producer_next(rb);
        r->raw_len = 0;
        ringbuf_producer_commit(rb);
    }
    CHECK(ringbuf_notify_sent(rb) == 1);
    ringbuf_destroy(rb);
}

int main(void) {
    test_basic();
    test_stress();
    test_wakeup();
    test_wakeup_quiet();
    TEST_MAIN_END();
}
