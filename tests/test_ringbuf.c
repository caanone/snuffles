#include "ringbuf.h"
#include "test_common.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

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

int main(void) {
    test_basic();
    test_stress();
    TEST_MAIN_END();
}
