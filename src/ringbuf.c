#include "ringbuf.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifndef _WIN32
  #include <unistd.h>
  #include <fcntl.h>
#endif

ringbuf_t *ringbuf_create(uint32_t capacity, uint32_t snaplen) {
    ringbuf_t *rb = calloc(1, sizeof(ringbuf_t));
    if (!rb) return NULL;

    rb->capacity = capacity;
    rb->snaplen  = snaplen;

    rb->records = calloc(capacity, sizeof(pkt_record_t));
    if (!rb->records) { free(rb); return NULL; }

    rb->data_pool = calloc(capacity, (size_t)snaplen);
    if (!rb->data_pool) { free(rb->records); free(rb); return NULL; }

    rb->slot_gen = calloc(capacity, sizeof(atomic_uint_fast64_t));
    if (!rb->slot_gen) {
        free(rb->data_pool); free(rb->records); free(rb);
        return NULL;
    }

    /* point each record's raw_data into the flat pool */
    for (uint32_t i = 0; i < capacity; i++) {
        rb->records[i].raw_data = rb->data_pool + (size_t)i * snaplen;
    }

    atomic_store(&rb->write_seq, 0);
    atomic_store(&rb->commit_seq, 0);
    atomic_store(&rb->clear_seq, 0);
    atomic_store(&rb->nwaiters, 0);
    atomic_store(&rb->nwaiting, 0);
    atomic_store(&rb->notify_sent, 0);
    for (int i = 0; i < RINGBUF_MAX_WAITERS; i++) {
        atomic_store(&rb->waiters[i].waiting, 0);
        atomic_store(&rb->waiters[i].next_seq, RINGBUF_NO_CONSUMER);
#ifdef _WIN32
        rb->waiters[i].event = NULL;
#else
        rb->waiters[i].pipe[0] = rb->waiters[i].pipe[1] = -1;
#endif
    }

    /* slot 0: the display / headless consumer */
    if (ringbuf_waiter_add(rb) != 0) {
        free(rb->slot_gen);
        free(rb->data_pool);
        free(rb->records);
        free(rb);
        return NULL;
    }

    return rb;
}

void ringbuf_destroy(ringbuf_t *rb) {
    if (!rb) return;
    int n = atomic_load(&rb->nwaiters);
    for (int i = 0; i < n; i++) {
#ifdef _WIN32
        if (rb->waiters[i].event) CloseHandle(rb->waiters[i].event);
#else
        close(rb->waiters[i].pipe[0]);
        close(rb->waiters[i].pipe[1]);
#endif
    }
    free(rb->slot_gen);
    free(rb->data_pool);
    free(rb->records);
    free(rb);
}

/* Cold path of commit: nwaiting is nonzero. The exchange claims each
 * wakeup so a burst costs one syscall per sleeping consumer. */
static void ringbuf_wake_waiters(ringbuf_t *rb) {
    int n = atomic_load(&rb->nwaiters);
    for (int i = 0; i < n; i++) {
        ringbuf_waiter_t *w = &rb->waiters[i];
        if (!atomic_load(&w->waiting) || !atomic_exchange(&w->waiting, 0))
            continue;
        atomic_fetch_sub(&rb->nwaiting, 1);
        atomic_fetch_add_explicit(&rb->notify_sent, 1, memory_order_relaxed);
#ifdef _WIN32
        SetEvent(w->event);
#else
        char c = 1;
        (void)write(w->pipe[1], &c, 1);
#endif
    }
}

pkt_record_t *ringbuf_producer_next(ringbuf_t *rb) {
    uint64_t seq = atomic_load(&rb->write_seq);
    uint32_t idx = (uint32_t)(seq % rb->capacity);
    atomic_fetch_add(&rb->slot_gen[idx], 1);   /* even -> odd: write begins */
    /* The RMW's store half doesn't order the caller's later plain data
     * stores after it on weakly-ordered CPUs (arm64): a lapped reader
     * could see new data before the odd generation and validate a torn
     * copy. Fence so the odd mark is visible before any data write. */
    atomic_thread_fence(memory_order_release);
    return &rb->records[idx];
}

void ringbuf_producer_commit(ringbuf_t *rb) {
    uint64_t seq = atomic_load(&rb->write_seq);
    uint32_t idx = (uint32_t)(seq % rb->capacity);
    rb->records[idx].seq_num = seq;
    atomic_fetch_add(&rb->slot_gen[idx], 1);   /* odd -> even: slot stable */
    atomic_store(&rb->write_seq, seq + 1);
    atomic_fetch_add(&rb->commit_seq, 1);

    /* Wake the consumers that announced they are about to block. Both
     * this load and a consumer's flag/count stores are seq_cst, and so are
     * the commit_seq RMW above and the consumer's re-check load: in the
     * single total order either we see the count (and deliver a wakeup)
     * or the consumer's re-check sees this commit (and doesn't block). */
    if (atomic_load(&rb->nwaiting))
        ringbuf_wake_waiters(rb);
}

uint64_t ringbuf_oldest(const ringbuf_t *rb) {
    uint64_t total = atomic_load(&rb->commit_seq);
    uint64_t clear = atomic_load(&rb->clear_seq);
    uint64_t oldest = (total > rb->capacity) ? total - rb->capacity : 0;
    return (clear > oldest) ? clear : oldest;
}

uint32_t ringbuf_count(const ringbuf_t *rb) {
    uint64_t total = atomic_load(&rb->commit_seq);
    return (uint32_t)(total - ringbuf_oldest(rb));
}

uint64_t ringbuf_total(const ringbuf_t *rb) {
    return atomic_load(&rb->commit_seq);
}

int ringbuf_read(ringbuf_t *rb, uint32_t idx, pkt_record_t *out, uint8_t *data) {
    for (int attempt = 0; attempt < 4; attempt++) {
        uint64_t total  = atomic_load(&rb->commit_seq);
        uint64_t oldest = ringbuf_oldest(rb);
        if (idx >= (uint32_t)(total - oldest)) return 0;

        uint64_t target = oldest + idx;
        uint32_t slot   = (uint32_t)(target % rb->capacity);

        uint64_t g1 = atomic_load(&rb->slot_gen[slot]);
        if (g1 & 1) continue;   /* producer mid-write, retry */

        *out = rb->records[slot];
        uint32_t rl = out->raw_len;
        if (rl > rb->snaplen) rl = rb->snaplen;   /* torn read paranoia */
        out->raw_len = rl;
        if (data) {
            memcpy(data, rb->data_pool + (size_t)slot * rb->snaplen, rl);
            out->raw_data = data;
        } else {
            out->raw_data = NULL;
        }

        /* The data copy above uses plain loads; on weakly-ordered CPUs
         * (arm64) they may be satisfied after the recheck load below,
         * validating a torn read. Fence so the copy completes first. */
        atomic_thread_fence(memory_order_acquire);
        if (atomic_load(&rb->slot_gen[slot]) == g1 && out->seq_num == target)
            return 1;
    }
    return 0;
}

int ringbuf_read_seq(ringbuf_t *rb, uint64_t seq, pkt_record_t *out,
                     uint8_t *data) {
    for (int attempt = 0; attempt < 4; attempt++) {
        uint64_t total  = atomic_load(&rb->commit_seq);
        uint64_t oldest = ringbuf_oldest(rb);
        if (seq < oldest || seq >= total) return 0;

        uint32_t slot = (uint32_t)(seq % rb->capacity);

        uint64_t g1 = atomic_load(&rb->slot_gen[slot]);
        if (g1 & 1) continue;   /* producer mid-write, retry */

        *out = rb->records[slot];
        uint32_t rl = out->raw_len;
        if (rl > rb->snaplen) rl = rb->snaplen;   /* torn read paranoia */
        out->raw_len = rl;
        if (data) {
            memcpy(data, rb->data_pool + (size_t)slot * rb->snaplen, rl);
            out->raw_data = data;
        } else {
            out->raw_data = NULL;
        }

        atomic_thread_fence(memory_order_acquire);
        if (atomic_load(&rb->slot_gen[slot]) == g1 && out->seq_num == seq)
            return 1;
    }
    return 0;
}

void ringbuf_clear(ringbuf_t *rb) {
    /* Never reset the producer counters (the capture thread may be between
     * its write_seq/commit_seq updates); just raise the visibility floor. */
    atomic_store(&rb->clear_seq, atomic_load(&rb->commit_seq));
}

/* ── waiter slots ────────────────────────────────────────────── */

int ringbuf_waiter_add(ringbuf_t *rb) {
    int id = atomic_load(&rb->nwaiters);
    if (id >= RINGBUF_MAX_WAITERS) return -1;
    ringbuf_waiter_t *w = &rb->waiters[id];
#ifdef _WIN32
    w->event = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!w->event) return -1;
#else
    if (pipe(w->pipe) != 0) return -1;
    /* make both ends non-blocking */
    fcntl(w->pipe[0], F_SETFL, O_NONBLOCK);
    fcntl(w->pipe[1], F_SETFL, O_NONBLOCK);
#endif
    /* The producer scans slots only after a will_wait on one of them
     * (seq_cst), so the channel above is visible to it by then. */
    atomic_store(&rb->nwaiters, id + 1);
    return id;
}

int ringbuf_waiter_fd(ringbuf_t *rb, int id) {
#ifdef _WIN32
    (void)rb; (void)id;
    return -1; /* use waiters[id].event on Windows */
#else
    return rb->waiters[id].pipe[0];
#endif
}

void ringbuf_waiter_will_wait(ringbuf_t *rb, int id) {
    /* Count first, then set the flag: the producer decrements only after
     * it claimed a set flag, so the count never runs below the flags set.
     * An announcement that was still standing is not counted twice. */
    atomic_fetch_add(&rb->nwaiting, 1);
    if (atomic_exchange(&rb->waiters[id].waiting, 1))
        atomic_fetch_sub(&rb->nwaiting, 1);
}

void ringbuf_waiter_drain(ringbuf_t *rb, int id) {
    ringbuf_waiter_t *w = &rb->waiters[id];
    /* Awake now: withdraw the announcement so commits that land while we
     * process this batch don't queue a stale wakeup. */
    if (atomic_load_explicit(&w->waiting, memory_order_relaxed) &&
        atomic_exchange(&w->waiting, 0))
        atomic_fetch_sub(&rb->nwaiting, 1);
#ifdef _WIN32
    (void)rb;
#else
    char buf[256];
    while (read(w->pipe[0], buf, sizeof(buf)) > 0)
        ;
#endif
}

int ringbuf_get_notify_fd(ringbuf_t *rb) {
    return ringbuf_waiter_fd(rb, 0);
}

void ringbuf_consumer_will_wait(ringbuf_t *rb) {
    ringbuf_waiter_will_wait(rb, 0);
}

void ringbuf_drain_notify(ringbuf_t *rb) {
    ringbuf_waiter_drain(rb, 0);
}

uint64_t ringbuf_notify_sent(const ringbuf_t *rb) {
    return atomic_load_explicit(&rb->notify_sent, memory_order_relaxed);
}

/* ── consumer position (offline back-pressure) ───────────────── */

void ringbuf_waiter_attach(ringbuf_t *rb, int id) {
    atomic_store(&rb->waiters[id].next_seq, 0);
}

void ringbuf_waiter_publish(ringbuf_t *rb, int id, uint64_t next_seq) {
    atomic_store_explicit(&rb->waiters[id].next_seq, next_seq,
                          memory_order_release);
}

void ringbuf_consumer_attach(ringbuf_t *rb) {
    ringbuf_waiter_attach(rb, 0);
}

void ringbuf_consumer_publish(ringbuf_t *rb, uint64_t next_seq) {
    ringbuf_waiter_publish(rb, 0, next_seq);
}

uint64_t ringbuf_consumer_seq(const ringbuf_t *rb) {
    return atomic_load_explicit(&rb->waiters[0].next_seq, memory_order_acquire);
}

int ringbuf_producer_may_write(const ringbuf_t *rb) {
    uint64_t total = atomic_load_explicit(&rb->commit_seq, memory_order_relaxed);
    int n = atomic_load(&rb->nwaiters);
    for (int i = 0; i < n; i++) {
        uint64_t c = atomic_load_explicit(&rb->waiters[i].next_seq,
                                          memory_order_acquire);
        if (c == RINGBUF_NO_CONSUMER) continue;
        /* c can run ahead of total only transiently (consumer published a
         * sequence it expects next): no back-pressure in that case. */
        if (c >= total) continue;
        if ((total - c) >= (uint64_t)rb->capacity - 1) return 0;
    }
    return 1;
}
