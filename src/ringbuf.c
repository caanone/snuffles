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
    atomic_store(&rb->consumer_waiting, 0);
    atomic_store(&rb->notify_sent, 0);

#ifdef _WIN32
    rb->notify_event = CreateEvent(NULL, FALSE, FALSE, NULL);
#else
    if (pipe(rb->notify_pipe) != 0) {
        free(rb->data_pool);
        free(rb->records);
        free(rb);
        return NULL;
    }
    /* make both ends non-blocking */
    fcntl(rb->notify_pipe[0], F_SETFL, O_NONBLOCK);
    fcntl(rb->notify_pipe[1], F_SETFL, O_NONBLOCK);
#endif

    return rb;
}

void ringbuf_destroy(ringbuf_t *rb) {
    if (!rb) return;
#ifdef _WIN32
    CloseHandle(rb->notify_event);
#else
    close(rb->notify_pipe[0]);
    close(rb->notify_pipe[1]);
#endif
    free(rb->slot_gen);
    free(rb->data_pool);
    free(rb->records);
    free(rb);
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

    /* Wake the consumer only if it announced it is about to block. Both
     * this load and the consumer's flag store are seq_cst, and so are the
     * commit_seq RMW above and the consumer's re-check load: in the
     * single total order either we see the flag (and deliver a wakeup)
     * or the consumer's re-check sees this commit (and doesn't block).
     * The exchange claims the wakeup so a burst costs one syscall. */
    if (atomic_load(&rb->consumer_waiting) &&
        atomic_exchange(&rb->consumer_waiting, 0)) {
        atomic_fetch_add_explicit(&rb->notify_sent, 1, memory_order_relaxed);
#ifdef _WIN32
        SetEvent(rb->notify_event);
#else
        char c = 1;
        (void)write(rb->notify_pipe[1], &c, 1);
#endif
    }
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

void ringbuf_clear(ringbuf_t *rb) {
    /* Never reset the producer counters (the capture thread may be between
     * its write_seq/commit_seq updates); just raise the visibility floor. */
    atomic_store(&rb->clear_seq, atomic_load(&rb->commit_seq));
}

int ringbuf_get_notify_fd(ringbuf_t *rb) {
#ifdef _WIN32
    (void)rb;
    return -1; /* use notify_event on Windows */
#else
    return rb->notify_pipe[0];
#endif
}

void ringbuf_consumer_will_wait(ringbuf_t *rb) {
    atomic_store(&rb->consumer_waiting, 1);
}

void ringbuf_drain_notify(ringbuf_t *rb) {
    /* Awake now: withdraw the announcement so commits that land while we
     * process this batch don't queue a stale wakeup. */
    if (atomic_load_explicit(&rb->consumer_waiting, memory_order_relaxed))
        atomic_store(&rb->consumer_waiting, 0);
#ifdef _WIN32
    (void)rb;
#else
    char buf[256];
    while (read(rb->notify_pipe[0], buf, sizeof(buf)) > 0)
        ;
#endif
}

uint64_t ringbuf_notify_sent(const ringbuf_t *rb) {
    return atomic_load_explicit(&rb->notify_sent, memory_order_relaxed);
}
