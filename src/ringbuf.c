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
    ns_mutex_init(&rb->mtx);
    ns_cond_init(&rb->cond);

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
    ns_mutex_destroy(&rb->mtx);
    ns_cond_destroy(&rb->cond);
    free(rb->slot_gen);
    free(rb->data_pool);
    free(rb->records);
    free(rb);
}

pkt_record_t *ringbuf_producer_next(ringbuf_t *rb) {
    uint64_t seq = atomic_load(&rb->write_seq);
    uint32_t idx = (uint32_t)(seq % rb->capacity);
    atomic_fetch_add(&rb->slot_gen[idx], 1);   /* even -> odd: write begins */
    return &rb->records[idx];
}

void ringbuf_producer_commit(ringbuf_t *rb) {
    uint64_t seq = atomic_load(&rb->write_seq);
    uint32_t idx = (uint32_t)(seq % rb->capacity);
    rb->records[idx].seq_num = seq;
    atomic_fetch_add(&rb->slot_gen[idx], 1);   /* odd -> even: slot stable */
    atomic_store(&rb->write_seq, seq + 1);
    atomic_fetch_add(&rb->commit_seq, 1);

    /* wake consumer */
    ns_mutex_lock(&rb->mtx);
    ns_cond_signal(&rb->cond);
    ns_mutex_unlock(&rb->mtx);

#ifdef _WIN32
    SetEvent(rb->notify_event);
#else
    char c = 1;
    (void)write(rb->notify_pipe[1], &c, 1);
#endif
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

void ringbuf_drain_notify(ringbuf_t *rb) {
#ifdef _WIN32
    (void)rb;
#else
    char buf[256];
    while (read(rb->notify_pipe[0], buf, sizeof(buf)) > 0)
        ;
#endif
}
