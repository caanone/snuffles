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

    /* point each record's raw_data into the flat pool */
    for (uint32_t i = 0; i < capacity; i++) {
        rb->records[i].raw_data = rb->data_pool + (size_t)i * snaplen;
    }

    atomic_store(&rb->write_seq, 0);
    atomic_store(&rb->commit_seq, 0);
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
    free(rb->data_pool);
    free(rb->records);
    free(rb);
}

pkt_record_t *ringbuf_producer_next(ringbuf_t *rb) {
    uint64_t seq = atomic_load(&rb->write_seq);
    uint32_t idx = (uint32_t)(seq % rb->capacity);
    return &rb->records[idx];
}

void ringbuf_producer_commit(ringbuf_t *rb) {
    uint64_t seq = atomic_fetch_add(&rb->write_seq, 1);
    rb->records[seq % rb->capacity].seq_num = seq;
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

uint32_t ringbuf_count(const ringbuf_t *rb) {
    uint64_t total = atomic_load(&rb->commit_seq);
    if (total > rb->capacity) return rb->capacity;
    return (uint32_t)total;
}

uint64_t ringbuf_total(const ringbuf_t *rb) {
    return atomic_load(&rb->commit_seq);
}

const pkt_record_t *ringbuf_peek(ringbuf_t *rb, uint32_t idx) {
    uint64_t total   = atomic_load(&rb->commit_seq);
    uint32_t count   = ringbuf_count(rb);

    if (idx >= count) return NULL;

    uint64_t oldest_seq;
    if (total <= rb->capacity) {
        oldest_seq = 0;
    } else {
        oldest_seq = total - rb->capacity;
    }

    uint64_t target_seq = oldest_seq + idx;
    uint32_t slot = (uint32_t)(target_seq % rb->capacity);
    return &rb->records[slot];
}

void ringbuf_clear(ringbuf_t *rb) {
    atomic_store(&rb->write_seq, 0);
    atomic_store(&rb->commit_seq, 0);
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
