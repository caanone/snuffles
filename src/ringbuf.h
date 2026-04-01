#ifndef RINGBUF_H
#define RINGBUF_H

#include "snuffles.h"
#include <stdatomic.h>

typedef struct ringbuf {
    pkt_record_t   *records;
    uint8_t        *data_pool;
    uint32_t        capacity;
    uint32_t        snaplen;
    atomic_uint_fast64_t write_seq;
    atomic_uint_fast64_t commit_seq;
    ns_mutex_t      mtx;
    ns_cond_t       cond;
#ifdef _WIN32
    HANDLE          notify_event;
#else
    int             notify_pipe[2];
#endif
} ringbuf_t;

ringbuf_t          *ringbuf_create(uint32_t capacity, uint32_t snaplen);
void                ringbuf_destroy(ringbuf_t *rb);

pkt_record_t       *ringbuf_producer_next(ringbuf_t *rb);
void                ringbuf_producer_commit(ringbuf_t *rb);

uint32_t            ringbuf_count(const ringbuf_t *rb);
uint64_t            ringbuf_total(const ringbuf_t *rb);
const pkt_record_t *ringbuf_peek(ringbuf_t *rb, uint32_t idx);
void                ringbuf_clear(ringbuf_t *rb);
int                 ringbuf_get_notify_fd(ringbuf_t *rb);
void                ringbuf_drain_notify(ringbuf_t *rb);

#endif /* RINGBUF_H */
