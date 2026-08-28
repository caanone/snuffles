#ifndef RINGBUF_H
#define RINGBUF_H

#include "snuffles.h"
#include <stdatomic.h>

typedef struct ringbuf {
    pkt_record_t   *records;
    uint8_t        *data_pool;
    /* Per-slot seqlock generation: odd while the producer is writing the
     * slot, even when it is stable. Readers copy out and retry on change. */
    atomic_uint_fast64_t *slot_gen;
    uint32_t        capacity;
    uint32_t        snaplen;
    atomic_uint_fast64_t write_seq;
    atomic_uint_fast64_t commit_seq;
    /* Clear floor: consumers treat sequences below this as gone. The
     * producer counters are never reset, so clearing cannot race commits. */
    atomic_uint_fast64_t clear_seq;
    /* Wakeup handshake. A consumer sets consumer_waiting right before it
     * blocks (ringbuf_consumer_will_wait); the producer only touches the
     * pipe/event when it finds the flag set, and clears it so one commit
     * per idle period pays for a syscall instead of every commit. */
    atomic_int      consumer_waiting;
    atomic_uint_fast64_t notify_sent;   /* wakeups actually delivered */
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
uint64_t            ringbuf_oldest(const ringbuf_t *rb);

/* Copy the record with absolute sequence number seq into *out. Returns 0
 * if seq is not (or no longer) in the ring — i.e. the producer has lapped
 * the caller, or seq is not committed yet — or the slot changed underneath
 * the copy. Streaming consumers must use this rather than a display index:
 * an index is relative to a floor that moves while they iterate. */
int                 ringbuf_read_seq(ringbuf_t *rb, uint64_t seq,
                                     pkt_record_t *out, uint8_t *data);

/* Copy the record at display index idx (0 = oldest visible) into *out.
 * If data is non-NULL it must hold at least snaplen bytes; the packet
 * bytes are copied there and out->raw_data points at it. With data NULL
 * only the summary is copied and out->raw_data is NULL.
 * Returns 1 on success, 0 if the slot is gone or was overwritten mid-read. */
int                 ringbuf_read(ringbuf_t *rb, uint32_t idx,
                                 pkt_record_t *out, uint8_t *data);
void                ringbuf_clear(ringbuf_t *rb);
int                 ringbuf_get_notify_fd(ringbuf_t *rb);

/* Consumer wakeup protocol (no lost wakeups):
 *   if (ringbuf_total(rb) == last_seen) {      // nothing pending
 *       ringbuf_consumer_will_wait(rb);
 *       if (ringbuf_total(rb) == last_seen)    // re-check after announcing
 *           select()/WaitForSingleObject() on the notify fd/event;
 *   }
 *   ringbuf_drain_notify(rb);
 * The re-check catches a commit that raced the announcement; a commit
 * after the announcement finds the flag set and delivers the wakeup. */
void                ringbuf_consumer_will_wait(ringbuf_t *rb);
void                ringbuf_drain_notify(ringbuf_t *rb);
uint64_t            ringbuf_notify_sent(const ringbuf_t *rb);

#endif /* RINGBUF_H */
