#ifndef RINGBUF_H
#define RINGBUF_H

#include "snuffles.h"
#include <stdatomic.h>

/* Consumers that block on the ring each own a waiter slot: a wake-up
 * channel (pipe on POSIX, auto-reset event on Windows), a waiting flag
 * and, for offline back-pressure, the position they will read next.
 * Slot 0 is the display/headless consumer and exists from creation; an
 * output thread takes another with ringbuf_waiter_add(). */
#define RINGBUF_MAX_WAITERS 4

typedef struct {
    atomic_int           waiting;   /* set right before the owner blocks */
    atomic_uint_fast64_t next_seq;  /* position hook, RINGBUF_NO_CONSUMER
                                       when the slot is not attached */
#ifdef _WIN32
    HANDLE               event;
#else
    int                  pipe[2];
#endif
} ringbuf_waiter_t;

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
    /* Wakeup handshake. A consumer sets its slot's waiting flag right
     * before it blocks (ringbuf_waiter_will_wait); nwaiting counts the
     * flags set. The producer looks at the slots only when nwaiting is
     * nonzero, clears the flags it finds and touches those pipes/events,
     * so one commit per idle period pays for a syscall per sleeping
     * consumer instead of every commit, and a commit with nobody waiting
     * costs one atomic load whatever the number of slots. */
    ringbuf_waiter_t waiters[RINGBUF_MAX_WAITERS];
    atomic_int      nwaiters;           /* slots in use (>= 1) */
    atomic_int      nwaiting;           /* slots with waiting set */
    atomic_uint_fast64_t notify_sent;   /* wakeups actually delivered */
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

/* Consumer wakeup protocol (no lost wakeups), for waiter slot id:
 *   if (ringbuf_total(rb) == last_seen) {      // nothing pending
 *       ringbuf_waiter_will_wait(rb, id);
 *       if (ringbuf_total(rb) == last_seen)    // re-check after announcing
 *           select()/WaitForSingleObject() on the slot's fd/event;
 *   }
 *   ringbuf_waiter_drain(rb, id);
 * The re-check catches a commit that raced the announcement; a commit
 * after the announcement finds the flag set and delivers the wakeup.
 * The ringbuf_consumer_* forms below are the same calls for slot 0. */
int                 ringbuf_waiter_add(ringbuf_t *rb);   /* new slot id, -1 if full */
int                 ringbuf_waiter_fd(ringbuf_t *rb, int id);   /* -1 on Windows */
void                ringbuf_waiter_will_wait(ringbuf_t *rb, int id);
void                ringbuf_waiter_drain(ringbuf_t *rb, int id);

void                ringbuf_consumer_will_wait(ringbuf_t *rb);
void                ringbuf_drain_notify(ringbuf_t *rb);
int                 ringbuf_get_notify_fd(ringbuf_t *rb);
uint64_t            ringbuf_notify_sent(const ringbuf_t *rb);

/* Consumer-position hook (offline replay back-pressure).
 *   ringbuf_waiter_attach     registers slot id as a streaming consumer at
 *                             sequence 0; call it before the producer
 *                             starts so it can never lap the consumer's
 *                             start.
 *   ringbuf_waiter_publish    the consumer stores the next sequence it will
 *                             read (release: its copies of earlier records
 *                             are complete before the producer may reuse
 *                             their slots).
 *   ringbuf_producer_may_write  1 if taking the next slot cannot overwrite a
 *                             record an attached consumer has not read yet
 *                             (commit_seq - next_seq < capacity - 1 for the
 *                             slowest one: one slot of slack because the
 *                             record at commit_seq - capacity is still
 *                             visible while it is being overwritten); always
 *                             1 without an attached consumer. A producer
 *                             that must not lose records waits until this
 *                             returns 1.
 * The ringbuf_consumer_* forms are the same calls for slot 0. */
#define RINGBUF_NO_CONSUMER UINT64_MAX
void                ringbuf_waiter_attach(ringbuf_t *rb, int id);
void                ringbuf_waiter_publish(ringbuf_t *rb, int id, uint64_t next_seq);
void                ringbuf_consumer_attach(ringbuf_t *rb);
void                ringbuf_consumer_publish(ringbuf_t *rb, uint64_t next_seq);
uint64_t            ringbuf_consumer_seq(const ringbuf_t *rb);
int                 ringbuf_producer_may_write(const ringbuf_t *rb);

#endif /* RINGBUF_H */
