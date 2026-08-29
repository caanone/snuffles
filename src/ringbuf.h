#ifndef RINGBUF_H
#define RINGBUF_H

#include "snuffles.h"
#include <stdatomic.h>

/* Payload arena: one byte ring shared by all records instead of a
 * snaplen-sized slot per record. The producer bump-allocates each
 * packet's bytes (never split across the end: a packet that does not fit
 * in the tail skips to offset 0). Positions are 64-bit and never wrap;
 * the byte at position p lives at arena[p % arena_size], and a payload
 * starting at position P is still intact as long as the producer's
 * allocation cursor has not passed P + arena_size — which is what
 * readers check after copying. The default arena is
 * capacity x min(snaplen, RINGBUF_ARENA_SLOT) bytes. */
#define RINGBUF_ARENA_SLOT 2048u

typedef struct ringbuf {
    pkt_record_t   *records;
    uint8_t        *arena;
    uint64_t        arena_size;
    uint64_t        arena_off;      /* producer only: next free offset */
    /* Allocation cursor (position, not offset). Advanced before the
     * producer writes the bytes it just claimed, so a reader that loads
     * it after copying can tell whether its copy could have been
     * overwritten. */
    atomic_uint_fast64_t arena_pos;
    /* Per-slot seqlock generation: odd while the producer is writing the
     * slot, even when it is stable. Readers copy out and retry on change. */
    atomic_uint_fast64_t *slot_gen;
    uint32_t        capacity;
    uint32_t        snaplen;        /* max payload bytes per record */
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
    /* Position of the (single) streaming consumer: the next sequence it
     * will read, or RINGBUF_NO_CONSUMER when none is attached. Only used
     * for back-pressure by producers that can afford to wait (offline
     * replay); live capture never blocks on it. */
    atomic_uint_fast64_t consumer_seq;
#ifdef _WIN32
    HANDLE          notify_event;
#else
    int             notify_pipe[2];
#endif
} ringbuf_t;

/* arena_bytes 0 selects the default (capacity x min(snaplen, 2048)); any
 * value is raised to at least snaplen so one full packet always fits. */
ringbuf_t          *ringbuf_create(uint32_t capacity, uint32_t snaplen,
                                   uint64_t arena_bytes);
void                ringbuf_destroy(ringbuf_t *rb);

/* Claim the next slot and wanted bytes of payload space (granted =
 * min(wanted, snaplen)). On return rec->raw_data points into the arena
 * and rec->raw_len is the granted length: the caller copies that many
 * bytes there (it may lower raw_len, never raise it), fills the summary
 * and commits. Between next and commit the slot and its bytes belong to
 * the caller. */
pkt_record_t       *ringbuf_producer_next(ringbuf_t *rb, uint32_t wanted);
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
 * A record whose payload the arena has since reclaimed (large frames
 * push older bytes out before their slots are reused) comes back with
 * raw_len 0 and an intact summary; a payload is never returned torn.
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

/* Consumer-position hook (offline replay back-pressure).
 *   ringbuf_consumer_attach   registers a streaming consumer at sequence 0;
 *                             call it before the producer starts so the
 *                             producer can never lap the consumer's start.
 *   ringbuf_consumer_publish  the consumer stores the next sequence it will
 *                             read (release: its copies of earlier records
 *                             are complete before the producer may reuse
 *                             their slots).
 *   ringbuf_producer_may_write  1 if taking the next slot cannot overwrite a
 *                             record the attached consumer has not read yet
 *                             (commit_seq - consumer_seq < capacity - 1: one
 *                             slot of slack because the record at
 *                             commit_seq - capacity is still visible while
 *                             it is being overwritten); always 1 without an
 *                             attached consumer. A producer that must not
 *                             lose records waits until this returns 1. */
#define RINGBUF_NO_CONSUMER UINT64_MAX
void                ringbuf_consumer_attach(ringbuf_t *rb);
void                ringbuf_consumer_publish(ringbuf_t *rb, uint64_t next_seq);
uint64_t            ringbuf_consumer_seq(const ringbuf_t *rb);
int                 ringbuf_producer_may_write(const ringbuf_t *rb);

#endif /* RINGBUF_H */
