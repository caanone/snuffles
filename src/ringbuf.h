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
 * capacity x min(snaplen, RINGBUF_ARENA_SLOT) bytes. With several
 * producers the arena is split into one equal slice per producer and
 * both the position and that check are per slice. */
#define RINGBUF_ARENA_SLOT 2048u

/* Producers. One capture worker owns one producer id; -j N gives N of
 * them (see capture.h). Each producer bump-allocates from its own slice
 * of the arena, so the only counter producers share is the ring's
 * reservation cursor. */
#define RINGBUF_MAX_PRODUCERS 16

/* Consumers that block on the ring each own a waiter slot: a wake-up
 * channel (pipe on POSIX, auto-reset event on Windows), a waiting flag
 * and, for offline back-pressure, the position they will read next.
 * Slot 0 is the display/headless consumer and exists from creation; each
 * output worker slot takes another with ringbuf_waiter_add(): up to
 * OUTPUT_MAX_THREADS syslog threads plus one -w stream worker. */
#define RINGBUF_MAX_WAITERS 18

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

/* Per-producer state. The arena is split into one equal slice per
 * producer: allocation is then thread-local (no shared cursor to
 * contend on) and a record only has to say which slice it points into.
 * Positions are slice-relative and never wrap; the byte at position p of
 * producer i lives at arena[arena_base + p % arena_len]. */
typedef struct {
    /* Allocation cursor (position, not offset). Advanced before the
     * producer writes the bytes it just claimed, so a reader that loads
     * it after copying can tell whether its copy could have been
     * overwritten. */
    atomic_uint_fast64_t arena_pos;
    uint64_t        arena_base;     /* slice start, byte offset into arena */
    uint64_t        arena_len;      /* slice size */
    uint64_t        arena_off;      /* producer only: next free slice offset */
    uint64_t        seq;            /* producer only: reservation held now */
    /* one producer per cache line: arena_pos is read by every consumer */
    char            pad[64 > 5 * sizeof(uint64_t)
                        ? 64 - 5 * sizeof(uint64_t) : 8];
} ringbuf_prod_t;

typedef struct ringbuf {
    pkt_record_t   *records;
    uint8_t        *arena;
    uint64_t        arena_size;
    /* Per-slot seqlock generation, seq * 2 + (1 while being written).
     * Readers copy out and retry on change. The generation carries the
     * sequence rather than counting writes so that a reader can tell a
     * stable slot from one two producers are lapping onto at once: the
     * value is unique per record, so "unchanged across the copy" implies
     * "nobody touched the slot", whatever the number of producers. */
    atomic_uint_fast64_t *slot_gen;
    ringbuf_prod_t *prods;
    void           *prods_raw;      /* prods before cache-line alignment */
    int             nprod;          /* producers (1 = single-producer) */
    int             mp;             /* nprod > 1: shared cursors are atomic */
    uint32_t        capacity;
    uint32_t        snaplen;        /* max payload bytes per record */
    /* write_seq reserves slots (a plain counter with one producer, a
     * fetch-add cursor with several); commit_seq is the publication
     * point and only ever advances over records whose slots are marked
     * published, so a reader never sees a hole. */
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

/* arena_bytes 0 selects the default (capacity x min(snaplen, 2048)); any
 * value is raised to at least nproducers x snaplen so one full packet
 * always fits in every producer's slice. */
ringbuf_t          *ringbuf_create(uint32_t capacity, uint32_t snaplen,
                                   uint64_t arena_bytes);
ringbuf_t          *ringbuf_create_mp(uint32_t capacity, uint32_t snaplen,
                                      uint64_t arena_bytes, int nproducers);
/* Lower the producer count (re-splitting the arena) before anything has
 * been produced: capture may end up with fewer workers than asked for. */
void                ringbuf_set_producers(ringbuf_t *rb, int nproducers);
int                 ringbuf_producers(const ringbuf_t *rb);
void                ringbuf_destroy(ringbuf_t *rb);

/* Claim the next slot and wanted bytes of payload space (granted =
 * min(wanted, snaplen)). On return rec->raw_data points into the arena
 * and rec->raw_len is the granted length: the caller copies that many
 * bytes there (it may lower raw_len, never raise it), fills the summary
 * and commits. Between next and commit the slot and its bytes belong to
 * the caller. */
pkt_record_t       *ringbuf_producer_next(ringbuf_t *rb, uint32_t wanted);
void                ringbuf_producer_commit(ringbuf_t *rb);
/* Same for producer id pid (0 <= pid < nproducers). Producers run
 * concurrently: each reserves its own slot and payload bytes, fills it
 * and publishes, and commit_seq then advances over the published prefix
 * (see ringbuf.c). The single-producer forms above are pid 0 and take no
 * atomic beyond the ones the single-producer ring already used. */
pkt_record_t       *ringbuf_producer_next_w(ringbuf_t *rb, int pid,
                                            uint32_t wanted);
void                ringbuf_producer_commit_w(ringbuf_t *rb, int pid);

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
/* Wake slot id without an announcement: its owner blocks on the channel
 * for reasons of its own (a parked output helper) and another thread
 * wakes it. The owner drains as usual. Not counted in notify_sent. */
void                ringbuf_waiter_kick(ringbuf_t *rb, int id);

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
/* Attach mid-stream (a helper joining at the sequence it will read next)
 * and detach (the slot no longer holds the producer back). */
void                ringbuf_waiter_attach_at(ringbuf_t *rb, int id, uint64_t next_seq);
void                ringbuf_waiter_detach(ringbuf_t *rb, int id);
void                ringbuf_waiter_publish(ringbuf_t *rb, int id, uint64_t next_seq);
void                ringbuf_consumer_attach(ringbuf_t *rb);
void                ringbuf_consumer_publish(ringbuf_t *rb, uint64_t next_seq);
uint64_t            ringbuf_consumer_seq(const ringbuf_t *rb);
int                 ringbuf_producer_may_write(const ringbuf_t *rb);

#endif /* RINGBUF_H */
