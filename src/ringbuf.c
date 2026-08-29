#include "ringbuf.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#ifndef _WIN32
  #include <unistd.h>
  #include <fcntl.h>
  #include <sched.h>
#endif

/* Spin hint while a producer waits for the slot one lap back (see
 * ringbuf_producer_next_w). The wait is short — the other producer is
 * mid-packet — so pause first and only yield once it is clear the owner
 * is not running. */
static inline void spin_pause(unsigned n) {
#if defined(__x86_64__) || defined(__i386__)
    __builtin_ia32_pause();
#elif defined(__aarch64__)
    __asm__ __volatile__("yield" ::: "memory");
#endif
    if ((n & 63u) == 63u) {
#ifdef _WIN32
        SwitchToThread();
#else
        sched_yield();
#endif
    }
}

/* Split the arena into one equal slice per producer. Called before
 * anything is produced, so resetting the cursors is safe. */
static void split_arena(ringbuf_t *rb) {
    uint64_t per = rb->arena_size / (uint64_t)rb->nprod;
    for (int i = 0; i < rb->nprod; i++) {
        ringbuf_prod_t *p = &rb->prods[i];
        p->arena_base = per * (uint64_t)i;
        p->arena_len  = per;
        p->arena_off  = 0;
        p->seq        = 0;
        atomic_store(&p->arena_pos, 0);
    }
}

ringbuf_t *ringbuf_create_mp(uint32_t capacity, uint32_t snaplen,
                             uint64_t arena_bytes, int nproducers) {
    if (nproducers < 1) nproducers = 1;
    if (nproducers > RINGBUF_MAX_PRODUCERS) nproducers = RINGBUF_MAX_PRODUCERS;

    ringbuf_t *rb = calloc(1, sizeof(ringbuf_t));
    if (!rb) return NULL;

    rb->capacity = capacity;
    rb->snaplen  = snaplen;
    rb->nprod    = nproducers;
    rb->mp       = nproducers > 1;

    rb->records = calloc(capacity, sizeof(pkt_record_t));
    if (!rb->records) { free(rb); return NULL; }

    if (arena_bytes == 0) {
        uint32_t per = snaplen < RINGBUF_ARENA_SLOT ? snaplen : RINGBUF_ARENA_SLOT;
        arena_bytes = (uint64_t)capacity * per;
    }
    /* one full packet must fit in every producer's slice */
    if (arena_bytes < (uint64_t)snaplen * (uint64_t)nproducers)
        arena_bytes = (uint64_t)snaplen * (uint64_t)nproducers;
    if (arena_bytes < (uint64_t)nproducers) arena_bytes = (uint64_t)nproducers;
    if (arena_bytes > SIZE_MAX / 2) { free(rb->records); free(rb); return NULL; }
    rb->arena_size = arena_bytes;
    rb->arena = calloc(1, (size_t)arena_bytes);
    if (!rb->arena) { free(rb->records); free(rb); return NULL; }

    rb->slot_gen = calloc(capacity, sizeof(atomic_uint_fast64_t));
    if (!rb->slot_gen) {
        free(rb->arena); free(rb->records); free(rb);
        return NULL;
    }
    /* A zeroed generation would read as "holds record 0, published", so
     * every slot starts as "record 0, still being written": no reader
     * and no commit can mistake an untouched slot for a record. */
    for (uint32_t i = 0; i < capacity; i++)
        atomic_store(&rb->slot_gen[i], 1);

    /* producers on their own cache lines (arena_pos is read by every
     * consumer, written per packet by its owner) */
    rb->prods_raw = calloc(1, sizeof(ringbuf_prod_t) * RINGBUF_MAX_PRODUCERS + 63);
    if (!rb->prods_raw) {
        free(rb->slot_gen); free(rb->arena); free(rb->records); free(rb);
        return NULL;
    }
    rb->prods = (ringbuf_prod_t *)(void *)
                (((uintptr_t)rb->prods_raw + 63u) & ~(uintptr_t)63u);
    split_arena(rb);

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
        free(rb->prods_raw);
        free(rb->slot_gen);
        free(rb->arena);
        free(rb->records);
        free(rb);
        return NULL;
    }

    return rb;
}

ringbuf_t *ringbuf_create(uint32_t capacity, uint32_t snaplen,
                          uint64_t arena_bytes) {
    return ringbuf_create_mp(capacity, snaplen, arena_bytes, 1);
}

void ringbuf_set_producers(ringbuf_t *rb, int nproducers) {
    if (!rb || nproducers < 1) return;
    if (nproducers > RINGBUF_MAX_PRODUCERS) nproducers = RINGBUF_MAX_PRODUCERS;
    /* a slice must still hold one whole packet (creation guarantees this
     * for the count asked for there, so this only ever refuses a raise) */
    if (rb->snaplen && (uint64_t)nproducers > rb->arena_size / rb->snaplen)
        return;
    if (nproducers == rb->nprod) return;
    rb->nprod = nproducers;
    rb->mp    = nproducers > 1;
    split_arena(rb);
}

int ringbuf_producers(const ringbuf_t *rb) {
    return rb ? rb->nprod : 1;
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
    free(rb->prods_raw);
    free(rb->slot_gen);
    free(rb->arena);
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

pkt_record_t *ringbuf_producer_next_w(ringbuf_t *rb, int pid, uint32_t wanted) {
    ringbuf_prod_t *p = &rb->prods[pid];
    uint64_t seq;
    uint32_t idx;

    if (rb->mp) {
        /* Reserve a sequence, then take exclusive ownership of its slot:
         * the generation moves from "holds the record one lap back,
         * published" to "holds seq, being written", and only the producer
         * of seq can make that transition. That is what keeps two
         * producers off one slot — a plain mark would let a producer that
         * was descheduled for a whole lap scribble over the record that
         * replaced it, with the generation of the new owner still in
         * place, so no reader could tell. If the previous occupant is
         * still being written (its producer is not running), wait for it:
         * the producer holding the oldest reservation never waits, so the
         * ring always drains. */
        seq = atomic_fetch_add_explicit(&rb->write_seq, 1, memory_order_relaxed);
        idx = (uint32_t)(seq % rb->capacity);
        uint64_t prev = seq >= rb->capacity ? (seq - rb->capacity) * 2u : 1u;
        uint64_t exp  = prev;
        for (unsigned n = 0; !atomic_compare_exchange_weak_explicit(
                 &rb->slot_gen[idx], &exp, seq * 2u + 1u,
                 memory_order_acq_rel, memory_order_relaxed); n++) {
            exp = prev;             /* the failed CAS overwrote it */
            spin_pause(n);
        }
    } else {
        seq = atomic_load_explicit(&rb->write_seq, memory_order_relaxed);
        idx = (uint32_t)(seq % rb->capacity);
        /* seq * 2 + 1: this slot now holds record seq and is being
         * written. One producer cannot race itself. */
        atomic_store_explicit(&rb->slot_gen[idx], seq * 2u + 1u,
                              memory_order_relaxed);
    }
    p->seq = seq;

    /* Bump-allocate the payload from this producer's arena slice. A
     * packet never straddles the end of the slice: the unused tail is
     * skipped (and counted as consumed, so position % len stays the
     * offset). */
    if (wanted > rb->snaplen) wanted = rb->snaplen;
    uint64_t pos = atomic_load_explicit(&p->arena_pos, memory_order_relaxed);
    uint64_t off = p->arena_off;
    if (wanted > p->arena_len - off) {
        pos += p->arena_len - off;
        off  = 0;
    }
    pkt_record_t *rec = &rb->records[idx];
    rec->raw_data = rb->arena + p->arena_base + off;
    rec->raw_len  = wanted;
    rec->data_pos = pos;
    rec->prod_id  = (uint32_t)pid;
    p->arena_off  = off + wanted;
    /* The cursor moves before the bytes are written (readers rely on
     * seeing the move if they could see the bytes). Publishing it with
     * a release store is not enough: that orders *earlier* writes before
     * it, and the caller's payload copy comes after. The fence below
     * covers both this store and the slot generation. */
    atomic_store_explicit(&p->arena_pos, pos + wanted, memory_order_relaxed);
    /* The stores above don't order the caller's later plain data stores
     * after them on weakly-ordered CPUs (arm64): a lapped reader could
     * see new data before the odd generation and validate a torn copy.
     * Fence so the odd mark is visible before any data write. */
    atomic_thread_fence(memory_order_release);
    return rec;
}

pkt_record_t *ringbuf_producer_next(ringbuf_t *rb, uint32_t wanted) {
    return ringbuf_producer_next_w(rb, 0, wanted);
}

/* Multi-producer publication. Reservations complete out of order, so
 * commit_seq — the point below which consumers may look — may only step
 * over record c once slot c % capacity says c is finished with. Reading
 * the slot's generation g (record g >> 1, still being written while
 * g & 1):
 *
 *   g >> 1 <  c   the slot has not been claimed for c yet: stop.
 *   g == c * 2+1  c's producer is still filling it: stop, so no consumer
 *                 ever sees a record before its producer finished.
 *   g == c * 2    c is published: step over it.
 *   g >> 1 >  c   a later record owns the slot now. Claiming it required
 *                 c to be published first (ringbuf_producer_next_w), so
 *                 c did complete; its bytes are simply gone, and a
 *                 consumer asking for c gets the same miss a
 *                 single-producer overrun gives it. Stepping over this
 *                 case is what keeps the ring from wedging the moment
 *                 producers lap the publication point.
 *
 * Every producer runs this after publishing its own slot, so whoever
 * finishes last also publishes the records that were waiting behind it;
 * a producer that stalls holds back the records reserved after it until
 * it comes back.
 * Returns 1 if commit_seq moved (i.e. a consumer has something new). */
static int mp_advance_commit(ringbuf_t *rb) {
    int advanced = 0;
    uint64_t c = atomic_load(&rb->commit_seq);
    for (;;) {
        uint64_t g = atomic_load_explicit(&rb->slot_gen[(uint32_t)(c % rb->capacity)],
                                          memory_order_acquire);
        uint64_t held = g >> 1;
        if (held < c) break;                 /* slot not claimed for c */
        if (held == c && (g & 1)) break;     /* c still being written */
        if (atomic_compare_exchange_weak(&rb->commit_seq, &c, c + 1)) {
            advanced = 1;
            c++;
        }
        /* on failure the CAS reloaded c: another thread advanced it */
    }
    return advanced;
}

/* Consumer-side sync. A producer looks at the publication point once,
 * after its own release store, and its store need not be visible to the
 * next producer that looks: the consumer running the same loop is what
 * guarantees the last records of a run always become visible. No-op with
 * one producer, whose commit_seq is always current. Const because the
 * callers are read-only queries: the publication point is not observable
 * state to them. */
static void mp_sync(const ringbuf_t *rb) {
    if (rb->mp) (void)mp_advance_commit((ringbuf_t *)rb);
}

void ringbuf_producer_commit_w(ringbuf_t *rb, int pid) {
    uint64_t seq = rb->prods[pid].seq;
    uint32_t idx = (uint32_t)(seq % rb->capacity);
    rb->records[idx].seq_num = seq;
    /* release: the record and its payload are complete before the slot
     * is marked stable (seq * 2) */
    atomic_store_explicit(&rb->slot_gen[idx], seq * 2u, memory_order_release);

    if (!rb->mp) {
        atomic_store_explicit(&rb->write_seq, seq + 1, memory_order_relaxed);
        atomic_fetch_add(&rb->commit_seq, 1);
    } else if (!mp_advance_commit(rb)) {
        return;     /* nothing became visible: no wakeup owed */
    }

    /* Wake the consumers that announced they are about to block. Both
     * this load and a consumer's flag/count stores are seq_cst, and so are
     * the commit_seq RMW above and the consumer's re-check load: in the
     * single total order either we see the count (and deliver a wakeup)
     * or the consumer's re-check sees this commit (and doesn't block). */
    if (atomic_load(&rb->nwaiting))
        ringbuf_wake_waiters(rb);
}

void ringbuf_producer_commit(ringbuf_t *rb) {
    ringbuf_producer_commit_w(rb, 0);
}

uint64_t ringbuf_oldest(const ringbuf_t *rb) {
    uint64_t total = atomic_load(&rb->commit_seq);
    uint64_t clear = atomic_load(&rb->clear_seq);
    uint64_t oldest = (total > rb->capacity) ? total - rb->capacity : 0;
    return (clear > oldest) ? clear : oldest;
}

uint32_t ringbuf_count(const ringbuf_t *rb) {
    mp_sync(rb);
    uint64_t total = atomic_load(&rb->commit_seq);
    return (uint32_t)(total - ringbuf_oldest(rb));
}

uint64_t ringbuf_total(const ringbuf_t *rb) {
    mp_sync(rb);
    return atomic_load(&rb->commit_seq);
}

/* Seqlock read of one slot, expecting sequence want. Returns 1 with *out
 * filled, 0 if the slot was being written, changed underneath the copy or
 * holds another sequence. The payload is copied into data (if given)
 * before the recheck, like the record itself, and then validated against
 * the arena cursor: if the producer's allocations have passed the copied
 * bytes since they were claimed, the copy may be torn and is dropped
 * (raw_len 0) — the summary is still good. */
static int read_slot(ringbuf_t *rb, uint32_t slot, uint64_t want,
                     pkt_record_t *out, uint8_t *data) {
    uint64_t g1 = atomic_load(&rb->slot_gen[slot]);
    /* want * 2 = "holds record want, nobody writing". Any other value is
     * a different record or a write in progress — including a producer
     * lapping onto this slot while another is still filling it. */
    if (g1 != want * 2u) return 0;

    *out = rb->records[slot];
    /* Bounds from a possibly torn record copy: clamp before touching
     * memory, the recheck below decides whether the copy counts. */
    uint32_t pid = out->prod_id;
    if (pid >= (uint32_t)rb->nprod) pid = 0;
    const ringbuf_prod_t *p = &rb->prods[pid];
    uint32_t rl  = out->raw_len;
    uint64_t off = out->data_pos % p->arena_len;
    if (rl > rb->snaplen) rl = rb->snaplen;
    if (rl > p->arena_len - off) rl = (uint32_t)(p->arena_len - off);
    if (data && rl)
        memcpy(data, rb->arena + p->arena_base + off, rl);

    /* The copies above use plain loads; on weakly-ordered CPUs (arm64)
     * they may be satisfied after the recheck loads below, validating a
     * torn read. Fence so the copies complete first. */
    atomic_thread_fence(memory_order_acquire);
    uint64_t cursor = atomic_load(&p->arena_pos);
    if (atomic_load(&rb->slot_gen[slot]) != g1 || out->seq_num != want)
        return 0;
    /* Record consistent, so prod_id/data_pos/raw_len are the producer's.
     * The bytes at [data_pos, data_pos + rl) have been reused iff its
     * cursor went past data_pos + slice size (the skipped tail counts as
     * used, which only makes this conservative). The cursor was loaded
     * after the fence: if it still permits the copy, no overwrite could
     * have been visible to it. (Loaded before the generation recheck so a
     * claim that lands between the two costs a payload only when it is
     * about to be overwritten anyway.) */
    if (rl && cursor - out->data_pos > p->arena_len)
        rl = 0;
    out->raw_len  = rl;
    out->raw_data = data ? data : NULL;
    return 1;
}

int ringbuf_read(ringbuf_t *rb, uint32_t idx, pkt_record_t *out, uint8_t *data) {
    for (int attempt = 0; attempt < 4; attempt++) {
        uint64_t total  = atomic_load(&rb->commit_seq);
        uint64_t oldest = ringbuf_oldest(rb);
        if (idx >= (uint32_t)(total - oldest)) return 0;

        uint64_t target = oldest + idx;
        if (read_slot(rb, (uint32_t)(target % rb->capacity), target, out, data))
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

        if (read_slot(rb, (uint32_t)(seq % rb->capacity), seq, out, data))
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
