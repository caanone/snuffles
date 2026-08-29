#include "ringbuf.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#ifndef _WIN32
  #include <unistd.h>
  #include <fcntl.h>
#endif

ringbuf_t *ringbuf_create(uint32_t capacity, uint32_t snaplen,
                          uint64_t arena_bytes) {
    ringbuf_t *rb = calloc(1, sizeof(ringbuf_t));
    if (!rb) return NULL;

    rb->capacity = capacity;
    rb->snaplen  = snaplen;

    rb->records = calloc(capacity, sizeof(pkt_record_t));
    if (!rb->records) { free(rb); return NULL; }

    if (arena_bytes == 0) {
        uint32_t per = snaplen < RINGBUF_ARENA_SLOT ? snaplen : RINGBUF_ARENA_SLOT;
        arena_bytes = (uint64_t)capacity * per;
    }
    if (arena_bytes < snaplen) arena_bytes = snaplen;   /* one full packet fits */
    if (arena_bytes == 0) arena_bytes = 1;              /* readers divide by it */
    if (arena_bytes > SIZE_MAX / 2) { free(rb->records); free(rb); return NULL; }
    rb->arena_size = arena_bytes;
    rb->arena = calloc(1, (size_t)arena_bytes);
    if (!rb->arena) { free(rb->records); free(rb); return NULL; }

    rb->slot_gen = calloc(capacity, sizeof(atomic_uint_fast64_t));
    if (!rb->slot_gen) {
        free(rb->arena); free(rb->records); free(rb);
        return NULL;
    }

    atomic_store(&rb->write_seq, 0);
    atomic_store(&rb->commit_seq, 0);
    atomic_store(&rb->clear_seq, 0);
    atomic_store(&rb->arena_pos, 0);
    atomic_store(&rb->consumer_waiting, 0);
    atomic_store(&rb->notify_sent, 0);
    atomic_store(&rb->consumer_seq, RINGBUF_NO_CONSUMER);

#ifdef _WIN32
    rb->notify_event = CreateEvent(NULL, FALSE, FALSE, NULL);
#else
    if (pipe(rb->notify_pipe) != 0) {
        free(rb->slot_gen);
        free(rb->arena);
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
    free(rb->arena);
    free(rb->records);
    free(rb);
}

pkt_record_t *ringbuf_producer_next(ringbuf_t *rb, uint32_t wanted) {
    uint64_t seq = atomic_load(&rb->write_seq);
    uint32_t idx = (uint32_t)(seq % rb->capacity);
    atomic_fetch_add(&rb->slot_gen[idx], 1);   /* even -> odd: write begins */

    /* Bump-allocate the payload. A packet never straddles the end of the
     * arena: the unused tail is skipped (and counted as consumed, so
     * position % size stays the offset). */
    if (wanted > rb->snaplen) wanted = rb->snaplen;
    uint64_t pos = atomic_load_explicit(&rb->arena_pos, memory_order_relaxed);
    uint64_t off = rb->arena_off;
    if (wanted > rb->arena_size - off) {
        pos += rb->arena_size - off;
        off  = 0;
    }
    pkt_record_t *rec = &rb->records[idx];
    rec->raw_data = rb->arena + off;
    rec->raw_len  = wanted;
    rec->data_pos = pos;
    rb->arena_off = off + wanted;
    /* The cursor moves before the bytes are written (readers rely on
     * seeing the move if they could see the bytes). Publishing it with
     * a release store is not enough: that orders *earlier* writes before
     * it, and the caller's payload copy comes after. The fence below
     * covers both this store and the slot generation. */
    atomic_store_explicit(&rb->arena_pos, pos + wanted, memory_order_relaxed);
    /* The RMW's store half doesn't order the caller's later plain data
     * stores after it on weakly-ordered CPUs (arm64): a lapped reader
     * could see new data before the odd generation and validate a torn
     * copy. Fence so the odd mark is visible before any data write. */
    atomic_thread_fence(memory_order_release);
    return rec;
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
    if (g1 & 1) return 0;   /* producer mid-write */

    *out = rb->records[slot];
    /* Bounds from a possibly torn record copy: clamp before touching
     * memory, the recheck below decides whether the copy counts. */
    uint32_t rl  = out->raw_len;
    uint64_t off = out->data_pos % rb->arena_size;
    if (rl > rb->snaplen) rl = rb->snaplen;
    if (rl > rb->arena_size - off) rl = (uint32_t)(rb->arena_size - off);
    if (data && rl)
        memcpy(data, rb->arena + off, rl);

    /* The copies above use plain loads; on weakly-ordered CPUs (arm64)
     * they may be satisfied after the recheck loads below, validating a
     * torn read. Fence so the copies complete first. */
    atomic_thread_fence(memory_order_acquire);
    uint64_t cursor = atomic_load(&rb->arena_pos);
    if (atomic_load(&rb->slot_gen[slot]) != g1 || out->seq_num != want)
        return 0;
    /* Record consistent, so data_pos/raw_len are the producer's. The
     * bytes at [data_pos, data_pos + rl) have been reused iff the cursor
     * went past data_pos + arena_size (the skipped tail counts as used,
     * which only makes this conservative). The cursor was loaded after
     * the fence: if it still permits the copy, no overwrite could have
     * been visible to it. (Loaded before the generation recheck so a
     * claim that lands between the two costs a payload only when it is
     * about to be overwritten anyway.) */
    if (rl && cursor - out->data_pos > rb->arena_size)
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

/* ── consumer position (offline back-pressure) ───────────────── */

void ringbuf_consumer_attach(ringbuf_t *rb) {
    atomic_store(&rb->consumer_seq, 0);
}

void ringbuf_consumer_publish(ringbuf_t *rb, uint64_t next_seq) {
    atomic_store_explicit(&rb->consumer_seq, next_seq, memory_order_release);
}

uint64_t ringbuf_consumer_seq(const ringbuf_t *rb) {
    return atomic_load_explicit(&rb->consumer_seq, memory_order_acquire);
}

int ringbuf_producer_may_write(const ringbuf_t *rb) {
    uint64_t c = atomic_load_explicit(&rb->consumer_seq, memory_order_acquire);
    if (c == RINGBUF_NO_CONSUMER) return 1;
    uint64_t total = atomic_load_explicit(&rb->commit_seq, memory_order_relaxed);
    /* c can run ahead of total only transiently (consumer published a
     * sequence it expects next): no back-pressure in that case. */
    if (c >= total) return 1;
    return (total - c) < (uint64_t)rb->capacity - 1;
}
