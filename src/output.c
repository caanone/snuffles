#include "output.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <time.h>

#ifndef _WIN32
  #include <unistd.h>
  #include <sched.h>
  #include <sys/select.h>
  #include <sys/time.h>
#endif
#ifdef __linux__
  #include <sys/prctl.h>
#endif

#define OUTPUT_CHUNK    SYSLOG_BATCH    /* records claimed at a time: one sendmmsg batch */
#define OUTPUT_KICK_NS  2000000LL       /* one more helper per 2 ms while the backlog stays high */
#define OUTPUT_LINGER   8               /* empty claims a helper yields through before parking */
#define OUTPUT_WAIT_MS  100             /* longest sleep between looks at the ring; the wakeup
                                           usually ends it, this bounds how late stop is seen */

typedef struct {
    output_t            *o;
    int                  idx;           /* syslog worker index; -1 for the stream worker */
    syslog_out_t        *syslog;        /* owned; NULL on the stream worker */
    pcap_writer_t       *stream;        /* o->stream while it is open, else NULL */
    int                  is_stream;
    int                  waiter;        /* ring waiter slot */
    char                 name[16];
    ns_thread_t          thread;
    atomic_int           engaged;       /* syslog: 1 while running (or kicked), 0 parked */
    atomic_uint_fast64_t missed;        /* records this worker claimed/owned but could not read */
} output_worker_t;

struct output {
    ringbuf_t           *rb;
    pcap_writer_t       *stream;        /* owned; NULL: no -w (or it failed) */
    char                 stream_name[512];
    output_worker_t      w[OUTPUT_MAX_THREADS + 1];
    int                  nworkers;
    int                  nsyslog;       /* syslog workers = sockets */
    int                  min_active;    /* syslog workers 0..min_active-1 never park */
    uint64_t             up_lag;        /* unclaimed backlog that wakes one more helper */
    int                  attached;      /* positions published (offline replay) */
    int                  started;
    atomic_int           stop;
    atomic_uint_fast64_t cursor;        /* next sequence no syslog worker has claimed */
    atomic_uint_fast64_t skipped;       /* sequences the cursor jumped: lapped before any claim */
    atomic_int           active;        /* syslog workers running */
    atomic_int           hwm;           /* most running at once since the last stats read */
    atomic_llong         last_kick;     /* monotonic ns of the last helper wake-up */
    atomic_uint_fast64_t streamed;
};

static long long mono_ns(void) {
#ifdef _WIN32
    return (long long)GetTickCount64() * 1000000LL;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
#endif
}

static void output_wait(ringbuf_t *rb, int waiter) {
#ifdef _WIN32
    WaitForSingleObject(rb->waiters[waiter].event, OUTPUT_WAIT_MS);
#else
    int fd = ringbuf_waiter_fd(rb, waiter);
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(fd, &fds);
    struct timeval tv = { .tv_sec = 0, .tv_usec = OUTPUT_WAIT_MS * 1000 };
    select(fd + 1, &fds, NULL, NULL, &tv);
#endif
}

static void yield_cpu(void) {
#ifdef _WIN32
    SwitchToThread();
#else
    sched_yield();
#endif
}

/* ── syslog workers ──────────────────────────────────────────── */

/* Wake one parked helper if the unclaimed backlog says the running workers
 * are not keeping up. Rate-limited so the helper gets to contribute before
 * the next one is judged necessary. Called by any running syslog worker
 * after each chunk. */
static void maybe_kick(output_t *o) {
    uint64_t total  = ringbuf_total(o->rb);
    uint64_t cursor = atomic_load_explicit(&o->cursor, memory_order_relaxed);
    if (total <= cursor || total - cursor <= o->up_lag) return;
    if (atomic_load_explicit(&o->active, memory_order_relaxed) >= o->nsyslog) return;
    long long now = mono_ns();
    long long last = atomic_load_explicit(&o->last_kick, memory_order_relaxed);
    if (now - last < OUTPUT_KICK_NS) return;
    if (!atomic_compare_exchange_strong(&o->last_kick, &last, now)) return;
    for (int i = o->min_active; i < o->nsyslog; i++) {
        int parked = 0;
        if (!atomic_compare_exchange_strong(&o->w[i].engaged, &parked, 1))
            continue;
        int a = atomic_fetch_add(&o->active, 1) + 1;
        int h = atomic_load(&o->hwm);
        while (a > h && !atomic_compare_exchange_weak(&o->hwm, &h, a))
            ;
        ringbuf_waiter_kick(o->rb, o->w[i].waiter);
        return;
    }
}

/* Block until kicked (1) or stopped (0). The caller has already taken the
 * worker out of the running count. */
static int park_wait(output_worker_t *w) {
    output_t *o = w->o;
    for (;;) {
        if (atomic_load(&o->stop)) return 0;
        if (atomic_load(&w->engaged)) break;
        output_wait(o->rb, w->waiter);
        ringbuf_waiter_drain(o->rb, w->waiter);
    }
    return 1;
}

static void run_syslog(output_worker_t *w) {
    output_t  *o  = w->o;
    ringbuf_t *rb = o->rb;
    int helper = w->idx >= o->min_active;
    int empty  = 0;

    if (helper) {
        if (!park_wait(w)) return;
        if (o->attached)
            ringbuf_waiter_attach_at(rb, w->waiter,
                                     atomic_load(&o->cursor));
    }

    for (;;) {
        uint64_t c     = atomic_load(&o->cursor);
        uint64_t total = ringbuf_total(rb);

        if (c >= total) {
            /* nothing left to claim: the batch leaves now, so a record waits
             * at most one wake-up at low rates */
            syslog_out_flush(w->syslog);
            if (atomic_load(&o->stop)) {
                /* stop is set after the last commit, but total above was
                 * read before the flush: look again under the flag, or the
                 * tail committed meanwhile would be left behind */
                if (atomic_load(&o->cursor) >= ringbuf_total(rb)) break;
                continue;
            }
            if (helper) {
                /* a burst is committed over a few hundred microseconds:
                 * yield through a momentary gap rather than park/unpark */
                if (++empty < OUTPUT_LINGER) { yield_cpu(); continue; }
                empty = 0;
                atomic_fetch_sub(&o->active, 1);
                atomic_store(&w->engaged, 0);
                if (o->attached) ringbuf_waiter_detach(rb, w->waiter);
                if (!park_wait(w)) break;
                if (o->attached)
                    ringbuf_waiter_attach_at(rb, w->waiter,
                                             atomic_load(&o->cursor));
                continue;
            }
            /* running workers sleep on the ring: announce, re-check, block */
            if (o->attached) ringbuf_waiter_publish(rb, w->waiter, c);
            ringbuf_waiter_will_wait(rb, w->waiter);
            if (atomic_load(&o->cursor) >= ringbuf_total(rb))
                output_wait(rb, w->waiter);
            ringbuf_waiter_drain(rb, w->waiter);
            continue;
        }
        empty = 0;

        /* lapped before anyone claimed them: count them and move on */
        uint64_t oldest = ringbuf_oldest(rb);
        if (c < oldest) {
            if (atomic_compare_exchange_strong(&o->cursor, &c, oldest))
                atomic_fetch_add_explicit(&o->skipped, oldest - c,
                                          memory_order_relaxed);
            continue;
        }

        uint64_t n = total - c;
        if (n > OUTPUT_CHUNK) n = OUTPUT_CHUNK;
        if (!atomic_compare_exchange_strong(&o->cursor, &c, c + n))
            continue;
        if (o->attached) ringbuf_waiter_publish(rb, w->waiter, c);

        for (uint64_t s = c; s < c + n; s++) {
            pkt_record_t rec;
            if (ringbuf_read_seq(rb, s, &rec, NULL)) {
                /* skip our own syslog traffic to prevent a feedback loop */
                if (!syslog_out_is_self(w->syslog, &rec.summary))
                    syslog_out_send(w->syslog, &rec.summary);
            } else {
                atomic_fetch_add_explicit(&w->missed, 1, memory_order_relaxed);
            }
        }
        if (o->attached) ringbuf_waiter_publish(rb, w->waiter, c + n);
        maybe_kick(o);
    }
}

/* ── the -w stream worker ────────────────────────────────────── */

static void run_stream(output_worker_t *w) {
    output_t  *o  = w->o;
    ringbuf_t *rb = o->rb;

    /* The packet bytes are copied out of the ring into this thread-local
     * buffer, since the slot may be overwritten while the write is in
     * progress. */
    uint8_t *data = malloc(rb->snaplen);
    if (!data) {
        fprintf(stderr, "output: out of memory; disabling -w output\n");
        pcap_writer_close(o->stream);
        o->stream = w->stream = NULL;
    }

    uint64_t last = 0;   /* next sequence to write */
    for (;;) {
        if (ringbuf_total(rb) <= last) {
            /* stop is set after the last commit: re-read the total under
             * the flag before leaving, the first read may predate that
             * commit */
            if (atomic_load(&o->stop) && ringbuf_total(rb) <= last) break;
            ringbuf_waiter_will_wait(rb, w->waiter);
            if (ringbuf_total(rb) <= last)
                output_wait(rb, w->waiter);
        }
        ringbuf_waiter_drain(rb, w->waiter);

        uint64_t total  = ringbuf_total(rb);
        uint64_t oldest = ringbuf_oldest(rb);
        if (last < oldest) {
            /* the ring wrapped past us (or was cleared): those are gone */
            atomic_fetch_add_explicit(&w->missed, oldest - last,
                                      memory_order_relaxed);
            last = oldest;
        }
        while (last < total) {
            pkt_record_t rec;
            if (ringbuf_read_seq(rb, last, &rec, data)) {
                if (w->stream) {
                    if (pcap_writer_write(w->stream, &rec) != 0) {
                        fprintf(stderr, "stream write failed; disabling -w "
                                        "output\n");
                        pcap_writer_close(o->stream);
                        o->stream = w->stream = NULL;
                    } else {
                        atomic_fetch_add_explicit(&o->streamed, 1,
                                                  memory_order_relaxed);
                    }
                }
            } else {
                atomic_fetch_add_explicit(&w->missed, 1, memory_order_relaxed);
            }
            last++;
            if (o->attached) ringbuf_waiter_publish(rb, w->waiter, last);
        }
        /* caught up: the buffer goes to the file before we block */
        if (w->stream) pcap_writer_flush(w->stream);
    }
    free(data);
}

static void *output_thread_fn(void *arg) {
    output_worker_t *w = (output_worker_t *)arg;
#ifdef __linux__
    prctl(PR_SET_NAME, w->name, 0, 0, 0);
#endif
    if (w->is_stream) run_stream(w);
    else              run_syslog(w);
    return NULL;
}

/* ── public API ──────────────────────────────────────────────── */

output_t *output_create(ringbuf_t *rb, syslog_out_t *sl, int min_threads,
                        int max_threads, pcap_writer_t *pw,
                        const char *stream_name) {
    output_t *o = calloc(1, sizeof(*o));
    if (!o) return NULL;
    o->rb     = rb;
    o->stream = pw;
    if (stream_name)
        snprintf(o->stream_name, sizeof(o->stream_name), "%s", stream_name);
    atomic_store(&o->stop, 0);
    atomic_store(&o->streamed, 0);
    atomic_store(&o->cursor, 0);
    atomic_store(&o->skipped, 0);
    atomic_store(&o->last_kick, 0);

    /* Sockets: the one we were given plus clones, one per worker. */
    syslog_out_t *sls[OUTPUT_MAX_THREADS];
    int ns = 0;
    if (sl) {
        if (max_threads < 1) max_threads = 1;
        if (max_threads > OUTPUT_MAX_THREADS) max_threads = OUTPUT_MAX_THREADS;
        sls[ns++] = sl;
        while (ns < max_threads) {
            syslog_out_t *c = syslog_out_clone(sl);
            if (!c) {
                fprintf(stderr, "syslog: cannot open socket %d of %d; using %d "
                                "output thread(s)\n", ns + 1, max_threads, ns);
                break;
            }
            sls[ns++] = c;
        }
    }

    /* Workers: one per syslog socket, plus the stream's own. */
    int nw = ns + (pw ? 1 : 0);
    if (nw == 0) nw = 1;           /* nothing to do, but the object works */

    /* Ring slots. When short, shed syslog workers, never the stream. */
    int slots[OUTPUT_MAX_THREADS + 1];
    int got = 0;
    while (got < nw) {
        int s = ringbuf_waiter_add(rb);
        if (s < 0) break;
        slots[got++] = s;
    }
    if (got == 0) {
        fprintf(stderr, "output: no ring waiter slot free\n");
        for (int i = 1; i < ns; i++) syslog_out_destroy(sls[i]);
        free(o);
        return NULL;
    }
    if (got < nw) {
        int keep = got - (pw ? 1 : 0);              /* the stream keeps its slot */
        if (keep < 0)  keep = 0;
        if (keep > ns) keep = ns;
        fprintf(stderr, "output: only %d ring slot(s) free; using %d syslog "
                        "thread(s)\n", got, keep);
        for (int i = keep; i < ns; i++) syslog_out_destroy(sls[i]);
        ns = keep;
        nw = ns + (pw ? 1 : 0);
        if (nw == 0) nw = 1;
    }
    if (ns > 1) syslog_out_link(sls, (unsigned)ns);

    if (min_threads < 1) min_threads = 1;
    if (min_threads > ns) min_threads = ns;
    o->nsyslog    = ns;
    o->min_active = ns ? min_threads : 0;
    o->up_lag     = rb->capacity / 8;
    if (o->up_lag < 2 * OUTPUT_CHUNK) o->up_lag = 2 * OUTPUT_CHUNK;

    int k = 0;
    for (int i = 0; i < ns; i++, k++) {
        output_worker_t *w = &o->w[k];
        w->idx    = i;
        w->syslog = sls[i];
        atomic_store(&w->engaged, i < o->min_active);
        if (ns == 1 && !pw) snprintf(w->name, sizeof(w->name), "snf-output");
        else                snprintf(w->name, sizeof(w->name), "snf-syslog%d", i);
    }
    if (pw || ns == 0) {
        /* the stream worker; with no sink at all an idle one of the same
         * kind, so the object still starts and stops like any other */
        output_worker_t *w = &o->w[k++];
        w->idx = -1;
        w->stream = pw; w->is_stream = 1;
        snprintf(w->name, sizeof(w->name), ns ? "snf-stream" : "snf-output");
    }
    for (int i = 0; i < k; i++) {
        o->w[i].o      = o;
        o->w[i].waiter = slots[i];
        atomic_store(&o->w[i].missed, 0);
    }
    o->nworkers = k;
    atomic_store(&o->active, o->min_active);
    atomic_store(&o->hwm, o->min_active);
    if (ns > 1) {
        if (o->min_active == ns)
            fprintf(stderr, "Syslog output: %d threads, one socket each\n", ns);
        else
            fprintf(stderr, "Syslog output: %d-%d threads (scaling with the "
                            "backlog), one socket each\n", o->min_active, ns);
    }
    return o;
}

void output_attach_position(output_t *o) {
    if (!o) return;
    for (int i = 0; i < o->nworkers; i++) {
        output_worker_t *w = &o->w[i];
        if (w->is_stream || w->idx < o->min_active)
            ringbuf_waiter_attach(o->rb, w->waiter);   /* helpers attach when they wake */
    }
    o->attached = 1;
}

int output_start(output_t *o) {
    if (!o) return -1;
    for (int i = 0; i < o->nworkers; i++) {
        if (ns_thread_create(&o->w[i].thread, output_thread_fn, &o->w[i]) != 0) {
            fprintf(stderr, "Failed to create output thread\n");
            atomic_store(&o->stop, 1);
            for (int j = 0; j < i; j++) {
                ringbuf_waiter_kick(o->rb, o->w[j].waiter);
                ns_thread_join(o->w[j].thread);
            }
            return -1;
        }
    }
    o->started = 1;
    return 0;
}

void output_stop(output_t *o) {
    if (!o || !o->started) return;
    atomic_store(&o->stop, 1);
    for (int i = 0; i < o->nworkers; i++) ringbuf_waiter_kick(o->rb, o->w[i].waiter);
    for (int i = 0; i < o->nworkers; i++) ns_thread_join(o->w[i].thread);
    o->started = 0;
}

void output_destroy(output_t *o) {
    if (!o) return;
    output_stop(o);
    if (o->stream) {
        uint64_t n = pcap_writer_count(o->stream);
        if (pcap_writer_close(o->stream) != 0)
            fprintf(stderr, "Warning: error finalizing -w stream file\n");
        else
            fprintf(stderr, "Streamed %llu packets to %s\n",
                    (unsigned long long)n, o->stream_name);
        o->stream = NULL;
    }
    for (int i = 0; i < o->nworkers; i++) syslog_out_destroy(o->w[i].syslog);
    free(o);
}

void output_get_stats(output_t *o, output_stats_t *out) {
    memset(out, 0, sizeof(*out));
    if (!o) return;
    uint64_t sys = atomic_load_explicit(&o->skipped, memory_order_relaxed);
    uint64_t str = 0;
    for (int i = 0; i < o->nworkers; i++) {
        output_worker_t *w = &o->w[i];
        uint64_t m = atomic_load_explicit(&w->missed, memory_order_relaxed);
        if (w->syslog) {
            uint64_t sent, failed;
            syslog_out_counts(w->syslog, &sent, &failed);
            out->syslog_sent   += sent;
            out->syslog_failed += failed;
            sys += m;
        }
        if (w->is_stream) str += m;
    }
    out->streamed      = atomic_load_explicit(&o->streamed, memory_order_relaxed);
    out->missed        = o->nsyslog ? sys : str;
    out->stream_missed = str;
    if (o->nsyslog) {
        int a = atomic_load(&o->active);
        out->syslog_threads = atomic_exchange(&o->hwm, a);
        if (out->syslog_threads < a) out->syslog_threads = a;
    }
}

int output_syslog_threads(const output_t *o) {
    return o ? o->nsyslog : 0;
}
