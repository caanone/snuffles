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

#define OUTPUT_CHUNK        SYSLOG_BATCH    /* records claimed at a time: one sendmmsg batch */
#define OUTPUT_GROW_NS      2000000LL       /* at most one thread woken or created per 2 ms */
#define OUTPUT_SHRINK_NS    20000000LL      /* at most one thread parked per 20 ms */
#define OUTPUT_WINDOW_NS    50000000LL      /* busy-fraction sampling window: several kernel
                                               block bursts, so the duty cycle is measured,
                                               not the burst */
#define OUTPUT_GROW_PM      900             /* grow: running workers average >= 90 % busy */
#define OUTPUT_SHRINK_PM    800             /* park: the others would average <= 80 % busy */
#define OUTPUT_IDLE_EXIT_MS 3000            /* a parked thread exits after this without work */
#define OUTPUT_WAIT_MS      100             /* longest sleep between looks at the ring; the wakeup
                                               usually ends it, this bounds how late stop is seen */

/* A syslog slot's thread state. NONE: no thread (never started, or exited
 * and joined). ENGAGED: running, claiming chunks or waiting on the ring for
 * more. PARKED: alive, waiting to be woken by a peer. EXITED: the thread
 * has returned and waits to be joined before the slot is reused. */
enum { W_NONE = 0, W_ENGAGED, W_PARKED, W_EXITED };

typedef struct {
    output_t            *o;
    int                  idx;           /* syslog slot index; -1 for the stream worker */
    syslog_out_t        *syslog;        /* owned; NULL on the stream worker */
    pcap_writer_t       *stream;        /* o->stream while it is open, else NULL */
    int                  is_stream;
    int                  waiter;        /* ring waiter slot */
    char                 name[16];
    ns_thread_t          thread;
    atomic_int           state;         /* W_* (syslog slots) */
    atomic_uint          busy_pm;       /* busy fraction, per mille, running average */
    atomic_int           measured;      /* busy_pm has seen a full window since the thread
                                           started or was woken */
    atomic_uint_fast64_t missed;        /* records this slot claimed/owned but could not read */
} output_worker_t;

struct output {
    ringbuf_t           *rb;
    pcap_writer_t       *stream;        /* owned; NULL: no -w (or it failed) */
    char                 stream_name[512];
    output_worker_t      w[OUTPUT_MAX_THREADS + 1];
    int                  nworkers;      /* slots in use, stream included */
    int                  nsyslog;       /* syslog slots = sockets = most threads */
    int                  min_active;    /* syslog threads 0..min_active-1 exist always */
    uint64_t             up_lag;        /* unclaimed backlog that grows the pool at once */
    int                  idle_exit_ms;
    int                  attached;      /* positions published (offline replay) */
    int                  started;
    atomic_int           stop;
    atomic_int           growing;       /* a thread is being created */
    atomic_uint_fast64_t cursor;        /* next sequence no syslog worker has claimed */
    atomic_uint_fast64_t skipped;       /* sequences the cursor jumped: lapped before any claim */
    atomic_int           active;        /* syslog threads engaged */
    atomic_int           alive;         /* syslog threads that exist */
    atomic_int           hwm;           /* most alive at once since the last stats read */
    atomic_llong         last_grow;     /* monotonic ns */
    atomic_llong         last_shrink;
    atomic_uint_fast64_t streamed;
};

static long long mono_ns(void) {
#ifdef _WIN32
    static LARGE_INTEGER freq;
    LARGE_INTEGER c;
    if (!freq.QuadPart) QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&c);
    return (long long)((double)c.QuadPart * 1e9 / (double)freq.QuadPart);
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

static void *output_thread_fn(void *arg);

/* ── the pool ────────────────────────────────────────────────── */

/* Sum of the busy fractions of the engaged syslog threads, and how many.
 * A thread that has not completed a window yet counts as `unmeasured`:
 * idle for the grow rule (do not add threads on an assumption) and busy
 * for the park rule (do not retire one before it has been measured). */
static unsigned busy_sum(output_t *o, int *engaged, unsigned unmeasured) {
    unsigned sum = 0;
    int n = 0;
    for (int i = 0; i < o->nsyslog; i++) {
        output_worker_t *w = &o->w[i];
        if (atomic_load_explicit(&w->state, memory_order_relaxed) != W_ENGAGED)
            continue;
        sum += atomic_load_explicit(&w->measured, memory_order_relaxed)
             ? atomic_load_explicit(&w->busy_pm, memory_order_relaxed) : unmeasured;
        n++;
    }
    *engaged = n;
    return sum;
}

/* Start a thread in syslog slot i (state already ENGAGED). */
static int slot_start(output_t *o, int i) {
    output_worker_t *w = &o->w[i];
    atomic_store(&w->busy_pm, 1000);
    atomic_store(&w->measured, 0);
    if (ns_thread_create(&w->thread, output_thread_fn, w) != 0) return -1;
    int a = atomic_fetch_add(&o->alive, 1) + 1;
    int h = atomic_load(&o->hwm);
    while (a > h && !atomic_compare_exchange_weak(&o->hwm, &h, a))
        ;
    return 0;
}

/* One more syslog thread, if the pool says so: wake a parked one, else
 * create one in an empty slot. Called by a running worker after each
 * chunk and after each wake-up; rate-limited so a change gets to count
 * before the next is judged. */
static void maybe_grow(output_t *o, long long now) {
    long long last = atomic_load_explicit(&o->last_grow, memory_order_relaxed);
    if (now - last < OUTPUT_GROW_NS) return;
    int n = atomic_load_explicit(&o->active, memory_order_relaxed);
    if (n >= o->nsyslog) return;

    uint64_t total  = ringbuf_total(o->rb);
    uint64_t cursor = atomic_load_explicit(&o->cursor, memory_order_relaxed);
    uint64_t lag    = total > cursor ? total - cursor : 0;
    if (lag <= o->up_lag) {
        /* no emergency: grow only when everyone running is near saturation
         * and there is a queue at all */
        if (lag <= OUTPUT_CHUNK) return;
        int engaged;
        unsigned sum = busy_sum(o, &engaged, 0);
        if (engaged == 0 || sum < (unsigned)engaged * OUTPUT_GROW_PM) return;
    }
    if (atomic_load(&o->stop)) return;
    if (!atomic_compare_exchange_strong(&o->last_grow, &last, now)) return;

    /* 1. a parked thread is the cheapest */
    for (int i = o->min_active; i < o->nsyslog; i++) {
        int parked = W_PARKED;
        if (atomic_compare_exchange_strong(&o->w[i].state, &parked, W_ENGAGED)) {
            atomic_fetch_add(&o->active, 1);
            ringbuf_waiter_kick(o->rb, o->w[i].waiter);
            return;
        }
    }
    /* 2. a new thread in an empty slot (joining one that exited first) */
    atomic_store(&o->growing, 1);
    if (atomic_load(&o->stop)) { atomic_store(&o->growing, 0); return; }
    for (int i = o->min_active; i < o->nsyslog; i++) {
        int st = atomic_load(&o->w[i].state);
        if (st == W_EXITED) {
            ns_thread_join(o->w[i].thread);
            atomic_store(&o->w[i].state, W_NONE);
            st = W_NONE;
        }
        if (st != W_NONE) continue;
        atomic_store(&o->w[i].state, W_ENGAGED);
        atomic_fetch_add(&o->active, 1);
        if (slot_start(o, i) != 0) {
            atomic_fetch_sub(&o->active, 1);
            atomic_store(&o->w[i].state, W_NONE);
        }
        break;
    }
    atomic_store(&o->growing, 0);
}

/* Should this helper park? When the others would still average no more
 * than OUTPUT_SHRINK_PM busy without it. Rate-limited, so two helpers
 * looking at the same numbers do not both leave. */
static int should_park(output_t *o, long long now) {
    int engaged;
    unsigned sum = busy_sum(o, &engaged, 1000);
    if (engaged <= o->min_active || engaged <= 1) return 0;
    if (sum > (unsigned)(engaged - 1) * OUTPUT_SHRINK_PM) return 0;
    long long last = atomic_load_explicit(&o->last_shrink, memory_order_relaxed);
    if (now - last < OUTPUT_SHRINK_NS) return 0;
    return atomic_compare_exchange_strong(&o->last_shrink, &last, now);
}

/* Wait, parked, for a peer's wake-up. 1: woken (state is ENGAGED again);
 * 0: the thread should exit — idle for idle_exit_ms, or stopped. */
static int park_wait(output_worker_t *w) {
    output_t *o = w->o;
    long long start = mono_ns();
    for (;;) {
        if (atomic_load(&o->stop)) return 0;
        if (atomic_load(&w->state) == W_ENGAGED) return 1;
        output_wait(o->rb, w->waiter);
        ringbuf_waiter_drain(o->rb, w->waiter);
        if (mono_ns() - start >= (long long)o->idle_exit_ms * 1000000LL) {
            int parked = W_PARKED;
            if (atomic_compare_exchange_strong(&w->state, &parked, W_EXITED))
                return 0;
            /* a peer woke us in the same instant: state is ENGAGED */
        }
    }
}

/* ── syslog workers ──────────────────────────────────────────── */

static void run_syslog(output_worker_t *w) {
    output_t  *o  = w->o;
    ringbuf_t *rb = o->rb;
    int helper = w->idx >= o->min_active;
    long long win_start = mono_ns(), win_busy = 0;

    if (helper && o->attached)
        ringbuf_waiter_attach_at(rb, w->waiter, atomic_load(&o->cursor));

    for (;;) {
        long long now = mono_ns();
        if (now - win_start >= OUTPUT_WINDOW_NS) {
            unsigned frac = (unsigned)(win_busy * 1000 / (now - win_start));
            if (frac > 1000) frac = 1000;
            unsigned pm = atomic_load_explicit(&w->busy_pm, memory_order_relaxed);
            atomic_store_explicit(&w->busy_pm, (pm + frac) / 2, memory_order_relaxed);
            atomic_store_explicit(&w->measured, 1, memory_order_relaxed);
            win_start = now;
            win_busy  = 0;
        }

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
            if (helper && should_park(o, now)) {
                atomic_store(&w->state, W_PARKED);
                atomic_fetch_sub(&o->active, 1);
                if (o->attached) ringbuf_waiter_detach(rb, w->waiter);
                if (!park_wait(w)) break;
                /* woken: unmeasured until a window has passed, so we are
                 * neither parked again on the numbers that preceded the
                 * wake-up nor counted as saturated */
                atomic_store(&w->busy_pm, 1000);
                atomic_store(&w->measured, 0);
                win_start = mono_ns();
                win_busy  = 0;
                if (o->attached)
                    ringbuf_waiter_attach_at(rb, w->waiter, atomic_load(&o->cursor));
                continue;
            }
            /* wanted, but momentarily idle: sleep on the ring like the
             * primary — announce, re-check, block */
            if (o->attached) ringbuf_waiter_publish(rb, w->waiter, c);
            ringbuf_waiter_will_wait(rb, w->waiter);
            if (atomic_load(&o->cursor) >= ringbuf_total(rb))
                output_wait(rb, w->waiter);
            ringbuf_waiter_drain(rb, w->waiter);
            continue;
        }

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
            continue;   /* a peer took it: look again (never yield here — on a
                           crowded CPU that hands the core away for milliseconds) */
        if (o->attached) ringbuf_waiter_publish(rb, w->waiter, c);

        long long t0 = mono_ns();
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
        long long t1 = mono_ns();
        win_busy += t1 - t0;
        if (o->attached) ringbuf_waiter_publish(rb, w->waiter, c + n);
        maybe_grow(o, t1);
    }

    if (helper) {
        atomic_store(&w->state, W_EXITED);
        atomic_fetch_sub(&o->alive, 1);
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
    o->idle_exit_ms = OUTPUT_IDLE_EXIT_MS;
    if (stream_name)
        snprintf(o->stream_name, sizeof(o->stream_name), "%s", stream_name);
    atomic_store(&o->stop, 0);
    atomic_store(&o->growing, 0);
    atomic_store(&o->streamed, 0);
    atomic_store(&o->cursor, 0);
    atomic_store(&o->skipped, 0);
    atomic_store(&o->last_grow, 0);
    atomic_store(&o->last_shrink, 0);

    /* Sockets: the one we were given plus clones, one per possible thread. */
    syslog_out_t *sls[OUTPUT_MAX_THREADS];
    int ns = 0;
    if (sl) {
        if (max_threads < 1) max_threads = 1;
        if (max_threads > OUTPUT_MAX_THREADS) max_threads = OUTPUT_MAX_THREADS;
        sls[ns++] = sl;
        while (ns < max_threads) {
            syslog_out_t *c = syslog_out_clone(sl);
            if (!c) {
                fprintf(stderr, "syslog: cannot open socket %d of %d; at most %d "
                                "output thread(s)\n", ns + 1, max_threads, ns);
                break;
            }
            sls[ns++] = c;
        }
    }

    /* Worker slots: one per syslog socket, plus the stream's own. */
    int nw = ns + (pw ? 1 : 0);
    if (nw == 0) nw = 1;           /* nothing to do, but the object works */

    /* Ring slots. When short, shed syslog slots, never the stream. */
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
        fprintf(stderr, "output: only %d ring slot(s) free; at most %d syslog "
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
        atomic_store(&w->state, W_NONE);
        atomic_store(&w->busy_pm, 1000);
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
    atomic_store(&o->active, 0);
    atomic_store(&o->alive, 0);
    atomic_store(&o->hwm, 0);
    if (ns > 1) {
        if (o->min_active == ns)
            fprintf(stderr, "Syslog output: %d threads, one socket each\n", ns);
        else
            fprintf(stderr, "Syslog output: %d-%d threads (created and retired "
                            "with the load), one socket each\n", o->min_active, ns);
    }
    return o;
}

void output_set_idle_exit_ms(output_t *o, int ms) {
    if (o && ms > 0) o->idle_exit_ms = ms;
}

void output_attach_position(output_t *o) {
    if (!o) return;
    for (int i = 0; i < o->nworkers; i++) {
        output_worker_t *w = &o->w[i];
        if (w->is_stream || w->idx < o->min_active)
            ringbuf_waiter_attach(o->rb, w->waiter);   /* helpers attach when they start */
    }
    o->attached = 1;
}

int output_start(output_t *o) {
    if (!o) return -1;
    for (int i = 0; i < o->nworkers; i++) {
        output_worker_t *w = &o->w[i];
        if (!w->is_stream && w->idx >= o->min_active) continue;   /* created on demand */
        int rc;
        if (w->is_stream) {
            rc = ns_thread_create(&w->thread, output_thread_fn, w);
        } else {
            atomic_store(&w->state, W_ENGAGED);
            atomic_fetch_add(&o->active, 1);
            rc = slot_start(o, w->idx);
        }
        if (rc != 0) {
            fprintf(stderr, "Failed to create output thread\n");
            if (!w->is_stream) { atomic_store(&w->state, W_NONE); atomic_fetch_sub(&o->active, 1); }
            o->started = 1;
            output_stop(o);
            return -1;
        }
    }
    o->started = 1;
    return 0;
}

void output_stop(output_t *o) {
    if (!o || !o->started) return;
    atomic_store(&o->stop, 1);
    while (atomic_load(&o->growing)) yield_cpu();     /* a creation in flight */
    for (int i = 0; i < o->nworkers; i++) {
        output_worker_t *w = &o->w[i];
        if (!w->is_stream && atomic_load(&w->state) == W_NONE) continue;
        ringbuf_waiter_kick(o->rb, w->waiter);
    }
    for (int i = 0; i < o->nworkers; i++) {
        output_worker_t *w = &o->w[i];
        if (!w->is_stream && atomic_load(&w->state) == W_NONE) continue;
        ns_thread_join(w->thread);
        atomic_store(&w->state, W_NONE);
    }
    atomic_store(&o->alive, 0);
    atomic_store(&o->active, 0);
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
        int a = atomic_load(&o->alive);
        out->syslog_alive   = a;
        out->syslog_threads = atomic_exchange(&o->hwm, a);
        if (out->syslog_threads < a) out->syslog_threads = a;
    }
}

int output_syslog_threads(const output_t *o) {
    return o ? o->nsyslog : 0;
}
