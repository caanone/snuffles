#include "output.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>

#ifndef _WIN32
  #include <unistd.h>
  #include <sys/select.h>
  #include <sys/time.h>
#endif
#ifdef __linux__
  #include <sys/prctl.h>
#endif

/* One thread. It owns the sequences first, first + step, first + 2*step,
 * ...: a lone worker has step 1, syslog shard k of N has first k, step N,
 * and the stream worker has step 1 again. */
typedef struct {
    output_t            *o;
    syslog_out_t        *syslog;    /* owned; NULL: no syslog on this worker */
    pcap_writer_t       *stream;    /* o->stream while it is open, else NULL */
    int                  is_stream; /* this worker serves -w */
    int                  waiter;    /* ring waiter slot */
    uint64_t             first;
    uint64_t             step;
    char                 name[16];
    ns_thread_t          thread;
    atomic_uint_fast64_t missed;
} output_worker_t;

struct output {
    ringbuf_t           *rb;
    pcap_writer_t       *stream;    /* owned; NULL: no -w (or it failed) */
    char                 stream_name[512];
    output_worker_t      w[OUTPUT_MAX_THREADS + 1];
    int                  nworkers;
    int                  nsyslog;   /* workers with a syslog socket */
    int                  attached;  /* positions published (offline replay) */
    int                  started;
    atomic_int           stop;
    atomic_uint_fast64_t streamed;
};

/* Longest sleep between looks at the ring; the wakeup usually ends it
 * long before, this only bounds how late a worker notices stop. */
#define OUTPUT_WAIT_MS 100

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

static void *output_thread_fn(void *arg) {
    output_worker_t *w  = (output_worker_t *)arg;
    output_t        *o  = w->o;
    ringbuf_t       *rb = o->rb;
#ifdef __linux__
    prctl(PR_SET_NAME, w->name, 0, 0, 0);
#endif

    /* -w needs the packet bytes: they are copied out of the ring into
     * this thread-local buffer, since the slot may be overwritten while
     * the write is in progress. */
    uint8_t *data = NULL;
    if (w->stream) {
        data = malloc(rb->snaplen);
        if (!data) {
            fprintf(stderr, "output: out of memory; disabling -w output\n");
            pcap_writer_close(o->stream);
            o->stream = w->stream = NULL;
        }
    }

    uint64_t       last = w->first;   /* next sequence of ours to emit */
    const uint64_t step = w->step;

    for (;;) {
        /* Same protocol as the headless printer: announce a wait only when
         * nothing is pending, re-check, then block on our slot. A stop
         * request ends the loop once everything committed has gone out
         * (the capture thread is joined before stop is set). */
        if (ringbuf_total(rb) <= last) {
            if (atomic_load(&o->stop)) break;
            ringbuf_waiter_will_wait(rb, w->waiter);
            if (ringbuf_total(rb) <= last)
                output_wait(rb, w->waiter);
        }
        ringbuf_waiter_drain(rb, w->waiter);

        uint64_t total  = ringbuf_total(rb);
        uint64_t oldest = ringbuf_oldest(rb);
        if (last < oldest) {
            /* the ring wrapped past us (or was cleared): our sequences in
             * [last, oldest) are gone; land on the first one at or after
             * the floor */
            uint64_t gone = (oldest - last + step - 1) / step;
            atomic_fetch_add_explicit(&w->missed, gone, memory_order_relaxed);
            last += gone * step;
        }

        while (last < total) {
            pkt_record_t rec;
            if (ringbuf_read_seq(rb, last, &rec, data)) {
                /* skip our own syslog traffic to prevent a feedback loop */
                if (w->syslog && !syslog_out_is_self(w->syslog, &rec.summary))
                    syslog_out_send(w->syslog, &rec.summary);
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
            last += step;
            if (o->attached) ringbuf_waiter_publish(rb, w->waiter, last);
        }

        /* Caught up: the syslog batch leaves now (one sendmmsg per batch,
         * so a record waits at most one wakeup at low rates) and the -w
         * buffer goes to the file before we block. Under load neither
         * happens per packet: the batch fills and the 1 MB buffer wraps. */
        syslog_out_flush(w->syslog);
        if (w->stream) pcap_writer_flush(w->stream);
    }

    free(data);
    return NULL;
}

/* ── public API ──────────────────────────────────────────────── */

output_t *output_create(ringbuf_t *rb, syslog_out_t *sl, int syslog_threads,
                        pcap_writer_t *pw, const char *stream_name) {
    output_t *o = calloc(1, sizeof(*o));
    if (!o) return NULL;
    o->rb     = rb;
    o->stream = pw;
    if (stream_name)
        snprintf(o->stream_name, sizeof(o->stream_name), "%s", stream_name);
    atomic_store(&o->stop, 0);
    atomic_store(&o->streamed, 0);

    /* Sockets: the one we were given plus clones for the other shards. */
    syslog_out_t *sls[OUTPUT_MAX_THREADS];
    int ns = 0;
    if (sl) {
        if (syslog_threads < 1) syslog_threads = 1;
        if (syslog_threads > OUTPUT_MAX_THREADS) syslog_threads = OUTPUT_MAX_THREADS;
        sls[ns++] = sl;
        while (ns < syslog_threads) {
            syslog_out_t *c = syslog_out_clone(sl);
            if (!c) {
                fprintf(stderr, "syslog: cannot open socket %d of %d; using %d "
                                "output thread(s)\n", ns + 1, syslog_threads, ns);
                break;
            }
            sls[ns++] = c;
        }
    }

    /* Workers: one per syslog socket; the stream shares the worker when
     * there is at most one socket, otherwise it gets its own. */
    int stream_own = (pw && ns > 1);
    int nw = (ns ? ns : 1) + (stream_own ? 1 : 0);

    /* Ring slots. When short, shed syslog shards, never the stream. */
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
        int keep = stream_own ? got - 1 : got;
        if (keep < 1) { keep = 1; stream_own = 0; }
        fprintf(stderr, "output: only %d ring slot(s) free; using %d syslog "
                        "thread(s)\n", got, keep);
        for (int i = keep; i < ns; i++) syslog_out_destroy(sls[i]);
        ns = keep;
        nw = ns + (stream_own ? 1 : 0);
    }
    if (ns > 1) syslog_out_link(sls, (unsigned)ns);

    int k = 0;
    if (ns == 0) {
        /* -w only (or nothing at all) */
        output_worker_t *w = &o->w[k];
        w->stream = pw; w->is_stream = (pw != NULL);
        w->first = 0; w->step = 1;
        snprintf(w->name, sizeof(w->name), "snf-output");
        k++;
    } else {
        for (int i = 0; i < ns; i++) {
            output_worker_t *w = &o->w[k];
            w->syslog = sls[i];
            if (!stream_own && i == 0) { w->stream = pw; w->is_stream = (pw != NULL); }
            w->first = (uint64_t)i; w->step = (uint64_t)ns;
            if (ns == 1) snprintf(w->name, sizeof(w->name), "snf-output");
            else         snprintf(w->name, sizeof(w->name), "snf-syslog%d", i);
            k++;
        }
        if (stream_own) {
            output_worker_t *w = &o->w[k];
            w->stream = pw; w->is_stream = 1;
            w->first = 0; w->step = 1;
            snprintf(w->name, sizeof(w->name), "snf-stream");
            k++;
        }
    }
    for (int i = 0; i < k; i++) {
        o->w[i].o      = o;
        o->w[i].waiter = slots[i];
        atomic_store(&o->w[i].missed, 0);
    }
    o->nworkers = k;
    o->nsyslog  = ns;
    if (ns > 1)
        fprintf(stderr, "Syslog output: %d threads, one socket each\n", ns);
    return o;
}

void output_attach_position(output_t *o) {
    if (!o) return;
    for (int i = 0; i < o->nworkers; i++)
        ringbuf_waiter_attach(o->rb, o->w[i].waiter);
    o->attached = 1;
}

int output_start(output_t *o) {
    if (!o) return -1;
    for (int i = 0; i < o->nworkers; i++) {
        if (ns_thread_create(&o->w[i].thread, output_thread_fn, &o->w[i]) != 0) {
            fprintf(stderr, "Failed to create output thread\n");
            atomic_store(&o->stop, 1);
            for (int j = 0; j < i; j++) ns_thread_join(o->w[j].thread);
            return -1;
        }
    }
    o->started = 1;
    return 0;
}

void output_stop(output_t *o) {
    if (!o || !o->started) return;
    atomic_store(&o->stop, 1);
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

void output_get_stats(const output_t *o, output_stats_t *out) {
    memset(out, 0, sizeof(*out));
    if (!o) return;
    uint64_t all = 0, sys = 0, str = 0;
    for (int i = 0; i < o->nworkers; i++) {
        const output_worker_t *w = &o->w[i];
        uint64_t m = atomic_load_explicit(&w->missed, memory_order_relaxed);
        all += m;
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
    out->missed        = o->nsyslog ? sys : all;
    out->stream_missed = str;
}

int output_syslog_threads(const output_t *o) {
    return o ? o->nsyslog : 0;
}
