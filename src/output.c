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

struct output {
    ringbuf_t           *rb;
    syslog_out_t        *syslog;    /* owned; NULL: no --syslog */
    pcap_writer_t       *stream;    /* owned; NULL: no -w (or it failed) */
    char                 stream_name[512];
    int                  waiter;    /* ring waiter slot */
    int                  attached;  /* position published (offline replay) */
    ns_thread_t          thread;
    int                  started;
    atomic_int           stop;
    atomic_uint_fast64_t streamed;
    atomic_uint_fast64_t missed;
};

/* Longest sleep between looks at the ring; the wakeup usually ends it
 * long before, this only bounds how late the thread notices stop. */
#define OUTPUT_WAIT_MS 100

static void output_wait(output_t *o) {
#ifdef _WIN32
    WaitForSingleObject(o->rb->waiters[o->waiter].event, OUTPUT_WAIT_MS);
#else
    int fd = ringbuf_waiter_fd(o->rb, o->waiter);
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(fd, &fds);
    struct timeval tv = { .tv_sec = 0, .tv_usec = OUTPUT_WAIT_MS * 1000 };
    select(fd + 1, &fds, NULL, NULL, &tv);
#endif
}

static void *output_thread_fn(void *arg) {
    output_t  *o  = (output_t *)arg;
    ringbuf_t *rb = o->rb;
#ifdef __linux__
    prctl(PR_SET_NAME, "snf-output", 0, 0, 0);
#endif

    /* -w needs the packet bytes: they are copied out of the ring into
     * this thread-local buffer, since the slot may be overwritten while
     * the write is in progress. */
    uint8_t *data = NULL;
    if (o->stream) {
        data = malloc(rb->snaplen);
        if (!data) {
            fprintf(stderr, "output: out of memory; disabling -w output\n");
            pcap_writer_close(o->stream);
            o->stream = NULL;
        }
    }

    uint64_t last = 0;   /* next sequence to emit */

    for (;;) {
        /* Same protocol as the headless printer: announce a wait only when
         * nothing is pending, re-check, then block on our slot. A stop
         * request ends the loop once everything committed has gone out
         * (the capture thread is joined before stop is set). */
        if (ringbuf_total(rb) <= last) {
            if (atomic_load(&o->stop)) break;
            ringbuf_waiter_will_wait(rb, o->waiter);
            if (ringbuf_total(rb) <= last)
                output_wait(o);
        }
        ringbuf_waiter_drain(rb, o->waiter);

        uint64_t total  = ringbuf_total(rb);
        uint64_t oldest = ringbuf_oldest(rb);
        if (last < oldest) {
            /* the ring wrapped past us (or was cleared): those are gone */
            atomic_fetch_add_explicit(&o->missed, oldest - last,
                                      memory_order_relaxed);
            last = oldest;
        }

        while (last < total) {
            pkt_record_t rec;
            if (ringbuf_read_seq(rb, last, &rec, data)) {
                /* skip our own syslog traffic to prevent a feedback loop */
                if (o->syslog && !syslog_out_is_self(o->syslog, &rec.summary))
                    syslog_out_send(o->syslog, &rec.summary);
                if (o->stream) {
                    if (pcap_writer_write(o->stream, &rec) != 0) {
                        fprintf(stderr, "stream write failed; disabling -w "
                                        "output\n");
                        pcap_writer_close(o->stream);
                        o->stream = NULL;
                    } else {
                        atomic_fetch_add_explicit(&o->streamed, 1,
                                                  memory_order_relaxed);
                    }
                }
            } else {
                atomic_fetch_add_explicit(&o->missed, 1, memory_order_relaxed);
            }
            last++;
            if (o->attached) ringbuf_waiter_publish(rb, o->waiter, last);
        }

        /* Caught up: the syslog batch leaves now (one sendmmsg per batch,
         * so a record waits at most one wakeup at low rates) and the -w
         * buffer goes to the file before we block. Under load neither
         * happens per packet: the batch fills and the 1 MB buffer wraps. */
        syslog_out_flush(o->syslog);
        if (o->stream) pcap_writer_flush(o->stream);
    }

    free(data);
    return NULL;
}

/* ── public API ──────────────────────────────────────────────── */

output_t *output_create(ringbuf_t *rb, syslog_out_t *sl, pcap_writer_t *pw,
                        const char *stream_name) {
    output_t *o = calloc(1, sizeof(*o));
    if (!o) return NULL;
    o->rb     = rb;
    o->syslog = sl;
    o->stream = pw;
    if (stream_name)
        snprintf(o->stream_name, sizeof(o->stream_name), "%s", stream_name);
    o->waiter = ringbuf_waiter_add(rb);
    if (o->waiter < 0) {
        fprintf(stderr, "output: no ring waiter slot free\n");
        free(o);
        return NULL;
    }
    atomic_store(&o->stop, 0);
    atomic_store(&o->streamed, 0);
    atomic_store(&o->missed, 0);
    return o;
}

void output_attach_position(output_t *o) {
    if (!o) return;
    ringbuf_waiter_attach(o->rb, o->waiter);
    o->attached = 1;
}

int output_start(output_t *o) {
    if (!o) return -1;
    if (ns_thread_create(&o->thread, output_thread_fn, o) != 0) {
        fprintf(stderr, "Failed to create output thread\n");
        return -1;
    }
    o->started = 1;
    return 0;
}

void output_stop(output_t *o) {
    if (!o || !o->started) return;
    atomic_store(&o->stop, 1);
    ns_thread_join(o->thread);
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
    syslog_out_destroy(o->syslog);
    free(o);
}

void output_get_stats(const output_t *o, output_stats_t *out) {
    memset(out, 0, sizeof(*out));
    if (!o) return;
    syslog_out_counts(o->syslog, &out->syslog_sent, &out->syslog_failed);
    out->streamed = atomic_load_explicit(&o->streamed, memory_order_relaxed);
    out->missed   = atomic_load_explicit(&o->missed, memory_order_relaxed);
}
