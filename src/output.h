#ifndef OUTPUT_H
#define OUTPUT_H

#include "snuffles.h"
#include "ringbuf.h"
#include "syslog_out.h"
#include "export_pcap.h"

/* Output workers: the --syslog and -w sinks, fed from the ring by sequence
 * like the headless printer, so a slow collector or disk never slows the
 * capture thread. Records the ring overwrote before a worker reached them
 * are counted, not waited for.
 *
 * Syslog threads come and go with the traffic. One socket per possible
 * thread is opened at creation (sockets need privileges that are dropped
 * once capture is open), but only min_threads threads exist from the
 * start. Workers claim records in 32-record chunks from a shared cursor,
 * so any number of them can share the stream. The primary meters the
 * arrival rate and each thread its service rate (records per second of
 * busy time). A running worker wakes a parked thread or, failing that,
 * creates a new one (at most one every 2 ms, up to max_threads) when the
 * backlog would not drain, at those rates, within half the time the ring
 * has left before it laps — or, until the rates are measured, when the
 * backlog exceeds an eighth of the ring; half a ring grows the pool
 * regardless. A helper parks when the others' capacity covers the
 * arrival at no more than 80 % load, and a parked thread exits after 3 s
 * without work. The -w stream has a sequential worker of its own, since a
 * capture file must hold every record in order. */

#define OUTPUT_MAX_THREADS SYSLOG_MAX_SOCKETS

typedef struct output output_t;

typedef struct {
    uint64_t    syslog_sent;    /* datagrams handed to the kernel, all sockets */
    uint64_t    syslog_failed;  /* datagrams the kernel would not take */
    uint64_t    streamed;       /* packets written by -w */
    uint64_t    missed;         /* records the syslog path never saw: the ring
                                   lapped them before a worker claimed them, or
                                   the slot was overwritten mid-read (the
                                   stream worker's when there is no syslog) */
    uint64_t    stream_missed;  /* the same for the -w path */
    int         syslog_threads; /* most syslog threads alive at once since the
                                   previous call (0 without --syslog) */
    int         syslog_alive;   /* syslog threads alive now */
} output_stats_t;

/* Takes ownership of sl and pw (either may be NULL; nothing to do with
 * both NULL, but the object still works). min_threads..max_threads (1..
 * OUTPUT_MAX_THREADS) bound the syslog threads; fewer are possible, with
 * a warning, if a socket or a ring waiter slot cannot be had. Each
 * possible worker takes a waiter slot on the ring (ringbuf_waiter_add):
 * call it before the producer starts. stream_name is printed with the
 * count at destroy time (-w path). */
output_t       *output_create(ringbuf_t *rb, syslog_out_t *sl, int min_threads,
                              int max_threads, pcap_writer_t *pw,
                              const char *stream_name);
/* How long a parked syslog thread waits for work before it exits
 * (default 3000 ms). Before output_start(). */
void            output_set_idle_exit_ms(output_t *o, int ms);
/* Offline replay: publish the running workers' positions so the reader
 * waits for the slowest instead of lapping the ring (threads created later
 * publish theirs while they run). Before output_start(). */
void            output_attach_position(output_t *o);
int             output_start(output_t *o);
/* Stop the capture first: the workers emit every record committed by
 * then, flush both sinks and exit; this joins them. */
void            output_stop(output_t *o);
/* Closes the sinks (prints 'Streamed N packets to ...') and frees o. */
void            output_destroy(output_t *o);
/* Counters; resets the syslog_threads high-water mark to the alive count. */
void            output_get_stats(output_t *o, output_stats_t *out);
/* Syslog threads possible, i.e. sockets (0 without --syslog). */
int             output_syslog_threads(const output_t *o);

#endif /* OUTPUT_H */
