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
 * One worker ('snf-output') serves both sinks by default. --syslog-threads
 * N > 1 runs N syslog workers ('snf-syslogK'), each with its own UDP
 * socket, taking every Nth record by sequence number (a datagram costs a
 * few microseconds of kernel time, which is what bounds one thread); the
 * -w stream then has a worker of its own ('snf-stream'), since it needs
 * every record. */

#define OUTPUT_MAX_THREADS SYSLOG_MAX_SOCKETS

typedef struct output output_t;

typedef struct {
    uint64_t    syslog_sent;    /* datagrams handed to the kernel, all sockets */
    uint64_t    syslog_failed;  /* datagrams the kernel would not take */
    uint64_t    streamed;       /* packets written by -w */
    uint64_t    missed;         /* records the syslog path never saw: the ring
                                   lapped them or the slot was overwritten
                                   mid-read (summed over the syslog workers;
                                   the stream worker's when there is no syslog) */
    uint64_t    stream_missed;  /* the same for the -w path (equal to missed
                                   when one worker serves both sinks) */
} output_stats_t;

/* Takes ownership of sl and pw (either may be NULL; nothing to do with
 * both NULL, but the object still works). syslog_threads (1..
 * OUTPUT_MAX_THREADS) is the number of syslog workers and sockets; fewer
 * are used, with a warning, if a socket or a ring waiter slot cannot be
 * had. Each worker takes a waiter slot on the ring (ringbuf_waiter_add):
 * call it before the producer starts. stream_name is printed with the
 * count at destroy time (-w path). */
output_t       *output_create(ringbuf_t *rb, syslog_out_t *sl, int syslog_threads,
                              pcap_writer_t *pw, const char *stream_name);
/* Offline replay: publish every worker's position so the reader waits for
 * the slowest instead of lapping the ring. Before output_start(). */
void            output_attach_position(output_t *o);
int             output_start(output_t *o);
/* Stop the capture first: the workers emit every record committed by
 * then, flush both sinks and exit; this joins them. */
void            output_stop(output_t *o);
/* Closes the sinks (prints 'Streamed N packets to ...') and frees o. */
void            output_destroy(output_t *o);
void            output_get_stats(const output_t *o, output_stats_t *out);
/* Syslog workers actually running (0 without --syslog). */
int             output_syslog_threads(const output_t *o);

#endif /* OUTPUT_H */
