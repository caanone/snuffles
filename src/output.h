#ifndef OUTPUT_H
#define OUTPUT_H

#include "snuffles.h"
#include "ringbuf.h"
#include "syslog_out.h"
#include "export_pcap.h"

/* Output thread ('snf-output'): the --syslog and -w sinks, fed from the
 * ring by sequence like the headless printer, so a slow collector or disk
 * never slows the capture thread. Records the ring overwrote before the
 * thread reached them are counted, not waited for. */

typedef struct output output_t;

typedef struct {
    uint64_t    syslog_sent;    /* datagrams handed to the kernel */
    uint64_t    syslog_failed;  /* datagrams the kernel would not take */
    uint64_t    streamed;       /* packets written by -w */
    uint64_t    missed;         /* records the ring lapped before we read them */
} output_stats_t;

/* Takes ownership of sl and pw (either may be NULL; nothing to do with
 * both NULL, but the object still works). Takes a waiter slot on the ring
 * (ringbuf_waiter_add): call it before the producer starts. stream_name
 * is printed with the count at destroy time (-w path). */
output_t       *output_create(ringbuf_t *rb, syslog_out_t *sl,
                              pcap_writer_t *pw, const char *stream_name);
/* Offline replay: publish the thread's position so the reader waits for
 * it instead of lapping the ring. Before output_start(). */
void            output_attach_position(output_t *o);
int             output_start(output_t *o);
/* Stop the capture first: the thread emits every record committed by
 * then, flushes both sinks and exits; this joins it. */
void            output_stop(output_t *o);
/* Closes the sinks (prints 'Streamed N packets to ...') and frees o. */
void            output_destroy(output_t *o);
void            output_get_stats(const output_t *o, output_stats_t *out);

#endif /* OUTPUT_H */
