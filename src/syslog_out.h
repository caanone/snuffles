#ifndef SYSLOG_OUT_H
#define SYSLOG_OUT_H

#include "snuffles.h"

typedef struct syslog_out syslog_out_t;

/* Records queued per sendmmsg() (Linux); other platforms send one datagram
 * per record from the same queue. */
#define SYSLOG_BATCH 32

/* Sockets one --syslog target may fan out over (--syslog-threads). */
#define SYSLOG_MAX_SOCKETS 16

/* Open the UDP socket. Call BEFORE ns_drop_privileges(): the 16 MB send
 * buffer (SO_SNDBUFFORCE) and SO_BINDTODEVICE need capabilities. */
syslog_out_t   *syslog_out_create(const char *host_port,
                                   const char *src_iface);
/* Another socket to the same collector, bound like the original (same
 * source address/device), for a second output thread. Prints nothing:
 * the original already announced the target. NULL on failure. */
syslog_out_t   *syslog_out_clone(const syslog_out_t *sl);
/* Make every object in the group recognise every group member's own
 * datagrams in syslog_out_is_self(): a record lands on whichever thread
 * its sequence number selects, not on the socket that sent it. Call once
 * after cloning, before the threads start. */
void            syslog_out_link(syslog_out_t *const *sls, unsigned n);
/* The socket's own UDP source port (0 if unknown). */
uint16_t        syslog_out_src_port(const syslog_out_t *sl);
int             syslog_out_is_self(const syslog_out_t *sl, const pkt_summary_t *pkt);
/* Format one CSV record into the outgoing batch (output thread only).
 * Flushes by itself once SYSLOG_BATCH records are queued; the output
 * thread calls syslog_out_flush() whenever it catches up with the ring so
 * a record never waits longer than one wake-up. */
void            syslog_out_send(syslog_out_t *sl, const pkt_summary_t *pkt);
/* Transmit everything queued. Never blocks: datagrams the kernel cannot
 * take (EAGAIN/ENOBUFS, send buffer full) are dropped and counted as
 * failed. Output thread only (also safe after the thread has been joined). */
void            syslog_out_flush(syslog_out_t *sl);
/* Records queued and not yet handed to the kernel. */
unsigned        syslog_out_pending(const syslog_out_t *sl);
/* Cumulative datagrams handed to the kernel / dropped (thread-safe). */
void            syslog_out_counts(const syslog_out_t *sl, uint64_t *sent,
                                  uint64_t *failed);
void            syslog_out_destroy(syslog_out_t *sl);

#endif /* SYSLOG_OUT_H */
