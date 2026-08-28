#ifndef SYSLOG_OUT_H
#define SYSLOG_OUT_H

#include "snuffles.h"

typedef struct syslog_out syslog_out_t;

syslog_out_t   *syslog_out_create(const char *host_port,
                                   const char *src_iface);
int             syslog_out_is_self(const syslog_out_t *sl, const pkt_summary_t *pkt);
void            syslog_out_send(syslog_out_t *sl, const pkt_summary_t *pkt);
/* Cumulative sendto() successes/failures (thread-safe). */
void            syslog_out_counts(const syslog_out_t *sl, uint64_t *sent,
                                  uint64_t *failed);
void            syslog_out_destroy(syslog_out_t *sl);

#endif /* SYSLOG_OUT_H */
