#ifndef STATS_H
#define STATS_H

#include "snuffles.h"

typedef struct {
    uint64_t        total_packets;
    uint64_t        total_bytes;
    uint64_t        proto_counts[PROTO_MAX];
    double          pps;
    double          bps;
    struct timeval  start_time;

    /* rolling window internals */
    uint64_t        win_packets;
    uint64_t        win_bytes;
    struct timeval  win_start;
} stats_t;

void stats_init(stats_t *s);
void stats_update(stats_t *s, const pkt_summary_t *pkt);
void stats_compute_rates(stats_t *s);
void stats_format(const stats_t *s, char *buf, size_t len);

#endif /* STATS_H */
