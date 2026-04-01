#include "stats.h"
#include <stdio.h>
#include <string.h>

#ifndef _WIN32
  #include <sys/time.h>
#endif

static double tv_diff_sec(const struct timeval *a, const struct timeval *b) {
    return (double)(a->tv_sec - b->tv_sec) +
           (double)(a->tv_usec - b->tv_usec) / 1e6;
}

static void tv_now(struct timeval *tv) {
#ifdef _WIN32
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    uint64_t t = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    t -= 116444736000000000ULL;
    tv->tv_sec  = (long)(t / 10000000);
    tv->tv_usec = (long)((t / 10) % 1000000);
#else
    gettimeofday(tv, NULL);
#endif
}

void stats_init(stats_t *s) {
    memset(s, 0, sizeof(*s));
    tv_now(&s->start_time);
    s->win_start = s->start_time;
}

void stats_update(stats_t *s, const pkt_summary_t *pkt) {
    s->total_packets++;
    s->total_bytes += pkt->length;
    s->win_packets++;
    s->win_bytes += pkt->length;
    if (pkt->highest_proto < PROTO_MAX)
        s->proto_counts[pkt->highest_proto]++;
}

void stats_compute_rates(stats_t *s) {
    struct timeval now;
    tv_now(&now);

    double elapsed = tv_diff_sec(&now, &s->win_start);
    if (elapsed >= 1.0) {
        s->pps = (double)s->win_packets / elapsed;
        s->bps = (double)s->win_bytes * 8.0 / elapsed;
        s->win_packets = 0;
        s->win_bytes   = 0;
        s->win_start   = now;
    }
}

static void format_bytes(uint64_t bytes, char *buf, size_t len) {
    if (bytes >= 1073741824ULL)
        snprintf(buf, len, "%.1f GB", (double)bytes / 1073741824.0);
    else if (bytes >= 1048576ULL)
        snprintf(buf, len, "%.1f MB", (double)bytes / 1048576.0);
    else if (bytes >= 1024ULL)
        snprintf(buf, len, "%.1f KB", (double)bytes / 1024.0);
    else
        snprintf(buf, len, "%lu B", (unsigned long)bytes);
}

static void format_rate(double bps, char *buf, size_t len) {
    if (bps >= 1e9)
        snprintf(buf, len, "%.1f Gbps", bps / 1e9);
    else if (bps >= 1e6)
        snprintf(buf, len, "%.1f Mbps", bps / 1e6);
    else if (bps >= 1e3)
        snprintf(buf, len, "%.1f Kbps", bps / 1e3);
    else
        snprintf(buf, len, "%.0f bps", bps);
}

void stats_format(const stats_t *s, char *buf, size_t len) {
    char bytes_str[32], rate_str[32];
    format_bytes(s->total_bytes, bytes_str, sizeof(bytes_str));
    format_rate(s->bps, rate_str, sizeof(rate_str));

    snprintf(buf, len, "Pkts: %lu  %s  PPS: %.1f  %s",
             (unsigned long)s->total_packets, bytes_str, s->pps, rate_str);
}
