#ifndef CAPTURE_H
#define CAPTURE_H

#include "snuffles.h"
#include "ringbuf.h"
#include "session.h"

/* -j N: N capture workers in one PACKET_FANOUT group (Linux only). */
#define CAPTURE_MAX_WORKERS 16

typedef struct {
    uint64_t    pkts_recv;
    uint64_t    pkts_drop;      /* dropped by the kernel (socket buffer full) */
    uint64_t    bytes_total;
    uint64_t    pkts_ifdrop;    /* dropped by the interface/driver (pcap only) */
    int         nworkers;
    uint64_t    kdrop_w[CAPTURE_MAX_WORKERS];   /* kernel drops per worker */
} capture_stats_raw_t;

typedef struct capture_ctx capture_ctx_t;

/* Workers the configuration will actually use (clamped, and 1 wherever
 * PACKET_FANOUT is not available) — the caller sizes the ring's producer
 * set and the session shards with it. */
int             capture_cfg_workers(const capture_cfg_t *cfg);
/* sts is one session table per worker (NULL, or fewer than nworkers, is
 * allowed: those workers keep no sessions). */
capture_ctx_t  *capture_create(const capture_cfg_t *cfg, ringbuf_t *rb,
                               session_table_t *const *sts, int nsts);
int             capture_start(capture_ctx_t *ctx);
void            capture_stop(capture_ctx_t *ctx);
void            capture_destroy(capture_ctx_t *ctx);
int             capture_is_running(const capture_ctx_t *ctx);
/* Workers actually running (1 unless -j N got its fan-out group). */
int             capture_worker_count(const capture_ctx_t *ctx);
int             capture_is_offline(const capture_ctx_t *ctx);
void            capture_get_stats(capture_ctx_t *ctx, capture_stats_raw_t *out);
const char     *capture_get_iface(const capture_ctx_t *ctx);
const char     *capture_get_bpf(const capture_ctx_t *ctx);
/* pcap linktype of the capture (DLT_EN10MB, DLT_RAW, ...) for exporters. */
int             capture_get_datalink(const capture_ctx_t *ctx);
/* Nonzero if the capture thread terminated on an error; msg valid then. */
int             capture_had_error(const capture_ctx_t *ctx);
const char     *capture_error_msg(const capture_ctx_t *ctx);
int             capture_set_bpf(capture_ctx_t *ctx, const char *expr,
                                char *errbuf, size_t errlen);
int             capture_list_interfaces(void);

#endif /* CAPTURE_H */
