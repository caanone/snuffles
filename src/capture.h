#ifndef CAPTURE_H
#define CAPTURE_H

#include "snuffles.h"
#include "ringbuf.h"
#include "session.h"

typedef struct {
    uint64_t    pkts_recv;
    uint64_t    pkts_drop;
    uint64_t    bytes_total;
} capture_stats_raw_t;

typedef struct capture_ctx capture_ctx_t;

capture_ctx_t  *capture_create(const capture_cfg_t *cfg, ringbuf_t *rb,
                               session_table_t *st);
int             capture_start(capture_ctx_t *ctx);
void            capture_stop(capture_ctx_t *ctx);
void            capture_destroy(capture_ctx_t *ctx);
int             capture_is_running(const capture_ctx_t *ctx);
int             capture_is_offline(const capture_ctx_t *ctx);
void            capture_get_stats(capture_ctx_t *ctx, capture_stats_raw_t *out);
const char     *capture_get_iface(const capture_ctx_t *ctx);
const char     *capture_get_bpf(const capture_ctx_t *ctx);
int             capture_set_bpf(capture_ctx_t *ctx, const char *expr,
                                char *errbuf, size_t errlen);
int             capture_list_interfaces(void);

#endif /* CAPTURE_H */
