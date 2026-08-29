#ifndef UI_H
#define UI_H

#include "snuffles.h"
#include "ringbuf.h"
#include "capture.h"
#include "filter.h"
#include "stats.h"
#include "session.h"
#include "config.h"

typedef struct ui_ctx ui_ctx_t;

/* presets may be NULL/0; the caller keeps the array alive for the UI's
 * lifetime (the ctx stores the pointer, not a copy). */
/* sts is the capture's session shards (one per worker, may be NULL/0);
   the UI shows their union. */
ui_ctx_t   *ui_create(ringbuf_t *rb, capture_ctx_t *cap,
                       const capture_cfg_t *cfg, session_table_t *const *sts,
                       int nsts, const filter_preset_t *presets, int npresets);
void        ui_destroy(ui_ctx_t *ctx);
void        ui_run(ui_ctx_t *ctx);
void        ui_request_stop(ui_ctx_t *ctx);
/* Async-signal-safe: sets a flag the UI loop polls; no context needed. */
void        ui_request_stop_async(void);

#endif /* UI_H */
