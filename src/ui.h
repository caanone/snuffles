#ifndef UI_H
#define UI_H

#include "snuffles.h"
#include "ringbuf.h"
#include "capture.h"
#include "filter.h"
#include "stats.h"
#include "session.h"

typedef struct ui_ctx ui_ctx_t;

ui_ctx_t   *ui_create(ringbuf_t *rb, capture_ctx_t *cap,
                       const capture_cfg_t *cfg, session_table_t *st);
void        ui_destroy(ui_ctx_t *ctx);
void        ui_run(ui_ctx_t *ctx);
void        ui_request_stop(ui_ctx_t *ctx);

#endif /* UI_H */
