#ifndef EXPORT_JSON_H
#define EXPORT_JSON_H

#include <stdio.h>
#include "snuffles.h"
#include "ringbuf.h"
#include "filter.h"

int export_json(const char *path, ringbuf_t *rb,
                const display_filter_t *filt,
                const char *iface, const char *bpf_filter);

/* Write one packet as a single JSON object on one line (JSON Lines). */
void json_line_write(FILE *f, const pkt_summary_t *s);

#endif /* EXPORT_JSON_H */
