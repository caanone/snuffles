#ifndef EXPORT_JSON_H
#define EXPORT_JSON_H

#include "snuffles.h"
#include "ringbuf.h"
#include "filter.h"

int export_json(const char *path, ringbuf_t *rb,
                const display_filter_t *filt,
                const char *iface, const char *bpf_filter);

#endif /* EXPORT_JSON_H */
