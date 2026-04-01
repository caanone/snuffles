#ifndef SESSION_H
#define SESSION_H

#include "snuffles.h"

/* ── TCP session states ──────────────────────────────────────── */

typedef enum {
    SESS_NEW = 0,
    SESS_SYN_SENT,
    SESS_ESTABLISHED,
    SESS_CLOSING,
    SESS_CLOSED,
    SESS_RST,
} session_state_t;

/* ── Session key (normalized 5-tuple) ────────────────────────── */

typedef struct {
    char     ip_a[46];
    char     ip_b[46];
    uint16_t port_a;
    uint16_t port_b;
    uint8_t  proto;     /* proto_id_t (l4_proto) */
} session_key_t;

/* ── Session entry ───────────────────────────────────────────── */

typedef struct session_entry {
    session_key_t       key;
    uint32_t            id;
    uint64_t            pkts_a_to_b;
    uint64_t            pkts_b_to_a;
    uint64_t            bytes_a_to_b;
    uint64_t            bytes_b_to_a;
    struct timeval      first_seen;
    struct timeval      last_seen;
    session_state_t     tcp_state;
    uint8_t             tcp_flags_seen;
    struct session_entry *next;     /* hash chain */
} session_entry_t;

/* ── Sort modes ──────────────────────────────────────────────── */

typedef enum {
    SORT_BYTES,
    SORT_PACKETS,
    SORT_RECENT,
    SORT_DURATION,
} session_sort_t;

/* ── Session table ───────────────────────────────────────────── */

typedef struct {
    session_entry_t   **buckets;
    uint32_t            bucket_count;
    uint32_t            session_count;
    uint32_t            next_id;
    uint32_t            max_sessions;   /* evict oldest when exceeded */
    ns_mutex_t          mtx;
} session_table_t;

#define SESSION_DEFAULT_MAX  100000

session_table_t    *session_table_create(uint32_t bucket_count);
void                session_table_destroy(session_table_t *st);
session_entry_t    *session_table_update(session_table_t *st,
                                         const pkt_summary_t *pkt);
void                session_table_clear(session_table_t *st);
uint32_t            session_table_count(const session_table_t *st);

/* Returns malloc'd array of pointers (caller frees the array, not entries). */
session_entry_t   **session_table_snapshot(session_table_t *st,
                                            uint32_t *out_count,
                                            session_sort_t sort);

const char         *session_state_str(session_state_t s);

#endif /* SESSION_H */
