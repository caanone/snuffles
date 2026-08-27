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
    /* TCP stream reassembly (populated only when reasm is enabled).
     * Buffers are owned by the table and only touched under its lock;
     * snapshot copies carry NULL stream pointers. */
    uint8_t            *stream_a;       /* a->b payload bytes */
    uint8_t            *stream_b;       /* b->a payload bytes */
    uint32_t            stream_len_a;
    uint32_t            stream_len_b;
    uint32_t            next_seq_a;     /* next expected sequence number */
    uint32_t            next_seq_b;
    uint8_t             seq_init_a;
    uint8_t             seq_init_b;
    uint32_t            gaps;           /* sequence holes seen (both dirs) */
    struct session_entry *next;     /* hash chain */
    struct session_entry *lru_prev; /* intrusive LRU list (head = most recent) */
    struct session_entry *lru_next;
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
    session_entry_t    *lru_head;   /* most recently touched */
    session_entry_t    *lru_tail;   /* eviction candidate */
    uint32_t            bucket_count;
    uint32_t            session_count;
    uint32_t            next_id;
    uint32_t            max_sessions;   /* evict oldest when exceeded */
    int                 reasm_enabled;
    size_t              reasm_used;     /* stream-buffer bytes allocated */
    size_t              reasm_budget;   /* global cap on stream memory */
    ns_mutex_t          mtx;
} session_table_t;

#define SESSION_DEFAULT_MAX  100000
#define SESSION_STREAM_CAP   16384      /* per-direction per-session bytes */

session_table_t    *session_table_create(uint32_t bucket_count);
void                session_table_destroy(session_table_t *st);
/* Returns the session id the packet belongs to, or 0 if untracked.
 * payload/paylen (may be NULL/0) are the TCP payload bytes, consumed only
 * when reassembly is enabled. */
uint32_t            session_table_update(session_table_t *st,
                                         const pkt_summary_t *pkt,
                                         const uint8_t *payload,
                                         uint32_t paylen);
/* Opt in to TCP stream reassembly; budget_bytes bounds total stream memory
 * across all sessions. */
void                session_table_enable_reasm(session_table_t *st,
                                               size_t budget_bytes);
/* Copies up to cap reassembled bytes of session `id` (dir 0 = a->b) into
 * out under the table lock; returns bytes copied (0 if not found/empty). */
/* Copy both directions inside one critical section (coherent pair). */
void                session_streams_copy(session_table_t *st, uint32_t id,
                                         uint8_t *out_a, uint8_t *out_b,
                                         uint32_t cap,
                                         uint32_t *len_a, uint32_t *len_b);
uint32_t            session_stream_copy(session_table_t *st, uint32_t id,
                                        int dir, uint8_t *out, uint32_t cap);
void                session_table_clear(session_table_t *st);
uint32_t            session_table_count(const session_table_t *st);

/* Returns a malloc'd array of entry COPIES taken under the table lock
 * (caller frees the array). Entries stay valid regardless of concurrent
 * eviction/clear; their .next pointers are NULL. */
session_entry_t    *session_table_snapshot(session_table_t *st,
                                           uint32_t *out_count,
                                           session_sort_t sort);

const char         *session_state_str(session_state_t s);

#endif /* SESSION_H */
