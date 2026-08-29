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

/* ── Session key ─────────────────────────────────────────────── */

/* Display form of the normalized 5-tuple: formatted ONCE when a session is
 * created (the UI and exporters read these; the packet path never touches
 * them). Side A is the lower binary address (then lower port). */
typedef struct {
    char     ip_a[46];
    char     ip_b[46];
    uint16_t port_a;
    uint16_t port_b;
    uint8_t  proto;     /* proto_id_t (l4_proto) */
} session_key_t;

/* Lookup form: packed canonical binary tuple, compared with memcmp and
 * hashed with a seeded mixer. Both directions of a flow canonicalize to
 * the same bytes (the smaller address/port pair lands in slot A). Every
 * byte including padding is defined, so memcmp is a valid equality test. */
typedef struct {
    uint8_t  addr_a[16];    /* IPv4 in the first 4 bytes, rest zero */
    uint8_t  addr_b[16];
    uint16_t port_a;
    uint16_t port_b;
    uint8_t  proto;         /* proto_id_t (l4_proto) */
    uint8_t  family;        /* 4 or 6 */
    uint8_t  pad[2];        /* always zero */
} session_bkey_t;

/* ── Session entry ───────────────────────────────────────────── */

typedef struct session_entry {
    session_key_t       key;        /* display fields (see above) */
    session_bkey_t      bkey;       /* lookup key */
    uint32_t            hash;       /* full hash of bkey (cheap pre-compare) */
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
    uint8_t             hold_which;     /* holder list membership (0 = none) */
    /* hash chain: doubly linked (pprev points at whatever points at us,
     * the bucket head or the previous entry's next) so unlinking an
     * arbitrary entry — the LRU victim — is O(1) without a chain walk */
    struct session_entry  *next;
    struct session_entry **pprev;
    struct session_entry  *lru_prev; /* intrusive LRU list (head = most recent) */
    struct session_entry  *lru_next;
    /* intrusive list of entries holding stream buffers, ordered by last
     * packet (head = most recent); the tail is the first to give its
     * buffers up when the budget is exhausted or it goes idle */
    struct session_entry  *hold_prev;
    struct session_entry  *hold_next;
} session_entry_t;

/* ── Sort modes ──────────────────────────────────────────────── */

typedef enum {
    SORT_BYTES,
    SORT_PACKETS,
    SORT_RECENT,
    SORT_DURATION,
} session_sort_t;

/* ── Session table ───────────────────────────────────────────── */

typedef struct { session_entry_t *head, *tail; } session_hold_list_t;

typedef struct {
    session_entry_t   **buckets;
    session_entry_t    *lru_head;   /* most recently touched */
    session_entry_t    *lru_tail;   /* eviction candidate */
    uint32_t            bucket_count;   /* power of two, >= 2 x pool size */
    uint32_t            bucket_mask;
    uint32_t            session_count;
    uint32_t            next_id;
    uint32_t            id_first;       /* first id this table hands out */
    uint32_t            id_stride;      /* ids step by this (shards: 1 per worker) */
    uint32_t            max_sessions;   /* evict oldest when exceeded */
    uint64_t            hash_seed;      /* random per table: no hash flooding */
    /* entry pool: one calloc'd array sized to the session cap, handed out
     * bump-style then recycled through a free list, so the packet path
     * does no malloc/free once warm. Entries outside the pool (only if
     * max_sessions is raised above pool_cap after creation) are heap. */
    session_entry_t    *pool;
    uint32_t            pool_cap;
    uint32_t            pool_used;      /* bump index */
    session_entry_t    *free_list;      /* recycled entries (via .next) */
    /* stream reassembly */
    int                 reasm_enabled;
    size_t              reasm_used;     /* stream-buffer bytes held by sessions */
    size_t              reasm_budget;   /* global cap on stream memory */
    uint32_t            buf_max;        /* budget / SESSION_STREAM_CAP */
    uint32_t            buf_alloc;      /* buffers malloc'd so far (held + free) */
    uint8_t            *buf_free;       /* free buffers (next pointer in bytes 0..7) */
    session_hold_list_t hold_active;    /* buffer holders, most recent first */
    session_hold_list_t hold_closed;    /* holders in CLOSED/RST: reclaimed first */
    uint32_t            reasm_idle_sec; /* release a holder's buffers after this
                                         * many seconds without a packet
                                         * (packet-timestamp clock); 0 = never */
    ns_mutex_t          mtx;
} session_table_t;

#define SESSION_DEFAULT_MAX        100000
#define SESSION_STREAM_CAP         16384    /* per-direction per-session bytes */
#define SESSION_REASM_IDLE_DEFAULT 60       /* seconds */

/* bucket_count is a minimum: the table rounds up to a power of two of at
 * least 2 x SESSION_DEFAULT_MAX so chains stay short at the cap. */
session_table_t    *session_table_create(uint32_t bucket_count);
void                session_table_destroy(session_table_t *st);
/* Shards (one session table per capture worker) hand out disjoint id
 * sequences — first, first + stride, ... — so a session id names one
 * shard and one session across the whole capture. Default: 1, 1. */
void                session_table_set_ids(session_table_t *st, uint32_t first,
                                          uint32_t stride);
/* Returns the session id the packet belongs to, or 0 if untracked (no IP
 * addresses, or a non-first IP fragment — those carry no L4 header and
 * must not create port-0 pseudo-sessions).
 * payload/paylen (may be NULL/0) are the TCP payload bytes, consumed only
 * when reassembly is enabled. */
uint32_t            session_table_update(session_table_t *st,
                                         const pkt_summary_t *pkt,
                                         const uint8_t *payload,
                                         uint32_t paylen);
/* Opt in to TCP stream reassembly; budget_bytes bounds total stream memory
 * across all sessions. Buffers are recycled: a session that reaches
 * CLOSED/RST becomes the first reclaim candidate, an idle holder (see
 * reasm_idle_sec) gives its buffers back, and when the budget is exhausted
 * a new payload-bearing session takes the oldest holder's buffers. */
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

/* ── Shard set (multi-worker capture) ────────────────────────── */
/* PACKET_FANOUT_HASH keeps a flow on one worker, so a session never
 * spans shards and these are plain unions over the per-worker tables.
 * n == 1 is the single-table case and costs nothing extra. */
uint32_t            session_tables_count(session_table_t *const *sts, int n);
void                session_tables_clear(session_table_t *const *sts, int n);
session_entry_t    *session_tables_snapshot(session_table_t *const *sts, int n,
                                            uint32_t *out_count,
                                            session_sort_t sort);
/* Copies both stream directions of session `id` from whichever shard
 * hands out that id (see session_table_set_ids). */
void                session_tables_streams_copy(session_table_t *const *sts,
                                                int n, uint32_t id,
                                                uint8_t *out_a, uint8_t *out_b,
                                                uint32_t cap, uint32_t *len_a,
                                                uint32_t *len_b);

/* Returns a malloc'd array of entry COPIES taken under the table lock
 * (caller frees the array). Entries stay valid regardless of concurrent
 * eviction/clear; their .next pointers are NULL. */
session_entry_t    *session_table_snapshot(session_table_t *st,
                                           uint32_t *out_count,
                                           session_sort_t sort);

const char         *session_state_str(session_state_t s);

#endif /* SESSION_H */
