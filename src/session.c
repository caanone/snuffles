#include "session.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
  #include <sys/time.h>
#endif

/* TCP flag bits (duplicated from dissect.c to stay self-contained) */
#define TF_FIN  0x01
#define TF_SYN  0x02
#define TF_RST  0x04
#define TF_ACK  0x10

/* The lookup key is hashed and compared as raw bytes: its size must be a
 * whole number of 64-bit words and every byte (padding included) must be
 * written by make_key(). */
_Static_assert(sizeof(session_bkey_t) == 40, "session_bkey_t must be 40 bytes");

/* ── Seeded hash (xxHash64-style 8-byte rounds + avalanche) ───── */

#define HP1 0x9E3779B185EBCA87ULL
#define HP2 0xC2B2AE3D27D4EB4FULL
#define HP3 0x165667B19E3779F9ULL
#define HP4 0x85EBCA77C2B2AE63ULL
#define HP5 0x27D4EB2F165667C5ULL

static inline uint64_t rotl64(uint64_t x, int r) {
    return (x << r) | (x >> (64 - r));
}

static inline uint64_t hash_avalanche(uint64_t h) {
    h ^= h >> 33; h *= HP2;
    h ^= h >> 29; h *= HP3;
    h ^= h >> 32;
    return h;
}

static uint64_t bkey_hash(const session_bkey_t *k, uint64_t seed) {
    uint64_t w[sizeof(*k) / 8];
    memcpy(w, k, sizeof(w));
    uint64_t h = seed + HP5 + sizeof(*k);
    for (size_t i = 0; i < sizeof(w) / sizeof(w[0]); i++) {
        uint64_t v = w[i] * HP2;
        v = rotl64(v, 31) * HP1;
        h ^= v;
        h = rotl64(h, 27) * HP1 + HP4;
    }
    return hash_avalanche(h);
}

/* Per-table seed so an attacker cannot precompute colliding tuples. */
static uint64_t random_seed(void) {
    uint64_t s = 0;
#ifdef _WIN32
    LARGE_INTEGER qpc;
    QueryPerformanceCounter(&qpc);
    s = (uint64_t)qpc.QuadPart ^ ((uint64_t)GetCurrentProcessId() << 32) ^
        (uint64_t)GetTickCount64();
#else
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        if (fread(&s, sizeof(s), 1, f) != 1) s = 0;
        fclose(f);
    }
    if (s == 0) {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        s = ((uint64_t)tv.tv_sec << 32) ^ (uint64_t)tv.tv_usec ^
            ((uint64_t)getpid() << 16);
    }
#endif
    s ^= (uint64_t)(uintptr_t)&s;   /* stack address: ASLR entropy */
    return hash_avalanche(s | 1);
}

static uint32_t round_pow2(uint32_t v) {
    uint32_t p = 1;
    while (p < v && p < (1u << 31)) p <<= 1;
    return p;
}

/* ── Key canonicalisation ────────────────────────────────────── */

/* Fills the packed key (side A = lower address, then lower port) and
 * returns 1 when the packet's source is side A. Every byte of *key is
 * written, so the struct can be compared with memcmp. */
static inline int make_key(session_bkey_t *key, const pkt_summary_t *pkt) {
    size_t alen = (pkt->addr_family == 6) ? 16 : 4;
    memset(key, 0, sizeof(*key));
    int cmp = memcmp(pkt->src_addr, pkt->dst_addr, alen);
    if (cmp == 0) cmp = (int)pkt->src_port - (int)pkt->dst_port;
    if (cmp <= 0) {
        memcpy(key->addr_a, pkt->src_addr, alen);
        memcpy(key->addr_b, pkt->dst_addr, alen);
        key->port_a = pkt->src_port;
        key->port_b = pkt->dst_port;
    } else {
        memcpy(key->addr_a, pkt->dst_addr, alen);
        memcpy(key->addr_b, pkt->src_addr, alen);
        key->port_a = pkt->dst_port;
        key->port_b = pkt->src_port;
    }
    key->proto  = (uint8_t)pkt->l4_proto;
    key->family = pkt->addr_family;
    return cmp <= 0;
}

/* ── Hash chain (doubly linked via pprev) ────────────────────── */

static inline void chain_insert(session_table_t *st, session_entry_t *e,
                                uint32_t bucket) {
    session_entry_t *first = st->buckets[bucket];
    e->next = first;
    if (first) first->pprev = &e->next;
    st->buckets[bucket] = e;
    e->pprev = &st->buckets[bucket];
}

static inline void chain_unlink(session_entry_t *e) {
    *e->pprev = e->next;
    if (e->next) e->next->pprev = e->pprev;
    e->next = NULL;
    e->pprev = NULL;
}

/* ── LRU list (head = most recently touched, tail = evict next) ── */

static void lru_unlink(session_table_t *st, session_entry_t *e) {
    if (e->lru_prev) e->lru_prev->lru_next = e->lru_next;
    else             st->lru_head = e->lru_next;
    if (e->lru_next) e->lru_next->lru_prev = e->lru_prev;
    else             st->lru_tail = e->lru_prev;
    e->lru_prev = e->lru_next = NULL;
}

static void lru_push_front(session_table_t *st, session_entry_t *e) {
    e->lru_prev = NULL;
    e->lru_next = st->lru_head;
    if (st->lru_head) st->lru_head->lru_prev = e;
    st->lru_head = e;
    if (!st->lru_tail) st->lru_tail = e;
}

/* ── Entry pool ──────────────────────────────────────────────── */

static session_entry_t *entry_alloc(session_table_t *st) {
    session_entry_t *e = st->free_list;
    if (e) {
        st->free_list = e->next;
    } else if (st->pool_used < st->pool_cap) {
        e = &st->pool[st->pool_used++];
    } else {
        e = malloc(sizeof(*e));
        if (!e) return NULL;
    }
    memset(e, 0, sizeof(*e));
    return e;
}

static inline int entry_in_pool(const session_table_t *st,
                                const session_entry_t *e) {
    uintptr_t p = (uintptr_t)e, lo = (uintptr_t)st->pool;
    return st->pool && p >= lo && p < lo + (uintptr_t)st->pool_cap * sizeof(*e);
}

static void entry_free(session_table_t *st, session_entry_t *e) {
    if (entry_in_pool(st, e)) {
        e->next = st->free_list;
        st->free_list = e;
    } else {
        free(e);
    }
}

/* ── Stream buffer pool and holder lists ─────────────────────── */

/* Holders live on one of two lists, each ordered by last packet (head =
 * most recent): active flows, and flows that reached CLOSED/RST. Closed
 * flows keep their bytes viewable ("Follow stream" on a finished HTTP
 * exchange) but are the first to give them up when the budget is
 * exhausted; idle holders on either list are released after
 * reasm_idle_sec. */
#define HOLD_NONE   0
#define HOLD_ACTIVE 1
#define HOLD_CLOSED 2

typedef session_hold_list_t hold_list_t;

static inline hold_list_t *hold_list(session_table_t *st, int which) {
    return (which == HOLD_CLOSED) ? &st->hold_closed : &st->hold_active;
}

static void hold_unlink(hold_list_t *l, session_entry_t *e) {
    if (e->hold_prev) e->hold_prev->hold_next = e->hold_next;
    else              l->head = e->hold_next;
    if (e->hold_next) e->hold_next->hold_prev = e->hold_prev;
    else              l->tail = e->hold_prev;
    e->hold_prev = e->hold_next = NULL;
}

static void hold_push_front(hold_list_t *l, session_entry_t *e) {
    e->hold_prev = NULL;
    e->hold_next = l->head;
    if (l->head) l->head->hold_prev = e;
    l->head = e;
    if (!l->tail) l->tail = e;
}

/* Move a holder to the front of its list (it just saw a packet). */
static inline void holder_touch(session_table_t *st, session_entry_t *e) {
    if (!e->hold_which) return;
    hold_list_t *l = hold_list(st, e->hold_which);
    if (l->head == e) return;
    hold_unlink(l, e);
    hold_push_front(l, e);
}

static void buf_put(session_table_t *st, uint8_t *b) {
    memcpy(b, &st->buf_free, sizeof(uint8_t *));
    st->buf_free = b;
}

/* Returns an entry's stream buffers to the free pool and drops it from
 * the holder lists; the budget charge is refunded. */
static void entry_release_streams(session_table_t *st, session_entry_t *e) {
    if (e->stream_a) {
        buf_put(st, e->stream_a);
        e->stream_a = NULL;
        st->reasm_used -= SESSION_STREAM_CAP;
    }
    if (e->stream_b) {
        buf_put(st, e->stream_b);
        e->stream_b = NULL;
        st->reasm_used -= SESSION_STREAM_CAP;
    }
    e->stream_len_a = e->stream_len_b = 0;
    if (e->hold_which) {
        hold_unlink(hold_list(st, e->hold_which), e);
        e->hold_which = HOLD_NONE;
    }
}

/* Reconcile an entry's holder-list membership with what it holds and its
 * TCP state; must run after every update of a TCP entry. Cheap for the
 * common non-holder case (two loads and a compare). */
static void holder_sync(session_table_t *st, session_entry_t *e) {
    int want = HOLD_NONE;
    if (e->stream_a || e->stream_b)
        want = (e->tcp_state == SESS_CLOSED || e->tcp_state == SESS_RST)
               ? HOLD_CLOSED : HOLD_ACTIVE;
    if (e->hold_which == want) return;
    if (e->hold_which) hold_unlink(hold_list(st, e->hold_which), e);
    e->hold_which = (uint8_t)want;
    if (want) hold_push_front(hold_list(st, want), e);
}

/* A buffer for `self`: from the free pool, a fresh allocation while the
 * budget allows, else reclaimed from the oldest holder (closed flows
 * first). NULL when nothing can be had. */
static uint8_t *buf_get(session_table_t *st, session_entry_t *self) {
    uint8_t *b = st->buf_free;
    if (!b && st->buf_alloc < st->buf_max) {
        b = malloc(SESSION_STREAM_CAP);
        if (b) st->buf_alloc++;
        return b;
    }
    if (!b) {
        session_entry_t *victim = st->hold_closed.tail;
        if (!victim) victim = st->hold_active.tail;
        if (!victim || victim == self) return NULL;
        entry_release_streams(st, victim);
        b = st->buf_free;
        if (!b) return NULL;
    }
    memcpy(&st->buf_free, b, sizeof(uint8_t *));
    return b;
}

/* Release holders that have not seen a packet for reasm_idle_sec (by the
 * packet-timestamp clock); bounded work per call, run from update(). */
static void holders_expire(session_table_t *st, const struct timeval *now) {
    if (!st->reasm_idle_sec) return;
    for (int which = HOLD_ACTIVE; which <= HOLD_CLOSED; which++) {
        hold_list_t *l = hold_list(st, which);
        for (int n = 0; n < 4; n++) {
            session_entry_t *t = l->tail;
            if (!t) break;
            int64_t idle = (int64_t)now->tv_sec - (int64_t)t->last_seen.tv_sec;
            if (idle < (int64_t)st->reasm_idle_sec) break;
            entry_release_streams(st, t);
        }
    }
}

/* Frees the pooled (unheld) buffers; call only when no entry holds any. */
static void buf_pool_drain(session_table_t *st) {
    while (st->buf_free) {
        uint8_t *b = st->buf_free;
        memcpy(&st->buf_free, b, sizeof(uint8_t *));
        free(b);
    }
    st->buf_alloc = 0;
}

/* ── TCP stream reassembly (all under the table lock) ────────── */

/* One direction of the flow. Sequence tracking always advances (SYN and
 * FIN each consume one sequence number); bytes are stored only while the
 * per-direction cap and the global budget allow. */
static void stream_update(session_table_t *st, session_entry_t *e, int a2b,
                          const pkt_summary_t *pkt,
                          const uint8_t *payload, uint32_t paylen) {
    uint8_t  *init = a2b ? &e->seq_init_a   : &e->seq_init_b;
    uint32_t *nseq = a2b ? &e->next_seq_a   : &e->next_seq_b;
    uint8_t **buf  = a2b ? &e->stream_a     : &e->stream_b;
    uint32_t *blen = a2b ? &e->stream_len_a : &e->stream_len_b;

    if (!payload) paylen = 0;

    if (!*init) {
        *nseq = pkt->tcp_seq + ((pkt->tcp_flags & TF_SYN) ? 1 : 0);
        *init = 1;
    }

    int32_t d = (int32_t)(pkt->tcp_seq - *nseq);
    if (d < 0) return;      /* retransmit/overlap: drop the segment */
    if (d > 0) {            /* hole: count it and resync past it */
        e->gaps++;
        *nseq = pkt->tcp_seq;
    }

    if (paylen > 0) {
        if (!*buf) {
            *buf = buf_get(st, e);
            if (*buf) {
                st->reasm_used += SESSION_STREAM_CAP;
                *blen = 0;
            }
        }
        if (*buf && *blen < SESSION_STREAM_CAP) {
            uint32_t room = SESSION_STREAM_CAP - *blen;
            uint32_t n = paylen < room ? paylen : room;
            memcpy(*buf + *blen, payload, n);
            *blen += n;
        }
    }

    /* Advance by the WIRE payload length, not the captured length: with a
     * short snaplen every segment is truncated, and advancing by captured
     * bytes would register a spurious gap on each following segment. */
    uint32_t wire_paylen = paylen;
    if (pkt->length > pkt->l7_off && pkt->length - pkt->l7_off > paylen)
        wire_paylen = pkt->length - pkt->l7_off;
    *nseq += wire_paylen;
    if (pkt->tcp_flags & TF_SYN) (*nseq)++;
    if (pkt->tcp_flags & TF_FIN) (*nseq)++;
}

/* ── TCP state machine ───────────────────────────────────────── */

static session_state_t tcp_next_state(session_state_t cur, uint8_t flags) {
    if (flags & TF_RST) return SESS_RST;

    switch (cur) {
        case SESS_NEW:
            if (flags & TF_SYN) return SESS_SYN_SENT;
            if (flags & TF_ACK) return SESS_ESTABLISHED; /* mid-stream join */
            return SESS_NEW;

        case SESS_SYN_SENT:
            if ((flags & (TF_SYN | TF_ACK)) == (TF_SYN | TF_ACK))
                return SESS_ESTABLISHED;
            if (flags & TF_ACK) return SESS_ESTABLISHED;
            return SESS_SYN_SENT;

        case SESS_ESTABLISHED:
            if (flags & TF_FIN) return SESS_CLOSING;
            return SESS_ESTABLISHED;

        case SESS_CLOSING:
            if (flags & TF_FIN) return SESS_CLOSED;
            if (flags & TF_ACK) return SESS_CLOSING;
            return SESS_CLOSING;

        case SESS_CLOSED:
        case SESS_RST:
            /* new SYN can re-open */
            if (flags & TF_SYN) return SESS_SYN_SENT;
            return cur;
    }
    return cur;
}

/* ── Public API ──────────────────────────────────────────────── */

session_table_t *session_table_create(uint32_t bucket_count) {
    session_table_t *st = calloc(1, sizeof(session_table_t));
    if (!st) return NULL;

    /* buckets: at least 2 x the session cap, power of two, so the mean
     * chain stays under one entry even when the table is full */
    uint32_t want = 2u * SESSION_DEFAULT_MAX;
    if (bucket_count > want) want = bucket_count;
    bucket_count = round_pow2(want);
    st->buckets = calloc(bucket_count, sizeof(session_entry_t *));
    if (!st->buckets) { free(st); return NULL; }

    /* entry pool: calloc gives untouched zero pages, so RSS grows only
     * with the sessions actually created */
    st->pool_cap = SESSION_DEFAULT_MAX;
    st->pool = calloc(st->pool_cap, sizeof(session_entry_t));
    if (!st->pool) st->pool_cap = 0;   /* heap entries instead */

    st->bucket_count   = bucket_count;
    st->bucket_mask    = bucket_count - 1;
    st->next_id        = 1;
    st->max_sessions   = SESSION_DEFAULT_MAX;
    st->hash_seed      = random_seed();
    st->reasm_idle_sec = SESSION_REASM_IDLE_DEFAULT;
    ns_mutex_init(&st->mtx);
    return st;
}

/* Drops every session and every stream buffer (lock held by caller). */
static void table_reset_locked(session_table_t *st) {
    session_entry_t *e = st->lru_head;
    while (e) {
        session_entry_t *next = e->lru_next;
        entry_release_streams(st, e);
        if (!entry_in_pool(st, e)) free(e);
        e = next;
    }
    memset(st->buckets, 0, st->bucket_count * sizeof(session_entry_t *));
    st->lru_head = st->lru_tail = NULL;
    st->hold_active.head = st->hold_active.tail = NULL;
    st->hold_closed.head = st->hold_closed.tail = NULL;
    st->free_list = NULL;
    st->pool_used = 0;
    st->session_count = 0;
    st->next_id = 1;
    buf_pool_drain(st);
}

void session_table_destroy(session_table_t *st) {
    if (!st) return;
    table_reset_locked(st);
    ns_mutex_destroy(&st->mtx);
    free(st->pool);
    free(st->buckets);
    free(st);
}

void session_table_enable_reasm(session_table_t *st, size_t budget_bytes) {
    if (!st) return;
    ns_mutex_lock(&st->mtx);
    st->reasm_enabled = 1;
    st->reasm_budget  = budget_bytes;
    st->buf_max       = (uint32_t)(budget_bytes / SESSION_STREAM_CAP);
    ns_mutex_unlock(&st->mtx);
}

void session_table_clear(session_table_t *st) {
    if (!st) return;
    ns_mutex_lock(&st->mtx);
    table_reset_locked(st);
    ns_mutex_unlock(&st->mtx);
}

uint32_t session_table_update(session_table_t *st,
                              const pkt_summary_t *pkt,
                              const uint8_t *payload,
                              uint32_t paylen) {
    if (!st) return 0;
    /* skip packets without IP info */
    if (pkt->addr_family == 0) return 0;
    /* non-first fragments carry no L4 header: nothing to attach them to */
    if ((pkt->ip_frag_off & 0x1FFF) != 0) return 0;

    session_bkey_t key;
    int a2b = make_key(&key, pkt);
    uint32_t h = (uint32_t)bkey_hash(&key, st->hash_seed);
    uint32_t bucket = h & st->bucket_mask;

    ns_mutex_lock(&st->mtx);

    /* find existing */
    session_entry_t *e = st->buckets[bucket];
    while (e) {
        if (e->hash == h && memcmp(&e->bkey, &key, sizeof(key)) == 0) break;
        e = e->next;
    }

    if (!e) {
        /* at capacity: evict the LRU tail in O(1) */
        if (st->max_sessions > 0 && st->session_count >= st->max_sessions &&
            st->lru_tail) {
            session_entry_t *old = st->lru_tail;
            chain_unlink(old);
            lru_unlink(st, old);
            entry_release_streams(st, old);
            entry_free(st, old);
            st->session_count--;
        }

        /* create new session */
        e = entry_alloc(st);
        if (!e) { ns_mutex_unlock(&st->mtx); return 0; }
        e->bkey = key;
        e->hash = h;
        e->id = st->next_id++;
        e->first_seen = pkt->ts;
        e->tcp_state = SESS_NEW;
        /* display fields: formatted once, here, never per packet */
        ns_ip_str(key.family, key.addr_a, e->key.ip_a, sizeof(e->key.ip_a));
        ns_ip_str(key.family, key.addr_b, e->key.ip_b, sizeof(e->key.ip_b));
        e->key.port_a = key.port_a;
        e->key.port_b = key.port_b;
        e->key.proto  = key.proto;
        chain_insert(st, e, bucket);
        st->session_count++;
        lru_push_front(st, e);
    } else if (st->lru_head != e) {
        /* touch: move to the front of the LRU list */
        lru_unlink(st, e);
        lru_push_front(st, e);
    }

    /* update counters */
    if (a2b) {
        e->pkts_a_to_b++;
        e->bytes_a_to_b += pkt->length;
    } else {
        e->pkts_b_to_a++;
        e->bytes_b_to_a += pkt->length;
    }
    e->last_seen = pkt->ts;

    /* TCP state */
    if (pkt->l4_proto == PROTO_TCP) {
        e->tcp_flags_seen |= pkt->tcp_flags;
        e->tcp_state = tcp_next_state(e->tcp_state, pkt->tcp_flags);
        if (st->reasm_enabled) {
            holder_touch(st, e);
            stream_update(st, e, a2b, pkt, payload, paylen);
            holder_sync(st, e);
        }
    } else {
        e->tcp_state = SESS_ESTABLISHED;
    }
    /* any tracked packet advances the idle clock for stream holders */
    if (st->reasm_enabled) holders_expire(st, &pkt->ts);

    uint32_t id = e->id;
    ns_mutex_unlock(&st->mtx);
    return id;
}

uint32_t session_table_count(const session_table_t *st) {
    if (!st) return 0;
    /* the capture thread mutates session_count under the mutex */
    session_table_t *m = (session_table_t *)st;
    ns_mutex_lock(&m->mtx);
    uint32_t c = st->session_count;
    ns_mutex_unlock(&m->mtx);
    return c;
}

static uint32_t stream_copy_locked(const session_entry_t *e, int dir,
                                   uint8_t *out, uint32_t cap) {
    const uint8_t *src = (dir == 0) ? e->stream_a     : e->stream_b;
    uint32_t       len = (dir == 0) ? e->stream_len_a : e->stream_len_b;
    if (!src || len == 0) return 0;
    uint32_t n = len < cap ? len : cap;
    memcpy(out, src, n);
    return n;
}

/* Lookup by id (rare: "Follow stream"), lock held. */
static session_entry_t *find_by_id_locked(session_table_t *st, uint32_t id) {
    for (session_entry_t *e = st->lru_head; e; e = e->lru_next)
        if (e->id == id) return e;
    return NULL;
}

uint32_t session_stream_copy(session_table_t *st, uint32_t id, int dir,
                             uint8_t *out, uint32_t cap) {
    if (!st || !out || cap == 0) return 0;

    ns_mutex_lock(&st->mtx);
    session_entry_t *e = find_by_id_locked(st, id);
    uint32_t n = e ? stream_copy_locked(e, dir, out, cap) : 0;
    ns_mutex_unlock(&st->mtx);
    return n;
}

void session_streams_copy(session_table_t *st, uint32_t id,
                          uint8_t *out_a, uint8_t *out_b, uint32_t cap,
                          uint32_t *len_a, uint32_t *len_b) {
    *len_a = *len_b = 0;
    if (!st || !out_a || !out_b || cap == 0) return;

    /* one critical section so the two directions form a coherent
     * point-in-time view of the session */
    ns_mutex_lock(&st->mtx);
    session_entry_t *e = find_by_id_locked(st, id);
    if (e) {
        *len_a = stream_copy_locked(e, 0, out_a, cap);
        *len_b = stream_copy_locked(e, 1, out_b, cap);
    }
    ns_mutex_unlock(&st->mtx);
}

/* ── Snapshot for UI ─────────────────────────────────────────── */

static int cmp_bytes(const void *a, const void *b) {
    const session_entry_t *ea = (const session_entry_t *)a;
    const session_entry_t *eb = (const session_entry_t *)b;
    uint64_t ta = ea->bytes_a_to_b + ea->bytes_b_to_a;
    uint64_t tb = eb->bytes_a_to_b + eb->bytes_b_to_a;
    return (ta < tb) ? 1 : (ta > tb) ? -1 : 0;
}

static int cmp_packets(const void *a, const void *b) {
    const session_entry_t *ea = (const session_entry_t *)a;
    const session_entry_t *eb = (const session_entry_t *)b;
    uint64_t ta = ea->pkts_a_to_b + ea->pkts_b_to_a;
    uint64_t tb = eb->pkts_a_to_b + eb->pkts_b_to_a;
    return (ta < tb) ? 1 : (ta > tb) ? -1 : 0;
}

static int cmp_recent(const void *a, const void *b) {
    const session_entry_t *ea = (const session_entry_t *)a;
    const session_entry_t *eb = (const session_entry_t *)b;
    if (ea->last_seen.tv_sec != eb->last_seen.tv_sec)
        return (ea->last_seen.tv_sec < eb->last_seen.tv_sec) ? 1 : -1;
    if (ea->last_seen.tv_usec != eb->last_seen.tv_usec)
        return (ea->last_seen.tv_usec < eb->last_seen.tv_usec) ? 1 : -1;
    return 0;
}

static int cmp_duration(const void *a, const void *b) {
    const session_entry_t *ea = (const session_entry_t *)a;
    const session_entry_t *eb = (const session_entry_t *)b;
    double da = (double)(ea->last_seen.tv_sec - ea->first_seen.tv_sec) +
                (double)(ea->last_seen.tv_usec - ea->first_seen.tv_usec) / 1e6;
    double db = (double)(eb->last_seen.tv_sec - eb->first_seen.tv_sec) +
                (double)(eb->last_seen.tv_usec - eb->first_seen.tv_usec) / 1e6;
    return (da < db) ? 1 : (da > db) ? -1 : 0;
}

session_entry_t *session_table_snapshot(session_table_t *st,
                                        uint32_t *out_count,
                                        session_sort_t sort) {
    if (!st) { *out_count = 0; return NULL; }

    ns_mutex_lock(&st->mtx);

    uint32_t count = st->session_count;
    if (count == 0) {
        ns_mutex_unlock(&st->mtx);
        *out_count = 0;
        return NULL;
    }

    session_entry_t *arr = malloc(count * sizeof(session_entry_t));
    if (!arr) {
        ns_mutex_unlock(&st->mtx);
        *out_count = 0;
        return NULL;
    }

    /* walk the LRU list: every live entry, no empty buckets to skip */
    uint32_t idx = 0;
    for (session_entry_t *e = st->lru_head; e && idx < count; e = e->lru_next) {
        arr[idx] = *e;
        arr[idx].next = NULL;
        arr[idx].pprev = NULL;
        arr[idx].lru_prev = NULL;
        arr[idx].lru_next = NULL;
        arr[idx].hold_prev = NULL;
        arr[idx].hold_next = NULL;
        arr[idx].hold_which = HOLD_NONE;
        /* stream buffers stay owned by the table: copies must never
         * carry live pointers (use session_stream_copy instead) */
        arr[idx].stream_a = NULL;
        arr[idx].stream_b = NULL;
        idx++;
    }
    count = idx;

    ns_mutex_unlock(&st->mtx);

    int (*cmpfn)(const void *, const void *) = cmp_bytes;
    switch (sort) {
        case SORT_BYTES:    cmpfn = cmp_bytes;    break;
        case SORT_PACKETS:  cmpfn = cmp_packets;  break;
        case SORT_RECENT:   cmpfn = cmp_recent;   break;
        case SORT_DURATION: cmpfn = cmp_duration;  break;
    }
    qsort(arr, count, sizeof(session_entry_t), cmpfn);

    *out_count = count;
    return arr;
}

const char *session_state_str(session_state_t s) {
    switch (s) {
        case SESS_NEW:         return "NEW";
        case SESS_SYN_SENT:    return "SYN";
        case SESS_ESTABLISHED: return "EST";
        case SESS_CLOSING:     return "FIN";
        case SESS_CLOSED:      return "CLOSED";
        case SESS_RST:         return "RST";
    }
    return "???";
}
