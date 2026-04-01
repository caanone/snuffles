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

/* ── FNV-1a hash ─────────────────────────────────────────────── */

static uint32_t fnv1a(const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < len; i++) {
        h ^= p[i];
        h *= 16777619u;
    }
    return h;
}

/* ── Normalize key: side_a is the "lower" side ───────────────── */

static void normalize_key(session_key_t *key,
                          const char *src_ip, const char *dst_ip,
                          uint16_t src_port, uint16_t dst_port,
                          uint8_t proto) {
    int cmp = strcmp(src_ip, dst_ip);
    if (cmp == 0) cmp = (int)src_port - (int)dst_port;

    if (cmp <= 0) {
        snprintf(key->ip_a, sizeof(key->ip_a), "%s", src_ip);
        snprintf(key->ip_b, sizeof(key->ip_b), "%s", dst_ip);
        key->port_a = src_port;
        key->port_b = dst_port;
    } else {
        snprintf(key->ip_a, sizeof(key->ip_a), "%s", dst_ip);
        snprintf(key->ip_b, sizeof(key->ip_b), "%s", src_ip);
        key->port_a = dst_port;
        key->port_b = src_port;
    }
    key->proto = proto;
}

static int is_a_to_b(const session_key_t *key,
                     const char *src_ip, uint16_t src_port) {
    return (strcmp(src_ip, key->ip_a) == 0 && src_port == key->port_a);
}

static uint32_t key_hash(const session_key_t *key, uint32_t bucket_count) {
    uint32_t h = fnv1a(key->ip_a, strlen(key->ip_a));
    h = h * 16777619u ^ fnv1a(key->ip_b, strlen(key->ip_b));
    h = h * 16777619u ^ (uint32_t)key->port_a;
    h = h * 16777619u ^ (uint32_t)key->port_b;
    h = h * 16777619u ^ (uint32_t)key->proto;
    return h % bucket_count;
}

static int keys_equal(const session_key_t *a, const session_key_t *b) {
    return strcmp(a->ip_a, b->ip_a) == 0 &&
           strcmp(a->ip_b, b->ip_b) == 0 &&
           a->port_a == b->port_a &&
           a->port_b == b->port_b &&
           a->proto  == b->proto;
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

    if (bucket_count == 0) bucket_count = 4096;
    st->buckets = calloc(bucket_count, sizeof(session_entry_t *));
    if (!st->buckets) { free(st); return NULL; }

    st->bucket_count  = bucket_count;
    st->next_id       = 1;
    st->max_sessions  = SESSION_DEFAULT_MAX;
    ns_mutex_init(&st->mtx);
    return st;
}

void session_table_destroy(session_table_t *st) {
    if (!st) return;
    for (uint32_t i = 0; i < st->bucket_count; i++) {
        session_entry_t *e = st->buckets[i];
        while (e) {
            session_entry_t *next = e->next;
            free(e);
            e = next;
        }
    }
    ns_mutex_destroy(&st->mtx);
    free(st->buckets);
    free(st);
}

void session_table_clear(session_table_t *st) {
    if (!st) return;
    ns_mutex_lock(&st->mtx);
    for (uint32_t i = 0; i < st->bucket_count; i++) {
        session_entry_t *e = st->buckets[i];
        while (e) {
            session_entry_t *next = e->next;
            free(e);
            e = next;
        }
        st->buckets[i] = NULL;
    }
    st->session_count = 0;
    st->next_id = 1;
    ns_mutex_unlock(&st->mtx);
}

session_entry_t *session_table_update(session_table_t *st,
                                       const pkt_summary_t *pkt) {
    if (!st) return NULL;
    /* skip packets without IP info */
    if (!pkt->src_ip[0] || !pkt->dst_ip[0]) return NULL;

    session_key_t key;
    normalize_key(&key, pkt->src_ip, pkt->dst_ip,
                  pkt->src_port, pkt->dst_port,
                  (uint8_t)pkt->l4_proto);

    uint32_t bucket = key_hash(&key, st->bucket_count);

    ns_mutex_lock(&st->mtx);

    /* find existing */
    session_entry_t *e = st->buckets[bucket];
    while (e) {
        if (keys_equal(&e->key, &key)) break;
        e = e->next;
    }

    if (!e) {
        /* evict oldest session if at capacity */
        if (st->max_sessions > 0 && st->session_count >= st->max_sessions) {
            session_entry_t *oldest = NULL;
            uint32_t oldest_bucket = 0;
            for (uint32_t bi = 0; bi < st->bucket_count; bi++) {
                for (session_entry_t *s = st->buckets[bi]; s; s = s->next) {
                    if (!oldest || s->last_seen.tv_sec < oldest->last_seen.tv_sec ||
                        (s->last_seen.tv_sec == oldest->last_seen.tv_sec &&
                         s->last_seen.tv_usec < oldest->last_seen.tv_usec)) {
                        oldest = s;
                        oldest_bucket = bi;
                    }
                }
            }
            if (oldest) {
                session_entry_t **pp = &st->buckets[oldest_bucket];
                while (*pp && *pp != oldest) pp = &(*pp)->next;
                if (*pp) { *pp = oldest->next; free(oldest); st->session_count--; }
            }
        }

        /* create new session */
        e = calloc(1, sizeof(session_entry_t));
        if (!e) { ns_mutex_unlock(&st->mtx); return NULL; }
        e->key = key;
        e->id = st->next_id++;
        e->first_seen = pkt->ts;
        e->tcp_state = SESS_NEW;
        e->next = st->buckets[bucket];
        st->buckets[bucket] = e;
        st->session_count++;
    }

    /* update counters */
    if (is_a_to_b(&key, pkt->src_ip, pkt->src_port)) {
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
    } else {
        e->tcp_state = SESS_ESTABLISHED;
    }

    ns_mutex_unlock(&st->mtx);
    return e;
}

uint32_t session_table_count(const session_table_t *st) {
    return st ? st->session_count : 0;
}

/* ── Snapshot for UI ─────────────────────────────────────────── */

static int cmp_bytes(const void *a, const void *b) {
    const session_entry_t *ea = *(const session_entry_t *const *)a;
    const session_entry_t *eb = *(const session_entry_t *const *)b;
    uint64_t ta = ea->bytes_a_to_b + ea->bytes_b_to_a;
    uint64_t tb = eb->bytes_a_to_b + eb->bytes_b_to_a;
    return (ta < tb) ? 1 : (ta > tb) ? -1 : 0;
}

static int cmp_packets(const void *a, const void *b) {
    const session_entry_t *ea = *(const session_entry_t *const *)a;
    const session_entry_t *eb = *(const session_entry_t *const *)b;
    uint64_t ta = ea->pkts_a_to_b + ea->pkts_b_to_a;
    uint64_t tb = eb->pkts_a_to_b + eb->pkts_b_to_a;
    return (ta < tb) ? 1 : (ta > tb) ? -1 : 0;
}

static int cmp_recent(const void *a, const void *b) {
    const session_entry_t *ea = *(const session_entry_t *const *)a;
    const session_entry_t *eb = *(const session_entry_t *const *)b;
    if (ea->last_seen.tv_sec != eb->last_seen.tv_sec)
        return (ea->last_seen.tv_sec < eb->last_seen.tv_sec) ? 1 : -1;
    return (ea->last_seen.tv_usec < eb->last_seen.tv_usec) ? 1 : -1;
}

static int cmp_duration(const void *a, const void *b) {
    const session_entry_t *ea = *(const session_entry_t *const *)a;
    const session_entry_t *eb = *(const session_entry_t *const *)b;
    double da = (double)(ea->last_seen.tv_sec - ea->first_seen.tv_sec) +
                (double)(ea->last_seen.tv_usec - ea->first_seen.tv_usec) / 1e6;
    double db = (double)(eb->last_seen.tv_sec - eb->first_seen.tv_sec) +
                (double)(eb->last_seen.tv_usec - eb->first_seen.tv_usec) / 1e6;
    return (da < db) ? 1 : (da > db) ? -1 : 0;
}

session_entry_t **session_table_snapshot(session_table_t *st,
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

    session_entry_t **arr = malloc(count * sizeof(session_entry_t *));
    if (!arr) {
        ns_mutex_unlock(&st->mtx);
        *out_count = 0;
        return NULL;
    }

    uint32_t idx = 0;
    for (uint32_t i = 0; i < st->bucket_count && idx < count; i++) {
        for (session_entry_t *e = st->buckets[i]; e && idx < count; e = e->next) {
            arr[idx++] = e;
        }
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
    qsort(arr, count, sizeof(session_entry_t *), cmpfn);

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
