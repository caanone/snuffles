#include "capture.h"
#include "dissect.h"
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdatomic.h>
#include <limits.h>
#include <time.h>
#ifdef __linux__
  #include <sys/prctl.h>
#endif

#ifndef _WIN32
  #include <unistd.h>
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <sys/ioctl.h>
  #include <net/if.h>
  #include <pwd.h>
  #include <errno.h>
#endif
#ifdef __linux__
  #include <linux/if_packet.h>   /* PACKET_FANOUT */
#endif

/* One capture worker: its own pcap handle (its own kernel buffer), its
 * own session table shard and its own thread. With -j 1 there is exactly
 * one and everything below behaves as it did before. */
typedef struct capture_worker {
    struct capture_ctx *ctx;
    int                 idx;
    pcap_t             *handle;
    session_table_t    *st;
    ns_thread_t         thread;
    uint64_t            budget;             /* -c tally, single worker only */
    int                 last_pkt;           /* -c reached on this packet */
    int                 started;            /* thread created (join it) */
    atomic_uint_fast64_t drops;             /* published by the worker thread */
    atomic_uint_fast64_t ifdrops;           /* pcap ps_ifdrop */
    atomic_int          bpf_req;
} capture_worker_t;

struct capture_ctx {
    ringbuf_t          *rb;
    capture_cfg_t       cfg;
    capture_worker_t    w[CAPTURE_MAX_WORKERS];
    int                 nworkers;
    atomic_int          running;    /* worker threads still in their loop */
    atomic_int          stop_req;
    /* -c across workers: reserved before a packet is taken, so exactly
     * count packets reach the ring however they are distributed. */
    atomic_uint_fast64_t budget;
    int                 datalink;
    int                 offline;
    int                 iface_mtu;      /* live: MTU of the interface, 0 unknown */
    char                errbuf[PCAP_ERRBUF_SIZE];
    char                iface_name[64];
    char                bpf_active[512]; /* UI thread only (after create) */

    /* BPF changes are queued here by the UI thread and applied by each
     * capture thread between dispatch calls: a pcap_t handle must only
     * be used from its own capture thread (pcap_breakloop excepted). */
    ns_mutex_t          bpf_mtx;
    char                bpf_pending[512];

    atomic_int          superframe_warned;  /* GRO/GSO note: once per capture */
    atomic_int          err_claim;  /* first worker to fail writes err_msg */
    atomic_int          had_error;
    char                err_msg[256]; /* written before had_error is set */
};

/* ── Helpers ─────────────────────────────────────────────────── */

/* 100 us pause while the offline producer waits for the consumer. */
static void offline_nap(void) {
#ifdef _WIN32
    Sleep(1);
#else
    struct timespec ts = { 0, 100000 };
    nanosleep(&ts, NULL);
#endif
}

/* MTU of a live interface, 0 if unknown (pseudo-devices, non-POSIX). */
static int iface_mtu(const char *name) {
#if defined(_WIN32) || !defined(SIOCGIFMTU)
    (void)name;
    return 0;
#else
    struct ifreq ifr;
    if (strlen(name) >= sizeof(ifr.ifr_name)) return 0;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return 0;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", name);
    int mtu = (ioctl(fd, SIOCGIFMTU, &ifr) == 0) ? ifr.ifr_mtu : 0;
    close(fd);
    return mtu;
#endif
}

/* ── Capture callback ────────────────────────────────────────── */

/* Stop every worker, from any of them. A worker sitting in
 * pcap_dispatch on a quiet handle stays there until *its* handle is
 * broken (libpcap keeps polling across the read timeout), so one worker
 * reaching -c has to break them all — capture_stop is not reached until
 * they have. */
static void stop_all(capture_ctx_t *ctx) {
    atomic_store(&ctx->stop_req, 1);
    for (int i = 0; i < ctx->nworkers; i++)
        if (ctx->w[i].handle) pcap_breakloop(ctx->w[i].handle);
}

/* Ask for room for one more packet under -c. Returns 0 when the limit is
 * already spoken for (the packet is dropped and the capture stops), and
 * arms w->last_pkt on the packet that reaches it. With several workers
 * the tally must be shared, or -c 20 would stop at 20 per worker; with
 * one it stays a plain counter. */
static int take_budget(capture_ctx_t *ctx, capture_worker_t *w) {
    if (ctx->cfg.count <= 0) return 1;
    uint64_t n = (ctx->nworkers > 1)
        ? atomic_fetch_add_explicit(&ctx->budget, 1, memory_order_relaxed) + 1
        : ++w->budget;
    if (n > (uint64_t)ctx->cfg.count) {
        stop_all(ctx);
        return 0;
    }
    if (n == (uint64_t)ctx->cfg.count) w->last_pkt = 1;
    return 1;
}

static void capture_callback(u_char *user, const struct pcap_pkthdr *hdr,
                             const u_char *data) {
    capture_worker_t *w = (capture_worker_t *)user;
    capture_ctx_t *ctx = w->ctx;

    if (atomic_load(&ctx->stop_req)) {
        pcap_breakloop(w->handle);
        return;
    }

    /* Offline replay back-pressure: a file read has no reason to lose
     * records, so when a streaming consumer is attached to the ring, wait
     * for it instead of lapping it. Live capture never waits here (the
     * kernel buffer is the only place a live burst can be absorbed). */
    if (ctx->offline) {
        while (!ringbuf_producer_may_write(ctx->rb)) {
            if (atomic_load(&ctx->stop_req)) {
                pcap_breakloop(w->handle);
                return;
            }
            offline_nap();
        }
    }

    if (!take_budget(ctx, w)) {
        pcap_breakloop(w->handle);
        return;
    }

    /* GRO/GSO super-frames: a frame longer than a standard Ethernet MTU
     * frame on a non-jumbo interface was coalesced by the kernel before
     * the tap saw it. Harmless for dissection, but each one costs a large
     * memcpy and the -s/ring math assumes wire-sized frames. Warn once,
     * headless modes only (stderr would scribble over the TUI). */
    if (hdr->len > 1518 && !atomic_load(&ctx->superframe_warned) &&
        !atomic_exchange(&ctx->superframe_warned, 1)) {
        if (ctx->cfg.no_ui && ctx->iface_mtu > 0 && ctx->iface_mtu <= 1500)
            fprintf(stderr, "snuffles: %u-byte frame on %s (MTU %d): the kernel "
                    "is coalescing packets (GRO/GSO super-frames); "
                    "for wire-sized frames try: ethtool -K %s gro off gso off "
                    "tso off\n", hdr->len, ctx->iface_name, ctx->iface_mtu,
                    ctx->iface_name);
        else if (ctx->cfg.no_ui && hdr->len > (bpf_u_int32)ctx->cfg.snaplen)
            fprintf(stderr, "snuffles: %u-byte frame on %s exceeds the snaplen "
                    "(%d) and is truncated; use -s to keep whole jumbo "
                    "frames\n", hdr->len, ctx->iface_name, ctx->cfg.snaplen);
    }

    /* claim a slot and arena space, copy the raw bytes (granted length is
     * min(caplen, snaplen)) */
    pkt_record_t *rec = ringbuf_producer_next_w(ctx->rb, w->idx, hdr->caplen);
    memcpy(rec->raw_data, data, rec->raw_len);

    /* dissect */
    dissect_packet(data, hdr->caplen, ctx->datalink, &rec->summary);
    rec->summary.ts     = hdr->ts;
    rec->summary.length = hdr->len;

    /* update this worker's session shard (TCP payload bytes clamped to
     * what we copied). A flow stays on one worker, so it never spans
     * shards. */
    if (w->st) {
        const uint8_t *pl = NULL;
        uint32_t pln = 0;
        if (rec->summary.l4_proto == PROTO_TCP && rec->summary.l7_len > 0 &&
            rec->summary.l7_off < rec->raw_len) {
            pl  = rec->raw_data + rec->summary.l7_off;
            pln = rec->summary.l7_len;
            if (pln > rec->raw_len - rec->summary.l7_off)
                pln = rec->raw_len - rec->summary.l7_off;
        }
        uint32_t sid = session_table_update(w->st, &rec->summary, pl, pln);
        if (sid) rec->summary.session_id = sid;
    }

    /* --syslog and -w are served by the output thread from the ring */
    ringbuf_producer_commit_w(ctx->rb, w->idx);

    if (w->last_pkt) {
        /* -c reached: stop every worker loop as well, otherwise they
         * re-enter pcap_dispatch and keep delivering. */
        stop_all(ctx);
    }
}

/* ── Capture thread ──────────────────────────────────────────── */

/* Runs on a capture thread between dispatch calls. */
static void apply_pending_bpf(capture_worker_t *w) {
    capture_ctx_t *ctx = w->ctx;
    char expr[sizeof(ctx->bpf_pending)];
    ns_mutex_lock(&ctx->bpf_mtx);
    memcpy(expr, ctx->bpf_pending, sizeof(expr));
    ns_mutex_unlock(&ctx->bpf_mtx);

    struct bpf_program fp;
    if (pcap_compile(w->handle, &fp, expr, 1, PCAP_NETMASK_UNKNOWN) != 0) {
        fprintf(stderr, "BPF compile error: %s\n", pcap_geterr(w->handle));
        return;
    }
    if (pcap_setfilter(w->handle, &fp) != 0)
        fprintf(stderr, "BPF setfilter error: %s\n", pcap_geterr(w->handle));
    pcap_freecode(&fp);
}

/* Packets handed to pcap_dispatch per call. stop_req is checked in the
 * callback and -c breaks the loop exactly, so a large batch only saves the
 * per-call overhead (poll/return path plus the stats sample below). */
#define CAPTURE_BATCH      1024
/* Minimum spacing between pcap_stats() samples while packets flow. */
#define STATS_INTERVAL_MS  250

static uint64_t mono_ms(void) {
#ifdef _WIN32
    return (uint64_t)GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
#endif
}

static void *capture_thread_fn(void *arg) {
    capture_worker_t *w   = (capture_worker_t *)arg;
    capture_ctx_t    *ctx = w->ctx;
#ifdef __linux__
    if (ctx->nworkers > 1) {
        char name[16];
        snprintf(name, sizeof(name), "snf-cap%d", w->idx);
        prctl(PR_SET_NAME, name, 0, 0, 0);
    } else {
        prctl(PR_SET_NAME, "snf-capture", 0, 0, 0);
    }
#endif

    uint64_t last_stats_ms = 0;

    while (!atomic_load(&ctx->stop_req)) {
        if (atomic_exchange(&w->bpf_req, 0))
            apply_pending_bpf(w);

        int ret = pcap_dispatch(w->handle, CAPTURE_BATCH, capture_callback,
                                (u_char *)w);

        /* pcap_stats() is a getsockopt() round trip: sample it at most every
         * STATS_INTERVAL_MS while packets flow, and whenever dispatch came
         * back empty (idle, break-out, or exit) so the counters last
         * published are current. */
        if (!ctx->offline) {
            uint64_t now = mono_ms();
            if (ret <= 0 || now - last_stats_ms >= STATS_INTERVAL_MS) {
                struct pcap_stat ps;
                if (pcap_stats(w->handle, &ps) == 0) {
                    atomic_store(&w->drops, (uint64_t)ps.ps_drop);
                    atomic_store(&w->ifdrops, (uint64_t)ps.ps_ifdrop);
                }
                last_stats_ms = now;
            }
        }

        if (ret == PCAP_ERROR_BREAK || ret == 0) {
            if (ctx->offline) break;
            if (atomic_load(&ctx->stop_req)) break;
        }
        if (ret == PCAP_ERROR) {
            /* No stderr here: it would scribble over the TUI. The UI status
             * bar and main's exit path surface the stored message, from
             * whichever worker failed first. */
            if (!atomic_exchange(&ctx->err_claim, 1)) {
                snprintf(ctx->err_msg, sizeof(ctx->err_msg), "%s",
                         pcap_geterr(w->handle));
                atomic_store(&ctx->had_error, 1);
            }
            stop_all(ctx);   /* a dead handle ends the capture, as with one */
            break;
        }
    }

    atomic_fetch_sub(&ctx->running, 1);
    return NULL;
}

/* ── Public API ──────────────────────────────────────────────── */

static int find_default_interface(char *buf, size_t len) {
    pcap_if_t *alldevs = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) != 0) {
        fprintf(stderr, "pcap_findalldevs: %s\n", errbuf);
        return -1;
    }

    int found = 0;
    for (pcap_if_t *d = alldevs; d; d = d->next) {
        if (d->flags & PCAP_IF_LOOPBACK) continue;
        if (d->flags & PCAP_IF_UP) {
            snprintf(buf, len, "%s", d->name);
            found = 1;
            break;
        }
    }

    if (!found && alldevs) {
        snprintf(buf, len, "%s", alldevs->name);
        found = 1;
    }

    pcap_freealldevs(alldevs);
    return found ? 0 : -1;
}

/* Open and activate one live handle on iface with the configured
 * snaplen / promisc / buffer / timeout. Returns NULL and prints why. */
static pcap_t *open_live(const capture_cfg_t *cfg, const char *iface,
                         char *errbuf) {
    pcap_t *h = pcap_create(iface, errbuf);
    if (!h) {
        fprintf(stderr, "pcap_create(%s): %s\n", iface, errbuf);
        return NULL;
    }

    pcap_set_snaplen(h, cfg->snaplen);
    pcap_set_promisc(h, cfg->promisc);

    /* Kernel capture buffer (TPACKET ring on Linux, BPF store buffer
     * on BSD/macOS, Npcap kernel buffer on Windows). libpcap's default
     * is 2 MB: ~16k small packets packed into TPACKET_V3 blocks, or a
     * mere 31 frames on a per-frame TPACKET_V2 ring at snaplen 65535,
     * of scheduling jitter before the kernel drops. 64 MB rides out
     * ~500k small packets. libpcap shrinks the request itself if the
     * kernel refuses it. Each worker gets its own buffer of this size. */
    if (cfg->buffer_mb > 0) {   /* <= 0 (unset cfg): libpcap default */
        long long bytes = (long long)cfg->buffer_mb * 1024 * 1024;
        if (bytes > INT_MAX) bytes = INT_MAX;
        pcap_set_buffer_size(h, (int)bytes);
    }

    if (cfg->immediate) {
        /* one wakeup per packet; on Linux this forces TPACKET_V2 */
        pcap_set_immediate_mode(h, 1);
        pcap_set_timeout(h, 100);
    } else {
        /* Batched delivery: on Linux libpcap picks TPACKET_V3 and
         * retires a block every 10 ms (or when full). The TUI redraws
         * every 50 ms, so this adds no visible latency. */
        pcap_set_timeout(h, 10);
    }

    int err = pcap_activate(h);
    if (err < 0) {
        fprintf(stderr, "pcap_activate(%s): %s\n", iface, pcap_geterr(h));
#ifdef __APPLE__
        if (err == PCAP_ERROR_PERM_DENIED)
            fprintf(stderr, "Hint: try running with sudo.\n");
#elif defined(__linux__)
        if (err == PCAP_ERROR_PERM_DENIED) {
            fprintf(stderr, "Hint: run with sudo or set CAP_NET_RAW:\n");
            fprintf(stderr, "  sudo setcap cap_net_raw+ep ./snuffles\n");
        }
#endif
        pcap_close(h);
        return NULL;
    }
    return h;
}

#ifdef __linux__
/* Put an activated handle into PACKET_FANOUT group `group` in
 * PACKET_FANOUT_HASH mode: the kernel hashes each frame's flow and
 * always delivers it to the same socket of the group, so a flow stays on
 * one worker and in order. libpcap has no API for this, so it goes
 * straight onto the handle's AF_PACKET socket — which is why the fd is
 * checked first (an offline read, a DLT that is not AF_PACKET-backed, or
 * a non-Linux capture must fall back to one worker). */
static int fanout_join(pcap_t *h, int group, char *why, size_t whylen) {
    int fd = pcap_get_selectable_fd(h);
    if (fd < 0) fd = pcap_fileno(h);
    if (fd < 0) {
        snprintf(why, whylen, "no capture descriptor");
        return -1;
    }
    struct sockaddr_storage ss;
    socklen_t sl = sizeof(ss);
    if (getsockname(fd, (struct sockaddr *)&ss, &sl) != 0 ||
        ss.ss_family != AF_PACKET) {
        snprintf(why, whylen, "not an AF_PACKET socket");
        return -1;
    }
    int arg = (group & 0xffff) | (PACKET_FANOUT_HASH << 16);
    if (setsockopt(fd, SOL_PACKET, PACKET_FANOUT, &arg, sizeof(arg)) != 0) {
        snprintf(why, whylen, "%s", strerror(errno));
        return -1;
    }
    return 0;
}
#endif

/* How many workers the configuration asks for, before the fan-out group
 * is actually built (capture_create may still fall back to 1). */
static int wanted_workers(const capture_cfg_t *cfg, int warn) {
    int n = cfg->workers > 0 ? cfg->workers : 1;
    if (n > CAPTURE_MAX_WORKERS) n = CAPTURE_MAX_WORKERS;
    if (n <= 1) return 1;
    if (cfg->pcap_file[0]) {
        if (warn) fprintf(stderr, "snuffles: -j is for live capture; reading "
                                  "a file uses one worker\n");
        return 1;
    }
#ifndef __linux__
    if (warn) fprintf(stderr, "snuffles: -j needs Linux PACKET_FANOUT; "
                              "using one worker\n");
    return 1;
#else
    return n;
#endif
}

int capture_cfg_workers(const capture_cfg_t *cfg) {
    return wanted_workers(cfg, 0);
}

capture_ctx_t *capture_create(const capture_cfg_t *cfg, ringbuf_t *rb,
                              session_table_t *const *sts, int nsts) {
    capture_ctx_t *ctx = calloc(1, sizeof(capture_ctx_t));
    if (!ctx) return NULL;

    ctx->rb  = rb;
    ctx->cfg = *cfg;
    ctx->nworkers = wanted_workers(cfg, 1);
    ns_mutex_init(&ctx->bpf_mtx);
    for (int i = 0; i < CAPTURE_MAX_WORKERS; i++) {
        ctx->w[i].ctx = ctx;
        ctx->w[i].idx = i;
        ctx->w[i].st  = (sts && i < nsts) ? sts[i] : NULL;
    }

    if (cfg->pcap_file[0]) {
        /* offline mode */
        ctx->w[0].handle = pcap_open_offline(cfg->pcap_file, ctx->errbuf);
        if (!ctx->w[0].handle) {
            fprintf(stderr, "Cannot open pcap file: %s\n", ctx->errbuf);
            ns_mutex_destroy(&ctx->bpf_mtx);
            free(ctx);
            return NULL;
        }
        ctx->offline = 1;
        snprintf(ctx->iface_name, sizeof(ctx->iface_name), "file:%s", cfg->pcap_file);
    } else {
        /* live capture */
        char iface[64];
        if (cfg->iface[0]) {
            snprintf(iface, sizeof(iface), "%s", cfg->iface);
        } else {
            if (find_default_interface(iface, sizeof(iface)) != 0) {
                fprintf(stderr, "No suitable network interface found.\n");
#ifdef __linux__
                fprintf(stderr, "Hint: try running with sudo or set CAP_NET_RAW:\n");
                fprintf(stderr, "  sudo setcap cap_net_raw+ep ./snuffles\n");
#elif defined(__APPLE__)
                fprintf(stderr, "Hint: try running with sudo.\n");
#endif
                ns_mutex_destroy(&ctx->bpf_mtx);
                free(ctx);
                return NULL;
            }
        }

        for (int i = 0; i < ctx->nworkers; i++) {
            ctx->w[i].handle = open_live(cfg, iface, ctx->errbuf);
            if (!ctx->w[i].handle) {
                for (int j = 0; j < i; j++) pcap_close(ctx->w[j].handle);
                ns_mutex_destroy(&ctx->bpf_mtx);
                free(ctx);
                return NULL;
            }
        }

#ifdef __linux__
        /* One fan-out group per process (the group id is what ties the
         * sockets together; another snuffles gets its own). */
        if (ctx->nworkers > 1) {
            char why[128] = "";
            int  group = (int)(getpid() & 0xffff);
            int  ok = 1;
            for (int i = 0; i < ctx->nworkers && ok; i++)
                ok = fanout_join(ctx->w[i].handle, group, why, sizeof(why)) == 0;
            if (!ok) {
                fprintf(stderr, "snuffles: PACKET_FANOUT unavailable (%s); "
                        "capturing with one worker\n", why);
                for (int i = 1; i < ctx->nworkers; i++) {
                    pcap_close(ctx->w[i].handle);
                    ctx->w[i].handle = NULL;
                }
                ctx->nworkers = 1;   /* worker 0 alone still gets every frame */
            }
        }
#endif

        snprintf(ctx->iface_name, sizeof(ctx->iface_name), "%s", iface);
        ctx->iface_mtu = iface_mtu(iface);
    }

    ctx->datalink = pcap_datalink(ctx->w[0].handle);

    /* apply BPF filter to every worker */
    if (cfg->bpf_filter[0]) {
        for (int i = 0; i < ctx->nworkers; i++) {
            struct bpf_program fp;
            pcap_t *h = ctx->w[i].handle;
            if (pcap_compile(h, &fp, cfg->bpf_filter, 1, PCAP_NETMASK_UNKNOWN) != 0) {
                fprintf(stderr, "BPF compile error: %s\n", pcap_geterr(h));
                goto bpf_fail;
            }
            if (pcap_setfilter(h, &fp) != 0) {
                fprintf(stderr, "BPF setfilter error: %s\n", pcap_geterr(h));
                pcap_freecode(&fp);
                goto bpf_fail;
            }
            pcap_freecode(&fp);
            continue;
        bpf_fail:
            for (int j = 0; j < ctx->nworkers; j++)
                if (ctx->w[j].handle) pcap_close(ctx->w[j].handle);
            ns_mutex_destroy(&ctx->bpf_mtx);
            free(ctx);
            return NULL;
        }
        snprintf(ctx->bpf_active, sizeof(ctx->bpf_active), "%s", cfg->bpf_filter);
    }

    /* drop root privileges after capture devices are opened */
#ifndef _WIN32
    if (ns_drop_privileges() != 0)
        fprintf(stderr, "Warning: failed to drop root privileges; "
                        "continuing as root\n");
#endif

    return ctx;
}

int capture_start(capture_ctx_t *ctx) {
    atomic_store(&ctx->stop_req, 0);
    for (int i = 0; i < ctx->nworkers; i++) {
        /* counted before the thread starts, so capture_is_running() is
         * true from here on however the threads are scheduled */
        atomic_fetch_add(&ctx->running, 1);
        if (ns_thread_create(&ctx->w[i].thread, capture_thread_fn,
                             &ctx->w[i]) != 0) {
            atomic_fetch_sub(&ctx->running, 1);
            fprintf(stderr, "Failed to create capture thread\n");
            if (i == 0) return -1;
            /* some workers are up: stop them and carry on with none */
            atomic_store(&ctx->stop_req, 1);
            for (int j = 0; j < i; j++) {
                pcap_breakloop(ctx->w[j].handle);
                ns_thread_join(ctx->w[j].thread);
            }
            return -1;
        }
        ctx->w[i].started = 1;
    }
    return 0;
}

void capture_stop(capture_ctx_t *ctx) {
    if (!ctx) return;
    atomic_store(&ctx->stop_req, 1);
    for (int i = 0; i < ctx->nworkers; i++) {
        if (ctx->w[i].handle)
            pcap_breakloop(ctx->w[i].handle);   /* documented as thread-safe */
    }
    for (int i = 0; i < ctx->nworkers; i++) {
        if (ctx->w[i].started) {
            ns_thread_join(ctx->w[i].thread);
            ctx->w[i].started = 0;
        }
    }
}

void capture_destroy(capture_ctx_t *ctx) {
    if (!ctx) return;
    for (int i = 0; i < ctx->nworkers; i++)
        if (ctx->w[i].handle) pcap_close(ctx->w[i].handle);
    ns_mutex_destroy(&ctx->bpf_mtx);
    free(ctx);
}

int capture_is_running(const capture_ctx_t *ctx) {
    return ctx ? atomic_load(&ctx->running) > 0 : 0;
}

int capture_worker_count(const capture_ctx_t *ctx) {
    return ctx ? ctx->nworkers : 1;
}

int capture_is_offline(const capture_ctx_t *ctx) {
    return ctx ? ctx->offline : 0;
}

void capture_get_stats(capture_ctx_t *ctx, capture_stats_raw_t *out) {
    memset(out, 0, sizeof(*out));
    if (!ctx) return;

    /* No pcap calls here: this runs on the UI thread. Each capture thread
     * publishes its own drop counts; the totals are their sum. */
    out->pkts_recv = ringbuf_total(ctx->rb);
    out->nworkers  = ctx->nworkers;
    for (int i = 0; i < ctx->nworkers; i++) {
        uint64_t d = atomic_load(&ctx->w[i].drops);
        out->kdrop_w[i]   = d;
        out->pkts_drop   += d;
        out->pkts_ifdrop += atomic_load(&ctx->w[i].ifdrops);
    }
}

int capture_get_datalink(const capture_ctx_t *ctx) {
    return ctx ? ctx->datalink : 1;
}

int capture_had_error(const capture_ctx_t *ctx) {
    return ctx ? atomic_load(&ctx->had_error) : 0;
}

const char *capture_error_msg(const capture_ctx_t *ctx) {
    return (ctx && atomic_load(&ctx->had_error)) ? ctx->err_msg : "";
}

const char *capture_get_iface(const capture_ctx_t *ctx) {
    return ctx ? ctx->iface_name : "???";
}

const char *capture_get_bpf(const capture_ctx_t *ctx) {
    if (!ctx) return "";
    return ctx->bpf_active;
}

int capture_set_bpf(capture_ctx_t *ctx, const char *expr,
                    char *errbuf, size_t errlen) {
    if (!ctx || !ctx->w[0].handle) {
        snprintf(errbuf, errlen, "No capture handle");
        return -1;
    }
    if (!expr) expr = "";

    /* Called from the UI thread. Validate the expression on a throwaway
     * dead handle (same datalink/snaplen) so syntax errors are reported
     * immediately, then queue it for the capture thread to apply — the
     * live pcap_t must not be touched from this thread. */
    pcap_t *dead = pcap_open_dead(ctx->datalink, ctx->cfg.snaplen);
    if (!dead) {
        snprintf(errbuf, errlen, "pcap_open_dead failed");
        return -1;
    }
    struct bpf_program fp;
    if (pcap_compile(dead, &fp, expr, 1, PCAP_NETMASK_UNKNOWN) != 0) {
        snprintf(errbuf, errlen, "%s", pcap_geterr(dead));
        pcap_close(dead);
        return -1;
    }
    pcap_freecode(&fp);
    pcap_close(dead);

    ns_mutex_lock(&ctx->bpf_mtx);
    snprintf(ctx->bpf_pending, sizeof(ctx->bpf_pending), "%s", expr);
    ns_mutex_unlock(&ctx->bpf_mtx);
    for (int i = 0; i < ctx->nworkers; i++)
        atomic_store(&ctx->w[i].bpf_req, 1);

    snprintf(ctx->bpf_active, sizeof(ctx->bpf_active), "%s", expr);
    return 0;
}

int capture_list_interfaces(void) {
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) != 0) {
        fprintf(stderr, "pcap_findalldevs: %s\n", errbuf);
        return -1;
    }

    int idx = 0;
    for (pcap_if_t *d = alldevs; d; d = d->next) {
        printf("%d. %s", ++idx, d->name);
        if (d->description) printf(" (%s)", d->description);
        if (d->flags & PCAP_IF_LOOPBACK) printf(" [Loopback]");
        if (d->flags & PCAP_IF_UP)       printf(" [Up]");

        for (pcap_addr_t *a = d->addresses; a; a = a->next) {
            if (a->addr && a->addr->sa_family == AF_INET) {
                char ip[INET_ADDRSTRLEN];
                struct sockaddr_in *sin = (struct sockaddr_in *)a->addr;
                inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
                printf(" %s", ip);
            }
        }
        printf("\n");
    }

    if (idx == 0) printf("No interfaces found.\n");

    pcap_freealldevs(alldevs);
    return 0;
}
