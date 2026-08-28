#include "capture.h"
#include "dissect.h"
#include "export_pcap.h"
#include "syslog_out.h"
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdatomic.h>
#ifdef __linux__
  #include <sys/prctl.h>
#endif

#ifndef _WIN32
  #include <unistd.h>
  #include <sys/types.h>
  #include <pwd.h>
#endif

struct capture_ctx {
    pcap_t             *handle;
    ringbuf_t          *rb;
    session_table_t    *st;
    capture_cfg_t       cfg;
    ns_thread_t         thread;
    atomic_int          running;
    atomic_int          stop_req;
    int                 datalink;
    int                 offline;
    uint64_t            pkt_count;      /* capture thread only */
    atomic_uint_fast64_t drops;         /* published by capture thread */
    atomic_uint_fast64_t ifdrops;       /* pcap ps_ifdrop */
    atomic_uint_fast64_t stream_pkts;   /* -w packets written */
    char                errbuf[PCAP_ERRBUF_SIZE];
    char                iface_name[64];
    char                bpf_active[512]; /* UI thread only (after create) */
    syslog_out_t       *syslog;

    /* BPF changes are queued here by the UI thread and applied by the
     * capture thread between dispatch calls: the pcap_t handle must only
     * be used from the capture thread (pcap_breakloop excepted). */
    ns_mutex_t          bpf_mtx;
    char                bpf_pending[512];
    atomic_int          bpf_req;

    pcap_writer_t      *stream;     /* -w: capture thread only */

    atomic_int          had_error;  /* set by the capture thread on fatal error */
    char                err_msg[256]; /* written before had_error is set */
};

/* ── Capture callback ────────────────────────────────────────── */

static void capture_callback(u_char *user, const struct pcap_pkthdr *hdr,
                             const u_char *data) {
    capture_ctx_t *ctx = (capture_ctx_t *)user;

    if (atomic_load(&ctx->stop_req)) {
        pcap_breakloop(ctx->handle);
        return;
    }

    pkt_record_t *rec = ringbuf_producer_next(ctx->rb);

    /* copy raw packet data */
    uint32_t copylen = hdr->caplen;
    if (copylen > (uint32_t)ctx->cfg.snaplen)
        copylen = (uint32_t)ctx->cfg.snaplen;
    memcpy(rec->raw_data, data, copylen);
    rec->raw_len = copylen;

    /* dissect */
    dissect_packet(data, hdr->caplen, ctx->datalink, &rec->summary);
    rec->summary.ts     = hdr->ts;
    rec->summary.length = hdr->len;

    /* update session table (TCP payload bytes clamped to what we copied) */
    if (ctx->st) {
        const uint8_t *pl = NULL;
        uint32_t pln = 0;
        if (rec->summary.l4_proto == PROTO_TCP && rec->summary.l7_len > 0 &&
            rec->summary.l7_off < rec->raw_len) {
            pl  = rec->raw_data + rec->summary.l7_off;
            pln = rec->summary.l7_len;
            if (pln > rec->raw_len - rec->summary.l7_off)
                pln = rec->raw_len - rec->summary.l7_off;
        }
        uint32_t sid = session_table_update(ctx->st, &rec->summary, pl, pln);
        if (sid) rec->summary.session_id = sid;
    }

    /* syslog output (skip our own syslog traffic to prevent feedback loop) */
    if (ctx->syslog && !syslog_out_is_self(ctx->syslog, &rec->summary))
        syslog_out_send(ctx->syslog, &rec->summary);

    /* streaming -w write (before commit: the slot is still ours) */
    if (ctx->stream) {
        if (pcap_writer_write(ctx->stream, rec) != 0) {
            fprintf(stderr, "stream write failed; disabling -w output\n");
            pcap_writer_close(ctx->stream);
            ctx->stream = NULL;
        } else {
            atomic_fetch_add_explicit(&ctx->stream_pkts, 1, memory_order_relaxed);
        }
    }

    ringbuf_producer_commit(ctx->rb);

    ctx->pkt_count++;
    if (ctx->cfg.count > 0 && ctx->pkt_count >= (uint64_t)ctx->cfg.count) {
        pcap_breakloop(ctx->handle);
    }
}

/* ── Capture thread ──────────────────────────────────────────── */

/* Runs on the capture thread between dispatch calls. */
static void apply_pending_bpf(capture_ctx_t *ctx) {
    char expr[sizeof(ctx->bpf_pending)];
    ns_mutex_lock(&ctx->bpf_mtx);
    memcpy(expr, ctx->bpf_pending, sizeof(expr));
    ns_mutex_unlock(&ctx->bpf_mtx);

    struct bpf_program fp;
    if (pcap_compile(ctx->handle, &fp, expr, 1, PCAP_NETMASK_UNKNOWN) != 0) {
        fprintf(stderr, "BPF compile error: %s\n", pcap_geterr(ctx->handle));
        return;
    }
    if (pcap_setfilter(ctx->handle, &fp) != 0)
        fprintf(stderr, "BPF setfilter error: %s\n", pcap_geterr(ctx->handle));
    pcap_freecode(&fp);
}

static void *capture_thread_fn(void *arg) {
    capture_ctx_t *ctx = (capture_ctx_t *)arg;
    atomic_store(&ctx->running, 1);
#ifdef __linux__
    prctl(PR_SET_NAME, "snf-capture", 0, 0, 0);
#endif

    while (!atomic_load(&ctx->stop_req)) {
        if (atomic_exchange(&ctx->bpf_req, 0))
            apply_pending_bpf(ctx);

        int ret = pcap_dispatch(ctx->handle, 64, capture_callback, (u_char *)ctx);

        /* One non-blocking sendmmsg() per dispatch cycle for whatever the
         * callbacks queued: a record waits at most one cycle (<= 100 ms)
         * instead of costing a syscall each. */
        syslog_out_flush(ctx->syslog);

        if (!ctx->offline) {
            struct pcap_stat ps;
            if (pcap_stats(ctx->handle, &ps) == 0) {
                atomic_store(&ctx->drops, (uint64_t)ps.ps_drop);
                atomic_store(&ctx->ifdrops, (uint64_t)ps.ps_ifdrop);
            }
        }

        if (ret == PCAP_ERROR_BREAK || ret == 0) {
            if (ctx->offline) break;
            if (atomic_load(&ctx->stop_req)) break;
        }
        if (ret == PCAP_ERROR) {
            /* No stderr here: it would scribble over the TUI. The UI status
             * bar and main's exit path surface the stored message. */
            snprintf(ctx->err_msg, sizeof(ctx->err_msg), "%s",
                     pcap_geterr(ctx->handle));
            atomic_store(&ctx->had_error, 1);
            break;
        }
    }

    syslog_out_flush(ctx->syslog);   /* records queued by the last cycle */
    atomic_store(&ctx->running, 0);
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

capture_ctx_t *capture_create(const capture_cfg_t *cfg, ringbuf_t *rb,
                              session_table_t *st) {
    capture_ctx_t *ctx = calloc(1, sizeof(capture_ctx_t));
    if (!ctx) return NULL;

    ctx->rb  = rb;
    ctx->st  = st;
    ctx->cfg = *cfg;
    ns_mutex_init(&ctx->bpf_mtx);

    if (cfg->pcap_file[0]) {
        /* offline mode */
        ctx->handle = pcap_open_offline(cfg->pcap_file, ctx->errbuf);
        if (!ctx->handle) {
            fprintf(stderr, "Cannot open pcap file: %s\n", ctx->errbuf);
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
                free(ctx);
                return NULL;
            }
        }

        ctx->handle = pcap_create(iface, ctx->errbuf);
        if (!ctx->handle) {
            fprintf(stderr, "pcap_create(%s): %s\n", iface, ctx->errbuf);
            free(ctx);
            return NULL;
        }

        pcap_set_snaplen(ctx->handle, cfg->snaplen);
        pcap_set_promisc(ctx->handle, cfg->promisc);
        pcap_set_timeout(ctx->handle, 100);
#ifdef PCAP_SET_IMMEDIATE_MODE
        pcap_set_immediate_mode(ctx->handle, 1);
#endif

        int err = pcap_activate(ctx->handle);
        if (err < 0) {
            fprintf(stderr, "pcap_activate(%s): %s\n", iface, pcap_geterr(ctx->handle));
#ifdef __APPLE__
            if (err == PCAP_ERROR_PERM_DENIED) {
                fprintf(stderr, "Hint: try running with sudo.\n");
            }
#elif defined(__linux__)
            if (err == PCAP_ERROR_PERM_DENIED) {
                fprintf(stderr, "Hint: run with sudo or set CAP_NET_RAW:\n");
                fprintf(stderr, "  sudo setcap cap_net_raw+ep ./snuffles\n");
            }
#endif
            pcap_close(ctx->handle);
            free(ctx);
            return NULL;
        }

        snprintf(ctx->iface_name, sizeof(ctx->iface_name), "%s", iface);
    }

    ctx->datalink = pcap_datalink(ctx->handle);

    /* apply BPF filter */
    if (cfg->bpf_filter[0]) {
        struct bpf_program fp;
        if (pcap_compile(ctx->handle, &fp, cfg->bpf_filter, 1, PCAP_NETMASK_UNKNOWN) != 0) {
            fprintf(stderr, "BPF compile error: %s\n", pcap_geterr(ctx->handle));
            pcap_close(ctx->handle);
            free(ctx);
            return NULL;
        }
        if (pcap_setfilter(ctx->handle, &fp) != 0) {
            fprintf(stderr, "BPF setfilter error: %s\n", pcap_geterr(ctx->handle));
            pcap_freecode(&fp);
            pcap_close(ctx->handle);
            free(ctx);
            return NULL;
        }
        pcap_freecode(&fp);
        snprintf(ctx->bpf_active, sizeof(ctx->bpf_active), "%s", cfg->bpf_filter);
    }

    /* open syslog output if configured: before the privilege drop, so the
       16 MB send buffer (SO_SNDBUFFORCE) and --syslog-iface <dev>
       (SO_BINDTODEVICE) get the capabilities they need */
    if (cfg->syslog_target[0]) {
        ctx->syslog = syslog_out_create(cfg->syslog_target, cfg->syslog_iface);
        if (!ctx->syslog)
            fprintf(stderr, "Warning: syslog output disabled\n");
    }

    /* drop root privileges after capture device is opened */
#ifndef _WIN32
    if (ns_drop_privileges() != 0)
        fprintf(stderr, "Warning: failed to drop root privileges; "
                        "continuing as root\n");
#endif

    /* streaming -w writer (opened after the privilege drop so the file is
       owned by the invoking user, not root) */
    if (cfg->stream_file[0]) {
        ctx->stream = pcap_writer_open(cfg->stream_file, (uint32_t)cfg->snaplen,
                                       (uint32_t)ctx->datalink);
        if (!ctx->stream)
            fprintf(stderr, "Warning: cannot open '%s' for -w streaming\n",
                    cfg->stream_file);
    }

    return ctx;
}

int capture_start(capture_ctx_t *ctx) {
    atomic_store(&ctx->stop_req, 0);
    atomic_store(&ctx->running, 1); /* set before thread starts to avoid race */
    if (ns_thread_create(&ctx->thread, capture_thread_fn, ctx) != 0) {
        atomic_store(&ctx->running, 0);
        fprintf(stderr, "Failed to create capture thread\n");
        return -1;
    }
    return 0;
}

void capture_stop(capture_ctx_t *ctx) {
    if (!ctx) return;
    atomic_store(&ctx->stop_req, 1);
    if (ctx->handle)
        pcap_breakloop(ctx->handle);   /* documented as thread-safe */
    ns_thread_join(ctx->thread);
}

void capture_destroy(capture_ctx_t *ctx) {
    if (!ctx) return;
    if (ctx->stream) {
        uint64_t n = pcap_writer_count(ctx->stream);
        if (pcap_writer_close(ctx->stream) != 0)
            fprintf(stderr, "Warning: error finalizing -w stream file\n");
        else
            fprintf(stderr, "Streamed %llu packets to %s\n",
                    (unsigned long long)n, ctx->cfg.stream_file);
        ctx->stream = NULL;
    }
    syslog_out_destroy(ctx->syslog);
    if (ctx->handle)
        pcap_close(ctx->handle);
    ns_mutex_destroy(&ctx->bpf_mtx);
    free(ctx);
}

int capture_is_running(const capture_ctx_t *ctx) {
    return ctx ? atomic_load(&ctx->running) : 0;
}

int capture_is_offline(const capture_ctx_t *ctx) {
    return ctx ? ctx->offline : 0;
}

void capture_get_stats(capture_ctx_t *ctx, capture_stats_raw_t *out) {
    memset(out, 0, sizeof(*out));
    if (!ctx) return;

    /* No pcap calls here: this runs on the UI thread. The capture thread
     * publishes drop counts into ctx->drops. */
    out->pkts_recv   = ringbuf_total(ctx->rb);
    out->pkts_drop   = atomic_load(&ctx->drops);
    out->pkts_ifdrop = atomic_load(&ctx->ifdrops);
    out->stream_pkts = atomic_load_explicit(&ctx->stream_pkts, memory_order_relaxed);
    syslog_out_counts(ctx->syslog, &out->syslog_sent, &out->syslog_failed);
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
    if (!ctx || !ctx->handle) {
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
    atomic_store(&ctx->bpf_req, 1);

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
