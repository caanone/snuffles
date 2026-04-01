#include "capture.h"
#include "dissect.h"
#include "syslog_out.h"
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

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
    volatile int        running;
    volatile int        stop_req;
    int                 datalink;
    int                 offline;
    uint64_t            pkt_count;
    char                errbuf[PCAP_ERRBUF_SIZE];
    char                iface_name[64];
    char                bpf_active[512];
    syslog_out_t       *syslog;
};

/* ── Capture callback ────────────────────────────────────────── */

static void capture_callback(u_char *user, const struct pcap_pkthdr *hdr,
                             const u_char *data) {
    capture_ctx_t *ctx = (capture_ctx_t *)user;

    if (ctx->stop_req) {
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

    /* update session table */
    if (ctx->st) {
        session_entry_t *se = session_table_update(ctx->st, &rec->summary);
        if (se) rec->summary.session_id = se->id;
    }

    /* syslog output (skip our own syslog traffic to prevent feedback loop) */
    if (ctx->syslog && !syslog_out_is_self(ctx->syslog, &rec->summary))
        syslog_out_send(ctx->syslog, &rec->summary);

    ringbuf_producer_commit(ctx->rb);

    ctx->pkt_count++;
    if (ctx->cfg.count > 0 && ctx->pkt_count >= (uint64_t)ctx->cfg.count) {
        pcap_breakloop(ctx->handle);
    }
}

/* ── Capture thread ──────────────────────────────────────────── */

static void *capture_thread_fn(void *arg) {
    capture_ctx_t *ctx = (capture_ctx_t *)arg;
    ctx->running = 1;

    while (!ctx->stop_req) {
        int ret = pcap_dispatch(ctx->handle, 64, capture_callback, (u_char *)ctx);
        if (ret == PCAP_ERROR_BREAK || ret == 0) {
            if (ctx->offline) break;
            if (ctx->stop_req) break;
        }
        if (ret == PCAP_ERROR) {
            fprintf(stderr, "pcap error: %s\n", pcap_geterr(ctx->handle));
            break;
        }
    }

    ctx->running = 0;
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

    /* drop root privileges after capture device is opened */
#ifndef _WIN32
    if (geteuid() == 0) {
        uid_t orig_uid = getuid();
        if (orig_uid != 0) {
            /* started via sudo: drop back to the real user */
            if (setgid(getgid()) == 0)
                setuid(orig_uid);
        } else {
            /* truly running as root: try to drop to nobody */
            struct passwd *pw = getpwnam("nobody");
            if (pw) {
                setgid(pw->pw_gid);
                setuid(pw->pw_uid);
            }
        }
    }
#endif

    /* open syslog output if configured */
    if (cfg->syslog_target[0]) {
        ctx->syslog = syslog_out_create(cfg->syslog_target, cfg->syslog_iface);
        if (!ctx->syslog)
            fprintf(stderr, "Warning: syslog output disabled\n");
    }

    return ctx;
}

int capture_start(capture_ctx_t *ctx) {
    ctx->stop_req = 0;
    ctx->running  = 1; /* set before thread starts to avoid race */
    if (ns_thread_create(&ctx->thread, capture_thread_fn, ctx) != 0) {
        ctx->running = 0;
        fprintf(stderr, "Failed to create capture thread\n");
        return -1;
    }
    return 0;
}

void capture_stop(capture_ctx_t *ctx) {
    if (!ctx) return;
    ctx->stop_req = 1;
    if (ctx->handle)
        pcap_breakloop(ctx->handle);
    ns_thread_join(ctx->thread);
}

void capture_destroy(capture_ctx_t *ctx) {
    if (!ctx) return;
    syslog_out_destroy(ctx->syslog);
    if (ctx->handle)
        pcap_close(ctx->handle);
    free(ctx);
}

int capture_is_running(const capture_ctx_t *ctx) {
    return ctx ? ctx->running : 0;
}

int capture_is_offline(const capture_ctx_t *ctx) {
    return ctx ? ctx->offline : 0;
}

void capture_get_stats(capture_ctx_t *ctx, capture_stats_raw_t *out) {
    memset(out, 0, sizeof(*out));
    if (!ctx || !ctx->handle) return;

    out->pkts_recv = ringbuf_total(ctx->rb);

    struct pcap_stat ps;
    if (pcap_stats(ctx->handle, &ps) == 0) {
        out->pkts_drop = ps.ps_drop;
    }
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

    struct bpf_program fp;

    if (!expr || !expr[0]) {
        /* clear filter — install empty program to accept all */
        if (pcap_compile(ctx->handle, &fp, "", 1, PCAP_NETMASK_UNKNOWN) != 0) {
            snprintf(errbuf, errlen, "%s", pcap_geterr(ctx->handle));
            return -1;
        }
    } else {
        if (pcap_compile(ctx->handle, &fp, expr, 1, PCAP_NETMASK_UNKNOWN) != 0) {
            snprintf(errbuf, errlen, "%s", pcap_geterr(ctx->handle));
            return -1;
        }
    }

    if (pcap_setfilter(ctx->handle, &fp) != 0) {
        snprintf(errbuf, errlen, "%s", pcap_geterr(ctx->handle));
        pcap_freecode(&fp);
        return -1;
    }

    pcap_freecode(&fp);
    snprintf(ctx->bpf_active, sizeof(ctx->bpf_active), "%s", expr ? expr : "");
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
