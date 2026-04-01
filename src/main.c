#include "snuffles.h"
#include "ringbuf.h"
#include "capture.h"
#include "dissect.h"
#include "filter.h"
#include "stats.h"
#include "ui.h"
#include "session.h"
#include "export_pcap.h"
#include "export_json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>

#ifndef _WIN32
  #include <unistd.h>
  #include <sys/select.h>
#endif

/* ── Globals (minimal, per spec) ─────────────────────────────── */

static volatile sig_atomic_t g_stop = 0;
static capture_ctx_t        *g_capture = NULL;
static ui_ctx_t             *g_ui = NULL;

/* ── Signal handler ──────────────────────────────────────────── */

static void signal_handler(int sig) {
    (void)sig;
    g_stop = 1;
    /* only set volatile flags — async-signal-safe */
    if (g_ui) ui_request_stop(g_ui);
    /* pcap_breakloop is NOT guaranteed async-signal-safe;
       the main loop checks g_stop and calls capture_stop itself */
}

/* ── Usage ───────────────────────────────────────────────────── */

static void print_usage(const char *prog) {
    printf("Usage: %s [OPTIONS]\n\n"
           "Options:\n"
           "  -i <iface>        Interface to capture on (default: auto)\n"
           "  -r <file.pcap>    Read from pcap file instead of live capture\n"
           "  -f <bpf_filter>   BPF capture filter (e.g. \"tcp port 80\")\n"
           "  -c <count>        Stop after N packets\n"
           "  -s <snaplen>      Snapshot length (default: 65535)\n"
           "  -b <ring_size>    Ring buffer size (default: 10000)\n"
           "  -o <file>         Auto-export on exit (.pcap or .json)\n"
           "  --no-ui           Headless mode (print to stdout)\n"
           "  --syslog <h:p>   Send packet CSV to syslog server (UDP)\n"
           "  --syslog-iface <ip|dev>  Source interface/IP for syslog\n"
           "  --list-ifaces     List available interfaces and exit\n"
           "  -v                Print version and exit\n"
           "  -h, --help        Show this help\n",
           prog);
}

static void print_version(void) {
    printf("%s v%s\n", SNUFFLES_NAME, SNUFFLES_VERSION_STR);
    printf("Built: %s %s\n", __DATE__, __TIME__);
#ifdef __clang__
    printf("Compiler: clang %s\n", __clang_version__);
#elif defined(__GNUC__)
    printf("Compiler: gcc %d.%d.%d\n", __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
#endif
}

/* ── Headless mode ───────────────────────────────────────────── */

static void run_headless(ringbuf_t *rb, capture_ctx_t *cap) {
    uint64_t last = 0;
    int notify_fd = ringbuf_get_notify_fd(rb);

    while (!g_stop) {
#ifndef _WIN32
        fd_set fds;
        struct timeval tv = { .tv_sec = 0, .tv_usec = 100000 };
        FD_ZERO(&fds);
        if (notify_fd >= 0) {
            FD_SET(notify_fd, &fds);
            select(notify_fd + 1, &fds, NULL, NULL, &tv);
            if (FD_ISSET(notify_fd, &fds))
                ringbuf_drain_notify(rb);
        } else {
            select(0, NULL, NULL, NULL, &tv);
        }
#else
        Sleep(100);
#endif

        uint64_t total = ringbuf_total(rb);
        uint32_t count = ringbuf_count(rb);

        /* if ring wrapped past us, jump to oldest available */
        if (total > (uint64_t)count && last < total - count)
            last = total - count;

        while (last < total) {
            /* convert absolute seq to ring index */
            uint64_t oldest_seq = (total > count) ? total - count : 0;
            uint32_t idx = (uint32_t)(last - oldest_seq);

            const pkt_record_t *rec = ringbuf_peek(rb, idx);
            if (rec) {
                const pkt_summary_t *s = &rec->summary;
                long sec = (long)(s->ts.tv_sec % 86400);
                printf("%02ld:%02ld:%02ld.%06ld  %-21s -> %-21s  %-6s  %s\n",
                       sec / 3600, (sec % 3600) / 60, sec % 60,
                       (long)s->ts.tv_usec,
                       s->src_ip[0] ? s->src_ip : s->src_mac,
                       s->dst_ip[0] ? s->dst_ip : s->dst_mac,
                       s->protocol, s->info);
                fflush(stdout);
            }
            last++;
        }

        /* only exit after capture thread finishes AND we've printed everything */
        if (!capture_is_running(cap) && ringbuf_total(rb) <= last)
            break;
    }
}

/* ── Main ────────────────────────────────────────────────────── */

int main(int argc, char *argv[]) {
    capture_cfg_t cfg;
    capture_cfg_defaults(&cfg);

    static struct option long_opts[] = {
        {"interface",   required_argument, 0, 'i'},
        {"read",        required_argument, 0, 'r'},
        {"filter",      required_argument, 0, 'f'},
        {"count",       required_argument, 0, 'c'},
        {"snaplen",     required_argument, 0, 's'},
        {"ring-size",   required_argument, 0, 'b'},
        {"output",      required_argument, 0, 'o'},
        {"no-ui",       no_argument,       0, 'N'},
        {"list-ifaces", no_argument,       0, 'L'},
        {"syslog",       required_argument, 0, 'Y'},
        {"syslog-iface", required_argument, 0, 'Z'},
        {"version",     no_argument,       0, 'v'},
        {"help",        no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "i:r:f:c:s:b:o:vh", long_opts, NULL)) != -1) {
        switch (opt) {
            case 'i': snprintf(cfg.iface,      sizeof(cfg.iface),      "%s", optarg); break;
            case 'r': snprintf(cfg.pcap_file,   sizeof(cfg.pcap_file),  "%s", optarg); break;
            case 'f': snprintf(cfg.bpf_filter,  sizeof(cfg.bpf_filter), "%s", optarg); break;
            case 'o': snprintf(cfg.output_file, sizeof(cfg.output_file),"%s", optarg); break;
            case 'c': cfg.count     = atoi(optarg); break;
            case 's': cfg.snaplen   = atoi(optarg); break;
            case 'b': cfg.ring_size = atoi(optarg); break;
            case 'N': cfg.no_ui       = 1; break;
            case 'L': cfg.list_ifaces = 1; break;
            case 'Y': snprintf(cfg.syslog_target, sizeof(cfg.syslog_target), "%s", optarg); break;
            case 'Z': snprintf(cfg.syslog_iface, sizeof(cfg.syslog_iface), "%s", optarg); break;
            case 'v': print_version(); return 0;
            case 'h': print_usage(argv[0]); return 0;
            default:  print_usage(argv[0]); return 1;
        }
    }

    if (cfg.list_ifaces) {
        return capture_list_interfaces();
    }

    /* validate parameters */
    if (cfg.snaplen < 64)    cfg.snaplen = 64;
    if (cfg.snaplen > 65535) cfg.snaplen = 65535;
    if (cfg.ring_size < 16)      cfg.ring_size = 16;
    if (cfg.ring_size > 1000000) cfg.ring_size = 1000000;
    if (cfg.count < 0) cfg.count = 0;

    /* in headless mode, minimize memory: tiny ring buffer, skip session table
       if no export is needed (syslog sends directly from capture thread) */
    int headless_minimal = (cfg.no_ui && !cfg.output_file[0]);
    if (headless_minimal) {
        cfg.ring_size = 64;    /* tiny scratch buffer */
        if (cfg.syslog_target[0] && cfg.snaplen > 256)
            cfg.snaplen = 256; /* syslog only needs headers, not payload */
    }

    /* create ring buffer */
    ringbuf_t *rb = ringbuf_create((uint32_t)cfg.ring_size, (uint32_t)cfg.snaplen);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer (%d slots x %d bytes)\n",
                cfg.ring_size, cfg.snaplen);
        return 1;
    }

    /* create session table (skip in headless-minimal mode to save memory) */
    session_table_t *sessions = headless_minimal ? NULL : session_table_create(4096);

    /* create capture context */
    capture_ctx_t *cap = capture_create(&cfg, rb, sessions);
    if (!cap) {
        session_table_destroy(sessions);
        ringbuf_destroy(rb);
        return 1;
    }
    g_capture = cap;

    /* install signal handlers */
    signal(SIGINT,  signal_handler);
    signal(SIGTERM, signal_handler);
#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);
#endif

    /* start capture thread */
    if (capture_start(cap) != 0) {
        capture_destroy(cap);
        ringbuf_destroy(rb);
        return 1;
    }

    if (cfg.no_ui) {
        run_headless(rb, cap);
    } else {
        ui_ctx_t *ui = ui_create(rb, cap, &cfg, sessions);
        if (!ui) {
            fprintf(stderr, "Failed to create UI\n");
            capture_stop(cap);
            capture_destroy(cap);
            ringbuf_destroy(rb);
            return 1;
        }
        g_ui = ui;
        ui_run(ui);
        g_ui = NULL;
        ui_destroy(ui);
    }

    /* stop capture */
    capture_stop(cap);

    /* auto-export if -o specified */
    if (cfg.output_file[0]) {
        size_t plen = strlen(cfg.output_file);
        display_filter_t no_filter = { .valid = true, .root = -1 };

        if (plen > 5 && strcmp(cfg.output_file + plen - 5, ".json") == 0) {
            int n = export_json(cfg.output_file, rb, &no_filter,
                                capture_get_iface(cap), cfg.bpf_filter);
            fprintf(stderr, "Exported %d packets to %s\n", n, cfg.output_file);
        } else {
            int n = export_pcap(cfg.output_file, rb, &no_filter,
                                (uint32_t)cfg.snaplen);
            fprintf(stderr, "Exported %d packets to %s\n", n, cfg.output_file);
        }
    }

    capture_destroy(cap);
    g_capture = NULL;
    session_table_destroy(sessions);
    ringbuf_destroy(rb);

    return 0;
}
