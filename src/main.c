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

/* ── Signal handler ──────────────────────────────────────────── */

static void signal_handler(int sig) {
    (void)sig;
    g_stop = 1;
    /* only sets sig_atomic_t flags — async-signal-safe, and no pointer
       that teardown could have freed */
    ui_request_stop_async();
    /* pcap_breakloop is NOT guaranteed async-signal-safe;
       the main loop checks g_stop and calls capture_stop itself */
}

/* ── Strict numeric option parsing ───────────────────────────── */

static long parse_num(const char *s, const char *what, long lo, long hi) {
    char *end;
    long v = strtol(s, &end, 10);
    if (end == s || *end != '\0' || v < lo || v > hi) {
        fprintf(stderr, "snuffles: invalid %s '%s' (expected %ld-%ld)\n",
                what, s, lo, hi);
        exit(1);
    }
    return v;
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
           "  -w <file>         Stream packets to a pcap file while capturing\n"
           "                    ('-w -' writes to stdout; combine with -q)\n"
           "  --no-ui           Headless mode (print to stdout)\n"
           "  --jsonl           Headless mode, one JSON object per packet\n"
           "  -q, --quiet       Silent mode (no terminal output, use with --syslog)\n"
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

static void run_headless(ringbuf_t *rb, capture_ctx_t *cap,
                         const capture_cfg_t *cfg) {
    if (cfg->quiet) {
        /* silent mode: capture thread handles syslog, we just wait */
        while (!g_stop) {
#ifndef _WIN32
            struct timeval tv = { .tv_sec = 0, .tv_usec = 200000 };
            select(0, NULL, NULL, NULL, &tv);
#else
            Sleep(200);
#endif
            if (!capture_is_running(cap)) break;
        }
        return;
    }

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
            uint64_t oldest_seq = (total > count) ? total - count : 0;
            uint32_t idx = (uint32_t)(last - oldest_seq);

            pkt_record_t rec;
            if (ringbuf_read(rb, idx, &rec, NULL)) {
                const pkt_summary_t *s = &rec.summary;
                if (cfg->jsonl) {
                    json_line_write(stdout, s);
                } else {
                    time_t tsec = (time_t)s->ts.tv_sec;
                    struct tm lt;
                    if (ns_localtime(&tsec, &lt))
                        printf("%02d:%02d:%02d.%06ld  %-21s -> %-21s  %-6s  %s\n",
                               lt.tm_hour, lt.tm_min, lt.tm_sec,
                               (long)s->ts.tv_usec,
                               s->src_ip[0] ? s->src_ip : s->src_mac,
                               s->dst_ip[0] ? s->dst_ip : s->dst_mac,
                               s->protocol, s->info);
                }
                fflush(stdout);
            }
            last++;
        }

        if (ferror(stdout))   /* reader went away (pipe closed) */
            break;

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
        {"write",       required_argument, 0, 'w'},
        {"no-ui",       no_argument,       0, 'N'},
        {"quiet",       no_argument,       0, 'q'},
        {"jsonl",       no_argument,       0, 'J'},
        {"list-ifaces", no_argument,       0, 'L'},
        {"syslog",       required_argument, 0, 'Y'},
        {"syslog-iface", required_argument, 0, 'Z'},
        {"version",     no_argument,       0, 'v'},
        {"help",        no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    int ring_set = 0, snaplen_set = 0;
    while ((opt = getopt_long(argc, argv, "i:r:f:c:s:b:o:w:qvh", long_opts, NULL)) != -1) {
        switch (opt) {
            case 'i': snprintf(cfg.iface,      sizeof(cfg.iface),      "%s", optarg); break;
            case 'r': snprintf(cfg.pcap_file,   sizeof(cfg.pcap_file),  "%s", optarg); break;
            case 'f': snprintf(cfg.bpf_filter,  sizeof(cfg.bpf_filter), "%s", optarg); break;
            case 'o': snprintf(cfg.output_file, sizeof(cfg.output_file),"%s", optarg); break;
            case 'w': snprintf(cfg.stream_file, sizeof(cfg.stream_file),"%s", optarg); break;
            case 'c': cfg.count     = (int)parse_num(optarg, "count", 1, 1000000000); break;
            case 's': cfg.snaplen   = (int)parse_num(optarg, "snaplen", 64, 65535);
                      snaplen_set = 1; break;
            case 'b': cfg.ring_size = (int)parse_num(optarg, "ring size", 16, 1000000);
                      ring_set    = 1; break;
            case 'N': cfg.no_ui       = 1; break;
            case 'q': cfg.quiet      = 1; cfg.no_ui = 1; break;
            case 'J': cfg.jsonl      = 1; cfg.no_ui = 1; break;
            case 'L': cfg.list_ifaces = 1; break;
            case 'Y': snprintf(cfg.syslog_target, sizeof(cfg.syslog_target), "%s", optarg); break;
            case 'Z': snprintf(cfg.syslog_iface, sizeof(cfg.syslog_iface), "%s", optarg); break;
            case 'v': print_version(); return 0;
            case 'h': print_usage(argv[0]); return 0;
            default:  print_usage(argv[0]); return 1;
        }
    }

    if (optind < argc) {
        fprintf(stderr, "snuffles: unexpected argument '%s'\n\n", argv[optind]);
        print_usage(argv[0]);
        return 1;
    }

    if (cfg.list_ifaces) {
        return capture_list_interfaces();
    }

    if (cfg.stream_file[0] && strcmp(cfg.stream_file, "-") == 0 && !cfg.quiet) {
        fprintf(stderr, "snuffles: '-w -' writes pcap to stdout; combine it "
                        "with -q so text output does not corrupt the stream\n");
        return 1;
    }

    if (cfg.quiet && !cfg.syslog_target[0] && !cfg.stream_file[0])
        fprintf(stderr, "Warning: -q without --syslog captures packets "
                        "but produces no output anywhere\n");

    /* Lean mode (tiny ring, no session table) applies only to the syslog
       forwarding modes documented in the README: headless/quiet WITH
       --syslog and no export file. Plain --no-ui keeps the full ring and
       sessions, and explicit -b/-s always win. */
    int headless_minimal = (cfg.no_ui && cfg.syslog_target[0] &&
                            !cfg.output_file[0]);
    if (headless_minimal) {
        if (!ring_set)
            cfg.ring_size = 64;    /* tiny scratch buffer */
        if (!snaplen_set && cfg.snaplen > 256)
            cfg.snaplen = 256;     /* syslog only needs headers */
    }

#ifndef _WIN32
    /* The TUI writes raw ANSI and needs key input: refuse pipes early. */
    if (!cfg.no_ui && (!isatty(STDOUT_FILENO) || !isatty(STDIN_FILENO))) {
        fprintf(stderr, "snuffles: the TUI needs a terminal on stdin/stdout; "
                        "use --no-ui when piping.\n");
        return 1;
    }
#endif

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
        session_table_destroy(sessions);
        ringbuf_destroy(rb);
        return 1;
    }

    if (cfg.no_ui) {
        run_headless(rb, cap, &cfg);
    } else {
        ui_ctx_t *ui = ui_create(rb, cap, &cfg, sessions);
        if (!ui) {
            fprintf(stderr, "Failed to create UI\n");
            capture_stop(cap);
            capture_destroy(cap);
            session_table_destroy(sessions);
            ringbuf_destroy(rb);
            return 1;
        }
        ui_run(ui);
        ui_destroy(ui);
    }

    /* stop capture */
    capture_stop(cap);

    /* auto-export if -o specified */
    int exit_rc = 0;
    if (cfg.output_file[0]) {
        size_t plen = strlen(cfg.output_file);
        display_filter_t no_filter = { .valid = true, .root = -1 };
        int n;

        if (plen > 5 && strcmp(cfg.output_file + plen - 5, ".json") == 0) {
            n = export_json(cfg.output_file, rb, &no_filter,
                            capture_get_iface(cap), cfg.bpf_filter);
        } else {
            n = export_pcap(cfg.output_file, rb, &no_filter,
                            (uint32_t)cfg.snaplen,
                            capture_get_datalink(cap));
        }
        if (n < 0) {
            fprintf(stderr, "Export FAILED: %s\n", cfg.output_file);
            exit_rc = 1;
        } else {
            fprintf(stderr, "Exported %d packets to %s\n", n, cfg.output_file);
        }
    }

    if (capture_had_error(cap)) {
        fprintf(stderr, "capture error: %s\n", capture_error_msg(cap));
        exit_rc = 1;
    }

    capture_destroy(cap);
    g_capture = NULL;
    session_table_destroy(sessions);
    ringbuf_destroy(rb);

    return exit_rc;
}
