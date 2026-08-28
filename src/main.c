#include "snuffles.h"
#include "config.h"
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
#include <stdatomic.h>

#ifndef _WIN32
  #include <sys/time.h>
#endif
#ifdef __linux__
  #include <sys/prctl.h>
#endif

#ifndef _WIN32
  #include <unistd.h>
  #include <sys/select.h>
  #include <errno.h>
  #include <pthread.h>
  #include <sched.h>
#else
  #include <io.h>          /* _isatty, _fileno */
#endif
#ifdef __linux__
  #include <sys/syscall.h>
#endif

/* ── Globals (minimal, per spec) ─────────────────────────────── */

static volatile sig_atomic_t g_stop = 0;
static volatile sig_atomic_t g_usr1 = 0;   /* SIGUSR1: print one stats line */
static capture_ctx_t        *g_capture = NULL;

/* Headless consumer progress: records emitted to stdout and records the
   consumer never saw because the ring wrapped past it (published for the
   --stats reporter). */
static atomic_uint_fast64_t  g_emitted;
static atomic_uint_fast64_t  g_missed;

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

#ifndef _WIN32
static void usr1_handler(int sig) {
    (void)sig;
    g_usr1 = 1;   /* the headless loop / stats thread prints; select()
                     returns EINTR so the line appears at once */
}
#endif

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
           "  -B <MB>           Kernel capture buffer in MB, 1-2047 (default: 64;\n"
           "                    libpcap: TPACKET ring, raw: socket receive buffer)\n"
           "  -o <file>         Auto-export on exit (.pcap or .json)\n"
           "  -w <file>         Stream packets to a pcap file while capturing\n"
           "                    ('-w -' writes to stdout; combine with -q)\n"
           "  --no-ui           Headless mode (print to stdout)\n"
           "  --jsonl           Headless mode, one JSON object per packet\n"
           "  -q, --quiet       Silent mode (no terminal output, use with --syslog)\n"
           "  --syslog <h:p>   Send packet CSV to syslog server (UDP)\n"
           "  --syslog-iface <ip|dev>  Source interface/IP for syslog\n"
           "  --stats[=FILE]    Report capture/drop counters every second and\n"
           "                    at exit (stderr, or FILE; the TUI needs FILE)\n"
           "  --no-summary      Headless modes: no counters line at exit\n"
           "                    (SIGUSR1 prints one at any time)\n"
           "  --cpu <N>         Pin the capture thread to CPU N; headless\n"
           "                    consumers stay off that CPU (Linux)\n"
           "  --rt              Run the capture thread at SCHED_FIFO priority 1\n"
           "                    (needs root/CAP_SYS_NICE; warns and goes on)\n"
           "  --immediate       Deliver packets one at a time instead of in\n"
           "                    10 ms batches (libpcap build; costs CPU)\n"
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

/* ── --stats reporter ────────────────────────────────────────── */

typedef struct {
    FILE               *out;
    ringbuf_t          *rb;
    capture_ctx_t      *cap;
    session_table_t    *st;
    struct timeval      t0;
    atomic_int          stop;
    int                 poll_usr1;   /* this thread answers SIGUSR1 (TUI) */
    ns_thread_t         thread;
} stats_reporter_t;

static void wall_now(struct timeval *tv) {
#ifdef _WIN32
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    uint64_t t = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    t -= 116444736000000000ULL;            /* 1601 -> 1970 epoch, 100 ns units */
    tv->tv_sec  = (long)(t / 10000000);
    tv->tv_usec = (long)((t / 10) % 1000000);
#else
    gettimeofday(tv, NULL);
#endif
}

static double tv_secs(const struct timeval *a, const struct timeval *b) {
    return (double)(a->tv_sec - b->tv_sec) + (double)(a->tv_usec - b->tv_usec) / 1e6;
}

static long rss_kb(void) {
#ifdef __linux__
    FILE *f = fopen("/proc/self/statm", "r");
    if (!f) return -1;
    long size = 0, res = 0;
    int n = fscanf(f, "%ld %ld", &size, &res);
    fclose(f);
    return n == 2 ? res * (long)(sysconf(_SC_PAGESIZE) / 1024) : -1;
#else
    return -1;
#endif
}

static void stats_report_line(stats_reporter_t *r, const char *tag) {
    capture_stats_raw_t cs;
    capture_get_stats(r->cap, &cs);
    struct timeval now;
    wall_now(&now);
    fprintf(r->out,
            "%s t=%.3f captured=%llu kdrop=%llu ifdrop=%llu ring=%u "
            "emitted=%llu missed=%llu syslog_sent=%llu syslog_fail=%llu "
            "streamed=%llu sessions=%u wakeups=%llu rss_kb=%ld\n",
            tag, tv_secs(&now, &r->t0),
            (unsigned long long)cs.pkts_recv,
            (unsigned long long)cs.pkts_drop,
            (unsigned long long)cs.pkts_ifdrop,
            ringbuf_count(r->rb),
            (unsigned long long)atomic_load_explicit(&g_emitted, memory_order_relaxed),
            (unsigned long long)atomic_load_explicit(&g_missed, memory_order_relaxed),
            (unsigned long long)cs.syslog_sent,
            (unsigned long long)cs.syslog_failed,
            (unsigned long long)cs.stream_pkts,
            r->st ? session_table_count(r->st) : 0u,
            (unsigned long long)ringbuf_notify_sent(r->rb),
            rss_kb());
    fflush(r->out);
}

/* SIGUSR1 sets a flag; whoever owns the periodic loop prints the line. */
static void stats_poll_usr1(stats_reporter_t *r) {
    if (g_usr1) {
        g_usr1 = 0;
        stats_report_line(r, "stats");
    }
}

static void *stats_thread_fn(void *arg) {
    stats_reporter_t *r = (stats_reporter_t *)arg;
#ifdef __linux__
    prctl(PR_SET_NAME, "snf-stats", 0, 0, 0);
#endif
    while (!atomic_load(&r->stop)) {
        /* 1 s period in 100 ms slices so shutdown does not wait a full
         * second for this thread to notice stop. */
        for (int i = 0; i < 10 && !atomic_load(&r->stop); i++) {
#ifndef _WIN32
            struct timeval tv = { .tv_sec = 0, .tv_usec = 100000 };
            select(0, NULL, NULL, NULL, &tv);
#else
            Sleep(100);
#endif
            if (r->poll_usr1) stats_poll_usr1(r);
        }
        if (atomic_load(&r->stop)) break;
        stats_report_line(r, "stats");
    }
    return NULL;
}

/* ── Headless mode ───────────────────────────────────────────── */

static void run_headless(ringbuf_t *rb, capture_ctx_t *cap,
                         const capture_cfg_t *cfg, stats_reporter_t *rep) {
    if (cfg->quiet) {
        /* silent mode: capture thread handles syslog, we just wait */
        while (!g_stop) {
#ifndef _WIN32
            struct timeval tv = { .tv_sec = 0, .tv_usec = 200000 };
            select(0, NULL, NULL, NULL, &tv);
#else
            Sleep(200);
#endif
            stats_poll_usr1(rep);
            if (!capture_is_running(cap)) break;
        }
        return;
    }

    /* Offline replay: publish our position so the file reader waits for
     * us instead of lapping the ring (ringbuf_consumer_attach() was done
     * in main before the capture thread started). */
    int publish = capture_is_offline(cap);

    /* A file or pipe consumer gets a 1 MiB fully-buffered stdout and one
       flush per drain batch (below, before every wait): a write() per
       record made this loop the bottleneck under load, so the ring
       wrapped past it (missed= in --stats). A terminal keeps stdio's
       line buffering so interactive output looks the same as before. */
#ifdef _WIN32
    int stdout_tty = _isatty(_fileno(stdout));
#else
    int stdout_tty = isatty(STDOUT_FILENO);
#endif
    /* The buffer is supplied explicitly: given a NULL buf, glibc and musl
       ignore the size and hand out their default block (4 KiB on glibc),
       while BSD libc and MSVC honour it. Static so it outlives the stream;
       exit() flushes it. */
    static char outbuf[1 << 20];
    if (!stdout_tty)
        setvbuf(stdout, outbuf, _IOFBF, sizeof(outbuf));

    uint64_t last = 0;
    int notify_fd = ringbuf_get_notify_fd(rb);

    while (!g_stop) {
#ifndef _WIN32
        struct timeval tv = { .tv_sec = 0, .tv_usec = 100000 };
        if (notify_fd >= 0) {
            /* Only announce a wait when nothing is pending, then re-check:
             * a commit that raced the announcement gets no wakeup, so it
             * must be caught here. Under sustained load the announcement
             * never happens and the producer never touches the pipe. */
            if (ringbuf_total(rb) <= last) {
                ringbuf_consumer_will_wait(rb);
                if (ringbuf_total(rb) <= last) {
                    fd_set fds;
                    FD_ZERO(&fds);
                    FD_SET(notify_fd, &fds);
                    select(notify_fd + 1, &fds, NULL, NULL, &tv);
                }
            }
            ringbuf_drain_notify(rb);
        } else {
            select(0, NULL, NULL, NULL, &tv);
        }
#else
        Sleep(100);
#endif

        stats_poll_usr1(rep);

        uint64_t total = ringbuf_total(rb);
        uint32_t count = ringbuf_count(rb);

        /* if ring wrapped past us, jump to oldest available */
        if (total > (uint64_t)count && last < total - count) {
            atomic_fetch_add_explicit(&g_missed, (total - count) - last,
                                      memory_order_relaxed);
            last = total - count;
        }

        while (last < total) {
            /* Read by absolute sequence: the ring's floor keeps moving while
             * we drain, so an index computed once per batch would silently
             * shift to a different (newer) record after a lap. */
            pkt_record_t rec;
            if (ringbuf_read_seq(rb, last, &rec, NULL)) {
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
                atomic_fetch_add_explicit(&g_emitted, 1, memory_order_relaxed);
            } else {
                atomic_fetch_add_explicit(&g_missed, 1, memory_order_relaxed);
            }
            last++;
            if (publish) ringbuf_consumer_publish(rb, last);
        }

        /* One flush per batch, before blocking in select() above. SIGPIPE
           is ignored, so a closed pipe surfaces here as a write error. */
        fflush(stdout);
        if (ferror(stdout))   /* reader went away (pipe closed) */
            break;

        if (!capture_is_running(cap) && ringbuf_total(rb) <= last)
            break;
    }
}

/* ── Capture-thread placement (--cpu / --rt) ─────────────────── */

/* Both are applied through inheritance: the main thread takes the
 * affinity mask / scheduling policy the capture thread should have, starts
 * it (a new thread inherits both), then moves itself off again. That
 * keeps the backends untouched, needs no _GNU_SOURCE pthread extensions,
 * lets --rt run before the privilege drop inside capture_create(), and
 * reports errors before the TUI owns the terminal. */

#ifdef __linux__
/* Raw sched_{get,set}affinity on the calling thread. The buffer covers
 * AFF_CPUS CPUs (the --cpu range) so the kernel never rejects it as too
 * small; it copies only its own cpumask size. */
#define AFF_CPUS  8192
#define AFF_WORDS (AFF_CPUS / (8 * sizeof(unsigned long)))
typedef struct { unsigned long w[AFF_WORDS]; } aff_mask_t;

static int aff_get(aff_mask_t *m) {
    memset(m, 0, sizeof(*m));
    return syscall(SYS_sched_getaffinity, 0, sizeof(*m), m->w) > 0 ? 0 : -1;
}
static int aff_set(const aff_mask_t *m) {
    return syscall(SYS_sched_setaffinity, 0, sizeof(*m), m->w) == 0 ? 0 : -1;
}
static int aff_test(const aff_mask_t *m, int cpu) {
    return (m->w[cpu / (8 * sizeof(unsigned long))] >>
            (cpu % (8 * sizeof(unsigned long)))) & 1UL;
}
static void aff_clear(aff_mask_t *m, int cpu) {
    m->w[cpu / (8 * sizeof(unsigned long))] &=
        ~(1UL << (cpu % (8 * sizeof(unsigned long))));
}
static int aff_empty(const aff_mask_t *m) {
    for (size_t i = 0; i < AFF_WORDS; i++)
        if (m->w[i]) return 0;
    return 1;
}
#endif

typedef struct {
    int         cpu;        /* -1: no pinning */
    int         rt;
#ifdef __linux__
    aff_mask_t  orig;       /* main thread's mask before pinning */
#endif
} placement_t;

/* Before capture_create(): raise the main thread to SCHED_FIFO 1 while it
 * still holds root/CAP_SYS_NICE. Warns and clears rt on failure. */
static void placement_rt_raise(placement_t *pl) {
    if (!pl->rt) return;
#ifdef _WIN32
    fprintf(stderr, "snuffles: --rt is not supported on Windows; ignored\n");
    pl->rt = 0;
#else
    struct sched_param sp;
    memset(&sp, 0, sizeof(sp));
    sp.sched_priority = 1;
    int rc = pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp);
    if (rc != 0) {
        fprintf(stderr, "snuffles: --rt: cannot set SCHED_FIFO (%s); "
                        "continuing without real-time priority\n", strerror(rc));
        pl->rt = 0;
    }
#endif
}

/* Before capture_start(): pin the main thread to the capture CPU so the
 * capture thread inherits it. Warns and clears cpu on failure. */
static void placement_pin_capture(placement_t *pl) {
    if (pl->cpu < 0) return;
#ifdef __linux__
    aff_mask_t want;
    if (aff_get(&pl->orig) != 0) {
        fprintf(stderr, "snuffles: --cpu: cannot read the CPU affinity mask "
                        "(%s); ignored\n", strerror(errno));
        pl->cpu = -1;
        return;
    }
    if (!aff_test(&pl->orig, pl->cpu)) {
        fprintf(stderr, "snuffles: --cpu %d: CPU not available to this "
                        "process (offline, or outside the affinity/cpuset); "
                        "ignored\n", pl->cpu);
        pl->cpu = -1;
        return;
    }
    memset(&want, 0, sizeof(want));
    want.w[pl->cpu / (8 * sizeof(unsigned long))] =
        1UL << (pl->cpu % (8 * sizeof(unsigned long)));
    if (aff_set(&want) != 0) {
        fprintf(stderr, "snuffles: --cpu %d: sched_setaffinity: %s; ignored\n",
                pl->cpu, strerror(errno));
        pl->cpu = -1;
    }
#else
    fprintf(stderr, "snuffles: --cpu is only supported on Linux; ignored\n");
    pl->cpu = -1;
#endif
}

/* After capture_start(): the main thread gives up the real-time policy
 * (always allowed, even unprivileged) and moves off the capture CPU. In
 * headless modes it takes the complement of the original mask so the
 * consumer (and the stats thread created afterwards) never compete with
 * capture; the TUI keeps its original mask. */
static void placement_release_main(placement_t *pl, int headless) {
#ifndef _WIN32
    if (pl->rt) {
        struct sched_param sp;
        memset(&sp, 0, sizeof(sp));
        (void)pthread_setschedparam(pthread_self(), SCHED_OTHER, &sp);
    }
#endif
#ifdef __linux__
    if (pl->cpu >= 0) {
        aff_mask_t m = pl->orig;
        if (headless) {
            aff_clear(&m, pl->cpu);
            if (aff_empty(&m)) {
                fprintf(stderr, "snuffles: --cpu %d: no other CPU available "
                                "for the consumer; sharing it\n", pl->cpu);
                m = pl->orig;
            }
        }
        if (aff_set(&m) != 0)
            fprintf(stderr, "snuffles: --cpu: cannot move the main thread "
                            "(%s)\n", strerror(errno));
    }
#else
    (void)pl;
    (void)headless;
#endif
}

/* ── Main ────────────────────────────────────────────────────── */

#define MAIN_MAX_PRESETS 32

int main(int argc, char *argv[]) {
    capture_cfg_t cfg;
    capture_cfg_defaults(&cfg);

    /* config file first, so CLI flags below override it */
    filter_preset_t presets[MAIN_MAX_PRESETS];
    int npresets = config_load(NULL, &cfg, presets, MAIN_MAX_PRESETS);

    static struct option long_opts[] = {
        {"interface",   required_argument, 0, 'i'},
        {"read",        required_argument, 0, 'r'},
        {"filter",      required_argument, 0, 'f'},
        {"count",       required_argument, 0, 'c'},
        {"snaplen",     required_argument, 0, 's'},
        {"ring-size",   required_argument, 0, 'b'},
        {"buffer-mb",   required_argument, 0, 'B'},
        {"immediate",   no_argument,       0, 'I'},
        {"output",      required_argument, 0, 'o'},
        {"write",       required_argument, 0, 'w'},
        {"no-ui",       no_argument,       0, 'N'},
        {"quiet",       no_argument,       0, 'q'},
        {"jsonl",       no_argument,       0, 'J'},
        {"list-ifaces", no_argument,       0, 'L'},
        {"syslog",       required_argument, 0, 'Y'},
        {"syslog-iface", required_argument, 0, 'Z'},
        {"stats",        optional_argument, 0, 'S'},
        {"no-summary",   no_argument,       0, 'X'},
        {"cpu",          required_argument, 0, 'C'},
        {"rt",           no_argument,       0, 'R'},
        {"version",     no_argument,       0, 'v'},
        {"help",        no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    int ring_set = 0, snaplen_set = 0, buffer_set = 0;
    int stats_on = 0;
    char stats_path[512] = "";
    while ((opt = getopt_long(argc, argv, "i:r:f:c:s:b:B:o:w:qvh", long_opts, NULL)) != -1) {
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
            case 'B': cfg.buffer_mb = (int)parse_num(optarg, "buffer size (MB)", 1, 2047);
                      buffer_set = 1; break;
            case 'I': cfg.immediate = 1; break;
            case 'N': cfg.no_ui       = 1; break;
            case 'q': cfg.quiet      = 1; cfg.no_ui = 1; break;
            case 'J': cfg.jsonl      = 1; cfg.no_ui = 1; break;
            case 'L': cfg.list_ifaces = 1; break;
            case 'Y': snprintf(cfg.syslog_target, sizeof(cfg.syslog_target), "%s", optarg); break;
            case 'Z': snprintf(cfg.syslog_iface, sizeof(cfg.syslog_iface), "%s", optarg); break;
            case 'S': stats_on = 1;
                      if (optarg) snprintf(stats_path, sizeof(stats_path), "%s", optarg);
                      break;
            case 'X': cfg.no_summary = 1; break;
            case 'C': cfg.cpu = (int)parse_num(optarg, "cpu", 0, 8191); break;   /* AFF_CPUS - 1 */
            case 'R': cfg.rt  = 1; break;
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
        if (!buffer_set && cfg.buffer_mb > 8)
            cfg.buffer_mb = 8;     /* keep the forwarder's footprint small:
                                      8 MB still buffers ~30 ms at 1 M pps */
    }

    if (stats_on && !cfg.no_ui && !stats_path[0]) {
        fprintf(stderr, "snuffles: --stats needs a file in TUI mode "
                        "(--stats=FILE), stderr would corrupt the screen\n");
        return 1;
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
    if (sessions)
        session_table_enable_reasm(sessions, 16 * 1024 * 1024);

    /* --rt: take SCHED_FIFO now, while capture_create() still has root
       (it drops privileges after opening the device); the capture thread
       inherits the policy when it is started below */
    placement_t place = { .cpu = cfg.cpu, .rt = cfg.rt };
    placement_rt_raise(&place);

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
    /* SIGUSR1 prints a stats line. Block it before any thread exists so
       the threads inherit the block and the signal always lands on the
       main thread, whose select() it interrupts; unblocked further down. */
    signal(SIGUSR1, usr1_handler);
    sigset_t usr1_set;
    sigemptyset(&usr1_set);
    sigaddset(&usr1_set, SIGUSR1);
    pthread_sigmask(SIG_BLOCK, &usr1_set, NULL);
#endif

    /* Offline replay into a headless consumer: register the consumer at
       sequence 0 before the reader starts, so it can never lap us. */
    if (cfg.no_ui && !cfg.quiet && capture_is_offline(cap))
        ringbuf_consumer_attach(rb);

    /* start capture thread (inherits the --cpu mask and --rt policy) */
    placement_pin_capture(&place);
    int started = capture_start(cap);
    placement_release_main(&place, cfg.no_ui);
    if (started != 0) {
        capture_destroy(cap);
        session_table_destroy(sessions);
        ringbuf_destroy(rb);
        return 1;
    }

    /* The reporter is always set up: headless modes print the summary
       line at exit (and answer SIGUSR1) even without --stats. */
    stats_reporter_t rep;
    memset(&rep, 0, sizeof(rep));
    rep.out = stderr;
    rep.rb = rb; rep.cap = cap; rep.st = sessions;
    wall_now(&rep.t0);
    atomic_store(&rep.stop, 0);
    if (stats_on) {
        if (stats_path[0]) {
            rep.out = fopen(stats_path, "w");
            if (!rep.out) {
                fprintf(stderr, "snuffles: cannot open stats file '%s'\n", stats_path);
                rep.out = stderr;
            }
        }
        rep.poll_usr1 = !cfg.no_ui;   /* TUI: only the stats thread may print */
        if (ns_thread_create(&rep.thread, stats_thread_fn, &rep) != 0) {
            fprintf(stderr, "snuffles: cannot start stats thread\n");
            stats_on = 0;
        }
    }
#ifndef _WIN32
    pthread_sigmask(SIG_UNBLOCK, &usr1_set, NULL);
#endif

    if (cfg.no_ui) {
        run_headless(rb, cap, &cfg, &rep);
    } else {
        ui_ctx_t *ui = ui_create(rb, cap, &cfg, sessions, presets, npresets);
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

    if (stats_on) {
        atomic_store(&rep.stop, 1);
        ns_thread_join(rep.thread);
    }
    if (stats_on || (cfg.no_ui && !cfg.no_summary))
        stats_report_line(&rep, "summary");
    if (rep.out != stderr) fclose(rep.out);

    if (cfg.no_ui && !cfg.no_summary) {
        capture_stats_raw_t cs;
        capture_get_stats(cap, &cs);
        if (cs.pkts_drop > 0)
            fprintf(stderr, "%llu packets dropped by the kernel: the capture "
                    "thread could not keep up; try -B <bigger>, -s <smaller>, "
                    "-q, or --cpu\n", (unsigned long long)cs.pkts_drop);
    }

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
