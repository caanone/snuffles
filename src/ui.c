#include "ui.h"
#include "dissect.h"
#include "export_pcap.h"
#include "export_json.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <math.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>

#ifdef _WIN32
  #include <conio.h>
#else
  #include <unistd.h>
  #include <termios.h>
  #include <sys/ioctl.h>
  #include <sys/select.h>
#endif

/* ── ANSI escape helpers ─────────────────────────────────────── */

#define ESC_CLEAR       "\033[2J"
#define ESC_HOME        "\033[H"
#define ESC_HIDE_CUR    "\033[?25l"
#define ESC_SHOW_CUR    "\033[?25h"
#define ESC_CLR_LINE    "\033[K"
#define ESC_CLR_BELOW   "\033[J"
#define ESC_RESET       "\033[0m"
#define ESC_BOLD        "\033[1m"
#define ESC_DIM         "\033[2m"
#define ESC_REVERSE     "\033[7m"
#define ESC_UNDERLINE   "\033[4m"

/* protocol colors */
#define CLR_TCP    "\033[36m"
#define CLR_UDP    "\033[33m"
#define CLR_ICMP   "\033[35m"
#define CLR_DNS    "\033[32m"
#define CLR_HTTP   "\033[31m"
#define CLR_TLS    "\033[91m"
#define CLR_ARP    "\033[37m"
#define CLR_SCTP   "\033[34m"
#define CLR_OTHER  "\033[90m"

#define OUTBUF_MAX_SIZE  (4 * 1024 * 1024)  /* 4 MB cap on render buffer */

/* ── Input mode ──────────────────────────────────────────────── */

typedef enum {
    MODE_NORMAL,
    MODE_FILTER,        /* display filter (post-capture) */
    MODE_BPF,           /* capture filter (kernel-level BPF) */
    MODE_EXPORT,
    MODE_HELP,
    MODE_STATS,
    MODE_SEARCH,
    MODE_FOLLOW,        /* follow-stream overlay (session view) */
} input_mode_t;

typedef enum {
    VIEW_PACKETS,
    VIEW_SESSIONS,
} view_mode_t;

/* ── UI context ──────────────────────────────────────────────── */

struct ui_ctx {
    ringbuf_t          *rb;
    capture_ctx_t      *cap;
    capture_cfg_t       cfg;
    stats_t             stats;
    display_filter_t    dfilter;
    session_table_t    *sessions;

    int                 rows, cols;
    int                 scroll_off;
    int                 selected;
    int                 detail_open;
    int                 paused;
    volatile int        stop;

    input_mode_t        mode;
    view_mode_t         view;
    char                input_buf[256];
    int                 input_pos;

    char                bpf_msg[128];   /* feedback after BPF apply */
    int                 bpf_msg_frames; /* frames to show message */

    /* session view state */
    int                 sess_scroll;
    int                 sess_selected;
    session_sort_t      sess_sort;
    session_entry_t    *sess_snap;      /* value copies (see session.h) */
    uint32_t            sess_snap_count;

    /* follow-stream overlay: copies taken on open, freed on close */
    uint8_t            *follow_a;       /* a->b bytes (SESSION_STREAM_CAP) */
    uint8_t            *follow_b;       /* b->a bytes (SESSION_STREAM_CAP) */
    uint32_t            follow_len_a;
    uint32_t            follow_len_b;
    uint32_t            follow_id;
    int                 follow_scroll;  /* in wrapped-line units */

    /* scratch for copy-out ring reads */
    pkt_record_t        peek_rec;
    uint8_t            *peek_data;      /* snaplen bytes */

    /* filtered-index cache: sequence numbers of packets matching the
     * display filter, kept sorted. Makes row access O(1) instead of a
     * full ring scan per row. */
    uint64_t           *fcache;
    uint32_t            fcache_cap;
    uint32_t            fcache_len;     /* entries incl. expired head */
    uint32_t            fcache_head;    /* first non-expired entry */
    uint64_t            fcache_scanned; /* next seq to evaluate */

    char                search[128];    /* last search string */
    int                 hex_scroll;     /* detail-panel hex dump row offset */

    /* saved display-filter presets ("@name"); owned by the caller */
    const filter_preset_t *presets;
    int                 npresets;

    uint64_t            last_total;
    int                 cur_row;

    char               *outbuf;
    size_t              outbuf_size;
    size_t              outbuf_pos;

#ifndef _WIN32
    struct termios      orig_tio;
#endif
};

/* Set from signal handlers: no pointers involved, so there is no window
 * where a signal during teardown dereferences a freed ui_ctx. */
static volatile sig_atomic_t g_async_stop = 0;

/* ── Terminal helpers ────────────────────────────────────────── */

static void get_term_size(int *rows, int *cols) {
#ifdef _WIN32
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi);
    *cols = csbi.srWindow.Right  - csbi.srWindow.Left + 1;
    *rows = csbi.srWindow.Bottom - csbi.srWindow.Top  + 1;
#else
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0) {
        *rows = ws.ws_row;
        *cols = ws.ws_col;
    } else {
        *rows = 24;
        *cols = 80;
    }
#endif
}

#ifndef _WIN32
/* Restore state shared with signal handlers so the terminal is never left
 * in raw mode by a crash, SIGQUIT, or Ctrl+Z. Only async-signal-safe
 * calls are used in the handlers. */
static struct termios        g_orig_tio;
static volatile sig_atomic_t g_tio_saved = 0;

static void tty_restore_now(void) {
    if (g_tio_saved) {
        tcsetattr(STDIN_FILENO, TCSANOW, &g_orig_tio);
        (void)!write(STDOUT_FILENO, "\033[?25h\033[0m\n", 11);
    }
}

static void tty_fatal_handler(int sig) {
    tty_restore_now();
    signal(sig, SIG_DFL);
    raise(sig);
}

static void tty_raw_apply(void) {
    struct termios tio = g_orig_tio;
    tio.c_lflag &= (tcflag_t)~(ICANON | ECHO);
    tio.c_cc[VMIN]  = 0;
    tio.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSANOW, &tio);
}

static void tty_tstp_handler(int sig) {
    (void)sig;
    tty_restore_now();
    signal(SIGTSTP, SIG_DFL);
    raise(SIGTSTP);
}

static void tty_cont_handler(int sig) {
    (void)sig;
    if (g_tio_saved) {
        tty_raw_apply();
        signal(SIGTSTP, tty_tstp_handler);
    }
}
#endif

#ifdef _WIN32
/* Original console output mode: restored on exit so VT processing does
 * not leak into the parent shell. */
static DWORD g_win_orig_mode;
static int   g_win_mode_saved = 0;
#endif

static void term_raw_enable(ui_ctx_t *ctx) {
#ifdef _WIN32
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode;
    if (GetConsoleMode(h, &mode)) {
        g_win_orig_mode  = mode;
        g_win_mode_saved = 1;
        SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    }
    (void)ctx;
#else
    if (tcgetattr(STDIN_FILENO, &ctx->orig_tio) != 0)
        return;   /* not a terminal; main gates this, but stay safe */
    g_orig_tio  = ctx->orig_tio;
    g_tio_saved = 1;
    tty_raw_apply();

    static int hooked = 0;
    if (!hooked) {
        hooked = 1;
        atexit(tty_restore_now);
        signal(SIGSEGV, tty_fatal_handler);
        signal(SIGBUS,  tty_fatal_handler);
        signal(SIGFPE,  tty_fatal_handler);
        signal(SIGILL,  tty_fatal_handler);
        signal(SIGABRT, tty_fatal_handler);
        signal(SIGQUIT, tty_fatal_handler);
        signal(SIGTSTP, tty_tstp_handler);
        signal(SIGCONT, tty_cont_handler);
    }
#endif
}

static void term_raw_disable(ui_ctx_t *ctx) {
#ifdef _WIN32
    if (g_win_mode_saved) {
        SetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), g_win_orig_mode);
        g_win_mode_saved = 0;
    }
    (void)ctx;
#else
    tcsetattr(STDIN_FILENO, TCSANOW, &ctx->orig_tio);
    g_tio_saved = 0;   /* atexit/signal restore no longer needed */
#endif
}

/* ── Output buffer ───────────────────────────────────────────── */

static void ob_reset(ui_ctx_t *ctx) {
    ctx->outbuf_pos = 0;
}

static void ob_append(ui_ctx_t *ctx, const char *s, size_t len) {
    if (ctx->outbuf_pos + len >= ctx->outbuf_size) {
        size_t need = ctx->outbuf_pos + len + 4096;
        if (need > OUTBUF_MAX_SIZE) return;  /* refuse to grow past cap */
        char *nb = realloc(ctx->outbuf, need);
        if (!nb) return;  /* drop output rather than crash */
        ctx->outbuf = nb;
        ctx->outbuf_size = need;
    }
    memcpy(ctx->outbuf + ctx->outbuf_pos, s, len);
    ctx->outbuf_pos += len;
}

static void ob_str(ui_ctx_t *ctx, const char *s) {
    ob_append(ctx, s, strlen(s));
}

static void ob_printf(ui_ctx_t *ctx, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

static void ob_printf(ui_ctx_t *ctx, const char *fmt, ...) {
    char tmp[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (n > 0) ob_append(ctx, tmp, (size_t)n);
}

static void ob_flush(ui_ctx_t *ctx) {
#ifdef _WIN32
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD written;
    WriteFile(h, ctx->outbuf, (DWORD)ctx->outbuf_pos, &written, NULL);
#else
    (void)write(STDOUT_FILENO, ctx->outbuf, ctx->outbuf_pos);
#endif
}

/* Move to row (1-based) and emit ESC_CLR_LINE. Never exceeds ctx->rows. */
static void ob_moveto(ui_ctx_t *ctx, int row) {
    ctx->cur_row = row;
    ob_printf(ctx, "\033[%d;1H" ESC_CLR_LINE, row);
}

/* ── Protocol color ──────────────────────────────────────────── */

static const char *proto_color(proto_id_t p) {
    switch (p) {
        case PROTO_TCP:   return CLR_TCP;
        case PROTO_UDP:   return CLR_UDP;
        case PROTO_ICMP4:
        case PROTO_ICMP6: return CLR_ICMP;
        case PROTO_DNS:   return CLR_DNS;
        case PROTO_HTTP:  return CLR_HTTP;
        case PROTO_TLS:   return CLR_TLS;
        case PROTO_ARP:   return CLR_ARP;
        case PROTO_SCTP:  return CLR_SCTP;
        default:          return CLR_OTHER;
    }
}

/* ── Filtered packet count & access ──────────────────────────── */

static int dfilter_active(const ui_ctx_t *ctx) {
    return ctx->dfilter.valid && ctx->dfilter.root >= 0;
}

/* Invalidate the cache; called whenever the display filter changes or the
 * ring is cleared. */
static void fcache_reset(ui_ctx_t *ctx) {
    ctx->fcache_len     = 0;
    ctx->fcache_head    = 0;
    ctx->fcache_scanned = ringbuf_oldest(ctx->rb);
}

static void fcache_push(ui_ctx_t *ctx, uint64_t seq) {
    if (ctx->fcache_len == ctx->fcache_cap) {
        uint32_t ncap = ctx->fcache_cap ? ctx->fcache_cap * 2 : 1024;
        uint64_t *nb = realloc(ctx->fcache, (size_t)ncap * sizeof(uint64_t));
        if (!nb) return;   /* degrade: drop the entry */
        ctx->fcache = nb;
        ctx->fcache_cap = ncap;
    }
    ctx->fcache[ctx->fcache_len++] = seq;
}

/* Amortized maintenance: expire entries that fell off the ring, compact,
 * and evaluate the filter on newly committed packets only. */
static void fcache_sync(ui_ctx_t *ctx) {
    uint64_t oldest = ringbuf_oldest(ctx->rb);
    uint64_t total  = ringbuf_total(ctx->rb);

    while (ctx->fcache_head < ctx->fcache_len &&
           ctx->fcache[ctx->fcache_head] < oldest)
        ctx->fcache_head++;
    if (ctx->fcache_head > 4096 || ctx->fcache_head == ctx->fcache_len) {
        memmove(ctx->fcache, ctx->fcache + ctx->fcache_head,
                (size_t)(ctx->fcache_len - ctx->fcache_head) * sizeof(uint64_t));
        ctx->fcache_len -= ctx->fcache_head;
        ctx->fcache_head = 0;
    }

    if (ctx->fcache_scanned < oldest)
        ctx->fcache_scanned = oldest;

    pkt_record_t rec;
    while (ctx->fcache_scanned < total) {
        uint32_t idx = (uint32_t)(ctx->fcache_scanned - oldest);
        if (ringbuf_read(ctx->rb, idx, &rec, NULL) &&
            filter_eval(&ctx->dfilter, &rec.summary))
            fcache_push(ctx, ctx->fcache_scanned);
        ctx->fcache_scanned++;
    }
}

static uint32_t filtered_count(ui_ctx_t *ctx) {
    if (!dfilter_active(ctx))
        return ringbuf_count(ctx->rb);
    fcache_sync(ctx);
    return ctx->fcache_len - ctx->fcache_head;
}

/* Copies the record into ctx->peek_rec/peek_data; the pointer is only
 * valid until the next filtered_peek call. */
static const pkt_record_t *filtered_peek(ui_ctx_t *ctx, uint32_t idx) {
    if (!dfilter_active(ctx)) {
        if (ringbuf_read(ctx->rb, idx, &ctx->peek_rec, ctx->peek_data))
            return &ctx->peek_rec;
        return NULL;
    }

    fcache_sync(ctx);
    if (idx >= ctx->fcache_len - ctx->fcache_head)
        return NULL;
    uint64_t seq    = ctx->fcache[ctx->fcache_head + idx];
    uint64_t oldest = ringbuf_oldest(ctx->rb);
    if (seq < oldest)
        return NULL;   /* raced away between sync and read */
    if (ringbuf_read(ctx->rb, (uint32_t)(seq - oldest),
                     &ctx->peek_rec, ctx->peek_data))
        return &ctx->peek_rec;
    return NULL;
}

/* ── Filter presets ──────────────────────────────────────────── */

/* Case-insensitive preset lookup; tolerates spaces around the name. */
static const filter_preset_t *preset_find(const ui_ctx_t *ctx,
                                          const char *name) {
    while (*name == ' ') name++;
    size_t n = strlen(name);
    while (n > 0 && name[n - 1] == ' ') n--;
    if (n == 0) return NULL;

    for (int i = 0; i < ctx->npresets; i++) {
        const char *pn = ctx->presets[i].name;
        size_t j = 0;
        while (j < n && pn[j] &&
               tolower((unsigned char)pn[j]) == tolower((unsigned char)name[j]))
            j++;
        if (j == n && pn[n] == '\0') return &ctx->presets[i];
    }
    return NULL;
}

/* ── Search ──────────────────────────────────────────────────── */

static int ci_contains(const char *hay, const char *needle) {
    size_t nlen = strlen(needle);
    if (!nlen) return 1;
    for (const char *p = hay; *p; p++) {
        size_t i = 0;
        while (i < nlen && p[i] &&
               tolower((unsigned char)p[i]) == tolower((unsigned char)needle[i]))
            i++;
        if (i == nlen) return 1;
    }
    return 0;
}

/* Move the selection to the next row (dir=+1) or previous row (dir=-1)
 * whose info/IPs/protocol contain ctx->search, wrapping around. */
static void do_search(ui_ctx_t *ctx, int dir) {
    if (!ctx->search[0] || ctx->view != VIEW_PACKETS) return;
    uint32_t n = filtered_count(ctx);
    if (n == 0) goto miss;

    for (uint32_t step = 1; step <= n; step++) {
        long i = (long)ctx->selected + (long)step * dir;
        i %= (long)n;
        if (i < 0) i += n;
        const pkt_record_t *rec = filtered_peek(ctx, (uint32_t)i);
        if (!rec) continue;
        const pkt_summary_t *s = &rec->summary;
        if (ci_contains(s->info, ctx->search) ||
            ci_contains(s->src_ip, ctx->search) ||
            ci_contains(s->dst_ip, ctx->search) ||
            ci_contains(s->protocol, ctx->search)) {
            ctx->selected = (int)i;
            return;
        }
    }
miss:
    snprintf(ctx->bpf_msg, sizeof(ctx->bpf_msg),
             "\033[33mNot found: %s\033[0m", ctx->search);
    ctx->bpf_msg_frames = 60;
}

/* ── Follow-stream overlay ───────────────────────────────────── */

static void follow_open(ui_ctx_t *ctx, uint32_t id) {
    uint8_t *a = malloc(SESSION_STREAM_CAP);
    uint8_t *b = malloc(SESSION_STREAM_CAP);
    if (!a || !b) { free(a); free(b); return; }
    ctx->follow_a = a;
    ctx->follow_b = b;
    ctx->follow_len_a = session_stream_copy(ctx->sessions, id, 0,
                                            a, SESSION_STREAM_CAP);
    ctx->follow_len_b = session_stream_copy(ctx->sessions, id, 1,
                                            b, SESSION_STREAM_CAP);
    ctx->follow_id     = id;
    ctx->follow_scroll = 0;
    ctx->mode = MODE_FOLLOW;
}

static void follow_close(ui_ctx_t *ctx) {
    free(ctx->follow_a);
    free(ctx->follow_b);
    ctx->follow_a = NULL;
    ctx->follow_b = NULL;
    ctx->follow_len_a = ctx->follow_len_b = 0;
    ctx->mode = MODE_NORMAL;
}

/* ── Render ──────────────────────────────────────────────────── */

static void render_frame(ui_ctx_t *ctx) {
    get_term_size(&ctx->rows, &ctx->cols);
    if (ctx->cols < 40) ctx->cols = 40;
    if (ctx->rows < 10) ctx->rows = 10;

    ob_reset(ctx);
    ob_str(ctx, ESC_HIDE_CUR);

    int row = 1;

    /* ── Row 1: Title bar ───────────────────────────────────── */
    capture_stats_raw_t cstats;
    capture_get_stats(ctx->cap, &cstats);

    ob_moveto(ctx, row++);
    ob_str(ctx, ESC_BOLD ESC_REVERSE);
    ob_printf(ctx, " %s v%s | %s | captured: %llu | dropped: %llu ",
              SNUFFLES_NAME, SNUFFLES_VERSION_STR,
              capture_get_iface(ctx->cap),
              (unsigned long long)ringbuf_total(ctx->rb),
              (unsigned long long)cstats.pkts_drop);
    ob_str(ctx, ESC_RESET);
    if (!capture_is_running(ctx->cap)) {
        if (capture_had_error(ctx->cap))
            ob_printf(ctx, " \033[1;31m[CAPTURE ERROR: %.48s]\033[0m",
                      capture_error_msg(ctx->cap));
        else
            ob_str(ctx, ESC_DIM " [capture ended]" ESC_RESET);
    }

    /* ── Row 2: Hotkey bar ──────────────────────────────────── */
    ob_moveto(ctx, row++);
    ob_str(ctx, ESC_DIM);
    ob_printf(ctx, " [S]%s  [V]Stats  [F]ilter  [B]PF  [E]xport  [C]lear  [P]%s  [H]elp  [Q]uit",
              ctx->view == VIEW_SESSIONS ? "Packets" : "essions",
              ctx->paused ? "Resume" : "ause");
    ob_str(ctx, ESC_RESET);

    /* ── Help overlay ───────────────────────────────────────── */
    if (ctx->mode == MODE_HELP) {
        static const char *help[] = {
            "",
            ESC_BOLD "  NAVIGATION" ESC_RESET,
            "    Up/Down       Scroll packet/session list",
            "    PgUp/PgDn     Scroll by page",
            "    Home/End      Jump to first/last",
            "    Enter         Toggle detail panel (packet view)",
            "    Left/Right    Scroll the hex dump in the detail panel",
            "                  Drill into session (session view)",
            "",
            ESC_BOLD "  VIEWS" ESC_RESET,
            "    S             Toggle between Packets and Sessions view",
            "    T             Cycle session sort (bytes/packets/recent/duration)",
            "    O             Follow the reassembled TCP stream (session view)",
            "    V             Protocol statistics overlay",
            "",
            ESC_BOLD "  SEARCH" ESC_RESET,
            "    /             Search packet list (info, IPs, protocol)",
            "    n / N         Next / previous match",
            "",
            ESC_BOLD "  FILTERS" ESC_RESET,
            "    F             Display filter (post-capture, hides packets from view)",
            "                  Syntax: tcp | 10.0.0.1 | port 443 | ip == 10.0.0.0/24",
            "                          info contains GET | session == 5 | !arp",
            "                          Combine: and or not () && || !",
            "                  @name applies a saved preset from the config file",
            "    B             BPF capture filter (kernel-level, drops non-matching)",
            "                  Syntax: tcp port 443 | host 10.0.0.1 | udp | icmp",
            "",
            ESC_BOLD "  ACTIONS" ESC_RESET,
            "    E             Export captured packets (.pcap or .json by extension)",
            "    C             Clear all packets and sessions",
            "    P             Pause / Resume capture",
            "    Q             Quit",
            "",
            ESC_BOLD "  INPUT MODES" ESC_RESET,
            "    Enter         Apply filter / export",
            "    Escape        Cancel input",
            "    Backspace     Delete character",
            "",
            ESC_DIM "  Press any key to close help" ESC_RESET,
        };
        int nlines = (int)(sizeof(help) / sizeof(help[0]));
        for (int i = 0; i < nlines && row <= ctx->rows; i++) {
            ob_moveto(ctx, row++);
            ob_str(ctx, help[i]);
        }
        ob_str(ctx, ESC_CLR_BELOW);
        ob_flush(ctx);
        return;
    }

    /* ── Follow-stream overlay ──────────────────────────────── */
    if (ctx->mode == MODE_FOLLOW) {
        int w = ctx->cols - 2;          /* leading space + margin */
        if (w < 1) w = 1;
        if (w > 1000) w = 1000;         /* line assembly buffer bound */

        /* virtual lines: A rule, wrapped A bytes, B rule, wrapped B bytes */
        uint32_t lines_a = (ctx->follow_len_a + (uint32_t)w - 1) / (uint32_t)w;
        uint32_t lines_b = (ctx->follow_len_b + (uint32_t)w - 1) / (uint32_t)w;
        uint32_t vtotal  = lines_a + lines_b + 2;
        int avail = ctx->rows - 3;      /* title, hotkeys, overlay header */
        if (avail < 1) avail = 1;
        int max_scroll = (vtotal > (uint32_t)avail)
                         ? (int)(vtotal - (uint32_t)avail) : 0;
        if (ctx->follow_scroll < 0) ctx->follow_scroll = 0;
        if (ctx->follow_scroll > max_scroll) ctx->follow_scroll = max_scroll;

        ob_moveto(ctx, row++);
        ob_printf(ctx, ESC_BOLD " Follow session #%u \xe2\x80\x94 A->B %u bytes, "
                  "B->A %u bytes (Up/Down scroll, ESC close)" ESC_RESET,
                  ctx->follow_id, ctx->follow_len_a, ctx->follow_len_b);

        char line[1004];
        for (int i = 0; i < avail && row <= ctx->rows; i++) {
            uint32_t v = (uint32_t)ctx->follow_scroll + (uint32_t)i;
            if (v >= vtotal) break;
            ob_moveto(ctx, row++);
            if (v == 0 || v == lines_a + 1) {
                ob_printf(ctx, "%s \xe2\x94\x80\xe2\x94\x80 %s "
                          "\xe2\x94\x80\xe2\x94\x80" ESC_RESET,
                          v == 0 ? CLR_TCP : CLR_UDP,   /* cyan / yellow */
                          v == 0 ? "A -> B" : "B -> A");
                continue;
            }
            const uint8_t *src;
            uint32_t slen, chunk;
            if (v <= lines_a) {
                src = ctx->follow_a; slen = ctx->follow_len_a; chunk = v - 1;
            } else {
                src = ctx->follow_b; slen = ctx->follow_len_b;
                chunk = v - lines_a - 2;
            }
            uint32_t start = chunk * (uint32_t)w;
            uint32_t n = slen - start;
            if (n > (uint32_t)w) n = (uint32_t)w;
            line[0] = ' ';
            for (uint32_t j = 0; j < n; j++) {
                uint8_t bc = src[start + j];
                line[1 + j] = (bc >= 0x20 && bc < 0x7f) ? (char)bc : '.';
            }
            ob_append(ctx, line, 1 + n);
        }
        ob_str(ctx, ESC_CLR_BELOW);
        ob_flush(ctx);
        return;
    }

    /* ── Statistics overlay ─────────────────────────────────── */
    if (ctx->mode == MODE_STATS) {
        stats_compute_rates(&ctx->stats);

        ob_moveto(ctx, row++);
        ob_moveto(ctx, row++);
        ob_str(ctx, ESC_BOLD "  CAPTURE STATISTICS" ESC_RESET);
        ob_moveto(ctx, row++);

        long up = (long)(time(NULL) - (time_t)ctx->stats.start_time.tv_sec);
        if (up < 0) up = 0;
        ob_moveto(ctx, row++);
        ob_printf(ctx, "    Uptime: %02ld:%02ld:%02ld    Packets: %llu    Dropped: %llu    Sessions: %u",
                  up / 3600, (up % 3600) / 60, up % 60,
                  (unsigned long long)ctx->stats.total_packets,
                  (unsigned long long)cstats.pkts_drop,
                  session_table_count(ctx->sessions));

        char sline[128];
        stats_format(&ctx->stats, sline, sizeof(sline));
        ob_moveto(ctx, row++);
        ob_printf(ctx, "    %s", sline);
        ob_moveto(ctx, row++);

        /* per-protocol breakdown, sorted by packet count */
        int order[PROTO_MAX];
        int n = 0;
        for (int i = 0; i < PROTO_MAX; i++)
            if (ctx->stats.proto_counts[i] > 0) order[n++] = i;
        for (int i = 1; i < n; i++) {
            int key = order[i], j = i - 1;
            while (j >= 0 && ctx->stats.proto_counts[order[j]] <
                             ctx->stats.proto_counts[key]) {
                order[j + 1] = order[j];
                j--;
            }
            order[j + 1] = key;
        }

        ob_moveto(ctx, row++);
        ob_str(ctx, ESC_BOLD "  PROTOCOLS" ESC_RESET);
        uint64_t total = ctx->stats.total_packets ? ctx->stats.total_packets : 1;
        for (int i = 0; i < n && row <= ctx->rows - 2; i++) {
            uint64_t c = ctx->stats.proto_counts[order[i]];
            int pct = (int)(c * 100 / total);
            int bar = (int)(c * 40 / total);
            char barbuf[48];
            int b = 0;
            for (; b < bar && b < 40; b++) barbuf[b] = '#';
            barbuf[b] = '\0';
            ob_moveto(ctx, row++);
            ob_printf(ctx, "    %-7s %10llu  %3d%%  %s%s%s",
                      proto_name((proto_id_t)order[i]),
                      (unsigned long long)c, pct,
                      proto_color((proto_id_t)order[i]), barbuf, ESC_RESET);
        }
        if (n == 0) {
            ob_moveto(ctx, row++);
            ob_str(ctx, ESC_DIM "    (no packets yet)" ESC_RESET);
        }

        ob_moveto(ctx, row++);
        ob_moveto(ctx, row++);
        ob_str(ctx, ESC_DIM "  Press any key to close" ESC_RESET);
        ob_str(ctx, ESC_CLR_BELOW);
        ob_flush(ctx);
        return;
    }

    /* ── Layout math ────────────────────────────────────────── */
    int header_rows = 3;
    int footer_rows = 2;
    int detail_rows = (ctx->view == VIEW_PACKETS && ctx->detail_open)
                      ? NS_MIN(10, (ctx->rows - header_rows - footer_rows) / 3) : 0;
    int list_rows   = ctx->rows - header_rows - footer_rows - detail_rows;
    if (list_rows < 1) list_rows = 1;

    if (ctx->view == VIEW_SESSIONS) {
        /* ═══════════ SESSION TABLE VIEW ═══════════ */

        /* column headers */
        ob_moveto(ctx, row++);
        ob_str(ctx, ESC_BOLD ESC_UNDERLINE);
        ob_printf(ctx, " %4s  %-5s  %-22s  %-22s  %7s  %7s  %9s  %-6s  %s",
                  "#", "Proto", "Side A", "Side B",
                  "Pkts\xe2\x86\x91", "Pkts\xe2\x86\x93",
                  "Bytes", "State", "Duration");
        ob_str(ctx, ESC_RESET);

        /* refresh snapshot */
        free(ctx->sess_snap);
        ctx->sess_snap = session_table_snapshot(ctx->sessions,
                                                 &ctx->sess_snap_count,
                                                 ctx->sess_sort);

        uint32_t stotal = ctx->sess_snap_count;

        /* clamp */
        if (ctx->sess_selected < 0) ctx->sess_selected = 0;
        if (ctx->sess_selected >= (int)stotal && stotal > 0)
            ctx->sess_selected = (int)stotal - 1;
        if (ctx->sess_scroll < 0) ctx->sess_scroll = 0;
        if (ctx->sess_selected < ctx->sess_scroll)
            ctx->sess_scroll = ctx->sess_selected;
        if (ctx->sess_selected >= ctx->sess_scroll + list_rows)
            ctx->sess_scroll = ctx->sess_selected - list_rows + 1;

        for (int i = 0; i < list_rows; i++) {
            ob_moveto(ctx, row++);
            uint32_t si = (uint32_t)(ctx->sess_scroll + i);
            if (si < stotal && ctx->sess_snap) {
                const session_entry_t *se = &ctx->sess_snap[si];
                int is_sel = ((int)si == ctx->sess_selected);

                /* color by state */
                const char *clr = CLR_OTHER;
                switch (se->tcp_state) {
                    case SESS_ESTABLISHED: clr = "\033[32m"; break;  /* green */
                    case SESS_SYN_SENT:    clr = "\033[33m"; break;  /* yellow */
                    case SESS_RST:         clr = "\033[31m"; break;  /* red */
                    case SESS_CLOSED:      clr = ESC_DIM;    break;
                    default: break;
                }
                if (is_sel) ob_str(ctx, ESC_REVERSE);
                ob_str(ctx, clr);

                /* format addresses */
                char sa[48], sb[48];
                if (se->key.port_a)
                    snprintf(sa, sizeof(sa), "%s:%u", se->key.ip_a, se->key.port_a);
                else
                    snprintf(sa, sizeof(sa), "%s", se->key.ip_a);
                if (se->key.port_b)
                    snprintf(sb, sizeof(sb), "%s:%u", se->key.ip_b, se->key.port_b);
                else
                    snprintf(sb, sizeof(sb), "%s", se->key.ip_b);

                /* total bytes formatted */
                uint64_t tbytes = se->bytes_a_to_b + se->bytes_b_to_a;
                char bstr[16];
                if (tbytes >= 1048576)
                    snprintf(bstr, sizeof(bstr), "%.1fM", (double)tbytes / 1048576.0);
                else if (tbytes >= 1024)
                    snprintf(bstr, sizeof(bstr), "%.1fK", (double)tbytes / 1024.0);
                else
                    snprintf(bstr, sizeof(bstr), "%lu", (unsigned long)tbytes);

                /* duration */
                double dur = (double)(se->last_seen.tv_sec - se->first_seen.tv_sec) +
                             (double)(se->last_seen.tv_usec - se->first_seen.tv_usec) / 1e6;
                char dstr[16];
                if (dur >= 60.0)
                    snprintf(dstr, sizeof(dstr), "%.0fm%02.0fs", dur / 60, fmod(dur, 60));
                else
                    snprintf(dstr, sizeof(dstr), "%.1fs", dur);

                ob_printf(ctx, " %4u  %-5.5s  %-22.22s  %-22.22s  %7lu  %7lu  %9s  %-6s  %s",
                          se->id,
                          proto_name((proto_id_t)se->key.proto),
                          sa, sb,
                          (unsigned long)(se->pkts_a_to_b),
                          (unsigned long)(se->pkts_b_to_a),
                          bstr,
                          session_state_str(se->tcp_state),
                          dstr);

                ob_str(ctx, ESC_RESET);
            }
        }

    } else {
        /* ═══════════ PACKET LIST VIEW ═══════════ */

        /* column headers */
        ob_moveto(ctx, row++);
        ob_str(ctx, ESC_BOLD ESC_UNDERLINE);
        int info_w = NS_MAX(ctx->cols - 68, 6);
        ob_printf(ctx, " %5s  %-12s  %-21s  %-21s  %-6s  %-*s",
                  "#", "Time", "Source", "Destination", "Proto",
                  info_w, "Info");
        ob_str(ctx, ESC_RESET);

        uint32_t total = filtered_count(ctx);

        /* auto-scroll to bottom */
        if (!ctx->paused && total > 0) {
            if ((int)total > list_rows) {
                ctx->scroll_off = (int)total - list_rows;
                ctx->selected = (int)total - 1;
            }
        }

        /* clamp selection */
        if (ctx->selected < 0) ctx->selected = 0;
        if (ctx->selected >= (int)total && total > 0) ctx->selected = (int)total - 1;
        if (ctx->scroll_off < 0) ctx->scroll_off = 0;
        if (ctx->selected < ctx->scroll_off)
            ctx->scroll_off = ctx->selected;
        if (ctx->selected >= ctx->scroll_off + list_rows)
            ctx->scroll_off = ctx->selected - list_rows + 1;

        for (int i = 0; i < list_rows; i++) {
            ob_moveto(ctx, row++);
            uint32_t idx = (uint32_t)(ctx->scroll_off + i);
            if (idx < total) {
                const pkt_record_t *rec = filtered_peek(ctx, idx);
                if (rec) {
                    const pkt_summary_t *s = &rec->summary;
                    int is_sel = ((int)idx == ctx->selected);

                    if (is_sel) ob_str(ctx, ESC_REVERSE);
                    ob_str(ctx, proto_color(s->highest_proto));

                    char ts[16];
                    time_t tsec = (time_t)s->ts.tv_sec;
                    struct tm lt;
                    if (ns_localtime(&tsec, &lt))
                        snprintf(ts, sizeof(ts), "%02d:%02d:%02d.%03ld",
                                 lt.tm_hour, lt.tm_min, lt.tm_sec,
                                 (long)(s->ts.tv_usec / 1000));
                    else
                        snprintf(ts, sizeof(ts), "??:??:??.???");

                    char src[48], dst[48];
                    if (s->src_port)
                        snprintf(src, sizeof(src), "%s:%u", s->src_ip, s->src_port);
                    else
                        snprintf(src, sizeof(src), "%s", s->src_ip[0] ? s->src_ip : s->src_mac);

                    if (s->dst_port)
                        snprintf(dst, sizeof(dst), "%s:%u", s->dst_ip, s->dst_port);
                    else
                        snprintf(dst, sizeof(dst), "%s", s->dst_ip[0] ? s->dst_ip : s->dst_mac);

                    ob_printf(ctx, " %5u  %s  %-21.21s  %-21.21s  %-6.6s  %-*.*s",
                              idx + 1, ts, src, dst, s->protocol,
                              info_w, info_w, s->info);

                    ob_str(ctx, ESC_RESET);
                }
            }
        }

        /* ── Detail panel ───────────────────────────────────── */
        if (ctx->detail_open && detail_rows > 0) {
            const pkt_record_t *rec = NULL;
            if (ctx->selected >= 0 && (uint32_t)ctx->selected < total)
                rec = filtered_peek(ctx, (uint32_t)ctx->selected);

            int used = 0;

            ob_moveto(ctx, row++);
            ob_str(ctx, ESC_DIM);
            for (int i = 0; i < ctx->cols; i++) ob_str(ctx, "\xe2\x94\x80");
            ob_str(ctx, ESC_RESET);
            used++;

            if (rec) {
                const pkt_summary_t *s = &rec->summary;

                char lines[6][128];
                int nlines = 0;

                uint32_t hex_rows = (rec->raw_len + 15) / 16;
                if (ctx->hex_scroll < 0) ctx->hex_scroll = 0;
                if (hex_rows > 0 && (uint32_t)ctx->hex_scroll >= hex_rows)
                    ctx->hex_scroll = (int)hex_rows - 1;
                snprintf(lines[nlines++], 128,
                         " Pkt #%d (session %u): %u bytes, %u captured | hex row %d/%u (Left/Right)",
                         ctx->selected + 1, s->session_id, s->length, rec->raw_len,
                         ctx->hex_scroll + 1, hex_rows ? hex_rows : 1);
                snprintf(lines[nlines++], 128, " Eth: %s -> %s  Type: 0x%04x",
                         s->src_mac, s->dst_mac, s->ethertype);
                if (s->vlan_id)
                    snprintf(lines[nlines++], 128, " VLAN: %u", s->vlan_id);
                if (s->src_ip[0])
                    snprintf(lines[nlines++], 128, " %s: %s -> %s  TTL=%u",
                             proto_name(s->l3_proto), s->src_ip, s->dst_ip, s->ip_ttl);
                if (s->l4_proto != PROTO_UNKNOWN)
                    snprintf(lines[nlines++], 128, " %s: %s",
                             proto_name(s->l4_proto), s->info);

                for (int i = 0; i < nlines && used < detail_rows; i++) {
                    ob_moveto(ctx, row++);
                    ob_str(ctx, lines[i]);
                    used++;
                }

                for (uint32_t off = (uint32_t)ctx->hex_scroll * 16;
                     off < rec->raw_len && used < detail_rows; off += 16) {
                    ob_moveto(ctx, row++);
                    ob_printf(ctx, " %04x: ", off);
                    for (int j = 0; j < 16; j++) {
                        if (off + (uint32_t)j < rec->raw_len)
                            ob_printf(ctx, "%02x ", rec->raw_data[off + j]);
                        else
                            ob_str(ctx, "   ");
                        if (j == 7) ob_str(ctx, " ");
                    }
                    ob_str(ctx, "|");
                    for (int j = 0; j < 16 && (off + (uint32_t)j) < rec->raw_len; j++) {
                        uint8_t c = rec->raw_data[off + j];
                        char ch = (c >= 0x20 && c < 0x7f) ? (char)c : '.';
                        ob_printf(ctx, "%c", ch);
                    }
                    ob_str(ctx, "|");
                    used++;
                }
            } else {
                ob_moveto(ctx, row++);
                ob_str(ctx, ESC_DIM " (no packet selected)" ESC_RESET);
                used++;
            }

            while (used < detail_rows) {
                ob_moveto(ctx, row++);
                used++;
            }
        }
    } /* end VIEW_PACKETS */

    /* ── Footer: filter line ────────────────────────────────── */
    ob_moveto(ctx, row++);
    ob_str(ctx, ESC_DIM);
    for (int i = 0; i < ctx->cols; i++) ob_str(ctx, "\xe2\x94\x80");
    ob_str(ctx, ESC_RESET);

    ob_moveto(ctx, row++);
    if (ctx->mode == MODE_FILTER) {
        ob_str(ctx, ESC_BOLD " Filter> " ESC_RESET);
        ob_str(ctx, ctx->input_buf);
        ob_str(ctx, "\xe2\x96\x88");

        /* live preview: compile and count matches (throttled — caps scan to 2000 packets) */
        if (ctx->input_buf[0] == '@') {
            const filter_preset_t *p = preset_find(ctx, ctx->input_buf + 1);
            if (p)
                ob_printf(ctx, ESC_DIM "  = %s" ESC_RESET, p->expr);
            else
                ob_str(ctx, ESC_DIM "  (saved preset name)" ESC_RESET);
        } else if (ctx->input_buf[0]) {
            display_filter_t preview;
            if (filter_compile(ctx->input_buf, &preview) == 0) {
                uint32_t matches = 0;
                uint32_t rb_count = ringbuf_count(ctx->rb);
                uint32_t scan_limit = rb_count < 2000 ? rb_count : 2000;
                pkt_record_t prec;
                for (uint32_t fi = 0; fi < scan_limit; fi++) {
                    if (ringbuf_read(ctx->rb, fi, &prec, NULL) &&
                        filter_eval(&preview, &prec.summary)) matches++;
                }
                if (scan_limit < rb_count)
                    ob_printf(ctx, ESC_DIM "  (~%u/%u sampled)" ESC_RESET,
                              matches, scan_limit);
                else
                    ob_printf(ctx, ESC_DIM "  (%u/%u match)" ESC_RESET,
                              matches, rb_count);
            } else {
                ob_printf(ctx, "  \033[31m%s" ESC_RESET, preview.error);
            }
        } else if (ctx->npresets > 0) {
            /* empty prompt with presets on file: hint up to 5 names */
            ob_str(ctx, ESC_DIM "  presets:");
            int shown = NS_MIN(ctx->npresets, 5);
            for (int i = 0; i < shown; i++)
                ob_printf(ctx, " @%s", ctx->presets[i].name);
            if (ctx->npresets > shown) ob_str(ctx, " ...");
            ob_str(ctx, ESC_RESET);
        } else {
            ob_str(ctx, ESC_DIM
                   "  tcp | 10.0.0.1 | port 443 | ip == 10.0.0.0/24 | info contains GET"
                   ESC_RESET);
        }
    } else if (ctx->mode == MODE_BPF) {
        ob_str(ctx, ESC_BOLD " BPF Capture> " ESC_RESET);
        ob_str(ctx, ctx->input_buf);
        ob_str(ctx, "\xe2\x96\x88");
        if (!ctx->input_buf[0]) {
            ob_str(ctx, ESC_DIM
                   "  tcp port 443 | host 10.0.0.1 | udp | icmp  (empty = accept all)"
                   ESC_RESET);
        }
    } else if (ctx->mode == MODE_EXPORT) {
        ob_str(ctx, ESC_BOLD " Export (.pcap/.json): " ESC_RESET);
        ob_str(ctx, ctx->input_buf);
        ob_str(ctx, "\xe2\x96\x88");
    } else if (ctx->mode == MODE_SEARCH) {
        ob_str(ctx, ESC_BOLD " Search> " ESC_RESET);
        ob_str(ctx, ctx->input_buf);
        ob_str(ctx, "\xe2\x96\x88");
        ob_str(ctx, ESC_DIM "  (matches info, IPs, protocol; n/N = next/prev)" ESC_RESET);
    } else {
        stats_compute_rates(&ctx->stats);
        char stats_str[256];
        stats_format(&ctx->stats, stats_str, sizeof(stats_str));

        /* build status line */
        const char *bpf = capture_get_bpf(ctx->cap);
        int has_bpf = (bpf && bpf[0]);
        int has_dfilter = (ctx->dfilter.valid && ctx->dfilter.root >= 0);

        ob_printf(ctx, " %s  Dropped: %lu", stats_str, (unsigned long)cstats.pkts_drop);

        if (has_bpf)
            ob_printf(ctx, "  BPF: \033[35m%s\033[0m", bpf);

        if (has_dfilter) {
            uint32_t shown = filtered_count(ctx);
            uint32_t rb_total = ringbuf_count(ctx->rb);
            ob_printf(ctx, "  Display: \033[33m%s\033[0m (%u/%u)",
                      ctx->dfilter.expr, shown, rb_total);
        }

        if (ctx->view == VIEW_SESSIONS)
            ob_str(ctx, "  [O]Follow stream");

        if (ctx->paused)
            ob_str(ctx, "  [PAUSED]");

        /* show BPF apply feedback briefly */
        if (ctx->bpf_msg[0] && ctx->bpf_msg_frames > 0) {
            ob_printf(ctx, "  %s", ctx->bpf_msg);
            ctx->bpf_msg_frames--;
            if (ctx->bpf_msg_frames <= 0)
                ctx->bpf_msg[0] = '\0';
        }
    }

    /* clear everything below (handles resize gracefully) */
    ob_str(ctx, ESC_CLR_BELOW);

    if (ctx->mode != MODE_NORMAL)
        ob_str(ctx, ESC_SHOW_CUR);

    ob_flush(ctx);
}

/* ── Update stats from new packets ───────────────────────────── */

static void sync_stats(ui_ctx_t *ctx) {
    uint64_t total = ringbuf_total(ctx->rb);
    /* Skip records that already fell out of the ring; this also bounds
     * the catch-up after a long pause to at most one ring's worth. */
    uint64_t oldest = ringbuf_oldest(ctx->rb);
    if (ctx->last_total < oldest) ctx->last_total = oldest;

    pkt_record_t rec;
    while (ctx->last_total < total) {
        uint32_t idx = (uint32_t)(ctx->last_total - oldest);
        if (ringbuf_read(ctx->rb, idx, &rec, NULL))
            stats_update(&ctx->stats, &rec.summary);
        ctx->last_total++;
    }
}

/* ── Input handling ──────────────────────────────────────────── */

/* Logical navigation keys, produced by both the ANSI escape parser and
 * the Windows extended-key translation. */
enum {
    KEY_UP = 1000, KEY_DOWN, KEY_PGUP, KEY_PGDN, KEY_HOME, KEY_END,
    KEY_LEFT, KEY_RIGHT
};

static void navigate(ui_ctx_t *ctx, int key) {
    if (ctx->view == VIEW_SESSIONS) {
        switch (key) {
            case KEY_UP:   if (ctx->sess_selected > 0) ctx->sess_selected--; break;
            case KEY_DOWN: ctx->sess_selected++; break;
            case KEY_PGUP: ctx->sess_selected -= 20;
                           if (ctx->sess_selected < 0) ctx->sess_selected = 0;
                           break;
            case KEY_PGDN: ctx->sess_selected += 20; break;
            case KEY_HOME: ctx->sess_selected = 0; break;
            case KEY_END:  ctx->sess_selected = (int)ctx->sess_snap_count - 1; break;
        }
    } else {
        switch (key) {
            case KEY_UP:   if (ctx->selected > 0) ctx->selected--; break;
            case KEY_DOWN: ctx->selected++; break;
            case KEY_PGUP: ctx->selected -= 20;
                           if (ctx->selected < 0) ctx->selected = 0;
                           break;
            case KEY_PGDN: ctx->selected += 20; break;
            case KEY_HOME: ctx->selected = 0; break;
            case KEY_END:  ctx->selected = (int)filtered_count(ctx) - 1; break;
            case KEY_LEFT:  if (ctx->hex_scroll > 0) ctx->hex_scroll--; return;
            case KEY_RIGHT: ctx->hex_scroll++; return;   /* clamped in render */
        }
        ctx->hex_scroll = 0;   /* selection moved: restart the hex view */
    }
}

static int read_key(void) {
#ifdef _WIN32
    if (!_kbhit()) return -1;
    int c = _getch();
    /* Extended keys arrive as a 0x00/0xE0 prefix plus a scan code; the
     * scan code must not be interpreted as a normal character (it made
     * PgDn quit and Up open Help). */
    if (c == 0 || c == 0xE0) {
        int scan = _kbhit() ? _getch() : -1;
        switch (scan) {
            case 72: return KEY_UP;
            case 80: return KEY_DOWN;
            case 73: return KEY_PGUP;
            case 81: return KEY_PGDN;
            case 71: return KEY_HOME;
            case 79: return KEY_END;
            case 75: return KEY_LEFT;
            case 77: return KEY_RIGHT;
            default: return -1;
        }
    }
    return c;
#else
    unsigned char c;
    if (read(STDIN_FILENO, &c, 1) == 1) return c;
    return -1;
#endif
}

static void handle_input(ui_ctx_t *ctx) {
    int c = read_key();
    if (c < 0) return;

    if (ctx->mode == MODE_FOLLOW) {
        int page = ctx->rows - 3;      /* matches the overlay's line count */
        if (page < 1) page = 1;
        if (c == 27) {
            int c2 = read_key();
            if (c2 == '[') {           /* nav escape sequence: scroll */
                int c3 = read_key();
                switch (c3) {
                    case 'A': ctx->follow_scroll--; break;
                    case 'B': ctx->follow_scroll++; break;
                    case '5': read_key(); ctx->follow_scroll -= page; break;
                    case '6': read_key(); ctx->follow_scroll += page; break;
                }
                if (ctx->follow_scroll < 0) ctx->follow_scroll = 0;
                return;                /* upper clamp happens in render */
            }
            follow_close(ctx);         /* bare ESC */
        } else if (c == 'q' || c == 'Q' || c == '\n' || c == '\r') {
            follow_close(ctx);
        } else if (c == KEY_UP) {
            if (ctx->follow_scroll > 0) ctx->follow_scroll--;
        } else if (c == KEY_DOWN) {
            ctx->follow_scroll++;
        } else if (c == KEY_PGUP) {
            ctx->follow_scroll -= page;
            if (ctx->follow_scroll < 0) ctx->follow_scroll = 0;
        } else if (c == KEY_PGDN) {
            ctx->follow_scroll += page;
        }
        return;
    }

    if (ctx->mode == MODE_HELP || ctx->mode == MODE_STATS) {
        ctx->mode = MODE_NORMAL;  /* any key dismisses the overlay */
        return;
    }

    if (ctx->mode == MODE_FILTER || ctx->mode == MODE_BPF ||
        ctx->mode == MODE_EXPORT || ctx->mode == MODE_SEARCH) {
        if (c == 27) {
            int c2 = read_key();
            if (c2 == '[') {
                /* arrow/nav escape sequence: swallow it, keep the prompt */
                int c3 = read_key();
                if (c3 == '5' || c3 == '6') read_key();   /* trailing ~ */
                return;
            }
            ctx->mode = MODE_NORMAL;   /* bare ESC cancels */
            ctx->input_pos = 0;
            ctx->input_buf[0] = '\0';
        } else if (c >= KEY_UP && c <= KEY_RIGHT) {
            /* ignore translated nav keys inside prompts (Windows path) */
        } else if (c == '\n' || c == '\r') {
            if (ctx->mode == MODE_FILTER) {
                const char *expr = ctx->input_buf;
                if (expr[0] == '@') {
                    /* "@name" applies a saved preset's expression */
                    const filter_preset_t *p = preset_find(ctx, expr + 1);
                    if (p) {
                        expr = p->expr;
                    } else {
                        snprintf(ctx->bpf_msg, sizeof(ctx->bpf_msg),
                                 "\033[31mUnknown preset: %.40s\033[0m",
                                 ctx->input_buf);
                        ctx->bpf_msg_frames = 80;
                        expr = NULL;   /* keep the current display filter */
                    }
                }
                if (expr) {
                    filter_compile(expr, &ctx->dfilter);
                    fcache_reset(ctx);
                    ctx->selected = 0;
                    ctx->scroll_off = 0;
                }
            } else if (ctx->mode == MODE_SEARCH) {
                snprintf(ctx->search, sizeof(ctx->search), "%s", ctx->input_buf);
                do_search(ctx, +1);
            } else if (ctx->mode == MODE_BPF) {
                char errbuf[256];
                if (capture_set_bpf(ctx->cap, ctx->input_buf, errbuf, sizeof(errbuf)) == 0) {
                    if (ctx->input_buf[0])
                        snprintf(ctx->bpf_msg, sizeof(ctx->bpf_msg),
                                 "\033[32mBPF applied: %s\033[0m", ctx->input_buf);
                    else
                        snprintf(ctx->bpf_msg, sizeof(ctx->bpf_msg),
                                 "\033[32mBPF cleared (accept all)\033[0m");
                    ctx->bpf_msg_frames = 60; /* show for ~3 seconds */
                } else {
                    snprintf(ctx->bpf_msg, sizeof(ctx->bpf_msg),
                             "\033[31mBPF error: %s\033[0m", errbuf);
                    ctx->bpf_msg_frames = 80;
                }
            } else if (ctx->mode == MODE_EXPORT) {
                const char *path = ctx->input_buf;
                size_t plen = strlen(path);
                int n = 0;
                if (plen > 0) {
                    if (plen > 5 && strcmp(path + plen - 5, ".json") == 0) {
                        n = export_json(path, ctx->rb, &ctx->dfilter,
                                        capture_get_iface(ctx->cap),
                                        ctx->cfg.bpf_filter);
                    } else {
                        n = export_pcap(path, ctx->rb, &ctx->dfilter,
                                        (uint32_t)ctx->cfg.snaplen,
                                        capture_get_datalink(ctx->cap));
                    }
                    if (n >= 0)
                        snprintf(ctx->bpf_msg, sizeof(ctx->bpf_msg),
                                 "\033[32mExported %d packets to %s\033[0m", n, path);
                    else
                        snprintf(ctx->bpf_msg, sizeof(ctx->bpf_msg),
                                 "\033[31mExport failed: %s (%s)\033[0m",
                                 path, strerror(errno));
                    ctx->bpf_msg_frames = 80;
                }
            }
            ctx->mode = MODE_NORMAL;
            ctx->input_pos = 0;
            ctx->input_buf[0] = '\0';
        } else if (c == 127 || c == 8) {
            if (ctx->input_pos > 0) {
                ctx->input_pos--;
                ctx->input_buf[ctx->input_pos] = '\0';
            }
        } else if (c >= 32 && c < 127 && ctx->input_pos < 254) {
            ctx->input_buf[ctx->input_pos++] = (char)c;
            ctx->input_buf[ctx->input_pos] = '\0';
        }
        return;
    }

    /* normal mode */
    if (c == 'q' || c == 'Q') {
        ctx->stop = 1;
    } else if (c == 's' || c == 'S') {
        if (ctx->view == VIEW_SESSIONS) {
            ctx->view = VIEW_PACKETS;
        } else {
            ctx->view = VIEW_SESSIONS;
            ctx->sess_selected = 0;
            ctx->sess_scroll = 0;
        }
    } else if (c == 'f' || c == 'F') {
        ctx->mode = MODE_FILTER;
        ctx->input_pos = 0;
        ctx->input_buf[0] = '\0';
    } else if (c == 'b' || c == 'B') {
        ctx->mode = MODE_BPF;
        ctx->input_pos = 0;
        /* pre-fill with current BPF */
        const char *cur = capture_get_bpf(ctx->cap);
        if (cur && cur[0]) {
            snprintf(ctx->input_buf, sizeof(ctx->input_buf), "%s", cur);
            ctx->input_pos = (int)strlen(ctx->input_buf);
        } else {
            ctx->input_buf[0] = '\0';
        }
    } else if (c == 'e' || c == 'E') {
        ctx->mode = MODE_EXPORT;
        /* pre-fill with default writable path */
        {
            const char *dir = "/tmp";  /* always writable fallback */
#ifndef _WIN32
            /* try user's home — handle sudo where $HOME=/var/root */
            const char *sudo_user = getenv("SUDO_USER");
            static char homedir[256];
            if (sudo_user) {
                /* try platform home dirs */
#ifdef __APPLE__
                snprintf(homedir, sizeof(homedir), "/Users/%s", sudo_user);
#else
                snprintf(homedir, sizeof(homedir), "/home/%s", sudo_user);
#endif
                if (access(homedir, W_OK) == 0) dir = homedir;
            } else {
                const char *h = getenv("HOME");
                if (h && access(h, W_OK) == 0) dir = h;
            }
#else
            const char *h = getenv("USERPROFILE");
            if (h) dir = h;
#endif
            snprintf(ctx->input_buf, sizeof(ctx->input_buf), "%s/capture.pcap", dir);
            ctx->input_pos = (int)strlen(ctx->input_buf);
        }
    } else if (c == 'c' || c == 'C') {
        ringbuf_clear(ctx->rb);
        if (ctx->sessions) session_table_clear(ctx->sessions);
        stats_init(&ctx->stats);
        fcache_reset(ctx);
        ctx->last_total = ringbuf_total(ctx->rb);
        ctx->selected = 0;
        ctx->scroll_off = 0;
    } else if (c == 'p' || c == 'P') {
        ctx->paused = !ctx->paused;
    } else if (c == 'h' || c == 'H' || c == '?') {
        ctx->mode = MODE_HELP;
    } else if (c == 'v' || c == 'V') {
        ctx->mode = MODE_STATS;
    } else if (c == '/') {
        ctx->mode = MODE_SEARCH;
        ctx->input_pos = 0;
        ctx->input_buf[0] = '\0';
    } else if (c == 'n') {
        do_search(ctx, +1);
    } else if (c == 'N') {
        do_search(ctx, -1);
    } else if (c == '\n' || c == '\r') {
        if (ctx->view == VIEW_SESSIONS) {
            /* drill into selected session: switch to packet view with filter */
            if (ctx->sess_snap && ctx->sess_selected >= 0 &&
                (uint32_t)ctx->sess_selected < ctx->sess_snap_count) {
                uint32_t sid = ctx->sess_snap[ctx->sess_selected].id;
                char expr[32];
                snprintf(expr, sizeof(expr), "session == %u", sid);
                filter_compile(expr, &ctx->dfilter);
                fcache_reset(ctx);
                ctx->view = VIEW_PACKETS;
                ctx->selected = 0;
                ctx->scroll_off = 0;
                ctx->detail_open = 0;
            }
        } else {
            ctx->detail_open = !ctx->detail_open;
            ctx->hex_scroll = 0;
        }
    } else if (c == 't' || c == 'T') {
        /* cycle session sort in session view */
        if (ctx->view == VIEW_SESSIONS) {
            ctx->sess_sort = (session_sort_t)((ctx->sess_sort + 1) % 4);
        }
    } else if (c == 'o' || c == 'O') {
        /* follow the selected session's reassembled TCP stream */
        if (ctx->view == VIEW_SESSIONS && ctx->sess_snap &&
            ctx->sess_selected >= 0 &&
            (uint32_t)ctx->sess_selected < ctx->sess_snap_count) {
            follow_open(ctx, ctx->sess_snap[ctx->sess_selected].id);
        }
    } else if (c == 27) {
        int c2 = read_key();
        if (c2 == '[') {
            int c3  = read_key();
            int key = -1;
            switch (c3) {
                case 'A': key = KEY_UP;   break;
                case 'B': key = KEY_DOWN; break;
                case '5': read_key(); key = KEY_PGUP; break;
                case '6': read_key(); key = KEY_PGDN; break;
                case 'H': key = KEY_HOME; break;
                case 'F': key = KEY_END;  break;
                case 'C': key = KEY_RIGHT; break;
                case 'D': key = KEY_LEFT;  break;
            }
            if (key >= 0) navigate(ctx, key);
        }
    } else if (c >= KEY_UP && c <= KEY_RIGHT) {
        navigate(ctx, c);   /* Windows extended keys */
    }
}

/* ── Public API ──────────────────────────────────────────────── */

ui_ctx_t *ui_create(ringbuf_t *rb, capture_ctx_t *cap,
                     const capture_cfg_t *cfg, session_table_t *st,
                     const filter_preset_t *presets, int npresets) {
    ui_ctx_t *ctx = calloc(1, sizeof(ui_ctx_t));
    if (!ctx) return NULL;

    ctx->rb       = rb;
    ctx->cap      = cap;
    ctx->cfg      = *cfg;
    ctx->sessions = st;
    ctx->presets  = presets;
    ctx->npresets = (presets && npresets > 0) ? npresets : 0;
    ctx->outbuf_size = 65536;
    ctx->outbuf = malloc(ctx->outbuf_size);
    if (!ctx->outbuf) { free(ctx); return NULL; }
    ctx->peek_data = malloc(rb->snaplen);
    if (!ctx->peek_data) { free(ctx->outbuf); free(ctx); return NULL; }

    stats_init(&ctx->stats);
    memset(&ctx->dfilter, 0, sizeof(ctx->dfilter));
    ctx->dfilter.valid = true;
    ctx->dfilter.root = -1;

    return ctx;
}

void ui_destroy(ui_ctx_t *ctx) {
    if (!ctx) return;
    free(ctx->follow_a);
    free(ctx->follow_b);
    free(ctx->sess_snap);
    free(ctx->fcache);
    free(ctx->peek_data);
    free(ctx->outbuf);
    free(ctx);
}

void ui_run(ui_ctx_t *ctx) {
    term_raw_enable(ctx);

#ifdef _WIN32
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD written;
    WriteFile(h, ESC_CLEAR ESC_HOME, strlen(ESC_CLEAR ESC_HOME), &written, NULL);
#else
    (void)write(STDOUT_FILENO, ESC_CLEAR ESC_HOME, strlen(ESC_CLEAR ESC_HOME));
#endif

    int notify_fd = ringbuf_get_notify_fd(ctx->rb);

    while (!ctx->stop) {
        if (g_async_stop) break;
#ifdef _WIN32
        Sleep(50);
#else
        fd_set fds;
        struct timeval tv = { .tv_sec = 0, .tv_usec = 50000 };
        FD_ZERO(&fds);
        FD_SET(STDIN_FILENO, &fds);
        int maxfd = STDIN_FILENO;
        if (notify_fd >= 0) {
            FD_SET(notify_fd, &fds);
            if (notify_fd > maxfd) maxfd = notify_fd;
        }
        select(maxfd + 1, &fds, NULL, NULL, &tv);
        if (notify_fd >= 0 && FD_ISSET(notify_fd, &fds))
            ringbuf_drain_notify(ctx->rb);
#endif

        if (!ctx->paused)
            sync_stats(ctx);

        handle_input(ctx);
        render_frame(ctx);
    }

#ifdef _WIN32
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),
              ESC_SHOW_CUR ESC_RESET "\n", strlen(ESC_SHOW_CUR ESC_RESET "\n"),
              &(DWORD){0}, NULL);
#else
    (void)write(STDOUT_FILENO, ESC_SHOW_CUR ESC_RESET ESC_CLEAR ESC_HOME,
                strlen(ESC_SHOW_CUR ESC_RESET ESC_CLEAR ESC_HOME));
#endif

    term_raw_disable(ctx);
}

void ui_request_stop_async(void) {
    g_async_stop = 1;
}

void ui_request_stop(ui_ctx_t *ctx) {
    if (ctx) ctx->stop = 1;
}
