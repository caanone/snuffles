#include "ui.h"
#include "dissect.h"
#include "export_pcap.h"
#include "export_json.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <math.h>
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
    session_entry_t   **sess_snap;
    uint32_t            sess_snap_count;

    uint64_t            last_total;
    int                 cur_row;

    char               *outbuf;
    size_t              outbuf_size;
    size_t              outbuf_pos;

#ifndef _WIN32
    struct termios      orig_tio;
#endif
};

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

static void term_raw_enable(ui_ctx_t *ctx) {
#ifdef _WIN32
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode;
    GetConsoleMode(h, &mode);
    SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
#else
    struct termios tio;
    tcgetattr(STDIN_FILENO, &ctx->orig_tio);
    tio = ctx->orig_tio;
    tio.c_lflag &= ~(ICANON | ECHO);
    tio.c_cc[VMIN]  = 0;
    tio.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSANOW, &tio);
#endif
}

static void term_raw_disable(ui_ctx_t *ctx) {
#ifdef _WIN32
    (void)ctx;
#else
    tcsetattr(STDIN_FILENO, TCSANOW, &ctx->orig_tio);
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

static uint32_t filtered_count(ui_ctx_t *ctx) {
    uint32_t total = ringbuf_count(ctx->rb);
    if (!ctx->dfilter.valid || ctx->dfilter.root < 0)
        return total;

    uint32_t c = 0;
    for (uint32_t i = 0; i < total; i++) {
        const pkt_record_t *rec = ringbuf_peek(ctx->rb, i);
        if (rec && filter_eval(&ctx->dfilter, &rec->summary))
            c++;
    }
    return c;
}

static const pkt_record_t *filtered_peek(ui_ctx_t *ctx, uint32_t idx) {
    uint32_t total = ringbuf_count(ctx->rb);
    if (!ctx->dfilter.valid || ctx->dfilter.root < 0)
        return ringbuf_peek(ctx->rb, idx);

    uint32_t c = 0;
    for (uint32_t i = 0; i < total; i++) {
        const pkt_record_t *rec = ringbuf_peek(ctx->rb, i);
        if (!rec) continue;
        if (filter_eval(&ctx->dfilter, &rec->summary)) {
            if (c == idx) return rec;
            c++;
        }
    }
    return NULL;
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
    ob_printf(ctx, " %s v%s | %s | captured: %lu | dropped: %lu ",
              SNUFFLES_NAME, SNUFFLES_VERSION_STR,
              capture_get_iface(ctx->cap),
              (unsigned long)ringbuf_total(ctx->rb),
              (unsigned long)cstats.pkts_drop);
    ob_str(ctx, ESC_RESET);

    /* ── Row 2: Hotkey bar ──────────────────────────────────── */
    ob_moveto(ctx, row++);
    ob_str(ctx, ESC_DIM);
    ob_printf(ctx, " [S]%s  [F]ilter  [B]PF  [E]xport  [C]lear  [P]%s  [H]elp  [Q]uit",
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
            "                  Drill into session (session view)",
            "",
            ESC_BOLD "  VIEWS" ESC_RESET,
            "    S             Toggle between Packets and Sessions view",
            "    T             Cycle session sort (bytes/packets/recent/duration)",
            "",
            ESC_BOLD "  FILTERS" ESC_RESET,
            "    F             Display filter (post-capture, hides packets from view)",
            "                  Syntax: tcp | 10.0.0.1 | port 443 | ip == 10.0.0.0/24",
            "                          info contains GET | session == 5 | !arp",
            "                          Combine: and or not () && || !",
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
                const session_entry_t *se = ctx->sess_snap[si];
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
                    long sec = (long)(s->ts.tv_sec % 86400);
                    snprintf(ts, sizeof(ts), "%02ld:%02ld:%02ld.%03ld",
                             sec / 3600, (sec % 3600) / 60, sec % 60,
                             (long)(s->ts.tv_usec / 1000));

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

                snprintf(lines[nlines++], 128, " Pkt #%d (session %u): %u bytes, %u captured",
                         ctx->selected + 1, s->session_id, s->length, rec->raw_len);
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

                for (uint32_t off = 0; off < rec->raw_len && used < detail_rows; off += 16) {
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
        if (ctx->input_buf[0]) {
            display_filter_t preview;
            if (filter_compile(ctx->input_buf, &preview) == 0) {
                uint32_t matches = 0;
                uint32_t rb_count = ringbuf_count(ctx->rb);
                uint32_t scan_limit = rb_count < 2000 ? rb_count : 2000;
                for (uint32_t fi = 0; fi < scan_limit; fi++) {
                    const pkt_record_t *r = ringbuf_peek(ctx->rb, fi);
                    if (r && filter_eval(&preview, &r->summary)) matches++;
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
    while (ctx->last_total < total) {
        uint32_t count = ringbuf_count(ctx->rb);
        uint32_t idx;
        if (total <= count)
            idx = (uint32_t)ctx->last_total;
        else
            idx = (uint32_t)(ctx->last_total - (total - count));
        const pkt_record_t *rec = ringbuf_peek(ctx->rb, idx);
        if (rec) stats_update(&ctx->stats, &rec->summary);
        ctx->last_total++;
    }
}

/* ── Input handling ──────────────────────────────────────────── */

static int read_key(void) {
#ifdef _WIN32
    if (_kbhit()) return _getch();
    return -1;
#else
    unsigned char c;
    if (read(STDIN_FILENO, &c, 1) == 1) return c;
    return -1;
#endif
}

static void handle_input(ui_ctx_t *ctx) {
    int c = read_key();
    if (c < 0) return;

    if (ctx->mode == MODE_HELP) {
        ctx->mode = MODE_NORMAL;  /* any key dismisses help */
        return;
    }

    if (ctx->mode == MODE_FILTER || ctx->mode == MODE_BPF || ctx->mode == MODE_EXPORT) {
        if (c == 27) {
            ctx->mode = MODE_NORMAL;
            ctx->input_pos = 0;
            ctx->input_buf[0] = '\0';
        } else if (c == '\n' || c == '\r') {
            if (ctx->mode == MODE_FILTER) {
                filter_compile(ctx->input_buf, &ctx->dfilter);
                ctx->selected = 0;
                ctx->scroll_off = 0;
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
                                        (uint32_t)ctx->cfg.snaplen);
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
        ctx->last_total = 0;
        ctx->selected = 0;
        ctx->scroll_off = 0;
    } else if (c == 'p' || c == 'P') {
        ctx->paused = !ctx->paused;
    } else if (c == 'h' || c == 'H' || c == '?') {
        ctx->mode = MODE_HELP;
    } else if (c == '\n' || c == '\r') {
        if (ctx->view == VIEW_SESSIONS) {
            /* drill into selected session: switch to packet view with filter */
            if (ctx->sess_snap && ctx->sess_selected >= 0 &&
                (uint32_t)ctx->sess_selected < ctx->sess_snap_count) {
                uint32_t sid = ctx->sess_snap[ctx->sess_selected]->id;
                char expr[32];
                snprintf(expr, sizeof(expr), "session == %u", sid);
                filter_compile(expr, &ctx->dfilter);
                ctx->view = VIEW_PACKETS;
                ctx->selected = 0;
                ctx->scroll_off = 0;
                ctx->detail_open = 0;
            }
        } else {
            ctx->detail_open = !ctx->detail_open;
        }
    } else if (c == 't' || c == 'T') {
        /* cycle session sort in session view */
        if (ctx->view == VIEW_SESSIONS) {
            ctx->sess_sort = (session_sort_t)((ctx->sess_sort + 1) % 4);
        }
    } else if (c == 27) {
        int c2 = read_key();
        if (c2 == '[') {
            int c3 = read_key();
            if (ctx->view == VIEW_SESSIONS) {
                switch (c3) {
                    case 'A': if (ctx->sess_selected > 0) ctx->sess_selected--; break;
                    case 'B': ctx->sess_selected++; break;
                    case '5': read_key(); ctx->sess_selected -= 20;
                              if (ctx->sess_selected < 0) ctx->sess_selected = 0; break;
                    case '6': read_key(); ctx->sess_selected += 20; break;
                    case 'H': ctx->sess_selected = 0; break;
                    case 'F': ctx->sess_selected = (int)ctx->sess_snap_count - 1; break;
                }
            } else {
                switch (c3) {
                    case 'A': if (ctx->selected > 0) ctx->selected--; break;
                    case 'B': ctx->selected++; break;
                    case '5': read_key(); ctx->selected -= 20;
                              if (ctx->selected < 0) ctx->selected = 0; break;
                    case '6': read_key(); ctx->selected += 20; break;
                    case 'H': ctx->selected = 0; break;
                    case 'F': ctx->selected = (int)filtered_count(ctx) - 1; break;
                }
            }
        }
    }
}

/* ── Public API ──────────────────────────────────────────────── */

ui_ctx_t *ui_create(ringbuf_t *rb, capture_ctx_t *cap,
                     const capture_cfg_t *cfg, session_table_t *st) {
    ui_ctx_t *ctx = calloc(1, sizeof(ui_ctx_t));
    if (!ctx) return NULL;

    ctx->rb       = rb;
    ctx->cap      = cap;
    ctx->cfg      = *cfg;
    ctx->sessions = st;
    ctx->outbuf_size = 65536;
    ctx->outbuf = malloc(ctx->outbuf_size);
    if (!ctx->outbuf) { free(ctx); return NULL; }

    stats_init(&ctx->stats);
    memset(&ctx->dfilter, 0, sizeof(ctx->dfilter));
    ctx->dfilter.valid = true;
    ctx->dfilter.root = -1;

    return ctx;
}

void ui_destroy(ui_ctx_t *ctx) {
    if (!ctx) return;
    free(ctx->sess_snap);
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

void ui_request_stop(ui_ctx_t *ctx) {
    if (ctx) ctx->stop = 1;
}
