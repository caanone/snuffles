#include "export_json.h"
#include "dissect.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ── JSON writing helpers ────────────────────────────────────── */

static void json_write_escaped(FILE *f, const char *s) {
    fputc('"', f);
    for (; *s; s++) {
        switch (*s) {
            case '"':  fputs("\\\"", f); break;
            case '\\': fputs("\\\\", f); break;
            case '\b': fputs("\\b",  f); break;
            case '\f': fputs("\\f",  f); break;
            case '\n': fputs("\\n",  f); break;
            case '\r': fputs("\\r",  f); break;
            case '\t': fputs("\\t",  f); break;
            default:
                if ((unsigned char)*s < 0x20)
                    fprintf(f, "\\u%04x", (unsigned char)*s);
                else
                    fputc(*s, f);
                break;
        }
    }
    fputc('"', f);
}

static void json_kv_str(FILE *f, const char *key, const char *val, int comma) {
    if (comma) fputs(",\n", f);
    fprintf(f, "      ");
    json_write_escaped(f, key);
    fputs(": ", f);
    json_write_escaped(f, val);
}

static void json_kv_int(FILE *f, const char *key, long long val, int comma) {
    if (comma) fputs(",\n", f);
    fprintf(f, "      ");
    json_write_escaped(f, key);
    fprintf(f, ": %lld", val);
}

static void json_kv_hex(FILE *f, const char *key, const uint8_t *data,
                        uint32_t len, int comma) {
    if (comma) fputs(",\n", f);
    fprintf(f, "      ");
    json_write_escaped(f, key);
    fputs(": \"", f);
    for (uint32_t i = 0; i < len; i++) {
        if (i > 0) fputc(' ', f);
        fprintf(f, "%02x", data[i]);
    }
    fputc('"', f);
}

/* ── JSON Lines (headless --jsonl) ───────────────────────────── */

/* Each line is assembled in a stack buffer and handed to stdio with one
 * fwrite. The previous per-character fputc/fputs path took a stream lock
 * and a call per byte, which made the headless consumer the bottleneck
 * under load. Escaping is byte-for-byte what json_write_escaped() does
 * (tests/test_export_json.c pins that). Appends are bounds-checked, and
 * JL_LINE_MAX is sized so a summary whose every character needs the
 * six-byte \u00xx form still fits, so truncation is unreachable for
 * NUL-terminated summaries. */

#define JL_LINE_MAX 2048

_Static_assert(JL_LINE_MAX >= 6 * (sizeof(((pkt_summary_t *)0)->src_ip) +
                                   sizeof(((pkt_summary_t *)0)->dst_ip) +
                                   sizeof(((pkt_summary_t *)0)->protocol) +
                                   sizeof(((pkt_summary_t *)0)->info))
                              + 32 /* ts_str */ + 256 /* keys, ints */,
               "JL_LINE_MAX cannot hold a fully escaped summary");

typedef struct {
    char   *buf;
    size_t  cap;
    size_t  len;
} jl_buf_t;

static void jl_putc(jl_buf_t *b, char c) {
    if (b->len < b->cap) b->buf[b->len++] = c;
}

static void jl_putn(jl_buf_t *b, const char *s, size_t n) {
    if (n > b->cap - b->len) n = b->cap - b->len;
    memcpy(b->buf + b->len, s, n);
    b->len += n;
}

static void jl_escaped(jl_buf_t *b, const char *s) {
    static const char hex[] = "0123456789abcdef";
    jl_putc(b, '"');
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        switch (c) {
            case '"':  jl_putn(b, "\\\"", 2); break;
            case '\\': jl_putn(b, "\\\\", 2); break;
            case '\b': jl_putn(b, "\\b",  2); break;
            case '\f': jl_putn(b, "\\f",  2); break;
            case '\n': jl_putn(b, "\\n",  2); break;
            case '\r': jl_putn(b, "\\r",  2); break;
            case '\t': jl_putn(b, "\\t",  2); break;
            default:
                if (c < 0x20) {
                    char u[6] = { '\\', 'u', '0', '0', hex[c >> 4], hex[c & 15] };
                    jl_putn(b, u, sizeof(u));
                } else {
                    jl_putc(b, (char)c);
                }
                break;
        }
    }
    jl_putc(b, '"');
}

static void jl_str(jl_buf_t *b, const char *key, const char *val, int comma) {
    if (comma) jl_putc(b, ',');
    jl_escaped(b, key);
    jl_putc(b, ':');
    jl_escaped(b, val);
}

static void jl_int(jl_buf_t *b, const char *key, long long val, int comma) {
    char num[24];
    int n = snprintf(num, sizeof(num), "%lld", val);
    if (comma) jl_putc(b, ',');
    jl_escaped(b, key);
    jl_putc(b, ':');
    if (n > 0) jl_putn(b, num, (size_t)n);
}

void json_line_write(FILE *f, const pkt_summary_t *s) {
    char line[JL_LINE_MAX];
    jl_buf_t b = { line, sizeof(line), 0 };
    char ts_str[32];
    snprintf(ts_str, sizeof(ts_str), "%ld.%06ld",
             (long)s->ts.tv_sec, (long)s->ts.tv_usec);
    jl_putc(&b, '{');
    jl_str(&b, "ts",       ts_str,      0);
    jl_str(&b, "src_ip",   s->src_ip,   1);
    jl_int(&b, "src_port", s->src_port, 1);
    jl_str(&b, "dst_ip",   s->dst_ip,   1);
    jl_int(&b, "dst_port", s->dst_port, 1);
    jl_str(&b, "protocol", s->protocol, 1);
    jl_int(&b, "length",   s->length,   1);
    if (s->vlan_id)
        jl_int(&b, "vlan", s->vlan_id, 1);
    if (s->session_id)
        jl_int(&b, "session", s->session_id, 1);
    jl_str(&b, "info",     s->info,     1);
    jl_putn(&b, "}\n", 2);
    fwrite(line, 1, b.len, f);
}

/* ── Public API ──────────────────────────────────────────────── */

int export_json(const char *path, ringbuf_t *rb,
                const display_filter_t *filt,
                const char *iface, const char *bpf_filter) {
    FILE *f = fopen(path, "w");
    if (!f) return -1;

    uint32_t count = ringbuf_count(rb);
    pkt_record_t rec;

    /* count matching packets */
    uint32_t match_count = 0;
    for (uint32_t i = 0; i < count; i++) {
        if (!ringbuf_read(rb, i, &rec, NULL)) continue;
        if (filt && filt->valid && filt->root >= 0) {
            if (!filter_eval(filt, &rec.summary)) continue;
        }
        match_count++;
    }

    /* header */
    fputs("{\n", f);
    fputs("  \"capture_info\": {\n", f);
    fprintf(f, "    ");
    json_write_escaped(f, "interface"); fputs(": ", f);
    json_write_escaped(f, iface ? iface : "unknown");
    fputs(",\n", f);

    /* start time from first packet */
    char time_str[64] = "N/A";
    if (count > 0) {
        if (ringbuf_read(rb, 0, &rec, NULL)) {
            time_t t = rec.summary.ts.tv_sec;
            struct tm *tm = gmtime(&t);
            if (tm)
                strftime(time_str, sizeof(time_str), "%Y-%m-%dT%H:%M:%SZ", tm);
        }
    }
    fprintf(f, "    ");
    json_write_escaped(f, "start_time"); fputs(": ", f);
    json_write_escaped(f, time_str); fputs(",\n", f);

    fprintf(f, "    ");
    json_write_escaped(f, "packet_count"); fprintf(f, ": %u,\n", match_count);

    fprintf(f, "    ");
    json_write_escaped(f, "filter"); fputs(": ", f);
    json_write_escaped(f, bpf_filter ? bpf_filter : "");
    fputc('\n', f);

    fputs("  },\n", f);
    fputs("  \"packets\": [\n", f);

    int first_pkt = 1;
    int pkt_no = 0;

    uint8_t *data = malloc(rb->snaplen);
    if (!data) { fclose(f); return -1; }

    for (uint32_t i = 0; i < count; i++) {
        if (!ringbuf_read(rb, i, &rec, data)) continue;

        if (filt && filt->valid && filt->root >= 0) {
            if (!filter_eval(filt, &rec.summary)) continue;
        }
        summary_format(&rec.summary);   /* text columns, our copy */

        if (!first_pkt) fputs(",\n", f);
        first_pkt = 0;
        pkt_no++;

        fputs("    {\n", f);

        const pkt_summary_t *s = &rec.summary;

        char ts_str[32];
        snprintf(ts_str, sizeof(ts_str), "%ld.%06ld",
                 (long)s->ts.tv_sec, (long)s->ts.tv_usec);

        json_kv_int(f, "no",        pkt_no,      0);
        json_kv_str(f, "timestamp", ts_str,       1);
        json_kv_str(f, "src_ip",    s->src_ip,    1);
        json_kv_int(f, "src_port",  s->src_port,  1);
        json_kv_str(f, "dst_ip",    s->dst_ip,    1);
        json_kv_int(f, "dst_port",  s->dst_port,  1);
        json_kv_str(f, "protocol",  s->protocol,  1);
        json_kv_int(f, "length",    s->length,    1);
        json_kv_str(f, "info",      s->info,      1);
        json_kv_hex(f, "hex", rec.raw_data, rec.raw_len, 1);

        fputs("\n    }", f);
    }

    fputs("\n  ]\n", f);
    fputs("}\n", f);

    free(data);
    fclose(f);
    return pkt_no;
}
