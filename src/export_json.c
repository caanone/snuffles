#include "export_json.h"
#include <stdio.h>
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

/* ── Public API ──────────────────────────────────────────────── */

int export_json(const char *path, ringbuf_t *rb,
                const display_filter_t *filt,
                const char *iface, const char *bpf_filter) {
    FILE *f = fopen(path, "w");
    if (!f) return -1;

    uint32_t count = ringbuf_count(rb);

    /* count matching packets */
    uint32_t match_count = 0;
    for (uint32_t i = 0; i < count; i++) {
        const pkt_record_t *rec = ringbuf_peek(rb, i);
        if (!rec) continue;
        if (filt && filt->valid && filt->root >= 0) {
            if (!filter_eval(filt, &rec->summary)) continue;
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
        const pkt_record_t *first = ringbuf_peek(rb, 0);
        if (first) {
            time_t t = first->summary.ts.tv_sec;
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

    for (uint32_t i = 0; i < count; i++) {
        const pkt_record_t *rec = ringbuf_peek(rb, i);
        if (!rec) continue;

        if (filt && filt->valid && filt->root >= 0) {
            if (!filter_eval(filt, &rec->summary)) continue;
        }

        if (!first_pkt) fputs(",\n", f);
        first_pkt = 0;
        pkt_no++;

        fputs("    {\n", f);

        const pkt_summary_t *s = &rec->summary;

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
        json_kv_hex(f, "hex", rec->raw_data, rec->raw_len, 1);

        fputs("\n    }", f);
    }

    fputs("\n  ]\n", f);
    fputs("}\n", f);

    fclose(f);
    return pkt_no;
}
