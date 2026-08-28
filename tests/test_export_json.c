#include "export_json.h"
#include "test_common.h"
#include <stdlib.h>
#include <string.h>

/* json_line_write() builds each line in a stack buffer and emits it with
 * one fwrite. The reference below is the previous per-character
 * FILE-based writer, kept verbatim: the buffered path must produce the
 * exact same bytes for every summary, escaping included. */

static void ref_write_escaped(FILE *f, const char *s) {
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

static void ref_str(FILE *f, const char *key, const char *val, int comma) {
    if (comma) fputc(',', f);
    ref_write_escaped(f, key);
    fputc(':', f);
    ref_write_escaped(f, val);
}

static void ref_int(FILE *f, const char *key, long long val, int comma) {
    if (comma) fputc(',', f);
    ref_write_escaped(f, key);
    fprintf(f, ":%lld", val);
}

static void ref_line_write(FILE *f, const pkt_summary_t *s) {
    char ts_str[32];
    snprintf(ts_str, sizeof(ts_str), "%ld.%06ld",
             (long)s->ts.tv_sec, (long)s->ts.tv_usec);
    fputc('{', f);
    ref_str(f, "ts",       ts_str,      0);
    ref_str(f, "src_ip",   s->src_ip,   1);
    ref_int(f, "src_port", s->src_port, 1);
    ref_str(f, "dst_ip",   s->dst_ip,   1);
    ref_int(f, "dst_port", s->dst_port, 1);
    ref_str(f, "protocol", s->protocol, 1);
    ref_int(f, "length",   s->length,   1);
    if (s->vlan_id)
        ref_int(f, "vlan", s->vlan_id, 1);
    if (s->session_id)
        ref_int(f, "session", s->session_id, 1);
    ref_str(f, "info",     s->info,     1);
    fputs("}\n", f);
}

/* ── harness ─────────────────────────────────────────────────── */

typedef void (*line_fn)(FILE *, const pkt_summary_t *);

/* Run fn over the summaries into a temp file; return the bytes written. */
static size_t capture(line_fn fn, const pkt_summary_t *v, int n,
                      char *out, size_t cap) {
    FILE *f = tmpfile();
    if (!f) { printf("tmpfile failed\n"); exit(1); }
    for (int i = 0; i < n; i++) fn(f, &v[i]);
    fflush(f);
    rewind(f);
    size_t len = fread(out, 1, cap, f);
    int eof = feof(f);
    fclose(f);
    if (!eof) { printf("capture buffer too small\n"); exit(1); }
    return len;
}

static int same_bytes(const pkt_summary_t *v, int n) {
    static char a[1 << 16], b[1 << 16];
    size_t la = capture(ref_line_write, v, n, a, sizeof(a));
    size_t lb = capture(json_line_write, v, n, b, sizeof(b));
    if (la != lb || memcmp(a, b, la) != 0) {
        printf("mismatch (%zu vs %zu bytes)\nref: %.*s\nnew: %.*s\n",
               la, lb, (int)la, a, (int)lb, b);
        return 0;
    }
    return 1;
}

static pkt_summary_t mk(const char *si, const char *di, int sp, int dp,
                        const char *proto, const char *info) {
    pkt_summary_t p;
    memset(&p, 0, sizeof(p));
    snprintf(p.src_ip, sizeof(p.src_ip), "%s", si);
    snprintf(p.dst_ip, sizeof(p.dst_ip), "%s", di);
    p.src_port = (uint16_t)sp;
    p.dst_port = (uint16_t)dp;
    snprintf(p.protocol, sizeof(p.protocol), "%s", proto);
    snprintf(p.info, sizeof(p.info), "%s", info);
    p.length = 74;
    p.ts.tv_sec = 1700000000;
    p.ts.tv_usec = 123;
    return p;
}

/* Fill a fixed-size field with n copies of c, NUL-terminated. */
static void fill(char *dst, size_t size, char c, size_t n) {
    if (n > size - 1) n = size - 1;
    memset(dst, c, n);
    dst[n] = '\0';
}

int main(void) {
    /* ── plain records ──────────────────────────────────────── */
    {
        pkt_summary_t v[3];
        v[0] = mk("10.0.0.5", "8.8.8.8", 40000, 443, "TCP", "40000 -> 443 [SYN]");
        v[1] = mk("fe80::1", "ff02::fb", 5353, 5353, "mDNS", "Standard query");
        v[2] = mk("", "", 0, 0, "ARP", "");           /* empty strings */
        CHECK(same_bytes(v, 3));

        /* the exact shape jq consumers depend on */
        char out[512];
        size_t n = capture(json_line_write, v, 1, out, sizeof(out));
        const char *want =
            "{\"ts\":\"1700000000.000123\",\"src_ip\":\"10.0.0.5\","
            "\"src_port\":40000,\"dst_ip\":\"8.8.8.8\",\"dst_port\":443,"
            "\"protocol\":\"TCP\",\"length\":74,"
            "\"info\":\"40000 -> 443 [SYN]\"}\n";
        CHECK(n == strlen(want) && memcmp(out, want, n) == 0);
    }

    /* ── every escape class ─────────────────────────────────── */
    {
        pkt_summary_t v[6];
        v[0] = mk("1.1.1.1", "2.2.2.2", 1, 2, "HTTP",
                  "GET /a?q=\"x\" \\ back\\slash");
        v[1] = mk("1.1.1.1", "2.2.2.2", 1, 2, "HTTP",
                  "ctl\b\f\n\r\t end");
        v[2] = mk("1.1.1.1", "2.2.2.2", 1, 2, "DNS",
                  "\x01\x02\x1f\x7f mixed \x1b[31mansi\x1b[0m");
        v[3] = mk("1.1.1.1", "2.2.2.2", 1, 2, "TLS",
                  "high \x80\xc3\xa9\xff bytes pass through");
        v[4] = mk("\"quoted\"", "back\\slash", 1, 2, "\t\n", "");
        v[5] = mk("1.1.1.1", "2.2.2.2", 1, 2, "TCP", "\"");
        CHECK(same_bytes(v, 6));

        /* spot-check the escaping itself, not just parity */
        char out[512];
        size_t n = capture(json_line_write, &v[1], 1, out, sizeof(out));
        CHECK(n > 0 && strstr(out, "\"info\":\"ctl\\b\\f\\n\\r\\t end\"}") != NULL);
        n = capture(json_line_write, &v[2], 1, out, sizeof(out));
        CHECK(n > 0 && strstr(out, "\\u0001\\u0002\\u001f\x7f mixed \\u001b[31m") != NULL);
    }

    /* ── optional keys ──────────────────────────────────────── */
    {
        pkt_summary_t v[4];
        v[0] = mk("10.0.0.1", "10.0.0.2", 1, 2, "TCP", "vlan only");
        v[0].vlan_id = 100;
        v[1] = mk("10.0.0.1", "10.0.0.2", 1, 2, "TCP", "session only");
        v[1].session_id = 7;
        v[2] = mk("10.0.0.1", "10.0.0.2", 1, 2, "TCP", "both");
        v[2].vlan_id = 4095; v[2].session_id = 0xFFFFFFFFu;
        v[3] = mk("10.0.0.1", "10.0.0.2", 65535, 65535, "TCP", "neither");
        v[3].length = 0xFFFFFFFFu;
        CHECK(same_bytes(v, 4));

        char out[512];
        size_t n = capture(json_line_write, &v[2], 1, out, sizeof(out));
        CHECK(n > 0 && strstr(out, "\"length\":74,\"vlan\":4095,\"session\":4294967295,\"info\"") != NULL);
        n = capture(json_line_write, &v[3], 1, out, sizeof(out));
        CHECK(n > 0 && strstr(out, "\"length\":4294967295,\"info\"") != NULL);
        CHECK(strstr(out, "vlan") == NULL && strstr(out, "session") == NULL);
    }

    /* ── timestamps ─────────────────────────────────────────── */
    {
        pkt_summary_t v[3];
        v[0] = mk("1.1.1.1", "2.2.2.2", 1, 2, "TCP", "epoch");
        v[0].ts.tv_sec = 0; v[0].ts.tv_usec = 0;
        v[1] = mk("1.1.1.1", "2.2.2.2", 1, 2, "TCP", "usec max");
        v[1].ts.tv_sec = 2147483647L; v[1].ts.tv_usec = 999999;
        v[2] = mk("1.1.1.1", "2.2.2.2", 1, 2, "TCP", "negative");
        v[2].ts.tv_sec = -1; v[2].ts.tv_usec = -5;
        CHECK(same_bytes(v, 3));
    }

    /* ── worst case: every field full and every byte escaped ─── */
    {
        pkt_summary_t v[2];
        memset(v, 0, sizeof(v));
        fill(v[0].src_ip,   sizeof(v[0].src_ip),   '"',  sizeof(v[0].src_ip));
        fill(v[0].dst_ip,   sizeof(v[0].dst_ip),   '\\', sizeof(v[0].dst_ip));
        fill(v[0].protocol, sizeof(v[0].protocol), '\n', sizeof(v[0].protocol));
        fill(v[0].info,     sizeof(v[0].info),     '\x01', sizeof(v[0].info));
        v[0].src_port = 65535; v[0].dst_port = 65535;
        v[0].length = 0xFFFFFFFFu; v[0].vlan_id = 4095;
        v[0].session_id = 0xFFFFFFFFu;
        v[0].ts.tv_sec = 2147483647L; v[0].ts.tv_usec = 999999;
        v[1] = v[0];                     /* six bytes per input byte */
        fill(v[1].src_ip,   sizeof(v[1].src_ip),   '\x1f', sizeof(v[1].src_ip));
        fill(v[1].dst_ip,   sizeof(v[1].dst_ip),   '\x1f', sizeof(v[1].dst_ip));
        fill(v[1].protocol, sizeof(v[1].protocol), '\x1f', sizeof(v[1].protocol));
        fill(v[1].info,     sizeof(v[1].info),     '\x1f', sizeof(v[1].info));
        CHECK(same_bytes(v, 2));

        /* nothing was truncated: 232 escaped bytes * 6 + keys/numbers */
        char out[4096];
        size_t n = capture(json_line_write, &v[1], 1, out, sizeof(out));
        CHECK(n > 232 * 6 && n < 2048);
        CHECK(out[n - 2] == '}' && out[n - 1] == '\n');
        CHECK(memchr(out, '\n', n - 1) == NULL);   /* one record, one line */
        printf("worst-case line: %zu bytes\n", n);
    }

    /* ── a burst: consecutive records do not leak state ──────── */
    {
        enum { N = 200 };
        static pkt_summary_t v[N];
        for (int i = 0; i < N; i++) {
            char info[128];
            snprintf(info, sizeof(info), "pkt %d \"q\" \\ \x02 end", i);
            v[i] = mk("192.168.1.1", "192.168.1.2", 1000 + i, 80,
                      (i & 1) ? "TCP" : "UDP", info);
            v[i].ts.tv_usec = i;
            if (i % 3 == 0) v[i].vlan_id = (uint16_t)i;
            if (i % 5 == 0) v[i].session_id = (uint32_t)i;
        }
        CHECK(same_bytes(v, N));
    }

    TEST_MAIN_END();
}
