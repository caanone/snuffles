#include "cbpf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>

/* BPF opcodes (classic) */
#define OP_LD_ABS   0x20   /* A = u32 at [k] */
#define OP_LDH_ABS  0x28   /* A = u16 at [k] */
#define OP_LDB_ABS  0x30   /* A = u8  at [k] */
#define OP_LDH_IND  0x48   /* A = u16 at [X+k] */
#define OP_LDX_MSH  0xb1   /* X = 4 * (u8 at [k] & 0x0f)  (IP header length) */
#define OP_JEQ      0x15
#define OP_JSET     0x45
#define OP_RET      0x06

/* Ethernet frame offsets (DLT_EN10MB) */
#define OFF_ETHERTYPE 12
#define OFF_IP        14
#define OFF_IP_FRAG   (OFF_IP + 6)
#define OFF_IP_PROTO  (OFF_IP + 9)
#define OFF_IP_SRC    (OFF_IP + 12)
#define OFF_IP_DST    (OFF_IP + 16)

typedef struct {
    cbpf_insn_t *insns;
    int          count;
    int          max;
    /* indices whose jt/jf must be patched to jump to REJECT */
    int          fix_idx[CBPF_MAX_INSNS];
    char         fix_which[CBPF_MAX_INSNS];   /* 't' or 'f' */
    int          fix_count;
    uint16_t     ethertype_checked;           /* 0 = not yet */
    char        *errbuf;
    size_t       errlen;
} cg_t;

static int emit(cg_t *g, uint16_t code, uint8_t jt, uint8_t jf, uint32_t k) {
    if (g->count >= g->max) {
        snprintf(g->errbuf, g->errlen, "filter too complex");
        return -1;
    }
    g->insns[g->count].code = code;
    g->insns[g->count].jt   = jt;
    g->insns[g->count].jf   = jf;
    g->insns[g->count].k    = k;
    return g->count++;
}

/* Emit a jump whose true/false branch must be patched to REJECT. */
static int emit_j(cg_t *g, uint16_t code, uint32_t k, char reject_branch,
                  uint8_t other_off) {
    int idx = (reject_branch == 'f')
                  ? emit(g, code, other_off, 0, k)
                  : emit(g, code, 0, other_off, k);
    if (idx < 0) return -1;
    g->fix_idx[g->fix_count]   = idx;
    g->fix_which[g->fix_count] = reject_branch;
    g->fix_count++;
    return idx;
}

static int need_ethertype(cg_t *g, uint16_t et) {
    if (g->ethertype_checked == et) return 0;
    if (g->ethertype_checked != 0) {
        snprintf(g->errbuf, g->errlen, "conflicting protocols in filter");
        return -1;
    }
    if (emit(g, OP_LDH_ABS, 0, 0, OFF_ETHERTYPE) < 0) return -1;
    if (emit_j(g, OP_JEQ, et, 'f', 0) < 0) return -1;
    g->ethertype_checked = et;
    return 0;
}

static int emit_proto(cg_t *g, uint8_t proto) {
    if (need_ethertype(g, 0x0800) < 0) return -1;
    if (emit(g, OP_LDB_ABS, 0, 0, OFF_IP_PROTO) < 0) return -1;
    return emit_j(g, OP_JEQ, proto, 'f', 0);
}

static int emit_host(cg_t *g, uint32_t ip, int dir /* 0=both 1=src 2=dst */) {
    if (need_ethertype(g, 0x0800) < 0) return -1;
    if (dir == 0) {
        if (emit(g, OP_LD_ABS, 0, 0, OFF_IP_SRC) < 0) return -1;
        if (emit(g, OP_JEQ, 2, 0, ip) < 0) return -1;   /* match: skip dst check */
        if (emit(g, OP_LD_ABS, 0, 0, OFF_IP_DST) < 0) return -1;
        return emit_j(g, OP_JEQ, ip, 'f', 0);
    }
    if (emit(g, OP_LD_ABS, 0, 0, dir == 1 ? OFF_IP_SRC : OFF_IP_DST) < 0)
        return -1;
    return emit_j(g, OP_JEQ, ip, 'f', 0);
}

static int emit_port(cg_t *g, uint16_t port, int dir) {
    if (need_ethertype(g, 0x0800) < 0) return -1;
    /* ports exist only for TCP(6)/UDP(17)/SCTP(132) */
    if (emit(g, OP_LDB_ABS, 0, 0, OFF_IP_PROTO) < 0) return -1;
    if (emit(g, OP_JEQ, 2, 0, 6) < 0) return -1;    /* TCP: skip to port test */
    if (emit(g, OP_JEQ, 1, 0, 17) < 0) return -1;   /* UDP */
    if (emit_j(g, OP_JEQ, 132, 'f', 0) < 0) return -1;
    /* non-first fragments carry no L4 header */
    if (emit(g, OP_LDH_ABS, 0, 0, OFF_IP_FRAG) < 0) return -1;
    if (emit_j(g, OP_JSET, 0x1FFF, 't', 0) < 0) return -1;
    /* X = IP header length */
    if (emit(g, OP_LDX_MSH, 0, 0, OFF_IP) < 0) return -1;
    if (dir == 0) {
        if (emit(g, OP_LDH_IND, 0, 0, OFF_IP) < 0) return -1;      /* src */
        if (emit(g, OP_JEQ, 2, 0, port) < 0) return -1;  /* match: skip dst */
        if (emit(g, OP_LDH_IND, 0, 0, OFF_IP + 2) < 0) return -1;  /* dst */
        return emit_j(g, OP_JEQ, port, 'f', 0);
    }
    if (emit(g, OP_LDH_IND, 0, 0, dir == 1 ? OFF_IP : OFF_IP + 2) < 0)
        return -1;
    return emit_j(g, OP_JEQ, port, 'f', 0);
}

static int parse_ipv4(const char *s, uint32_t *out) {
    unsigned a, b, c, d;
    char extra;
    if (sscanf(s, "%u.%u.%u.%u%c", &a, &b, &c, &d, &extra) != 4) return -1;
    if (a > 255 || b > 255 || c > 255 || d > 255) return -1;
    *out = (a << 24) | (b << 16) | (c << 8) | d;
    return 0;
}

int cbpf_compile(const char *expr, cbpf_insn_t *out, int max,
                 char *errbuf, size_t errlen) {
    cg_t g = { .insns = out, .max = max, .errbuf = errbuf, .errlen = errlen };

    char buf[512];
    snprintf(buf, sizeof(buf), "%s", expr ? expr : "");
    char *tok[32];
    int ntok = 0;
    for (char *p = strtok(buf, " \t"); p && ntok < 32; p = strtok(NULL, " \t"))
        tok[ntok++] = p;
    if (ntok == 0) {
        snprintf(errbuf, errlen, "empty filter");
        return -1;
    }

    int emitted = 0;
    for (int i = 0; i < ntok; i++) {
        int dir = 0;   /* 0=both 1=src 2=dst */
        if (strcasecmp(tok[i], "and") == 0 || strcmp(tok[i], "&&") == 0)
            continue;
        if (strcasecmp(tok[i], "or") == 0 || strcasecmp(tok[i], "not") == 0 ||
            strchr(tok[i], '(') || strchr(tok[i], ')')) {
            snprintf(errbuf, errlen,
                     "'%s' not supported (only primitives joined by 'and')",
                     tok[i]);
            return -1;
        }
        if (strcasecmp(tok[i], "src") == 0 || strcasecmp(tok[i], "dst") == 0) {
            dir = (tolower((unsigned char)tok[i][0]) == 's') ? 1 : 2;
            i++;
            if (i >= ntok) {
                snprintf(errbuf, errlen, "expected host/port after src/dst");
                return -1;
            }
        }
        if (strcasecmp(tok[i], "tcp") == 0) {
            if (emit_proto(&g, 6) < 0) return -1;
        } else if (strcasecmp(tok[i], "udp") == 0) {
            if (emit_proto(&g, 17) < 0) return -1;
        } else if (strcasecmp(tok[i], "icmp") == 0) {
            if (emit_proto(&g, 1) < 0) return -1;
        } else if (strcasecmp(tok[i], "sctp") == 0) {
            if (emit_proto(&g, 132) < 0) return -1;
        } else if (strcasecmp(tok[i], "ip") == 0) {
            if (need_ethertype(&g, 0x0800) < 0) return -1;
        } else if (strcasecmp(tok[i], "arp") == 0) {
            if (need_ethertype(&g, 0x0806) < 0) return -1;
        } else if (strcasecmp(tok[i], "host") == 0) {
            uint32_t ip;
            if (++i >= ntok || parse_ipv4(tok[i], &ip) != 0) {
                snprintf(errbuf, errlen, "expected IPv4 address after 'host'");
                return -1;
            }
            if (emit_host(&g, ip, dir) < 0) return -1;
        } else if (strcasecmp(tok[i], "port") == 0) {
            char *end;
            long p = (++i < ntok) ? strtol(tok[i], &end, 10) : 0;
            if (i >= ntok || *end != '\0' || p < 1 || p > 65535) {
                snprintf(errbuf, errlen, "expected port 1-65535 after 'port'");
                return -1;
            }
            if (emit_port(&g, (uint16_t)p, dir) < 0) return -1;
        } else {
            snprintf(errbuf, errlen, "unknown primitive '%s'", tok[i]);
            return -1;
        }
        emitted = 1;
    }
    if (!emitted) {
        snprintf(errbuf, errlen, "empty filter");
        return -1;
    }

    int accept = emit(&g, OP_RET, 0, 0, 0xFFFFFFFF);
    int reject = emit(&g, OP_RET, 0, 0, 0);
    if (accept < 0 || reject < 0) return -1;

    for (int i = 0; i < g.fix_count; i++) {
        int off = reject - g.fix_idx[i] - 1;
        if (off > 255) {
            snprintf(errbuf, errlen, "filter too complex");
            return -1;
        }
        if (g.fix_which[i] == 'f')
            g.insns[g.fix_idx[i]].jf = (uint8_t)off;
        else
            g.insns[g.fix_idx[i]].jt = (uint8_t)off;
    }
    return g.count;
}

int cbpf_set_snaplen(cbpf_insn_t *insns, int n, uint32_t snaplen) {
    int changed = 0;
    for (int i = 0; i < n; i++) {
        if (insns[i].code == OP_RET && insns[i].k == 0xFFFFFFFFu) {
            insns[i].k = snaplen;
            changed++;
        }
    }
    return changed;
}

int cbpf_accept_all(cbpf_insn_t *out, uint32_t snaplen) {
    out[0].code = OP_RET;
    out[0].jt   = 0;
    out[0].jf   = 0;
    out[0].k    = snaplen;
    return 1;
}
