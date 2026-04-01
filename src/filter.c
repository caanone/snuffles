#include "filter.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #include <arpa/inet.h>
#endif

/* ── Shorthand protocol names ────────────────────────────────── */

static int is_proto_shorthand(const char *s) {
    static const char *protos[] = {
        "tcp", "udp", "icmp", "icmpv6", "arp", "dns",
        "http", "tls", "sctp", "ipv4", "ipv6", "vlan", NULL
    };
    for (int i = 0; protos[i]; i++) {
        if (strcasecmp(s, protos[i]) == 0) return 1;
    }
    return 0;
}

/* Check if string looks like an IPv4 address (with optional /CIDR) */
static int looks_like_ipv4(const char *s) {
    int dots = 0, digits = 0;
    for (const char *p = s; *p; p++) {
        if (*p == '.') dots++;
        else if (*p == '/') break;
        else if (isdigit((unsigned char)*p)) digits++;
        else return 0;
    }
    return (dots == 3 && digits >= 4);
}

/* ── CIDR helpers ────────────────────────────────────────────── */

static int parse_cidr(const char *s, uint32_t *net, uint32_t *mask) {
    char buf[64];
    snprintf(buf, sizeof(buf), "%s", s);

    char *slash = strchr(buf, '/');
    int prefix = 32;
    if (slash) {
        *slash = '\0';
        prefix = atoi(slash + 1);
        if (prefix < 0 || prefix > 32) return 0;
    }

    struct in_addr addr;
    if (inet_pton(AF_INET, buf, &addr) != 1) return 0;

    *net  = ntohl(addr.s_addr);
    *mask = (prefix == 0) ? 0 : (~0U << (32 - prefix));
    *net &= *mask;
    return 1;
}

static int ip_matches_cidr(const char *ip_str, uint32_t net, uint32_t mask) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) != 1) return 0;
    uint32_t ip = ntohl(addr.s_addr);
    return (ip & mask) == net;
}

/* ── Port range helper ───────────────────────────────────────── */

static int parse_port_range(const char *s, long *lo, long *hi) {
    char *dash = strchr(s, '-');
    if (!dash) return 0;
    char buf[64];
    snprintf(buf, sizeof(buf), "%s", s);
    dash = strchr(buf, '-');
    *dash = '\0';
    *lo = atol(buf);
    *hi = atol(dash + 1);
    return (*lo > 0 && *hi > 0 && *hi >= *lo);
}

/* ── Tokenizer ───────────────────────────────────────────────── */

typedef enum {
    TOK_FIELD,
    TOK_OP,
    TOK_VALUE,
    TOK_AND,
    TOK_OR,
    TOK_NOT,
    TOK_LPAREN,
    TOK_RPAREN,
    TOK_SHORTHAND,  /* bare protocol name like "tcp" */
    TOK_BARE_IP,    /* bare IP like "10.0.0.1" or "10.0.0.0/24" */
    TOK_PORT_KW,    /* the keyword "port" in "port 443" */
    TOK_EOF,
} token_type_t;

typedef struct {
    token_type_t type;
    char         val[64];
    int          pos;
} token_t;

typedef struct {
    token_t     tokens[FILTER_MAX_TOKENS];
    int         count;
    int         cursor;
} tokenizer_t;

static int is_field(const char *s) {
    static const char *fields[] = {
        "src_ip", "dst_ip", "ip", "src_port", "dst_port", "port",
        "proto", "length", "src_mac", "dst_mac", "vlan", "info",
        "session", "stream", "src", "dst", NULL
    };
    for (int i = 0; fields[i]; i++) {
        if (strcasecmp(s, fields[i]) == 0) return 1;
    }
    return 0;
}

static filter_field_t field_from_str(const char *s) {
    if (strcasecmp(s, "src_ip")   == 0) return FIELD_SRC_IP;
    if (strcasecmp(s, "src")      == 0) return FIELD_SRC_IP;
    if (strcasecmp(s, "dst_ip")   == 0) return FIELD_DST_IP;
    if (strcasecmp(s, "dst")      == 0) return FIELD_DST_IP;
    if (strcasecmp(s, "ip")       == 0) return FIELD_IP;
    if (strcasecmp(s, "src_port") == 0) return FIELD_SRC_PORT;
    if (strcasecmp(s, "dst_port") == 0) return FIELD_DST_PORT;
    if (strcasecmp(s, "port")     == 0) return FIELD_PORT;
    if (strcasecmp(s, "proto")    == 0) return FIELD_PROTO;
    if (strcasecmp(s, "length")   == 0) return FIELD_LENGTH;
    if (strcasecmp(s, "src_mac")  == 0) return FIELD_SRC_MAC;
    if (strcasecmp(s, "dst_mac")  == 0) return FIELD_DST_MAC;
    if (strcasecmp(s, "vlan")     == 0) return FIELD_VLAN;
    if (strcasecmp(s, "info")     == 0) return FIELD_INFO;
    if (strcasecmp(s, "session") == 0) return FIELD_SESSION;
    if (strcasecmp(s, "stream")  == 0) return FIELD_SESSION;
    return FIELD_SRC_IP;
}

static filter_op_t op_from_str(const char *s) {
    if (strcmp(s, "==") == 0)       return OP_EQ;
    if (strcmp(s, "=") == 0)        return OP_EQ;
    if (strcmp(s, "!=") == 0)       return OP_NEQ;
    if (strcmp(s, ">") == 0)        return OP_GT;
    if (strcmp(s, "<") == 0)        return OP_LT;
    if (strcmp(s, ">=") == 0)       return OP_GTE;
    if (strcmp(s, "<=") == 0)       return OP_LTE;
    if (strcasecmp(s, "contains") == 0)  return OP_CONTAINS;
    if (strcasecmp(s, "~") == 0)         return OP_CONTAINS;
    return OP_EQ;
}

static int tokenize(const char *expr, tokenizer_t *t, char *errbuf) {
    t->count  = 0;
    t->cursor = 0;
    const char *p = expr;
    int pos = 0;

    while (*p) {
        while (*p && isspace((unsigned char)*p)) { p++; pos++; }
        if (!*p) break;

        if (t->count >= FILTER_MAX_TOKENS) {
            snprintf(errbuf, 128, "Too many tokens");
            return -1;
        }

        token_t *tok = &t->tokens[t->count];
        tok->pos = pos;

        /* operators */
        if (*p == '(') {
            tok->type = TOK_LPAREN; tok->val[0] = '('; tok->val[1] = '\0'; p++; pos++;
        } else if (*p == ')') {
            tok->type = TOK_RPAREN; tok->val[0] = ')'; tok->val[1] = '\0'; p++; pos++;
        } else if (*p == '=' && *(p+1) == '=') {
            tok->type = TOK_OP; strcpy(tok->val, "=="); p += 2; pos += 2;
        } else if (*p == '=' && *(p+1) != '=') {
            tok->type = TOK_OP; strcpy(tok->val, "="); p++; pos++;
        } else if (*p == '!' && *(p+1) == '=') {
            tok->type = TOK_OP; strcpy(tok->val, "!="); p += 2; pos += 2;
        } else if (*p == '!' && (*(p+1) == ' ' || *(p+1) == '(' || isalpha((unsigned char)*(p+1)))) {
            tok->type = TOK_NOT; strcpy(tok->val, "!"); p++; pos++;
        } else if (*p == '>' && *(p+1) == '=') {
            tok->type = TOK_OP; strcpy(tok->val, ">="); p += 2; pos += 2;
        } else if (*p == '<' && *(p+1) == '=') {
            tok->type = TOK_OP; strcpy(tok->val, "<="); p += 2; pos += 2;
        } else if (*p == '>') {
            tok->type = TOK_OP; strcpy(tok->val, ">"); p++; pos++;
        } else if (*p == '<') {
            tok->type = TOK_OP; strcpy(tok->val, "<"); p++; pos++;
        } else if (*p == '~') {
            tok->type = TOK_OP; strcpy(tok->val, "~"); p++; pos++;
        } else if (*p == '&' && *(p+1) == '&') {
            tok->type = TOK_AND; strcpy(tok->val, "&&"); p += 2; pos += 2;
        } else if (*p == '|' && *(p+1) == '|') {
            tok->type = TOK_OR; strcpy(tok->val, "||"); p += 2; pos += 2;
        } else if (*p == '"') {
            p++; pos++;
            int i = 0;
            while (*p && *p != '"' && i < 62) {
                tok->val[i++] = *p++; pos++;
            }
            tok->val[i] = '\0';
            if (*p == '"') { p++; pos++; }
            tok->type = TOK_VALUE;
        } else if (isalnum((unsigned char)*p) || *p == '_' || *p == '.' || *p == ':') {
            int i = 0;
            while (*p && (isalnum((unsigned char)*p) || *p == '_' ||
                          *p == '.' || *p == ':' || *p == '/') && i < 62) {
                tok->val[i++] = *p++; pos++;
            }
            /* also allow dash for port ranges like 80-443 */
            if (*p == '-' && i > 0 && isdigit((unsigned char)tok->val[0])) {
                tok->val[i++] = *p++; pos++;
                while (*p && isdigit((unsigned char)*p) && i < 62) {
                    tok->val[i++] = *p++; pos++;
                }
            }
            tok->val[i] = '\0';

            if (strcasecmp(tok->val, "and") == 0) {
                tok->type = TOK_AND;
            } else if (strcasecmp(tok->val, "or") == 0) {
                tok->type = TOK_OR;
            } else if (strcasecmp(tok->val, "not") == 0) {
                tok->type = TOK_NOT;
            } else if (strcasecmp(tok->val, "contains") == 0) {
                tok->type = TOK_OP;
            } else if (strcasecmp(tok->val, "port") == 0) {
                tok->type = TOK_PORT_KW;
            } else if (is_field(tok->val)) {
                tok->type = TOK_FIELD;
            } else if (is_proto_shorthand(tok->val)) {
                tok->type = TOK_SHORTHAND;
            } else if (looks_like_ipv4(tok->val)) {
                tok->type = TOK_BARE_IP;
            } else {
                tok->type = TOK_VALUE;
            }
        } else {
            snprintf(errbuf, 128, "Unexpected char '%c' at pos %d", *p, pos);
            return -1;
        }

        t->count++;
    }

    if (t->count < FILTER_MAX_TOKENS) {
        t->tokens[t->count].type = TOK_EOF;
        t->tokens[t->count].val[0] = '\0';
        t->tokens[t->count].pos = pos;
    }

    return 0;
}

/* ── Recursive descent parser ────────────────────────────────── */

typedef struct {
    tokenizer_t       *t;
    display_filter_t  *filt;
    char              *errbuf;
} parser_t;

static token_t *peek(parser_t *p) {
    return &p->t->tokens[p->t->cursor];
}

static token_t *advance(parser_t *p) {
    token_t *tok = &p->t->tokens[p->t->cursor];
    if (tok->type != TOK_EOF) p->t->cursor++;
    return tok;
}

static int alloc_node(parser_t *p) {
    if (p->filt->node_count >= FILTER_MAX_NODES) {
        snprintf(p->errbuf, 128, "Expression too complex (max %d nodes)", FILTER_MAX_NODES);
        return -1;
    }
    return p->filt->node_count++;
}

static void setup_cmp_extras(filter_node_t *n) {
    n->cmp.has_cidr = 0;
    n->cmp.has_range = 0;

    /* detect CIDR: value contains '/' */
    if (strchr(n->cmp.value, '/')) {
        if (parse_cidr(n->cmp.value, &n->cmp.cidr_ip, &n->cmp.cidr_mask))
            n->cmp.has_cidr = 1;
    }

    /* detect port range: value contains '-' and is numeric */
    if (strchr(n->cmp.value, '-') && isdigit((unsigned char)n->cmp.value[0])) {
        if (parse_port_range(n->cmp.value, &n->cmp.range_lo, &n->cmp.range_hi))
            n->cmp.has_range = 1;
    }
}

static int parse_expr(parser_t *p);

static int parse_primary(parser_t *p) {
    token_t *tok = peek(p);

    /* parentheses */
    if (tok->type == TOK_LPAREN) {
        advance(p);
        int node = parse_expr(p);
        if (node < 0) return -1;
        tok = peek(p);
        if (tok->type != TOK_RPAREN) {
            snprintf(p->errbuf, 128, "Expected ')' at pos %d", tok->pos);
            return -1;
        }
        advance(p);
        return node;
    }

    /* NOT */
    if (tok->type == TOK_NOT) {
        advance(p);
        int child = parse_primary(p);
        if (child < 0) return -1;
        int idx = alloc_node(p);
        if (idx < 0) return -1;
        p->filt->nodes[idx].type = NODE_NOT;
        p->filt->nodes[idx].unary.child = child;
        return idx;
    }

    /* bare protocol shorthand: "tcp", "dns", etc. → proto == tcp */
    if (tok->type == TOK_SHORTHAND) {
        token_t *proto_tok = advance(p);
        int idx = alloc_node(p);
        if (idx < 0) return -1;
        p->filt->nodes[idx].type = NODE_CMP;
        p->filt->nodes[idx].cmp.field = FIELD_PROTO;
        p->filt->nodes[idx].cmp.op    = OP_EQ;
        snprintf(p->filt->nodes[idx].cmp.value,
                 sizeof(p->filt->nodes[idx].cmp.value), "%s", proto_tok->val);
        setup_cmp_extras(&p->filt->nodes[idx]);
        return idx;
    }

    /* bare IP: "10.0.0.1" or "10.0.0.0/24" → ip == value */
    if (tok->type == TOK_BARE_IP) {
        token_t *ip_tok = advance(p);
        int idx = alloc_node(p);
        if (idx < 0) return -1;
        p->filt->nodes[idx].type = NODE_CMP;
        p->filt->nodes[idx].cmp.field = FIELD_IP;
        p->filt->nodes[idx].cmp.op    = OP_EQ;
        snprintf(p->filt->nodes[idx].cmp.value,
                 sizeof(p->filt->nodes[idx].cmp.value), "%s", ip_tok->val);
        setup_cmp_extras(&p->filt->nodes[idx]);
        return idx;
    }

    /* "port 443" or "port 80-443" shorthand */
    if (tok->type == TOK_PORT_KW) {
        advance(p);
        token_t *val_tok = peek(p);
        if (val_tok->type != TOK_VALUE && val_tok->type != TOK_BARE_IP) {
            snprintf(p->errbuf, 128, "Expected port number after 'port' at pos %d", val_tok->pos);
            return -1;
        }
        advance(p);
        int idx = alloc_node(p);
        if (idx < 0) return -1;
        p->filt->nodes[idx].type = NODE_CMP;
        p->filt->nodes[idx].cmp.field = FIELD_PORT;
        p->filt->nodes[idx].cmp.op    = OP_EQ;
        snprintf(p->filt->nodes[idx].cmp.value,
                 sizeof(p->filt->nodes[idx].cmp.value), "%s", val_tok->val);
        setup_cmp_extras(&p->filt->nodes[idx]);
        return idx;
    }

    /* field comparison: field op value */
    if (tok->type == TOK_FIELD) {
        token_t *field_tok = advance(p);
        token_t *op_tok = peek(p);
        if (op_tok->type != TOK_OP) {
            snprintf(p->errbuf, 128, "Expected operator after '%s' at pos %d",
                     field_tok->val, op_tok->pos);
            return -1;
        }
        advance(p);
        token_t *val_tok = peek(p);
        if (val_tok->type != TOK_VALUE && val_tok->type != TOK_FIELD &&
            val_tok->type != TOK_BARE_IP && val_tok->type != TOK_SHORTHAND) {
            snprintf(p->errbuf, 128, "Expected value after operator at pos %d", val_tok->pos);
            return -1;
        }
        advance(p);

        int idx = alloc_node(p);
        if (idx < 0) return -1;
        p->filt->nodes[idx].type = NODE_CMP;
        p->filt->nodes[idx].cmp.field = field_from_str(field_tok->val);
        p->filt->nodes[idx].cmp.op    = op_from_str(op_tok->val);
        snprintf(p->filt->nodes[idx].cmp.value,
                 sizeof(p->filt->nodes[idx].cmp.value), "%s", val_tok->val);
        setup_cmp_extras(&p->filt->nodes[idx]);
        return idx;
    }

    snprintf(p->errbuf, 128, "Unexpected '%s' at pos %d. Try: tcp, 10.0.0.1, port 80, src_ip == ...",
             tok->val, tok->pos);
    return -1;
}

static int parse_and(parser_t *p) {
    int left = parse_primary(p);
    if (left < 0) return -1;

    while (peek(p)->type == TOK_AND) {
        advance(p);
        int right = parse_primary(p);
        if (right < 0) return -1;
        int idx = alloc_node(p);
        if (idx < 0) return -1;
        p->filt->nodes[idx].type = NODE_AND;
        p->filt->nodes[idx].binary.left  = left;
        p->filt->nodes[idx].binary.right = right;
        left = idx;
    }
    return left;
}

static int parse_expr(parser_t *p) {
    int left = parse_and(p);
    if (left < 0) return -1;

    while (peek(p)->type == TOK_OR) {
        advance(p);
        int right = parse_and(p);
        if (right < 0) return -1;
        int idx = alloc_node(p);
        if (idx < 0) return -1;
        p->filt->nodes[idx].type = NODE_OR;
        p->filt->nodes[idx].binary.left  = left;
        p->filt->nodes[idx].binary.right = right;
        left = idx;
    }
    return left;
}

/* ── Evaluator ───────────────────────────────────────────────── */

static bool str_contains_ci(const char *haystack, const char *needle) {
    if (!needle[0]) return true;
    size_t nlen = strlen(needle);
    size_t hlen = strlen(haystack);
    if (nlen > hlen) return false;
    for (size_t i = 0; i <= hlen - nlen; i++) {
        if (strncasecmp(haystack + i, needle, nlen) == 0)
            return true;
    }
    return false;
}

static bool cmp_str(const char *a, const char *b, filter_op_t op) {
    if (op == OP_CONTAINS)
        return str_contains_ci(a, b);
    int c = strcasecmp(a, b);
    switch (op) {
        case OP_EQ:  return c == 0;
        case OP_NEQ: return c != 0;
        case OP_GT:  return c > 0;
        case OP_LT:  return c < 0;
        case OP_GTE: return c >= 0;
        case OP_LTE: return c <= 0;
        default:     return false;
    }
}

static bool cmp_int(long a, long b, filter_op_t op) {
    switch (op) {
        case OP_EQ:       return a == b;
        case OP_NEQ:      return a != b;
        case OP_GT:       return a > b;
        case OP_LT:       return a < b;
        case OP_GTE:      return a >= b;
        case OP_LTE:      return a <= b;
        case OP_CONTAINS: return a == b;
    }
    return false;
}

static bool match_proto(const pkt_summary_t *pkt, const char *val) {
    /* match against highest proto, but also match layer names */
    if (strcasecmp(proto_name(pkt->highest_proto), val) == 0) return true;
    if (strcasecmp(proto_name(pkt->l3_proto), val) == 0) return true;
    if (strcasecmp(proto_name(pkt->l4_proto), val) == 0) return true;
    if (strcasecmp(proto_name(pkt->l7_proto), val) == 0) return true;
    /* also match protocol field string */
    if (strcasecmp(pkt->protocol, val) == 0) return true;
    return false;
}

static bool eval_ip_field(const char *ip, const filter_node_t *n) {
    if (n->cmp.has_cidr)
        return ip_matches_cidr(ip, n->cmp.cidr_ip, n->cmp.cidr_mask);
    return cmp_str(ip, n->cmp.value, n->cmp.op);
}

static bool eval_port_field(uint16_t port, const filter_node_t *n) {
    if (n->cmp.has_range)
        return (long)port >= n->cmp.range_lo && (long)port <= n->cmp.range_hi;
    return cmp_int(port, atol(n->cmp.value), n->cmp.op);
}

static bool eval_node(const display_filter_t *filt, int idx,
                      const pkt_summary_t *pkt) {
    if (idx < 0 || idx >= filt->node_count) return false;
    const filter_node_t *n = &filt->nodes[idx];

    switch (n->type) {
        case NODE_AND:
            return eval_node(filt, n->binary.left, pkt) &&
                   eval_node(filt, n->binary.right, pkt);
        case NODE_OR:
            return eval_node(filt, n->binary.left, pkt) ||
                   eval_node(filt, n->binary.right, pkt);
        case NODE_NOT:
            return !eval_node(filt, n->unary.child, pkt);
        case NODE_CMP: {
            switch (n->cmp.field) {
                case FIELD_SRC_IP:
                    return eval_ip_field(pkt->src_ip, n);
                case FIELD_DST_IP:
                    return eval_ip_field(pkt->dst_ip, n);
                case FIELD_IP:
                    return eval_ip_field(pkt->src_ip, n) ||
                           eval_ip_field(pkt->dst_ip, n);
                case FIELD_SRC_PORT:
                    return eval_port_field(pkt->src_port, n);
                case FIELD_DST_PORT:
                    return eval_port_field(pkt->dst_port, n);
                case FIELD_PORT:
                    return eval_port_field(pkt->src_port, n) ||
                           eval_port_field(pkt->dst_port, n);
                case FIELD_PROTO:
                    if (n->cmp.op == OP_EQ)  return match_proto(pkt, n->cmp.value);
                    if (n->cmp.op == OP_NEQ) return !match_proto(pkt, n->cmp.value);
                    return cmp_str(proto_name(pkt->highest_proto), n->cmp.value, n->cmp.op);
                case FIELD_LENGTH:
                    return cmp_int((long)pkt->length, atol(n->cmp.value), n->cmp.op);
                case FIELD_SRC_MAC:
                    return cmp_str(pkt->src_mac, n->cmp.value, n->cmp.op);
                case FIELD_DST_MAC:
                    return cmp_str(pkt->dst_mac, n->cmp.value, n->cmp.op);
                case FIELD_VLAN:
                    return cmp_int(pkt->vlan_id, atol(n->cmp.value), n->cmp.op);
                case FIELD_INFO:
                    return cmp_str(pkt->info, n->cmp.value, n->cmp.op);
                case FIELD_SESSION:
                    return cmp_int((long)pkt->session_id, atol(n->cmp.value), n->cmp.op);
            }
            break;
        }
    }
    return false;
}

/* ── Public API ──────────────────────────────────────────────── */

int filter_compile(const char *expr, display_filter_t *filt) {
    memset(filt, 0, sizeof(*filt));
    snprintf(filt->expr, sizeof(filt->expr), "%s", expr);

    if (!expr || !expr[0]) {
        filt->valid = true;
        filt->root  = -1;
        return 0;
    }

    tokenizer_t t;
    if (tokenize(expr, &t, filt->error) != 0) {
        filt->valid = false;
        return -1;
    }

    parser_t p = { .t = &t, .filt = filt, .errbuf = filt->error };
    int root = parse_expr(&p);
    if (root < 0) {
        filt->valid = false;
        return -1;
    }

    if (peek(&p)->type != TOK_EOF) {
        snprintf(filt->error, sizeof(filt->error),
                 "Unexpected token '%s' at pos %d",
                 peek(&p)->val, peek(&p)->pos);
        filt->valid = false;
        return -1;
    }

    filt->root  = root;
    filt->valid = true;
    return 0;
}

bool filter_eval(const display_filter_t *filt, const pkt_summary_t *pkt) {
    if (!filt || !filt->valid || filt->root < 0) return true;
    return eval_node(filt, filt->root, pkt);
}

const char *filter_error(const display_filter_t *filt) {
    if (!filt) return "";
    return filt->error;
}
