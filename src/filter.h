#ifndef FILTER_H
#define FILTER_H

#include "snuffles.h"

#define FILTER_MAX_TOKENS  64
#define FILTER_MAX_NODES   48
#define FILTER_MAX_EXPR    512

typedef enum {
    NODE_CMP,
    NODE_AND,
    NODE_OR,
    NODE_NOT,
} filter_node_type_t;

typedef enum {
    FIELD_SRC_IP,
    FIELD_DST_IP,
    FIELD_IP,           /* matches either src or dst */
    FIELD_SRC_PORT,
    FIELD_DST_PORT,
    FIELD_PORT,         /* matches either src or dst */
    FIELD_PROTO,
    FIELD_LENGTH,
    FIELD_SRC_MAC,
    FIELD_DST_MAC,
    FIELD_VLAN,
    FIELD_INFO,         /* matches against info string */
    FIELD_SESSION,      /* matches session ID */
} filter_field_t;

typedef enum {
    OP_EQ,          /* == */
    OP_NEQ,         /* != */
    OP_GT,          /* >  */
    OP_LT,          /* <  */
    OP_GTE,         /* >= */
    OP_LTE,         /* <= */
    OP_CONTAINS,    /* contains (substring match) */
} filter_op_t;

typedef struct {
    filter_node_type_t type;
    union {
        struct {
            filter_field_t field;
            filter_op_t    op;
            char           value[64];
            uint32_t       cidr_ip;     /* for CIDR: network address */
            uint32_t       cidr_mask;   /* for CIDR: mask */
            int            has_cidr;
            long           range_lo;    /* for port ranges */
            long           range_hi;
            int            has_range;
        } cmp;
        struct { int left; int right; } binary;
        struct { int child; } unary;
    };
} filter_node_t;

typedef struct {
    filter_node_t nodes[FILTER_MAX_NODES];
    int           node_count;
    int           root;
    char          expr[FILTER_MAX_EXPR];
    char          error[128];
    bool          valid;
} display_filter_t;

int   filter_compile(const char *expr, display_filter_t *filt);
bool  filter_eval(const display_filter_t *filt, const pkt_summary_t *pkt);
const char *filter_error(const display_filter_t *filt);

#endif /* FILTER_H */
