/* libFuzzer harness for the display-filter compiler and evaluator.
 *
 * Build:
 *   clang -std=c11 -g -O1 -fsanitize=fuzzer,address,undefined \
 *         -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE -Iinclude -Isrc \
 *         fuzz/fuzz_filter.c src/filter.c src/dissect.c -o fuzz_filter
 */
#include "filter.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > 512) return 0;

    char expr[513];
    memcpy(expr, data, size);
    expr[size] = '\0';

    display_filter_t f;
    if (filter_compile(expr, &f) == 0) {
        pkt_summary_t p;
        memset(&p, 0, sizeof(p));
        strcpy(p.src_ip, "10.0.0.1");
        strcpy(p.dst_ip, "8.8.8.8");
        p.src_port = 1234;
        p.dst_port = 443;
        p.l4_proto = PROTO_TCP;
        p.vlan_id  = 5;
        strcpy(p.protocol, "TCP");
        strcpy(p.info, "1234 -> 443 [S]");
        filter_eval(&f, &p);
    }
    return 0;
}
