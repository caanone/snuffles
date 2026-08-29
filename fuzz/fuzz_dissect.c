/* libFuzzer harness for the protocol dissectors.
 *
 * Build:
 *   clang -std=c11 -g -O1 -fsanitize=fuzzer,address,undefined \
 *         -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE -Iinclude -Isrc \
 *         fuzz/fuzz_dissect.c src/dissect.c -o fuzz_dissect
 */
#include "dissect.h"
#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 65535) return 0;
    pkt_summary_t out;
    /* the binary summary, then the text columns a consumer would produce */
    dissect_packet(data, (uint32_t)size, 1, &out);     /* Ethernet */
    summary_format(&out);
    dissect_packet(data, (uint32_t)size, 228, &out);   /* raw IPv4 */
    summary_format(&out);
    dissect_packet(data, (uint32_t)size, 229, &out);   /* raw IPv6 */
    summary_format(&out);
    return 0;
}
