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
    dissect_packet(data, (uint32_t)size, 1, &out);     /* Ethernet */
    dissect_packet(data, (uint32_t)size, 228, &out);   /* raw IPv4 */
    dissect_packet(data, (uint32_t)size, 229, &out);   /* raw IPv6 */
    return 0;
}
