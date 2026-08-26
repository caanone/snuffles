#ifndef CBPF_H
#define CBPF_H

#include <stdint.h>
#include <stddef.h>

/* Classic-BPF compiler for the raw-socket backend: makes -f work without
 * libpcap by compiling a useful subset of tcpdump filter syntax to cBPF
 * for SO_ATTACH_FILTER (Linux, DLT_EN10MB framing).
 *
 * Supported grammar (conjunctions only; "and" may be implicit):
 *   tcp | udp | icmp | ip | arp
 *   [src|dst] host <ipv4>
 *   [src|dst] port <1-65535>
 * Examples: "tcp port 443", "udp and host 8.8.8.8", "src port 53"
 * Port matching implies IPv4 TCP/UDP/SCTP and excludes non-first fragments.
 */

#define CBPF_MAX_INSNS 64

typedef struct {
    uint16_t code;
    uint8_t  jt, jf;
    uint32_t k;
} cbpf_insn_t;   /* layout-compatible with struct sock_filter */

/* Compiles expr into out (capacity max). Returns the instruction count,
 * or -1 with a message in errbuf. */
int cbpf_compile(const char *expr, cbpf_insn_t *out, int max,
                 char *errbuf, size_t errlen);

#endif /* CBPF_H */
