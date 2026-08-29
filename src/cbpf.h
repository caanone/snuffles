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
 * or -1 with a message in errbuf. Accepting returns yield 0xFFFFFFFF
 * (whole frame); see cbpf_set_snaplen(). */
int cbpf_compile(const char *expr, cbpf_insn_t *out, int max,
                 char *errbuf, size_t errlen);

/* Rewrites the accepting returns of a compiled program to snaplen, so the
 * kernel copies at most that many bytes of each matching frame into the
 * capture buffer (the in-kernel truncation libpcap's filters do; rejects
 * stay 0). Returns the number of returns rewritten. */
int cbpf_set_snaplen(cbpf_insn_t *insns, int n, uint32_t snaplen);

/* One-instruction program accepting every frame, truncated to snaplen —
 * what an absent -f attaches so snaplen still applies in the kernel.
 * Returns the instruction count (1). */
int cbpf_accept_all(cbpf_insn_t *out, uint32_t snaplen);

#endif /* CBPF_H */
