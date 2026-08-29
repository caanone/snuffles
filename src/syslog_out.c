#ifdef __linux__
  #define _GNU_SOURCE   /* sendmmsg(), struct mmsghdr */
#endif
#include "syslog_out.h"
#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
  typedef SOCKET sock_t;
  #define SOCK_INVALID INVALID_SOCKET
  #define SEND_FLAGS 0          /* socket is switched to FIONBIO instead */
#else
  #include <unistd.h>
  #include <sys/socket.h>
  #include <sys/uio.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <netdb.h>
  typedef int sock_t;
  #define SOCK_INVALID (-1)
  #define SEND_FLAGS MSG_DONTWAIT
#endif

#define SYSLOG_DEFAULT_PORT 514
#define SYSLOG_MSG_MAX      512                 /* one formatted CSV record */
#define SYSLOG_SNDBUF       (16 * 1024 * 1024)  /* kernel send queue, bytes */

#ifdef _WIN32
/* socket()/getaddrinfo() fail with WSANOTINITIALISED unless Winsock is
 * started; the pcap backend initializes it as a side effect, the raw
 * build must not rely on that. Called once, never torn down: Windows
 * cleans up at process exit. */
static void ensure_wsa(void) {
    static int done = 0;
    if (!done) {
        WSADATA wsa;
        (void)WSAStartup(MAKEWORD(2, 2), &wsa);
        done = 1;
    }
}
#endif

struct syslog_out {
    int                  connected;   /* connect() succeeded: send without an address */
    sock_t              sock;
    struct sockaddr_in  dest;
    char                dest_ip[46];   /* resolved IP string (banner) */
    uint8_t             dest_addr[4];  /* same, binary, for the self-check */
    uint16_t            dest_port;
    uint16_t            src_port;      /* our bound port, for the self-check */
    atomic_uint_fast64_t sent;
    atomic_uint_fast64_t failed;

    /* Outgoing batch, owned by the output thread. Records are formatted
     * straight into msgs[] and leave in one sendmmsg() (Linux) when the
     * batch is full or the output thread flushes on idle. */
    unsigned            nbatch;
    int                 lens[SYSLOG_BATCH];
    char                msgs[SYSLOG_BATCH][SYSLOG_MSG_MAX];
#ifdef __linux__
    struct iovec        iov[SYSLOG_BATCH];
    struct mmsghdr      mm[SYSLOG_BATCH];
#endif
};

/* ── Send buffer: 16 MB so a slow collector or NIC backpressure is absorbed
 *    in the kernel instead of stalling the capture thread ────────────── */

static void set_sndbuf(syslog_out_t *sl) {
    int want = SYSLOG_SNDBUF;
    int done = 0;
#if defined(__linux__) && defined(SO_SNDBUFFORCE)
    /* Ignores net.core.wmem_max; needs CAP_NET_ADMIN, which is why the
     * socket is opened before privileges are dropped. */
    if (setsockopt(sl->sock, SOL_SOCKET, SO_SNDBUFFORCE,
                   &want, sizeof(want)) == 0)
        done = 1;
#endif
    /* Plain SO_SNDBUF is clipped to wmem_max (Linux) or rejected outright
     * when above the platform ceiling (macOS): halve until it sticks. */
    for (int v = want; !done && v >= 256 * 1024; v /= 2) {
        if (setsockopt(sl->sock, SOL_SOCKET, SO_SNDBUF,
                       (const char *)&v, sizeof(v)) == 0)
            done = 1;
    }

    int got = 0;
    socklen_t gl = sizeof(got);
    if (getsockopt(sl->sock, SOL_SOCKET, SO_SNDBUF, (char *)&got, &gl) != 0)
        got = 0;
    /* Linux reports twice the requested value (bookkeeping overhead);
     * anything below the request means the kernel clipped it. */
    if (got < want)
        fprintf(stderr, "syslog: send buffer limited to %d KB by the "
                        "kernel (wanted %d KB"
#ifdef __linux__
                        "; raise net.core.wmem_max or run with CAP_NET_ADMIN"
#endif
                        ")\n",
                got / 1024, want / 1024);
}

/* ── Create: parse host:port, resolve, open UDP socket ───────── */

syslog_out_t *syslog_out_create(const char *host_port, const char *src_iface) {
#ifdef _WIN32
    ensure_wsa();
#endif
    if (!host_port || !host_port[0]) return NULL;

    syslog_out_t *sl = calloc(1, sizeof(syslog_out_t));
    if (!sl) return NULL;

    /* parse host:port */
    char buf[256];
    snprintf(buf, sizeof(buf), "%s", host_port);

    uint16_t port = SYSLOG_DEFAULT_PORT;
    char *colon = strrchr(buf, ':');
    if (colon && strchr(buf, ':') != colon) {
        fprintf(stderr, "syslog: IPv6 targets are not supported "
                        "(use an IPv4 address or hostname)\n");
        free(sl);
        return NULL;
    }
    if (colon) {
        *colon = '\0';
        char *end;
        long p = strtol(colon + 1, &end, 10);
        if (end == colon + 1 || *end != '\0' || p < 1 || p > 65535) {
            fprintf(stderr, "syslog: invalid port '%s'\n", colon + 1);
            free(sl);
            return NULL;
        }
        port = (uint16_t)p;
    }

    /* resolve hostname */
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    if (getaddrinfo(buf, NULL, &hints, &res) != 0 || !res) {
        fprintf(stderr, "syslog: cannot resolve '%s'\n", buf);
        free(sl);
        return NULL;
    }

    memcpy(&sl->dest, res->ai_addr, sizeof(sl->dest));
    sl->dest.sin_port = htons(port);
    sl->dest_port = port;

    /* store resolved IP for the banner and the self-check */
    inet_ntop(AF_INET, &sl->dest.sin_addr, sl->dest_ip, sizeof(sl->dest_ip));
    memcpy(sl->dest_addr, &sl->dest.sin_addr, 4);

    freeaddrinfo(res);

    /* open UDP socket */
    sl->sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sl->sock == SOCK_INVALID) {
        fprintf(stderr, "syslog: socket() failed\n");
        free(sl);
        return NULL;
    }

    set_sndbuf(sl);
#ifdef _WIN32
    /* No MSG_DONTWAIT on Winsock: make the socket itself non-blocking. */
    u_long nb = 1;
    (void)ioctlsocket(sl->sock, FIONBIO, &nb);
#endif

    /* bind to source interface/IP if specified */
    if (src_iface && src_iface[0]) {
        struct sockaddr_in src_addr;
        memset(&src_addr, 0, sizeof(src_addr));
        src_addr.sin_family = AF_INET;

        /* try as IP address first */
        if (inet_pton(AF_INET, src_iface, &src_addr.sin_addr) == 1) {
            if (bind(sl->sock, (struct sockaddr *)&src_addr, sizeof(src_addr)) != 0)
                fprintf(stderr, "syslog: warning: bind to %s failed\n", src_iface);
            else
                fprintf(stderr, "Syslog source: %s\n", src_iface);
        }
#if !defined(_WIN32) && defined(SO_BINDTODEVICE)
        /* try as interface name (Linux only) */
        else {
            if (setsockopt(sl->sock, SOL_SOCKET, SO_BINDTODEVICE,
                           src_iface, (socklen_t)strlen(src_iface)) != 0)
                fprintf(stderr, "syslog: warning: bind to device %s failed\n", src_iface);
            else
                fprintf(stderr, "Syslog source device: %s\n", src_iface);
        }
#endif
    }

    /* Learn our own source port so the self-check can match precisely
     * instead of swallowing all third-party traffic on the syslog port. */
    struct sockaddr_in local;
    socklen_t llen = sizeof(local);
    memset(&local, 0, sizeof(local));
    if (getsockname(sl->sock, (struct sockaddr *)&local, &llen) != 0 ||
        local.sin_port == 0) {
        memset(&local, 0, sizeof(local));
        local.sin_family      = AF_INET;
        local.sin_addr.s_addr = htonl(INADDR_ANY);
        local.sin_port        = 0;
        (void)bind(sl->sock, (struct sockaddr *)&local, sizeof(local));
        llen = sizeof(local);
        (void)getsockname(sl->sock, (struct sockaddr *)&local, &llen);
    }
    sl->src_port = ntohs(local.sin_port);

    /* Connect the UDP socket: an unconnected sendto() does a full route
     * lookup (fib_table_lookup / ip_route_output) per datagram, which the
     * load-test profile showed dominating the syslog path. A connected
     * socket caches the route; send() / sendmmsg() with a NULL address
     * then skip it. */
    sl->connected = (connect(sl->sock, (struct sockaddr *)&sl->dest,
                             sizeof(sl->dest)) == 0);

#ifdef __linux__
    /* Fixed parts of the sendmmsg() vector; only iov_len varies per flush. */
    for (unsigned i = 0; i < SYSLOG_BATCH; i++) {
        sl->iov[i].iov_base           = sl->msgs[i];
        sl->mm[i].msg_hdr.msg_name    = sl->connected ? NULL : (void *)&sl->dest;
        sl->mm[i].msg_hdr.msg_namelen = sl->connected ? 0 : sizeof(sl->dest);
        sl->mm[i].msg_hdr.msg_iov     = &sl->iov[i];
        sl->mm[i].msg_hdr.msg_iovlen  = 1;
    }
#endif

    fprintf(stderr, "Syslog output: %s:%u (UDP)\n", sl->dest_ip, port);
    return sl;
}

/* ── Self-check: is this packet our own syslog traffic? ──────── */

int syslog_out_is_self(const syslog_out_t *sl, const pkt_summary_t *pkt) {
    if (!sl) return 0;
    /* the collector is IPv4: compare the binary address pair (the text
     * columns are not produced on the capture thread) */
    if (pkt->addr_family != 4) return 0;
    int to_dest   = memcmp(pkt->dst_addr, sl->dest_addr, 4) == 0;
    int from_dest = memcmp(pkt->src_addr, sl->dest_addr, 4) == 0;

    /* our own datagrams to the collector */
    if (pkt->l4_proto == PROTO_UDP && to_dest &&
        pkt->dst_port == sl->dest_port &&
        (sl->src_port == 0 || pkt->src_port == sl->src_port)) {
        return 1;
    }

    /* replies from the collector back to us */
    if (pkt->l4_proto == PROTO_UDP && from_dest &&
        pkt->src_port == sl->dest_port &&
        (sl->src_port == 0 || pkt->dst_port == sl->src_port)) {
        return 1;
    }

    /* ICMP errors involving the collector (e.g. port unreachable while it
     * is down): forwarding them would elicit more of them, forever. */
    if ((pkt->l4_proto == PROTO_ICMP4 || pkt->l4_proto == PROTO_ICMP6) &&
        (from_dest || to_dest)) {
        return 1;
    }

    return 0;
}

/* ── Send: format CSV into the batch ─────────────────────────── */

void syslog_out_send(syslog_out_t *sl, const pkt_summary_t *pkt) {
    if (!sl || sl->sock == SOCK_INVALID) return;

    /* skip packets without IP info */
    if (!pkt->addr_family) return;

    /* Address and protocol text from the binary summary: this runs on the
     * capture thread, so only what the record needs is produced (never the
     * info line). ns_ip_str writes IPv4 by hand; IPv6 goes through
     * inet_ntop. A hand-built summary with the label unset keeps its
     * protocol string. */
    char src_ip[46], dst_ip[46];
    ns_ip_str(pkt->addr_family, pkt->src_addr, src_ip, sizeof(src_ip));
    ns_ip_str(pkt->addr_family, pkt->dst_addr, dst_ip, sizeof(dst_ip));
    const char *protocol = pkt->proto_label ? proto_label_str(pkt->proto_label)
                                            : pkt->protocol;

    /* format TCP flags string */
    char flags[16] = "-";
    if (pkt->l4_proto == PROTO_TCP) {
        int fp = 0;
        if (pkt->tcp_flags & 0x02) flags[fp++] = 'S';
        if (pkt->tcp_flags & 0x10) flags[fp++] = 'A';
        if (pkt->tcp_flags & 0x01) flags[fp++] = 'F';
        if (pkt->tcp_flags & 0x04) flags[fp++] = 'R';
        if (pkt->tcp_flags & 0x08) flags[fp++] = 'P';
        if (pkt->tcp_flags & 0x20) flags[fp++] = 'U';
        if (fp == 0) flags[fp++] = '-';
        flags[fp] = '\0';
    }

    char *msg = sl->msgs[sl->nbatch];
    int len;

    /* always 16 fields:
       src_ip,src_port,dst_ip,dst_port,epoch,length,protocol,
       ttl,ip_id,ip_checksum,frag,flags,seq,ack,window,tcp_checksum
       non-TCP packets have empty values for TCP-specific fields */
    if (pkt->l4_proto == PROTO_TCP) {
        len = snprintf(msg, SYSLOG_MSG_MAX,
            "%s,%u,%s,%u,%ld,%u,%s,"
            "%u,%u,0x%04x,0x%04x,%s,%u,%u,%u,0x%04x\n",
            src_ip, pkt->src_port,
            dst_ip, pkt->dst_port,
            (long)pkt->ts.tv_sec,
            pkt->length, protocol,
            pkt->ip_ttl, pkt->ip_id,
            pkt->ip_checksum, pkt->ip_frag_off,
            flags, pkt->tcp_seq, pkt->tcp_ack,
            pkt->tcp_window, pkt->tcp_checksum);
    } else {
        len = snprintf(msg, SYSLOG_MSG_MAX,
            "%s,%u,%s,%u,%ld,%u,%s,"
            "%u,%u,0x%04x,0x%04x,,,,,\n",
            src_ip, pkt->src_port,
            dst_ip, pkt->dst_port,
            (long)pkt->ts.tv_sec,
            pkt->length, protocol,
            pkt->ip_ttl, pkt->ip_id,
            pkt->ip_checksum, pkt->ip_frag_off);
    }

    if (len <= 0) return;
    if (len >= SYSLOG_MSG_MAX) len = SYSLOG_MSG_MAX - 1;  /* cannot happen: bounded fields */
    sl->lens[sl->nbatch++] = len;

    if (sl->nbatch == SYSLOG_BATCH)
        syslog_out_flush(sl);
}

/* ── Flush: hand the batch to the kernel without ever blocking ── */

void syslog_out_flush(syslog_out_t *sl) {
    if (!sl || sl->nbatch == 0) return;
    unsigned n = sl->nbatch;
    sl->nbatch = 0;

#ifdef __linux__
    for (unsigned i = 0; i < n; i++)
        sl->iov[i].iov_len = (size_t)sl->lens[i];

    unsigned off = 0;
    while (off < n) {
        int r = sendmmsg(sl->sock, sl->mm + off, n - off, MSG_DONTWAIT);
        if (r > 0) {
            atomic_fetch_add_explicit(&sl->sent, (uint64_t)r, memory_order_relaxed);
            off += (unsigned)r;
            continue;   /* short count: the message at 'off' failed; retry
                           from there (a persisting error ends the batch
                           below, so this loop is bounded by n) */
        }
        if (r < 0 && errno == EINTR) continue;
        /* EAGAIN/ENOBUFS (send queue full) or a hard error: drop the rest
         * of the batch rather than wait for room: a stalled output thread
         * would only be lapped by the ring (out_missed) instead. */
        atomic_fetch_add_explicit(&sl->failed, (uint64_t)(n - off), memory_order_relaxed);
        break;
    }
#else
    for (unsigned i = 0; i < n; i++) {
        if (sendto(sl->sock, sl->msgs[i], (size_t)sl->lens[i], SEND_FLAGS,
                   sl->connected ? NULL : (struct sockaddr *)&sl->dest,
                   sl->connected ? 0 : (socklen_t)sizeof(sl->dest)) < 0)
            atomic_fetch_add_explicit(&sl->failed, 1, memory_order_relaxed);
        else
            atomic_fetch_add_explicit(&sl->sent, 1, memory_order_relaxed);
    }
#endif
}

unsigned syslog_out_pending(const syslog_out_t *sl) {
    return sl ? sl->nbatch : 0;
}

void syslog_out_counts(const syslog_out_t *sl, uint64_t *sent, uint64_t *failed) {
    *sent = *failed = 0;
    if (!sl) return;
    *sent   = atomic_load_explicit(&sl->sent,   memory_order_relaxed);
    *failed = atomic_load_explicit(&sl->failed, memory_order_relaxed);
}

/* ── Destroy ─────────────────────────────────────────────────── */

void syslog_out_destroy(syslog_out_t *sl) {
    if (!sl) return;
    syslog_out_flush(sl);   /* output thread is joined by now: nothing races */
    if (sl->sock != SOCK_INVALID) {
#ifdef _WIN32
        closesocket(sl->sock);
#else
        close(sl->sock);
#endif
    }
    free(sl);
}
