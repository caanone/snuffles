#include "syslog_out.h"
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
#else
  #include <unistd.h>
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <netdb.h>
  typedef int sock_t;
  #define SOCK_INVALID (-1)
#endif

#define SYSLOG_DEFAULT_PORT 514

struct syslog_out {
    sock_t              sock;
    struct sockaddr_in  dest;
    char                dest_ip[46];   /* resolved IP string for self-check */
    uint16_t            dest_port;
    uint16_t            src_port;      /* our bound port, for the self-check */
};

/* ── Create: parse host:port, resolve, open UDP socket ───────── */

syslog_out_t *syslog_out_create(const char *host_port, const char *src_iface) {
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

    /* store resolved IP for self-check */
    inet_ntop(AF_INET, &sl->dest.sin_addr, sl->dest_ip, sizeof(sl->dest_ip));

    freeaddrinfo(res);

    /* open UDP socket */
    sl->sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sl->sock == SOCK_INVALID) {
        fprintf(stderr, "syslog: socket() failed\n");
        free(sl);
        return NULL;
    }

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

    fprintf(stderr, "Syslog output: %s:%u (UDP)\n", sl->dest_ip, port);
    return sl;
}

/* ── Self-check: is this packet our own syslog traffic? ──────── */

int syslog_out_is_self(const syslog_out_t *sl, const pkt_summary_t *pkt) {
    if (!sl) return 0;

    /* our own datagrams to the collector */
    if (pkt->l4_proto == PROTO_UDP &&
        pkt->dst_port == sl->dest_port &&
        (sl->src_port == 0 || pkt->src_port == sl->src_port) &&
        strcmp(pkt->dst_ip, sl->dest_ip) == 0) {
        return 1;
    }

    /* replies from the collector back to us */
    if (pkt->l4_proto == PROTO_UDP &&
        pkt->src_port == sl->dest_port &&
        (sl->src_port == 0 || pkt->dst_port == sl->src_port) &&
        strcmp(pkt->src_ip, sl->dest_ip) == 0) {
        return 1;
    }

    /* ICMP errors involving the collector (e.g. port unreachable while it
     * is down): forwarding them would elicit more of them, forever. */
    if ((pkt->l4_proto == PROTO_ICMP4 || pkt->l4_proto == PROTO_ICMP6) &&
        (strcmp(pkt->src_ip, sl->dest_ip) == 0 ||
         strcmp(pkt->dst_ip, sl->dest_ip) == 0)) {
        return 1;
    }

    return 0;
}

/* ── Send: format CSV + sendto ───────────────────────────────── */

void syslog_out_send(syslog_out_t *sl, const pkt_summary_t *pkt) {
    if (!sl || sl->sock == SOCK_INVALID) return;

    /* skip packets without IP info */
    if (!pkt->src_ip[0] || !pkt->dst_ip[0]) return;

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

    char msg[512];
    int len;

    /* always 16 fields:
       src_ip,src_port,dst_ip,dst_port,epoch,length,protocol,
       ttl,ip_id,ip_checksum,frag,flags,seq,ack,window,tcp_checksum
       non-TCP packets have empty values for TCP-specific fields */
    if (pkt->l4_proto == PROTO_TCP) {
        len = snprintf(msg, sizeof(msg),
            "%s,%u,%s,%u,%ld,%u,%s,"
            "%u,%u,0x%04x,0x%04x,%s,%u,%u,%u,0x%04x\n",
            pkt->src_ip, pkt->src_port,
            pkt->dst_ip, pkt->dst_port,
            (long)pkt->ts.tv_sec,
            pkt->length, pkt->protocol,
            pkt->ip_ttl, pkt->ip_id,
            pkt->ip_checksum, pkt->ip_frag_off,
            flags, pkt->tcp_seq, pkt->tcp_ack,
            pkt->tcp_window, pkt->tcp_checksum);
    } else {
        len = snprintf(msg, sizeof(msg),
            "%s,%u,%s,%u,%ld,%u,%s,"
            "%u,%u,0x%04x,0x%04x,,,,,\n",
            pkt->src_ip, pkt->src_port,
            pkt->dst_ip, pkt->dst_port,
            (long)pkt->ts.tv_sec,
            pkt->length, pkt->protocol,
            pkt->ip_ttl, pkt->ip_id,
            pkt->ip_checksum, pkt->ip_frag_off);
    }

    if (len > 0) {
        sendto(sl->sock, msg, (size_t)len, 0,
               (struct sockaddr *)&sl->dest, sizeof(sl->dest));
    }
}

/* ── Destroy ─────────────────────────────────────────────────── */

void syslog_out_destroy(syslog_out_t *sl) {
    if (!sl) return;
    if (sl->sock != SOCK_INVALID) {
#ifdef _WIN32
        closesocket(sl->sock);
#else
        close(sl->sock);
#endif
    }
    free(sl);
}
