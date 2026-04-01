#include "dissect.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #include <arpa/inet.h>
#endif

/* ── Ethernet constants ──────────────────────────────────────── */

#define ETH_HLEN       14
#define ETH_P_IP       0x0800
#define ETH_P_ARP      0x0806
#define ETH_P_8021Q    0x8100
#define ETH_P_IPV6     0x86DD

/* ── TCP flag bits ───────────────────────────────────────────── */

#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20

/* ── Portable header structs (no alignment assumptions) ──────── */

static inline uint16_t rd16(const uint8_t *p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}
static inline uint32_t rd32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
}

/* ── Helpers ─────────────────────────────────────────────────── */

void format_mac(const uint8_t *mac, char *buf, size_t len) {
    snprintf(buf, len, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void format_ipv4(const uint8_t *ip, char *buf, size_t len) {
    snprintf(buf, len, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
}

static void format_ipv6(const uint8_t *ip, char *buf, size_t len) {
    struct in6_addr addr;
    memcpy(&addr, ip, 16);
    inet_ntop(AF_INET6, &addr, buf, (socklen_t)len);
}

static void format_tcp_flags(uint8_t flags, char *buf, size_t len) {
    snprintf(buf, len, "[%s%s%s%s%s%s]",
             (flags & TH_SYN)  ? "S" : "",
             (flags & TH_ACK)  ? "A" : "",
             (flags & TH_FIN)  ? "F" : "",
             (flags & TH_RST)  ? "R" : "",
             (flags & TH_PUSH) ? "P" : "",
             (flags & TH_URG)  ? "U" : "");
}

void format_hex_dump(const uint8_t *data, uint32_t len,
                     char *buf, size_t bufsize) {
    size_t pos = 0;
    for (uint32_t off = 0; off < len && pos + 80 < bufsize; off += 16) {
        pos += (size_t)snprintf(buf + pos, bufsize - pos, "%04x: ", off);
        for (int j = 0; j < 16; j++) {
            if (off + j < len)
                pos += (size_t)snprintf(buf + pos, bufsize - pos, "%02x ", data[off + j]);
            else
                pos += (size_t)snprintf(buf + pos, bufsize - pos, "   ");
            if (j == 7) buf[pos++] = ' ';
        }
        pos += (size_t)snprintf(buf + pos, bufsize - pos, " |");
        for (int j = 0; j < 16 && (off + j) < len; j++) {
            uint8_t c = data[off + j];
            buf[pos++] = (c >= 0x20 && c < 0x7f) ? (char)c : '.';
        }
        pos += (size_t)snprintf(buf + pos, bufsize - pos, "|\n");
    }
    if (pos < bufsize) buf[pos] = '\0';
}

/* ── Layer 7 dissectors ──────────────────────────────────────── */

static void dissect_dns(const uint8_t *data, uint32_t len, pkt_summary_t *out) {
    if (len < 12) return;
    out->l7_proto = PROTO_DNS;
    out->highest_proto = PROTO_DNS;

    uint16_t flags = rd16(data + 2);
    int is_response = (flags >> 15) & 1;
    uint16_t qdcount = rd16(data + 4);

    char name[128];
    size_t npos = 0;
    uint32_t offset = 12;

    if (qdcount > 0) {
        int labels = 0;
        while (offset < len && data[offset] != 0 && labels < 128) {
            uint8_t llen = data[offset++];
            if ((llen & 0xC0) == 0xC0) break;  /* compression pointer */
            if (llen > 63) break;               /* RFC max label = 63 */
            if (offset + llen > len) break;     /* bounds check */
            if (npos > 0 && npos < sizeof(name) - 1)
                name[npos++] = '.';
            for (uint8_t i = 0; i < llen && npos < sizeof(name) - 1; i++)
                name[npos++] = (char)data[offset++];
            labels++;
        }
    }
    name[npos] = '\0';

    const char *qr = is_response ? "R" : "Q";
    /* extract qtype if present */
    const char *qtype = "";
    if (offset + 1 < len) {
        offset++; /* skip null terminator */
        if (offset + 2 <= len) {
            uint16_t qt = rd16(data + offset);
            switch (qt) {
                case 1:   qtype = "A";     break;
                case 28:  qtype = "AAAA";  break;
                case 5:   qtype = "CNAME"; break;
                case 15:  qtype = "MX";    break;
                case 2:   qtype = "NS";    break;
                case 12:  qtype = "PTR";   break;
                case 6:   qtype = "SOA";   break;
                case 16:  qtype = "TXT";   break;
                case 33:  qtype = "SRV";   break;
                default:  qtype = "";      break;
            }
        }
    }

    snprintf(out->info, sizeof(out->info), "DNS %s %s %s", qr, qtype, name);
    snprintf(out->protocol, sizeof(out->protocol), "DNS");
}

static void dissect_http(const uint8_t *data, uint32_t len, pkt_summary_t *out) {
    if (len < 4) return;

    /* check for request methods or response */
    const char *methods[] = { "GET ", "POST ", "PUT ", "DELETE ", "HEAD ",
                              "OPTIONS ", "PATCH ", "CONNECT " };
    for (int i = 0; i < 8; i++) {
        size_t mlen = strlen(methods[i]);
        if (len >= mlen && memcmp(data, methods[i], mlen) == 0) {
            out->l7_proto = PROTO_HTTP;
            out->highest_proto = PROTO_HTTP;
            /* extract method + path (first line) */
            size_t end = mlen;
            while (end < len && end < 120 && data[end] != '\r' && data[end] != '\n')
                end++;
            snprintf(out->info, sizeof(out->info), "HTTP %.*s", (int)(end), (const char *)data);
            snprintf(out->protocol, sizeof(out->protocol), "HTTP");
            return;
        }
    }

    if (len >= 9 && memcmp(data, "HTTP/1.", 7) == 0) {
        out->l7_proto = PROTO_HTTP;
        out->highest_proto = PROTO_HTTP;
        size_t end = 0;
        while (end < len && end < 120 && data[end] != '\r' && data[end] != '\n')
            end++;
        snprintf(out->info, sizeof(out->info), "%.*s", (int)end, (const char *)data);
        snprintf(out->protocol, sizeof(out->protocol), "HTTP");
    }
}

static void dissect_tls(const uint8_t *data, uint32_t len, pkt_summary_t *out) {
    /* TLS record: type(1) version(2) length(2) */
    if (len < 5) return;
    if (data[0] != 0x16) return;        /* not handshake */
    if (data[1] != 0x03) return;        /* not TLS */
    if (len < 6) return;

    uint8_t hs_type = data[5];
    out->l7_proto = PROTO_TLS;
    out->highest_proto = PROTO_TLS;

    if (hs_type == 0x01) {
        /* ClientHello — try to extract SNI */
        snprintf(out->protocol, sizeof(out->protocol), "TLS");
        /* ClientHello: skip handshake header (4) + version(2) + random(32) */
        uint32_t off = 5 + 4 + 2 + 32;
        if (off + 1 >= len) goto tls_done;

        /* session ID length */
        uint8_t sid_len = data[off++];
        off += sid_len;
        if (off + 2 > len) goto tls_done;

        /* cipher suites length */
        uint16_t cs_len = rd16(data + off); off += 2;
        off += cs_len;
        if (off + 1 > len) goto tls_done;

        /* compression methods length */
        uint8_t cm_len = data[off++];
        off += cm_len;
        if (off + 2 > len) goto tls_done;

        /* extensions length */
        uint16_t ext_total = rd16(data + off); off += 2;
        uint32_t ext_end = off + ext_total;
        if (ext_end > len) ext_end = len;

        while (off + 4 <= ext_end) {
            uint16_t ext_type = rd16(data + off); off += 2;
            uint16_t ext_len  = rd16(data + off); off += 2;
            if (off + ext_len > ext_end) break;

            if (ext_type == 0x0000 && ext_len >= 5) {
                /* SNI extension */
                uint32_t sni_off = off + 2; /* skip SNI list length */
                if (sni_off + 3 > off + ext_len) break;
                /* uint8_t sni_type = data[sni_off]; */
                sni_off++;
                uint16_t name_len = rd16(data + sni_off); sni_off += 2;
                if (sni_off + name_len <= off + ext_len && name_len > 0 && name_len < 254) {
                    char sni[256];
                    memcpy(sni, data + sni_off, name_len);
                    sni[name_len] = '\0';
                    snprintf(out->info, sizeof(out->info),
                             "TLS ClientHello SNI=%s", sni);
                    return;
                }
            }
            off += ext_len;
        }

tls_done:
        snprintf(out->info, sizeof(out->info), "TLS ClientHello");
    } else if (hs_type == 0x02) {
        snprintf(out->protocol, sizeof(out->protocol), "TLS");
        snprintf(out->info, sizeof(out->info), "TLS ServerHello");
    } else {
        snprintf(out->protocol, sizeof(out->protocol), "TLS");
        const char *desc = "Handshake";
        switch (hs_type) {
            case 0x0b: desc = "Certificate";      break;
            case 0x0c: desc = "ServerKeyExchange"; break;
            case 0x0e: desc = "ServerHelloDone";   break;
            case 0x10: desc = "ClientKeyExchange";  break;
            case 0x14: desc = "Finished";          break;
        }
        snprintf(out->info, sizeof(out->info), "TLS %s", desc);
    }
}

/* ── Layer 4 dissectors ──────────────────────────────────────── */

static int dissect_tcp(const uint8_t *data, uint32_t len, pkt_summary_t *out) {
    if (len < 20) return -1;

    out->src_port  = rd16(data);
    out->dst_port  = rd16(data + 2);
    uint32_t seq   = rd32(data + 4);
    uint32_t ack   = rd32(data + 8);
    uint8_t  doff  = (data[12] >> 4) * 4;
    if (doff < 20 || doff > len) return -1;  /* validate data offset */
    uint8_t  flags = data[13];
    uint16_t win   = rd16(data + 14);

    out->tcp_flags    = flags;
    out->tcp_seq      = seq;
    out->tcp_ack      = ack;
    out->tcp_window   = win;
    out->tcp_checksum = rd16(data + 16);
    out->l4_proto     = PROTO_TCP;
    out->highest_proto = PROTO_TCP;
    snprintf(out->protocol, sizeof(out->protocol), "TCP");

    char flagstr[16];
    format_tcp_flags(flags, flagstr, sizeof(flagstr));
    snprintf(out->info, sizeof(out->info),
             "%u \xe2\x86\x92 %u %s Seq=%u Ack=%u Win=%u",
             out->src_port, out->dst_port, flagstr, seq, ack, win);

    /* try L7 if there's payload */
    if (doff < len) {
        const uint8_t *payload = data + doff;
        uint32_t plen = len - doff;

        if (out->src_port == 53 || out->dst_port == 53) {
            /* DNS over TCP (skip 2-byte length) */
            if (plen > 2) dissect_dns(payload + 2, plen - 2, out);
        } else if (out->src_port == 80 || out->dst_port == 80 ||
                   out->src_port == 8080 || out->dst_port == 8080) {
            dissect_http(payload, plen, out);
        } else if (out->src_port == 443 || out->dst_port == 443 ||
                   out->src_port == 8443 || out->dst_port == 8443) {
            dissect_tls(payload, plen, out);
        } else {
            /* generic TLS detection */
            dissect_tls(payload, plen, out);
            if (out->l7_proto == PROTO_UNKNOWN) {
                dissect_http(payload, plen, out);
            }
        }
    }

    return 0;
}

static int dissect_udp(const uint8_t *data, uint32_t len, pkt_summary_t *out) {
    if (len < 8) return -1;

    out->src_port = rd16(data);
    out->dst_port = rd16(data + 2);
    uint16_t ulen = rd16(data + 4);

    out->l4_proto    = PROTO_UDP;
    out->highest_proto = PROTO_UDP;
    snprintf(out->protocol, sizeof(out->protocol), "UDP");
    snprintf(out->info, sizeof(out->info),
             "%u \xe2\x86\x92 %u Len=%u", out->src_port, out->dst_port, ulen);

    /* try L7 */
    if (len > 8) {
        const uint8_t *payload = data + 8;
        uint32_t plen = len - 8;

        if (out->src_port == 53 || out->dst_port == 53) {
            dissect_dns(payload, plen, out);
        }
    }

    return 0;
}

static int dissect_sctp(const uint8_t *data, uint32_t len, pkt_summary_t *out) {
    if (len < 12) return -1;

    out->src_port = rd16(data);
    out->dst_port = rd16(data + 2);

    out->l4_proto    = PROTO_SCTP;
    out->highest_proto = PROTO_SCTP;
    snprintf(out->protocol, sizeof(out->protocol), "SCTP");
    snprintf(out->info, sizeof(out->info),
             "%u \xe2\x86\x92 %u", out->src_port, out->dst_port);
    return 0;
}

/* ── Layer 3 dissectors ──────────────────────────────────────── */

static int dissect_icmpv4(const uint8_t *data, uint32_t len, pkt_summary_t *out) {
    if (len < 4) return -1;

    uint8_t type = data[0];
    uint8_t code = data[1];

    out->l4_proto    = PROTO_ICMP4;
    out->highest_proto = PROTO_ICMP4;
    snprintf(out->protocol, sizeof(out->protocol), "ICMP");

    const char *desc = "Other";
    switch (type) {
        case 0:  desc = "Echo Reply";              break;
        case 3:  desc = "Destination Unreachable";  break;
        case 5:  desc = "Redirect";                break;
        case 8:  desc = "Echo Request";            break;
        case 11: desc = "Time Exceeded";           break;
    }

    if ((type == 0 || type == 8) && len >= 8) {
        uint16_t id  = rd16(data + 4);
        uint16_t seq = rd16(data + 6);
        snprintf(out->info, sizeof(out->info),
                 "%s id=%u seq=%u", desc, id, seq);
    } else {
        snprintf(out->info, sizeof(out->info),
                 "%s (type=%u code=%u)", desc, type, code);
    }
    return 0;
}

static int dissect_icmpv6(const uint8_t *data, uint32_t len, pkt_summary_t *out) {
    if (len < 4) return -1;

    uint8_t type = data[0];
    uint8_t code = data[1];

    out->l4_proto    = PROTO_ICMP6;
    out->highest_proto = PROTO_ICMP6;
    snprintf(out->protocol, sizeof(out->protocol), "ICMPv6");

    const char *desc = "Other";
    switch (type) {
        case 1:   desc = "Destination Unreachable"; break;
        case 2:   desc = "Packet Too Big";          break;
        case 3:   desc = "Time Exceeded";           break;
        case 128: desc = "Echo Request";            break;
        case 129: desc = "Echo Reply";              break;
        case 133: desc = "Router Solicitation";     break;
        case 134: desc = "Router Advertisement";    break;
        case 135: desc = "Neighbor Solicitation";   break;
        case 136: desc = "Neighbor Advertisement";  break;
    }

    snprintf(out->info, sizeof(out->info),
             "%s (type=%u code=%u)", desc, type, code);
    return 0;
}

static int dissect_ipv4(const uint8_t *data, uint32_t len, pkt_summary_t *out) {
    if (len < 20) return -1;

    uint8_t  ihl    = (data[0] & 0x0F) * 4;
    if (ihl < 20 || ihl > len) return -1;   /* validate IHL */
    uint8_t  ttl    = data[8];
    uint8_t  proto  = data[9];

    out->ip_ttl      = ttl;
    out->ip_proto    = proto;
    out->ip_id       = rd16(data + 4);
    out->ip_frag_off = rd16(data + 6);
    out->ip_checksum = rd16(data + 10);
    out->l3_proto    = PROTO_IPV4;

    format_ipv4(data + 12, out->src_ip, sizeof(out->src_ip));
    format_ipv4(data + 16, out->dst_ip, sizeof(out->dst_ip));

    const uint8_t *l4 = data + ihl;
    uint32_t l4len = len - ihl;

    switch (proto) {
        case 1:   /* ICMP */
            dissect_icmpv4(l4, l4len, out);
            break;
        case 6:   /* TCP */
            dissect_tcp(l4, l4len, out);
            break;
        case 17:  /* UDP */
            dissect_udp(l4, l4len, out);
            break;
        case 132: /* SCTP */
            dissect_sctp(l4, l4len, out);
            break;
        default:
            out->highest_proto = PROTO_IPV4;
            snprintf(out->protocol, sizeof(out->protocol), "IPv4");
            snprintf(out->info, sizeof(out->info),
                     "%s \xe2\x86\x92 %s proto=%u",
                     out->src_ip, out->dst_ip, proto);
            break;
    }
    return 0;
}

static int dissect_ipv6(const uint8_t *data, uint32_t len, pkt_summary_t *out) {
    if (len < 40) return -1;

    uint8_t  next_hdr = data[6];
    uint8_t  hop_limit = data[7];

    out->ip_ttl   = hop_limit;
    out->l3_proto = PROTO_IPV6;

    format_ipv6(data + 8, out->src_ip, sizeof(out->src_ip));
    format_ipv6(data + 24, out->dst_ip, sizeof(out->dst_ip));

    const uint8_t *l4 = data + 40;
    uint32_t l4len = len - 40;

    switch (next_hdr) {
        case 58:  /* ICMPv6 */
            dissect_icmpv6(l4, l4len, out);
            break;
        case 6:   /* TCP */
            dissect_tcp(l4, l4len, out);
            break;
        case 17:  /* UDP */
            dissect_udp(l4, l4len, out);
            break;
        case 132: /* SCTP */
            dissect_sctp(l4, l4len, out);
            break;
        default:
            out->highest_proto = PROTO_IPV6;
            snprintf(out->protocol, sizeof(out->protocol), "IPv6");
            snprintf(out->info, sizeof(out->info),
                     "%s \xe2\x86\x92 %s next=%u",
                     out->src_ip, out->dst_ip, next_hdr);
            break;
    }
    return 0;
}

/* ── Layer 2 dissectors ──────────────────────────────────────── */

static int dissect_arp(const uint8_t *data, uint32_t len, pkt_summary_t *out) {
    if (len < 28) return -1;

    uint16_t op = rd16(data + 6);

    out->l3_proto    = PROTO_ARP;
    out->highest_proto = PROTO_ARP;
    snprintf(out->protocol, sizeof(out->protocol), "ARP");

    char sha[18], spa[16], tha[18], tpa[16];
    format_mac(data + 8, sha, sizeof(sha));
    format_ipv4(data + 14, spa, sizeof(spa));
    format_mac(data + 18, tha, sizeof(tha));
    format_ipv4(data + 24, tpa, sizeof(tpa));

    /* set IP fields for filtering */
    snprintf(out->src_ip, sizeof(out->src_ip), "%s", spa);
    snprintf(out->dst_ip, sizeof(out->dst_ip), "%s", tpa);

    if (op == 1) {
        snprintf(out->info, sizeof(out->info),
                 "Who has %s? Tell %s", tpa, spa);
    } else if (op == 2) {
        snprintf(out->info, sizeof(out->info),
                 "%s is at %s", spa, sha);
    } else {
        snprintf(out->info, sizeof(out->info),
                 "ARP op=%u", op);
    }
    return 0;
}

static int dissect_ethernet(const uint8_t *data, uint32_t len, pkt_summary_t *out) {
    if (len < ETH_HLEN) return -1;

    format_mac(data, out->src_mac, sizeof(out->src_mac));
    format_mac(data + 6, out->dst_mac, sizeof(out->dst_mac));
    uint16_t ethertype = rd16(data + 12);
    out->ethertype = ethertype;

    const uint8_t *payload = data + ETH_HLEN;
    uint32_t plen = len - ETH_HLEN;

    /* handle 802.1Q VLAN tag */
    if (ethertype == ETH_P_8021Q) {
        if (plen < 4) return -1;
        out->vlan_id = rd16(payload) & 0x0FFF;
        ethertype = rd16(payload + 2);
        out->ethertype = ethertype;
        payload += 4;
        plen -= 4;
        out->highest_proto = PROTO_VLAN;
    }

    switch (ethertype) {
        case ETH_P_IP:
            return dissect_ipv4(payload, plen, out);
        case ETH_P_ARP:
            return dissect_arp(payload, plen, out);
        case ETH_P_IPV6:
            return dissect_ipv6(payload, plen, out);
        default:
            out->highest_proto = PROTO_ETH;
            snprintf(out->protocol, sizeof(out->protocol), "ETH");
            snprintf(out->info, sizeof(out->info),
                     "%s \xe2\x86\x92 %s type=0x%04x",
                     out->src_mac, out->dst_mac, ethertype);
            return 0;
    }
}

/* ── Public entry point ──────────────────────────────────────── */

void dissect_packet(const uint8_t *data, uint32_t caplen,
                    int datalink_type, pkt_summary_t *out) {
    memset(out, 0, sizeof(*out));
    out->length = caplen;
    out->highest_proto = PROTO_UNKNOWN;

    switch (datalink_type) {
        case 1:   /* DLT_EN10MB (Ethernet) */
            dissect_ethernet(data, caplen, out);
            break;
        case 228: /* DLT_IPV4 (raw IPv4, no Ethernet header) */
            dissect_ipv4(data, caplen, out);
            break;
        case 229: /* DLT_IPV6 (raw IPv6, no Ethernet header) */
            dissect_ipv6(data, caplen, out);
            break;
        default:
            snprintf(out->protocol, sizeof(out->protocol), "???");
            snprintf(out->info, sizeof(out->info), "Unknown datalink %d", datalink_type);
            break;
    }
}
