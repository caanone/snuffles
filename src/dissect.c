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
    ns_ip_str(4, ip, buf, len);
}

static void format_ipv6(const uint8_t *ip, char *buf, size_t len) {
    ns_ip_str(6, ip, buf, len);
}

static inline void set_label(pkt_summary_t *out, proto_id_t id) {
    out->proto_label = proto_label_of(id);
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

    memset(&out->u, 0, sizeof(out->u));   /* was the L4 dissector's */
    out->info_kind = INFO_DNS;
    out->u.dns.response = (uint8_t)is_response;
    char *name = out->u.dns.name;
    size_t npos = 0;
    uint32_t offset = 12;

    if (qdcount > 0) {
        int labels = 0;
        while (offset < len && data[offset] != 0 && labels < 128) {
            uint8_t llen = data[offset++];
            if ((llen & 0xC0) == 0xC0) break;  /* compression pointer */
            if (llen > 63) break;               /* RFC max label = 63 */
            if (offset + llen > len) break;     /* bounds check */
            if (npos > 0 && npos < sizeof(out->u.dns.name) - 1)
                name[npos++] = '.';
            for (uint8_t i = 0; i < llen && npos < sizeof(out->u.dns.name) - 1; i++)
                name[npos++] = (char)data[offset++];
            labels++;
        }
    }
    name[npos] = '\0';

    /* extract qtype if present */
    if (offset + 1 < len) {
        offset++; /* skip null terminator */
        if (offset + 2 <= len)
            out->u.dns.qtype = rd16(data + offset);
    }

    set_label(out, PROTO_DNS);

    if (!is_response)
        return;

    /* Response: surface rcode, and the first A/AAAA answer if present. */
    uint8_t  rcode   = flags & 0x0F;
    uint16_t ancount = rd16(data + 6);
    out->u.dns.rcode = rcode;

    if (rcode == 0 && qdcount > 0 && ancount > 0 && offset + 4 <= len) {
        uint32_t aoff = offset + 4;   /* past qtype + qclass */
        for (uint16_t a = 0; a < ancount && a < 16 && aoff < len &&
             !out->u.dns.rdata_kind; a++) {
            /* skip the answer name: compression pointer or label sequence */
            if ((data[aoff] & 0xC0) == 0xC0) {
                aoff += 2;
            } else {
                int lb = 0;
                while (aoff < len && data[aoff] != 0 && lb++ < 128) {
                    uint8_t ll = data[aoff];
                    if ((ll & 0xC0) == 0xC0) { aoff++; break; }
                    if (ll > 63) { aoff = len; break; }
                    aoff += 1u + ll;
                }
                aoff++;
            }
            if (aoff + 10 > len) break;
            uint16_t atype = rd16(data + aoff);
            uint16_t rdlen = rd16(data + aoff + 8);
            aoff += 10;
            if (rdlen > len - aoff) break;
            if (atype == 1 && rdlen == 4) {
                memcpy(out->u.dns.rdata, data + aoff, 4);
                out->u.dns.rdata_kind = DNS_RDATA_A;
            } else if (atype == 28 && rdlen == 16) {
                memcpy(out->u.dns.rdata, data + aoff, 16);
                out->u.dns.rdata_kind = DNS_RDATA_AAAA;
            } else if (atype == 5) {
                out->u.dns.rdata_kind = DNS_RDATA_CNAME;
            }
            aoff += rdlen;
        }
    }
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
            memset(&out->u, 0, sizeof(out->u));
            out->info_kind = INFO_HTTP;
            out->u.http.request = 1;
            out->u.http.len = (uint8_t)end;
            memcpy(out->u.http.line, data, end);
            set_label(out, PROTO_HTTP);
            return;
        }
    }

    if (len >= 9 && memcmp(data, "HTTP/1.", 7) == 0) {
        out->l7_proto = PROTO_HTTP;
        out->highest_proto = PROTO_HTTP;
        size_t end = 0;
        while (end < len && end < 120 && data[end] != '\r' && data[end] != '\n')
            end++;
        memset(&out->u, 0, sizeof(out->u));
        out->info_kind = INFO_HTTP;
        out->u.http.request = 0;
        out->u.http.len = (uint8_t)end;
        memcpy(out->u.http.line, data, end);
        set_label(out, PROTO_HTTP);
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
    set_label(out, PROTO_TLS);
    memset(&out->u, 0, sizeof(out->u));
    out->info_kind = INFO_TLS;
    out->u.tls.hs_type = hs_type;

    if (hs_type == 0x01) {
        /* ClientHello — try to extract SNI */
        /* ClientHello: skip handshake header (4) + version(2) + random(32) */
        uint32_t off = 5 + 4 + 2 + 32;
        if (off + 1 >= len) return;

        /* session ID length */
        uint8_t sid_len = data[off++];
        off += sid_len;
        if (off + 2 > len) return;

        /* cipher suites length */
        uint16_t cs_len = rd16(data + off); off += 2;
        off += cs_len;
        if (off + 1 > len) return;

        /* compression methods length */
        uint8_t cm_len = data[off++];
        off += cm_len;
        if (off + 2 > len) return;

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
                    /* the info line holds at most sizeof(sni) - 1 of it
                     * after its "TLS ClientHello SNI=" prefix anyway */
                    uint16_t keep = name_len;
                    if (keep > sizeof(out->u.tls.sni) - 1)
                        keep = sizeof(out->u.tls.sni) - 1;
                    memcpy(out->u.tls.sni, data + sni_off, keep);
                    out->u.tls.sni[keep] = '\0';
                    out->u.tls.sni_len = (uint8_t)keep;
                    return;
                }
            }
            off += ext_len;
        }
    }
}

static void dissect_dhcp(const uint8_t *data, uint32_t len, pkt_summary_t *out) {
    /* BOOTP fixed header is 236 bytes; DHCP requires the magic cookie
     * right after it, then TLV options (0 = pad, 255 = end). */
    if (len < 240) return;
    if (rd32(data + 236) != 0x63825363) return;

    out->l7_proto = PROTO_DHCP;
    out->highest_proto = PROTO_DHCP;
    set_label(out, PROTO_DHCP);
    memset(&out->u, 0, sizeof(out->u));
    out->info_kind = INFO_DHCP;

    uint8_t op = data[0];
    int msg_type = -1;
    uint32_t off = 240;
    while (off < len) {
        uint8_t opt = data[off++];
        if (opt == 0) continue;         /* pad */
        if (opt == 255) break;          /* end */
        if (off >= len) break;
        uint8_t olen = data[off++];
        if (olen > len - off) break;    /* option data must fit */
        if (opt == 53 && olen >= 1) msg_type = data[off];
        off += olen;
    }

    out->u.dhcp.msg_type = (int16_t)msg_type;
    out->u.dhcp.op = op;

    /* OFFER/ACK carry the assigned address in yiaddr; other messages
     * may carry the client's current address in ciaddr. */
    if ((msg_type == 2 || msg_type == 5) && rd32(data + 16) != 0) {
        memcpy(out->u.dhcp.addr, data + 16, 4);
        out->u.dhcp.has_addr = 1;
    } else if (msg_type != 2 && msg_type != 5 && rd32(data + 12) != 0) {
        memcpy(out->u.dhcp.addr, data + 12, 4);
        out->u.dhcp.has_addr = 1;
    }
}

static void dissect_ntp(const uint8_t *data, uint32_t len, pkt_summary_t *out) {
    if (len < 48) return;

    uint8_t vn      = (data[0] >> 3) & 0x07;
    uint8_t mode    = data[0] & 0x07;
    uint8_t stratum = data[1];

    out->l7_proto = PROTO_NTP;
    out->highest_proto = PROTO_NTP;
    set_label(out, PROTO_NTP);
    memset(&out->u, 0, sizeof(out->u));
    out->info_kind = INFO_NTP;
    out->u.ntp.vn = vn;
    out->u.ntp.mode = mode;
    out->u.ntp.stratum = stratum;
}

static void dissect_quic(const uint8_t *data, uint32_t len, pkt_summary_t *out) {
    /* Long header only: short headers carry no version and are
     * indistinguishable from random payload, so they stay plain UDP. */
    if (len < 5) return;
    if (!(data[0] & 0x80)) return;

    uint32_t version = rd32(data + 1);
    uint8_t  ptype   = (data[0] >> 4) & 3;

    out->l7_proto = PROTO_QUIC;
    out->highest_proto = PROTO_QUIC;
    set_label(out, PROTO_QUIC);
    memset(&out->u, 0, sizeof(out->u));
    out->info_kind = INFO_QUIC;
    out->u.quic.version = version;
    out->u.quic.ptype = ptype;
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
    out->l7_off      += doff;           /* doff <= len validated above */
    out->l7_len       = len - doff;
    out->l4_proto     = PROTO_TCP;
    out->highest_proto = PROTO_TCP;
    set_label(out, PROTO_TCP);
    out->info_kind = INFO_TCP;

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
    set_label(out, PROTO_UDP);
    out->info_kind = INFO_UDP;
    out->u.udp.len = ulen;

    /* try L7 */
    if (len > 8) {
        const uint8_t *payload = data + 8;
        uint32_t plen = len - 8;

        if (out->src_port == 53 || out->dst_port == 53) {
            dissect_dns(payload, plen, out);
        } else if (out->src_port == 67 || out->dst_port == 67 ||
                   out->src_port == 68 || out->dst_port == 68) {
            dissect_dhcp(payload, plen, out);
        } else if (out->src_port == 123 || out->dst_port == 123) {
            dissect_ntp(payload, plen, out);
        } else if (out->src_port == 5353 || out->dst_port == 5353) {
            /* mDNS is DNS on the wire: reuse the dissector, relabel */
            dissect_dns(payload, plen, out);
            if (out->l7_proto == PROTO_DNS) {
                out->l7_proto = PROTO_MDNS;
                out->highest_proto = PROTO_MDNS;
                set_label(out, PROTO_MDNS);
            }
        } else if (out->src_port == 443 || out->dst_port == 443) {
            dissect_quic(payload, plen, out);
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
    set_label(out, PROTO_SCTP);
    out->info_kind = INFO_SCTP;
    return 0;
}

/* ── Layer 3 dissectors ──────────────────────────────────────── */

static int dissect_icmpv4(const uint8_t *data, uint32_t len, pkt_summary_t *out) {
    if (len < 4) return -1;

    uint8_t type = data[0];
    uint8_t code = data[1];

    out->l4_proto    = PROTO_ICMP4;
    out->highest_proto = PROTO_ICMP4;
    set_label(out, PROTO_ICMP4);
    out->info_kind = INFO_ICMP4;
    out->u.icmp.type = type;
    out->u.icmp.code = code;

    if ((type == 0 || type == 8) && len >= 8) {
        out->u.icmp.echo = 1;
        out->u.icmp.id  = rd16(data + 4);
        out->u.icmp.seq = rd16(data + 6);
    }
    return 0;
}

static int dissect_icmpv6(const uint8_t *data, uint32_t len, pkt_summary_t *out) {
    if (len < 4) return -1;

    uint8_t type = data[0];
    uint8_t code = data[1];

    out->l4_proto    = PROTO_ICMP6;
    out->highest_proto = PROTO_ICMP6;
    set_label(out, PROTO_ICMP6);
    out->info_kind = INFO_ICMP6;
    out->u.icmp.type = type;
    out->u.icmp.code = code;
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

    memcpy(out->src_addr, data + 12, 4);
    memcpy(out->dst_addr, data + 16, 4);
    out->addr_family = 4;

    /* Non-first fragments carry no L4 header: parsing them as TCP/UDP
     * would fill sessions and syslog with garbage ports. */
    if ((out->ip_frag_off & 0x1FFF) != 0) {
        out->highest_proto = PROTO_IPV4;
        set_label(out, PROTO_IPV4);
        out->info_kind = INFO_IP4_FRAG;
        return 0;
    }

    const uint8_t *l4 = data + ihl;
    uint32_t l4len = len - ihl;
    out->l7_off += ihl;

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
            set_label(out, PROTO_IPV4);
            out->info_kind = INFO_IP4_PROTO;
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

    memcpy(out->src_addr, data + 8, 16);
    memcpy(out->dst_addr, data + 24, 16);
    out->addr_family = 6;

    const uint8_t *l4 = data + 40;
    uint32_t l4len = len - 40;
    out->l7_off += 40;

    /* Walk the extension-header chain so packets with hop-by-hop, routing,
     * fragment or destination options still get L4/L7 dissection. */
    for (int guard = 0; guard < 8; guard++) {
        uint32_t ext_len;
        switch (next_hdr) {
            case 0:    /* hop-by-hop */
            case 43:   /* routing */
            case 60:   /* destination options */
            case 135:  /* mobility */
                ext_len = (l4len >= 8) ? ((uint32_t)l4[1] + 1) * 8 : 0;
                break;
            case 51:   /* authentication header: length in 4-byte units */
                ext_len = (l4len >= 8) ? ((uint32_t)l4[1] + 2) * 4 : 0;
                break;
            case 44:   /* fragment header (fixed 8 bytes) */
                if (l4len >= 8) {
                    /* expose offset/MF in the IPv4 ip_frag_off layout so
                     * consumers (session table, syslog) test one field */
                    uint16_t fo = rd16(l4 + 2);
                    out->ip_frag_off = (uint16_t)((fo >> 3) | ((fo & 1) << 13));
                    out->ip_id = rd16(l4 + 6);   /* low 16 bits of the id */
                }
                if (l4len >= 8 && (rd16(l4 + 2) & 0xFFF8) != 0) {
                    /* non-first fragment: no L4 header follows */
                    out->highest_proto = PROTO_IPV6;
                    set_label(out, PROTO_IPV6);
                    out->info_kind = INFO_IP6_FRAG;
                    return 0;
                }
                ext_len = (l4len >= 8) ? 8 : 0;
                break;
            default:
                ext_len = 0;
                guard = 8;   /* not an extension header: dispatch below */
                break;
        }
        if (guard >= 8) break;
        if (ext_len == 0 || ext_len > l4len) {
            out->highest_proto = PROTO_IPV6;
            set_label(out, PROTO_IPV6);
            out->info_kind = INFO_IP6_TRUNC;
            return 0;
        }
        next_hdr = l4[0];
        l4    += ext_len;
        l4len -= ext_len;
        out->l7_off += ext_len;
    }
    out->ip_proto = next_hdr;

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
            set_label(out, PROTO_IPV6);
            out->info_kind = INFO_IP6_NEXT;
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
    set_label(out, PROTO_ARP);

    /* sender/target protocol addresses double as the IP pair (filtering,
     * sessions); the sender hardware address feeds the reply line */
    memcpy(out->src_addr, data + 14, 4);
    memcpy(out->dst_addr, data + 24, 4);
    out->addr_family = 4;
    out->info_kind = INFO_ARP;
    out->u.arp.op = op;
    memcpy(out->u.arp.sha, data + 8, 6);
    return 0;
}

static int dissect_ethernet(const uint8_t *data, uint32_t len, pkt_summary_t *out) {
    if (len < ETH_HLEN) return -1;

    memcpy(out->src_mac_raw, data, 6);
    memcpy(out->dst_mac_raw, data + 6, 6);
    out->has_mac = 1;
    uint16_t ethertype = rd16(data + 12);
    out->ethertype = ethertype;

    const uint8_t *payload = data + ETH_HLEN;
    uint32_t plen = len - ETH_HLEN;
    out->l7_off += ETH_HLEN;

    /* handle 802.1Q VLAN tag */
    if (ethertype == ETH_P_8021Q) {
        if (plen < 4) return -1;
        out->vlan_id = rd16(payload) & 0x0FFF;
        ethertype = rd16(payload + 2);
        out->ethertype = ethertype;
        payload += 4;
        plen -= 4;
        out->l7_off += 4;
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
            set_label(out, PROTO_ETH);
            out->info_kind = INFO_ETH;
            return 0;
    }
}

/* ── Other datalinks ─────────────────────────────────────────── */

static int dissect_by_ethertype(uint16_t ethertype, const uint8_t *p,
                                uint32_t plen, pkt_summary_t *out,
                                uint8_t l2label) {
    out->ethertype = ethertype;
    switch (ethertype) {
        case ETH_P_IP:   return dissect_ipv4(p, plen, out);
        case ETH_P_IPV6: return dissect_ipv6(p, plen, out);
        case ETH_P_ARP:  return dissect_arp(p, plen, out);
        default:
            out->highest_proto = PROTO_ETH;
            out->proto_label = l2label;
            out->info_kind = INFO_L2_FRAME;
            return 0;
    }
}

/* Linux cooked capture (DLT_LINUX_SLL, the "any" device): 16-byte header
 * with the EtherType in the last two bytes. */
static int dissect_sll(const uint8_t *data, uint32_t len, pkt_summary_t *out) {
    if (len < 16) return -1;
    out->l7_off += 16;
    return dissect_by_ethertype(rd16(data + 14), data + 16, len - 16, out, LABEL_SLL);
}

/* Linux cooked capture v2 (DLT_LINUX_SLL2): 20-byte header, EtherType first. */
static int dissect_sll2(const uint8_t *data, uint32_t len, pkt_summary_t *out) {
    if (len < 20) return -1;
    out->l7_off += 20;
    return dissect_by_ethertype(rd16(data), data + 20, len - 20, out, LABEL_SLL2);
}

/* DLT_NULL / DLT_LOOP (BSD and macOS loopback): 4-byte address family in
 * the capturing host's byte order (LOOP: network order) — normalize both. */
static int dissect_null(const uint8_t *data, uint32_t len, pkt_summary_t *out) {
    if (len < 4) return -1;
    uint32_t fam = (uint32_t)data[0] | ((uint32_t)data[1] << 8) |
                   ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
    if (fam > 0xFF)
        fam = ((fam >> 24) & 0xFF) | ((fam >> 8) & 0xFF00);

    const uint8_t *p = data + 4;
    uint32_t plen = len - 4;
    out->l7_off += 4;
    if (fam == 2)                                   /* AF_INET */
        return dissect_ipv4(p, plen, out);
    if (fam == 10 || fam == 24 || fam == 28 || fam == 30)   /* AF_INET6 */
        return dissect_ipv6(p, plen, out);

    out->highest_proto = PROTO_UNKNOWN;
    out->proto_label = LABEL_LOOP;
    out->info_kind = INFO_LOOP;
    out->u.loop.family = fam;
    return 0;
}

/* ── Public entry point ──────────────────────────────────────── */

void dissect_packet(const uint8_t *data, uint32_t caplen,
                    int datalink_type, pkt_summary_t *out) {
    memset(out, 0, sizeof(*out));
    out->length = caplen;
    out->highest_proto = PROTO_UNKNOWN;
    out->text_pending = 1;      /* proto_label/info_kind: none, from memset */

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
        case 113: /* DLT_LINUX_SLL (Linux "any" device) */
            dissect_sll(data, caplen, out);
            break;
        case 276: /* DLT_LINUX_SLL2 */
            dissect_sll2(data, caplen, out);
            break;
        case 0:   /* DLT_NULL (BSD/macOS loopback) */
        case 108: /* DLT_LOOP */
            dissect_null(data, caplen, out);
            break;
        default:
            set_label(out, PROTO_UNKNOWN);   /* "???" */
            out->info_kind = INFO_BAD_DLT;
            out->u.bad_dlt.dlt = datalink_type;
            break;
    }

    /* Consumers index the captured bytes with l7_off/l7_len directly:
     * clamp so the pair can never reach past caplen. */
    if (out->l7_off > caplen) {
        out->l7_off = caplen;
        out->l7_len = 0;
    }
    if (out->l7_len > caplen - out->l7_off)
        out->l7_len = caplen - out->l7_off;
}

/* ── Text columns, produced on demand ────────────────────────── */

static const char *dns_qtype_str(uint16_t qt) {
    switch (qt) {
        case 1:   return "A";
        case 28:  return "AAAA";
        case 5:   return "CNAME";
        case 15:  return "MX";
        case 2:   return "NS";
        case 12:  return "PTR";
        case 6:   return "SOA";
        case 16:  return "TXT";
        case 33:  return "SRV";
        default:  return "";
    }
}

/* The info column is a fixed 128-byte line: packet-derived strings (DNS
 * names, HTTP request lines, SNI) are cut to fit by design. */
#if defined(__GNUC__) && !defined(__clang__)
  #pragma GCC diagnostic push
  #pragma GCC diagnostic ignored "-Wformat-truncation"
#endif

static void format_info(pkt_summary_t *s) {
    char *info = s->info;
    size_t cap = sizeof(s->info);

    switch ((info_kind_t)s->info_kind) {
    case INFO_NONE:
        info[0] = '\0';
        break;
    case INFO_ETH:
        snprintf(info, cap, "%s -> %s type=0x%04x",
                 s->src_mac, s->dst_mac, s->ethertype);
        break;
    case INFO_L2_FRAME:
        snprintf(info, cap, "%s frame type=0x%04x",
                 proto_label_str(s->proto_label), s->ethertype);
        break;
    case INFO_LOOP:
        snprintf(info, cap, "loopback family=%u", s->u.loop.family);
        break;
    case INFO_BAD_DLT:
        snprintf(info, cap, "Unknown datalink %d", s->u.bad_dlt.dlt);
        break;
    case INFO_RAWIP:
        snprintf(info, cap, "Raw IP (ver=%d, len=%u)",
                 s->u.rawip.ver, s->u.rawip.len);
        break;
    case INFO_ARP:
        if (s->u.arp.op == 1) {
            snprintf(info, cap, "Who has %s? Tell %s", s->dst_ip, s->src_ip);
        } else if (s->u.arp.op == 2) {
            char sha[18];
            format_mac(s->u.arp.sha, sha, sizeof(sha));
            snprintf(info, cap, "%s is at %s", s->src_ip, sha);
        } else {
            snprintf(info, cap, "ARP op=%u", s->u.arp.op);
        }
        break;
    case INFO_IP4_FRAG:
        snprintf(info, cap, "%s -> %s fragment proto=%u off=%u",
                 s->src_ip, s->dst_ip, s->ip_proto,
                 (unsigned)((s->ip_frag_off & 0x1FFF) * 8));
        break;
    case INFO_IP4_PROTO:
        snprintf(info, cap, "%s -> %s proto=%u",
                 s->src_ip, s->dst_ip, s->ip_proto);
        break;
    case INFO_IP6_FRAG:
        snprintf(info, cap, "%s -> %s fragment", s->src_ip, s->dst_ip);
        break;
    case INFO_IP6_TRUNC:
        snprintf(info, cap, "%s -> %s truncated extension chain",
                 s->src_ip, s->dst_ip);
        break;
    case INFO_IP6_NEXT:
        snprintf(info, cap, "%s -> %s next=%u",
                 s->src_ip, s->dst_ip, s->ip_proto);
        break;
    case INFO_ICMP4: {
        const char *desc = "Other";
        switch (s->u.icmp.type) {
            case 0:  desc = "Echo Reply";              break;
            case 3:  desc = "Destination Unreachable";  break;
            case 5:  desc = "Redirect";                break;
            case 8:  desc = "Echo Request";            break;
            case 11: desc = "Time Exceeded";           break;
        }
        if (s->u.icmp.echo)
            snprintf(info, cap, "%s id=%u seq=%u",
                     desc, s->u.icmp.id, s->u.icmp.seq);
        else
            snprintf(info, cap, "%s (type=%u code=%u)",
                     desc, s->u.icmp.type, s->u.icmp.code);
        break;
    }
    case INFO_ICMP6: {
        const char *desc = "Other";
        switch (s->u.icmp.type) {
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
        snprintf(info, cap, "%s (type=%u code=%u)",
                 desc, s->u.icmp.type, s->u.icmp.code);
        break;
    }
    case INFO_TCP: {
        char flagstr[16];
        format_tcp_flags(s->tcp_flags, flagstr, sizeof(flagstr));
        snprintf(info, cap, "%u -> %u %s Seq=%u Ack=%u Win=%u",
                 s->src_port, s->dst_port, flagstr,
                 s->tcp_seq, s->tcp_ack, s->tcp_window);
        break;
    }
    case INFO_UDP:
        snprintf(info, cap, "%u -> %u Len=%u",
                 s->src_port, s->dst_port, s->u.udp.len);
        break;
    case INFO_SCTP:
        snprintf(info, cap, "%u -> %u", s->src_port, s->dst_port);
        break;
    case INFO_DNS: {
        const char *qtype = dns_qtype_str(s->u.dns.qtype);
        const char *name  = s->u.dns.name;
        if (!s->u.dns.response) {
            snprintf(info, cap, "DNS Q %s %s", qtype, name);
            break;
        }
        static const char *rcodes[] = { "", "FormErr", "ServFail", "NXDOMAIN",
                                        "NotImp", "Refused" };
        if (s->u.dns.rcode != 0) {
            const char *rstr = (s->u.dns.rcode <= 5) ? rcodes[s->u.dns.rcode]
                                                     : "Err";
            snprintf(info, cap, "DNS R %s %s", rstr, name);
        } else if (s->u.dns.rdata_kind != DNS_RDATA_NONE) {
            char rdata[64];
            if (s->u.dns.rdata_kind == DNS_RDATA_A)
                format_ipv4(s->u.dns.rdata, rdata, sizeof(rdata));
            else if (s->u.dns.rdata_kind == DNS_RDATA_AAAA)
                format_ipv6(s->u.dns.rdata, rdata, sizeof(rdata));
            else
                snprintf(rdata, sizeof(rdata), "CNAME");
            snprintf(info, cap, "DNS R %s %s = %s", qtype, name, rdata);
        } else {
            snprintf(info, cap, "DNS R %s %s", qtype, name);
        }
        break;
    }
    case INFO_HTTP:
        if (s->u.http.request)
            snprintf(info, cap, "HTTP %.*s", (int)s->u.http.len, s->u.http.line);
        else
            snprintf(info, cap, "%.*s", (int)s->u.http.len, s->u.http.line);
        break;
    case INFO_TLS:
        if (s->u.tls.hs_type == 0x01) {
            if (s->u.tls.sni_len)
                snprintf(info, cap, "TLS ClientHello SNI=%s", s->u.tls.sni);
            else
                snprintf(info, cap, "TLS ClientHello");
        } else if (s->u.tls.hs_type == 0x02) {
            snprintf(info, cap, "TLS ServerHello");
        } else {
            const char *desc = "Handshake";
            switch (s->u.tls.hs_type) {
                case 0x0b: desc = "Certificate";      break;
                case 0x0c: desc = "ServerKeyExchange"; break;
                case 0x0e: desc = "ServerHelloDone";   break;
                case 0x10: desc = "ClientKeyExchange";  break;
                case 0x14: desc = "Finished";          break;
            }
            snprintf(info, cap, "TLS %s", desc);
        }
        break;
    case INFO_DHCP: {
        int msg_type = s->u.dhcp.msg_type;
        char type[16];
        switch (msg_type) {
            case 1:  snprintf(type, sizeof(type), "DISCOVER"); break;
            case 2:  snprintf(type, sizeof(type), "OFFER");    break;
            case 3:  snprintf(type, sizeof(type), "REQUEST");  break;
            case 5:  snprintf(type, sizeof(type), "ACK");      break;
            case 6:  snprintf(type, sizeof(type), "NAK");      break;
            case 7:  snprintf(type, sizeof(type), "RELEASE");  break;
            default:
                if (msg_type >= 0)
                    snprintf(type, sizeof(type), "type=%d", msg_type);
                else if (s->u.dhcp.op == 1 || s->u.dhcp.op == 2)
                    snprintf(type, sizeof(type), "%s",
                             (s->u.dhcp.op == 1) ? "request" : "reply");
                else
                    snprintf(type, sizeof(type), "op=%u", s->u.dhcp.op);
                break;
        }
        char addr[24] = "";
        if (s->u.dhcp.has_addr) {
            char ip[16];
            format_ipv4(s->u.dhcp.addr, ip, sizeof(ip));
            snprintf(addr, sizeof(addr), " %s", ip);
        }
        snprintf(info, cap, "DHCP %s%s", type, addr);
        break;
    }
    case INFO_NTP:
        if (s->u.ntp.mode == 3)
            snprintf(info, cap, "NTP client v%u", s->u.ntp.vn);
        else if (s->u.ntp.mode == 4)
            snprintf(info, cap, "NTP server v%u stratum %u",
                     s->u.ntp.vn, s->u.ntp.stratum);
        else
            snprintf(info, cap, "NTP mode=%u v%u", s->u.ntp.mode, s->u.ntp.vn);
        break;
    case INFO_QUIC: {
        static const char *types[] = { "Initial", "0-RTT", "Handshake", "Retry" };
        char ver[16];
        if (s->u.quic.version == 0x00000001)
            snprintf(ver, sizeof(ver), "v1");
        else
            snprintf(ver, sizeof(ver), "v0x%08x", s->u.quic.version);
        snprintf(info, cap, "QUIC %s %s", types[s->u.quic.ptype & 3], ver);
        break;
    }
    }

    /* Packet bytes flow into info (HTTP lines, DNS names, TLS SNI) and are
     * later printed to the operator's terminal: strip anything that could
     * carry escape sequences or break the JSON export's UTF-8. */
    for (char *ip = info; *ip; ip++) {
        unsigned char ch = (unsigned char)*ip;
        if (ch < 0x20 || ch >= 0x7f) *ip = '.';
    }
}

#if defined(__GNUC__) && !defined(__clang__)
  #pragma GCC diagnostic pop
#endif

void summary_format(pkt_summary_t *s) {
    if (!s->text_pending) return;

    if (s->has_mac) {
        format_mac(s->src_mac_raw, s->src_mac, sizeof(s->src_mac));
        format_mac(s->dst_mac_raw, s->dst_mac, sizeof(s->dst_mac));
    } else {
        s->src_mac[0] = s->dst_mac[0] = '\0';
    }
    ns_ip_str(s->addr_family, s->src_addr, s->src_ip, sizeof(s->src_ip));
    ns_ip_str(s->addr_family, s->dst_addr, s->dst_ip, sizeof(s->dst_ip));
    snprintf(s->protocol, sizeof(s->protocol), "%s",
             proto_label_str(s->proto_label));
    format_info(s);

    s->text_pending = 0;
}
