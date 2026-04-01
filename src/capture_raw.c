/*
 * capture_raw.c — Raw socket capture backend (NO libpcap / Npcap dependency)
 *
 * Build with: -DNO_PCAP
 *
 * Windows: SOCK_RAW + SIO_RCVALL (captures all IP packets on an interface)
 * Linux:   AF_PACKET + SOCK_RAW  (captures all Ethernet frames)
 *
 * Limitations vs. libpcap backend:
 *   - Windows: captures IP-level only (no Ethernet header, no ARP)
 *   - No kernel BPF filters (capture_set_bpf is a no-op; use display filters)
 *   - No offline pcap file reading (use the pcap backend for that)
 */

#include "capture.h"
#include "dissect.h"
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
  #include <iphlpapi.h>
  #include <mstcpip.h>
  #pragma comment(lib, "ws2_32.lib")
  #pragma comment(lib, "iphlpapi.lib")

  typedef SOCKET raw_sock_t;
  #define RAW_INVALID INVALID_SOCKET
  #define RAW_CLOSE(s) closesocket(s)
#else
  #include <unistd.h>
  #include <sys/socket.h>
  #include <sys/ioctl.h>
  #include <net/if.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #ifdef __linux__
    #include <netpacket/packet.h>
    #include <net/ethernet.h>
  #endif

  typedef int raw_sock_t;
  #define RAW_INVALID (-1)
  #define RAW_CLOSE(s) close(s)
#endif

/* ── Context ─────────────────────────────────────────────────── */

struct capture_ctx {
    raw_sock_t          sock;
    ringbuf_t          *rb;
    session_table_t    *st;
    capture_cfg_t       cfg;
    ns_thread_t         thread;
    volatile int        running;
    volatile int        stop_req;
    int                 has_eth;    /* 1 if we get Ethernet headers (Linux AF_PACKET) */
    uint64_t            pkt_count;
    char                iface_name[64];
    char                bpf_expr[512]; /* stored but not kernel-applied */
    syslog_out_t       *syslog;
};

/* ── Capture thread ──────────────────────────────────────────── */

static void *capture_thread_fn(void *arg) {
    capture_ctx_t *ctx = (capture_ctx_t *)arg;
    ctx->running = 1;

    uint8_t buf[65536];

    while (!ctx->stop_req) {
        /* use a timeout so we can check stop_req periodically */
#ifdef _WIN32
        /* Winsock SO_RCVTIMEO is in milliseconds (DWORD) */
        /* already set in capture_create */
#else
        /* already set via SO_RCVTIMEO in capture_create */
#endif
        int len = (int)recv(ctx->sock, (char *)buf, sizeof(buf), 0);
        if (len <= 0) {
            if (ctx->stop_req) break;
            continue; /* timeout or error */
        }

        pkt_record_t *rec = ringbuf_producer_next(ctx->rb);

        uint32_t copylen = (uint32_t)len;
        if (copylen > (uint32_t)ctx->cfg.snaplen)
            copylen = (uint32_t)ctx->cfg.snaplen;
        memcpy(rec->raw_data, buf, copylen);
        rec->raw_len = copylen;

        /* dissect */
        if (ctx->has_eth) {
            /* Linux AF_PACKET: full Ethernet frame */
            dissect_packet(buf, (uint32_t)len, 1 /* DLT_EN10MB */, &rec->summary);
        } else {
            /* Windows raw socket: IP header only, no Ethernet.
             * Fake an Ethernet header isn't needed — just dissect from IP.
             * We call dissect with datalink=228 (DLT_IPV4) but our dissect
             * only handles DLT_EN10MB (1). So we manually call IPv4/IPv6. */
            memset(&rec->summary, 0, sizeof(rec->summary));
            rec->summary.length = (uint32_t)len;
            if (len >= 1) {
                uint8_t ver = (buf[0] >> 4) & 0x0F;
                if (ver == 4 && len >= 20) {
                    /* manually extract IPs and call dissect chain */
                    dissect_packet(buf, (uint32_t)len, 228 /* DLT_IPV4 */, &rec->summary);
                } else if (ver == 6 && len >= 40) {
                    dissect_packet(buf, (uint32_t)len, 229 /* DLT_IPV6 */, &rec->summary);
                } else {
                    snprintf(rec->summary.protocol, sizeof(rec->summary.protocol), "RAW");
                    snprintf(rec->summary.info, sizeof(rec->summary.info),
                             "Raw IP (ver=%d, len=%d)", ver, len);
                }
            }
        }

        /* timestamp */
        struct timeval tv;
#ifdef _WIN32
        FILETIME ft;
        GetSystemTimeAsFileTime(&ft);
        uint64_t t = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
        t -= 116444736000000000ULL;
        tv.tv_sec  = (long)(t / 10000000);
        tv.tv_usec = (long)((t / 10) % 1000000);
#else
        gettimeofday(&tv, NULL);
#endif
        rec->summary.ts = tv;

        /* session tracking */
        if (ctx->st) {
            session_entry_t *se = session_table_update(ctx->st, &rec->summary);
            if (se) rec->summary.session_id = se->id;
        }

        /* syslog output (skip own traffic to prevent feedback loop) */
        if (ctx->syslog && !syslog_out_is_self(ctx->syslog, &rec->summary))
            syslog_out_send(ctx->syslog, &rec->summary);

        ringbuf_producer_commit(ctx->rb);

        ctx->pkt_count++;
        if (ctx->cfg.count > 0 && ctx->pkt_count >= (uint64_t)ctx->cfg.count) {
            break;
        }
    }

    ctx->running = 0;
    return NULL;
}

/* ── Interface listing ───────────────────────────────────────── */

#ifdef _WIN32
static int find_interface_ip(const char *name, struct sockaddr_in *out) {
    /* If name is an IP, use it directly */
    if (inet_pton(AF_INET, name, &out->sin_addr) == 1) {
        out->sin_family = AF_INET;
        out->sin_port = 0;
        return 0;
    }
    /* Otherwise enumerate and find by adapter name */
    ULONG buflen = 15000;
    PIP_ADAPTER_ADDRESSES addrs = malloc(buflen);
    if (!addrs) return -1;
    if (GetAdaptersAddresses(AF_INET, 0, NULL, addrs, &buflen) != NO_ERROR) {
        free(addrs);
        return -1;
    }
    int found = 0;
    for (PIP_ADAPTER_ADDRESSES a = addrs; a; a = a->Next) {
        /* match by friendly name (wide) or adapter name (ASCII) */
        if (a->FirstUnicastAddress && a->FirstUnicastAddress->Address.lpSockaddr) {
            char aname[256];
            WideCharToMultiByte(CP_UTF8, 0, a->FriendlyName, -1, aname, sizeof(aname), NULL, NULL);
            if (_stricmp(aname, name) == 0 || _stricmp(a->AdapterName, name) == 0) {
                memcpy(out, a->FirstUnicastAddress->Address.lpSockaddr, sizeof(*out));
                found = 1;
                break;
            }
        }
    }
    /* if name not specified, use first non-loopback */
    if (!found && (!name || !name[0])) {
        for (PIP_ADAPTER_ADDRESSES a = addrs; a; a = a->Next) {
            if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
            if (a->OperStatus != IfOperStatusUp) continue;
            if (a->FirstUnicastAddress && a->FirstUnicastAddress->Address.lpSockaddr) {
                memcpy(out, a->FirstUnicastAddress->Address.lpSockaddr, sizeof(*out));
                found = 1;
                break;
            }
        }
    }
    free(addrs);
    return found ? 0 : -1;
}
#endif

/* ── Public API ──────────────────────────────────────────────── */

capture_ctx_t *capture_create(const capture_cfg_t *cfg, ringbuf_t *rb,
                              session_table_t *st) {
    capture_ctx_t *ctx = calloc(1, sizeof(capture_ctx_t));
    if (!ctx) return NULL;

    ctx->rb   = rb;
    ctx->st   = st;
    ctx->cfg  = *cfg;
    ctx->sock = RAW_INVALID;

    if (cfg->pcap_file[0]) {
        fprintf(stderr, "Offline pcap reading requires the libpcap build.\n"
                        "Build without -DNO_PCAP to enable pcap file support.\n");
        free(ctx);
        return NULL;
    }

#ifdef _WIN32
    /* ── Windows: SOCK_RAW + SIO_RCVALL ─────────────────────── */
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        free(ctx);
        return NULL;
    }

    ctx->sock = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if (ctx->sock == RAW_INVALID) {
        fprintf(stderr, "socket(SOCK_RAW) failed: %d\n", WSAGetLastError());
        fprintf(stderr, "Hint: run as Administrator.\n");
        free(ctx);
        return NULL;
    }

    /* bind to interface */
    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    if (find_interface_ip(cfg->iface, &bind_addr) != 0) {
        fprintf(stderr, "Cannot find interface '%s'\n", cfg->iface);
        RAW_CLOSE(ctx->sock);
        free(ctx);
        return NULL;
    }

    if (bind(ctx->sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) != 0) {
        fprintf(stderr, "bind() failed: %d\n", WSAGetLastError());
        RAW_CLOSE(ctx->sock);
        free(ctx);
        return NULL;
    }

    /* enable promiscuous capture */
    DWORD rcvall = RCVALL_ON;
    DWORD ret_bytes = 0;
    if (WSAIoctl(ctx->sock, SIO_RCVALL, &rcvall, sizeof(rcvall),
                 NULL, 0, &ret_bytes, NULL, NULL) != 0) {
        fprintf(stderr, "SIO_RCVALL failed: %d\n", WSAGetLastError());
        fprintf(stderr, "Hint: run as Administrator.\n");
        RAW_CLOSE(ctx->sock);
        free(ctx);
        return NULL;
    }

    /* receive timeout for the capture loop */
    DWORD tv_ms = 100;
    setsockopt(ctx->sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv_ms, sizeof(tv_ms));

    ctx->has_eth = 0; /* Windows raw socket gives IP headers only */
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &bind_addr.sin_addr, ip_str, sizeof(ip_str));
    snprintf(ctx->iface_name, sizeof(ctx->iface_name), "%s",
             cfg->iface[0] ? cfg->iface : ip_str);

#elif defined(__linux__)
    /* ── Linux: AF_PACKET + SOCK_RAW ────────────────────────── */
    ctx->sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (ctx->sock == RAW_INVALID) {
        fprintf(stderr, "socket(AF_PACKET) failed. ");
        if (getuid() != 0)
            fprintf(stderr, "Hint: run with sudo or set CAP_NET_RAW.\n");
        else
            perror("");
        free(ctx);
        return NULL;
    }

    /* bind to specific interface if requested */
    if (cfg->iface[0]) {
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        snprintf(ifr.ifr_name, IFNAMSIZ, "%s", cfg->iface);
        if (setsockopt(ctx->sock, SOL_SOCKET, SO_BINDTODEVICE,
                       &ifr, sizeof(ifr)) != 0) {
            perror("SO_BINDTODEVICE");
            RAW_CLOSE(ctx->sock);
            free(ctx);
            return NULL;
        }
        snprintf(ctx->iface_name, sizeof(ctx->iface_name), "%s", cfg->iface);
    } else {
        snprintf(ctx->iface_name, sizeof(ctx->iface_name), "any");
    }

    /* set promiscuous mode if requested */
    if (cfg->promisc && cfg->iface[0]) {
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        snprintf(ifr.ifr_name, IFNAMSIZ, "%s", cfg->iface);
        if (ioctl(ctx->sock, SIOCGIFFLAGS, &ifr) == 0) {
            ifr.ifr_flags |= IFF_PROMISC;
            ioctl(ctx->sock, SIOCSIFFLAGS, &ifr);
        }
    }

    /* receive timeout */
    struct timeval tv = { .tv_sec = 0, .tv_usec = 100000 };
    setsockopt(ctx->sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    ctx->has_eth = 1; /* AF_PACKET gives full Ethernet frames */

#else
    /* ── macOS / other: not supported without libpcap ────────── */
    fprintf(stderr, "Raw socket capture is not supported on this platform.\n"
                    "Build without -DNO_PCAP to use the libpcap backend.\n");
    free(ctx);
    return NULL;
#endif

    /* open syslog output if configured */
    if (cfg->syslog_target[0]) {
        ctx->syslog = syslog_out_create(cfg->syslog_target, cfg->syslog_iface);
        if (!ctx->syslog)
            fprintf(stderr, "Warning: syslog output disabled\n");
    }

    return ctx;
}

int capture_start(capture_ctx_t *ctx) {
    ctx->stop_req = 0;
    ctx->running  = 1;
    if (ns_thread_create(&ctx->thread, capture_thread_fn, ctx) != 0) {
        ctx->running = 0;
        fprintf(stderr, "Failed to create capture thread\n");
        return -1;
    }
    return 0;
}

void capture_stop(capture_ctx_t *ctx) {
    if (!ctx) return;
    ctx->stop_req = 1;
    ns_thread_join(ctx->thread);
}

void capture_destroy(capture_ctx_t *ctx) {
    if (!ctx) return;
    syslog_out_destroy(ctx->syslog);
    if (ctx->sock != RAW_INVALID)
        RAW_CLOSE(ctx->sock);
#ifdef _WIN32
    WSACleanup();
#endif
    free(ctx);
}

int capture_is_running(const capture_ctx_t *ctx) {
    return ctx ? ctx->running : 0;
}

int capture_is_offline(const capture_ctx_t *ctx) {
    (void)ctx;
    return 0; /* raw sockets are always live */
}

void capture_get_stats(capture_ctx_t *ctx, capture_stats_raw_t *out) {
    memset(out, 0, sizeof(*out));
    if (!ctx) return;
    out->pkts_recv = ctx->pkt_count;
}

const char *capture_get_iface(const capture_ctx_t *ctx) {
    return ctx ? ctx->iface_name : "???";
}

const char *capture_get_bpf(const capture_ctx_t *ctx) {
    return ctx ? ctx->bpf_expr : "";
}

int capture_set_bpf(capture_ctx_t *ctx, const char *expr,
                    char *errbuf, size_t errlen) {
    if (!ctx) {
        snprintf(errbuf, errlen, "No capture context");
        return -1;
    }
    /* Raw socket backend doesn't support kernel BPF.
     * Store the expression — the UI display filter handles filtering. */
    snprintf(ctx->bpf_expr, sizeof(ctx->bpf_expr), "%s", expr ? expr : "");
    snprintf(errbuf, errlen, "Note: BPF not available in raw socket mode. Use display filter [F].");
    return -1;
}

int capture_list_interfaces(void) {
#ifdef _WIN32
    ULONG buflen = 15000;
    PIP_ADAPTER_ADDRESSES addrs = malloc(buflen);
    if (!addrs) return -1;

    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    if (GetAdaptersAddresses(AF_INET, 0, NULL, addrs, &buflen) != NO_ERROR) {
        fprintf(stderr, "GetAdaptersAddresses failed\n");
        free(addrs);
        return -1;
    }

    int idx = 0;
    for (PIP_ADAPTER_ADDRESSES a = addrs; a; a = a->Next) {
        if (a->OperStatus != IfOperStatusUp) continue;
        char name[256];
        WideCharToMultiByte(CP_UTF8, 0, a->FriendlyName, -1, name, sizeof(name), NULL, NULL);
        printf("%d. %s", ++idx, name);
        if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) printf(" [Loopback]");
        printf(" [Up]");
        for (PIP_ADAPTER_UNICAST_ADDRESS u = a->FirstUnicastAddress; u; u = u->Next) {
            if (u->Address.lpSockaddr->sa_family == AF_INET) {
                struct sockaddr_in *sin = (struct sockaddr_in *)u->Address.lpSockaddr;
                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
                printf(" %s", ip);
            }
        }
        printf("\n");
    }
    if (idx == 0) printf("No interfaces found.\n");
    free(addrs);
    WSACleanup();
    return 0;

#elif defined(__linux__)
    struct if_nameindex *ifs = if_nameindex();
    if (!ifs) { perror("if_nameindex"); return -1; }
    int idx = 0;
    for (struct if_nameindex *i = ifs; i->if_index != 0; i++) {
        printf("%d. %s\n", ++idx, i->if_name);
    }
    if (idx == 0) printf("No interfaces found.\n");
    if_freenameindex(ifs);
    return 0;

#else
    printf("Interface listing requires libpcap on this platform.\n");
    return -1;
#endif
}
