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
 *
 * Linux receive path: recvmmsg() batches of RAW_BATCH frames into
 * preallocated buffers, kernel SO_TIMESTAMP per frame, socket receive
 * queue sized by -B (SO_RCVBUFFORCE while still root).
 */

#ifndef _GNU_SOURCE
  #define _GNU_SOURCE   /* recvmmsg, struct mmsghdr, MSG_WAITFORONE */
#endif

#include "capture.h"
#include "dissect.h"
#include "export_pcap.h"
#include "syslog_out.h"
#include <stdatomic.h>
#ifdef __linux__
  #include <sys/prctl.h>
#endif
#include <errno.h>
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
  #include <sys/uio.h>
  #include <sys/ioctl.h>
  #include <net/if.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #ifdef __linux__
    #include <netpacket/packet.h>
    #include <net/ethernet.h>
    #include <linux/filter.h>
    #include "cbpf.h"
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
    atomic_int          running;
    atomic_int          stop_req;
    int                 has_eth;    /* 1 if we get Ethernet headers (Linux AF_PACKET) */
    atomic_uint_fast64_t pkt_count;
    atomic_uint_fast64_t drops;         /* Linux PACKET_STATISTICS, cumulative */
    atomic_uint_fast64_t stream_pkts;   /* -w packets written */
    char                iface_name[64];
    char                bpf_expr[512]; /* stored but not kernel-applied */
    syslog_out_t       *syslog;
    pcap_writer_t      *stream;     /* -w: capture thread only */
#ifdef __linux__
    uint8_t            *bufs;       /* RAW_BATCH x bufsz recvmmsg buffers */
    uint32_t            bufsz;      /* max(snaplen, RAW_MIN_BUFSZ) */
#endif
};

#ifdef __linux__
  #define RAW_BATCH     64      /* frames per recvmmsg() */
  #define RAW_MIN_BUFSZ 2048    /* per-frame buffer floor (headers fit) */
#endif

/* ── Per-packet processing ───────────────────────────────────── */

/* Shared by the Linux recvmmsg loop and the recv() loop: pkt/caplen are
 * the bytes we hold, wirelen the on-the-wire length, ts the capture
 * timestamp. Returns 1 when the -c limit has been reached. */
static int process_packet(capture_ctx_t *ctx, const uint8_t *pkt,
                          uint32_t caplen, uint32_t wirelen,
                          struct timeval ts) {
    pkt_record_t *rec = ringbuf_producer_next(ctx->rb);

    uint32_t copylen = caplen;
    if (copylen > (uint32_t)ctx->cfg.snaplen)
        copylen = (uint32_t)ctx->cfg.snaplen;
    memcpy(rec->raw_data, pkt, copylen);
    rec->raw_len = copylen;

    /* dissect */
    if (ctx->has_eth) {
        /* Linux AF_PACKET: full Ethernet frame */
        dissect_packet(pkt, caplen, 1 /* DLT_EN10MB */, &rec->summary);
    } else {
        /* Windows raw socket: IP header only, no Ethernet.
         * Fake an Ethernet header isn't needed — just dissect from IP.
         * We call dissect with datalink=228 (DLT_IPV4) but our dissect
         * only handles DLT_EN10MB (1). So we manually call IPv4/IPv6. */
        memset(&rec->summary, 0, sizeof(rec->summary));
        if (caplen >= 1) {
            uint8_t ver = (pkt[0] >> 4) & 0x0F;
            if (ver == 4 && caplen >= 20) {
                /* manually extract IPs and call dissect chain */
                dissect_packet(pkt, caplen, 228 /* DLT_IPV4 */, &rec->summary);
            } else if (ver == 6 && caplen >= 40) {
                dissect_packet(pkt, caplen, 229 /* DLT_IPV6 */, &rec->summary);
            } else {
                snprintf(rec->summary.protocol, sizeof(rec->summary.protocol), "RAW");
                snprintf(rec->summary.info, sizeof(rec->summary.info),
                         "Raw IP (ver=%d, len=%u)", ver, caplen);
            }
        }
    }
    rec->summary.length = wirelen;
    rec->summary.ts     = ts;

    /* session tracking (TCP payload bytes clamped to what we copied) */
    if (ctx->st) {
        const uint8_t *pl = NULL;
        uint32_t pln = 0;
        if (rec->summary.l4_proto == PROTO_TCP && rec->summary.l7_len > 0 &&
            rec->summary.l7_off < rec->raw_len) {
            pl  = rec->raw_data + rec->summary.l7_off;
            pln = rec->summary.l7_len;
            if (pln > rec->raw_len - rec->summary.l7_off)
                pln = rec->raw_len - rec->summary.l7_off;
        }
        uint32_t sid = session_table_update(ctx->st, &rec->summary, pl, pln);
        if (sid) rec->summary.session_id = sid;
    }

    /* syslog output (skip own traffic to prevent feedback loop) */
    if (ctx->syslog && !syslog_out_is_self(ctx->syslog, &rec->summary))
        syslog_out_send(ctx->syslog, &rec->summary);

    /* streaming -w write (before commit: the slot is still ours) */
    if (ctx->stream) {
        if (pcap_writer_write(ctx->stream, rec) != 0) {
            fprintf(stderr, "stream write failed; disabling -w output\n");
            pcap_writer_close(ctx->stream);
            ctx->stream = NULL;
        } else {
            atomic_fetch_add_explicit(&ctx->stream_pkts, 1, memory_order_relaxed);
        }
    }

    ringbuf_producer_commit(ctx->rb);

    uint64_t n = atomic_fetch_add(&ctx->pkt_count, 1) + 1;
    return ctx->cfg.count > 0 && n >= (uint64_t)ctx->cfg.count;
}

/* ── Capture thread ──────────────────────────────────────────── */

#ifdef __linux__

/* Kernel-side drop counter. PACKET_STATISTICS resets on every read, so
 * accumulate. Polled on idle timeouts and every ~4096 packets to keep
 * the syscall off the per-packet path. */
static void poll_kernel_drops(capture_ctx_t *ctx) {
    struct { unsigned int tp_packets, tp_drops; } st; /* struct tpacket_stats */
    socklen_t sl = sizeof(st);
    if (getsockopt(ctx->sock, SOL_PACKET, PACKET_STATISTICS, &st, &sl) == 0)
        atomic_fetch_add(&ctx->drops, (uint64_t)st.tp_drops);
}

/* SO_TIMESTAMP delivers the kernel receive time as an SCM_TIMESTAMP
 * control message. Returns 1 and fills *ts if present. */
static int cmsg_timestamp(struct msghdr *mh, struct timeval *ts) {
    for (struct cmsghdr *c = CMSG_FIRSTHDR(mh); c; c = CMSG_NXTHDR(mh, c)) {
        if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_TIMESTAMP &&
            c->cmsg_len >= CMSG_LEN(sizeof(struct timeval))) {
            memcpy(ts, CMSG_DATA(c), sizeof(*ts));
            return 1;
        }
    }
    return 0;
}

static void *capture_thread_fn(void *arg) {
    capture_ctx_t *ctx = (capture_ctx_t *)arg;
    atomic_store(&ctx->running, 1);
    prctl(PR_SET_NAME, "snf-capture", 0, 0, 0);

    /* recvmmsg batch: one iovec + one cmsg slot per preallocated buffer.
     * Everything is set up once; only msg_controllen (shrunk by the
     * kernel to what it filled) is restored per call. */
    struct mmsghdr msgs[RAW_BATCH];
    struct iovec   iov[RAW_BATCH];
    union {
        struct cmsghdr hdr;
        uint8_t        raw[CMSG_SPACE(sizeof(struct timeval))];
    } cmsg[RAW_BATCH];
    memset(msgs, 0, sizeof(msgs));
    for (int i = 0; i < RAW_BATCH; i++) {
        iov[i].iov_base = ctx->bufs + (size_t)i * ctx->bufsz;
        iov[i].iov_len  = ctx->bufsz;
        msgs[i].msg_hdr.msg_iov        = &iov[i];
        msgs[i].msg_hdr.msg_iovlen     = 1;
        msgs[i].msg_hdr.msg_control    = cmsg[i].raw;
        msgs[i].msg_hdr.msg_controllen = sizeof(cmsg[i].raw);
    }

    uint32_t since_poll = 0;

    while (!atomic_load(&ctx->stop_req)) {
        /* -c: never pull more frames from the kernel than we will keep */
        unsigned vlen = RAW_BATCH;
        if (ctx->cfg.count > 0) {
            uint64_t done = atomic_load_explicit(&ctx->pkt_count,
                                                 memory_order_relaxed);
            uint64_t left = (uint64_t)ctx->cfg.count - done;
            if (left < vlen) vlen = left ? (unsigned)left : 1u;
        }

        /* MSG_WAITFORONE: block (bounded by SO_RCVTIMEO, so stop_req is
         * still honoured) for the first frame, then drain whatever else
         * is queued without waiting — one syscall per burst, no added
         * latency at low rates. MSG_TRUNC: msg_len reports the wire
         * length even when the frame was cut to the buffer. */
        int n = recvmmsg(ctx->sock, msgs, vlen, MSG_WAITFORONE | MSG_TRUNC, NULL);
        int err = errno;   /* poll_kernel_drops() below may clobber it */

        if (n <= 0) {
            poll_kernel_drops(ctx);
            since_poll = 0;
            if (atomic_load(&ctx->stop_req)) break;
            if (n < 0 && err != EAGAIN && err != EWOULDBLOCK && err != EINTR) {
                struct timeval nap = { .tv_sec = 0, .tv_usec = 100000 };
                select(0, NULL, NULL, NULL, &nap);   /* hard error: don't spin */
            }
            continue;
        }

        struct timeval now = { 0, 0 };
        int have_now = 0, done = 0;
        for (int i = 0; i < n && !done; i++) {
            struct msghdr *mh = &msgs[i].msg_hdr;
            uint32_t wirelen = msgs[i].msg_len;
            uint32_t caplen  = wirelen > ctx->bufsz ? ctx->bufsz : wirelen;

            struct timeval ts;
            if (!cmsg_timestamp(mh, &ts)) {
                if (!have_now) { gettimeofday(&now, NULL); have_now = 1; }
                ts = now;
            }
            mh->msg_controllen = sizeof(cmsg[i].raw);

            if (caplen == 0) continue;   /* mirrors recv() == 0 */
            done = process_packet(ctx, (const uint8_t *)iov[i].iov_base,
                                  caplen, wirelen, ts);
        }
        if (done) break;

        since_poll += (uint32_t)n;
        if (since_poll >= 4096) {
            poll_kernel_drops(ctx);
            since_poll = 0;
        }
    }

    /* final read so a -c run's summary carries the drops since the last
     * 4096-frame poll (up to a few thousand under load) */
    poll_kernel_drops(ctx);

    atomic_store(&ctx->running, 0);
    return NULL;
}

#else /* !__linux__ */

static void *capture_thread_fn(void *arg) {
    capture_ctx_t *ctx = (capture_ctx_t *)arg;
    atomic_store(&ctx->running, 1);

    uint8_t buf[65536];

    while (!atomic_load(&ctx->stop_req)) {
        /* SO_RCVTIMEO (set in capture_create) bounds this so stop_req is
         * checked periodically */
        int len = (int)recv(ctx->sock, (char *)buf, sizeof(buf), 0);
        if (len <= 0) {
            if (atomic_load(&ctx->stop_req)) break;
#ifdef _WIN32
            if (len < 0 && WSAGetLastError() != WSAETIMEDOUT)
                Sleep(100);              /* hard error: don't busy-spin */
#else
            if (len < 0 && errno != EAGAIN && errno != EWOULDBLOCK &&
                errno != EINTR) {
                struct timeval nap = { .tv_sec = 0, .tv_usec = 100000 };
                select(0, NULL, NULL, NULL, &nap);
            }
#endif
            continue; /* timeout or error */
        }

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
        if (process_packet(ctx, buf, (uint32_t)len, (uint32_t)len, tv))
            break;
    }

    atomic_store(&ctx->running, 0);
    return NULL;
}

#endif /* __linux__ */

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

    if (cfg->bpf_filter[0])
        fprintf(stderr, "Warning: -f is not supported by the Windows raw "
                        "backend; capturing unfiltered\n");

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

    /* bind to specific interface if requested. AF_PACKET ignores
     * SO_BINDTODEVICE for delivery (it only sets sk_bound_dev_if, which
     * packet_rcv never checks) — the socket must be bound to the ifindex
     * with sockaddr_ll, otherwise -i captures every interface. */
    if (cfg->iface[0]) {
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family   = AF_PACKET;
        sll.sll_protocol = htons(ETH_P_ALL);
        sll.sll_ifindex  = (int)if_nametoindex(cfg->iface);
        if (sll.sll_ifindex == 0) {
            fprintf(stderr, "Cannot find interface '%s'\n", cfg->iface);
            RAW_CLOSE(ctx->sock);
            free(ctx);
            return NULL;
        }
        if (bind(ctx->sock, (struct sockaddr *)&sll, sizeof(sll)) != 0) {
            perror("bind(AF_PACKET)");
            RAW_CLOSE(ctx->sock);
            free(ctx);
            return NULL;
        }
        snprintf(ctx->iface_name, sizeof(ctx->iface_name), "%s", cfg->iface);
    } else {
        snprintf(ctx->iface_name, sizeof(ctx->iface_name), "any");
    }

    /* Promiscuous mode via PACKET_ADD_MEMBERSHIP: the kernel reference-
     * counts it and clears it when the socket closes. (SIOCSIFFLAGS left
     * the interface promiscuous forever after exit, and restoring it
     * ourselves is impossible once privileges are dropped.) */
    if (cfg->promisc && cfg->iface[0]) {
        struct packet_mreq mr;
        memset(&mr, 0, sizeof(mr));
        mr.mr_ifindex = (int)if_nametoindex(cfg->iface);
        mr.mr_type    = PACKET_MR_PROMISC;
        if (mr.mr_ifindex == 0 ||
            setsockopt(ctx->sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
                       &mr, sizeof(mr)) != 0)
            fprintf(stderr, "Warning: could not enable promiscuous mode on %s\n",
                    cfg->iface);
    }

    /* Socket receive queue (-B). The default, net.core.rmem_default
     * (~208 KB), holds only ~100 small frames, so any consumer hiccup
     * drops packets. SO_RCVBUFFORCE ignores net.core.rmem_max but needs
     * CAP_NET_ADMIN, which we still hold before the privilege drop; fall
     * back to SO_RCVBUF (silently capped at rmem_max) otherwise. */
    {
        int want = cfg->buffer_mb * 1024 * 1024;
        if (setsockopt(ctx->sock, SOL_SOCKET, SO_RCVBUFFORCE,
                       &want, sizeof(want)) != 0)
            (void)setsockopt(ctx->sock, SOL_SOCKET, SO_RCVBUF,
                             &want, sizeof(want));
        int got = 0;
        socklen_t gl = sizeof(got);
        if (getsockopt(ctx->sock, SOL_SOCKET, SO_RCVBUF, &got, &gl) == 0) {
            /* the kernel reports double the requested size (bookkeeping) */
            long got_kb = (long)got / 2 / 1024;
            int  got_mb = (int)((got_kb + 512) / 1024);
            if (got_mb < cfg->buffer_mb) {
                if (got_mb >= 1)
                    fprintf(stderr, "Warning: kernel capped the capture buffer "
                            "at %d MiB (-B %d); raise net.core.rmem_max or run "
                            "as root\n", got_mb, cfg->buffer_mb);
                else    /* default rmem_max (208 KiB) lands here */
                    fprintf(stderr, "Warning: kernel capped the capture buffer "
                            "at %ld KiB (-B %d); raise net.core.rmem_max or run "
                            "as root\n", got_kb, cfg->buffer_mb);
            }
        }
    }

    /* kernel receive timestamps as SCM_TIMESTAMP cmsg (else gettimeofday) */
    int one = 1;
    (void)setsockopt(ctx->sock, SOL_SOCKET, SO_TIMESTAMP, &one, sizeof(one));

    /* recvmmsg batch buffers: RAW_BATCH x max(snaplen, RAW_MIN_BUFSZ) */
    ctx->bufsz = (uint32_t)cfg->snaplen;
    if (ctx->bufsz < RAW_MIN_BUFSZ) ctx->bufsz = RAW_MIN_BUFSZ;
    ctx->bufs = malloc((size_t)RAW_BATCH * ctx->bufsz);
    if (!ctx->bufs) {
        fprintf(stderr, "Cannot allocate receive buffers (%u x %u bytes)\n",
                RAW_BATCH, ctx->bufsz);
        RAW_CLOSE(ctx->sock);
        free(ctx);
        return NULL;
    }

    /* receive timeout */
    struct timeval tv = { .tv_sec = 0, .tv_usec = 100000 };
    setsockopt(ctx->sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* -f: compile the subset syntax to classic BPF and attach in-kernel */
    if (cfg->bpf_filter[0]) {
        cbpf_insn_t insns[CBPF_MAX_INSNS];
        char cerr[128];
        int n = cbpf_compile(cfg->bpf_filter, insns, CBPF_MAX_INSNS,
                             cerr, sizeof(cerr));
        if (n < 0) {
            fprintf(stderr, "BPF (raw build): %s\n"
                    "Supported: tcp/udp/icmp/sctp/ip/arp, [src|dst] host A.B.C.D, "
                    "[src|dst] port N, joined with 'and'\n", cerr);
            RAW_CLOSE(ctx->sock);
            free(ctx->bufs);
            free(ctx);
            return NULL;
        }
        struct sock_fprog prog = {
            .len    = (unsigned short)n,
            .filter = (struct sock_filter *)insns,
        };
        if (setsockopt(ctx->sock, SOL_SOCKET, SO_ATTACH_FILTER,
                       &prog, sizeof(prog)) != 0) {
            perror("SO_ATTACH_FILTER");
            RAW_CLOSE(ctx->sock);
            free(ctx->bufs);
            free(ctx);
            return NULL;
        }
        snprintf(ctx->bpf_expr, sizeof(ctx->bpf_expr), "%s", cfg->bpf_filter);
    }

    ctx->has_eth = 1; /* AF_PACKET gives full Ethernet frames */

#else
    /* ── macOS / other: not supported without libpcap ────────── */
    fprintf(stderr, "Raw socket capture is not supported on this platform.\n"
                    "Build without -DNO_PCAP to use the libpcap backend.\n");
    free(ctx);
    return NULL;
#endif

    /* drop root privileges now that the raw socket is open */
#ifndef _WIN32
    if (ns_drop_privileges() != 0)
        fprintf(stderr, "Warning: failed to drop root privileges; "
                        "continuing as root\n");
#endif

    /* open syslog output if configured */
    if (cfg->syslog_target[0]) {
        ctx->syslog = syslog_out_create(cfg->syslog_target, cfg->syslog_iface);
        if (!ctx->syslog)
            fprintf(stderr, "Warning: syslog output disabled\n");
    }

    /* streaming -w writer (after the privilege drop: file owned by user) */
    if (cfg->stream_file[0]) {
        ctx->stream = pcap_writer_open(cfg->stream_file, (uint32_t)cfg->snaplen,
                                       ctx->has_eth ? 1u : 101u /* DLT_RAW */);
        if (!ctx->stream)
            fprintf(stderr, "Warning: cannot open '%s' for -w streaming\n",
                    cfg->stream_file);
    }

    return ctx;
}

int capture_start(capture_ctx_t *ctx) {
    atomic_store(&ctx->stop_req, 0);
    atomic_store(&ctx->running, 1);
    if (ns_thread_create(&ctx->thread, capture_thread_fn, ctx) != 0) {
        atomic_store(&ctx->running, 0);
        fprintf(stderr, "Failed to create capture thread\n");
        return -1;
    }
    return 0;
}

void capture_stop(capture_ctx_t *ctx) {
    if (!ctx) return;
    atomic_store(&ctx->stop_req, 1);
    ns_thread_join(ctx->thread);
}

void capture_destroy(capture_ctx_t *ctx) {
    if (!ctx) return;
    if (ctx->stream) {
        uint64_t n = pcap_writer_count(ctx->stream);
        if (pcap_writer_close(ctx->stream) != 0)
            fprintf(stderr, "Warning: error finalizing -w stream file\n");
        else
            fprintf(stderr, "Streamed %llu packets to %s\n",
                    (unsigned long long)n, ctx->cfg.stream_file);
        ctx->stream = NULL;
    }
    syslog_out_destroy(ctx->syslog);
    if (ctx->sock != RAW_INVALID)
        RAW_CLOSE(ctx->sock);
#ifdef __linux__
    free(ctx->bufs);
#endif
#ifdef _WIN32
    WSACleanup();
#endif
    free(ctx);
}

int capture_is_running(const capture_ctx_t *ctx) {
    return ctx ? atomic_load(&ctx->running) : 0;
}

int capture_is_offline(const capture_ctx_t *ctx) {
    (void)ctx;
    return 0; /* raw sockets are always live */
}

int capture_had_error(const capture_ctx_t *ctx) {
    (void)ctx;
    return 0;   /* raw backend treats socket errors as transient */
}

const char *capture_error_msg(const capture_ctx_t *ctx) {
    (void)ctx;
    return "";
}

int capture_get_datalink(const capture_ctx_t *ctx) {
    /* Linux AF_PACKET delivers Ethernet frames; the Windows raw socket
     * delivers bare IP packets (DLT_RAW). */
    return (ctx && ctx->has_eth) ? 1 : 101;
}

void capture_get_stats(capture_ctx_t *ctx, capture_stats_raw_t *out) {
    memset(out, 0, sizeof(*out));
    if (!ctx) return;
    out->pkts_recv   = atomic_load(&ctx->pkt_count);
    out->pkts_drop   = atomic_load(&ctx->drops);
    out->stream_pkts = atomic_load_explicit(&ctx->stream_pkts, memory_order_relaxed);
    syslog_out_counts(ctx->syslog, &out->syslog_sent, &out->syslog_failed);
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
#ifdef __linux__
    if (!expr || !expr[0]) {
        int dummy = 0;
        /* detaching with nothing attached returns ENOENT; that's fine */
        (void)setsockopt(ctx->sock, SOL_SOCKET, SO_DETACH_FILTER,
                         &dummy, sizeof(dummy));
        ctx->bpf_expr[0] = '\0';
        return 0;
    }
    cbpf_insn_t insns[CBPF_MAX_INSNS];
    char cerr[128];
    int n = cbpf_compile(expr, insns, CBPF_MAX_INSNS, cerr, sizeof(cerr));
    if (n < 0) {
        snprintf(errbuf, errlen, "%s (subset: proto, host, port, 'and')", cerr);
        return -1;
    }
    struct sock_fprog prog = {
        .len    = (unsigned short)n,
        .filter = (struct sock_filter *)insns,
    };
    if (setsockopt(ctx->sock, SOL_SOCKET, SO_ATTACH_FILTER,
                   &prog, sizeof(prog)) != 0) {
        snprintf(errbuf, errlen, "SO_ATTACH_FILTER failed");
        return -1;
    }
    snprintf(ctx->bpf_expr, sizeof(ctx->bpf_expr), "%s", expr);
    return 0;
#else
    (void)expr;
    snprintf(errbuf, errlen,
             "BPF needs Linux in the raw build. Use display filter [F].");
    return -1;
#endif
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
