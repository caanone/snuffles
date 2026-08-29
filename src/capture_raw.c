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
 * Linux receive path: a PACKET_RX_RING in TPACKET_V3 mode mapped into the
 * process — the kernel packs frames into 256 KiB blocks sized by -B and
 * wakes us once per block (10 ms retire timeout), so the per-packet cost
 * is the dissection, not syscalls. When the ring cannot be set up (old
 * kernel, ENOMEM), or --immediate asks for per-packet delivery, it uses
 * recvmmsg() batches of RAW_BATCH frames with kernel SO_TIMESTAMP and a
 * socket receive queue sized by -B (SO_RCVBUFFORCE while still root).
 */

#ifndef _GNU_SOURCE
  #define _GNU_SOURCE   /* recvmmsg, struct mmsghdr, MSG_WAITFORONE */
#endif

#include "capture.h"
#include "dissect.h"
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
    #include <linux/if_packet.h>   /* sockaddr_ll + TPACKET_V3 ring structs */
    #include <net/ethernet.h>
    #include <linux/filter.h>
    #include <sys/mman.h>
    #include <poll.h>
    #include <limits.h>
    #include "cbpf.h"
    #include "rawring.h"
  #endif

  typedef int raw_sock_t;
  #define RAW_INVALID (-1)
  #define RAW_CLOSE(s) close(s)
#endif

/* ── Context ─────────────────────────────────────────────────── */

/* One capture worker: its own socket (its own kernel ring / receive
 * queue), its own session table shard and its own thread. With -j 1
 * there is exactly one and everything below behaves as it did before. */
typedef struct capture_worker {
    struct capture_ctx *ctx;
    int                 idx;
    raw_sock_t          sock;
    session_table_t    *st;
    ns_thread_t         thread;
    int                 started;
    uint64_t            budget;         /* -c tally, single worker only */
    int                 last_pkt;       /* -c reached on this packet */
    atomic_uint_fast64_t pkt_count;
    atomic_uint_fast64_t drops;         /* Linux PACKET_STATISTICS, cumulative */
#ifdef __linux__
    /* TPACKET_V3 block ring (NULL when the recvmmsg fallback is in use) */
    uint8_t            *ring;
    size_t              ring_len;
    rawring_geom_t      geom;
    uint32_t            ring_cur;   /* next block to consume (capture thread) */
    /* recvmmsg fallback */
    uint8_t            *bufs;       /* RAW_BATCH x bufsz recvmmsg buffers */
    uint32_t            bufsz;      /* max(snaplen, RAW_MIN_BUFSZ) */
#endif
} capture_worker_t;

struct capture_ctx {
    ringbuf_t          *rb;
    capture_cfg_t       cfg;
    capture_worker_t    w[CAPTURE_MAX_WORKERS];
    int                 nworkers;
    atomic_int          running;    /* worker threads still in their loop */
    atomic_int          stop_req;
    atomic_uint_fast64_t budget;    /* -c across workers */
    int                 has_eth;    /* 1 if we get Ethernet headers (Linux AF_PACKET) */
    char                iface_name[64];
    char                bpf_expr[512]; /* stored but not kernel-applied */
#ifdef __linux__
    int                 lo_ifindex; /* loopback: skip its PACKET_OUTGOING copies */
#endif
};

#ifdef __linux__
  #define RAW_BATCH     64      /* frames per recvmmsg() */
  #define RAW_MIN_BUFSZ 2048    /* per-frame buffer floor (headers fit) */
#endif

/* ── Per-packet processing ───────────────────────────────────── */

/* Shared by the Linux ring and recvmmsg loops and the recv() loop:
 * pkt/caplen are the bytes we hold (the dissector sees all of them; the
 * kernel filter already cut a Linux frame to snaplen, and at most snaplen
 * bytes are copied into the ring slot in any case), wirelen the
 * on-the-wire length, ts the capture timestamp. Returns 1 when the -c
 * limit has been reached. */
/* Ask for room for one more packet under -c (see capture.c). */
static int take_budget(capture_ctx_t *ctx, capture_worker_t *w) {
    if (ctx->cfg.count <= 0) return 1;
    uint64_t n = (ctx->nworkers > 1)
        ? atomic_fetch_add_explicit(&ctx->budget, 1, memory_order_relaxed) + 1
        : ++w->budget;
    if (n > (uint64_t)ctx->cfg.count) return 0;
    if (n == (uint64_t)ctx->cfg.count) w->last_pkt = 1;
    return 1;
}

static int process_packet(capture_worker_t *w, const uint8_t *pkt,
                          uint32_t caplen, uint32_t wirelen,
                          struct timeval ts) {
    capture_ctx_t *ctx = w->ctx;

    if (!take_budget(ctx, w)) {
        atomic_store(&ctx->stop_req, 1);
        return 1;
    }

    /* claim a slot and arena space, copy the raw bytes (granted length is
     * min(caplen, snaplen)) */
    pkt_record_t *rec = ringbuf_producer_next_w(ctx->rb, w->idx, caplen);
    memcpy(rec->raw_data, pkt, rec->raw_len);

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
                rec->summary.proto_label  = LABEL_RAW;
                rec->summary.info_kind    = INFO_RAWIP;
                rec->summary.u.rawip.ver  = ver;
                rec->summary.u.rawip.len  = caplen;
                rec->summary.text_pending = 1;
            }
        }
    }
    rec->summary.length = wirelen;
    rec->summary.ts     = ts;

    /* session tracking on this worker's shard (TCP payload bytes clamped
     * to what we copied) */
    if (w->st) {
        const uint8_t *pl = NULL;
        uint32_t pln = 0;
        if (rec->summary.l4_proto == PROTO_TCP && rec->summary.l7_len > 0 &&
            rec->summary.l7_off < rec->raw_len) {
            pl  = rec->raw_data + rec->summary.l7_off;
            pln = rec->summary.l7_len;
            if (pln > rec->raw_len - rec->summary.l7_off)
                pln = rec->raw_len - rec->summary.l7_off;
        }
        uint32_t sid = session_table_update(w->st, &rec->summary, pl, pln);
        if (sid) rec->summary.session_id = sid;
    }

    /* --syslog and -w are served by the output thread from the ring */
    ringbuf_producer_commit_w(ctx->rb, w->idx);

    atomic_fetch_add_explicit(&w->pkt_count, 1, memory_order_relaxed);
    if (w->last_pkt) atomic_store(&ctx->stop_req, 1);
    return w->last_pkt;
}

/* ── Capture thread ──────────────────────────────────────────── */

#ifdef __linux__

/* Kernel-side drop counter. PACKET_STATISTICS resets on every read, so
 * accumulate. Polled on idle timeouts and every ~4096 packets to keep
 * the syscall off the per-packet path. */
static void poll_kernel_drops(capture_worker_t *w) {
    struct { unsigned int tp_packets, tp_drops; } st; /* struct tpacket_stats */
    socklen_t sl = sizeof(st);
    if (getsockopt(w->sock, SOL_PACKET, PACKET_STATISTICS, &st, &sl) == 0)
        atomic_fetch_add(&w->drops, (uint64_t)st.tp_drops);
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

/* Sleep the capture thread for 100 ms after a hard error so it does not
 * spin on a socket that keeps failing. */
static void error_nap(void) {
    struct timeval nap = { .tv_sec = 0, .tv_usec = 100000 };
    select(0, NULL, NULL, NULL, &nap);
}

/* ── TPACKET_V3 block ring ───────────────────────────────────── */

typedef struct {
    capture_worker_t *w;
    int               done;    /* -c reached inside the block */
} ring_walk_t;

/* A frame sent over the loopback interface is seen twice — once as
 * PACKET_OUTGOING on transmit and again as PACKET_HOST when lo delivers
 * it. Keep the incoming copy only, as libpcap does. */
static inline int lo_outgoing(const capture_ctx_t *ctx, int ifindex,
                              uint8_t pkttype) {
    return pkttype == PACKET_OUTGOING && ifindex == ctx->lo_ifindex;
}

static int ring_frame_cb(void *user, const rawring_frame_t *f) {
    ring_walk_t *rw = (ring_walk_t *)user;
    if (f->caplen == 0) return 0;   /* mirrors recv() == 0 */
    if (lo_outgoing(rw->w->ctx, f->ifindex, f->pkttype)) return 0;
    struct timeval ts = { .tv_sec  = (time_t)f->sec,
                          .tv_usec = (suseconds_t)(f->nsec / 1000u) };
    rw->done = process_packet(rw->w, f->data, f->caplen, f->wirelen, ts);
    return rw->done;
}

static inline struct tpacket_block_desc *ring_block(capture_worker_t *w,
                                                    uint32_t idx) {
    return (struct tpacket_block_desc *)
           (w->ring + (size_t)idx * w->geom.block_size);
}

/* Block status is written by the kernel (close: TP_STATUS_USER) and by us
 * (release: TP_STATUS_KERNEL); acquire/release keeps the frame reads
 * inside that window on weakly ordered CPUs. */
static inline uint32_t ring_block_status(struct tpacket_block_desc *bd) {
    return __atomic_load_n(&bd->hdr.bh1.block_status, __ATOMIC_ACQUIRE);
}

static inline void ring_block_release(struct tpacket_block_desc *bd) {
    __atomic_store_n(&bd->hdr.bh1.block_status, TP_STATUS_KERNEL,
                     __ATOMIC_RELEASE);
}

/* Hand back every block the kernel has already closed (nothing in them
 * is processed). Used once after setup, before the real filter goes on,
 * so frames that slipped in unfiltered never reach the consumer. Blocks
 * close in ring order, so the consume cursor simply follows. */
static void ring_drain(capture_worker_t *w) {
    for (uint32_t i = 0; i < w->geom.block_nr; i++) {
        struct tpacket_block_desc *bd = ring_block(w, w->ring_cur);
        if (!(ring_block_status(bd) & TP_STATUS_USER)) break;
        ring_block_release(bd);
        w->ring_cur = (w->ring_cur + 1 == w->geom.block_nr)
                        ? 0 : w->ring_cur + 1;
    }
}

/* One poll() per block: the kernel closes a block when it is full or
 * RAWRING_RETIRE_MS after its first frame, and poll(POLLIN) reports the
 * most recently closed block until we release it. Everything else —
 * timestamps, wire and captured lengths — is read out of the mapping. */
static void ring_loop(capture_worker_t *w) {
    capture_ctx_t *ctx = w->ctx;
    struct pollfd pfd = { .fd = w->sock, .events = POLLIN, .revents = 0 };

    while (!atomic_load(&ctx->stop_req)) {
        struct tpacket_block_desc *bd = ring_block(w, w->ring_cur);
        if (!(ring_block_status(bd) & TP_STATUS_USER)) {
            /* nothing closed yet: wait (100 ms so stop_req is honoured) */
            pfd.revents = 0;
            int r = poll(&pfd, 1, 100);
            if (r == 0) {
                poll_kernel_drops(w);          /* idle: refresh counters */
            } else if (r < 0) {
                if (errno != EINTR) error_nap();
            } else if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
                /* e.g. the interface went down (ENETDOWN): fetch and clear
                 * the pending error, otherwise poll() returns at once
                 * forever. The socket keeps delivering when it comes back. */
                int e = 0;
                socklen_t el = sizeof(e);
                (void)getsockopt(w->sock, SOL_SOCKET, SO_ERROR, &e, &el);
                if (!(pfd.revents & POLLIN)) error_nap();
            }
            continue;
        }

        ring_walk_t rw = { .w = w, .done = 0 };
        rawring_walk_block((const uint8_t *)bd, w->geom.block_size,
                           ring_frame_cb, &rw);
        ring_block_release(bd);
        w->ring_cur = (w->ring_cur + 1 == w->geom.block_nr)
                        ? 0 : w->ring_cur + 1;

        /* end of block: refresh the drop counter — one syscall per block,
         * i.e. per ~1 500 small frames under load */
        poll_kernel_drops(w);
        if (rw.done) break;
    }
}

/* ── recvmmsg fallback ───────────────────────────────────────── */

static void recvmmsg_loop(capture_worker_t *w) {
    capture_ctx_t *ctx = w->ctx;
    /* recvmmsg batch: one iovec + one cmsg slot per preallocated buffer.
     * Everything is set up once; only msg_controllen (shrunk by the
     * kernel to what it filled) is restored per call. */
    struct mmsghdr msgs[RAW_BATCH];
    struct iovec   iov[RAW_BATCH];
    struct sockaddr_ll sll[RAW_BATCH];
    union {
        struct cmsghdr hdr;
        uint8_t        raw[CMSG_SPACE(sizeof(struct timeval))];
    } cmsg[RAW_BATCH];
    memset(msgs, 0, sizeof(msgs));
    memset(sll, 0, sizeof(sll));
    for (int i = 0; i < RAW_BATCH; i++) {
        iov[i].iov_base = w->bufs + (size_t)i * w->bufsz;
        iov[i].iov_len  = w->bufsz;
        msgs[i].msg_hdr.msg_iov        = &iov[i];
        msgs[i].msg_hdr.msg_iovlen     = 1;
        msgs[i].msg_hdr.msg_name       = &sll[i];
        msgs[i].msg_hdr.msg_namelen    = sizeof(sll[i]);
        msgs[i].msg_hdr.msg_control    = cmsg[i].raw;
        msgs[i].msg_hdr.msg_controllen = sizeof(cmsg[i].raw);
    }

    uint32_t since_poll = 0;

    while (!atomic_load(&ctx->stop_req)) {
        /* -c: never pull more frames from the kernel than we will keep
         * (the budget is shared once there is more than one worker) */
        unsigned vlen = RAW_BATCH;
        if (ctx->cfg.count > 0) {
            uint64_t done = ctx->nworkers > 1
                ? atomic_load_explicit(&ctx->budget, memory_order_relaxed)
                : w->budget;
            uint64_t left = done < (uint64_t)ctx->cfg.count
                          ? (uint64_t)ctx->cfg.count - done : 0;
            if (left < vlen) vlen = left ? (unsigned)left : 1u;
        }

        /* MSG_WAITFORONE: block (bounded by SO_RCVTIMEO, so stop_req is
         * still honoured) for the first frame, then drain whatever else
         * is queued without waiting — one syscall per burst, no added
         * latency at low rates. MSG_TRUNC: msg_len reports the wire
         * length even when the frame was cut to the buffer. */
        int n = recvmmsg(w->sock, msgs, vlen,
                         MSG_WAITFORONE | MSG_TRUNC, NULL);
        int err = errno;   /* poll_kernel_drops() below may clobber it */

        if (n <= 0) {
            poll_kernel_drops(w);
            since_poll = 0;
            if (atomic_load(&ctx->stop_req)) break;
            if (n < 0 && err != EAGAIN && err != EWOULDBLOCK && err != EINTR)
                error_nap();                     /* hard error: don't spin */
            continue;
        }

        struct timeval now = { 0, 0 };
        int have_now = 0, done = 0;
        for (int i = 0; i < n && !done; i++) {
            struct msghdr *mh = &msgs[i].msg_hdr;
            uint32_t wirelen = msgs[i].msg_len;
            uint32_t caplen  = wirelen > w->bufsz ? w->bufsz : wirelen;

            struct timeval ts;
            if (!cmsg_timestamp(mh, &ts)) {
                if (!have_now) { gettimeofday(&now, NULL); have_now = 1; }
                ts = now;
            }
            mh->msg_controllen = sizeof(cmsg[i].raw);
            int      ifindex = sll[i].sll_ifindex;
            uint8_t  pkttype = sll[i].sll_pkttype;
            mh->msg_namelen  = sizeof(sll[i]);

            if (caplen == 0) continue;   /* mirrors recv() == 0 */
            if (lo_outgoing(ctx, ifindex, pkttype)) continue;
            done = process_packet(w, (const uint8_t *)iov[i].iov_base,
                                  caplen, wirelen, ts);
        }
        if (done) break;

        since_poll += (uint32_t)n;
        if (since_poll >= 4096) {
            poll_kernel_drops(w);
            since_poll = 0;
        }
    }
}

static void *capture_thread_fn(void *arg) {
    capture_worker_t *w   = (capture_worker_t *)arg;
    capture_ctx_t    *ctx = w->ctx;
    if (ctx->nworkers > 1) {
        char name[16];
        snprintf(name, sizeof(name), "snf-cap%d", w->idx);
        prctl(PR_SET_NAME, name, 0, 0, 0);
    } else {
        prctl(PR_SET_NAME, "snf-capture", 0, 0, 0);
    }

    if (w->ring) ring_loop(w);
    else         recvmmsg_loop(w);

    /* final read so a -c run's summary carries the drops since the last
     * poll (up to a few thousand frames' worth under load) */
    poll_kernel_drops(w);

    atomic_fetch_sub(&ctx->running, 1);
    return NULL;
}

#else /* !__linux__ */

static void *capture_thread_fn(void *arg) {
    capture_worker_t *w   = (capture_worker_t *)arg;
    capture_ctx_t    *ctx = w->ctx;

    uint8_t buf[65536];

    while (!atomic_load(&ctx->stop_req)) {
        /* SO_RCVTIMEO (set in capture_create) bounds this so stop_req is
         * checked periodically */
        int len = (int)recv(w->sock, (char *)buf, sizeof(buf), 0);
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
        if (process_packet(w, buf, (uint32_t)len, (uint32_t)len, tv))
            break;
    }

    atomic_fetch_sub(&ctx->running, 1);
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

/* ── Linux socket setup helpers ──────────────────────────────── */

#ifdef __linux__

/* PACKET_RX_RING in TPACKET_V3 mode, about buffer_mb MiB of 256 KiB
 * blocks. On failure the socket is left without a ring (so recvmmsg still
 * works on it) and *why says what failed. */
static int ring_setup(capture_worker_t *w, char *why, size_t whylen) {
    capture_ctx_t *ctx = w->ctx;
    int ver = TPACKET_V3;
    if (setsockopt(w->sock, SOL_PACKET, PACKET_VERSION,
                   &ver, sizeof(ver)) != 0) {
        snprintf(why, whylen, "PACKET_VERSION: %s", strerror(errno));
        return -1;
    }
    w->ring_len = rawring_geometry(ctx->cfg.buffer_mb,
                                     sysconf(_SC_PAGESIZE), &w->geom);
    struct tpacket_req3 req;
    memset(&req, 0, sizeof(req));
    req.tp_block_size      = w->geom.block_size;
    req.tp_block_nr        = w->geom.block_nr;
    req.tp_frame_size      = w->geom.frame_size;
    req.tp_frame_nr        = w->geom.frame_nr;
    req.tp_retire_blk_tov  = RAWRING_RETIRE_MS;
    req.tp_sizeof_priv     = 0;
    req.tp_feature_req_word = 0;
    if (setsockopt(w->sock, SOL_PACKET, PACKET_RX_RING,
                   &req, sizeof(req)) != 0) {
        snprintf(why, whylen, "PACKET_RX_RING (%u x %u KiB): %s",
                 req.tp_block_nr, req.tp_block_size / 1024, strerror(errno));
        return -1;
    }
    void *m = mmap(NULL, w->ring_len, PROT_READ | PROT_WRITE, MAP_SHARED,
                   w->sock, 0);
    if (m == MAP_FAILED) {
        snprintf(why, whylen, "mmap(%zu MiB): %s", w->ring_len >> 20,
                 strerror(errno));
        /* release the ring, or the socket delivers into it instead of
         * the receive queue the fallback reads from */
        memset(&req, 0, sizeof(req));
        (void)setsockopt(w->sock, SOL_PACKET, PACKET_RX_RING,
                         &req, sizeof(req));
        return -1;
    }
    w->ring = (uint8_t *)m;
    w->ring_cur = 0;
    return 0;
}

static void ring_teardown(capture_worker_t *w) {
    if (!w->ring) return;
    munmap(w->ring, w->ring_len);
    w->ring = NULL;
}

/* Fallback when there is no ring: size the socket receive queue (-B)
 * and allocate the recvmmsg batch buffers. */
static int fallback_setup(capture_worker_t *w) {
    capture_ctx_t *ctx = w->ctx;
    const capture_cfg_t *cfg = &ctx->cfg;

    /* Socket receive queue (-B). The default, net.core.rmem_default
     * (~208 KB), holds only ~100 small frames, so any consumer hiccup
     * drops packets. SO_RCVBUFFORCE ignores net.core.rmem_max but needs
     * CAP_NET_ADMIN, which we still hold before the privilege drop; fall
     * back to SO_RCVBUF (silently capped at rmem_max) otherwise. */
    int want = cfg->buffer_mb * 1024 * 1024;
    if (setsockopt(w->sock, SOL_SOCKET, SO_RCVBUFFORCE,
                   &want, sizeof(want)) != 0)
        (void)setsockopt(w->sock, SOL_SOCKET, SO_RCVBUF,
                         &want, sizeof(want));
    int got = 0;
    socklen_t gl = sizeof(got);
    if (getsockopt(w->sock, SOL_SOCKET, SO_RCVBUF, &got, &gl) == 0) {
        /* the kernel reports double the requested size (bookkeeping) */
        long got_kb = (long)got / 2 / 1024;
        int  got_mb = (int)((got_kb + 512) / 1024);
        if (got_mb < cfg->buffer_mb && w->idx == 0) {
            /* Either rmem_max capped a non-root SO_RCVBUF, or the request
             * hit the kernel's own ceiling (INT_MAX/2 per socket, so the
             * doubled figure reads INT_MAX-1): only the former is fixable
             * by the user. */
            const char *hint = ((long)got / 2 >= INT_MAX / 2)
                ? "kernel limit"
                : "raise net.core.rmem_max or run as root";
            if (got_mb >= 1)
                fprintf(stderr, "Warning: kernel capped the capture buffer "
                        "at %d MiB (-B %d); %s\n", got_mb, cfg->buffer_mb,
                        hint);
            else    /* default rmem_max (208 KiB) lands here */
                fprintf(stderr, "Warning: kernel capped the capture buffer "
                        "at %ld KiB (-B %d); %s\n", got_kb, cfg->buffer_mb,
                        hint);
        }
    }

    /* kernel receive timestamps as SCM_TIMESTAMP cmsg (else gettimeofday) */
    int one = 1;
    (void)setsockopt(w->sock, SOL_SOCKET, SO_TIMESTAMP, &one, sizeof(one));

    /* recvmmsg batch buffers: RAW_BATCH x max(snaplen, RAW_MIN_BUFSZ) */
    w->bufsz = (uint32_t)cfg->snaplen;
    if (w->bufsz < RAW_MIN_BUFSZ) w->bufsz = RAW_MIN_BUFSZ;
    w->bufs = malloc((size_t)RAW_BATCH * w->bufsz);
    if (!w->bufs) {
        fprintf(stderr, "Cannot allocate receive buffers (%u x %u bytes)\n",
                RAW_BATCH, w->bufsz);
        return -1;
    }

    /* receive timeout so the loop can check stop_req */
    struct timeval tv = { .tv_sec = 0, .tv_usec = 100000 };
    setsockopt(w->sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    return 0;
}

/* Throw away whatever the socket holds: closed ring blocks, or the
 * receive queue on the fallback path. */
static void drain_socket(capture_worker_t *w) {
    if (w->ring) {
        ring_drain(w);
        return;
    }
    uint8_t b;
    for (long i = 0; i < 1000000; i++)
        if (recv(w->sock, &b, 1, MSG_DONTWAIT | MSG_TRUNC) <= 0) break;
}

/* Accepting return value for the kernel filter. With the ring it is the
 * snaplen: the kernel copies that many bytes into the block and tp_len
 * still carries the wire length. On the recvmmsg path it must be the
 * whole frame, because packet_rcv() trims the skb to the return value
 * and the wire length would be lost (MSG_TRUNC reports the trimmed
 * length); truncation happens in user space there (bufsz). libpcap makes
 * the same distinction between its mmap and read paths. */
static inline uint32_t filter_snaplen(const capture_worker_t *w) {
    return w->ring ? (uint32_t)w->ctx->cfg.snaplen : 0xFFFFFFFFu;
}

static int attach_cbpf(int sock, const cbpf_insn_t *insns, int n) {
    struct sock_fprog prog = {
        .len    = (unsigned short)n,
        .filter = (struct sock_filter *)insns,
    };
    return setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog));
}

static void linux_release(capture_worker_t *w) {
    ring_teardown(w);
    free(w->bufs);
    w->bufs = NULL;
}


/* Put a bound AF_PACKET socket into fan-out group `group` in
 * PACKET_FANOUT_HASH mode, before its RX ring is mapped: the kernel
 * hashes each frame's flow and always delivers it to the same socket of
 * the group, so a flow stays on one worker and in order. */
static int fanout_join(int sock, int group) {
    int arg = (group & 0xffff) | (PACKET_FANOUT_HASH << 16);
    return setsockopt(sock, SOL_PACKET, PACKET_FANOUT, &arg, sizeof(arg));
}

#endif /* __linux__ */

/* ── Public API ──────────────────────────────────────────────── */

/* How many workers the configuration asks for, before the fan-out group
 * is actually built (capture_create may still fall back to 1). */
static int wanted_workers(const capture_cfg_t *cfg, int warn) {
    int n = cfg->workers > 0 ? cfg->workers : 1;
    if (n > CAPTURE_MAX_WORKERS) n = CAPTURE_MAX_WORKERS;
    if (n <= 1) return 1;
#ifndef __linux__
    if (warn) fprintf(stderr, "snuffles: -j needs Linux PACKET_FANOUT; "
                              "using one worker\n");
    return 1;
#else
    (void)warn;
    return n;
#endif
}

int capture_cfg_workers(const capture_cfg_t *cfg) {
    return wanted_workers(cfg, 0);
}

/* Give up one worker's socket and mapping (idempotent). */
static void worker_close(capture_worker_t *w) {
#ifdef __linux__
    linux_release(w);
#endif
    if (w->sock != RAW_INVALID) {
        RAW_CLOSE(w->sock);
        w->sock = RAW_INVALID;
    }
}

static void capture_free(capture_ctx_t *ctx) {
    for (int i = 0; i < CAPTURE_MAX_WORKERS; i++)
        worker_close(&ctx->w[i]);
    free(ctx);
}

#ifdef __linux__
/* Open one worker socket on ifindex (0 = every interface) and get it
 * ready to capture: reject everything until the real filter is on, bind,
 * promiscuous membership, fan-out group (before the ring is mapped),
 * the RX ring or the recvmmsg fallback, then drain and attach `insns`.
 * Returns 0 on success, -2 if only the fan-out group failed, -1 otherwise. */
static int worker_open_linux(capture_worker_t *w, const capture_cfg_t *cfg,
                             int ifindex, int group,
                             const cbpf_insn_t *insns, int ninsns) {
    w->sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (w->sock == RAW_INVALID) {
        fprintf(stderr, "socket(AF_PACKET) failed. ");
        if (getuid() != 0)
            fprintf(stderr, "Hint: run with sudo or set CAP_NET_RAW.\n");
        else
            perror("");
        return -1;
    }

    /* Reject-all filter first. The socket is hooked into the receive
     * path from socket() on, so frames arriving before the user's filter
     * goes on would be delivered unfiltered; with this in place they are
     * dropped instead. Whatever slipped in between the two calls is
     * drained below, before the real filter replaces it. */
    {
        cbpf_insn_t rej = { 0x06 /* BPF_RET|BPF_K */, 0, 0, 0 };
        if (attach_cbpf(w->sock, &rej, 1) != 0)
            fprintf(stderr, "Warning: SO_ATTACH_FILTER (reject-all) failed: "
                            "%s\n", strerror(errno));
    }

    /* bind to specific interface if requested. AF_PACKET ignores
     * SO_BINDTODEVICE for delivery (it only sets sk_bound_dev_if, which
     * packet_rcv never checks) — the socket must be bound to the ifindex
     * with sockaddr_ll, otherwise -i captures every interface. */
    if (ifindex) {
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family   = AF_PACKET;
        sll.sll_protocol = htons(ETH_P_ALL);
        sll.sll_ifindex  = ifindex;
        if (bind(w->sock, (struct sockaddr *)&sll, sizeof(sll)) != 0) {
            perror("bind(AF_PACKET)");
            return -1;
        }
    }

    /* Promiscuous mode via PACKET_ADD_MEMBERSHIP: the kernel reference-
     * counts it and clears it when the socket closes. (SIOCSIFFLAGS left
     * the interface promiscuous forever after exit, and restoring it
     * ourselves is impossible once privileges are dropped.) */
    if (cfg->promisc && ifindex) {
        struct packet_mreq mr;
        memset(&mr, 0, sizeof(mr));
        mr.mr_ifindex = ifindex;
        mr.mr_type    = PACKET_MR_PROMISC;
        if (setsockopt(w->sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
                       &mr, sizeof(mr)) != 0)
            fprintf(stderr, "Warning: could not enable promiscuous mode on %s\n",
                    cfg->iface);
    }

    /* Fan-out group before the ring is mapped. -2 tells the caller the
     * group is what failed, so it can fall back to a single worker. */
    if (group && fanout_join(w->sock, group) != 0) {
        fprintf(stderr, "snuffles: PACKET_FANOUT unavailable (%s); "
                "capturing with one worker\n", strerror(errno));
        return -2;
    }

    /* Capture buffer (-B): the TPACKET_V3 block ring, or the socket
     * receive queue + recvmmsg when the kernel cannot provide one or
     * --immediate asks for per-packet delivery: a V3 block is handed
     * over only when full or RAWRING_RETIRE_MS after its first frame
     * (~10 ms of latency for a lone packet), whereas recvmmsg with
     * MSG_WAITFORONE returns on the first frame — libpcap likewise leaves
     * TPACKET_V3 for immediate mode. Each worker gets its own. */
    {
        char why[160];
        int  have_ring = 0;
        if (cfg->immediate)
            ;   /* per-packet delivery: recvmmsg path */
        else if (ring_setup(w, why, sizeof(why)) == 0)
            have_ring = 1;
        else if (w->idx == 0)
            fprintf(stderr, "Note: TPACKET_V3 ring unavailable (%s); "
                            "using recvmmsg\n", why);
        if (!have_ring && fallback_setup(w) != 0)
            return -1;
    }

    /* Frames that got in between socket() and the reject-all filter
     * are still queued: throw them away, then put the real filter on. */
    drain_socket(w);

    /* The accepting return is the snaplen when the ring is in use
     * (filter_snaplen), so the kernel copies at most -s bytes of a frame
     * into the ring — as libpcap's filters do. */
    {
        cbpf_insn_t prog[CBPF_MAX_INSNS];
        memcpy(prog, insns, (size_t)ninsns * sizeof(prog[0]));
        cbpf_set_snaplen(prog, ninsns, filter_snaplen(w));
        if (attach_cbpf(w->sock, prog, ninsns) != 0) {
            perror("SO_ATTACH_FILTER");
            return -1;
        }
    }
    return 0;
}
#endif /* __linux__ */

capture_ctx_t *capture_create(const capture_cfg_t *cfg, ringbuf_t *rb,
                              session_table_t *const *sts, int nsts) {
    capture_ctx_t *ctx = calloc(1, sizeof(capture_ctx_t));
    if (!ctx) return NULL;

    ctx->rb   = rb;
    ctx->cfg  = *cfg;
    ctx->nworkers = wanted_workers(cfg, 1);
    for (int i = 0; i < CAPTURE_MAX_WORKERS; i++) {
        ctx->w[i].ctx  = ctx;
        ctx->w[i].idx  = i;
        ctx->w[i].sock = RAW_INVALID;
        ctx->w[i].st   = (sts && i < nsts) ? sts[i] : NULL;
    }
    capture_worker_t *w0 = &ctx->w[0];
    (void)w0;

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
        capture_free(ctx);
        return NULL;
    }

    w0->sock = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if (w0->sock == RAW_INVALID) {
        fprintf(stderr, "socket(SOCK_RAW) failed: %d\n", WSAGetLastError());
        fprintf(stderr, "Hint: run as Administrator.\n");
        capture_free(ctx);
        return NULL;
    }

    /* bind to interface */
    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    if (find_interface_ip(cfg->iface, &bind_addr) != 0) {
        fprintf(stderr, "Cannot find interface '%s'\n", cfg->iface);
        capture_free(ctx);
        return NULL;
    }

    if (bind(w0->sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) != 0) {
        fprintf(stderr, "bind() failed: %d\n", WSAGetLastError());
        capture_free(ctx);
        return NULL;
    }

    /* enable promiscuous capture */
    DWORD rcvall = RCVALL_ON;
    DWORD ret_bytes = 0;
    if (WSAIoctl(w0->sock, SIO_RCVALL, &rcvall, sizeof(rcvall),
                 NULL, 0, &ret_bytes, NULL, NULL) != 0) {
        fprintf(stderr, "SIO_RCVALL failed: %d\n", WSAGetLastError());
        fprintf(stderr, "Hint: run as Administrator.\n");
        capture_free(ctx);
        return NULL;
    }

    /* receive timeout for the capture loop */
    DWORD tv_ms = 100;
    setsockopt(w0->sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv_ms, sizeof(tv_ms));

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
    int ifindex = 0;
    if (cfg->iface[0]) {
        ifindex = (int)if_nametoindex(cfg->iface);
        if (ifindex == 0) {
            fprintf(stderr, "Cannot find interface '%s'\n", cfg->iface);
            free(ctx);
            return NULL;
        }
        snprintf(ctx->iface_name, sizeof(ctx->iface_name), "%s", cfg->iface);
    } else {
        snprintf(ctx->iface_name, sizeof(ctx->iface_name), "any");
    }

    /* -f: compile the subset syntax to classic BPF once and attach it to
     * every worker socket (replacing the reject-all program). No -f
     * attaches an accept-all program with the same snaplen return
     * instead of running unfiltered. */
    cbpf_insn_t insns[CBPF_MAX_INSNS];
    int ninsns;
    if (cfg->bpf_filter[0]) {
        char cerr[128];
        ninsns = cbpf_compile(cfg->bpf_filter, insns, CBPF_MAX_INSNS,
                              cerr, sizeof(cerr));
        if (ninsns < 0) {
            fprintf(stderr, "BPF (raw build): %s\n"
                    "Supported: tcp/udp/icmp/sctp/ip/arp, [src|dst] host A.B.C.D, "
                    "[src|dst] port N, joined with 'and'\n", cerr);
            free(ctx);
            return NULL;
        }
        snprintf(ctx->bpf_expr, sizeof(ctx->bpf_expr), "%s", cfg->bpf_filter);
    } else {
        ninsns = cbpf_accept_all(insns, 0xFFFFFFFFu);
    }

    /* One fan-out group per process (the group id ties the sockets
     * together; another snuffles gets its own). */
    int group = ctx->nworkers > 1 ? (int)(getpid() & 0xffff) : 0;
    for (int i = 0; i < ctx->nworkers; i++) {
        int rc = worker_open_linux(&ctx->w[i], cfg, ifindex, group,
                                   insns, ninsns);
        if (rc == 0) continue;
        if (i == 0) {
            /* the group itself is unavailable (old kernel, a device that
             * refuses it): capture with one worker, as the libpcap build
             * does */
            worker_close(&ctx->w[0]);
            if (rc == -2 && worker_open_linux(&ctx->w[0], cfg, ifindex, 0,
                                              insns, ninsns) == 0) {
                ctx->nworkers = 1;
                break;
            }
            capture_free(ctx);
            return NULL;
        }
        /* the group is short of a worker: carry on with the ones we have */
        fprintf(stderr, "snuffles: only %d of %d capture workers could be "
                "opened\n", i, ctx->nworkers);
        worker_close(&ctx->w[i]);
        ctx->nworkers = i;
        break;
    }

    ctx->has_eth = 1; /* AF_PACKET gives full Ethernet frames */
    ctx->lo_ifindex = (int)if_nametoindex("lo");   /* 0 if there is none */

#else
    /* ── macOS / other: not supported without libpcap ────────── */
    fprintf(stderr, "Raw socket capture is not supported on this platform.\n"
                    "Build without -DNO_PCAP to use the libpcap backend.\n");
    free(ctx);
    return NULL;
#endif

    /* drop root privileges now that the raw sockets are open */
#ifndef _WIN32
    if (ns_drop_privileges() != 0)
        fprintf(stderr, "Warning: failed to drop root privileges; "
                        "continuing as root\n");
#endif

    return ctx;
}

int capture_start(capture_ctx_t *ctx) {
    atomic_store(&ctx->stop_req, 0);
    for (int i = 0; i < ctx->nworkers; i++) {
        atomic_fetch_add(&ctx->running, 1);
        if (ns_thread_create(&ctx->w[i].thread, capture_thread_fn,
                             &ctx->w[i]) != 0) {
            atomic_fetch_sub(&ctx->running, 1);
            fprintf(stderr, "Failed to create capture thread\n");
            if (i == 0) return -1;
            atomic_store(&ctx->stop_req, 1);
            for (int j = 0; j < i; j++) ns_thread_join(ctx->w[j].thread);
            return -1;
        }
        ctx->w[i].started = 1;
    }
    return 0;
}

void capture_stop(capture_ctx_t *ctx) {
    if (!ctx) return;
    atomic_store(&ctx->stop_req, 1);
    for (int i = 0; i < ctx->nworkers; i++) {
        if (ctx->w[i].started) {
            ns_thread_join(ctx->w[i].thread);
            ctx->w[i].started = 0;
        }
    }
}

void capture_destroy(capture_ctx_t *ctx) {
    if (!ctx) return;
    capture_free(ctx);       /* unmaps the rings before the sockets go */
#ifdef _WIN32
    WSACleanup();
#endif
}

int capture_is_running(const capture_ctx_t *ctx) {
    return ctx ? atomic_load(&ctx->running) > 0 : 0;
}

int capture_worker_count(const capture_ctx_t *ctx) {
    return ctx ? ctx->nworkers : 1;
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
    out->nworkers = ctx->nworkers;
    for (int i = 0; i < ctx->nworkers; i++) {
        uint64_t d = atomic_load(&ctx->w[i].drops);
        out->kdrop_w[i] = d;
        out->pkts_drop += d;
        out->pkts_recv += atomic_load(&ctx->w[i].pkt_count);
    }
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
    cbpf_insn_t insns[CBPF_MAX_INSNS];
    int n;
    if (!expr || !expr[0]) {
        /* clearing the filter: accept everything, still cut to -s */
        n = cbpf_accept_all(insns, 0xFFFFFFFFu);
    } else {
        char cerr[128];
        n = cbpf_compile(expr, insns, CBPF_MAX_INSNS, cerr, sizeof(cerr));
        if (n < 0) {
            snprintf(errbuf, errlen, "%s (subset: proto, host, port, 'and')", cerr);
            return -1;
        }
    }
    /* every worker socket carries the same program (its own snaplen
     * return: a worker may be on the ring while another is not) */
    for (int i = 0; i < ctx->nworkers; i++) {
        cbpf_insn_t prog[CBPF_MAX_INSNS];
        memcpy(prog, insns, (size_t)n * sizeof(prog[0]));
        cbpf_set_snaplen(prog, n, filter_snaplen(&ctx->w[i]));
        if (attach_cbpf(ctx->w[i].sock, prog, n) != 0) {
            snprintf(errbuf, errlen, "SO_ATTACH_FILTER failed");
            return -1;
        }
    }
    snprintf(ctx->bpf_expr, sizeof(ctx->bpf_expr), "%s",
             (expr && expr[0]) ? expr : "");
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
