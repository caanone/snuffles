/*
 * udpflood — UDP flood generator for the snuffles load-test rig.
 *
 *   udpflood -d IP -p PORT -s SIZE -t THREADS -T SECONDS [-r]
 *            [-i IFACE] [--dst-mac MAC]
 *
 * Two modes:
 *
 *  - default (no -r): one *connected* UDP socket per thread (fixed source IP =
 *    the container's, fixed source port), sendmmsg in batches of 64, SO_SNDBUF
 *    forced to 32 MB. SIZE is the UDP PAYLOAD size in bytes; -s 4000 therefore
 *    produces IP-fragmented datagrams (3 fragments per datagram at MTU 1500).
 *    This is what the `frag` scenario uses.
 *
 *  - -r (flow churn): an AF_PACKET SOCK_RAW sender per thread, like synflood.c.
 *    Every frame is built by hand (14 eth + 20 IPv4 + 8 UDP + SIZE payload) and
 *    gets a FRESH random source IP in 10.77.128.0/17 (32768 addresses) and a
 *    random source port in 1024..65535 (64512 ports) — a flow pool of ~2.1e9
 *    unique 5-tuples, far past the "65536 source ports x several source IPs"
 *    the rig needs to exercise the session table. The source MAC is IFACE's
 *    hardware address and the destination MAC/IP default to the rig sink
 *    (02:53:4e:46:00:05 / the -d IP) so the bridge forwards the flood. The
 *    connected-socket path could only vary the source *port* (one bound source
 *    IP), so -r is now a real per-packet flow-churn generator.
 *
 * Prints exactly one JSON object as its last stdout line:
 *   {"tool":"udpflood","sent":N,"bytes":N,"seconds":F,"pps":F,"mbps":F,
 *    "errors":N,"threads":N,"size":N,"rand_src":0|1}
 * where "bytes" counts UDP payload bytes (size * sent), the same in both modes.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define BATCH 64

/* 10.77.128.0/17 source pool (host order), matching synflood.c */
#define SRC_BASE 0x0A4D8000u
#define SRC_MASK 0x00007FFFu /* 15 host bits => 32768 source IPs */

static volatile sig_atomic_t g_stop = 0;

static int g_size = 64;
static int g_threads = 2;
static int g_seconds = 10;
static int g_rand = 0;
static struct sockaddr_in g_dst;      /* connected mode */
static uint32_t g_dst_ip;             /* raw mode, network order */
static uint16_t g_dst_port;           /* host order */
static int g_ifindex = 0;             /* raw mode */
static uint8_t g_src_mac[6];
static uint8_t g_dst_mac[6] = {0x02, 0x53, 0x4e, 0x46, 0x00, 0x05};

struct targ {
    int id;
    int *socks;
    int nsocks;
    unsigned int seed;                /* raw mode PRNG state */
    unsigned long long sent;
    unsigned long long errors;
};

static void on_signal(int sig) { (void)sig; g_stop = 1; }

static double now_mono(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static inline uint32_t xorshift32(uint32_t *s) {
    uint32_t x = *s;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *s = x;
    return x;
}

/* Alias-safe running checksum (read the buffer as bytes via memcpy so -O2's
 * strict-aliasing analysis cannot reorder these loads past the header stores),
 * same technique as synflood.c. */
static uint32_t csum_acc(uint32_t sum, const void *data, int len) {
    const unsigned char *p = (const unsigned char *)data;
    while (len > 1) {
        uint16_t w;
        memcpy(&w, p, 2);
        sum += w;
        p += 2;
        len -= 2;
    }
    if (len == 1) sum += *p;
    return sum;
}

static uint16_t csum16(const void *data, int len, uint32_t seed) {
    uint32_t sum = csum_acc(seed, data, len);
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

static void set_sndbuf(int fd) {
    int v = 32 * 1024 * 1024;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUFFORCE, &v, sizeof v) < 0)
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &v, sizeof v);
}

/* ── connected-UDP mode (default; used by the frag scenario) ─────────────── */

static int make_sock(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    set_sndbuf(fd);
    if (connect(fd, (struct sockaddr *)&g_dst, sizeof g_dst) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void *worker_connected(void *p) {
    struct targ *a = (struct targ *)p;
    const int size = g_size;
    char *buf = malloc((size_t)size);
    if (!buf) return NULL;
    memset(buf, 0x42, (size_t)size);

    struct mmsghdr msgs[BATCH];
    struct iovec iovs[BATCH];
    memset(msgs, 0, sizeof msgs);
    for (int i = 0; i < BATCH; i++) {
        iovs[i].iov_base = buf;
        iovs[i].iov_len = (size_t)size;
        msgs[i].msg_hdr.msg_iov = &iovs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
    }

    int fd = a->socks[0];
    while (!g_stop) {
        int n = sendmmsg(fd, msgs, BATCH, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            a->errors++;
            continue;
        }
        a->sent += (unsigned long long)n;
    }
    free(buf);
    return NULL;
}

/* ── raw AF_PACKET flow-churn mode (-r) ──────────────────────────────────── */

#pragma pack(push, 1)
struct ipv4_hdr {
    uint8_t ihl_ver;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t proto;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};
struct udp_hdr {
    uint16_t sport;
    uint16_t dport;
    uint16_t len;
    uint16_t check;
};
#pragma pack(pop)

static void build_udp_template(uint8_t *f, int frame_len, int payload) {
    struct ether_header *eth = (struct ether_header *)f;
    memcpy(eth->ether_dhost, g_dst_mac, 6);
    memcpy(eth->ether_shost, g_src_mac, 6);
    eth->ether_type = htons(ETHERTYPE_IP);

    struct ipv4_hdr *ip = (struct ipv4_hdr *)(f + 14);
    ip->ihl_ver = 0x45;
    ip->tos = 0;
    ip->tot_len = htons((uint16_t)(20 + 8 + payload));
    ip->id = 0;
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->proto = IPPROTO_UDP;
    ip->check = 0;
    ip->saddr = 0;
    ip->daddr = g_dst_ip;

    struct udp_hdr *udp = (struct udp_hdr *)(f + 14 + 20);
    udp->sport = 0;
    udp->dport = htons(g_dst_port);
    udp->len = htons((uint16_t)(8 + payload));
    udp->check = 0;                    /* 0 = "no UDP checksum", legal for IPv4 */

    /* payload is a fixed 0x42 fill */
    memset(f + 14 + 20 + 8, 0x42, (size_t)payload);
    (void)frame_len;
}

static void randomize_udp(uint8_t *f, unsigned int *seed) {
    struct ipv4_hdr *ip = (struct ipv4_hdr *)(f + 14);
    struct udp_hdr *udp = (struct udp_hdr *)(f + 14 + 20);

    uint32_t r1 = xorshift32(seed);
    uint32_t r2 = xorshift32(seed);
    ip->saddr = htonl(SRC_BASE | (r1 & SRC_MASK));
    ip->id = (uint16_t)(r1 >> 16);
    ip->check = 0;
    ip->check = csum16(ip, 20, 0);
    udp->sport = htons((uint16_t)(1024 + (r2 % 64512)));
    /* udp->check stays 0 (source varies every packet; a 0 checksum keeps the
     * generator cheap and is valid for IPv4 UDP) */
}

static void *worker_raw(void *p) {
    struct targ *a = (struct targ *)p;
    const int payload = g_size;
    const int frame_len = 14 + 20 + 8 + payload;

    int fd = socket(AF_PACKET, SOCK_RAW, 0);
    if (fd < 0) {
        fprintf(stderr, "thread %d: socket: %s\n", a->id, strerror(errno));
        return NULL;
    }
    struct sockaddr_ll bindaddr;
    memset(&bindaddr, 0, sizeof bindaddr);
    bindaddr.sll_family = AF_PACKET;
    bindaddr.sll_ifindex = g_ifindex;
    bindaddr.sll_protocol = htons(ETH_P_IP);
    if (bind(fd, (struct sockaddr *)&bindaddr, sizeof bindaddr) < 0) {
        fprintf(stderr, "thread %d: bind: %s\n", a->id, strerror(errno));
        close(fd);
        return NULL;
    }
    set_sndbuf(fd);

    struct sockaddr_ll dst;
    memset(&dst, 0, sizeof dst);
    dst.sll_family = AF_PACKET;
    dst.sll_ifindex = g_ifindex;
    dst.sll_halen = 6;
    memcpy(dst.sll_addr, g_dst_mac, 6);

    uint8_t *frames = malloc((size_t)BATCH * frame_len);
    if (!frames) { close(fd); return NULL; }
    struct mmsghdr msgs[BATCH];
    struct iovec iovs[BATCH];
    memset(msgs, 0, sizeof msgs);
    for (int i = 0; i < BATCH; i++) {
        build_udp_template(frames + (size_t)i * frame_len, frame_len, payload);
        iovs[i].iov_base = frames + (size_t)i * frame_len;
        iovs[i].iov_len = (size_t)frame_len;
        msgs[i].msg_hdr.msg_iov = &iovs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
        msgs[i].msg_hdr.msg_name = &dst;
        msgs[i].msg_hdr.msg_namelen = sizeof dst;
    }

    while (!g_stop) {
        for (int i = 0; i < BATCH; i++)
            randomize_udp(frames + (size_t)i * frame_len, &a->seed);
        int n = sendmmsg(fd, msgs, BATCH, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            a->errors++;
            continue;
        }
        a->sent += (unsigned long long)n;
    }
    free(frames);
    close(fd);
    return NULL;
}

static int parse_mac(const char *s, uint8_t *out) {
    unsigned int v[6];
    if (sscanf(s, "%x:%x:%x:%x:%x:%x", &v[0], &v[1], &v[2], &v[3], &v[4],
               &v[5]) != 6)
        return -1;
    for (int i = 0; i < 6; i++) out[i] = (uint8_t)v[i];
    return 0;
}

static void usage(const char *p) {
    fprintf(stderr,
            "usage: %s -d IP -p PORT [-s SIZE] [-t THREADS] [-T SECONDS] [-r]\n"
            "          [-i IFACE] [--dst-mac MAC]\n"
            "  -r  AF_PACKET flow churn: random src IP (10.77.128.0/17) + src "
            "port per packet\n",
            p);
}

int main(int argc, char **argv) {
    const char *dst_ip = NULL;
    const char *iface = "eth0";
    const char *dst_mac_s = NULL;
    int dst_port = 0;
    int opt;
    static struct option lo[] = {
        {"dst-mac", required_argument, 0, 'M'},
        {"iface", required_argument, 0, 'i'},
        {0, 0, 0, 0}};
    while ((opt = getopt_long(argc, argv, "d:p:s:t:T:i:rh", lo, NULL)) != -1) {
        switch (opt) {
        case 'd': dst_ip = optarg; break;
        case 'p': dst_port = atoi(optarg); break;
        case 's': g_size = atoi(optarg); break;
        case 't': g_threads = atoi(optarg); break;
        case 'T': g_seconds = atoi(optarg); break;
        case 'i': iface = optarg; break;
        case 'M': dst_mac_s = optarg; break;
        case 'r': g_rand = 1; break;
        case 'h': usage(argv[0]); return 0;
        default: usage(argv[0]); return 2;
        }
    }
    if (!dst_ip || dst_port <= 0 || g_size <= 0 || g_threads <= 0 ||
        g_seconds <= 0) {
        usage(argv[0]);
        return 2;
    }
    g_dst_port = (uint16_t)dst_port;

    if (dst_mac_s && parse_mac(dst_mac_s, g_dst_mac) < 0) {
        fprintf(stderr, "bad --dst-mac: %s\n", dst_mac_s);
        return 2;
    }

    /* connected-mode destination */
    memset(&g_dst, 0, sizeof g_dst);
    g_dst.sin_family = AF_INET;
    g_dst.sin_port = htons((uint16_t)dst_port);
    if (inet_pton(AF_INET, dst_ip, &g_dst.sin_addr) != 1) {
        fprintf(stderr, "bad dst ip: %s\n", dst_ip);
        return 2;
    }
    g_dst_ip = g_dst.sin_addr.s_addr;  /* network order, for the raw path */

    /* raw mode needs IFACE's index + hardware address */
    if (g_rand) {
        int s = socket(AF_INET, SOCK_DGRAM, 0);
        struct ifreq ifr;
        memset(&ifr, 0, sizeof ifr);
        strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
        if (ioctl(s, SIOCGIFINDEX, &ifr) < 0) {
            fprintf(stderr, "SIOCGIFINDEX %s: %s\n", iface, strerror(errno));
            return 1;
        }
        g_ifindex = ifr.ifr_ifindex;
        if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) {
            fprintf(stderr, "SIOCGIFHWADDR %s: %s\n", iface, strerror(errno));
            return 1;
        }
        memcpy(g_src_mac, ifr.ifr_hwaddr.sa_data, 6);
        close(s);
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGALRM, on_signal);

    struct targ *args = calloc((size_t)g_threads, sizeof *args);
    pthread_t *tids = calloc((size_t)g_threads, sizeof *tids);
    if (!args || !tids) { perror("calloc"); return 1; }

    double t0 = now_mono();
    for (int t = 0; t < g_threads; t++) {
        args[t].id = t;
        args[t].seed = (unsigned int)(0xd7f100du ^ (t * 2654435761u) ^
                                      (unsigned int)(t0 * 1e6));
        if (args[t].seed == 0) args[t].seed = 1;
        if (!g_rand) {
            /* connected mode: one socket per thread */
            args[t].nsocks = 1;
            args[t].socks = calloc(1, sizeof(int));
            if (!args[t].socks) { perror("calloc"); return 1; }
            int fd = make_sock();
            if (fd < 0) {
                fprintf(stderr, "socket setup failed: %s\n", strerror(errno));
                return 1;
            }
            args[t].socks[0] = fd;
        }
    }

    for (int t = 0; t < g_threads; t++) {
        void *(*fn)(void *) = g_rand ? worker_raw : worker_connected;
        if (pthread_create(&tids[t], NULL, fn, &args[t]) != 0) {
            perror("pthread_create");
            return 1;
        }
    }
    /* run for the requested duration, then stop */
    alarm((unsigned)g_seconds);
    struct timespec left = {g_seconds, 0};
    while (!g_stop && nanosleep(&left, &left) < 0 && errno == EINTR) {
        if (g_stop) break;
    }
    g_stop = 1;
    for (int t = 0; t < g_threads; t++) pthread_join(tids[t], NULL);
    double elapsed = now_mono() - t0;
    if (elapsed <= 0) elapsed = 1e-9;

    unsigned long long sent = 0, errors = 0;
    for (int t = 0; t < g_threads; t++) {
        sent += args[t].sent;
        errors += args[t].errors;
        for (int s = 0; s < args[t].nsocks; s++) close(args[t].socks[s]);
        free(args[t].socks);
    }
    unsigned long long bytes = sent * (unsigned long long)g_size;
    double pps = (double)sent / elapsed;
    double mbps = (double)bytes * 8.0 / 1e6 / elapsed;

    printf("{\"tool\":\"udpflood\",\"sent\":%llu,\"bytes\":%llu,"
           "\"seconds\":%.3f,\"pps\":%.1f,\"mbps\":%.2f,\"errors\":%llu,"
           "\"threads\":%d,\"size\":%d,\"rand_src\":%d}\n",
           sent, bytes, elapsed, pps, mbps, errors, g_threads, g_size, g_rand);
    free(args);
    free(tids);
    return 0;
}
