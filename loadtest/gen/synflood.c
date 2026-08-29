/*
 * synflood — AF_PACKET TCP-SYN generator for the snuffles load-test rig.
 *
 *   synflood [-i IFACE] [-d DSTIP] [-p DSTPORT] [--dst-mac MAC]
 *            [-t THREADS] [-T SECONDS]
 *
 * Each thread owns an AF_PACKET SOCK_RAW socket bound to IFACE and blasts
 * 54-byte Ethernet frames (14 eth + 20 IPv4 + 20 TCP SYN) with sendmmsg in
 * batches of 64. Every frame gets a fresh random source IP in 10.77.128.0/17,
 * a random source port, and a random ISN; the source MAC is the real hardware
 * address of IFACE and the destination MAC/IP default to the rig sink
 * (02:53:4e:46:00:05 / 10.77.0.5:80) so nginx answers the SYNs.
 *
 * Prints exactly one JSON object as its last stdout line:
 *   {"tool":"synflood","sent":N,"bytes":N,"seconds":F,"pps":F,"mbps":F,
 *    "errors":N,"threads":N}
 * "bytes" counts wire bytes (54 * sent).
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
#define FRAME_LEN 54 /* 14 eth + 20 ip + 20 tcp */

static volatile sig_atomic_t g_stop = 0;

static int g_threads = 2;
static int g_seconds = 10;
static int g_ifindex = 0;
static uint8_t g_src_mac[6];
static uint8_t g_dst_mac[6] = {0x02, 0x53, 0x4e, 0x46, 0x00, 0x05};
static uint32_t g_dst_ip;   /* network order */
static uint16_t g_dst_port; /* host order */

/* 10.77.128.0/17 base, host order */
#define SRC_BASE 0x0A4D8000u
#define SRC_MASK 0x00007FFFu /* 15 host bits */

struct targ {
    int id;
    unsigned long long sent;
    unsigned long long errors;
    unsigned int seed;
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

/* Alias-safe running sum: read the buffer through unsigned char + memcpy so
 * -O2's strict-aliasing analysis cannot reorder these 16-bit loads past the
 * struct-field stores that fill the header (the old (uint16_t *)cast read stale
 * pseudo-header words at -O2, so every TCP checksum shipped wrong and the sink
 * dropped every SYN as TcpInCsumErrors — nginx never answered). */
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
struct tcp_hdr {
    uint16_t sport;
    uint16_t dport;
    uint32_t seq;
    uint32_t ack;
    uint8_t off; /* data offset << 4 */
    uint8_t flags;
    uint16_t window;
    uint16_t check;
    uint16_t urg;
};
struct pseudo_hdr {
    uint32_t saddr;
    uint32_t daddr;
    uint8_t zero;
    uint8_t proto;
    uint16_t len;
};
#pragma pack(pop)

static void build_template(uint8_t *f) {
    struct ether_header *eth = (struct ether_header *)f;
    memcpy(eth->ether_dhost, g_dst_mac, 6);
    memcpy(eth->ether_shost, g_src_mac, 6);
    eth->ether_type = htons(ETHERTYPE_IP);

    struct ipv4_hdr *ip = (struct ipv4_hdr *)(f + 14);
    ip->ihl_ver = 0x45;
    ip->tos = 0;
    ip->tot_len = htons(40);
    ip->id = 0;
    ip->frag_off = htons(0x4000); /* DF */
    ip->ttl = 64;
    ip->proto = IPPROTO_TCP;
    ip->check = 0;
    ip->saddr = 0;
    ip->daddr = g_dst_ip;

    struct tcp_hdr *tcp = (struct tcp_hdr *)(f + 14 + 20);
    tcp->sport = 0;
    tcp->dport = htons(g_dst_port);
    tcp->seq = 0;
    tcp->ack = 0;
    tcp->off = 5 << 4;
    tcp->flags = 0x02; /* SYN */
    tcp->window = htons(64240);
    tcp->check = 0;
    tcp->urg = 0;
}

static void randomize(uint8_t *f, unsigned int *seed) {
    struct ipv4_hdr *ip = (struct ipv4_hdr *)(f + 14);
    struct tcp_hdr *tcp = (struct tcp_hdr *)(f + 14 + 20);

    uint32_t r1 = xorshift32(seed);
    uint32_t r2 = xorshift32(seed);
    uint32_t saddr_h = SRC_BASE | (r1 & SRC_MASK);
    ip->saddr = htonl(saddr_h);
    ip->id = (uint16_t)(r1 >> 16);
    ip->check = 0;
    ip->check = csum16(ip, 20, 0);

    tcp->sport = htons((uint16_t)(1024 + (r2 % 64000)));
    tcp->seq = htonl(r2 ^ 0x9e3779b9u);
    tcp->check = 0;

    struct pseudo_hdr ph;
    ph.saddr = ip->saddr;
    ph.daddr = ip->daddr;
    ph.zero = 0;
    ph.proto = IPPROTO_TCP;
    ph.len = htons(20);
    uint32_t seed_sum = csum_acc(0, &ph, sizeof ph);
    tcp->check = csum16(tcp, 20, seed_sum);
}

static void *worker(void *p) {
    struct targ *a = (struct targ *)p;
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
    int sndbuf = 32 * 1024 * 1024;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUFFORCE, &sndbuf, sizeof sndbuf) < 0)
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof sndbuf);

    struct sockaddr_ll dst;
    memset(&dst, 0, sizeof dst);
    dst.sll_family = AF_PACKET;
    dst.sll_ifindex = g_ifindex;
    dst.sll_halen = 6;
    memcpy(dst.sll_addr, g_dst_mac, 6);

    uint8_t *frames = malloc((size_t)BATCH * FRAME_LEN);
    struct mmsghdr msgs[BATCH];
    struct iovec iovs[BATCH];
    memset(msgs, 0, sizeof msgs);
    for (int i = 0; i < BATCH; i++) {
        build_template(frames + (size_t)i * FRAME_LEN);
        iovs[i].iov_base = frames + (size_t)i * FRAME_LEN;
        iovs[i].iov_len = FRAME_LEN;
        msgs[i].msg_hdr.msg_iov = &iovs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
        msgs[i].msg_hdr.msg_name = &dst;
        msgs[i].msg_hdr.msg_namelen = sizeof dst;
    }

    while (!g_stop) {
        for (int i = 0; i < BATCH; i++)
            randomize(frames + (size_t)i * FRAME_LEN, &a->seed);
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
            "usage: %s [-i IFACE] [-d DSTIP] [-p DSTPORT] [--dst-mac MAC] "
            "[-t THREADS] [-T SECONDS]\n",
            p);
}

int main(int argc, char **argv) {
    const char *iface = "eth0";
    const char *dst_ip = "10.77.0.5";
    int dst_port = 80;
    const char *dst_mac_s = NULL;

    static struct option lo[] = {
        {"dst-mac", required_argument, 0, 'M'},
        {"iface", required_argument, 0, 'i'},
        {0, 0, 0, 0}};
    int opt;
    while ((opt = getopt_long(argc, argv, "i:d:p:t:T:h", lo, NULL)) != -1) {
        switch (opt) {
        case 'i': iface = optarg; break;
        case 'd': dst_ip = optarg; break;
        case 'p': dst_port = atoi(optarg); break;
        case 'M': dst_mac_s = optarg; break;
        case 't': g_threads = atoi(optarg); break;
        case 'T': g_seconds = atoi(optarg); break;
        case 'h': usage(argv[0]); return 0;
        default: usage(argv[0]); return 2;
        }
    }
    if (g_threads <= 0 || g_seconds <= 0 || dst_port <= 0) {
        usage(argv[0]);
        return 2;
    }
    if (dst_mac_s && parse_mac(dst_mac_s, g_dst_mac) < 0) {
        fprintf(stderr, "bad --dst-mac: %s\n", dst_mac_s);
        return 2;
    }
    if (inet_pton(AF_INET, dst_ip, &g_dst_ip) != 1) {
        fprintf(stderr, "bad dst ip: %s\n", dst_ip);
        return 2;
    }
    g_dst_port = (uint16_t)dst_port;

    /* resolve interface index + hardware address */
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

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGALRM, on_signal);

    struct targ *args = calloc((size_t)g_threads, sizeof *args);
    pthread_t *tids = calloc((size_t)g_threads, sizeof *tids);
    if (!args || !tids) { perror("calloc"); return 1; }

    double t0 = now_mono();
    for (int t = 0; t < g_threads; t++) {
        args[t].id = t;
        args[t].seed = (unsigned int)(0xdeadbeef ^ (t * 2654435761u) ^
                                      (unsigned int)(t0 * 1e6));
        if (args[t].seed == 0) args[t].seed = 1;
        if (pthread_create(&tids[t], NULL, worker, &args[t]) != 0) {
            perror("pthread_create");
            return 1;
        }
    }
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
    }
    unsigned long long bytes = sent * (unsigned long long)FRAME_LEN;
    double pps = (double)sent / elapsed;
    double mbps = (double)bytes * 8.0 / 1e6 / elapsed;

    printf("{\"tool\":\"synflood\",\"sent\":%llu,\"bytes\":%llu,"
           "\"seconds\":%.3f,\"pps\":%.1f,\"mbps\":%.2f,\"errors\":%llu,"
           "\"threads\":%d}\n",
           sent, bytes, elapsed, pps, mbps, errors, g_threads);
    free(args);
    free(tids);
    return 0;
}
