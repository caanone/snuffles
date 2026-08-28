/*
 * udpflood — connected-UDP flood generator for the snuffles load-test rig.
 *
 *   udpflood -d IP -p PORT -s SIZE -t THREADS -T SECONDS [-r]
 *
 * One connected UDP socket per thread (fixed source port), sendmmsg in
 * batches of 64, SO_SNDBUF forced to 32 MB. SIZE is the UDP PAYLOAD size in
 * bytes; -s 4000 therefore produces IP-fragmented datagrams (3 fragments per
 * datagram at MTU 1500). With -r ("random source port per batch") a pool of
 * THREADS*16 sockets is bound up front (kernel-assigned ephemeral ports) and
 * each thread round-robins over its 16 sockets, switching every batch, so the
 * source port varies without the cost of creating a socket per batch.
 *
 * Prints exactly one JSON object as its last stdout line:
 *   {"tool":"udpflood","sent":N,"bytes":N,"seconds":F,"pps":F,"mbps":F,
 *    "errors":N,"threads":N,"size":N,"rand_src":0|1}
 * where "bytes" counts UDP payload bytes (size * sent).
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define BATCH 64
#define POOL_PER_THREAD 16

static volatile sig_atomic_t g_stop = 0;

static int g_size = 64;
static int g_threads = 2;
static int g_seconds = 10;
static int g_rand = 0;
static struct sockaddr_in g_dst;

struct targ {
    int id;
    int *socks;
    int nsocks;
    unsigned long long sent;
    unsigned long long errors;
};

static void on_signal(int sig) { (void)sig; g_stop = 1; }

static double now_mono(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void set_sndbuf(int fd) {
    int v = 32 * 1024 * 1024;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUFFORCE, &v, sizeof v) < 0)
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &v, sizeof v);
}

/* create one connected UDP socket; bind to ephemeral port when want_bind. */
static int make_sock(int want_bind) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    set_sndbuf(fd);
    if (want_bind) {
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof sa);
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = htonl(INADDR_ANY);
        sa.sin_port = 0; /* kernel picks a distinct ephemeral port */
        if (bind(fd, (struct sockaddr *)&sa, sizeof sa) < 0) {
            close(fd);
            return -1;
        }
    }
    if (connect(fd, (struct sockaddr *)&g_dst, sizeof g_dst) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void *worker(void *p) {
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

    unsigned si = 0;
    while (!g_stop) {
        int fd = a->socks[si % (unsigned)a->nsocks];
        si++;
        int n = sendmmsg(fd, msgs, BATCH, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            /* ENOBUFS / EAGAIN under pressure: count and keep going */
            a->errors++;
            continue;
        }
        a->sent += (unsigned long long)n;
    }
    free(buf);
    return NULL;
}

static void usage(const char *p) {
    fprintf(stderr,
            "usage: %s -d IP -p PORT [-s SIZE] [-t THREADS] [-T SECONDS] [-r]\n",
            p);
}

int main(int argc, char **argv) {
    const char *dst_ip = NULL;
    int dst_port = 0;
    int opt;
    while ((opt = getopt(argc, argv, "d:p:s:t:T:rh")) != -1) {
        switch (opt) {
        case 'd': dst_ip = optarg; break;
        case 'p': dst_port = atoi(optarg); break;
        case 's': g_size = atoi(optarg); break;
        case 't': g_threads = atoi(optarg); break;
        case 'T': g_seconds = atoi(optarg); break;
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

    memset(&g_dst, 0, sizeof g_dst);
    g_dst.sin_family = AF_INET;
    g_dst.sin_port = htons((uint16_t)dst_port);
    if (inet_pton(AF_INET, dst_ip, &g_dst.sin_addr) != 1) {
        fprintf(stderr, "bad dst ip: %s\n", dst_ip);
        return 2;
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGALRM, on_signal);

    int per = g_rand ? POOL_PER_THREAD : 1;
    struct targ *args = calloc((size_t)g_threads, sizeof *args);
    pthread_t *tids = calloc((size_t)g_threads, sizeof *tids);
    if (!args || !tids) { perror("calloc"); return 1; }

    for (int t = 0; t < g_threads; t++) {
        args[t].id = t;
        args[t].nsocks = per;
        args[t].socks = calloc((size_t)per, sizeof(int));
        if (!args[t].socks) { perror("calloc"); return 1; }
        for (int s = 0; s < per; s++) {
            int fd = make_sock(g_rand);
            if (fd < 0) {
                fprintf(stderr, "socket setup failed: %s\n", strerror(errno));
                return 1;
            }
            args[t].socks[s] = fd;
        }
    }

    double t0 = now_mono();
    for (int t = 0; t < g_threads; t++) {
        if (pthread_create(&tids[t], NULL, worker, &args[t]) != 0) {
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
