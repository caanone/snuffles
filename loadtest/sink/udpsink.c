/*
 * udpsink - count UDP datagrams as fast as one core can (load-test sink).
 *
 *   udpsink -p PORT -o out.json [-b RCVBUF_BYTES]
 *
 * - binds 0.0.0.0:PORT, SO_RCVBUFFORCE (default 64 MiB; needs CAP_NET_ADMIN,
 *   falls back to SO_RCVBUF which is capped by net.core.rmem_max)
 * - recvmmsg() loop, non-blocking + poll() when the queue is empty
 * - once per second prints "t=<s> received=<n> bytes=<n>" (cumulative) to stderr
 * - on SIGINT/SIGTERM writes out.json atomically:
 *     {"received":N,"bytes":N,"seconds":F,
 *      "rcvbuf_errors_delta":N,"in_errors_delta":N}
 *   where the *_delta fields are the change of "Udp: RcvbufErrors" and
 *   "Udp: InErrors" in /proc/net/snmp (this netns) between start and stop,
 *   then exits 0.
 *
 * bytes = sum of real datagram lengths (MSG_TRUNC), even when a datagram is
 * larger than the receive buffer slot.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#define BATCH 512            /* datagrams per recvmmsg() */
#define SLOT  2048           /* bytes copied per datagram (MSG_TRUNC keeps the real length) */
#define DEFAULT_RCVBUF (64u * 1024u * 1024u)

static volatile sig_atomic_t g_stop = 0;

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

struct udp_snmp {
    uint64_t in_errors;
    uint64_t rcvbuf_errors;
    int ok;
};

/* Parse the "Udp:" header/value pair of /proc/net/snmp by column name. */
static void read_udp_snmp(struct udp_snmp *st)
{
    char hdr[2048], val[2048];
    FILE *f;

    memset(st, 0, sizeof *st);
    f = fopen("/proc/net/snmp", "r");
    if (!f)
        return;
    while (fgets(hdr, sizeof hdr, f)) {
        char *hs, *vs, *ht, *vt;
        if (strncmp(hdr, "Udp:", 4) != 0)
            continue;
        if (!fgets(val, sizeof val, f) || strncmp(val, "Udp:", 4) != 0)
            break;
        ht = strtok_r(hdr + 4, " \t\r\n", &hs);
        vt = strtok_r(val + 4, " \t\r\n", &vs);
        while (ht && vt) {
            if (strcmp(ht, "InErrors") == 0)
                st->in_errors = strtoull(vt, NULL, 10);
            else if (strcmp(ht, "RcvbufErrors") == 0)
                st->rcvbuf_errors = strtoull(vt, NULL, 10);
            ht = strtok_r(NULL, " \t\r\n", &hs);
            vt = strtok_r(NULL, " \t\r\n", &vs);
        }
        st->ok = 1;
        break;
    }
    fclose(f);
}

static double now_s(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* mkdir -p for the directory part of path (best effort). */
static void mkdir_parents(const char *path)
{
    char buf[4096];
    size_t n = strlen(path);
    char *p;

    if (n >= sizeof buf)
        return;
    memcpy(buf, path, n + 1);
    p = strrchr(buf, '/');
    if (!p || p == buf)
        return;
    *p = '\0';
    for (p = buf + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            (void)mkdir(buf, 0755);
            *p = '/';
        }
    }
    (void)mkdir(buf, 0755);
}

static int write_result(const char *path, uint64_t received, uint64_t bytes,
                        double seconds, uint64_t rcvbuf_delta, uint64_t inerr_delta)
{
    char tmp[4096];
    FILE *f;
    int fd;

    if (snprintf(tmp, sizeof tmp, "%s.tmp", path) >= (int)sizeof tmp) {
        fprintf(stderr, "udpsink: output path too long\n");
        return -1;
    }
    mkdir_parents(path);
    fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        fprintf(stderr, "udpsink: open %s: %s\n", tmp, strerror(errno));
        return -1;
    }
    f = fdopen(fd, "w");
    if (!f) {
        close(fd);
        return -1;
    }
    fprintf(f,
            "{\"received\": %" PRIu64 ", \"bytes\": %" PRIu64
            ", \"seconds\": %.3f, \"rcvbuf_errors_delta\": %" PRIu64
            ", \"in_errors_delta\": %" PRIu64 "}\n",
            received, bytes, seconds, rcvbuf_delta, inerr_delta);
    if (fflush(f) != 0 || fsync(fd) != 0) {
        fprintf(stderr, "udpsink: write %s: %s\n", tmp, strerror(errno));
        fclose(f);
        return -1;
    }
    fclose(f);
    if (rename(tmp, path) != 0) {
        fprintf(stderr, "udpsink: rename %s -> %s: %s\n", tmp, path, strerror(errno));
        return -1;
    }
    return 0;
}

static void usage(const char *argv0)
{
    fprintf(stderr,
            "usage: %s -p PORT -o out.json [-b RCVBUF_BYTES]\n"
            "  -p PORT     UDP port to bind on 0.0.0.0\n"
            "  -o FILE     JSON result written on SIGINT/SIGTERM\n"
            "  -b BYTES    SO_RCVBUFFORCE size (default %u)\n",
            argv0, DEFAULT_RCVBUF);
}

int main(int argc, char **argv)
{
    int port = 0, opt, fd, i;
    long rcvbuf = DEFAULT_RCVBUF;
    const char *out = NULL;
    struct sockaddr_in sa;
    struct sigaction sact;
    struct mmsghdr *msgs;
    struct iovec *iovs;
    unsigned char *bufs;
    struct udp_snmp snmp0, snmp1;
    uint64_t received = 0, bytes = 0;
    double t0, next_tick, now;
    unsigned tick = 0;
    int actual = 0;
    socklen_t alen = sizeof actual;

    while ((opt = getopt(argc, argv, "p:o:b:h")) != -1) {
        switch (opt) {
        case 'p':
            port = atoi(optarg);
            break;
        case 'o':
            out = optarg;
            break;
        case 'b':
            rcvbuf = atol(optarg);
            break;
        case 'h':
        default:
            usage(argv[0]);
            return opt == 'h' ? 0 : 2;
        }
    }
    if (port <= 0 || port > 65535 || !out || rcvbuf <= 0) {
        usage(argv[0]);
        return 2;
    }

    memset(&sact, 0, sizeof sact);
    sact.sa_handler = on_signal; /* no SA_RESTART: poll()/recvmmsg() return EINTR */
    sigemptyset(&sact.sa_mask);
    sigaction(SIGINT, &sact, NULL);
    sigaction(SIGTERM, &sact, NULL);
    signal(SIGPIPE, SIG_IGN);

    fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (fd < 0) {
        perror("udpsink: socket");
        return 1;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &rcvbuf, sizeof(int)) != 0) {
        int e = errno;
        int rb = (int)rcvbuf;
        fprintf(stderr, "udpsink: SO_RCVBUFFORCE failed (%s), falling back to SO_RCVBUF\n",
                strerror(e));
        if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rb, sizeof rb) != 0)
            perror("udpsink: SO_RCVBUF");
    }
    getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &actual, &alen);

    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    sa.sin_port = htons((uint16_t)port);
    if (bind(fd, (struct sockaddr *)&sa, sizeof sa) != 0) {
        fprintf(stderr, "udpsink: bind 0.0.0.0:%d: %s\n", port, strerror(errno));
        return 1;
    }

    msgs = calloc(BATCH, sizeof *msgs);
    iovs = calloc(BATCH, sizeof *iovs);
    bufs = malloc((size_t)BATCH * SLOT);
    if (!msgs || !iovs || !bufs) {
        fprintf(stderr, "udpsink: out of memory\n");
        return 1;
    }
    for (i = 0; i < BATCH; i++) {
        iovs[i].iov_base = bufs + (size_t)i * SLOT;
        iovs[i].iov_len = SLOT;
        msgs[i].msg_hdr.msg_iov = &iovs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
    }

    read_udp_snmp(&snmp0);
    t0 = now_s();
    next_tick = t0 + 1.0;
    fprintf(stderr, "udpsink: listening on 0.0.0.0:%d rcvbuf=%d (requested %ld) out=%s\n",
            port, actual, rcvbuf, out);

    while (!g_stop) {
        int n = recvmmsg(fd, msgs, BATCH, MSG_DONTWAIT | MSG_TRUNC, NULL);
        if (n > 0) {
            received += (uint64_t)n;
            for (i = 0; i < n; i++)
                bytes += msgs[i].msg_len;
        } else if (n < 0) {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                struct pollfd pfd = { .fd = fd, .events = POLLIN };
                double wait = next_tick - now_s();
                int ms = wait <= 0 ? 0 : (int)(wait * 1000.0) + 1;
                (void)poll(&pfd, 1, ms);
            } else {
                /* transient socket error (e.g. queued ICMP): report and keep going */
                fprintf(stderr, "udpsink: recvmmsg: %s\n", strerror(errno));
            }
        }
        now = now_s();
        if (now >= next_tick) {
            tick++;
            fprintf(stderr, "t=%u received=%" PRIu64 " bytes=%" PRIu64 "\n",
                    tick, received, bytes);
            do {
                next_tick += 1.0;
            } while (next_tick <= now);
        }
    }

    now = now_s();
    read_udp_snmp(&snmp1);
    {
        uint64_t rb = (snmp0.ok && snmp1.ok && snmp1.rcvbuf_errors >= snmp0.rcvbuf_errors)
                          ? snmp1.rcvbuf_errors - snmp0.rcvbuf_errors : 0;
        uint64_t ie = (snmp0.ok && snmp1.ok && snmp1.in_errors >= snmp0.in_errors)
                          ? snmp1.in_errors - snmp0.in_errors : 0;
        double secs = now - t0;
        int rc = write_result(out, received, bytes, secs, rb, ie);
        fprintf(stderr,
                "udpsink: stop received=%" PRIu64 " bytes=%" PRIu64 " seconds=%.3f"
                " rcvbuf_errors_delta=%" PRIu64 " in_errors_delta=%" PRIu64 " -> %s%s\n",
                received, bytes, secs, rb, ie, out, rc == 0 ? "" : " (WRITE FAILED)");
        close(fd);
        return rc == 0 ? 0 : 1;
    }
}
