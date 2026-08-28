/* syslog_out: CSV format, batching/flush semantics, counters, self-check.
 * A UDP listener on 127.0.0.1 (ephemeral port) plays the collector. */
#include "syslog_out.h"
#include "test_common.h"
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  typedef SOCKET lsock_t;
  #define LSOCK_INVALID INVALID_SOCKET
  static void lsock_close(lsock_t s) { closesocket(s); }
  static void lsock_timeout(lsock_t s, int ms) {
      DWORD v = (DWORD)ms;
      setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&v, sizeof(v));
  }
#else
  #include <unistd.h>
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  typedef int lsock_t;
  #define LSOCK_INVALID (-1)
  static void lsock_close(lsock_t s) { close(s); }
  static void lsock_timeout(lsock_t s, int ms) {
      struct timeval tv = { .tv_sec = ms / 1000, .tv_usec = (ms % 1000) * 1000 };
      setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  }
#endif

/* ── collector ───────────────────────────────────────────────── */

static lsock_t listener_open(char *target, size_t tlen) {
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
    lsock_t s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s == LSOCK_INVALID) return s;
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    if (bind(s, (struct sockaddr *)&a, sizeof(a)) != 0) {
        lsock_close(s);
        return LSOCK_INVALID;
    }
    socklen_t al = sizeof(a);
    getsockname(s, (struct sockaddr *)&a, &al);
    snprintf(target, tlen, "127.0.0.1:%u", (unsigned)ntohs(a.sin_port));
    return s;
}

/* Receive up to 'want' datagrams, giving up after 'ms' of silence.
 * Lines land in 'out' (NULL-terminated), at most 'cap' of them. */
#define LINE_CAP 600   /* >= recv buffer so a copy never truncates */

static int collect(lsock_t s, char out[][LINE_CAP], int cap, int want, int ms) {
    lsock_timeout(s, ms);
    int n = 0;
    while (n < want) {
        char buf[LINE_CAP];
        int r = (int)recv(s, buf, sizeof(buf) - 1, 0);
        if (r <= 0) break;
        buf[r] = '\0';
        if (n < cap) memcpy(out[n], buf, (size_t)r + 1);
        n++;
    }
    return n;
}

static int commas(const char *s) {
    int c = 0;
    for (; *s; s++) if (*s == ',') c++;
    return c;
}

/* ── fixtures ────────────────────────────────────────────────── */

static void tcp_pkt(pkt_summary_t *p) {
    memset(p, 0, sizeof(*p));
    snprintf(p->src_ip, sizeof(p->src_ip), "10.0.0.1");
    snprintf(p->dst_ip, sizeof(p->dst_ip), "93.184.216.34");
    snprintf(p->protocol, sizeof(p->protocol), "TCP");
    p->src_port = 55555; p->dst_port = 443;
    p->ts.tv_sec = 1774973651;
    p->length = 54;
    p->ip_ttl = 64; p->ip_id = 1; p->ip_checksum = 0; p->ip_frag_off = 0x4000;
    p->l4_proto = PROTO_TCP;
    p->tcp_flags = 0x12;            /* SYN|ACK */
    p->tcp_seq = 100; p->tcp_ack = 0; p->tcp_window = 65535;
    p->tcp_checksum = 0xbeef;
}

static void udp_pkt(pkt_summary_t *p) {
    memset(p, 0, sizeof(*p));
    snprintf(p->src_ip, sizeof(p->src_ip), "192.168.1.100");
    snprintf(p->dst_ip, sizeof(p->dst_ip), "8.8.8.8");
    snprintf(p->protocol, sizeof(p->protocol), "DNS");
    p->src_port = 54321; p->dst_port = 53;
    p->ts.tv_sec = 1774973652;
    p->length = 54;
    p->ip_ttl = 64; p->ip_id = 7; p->ip_checksum = 0x1234; p->ip_frag_off = 0;
    p->l4_proto = PROTO_UDP;
    p->l7_proto = PROTO_DNS;
}

/* ── tests ───────────────────────────────────────────────────── */

static char lines[128][LINE_CAP];

static void test_format(syslog_out_t *sl, lsock_t ls) {
    pkt_summary_t p;
    uint64_t sent, failed;

    tcp_pkt(&p);
    syslog_out_send(sl, &p);
    CHECK(syslog_out_pending(sl) == 1);
    syslog_out_flush(sl);
    CHECK(syslog_out_pending(sl) == 0);
    CHECK(collect(ls, lines, 128, 1, 500) == 1);
    CHECK(strcmp(lines[0],
        "10.0.0.1,55555,93.184.216.34,443,1774973651,54,TCP,"
        "64,1,0x0000,0x4000,SA,100,0,65535,0xbeef\n") == 0);
    CHECK(commas(lines[0]) == 15);

    udp_pkt(&p);
    syslog_out_send(sl, &p);
    syslog_out_flush(sl);
    CHECK(collect(ls, lines, 128, 1, 500) == 1);
    CHECK(strcmp(lines[0],
        "192.168.1.100,54321,8.8.8.8,53,1774973652,54,DNS,"
        "64,7,0x1234,0x0000,,,,,\n") == 0);
    CHECK(commas(lines[0]) == 15);

    /* no L3 info: nothing queued, nothing sent */
    p.src_ip[0] = '\0';
    syslog_out_send(sl, &p);
    CHECK(syslog_out_pending(sl) == 0);
    syslog_out_flush(sl);
    CHECK(collect(ls, lines, 128, 1, 50) == 0);

    syslog_out_counts(sl, &sent, &failed);
    CHECK(sent == 2);
    CHECK(failed == 0);
}

static void test_batching(syslog_out_t *sl, lsock_t ls) {
    pkt_summary_t p;
    uint64_t sent, failed, sent0, failed0;
    syslog_out_counts(sl, &sent0, &failed0);

    /* below the batch size nothing leaves until the loop flushes */
    tcp_pkt(&p);
    for (int i = 0; i < 3; i++) syslog_out_send(sl, &p);
    CHECK(syslog_out_pending(sl) == 3);
    CHECK(collect(ls, lines, 128, 1, 50) == 0);
    syslog_out_counts(sl, &sent, &failed);
    CHECK(sent == sent0);
    syslog_out_flush(sl);
    CHECK(syslog_out_pending(sl) == 0);
    CHECK(collect(ls, lines, 128, 3, 500) == 3);
    syslog_out_counts(sl, &sent, &failed);
    CHECK(sent == sent0 + 3);

    /* a full batch flushes by itself, in order, nothing lost or merged */
    for (int i = 0; i < SYSLOG_BATCH; i++) {
        p.ip_id = (uint16_t)i;
        syslog_out_send(sl, &p);
    }
    CHECK(syslog_out_pending(sl) == 0);
    CHECK(collect(ls, lines, 128, SYSLOG_BATCH, 500) == SYSLOG_BATCH);
    for (int i = 0; i < SYSLOG_BATCH; i++) {
        char want[64];
        snprintf(want, sizeof(want), ",64,%d,0x0000,", i);
        CHECK(strstr(lines[i], want) != NULL);
        CHECK(commas(lines[i]) == 15);
    }

    /* 100 records: three full batches plus a 4-record tail */
    for (int i = 0; i < 100; i++) {
        p.ip_id = (uint16_t)(1000 + i);
        syslog_out_send(sl, &p);
    }
    CHECK(syslog_out_pending(sl) == 4);
    syslog_out_flush(sl);
    CHECK(collect(ls, lines, 128, 100, 500) == 100);
    CHECK(strstr(lines[0],  ",64,1000,0x0000,") != NULL);
    CHECK(strstr(lines[99], ",64,1099,0x0000,") != NULL);
    syslog_out_counts(sl, &sent, &failed);
    CHECK(sent == sent0 + 3 + SYSLOG_BATCH + 100);
    CHECK(failed == failed0);

    /* empty flush is a no-op */
    syslog_out_flush(sl);
    CHECK(collect(ls, lines, 128, 1, 50) == 0);
}

static void test_self(syslog_out_t *sl, const char *target) {
    pkt_summary_t p;
    unsigned port = 0;
    sscanf(strrchr(target, ':') + 1, "%u", &port);

    /* third-party UDP to the same port is NOT ours (source port differs) */
    udp_pkt(&p);
    snprintf(p.dst_ip, sizeof(p.dst_ip), "127.0.0.1");
    p.dst_port = (uint16_t)port;
    p.src_port = 1;
    CHECK(syslog_out_is_self(sl, &p) == 0);

    /* ICMP touching the collector is swallowed (feedback loop guard) */
    p.l4_proto = PROTO_ICMP4;
    CHECK(syslog_out_is_self(sl, &p) == 1);

    /* unrelated traffic passes */
    tcp_pkt(&p);
    CHECK(syslog_out_is_self(sl, &p) == 0);
    CHECK(syslog_out_is_self(NULL, &p) == 0);
}

/* A destination the socket cannot send to (limited broadcast without
 * SO_BROADCAST -> EACCES on Linux/BSD/Winsock, or no route at all in an
 * isolated namespace) exercises the failure accounting: nothing counts as
 * sent, every record as failed, flushes keep the queue empty and a later
 * batch is accounted on its own. */
static void test_failure(void) {
    syslog_out_t *bad = syslog_out_create("255.255.255.255:514", NULL);
    CHECK(bad != NULL);
    if (!bad) return;

    pkt_summary_t p;
    uint64_t sent, failed;
    tcp_pkt(&p);
    for (int i = 0; i < 3; i++) syslog_out_send(bad, &p);
    CHECK(syslog_out_pending(bad) == 3);
    syslog_out_flush(bad);
    CHECK(syslog_out_pending(bad) == 0);
    syslog_out_counts(bad, &sent, &failed);
    CHECK(sent == 0);
    CHECK(failed == 3);

    /* a full batch fails as a whole, once (no double counting on retry) */
    for (int i = 0; i < SYSLOG_BATCH; i++) syslog_out_send(bad, &p);
    CHECK(syslog_out_pending(bad) == 0);
    syslog_out_counts(bad, &sent, &failed);
    CHECK(sent == 0);
    CHECK(failed == 3 + SYSLOG_BATCH);
    syslog_out_destroy(bad);
}

int main(void) {
    char target[64];
    lsock_t ls = listener_open(target, sizeof(target));
    CHECK(ls != LSOCK_INVALID);
    if (ls == LSOCK_INVALID) return 1;

    /* bad targets are refused */
    CHECK(syslog_out_create("", NULL) == NULL);
    CHECK(syslog_out_create("127.0.0.1:0", NULL) == NULL);
    CHECK(syslog_out_create("127.0.0.1:99999", NULL) == NULL);
    CHECK(syslog_out_create("::1:514", NULL) == NULL);

    syslog_out_t *sl = syslog_out_create(target, NULL);
    CHECK(sl != NULL);
    if (sl) {
        test_format(sl, ls);
        test_batching(sl, ls);
        test_self(sl, target);
        syslog_out_destroy(sl);
    }
    test_failure();
    syslog_out_flush(NULL);
    syslog_out_destroy(NULL);
    lsock_close(ls);
    TEST_MAIN_END();
}
