/* output thread: consumes the ring by sequence, feeds --syslog and -w,
 * counts what the ring lapped. A UDP listener on 127.0.0.1 plays the
 * collector; the -w stream goes to a scratch file that is parsed back. */
#include "output.h"
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
  static void nap_ms(int ms) { Sleep((DWORD)ms); }
#else
  #include <unistd.h>
  #include <sys/socket.h>
  #include <sys/select.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  typedef int lsock_t;
  #define LSOCK_INVALID (-1)
  static void lsock_close(lsock_t s) { close(s); }
  static void lsock_timeout(lsock_t s, int ms) {
      struct timeval tv = { .tv_sec = ms / 1000, .tv_usec = (ms % 1000) * 1000 };
      setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  }
  static void nap_ms(int ms) {
      struct timeval tv = { .tv_sec = ms / 1000, .tv_usec = (ms % 1000) * 1000 };
      select(0, NULL, NULL, NULL, &tv);
  }
#endif

#define STREAM_FILE "test_output_stream.pcap"

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
    int rcv = 4 * 1024 * 1024;   /* a burst must not be lost on our side */
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, (const char *)&rcv, sizeof(rcv));
    socklen_t al = sizeof(a);
    getsockname(s, (struct sockaddr *)&a, &al);
    snprintf(target, tlen, "127.0.0.1:%u", (unsigned)ntohs(a.sin_port));
    return s;
}

/* Count datagrams until 'ms' of silence; every line must carry the 16
 * CSV fields and the sequence we planted in the ip_id column. */
static int collect(lsock_t s, int ms, int *bad) {
    lsock_timeout(s, ms);
    int n = 0;
    *bad = 0;
    for (;;) {
        char buf[600];
        int r = (int)recv(s, buf, sizeof(buf) - 1, 0);
        if (r <= 0) break;
        buf[r] = '\0';
        int commas = 0;
        for (const char *c = buf; *c; c++) if (*c == ',') commas++;
        if (commas != 15 || strncmp(buf, "10.1.2.3,4000,10.9.9.9,53,", 26) != 0)
            (*bad)++;
        n++;
    }
    return n;
}

/* ── ring fixture ────────────────────────────────────────────── */

static void push(ringbuf_t *rb, uint32_t seq) {
    uint32_t len = 42 + seq % 20;
    pkt_record_t *r = ringbuf_producer_next(rb, len);
    pkt_summary_t *p = &r->summary;
    memset(p, 0, sizeof(*p));
    /* binary addresses: the syslog sink and its self-check format/compare
     * these, the text columns are only kept for compatibility */
    p->addr_family = 4;
    p->src_addr[0] = 10; p->src_addr[1] = 1; p->src_addr[2] = 2; p->src_addr[3] = 3;
    p->dst_addr[0] = 10; p->dst_addr[1] = 9; p->dst_addr[2] = 9; p->dst_addr[3] = 9;
    snprintf(p->src_ip, sizeof(p->src_ip), "10.1.2.3");
    snprintf(p->dst_ip, sizeof(p->dst_ip), "10.9.9.9");
    snprintf(p->protocol, sizeof(p->protocol), "DNS");
    p->src_port = 4000; p->dst_port = 53;
    p->l4_proto = PROTO_UDP;
    p->ts.tv_sec = 1774973652; p->ts.tv_usec = (long)(seq % 1000000);
    p->length = 60 + seq % 40;
    p->ip_ttl = 64; p->ip_id = (uint16_t)seq;
    memset(r->raw_data, (int)(seq & 0xff), r->raw_len);   /* raw_len == len */
    ringbuf_producer_commit(rb);
}

/* Parse the -w file: header, then records whose lengths and first byte
 * match what push() wrote for that sequence. Returns the record count,
 * -1 on a malformed file. */
static long pcap_records(const char *path, long *bad) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    unsigned char hdr[24];
    if (fread(hdr, 1, 24, f) != 24) { fclose(f); return -1; }
    uint32_t magic;
    memcpy(&magic, hdr, 4);
    if (magic != 0xa1b2c3d4u) { fclose(f); return -1; }
    long n = 0;
    *bad = 0;
    for (;;) {
        unsigned char ph[16];
        size_t got = fread(ph, 1, 16, f);
        if (got == 0) break;
        if (got != 16) { fclose(f); return -1; }
        uint32_t ts_usec, incl, orig;
        memcpy(&ts_usec, ph + 4, 4);
        memcpy(&incl, ph + 8, 4);
        memcpy(&orig, ph + 12, 4);
        unsigned char body[128];
        if (incl > sizeof(body) || fread(body, 1, incl, f) != incl) {
            fclose(f);
            return -1;
        }
        uint32_t seq = ts_usec;   /* push(): usec = seq % 1e6, seq < 1e6 */
        if (incl != 42 + seq % 20 || orig != 60 + seq % 40 ||
            body[0] != (unsigned char)(seq & 0xff))
            (*bad)++;
        n++;
    }
    fclose(f);
    return n;
}

/* ── tests ───────────────────────────────────────────────────── */

/* Slow producer: the thread sleeps between batches and is woken through
 * its own ring slot; every record reaches both sinks, nothing is missed. */
static void test_delivery(void) {
    char target[64];
    lsock_t ls = listener_open(target, sizeof(target));
    CHECK(ls != LSOCK_INVALID);

    ringbuf_t *rb = ringbuf_create(1024, 128, 0);
    CHECK(rb != NULL);
    syslog_out_t *sl = syslog_out_create(target, NULL);
    CHECK(sl != NULL);
    pcap_writer_t *pw = pcap_writer_open(STREAM_FILE, 128, 1);
    CHECK(pw != NULL);

    output_t *o = output_create(rb, sl, pw, STREAM_FILE);
    CHECK(o != NULL);
    CHECK(output_start(o) == 0);

    const uint32_t N = 500;
    for (uint32_t s = 0; s < N; s++) {
        push(rb, s);
        if (s % 50 == 49) nap_ms(20);   /* let the thread drain and block */
    }
    output_stop(o);

    output_stats_t st;
    output_get_stats(o, &st);
    CHECK(st.syslog_sent == N);
    CHECK(st.syslog_failed == 0);
    CHECK(st.streamed == N);
    CHECK(st.missed == 0);
    CHECK(ringbuf_notify_sent(rb) > 0);        /* it slept and was woken */

    int bad = 0;
    CHECK(collect(ls, 300, &bad) == (int)N);
    CHECK(bad == 0);

    output_destroy(o);                          /* closes the file */
    long pbad = 0;
    CHECK(pcap_records(STREAM_FILE, &pbad) == (long)N);
    CHECK(pbad == 0);
    remove(STREAM_FILE);
    ringbuf_destroy(rb);
    lsock_close(ls);
}

/* Fast producer into a 16-slot ring: the thread is lapped; whatever it
 * did not see is counted, and the accounting closes exactly. */
static void test_lapped(void) {
    char target[64];
    lsock_t ls = listener_open(target, sizeof(target));
    CHECK(ls != LSOCK_INVALID);

    ringbuf_t *rb = ringbuf_create(16, 128, 0);
    CHECK(rb != NULL);
    syslog_out_t *sl = syslog_out_create(target, NULL);
    CHECK(sl != NULL);
    pcap_writer_t *pw = pcap_writer_open(STREAM_FILE, 128, 1);
    CHECK(pw != NULL);
    output_t *o = output_create(rb, sl, pw, STREAM_FILE);
    CHECK(o != NULL);
    CHECK(output_start(o) == 0);

    const uint32_t N = 200000;
    for (uint32_t s = 0; s < N; s++) push(rb, s);
    output_stop(o);

    output_stats_t st;
    output_get_stats(o, &st);
    CHECK(st.syslog_sent + st.syslog_failed + st.missed == N);
    CHECK(st.streamed + st.missed == N);
    CHECK(st.streamed >= 16);                   /* the tail is always seen */
    printf("lapped: sent=%llu fail=%llu streamed=%llu missed=%llu\n",
           (unsigned long long)st.syslog_sent,
           (unsigned long long)st.syslog_failed,
           (unsigned long long)st.streamed, (unsigned long long)st.missed);

    int bad = 0;
    int got = collect(ls, 300, &bad);
    CHECK(got <= (int)st.syslog_sent);          /* the kernel may drop, never invent */
    CHECK(bad == 0);

    output_destroy(o);
    long pbad = 0;
    CHECK(pcap_records(STREAM_FILE, &pbad) == (long)st.streamed);
    CHECK(pbad == 0);                           /* every copied record intact */
    remove(STREAM_FILE);
    ringbuf_destroy(rb);
    lsock_close(ls);
}

/* Offline replay: with its position published, the producer that honours
 * may_write never laps the thread, so every record is streamed. */
static void test_attached(void) {
    ringbuf_t *rb = ringbuf_create(16, 128, 0);
    CHECK(rb != NULL);
    pcap_writer_t *pw = pcap_writer_open(STREAM_FILE, 128, 1);
    CHECK(pw != NULL);
    output_t *o = output_create(rb, NULL, pw, STREAM_FILE);
    CHECK(o != NULL);
    output_attach_position(o);
    CHECK(output_start(o) == 0);

    const uint32_t N = 20000;
    for (uint32_t s = 0; s < N; s++) {
        int spins = 0;
        while (!ringbuf_producer_may_write(rb)) {
            if (++spins > 100000) break;        /* never: fail loudly below */
            if (spins % 1000 == 0) nap_ms(1);
        }
        push(rb, s);
    }
    output_stop(o);
    output_stats_t st;
    output_get_stats(o, &st);
    CHECK(st.streamed == N);
    CHECK(st.missed == 0);
    output_destroy(o);
    long pbad = 0;
    CHECK(pcap_records(STREAM_FILE, &pbad) == (long)N);
    CHECK(pbad == 0);
    remove(STREAM_FILE);
    ringbuf_destroy(rb);
}

/* No sinks and never started: create/stop/destroy must be inert. */
static void test_idle(void) {
    ringbuf_t *rb = ringbuf_create(8, 64, 0);
    CHECK(rb != NULL);
    output_t *o = output_create(rb, NULL, NULL, NULL);
    CHECK(o != NULL);
    output_stop(o);
    output_stats_t st;
    output_get_stats(o, &st);
    CHECK(st.missed == 0 && st.streamed == 0 && st.syslog_sent == 0);
    output_destroy(o);
    output_stop(NULL);
    output_destroy(NULL);
    output_get_stats(NULL, &st);
    ringbuf_destroy(rb);
}

int main(void) {
    test_delivery();
    test_lapped();
    test_attached();
    test_idle();
    TEST_MAIN_END();
}
