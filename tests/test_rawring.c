#include "rawring.h"
#include "test_common.h"
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/* ── ring geometry ───────────────────────────────────────────── */

static void test_geometry(void) {
    rawring_geom_t g;

    size_t len = rawring_geometry(64, 4096, &g);
    CHECK(g.block_size == 256u * 1024u);
    CHECK(g.block_nr == 256);
    CHECK(g.frame_size == 2048);
    CHECK(g.frame_nr == g.block_nr * (g.block_size / g.frame_size));
    CHECK(len == (size_t)64 << 20);
    CHECK(len == (size_t)g.block_size * g.block_nr);   /* exact mmap length */

    /* the lean syslog default */
    len = rawring_geometry(8, 4096, &g);
    CHECK(g.block_nr == 32 && len == (size_t)8 << 20);

    /* smaller than one block still gets one block; nonsense gets one too */
    rawring_geometry(0, 4096, &g);
    CHECK(g.block_nr == 1);
    rawring_geometry(-5, 4096, &g);
    CHECK(g.block_nr == 1 && g.block_size == 256u * 1024u);

    /* 64 KiB pages: 256 KiB is already a multiple; an odd page size
     * rounds the block up to a multiple of it */
    rawring_geometry(64, 65536, &g);
    CHECK(g.block_size == 256u * 1024u);
    rawring_geometry(1, 3 * 65536, &g);
    CHECK(g.block_size % (3 * 65536) == 0 && g.block_size >= 256u * 1024u);
    rawring_geometry(64, 0, &g);                         /* sysconf failure */
    CHECK(g.block_size == 256u * 1024u && g.block_nr == 256);

    /* -B 2047 */
    len = rawring_geometry(2047, 4096, &g);
    CHECK(g.block_nr == 2047 * 4 && len == (size_t)2047 << 20);
}

#ifdef __linux__
#include <linux/if_packet.h>
#include <sys/socket.h>

/* ── block walk ──────────────────────────────────────────────── */

#define BLK 4096u

typedef struct {
    rawring_frame_t seen[16];
    int             n;
    int             stop_after;   /* cb returns 1 on this frame (1-based) */
} walk_t;

static int cb(void *user, const rawring_frame_t *f) {
    walk_t *w = (walk_t *)user;
    if (w->n < 16) w->seen[w->n] = *f;
    w->n++;
    return w->stop_after && w->n >= w->stop_after;
}

static uint8_t *blk_alloc(void) {
    uint8_t *b = calloc(1, BLK);
    struct tpacket_block_desc *bd = (struct tpacket_block_desc *)b;
    bd->version = TPACKET_V3;
    bd->hdr.bh1.block_status = TP_STATUS_USER;
    bd->hdr.bh1.offset_to_first_pkt = 48;   /* what the kernel uses */
    return b;
}

/* Append a frame the way tpacket_rcv lays it out: header at off, data at
 * off + tp_mac, next entry 16-aligned. Returns the next offset. */
static uint32_t blk_add(uint8_t *b, uint32_t off, uint32_t caplen,
                        uint32_t wirelen, uint32_t sec, uint32_t nsec,
                        uint8_t fill) {
    struct tpacket_block_desc *bd = (struct tpacket_block_desc *)b;
    struct tpacket3_hdr *h = (struct tpacket3_hdr *)(b + off);
    h->tp_mac     = 82;         /* TPACKET3_HDRLEN + 16 - 14 (Ethernet) */
    h->tp_net     = 96;
    h->tp_snaplen = caplen;
    h->tp_len     = wirelen;
    h->tp_sec     = sec;
    h->tp_nsec    = nsec;
    h->tp_status  = TP_STATUS_USER;
    struct sockaddr_ll *sll = (struct sockaddr_ll *)
        (b + off + TPACKET_ALIGN(sizeof(struct tpacket3_hdr)));
    sll->sll_family  = AF_PACKET;
    sll->sll_ifindex = 1 + (int)(fill & 1);
    sll->sll_pkttype = (fill & 1) ? PACKET_OUTGOING : PACKET_HOST;
    memset(b + off + h->tp_mac, fill, caplen);
    uint32_t total = (h->tp_mac + caplen + 15u) & ~15u;
    h->tp_next_offset = total;
    bd->hdr.bh1.num_pkts++;
    bd->hdr.bh1.blk_len = off + total;
    return off + total;
}

static void blk_close(uint8_t *b, uint32_t last_off) {
    ((struct tpacket3_hdr *)(b + last_off))->tp_next_offset = 0;
}

static void test_walk_basic(void) {
    uint8_t *b = blk_alloc();
    uint32_t o0 = 48;
    uint32_t o1 = blk_add(b, o0, 60, 60, 1000, 1000, 0xA1);
    uint32_t o2 = blk_add(b, o1, 128, 1514, 1000, 2000, 0xB2);  /* truncated by BPF */
    uint32_t o3 = blk_add(b, o2, 42, 42, 1001, 0, 0xC3);
    (void)o3;
    blk_close(b, o2);

    walk_t w = { .n = 0, .stop_after = 0 };
    uint32_t n = rawring_walk_block(b, BLK, cb, &w);
    CHECK(n == 3 && w.n == 3);
    CHECK(w.seen[0].caplen == 60 && w.seen[0].wirelen == 60);
    CHECK(w.seen[0].sec == 1000 && w.seen[0].nsec == 1000);
    CHECK(w.seen[0].data == b + o0 + 82 && w.seen[0].data[0] == 0xA1);
    CHECK(w.seen[1].caplen == 128 && w.seen[1].wirelen == 1514);
    CHECK(w.seen[1].data == b + o1 + 82 && w.seen[1].data[127] == 0xB2);
    CHECK(w.seen[2].caplen == 42 && w.seen[2].sec == 1001);
    CHECK(w.seen[2].data[41] == 0xC3);
    /* sockaddr_ll: 0xA1/0xC3 odd -> outgoing on ifindex 2, 0xB2 -> host */
    CHECK(w.seen[0].ifindex == 2 && w.seen[0].pkttype == PACKET_OUTGOING);
    CHECK(w.seen[1].ifindex == 1 && w.seen[1].pkttype == PACKET_HOST);
    CHECK(w.seen[2].ifindex == 2 && w.seen[2].pkttype == PACKET_OUTGOING);

    /* the callback can stop the walk (-c reached): later frames untouched */
    walk_t s = { .n = 0, .stop_after = 2 };
    n = rawring_walk_block(b, BLK, cb, &s);
    CHECK(n == 2 && s.n == 2);

    /* an empty block */
    uint8_t *e = blk_alloc();
    walk_t z = { .n = 0, .stop_after = 0 };
    CHECK(rawring_walk_block(e, BLK, cb, &z) == 0 && z.n == 0);

    free(e);
    free(b);
}

static void test_walk_malformed(void) {
    /* num_pkts larger than the chain: the tp_next_offset == 0 terminator
     * wins, nothing is invented */
    uint8_t *b = blk_alloc();
    uint32_t o1 = blk_add(b, 48, 60, 60, 1, 1, 0x11);
    blk_close(b, 48);
    ((struct tpacket_block_desc *)b)->hdr.bh1.num_pkts = 5;
    walk_t w = { .n = 0, .stop_after = 0 };
    CHECK(rawring_walk_block(b, BLK, cb, &w) == 1 && w.n == 1);

    /* tp_next_offset pointing past the block: first frame delivered,
     * the walk stops instead of reading outside */
    ((struct tpacket_block_desc *)b)->hdr.bh1.num_pkts = 2;
    ((struct tpacket3_hdr *)(b + 48))->tp_next_offset = BLK;
    w.n = 0;
    CHECK(rawring_walk_block(b, BLK, cb, &w) == 1 && w.n == 1);

    /* unaligned next offset */
    ((struct tpacket3_hdr *)(b + 48))->tp_next_offset = o1 - 48 + 4;
    w.n = 0;
    CHECK(rawring_walk_block(b, BLK, cb, &w) == 1 && w.n == 1);

    /* snaplen running past the end of the block: frame not delivered */
    ((struct tpacket_block_desc *)b)->hdr.bh1.num_pkts = 1;
    ((struct tpacket3_hdr *)(b + 48))->tp_snaplen = BLK;
    w.n = 0;
    CHECK(rawring_walk_block(b, BLK, cb, &w) == 0 && w.n == 0);
    /* exactly to the end is fine */
    ((struct tpacket3_hdr *)(b + 48))->tp_snaplen = BLK - 48 - 82;
    w.n = 0;
    CHECK(rawring_walk_block(b, BLK, cb, &w) == 1 && w.n == 1);
    CHECK(w.seen[0].data + w.seen[0].caplen == b + BLK);

    /* tp_mac past the end */
    ((struct tpacket3_hdr *)(b + 48))->tp_snaplen = 0;
    ((struct tpacket3_hdr *)(b + 48))->tp_mac = (uint16_t)(BLK - 48 + 1);
    w.n = 0;
    CHECK(rawring_walk_block(b, BLK, cb, &w) == 0 && w.n == 0);

    /* first-packet offset outside the block, or leaving no room for a
     * header */
    ((struct tpacket3_hdr *)(b + 48))->tp_mac = 82;
    ((struct tpacket_block_desc *)b)->hdr.bh1.offset_to_first_pkt = BLK + 16;
    w.n = 0;
    CHECK(rawring_walk_block(b, BLK, cb, &w) == 0);
    ((struct tpacket_block_desc *)b)->hdr.bh1.offset_to_first_pkt = BLK - 16;
    w.n = 0;
    CHECK(rawring_walk_block(b, BLK, cb, &w) == 0);
    /* room for the header but not for the sockaddr_ll behind it */
    ((struct tpacket_block_desc *)b)->hdr.bh1.offset_to_first_pkt = BLK - 64;
    w.n = 0;
    CHECK(rawring_walk_block(b, BLK, cb, &w) == 0);

    /* a block shorter than its descriptor */
    w.n = 0;
    CHECK(rawring_walk_block(b, 8, cb, &w) == 0);

    free(b);
}
#endif /* __linux__ */

int main(void) {
    test_geometry();
#ifdef __linux__
    test_walk_basic();
    test_walk_malformed();
#endif
    TEST_MAIN_END();
}
