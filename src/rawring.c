/* rawring.c — TPACKET_V3 block-ring helpers (see rawring.h). */

#include "rawring.h"

#ifdef __linux__
  #include <linux/if_packet.h>
#endif

size_t rawring_geometry(int buffer_mb, long page_size, rawring_geom_t *g) {
    uint32_t page = page_size > 0 ? (uint32_t)page_size : 4096u;
    uint32_t bs   = RAWRING_BLOCK_SIZE;
    if (bs % page) bs = (bs / page + 1) * page;   /* 64 KiB pages etc. */

    uint64_t want = buffer_mb > 0 ? (uint64_t)buffer_mb << 20 : 0;
    uint64_t nr   = want / bs;
    if (nr < 1) nr = 1;
    if (nr > 65536) nr = 65536;                   /* sanity, not a limit hit */

    g->block_size = bs;
    g->block_nr   = (uint32_t)nr;
    g->frame_size = RAWRING_FRAME_SIZE;
    g->frame_nr   = g->block_nr * (bs / RAWRING_FRAME_SIZE);
    return (size_t)bs * g->block_nr;
}

#ifdef __linux__

uint32_t rawring_walk_block(const uint8_t *block, uint32_t block_size,
                            rawring_frame_cb cb, void *user) {
    if (block_size < sizeof(struct tpacket_block_desc)) return 0;
    const struct tpacket_hdr_v1 *bh =
        &((const struct tpacket_block_desc *)block)->hdr.bh1;

    uint32_t off = bh->offset_to_first_pkt;
    uint32_t n   = 0;
    for (uint32_t i = 0; i < bh->num_pkts; i++) {
        /* header + sockaddr_ll must lie inside the block (the kernel
         * aligns entries to 16 bytes, so an unaligned offset is
         * corruption as well) */
        if (off & (TPACKET_ALIGNMENT - 1)) break;
        if (off > block_size || block_size - off < TPACKET3_HDRLEN)
            break;
        const struct tpacket3_hdr *h =
            (const struct tpacket3_hdr *)(block + off);
        const struct sockaddr_ll *sll = (const struct sockaddr_ll *)
            (block + off + TPACKET_ALIGN(sizeof(struct tpacket3_hdr)));

        /* frame bytes must lie inside the block */
        uint32_t mac = off + h->tp_mac;
        if (h->tp_mac > block_size - off || h->tp_snaplen > block_size - mac)
            break;

        rawring_frame_t f = {
            .data    = block + mac,
            .caplen  = h->tp_snaplen,
            .wirelen = h->tp_len,
            .sec     = h->tp_sec,
            .nsec    = h->tp_nsec,
            .ifindex = sll->sll_ifindex,
            .pkttype = sll->sll_pkttype,
        };
        n++;
        if (cb(user, &f)) break;

        if (h->tp_next_offset == 0) break;   /* last entry of the block */
        if (h->tp_next_offset > block_size - off) break;
        off += h->tp_next_offset;
    }
    return n;
}

#endif /* __linux__ */
