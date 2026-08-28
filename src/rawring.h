#ifndef RAWRING_H
#define RAWRING_H

#include <stdint.h>
#include <stddef.h>

/* PACKET_RX_RING (TPACKET_V3) helpers for the raw-socket backend. Pure
 * functions over a block of memory, so the ring geometry and the block
 * walk — including its bounds checks — are unit-testable without a
 * packet socket. The walk itself is Linux-only (kernel header layouts). */

#define RAWRING_BLOCK_SIZE  (256u * 1024u)  /* one block = one wakeup */
#define RAWRING_FRAME_SIZE  2048u           /* unused by V3, required */
#define RAWRING_RETIRE_MS   10u             /* block retire timeout */

typedef struct {
    uint32_t block_size;    /* multiple of the page size */
    uint32_t block_nr;      /* >= 1 */
    uint32_t frame_size;
    uint32_t frame_nr;      /* block_nr * (block_size / frame_size) */
} rawring_geom_t;

/* Sizes a ring of about buffer_mb MiB: RAWRING_BLOCK_SIZE blocks (rounded
 * up to a multiple of page_size), at least one block. Returns the ring
 * size in bytes (the mmap length). */
size_t rawring_geometry(int buffer_mb, long page_size, rawring_geom_t *g);

typedef struct {
    const uint8_t *data;    /* start of the frame (MAC header) */
    uint32_t caplen;        /* bytes present in the ring */
    uint32_t wirelen;       /* on-the-wire length */
    uint32_t sec, nsec;     /* kernel receive timestamp */
    int      ifindex;       /* sockaddr_ll: receiving interface */
    uint8_t  pkttype;       /* sockaddr_ll: PACKET_HOST/_OUTGOING/... */
} rawring_frame_t;

/* Called per frame; a nonzero return stops the walk. */
typedef int (*rawring_frame_cb)(void *user, const rawring_frame_t *f);

#ifdef __linux__
/* Walks the frames of one closed TPACKET_V3 block in order and calls cb
 * for each. Stops early when cb returns nonzero or when an offset points
 * outside the block (a malformed block is abandoned, never read past).
 * Returns the number of frames handed to cb. */
uint32_t rawring_walk_block(const uint8_t *block, uint32_t block_size,
                            rawring_frame_cb cb, void *user);
#endif

#endif /* RAWRING_H */
