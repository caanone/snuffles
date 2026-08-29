#ifndef DISSECT_H
#define DISSECT_H

#include "snuffles.h"

/* Fill the binary summary (addresses, ports, ids, info-line ingredients)
 * from the captured bytes. Does no string formatting: the text columns
 * stay empty and text_pending is set — see summary_format(). */
void dissect_packet(const uint8_t *data, uint32_t caplen,
                    int datalink_type, pkt_summary_t *out);

/* Produce the text columns (src_mac/dst_mac, src_ip/dst_ip, protocol,
 * info) from the binary summary. Idempotent: does nothing once the text
 * is in place (text_pending == 0), including for summaries built by hand
 * with their text filled in. Every consumer that reads a text column of a
 * record from the ring calls this on its own copy first. */
void summary_format(pkt_summary_t *s);

void format_mac(const uint8_t *mac, char *buf, size_t len);
void format_hex_dump(const uint8_t *data, uint32_t len,
                     char *buf, size_t bufsize);

#endif /* DISSECT_H */
