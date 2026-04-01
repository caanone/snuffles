#ifndef DISSECT_H
#define DISSECT_H

#include "snuffles.h"

void dissect_packet(const uint8_t *data, uint32_t caplen,
                    int datalink_type, pkt_summary_t *out);

void format_mac(const uint8_t *mac, char *buf, size_t len);
void format_hex_dump(const uint8_t *data, uint32_t len,
                     char *buf, size_t bufsize);

#endif /* DISSECT_H */
