#ifndef EXPORT_PCAP_H
#define EXPORT_PCAP_H

#include "snuffles.h"
#include "ringbuf.h"
#include "filter.h"

typedef struct pcap_writer pcap_writer_t;

/* Opens path ("-": stdout) with a 1 MB stdio buffer and writes the file
 * header. Writes are buffered: the owner calls pcap_writer_flush() when it
 * goes idle (a live pipe into wireshark sees the packets then). */
pcap_writer_t  *pcap_writer_open(const char *path, uint32_t snaplen, uint32_t linktype);
int             pcap_writer_write(pcap_writer_t *pw, const pkt_record_t *rec);
int             pcap_writer_flush(pcap_writer_t *pw);
/* Returns 0 if all buffered data reached the file, -1 otherwise. */
int             pcap_writer_close(pcap_writer_t *pw);
uint64_t        pcap_writer_count(const pcap_writer_t *pw);

int export_pcap(const char *path, ringbuf_t *rb,
                const display_filter_t *filt, uint32_t snaplen,
                int linktype);

#endif /* EXPORT_PCAP_H */
