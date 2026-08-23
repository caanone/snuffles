#ifndef EXPORT_PCAP_H
#define EXPORT_PCAP_H

#include "snuffles.h"
#include "ringbuf.h"
#include "filter.h"

typedef struct pcap_writer pcap_writer_t;

pcap_writer_t  *pcap_writer_open(const char *path, uint32_t snaplen, uint32_t linktype);
int             pcap_writer_write(pcap_writer_t *pw, const pkt_record_t *rec);
/* Returns 0 if all buffered data reached the file, -1 otherwise. */
int             pcap_writer_close(pcap_writer_t *pw);
uint64_t        pcap_writer_count(const pcap_writer_t *pw);

int export_pcap(const char *path, ringbuf_t *rb,
                const display_filter_t *filt, uint32_t snaplen,
                int linktype);

#endif /* EXPORT_PCAP_H */
