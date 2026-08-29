#include "export_pcap.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* PCAP file format constants (libpcap/tcpdump native byte order) */
#define PCAP_MAGIC       0xa1b2c3d4
#define PCAP_VERSION_MAJ 2
#define PCAP_VERSION_MIN 4

#pragma pack(push, 1)
typedef struct {
    uint32_t magic;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t linktype;
} pcap_file_hdr_t;

typedef struct {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} pcap_pkt_hdr_t;
#pragma pack(pop)

struct pcap_writer {
    FILE     *fp;
    uint32_t  snaplen;
    uint64_t  count;
    int       to_stdout;
    char     *buf;      /* stdio buffer (file); stdout uses a static one */
};

/* stdio buffer: with the default 4 KB block a write() every ~3 small
 * packets made -w to disk cost ~1.4 us per packet; 1 MB turns that into
 * one write() per ~700 full-size frames. The writer's owner flushes when
 * it goes idle. */
#define PCAP_WRITER_BUF (1 << 20)

pcap_writer_t *pcap_writer_open(const char *path, uint32_t snaplen, uint32_t linktype) {
    pcap_writer_t *pw = calloc(1, sizeof(pcap_writer_t));
    if (!pw) return NULL;

    /* The buffer is supplied explicitly: given a NULL buf, glibc and musl
       ignore the size and hand out their default block. Set before the
       first write (setvbuf must precede any I/O on the stream). */
    if (strcmp(path, "-") == 0) {
        static char outbuf[PCAP_WRITER_BUF];   /* outlives the stream */
        pw->fp = stdout;
        pw->to_stdout = 1;
        setvbuf(pw->fp, outbuf, _IOFBF, sizeof(outbuf));
    } else {
        pw->fp = fopen(path, "wb");
        if (pw->fp) {
            pw->buf = malloc(PCAP_WRITER_BUF);
            if (pw->buf)
                setvbuf(pw->fp, pw->buf, _IOFBF, PCAP_WRITER_BUF);
        }
    }
    if (!pw->fp) { free(pw); return NULL; }

    pw->snaplen = snaplen;

    pcap_file_hdr_t hdr = {
        .magic         = PCAP_MAGIC,
        .version_major = PCAP_VERSION_MAJ,
        .version_minor = PCAP_VERSION_MIN,
        .thiszone      = 0,
        .sigfigs       = 0,
        .snaplen       = snaplen,
        .linktype      = linktype,
    };

    if (fwrite(&hdr, sizeof(hdr), 1, pw->fp) != 1) {
        if (!pw->to_stdout) fclose(pw->fp);
        free(pw->buf);
        free(pw);
        return NULL;
    }

    return pw;
}

int pcap_writer_write(pcap_writer_t *pw, const pkt_record_t *rec) {
    if (!pw || !pw->fp) return -1;

    uint32_t incl = rec->raw_len;
    if (incl > pw->snaplen) incl = pw->snaplen;

    pcap_pkt_hdr_t phdr = {
        .ts_sec   = (uint32_t)rec->summary.ts.tv_sec,
        .ts_usec  = (uint32_t)rec->summary.ts.tv_usec,
        .incl_len = incl,
        .orig_len = rec->summary.length,
    };

    if (fwrite(&phdr, sizeof(phdr), 1, pw->fp) != 1) return -1;
    if (fwrite(rec->raw_data, 1, incl, pw->fp) != incl) return -1;

    pw->count++;
    return 0;
}

int pcap_writer_flush(pcap_writer_t *pw) {
    if (!pw || !pw->fp) return -1;
    return fflush(pw->fp) == 0 ? 0 : -1;
}

uint64_t pcap_writer_count(const pcap_writer_t *pw) {
    return pw ? pw->count : 0;
}

int pcap_writer_close(pcap_writer_t *pw) {
    if (!pw) return 0;
    int rc = 0;
    if (pw->fp) {
        if (pw->to_stdout) {
            if (fflush(pw->fp) != 0) rc = -1;   /* never fclose stdout */
        } else if (fclose(pw->fp) != 0) {
            rc = -1;
        }
    }
    free(pw->buf);   /* after fclose: the stream used it until then */
    free(pw);
    return rc;
}

int export_pcap(const char *path, ringbuf_t *rb,
                const display_filter_t *filt, uint32_t snaplen,
                int linktype) {
    pcap_writer_t *pw = pcap_writer_open(path, snaplen, (uint32_t)linktype);
    if (!pw) return -1;

    uint32_t count = ringbuf_count(rb);
    int written = 0;

    /* Copy each record out of the ring: the capture thread may still be
     * overwriting the oldest slots while we iterate. */
    uint8_t *data = malloc(rb->snaplen);
    if (!data) { pcap_writer_close(pw); return -1; }

    pkt_record_t rec;
    for (uint32_t i = 0; i < count; i++) {
        if (!ringbuf_read(rb, i, &rec, data)) continue;

        if (filt && filt->valid && filt->root >= 0) {
            if (!filter_eval(filt, &rec.summary))
                continue;
        }

        if (pcap_writer_write(pw, &rec) != 0) {
            free(data);
            pcap_writer_close(pw);
            return -1;
        }
        written++;
    }

    free(data);
    if (pcap_writer_close(pw) != 0) return -1;
    return written;
}
