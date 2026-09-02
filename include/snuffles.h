#ifndef SNUFFLES_H
#define SNUFFLES_H

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #include <winsock2.h>
  #include <windows.h>
  #include <ws2tcpip.h>

  typedef HANDLE              ns_thread_t;
  typedef CRITICAL_SECTION    ns_mutex_t;
  typedef CONDITION_VARIABLE  ns_cond_t;

  struct timeval_compat {
      long tv_sec;
      long tv_usec;
  };
  #ifndef _STRUCT_TIMEVAL
    #define _STRUCT_TIMEVAL
  #endif

  static inline int ns_thread_create(ns_thread_t *t, void *(*fn)(void *), void *arg) {
      *t = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)fn, arg, 0, NULL);
      return (*t == NULL) ? -1 : 0;
  }
  static inline int ns_thread_join(ns_thread_t t) {
      WaitForSingleObject(t, INFINITE);
      CloseHandle(t);
      return 0;
  }
  static inline int ns_mutex_init(ns_mutex_t *m) {
      InitializeCriticalSection(m);
      return 0;
  }
  static inline int ns_mutex_lock(ns_mutex_t *m) {
      EnterCriticalSection(m);
      return 0;
  }
  static inline int ns_mutex_unlock(ns_mutex_t *m) {
      LeaveCriticalSection(m);
      return 0;
  }
  static inline void ns_mutex_destroy(ns_mutex_t *m) {
      DeleteCriticalSection(m);
  }
  static inline int ns_cond_init(ns_cond_t *c) {
      InitializeConditionVariable(c);
      return 0;
  }
  static inline int ns_cond_signal(ns_cond_t *c) {
      WakeConditionVariable(c);
      return 0;
  }
  static inline int ns_cond_wait(ns_cond_t *c, ns_mutex_t *m) {
      SleepConditionVariableCS(c, m, INFINITE);
      return 0;
  }
  static inline int ns_cond_timedwait(ns_cond_t *c, ns_mutex_t *m, uint32_t ms) {
      SleepConditionVariableCS(c, m, ms);
      return 0;
  }
  static inline void ns_cond_destroy(ns_cond_t *c) {
      (void)c;
  }
#else
  #include <pthread.h>
  #include <sys/time.h>
  #include <unistd.h>
  #include <arpa/inet.h>
  #include <pwd.h>
  #include <grp.h>
  #include <stdlib.h>

  /* Drop root privileges after the capture socket/handle is open.
   * Target: the invoking user (real uid, or SUDO_UID under sudo),
   * falling back to "nobody". Returns 0 on success or nothing to drop,
   * -1 if the drop failed or could not be verified — the caller should
   * warn loudly, since capture then continues with root privileges. */
  static inline int ns_drop_privileges(void) {
      if (geteuid() != 0) return 0;

      uid_t uid = getuid();
      gid_t gid = getgid();
      if (uid == 0) {
          const char *su = getenv("SUDO_UID"), *sg = getenv("SUDO_GID");
          if (su && sg) {
              uid = (uid_t)strtoul(su, NULL, 10);
              gid = (gid_t)strtoul(sg, NULL, 10);
          }
      }
      if (uid == 0) {
          struct passwd *pw = getpwnam("nobody");
          if (!pw) return -1;
          uid = pw->pw_uid;
          gid = pw->pw_gid;
      }
      if (uid == 0) return -1;

      if (setgroups(0, NULL) != 0) return -1;
      if (setgid(gid) != 0) return -1;
      if (setuid(uid) != 0) return -1;
      /* verify the drop is irreversible */
      if (setuid(0) == 0 || geteuid() == 0) return -1;
      return 0;
  }

  typedef pthread_t         ns_thread_t;
  typedef pthread_mutex_t   ns_mutex_t;
  typedef pthread_cond_t    ns_cond_t;

  static inline int ns_thread_create(ns_thread_t *t, void *(*fn)(void *), void *arg) {
      return pthread_create(t, NULL, fn, arg);
  }
  static inline int ns_thread_join(ns_thread_t t) {
      return pthread_join(t, NULL);
  }
  static inline int ns_mutex_init(ns_mutex_t *m) {
      return pthread_mutex_init(m, NULL);
  }
  static inline int ns_mutex_lock(ns_mutex_t *m) {
      return pthread_mutex_lock(m);
  }
  static inline int ns_mutex_unlock(ns_mutex_t *m) {
      return pthread_mutex_unlock(m);
  }
  static inline void ns_mutex_destroy(ns_mutex_t *m) {
      pthread_mutex_destroy(m);
  }
  static inline int ns_cond_init(ns_cond_t *c) {
      return pthread_cond_init(c, NULL);
  }
  static inline int ns_cond_signal(ns_cond_t *c) {
      return pthread_cond_signal(c);
  }
  static inline int ns_cond_wait(ns_cond_t *c, ns_mutex_t *m) {
      return pthread_cond_wait(c, m);
  }
  static inline int ns_cond_timedwait(ns_cond_t *c, ns_mutex_t *m, uint32_t ms) {
      struct timespec ts;
      struct timeval tv;
      gettimeofday(&tv, NULL);
      ts.tv_sec  = tv.tv_sec + ms / 1000;
      ts.tv_nsec = (long)tv.tv_usec * 1000 + (long)(ms % 1000) * 1000000;
      if (ts.tv_nsec >= 1000000000L) {
          ts.tv_sec++;
          ts.tv_nsec -= 1000000000L;
      }
      return pthread_cond_timedwait(c, m, &ts);
  }
  static inline void ns_cond_destroy(ns_cond_t *c) {
      pthread_cond_destroy(c);
  }
#endif

/* ── Version ─────────────────────────────────────────────────── */

#define SNUFFLES_VERSION_MAJOR 1
#define SNUFFLES_VERSION_MINOR 4
#define SNUFFLES_VERSION_PATCH 0
#define SNUFFLES_VERSION_STR   "1.4.0"
#define SNUFFLES_NAME          "Snuffles"

/* ── Protocol IDs ────────────────────────────────────────────── */

typedef enum {
    PROTO_UNKNOWN = 0,
    PROTO_ETH,
    PROTO_VLAN,
    PROTO_ARP,
    PROTO_IPV4,
    PROTO_IPV6,
    PROTO_ICMP4,
    PROTO_ICMP6,
    PROTO_TCP,
    PROTO_UDP,
    PROTO_SCTP,
    PROTO_DNS,
    PROTO_HTTP,
    PROTO_TLS,
    PROTO_DHCP,
    PROTO_NTP,
    PROTO_MDNS,
    PROTO_QUIC,
    PROTO_MAX
} proto_id_t;

static inline const char *proto_name(proto_id_t id) {
    static const char *names[] = {
        [PROTO_UNKNOWN] = "???",
        [PROTO_ETH]     = "ETH",
        [PROTO_VLAN]    = "VLAN",
        [PROTO_ARP]     = "ARP",
        [PROTO_IPV4]    = "IPv4",
        [PROTO_IPV6]    = "IPv6",
        [PROTO_ICMP4]   = "ICMP",
        [PROTO_ICMP6]   = "ICMPv6",
        [PROTO_TCP]     = "TCP",
        [PROTO_UDP]     = "UDP",
        [PROTO_SCTP]    = "SCTP",
        [PROTO_DNS]     = "DNS",
        [PROTO_HTTP]    = "HTTP",
        [PROTO_TLS]     = "TLS",
        [PROTO_DHCP]    = "DHCP",
        [PROTO_NTP]     = "NTP",
        [PROTO_MDNS]    = "mDNS",
        [PROTO_QUIC]    = "QUIC",
    };
    if (id >= PROTO_MAX) return "???";
    return names[id];
}

/* ── Protocol label (text for pkt_summary_t.protocol) ─────────── */

/* The dissector records which label the protocol column gets; the text
 * is produced later by summary_format(). Zero means nothing was decoded
 * (empty column, e.g. a truncated frame). proto_id_t values are shifted
 * by one, and the link-layer labels that have no proto_id_t follow. */
typedef enum {
    LABEL_NONE   = 0,
    LABEL_PROTO0 = 1,                       /* LABEL_PROTO0 + proto_id_t */
    LABEL_SLL    = LABEL_PROTO0 + PROTO_MAX,
    LABEL_SLL2,
    LABEL_LOOP,
    LABEL_RAW,
} proto_label_t;

static inline uint8_t proto_label_of(proto_id_t id) {
    return (uint8_t)(LABEL_PROTO0 + id);
}

static inline const char *proto_label_str(uint8_t label) {
    if (label == LABEL_NONE) return "";
    if (label < LABEL_SLL)   return proto_name((proto_id_t)(label - LABEL_PROTO0));
    switch (label) {
        case LABEL_SLL:  return "SLL";
        case LABEL_SLL2: return "SLL2";
        case LABEL_LOOP: return "LOOP";
        case LABEL_RAW:  return "RAW";
        default:         return "";
    }
}

/* ── Info line ingredients ───────────────────────────────────── */

/* Which member of pkt_summary_t.u is live and which sentence
 * summary_format() builds from it. INFO_NONE leaves the line empty. */
typedef enum {
    INFO_NONE = 0,
    INFO_ETH,           /* "src -> dst type=0x%04x" (unknown EtherType) */
    INFO_L2_FRAME,      /* "SLL frame type=0x%04x" (cooked, unknown EtherType) */
    INFO_LOOP,          /* "loopback family=%u" */
    INFO_BAD_DLT,       /* "Unknown datalink %d" */
    INFO_RAWIP,         /* "Raw IP (ver=%d, len=%u)" (raw backend, no Ethernet) */
    INFO_ARP,
    INFO_IP4_FRAG,      /* non-first IPv4 fragment */
    INFO_IP4_PROTO,     /* IPv4 with an undissected protocol */
    INFO_IP6_FRAG,
    INFO_IP6_TRUNC,     /* IPv6 extension chain runs past the capture */
    INFO_IP6_NEXT,      /* IPv6 with an undissected next header */
    INFO_ICMP4,
    INFO_ICMP6,
    INFO_TCP,
    INFO_UDP,
    INFO_SCTP,
    INFO_DNS,
    INFO_HTTP,
    INFO_TLS,
    INFO_DHCP,
    INFO_NTP,
    INFO_QUIC,
} info_kind_t;

/* DNS answer surfaced in the info line (u.dns.rdata_kind) */
enum { DNS_RDATA_NONE = 0, DNS_RDATA_A, DNS_RDATA_AAAA, DNS_RDATA_CNAME };

/* ── Packet summary (filled by dissector) ────────────────────── */

/* The dissector fills the binary fields only (addresses, ports, ids, the
 * info-line ingredients in .u) and sets text_pending; the text columns
 * are produced from them by summary_format() when a consumer displays or
 * exports the record, never on the capture thread. A summary built by
 * hand with its text columns filled and text_pending clear is used as is. */
typedef struct {
    char        src_mac[18];
    char        dst_mac[18];
    char        src_ip[46];
    char        dst_ip[46];
    uint16_t    src_port;
    uint16_t    dst_port;
    /* Binary addresses for the session table (IPv4 in the first 4 bytes,
     * the rest zero; IPv6 all 16). addr_family: 0 = none, 4 or 6. */
    uint8_t     src_addr[16];
    uint8_t     dst_addr[16];
    uint8_t     addr_family;
    char        protocol[16];
    char        info[128];
    uint32_t    length;
    struct timeval ts;

    /* extended fields for filtering */
    uint16_t    vlan_id;
    uint16_t    ethertype;
    uint8_t     ip_ttl;
    uint8_t     ip_proto;       /* IP protocol number (6=TCP, 17=UDP, etc.) */
    uint16_t    ip_checksum;
    uint16_t    ip_id;
    uint16_t    ip_frag_off;    /* IPv4 layout: flags<<13 | offset/8; also set
                                 * from an IPv6 fragment header (MF as bit 13) */
    uint8_t     tcp_flags;
    uint32_t    tcp_seq;
    uint32_t    tcp_ack;
    uint16_t    tcp_window;
    uint16_t    tcp_checksum;
    proto_id_t  l3_proto;
    proto_id_t  l4_proto;
    proto_id_t  l7_proto;
    proto_id_t  highest_proto;
    uint32_t    session_id;

    /* L4 payload location within the captured bytes. l7_len is set only on
     * the TCP path (0 elsewhere/on truncation). Invariant, enforced by
     * dissect_packet: l7_off + l7_len <= caplen. */
    uint32_t    l7_off;
    uint32_t    l7_len;

    /* ── Binary form of the text columns (see summary_format) ── */
    uint8_t     src_mac_raw[6];
    uint8_t     dst_mac_raw[6];
    uint8_t     has_mac;        /* an Ethernet header was decoded */
    uint8_t     proto_label;    /* proto_label_t: text for .protocol */
    uint8_t     info_kind;      /* info_kind_t: which .u member is live */
    uint8_t     text_pending;   /* 1: text columns not yet produced */
    union {
        struct { uint32_t family; }                 loop;   /* INFO_LOOP */
        struct { int32_t  dlt; }                    bad_dlt;
        struct { uint32_t len; uint8_t ver; }       rawip;
        struct { uint16_t op; uint8_t sha[6]; }     arp;    /* spa/tpa: src/dst_addr */
        struct { uint16_t id, seq;
                 uint8_t  type, code, echo; }       icmp;   /* echo: "id= seq=" form */
        struct { uint16_t len; }                    udp;
        struct {
            uint16_t qtype;                 /* 0 when absent */
            uint8_t  response;
            uint8_t  rcode;
            uint8_t  rdata_kind;            /* DNS_RDATA_* */
            uint8_t  rdata[16];             /* A: 4 bytes, AAAA: 16 */
            char     name[128];             /* NUL-terminated, from the packet */
        } dns;
        struct { uint8_t request; uint8_t len;
                 char line[120]; }                  http;   /* first line, no NUL */
        struct { uint8_t hs_type; uint8_t sni_len;
                 char sni[110]; }                   tls;    /* NUL-terminated */
        struct { int16_t msg_type;              /* -1 when absent */
                 uint8_t op, has_addr;
                 uint8_t addr[4]; }                 dhcp;
        struct { uint8_t vn, mode, stratum; }       ntp;
        struct { uint32_t version; uint8_t ptype; } quic;
    } u;
} pkt_summary_t;

/* ── Packet record (stored in ring buffer) ───────────────────── */

typedef struct {
    pkt_summary_t   summary;
    uint8_t        *raw_data;
    uint32_t        raw_len;
    uint32_t        prod_id;    /* ring buffer: producer that wrote it */
    uint64_t        data_pos;   /* ring buffer: arena position of raw_data */
    uint64_t        seq_num;
} pkt_record_t;

/* ── Capture configuration ───────────────────────────────────── */

typedef struct {
    char        iface[64];
    char        pcap_file[512];
    char        bpf_filter[512];
    char        output_file[512];
    int         promisc;
    int         snaplen;
    int         ring_size;
    int         count;
    int         no_ui;
    int         quiet;          /* -q / --quiet: no terminal output at all */
    int         jsonl;          /* --jsonl: stream JSON Lines to stdout */
    char        stream_file[512]; /* -w: write pcap while capturing */
    int         list_ifaces;
    int         verbose;
    char        syslog_target[256];
    char        syslog_iface[64];
    int         syslog_threads;     /* --syslog-threads: most syslog output threads (one UDP
                                       socket each), 1-16; 0 = auto (CPUs we may run on, <= 16) */
    int         syslog_min_threads; /* --syslog-min-threads: ones that exist always, 1-16; 0 = 1 */
    int         buffer_mb;      /* -B: kernel capture buffer in MB (TPACKET ring; raw: SO_RCVBUF fallback) */
    int         arena_mb;       /* --arena-mb: payload arena in MB (0: ring x min(snaplen, 2 KB)) */
    int         immediate;      /* --immediate: per-packet delivery (no TPACKET_V3 blocks) */
    int         no_summary;     /* --no-summary: no exit counters in headless modes */
    int         cpu;            /* --cpu: pin the capture thread to this CPU (-1: unset) */
    int         workers;        /* -j/--workers: capture workers (PACKET_FANOUT), 1 = default */
    int         rt;             /* --rt: SCHED_FIFO for the capture thread */
} capture_cfg_t;

/* Default snaplen: whole frames for the TUI hex view; headless modes and
 * -w drop to one MTU-sized Ethernet frame (1500 + 14 + 4 VLAN) unless
 * -s / the config file say otherwise. */
#define NS_DEFAULT_SNAPLEN  65535
#define NS_HEADLESS_SNAPLEN 1518

static inline void capture_cfg_defaults(capture_cfg_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->promisc   = 1;
    cfg->snaplen   = NS_DEFAULT_SNAPLEN;
    cfg->ring_size = 10000;
    cfg->count     = 0;
    cfg->buffer_mb = 64;
    cfg->cpu       = -1;
    cfg->workers   = 1;
}

/* ── Default interface ───────────────────────────────────────── */

#ifdef __APPLE__
  #define NS_DEFAULT_IFACE "en0"
#elif defined(_WIN32)
  #define NS_DEFAULT_IFACE ""
#else
  #define NS_DEFAULT_IFACE ""
#endif

/* ── Common macros ───────────────────────────────────────────── */

#define NS_MIN(a, b) ((a) < (b) ? (a) : (b))
#define NS_MAX(a, b) ((a) > (b) ? (a) : (b))

#define NS_ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

/* Dotted-quad / RFC 5952 text of a binary address (family 4 or 6, as in
 * pkt_summary_t.src_addr); an unknown family yields "". IPv4 is written
 * by hand — the capture thread's syslog path and new-session bookkeeping
 * use this, and they must not pay for snprintf. buf must hold 46 bytes. */
static inline void ns_ip_str(uint8_t family, const uint8_t *addr,
                             char *buf, size_t len) {
    if (family == 4 && len >= 16) {
        char *p = buf;
        for (int i = 0; i < 4; i++) {
            unsigned v = addr[i];
            if (v >= 100) { *p++ = (char)('0' + v / 100); v %= 100;
                            *p++ = (char)('0' + v / 10);  v %= 10; }
            else if (v >= 10) { *p++ = (char)('0' + v / 10); v %= 10; }
            *p++ = (char)('0' + v);
            *p++ = '.';
        }
        p[-1] = '\0';
    } else if (family == 6 && len >= 46) {
        struct in6_addr a6;
        memcpy(&a6, addr, 16);
        if (!inet_ntop(AF_INET6, &a6, buf, (socklen_t)len)) buf[0] = '\0';
    } else if (len > 0) {
        buf[0] = '\0';
    }
}

/* Portable localtime into caller storage. */
static inline struct tm *ns_localtime(const time_t *t, struct tm *out) {
#ifdef _WIN32
    return (localtime_s(out, t) == 0) ? out : NULL;
#else
    return localtime_r(t, out);
#endif
}

#endif /* SNUFFLES_H */
