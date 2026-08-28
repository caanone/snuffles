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
#define SNUFFLES_VERSION_MINOR 3
#define SNUFFLES_VERSION_PATCH 1
#define SNUFFLES_VERSION_STR   "1.3.1"
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

/* ── Packet summary (filled by dissector) ────────────────────── */

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
} pkt_summary_t;

/* ── Packet record (stored in ring buffer) ───────────────────── */

typedef struct {
    pkt_summary_t   summary;
    uint8_t        *raw_data;
    uint32_t        raw_len;
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
    int         buffer_mb;      /* -B: kernel capture buffer in MB (libpcap ring / raw SO_RCVBUF) */
    int         immediate;      /* --immediate: per-packet delivery (libpcap) */
} capture_cfg_t;

static inline void capture_cfg_defaults(capture_cfg_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->promisc   = 1;
    cfg->snaplen   = 65535;
    cfg->ring_size = 10000;
    cfg->count     = 0;
    cfg->buffer_mb = 64;
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

/* Portable localtime into caller storage. */
static inline struct tm *ns_localtime(const time_t *t, struct tm *out) {
#ifdef _WIN32
    return (localtime_s(out, t) == 0) ? out : NULL;
#else
    return localtime_r(t, out);
#endif
}

#endif /* SNUFFLES_H */
