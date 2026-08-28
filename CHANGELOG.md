# Changelog

## [Unreleased]

### Changed
- **Session table rebuilt for flow churn.** Keys are now a packed binary
  5-tuple (canonical order, so both directions of a flow hit one entry)
  compared with `memcmp` and hashed with a per-process seeded xxHash-style
  mixer (no hash flooding); the bucket array is a power of two of at least
  twice the 100 000-session cap (262 144 buckets instead of 4 096, so the
  mean chain is under one entry when full); chains are doubly linked so
  evicting the LRU tail is O(1) instead of a second chain walk; entries
  come from a preallocated pool with a free list, so the packet path
  performs no `calloc`/`free` once warm; the display strings are formatted
  once per new session instead of two `snprintf`s per packet. The
  dissector now fills binary address fields (`src_addr`/`dst_addr`/
  `addr_family`) next to the existing strings. Visible side effect: the
  Sessions view's side A is now the numerically lower address (then the
  lower port) instead of the lexically lower string, so some pairs swap
  columns compared with v1.3.1 (e.g. 8.8.8.8 is side A next to 10.0.0.1);
  stream direction 0/1 in "Follow stream" follows the same rule. Micro-benchmark, 1 M
  distinct flows into the 100 k cap: 1 490 -> 130 ns per packet; hits on
  100 k resident flows: 415 -> 90 ns; live 400 k-flow UDP flood on `lo`:
  process user CPU 1.05 s -> 0.30 s per 300 k packets.
- **TCP stream buffers are recycled.** The 16 MB reassembly budget used to
  go to the first ~512 payload-carrying sessions for the life of the
  capture. Now a session that reaches CLOSED/RST keeps its bytes viewable
  but becomes the first reclaim candidate, holders idle for 60 s
  (`session_table_t.reasm_idle_sec`, packet-timestamp clock) release their
  buffers, and when the budget is exhausted a new payload-carrying session
  takes the oldest holder's buffers. Freed buffers go to a free list, not
  back to `malloc`.

### Fixed
- **Non-first IP fragments no longer create port-0 pseudo-sessions**
  (IPv4 and IPv6; the IPv6 fragment header now also fills `ip_frag_off`
  in the IPv4 layout: offset in the low 13 bits, MF as bit 13, and `ip_id`
  with the low 16 bits of the fragment identification, so the syslog CSV
  `ip_id`/`frag` columns are no longer always 0 for IPv6 fragments).

- **Ring buffer producer no longer pays a wakeup per packet.** Every commit
  used to lock/signal an unused condition variable and `write()` one byte
  to the consumer's notify pipe (a syscall per packet, `EAGAIN` once the
  pipe filled). Consumers now announce that they are about to block
  (`ringbuf_consumer_will_wait`) and re-check the ring before sleeping;
  the producer writes to the pipe (or signals the Win32 event) only when
  it finds that flag set, and claims it, so an idle period costs one
  syscall instead of one per packet. Under sustained load the capture
  thread makes no wakeup syscalls at all. `--stats` reports the delivered
  wakeups as `wakeups=`.

## [1.3.1] — 2026-08-27

### Fixed
- **Ring buffer torn reads on weakly-ordered CPUs (arm64)**: the seqlock
  was missing both memory fences — a release fence after the producer's
  write-begin mark, and an acquire fence before the reader's generation
  recheck. Without them a reader could validate a half-overwritten packet
  record, corrupting the TUI, headless output, and exports. x86's stronger
  ordering masked this completely; it was found by running the test suite
  on Apple Silicon.

  **Anyone running v1.3.0 on arm64 (Apple Silicon, arm64 Linux) should
  upgrade.** x86_64 builds are unaffected in practice.

### Changed
- CI: every job that builds now also runs the full test suite. The macOS
  job (Apple Silicon) previously only compiled and smoke-tested, which is
  why the above escaped; added a Linux arm64 job as a second
  weakly-ordered platform, plus `make test`, `make test SAN=1` and
  `make test-stress` so the suites run off the make path too.

## [1.3.0] — 2026-08-27

### Added
- **TCP stream reassembly + follow-stream**: per-direction, budget-capped
  reassembly (retransmit-safe, gap-aware, snaplen-aware) under the session
  table; press `O` on a session to read both directions as text
- **UDP dissectors**: DHCP (message types, addresses), NTP (mode/version/
  stratum), mDNS, and QUIC long-header recognition, with filter shorthands
- **Config file** `~/.snufflesrc` (or `$SNUFFLES_CONFIG`): defaults for
  interface/snaplen/ring/promisc/syslog plus named display-filter presets,
  usable in the TUI as `@name`
- Windows: console mode restored on exit; Winsock initialized explicitly

## [1.2.0] — 2026-08-27

### Added
- Raw-socket builds get kernel BPF on Linux: a built-in classic-BPF
  compiler (subset: proto, `[src|dst] host`, `[src|dst] port`, `and`)
  attaches via `SO_ATTACH_FILTER`, for both `-f` and the TUI `[B]` prompt
- DNS response dissection: rcode and the first A/AAAA answer
- Scrollable detail-panel hex dump (Left/Right)
- Man page (`docs/snuffles.1`) and `make install`/`uninstall`

### Fixed
- Session eviction at the cap is O(1) via an intrusive LRU list
  (was a full-table scan per new session)
- Capture-thread errors now show in the TUI title bar and set a nonzero
  exit code instead of dying silently with exit 0
- Arrow keys inside Filter/BPF/Export/Search prompts no longer cancel
  the prompt and leak keys into normal mode

## [1.1.0] — 2026-08-23

The "audit release": a full multi-dimension review of the codebase followed
by five waves of fixes, hardening, tests, and features.

### Added
- **Streaming `-w <file>`** — write packets to a pcap file *while capturing*
  (tcpdump-style); `-w -` streams to stdout for piping into Wireshark
- **`--jsonl`** — headless mode emitting one JSON object per packet
- **`/` search** in the packet list (info, IPs, protocol), `n`/`N` for
  next/previous match
- **`[V]` protocol statistics overlay** — uptime, totals, rates, drops,
  per-protocol breakdown
- **New datalinks**: Linux cooked capture SLL/SLL2 (the `any` device) and
  BSD/macOS loopback (DLT_NULL/DLT_LOOP)
- **IPv6 extension-header walking** — hop-by-hop/routing/fragment/dest-opts/AH
  chains are traversed to the real L4
- Unit-test suites (filter, ring buffer, sessions, dissectors) via CTest;
  libFuzzer harnesses for the dissectors and filter compiler
- CI: Linux gcc/clang × make/CMake × pcap/raw, macOS, ASan/UBSan + LSan,
  fuzz smoke, and the full unit suite running on the **Windows** build
  under Wine (`scripts/test-windows.sh`, also usable locally via Docker)

### Fixed
- Build failure on gcc ≥ 14 / clang ≥ 16 (missing `<strings.h>`,
  feature-test macros hiding `struct ifreq` and friends)
- Torn reads of ring-buffer slots being overwritten by the capture thread
  (per-slot seqlock + copy-out API); corrupted exports from a live ring
- Session-table use-after-free (snapshots now copy entries under the lock)
- `pcap_t` used from two threads (stats and BPF changes now confined to
  the capture thread)
- Privilege dropping: the raw-socket backend never dropped root; the
  libpcap drop was unchecked and unverified — both now use one verified
  `setgroups`/`setgid`/`setuid` path
- Terminal escape injection via packet-derived strings (HTTP/DNS/SNI are
  sanitized to printable ASCII)
- Windows TUI extended keys (PgDn quit the program, Up opened Help)
- Terminal left in raw mode on crash/SIGQUIT/Ctrl+Z; TUI writing ANSI
  into pipes
- Display filter: `port == 443` failing to parse, `!=` acting as `==` on
  CIDR/ranges, either-side `!=` matching nearly everything, malformed
  CIDR matching everything, 64-token expressions reading out of bounds
- Syslog: infinite ICMP feedback loop when the collector is down;
  self-check swallowing all third-party traffic on the collector port
- pcap export hardcoding Ethernet linktype; export failures reported as
  success with exit code 0
- Non-first IPv4/IPv6 fragments misparsed as TCP/UDP garbage
- `--no-ui` silently shrinking the ring and disabling sessions contrary
  to the docs; `-b`/`-s` now always honored, invalid values rejected loudly
- Interface left in promiscuous mode after raw-backend exit
- Timestamps now display in local time

### Changed
- Makefile: per-variant object dirs, header dependency tracking, parallel
  `make debug` fixed; CMake exports `compile_commands.json`
- Lean memory mode applies only to syslog-forwarding modes, as documented

## [1.0.0]

Initial release.
