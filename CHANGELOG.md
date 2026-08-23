# Changelog

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
