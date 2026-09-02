# Changelog

## [Unreleased]

### Added
- **Syslog output threads are created and retired with the traffic.** A
  single output thread is bounded at ~200-330k records/s by the kernel's
  per-datagram send path (formatting is under 10% of the cost). One UDP
  socket per possible thread is opened at start (`--syslog-threads N|auto`,
  auto = the CPUs the process may run on, at most 16), but only
  `--syslog-min-threads` threads run (default 1). Workers claim records in
  32-record chunks from a shared cursor and keep a running busy fraction;
  when the unclaimed backlog exceeds an eighth of the ring, or the running
  threads average 90% busy with records queued, a running thread wakes a
  parked one or creates a new one (at most one every 2 ms); a helper parks
  when the others would average no more than 80% busy without it, and a
  parked thread exits after 3 s without work. The record format is
  unchanged; the collector sees up to N source ports. With `-w` the stream
  runs on a worker of its own. `--stats` gains `stream_missed=` (records the
  `-w` path lost, next to `out_missed=` for the syslog path),
  `syslog_threads=` (most threads alive at once since the previous line)
  and `syslog_alive=` (alive now). Config keys `syslog_threads` (a number or
  `auto`) and `syslog_min_threads`. Measured on the rig with no flags (30 s,
  four CPUs available): see the table below.

### Fixed
- An output worker could exit on stop with the last committed records
  unprocessed: it read the ring's total, flushed its batch, then saw the
  stop flag, which is set only after the capture thread's final commit.
  The window was a few nanoseconds for the single output thread of 1.4.0
  and a whole syslog flush for the chunk-claiming workers, where Wine and
  the macOS runner hit it. Workers now re-read the total under the flag.

### Changed
- **The lean `-q --syslog` forwarder sizes its ring to the kernel buffer**
  (8192 slots per MB of `-B`, 4096-65536; 65536 slots, ~38 MB, for the
  default 8 MB) instead of a fixed 4096. The capture thread hands over
  every retired kernel block in one go, and with 4096 slots (8 ms at
  500 kpps) four output threads at half a core each still lost 7% of the
  records to scheduling gaps. Re-measured on the rig at 500 kpps with four
  threads: 100% delivered, nothing missed, ~52% of a core per thread,
  ~51 MB RSS; at 1 Mpps the same four threads deliver 77% (from 40%) and
  are CPU-bound on the rig's two SUT cores. `-b` overrides the size; the
  payload arena stays at 1 MB. `-w` no longer selects the lean defaults,
  since the stream needs whole payloads.
- The concurrency stress loop in CI (`make test-stress`) prints the output
  of every failing round and a manual workflow run can set the round count,
  after a 1-in-30 failure on the macOS arm64 runner left no trace of which
  check tripped. The next occurrence named it: the multi-producer lapping
  test's reader had been descheduled for the entire run on the 3-core
  runner (`reads=0`, nothing torn), a run that validated nothing. The test
  now repeats a starved run instead of counting it either way.

## [1.4.0] - 2026-08-29

A performance release: a full load-test rig, a measured hardening pass over
the capture path, and seven bug fixes found while measuring. Under a
2.5 Mpps flood of 64-byte frames v1.3.1 captured ~600 kpps at 100% of a
core and dropped 79% of the traffic; v1.4.0 captures the same flood with
no kernel drops at under a third of a core, in 87 MB instead of 630 MB.

### Added
- **Load-test regression gate.** `loadtest/gate.sh` runs a fixed set of
  five rig scenarios (A2, A3d, A6, B3, B6 at 20 s) plus the `ndr.sh`
  no-drop-rate search on A-class 64 B traffic, compares `captured_pps`,
  `kdrop_pct_win` and `ndr_pps` against the committed
  `loadtest/gate-baseline.json`, prints a pass/fail table and exits
  non-zero on a regression. Tolerances (default: 15% below baseline for
  a rate, 2 points above for kernel drops) live in the baseline file and
  can be tuned per scenario; `--update-baseline` rewrites only the
  measured numbers and keeps existing tolerances. Flags: `--run-id`,
  `--duration`, `--skip-ndr`, `--only`, `--baseline`,
  `--update-baseline`. `.github/workflows/loadtest.yml` runs it manually
  (`workflow_dispatch`) on a self-hosted runner — never on push/PR,
  which GitHub-hosted runners cannot serve. `run-scenario.sh` gained
  `RS_SNF_EXTRA_ARGS` for appending snuffles arguments to a run.
- **`-j N` / `--workers N`: multi-worker capture with `PACKET_FANOUT`**
  (config key `workers`, 1-16, default 1 = unchanged behaviour). N capture
  sockets on the same interface join one `PACKET_FANOUT` group in
  `PACKET_FANOUT_HASH` mode (group id: the pid), each with its own thread,
  its own kernel buffer and its own session table shard, so one
  interface's capture work spreads over N cores instead of one. The flow
  hash keeps a flow on one worker and in order, so a session never spans
  shards; the shards hand out disjoint session ids and the TUI, `--stats`
  and exports show their union. `-B` is per worker (total kernel memory is
  N x B); `-c`, the display filter, `-w`, `--syslog` and the export are
  shared and unchanged. Linux live capture only: `-r`, other platforms and
  a handle that is not an `AF_PACKET` socket warn once and use one worker.
  The TUI title bar shows "N workers" and `--stats` adds per-worker kernel
  drops (`kdrop_w=a,b,c`). Records reach the ring in commit order, so with
  `-j N > 1` the list, `-w` and the exports are not strictly
  timestamp-sorted across flows (17% of records stepped back by up to one
  16 ms block interval on a 4-flow loopback run; a flow's own packets stay
  in order), and `--cpu` — which would pin every worker to one CPU — warns. Both backends: the libpcap build sets the
  socket option on each activated handle's descriptor (libpcap has no API
  for it), the raw build before each ring is mapped.
- **Multi-producer ring buffer.** With `-j N > 1` the capture workers all
  commit into the one ring: a producer reserves a sequence with one
  fetch-add, takes the slot from the record one lap back with a CAS (so
  two producers can never write one slot — a producer descheduled for a
  whole lap would otherwise corrupt the record that replaced it, with no
  generation change for a reader to notice), fills it and publishes, and
  `commit_seq` then steps over the published prefix. Each producer
  bump-allocates payload bytes from its own slice of the arena. The
  single-producer path takes none of those atomics (measured: 109.6 vs
  109.2 ns of capture-thread CPU per packet, within run-to-run noise) and
  the slot generation now carries the record's sequence instead of
  counting writes, which also removes two atomic read-modify-writes per
  packet from it. `tests/test_ringbuf.c` adds a multi-producer
  completeness test (every reservation visible exactly once, in producer
  order, payloads intact) and a lapping stress test.
- **Telemetry on by default in headless modes.** `--no-ui`, `--jsonl` and
  `-q` print the `summary ...` counters line to stderr at exit even
  without `--stats` (`--no-summary` turns it off), `SIGUSR1` prints one
  `stats ...` line on demand, a hint follows the summary when the kernel
  dropped packets, and a frame longer than 1518 bytes on a non-jumbo
  interface warns once about GRO/GSO super-frames (libpcap build).
- **`--cpu N` and `--rt`** (config keys `cpu`, `rt`): pin the capture thread
  to one CPU — the consumer (headless printer or TUI) and the stats thread
  stay on the other CPUs — and run it under `SCHED_FIFO` priority 1 (set
  before the privilege drop; warns and continues without root/CAP_SYS_NICE).
- **Offline replay back-pressure.** `-r file` into a headless consumer waits
  for the consumer instead of lapping the ring, so every packet of the
  file is emitted with `missed=0` whatever `-b` is (a blocked stdout used
  to lose most of a 200 k-packet file). Ring buffer: `ringbuf_consumer_*`
  position hook and `ringbuf_producer_may_write()`.

### Changed
- **Lazy dissection: no string formatting on the capture thread.**
  `dissect_packet()` used to fill the text columns of every record
  (`src_mac`/`dst_mac` via `snprintf`, `src_ip`/`dst_ip` via `snprintf`/
  `inet_ntop`, `protocol`, and the `info` line through several more
  `snprintf` calls) — after the wakeup and syscall work of this release it
  was the largest user-space cost left on the capture thread. It now
  records a binary summary only (raw MAC bytes, a protocol label id, an
  `info_kind` and a small union with the line's ingredients: ICMP
  type/code/id/seq, UDP length, DNS name/type/rcode/answer, HTTP first
  line, TLS handshake type and SNI, DHCP/NTP/QUIC fields, ARP sender MAC;
  strings that come from the packet are copied with `memcpy`) and sets
  `text_pending`; the new `summary_format()` produces the text columns
  from it, once, on the consumer's copy — the headless printer, `--jsonl`,
  the JSON export, the TUI rows/detail panel/search and the display
  filter's MAC and `info` predicates (IP, port, protocol and the other
  predicates evaluate on the binary fields; IP literals in a filter now
  compare as addresses, so `fe80:0:0:0:0:0:0:1` matches `fe80::1`).
  Session display strings are still formatted once per new session
  (`ns_ip_str`, a hand-written dotted-quad writer, `inet_ntop` for IPv6);
  `--syslog` formats only the two addresses of each record with it, and
  its self-check compares binary addresses. Output is byte-identical
  (checked with `-r ... --no-ui` and `--jsonl` on a 10 000-frame corpus
  covering every info line). Measured on `lo` (libpcap build, `-q`,
  ~580 kpps captured: ~390 kpps background ICMP echo plus a 240 kpps UDP
  flood): capture-thread CPU per packet 0.69 -> 0.13 µs (40.7% -> 7.6%
  of a core), 0.71 -> 0.13 µs at ~950 kpps captured (65.8% -> 12.1%),
  0.74 -> 0.17 µs with a DNS-query flood instead of plain UDP; raw-socket
  build (TPACKET_V3 ring) 1.01 -> 0.17 µs. `pkt_summary_t` grows from 392 to
  560 bytes (the text columns are kept for compatibility); tests that
  build summaries by hand keep working (a summary with text in place and
  `text_pending` clear is used as is).
- **Packet bytes live in a shared payload arena; headless snaplen 1518.**
  The ring used to reserve a snaplen-sized slot per record (10 000 x
  65 535 B = 655 MB, resident within a second under transparent huge
  pages) and copy every frame into a cold 64 KB slot. Records now
  bump-allocate exactly their captured bytes from one circular arena of
  `ring_size x min(snaplen, 2048)` bytes (20 MB by default;
  `--arena-mb` / config `arena_mb` override). When large frames wrap the
  arena before the ring wraps, the oldest records keep their summary and
  come back with a captured length of 0 — readers validate the arena
  cursor after copying, the same way they validate the slot seqlock, so
  an overwritten payload is never presented as valid (the TUI hex view
  says "payload no longer buffered", `-o` writes a zero-length capture).
  `--no-ui`, `--jsonl`, `-q` and `-w` default the snaplen to 1518 unless
  `-s` or the config file set it (a config-file snaplen now counts as
  explicit for the lean syslog mode too); a headless capture on a jumbo
  interface warns once when a frame exceeds it. Ring API:
  `ringbuf_create()` takes the arena size, `ringbuf_producer_next()` the
  wanted length and returns the granted `raw_len`/`raw_data`. Measured on
  `lo` (libpcap build, `-q`): RSS 712 MB -> 88 MB (64 MB of it the kernel
  ring); capture-thread CPU per packet 0.78 -> 0.68 us at 64 B and
  1.11 -> 0.85 us at 1472 B UDP payloads.
- **`--syslog` and `-w` moved off the capture thread.** An output thread
  (`snf-output`) reads committed records from the ring buffer by sequence,
  like the headless printer, formats and sends the syslog batches and
  writes the `-w` stream (1 MB stdio buffer, flushed when idle and at
  exit). The capture callbacks no longer touch either sink, so a slow
  collector or disk can no longer slow capture: the ring wraps past the
  output thread instead and the records it never saw are counted as
  `out_missed=` in `--stats` (`syslog_sent + syslog_fail + out_missed ==
  captured`). The lean `-q --syslog` ring grows from 64 to 4 096 slots
  (~3.4 MB with its 256-byte-per-slot payload arena) so the thread has
  headroom; `-b` still overrides it. Offline
  replay (`-r`) waits for the output thread as it does for the headless
  consumer, so `-r file -w out.pcap` still copies every packet. Ring
  buffer: the wake-up handshake now has one slot per blocking consumer
  (`ringbuf_waiter_*`), with a single waiter count on the producer's
  path, so the printer/TUI and the output thread each get their own
  wake-up. Measured on `lo` at 150 kpps with `--syslog`: capture thread
  5.6-6.0 µs -> 0.8 µs per packet (quiet-mode cost), output thread
  ~5.4 µs per datagram.
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
- **TUI frame rate capped at ~30/s; session snapshots rate-limited.** The
  screen used to be redrawn after every ring wake-up (thousands of
  full-screen `write()`s per second under load), and the sessions view
  copied and sorted the whole session table under its lock on every one
  of them, stalling the capture thread (with 100 k sessions: capture
  thread at 58%, 23% kernel drops). Frames are now drawn at most every
  33 ms when something changed, at once on a key press, and every 250 ms
  otherwise; the sessions view refreshes its snapshot every 250 ms (or
  immediately on view switch, sort change, page jump or clear) and renders
  from the cached copy in between. Between frames the loop still looks at
  the ring at least every 5 ms while packets are pending (the capture
  side delivers in 10 ms blocks), so the `V` stats overlay stays complete
  at the rates the capture thread sustains. Measured on a 200x50 terminal:
  UI thread 43% -> 1.6% at 350-530 kpps; sessions view with 100 k sessions
  100% -> 9% UI, capture thread unblocked (58% -> 82% busy, 0% drops).
- **Raw build (Linux) captures from a TPACKET_V3 block ring.** The
  no-libpcap backend now maps a `PACKET_RX_RING` of 256 KiB blocks (sized
  by `-B`, 10 ms retire timeout) into the process and takes one `poll()`
  per block instead of a `recvmmsg()` per batch of 64 frames, with kernel
  timestamps and lengths read out of the mapping. Per-packet capture cost
  on a UDP flood over `lo` fell from ~2.4 µs to ~1.1–1.5 µs (about half),
  so the raw build's ceiling roughly doubles. When the kernel cannot set
  up the ring (ENOMEM, pre-3.2 kernel) a note is printed and the previous
  `recvmmsg` + `SO_RCVBUF` path is used. `ss -0 -e -m` shows the ring.
  The in-kernel filter now returns `-s` as its accepting value (an
  accept-all program is attached when there is no `-f`), so the kernel
  copies at most snaplen bytes of a frame into the ring, as libpcap's
  filters do; a TCP bulk transfer over `lo` under `-s 128` no longer costs
  the sender a 64 KiB copy per segment. `--immediate` now applies to the
  raw build too: it keeps the `recvmmsg` path, whose first-frame return
  delivers a lone packet in ~0.1 ms instead of the ring's ~10 ms block
  retire.

### Fixed
- **Raw build: frames were delivered unfiltered before `-f` took effect.**
  A packet socket receives from the moment it is created; frames queued
  between `socket()` and `SO_ATTACH_FILTER` bypassed the filter. A
  reject-all program is now attached before `bind()`, the queue (or ring)
  is drained after setup, and only then is the user's filter attached (or
  the reject-all program detached when there is none).
- **Raw build: the "raise net.core.rmem_max or run as root" hint** was
  printed even when the socket buffer request hit the kernel's own
  per-socket ceiling (1024 MiB); it now says "kernel limit" in that case.
- **Raw build: every packet on `lo` was captured twice.** A frame sent over
  the loopback interface passes the packet tap twice (`PACKET_OUTGOING` on
  transmit, `PACKET_HOST` on delivery); the raw backend now keeps only the
  incoming copy, as libpcap does, so counts, sessions and `-w` files match
  the libpcap build on `lo`.

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
