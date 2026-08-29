<h1 align="center">🐶 Snuffles</h1>

<p align="center"><b>A lightweight terminal packet analyzer that sniffs everything out.</b></p>

<p align="center">
  <a href="https://github.com/caanone/snuffles/actions/workflows/ci.yml"><img src="https://github.com/caanone/snuffles/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/C11-single%20binary-blue" alt="C11">
  <img src="https://img.shields.io/badge/platforms-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey" alt="Platforms">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT">
</p>

Live capture, Wireshark-style display filters, TCP session tracking, syslog
forwarding, and PCAP/JSON export — in one small C11 binary with no
dependencies beyond (optional) libpcap.

```text
 Snuffles v1.0.0 | eth0 | captured: 14203 | dropped: 0
 [S]essions  [V]Stats  [F]ilter  [B]PF  [E]xport  [C]lear  [P]ause  [H]elp  [Q]uit
  1201  14:31:07.412  10.0.0.5:52814      -> 142.250.74.78:443    TLS   ClientHello SNI=fonts.gstatic.com
  1202  14:31:07.415  10.0.0.5:49732      -> 8.8.8.8:53           DNS   DNS Q A example.org
  1203  14:31:07.417  8.8.8.8:53          -> 10.0.0.5:49732       DNS   DNS R A example.org
  1204  14:31:07.502  10.0.0.5:52816      -> 93.184.216.34:80     HTTP  GET /index.html
 ─────────────────────────────────────────────────────────────────────────────────────
  Display: tcp and port 443 (2841/14203)
```

---

## Features

- Live capture and offline `.pcap` file reading
- Protocol dissection: Ethernet, VLAN, ARP, Linux cooked capture (SLL/SLL2),
  BSD/macOS loopback, IPv4 (fragment-aware), IPv6 with extension-header
  chain walking, ICMPv4/v6, TCP, UDP, SCTP, DNS, HTTP/1.x, TLS (SNI)
- Two-level filtering:
  - **BPF capture filter** `[B]` — kernel-level, standard pcap syntax
  - **Display filter** `[F]` — Wireshark-like expressions with CIDR, port ranges, substring match
- Session/stream tracking `[S]` — bidirectional 5-tuple aggregation with TCP state machine
- Protocol statistics `[V]` — live per-protocol breakdown with rates and drop counts
- Syslog forwarding `--syslog` — real-time UDP CSV with full header details, feedback loop prevention
- Silent mode `-q` — no packet output, minimal user-space memory (~40KB ring; the libpcap build adds a kernel capture buffer, `-B`), pure syslog forwarder
- ANSI terminal UI with color-coded protocols, scrollable list, detail panel, hex dump, help overlay
- Streaming write `-w` — tcpdump-style write-while-capturing (`-w -` pipes into Wireshark)
- JSON Lines output `--jsonl` — one JSON object per packet on stdout, made for `jq`
- Search `/` — find packets by info, IP, or protocol; `n`/`N` to step through matches
- Export to PCAP and JSON `[E]`
- Security hardened: verified privilege dropping, bounds-checked parsing
  (unit-tested and continuously fuzzed), sanitized display of packet-derived
  strings, memory-capped buffers
- Two build backends:
  - **libpcap** (default) — full features on Linux/macOS/Windows
  - **Raw sockets** (`make nopcap`) — zero dependencies, works on Windows without Npcap

---

## Build

### Default (libpcap)

| Platform | Prerequisites |
|----------|---------------|
| Linux    | `sudo apt install libpcap-dev` or `sudo dnf install libpcap-devel` |
| macOS    | Included with Xcode Command Line Tools |
| Windows  | [Npcap SDK](https://npcap.com/#download) + [Npcap runtime](https://npcap.com/) |

```bash
make
```

CMake:

```bash
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make
```

### Raw Sockets (no libpcap / no Npcap)

```bash
make nopcap
```

CMake:

```bash
cmake -DNO_PCAP=ON ..
make
```

Windows MinGW one-liner:

```bash
gcc -std=c11 -Wall -O2 -DNO_PCAP -D_WIN32_WINNT=0x0601 -Iinclude ^
    src/main.c src/capture_raw.c src/cbpf.c src/dissect.c src/filter.c ^
    src/ringbuf.c src/ui.c src/export_pcap.c src/export_json.c src/stats.c ^
    src/session.c src/syslog_out.c -o snuffles.exe -lws2_32 -liphlpapi
```

### Cross-Compilation

```bash
cmake -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain-linux-aarch64.cmake ..
cmake -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain-macos-arm64.cmake ..
cmake -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain-windows-x64.cmake -DNO_PCAP=ON ..
```

### Other Targets

```bash
make debug           # AddressSanitizer + UBSan
make analyze         # Clang static analysis
make clean           # Remove artifacts
```

### Tests

Unit tests (filter, ring buffer, sessions, dissectors, BPF compiler,
config, JSON Lines writer) run either from the Makefile or via CTest:

```bash
make test                 # all suites
make test SAN=1           # under AddressSanitizer + UBSan
make test-stress RUNS=30  # repeat the concurrency suites

cmake -B build && cmake --build build -j && ctest --test-dir build
```

libFuzzer harnesses for the dissectors and filter compiler live in `fuzz/`
(build commands in the file headers). CI runs the test suite under
ASan/UBSan and a fuzz smoke pass on every push.

The full unit suite also runs against the **Windows** build (MinGW cross +
Wine) — locally via Docker with `./scripts/test-windows.sh`, and in CI on
every push. Raw-socket capture and console quirks still warrant a real
Windows machine; everything else is covered.

---

## Usage

```
snuffles [OPTIONS]

Options:
  -i <iface>          Capture interface (default: auto-detect)
  -r <file.pcap>      Read from pcap file (libpcap build only)
  -f <bpf_filter>     BPF capture filter (e.g. "tcp port 80")
  -c <count>          Stop after N packets
  -s <snaplen>        Snapshot length (default: 65535 in the TUI;
                      1518 for --no-ui/--jsonl/-q/-w)
  -b <ring_size>      Ring buffer size (default: 10000)
  --arena-mb <MB>     Packet payload arena shared by the ring, 1-65536
                      (default: ring_size x min(snaplen, 2048) bytes)
  -B <MB>             Kernel capture buffer in MB, 1-2047 (default: 64)
  -o <file>           Export on exit (.pcap or .json)
  -w <file>           Stream packets to a pcap file while capturing
                      ('-w -' writes to stdout; combine with -q)
  --no-ui             Headless mode (print to stdout)
  --jsonl             Headless mode, one JSON object per packet
  -q, --quiet         Silent mode (no packet output, use with --syslog)
  --syslog <host:port> Forward packets via UDP syslog
  --syslog-iface <ip|dev>  Source interface/IP for syslog
  --stats[=FILE]      Capture/drop counters every second and at exit
  --no-summary        Headless modes: no counters line at exit
  --cpu <N>           Pin the capture thread to CPU N (Linux)
  --rt                SCHED_FIFO priority 1 for the capture thread (root)
  --immediate         Per-packet delivery instead of 10 ms batches 
  --list-ifaces       List interfaces and exit
  -v                  Version info
  -h, --help          Help
```

### Examples

```bash
# Live capture with TUI
sudo ./snuffles -i en0

# Capture HTTPS only, export on exit
sudo ./snuffles -i eth0 -f "tcp port 443" -o capture.pcap

# Read pcap file
./snuffles -r traffic.pcap

# Headless with syslog
sudo ./snuffles -i en0 --no-ui --syslog 10.0.0.100:514

# Silent syslog forwarder (minimal memory, no output)
sudo ./snuffles -i en0 -q --syslog 10.0.0.100:514

# Syslog via specific interface
sudo ./snuffles -i en0 -q --syslog 10.0.0.100:514 --syslog-iface 192.168.1.5

# Headless, 100 packets, JSON export
sudo ./snuffles -i en0 -c 100 --no-ui -o output.json

# Pipe through grep
sudo ./snuffles -i en0 --no-ui | grep DNS

# Stream to disk while watching the TUI
sudo ./snuffles -i eth0 -w rolling.pcap

# Live-pipe into Wireshark
sudo ./snuffles -i eth0 -q -w - | wireshark -k -i -

# JSON Lines into jq
sudo ./snuffles -i en0 --jsonl | jq -r '.dst_ip'

# Capture thread alone on CPU 3 at real-time priority, consumer elsewhere
sudo ./snuffles -i eth0 --jsonl --cpu 3 --rt > packets.jsonl

# Ask a running headless capture for its counters
kill -USR1 $(pidof snuffles)

# List interfaces
./snuffles --list-ifaces
```

---

## Configuration

Snuffles reads an optional config file at startup: `$SNUFFLES_CONFIG` if set,
otherwise `~/.snufflesrc` (`%USERPROFILE%\.snufflesrc` on Windows). A missing
file is silently ignored. CLI flags always override config values.

```ini
# ~/.snufflesrc — '#' comments, blank lines, key = value
interface    = eth0
snaplen      = 1500            # 64-65535 (explicit: no headless default)
ring_size    = 50000           # 16-1000000
buffer_mb    = 64              # 1-2047, kernel capture buffer
arena_mb     = 96              # 1-65536, payload arena (default derived)
promisc      = 1               # 0 or 1
syslog       = 10.0.0.100:514
syslog_iface = 192.168.1.5
cpu          = 3               # pin the capture thread (Linux)
rt           = 0               # 1: SCHED_FIFO capture thread (root)

# Saved display-filter presets (name: alnum/_/-, max 31 chars)
preset web = tcp and (port 80 or port 443)
preset dns = udp and port 53
preset noisy = not arp and not icmp
```

Bad lines (unknown keys, out-of-range values, malformed syntax) print one
warning each and are skipped — the config is never fatal.

In the TUI, apply a preset from the display-filter prompt (`F`) by typing
`@name` (case-insensitive), e.g. `@web`. With an empty prompt the filter bar
lists the first few preset names.

---

## Operating Modes

| Mode | Flags | Memory | Output |
|------|-------|--------|--------|
| **TUI** | (default) | ~24MB ring + sessions | Interactive terminal UI |
| **Headless** | `--no-ui` | ~19MB ring + sessions | Packets to stdout |
| **Headless + export** | `--no-ui -o file` | ~19MB ring + sessions | Stdout + file on exit |
| **Headless + syslog** | `--no-ui --syslog h:p` | ~16KB ring, no sessions | Stdout + UDP syslog |
| **Silent syslog** | `-q --syslog h:p` | ~16KB ring, no sessions | UDP syslog only |

---

## TUI Keyboard Shortcuts

Press `H` or `?` for the built-in help overlay.

| Key | Action |
|-----|--------|
| Up / Down | Scroll list |
| PgUp / PgDn | Scroll by page |
| Home / End | Jump to first / last |
| Enter | Detail panel (packets) / Drill into session (sessions) |
| / | Search packet list (info, IPs, protocol) |
| n / N | Next / previous search match |
| S | Toggle Packets / Sessions view |
| V | Protocol statistics overlay |
| T | Cycle session sort: bytes / packets / recent / duration |
| F | Display filter (post-capture) |
| B | BPF capture filter (kernel-level) |
| E | Export to file (.pcap or .json) |
| C | Clear all packets and sessions |
| P | Pause / Resume |
| H / ? | Help overlay |
| Q | Quit |
| Escape | Cancel input |

The screen is redrawn at most 30 times a second (at once on a key press,
every 250 ms when nothing changes), whatever the packet rate. The sessions
view works from a copy of the session table refreshed every 250 ms, or
immediately when you switch to it, change the sort or page through it.

---

## Display Filter

Press `F` in the TUI. Post-capture filtering with live preview.

### Quick Filters

```
tcp           udp           dns           arp
icmp          tls           http          sctp
10.0.0.1      192.168.1.0/24             port 443
port 80-8080
```

### Full Syntax

`field operator value` combined with `and or not && || ! ()`

| Field | Description |
|-------|-------------|
| `src_ip` / `src` | Source IP |
| `dst_ip` / `dst` | Destination IP |
| `ip` | Either src or dst IP |
| `src_port` / `dst_port` | Source / destination port |
| `port` | Either port |
| `proto` | Protocol name |
| `length` | Packet bytes |
| `src_mac` / `dst_mac` | MAC address |
| `vlan` | VLAN ID |
| `info` | Info string (substring) |
| `session` / `stream` | Session ID |

| Operator | Meaning |
|----------|---------|
| `==` `=` | Equal |
| `!=` | Not equal |
| `>` `<` `>=` `<=` | Numeric |
| `contains` `~` | Substring (case-insensitive) |

### Examples

```
tcp and port 443
ip == 10.0.0.0/8
not arp
info contains "ClientHello"
(tcp or udp) && port 53
session == 5
!icmp && ip == 192.168.1.0/24
```

---

## BPF Capture Filter

Press `B` in the TUI. Standard pcap/BPF syntax. Drops non-matching packets at kernel level.

```
tcp port 443
host 192.168.1.1 and not icmp
udp portrange 5000-6000
```

Empty string clears filter. Only available in libpcap build.

---

## Session Tracking

Press `S` to switch view. Bidirectional flow aggregation by normalized 5-tuple.

| Column | Description |
|--------|-------------|
| # | Session ID |
| Proto | TCP, UDP, etc. |
| Side A / B | Endpoints (IP:port) |
| Pkts up/dn | Per-direction count |
| Bytes | Total both directions |
| State | TCP: NEW / SYN / EST / FIN / CLOSED / RST |
| Duration | First to last packet |

Color-coded: green = EST, yellow = SYN, red = RST, dim = CLOSED.

Press `T` to cycle sort. Press `Enter` to drill into a session's packets. Capped at 100,000 entries with LRU eviction.

---

## Syslog Forwarding

```bash
sudo ./snuffles -i en0 --syslog 10.0.0.100:514
sudo ./snuffles -i en0 -q --syslog 10.0.0.100:514              # silent
sudo ./snuffles -i en0 -q --syslog 10.0.0.100:514 --syslog-iface 192.168.1.5  # source bind
```

### CSV Format (always 16 fields)

```
src_ip,src_port,dst_ip,dst_port,epoch,length,protocol,ttl,ip_id,ip_checksum,frag,flags,seq,ack,window,tcp_checksum
```

TCP example:

```
10.0.0.1,55555,93.184.216.34,443,1774973651,54,TCP,64,1,0x0000,0x0000,S,100,0,65535,0x0000
```

Non-TCP (empty TCP fields):

```
192.168.1.100,54321,8.8.8.8,53,1774973652,54,DNS,64,1,0x0000,0x0000,,,,,
```

### Fields

| # | Field | Description |
|---|-------|-------------|
| 1 | src_ip | Source IP |
| 2 | src_port | Source port |
| 3 | dst_ip | Destination IP |
| 4 | dst_port | Destination port |
| 5 | epoch | Unix timestamp |
| 6 | length | Packet size (bytes) |
| 7 | protocol | Highest detected protocol |
| 8 | ttl | IP TTL / Hop Limit |
| 9 | ip_id | IP Identification |
| 10 | ip_checksum | IP header checksum (hex) |
| 11 | frag | Fragment offset + flags (hex) |
| 12 | flags | TCP flags: S A F R P U |
| 13 | seq | TCP sequence number |
| 14 | ack | TCP acknowledgment |
| 15 | window | TCP window size |
| 16 | tcp_checksum | TCP checksum (hex) |

### Feedback Loop Prevention

Packets to/from the syslog destination are automatically excluded.

### Delivery

Records are queued on the capture thread and handed to the kernel in
batches of up to 32 with one non-blocking `sendmmsg(2)` (Linux; one
non-blocking `sendto(2)` per record elsewhere). A batch leaves as soon as
the capture loop goes idle, so a record never waits longer than one
dispatch cycle (<= 100 ms) at low rates. The socket gets a 16 MB send
buffer (`SO_SNDBUFFORCE`, needing the root/CAP_NET_ADMIN snuffles still
holds at that point; unprivileged it falls back to `SO_SNDBUF`, which the
kernel caps at `net.core.wmem_max`). When even that fills — a slow or absent
collector, NIC backpressure — the capture thread never blocks: those
datagrams are dropped and counted as `syslog_fail` in `--stats`, and
capture (and the kernel drop counters) carry on unaffected.

### Counters, summary and placement

Headless modes (`--no-ui`, `--jsonl`, `-q`) print one `summary ...` line to
stderr at exit — captured, kernel drops (`kdrop`), interface drops, records
the consumer missed, syslog/stream counts, sessions — even without
`--stats`; `--no-summary` turns it off, `--stats` adds the same line every
second (`--stats=FILE` sends everything to a file). `kill -USR1 <pid>`
prints a `stats ...` line on demand. If the kernel dropped packets, a hint
follows the summary (`try -B <bigger>, -s <smaller>, -q, or --cpu`), and a
frame longer than 1518 bytes on a non-jumbo interface warns once about
GRO/GSO super-frames (`ethtool -K <if> gro off gso off tso off` restores
wire-sized frames).

`--cpu N` pins the capture thread to CPU N and keeps every other thread
(the headless consumer or the TUI, and the stats thread) on the other
CPUs; `--rt` runs the capture thread at `SCHED_FIFO` priority 1 (set
before privileges are dropped, so it needs root or `CAP_SYS_NICE`;
unprivileged it warns and continues). Both are Linux features (`--rt`
also works on other POSIX systems); both have config keys (`cpu`, `rt`).
Use `--rt` together with `--cpu` on machines with spare cores: a
real-time capture thread that saturates its CPU starves whatever else was
scheduled there.

Reading a file with `-r` into a headless consumer never loses records: the
reader waits for the consumer instead of lapping the ring, so
`snuffles -r big.pcap --jsonl | slow-tool` emits every packet with
`missed=0` regardless of `-b`.

### Memory

| Mode | Memory |
|------|--------|
| `-q --syslog` | ~40KB ring (64 records + a 16KB payload arena, no sessions) + 18KB syslog batch |
| `--no-ui --syslog` | same + stdout buffering |
| TUI + syslog | Full ring buffer + sessions |

The ring buffer keeps one ~350-byte record per packet plus the packet
bytes in a shared payload arena, not a snaplen-sized slot per record: by
default `ring_size x min(snaplen, 2048)` bytes (20 MB for the default
10 000-packet ring, whatever the snaplen; `--arena-mb` / `arena_mb`
overrides it). Packets take only the bytes they need, so with MTU-sized
frames the arena outlives the ring; with larger frames (GRO/GSO
super-frames, jumbo, `-s 65535` in the TUI) the arena wraps before the
ring does and the oldest records keep their summary but lose their bytes
— the TUI hex view says so, `-o` writes them with a zero captured length
(Wireshark: "packet size limited during capture"). Headless modes and
`-w` default the snaplen to 1518 (one Ethernet frame with a VLAN tag)
unless `-s` or the config file set it; the TUI keeps 65535 for its hex
view.

These figures cover snuffles' own buffers. Both builds also map the
kernel capture buffer into the process (64 MB by default, so RSS shows
~70 MB; the lean `-q --syslog` forwarder defaults to 8 MB, ~13 MB RSS);
shrink it further with `-B 1` or `buffer_mb` in the config file where
memory matters more than burst tolerance. When the raw build has to fall
back to a socket receive queue (no TPACKET_V3 ring available) that memory
stays in the kernel and does not show up in RSS.

---

## Export

Press `E` in the TUI. Default path: `$HOME/capture.pcap`.

- `.pcap`: standard libpcap format (magic `0xa1b2c3d4`, v2.4)
- `.json`: structured JSON with metadata and hex dump
- Respects active display filter
- Status bar shows success/failure

```bash
sudo ./snuffles -i en0 -c 100 -o capture.pcap
sudo ./snuffles -i en0 -c 100 -o capture.json
```

---

## Protocols

| Layer | Protocol | Extracted Fields |
|-------|----------|------------------|
| L2 | Ethernet | src/dst MAC, EtherType |
| L2 | 802.1Q | VLAN ID |
| L2 | ARP | Operation, sender/target IP+MAC |
| L2 | Linux cooked (SLL/SLL2) | EtherType, payload dissection (the `any` device) |
| L2 | Loopback (NULL/LOOP) | Address family, payload dissection (macOS/BSD `lo`) |
| L3 | IPv4 | src/dst IP, TTL, ID, checksum, protocol; non-first fragments flagged, not misparsed |
| L3 | IPv6 | src/dst IP, hop limit; extension-header chain walked to the real L4 |
| L3 | ICMPv4 | Type, code, echo ID/seq |
| L3 | ICMPv6 | Type, code, neighbor discovery |
| L4 | TCP | Ports, flags, seq, ack, window, checksum |
| L4 | UDP | Ports, length |
| L4 | SCTP | Ports |
| L7 | DNS | Query/response, QNAME, type |
| L7 | HTTP/1.x | Method + path or status |
| L7 | TLS | Handshake type, SNI |
| L7 | DHCP | Message type (option 53), assigned/client IP |
| L7 | NTP | Mode (client/server), version, stratum |
| L7 | mDNS | Same fields as DNS (port 5353) |
| L7 | QUIC | Long-header packet type, version |

---

## Architecture

```
                      +-----------------+
                      | libpcap / raw   |
                      | socket backend  |
                      +-------+---------+
                              |
                       capture thread
                              |
              +---------------+---------------+
              |               |               |
              v               v               v
         Ring Buffer     Syslog Out     Session Table
         (pre-alloc)    (UDP sendto)    (FNV-1a hash)
              |                               |
              +---------- UI Thread ----------+
                          (select)
                         /        \
                  Packet View   Session View
```

- **Two threads**: capture (producer) + UI (consumer)
- **Ring buffer**: pre-allocated, no malloc in hot path
- **Lazy dissection**: the capture thread stores a binary summary only
  (addresses, ports, ids, MAC bytes, the info line's ingredients); the text
  columns (`src_ip`, `info`, ...) are produced by `summary_format()` on the
  consumer's copy when a record is printed, exported, searched or matched
  by a text predicate. No `snprintf`/`inet_ntop` runs per packet on the
  capture thread; syslog formats only the two addresses it sends
- **Silent mode**: capture thread only, main thread sleeps
- **Session table**: binary canonical 5-tuple key (both directions map to one
  entry), seeded hash over 2x-cap power-of-two buckets, preallocated entry
  pool, O(1) LRU eviction at the 100K cap; non-first IP fragments are not
  tracked. Stream buffers (16 MB budget) are recycled: closed flows are
  reclaimed first, idle holders (60 s) are released, oldest holder otherwise
- **Display filter**: recursive descent, 48-node fixed AST; IP, port,
  protocol, length, VLAN and session predicates evaluate on the binary
  fields, MAC and `info` predicates format a private copy of the record
- **Syslog**: single UDP socket (16 MB send buffer), 32-record batch, non-blocking `sendmmsg`, loop guard

---

## Project Structure

```
snuffles/
+-- CMakeLists.txt                # CMake (-DNO_PCAP supported)
+-- Makefile                      # all, nopcap, debug, clean
+-- LICENSE                       # MIT
+-- README.md
+-- cmake/
|   +-- FindPCAP.cmake
|   +-- toolchain-linux-aarch64.cmake
|   +-- toolchain-macos-arm64.cmake
|   +-- toolchain-windows-x64.cmake
+-- include/
|   +-- snuffles.h                # Shared types, platform wrappers
+-- src/
    +-- main.c                    # CLI, signals, orchestration
    +-- capture.c / .h            # libpcap backend
    +-- capture_raw.c             # Raw socket backend (NO_PCAP)
    +-- dissect.c / .h            # Protocol dissectors (L2-L7)
    +-- filter.c / .h             # Display filter parser + evaluator
    +-- ringbuf.c / .h            # Ring buffer + on-demand consumer wakeup
    +-- session.c / .h            # Session tracking hash table
    +-- syslog_out.c / .h         # UDP syslog forwarder
    +-- ui.c / .h                 # ANSI TUI
    +-- export_pcap.c / .h        # PCAP writer
    +-- export_json.c / .h        # JSON writer
    +-- stats.c / .h              # pps/bps statistics
```

---

## Security Hardening

### Privilege Dropping

Drops from root to original user (sudo) or `nobody` after opening capture device.

### Memory Limits

| Resource | Limit |
|----------|-------|
| snaplen | 64 - 65,535 bytes (default 65,535 TUI, 1,518 headless / `-w`) |
| ring_size | 16 - 1,000,000 packets |
| arena_mb | 1 - 65,536 MB payload arena (default ring_size x min(snaplen, 2048) bytes; a packet longer than the arena is cut to it) |
| buffer_mb | 1 - 2,047 MB kernel capture buffer (default 64; a TPACKET_V3 block ring in both builds, the raw build uses the socket receive queue when no ring is available) |
| Session table | 100,000 (LRU eviction) |
| UI render buffer | 4 MB |
| Filter preview | 2,000 packet scan |
| Quiet + syslog mode | ~16 KB user-space + kernel capture buffer (`-B`) |

### Parser Hardening

| Check | Rule |
|-------|------|
| IPv4 IHL | >= 20, <= caplen |
| TCP data offset | >= 20, <= segment length |
| DNS labels | <= 63 bytes, max 128 labels |
| TLS SNI | 256-byte buffer, bounds checked |
| Field reads | memcpy-based (ARM-safe) |

### Signal Safety

Handler only sets `volatile sig_atomic_t`. No async-unsafe calls.

### Syslog Loop Guard

Packets to/from syslog destination excluded automatically.

---

## Permissions

| Platform | Requirement |
|----------|-------------|
| Linux | `sudo ./snuffles` or `sudo setcap cap_net_raw+ep ./snuffles` |
| macOS | `sudo ./snuffles` |
| Windows | Run as Administrator |

---

## Build Comparison

| Feature | `make` (libpcap) | `make nopcap` (raw) |
|---------|-------------------|---------------------|
| Dependencies | libpcap / Npcap | None |
| BPF kernel filter | Yes | Linux: subset (proto/host/port + and) |
| Capture buffer `-B` | Kernel TPACKET ring (mmap'd) | Linux: TPACKET_V3 ring (mmap'd), kernel timestamps; recvmmsg + SO_RCVBUF when no ring |
| Offline pcap | Yes | No |
| Ethernet/ARP | Yes | Linux only |
| Syslog | Yes | Yes |
| Sessions | Yes | Yes |
| Silent mode | Yes | Yes |
| Windows w/o Npcap | No | Yes |
| macOS | Yes | No |

---

## License

MIT License. See [LICENSE](LICENSE).
