# Snuffles

A lightweight, cross-platform network packet analyzer written in C. Terminal UI, two-level filtering, session tracking, syslog forwarding, and PCAP/JSON export. Two build modes: libpcap (full-featured) or raw sockets (zero dependencies on Windows).

~4,800 lines of C across 23 source files. Zero external dependencies beyond libpcap (optional).

---

## Features

- Live capture and offline `.pcap` file reading
- Protocol dissection: Ethernet, VLAN, ARP, IPv4, IPv6, ICMPv4/v6, TCP, UDP, SCTP, DNS, HTTP/1.x, TLS (SNI)
- Two-level filtering:
  - **BPF capture filter** `[B]` — kernel-level, standard pcap syntax
  - **Display filter** `[F]` — application-level, Wireshark-like expressions with CIDR, port ranges, substring match
- Session/stream tracking `[S]` — bidirectional 5-tuple aggregation with TCP state machine
- Syslog forwarding `--syslog` — real-time UDP CSV output with full header details and feedback loop prevention
- ANSI terminal UI with color-coded protocols, scrollable list, detail panel, hex dump, help overlay
- Export to PCAP and JSON `[E]`
- Security hardened: privilege dropping, bounds-checked parsing, memory-capped buffers, LRU session eviction
- Two build backends:
  - **libpcap** (default) — full features on Linux/macOS/Windows
  - **Raw sockets** (`make nopcap`) — zero dependencies, works on Windows without Npcap

---

## Table of Contents

- [Build](#build)
- [Usage](#usage)
- [TUI Keyboard Shortcuts](#tui-keyboard-shortcuts)
- [Display Filter](#display-filter)
- [BPF Capture Filter](#bpf-capture-filter)
- [Session Tracking](#session-tracking)
- [Syslog Forwarding](#syslog-forwarding)
- [Export](#export)
- [Protocols](#protocols)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Security Hardening](#security-hardening)
- [Permissions](#permissions)
- [Build Comparison](#build-comparison)

---

## Build

### Default (libpcap)

| Platform | Prerequisites |
|----------|---------------|
| Linux    | `sudo apt install libpcap-dev` or `sudo dnf install libpcap-devel` |
| macOS    | Included with Xcode Command Line Tools |
| Windows  | [Npcap SDK](https://npcap.com/#download) + [Npcap runtime](https://npcap.com/) |

```bash
make                 # auto-detects platform, finds libpcap
```

CMake:

```bash
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make
```

### Raw Sockets (no libpcap / no Npcap)

```bash
make nopcap          # Linux or Windows (MinGW)
```

CMake:

```bash
cmake -DNO_PCAP=ON ..
make
```

Windows MinGW one-liner:

```bash
gcc -std=c11 -Wall -O2 -DNO_PCAP -D_WIN32_WINNT=0x0601 -Iinclude ^
    src/main.c src/capture_raw.c src/dissect.c src/filter.c src/ringbuf.c ^
    src/ui.c src/export_pcap.c src/export_json.c src/stats.c src/session.c ^
    src/syslog_out.c -o snuffles.exe -lws2_32 -liphlpapi
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

---

## Usage

```
snuffles [OPTIONS]

Options:
  -i <iface>          Interface to capture on (default: auto-detect)
  -r <file.pcap>      Read from pcap file (libpcap build only)
  -f <bpf_filter>     BPF capture filter (e.g. "tcp port 80")
  -c <count>          Stop after N packets
  -s <snaplen>        Snapshot length (default: 65535, max: 65535)
  -b <ring_size>      Ring buffer size (default: 10000, max: 1000000)
  -o <file>           Auto-export on exit (.pcap or .json by extension)
  --syslog <host:port> Forward packet summaries via UDP syslog
  --no-ui             Headless mode (print to stdout)
  --list-ifaces       List available interfaces and exit
  -v                  Print version and build info
  -h, --help          Show help
```

### Examples

```bash
# Live capture with TUI
sudo ./snuffles -i en0

# Capture only HTTPS, export on exit
sudo ./snuffles -i eth0 -f "tcp port 443" -o capture.pcap

# Read a pcap file
./snuffles -r traffic.pcap

# Headless with syslog forwarding
sudo ./snuffles -i en0 --no-ui --syslog 10.0.0.100:514

# Headless, 100 packets, export JSON
sudo ./snuffles -i en0 -c 100 --no-ui -o output.json

# Pipe through grep
sudo ./snuffles -i en0 --no-ui | grep DNS

# List interfaces
./snuffles --list-ifaces
```

---

## TUI Keyboard Shortcuts

Press `H` or `?` for the built-in help overlay.

| Key            | Action |
|----------------|--------|
| Up / Down      | Scroll list |
| PgUp / PgDn   | Scroll by page |
| Home / End     | Jump to first / last |
| Enter          | Detail panel (packets) / Drill into session (sessions) |
| S              | Toggle Packets / Sessions view |
| T              | Cycle session sort: bytes / packets / recent / duration |
| F              | Display filter (post-capture) |
| B              | BPF capture filter (kernel-level) |
| E              | Export to file (.pcap or .json) |
| C              | Clear all packets and sessions |
| P              | Pause / Resume |
| H / ?          | Help overlay |
| Q              | Quit |
| Escape         | Cancel input |

---

## Display Filter

Press `F` in the TUI. Filters are post-capture — they hide packets from view but keep them in the ring buffer. Live preview shows match count while typing.

### Quick Filters

```
tcp                         udp                         dns
arp                         icmp                        tls
http                        sctp                        10.0.0.1
192.168.1.0/24              port 443                    port 80-8080
```

### Full Syntax

`field operator value`, combined with `and` `or` `not` `&&` `||` `!` `()`

| Field                    | Description |
|--------------------------|-------------|
| `src_ip` / `src`         | Source IP |
| `dst_ip` / `dst`         | Destination IP |
| `ip`                     | Either src or dst IP |
| `src_port` / `dst_port`  | Source / destination port |
| `port`                   | Either src or dst port |
| `proto`                  | Protocol name (TCP, UDP, DNS, etc.) |
| `length`                 | Packet length in bytes |
| `src_mac` / `dst_mac`    | MAC address |
| `vlan`                   | VLAN ID |
| `info`                   | Info string (substring) |
| `session` / `stream`     | Session ID |

| Operator           | Meaning |
|---------------------|---------|
| `==` `=`           | Equal |
| `!=`               | Not equal |
| `>` `<` `>=` `<=`  | Numeric |
| `contains` `~`     | Substring (case-insensitive) |

### Examples

```
tcp and port 443
ip == 10.0.0.0/8
not arp
info contains "ClientHello"
(tcp or udp) && port 53
session == 5
length > 1400
!icmp && ip == 192.168.1.0/24
```

---

## BPF Capture Filter

Press `B` in the TUI. Uses standard pcap/BPF syntax. Drops non-matching packets at the kernel level before they reach the application.

```
tcp port 443
host 192.168.1.1 and not icmp
udp portrange 5000-6000
net 10.0.0.0/8
```

Empty string clears the filter. Only available in libpcap build.

---

## Session Tracking

Press `S` to switch to Sessions view. Packets are aggregated into bidirectional flows by normalized 5-tuple (src IP, dst IP, src port, dst port, protocol).

| Column     | Description |
|------------|-------------|
| #          | Session ID |
| Proto      | TCP, UDP, etc. |
| Side A     | First endpoint (IP:port) |
| Side B     | Second endpoint (IP:port) |
| Pkts up/dn | Per-direction packet count |
| Bytes      | Total bytes both directions |
| State      | TCP: NEW / SYN / EST / FIN / CLOSED / RST |
| Duration   | First to last packet |

Color-coded: green = ESTABLISHED, yellow = SYN, red = RST, dim = CLOSED.

Press `T` to cycle sort. Press `Enter` on a session to drill into its packets (auto-applies `session == <id>` filter). Press `S` to go back.

Capped at 100,000 sessions with LRU eviction of the oldest inactive session.

---

## Syslog Forwarding

```bash
sudo ./snuffles -i en0 --syslog 10.0.0.100:514
```

Sends a UDP datagram per packet in real-time from the capture thread. Default port 514 if omitted.

### Format

Always 16 fields per line (consistent CSV columns). Non-TCP packets have empty values for TCP-specific fields.

```
src_ip,src_port,dst_ip,dst_port,epoch,length,protocol,ttl,ip_id,ip_checksum,frag,flags,seq,ack,window,tcp_checksum
```

Examples:

```
10.0.0.1,55555,93.184.216.34,443,1774973651,54,TCP,64,1,0x0000,0x0000,S,100,0,65535,0x0000
192.168.1.100,54321,8.8.8.8,53,1774973652,54,DNS,64,1,0x0000,0x0000,,,,
10.0.0.1,0,8.8.8.8,0,1774973653,42,ICMP,64,1,0x0000,0x0000,,,,
```

### Field Reference

| Field          | Description |
|----------------|-------------|
| `src_ip`       | Source IP address |
| `src_port`     | Source port (0 for ICMP/ARP) |
| `dst_ip`       | Destination IP address |
| `dst_port`     | Destination port (0 for ICMP/ARP) |
| `epoch`        | Unix timestamp (seconds) |
| `length`       | Packet length on wire (bytes) |
| `protocol`     | Highest detected protocol (TCP, DNS, TLS, etc.) |
| `ttl`          | IP Time To Live / Hop Limit |
| `ip_id`        | IP Identification field |
| `ip_checksum`  | IP header checksum (hex) |
| `frag`         | IP fragment offset + flags (hex) |
| `flags`        | TCP flags: S=SYN A=ACK F=FIN R=RST P=PSH U=URG |
| `seq`          | TCP sequence number |
| `ack`          | TCP acknowledgment number |
| `window`       | TCP window size |
| `tcp_checksum` | TCP checksum (hex) |

### Feedback Loop Prevention

Packets destined to or from the syslog server IP:port over UDP are automatically excluded from syslog output to prevent infinite feedback loops.

### Memory

- UDP socket opened once at startup
- Per-packet formatting uses a 512-byte stack buffer
- `sendto()` is fire-and-forget (no retries, no queue)
- Zero heap allocations in the syslog hot path

---

## Export

Press `E` in the TUI. Default path: `$HOME/capture.pcap` (or `/tmp/capture.pcap` under sudo). Change extension to `.json` for JSON output.

- Respects active display filter: only matching packets are exported
- Status bar shows green success or red error with reason

### PCAP

Standard libpcap format: magic `0xa1b2c3d4`, version 2.4, LINKTYPE_ETHERNET. Written via raw file I/O (no libpcap write API dependency).

### JSON

```json
{
  "capture_info": {
    "interface": "en0",
    "start_time": "2024-01-01T12:00:00Z",
    "packet_count": 42,
    "filter": "tcp port 443"
  },
  "packets": [
    {
      "no": 1,
      "timestamp": "1711900800.123456",
      "src_ip": "10.0.0.1", "src_port": 54321,
      "dst_ip": "1.1.1.1",  "dst_port": 443,
      "protocol": "TLS", "length": 517,
      "info": "TLS ClientHello SNI=example.com",
      "hex": "45 00 02 05 ..."
    }
  ]
}
```

### CLI Export

```bash
sudo ./snuffles -i en0 -c 100 -o capture.pcap
sudo ./snuffles -i en0 -c 100 -o capture.json
```

---

## Protocols

| Layer | Protocol   | Extracted Fields |
|-------|------------|------------------|
| L2    | Ethernet   | src/dst MAC, EtherType |
| L2    | 802.1Q     | VLAN ID |
| L2    | ARP        | Operation, sender/target IP+MAC |
| L3    | IPv4       | src/dst IP, TTL, ID, checksum, fragment offset, protocol number |
| L3    | IPv6       | src/dst IP, hop limit, next header |
| L3    | ICMPv4     | Type, code, echo ID/sequence |
| L3    | ICMPv6     | Type, code, neighbor discovery types |
| L4    | TCP        | Ports, flags (SYN/ACK/FIN/RST/PSH/URG), seq, ack, window, checksum |
| L4    | UDP        | Ports, length |
| L4    | SCTP       | Ports |
| L7    | DNS        | Query/response, QNAME, type (A/AAAA/CNAME/MX/NS/PTR/SOA/TXT/SRV) |
| L7    | HTTP/1.x   | Method + path or status line |
| L7    | TLS        | Handshake type, SNI from ClientHello |

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
                      +-------v---------+
                      |  Ring Buffer    |  pre-allocated, atomic fast path
                      | (10K packets)   |  pipe notification for select()
                      +-------+---------+
                              |
   +----------+-------+------+------+-----------+
   |          |        |             |           |
   v          v        v             v           v
Dissect   Session   Syslog       Stats      UI Thread
(L2-L7)   Table     (UDP CSV)   (rolling    (select on
          (FNV-1a   per-packet   window)     stdin+pipe)
           hash,    with loop               /          \
           TCP SM,  exclusion)        Packet View  Session View
           LRU                       (list+detail  (sorted table,
           evict)                     +hex dump)    drill-in)
```

- **Two threads**: capture (producer) + UI (consumer)
- **Ring buffer**: pre-allocated `capacity * snaplen` data pool, no malloc in hot path
- **Self-pipe trick**: `select()` on both stdin and pipe fd for unified event loop
- **Session table**: FNV-1a hash, normalized 5-tuple, 100K cap, LRU eviction
- **Display filter**: recursive descent parser, fixed 48-node AST pool, no heap
- **Syslog**: single UDP socket, stack-formatted CSV, feedback loop guard

---

## Project Structure

```
snuffles/
+-- CMakeLists.txt                # CMake build (-DNO_PCAP supported)
+-- Makefile                      # targets: all, nopcap, debug, clean
+-- README.md
+-- cmake/
|   +-- FindPCAP.cmake            # libpcap/Npcap finder
|   +-- toolchain-linux-aarch64.cmake
|   +-- toolchain-macos-arm64.cmake
|   +-- toolchain-windows-x64.cmake
+-- include/
|   +-- snuffles.h                # Shared types, platform thread wrappers
+-- src/
    +-- main.c                    # CLI, signals, orchestration
    +-- capture.c / .h            # libpcap backend
    +-- capture_raw.c             # Raw socket backend (NO_PCAP)
    +-- dissect.c / .h            # Protocol dissectors (L2-L7)
    +-- filter.c / .h             # Display filter parser + evaluator
    +-- ringbuf.c / .h            # Ring buffer with pipe notification
    +-- session.c / .h            # Session tracking hash table
    +-- syslog_out.c / .h         # UDP syslog forwarder
    +-- ui.c / .h                 # ANSI TUI (packets, sessions, help)
    +-- export_pcap.c / .h        # Raw PCAP writer
    +-- export_json.c / .h        # JSON writer
    +-- stats.c / .h              # pps/bps rolling window
```

---

## Security Hardening

### Privilege Dropping

After opening the capture device, the process drops from root to the original user (`sudo` case) or `nobody`. All packet processing runs unprivileged.

### Memory Limits

| Resource           | Limit |
|--------------------|-------|
| CLI snaplen        | 64 - 65,535 bytes |
| CLI ring_size      | 16 - 1,000,000 packets |
| Session table      | 100,000 entries (LRU eviction) |
| UI render buffer   | 4 MB cap |
| Filter preview     | 2,000 packet scan limit |

All `malloc`/`calloc` return values are checked.

### Parser Hardening

| Check | Details |
|-------|---------|
| IPv4 IHL | Validated `>= 20` and `<= caplen` |
| TCP data offset | Validated `>= 20` and `<= segment length` |
| DNS labels | Capped at 63 bytes (RFC 1035), max 128 labels |
| TLS SNI | 256-byte buffer with explicit bounds |
| Field reads | Safe `memcpy`-based (no pointer casting, ARM-safe) |

### Signal Safety

`SIGINT`/`SIGTERM` handler only sets `volatile sig_atomic_t` flags. No async-signal-unsafe calls.

### Syslog Loop Prevention

Packets to/from the syslog destination IP:port over UDP are excluded from forwarding.

---

## Permissions

| Platform              | Requirement |
|-----------------------|-------------|
| Linux                 | `sudo ./snuffles` or `sudo setcap cap_net_raw+ep ./snuffles` |
| macOS                 | `sudo ./snuffles` |
| Windows (Npcap)       | Run as Administrator |
| Windows (raw socket)  | Run as Administrator |

---

## Build Comparison

| Feature                | libpcap (`make`)   | Raw socket (`make nopcap`) |
|------------------------|--------------------|----------------------------|
| Dependencies           | libpcap / Npcap    | None                       |
| BPF kernel filter      | Yes                | No (use display filter)    |
| Offline pcap reading   | Yes (`-r`)         | No                         |
| Ethernet/ARP capture   | Yes                | Linux only                 |
| Syslog forwarding      | Yes                | Yes                        |
| Session tracking       | Yes                | Yes                        |
| Windows without Npcap  | No                 | Yes                        |
| macOS                  | Yes                | No                         |

---

## License

MIT License. See [LICENSE](LICENSE).
