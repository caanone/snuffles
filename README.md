# Snuffles

A lightweight, cross-platform network packet analyzer written in C. Terminal UI, two-level filtering, session tracking, syslog forwarding, and PCAP/JSON export.

~4,900 lines of C. Zero external dependencies beyond libpcap (optional).

---

## Features

- Live capture and offline `.pcap` file reading
- Protocol dissection: Ethernet, VLAN, ARP, IPv4, IPv6, ICMPv4/v6, TCP, UDP, SCTP, DNS, HTTP/1.x, TLS (SNI)
- Two-level filtering:
  - **BPF capture filter** `[B]` — kernel-level, standard pcap syntax
  - **Display filter** `[F]` — Wireshark-like expressions with CIDR, port ranges, substring match
- Session/stream tracking `[S]` — bidirectional 5-tuple aggregation with TCP state machine
- Syslog forwarding `--syslog` — real-time UDP CSV with full header details, feedback loop prevention
- Silent mode `-q` — zero terminal output, minimal memory (~16KB), pure syslog forwarder
- ANSI terminal UI with color-coded protocols, scrollable list, detail panel, hex dump, help overlay
- Export to PCAP and JSON `[E]`
- Security hardened: privilege dropping, bounds-checked parsing, memory-capped buffers
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
  -i <iface>          Capture interface (default: auto-detect)
  -r <file.pcap>      Read from pcap file (libpcap build only)
  -f <bpf_filter>     BPF capture filter (e.g. "tcp port 80")
  -c <count>          Stop after N packets
  -s <snaplen>        Snapshot length (default: 65535)
  -b <ring_size>      Ring buffer size (default: 10000)
  -o <file>           Export on exit (.pcap or .json)
  --no-ui             Headless mode (print to stdout)
  -q, --quiet         Silent mode (no output, use with --syslog)
  --syslog <host:port> Forward packets via UDP syslog
  --syslog-iface <ip|dev>  Source interface/IP for syslog
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

# List interfaces
./snuffles --list-ifaces
```

---

## Operating Modes

| Mode | Flags | Memory | Output |
|------|-------|--------|--------|
| **TUI** | (default) | ~640MB ring + sessions | Interactive terminal UI |
| **Headless** | `--no-ui` | ~640MB ring + sessions | Packets to stdout |
| **Headless + export** | `--no-ui -o file` | ~640MB ring + sessions | Stdout + file on exit |
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
| S | Toggle Packets / Sessions view |
| T | Cycle session sort: bytes / packets / recent / duration |
| F | Display filter (post-capture) |
| B | BPF capture filter (kernel-level) |
| E | Export to file (.pcap or .json) |
| C | Clear all packets and sessions |
| P | Pause / Resume |
| H / ? | Help overlay |
| Q | Quit |
| Escape | Cancel input |

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

### Memory

| Mode | Memory |
|------|--------|
| `-q --syslog` | ~16KB (64 slots x 256 bytes, no sessions) |
| `--no-ui --syslog` | ~16KB + stdout buffering |
| TUI + syslog | Full ring buffer + sessions |

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
| L3 | IPv4 | src/dst IP, TTL, ID, checksum, fragment, protocol |
| L3 | IPv6 | src/dst IP, hop limit, next header |
| L3 | ICMPv4 | Type, code, echo ID/seq |
| L3 | ICMPv6 | Type, code, neighbor discovery |
| L4 | TCP | Ports, flags, seq, ack, window, checksum |
| L4 | UDP | Ports, length |
| L4 | SCTP | Ports |
| L7 | DNS | Query/response, QNAME, type |
| L7 | HTTP/1.x | Method + path or status |
| L7 | TLS | Handshake type, SNI |

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
- **Silent mode**: capture thread only, main thread sleeps
- **Session table**: normalized 5-tuple, 100K cap, LRU eviction
- **Display filter**: recursive descent, 48-node fixed AST
- **Syslog**: single UDP socket, stack buffer, loop guard

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
    +-- ringbuf.c / .h            # Ring buffer + pipe notification
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
| snaplen | 64 - 65,535 bytes |
| ring_size | 16 - 1,000,000 packets |
| Session table | 100,000 (LRU eviction) |
| UI render buffer | 4 MB |
| Filter preview | 2,000 packet scan |
| Quiet + syslog mode | ~16 KB total |

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
| BPF kernel filter | Yes | No |
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
