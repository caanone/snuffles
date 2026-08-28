# loadtest/gen — traffic generators (image `snuffles-gen`)

Everything here is baked into the `snuffles-gen` container image and driven from
the rig via `docker exec snf-gen-N /opt/gen/<driver> ...`. Each driver takes a
duration and **terminates by itself** (pktgen is driven by `start`/`stop`, see
below), and prints **exactly one JSON object as its last stdout line** so the
rig can capture it into `gen-<N>.json`. Human-readable tool output goes to
stderr.

Build:

    docker build -f loadtest/docker/gen.Dockerfile -t snuffles-gen loadtest

The build compiles `udpflood`/`synflood` and generates the replay corpus
(`/opt/gen/corpus.pcap`, ~20k frames) at image-build time.

## Files

| file            | what it is |
|-----------------|------------|
| `pktgen.sh`     | in-kernel pktgen driver (`start`/`stop`/`reset`/`result`/`run`) |
| `udpflood.c`    | connected-UDP flood (`/opt/gen/udpflood`) |
| `synflood.c`    | AF_PACKET TCP-SYN flood (`/opt/gen/synflood`) |
| `http.sh`       | wrk HTTP driver |
| `iperf.sh`      | iperf3 TCP throughput driver |
| `replay.sh`     | tcpreplay corpus driver |
| `frag.sh`       | udpflood wrapper with `-s 4000` (IP fragments) |
| `make-corpus.py`| scapy corpus builder (run at image build) |

## Driver CLIs and JSON output

### pktgen.sh
```
pktgen.sh start|stop|reset|result|run \
    -d eth0 --cpus 4,12 --size 64 --dst-mac <mac> --dst-ip <ip> \
    --pps 0 --flows N --src-ip 10.77.0.1N [--clone 1000] [--secs 10]
```
* `start` programs `kpktgend_<cpu>` (`rem_device_all` + `add_device eth0@<cpu>`),
  configures each `eth0@<cpu>` device (`count 0`, `clone_skb`, `pkt_size size-4`,
  `delay 0`, `dst_mac`, `dst`, source/UDP ranges, `flag NO_TIMESTAMP`,
  `ratep <pps>` when pps>0), then writes `start` to `pgctrl` **in the
  background** and returns immediately (`count 0` runs until stopped).
* `stop` writes `stop` to `pgctrl`. **pktgen counters are only final after
  `stop`.**
* `reset` writes `reset` to `pgctrl`.
* `result` parses each `/proc/net/pktgen/eth0@<cpu>` and prints one JSON object
  aggregating all devices:
  ```json
  {"tool":"pktgen","sent":N,"bytes":N,"pps":N,"bps":N,"errors":N,"seconds":F,
   "devices":[{"cpu":C,"sofar":N,"pps":N,"bps":N,"errors":N,"seconds":F,"bytes":N}]}
  ```
* `run` is a convenience for standalone use: `start`; `sleep --secs`; `stop`;
  `result` (the rig itself uses `start`/`sleep`/`stop`/`result`).
* `--flows 1` = fixed 5-tuple; `--flows N>1` sets `src_min 10.77.128.0 ..
  10.77.128.0+N-1` (capped 10.77.255.254) with `IPSRC_RND`, plus
  `udp_src 1024..65535` with `UDPSRC_RND`.

> **veth caveat (important):** `clone_skb > 0` requires `IFF_TX_SKB_SHARING`,
> which **veth does not set** — pktgen returns `ENOTSUPP` (errno 524). The rig's
> generator `eth0` is a veth, so `pktgen.sh` automatically falls back to
> `clone_skb 0` (logged to stderr) on those interfaces. This is correct but
> lowers the pktgen ceiling versus a physical NIC where cloning is allowed.

### udpflood  (`/opt/gen/udpflood`)
```
udpflood -d IP -p PORT [-s SIZE] [-t THREADS] [-T SECONDS] [-r]
```
Connected UDP, one socket per thread, `sendmmsg` batches of 64, `SO_SNDBUF`
32 MB. `SIZE` is the **UDP payload** size (so `-s 4000` fragments into 3 packets
at MTU 1500). `-r` binds a pool of `THREADS*16` sockets up front (kernel-picked
ephemeral source ports) and round-robins one per batch.
```json
{"tool":"udpflood","sent":N,"bytes":N,"seconds":F,"pps":F,"mbps":F,
 "errors":N,"threads":N,"size":N,"rand_src":0|1}
```
`bytes` counts UDP payload bytes (`size * sent`).

### synflood  (`/opt/gen/synflood`)
```
synflood [-i eth0] [-d 10.77.0.5] [-p 80] [--dst-mac MAC] [-t THREADS] [-T SECONDS]
```
AF_PACKET `SOCK_RAW`, `sendmmsg` batches of 64 of 54-byte TCP SYN frames. Every
frame: random source IP in `10.77.128.0/17`, random source port, random ISN;
source MAC = the real hwaddr of `-i`; dst MAC/IP default to the rig sink so
nginx answers.
```json
{"tool":"synflood","sent":N,"bytes":N,"seconds":F,"pps":F,"mbps":F,
 "errors":N,"threads":N}
```
`bytes` counts wire bytes (`54 * sent`).

### http.sh
```
http.sh --host IP --threads N --conns N --duration S [--url /] \
        [--keepalive true|false] [--extra "..."]
```
Runs `wrk -t<threads> -c<conns> -d<duration>s [-H 'Connection: close'] http://host<url>`.
```json
{"tool":"http","requests":N,"seconds":F,"rps":F,"transfer_bps":N,"bytes":N,
 "errors":N,"non_2xx":N,"threads":N,"conns":N,"url":"...","keepalive":B}
```

### iperf.sh
```
iperf.sh --host IP --threads N --duration S [--port 5201] [--extra "..."]
```
Runs `iperf3 -c host -P threads -t duration -J`, parsed with jq.
```json
{"tool":"iperf","bits_per_second":F,"bytes":N,"seconds":F,"retransmits":N,
 "recv_bits_per_second":F,"threads":N,"error":null|"..."}
```

### replay.sh
```
replay.sh -i eth0 --duration S [--pcap /opt/gen/corpus.pcap] [--mbps N]
```
`tcpreplay -i eth0 -K --loop=0 --topspeed --stats=1 <pcap>` looped forever and
killed after `duration` (tcpreplay's own `--duration` is unreliable across
builds); `--mbps` swaps `--topspeed` for a rate cap. Parses the final
`Actual:`/`Rated:` lines.
```json
{"tool":"replay","sent":N,"bytes":N,"seconds":F,"pps":F,"mbps":F,"pcap":"..."}
```

### frag.sh
```
frag.sh -d IP -p PORT [-t THREADS] [-T SECONDS] [-s 4000] [-r]
```
Thin wrapper over `udpflood -s 4000`; emits udpflood's JSON with `"tool":"frag"`.

## Corpus (`make-corpus.py` → `/opt/gen/corpus.pcap`)

~20,000 Ethernet frames, sizes **60..1514 B**, **17 distinct protocol
signatures**: DNS (A/AAAA/TXT + responses), HTTP GET/200, TLS ClientHello w/
SNI, DHCP discover/offer, mDNS, NTP, QUIC Initial, ICMP echo, ICMPv6 echo,
IPv6 with hop-by-hop and fragment extension headers, ARP, 802.1Q, IPv4
fragments, SCTP INIT/INIT-ACK. **L2 is always unicast gen-MAC → sink-MAC**
(even for frames whose L3 is normally broadcast/multicast) so the SUT bridge
**forwards** each frame to the sink port and never floods — while the L3/L4
content stays the real protocol so the dissector classifies it. Defaults:
`--gen-mac 02:53:4e:46:01:01 --sink-mac 02:53:4e:46:00:05` (override at build
via the `GEN_MAC`/`SINK_MAC` build args). Padding to reach a target size is
appended after scapy computes the real IP/UDP/TCP lengths, so it is pure
Ethernet padding and does not disturb dissection.

## Packages / substitutions (Debian trixie)

* **`wrk` is packaged in trixie** (4.1.0) — used directly; no source build / `ab`
  fallback needed.
* **`dnsutils` is a removed transitional package** in trixie — the image installs
  `bind9-dnsutils` (dig/nslookup/host) instead.
* `libc6-dev` is added so gcc can compile the C generators.

## Measured standalone ceilings

Measured on this host (AMD Ryzen 7 5700X, kernel 6.12) with a plain 8-queue
**veth** pair between a `--network none` `snuffles-gen` container and a peer
netns — i.e. the generator ceiling on the same veth datapath the rig uses, NOT
a physical-NIC number. `pktgen`/C-generator `sent` counters were validated to
equal the peer veth's `rx_packets` delta exactly (a handful of background IPv6
link-local frames aside).

| generator                     | rate |
|-------------------------------|------|
| pktgen 64 B, 1 CPU            | ~0.75–0.79 Mpps (clone_skb 0 forced on veth) |
| pktgen 64 B, 4 CPUs (4,5,6,7) | ~3.1 Mpps (near-linear ×4) |
| pktgen 1514 B, 4 CPUs         | ~3.05 Mpps ≈ 37 Gbps (veth is pps-bound, so ~same pps as 64 B) |
| udpflood 2 threads, 60 B      | ~0.56 Mpps |
| udpflood 2 threads, 1514 B    | ~0.55 Mpps ≈ 6.5 Gbps |
| synflood 2 threads            | ~1.0 Mpps (AF_PACKET bypasses the IP stack) |
| tcpreplay --topspeed (corpus) | ~0.45 Mpps ≈ 1.7 Gbps (mixed sizes, per-packet sendto) |
| wrk vs python `http.server`   | ~390 rps — **server-bound** (single-threaded python), validates parsing only |

These are veth-datapath ceilings for calibration; the rig's bridge + snuffles
capture path will be lower.
