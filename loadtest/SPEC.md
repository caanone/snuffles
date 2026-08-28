# Snuffles load-test rig — specification (contract for all rig scripts)

Goal: drive snuffles with extreme packet rates / byte rates / flow churn on this
host using Docker containers, collect telemetry (app, kernel, process, profiler),
and produce a summary that feeds an improvement plan.

Everything lives under `loadtest/`. Scripts are bash (`set -euo pipefail`),
run from the repo root, and are idempotent (`up` twice is fine).

## Host facts (do not re-discover, rely on these)

- Debian 13, kernel 6.12, AMD Ryzen 7 5700X: 8 cores / 16 threads; SMT pairs
  are (0,8) (1,9) (2,10) (3,11) (4,12) (5,13) (6,14) (7,15). 125 GB RAM.
- `sudo` is passwordless. Docker 29 (cgroup v2, runc). Kernel module `pktgen`
  is already loaded (`/proc/net/pktgen/kpktgend_N` exists per netns).
- Host is SHARED with other running workloads (CI runners, KVM soak VMs).
  Rules: never touch interfaces you did not create; only RAISE host limits and
  record originals for restore; keep everything you create prefixed `snf-`.
- `debian:trixie` image is cached locally. `tc`, `ethtool`, `perf`, `iperf3`,
  `tcpreplay`, `wrk` are NOT on the host — they live in the containers.
- Not namespaced (host-wide sysctls, set by tune-host.sh): net.core.rmem_max,
  wmem_max, netdev_max_backlog, netdev_budget(_usecs), optmem_max.
  Namespaced (set per container with `docker run --sysctl`): net.core.somaxconn,
  net.ipv4.ip_local_port_range, tcp_tw_reuse, tcp_fin_timeout,
  tcp_max_syn_backlog, net.ipv4.ip_forward, net.core.rmem_default?—NO (host).

## CPU plan

| role        | cpuset        | notes |
|-------------|---------------|-------|
| snf-sut     | 2,3,10,11     | snuffles (threads: `snuffles` main/consumer, `snf-capture`, `snf-stats`), telemetry, perf |
| snf-gen-1   | 4,12          | pktgen kthreads are per-CPU kernel threads, NOT cpuset-bound: a generator container programs `/proc/net/pktgen/kpktgend_<cpu>` for any of CPUs 4,5,6,7,12,13,14,15 |
| snf-gen-2   | 5,13          | |
| snf-gen-3   | 6,14          | |
| snf-gen-4   | 7,15          | |
| snf-sink    | 0,8           | nginx, iperf3 server, udpsink (syslog counter) |
| (host)      | 0,1,8,9       | left for the rest of the machine |

## Containers

All containers: `--privileged --network none --ulimit nofile=1048576:1048576
--ulimit memlock=-1:-1 --cpuset-cpus <see table> --name snf-<role>
--hostname snf-<role> -v $REPO/loadtest/results:/results -v $REPO:/repo:ro`
plus `--sysctl` for the namespaced keys (gen/sink: ip_local_port_range
"1024 65535", tcp_tw_reuse=1, tcp_fin_timeout=5, somaxconn=65535,
tcp_max_syn_backlog=65535). They run `sleep infinity` and get work via
`docker exec`. Images: `snuffles-sut`, `snuffles-gen`, `snuffles-sink`
(Dockerfiles in `loadtest/docker/`). Each image starts FROM debian:trixie.

- snuffles-sut: build-essential, libpcap-dev, linux-perf, iproute2, procps,
  python3, ethtool, nftables, strace, jq. `/opt/snuffles/build.sh` copies
  /repo to /src (rsync/cp, excluding build/ and .git) and builds
  `/opt/snuffles/pcap/snuffles` (`make`) and `/opt/snuffles/raw/snuffles`
  (`make nopcap`) with `CFLAGS="-g -fno-omit-frame-pointer"` (the Makefile
  adds its own -O2). Must be re-runnable at any time (experiments rebuild).
- snuffles-gen: iproute2, ethtool, tcpreplay, iperf3, wrk, hping3, nmap
  (nping), python3-scapy, gcc, make, procps, nftables, curl, dnsutils, jq.
  Builds `/opt/gen/udpflood` and `/opt/gen/synflood` from `loadtest/gen/*.c`
  at image build time.
- snuffles-sink: nginx, iperf3, iproute2, procps, python3, gcc, nftables, jq.
  Builds `/opt/sink/udpsink` from `loadtest/sink/udpsink.c`. nginx serves
  `/` (small page) and `/big` (100 MB random file), `worker_processes 2`,
  `worker_connections 65535`, `listen 80 backlog=65535 reuseport`,
  `access_log off`, `/status` = stub_status.

## Network topology (built by rig.sh with `nsenter -t <pid> -n -m`)

Inside the snf-sut netns:
- bridge `br0` 10.77.0.1/16, MAC 02:53:4e:46:00:01, `stp_state 0`,
  `mcast_snooping 0`, `ageing_time 0` is NOT used (keep learning).
- ports `p1..p4` = veth peers of snf-gen-N `eth0` (10.77.0.1N/16, MAC
  02:53:4e:46:01:0N), `p5` = peer of snf-sink `eth0` (10.77.0.5/16, MAC
  02:53:4e:46:00:05). veths created with `numrxqueues 8 numtxqueues 8`.
- `mgmt0` 10.78.0.1/24 <-> snf-sink `mgmt0` 10.78.0.5/24 (direct veth, NOT
  on br0) — the --syslog target is 10.78.0.5:514 so syslog output is never
  part of the captured traffic.
- Static ARP/neighbour entries everywhere (no ARP storms, no learning noise):
  every container has permanent neigh entries for every other IP on 10.77/16
  it talks to; br0 fdb learns normally.
- `tc qdisc add dev eth0 clsact` in snf-sink and `tc filter add dev eth0
  ingress pref 1 protocol ip u32 match ip dport 9 0xffff action drop`
  (flood traffic to UDP port 9 is dropped at ingress in the sink, so the
  bridge forwards it — and snuffles sees it in promisc — but no IP stack work
  happens). Same drop rule on br0 in snf-sut for dst=sut floods (packet taps
  run BEFORE tc ingress in __netif_receive_skb_core, so capture still sees it).
- MTU: default 1500 on everything; `rig.sh mtu 9000` switches br0+all
  veths (both ends) to 9000, `rig.sh mtu 1500` back.
- Offloads: `rig.sh offloads off|on` toggles tso/gso/gro/tx-checksumming on
  every gen/sink eth0 and the p* ports (ethtool -K). Default: on (that is
  what a real host sees: GSO super-frames > MTU on the capture side).
- RPS: `rig.sh rps on|off` writes the SUT cpumask (CPUs 2,3,10,11 =
  0x0c0c) or 0 into `/sys/class/net/{br0,p1..p5}/queues/rx-*/rps_cpus` in the
  SUT netns. Default off.

## Host tuning (`loadtest/tune-host.sh apply|restore|show`)

apply: saves current values to `loadtest/results/host-sysctl.before` (only
if that file does not exist yet) then sets
`net.core.rmem_max=536870912 net.core.wmem_max=536870912
net.core.netdev_max_backlog=250000 net.core.netdev_budget=1200
net.core.netdev_budget_usecs=20000 net.core.optmem_max=4194304`,
`modprobe pktgen`, and raises `vm.max_map_count` only if < 262144.
restore: writes back the saved values (idempotent) and leaves pktgen loaded.
Writes go through `sudo sh -c 'echo V > /proc/sys/...'` (no sysctl binary).

## Scenario file (JSON; one per scenario, under `loadtest/scenarios/*.json`)

```json
{
  "name": "A2-pktgen64-8t-max",
  "build": "pcap",                 // pcap | raw
  "mode": "quiet",                 // quiet | headless | headless-pipe | jsonl |
                                   // syslog | stream-null | stream-disk | tui | tui-sessions
  "snaplen": 65535, "ring": 10000, // omitted => snuffles defaults
  "iface": "br0",                  // br0 | p1..p5
  "bpf": "",                       // -f filter
  "duration": 30,                  // seconds of traffic
  "perf": true,                    // perf record 15s + perf stat 10s mid-run
  "mtu": 1500, "offloads": "on", "rps": "off",
  "traffic": {
    "kind": "pktgen",              // pktgen | udpflood | synflood | http | iperf | replay | frag
    "gens": [1,2,3,4],             // which generator containers drive
    "cpus": [4,5,6,7,12,13,14,15], // pktgen: kpktgend CPUs to use (split round-robin over gens)
    "pkt_size": 64,                // pktgen/udpflood: bytes on wire incl. Ethernet
    "pps": 0,                      // 0 = unlimited; otherwise per-thread pktgen `ratep`
    "flows": 1,                    // pktgen: 1 = fixed 5-tuple; N>1 => IPSRC_RND+UDPSRC_RND over N src IPs
    "dst": "sink",                 // sink | sut  (which MAC/IP the flood is addressed to)
    "threads": 2,                  // per gen: udpflood/synflood threads, wrk -t, iperf -P
    "conns": 256,                  // http: wrk -c per gen
    "keepalive": true,             // http: false adds 'Connection: close'
    "url": "/",                    // http: / or /big
    "extra": ""                    // free-form passthrough to the driver
  }
}
```

Modes map to snuffles argv (always add `--stats=/results/<run>/<name>/snuffles.stats`
and `-i <iface>`; run as root inside snf-sut; stdout as noted):

| mode           | argv                                         | stdout |
|----------------|----------------------------------------------|--------|
| quiet          | `-q`                                         | /dev/null |
| headless       | `--no-ui`                                    | /dev/null |
| headless-pipe  | `--no-ui`                                    | `\| wc -l > out.count` (slow consumer) |
| jsonl          | `--jsonl`                                    | /dev/null |
| syslog         | `-q --syslog 10.78.0.5:514`                  | /dev/null; udpsink counts on the sink |
| stream-null    | `-q -w /dev/null`                            | /dev/null |
| stream-disk    | `-q -w /results/<run>/<name>/stream.pcap`    | /dev/null (file deleted after size is recorded) |
| tui            | (none) under a pty 200x50 via python3 `pty`, `--stats=FILE`, send `q` at the end | pty, discarded |
| tui-sessions   | as tui; send `S` (sessions view) after 5 s, `V` at 15 s, `S` at 20 s | pty |

## Per-run procedure (`loadtest/run-scenario.sh <scenario.json> [run-id]`)

Results dir: `loadtest/results/<run-id>/<name>/` (run-id default: `$(date +%Y%m%d-%H%M%S)`;
`loadtest/matrix.sh <run-id> scenarios...` runs many with one run-id).

1. Prepare: kill stray snuffles / generators / udpsink / perf; `pgctrl reset` in
   every gen; apply scenario mtu/offloads/rps; nothing else changes.
2. Start `udpsink` on snf-sink (`-p 514 -o /results/.../sink.json`, SO_RCVBUFFORCE 64 MB,
   recvmmsg, 1 Hz count lines) for syslog mode; nginx/iperf3 servers are
   started once by `rig.sh up` and stay up.
3. Start `telemetry.sh` in snf-sut (1 Hz JSONL to telemetry.jsonl; see below).
4. Start snuffles in snf-sut per the mode table; wait until snuffles.stats has
   its first `stats` line (max 10 s) — else record `start_failed`.
5. Sleep 3 s (idle baseline), start traffic (all drivers take a duration and
   end by themselves; pktgen: `count 0` + `pgctrl start` in background, then
   `pgctrl stop` after duration), if perf: at +8 s `perf stat -p PID -e
   task-clock,context-switches,cpu-migrations,page-faults,cycles,instructions,
   cache-misses,branch-misses,syscalls:sys_enter_write,syscalls:sys_enter_sendto,
   syscalls:sys_enter_getsockopt,syscalls:sys_enter_recvfrom,syscalls:sys_enter_select,
   syscalls:sys_enter_poll -- sleep 10 > perf-stat.txt` then at +19 s
   `perf record -F 999 -g -p PID -o perf.data -- sleep 8`; afterwards
   `perf report --stdio --no-children -i perf.data | head -120 > perf-report.txt`,
   `perf script | stackcollapse` is NOT required (no flamegraph tools); keep
   perf.data out of git (results/ is gitignored except summary files).
6. Traffic ends; sleep 2 s; SIGINT snuffles; wait up to 30 s, SIGKILL if
   needed; record `exit_code`, `exit_latency_ms`, `killed`.
7. Collect: gen results (`gen-<N>.json`: sent_pkts, sent_bytes, seconds,
   pps, driver output verbatim), sink.json, snuffles.stats, snuffles.stderr,
   telemetry.jsonl, out.count (pipe mode), perf files, `manifest.json`
   (scenario, run-id, git sha of /repo, snuffles -v, start/end epoch, host
   uname, cpuset info).
8. `loadtest/analyze.py <run-id>` computes `summary.json` per scenario and
   `summary.csv` + `summary.md` per run. Per-scenario fields: name, build,
   mode, traffic kind, pkt_size, sent_pps (sum of gens), sent_total,
   captured_total (final `summary` line: captured), captured_pps,
   kdrop_total, kdrop_pct (= kdrop/(captured+kdrop)), ifdrop, missed
   (consumer), emitted, syslog_sent, syslog_fail, syslog_delivered
   (udpsink), streamed, sessions_final, rss_max_kb, cpu_capture_pct,
   cpu_main_pct, cpu_stats_pct (from per-thread telemetry, % of one CPU),
   ctxsw_per_s, syscalls_per_pkt (perf stat), ipc, exit_latency_ms,
   exit_code, killed, softnet_dropped_delta, softnet_squeezed_delta,
   br0_rx_pkts_delta, packet_socket_drops (ss).

## Telemetry sampler (`loadtest/sut/telemetry.sh <pid> <outfile>`; runs in snf-sut)

Every 1 s emits one JSON object: `t` (epoch float), `proc` {utime, stime,
rss_kb, threads, nvcsw, nivcsw, minflt, majflt} for the pid, `threads`
{comm: {utime, stime, nvcsw, nivcsw}} per task, `softnet` (sum over CPUs of
processed, dropped, time_squeeze) from /proc/net/softnet_stat,
`ifaces` {name: {rx_packets, rx_bytes, rx_dropped, tx_packets, tx_bytes,
tx_dropped}} for br0, p1..p5, mgmt0, `pktsock` {rmem, rcvbuf, drops} from
`ss -0 -e -m -H` (the `d<N>` field in skmem), `mem_current` from the
container's cgroup (`/sys/fs/cgroup/memory.current`), `loadavg`.
utime/stime are raw clock ticks; analyze.py converts using CLK_TCK=100.

## Generators (`loadtest/gen/`, executed inside snf-gen-N via docker exec)

- `pktgen.sh start|stop|reset|result -d eth0 --cpus 4,12 --size 64 --dst-mac
  <mac> --dst-ip <ip> --pps 0 --flows N --src-ip 10.77.0.1N`: programs
  kpktgend_<cpu> with `rem_device_all; add_device eth0@<cpu>` then per device:
  `count 0`, `clone_skb 1000`, `pkt_size <size-4>` (pktgen's size excludes
  the 4-byte FCS: wire 64 => pkt_size 60), `delay 0`, `dst_mac`, `dst`,
  `src_min/src_max` (= --src-ip when flows==1, else 10.77.128.0 ..
  10.77.128.0+flows-1 capped at 10.77.255.254 with `flag IPSRC_RND`),
  `udp_src_min 1024 udp_src_max 65535` + `flag UDPSRC_RND` when flows>1,
  `udp_dst_min 9 udp_dst_max 9`, `flag NO_TIMESTAMP`, `ratep <pps>` if
  pps>0, `burst 8`? — NO burst (veth path; keep default). `start` writes
  `start` to pgctrl in the background and returns; `stop` writes `stop`;
  `result` parses each `/proc/net/pktgen/eth0@<cpu>` into JSON
  {cpu, sofar, pps, bps, errors, seconds}. IMPORTANT: pktgen's counters are
  only final after `stop`.
- `udpflood.c`: `udpflood -d IP -p PORT -s SIZE -t THREADS -T SECONDS [-r]`
  connected UDP sockets, one per thread, sendmmsg batches of 64, SO_SNDBUF
  32 MB, prints JSON {sent, bytes, seconds, pps, errors}. `-r` = random source
  port per batch (new socket every 64 messages is too slow; instead bind
  THREADS*16 sockets up front and round-robin). Payload SIZE is UDP payload
  bytes; `-s 4000` produces IP fragments (3 per datagram at MTU 1500).
- `synflood.c`: AF_PACKET SOCK_RAW sendmmsg TCP SYN generator, random
  source IP in 10.77.128.0/17 and random source port, dst 10.77.0.5:80 (sink
  nginx; nginx answers SYN-ACK so both directions and RST/… flow), fixed
  src MAC of the container, `-t THREADS -T SECONDS`, JSON result.
- `http.sh`: `wrk -t<threads> -c<conns> -d<duration>s [-H 'Connection: close']
  http://10.77.0.5<url>` → parse "Requests/sec" and "Transfer/sec" → JSON.
- `iperf.sh`: `iperf3 -c 10.77.0.5 -P <threads> -t <duration> -J` → JSON
  bits_per_second, retransmits.
- `replay.sh`: `tcpreplay -i eth0 --topspeed --loop=0 --duration=<d>`
  is not available in all versions — use `--loop=0` and kill after duration,
  `-K --preload-pcap`; corpus at `/opt/gen/corpus.pcap`, built by
  `loadtest/gen/make-corpus.py` (scapy, at image build time): ~20k packets:
  DNS query/response (A/AAAA/TXT), HTTP GET/200, TLS ClientHello with SNI,
  DHCP discover/offer, mDNS, NTP, QUIC initial, ICMP echo, ICMPv6, IPv6
  TCP/UDP with hop-by-hop+fragment ext headers, ARP, 802.1Q tagged frames,
  IPv4 fragments, SCTP INIT, sizes 60..1514, src/dst MACs = gen MAC -> sink
  MAC so the bridge forwards (never floods). tcpreplay `--stats=1` output
  parsed to JSON {sent, bytes, seconds, pps}.
- `frag.sh`: udpflood with `-s 4000`.

## Sink (`loadtest/sink/`)

- `udpsink.c`: `udpsink -p PORT -o out.json [-b 67108864]` recvmmsg loop,
  SO_RCVBUFFORCE, prints per-second counts to stderr and on SIGINT/SIGTERM
  writes JSON {received, bytes, seconds, rcvbuf_errors_delta (from
  /proc/net/snmp Udp: RcvbufErrors)}.
- nginx config at `loadtest/sink/nginx.conf`; `rig.sh up` starts nginx and
  `iperf3 -s -D` in snf-sink.

## rig.sh commands

`rig.sh build` (docker build the 3 images), `rig.sh up` (tune-host apply,
create containers, topology, static neigh, tc drops, start sink services,
build snuffles in sut), `rig.sh down` (remove containers + host veths if any,
tune-host restore), `rig.sh status`, `rig.sh mtu N`, `rig.sh offloads on|off`,
`rig.sh rps on|off`, `rig.sh build-sut` (rebuild snuffles from /repo),
`rig.sh exec <role> <cmd...>`, `rig.sh smoke` (10 s pktgen 64B 1 CPU
scenario `S0-smoke` end-to-end, prints summary line).

## Results hygiene

`loadtest/results/` is gitignored EXCEPT `*/summary.csv`, `*/summary.md`,
`*/*/summary.json`, `*/*/manifest.json`, `*/*/snuffles.stats`,
`*/*/perf-report.txt`, `*/*/perf-stat.txt` (small text; kept in git).
perf.data, stream.pcap, telemetry.jsonl are never committed.
