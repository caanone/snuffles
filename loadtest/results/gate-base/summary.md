# Load-test summary — run `gate-base`

7 scenario(s). pps in k/M (3 sig. figs); percentages 2 dp.

| scenario | mode | kind | sent | bridge in | seen% | captured | offered pps | cap pps | kdrop% | kdrop% win | sinks | rss MB | cap% | main% | cyc/pkt | sys/pkt | ipc | win s | status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| A2-pktgen64-8cpu-max | quiet | pktgen | 52.3M | 52.3M | 100.00 | 52.3M | 2.57M | 2.57M | 0.00 | 0.00 | 0 | 86.8 | 30.77 | 0.00 | 475 |  |  | 19.1 | ok |
| A2-pktgen64-8cpu-max-ndr-ceil | quiet | pktgen | 52.4M | 52.4M | 100.00 | 52.4M | 2.58M | 2.58M | 0.00 | 0.00 | 0 | 86.6 | 32.45 | 0.00 | 500 |  |  | 19.1 | ok |
| A2-pktgen64-8cpu-max-ndr-confirm | quiet | pktgen | 52.3M | 52.3M | 100.00 | 52.3M | 2.58M | 2.58M | 0.00 | 0.00 | 0 | 86.8 | 31.89 | 0.00 | 492 |  |  | 19.1 | ok |
| A3d-pktgen64-8cpu-ratep-1m | quiet | pktgen | 20.3M | 20.3M | 100.00 | 20.3M | 1e+03k | 1e+03k | 0.00 | 0.00 | 0 | 86.8 | 11.89 | 0.00 | 473 |  |  | 19.1 | ok |
| A6-pktgen64-8cpu-flows1m | quiet | pktgen | 51.3M | 51.3M | 100.00 | 51.3M | 2.52M | 2.52M | 0.00 | 0.00 | 0 | 119.3 | 58.16 | 0.00 | 916 |  |  | 19.1 | ok |
| B3-syslog-1m | syslog | pktgen | 20.4M | 20.4M | 100.00 | 20.4M | 1M | 1M | 0.00 | 0.00 | 0 | 13.9 | 9.00 | 0.00 | 358 |  |  | 19.1 | ok |
| B6-tui-1m | tui | pktgen | 20.3M | 20.3M | 100.00 | 20.3M | 1e+03k | 1e+03k | 0.00 | 0.00 | 0 | 91.8 | 12.39 | 4.50 | 492 |  |  | 19.1 | ok |

Columns: **sent** = generator's own count in wire frames (udpflood/frag datagrams x fragments; blank for http/iperf whose drivers count requests/bytes). **bridge in** = frames that entered the SUT bridge on p1..p5 during the whole run (app-independent; includes sink replies). **seen%** = (captured+kdrop)/bridge in: 100 means every frame reached the packet socket, so kdrop is the ONLY loss point. **offered pps** / **cap pps** / **kdrop% win** are steady-state values over the trimmed traffic window (**win s**); **kdrop%** is whole-run. **sinks** = app-side output losses = missed (ring wrapped past the consumer) + syslog_fail + stream (-w) write failures; it closes the accounting chain generator -> bridge -> socket -> app sinks. **cyc/pkt** = capture CPU% x SUT MHz x 1e4 / cap pps (cycles the capture thread spends per packet). **sys/pkt** = write+sendto+getsockopt+recvfrom+select+poll+openat+read syscalls per captured packet during the perf-stat window. CPU% are per-thread, % of one CPU. Note for the pcap build the packet-socket ring drops are visible only through the app's kdrop (libpcap's TPACKET ring counts drops in tp_drops, not sk_drops which `ss` shows); the raw build's plain socket shows them in `ss` too (packet_socket_drops). jsonl-latency runs also report latency_p50/p95/p99_ms (capture-to-output) in summary.csv / summary.json.

## NDR search — `A2-pktgen64-8cpu-max`

- loss criterion: kdrop_pct_win <= **0%**  (threads: 8, trial 20s, confirm 20s)
- ceiling offered: **2577548 pps** (unlimited run)
- **NDR = ceiling** (sustained at the max offered rate)
- **NDR (confirmed): 2575095 pps** at confirm kdrop_pct_win **0.0%**
- iterations: 2 (see ndr.json)
