# Load-test summary — run `gate-verify`

7 scenario(s). pps in k/M (3 sig. figs); percentages 2 dp.

| scenario | mode | kind | sent | bridge in | seen% | captured | offered pps | cap pps | kdrop% | kdrop% win | sinks | rss MB | cap% | main% | cyc/pkt | sys/pkt | ipc | win s | status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| A2-pktgen64-8cpu-max | quiet | pktgen | 52.3M | 52.3M | 100.00 | 52.3M | 2.58M | 2.58M | 0.00 | 0.00 | 0 | 86.8 | 29.45 | 0.00 | 454 |  |  | 19.1 | ok |
| A2-pktgen64-8cpu-max-ndr-ceil | quiet | pktgen | 52.5M | 52.5M | 100.00 | 52.5M | 2.58M | 2.58M | 0.00 | 0.00 | 0 | 86.7 | 28.27 | 0.00 | 436 |  |  | 19.1 | ok |
| A2-pktgen64-8cpu-max-ndr-confirm | quiet | pktgen | 52.2M | 52.2M | 100.00 | 52.2M | 2.57M | 2.57M | 0.00 | 0.00 | 0 | 86.7 | 30.06 | 0.00 | 465 |  |  | 19.1 | ok |
| A3d-pktgen64-8cpu-ratep-1m | quiet | pktgen | 20.3M | 20.3M | 100.00 | 20.3M | 1M | 1M | 0.00 | 0.00 | 0 | 86.7 | 10.94 | 0.00 | 432 |  |  | 19.1 | ok |
| A6-pktgen64-8cpu-flows1m | quiet | pktgen | 51.3M | 51.3M | 100.00 | 51.3M | 2.52M | 2.52M | 0.00 | 0.00 | 0 | 119.2 | 59.66 | 0.06 | 940 |  |  | 19.1 | ok |
| B3-syslog-1m | syslog | pktgen | 20.3M | 20.3M | 100.00 | 20.3M | 1M | 1M | 0.00 | 0.00 | 0 | 14.0 | 7.95 | 0.00 | 316 |  |  | 19.1 | ok |
| B6-tui-1m | tui | pktgen | 20.3M | 20.3M | 100.00 | 20.3M | 1M | 1M | 0.00 | 0.00 | 0 | 91.9 | 12.06 | 4.28 | 479 |  |  | 19.1 | ok |

Columns: **sent** = generator's own count in wire frames (udpflood/frag datagrams x fragments; blank for http/iperf whose drivers count requests/bytes). **bridge in** = frames that entered the SUT bridge on p1..p5 during the whole run (app-independent; includes sink replies). **seen%** = (captured+kdrop)/bridge in: 100 means every frame reached the packet socket, so kdrop is the ONLY loss point. **offered pps** / **cap pps** / **kdrop% win** are steady-state values over the trimmed traffic window (**win s**); **kdrop%** is whole-run. **sinks** = app-side output losses = missed (ring wrapped past the consumer) + syslog_fail + stream (-w) write failures; it closes the accounting chain generator -> bridge -> socket -> app sinks. **cyc/pkt** = capture CPU% x SUT MHz x 1e4 / cap pps (cycles the capture thread spends per packet). **sys/pkt** = write+sendto+getsockopt+recvfrom+select+poll+openat+read syscalls per captured packet during the perf-stat window. CPU% are per-thread, % of one CPU. Note for the pcap build the packet-socket ring drops are visible only through the app's kdrop (libpcap's TPACKET ring counts drops in tp_drops, not sk_drops which `ss` shows); the raw build's plain socket shows them in `ss` too (packet_socket_drops). jsonl-latency runs also report latency_p50/p95/p99_ms (capture-to-output) in summary.csv / summary.json.

## NDR search — `A2-pktgen64-8cpu-max`

- loss criterion: kdrop_pct_win <= **0%**  (threads: 8, trial 20s, confirm 20s)
- ceiling offered: **2577007 pps** (unlimited run)
- **NDR = ceiling** (sustained at the max offered rate)
- **NDR (confirmed): 2571195 pps** at confirm kdrop_pct_win **0.0%**
- iterations: 2 (see ndr.json)

## Regression gate — `gate-verify`

Baseline: `gate-baseline.json` (generated 2026-08-29T08:16:25+03:00, commit `1e87a79`); duration 20s.

```
scenario                       metric            baseline     measured   delta%   kdrop b   kdrop m verdict notes
A2-pktgen64-8cpu-max           captured_pps       2572655      2576697     +0.2       0.0       0.0 pass    
A3d-pktgen64-8cpu-ratep-1m     captured_pps        999958      1000054       +0       0.0       0.0 pass    
A6-pktgen64-8cpu-flows1m       captured_pps       2524046      2522813       +0       0.0       0.0 pass    
B3-syslog-1m                   captured_pps       1000098      1000054       +0       0.0       0.0 pass    
B6-tui-1m                      captured_pps        999994      1000028       +0       0.0       0.0 pass    
ndr:A2-pktgen64-8cpu-max       ndr_pps            2575095      2571195     -0.2       0.0       0.0 pass    

result: PASS   (6 passed, 0 failed, 0 skipped)
```
