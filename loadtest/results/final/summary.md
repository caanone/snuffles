# Load-test summary — run `final`

9 scenario(s). pps in k/M (3 sig. figs); percentages 2 dp.

| scenario | mode | kind | sent | bridge in | seen% | captured | offered pps | cap pps | kdrop% | kdrop% win | rss MB | cap% | main% | sys/pkt | ipc | win s | status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| A2-pktgen64-8cpu-max | quiet | pktgen | 75.1M | 75.1M | 100.00 | 75.1M | 2.56M | 2.56M | 0.00 | 0.00 | 86.8 | 29.15 | 0.04 | 0.00058 | 1.71 | 28.1 | ok |
| A3d-pktgen64-8cpu-ratep-1m | quiet | pktgen | 20.3M | 20.3M | 100.00 | 20.3M | 1M | 1M | 0.00 | 0.00 | 86.8 | 11.05 | 0.00 |  |  | 19.1 | ok |
| A6-pktgen64-8cpu-flows1m | quiet | pktgen | 76.3M | 76.3M | 100.00 | 76.3M | 2.51M | 2.51M | 0.00 | 0.00 | 119.2 | 55.70 | 0.04 | 0.00058 | 1.15 | 29.1 | ok |
| A9-raw-pktgen64-8cpu-max | quiet | pktgen | 76.8M | 76.8M | 100.00 | 76.8M | 2.53M | 2.53M | 0.00 | 0.00 | 86.3 | 28.21 | 0.00 | 0.0011 | 1.69 | 29.1 | ok |
| B1-headless-1m | headless | pktgen | 30.4M | 30.4M | 100.00 | 30.4M | 1e+03k | 1e+03k | 0.00 | 0.00 | 87.4 | 12.39 | 91.31 |  |  | 29.1 | ok |
| B3-syslog-1m | syslog | pktgen | 30.4M | 30.4M | 100.00 | 30.4M | 1M | 1M | 0.00 | 0.00 | 14.0 | 8.25 | 0.00 | 0.00058 | 1.02 | 29.1 | ok |
| B6-tui-1m | tui | pktgen | 30.4M | 30.4M | 100.00 | 30.4M | 1e+03k | 1e+03k | 0.00 | 0.00 | 91.8 | 12.32 | 4.68 | 0.00068 | 1.39 | 29.1 | ok |
| B7-tuisessions-flows1m | tui-sessions | pktgen | 30.3M | 30.3M | 100.00 | 30.3M | 1M | 1M | 0.00 | 0.00 | 156.1 | 23.89 | 7.61 |  |  | 29.1 | ok |
| C4-iperf-tcp | quiet | iperf |  | 3.15M | 100.00 | 3.15M | 105k | 105k | 0.00 | 0.00 | 87.2 | 24.50 | 0.04 | 0.175 | 0.383 | 29.2 | ok |

Columns: **sent** = generator's own count in wire frames (udpflood/frag datagrams x fragments; blank for http/iperf whose drivers count requests/bytes). **bridge in** = frames that entered the SUT bridge on p1..p5 during the whole run (app-independent; includes sink replies). **seen%** = (captured+kdrop)/bridge in: 100 means every frame reached the packet socket, so kdrop is the ONLY loss point. **offered pps** / **cap pps** / **kdrop% win** are steady-state values over the trimmed traffic window (**win s**); **kdrop%** is whole-run. **sys/pkt** = write+sendto+getsockopt+recvfrom+select+poll syscalls per captured packet during the perf-stat window. CPU% are per-thread, % of one CPU. Note for the pcap build the packet-socket ring drops are visible only through the app's kdrop (libpcap's TPACKET ring counts drops in tp_drops, not sk_drops which `ss` shows); the raw build's plain socket shows them in `ss` too (packet_socket_drops).
