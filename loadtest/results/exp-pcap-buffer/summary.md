# Load-test summary — run `exp-pcap-buffer`

4 scenario(s). pps in k/M (3 sig. figs); percentages 2 dp.

| scenario | mode | kind | sent | bridge in | seen% | captured | offered pps | cap pps | kdrop% | kdrop% win | rss MB | cap% | main% | sys/pkt | ipc | win s | status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| A2-pktgen64-8cpu-max | quiet | pktgen | 84.7M | 84.7M | 100.00 | 20.7M | 2.79M | 664k | 75.61 | 76.23 | 692.3 | 99.91 | 0.00 | 1.01 | 1.85 | 29.1 | ok |
| A3d-pktgen64-8cpu-ratep-1m | quiet | pktgen | 19.3M | 19.3M | 100.00 | 14.1M | 999k | 714k | 26.88 | 28.54 | 692.4 | 99.81 | 0.06 |  |  | 18.1 | ok |
| B1-headless-1m | headless | pktgen | 29.3M | 29.3M | 100.00 | 16.5M | 1M | 554k | 43.74 | 44.65 | 692.6 | 99.87 | 99.43 |  |  | 28.1 | ok |
| B6-tui-1m | tui | pktgen | 29.4M | 29.4M | 100.00 | 14.4M | 1M | 473k | 51.05 | 52.72 | 694.4 | 99.78 | 97.41 | 1.03 | 1.61 | 28.1 | ok |

Columns: **sent** = generator's own count in wire frames (udpflood/frag datagrams x fragments; blank for http/iperf whose drivers count requests/bytes). **bridge in** = frames that entered the SUT bridge on p1..p5 during the whole run (app-independent; includes sink replies). **seen%** = (captured+kdrop)/bridge in: 100 means every frame reached the packet socket, so kdrop is the ONLY loss point. **offered pps** / **cap pps** / **kdrop% win** are steady-state values over the trimmed traffic window (**win s**); **kdrop%** is whole-run. **sys/pkt** = write+sendto+getsockopt+recvfrom+select+poll syscalls per captured packet during the perf-stat window. CPU% are per-thread, % of one CPU. Note for the pcap build the packet-socket ring drops are visible only through the app's kdrop (libpcap's TPACKET ring counts drops in tp_drops, not sk_drops which `ss` shows); the raw build's plain socket shows them in `ss` too (packet_socket_drops).
