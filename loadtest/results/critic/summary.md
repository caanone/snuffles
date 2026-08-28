# Load-test summary — run `critic`

12 scenario(s). pps in k/M (3 sig. figs); percentages 2 dp.

| scenario | mode | kind | sent | bridge in | seen% | captured | offered pps | cap pps | kdrop% | kdrop% win | rss MB | cap% | main% | sys/pkt | ipc | win s | status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| A1-pktgen64-1cpu | quiet | pktgen | 5.25M | 5.25M | 100.00 | 5.24M | 430k | 430k | 0.24 | 0.00 | 630.3 | 72.30 | 0.00 |  |  | 11.0 | ok |
| A2-pktgen64-8cpu-max | quiet | pktgen | 34.6M | 34.6M | 100.00 | 6.51M | 2.8M | 540k | 81.18 | 80.75 | 630.4 | 99.98 | 0.00 | 0.936 | 1.55 | 11.1 | ok |
| A9-raw-pktgen64-8cpu-max | quiet | pktgen | 34.9M | 34.9M | 100.00 | 4.92M | 2.83M | 398k | 85.88 | 85.92 | 629.9 | 99.97 | 0.00 | 1.98 | 1.33 | 11.1 | ok |
| B3-syslog-1m | syslog | pktgen | 12.4M | 12.4M | 100.00 | 1.9M | 1e+03k | 154k | 84.67 | 84.64 | 4.9 | 99.94 | 0.00 | 2.02 | 0.99 | 11.1 | ok |
| B6-tui-1m | tui | pktgen | 12.3M | 12.3M | 100.00 | 4.96M | 1M | 403k | 59.84 | 59.72 | 632.4 | 99.97 | 98.07 | 1.04 | 1.61 | 11.1 | ok |
| B7-tuisessions-flows1m | tui-sessions | pktgen | 12.3M | 12.3M | 100.00 | 1.31M | 1M | 95.8k | 89.35 | 90.42 | 678.9 | 55.30 | 97.70 |  |  | 11.0 | ok |
| B8-headlesspipe-1m | headless-pipe | pktgen | 12.3M | 12.3M | 100.00 | 5.39M | 1M | 441k | 56.29 | 55.89 | 630.4 | 99.89 | 96.19 |  |  | 11.0 | ok |
| C1-http-keepalive | quiet | http |  | 2.46M | 100.00 | 2.45M | 204k | 204k | 0.12 | 0.00 | 646.8 | 44.19 | 0.00 | 1.02 | 1.74 | 12.1 | ok |
| C4-iperf-tcp | quiet | iperf |  | 1.43M | 100.00 | 1.23M | 118k | 103k | 13.64 | 12.15 | 633.8 | 98.39 | 0.00 | 1.02 | 0.503 | 11.1 | ok |
| C5-replay-quiet | quiet | replay | 9.37M | 11.7M | 100.00 | 5.89M | 992k | 501k | 49.75 | 49.46 | 637.0 | 99.63 | 0.00 |  |  | 12.1 | ok |
| C6-synflood-quiet | quiet | synflood | 926k | 2.31M | 100.00 | 2.27M | 190k | 186k | 1.61 | 1.79 | 654.9 | 73.73 | 0.00 | 0.978 | 0.946 | 12.1 | ok |
| C8-frag-quiet | quiet | frag | 25.2M | 25.2M | 100.00 | 6.34M | 2.1M | 527k | 74.83 | 74.97 | 630.5 | 99.92 | 0.00 |  |  | 11.1 | ok |

Columns: **sent** = generator's own count in wire frames (udpflood/frag datagrams x fragments; blank for http/iperf whose drivers count requests/bytes). **bridge in** = frames that entered the SUT bridge on p1..p5 during the whole run (app-independent; includes sink replies). **seen%** = (captured+kdrop)/bridge in: 100 means every frame reached the packet socket, so kdrop is the ONLY loss point. **offered pps** / **cap pps** / **kdrop% win** are steady-state values over the trimmed traffic window (**win s**); **kdrop%** is whole-run. **sys/pkt** = write+sendto+getsockopt+recvfrom+select+poll syscalls per captured packet during the perf-stat window. CPU% are per-thread, % of one CPU. Note for the pcap build the packet-socket ring drops are visible only through the app's kdrop (libpcap's TPACKET ring counts drops in tp_drops, not sk_drops which `ss` shows); the raw build's plain socket shows them in `ss` too (packet_socket_drops).
