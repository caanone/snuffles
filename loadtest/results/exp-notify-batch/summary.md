# Load-test summary — run `exp-notify-batch`

4 scenario(s). pps in k/M (3 sig. figs); percentages 2 dp.

| scenario | mode | kind | sent | bridge in | seen% | captured | offered pps | cap pps | kdrop% | kdrop% win | rss MB | cap% | main% | sys/pkt | ipc | win s | status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| A2-pktgen64-8cpu-max | quiet | pktgen | 83.8M | 83.8M | 100.00 | 28.1M | 2.76M | 924k | 66.42 | 66.50 | 630.2 | 99.85 | 0.00 | 0.0157 | 2.61 | 29.1 | ok |
| A9-raw-pktgen64-8cpu-max | quiet | pktgen | 85.3M | 85.3M | 100.00 | 16.2M | 2.81M | 533k | 81.06 | 81.01 | 627.9 | 99.91 | 0.00 | 1 | 1.6 | 29.1 | ok |
| B1-headless-1m | headless | pktgen | 30.4M | 30.4M | 100.00 | 23.6M | 1M | 786k | 22.09 | 21.37 | 630.4 | 99.38 | 88.77 |  |  | 29.1 | ok |
| B6-tui-1m | tui | pktgen | 29.4M | 29.4M | 100.00 | 20.1M | 1e+03k | 681k | 31.85 | 31.90 | 630.5 | 99.89 | 97.59 | 0.0371 | 2.02 | 28.1 | ok |

Columns: **sent** = generator's own count in wire frames (udpflood/frag datagrams x fragments; blank for http/iperf whose drivers count requests/bytes). **bridge in** = frames that entered the SUT bridge on p1..p5 during the whole run (app-independent; includes sink replies). **seen%** = (captured+kdrop)/bridge in: 100 means every frame reached the packet socket, so kdrop is the ONLY loss point. **offered pps** / **cap pps** / **kdrop% win** are steady-state values over the trimmed traffic window (**win s**); **kdrop%** is whole-run. **sys/pkt** = write+sendto+getsockopt+recvfrom+select+poll syscalls per captured packet during the perf-stat window. CPU% are per-thread, % of one CPU. Note for the pcap build the packet-socket ring drops are visible only through the app's kdrop (libpcap's TPACKET ring counts drops in tp_drops, not sk_drops which `ss` shows); the raw build's plain socket shows them in `ss` too (packet_socket_drops).
