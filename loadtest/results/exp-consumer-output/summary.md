# Load-test summary — run `exp-consumer-output`

3 scenario(s). pps in k/M (3 sig. figs); percentages 2 dp.

| scenario | mode | kind | sent | bridge in | seen% | captured | offered pps | cap pps | kdrop% | kdrop% win | rss MB | cap% | main% | sys/pkt | ipc | win s | status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| B1-headless-1m | headless | pktgen | 30.4M | 30.4M | 100.00 | 12.6M | 1e+03k | 417k | 58.54 | 58.31 | 630.7 | 99.63 | 85.74 |  |  | 29.1 | ok |
| B2-jsonl-1m | jsonl | pktgen | 30.3M | 30.3M | 100.00 | 12.4M | 1e+03k | 409k | 59.21 | 59.11 | 630.9 | 99.51 | 86.55 |  |  | 29.1 | ok |
| B8-headlesspipe-1m | headless-pipe | pktgen | 30.3M | 30.3M | 100.00 | 11.2M | 1e+03k | 370k | 62.97 | 62.96 | 632.6 | 99.46 | 86.92 |  |  | 29.1 | ok |

Columns: **sent** = generator's own count in wire frames (udpflood/frag datagrams x fragments; blank for http/iperf whose drivers count requests/bytes). **bridge in** = frames that entered the SUT bridge on p1..p5 during the whole run (app-independent; includes sink replies). **seen%** = (captured+kdrop)/bridge in: 100 means every frame reached the packet socket, so kdrop is the ONLY loss point. **offered pps** / **cap pps** / **kdrop% win** are steady-state values over the trimmed traffic window (**win s**); **kdrop%** is whole-run. **sys/pkt** = write+sendto+getsockopt+recvfrom+select+poll syscalls per captured packet during the perf-stat window. CPU% are per-thread, % of one CPU. Note for the pcap build the packet-socket ring drops are visible only through the app's kdrop (libpcap's TPACKET ring counts drops in tp_drops, not sk_drops which `ss` shows); the raw build's plain socket shows them in `ss` too (packet_socket_drops).
