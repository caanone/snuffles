# Load-test summary — run `exp-syslog-connect`

3 scenario(s). pps in k/M (3 sig. figs); percentages 2 dp.

| scenario | mode | kind | sent | bridge in | seen% | captured | offered pps | cap pps | kdrop% | kdrop% win | rss MB | cap% | main% | sys/pkt | ipc | win s | status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| B3-syslog-1m | syslog | pktgen | 30.4M | 30.4M | 100.00 | 8.17M | 997k | 255k | 73.14 | 74.44 | 66.7 | 99.80 | 0.04 | 2e-05 | 1.32 | 29.1 | ok |
| B3x-syslog-max | syslog | pktgen | 86M | 86M | 100.00 | 7.99M | 2.82M | 247k | 90.70 | 91.24 | 66.9 | 99.86 | 0.04 |  |  | 29.1 | ok |
| B9-raw-syslog-1m | syslog | pktgen | 30.4M | 30.4M | 100.00 | 6.48M | 1M | 208k | 78.69 | 79.19 | 2.2 | 99.86 | 0.00 |  |  | 29.1 | ok |

Columns: **sent** = generator's own count in wire frames (udpflood/frag datagrams x fragments; blank for http/iperf whose drivers count requests/bytes). **bridge in** = frames that entered the SUT bridge on p1..p5 during the whole run (app-independent; includes sink replies). **seen%** = (captured+kdrop)/bridge in: 100 means every frame reached the packet socket, so kdrop is the ONLY loss point. **offered pps** / **cap pps** / **kdrop% win** are steady-state values over the trimmed traffic window (**win s**); **kdrop%** is whole-run. **sys/pkt** = write+sendto+getsockopt+recvfrom+select+poll syscalls per captured packet during the perf-stat window. CPU% are per-thread, % of one CPU. Note for the pcap build the packet-socket ring drops are visible only through the app's kdrop (libpcap's TPACKET ring counts drops in tp_drops, not sk_drops which `ss` shows); the raw build's plain socket shows them in `ss` too (packet_socket_drops).
