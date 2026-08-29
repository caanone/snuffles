# Load-test summary — run `exp-syslog-nonblock`

2 scenario(s). pps in k/M (3 sig. figs); percentages 2 dp.

| scenario | mode | kind | sent | bridge in | seen% | captured | offered pps | cap pps | kdrop% | kdrop% win | rss MB | cap% | main% | sys/pkt | ipc | win s | status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| B3-syslog-1m | syslog | pktgen | 30.4M | 30.4M | 100.00 | 5.72M | 1e+03k | 188k | 81.20 | 81.23 | 4.7 | 99.83 | 0.00 | 1.01 | 1.16 | 29.1 | ok |
| B9-raw-syslog-1m | syslog | pktgen | 30.4M | 30.4M | 100.00 | 5M | 1M | 164k | 83.55 | 83.59 | 2.2 | 99.93 | 0.00 |  |  | 29.1 | ok |

Columns: **sent** = generator's own count in wire frames (udpflood/frag datagrams x fragments; blank for http/iperf whose drivers count requests/bytes). **bridge in** = frames that entered the SUT bridge on p1..p5 during the whole run (app-independent; includes sink replies). **seen%** = (captured+kdrop)/bridge in: 100 means every frame reached the packet socket, so kdrop is the ONLY loss point. **offered pps** / **cap pps** / **kdrop% win** are steady-state values over the trimmed traffic window (**win s**); **kdrop%** is whole-run. **sys/pkt** = write+sendto+getsockopt+recvfrom+select+poll syscalls per captured packet during the perf-stat window. CPU% are per-thread, % of one CPU. Note for the pcap build the packet-socket ring drops are visible only through the app's kdrop (libpcap's TPACKET ring counts drops in tp_drops, not sk_drops which `ss` shows); the raw build's plain socket shows them in `ss` too (packet_socket_drops).
