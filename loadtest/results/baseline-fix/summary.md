# Load-test summary — run `baseline-fix`

2 scenario(s). pps in k/M (3 sig. figs); percentages 2 dp.

| scenario | mode | kind | sent | bridge in | seen% | captured | offered pps | cap pps | kdrop% | kdrop% win | rss MB | cap% | main% | sys/pkt | ipc | win s | status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| C3-http-close | quiet | http |  | 15.2M | 100.00 | 12.3M | 508k | 410k | 19.09 | 19.32 | 662.5 | 99.96 | 0.00 |  |  | 30.1 | ok |
| C3t-http-close-tui-sessions | tui-sessions | http |  | 14.8M | 100.00 | 6.93M | 494k | 228k | 53.30 | 53.76 | 684.5 | 69.42 | 97.52 |  |  | 30.1 | ok |

Columns: **sent** = generator's own count in wire frames (udpflood/frag datagrams x fragments; blank for http/iperf whose drivers count requests/bytes). **bridge in** = frames that entered the SUT bridge on p1..p5 during the whole run (app-independent; includes sink replies). **seen%** = (captured+kdrop)/bridge in: 100 means every frame reached the packet socket, so kdrop is the ONLY loss point. **offered pps** / **cap pps** / **kdrop% win** are steady-state values over the trimmed traffic window (**win s**); **kdrop%** is whole-run. **sys/pkt** = write+sendto+getsockopt+recvfrom+select+poll syscalls per captured packet during the perf-stat window. CPU% are per-thread, % of one CPU. Note for the pcap build the packet-socket ring drops are visible only through the app's kdrop (libpcap's TPACKET ring counts drops in tp_drops, not sk_drops which `ss` shows); the raw build's plain socket shows them in `ss` too (packet_socket_drops).
