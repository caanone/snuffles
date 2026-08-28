# Load-test summary — run `baseline-repeat`

4 scenario(s). pps in k/M (3 sig. figs); percentages 2 dp.

| scenario | mode | kind | sent | bridge in | seen% | captured | offered pps | cap pps | kdrop% | kdrop% win | rss MB | cap% | main% | sys/pkt | ipc | win s | status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| A2-pktgen64-8cpu-max | quiet | pktgen | 85M | 85M | 100.00 | 16.5M | 2.8M | 539k | 80.58 | 80.76 | 632.3 | 99.88 | 0.00 | 0.984 | 1.52 | 29.1 | ok |
| B1-headless-1m | headless | pktgen | 30.4M | 30.4M | 100.00 | 13.5M | 1e+03k | 444k | 55.60 | 55.64 | 630.7 | 99.25 | 87.29 |  |  | 29.1 | ok |
| B3-syslog-1m | syslog | pktgen | 30.4M | 30.4M | 100.00 | 4.66M | 1M | 153k | 84.67 | 84.67 | 4.8 | 99.83 | 0.00 | 2.02 | 0.977 | 29.1 | ok |
| B6-tui-1m | tui | pktgen | 30.4M | 30.4M | 100.00 | 12.5M | 1e+03k | 410k | 58.99 | 59.01 | 632.6 | 99.85 | 97.60 | 1.06 | 1.63 | 29.1 | ok |

Columns: **sent** = generator's own count in wire frames (udpflood/frag datagrams x fragments; blank for http/iperf whose drivers count requests/bytes). **bridge in** = frames that entered the SUT bridge on p1..p5 during the whole run (app-independent; includes sink replies). **seen%** = (captured+kdrop)/bridge in: 100 means every frame reached the packet socket, so kdrop is the ONLY loss point. **offered pps** / **cap pps** / **kdrop% win** are steady-state values over the trimmed traffic window (**win s**); **kdrop%** is whole-run. **sys/pkt** = write+sendto+getsockopt+recvfrom+select+poll syscalls per captured packet during the perf-stat window. CPU% are per-thread, % of one CPU. Note for the pcap build the packet-socket ring drops are visible only through the app's kdrop (libpcap's TPACKET ring counts drops in tp_drops, not sk_drops which `ss` shows); the raw build's plain socket shows them in `ss` too (packet_socket_drops).
