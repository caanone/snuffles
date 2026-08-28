# Load-test summary — run `integ`

12 scenario(s). pps in k/M (3 sig. figs); percentages 2 dp.

| scenario | mode | kind | sent | bridge in | seen% | captured | offered pps | cap pps | kdrop% | kdrop% win | rss MB | cap% | main% | sys/pkt | ipc | win s | status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| A1-pktgen64-1cpu | quiet | pktgen | 3.06M | 3.06M | 100.00 | 3.06M | 216k | 216k | 0.00 | 0.00 | 632.3 | 40.91 | 0.00 |  |  | 13.5 | ok |
| A2-pktgen64-8cpu-max | quiet | pktgen | 26.2M | 26.2M | 100.00 | 8.07M | 1.17M | 352k | 69.24 | 69.92 | 632.3 | 93.39 | 0.00 | 1.01 | 1.12 | 22.6 | ok |
| A9-raw-pktgen64-8cpu-max | quiet | pktgen | 25.3M | 25.3M | 100.00 | 7.81M | 1.17M | 356k | 69.12 | 69.54 | 627.8 | 98.69 | 0.00 | 1.82 | 1.13 | 21.6 | ok |
| B3-syslog-1m | syslog | pktgen | 18.2M | 18.2M | 100.00 | 3.34M | 842k | 151k | 81.60 | 82.06 | 4.9 | 99.86 | 0.00 | 1.95 | 0.953 | 21.5 | ok |
| B6-tui-1m | tui | pktgen | 18.2M | 18.2M | 100.00 | 8.5M | 842k | 390k | 53.27 | 53.61 | 632.3 | 95.89 | 93.46 | 0.993 | 1.54 | 21.6 | ok |
| B7-tuisessions-flows1m | tui-sessions | pktgen | 18.1M | 18.1M | 100.00 | 2.48M | 842k | 109k | 86.35 | 87.00 | 680.8 | 62.63 | 95.06 |  |  | 21.5 | ok |
| B8-headlesspipe-1m | headless-pipe | pktgen | 18.1M | 18.1M | 100.00 | 8.99M | 841k | 415k | 50.28 | 50.63 | 632.5 | 95.70 | 92.71 |  |  | 21.5 | ok |
| C1-http-keepalive | quiet | http |  | 2.5M | 100.00 | 2.49M | 207k | 207k | 0.14 | 0.00 | 648.4 | 47.92 | 0.00 | 1.01 | 1.69 | 12.1 | ok |
| C4-iperf-tcp | quiet | iperf |  | 1.39M | 100.00 | 1.22M | 115k | 103k | 12.13 | 10.73 | 633.8 | 98.24 | 0.00 | 0.985 | 0.505 | 11.1 | ok |
| C5-replay-quiet | quiet | replay | 10.8M | 11M | 100.00 | 5.98M | 928k | 512k | 45.57 | 44.75 | 637.1 | 99.97 | 0.00 |  |  | 12.1 | ok |
| C6-synflood-quiet | quiet | synflood | 28.3M | 28.3M | 100.00 | 2.85M | 2.36M | 238k | 89.96 | 89.91 | 656.8 | 99.90 | 0.00 | 0.982 | 0.986 | 12.1 | ok |
| C8-frag-quiet | quiet | frag | 10.5M | 31.6M | 100.00 | 6.32M | 2.64M | 525k | 79.97 | 80.11 | 632.4 | 99.87 | 0.00 |  |  | 11.1 | ok |

Columns: **sent** = generator's own count in wire frames (udpflood/frag datagrams x fragments; blank for http/iperf whose drivers count requests/bytes). **bridge in** = frames that entered the SUT bridge on p1..p5 during the whole run (app-independent; includes sink replies). **seen%** = (captured+kdrop)/bridge in: 100 means every frame reached the packet socket, so kdrop is the ONLY loss point. **offered pps** / **cap pps** / **kdrop% win** are steady-state values over the trimmed traffic window (**win s**); **kdrop%** is whole-run. **sys/pkt** = write+sendto+getsockopt+recvfrom+select+poll syscalls per captured packet during the perf-stat window. CPU% are per-thread, % of one CPU. Note for the pcap build the packet-socket ring drops are visible only through the app's kdrop (libpcap's TPACKET ring counts drops in tp_drops, not sk_drops which `ss` shows); the raw build's plain socket shows them in `ss` too (packet_socket_drops).
