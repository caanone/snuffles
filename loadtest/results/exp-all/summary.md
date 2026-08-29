# Load-test summary — run `exp-all`

19 scenario(s). pps in k/M (3 sig. figs); percentages 2 dp.

| scenario | mode | kind | sent | bridge in | seen% | captured | offered pps | cap pps | kdrop% | kdrop% win | rss MB | cap% | main% | sys/pkt | ipc | win s | status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| A1-pktgen64-1cpu | quiet | pktgen | 12.9M | 12.9M | 100.00 | 12.9M | 427k | 427k | 0.00 | 0.00 | 694.2 | 35.21 | 0.04 |  |  | 29.1 | ok |
| A13-raw-pktgen64-1cpu | quiet | pktgen | 12.7M | 12.7M | 100.00 | 12.7M | 421k | 421k | 0.00 | 0.00 | 633.7 | 97.18 | 0.00 |  |  | 29.1 | ok |
| A2-pktgen64-8cpu-max | quiet | pktgen | 82.7M | 82.7M | 100.00 | 35.5M | 2.72M | 1.16M | 57.04 | 57.37 | 694.5 | 99.83 | 0.04 | 0 | 3.07 | 29.1 | ok |
| A3d-pktgen64-8cpu-ratep-1m | quiet | pktgen | 20.4M | 20.4M | 100.00 | 20.4M | 1M | 1M | 0.00 | 0.00 | 692.3 | 88.05 | 0.06 |  |  | 19.1 | ok |
| A9-raw-pktgen64-8cpu-max | quiet | pktgen | 85.8M | 85.8M | 100.00 | 17.8M | 2.82M | 581k | 79.21 | 79.37 | 633.8 | 99.86 | 0.00 | 0.00024 | 1.89 | 29.1 | ok |
| B1-headless-1m | headless | pktgen | 29.4M | 29.4M | 100.00 | 26.7M | 991k | 894k | 9.11 | 9.78 | 693.2 | 99.74 | 98.48 |  |  | 28.1 | ok |
| B1x-headless-max | headless | pktgen | 83.8M | 83.8M | 100.00 | 27.4M | 2.76M | 887k | 67.35 | 67.82 | 694.8 | 99.78 | 98.85 |  |  | 29.1 | ok |
| B2-jsonl-1m | jsonl | pktgen | 30.4M | 30.4M | 100.00 | 28.3M | 987k | 916k | 6.94 | 7.22 | 695.2 | 99.48 | 98.94 |  |  | 29.1 | ok |
| B3-syslog-1m | syslog | pktgen | 30.4M | 30.4M | 100.00 | 6.86M | 998k | 210k | 77.46 | 79.00 | 66.8 | 99.77 | 0.04 | 2e-05 | 1.21 | 29.1 | ok |
| B3x-syslog-max | syslog | pktgen | 86.1M | 86.1M | 100.00 | 7.07M | 2.83M | 220k | 91.78 | 92.24 | 66.7 | 99.82 | 0.00 |  |  | 29.1 | ok |
| B6-tui-1m | tui | pktgen | 29.4M | 29.4M | 100.00 | 27.4M | 989k | 921k | 7.01 | 6.86 | 692.5 | 99.77 | 97.55 | 0.0152 | 2.19 | 28.2 | ok |
| B7-tuisessions-flows1m | tui-sessions | pktgen | 29.4M | 29.4M | 99.34 | 4.29M | 998k | 136k | 85.29 | 86.34 | 740.8 | 58.00 | 92.12 |  |  | 28.1 | ok |
| B8-headlesspipe-1m | headless-pipe | pktgen | 29.4M | 29.4M | 100.00 | 22.3M | 990k | 737k | 24.24 | 25.59 | 692.8 | 99.89 | 99.11 |  |  | 28.1 | ok |
| B9-raw-syslog-1m | syslog | pktgen | 30.4M | 30.4M | 100.00 | 6.04M | 1e+03k | 193k | 80.16 | 80.68 | 2.2 | 99.84 | 0.00 |  |  | 29.1 | ok |
| C1-http-keepalive | quiet | http |  | 6.09M | 100.00 | 6.09M | 203k | 203k | 0.00 | 0.00 | 708.9 | 26.34 | 0.00 | 0.00135 | 2.75 | 30.2 | ok |
| C4-iperf-tcp | quiet | iperf |  | 2.2M | 100.00 | 2.1M | 72.3k | 70.1k | 4.35 | 2.93 | 695.9 | 97.21 | 0.03 | 0.0055 | 0.324 | 29.3 | ok |
| C5-replay-quiet | quiet | replay | 22.9M | 28.7M | 100.00 | 27.4M | 959k | 917k | 4.29 | 4.42 | 701.0 | 99.82 | 0.03 |  |  | 30.1 | ok |
| C6-synflood-quiet | quiet | synflood | 2.51M | 5.93M | 99.85 | 5.92M | 195k | 195k | 0.00 | 0.00 | 718.9 | 56.48 | 0.00 | 0.00052 | 1.17 | 29.1 | ok |
| C8-frag-quiet | quiet | frag | 61.4M | 61.4M | 100.00 | 29.9M | 2.04M | 1M | 51.27 | 51.08 | 692.6 | 99.82 | 0.04 |  |  | 29.1 | ok |

Columns: **sent** = generator's own count in wire frames (udpflood/frag datagrams x fragments; blank for http/iperf whose drivers count requests/bytes). **bridge in** = frames that entered the SUT bridge on p1..p5 during the whole run (app-independent; includes sink replies). **seen%** = (captured+kdrop)/bridge in: 100 means every frame reached the packet socket, so kdrop is the ONLY loss point. **offered pps** / **cap pps** / **kdrop% win** are steady-state values over the trimmed traffic window (**win s**); **kdrop%** is whole-run. **sys/pkt** = write+sendto+getsockopt+recvfrom+select+poll syscalls per captured packet during the perf-stat window. CPU% are per-thread, % of one CPU. Note for the pcap build the packet-socket ring drops are visible only through the app's kdrop (libpcap's TPACKET ring counts drops in tp_drops, not sk_drops which `ss` shows); the raw build's plain socket shows them in `ss` too (packet_socket_drops).
