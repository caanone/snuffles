# Load-test summary — run `baseline`

48 scenario(s). pps in k/M (3 sig. figs); percentages 2 dp.

| scenario | mode | kind | sent | bridge in | seen% | captured | offered pps | cap pps | kdrop% | kdrop% win | rss MB | cap% | main% | sys/pkt | ipc | win s | status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| A1-pktgen64-1cpu | quiet | pktgen | 13M | 13M | 100.00 | 13M | 430k | 430k | 0.09 | 0.00 | 630.5 | 71.40 | 0.00 |  |  | 29.1 | ok |
| A10-pktgen64-8cpu-rps | quiet | pktgen | 57.4M | 57.4M | 23.24 | 10.9M | 420k | 353k | 18.12 | 15.90 | 630.4 | 98.62 | 0.00 |  |  | 29.1 | ok |
| A11-pktgen64-8cpu-dstsut | quiet | pktgen | 143M | 143M | 100.00 | 18M | 4.71M | 592k | 87.41 | 87.44 | 632.3 | 99.86 | 0.00 |  |  | 29.1 | ok |
| A12-pktgen64-8cpu-p1 | quiet | pktgen | 100M | 100M | 100.00 | 18.2M | 3.3M | 598k | 81.90 | 81.90 | 632.5 | 99.96 | 0.00 |  |  | 29.1 | ok |
| A13-raw-pktgen64-1cpu | quiet | pktgen | 12.9M | 12.9M | 100.00 | 12.8M | 425k | 424k | 0.48 | 0.28 | 628.0 | 98.76 | 0.00 |  |  | 29.1 | ok |
| A14-pktgen64-8cpu-bpf-hit | quiet | pktgen | 82.2M | 82.2M | 100.00 | 18.2M | 2.71M | 598k | 77.86 | 77.92 | 632.4 | 99.96 | 0.00 |  |  | 29.1 | ok |
| A15-pktgen64-8cpu-bpf-miss | quiet | pktgen | 86.2M | 86.2M | 0.00 | 0 | 0 | 0 | 0.00 | 0.00 | 8.5 | 0.00 | 0.00 |  |  | 29.1 | ok |
| A2-pktgen64-8cpu-max | quiet | pktgen | 85.2M | 85.2M | 100.00 | 18.1M | 2.8M | 595k | 78.76 | 78.78 | 632.5 | 99.95 | 0.00 | 1.01 | 1.76 | 29.1 | ok |
| A3a-pktgen64-8cpu-ratep-100k | quiet | pktgen | 2.03M | 2.03M | 100.00 | 2.03M | 100k | 100k | 0.00 | 0.00 | 630.5 | 17.73 | 0.00 |  |  | 19.1 | ok |
| A3b-pktgen64-8cpu-ratep-250k | quiet | pktgen | 5.08M | 5.08M | 100.00 | 5.08M | 250k | 250k | 0.00 | 0.00 | 632.3 | 46.06 | 0.00 |  |  | 19.1 | ok |
| A3c-pktgen64-8cpu-ratep-500k | quiet | pktgen | 10.2M | 10.2M | 100.00 | 9.97M | 500k | 492k | 1.96 | 1.68 | 632.3 | 85.23 | 0.00 |  |  | 19.1 | ok |
| A3d-pktgen64-8cpu-ratep-1m | quiet | pktgen | 20.3M | 20.3M | 100.00 | 12.2M | 1M | 606k | 39.67 | 39.40 | 632.2 | 99.93 | 0.00 |  |  | 19.1 | ok |
| A3e-pktgen64-8cpu-ratep-2m | quiet | pktgen | 40.6M | 40.6M | 100.00 | 12.5M | 2M | 616k | 69.21 | 69.18 | 630.4 | 99.93 | 0.00 |  |  | 19.1 | ok |
| A4-pktgen1514-8cpu-max | quiet | pktgen | 85.5M | 85.5M | 100.00 | 16.3M | 2.81M | 536k | 80.91 | 80.98 | 630.4 | 99.95 | 0.00 | 1.02 | 1.65 | 29.1 | ok |
| A5-pktgen9014-8cpu-max | quiet | pktgen | 55.3M | 55.3M | 100.00 | 13.4M | 1.82M | 443k | 75.74 | 75.70 | 631.1 | 99.94 | 0.00 |  |  | 29.1 | ok |
| A6-pktgen64-8cpu-flows1m | quiet | pktgen | 83.6M | 83.6M | 100.00 | 7.93M | 2.75M | 260k | 90.52 | 90.57 | 656.8 | 99.96 | 0.00 | 1.01 | 0.93 | 29.1 | ok |
| A7-pktgen64-8cpu-snap128 | quiet | pktgen | 85M | 85M | 100.00 | 18.9M | 2.8M | 620k | 77.82 | 77.88 | 9.6 | 99.95 | 0.00 |  |  | 29.1 | ok |
| A8-pktgen64-8cpu-ring1m-snap256 | quiet | pktgen | 85.1M | 85.1M | 100.00 | 16.7M | 2.81M | 549k | 80.36 | 80.43 | 614.9 | 99.96 | 0.00 |  |  | 29.1 | ok |
| A9-raw-pktgen64-8cpu-max | quiet | pktgen | 86.1M | 86.1M | 100.00 | 12.4M | 2.83M | 410k | 85.61 | 85.54 | 629.9 | 99.91 | 0.00 | 2 | 1.33 | 29.1 | ok |
| B1-headless-1m | headless | pktgen | 30.3M | 30.3M | 100.00 | 12.1M | 1M | 398k | 60.10 | 60.17 | 630.3 | 99.78 | 88.96 |  |  | 29.1 | ok |
| B1x-headless-max | headless | pktgen | 85.4M | 85.4M | 100.00 | 13.2M | 2.81M | 435k | 84.50 | 84.55 | 630.4 | 99.38 | 87.56 |  |  | 29.1 | ok |
| B2-jsonl-1m | jsonl | pktgen | 30.4M | 30.4M | 100.00 | 16.1M | 1e+03k | 533k | 46.84 | 46.65 | 630.5 | 99.78 | 99.07 |  |  | 29.1 | ok |
| B2x-jsonl-max | jsonl | pktgen | 85.2M | 85.2M | 100.00 | 15.6M | 2.81M | 514k | 81.63 | 81.70 | 632.3 | 99.93 | 99.39 |  |  | 29.1 | ok |
| B3-syslog-1m | syslog | pktgen | 29.4M | 29.4M | 100.00 | 4.55M | 1M | 154k | 84.52 | 84.61 | 4.7 | 99.85 | 0.00 | 2.02 | 0.977 | 28.1 | ok |
| B3x-syslog-max | syslog | pktgen | 86.5M | 86.5M | 100.00 | 4.67M | 2.85M | 153k | 94.61 | 94.64 | 4.8 | 99.86 | 0.00 |  |  | 29.1 | ok |
| B4-streamnull-1m | stream-null | pktgen | 30.4M | 30.4M | 100.00 | 17.3M | 1e+03k | 571k | 42.93 | 42.91 | 630.3 | 99.93 | 0.00 |  |  | 29.1 | ok |
| B5-streamdisk-1m-1514 | stream-disk | pktgen | 20.3M | 20.3M | 100.00 | 6.17M | 1e+03k | 303k | 69.65 | 69.65 | 632.5 | 99.82 | 0.00 |  |  | 19.1 | ok |
| B6-tui-1m | tui | pktgen | 29.4M | 29.4M | 100.00 | 11.9M | 1M | 402k | 59.59 | 59.84 | 630.5 | 99.85 | 97.78 | 1.05 | 1.59 | 28.1 | ok |
| B6x-tui-max | tui | pktgen | 82.7M | 82.7M | 100.00 | 11.7M | 2.82M | 400k | 85.80 | 85.82 | 632.3 | 99.77 | 95.25 |  |  | 28.1 | ok |
| B7-tuisessions-flows1m | tui-sessions | pktgen | 30.4M | 30.4M | 100.00 | 3.1M | 1e+03k | 100k | 89.78 | 90.00 | 678.9 | 57.53 | 95.60 |  |  | 29.1 | ok |
| B8-headlesspipe-1m | headless-pipe | pktgen | 29.3M | 29.3M | 100.00 | 13.7M | 1M | 470k | 53.16 | 53.04 | 630.5 | 99.74 | 97.33 |  |  | 28.1 | ok |
| B9-raw-syslog-1m | syslog | pktgen | 29.4M | 29.4M | 100.00 | 4.35M | 1M | 148k | 85.19 | 85.17 | 2.2 | 99.85 | 0.00 |  |  | 28.1 | ok |
| C1-http-keepalive | quiet | http |  | 6.19M | 100.00 | 6.19M | 206k | 206k | 0.05 | 0.00 | 646.6 | 47.87 | 0.00 | 1.02 | 1.6 | 30.2 | ok |
| C1h-http-keepalive-headless | headless | http |  | 6.17M | 100.00 | 6.16M | 205k | 205k | 0.03 | 0.00 | 648.6 | 56.17 | 48.84 |  |  | 30.1 | ok |
| C2-http-offloads-off | quiet | http |  | 5.94M | 100.00 | 5.94M | 198k | 198k | 0.03 | 0.00 | 646.7 | 43.53 | 0.00 |  |  | 30.1 | ok |
| C3-http-close | quiet | http |  | 6.24M | 100.00 | 6.23M | 208k | 208k | 0.05 | 0.00 | 648.6 | 45.86 | 0.00 |  |  | 30.1 | ok |
| C3t-http-close-tui-sessions | tui-sessions | http |  | 6.19M | 100.00 | 6.18M | 206k | 206k | 0.10 | 0.00 | 648.8 | 60.91 | 66.87 |  |  | 30.1 | ok |
| C4-iperf-tcp | quiet | iperf |  | 3.55M | 100.00 | 3.11M | 117k | 104k | 12.28 | 11.50 | 633.9 | 98.24 | 0.00 | 1.02 | 0.534 | 29.2 | ok |
| C4o-iperf-tcp-offloads-off | quiet | iperf |  | 25.1M | 100.00 | 14.6M | 819k | 487k | 41.71 | 40.54 | 631.1 | 98.28 | 0.00 |  |  | 30.1 | ok |
| C5-replay-quiet | quiet | replay | 23.5M | 29.4M | 100.00 | 14.7M | 985k | 495k | 49.83 | 49.73 | 636.8 | 98.28 | 0.00 |  |  | 30.1 | ok |
| C5j-replay-jsonl | jsonl | replay | 23.1M | 28.9M | 100.00 | 12.7M | 969k | 424k | 56.19 | 56.19 | 637.1 | 99.91 | 98.98 |  |  | 30.1 | ok |
| C5t-replay-tui | tui | replay | 23.1M | 28.9M | 100.00 | 10.8M | 969k | 363k | 62.48 | 62.48 | 636.9 | 98.21 | 97.08 |  |  | 30.1 | ok |
| C6-synflood-quiet | quiet | synflood | 2.56M | 6M | 99.26 | 5.89M | 197k | 194k | 1.11 | 1.20 | 656.7 | 74.10 | 0.00 | 0.998 | 1.07 | 29.2 | ok |
| C6t-synflood-tui-sessions | tui-sessions | synflood | 2.51M | 5.95M | 100.00 | 4.32M | 195k | 139k | 27.35 | 28.43 | 679.4 | 64.92 | 96.67 |  |  | 30.1 | ok |
| C7-udpflood-quiet | quiet | udpflood | 59.3M | 59.3M | 100.00 | 17.6M | 1.98M | 587k | 70.25 | 70.30 | 630.4 | 99.94 | 0.00 |  |  | 29.1 | ok |
| C7r-udpflood-randsrc | quiet | udpflood | 59.4M | 59.4M | 100.00 | 17.1M | 1.98M | 572k | 71.22 | 71.18 | 632.3 | 99.82 | 0.00 |  |  | 29.1 | ok |
| C8-frag-quiet | quiet | frag | 62.8M | 62.8M | 100.00 | 15.7M | 2.09M | 523k | 74.94 | 75.01 | 632.6 | 99.70 | 0.00 |  |  | 29.1 | ok |
| D1-soak-headless-5min | headless | pktgen | 845M | 845M | 100.00 | 131M | 2.82M | 436k | 84.50 | 84.51 | 630.4 | 99.56 | 87.75 |  |  | 298.9 | ok |

Columns: **sent** = generator's own count in wire frames (udpflood/frag datagrams x fragments; blank for http/iperf whose drivers count requests/bytes). **bridge in** = frames that entered the SUT bridge on p1..p5 during the whole run (app-independent; includes sink replies). **seen%** = (captured+kdrop)/bridge in: 100 means every frame reached the packet socket, so kdrop is the ONLY loss point. **offered pps** / **cap pps** / **kdrop% win** are steady-state values over the trimmed traffic window (**win s**); **kdrop%** is whole-run. **sys/pkt** = write+sendto+getsockopt+recvfrom+select+poll syscalls per captured packet during the perf-stat window. CPU% are per-thread, % of one CPU. Note for the pcap build the packet-socket ring drops are visible only through the app's kdrop (libpcap's TPACKET ring counts drops in tp_drops, not sk_drops which `ss` shows); the raw build's plain socket shows them in `ss` too (packet_socket_drops).
