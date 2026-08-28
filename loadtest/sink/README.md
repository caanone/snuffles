# loadtest/sink — the `snuffles-sink` image (traffic target + syslog counter)

Role `snf-sink` in the rig (see `loadtest/SPEC.md`): nginx (HTTP target for
wrk / synflood), an iperf3 server, and `udpsink`, the UDP datagram counter
that receives snuffles' `--syslog 10.78.0.5:514` output.

## Files

| file                 | in the image                          | purpose |
|----------------------|---------------------------------------|---------|
| `udpsink.c`          | `/opt/sink/udpsink` (built at image build) | recvmmsg datagram counter |
| `nginx.conf`         | `/etc/nginx/nginx.conf`               | `/`, `/big`, `/status` |
| `start-services.sh`  | `/opt/sink/start-services.sh`         | start nginx + `iperf3 -s -D`, idempotent |
| `../docker/sink.Dockerfile` | —                              | image definition |

Image packages: nginx 1.26, iperf3, iproute2, procps, python3, gcc (+libc6-dev),
nftables, jq, curl. Document root `/var/www/sink`: `index.html` (121 B) and
`big` (104857600 B = 100 MiB of `/dev/urandom`, generated at build time).

## Build

The Dockerfile uses repo-relative `COPY` paths, so build from the repo root:

```sh
docker build -f loadtest/docker/sink.Dockerfile -t snuffles-sink .
```

The container runs `sleep infinity`; everything is driven via `docker exec`.

## Services: `start-services.sh`

```sh
docker exec snf-sink /opt/sink/start-services.sh
```

- starts `nginx -c /etc/nginx/nginx.conf` (daemon, master + 2 workers) unless
  nginx is already listening on :80
- starts `iperf3 -s -D --logfile /var/log/iperf3.log` (port 5201) unless an
  `iperf3 -s` is already listening
- waits until both ports listen (5 s limit, non-zero exit otherwise), then
  prints `ss -ltnup`. Safe to call repeatedly.

nginx: `worker_processes 2`, `worker_connections 65535`,
`listen 80 default_server backlog=65535 reuseport` (two listen sockets, one
per worker), `access_log off`, `keepalive_requests 1000000` so nginx never
closes a keep-alive connection on its own, `open_file_cache` so `/big` stays
open. Endpoints:

| path      | response |
|-----------|----------|
| `/`       | 200, `text/html`, 121 bytes |
| `/big`    | 200, `application/octet-stream`, `Content-Length: 104857600` (sendfile) |
| `/status` | `stub_status` text |
| other     | 404 |

## `udpsink`

```
udpsink -p PORT -o out.json [-b RCVBUF_BYTES]
```

- binds `0.0.0.0:PORT` (UDP/IPv4), `SO_RCVBUFFORCE` = `-b` (default
  67108864 = 64 MiB; the kernel reports 2x that via `SO_RCVBUF`). Falls back
  to `SO_RCVBUF` (capped by `net.core.rmem_max`) if the force variant fails.
- `recvmmsg()` in batches of 512 (`MSG_DONTWAIT|MSG_TRUNC`, `poll()` when
  idle). `bytes` is the sum of the real datagram lengths.
- every second on stderr (cumulative):
  `t=<seconds since start> received=<datagrams> bytes=<bytes>`
- on SIGINT or SIGTERM writes `out.json` atomically (tmp + rename; parent
  directories are created if missing), prints a final summary line and exits 0:

  ```json
  {"received": 8206016, "bytes": 1641203200, "seconds": 8.002,
   "rcvbuf_errors_delta": 0, "in_errors_delta": 0}
  ```

  `seconds` is wall time from bind to signal; the `*_delta` fields are the
  changes of `Udp: RcvbufErrors` / `Udp: InErrors` in `/proc/net/snmp` (the
  container's netns) between start and stop — i.e. datagrams the kernel
  dropped because the socket buffer was full. `received + rcvbuf_errors_delta`
  equals the number of datagrams that reached the socket.
- exit codes: 0 result written, 1 bind/socket/write failure (e.g. port
  already in use — kill the stray instance first), 2 bad arguments.

Typical use (run-scenario, syslog mode):

```sh
docker exec -d snf-sink sh -c 'exec taskset -c 8 /opt/sink/udpsink -p 514 -o /results/RUN/NAME/sink.json 2>/results/RUN/NAME/udpsink.stderr'
...
docker exec snf-sink pkill -INT -x udpsink      # then wait for sink.json
```

`taskset` (util-linux) is in the image; pinning to CPU 8 keeps udpsink off
CPU 0, which the rest of the host also uses.

### Measured (this host, loopback inside a privileged `--network none` container)

sendmmsg blaster (64-datagram batches, 200 B payload) on CPUs 4,5,6,7,12,13;
udpsink pinned to CPU 8:

| senders | offered      | udpsink received | RcvbufErrors | note |
|---------|--------------|------------------|--------------|------|
| 1       | 0.41 Mpps    | 0.41 Mpps        | 0            | sender-bound |
| 2       | 0.93 Mpps    | 0.93 Mpps        | 0            | sender-bound |
| 3       | 1.37 Mpps    | 1.39 Mpps peak   | 0            | sender-bound |
| 6       | 2.21 Mpps    | 1.69 Mpps peak   | 4,289,401    | udpsink at 100 % of one core; received + drops == sent |

So one core counts ~1.7 M datagrams/s; anything above that shows up in
`rcvbuf_errors_delta` rather than being silently lost.
