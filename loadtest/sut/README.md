# loadtest/sut — system-under-test image and in-container harness

Everything here runs **inside** the `snf-sut` container (image `snuffles-sut`,
`loadtest/docker/sut.Dockerfile`). The image installs nothing from the repo:
`/opt/snuffles/{build.sh,telemetry.sh,run-snuffles.sh,perf.sh,tui.py}` are thin
wrappers that `exec` the live copies under `/repo/loadtest/sut/`, so editing a
script here never needs an image rebuild (only the package list does).

```
docker build -f loadtest/docker/sut.Dockerfile -t snuffles-sut .   # any context works
```

Packages: build-essential pkg-config libpcap-dev linux-perf (6.12.x, matches
the host kernel) iproute2 procps python3 ethtool nftables strace jq rsync
iputils-ping.

## build.sh

```
/opt/snuffles/build.sh
```
rsyncs `/repo` → `/src` (excluding `build/`, `.git`, `loadtest/results`,
`build-win`, `.claude`), does a **clean** build of `/opt/snuffles/pcap/snuffles`
(`make`) and `/opt/snuffles/raw/snuffles` (`make nopcap`) with
`CFLAGS="-g -fno-omit-frame-pointer"`, prints both `snuffles -v`, and writes
`/opt/snuffles/build-info.txt`. Takes ~1.5 s; re-run whenever `/repo` changed.

## run-snuffles.sh

```
run-snuffles.sh <mode> <build> <iface> <resultsdir> [extra snuffles args...]
run-snuffles.sh stop <resultsdir>
```

| mode          | argv added after `-i <iface> --stats=<resultsdir>/snuffles.stats` | stdout |
|---------------|---------------------------------------------------|-------------------------------|
| quiet         | `-q`                                              | /dev/null |
| headless      | `--no-ui`                                         | /dev/null |
| headless-pipe | `--no-ui`                                         | FIFO → `wc -l > out.count` |
| jsonl         | `--jsonl`                                         | /dev/null |
| syslog        | `-q --syslog 10.78.0.5:514` (`SNF_SYSLOG_TARGET`) | /dev/null |
| stream-null   | `-q -w /dev/null`                                 | /dev/null |
| stream-disk   | `-q -w <resultsdir>/stream.pcap`                  | /dev/null |
| tui           | (none), pty 200x50 via `tui.py`                   | pty, discarded |
| tui-sessions  | as tui; keys `S`@5 s, `V`@15 s, `S`@20 s          | pty, discarded |

`start` launches a detached supervisor (own session, no inherited stdio, so
`docker exec` returns in ~30 ms), waits for `snuffles.pid` and prints one line.
Files in `<resultsdir>`:

| file | content |
|------|---------|
| `snuffles.pid` | pid of the snuffles process (target for perf/telemetry) — the real snuffles pid also in tui modes |
| `tui.pid`, `tui.log` | tui modes: tui.py pid and its event log (spawn, every key, stop steps, exit) |
| `snuffles.stats` | the `--stats` file (`stats ...` once per second, `summary ...` at exit) |
| `snuffles.stderr` | snuffles' stderr (the TUI never writes to the pty's stderr) |
| `snuffles.cmdline`, `snuffles.mode` | exact argv (one per line) and the mode |
| `out.count` | headless-pipe: number of stdout lines (complete once `exit.status` exists) |
| `stream.pcap` | stream-disk: exists while running; `stop` records its size and **deletes** it (`SNF_KEEP_STREAM=1` keeps it) |
| `exit.status` | `<rc> <epoch_ms>` written by the supervisor when snuffles exits (rc=128+N for signal N) |
| `exit.json` | written by `stop`: `{"mode","pid","exit_code","exit_latency_ms","killed","stop_signal","stream_bytes"}` |

`stop`: non-tui → SIGINT; tui → SIGUSR1 to tui.py, which types `q`, types `q`
again after 3 s (an open overlay swallows the first), then SIGINTs snuffles
after 6 s. Waits up to 30 s (`SNF_STOP_TIMEOUT`), then SIGKILL (`killed:true`,
`exit_code:null`). `exit_latency_ms` = first signal → process gone.

**Privilege drop.** snuffles drops root right after opening the capture
(`SUDO_UID/SUDO_GID`, else `nobody`) and only then opens `--stats`, `-w` and
`-o` files. The harness sets `SUDO_UID/SUDO_GID` to the owner of the `/results`
mount (the host user; `nobody` if root) and chowns `<resultsdir>` (and
root-owned ancestors under `/results`) to that uid. Result: stats/stream/export
files are writable and end up owned by the host user. Override with
`SNF_RUN_UID`/`SNF_RUN_GID`.

## tui.py

```
tui.py [--pidfile F] [--stderr F] [--keys "5:S,15:V,20:S"] [--cols 200] [--rows 50] [--grace 3] -- cmd...
```
pty of the given size, `TERM=xterm-256color`, output drained and discarded,
scripted keys (literal chars or `enter esc space up down pgup pgdn`), stop
escalation on SIGUSR1/SIGTERM/SIGINT/SIGHUP as described above, exits with the
child's status.

## telemetry.sh

```
telemetry.sh <pid|pidfile> <outfile>
```
Appends one JSON object per second (aligned to whole seconds), exactly the
SPEC schema: `t`, `proc` {utime, stime, rss_kb, threads, nvcsw, nivcsw, minflt,
majflt}, `threads` {comm: {utime, stime, nvcsw, nivcsw}} (comms are `snuffles`,
`snf-capture`, `snf-stats`), `softnet` {processed, dropped, time_squeeze}
summed over CPUs, `ifaces` for br0 p1..p5 mgmt0 (missing ones skipped),
`pktsock` {rmem, rcvbuf, drops} from `ss -0 -e -m -p -H` (only the packet
sockets owned by `<pid>`; all packet sockets in the netns if it owns none),
`mem_current` (`/sys/fs/cgroup/memory.current`, `null` if unreadable),
`loadavg` [1,5,15]. utime/stime raw ticks (CLK_TCK=100); nvcsw/nivcsw summed
over tasks. Pure bash; the only fork per sample is `ss`. When the pid exits
(or turns zombie) it writes one last line with `"proc":null,"threads":{}` and
exits 0; SIGTERM/SIGINT also exit 0 promptly. A non-numeric first argument is
treated as a pid file and polled for up to 15 s.

## perf.sh

```
perf.sh <pid> <resultsdir>        # blocks ~19 s — background it
```
`perf stat -p PID -e <SPEC event list> -o perf-stat.txt -- sleep 10`, 1 s pause,
`perf record -F 999 -g -p PID -o perf.data -- sleep 8`,
`perf report --stdio --no-children | head -120 > perf-report.txt`. Mounts
tracefs inside the container's own mount namespace if `/sys/kernel/tracing`
is empty (needed for `syscalls:*`). A pid that exits early makes the remaining
steps skip with a note in `perf.log` and placeholder files; exit status 0.
Host settings: `perf_event_paranoid=3` and `kptr_restrict=0` are fine because
the container is `--privileged` (CAP_PERFMON/CAP_SYS_ADMIN bypass paranoid);
kernel symbols resolve via `/proc/kallsyms`.

## Things the integrator should know

* The supervisor (one `bash` per run) ends as a zombie because the container's
  PID 1 is `sleep infinity`, which never reaps. Harmless (one pid per run) but
  `docker run --init` on snf-sut makes them disappear; nothing else changes.
* `exit_latency_ms` includes up to 1 s spent joining the `--stats` thread
  (it sleeps in a 1 s `select`), so every mode shows 50–1100 ms even when idle.
* In `quiet`/`syslog`/`stream-*` modes the consumer is `-q`; syslog to an
  unreachable target does not stop snuffles (`syslog_fail` counts up).
* `-q` (quiet) prints a warning to stderr and TUI mode refuses `--stats`
  without `=FILE`; the harness always passes a file.
