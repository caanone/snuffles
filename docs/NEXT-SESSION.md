# Next session — resume point

Written 2026-09-02 at the end of the syslog fan-out session. Read this before touching
anything; it is the record, not recall.

## State

| | |
|---|---|
| `main` | tip carries the syslog auto-scaling (branch `perf/syslog-autoscale`, merged after CI), the lean-ring sizing and `--syslog-threads`, pushed |
| Release | **v1.4.0** is the latest tag — https://github.com/caanone/snuffles/releases/tag/v1.4.0. `main` carries unreleased work (see CHANGELOG `[Unreleased]`): syslog output threads that scale with the backlog, the lean ring sized to the kernel buffer, `stream_missed=`/`syslog_threads=` stats, stress-loop diagnostics and the flake fix |
| Release assets (v1.4.0) | `snuffles-1.4.0-linux-x86_64`, `snuffles-1.4.0-windows-x64.exe`, `SHA256SUMS`; **macOS arm64 still missing** |
| Working tree | clean; only `main` exists locally and remotely (stale branches deleted 2026-09-02) |
| Load-test rig | **down**. No `snf-*` containers, host sysctls restored (`rmem_max` 33554432) |
| Reports | `loadtest/REPORT.html` (v1.4.0 campaign) and https://claude.ai/code/artifact/d57768f9-db4d-46e0-9b5d-5d291c82cf49; this session's raw runs are in `loadtest/results/st1 st2 st4 st1h st4h` (untracked) |

## Preflight (run first, ~30 s)

```bash
git pull && git log --oneline -1
make -j8 && make nopcap -j8 && make test                      # 11 suites, all pass
docker ps --format '{{.Names}}' | grep '^snf-' ; echo "(no output = rig down)"
cat /proc/sys/net/core/rmem_max                               # 33554432 = host untuned
```

Note: the root `./snuffles` is whichever of `make` / `make nopcap` ran last. Offline replay
(`-r`) needs the libpcap build, `build/pcap/snuffles`.

## Done this session (2026-09-02)

**CI stress flake — resolved.** The macOS arm64 job for cbca8bf (docs-only) failed 1 of 30 stress
rounds with no output (the loop discarded it). `make test-stress` now prints each failing round's
full output and CI's round count is a `workflow_dispatch` input (`runs`). The next failure (2 of 30,
run 33602918592) named it: `test_ringbuf.c` `test_mp_stress`, `CHECK(ok > 1000)` with `reads=0` —
the reader thread was descheduled for the whole run behind 12 producers on the 3-core runner, and
`torn=0`. Not a ring bug; a run with no reads validates nothing. The test now repeats a starved
run (up to 5 attempts) instead of passing or failing on it.

**Lane 2, syslog export throughput → `--syslog-threads N`** (1-8, config key `syslog_threads`).
N output workers, one UDP socket each, record s goes to worker s % N; `-w` gets its own worker
when N > 1; the self-check knows all N source ports (`syslog_out_link`); `RINGBUF_MAX_WAITERS`
4 → 10; `--stats` gained `stream_missed=`. Measured:

| where | config | result |
|---|---|---|
| loopback microbench (`bench_syslog.c`, scratch) | 1 sender | 4.4 µs/record: 0.4 µs user (format), 4.0 µs kernel (send + loopback receive). Integer formatting instead of snprintf is worth < 10 % — not pursued |
| loopback | 4 senders, 4 listener sockets | ~210 krec/s each, linear |
| loopback | 4 senders, ONE listener socket | ~185 krec/s each: a shared collector socket costs ~10 %, not a bottleneck |
| rig B3 (1 Mpps offered, 30 s) | 1 thread | 198 kpps sent, thread at 92 % of a core, 80 % out_missed |
| rig B3 | 2 threads | 360 kpps |
| rig B3 | 4 threads | 397 kpps at ~40 % of a core **each** — CPU-starved, see hazards |
| rig B3h (500 kpps offered) | 1 thread | 244 kpps = 49 % delivered, 99 % of a core |
| rig B3h | 4 threads | 476 kpps = 93 % delivered, ~50 % of a core each |

**Full coverage.** The 7 % loss above was buffering, not capacity: the lean `-q --syslog` ring
was 4096 slots (8 ms at 500 kpps) while the capture thread hands over every retired kernel block
in one go. The ring now mirrors the kernel buffer (8192 slots per MB of `-B`, 4096-65536; 65536
slots, ~38 MB, at the default 8 MB) and the arena stays 1 MB; `-w` no longer selects the lean
defaults. Re-measured, same rig, 30 s:

| offered | config | before (4096 slots) | after (65536 slots) |
|---|---|---|---|
| 500 kpps | 4 threads | 93 % delivered, ~50 % of a core each | **100 % delivered, 0 missed**, ~52 % each, 51 MB RSS |
| 1 Mpps | 4 threads | 40 % (397 kpps) | 77 % (788 kpps), threads at 80-85 %: CPU-bound on the SUT's 2 cores |
| 500 kpps | 1 thread | 49 % | 58 %, thread at 100 %: capacity-bound |

Sanity check learned the hard way: with no collector listening, ICMP port-unreachable makes the
connected socket's sends fail and the records land in `syslog_fail`, not `syslog_sent` — read all
three counters (`syslog_sent + syslog_fail + out_missed == captured`) before suspecting a leak.

**Dynamic scaling (user request: "make dynamic scaling against high traffic").** The syslog
workers now scale at runtime: up to `--syslog-threads` (auto = CPUs the process may run on, ≤ 8)
exist from the start, `--syslog-min-threads` run always (default 1), the rest park; workers claim
32-record chunks from a shared cursor (`output.c`), a running worker wakes one parked helper when
the unclaimed backlog exceeds ring/8 (one per 2 ms, `ringbuf_waiter_kick`), a helper parks again
when nothing is left to claim. `--stats` shows the high-water mark as `syslog_threads=`. Rig, no
flags, 30 s (the SUT cpuset gives auto = 4):

| offered | delivered | `syslog_threads` per second | worker CPU (0/1/2/3) |
|---|---|---|---|
| 200 kpps | 100 % | 1 in every second | 77 / 0 / 0 / 0 % |
| 500 kpps | 100 %, 0 missed | 4 in 31 of 36 s (helpers cascade in within ~6 ms, drain, park) | 88 / 56 / 32 / 19 % |
| 1 Mpps | 80 % | 4 | 84 / 77 / 81 / 85 %: CPU-bound on 2 cores |

Found on the way, by CI on Wine and macOS: a worker that had read the ring total, flushed, and
then saw the stop flag could exit with the tail committed during the flush unclaimed (14 of 20000
in the attached scaling test). The single output thread of 1.4.0 had the same race a few
nanoseconds wide. Workers now re-read the total under the flag. Reproduce Windows-only failures
locally with `./scripts/test-windows.sh` (docker + Wine, ~3 min); it caught this one.

Runs: `loadtest/results/as200 as500 as1m` (untracked; the 200 k scenario is a scratch copy of B3
with `pps` 25000 — add it to `loadtest/scenarios/` if it is wanted again).

## Open lanes, in priority order

1. **macOS arm64 release asset for v1.4.0** — unchanged; build on a Mac from the tag:
   ```bash
   git checkout v1.4.0 && make nopcap && strip build/raw/snuffles
   mv build/raw/snuffles snuffles-1.4.0-macos-arm64
   shasum -a 256 snuffles-1.4.0-macos-arm64            # append to SHA256SUMS
   gh release upload v1.4.0 snuffles-1.4.0-macos-arm64
   ```
2. **Release v1.5.0** when wanted: CHANGELOG `[Unreleased]` is written; binaries follow the
   v1.4.0 procedure (static linux-x86_64 via `make nopcap`, windows-x64 via
   `scripts/test-windows.sh`'s MinGW container, SHA256SUMS, macOS by the user).
3. **Syslog, remaining ideas.** (-) Scaling tunables are compile-time (`OUTPUT_KICK_NS` 2 ms,
   threshold ring/8, `OUTPUT_LINGER` 8 yields): at 500 kpps the helpers cascade to all four every
   second and park again, which is correct but could be smoother with a lower threshold or a
   slower cascade; measure before touching. (0) The record struct is 592 B, of which ~270 B are text
   columns the syslog path never uses; a slimmer record would cut the lean ring's 38 MB and
   the copy per read. (a) Opt-in packing of several CSV lines per datagram would
   amortise the per-datagram kernel cost (~4 µs) — a wire-format change, so behind a flag; rsyslog
   `imudp` treats one datagram as one message. (b) `UDP_SEGMENT` (UDP GSO) does not fit:
   segments must be equal-sized and records are variable-length. (c) `analyze.py` parses
   `out_missed`/`stream_missed` but `summary.md` has no column for them — the `sinks` column
   only sums the consumer's `missed` and `syslog_fail`, which is why the syslog runs above read
   as lossless in the table. Add the column before the next syslog measurement.
4. **AF_XDP backend** — unchanged: needs a physical NIC (`enp41s0`) and a second machine.
5. **Scheduled regression gate** — unchanged: `loadtest/gate.sh` works, `.github/workflows/
   loadtest.yml` is manual-only and needs a self-hosted privileged runner.
6. **Report refresh** — `loadtest/REPORT.html` predates the syslog work; the table above is the
   material for a new section.

## Running the rig (for any of the above)

```bash
./loadtest/rig.sh build && ./loadtest/rig.sh up          # tunes host sysctls, saves originals
docker exec snf-sut /opt/snuffles/build.sh               # builds the current /repo checkout
./loadtest/matrix.sh <run-id> loadtest/scenarios/A2-*.json ...
RS_SNF_EXTRA_ARGS='--syslog-threads 4' ./loadtest/matrix.sh <run-id> loadtest/scenarios/B3-*.json
./loadtest/gate.sh --run-id <id>                         # regression gate vs the baseline
python3 loadtest/analyze.py <run-id>                     # summary.md / summary.csv
./loadtest/rig.sh down                                   # MANDATORY: restores host sysctls
```

Per-thread CPU is in each run's `telemetry.jsonl` (`threads.<name>.utime/stime`, clock ticks);
the raw counters are the `summary` line in `snuffles.stats`. To measure a branch instead of the
checked-out tree: `docker exec -e SNF_REPO=/repo/.claude/worktrees/<name> snf-sut /opt/snuffles/build.sh`.

## Hazards learned (do not re-derive)

- **`rig.sh down` is not optional.** It restores `net.core.*` on a host shared with CI runners
  and KVM guests. The originals live in `loadtest/results/host-sysctl.before`.
- **The host is shared.** Absolute pps varies with load (the single syslog thread did 330 kpps in
  August and 198-244 kpps today); compare builds by drop % at a fixed offered rate, in the same
  session, and re-run anything anomalous.
- **The SUT cpuset is 2,3,10,11: four hardware threads on two cores**, shared with the RX softirq
  for the offered traffic and, on veth, with the sink's receive path (`ip_route_input_slow`,
  `__netif_receive_skb_core` show up in the sender threads' profiles). Multi-threaded sinks
  cannot be measured beyond ~2 cores' worth here; compare per-record CPU (utime+stime per pps)
  and use a lower offered rate to show scaling.
- **arm64 CI is the memory-model oracle.** Two real bugs reproduced only in the sanitized arm64
  stress loop. Never weaken the ring's atomics without an arm64 stress run at high `runs`.
- **Timing assertions need platform guards.** Sanitized arm64 is ~20× slower and the shared
  macOS runner stalls for tens of ms; see the guards in `tests/test_ui.c` and
  `tests/test_session.c` (which uses `clock()`, CPU time, so stalls do not count against it).
- **The lean ring is now ~38 MB (65536 slots) by default**; `-B 1` gives 8192 slots. README's
  memory table and the man page describe the rule (8192 slots per MB of `-B`).
- **Python UDP listeners drop most of a burst** unless `SO_RCVBUF` is raised (16 MB worked for a
  5000-datagram replay); a low receive count is the listener, not the sender — check
  `syslog_sent`/`syslog_fail` first.
- **`jq '.x // true'` swallows `false`.** It silently made the HTTP `Connection: close` scenarios
  run with keep-alive for a whole matrix.
- **pktgen on veth cannot use `clone_skb`**, and the whole receive path is charged to the sending
  CPU, so the rig tops out near 2.8 Mpps offered. That is the rig's ceiling, not the app's.
- **The Windows test container writes root-owned files** into mounted worktrees; `chown` them back
  through the container, not with `sudo` on the host.
- **`test_syslog_out`'s broadcast-failure case is Linux-only** (macOS sends to 255.255.255.255 on a
  connected socket without `SO_BROADCAST`; Wine maps the error differently).
