# snuffles load-test rig

Drives snuffles at extreme packet/byte/flow rates in Docker containers on one
host, collects app + kernel + process + perf telemetry, and summarises it.
The binding contract is [`SPEC.md`](SPEC.md); this file is the operator guide.

## Run it (quickstart)

```sh
loadtest/rig.sh build                       # build snuffles-{sut,gen,sink} images
loadtest/rig.sh up                          # tune host, containers, topology, sink services, build snuffles
loadtest/rig.sh smoke                        # 10 s end-to-end sanity run (scenario S0-smoke)
loadtest/matrix.sh nightly loadtest/scenarios/A*.json loadtest/scenarios/B*.json
loadtest/matrix.sh apps    loadtest/scenarios/C*.json      # one run-id, continues past failures
loadtest/run-scenario.sh loadtest/scenarios/A2-pktgen64-8cpu-max.json myrun   # a single scenario
python3 loadtest/analyze.py nightly          # (re)build summary.csv/summary.md for a run
cat loadtest/results/nightly/summary.md      # the sorted results table
loadtest/rig.sh down                         # remove everything, restore host sysctls
```

Everything under `loadtest/results/<run-id>/` is git-ignored except the small
text artefacts (`summary.csv/md`, per-scenario `summary.json`, `manifest.json`,
`snuffles.stats`, `perf-*.txt`).

## rig.sh commands

`build`, `up`, `down`, `status`, `mtu <N>`, `offloads on|off`, `rps on|off`,
`build-sut` (rebuild snuffles from `/repo`), `exec <role> <cmd...>`
(`role` = `sut` | `gen-1..4` | `sink`), `smoke`. `up`/`down` are idempotent;
`down` removes everything it created even if `up` failed halfway. The topology
lives entirely inside the container netns (veths are created with both ends
already in the containers), so the host netns is never touched — verify with
`ip link` after `down`.

## What a scenario is

One JSON file per scenario under `scenarios/` (schema in SPEC "Scenario file").
Unspecified fields fall back to defaults; the generated files are fully explicit
except `snaplen`/`ring`, which are omitted to mean "snuffles' own default".
Groups: **A** pktgen rate/size/flow/knob matrix, **B** consumer modes
(headless/jsonl/syslog/stream/tui/…), **C** application + attack traffic
(http/iperf/replay/synflood/udpflood/frag), **D** a 5-minute soak.

## Per-run procedure (run-scenario.sh)

Kills strays → starts udpsink (syslog mode) → telemetry sampler → snuffles
(waits ≤10 s for its first `stats` line, else `start_failed`) → 3 s idle
baseline → traffic for `duration` (pktgen split round-robin over gens; the
others run in every listed gen concurrently) → optional `perf stat`+`record`
at +8 s → SIGINT snuffles (≤30 s, then SIGKILL) → collect → `analyze.py`.
pktgen is **always** stopped via an EXIT trap; `manifest.json` (with a `status`
of `ok|start_failed|gen_failed|killed`) is written even on failure; a one-line
human summary is printed at the end.

Addressing: `dst=sink` → `02:53:4e:46:00:05` / `10.77.0.5`, `dst=sut` →
`02:53:4e:46:00:01` / `10.77.0.1`, UDP dport 9.

## Measurement validity (what the numbers mean)

* **Traffic window.** `manifest.traffic_start` = every generator is running
  (pktgen: all four `start`s returned, they are issued concurrently and land
  within ~0.5 s); `traffic_end` = the first `stop` is issued. Rates and CPU%
  are computed over that window trimmed by 0.5 s at both ends (`window_secs`);
  totals are whole-run. `traffic_start_issued` / `traffic_stop_done` bound
  the full envelope. `snuffles.stats` lines are mapped to epoch with
  `stats_t0_epoch` (first stats line's arrival minus its `t`, +-0.1 s).
* **Accounting chain** (all whole-run, app-independent unless noted):
  `sent_total` (generator, wire frames; udpflood/frag datagrams x fragments)
  -> `bridge_in_pkts_total` (sum of rx_packets on p1..p5: every frame that
  entered the bridge, incl. sink replies) -> `br0_rx_pkts_total` (frames
  passed up to br0; equals bridge_in while the capture holds br0 in promisc)
  -> `captured_total + kdrop_total` (packet socket, app counters).
  `seen_pct` = (captured+kdrop)/bridge_in; 100 % means the packet socket ring
  is the only loss point. `sink_in/out_pkts_total` = p5 tx/rx.
  For pktgen dst=sink runs the four numbers are identical to the packet.
* **kdrop source.** pcap build: libpcap `ps_drop` (TPACKET ring `tp_drops`,
  accumulated). That counter is NOT visible in `ss -0` (`sk_drops` stays 0
  for the mmap ring), so `packet_socket_drops` is 0 for pcap builds even under
  heavy drop; the raw build's plain socket shows `packet_socket_drops ==
  kdrop_total` exactly. Use `seen_pct`/`bridge_in` as the independent check.
* **Bridge fdb.** rig.sh installs static+sticky fdb entries for the five fixed
  MACs (gen MACs on p1..p4, sink MAC on p5) and run-scenario re-asserts them.
  Without them the replay corpus (whose response frames carry the sink MAC as
  source) moves the sink MAC onto a gen port, and every later dst=sink flood
  is forwarded to that gen instead of the sink (p5 tx = 0), or flooded to all
  ports once the entry ages out. Learning stays on for everything else.
* **Generators are live.** `/opt/gen/*.sh` in the gen image are wrappers that
  exec `/repo/loadtest/gen/*.sh` (like the sut harness), so driver fixes never
  go stale in running containers; only the C tools and the corpus are baked.
  pktgen's background `start` writer detaches its stdio, otherwise `docker
  exec` lingers 2-3 s per gen and the gens start staggered.
* **perf.** `perf-window.json` records the stat/record epochs;
  `syscalls_per_pkt` = syscalls counted by perf stat / packets captured during
  exactly that window (never task-clock time). `perf_cpus_utilized` should
  agree with `cpu_total_pct`/100 (it does: 1.000 vs 99.9 % for A2).
* **Exit latency** comes from the FIRST `run-snuffles.sh stop` (manifest);
  `exit.json` can be rewritten by a second stop on an exited pid.
* **Host load.** pktgen kthreads run on CPUs 4-7/12-15 which other host
  workloads may also use; the offered rate therefore varies run to run
  (1.4 Mpps at loadavg 8-15 vs 2.8 Mpps at loadavg 2-3 for A2). Compare
  scenarios by `offered_pps_win`/`kdrop_pct_win`, not by absolute pps alone;
  `host_loadavg1_max` is recorded per scenario.

## analyze.py

`analyze.py <run-id>` writes per-scenario `summary.json` (every SPEC step-8
field) and per-run `summary.csv` + `summary.md` (sorted by name; pps in k/M with
3 sig. figs, percentages 2 dp). Tolerant of missing inputs (writes `null`) and
safe to re-run. Thread CPU% = `(Δ(utime+stime)/CLK_TCK)/Δwall·100` over the
traffic window; `captured_pps`/`kdrop` are measured over the same window (from
`snuffles.stats`, whose relative `t` is mapped to epoch via
`manifest.snuffles_start`); `loss_pct_total = 1 − captured/sent`.

## Generator driver contract (what run-scenario.sh calls)

Inside each `snf-gen-N`, in `$GEN_BIN_DIR` (default `/opt/gen`):

| kind | invocation |
|------|------------|
| pktgen | `pktgen.sh start\|stop\|result -d eth0 --cpus <list> --size <wire> --dst-mac M --dst-ip I --pps P --flows N --src-ip 10.77.0.1N` (all gens started/stopped concurrently) |
| udpflood | `udpflood -d <dstip> -p 9 -s <payload> -t <threads> -T <secs> [-r]` (payload = pkt_size − 42) |
| frag | `udpflood -d <dstip> -p 9 -s 4000 -t <threads> -T <secs>` |
| synflood | `synflood -t <threads> -T <secs>` |
| http | `http.sh --threads N --conns C --duration D --url U --keepalive true\|false` → JSON |
| iperf | `iperf.sh --threads N --duration D --port 5200+N` → JSON (one iperf3 server per gen on the sink) |
| replay | `replay.sh --duration D` → JSON |

The self-terminating drivers must print a JSON result object on stdout (keys
`sent,bytes,seconds,pps,errors` where meaningful); run-scenario captures it
verbatim into `gen-<N>.json`. The `.sh` driver argv above (http/iperf/replay) is
this rig's convention — SPEC pins their behaviour but not their flags, so the
generator image must match these, or adjust the `cmd_*` builders in
`run-scenario.sh`. On this kernel `clone_skb` returns ENOTSUPP over veth, so a
pktgen driver must tolerate non-fatal writes to the pktgen procfs.

## Test/override knobs (defaults = the real rig)

`RIG_PREFIX` (container prefix, `snf-`), `RIG_IMAGE_SUT|GEN|SINK`,
`GEN_BIN_DIR` (`/opt/gen`), `SNF_BIN_DIR` (`/opt/snuffles`),
`SINK_BIN_DIR` (`/opt/sink`), `RS_NO_ANALYZE=1` (matrix uses it to analyze once
at the end). These let the orchestration be exercised against stand-in
containers; production runs need none of them.
