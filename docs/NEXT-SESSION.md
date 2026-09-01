# Next session — resume point

Written 2026-09-01 at the end of the load-test / performance campaign.
Read this before touching anything; it is the record, not recall.

## State

| | |
|---|---|
| `main` | `2fb9d5e` (Merge branch 'fix/mp-ring-arm64'), pushed, CI green (24 checks) |
| Release | **v1.4.0** — https://github.com/caanone/snuffles/releases/tag/v1.4.0 |
| Release assets | `snuffles-1.4.0-linux-x86_64` (static, nopcap), `snuffles-1.4.0-windows-x64.exe` (static, raw sockets), `SHA256SUMS` — checksums verified after upload |
| Working tree | clean; only `main` exists locally |
| Load-test rig | **down**. No `snf-*` containers, no rig interfaces, host sysctls restored from `loadtest/results/host-sysctl.before` |
| Report | `loadtest/REPORT.html` in the repo, and https://claude.ai/code/artifact/d57768f9-db4d-46e0-9b5d-5d291c82cf49 |

Remote branches still present and fully contained in `main` — delete when convenient:
`loadtest`, `exp/all`, `fix/mp-ring-arm64`.

## Preflight (run first, ~30 s)

```bash
cd /home/ixo/snuffles && git pull && git log --oneline -1     # expect 2fb9d5e or later
make -j8 && make nopcap -j8 && make test                      # 11 suites, all pass
docker ps --format '{{.Names}}' | grep '^snf-' ; echo "(no output = rig down)"
cat /proc/sys/net/core/rmem_max                               # 33554432 = host untuned
```

## What shipped in v1.4.0

Capture path: on-demand consumer wake-ups (no mutex/condvar/`write()` per packet, N waiters),
`-B/--buffer-mb` kernel buffer with TPACKET_V3 blocks, throttled `pcap_stats`, raw build on a
TPACKET_V3 ring, lazy dissection (no string formatting on the capture thread — `summary_format()`
runs on consumers), a shared payload arena instead of a snaplen-sized slot per packet, binary
session keys with a sized table / O(1) eviction / entry pool / reassembly lifecycle, an output
thread for `--syslog` and `-w`, a TUI capped at ~30 fps with rate-limited session snapshots,
`-j N` multi-worker capture with `PACKET_FANOUT`, and `--cpu` / `--rt` / `--stats` / `SIGUSR1`.

Measured on the rig, 64-byte frames, 30 s: 2.56 Mpps offered (the rig's maximum) captured with
**0 % kernel drops at 29 % of one core** and 87 MB RSS, against 595 kpps / 79 % dropped / 100 % of
a core / 630 MB in v1.3.1. Full numbers: `loadtest/results/final/summary.md`.

## Open lanes, in priority order

1. **macOS arm64 release asset** — the only missing v1.4.0 binary. Build on a Mac from the tag
   and upload as `snuffles-1.4.0-macos-arm64`:
   ```bash
   git checkout v1.4.0 && make nopcap && strip build/raw/snuffles
   mv build/raw/snuffles snuffles-1.4.0-macos-arm64
   shasum -a 256 snuffles-1.4.0-macos-arm64            # append to SHA256SUMS
   gh release upload v1.4.0 snuffles-1.4.0-macos-arm64
   ```
2. **Multi-thread / cheaper syslog export.** Capture no longer loses anything the kernel
   delivers; the sinks are the limit and now count their own loss (`out_missed`, `missed`).
   One syslog output thread does ~330 kpps and the headless text printer ~840 kpps. Options:
   integer formatting instead of `snprintf` in `syslog_out.c`, N output threads sharding by
   session id, or a binary export format. Measure with scenarios `B3-syslog-1m` / `B3x-syslog-max`.
3. **AF_XDP backend.** Deliberately not attempted: the rig is veth-based and has no zero-copy
   path, so it cannot be validated here. Needs a physical NIC (the host has `enp41s0`) and a
   second machine or a hardware generator to drive it.
4. **Wire the regression gate into a scheduled run.** `loadtest/gate.sh` and
   `loadtest/gate-baseline.json` exist and are proven (passes on a clean re-run, fails on a
   handicapped build). `.github/workflows/loadtest.yml` is manual-only and needs a self-hosted
   runner with privileged Docker; nothing runs it automatically yet.
5. **Report/README refresh** if the numbers change again — `loadtest/REPORT.html` documents
   v1.3.1 → six experiments → post-plan, and would need a fourth column for any new wave.

## Running the rig (for any of the above)

```bash
./loadtest/rig.sh build && ./loadtest/rig.sh up          # tunes host sysctls, saves originals
docker exec snf-sut /opt/snuffles/build.sh               # builds the current /repo checkout
./loadtest/matrix.sh <run-id> loadtest/scenarios/A2-*.json ...
./loadtest/gate.sh --run-id <id>                         # regression gate vs the baseline
python3 loadtest/analyze.py <run-id>                     # summary.md / summary.csv
./loadtest/rig.sh down                                   # MANDATORY: restores host sysctls
```

To measure a branch instead of the checked-out tree, add a worktree and point the SUT at it:
`docker exec -e SNF_REPO=/repo/.claude/worktrees/<name> snf-sut /opt/snuffles/build.sh`.

## Hazards learned (do not re-derive)

- **`rig.sh down` is not optional.** It restores `net.core.*` on a host shared with CI runners
  and KVM guests. The originals live in `loadtest/results/host-sysctl.before`.
- **The host is shared.** Absolute pps varies with load; compare builds by drop % at a fixed
  offered rate, in the same session, and re-run anything anomalous.
- **arm64 CI is the memory-model oracle.** Two real bugs (seqlock fences, and a release fence on
  the wrong side of the record-header stores) reproduced only in the sanitized arm64 stress loop.
  Never weaken the ring's atomics without an arm64 stress run at high `RUNS`.
- **Timing assertions need platform guards.** Sanitized arm64 is ~20× slower and the shared macOS
  runner stalls for tens of ms; see the existing guards in `tests/test_ui.c` and
  `tests/test_session.c`. GCC has no `__has_feature` — use the `#if defined(__SANITIZE_ADDRESS__)`
  chain already there.
- **`jq '.x // true'` swallows `false`.** It silently made the HTTP `Connection: close` scenarios
  run with keep-alive for a whole matrix.
- **pktgen on veth cannot use `clone_skb`**, and the whole receive path is charged to the sending
  CPU, so the rig tops out near 2.8 Mpps offered. That is the rig's ceiling, not the app's.
- **The Windows test container writes root-owned files** into mounted worktrees; `chown` them back
  through the container, not with `sudo` on the host.
- **`test_syslog_out`'s broadcast-failure case is Linux-only** (macOS sends to 255.255.255.255 on a
  connected socket without `SO_BROADCAST`; Wine maps the error differently).
