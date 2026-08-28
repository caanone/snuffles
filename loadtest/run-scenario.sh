#!/usr/bin/env bash
# loadtest/run-scenario.sh <scenario.json> [run-id] [--duration N]
#
# Runs ONE scenario end to end (SPEC "Per-run procedure", 8 steps), driving the
# sut/gen/sink pieces through `docker exec`. Robust by construction:
#   * strays are killed first, and again on exit;
#   * pktgen is ALWAYS stopped (pgctrl stop in every gen) via an EXIT trap;
#   * every wait is time-bounded;
#   * manifest.json is written even on failure, with a "status" field
#     (ok | start_failed | gen_failed | killed);
#   * a one-line human summary is printed at the end.
# Then analyze.py <run-id> is run (tolerant + repeatable), so a single scenario
# already yields summary.{json,csv,md}.
#
# Overrides (defaults = the real rig; used by the orchestration self-tests):
#   RIG_PREFIX     container prefix (default snf-)
#   GEN_BIN_DIR    generator driver dir inside the gen containers (default /opt/gen)
#   SNF_BIN_DIR    harness dir inside snf-sut (default /opt/snuffles)
#   SINK_BIN_DIR   sink binaries dir (default /opt/sink)
#   RS_NO_ANALYZE  =1 skip the analyze.py call (matrix.sh calls it once at the end)
set -euo pipefail

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
LT="$REPO/loadtest"
RESULTS="$LT/results"
PREFIX="${RIG_PREFIX:-snf-}"
GEN_DIR="${GEN_BIN_DIR:-/opt/gen}"
SNF_DIR="${SNF_BIN_DIR:-/opt/snuffles}"
SINK_DIR="${SINK_BIN_DIR:-/opt/sink}"

cname() { printf '%s%s' "$PREFIX" "$1"; }
log()   { printf 'run: %s\n' "$*" >&2; }
die()   { printf 'run: ERROR: %s\n' "$*" >&2; exit 1; }
now()   { date +%s.%N; }

# addressing (SPEC)
dst_mac() { [ "$1" = sut ] && echo 02:53:4e:46:00:01 || echo 02:53:4e:46:00:05; }
dst_ip()  { [ "$1" = sut ] && echo 10.77.0.1        || echo 10.77.0.5; }

# ── args ────────────────────────────────────────────────────────────────────
SCEN=""; RUN_ID=""; DUR_OVERRIDE=""
while [ $# -gt 0 ]; do
    case "$1" in
        --duration) DUR_OVERRIDE=$2; shift 2 ;;
        --duration=*) DUR_OVERRIDE=${1#*=}; shift ;;
        -*) die "unknown flag $1" ;;
        *) if [ -z "$SCEN" ]; then SCEN=$1; elif [ -z "$RUN_ID" ]; then RUN_ID=$1; else die "extra arg $1"; fi; shift ;;
    esac
done
[ -n "$SCEN" ] || die "usage: run-scenario.sh <scenario.json> [run-id] [--duration N]"
[ -f "$SCEN" ] || die "scenario file not found: $SCEN"
RUN_ID=${RUN_ID:-$(date +%Y%m%d-%H%M%S)}

# ── parse scenario (jq on the host; defaults filled here) ────────────────────
jqget() { jq -r "$1 // empty" "$SCEN"; }
NAME=$(jqget '.name'); [ -n "$NAME" ] || die "scenario has no .name"
BUILD=$(jq -r '.build // "pcap"' "$SCEN")
MODE=$(jq -r '.mode // "quiet"' "$SCEN")
IFACE=$(jq -r '.iface // "br0"' "$SCEN")
BPF=$(jq -r '.bpf // ""' "$SCEN")
DURATION=$(jq -r '.duration // 30' "$SCEN")
[ -n "$DUR_OVERRIDE" ] && DURATION=$DUR_OVERRIDE
# perf schedule (SPEC: perf stat 10s at +8s, perf record 8s at +19s within a
# >=30s traffic window). For short --duration overrides, compress the windows
# so the record window still lands INSIDE the traffic window (otherwise perf
# would profile an idle process and show no packet-path symbols).
if [ "$DURATION" -ge 30 ] 2>/dev/null; then
    PERF_OFFSET=8; PERF_STAT_SECS=10; PERF_RECORD_SECS=8
else
    PERF_OFFSET=1
    _pbudget=$(( DURATION - PERF_OFFSET - 2 ))   # 1s stat/record gap + 1s tail
    [ "$_pbudget" -lt 6 ] && _pbudget=6
    PERF_STAT_SECS=$(( _pbudget / 2 ))
    PERF_RECORD_SECS=$(( _pbudget - PERF_STAT_SECS ))
fi
PERF=$(jq -r '.perf // false' "$SCEN")
MTU=$(jq -r '.mtu // 1500' "$SCEN")
OFFLOADS=$(jq -r '.offloads // "on"' "$SCEN")
RPS=$(jq -r '.rps // "off"' "$SCEN")
SNAPLEN=$(jq -r '.snaplen // empty' "$SCEN")
RING=$(jq -r '.ring // empty' "$SCEN")

KIND=$(jq -r '.traffic.kind // "pktgen"' "$SCEN")
mapfile -t GENS < <(jq -r '.traffic.gens // [1,2,3,4] | .[]' "$SCEN")
mapfile -t CPUS < <(jq -r '.traffic.cpus // [4,5,6,7,12,13,14,15] | .[]' "$SCEN")
PKT_SIZE=$(jq -r '.traffic.pkt_size // 64' "$SCEN")
PPS=$(jq -r '.traffic.pps // 0' "$SCEN")
FLOWS=$(jq -r '.traffic.flows // 1' "$SCEN")
DST=$(jq -r '.traffic.dst // "sink"' "$SCEN")
THREADS=$(jq -r '.traffic.threads // 2' "$SCEN")
CONNS=$(jq -r '.traffic.conns // 256' "$SCEN")
KEEPALIVE=$(jq -r 'if .traffic.keepalive == null then true else .traffic.keepalive end' "$SCEN")
URL=$(jq -r '.traffic.url // "/"' "$SCEN")
EXTRA=$(jq -r '.traffic.extra // ""' "$SCEN")
# IMIX (pktgen only): a per-thread packet-size mix. .traffic.imix is an array of
# {"size":wire,"weight":w}; pktgen has no per-packet size mix, so we approximate
# by assigning the sizes round-robin across the pktgen CPUs and setting each
# thread's ratep so the aggregate packet counts come out in the weight ratio
# (e.g. 64/570/1518 at 7:4:1). .traffic.imix_base is the per-weight-unit total
# pps (aggregate for a size = weight * base; default 100000).
IMIX=$(jq -c '.traffic.imix // empty' "$SCEN")
IMIX_BASE=$(jq -r '.traffic.imix_base // 100000' "$SCEN")

OUTDIR="$RESULTS/$RUN_ID/$NAME"
COUT="/results/$RUN_ID/$NAME"          # same dir seen inside the containers
mkdir -p "$OUTDIR"
# Re-running a scenario under the same run-id must not mix data with the
# previous attempt: telemetry.jsonl is appended to, gen-*.json of a gen no
# longer in the scenario would still be summed by analyze, an old sink.json /
# perf-stat.txt / out.count would be read as if current. Remove everything
# run-scenario.sh itself produces (never the directory).
rm -f "$OUTDIR"/telemetry.jsonl "$OUTDIR"/snuffles.stats "$OUTDIR"/snuffles.stderr \
      "$OUTDIR"/gen-*.json "$OUTDIR"/gen-*.raw "$OUTDIR"/gen-*.err "$OUTDIR"/gen-*.rc \
      "$OUTDIR"/sink.json "$OUTDIR"/out.count "$OUTDIR"/exit.json "$OUTDIR"/.stop.json \
      "$OUTDIR"/exit.status "$OUTDIR"/perf-stat.txt "$OUTDIR"/perf-report.txt \
      "$OUTDIR"/perf-window.json "$OUTDIR"/perf.log "$OUTDIR"/perf.data "$OUTDIR"/tui.log \
      "$OUTDIR"/latency.json "$OUTDIR"/latency.log \
      "$OUTDIR"/summary.json "$OUTDIR"/stream.pcap 2>/dev/null || true

# ── docker exec helpers ─────────────────────────────────────────────────────
dex()  { docker exec "$(cname "$1")" "${@:2}"; }        # foreground
dexd() { docker exec -d "$(cname "$1")" "${@:2}"; }     # detached
running() { [ "$(docker inspect -f '{{.State.Status}}' "$(cname "$1")" 2>/dev/null || echo absent)" = running ]; }
have_role() { running "$1"; }

STATUS=start_failed          # pessimistic; upgraded to ok on the happy path
TRAFFIC_START=""; TRAFFIC_END=""; RUN_START=$(now); SNUF_START=""
TRAFFIC_ISSUE=""; TRAFFIC_STOPPED=""; STATS_T0=""
SNUF_PID=""; EXIT_CODE=null; EXIT_LAT=null; KILLED=false; SNUF_STOPPED=0
declare -A GEN_RC=()

# Static sticky fdb entries for the five fixed MACs (rig.sh up installs them;
# re-asserted per scenario because the bridge's forwarding decision is part of
# what is measured: with a learned-only fdb the replay corpus moves the sink
# MAC onto a gen port and later dst=sink floods never reach the sink).
assert_fdb() {
    running sut || return 0
    dex sut sh -c 'for n in 1 2 3 4; do bridge fdb replace 02:53:4e:46:01:0$n dev p$n master static sticky 2>/dev/null; done;
                   bridge fdb replace 02:53:4e:46:00:05 dev p5 master static sticky 2>/dev/null' \
        || log "warning: could not assert static fdb entries"
}

# A synflood leaves the sink's listeners with up to 65535 half-open (SYN_RECV)
# request sockets each, whose SYN-ACK retransmits (5 over ~63 s) would bleed
# into the NEXT scenario's capture. Restart nginx (drops its SYN queues) when
# any are left, then wait until the netns shows none.
sink_quiesce() {
    running sink || return 0
    local n i
    n=$(dex sink sh -c "ss -tnH state syn-recv 2>/dev/null | wc -l" 2>/dev/null || echo 0)
    [ "${n:-0}" -gt 0 ] || return 0
    log "sink has $n half-open TCP connections from a previous scenario: restarting nginx to flush them"
    dex sink sh -c 'pkill -x nginx 2>/dev/null; sleep 0.5; /opt/sink/start-services.sh >/dev/null 2>&1' || log "warning: sink nginx restart failed"
    for i in $(seq 1 100); do
        n=$(dex sink sh -c "ss -tnH state syn-recv 2>/dev/null | wc -l" 2>/dev/null || echo 0)
        [ "${n:-0}" -eq 0 ] && return 0
        sleep 0.1
    done
    log "warning: sink still has $n half-open connections"
    return 0
}

# ── stray cleanup / pktgen safety ───────────────────────────────────────────
kill_strays() {
    local g
    # ALL four gens, not only this scenario's: a previous scenario (or a
    # crashed run) may have left pktgen transmitting from a gen we do not use.
    for g in 1 2 3 4; do
        running "gen-$g" || continue
        dex "gen-$g" pkill -x -9 udpflood  2>/dev/null || true
        dex "gen-$g" pkill -x -9 synflood  2>/dev/null || true
        dex "gen-$g" pkill -9 -f 'wrk '    2>/dev/null || true
        dex "gen-$g" pkill -9 -f 'iperf3 -c' 2>/dev/null || true
        dex "gen-$g" pkill -x -9 tcpreplay 2>/dev/null || true
        dex "gen-$g" sh -c 'echo stop > /proc/net/pktgen/pgctrl 2>/dev/null; echo reset > /proc/net/pktgen/pgctrl 2>/dev/null' || true
    done
    if running sut; then
        dex sut pkill -x -9 snuffles 2>/dev/null || true
        dex sut pkill -9 -f 'perf record' 2>/dev/null || true
        dex sut pkill -9 -f 'perf stat'   2>/dev/null || true
    fi
    running sink && dex sink pkill -x -9 udpsink 2>/dev/null || true
    return 0
}

pktgen_stop_all() {
    local g
    for g in "${GENS[@]}"; do
        running "gen-$g" || continue
        dex "gen-$g" sh -c 'echo stop > /proc/net/pktgen/pgctrl 2>/dev/null' || true
    done
}

FINALIZED=0
finalize() {
    local rc=$?
    [ "$FINALIZED" = 1 ] && return
    FINALIZED=1
    set +eu
    pktgen_stop_all
    # stop snuffles if still running (never twice: a second `stop` on an
    # already-exited pid rewrites exit.json with latency 2 ms / signal none)
    if [ "$SNUF_STOPPED" = 0 ] && running sut && [ -s "$OUTDIR/snuffles.pid" ]; then
        SNUF_STOPPED=1
        dex sut "$SNF_DIR/run-snuffles.sh" stop "$COUT" >/dev/null 2>&1
    fi
    # stop udpsink + telemetry
    running sink && dex sink pkill -TERM -x udpsink 2>/dev/null
    running sut  && dex sut  pkill -TERM -f 'telemetry.sh' 2>/dev/null
    kill_strays
    write_manifest
    print_summary
    [ "$STATUS" = ok ] && exit 0
    exit "$rc"
}
trap finalize EXIT INT TERM

# ── manifest / summary ──────────────────────────────────────────────────────
write_manifest() {
    local sha ver uname_s cpus_json gens_json
    sha=$(dex sut sh -c 'git -C /repo rev-parse HEAD 2>/dev/null' 2>/dev/null || git -C "$REPO" rev-parse HEAD 2>/dev/null || echo unknown)
    ver=$(dex sut "$SNF_DIR/$BUILD/snuffles" -v 2>/dev/null | head -1 || echo unknown)
    uname_s=$(uname -srmo 2>/dev/null || uname -a)
    cpus_json=$(printf '%s\n' "${CPUS[@]}" | jq -R . | jq -s 'map(tonumber)')
    gens_json=$(printf '%s\n' "${GENS[@]}" | jq -R . | jq -s 'map(tonumber)')
    jq -n \
        --arg name "$NAME" --arg run "$RUN_ID" --arg status "$STATUS" \
        --arg build "$BUILD" --arg mode "$MODE" --arg iface "$IFACE" \
        --argjson duration "$DURATION" --argjson perf "$PERF" \
        --arg kind "$KIND" --argjson pkt_size "$PKT_SIZE" --arg dst "$DST" \
        --argjson pps "$PPS" --argjson flows "$FLOWS" \
        --arg sha "$sha" --arg ver "$ver" --arg uname "$uname_s" \
        --argjson cpus "$cpus_json" --argjson gens "$gens_json" \
        --arg run_start "$RUN_START" --arg run_end "$(now)" \
        --arg snuf_start "${SNUF_START:-}" --arg stats_t0 "${STATS_T0:-}" \
        --arg tstart "${TRAFFIC_START:-}" --arg tend "${TRAFFIC_END:-}" \
        --arg tissue "${TRAFFIC_ISSUE:-}" --arg tstopped "${TRAFFIC_STOPPED:-}" \
        --argjson perf_offset "$PERF_OFFSET" --argjson perf_stat_secs "$PERF_STAT_SECS" \
        --argjson perf_record_secs "$PERF_RECORD_SECS" \
        --argjson exit_code "$EXIT_CODE" --argjson exit_lat "$EXIT_LAT" \
        --argjson killed "$KILLED" \
        --arg mtu "$MTU" --arg offloads "$OFFLOADS" --arg rps "$RPS" \
        --argjson snaplen "${SNAPLEN:-null}" --argjson ring "${RING:-null}" \
        --arg bpf "$BPF" \
        --slurpfile scenario "$SCEN" \
        '{
          name:$name, run_id:$run, status:$status, build:$build, mode:$mode,
          iface:$iface, duration:$duration, perf:$perf,
          traffic:{kind:$kind, pkt_size:$pkt_size, dst:$dst, pps:$pps, flows:$flows,
                   gens:$gens, cpus:$cpus},
          knobs:{mtu:($mtu|tonumber), offloads:$offloads, rps:$rps,
                 snaplen:$snaplen, ring:$ring, bpf:$bpf},
          git_sha:$sha, snuffles_version:$ver, host_uname:$uname,
          cpuset:{sut:"2,3,10,11", gen1:"4,12", gen2:"5,13", gen3:"6,14",
                  gen4:"7,15", sink:"0,8"},
          run_start:($run_start|tonumber),
          run_end:($run_end|tonumber),
          snuffles_start:(if $snuf_start=="" then null else ($snuf_start|tonumber) end),
          stats_t0_epoch:(if $stats_t0=="" then null else ($stats_t0|tonumber) end),
          traffic_start:(if $tstart=="" then null else ($tstart|tonumber) end),
          traffic_end:(if $tend=="" then null else ($tend|tonumber) end),
          traffic_start_issued:(if $tissue=="" then null else ($tissue|tonumber) end),
          traffic_stop_done:(if $tstopped=="" then null else ($tstopped|tonumber) end),
          window_note:"traffic_start = every generator running; traffic_end = stop issued to the first generator (steady-state window for rates/CPU%); traffic_start_issued/traffic_stop_done bound the full envelope",
          perf_schedule:{offset_s:$perf_offset, stat_s:$perf_stat_secs, record_s:$perf_record_secs},
          exit_code:$exit_code, exit_latency_ms:$exit_lat, killed:$killed
        }' > "$OUTDIR/manifest.json" 2>/dev/null \
      || echo "{\"name\":\"$NAME\",\"run_id\":\"$RUN_ID\",\"status\":\"$STATUS\"}" > "$OUTDIR/manifest.json"
}

print_summary() {
    local cap sent line
    cap=$(awk '/^summary /{for(i=1;i<=NF;i++)if($i~/^captured=/){split($i,a,"=");print a[2]}}' "$OUTDIR/snuffles.stats" 2>/dev/null | tail -1)
    [ -z "$cap" ] && cap=$(awk '/^stats /{for(i=1;i<=NF;i++)if($i~/^captured=/){split($i,a,"=");print a[2]}}' "$OUTDIR/snuffles.stats" 2>/dev/null | tail -1)
    sent=$(cat "$OUTDIR"/gen-*.json 2>/dev/null | jq -s '[.[].sent_pkts // 0]|add' 2>/dev/null)
    line="[$NAME] status=$STATUS build=$BUILD mode=$MODE kind=$KIND"
    local win=""
    [ -n "$TRAFFIC_START" ] && [ -n "$TRAFFIC_END" ] && win=$(awk -v a="$TRAFFIC_START" -v b="$TRAFFIC_END" 'BEGIN{printf "%.1f", b-a}')
    line="$line dur=${DURATION}s window=${win:-?}s sent=${sent:-?}pkts captured=${cap:-?}"
    line="$line exit=$EXIT_CODE killed=$KILLED"
    printf 'run: SUMMARY %s\n' "$line" >&2
}

# ── step 1: prepare ─────────────────────────────────────────────────────────
have_role sut  || die "container $(cname sut) not running (rig.sh up)"
have_role sink || log "warning: $(cname sink) not running (syslog/http/iperf scenarios will be empty)"
for g in "${GENS[@]}"; do have_role "gen-$g" || die "container $(cname gen-$g) not running"; done

log "[$NAME] run-id=$RUN_ID build=$BUILD mode=$MODE kind=$KIND dur=${DURATION}s -> $OUTDIR"
kill_strays
# apply mtu/offloads/rps for this scenario
"$LT/rig.sh" mtu "$MTU"      >/dev/null 2>&1 || log "warning: rig.sh mtu $MTU failed"
"$LT/rig.sh" offloads "$OFFLOADS" >/dev/null 2>&1 || log "warning: rig.sh offloads failed"
"$LT/rig.sh" rps "$RPS"     >/dev/null 2>&1 || log "warning: rig.sh rps failed"
assert_fdb
sink_quiesce

# ── step 2: udpsink (syslog mode) ───────────────────────────────────────────
if [ "$MODE" = syslog ] && have_role sink; then
    dexd sink "$SINK_DIR/udpsink" -p 514 -o "$COUT/sink.json" -b 67108864
    log "udpsink started on sink (:514 -> $COUT/sink.json)"
fi

# ── step 3: telemetry ───────────────────────────────────────────────────────
rm -f "$OUTDIR/snuffles.pid"
dexd sut "$SNF_DIR/telemetry.sh" "$COUT/snuffles.pid" "$COUT/telemetry.jsonl"
log "telemetry sampler started (waits for snuffles.pid)"

# ── step 4: start snuffles, wait for first stats line ───────────────────────
declare -a EXTRA_ARGS=()
[ -n "$SNAPLEN" ] && EXTRA_ARGS+=(-s "$SNAPLEN")
[ -n "$RING" ]    && EXTRA_ARGS+=(-b "$RING")
[ -n "$BPF" ]     && EXTRA_ARGS+=(-f "$BPF")

if ! dex sut "$SNF_DIR/run-snuffles.sh" "$MODE" "$BUILD" "$IFACE" "$COUT" "${EXTRA_ARGS[@]}"; then
    log "run-snuffles.sh start failed (see $OUTDIR/snuffles.stderr)"
    STATUS=start_failed
    exit 1
fi
SNUF_START=$(now)   # epoch when run-snuffles.sh returned (before pcap open)
# wait <=10 s for the first stats line
for _ in $(seq 1 100); do
    [ -s "$OUTDIR/snuffles.stats" ] && grep -q '^stats ' "$OUTDIR/snuffles.stats" && break
    sleep 0.1
done
if ! grep -q '^stats ' "$OUTDIR/snuffles.stats" 2>/dev/null; then
    log "snuffles produced no stats line within 10 s -> start_failed"
    STATUS=start_failed
    exit 1
fi
# snuffles.stats 't' is relative to its stats thread's t0, which starts only
# AFTER the capture is open (0.3-0.7 s after SNUF_START). Pin t0 to the epoch
# at which the first stats line appeared minus that line's t (error <= the
# 0.1 s poll above) so analyze.py maps stats lines to epoch accurately.
_first_t=$(awk '/^stats /{for(i=1;i<=NF;i++)if($i~/^t=/){split($i,a,"=");print a[2];exit}}' "$OUTDIR/snuffles.stats")
STATS_T0=$(awk -v now="$(now)" -v t="${_first_t:-0}" 'BEGIN{printf "%.6f", now - t}')
[ -s "$OUTDIR/snuffles.pid" ] && read -r SNUF_PID < "$OUTDIR/snuffles.pid"
log "snuffles up (pid=$SNUF_PID); first stats line seen"

# ── traffic drivers ─────────────────────────────────────────────────────────
# Each writes gen-<N>.json into $OUTDIR. pktgen aggregates per-cpu result;
# the others capture the driver's JSON stdout verbatim as .raw and normalise.

# IMIX: assign each pktgen CPU a size + ratep so the aggregate packet counts
# match the weight ratio. Fills IMIX_SIZE[cpu]/IMIX_PPS[cpu]; IMIX_ON=1 when set.
IMIX_ON=0
declare -A IMIX_SIZE=() IMIX_PPS=()
setup_imix() {
    [ -n "$IMIX" ] || return 0
    IMIX_ON=1
    local -a isz iwt
    mapfile -t isz < <(jq -r '.[].size' <<<"$IMIX")
    mapfile -t iwt < <(jq -r '.[].weight' <<<"$IMIX")
    local nsizes=${#isz[@]} i idx cpu
    [ "$nsizes" -ge 1 ] || die "imix has no sizes"
    declare -A cnt=()
    for ((i=0; i<${#CPUS[@]}; i++)); do idx=$(( i % nsizes )); cnt[$idx]=$(( ${cnt[$idx]:-0} + 1 )); done
    for ((i=0; i<${#CPUS[@]}; i++)); do
        idx=$(( i % nsizes )); cpu=${CPUS[$i]}
        IMIX_SIZE[$cpu]=${isz[$idx]}
        # ratep = weight*base / (#cpus with this size)  => aggregate = weight*base
        IMIX_PPS[$cpu]=$(( iwt[$idx] * IMIX_BASE / cnt[$idx] ))
    done
    log "imix: sizes=$(IFS=,; echo "${isz[*]}") weights=$(IFS=,; echo "${iwt[*]}") base=$IMIX_BASE over ${#CPUS[@]} cpus"
}

# build comma lists of per-cpu size/ratep for one gen's cpu set (in order)
imix_lists_for() {                        # imix_lists_for <cpu,csv>  -> sets IMIX_SIZE_CSV IMIX_PPS_CSV
    local cpus=$1 c; IMIX_SIZE_CSV=""; IMIX_PPS_CSV=""
    local IFS=,
    for c in $cpus; do
        IMIX_SIZE_CSV="${IMIX_SIZE_CSV:+$IMIX_SIZE_CSV,}${IMIX_SIZE[$c]}"
        IMIX_PPS_CSV="${IMIX_PPS_CSV:+$IMIX_PPS_CSV,}${IMIX_PPS[$c]}"
    done
}

# pktgen: split CPUS round-robin across GENS
start_pktgen() {
    local i g cpu dmac dip
    dmac=$(dst_mac "$DST"); dip=$(dst_ip "$DST")
    setup_imix
    declare -gA PG_CPUS=()
    i=0
    for cpu in "${CPUS[@]}"; do
        g=${GENS[$(( i % ${#GENS[@]} ))]}
        PG_CPUS[$g]="${PG_CPUS[$g]:+${PG_CPUS[$g]},}$cpu"
        i=$((i+1))
    done
    # start every gen CONCURRENTLY (each docker exec ~0.3 s; done serially the
    # gens would start staggered and run different lengths). Deterministic
    # gen order (GENS), not the hash order of "${!PG_CPUS[@]}".
    declare -ga PG_GENS=()
    local pids=()
    for g in "${GENS[@]}"; do
        [ -n "${PG_CPUS[$g]:-}" ] || continue
        PG_GENS+=("$g")
        local sip="10.77.0.1$g"
        local size_arg=$PKT_SIZE pps_arg=$PPS
        if [ "$IMIX_ON" = 1 ]; then
            imix_lists_for "${PG_CPUS[$g]}"
            size_arg=$IMIX_SIZE_CSV; pps_arg=$IMIX_PPS_CSV
        fi
        log "pktgen gen-$g cpus=${PG_CPUS[$g]} size=$size_arg pps=$pps_arg flows=$FLOWS dst=$DST"
        ( dex "gen-$g" "$GEN_DIR/pktgen.sh" start -d eth0 --cpus "${PG_CPUS[$g]}" \
            --size "$size_arg" --dst-mac "$dmac" --dst-ip "$dip" \
            --pps "$pps_arg" --flows "$FLOWS" --src-ip "$sip" >/dev/null 2>"$OUTDIR/gen-$g.err" ) &
        pids+=("$!:$g")
    done
    local pg
    for pg in "${pids[@]}"; do
        wait "${pg%%:*}" || GEN_RC[${pg##*:}]=1
    done
}
stop_pktgen() {
    local g pids=() p
    # stop all gens concurrently, THEN read the (final) counters
    for g in "${PG_GENS[@]}"; do
        ( dex "gen-$g" "$GEN_DIR/pktgen.sh" stop -d eth0 --cpus "${PG_CPUS[$g]}" >/dev/null 2>&1 ) &
        pids+=("$!")
    done
    for p in "${pids[@]}"; do wait "$p" || true; done
    TRAFFIC_STOPPED=$(now)
    for g in "${PG_GENS[@]}"; do
        local raw; raw=$(dex "gen-$g" "$GEN_DIR/pktgen.sh" result -d eth0 --cpus "${PG_CPUS[$g]}" 2>/dev/null || echo '[]')
        printf '%s' "$raw" > "$OUTDIR/gen-$g.raw"
        # pktgen.sh result emits ONE aggregate object {sent,bytes,pps,seconds,
        # errors,devices:[{sofar,bytes,...}]}. Read .sent (else sum devices'/
        # array's .sofar). bytes are WIRE bytes from .bytes (fallback sent*wire).
        jq -n --argjson raw "$(printf '%s' "$raw" | jq -c '. as $r | if ($r|type)=="array" then $r else [$r] end' 2>/dev/null || echo '[]')" \
              --arg gen "$g" --argjson wire "$PKT_SIZE" \
          '($raw | map(.devices // [.]) | add) as $dev
           | {gen:($gen|tonumber), kind:"pktgen",
              sent_pkts:([$raw[] | (.sent // .sofar // 0)] | add),
              pps:([$raw[].pps // 0]|add),
              seconds:([$raw[].seconds // 0]|max),
              errors:([$raw[].errors // 0]|add)}
           | .sent_pkts = (if (.sent_pkts // 0) > 0 then .sent_pkts
                           else ([$dev[] | (.sofar // 0)] | add) end)
           | .sent_bytes = (([$raw[] | (.bytes // 0)] | add) as $b
                            | if $b > 0 then $b else ((.sent_pkts // 0) * $wire) end)
           | .raw = $raw' > "$OUTDIR/gen-$g.json" 2>/dev/null \
          || echo "{\"gen\":$g,\"kind\":\"pktgen\",\"sent_pkts\":null,\"raw_error\":true}" > "$OUTDIR/gen-$g.json"
    done
}

# a self-terminating driver run concurrently in every listed gen
run_concurrent() {
    local build_cmd=$1     # name of a function: cmd_for_gen <g> -> prints argv
    local g pids=()
    for g in "${GENS[@]}"; do
        ( set +e
          docker exec "$(cname "gen-$g")" sh -c "$($build_cmd "$g")" \
              > "$OUTDIR/gen-$g.raw" 2> "$OUTDIR/gen-$g.err"
          echo $? > "$OUTDIR/gen-$g.rc" ) &
        pids+=($!)
    done
    # bound the wait to duration + 20 s slack; tick perf while drivers run
    local deadline=$(( $(date +%s) + DURATION + 20 ))
    local any=1
    while [ "$any" = 1 ] && [ "$(date +%s)" -lt "$deadline" ]; do
        maybe_perf
        any=0
        for p in "${pids[@]}"; do kill -0 "$p" 2>/dev/null && { any=1; break; }; done
        [ "$any" = 1 ] && sleep 1
    done
    for p in "${pids[@]}"; do
        kill -0 "$p" 2>/dev/null && { log "driver pid $p exceeded deadline, killing"; kill -TERM "$p" 2>/dev/null || true; }
        wait "$p" 2>/dev/null || true
    done
    for g in "${GENS[@]}"; do
        local rc; rc=$(cat "$OUTDIR/gen-$g.rc" 2>/dev/null || echo 1)
        [ "$rc" = 0 ] || GEN_RC[$g]=$rc
        normalise_gen "$g"
    done
}

# turn a driver's JSON stdout into gen-<N>.json with common fields.
# sent_pkts is always WIRE FRAMES: udpflood/frag report DATAGRAMS, and a
# datagram whose UDP payload exceeds mtu-28 is sent as ceil((payload+8)/(mtu-20))
# IP fragments (3 per 4000-byte datagram at MTU 1500). The datagram count is
# kept as sent_datagrams.
normalise_gen() {
    local g=$1 fpd=1 payload
    case "$KIND" in
        udpflood) payload=$(( PKT_SIZE - 42 )); [ "$payload" -lt 1 ] && payload=1 ;;
        frag)     payload=4000 ;;
        *)        payload=0 ;;
    esac
    if [ "$payload" -gt 0 ] && [ $(( payload + 8 )) -gt $(( MTU - 20 )) ]; then
        fpd=$(( (payload + 8 + (MTU - 20) - 1) / (MTU - 20) ))
    fi
    jq -n --arg gen "$g" --arg kind "$KIND" --argjson fpd "$fpd" \
          --slurpfile raw <(cat "$OUTDIR/gen-$g.raw" 2>/dev/null; echo) \
      '($raw[0] // {}) as $r
       | {gen:($gen|tonumber), kind:$kind,
          sent_pkts:(if $r.sent == null then null else ($r.sent * $fpd) end),
          sent_datagrams:($r.sent // null),
          frames_per_datagram:$fpd,
          sent_bytes:($r.bytes // null),
          seconds:($r.seconds // null),
          pps:(if $r.pps == null then null else ($r.pps * $fpd) end),
          errors:($r.errors // null),
          raw:$r}' > "$OUTDIR/gen-$g.json" 2>/dev/null \
      || echo "{\"gen\":$g,\"kind\":\"$KIND\",\"sent_pkts\":null,\"raw_error\":true,\"raw_text\":$(jq -Rs . < "$OUTDIR/gen-$g.raw" 2>/dev/null || echo '""')}" > "$OUTDIR/gen-$g.json"
}

# per-kind command builders (echo a shell command for `sh -c`)
DMAC=$(dst_mac "$DST"); DIP=$(dst_ip "$DST")
cmd_udpflood() { local pl=$(( PKT_SIZE - 42 )); [ "$pl" -lt 1 ] && pl=1
                 # --dst-mac/-i are only used by the -r (AF_PACKET flow-churn)
                 # path; harmless for the default connected-UDP path.
                 echo "$GEN_DIR/udpflood -d $DIP -p 9 -s $pl -t $THREADS -T $DURATION -i eth0 --dst-mac $DMAC $EXTRA"; }
cmd_frag()     { echo "$GEN_DIR/udpflood -d $DIP -p 9 -s 4000 -t $THREADS -T $DURATION $EXTRA"; }
cmd_synflood() { echo "$GEN_DIR/synflood -t $THREADS -T $DURATION $EXTRA"; }
cmd_http()     { echo "$GEN_DIR/http.sh --threads $THREADS --conns $CONNS --duration $DURATION --url '$URL' --keepalive $KEEPALIVE $EXTRA"; }
cmd_iperf()    { echo "$GEN_DIR/iperf.sh --threads $THREADS --duration $DURATION --port $((5200 + $1)) $EXTRA"; }
cmd_replay()   { echo "$GEN_DIR/replay.sh --duration $DURATION $EXTRA"; }

# ── step 5: baseline, start traffic, optional perf ──────────────────────────
sleep 3
TRAFFIC_ISSUE=$(now)
case "$KIND" in
    pktgen) start_pktgen ;;
esac
# traffic_start = every generator is running (pktgen: all `start`s returned;
# the others: the drivers are launched below within ~100 ms of each other)
TRAFFIC_START=$(now)
TRAFFIC_START_S=$(date +%s)
log "traffic start (kind=$KIND) at $TRAFFIC_START (issued $TRAFFIC_ISSUE)"

# perf: schedule at +${PERF_OFFSET}s (perf.sh blocks stat+1+record; run it detached)
PERF_STARTED=0
maybe_perf() {
    [ "$PERF" = true ] || return 0
    [ -n "$SNUF_PID" ] || return 0
    [ "$PERF_STARTED" = 0 ] || return 0
    [ $(( $(date +%s) - TRAFFIC_START_S )) -ge "$PERF_OFFSET" ] || return 0
    PERF_STARTED=1
    dexd sut sh -c "SNF_PERF_STAT_SECS=$PERF_STAT_SECS SNF_PERF_RECORD_SECS=$PERF_RECORD_SECS $SNF_DIR/perf.sh $SNUF_PID $COUT"
    log "perf.sh launched (pid=$SNUF_PID) at +${PERF_OFFSET}s (stat=${PERF_STAT_SECS}s record=${PERF_RECORD_SECS}s)"
}

case "$KIND" in
    pktgen)
        # pktgen runs until we stop it; sleep the duration, tick perf at +PERF_OFFSET
        local_end=$(( $(date +%s) + DURATION ))
        while [ "$(date +%s)" -lt "$local_end" ]; do
            maybe_perf
            sleep 1
        done
        TRAFFIC_END=$(now)          # steady state ends when the first stop is issued
        stop_pktgen
        ;;
    udpflood) run_concurrent cmd_udpflood ;;
    frag)     run_concurrent cmd_frag ;;
    synflood) run_concurrent cmd_synflood ;;
    http)     run_concurrent cmd_http ;;
    iperf)    run_concurrent cmd_iperf ;;
    replay)   run_concurrent cmd_replay ;;
    *) die "unknown traffic kind: $KIND" ;;
esac
[ -n "$TRAFFIC_END" ] || TRAFFIC_END=$(now)
[ -n "$TRAFFIC_STOPPED" ] || TRAFFIC_STOPPED=$TRAFFIC_END
log "traffic end at $TRAFFIC_END (all stopped $TRAFFIC_STOPPED)"

# if perf was requested but the run was too short to launch it, note it
if [ "$PERF" = true ] && [ "$PERF_STARTED" = 0 ]; then
    log "warning: perf requested but duration too short to reach +${PERF_OFFSET}s window"
fi
# let a detached perf.sh finish its record window (bounded)
if [ "$PERF_STARTED" = 1 ]; then
    for _ in $(seq 1 120); do
        dex sut pgrep -f 'perf record' >/dev/null 2>&1 || dex sut pgrep -f 'perf stat' >/dev/null 2>&1 || break
        sleep 1
    done
fi

# ── step 6: stop snuffles ───────────────────────────────────────────────────
sleep 2
log "stopping snuffles (SIGINT, up to 30 s)"
SNUF_STOPPED=1
dex sut "$SNF_DIR/run-snuffles.sh" stop "$COUT" > "$OUTDIR/.stop.json" 2>/dev/null || true
if [ -s "$OUTDIR/.stop.json" ]; then
    EXIT_CODE=$(jq -r '.exit_code // "null"' "$OUTDIR/.stop.json" 2>/dev/null); [ -z "$EXIT_CODE" ] && EXIT_CODE=null
    EXIT_LAT=$(jq -r '.exit_latency_ms // "null"' "$OUTDIR/.stop.json" 2>/dev/null); [ -z "$EXIT_LAT" ] && EXIT_LAT=null
    KILLED=$(jq -r '.killed // false' "$OUTDIR/.stop.json" 2>/dev/null); [ -z "$KILLED" ] && KILLED=false
    cp "$OUTDIR/.stop.json" "$OUTDIR/exit.json" 2>/dev/null || true
fi

# ── step 7: collect sink/telemetry, finalise status ─────────────────────────
if [ "$MODE" = syslog ] && have_role sink; then
    dex sink pkill -TERM -x udpsink 2>/dev/null || true
    for _ in $(seq 1 50); do [ -s "$OUTDIR/sink.json" ] && break; sleep 0.1; done
fi
dex sut pkill -TERM -f 'telemetry.sh' 2>/dev/null || true

# status: gen_failed if any driver returned non-zero, killed if snuffles was killed
if [ "$KILLED" = true ]; then
    STATUS=killed
elif [ "${#GEN_RC[@]}" -gt 0 ]; then
    STATUS=gen_failed
    log "gen failure(s): ${!GEN_RC[*]}"
else
    STATUS=ok
fi
log "[$NAME] done status=$STATUS"

# ── step 8: manifest, then analyze (single-scenario; tolerant + repeatable) ─
# Manifest MUST exist before analyze reads it (finalize also rewrites it, but
# on the happy path analyze needs the traffic-window epochs now).
write_manifest
if [ "${RS_NO_ANALYZE:-0}" != 1 ]; then
    python3 "$LT/analyze.py" "$RUN_ID" >/dev/null 2>&1 || log "analyze.py failed (non-fatal)"
fi
# finalize() runs on EXIT: it rewrites manifest + prints the summary line
exit 0
