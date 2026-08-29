#!/usr/bin/env bash
# loadtest/gate.sh — run the fixed regression-gate scenario set and compare the
# results against the committed baseline (loadtest/gate-baseline.json).
#
#   gate.sh [--run-id X] [--duration S] [--skip-ndr] [--only A,B]
#           [--baseline FILE] [--update-baseline]
#
#   --run-id X          results run-id (default gate-<timestamp>)
#   --duration S        traffic seconds per scenario / NDR trial (default 20)
#   --skip-ndr          do not run the NDR search (much faster; the ndr: row is
#                       then reported as "skip", which is not a failure)
#   --only A,B          run only these gate scenarios; the literal name "ndr"
#                       keeps the NDR step. Use it to re-run one scenario that
#                       looked anomalous (the host is shared).
#   --baseline FILE     compare against FILE instead of loadtest/gate-baseline.json
#   --update-baseline   REWRITE the baseline from this run instead of comparing.
#                       Never implied by anything else: updating the baseline
#                       must always be an explicit, deliberate act.
#
# Requires the rig to be up (loadtest/rig.sh up) with snuffles built in snf-sut.
#
# Scenarios are run from the committed scenario files with two overrides:
# `duration` = --duration and `perf` = false — perf stat/record runs on the SUT
# cpuset and adds run-to-run variance the gate does not want. Everything else
# (mode, packet size, offered rate, flows) is exactly the committed scenario.
#
# Metrics and tolerances (per SPEC "Measurement validity"): per scenario the
# steady-window `captured_pps` and `kdrop_pct_win` from summary.json; for the
# NDR row the `ndr_pps` and `confirm_kdrop_pct` from ndr.json. A scenario fails
# when its run status is not "ok", when captured_pps (or ndr_pps) is more than
# `captured_pps_drop_pct` (`ndr_pps_drop_pct`) percent BELOW baseline, or when
# kdrop_pct_win is more than `kdrop_pct_win_abs` points ABOVE baseline. Faster
# than baseline is never a failure. The tolerances live in the baseline file —
# `defaults` for all scenarios, an optional per-scenario `tolerance` object to
# override them — so a noisy scenario can be loosened without touching code.
# --update-baseline rewrites only the measured numbers and carries every
# existing per-scenario tolerance over unchanged; delete the file to reset them.
#
# Writes results/<run-id>/gate.json (measured, baseline, per-row verdicts) and
# appends a "## Regression gate" section to results/<run-id>/summary.md.
# Exit status: 0 all rows pass (or the baseline was updated), 1 a regression,
# 2 a usage/setup error.
set -euo pipefail

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
LT="$REPO/loadtest"
RESULTS="$LT/results"

# The gate set. Fixed on purpose: a gate whose scenario list drifts is not a
# gate. A2/A6 are the capture ceiling (single flow, 1 M flows), A3d is the
# loss-free 1 M pps point, B3/B6 are the two consumer paths that used to
# collapse under load (syslog forwarding, TUI).
GATE_SCENARIOS=(
    A2-pktgen64-8cpu-max
    A3d-pktgen64-8cpu-ratep-1m
    A6-pktgen64-8cpu-flows1m
    B3-syslog-1m
    B6-tui-1m
)
# NDR search: A-class 64 B traffic, loss-free criterion.
NDR_SCENARIO=A2-pktgen64-8cpu-max
NDR_LOSS=0

log() { printf 'gate: %s\n' "$*" >&2; }
die() { printf 'gate: ERROR: %s\n' "$*" >&2; exit 2; }

RUN_ID=""; DURATION=20; SKIP_NDR=0; UPDATE=0; ONLY=""; BASELINE="$LT/gate-baseline.json"
while [ $# -gt 0 ]; do
    case "$1" in
        --run-id)          RUN_ID=$2; shift 2 ;;
        --run-id=*)        RUN_ID=${1#*=}; shift ;;
        --duration)        DURATION=$2; shift 2 ;;
        --duration=*)      DURATION=${1#*=}; shift ;;
        --only)            ONLY=$2; shift 2 ;;
        --only=*)          ONLY=${1#*=}; shift ;;
        --baseline)        BASELINE=$2; shift 2 ;;
        --baseline=*)      BASELINE=${1#*=}; shift ;;
        --skip-ndr)        SKIP_NDR=1; shift ;;
        --update-baseline) UPDATE=1; shift ;;
        -h|--help)         sed -n '2,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//' | sed '$d'; exit 0 ;;
        *)                 die "unknown argument $1" ;;
    esac
done
[[ $DURATION =~ ^[0-9]+$ ]] && [ "$DURATION" -ge 5 ] || die "--duration must be an integer >= 5"
command -v jq >/dev/null || die "jq required"
command -v python3 >/dev/null || die "python3 required"
RUN_ID=${RUN_ID:-gate-$(date +%Y%m%d-%H%M%S)}
OUTDIR="$RESULTS/$RUN_ID"

# --only filter
declare -a RUN_SET=()
if [ -n "$ONLY" ]; then
    IFS=',' read -r -a _want <<<"$ONLY"
    for w in "${_want[@]}"; do
        [ "$w" = ndr ] && continue
        printf '%s\n' "${GATE_SCENARIOS[@]}" | grep -qx -- "$w" || die "--only: $w is not a gate scenario"
        RUN_SET+=("$w")
    done
    printf '%s\n' "${_want[@]}" | grep -qx ndr || SKIP_NDR=1
else
    RUN_SET=("${GATE_SCENARIOS[@]}")
fi

if [ "$UPDATE" = 1 ] && { [ -n "$ONLY" ] || [ "$SKIP_NDR" = 1 ]; }; then
    # A baseline written from a partial run would silently drop the rows that
    # were not measured, turning the next full gate run into "no baseline".
    die "--update-baseline needs a complete run (no --only, no --skip-ndr)"
fi
if [ "$UPDATE" != 1 ] && [ ! -f "$BASELINE" ]; then
    die "baseline not found: $BASELINE (create it with --update-baseline)"
fi

docker inspect -f '{{.State.Running}}' "${RIG_PREFIX:-snf-}sut" 2>/dev/null | grep -qx true \
    || die "${RIG_PREFIX:-snf-}sut is not running — bring the rig up first (loadtest/rig.sh up)"

mkdir -p "$OUTDIR"

log "run-id=$RUN_ID duration=${DURATION}s scenarios=${#RUN_SET[@]} ndr=$([ "$SKIP_NDR" = 1 ] && echo skip || echo "$NDR_SCENARIO") baseline=$BASELINE"

# ── run the gate scenarios ──────────────────────────────────────────────────
# RS_NO_ANALYZE=1: analyze once after the set, like matrix.sh. ndr.sh runs
# afterwards and appends its own section to the summary it regenerates.
for name in "${RUN_SET[@]}"; do
    scen="$LT/scenarios/$name.json"
    [ -f "$scen" ] || die "scenario file missing: $scen"
    tscen=$(mktemp "${TMPDIR:-/tmp}/gate-scen.XXXXXX.json")
    jq --argjson dur "$DURATION" '.duration=$dur | .perf=false' "$scen" > "$tscen"
    log "scenario $name (${DURATION}s)"
    RS_NO_ANALYZE=1 "$LT/run-scenario.sh" "$tscen" "$RUN_ID" \
        || log "  ($name exited non-zero; the summary it wrote is still read)"
    rm -f "$tscen"
done
python3 "$LT/analyze.py" "$RUN_ID" >/dev/null 2>&1 || log "analyze.py failed (rows may be missing)"

# ── NDR search on A-class 64 B traffic ──────────────────────────────────────
if [ "$SKIP_NDR" != 1 ]; then
    log "ndr search on $NDR_SCENARIO (loss<=${NDR_LOSS}%, trial/confirm ${DURATION}s)"
    "$LT/ndr.sh" "$LT/scenarios/$NDR_SCENARIO.json" --loss "$NDR_LOSS" \
        --trial "$DURATION" --confirm "$DURATION" --run-id "$RUN_ID" \
        || log "  (ndr.sh exited non-zero; ndr.json is read if it exists)"
fi

# ── collect the measured values ─────────────────────────────────────────────
MEASURED=$(jq -n --arg run "$RUN_ID" --argjson dur "$DURATION" \
    '{run_id:$run, duration:$dur, scenarios:{}}')
for name in "${RUN_SET[@]}"; do
    sj="$OUTDIR/$name/summary.json"
    if [ -s "$sj" ]; then
        MEASURED=$(jq --arg n "$name" --slurpfile s "$sj" \
            '.scenarios[$n] = {status: ($s[0].status // "missing"),
                               captured_pps: $s[0].captured_pps,
                               kdrop_pct_win: ($s[0].kdrop_pct_win // $s[0].kdrop_pct)}' <<<"$MEASURED")
    else
        MEASURED=$(jq --arg n "$name" '.scenarios[$n] = {status:"missing"}' <<<"$MEASURED")
    fi
done
if [ "$SKIP_NDR" != 1 ]; then
    nj="$OUTDIR/ndr.json"
    if [ -s "$nj" ]; then
        MEASURED=$(jq --arg n "ndr:$NDR_SCENARIO" --slurpfile s "$nj" \
            '.scenarios[$n] = {status:"ok", ndr_pps: $s[0].ndr_pps,
                               kdrop_pct_win: $s[0].confirm_kdrop_pct}' <<<"$MEASURED")
    else
        MEASURED=$(jq --arg n "ndr:$NDR_SCENARIO" '.scenarios[$n] = {status:"missing"}' <<<"$MEASURED")
    fi
fi

# ── update the baseline, or compare ─────────────────────────────────────────
DEFAULT_TOL='{"captured_pps_drop_pct":15,"ndr_pps_drop_pct":15,"kdrop_pct_win_abs":2}'

if [ "$UPDATE" = 1 ]; then
    bad=$(jq -r '[.scenarios | to_entries[] | select(.value.status != "ok") | .key] | join(", ")' <<<"$MEASURED")
    [ -z "$bad" ] || die "refusing to write a baseline from a run with failed scenarios: $bad"
    commit=$(git -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo unknown)
    # Only the MEASURED values are rewritten: an existing per-scenario tolerance
    # is carried over verbatim, so a tolerance someone widened on purpose is not
    # silently reset by a routine baseline refresh. Delete the file to start over.
    [ -f "$BASELINE" ] && cp -f "$BASELINE" "$BASELINE.prev" || echo '{}' > "$BASELINE.prev"
    jq --argjson tol "$DEFAULT_TOL" --arg when "$(date -Is)" --arg host "$(hostname)" \
       --arg commit "$commit" --slurpfile prev "$BASELINE.prev" \
       '($prev[0].scenarios // {}) as $old
        | {generated:$when, host:$host, commit:$commit, duration:.duration,
         run_id:.run_id, defaults:$tol,
         scenarios: (.scenarios | with_entries(
            .key as $k
            | .value = ({} + (if .value.captured_pps  != null then {captured_pps:  (.value.captured_pps|round)}  else {} end)
                         + (if .value.ndr_pps       != null then {ndr_pps:       (.value.ndr_pps|round)}       else {} end)
                         + (if .value.kdrop_pct_win != null then {kdrop_pct_win: .value.kdrop_pct_win}         else {} end)
                         + {tolerance: ($old[$k].tolerance //
                                        (if .value.ndr_pps != null
                                         then {ndr_pps_drop_pct: $tol.ndr_pps_drop_pct, kdrop_pct_win_abs: $tol.kdrop_pct_win_abs}
                                         else {captured_pps_drop_pct: $tol.captured_pps_drop_pct, kdrop_pct_win_abs: $tol.kdrop_pct_win_abs} end))})))}' <<<"$MEASURED" > "$BASELINE.tmp"
    rm -f "$BASELINE.prev"
    mv -f "$BASELINE.tmp" "$BASELINE"
    log "baseline written: $BASELINE"
    jq . "$BASELINE"
    exit 0
fi

# The comparison. One row per baseline-or-measured scenario; a row fails when
# the run did not finish ok, when a rate is below its floor, or when the kernel
# drop percentage is above its ceiling.
jq -n --slurpfile b "$BASELINE" --argjson m "$MEASURED" --argjson dtol "$DEFAULT_TOL" '
  ($b[0]) as $base
  | ($base.defaults // {}) as $bd
  | (($base.scenarios // {}) | keys) as $bk
  | ($m.scenarios | keys) as $mk
  | (($bk + $mk) | unique) as $names
  | { run_id: $m.run_id, duration: $m.duration, baseline_file_generated: $base.generated,
      baseline_commit: $base.commit,
      rows: [ $names[] as $n
        | ($base.scenarios[$n]) as $bs
        | ($m.scenarios[$n]) as $ms
        | (($bs.tolerance // {}) as $t
           | { captured_pps_drop_pct: ($t.captured_pps_drop_pct // $bd.captured_pps_drop_pct // $dtol.captured_pps_drop_pct),
               ndr_pps_drop_pct:      ($t.ndr_pps_drop_pct      // $bd.ndr_pps_drop_pct      // $dtol.ndr_pps_drop_pct),
               kdrop_pct_win_abs:     ($t.kdrop_pct_win_abs     // $bd.kdrop_pct_win_abs     // $dtol.kdrop_pct_win_abs) }) as $tol
        | (if $bs.ndr_pps != null then "ndr_pps" else "captured_pps" end) as $ratek
        | ($bs[$ratek]) as $brate
        | (if $ms == null then null else $ms[$ratek] end) as $mrate
        | (if $ratek == "ndr_pps" then $tol.ndr_pps_drop_pct else $tol.captured_pps_drop_pct end) as $droppct
        | (if $brate == null then null else ($brate * (1 - $droppct/100)) end) as $ratefloor
        | (if $bs.kdrop_pct_win == null then null else ($bs.kdrop_pct_win + $tol.kdrop_pct_win_abs) end) as $kceil
        | ([ (if $ms == null then "not run (skipped)" else empty end),
             (if $bs == null then "not in baseline" else empty end),
             (if $ms != null and $ms.status != "ok" then "status=\($ms.status)" else empty end),
             (if $mrate == null and $ms != null and $ms.status == "ok" and $brate != null then "no \($ratek) measured" else empty end),
             (if $ratefloor != null and $mrate != null and $mrate < $ratefloor
                then "\($ratek) \($mrate|round) < floor \($ratefloor|round) (-\($droppct)%)" else empty end),
             (if $kceil != null and ($ms.kdrop_pct_win // null) != null and $ms.kdrop_pct_win > $kceil
                then "kdrop_pct_win \($ms.kdrop_pct_win) > ceiling \($kceil)" else empty end)
           ]) as $notes
        | (if $ms == null and $bs != null then "skip"
           elif ($notes | length) > 0 then "FAIL" else "pass" end) as $verdict
        | { name: $n, metric: $ratek, verdict: $verdict,
            baseline_rate: $brate, measured_rate: $mrate, rate_floor: $ratefloor,
            rate_delta_pct: (if $brate != null and $mrate != null and $brate > 0
                             then ((($mrate - $brate) / $brate) * 1000 | round / 10 | if . == 0 then 0 else . end) else null end),
            baseline_kdrop: $bs.kdrop_pct_win, measured_kdrop: (if $ms == null then null else $ms.kdrop_pct_win end),
            kdrop_ceiling: $kceil, tolerance: $tol, notes: ($notes | join("; ")) } ]
    }
  | . + { failed: [.rows[] | select(.verdict == "FAIL") | .name],
          passed: [.rows[] | select(.verdict == "pass") | .name],
          skipped: [.rows[] | select(.verdict == "skip") | .name] }
  | . + { result: (if (.failed | length) > 0 then "FAIL" else "PASS" end) }
' > "$OUTDIR/gate.json"

# ── render ──────────────────────────────────────────────────────────────────
render() {
    printf '%-30s %-13s %12s %12s %8s %9s %9s %-7s %s\n' \
        scenario metric baseline measured 'delta%' 'kdrop b' 'kdrop m' verdict notes
    jq -r '.rows[] | [ .name, .metric,
        (if .baseline_rate == null then "-" else (.baseline_rate|round|tostring) end),
        (if .measured_rate == null then "-" else (.measured_rate|round|tostring) end),
        (if .rate_delta_pct == null then "-" else ((if .rate_delta_pct >= 0 then "+" else "" end) + (.rate_delta_pct|tostring)) end),
        (if .baseline_kdrop == null then "-" else (.baseline_kdrop|tostring) end),
        (if .measured_kdrop == null then "-" else (.measured_kdrop|tostring) end),
        .verdict, .notes ] | @tsv' "$OUTDIR/gate.json" \
    | while IFS=$'\t' read -r n me b m d kb km v no; do
        printf '%-30s %-13s %12s %12s %8s %9s %9s %-7s %s\n' "$n" "$me" "$b" "$m" "$d" "$kb" "$km" "$v" "$no"
      done
    printf '\nresult: %s   (%s passed, %s failed, %s skipped)\n' \
        "$(jq -r .result "$OUTDIR/gate.json")" \
        "$(jq -r '.passed|length' "$OUTDIR/gate.json")" \
        "$(jq -r '.failed|length' "$OUTDIR/gate.json")" \
        "$(jq -r '.skipped|length' "$OUTDIR/gate.json")"
}

echo
render | tee "$OUTDIR/gate.txt"
echo
log "wrote $OUTDIR/gate.json and $OUTDIR/gate.txt"

# append to summary.md so the uploaded artefact carries the verdict
{
    echo ""
    echo "## Regression gate — \`$RUN_ID\`"
    echo ""
    echo "Baseline: \`$(basename "$BASELINE")\` (generated $(jq -r '.generated // "?"' "$BASELINE"), commit \`$(jq -r '.commit // "?"' "$BASELINE")\`); duration ${DURATION}s."
    echo ""
    echo '```'
    cat "$OUTDIR/gate.txt"
    echo '```'
} >> "$OUTDIR/summary.md" 2>/dev/null || log "warning: could not append to summary.md"

[ "$(jq -r .result "$OUTDIR/gate.json")" = PASS ] || exit 1
exit 0
