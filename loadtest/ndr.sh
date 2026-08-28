#!/usr/bin/env bash
# loadtest/ndr.sh <scenario.json> [options]
#
# RFC 2544-style "no-drop rate" search for a pktgen scenario: find the highest
# offered rate snuffles sustains with kernel drops <= the loss criterion over the
# steady-state window.
#
#   --loss 0|0.1     loss criterion, percent kdrop_pct_win (default 0)
#   --precision P    stop when the search bracket is within P percent (default 2)
#   --trial S        trial duration, seconds (default 20)
#   --confirm S      confirmation-run duration, seconds (default 60)
#   --run-id X       results run-id (default ndr-<timestamp>)
#
# Method (all rates are the pktgen per-thread `ratep`; the aggregate offered rate
# is per-thread x number of pktgen CPUs):
#   1. one UNLIMITED trial (pps=0) to measure the ceiling the generator can push.
#      If it already sustains the loss criterion, the NDR is the ceiling.
#   2. otherwise binary-search the per-thread ratep in [0, ceiling/threads],
#      running one --trial-second trial per step, until the bracket is within
#      --precision percent.
#   3. one --confirm-second run at the found rate.
#
# A trial is "sustained" when its steady-window kdrop_pct_win <= --loss. Each
# trial is a normal run-scenario.sh run (its own results dir, preserved), so the
# telemetry / perf / accounting of every step is on disk.
#
# Writes results/<run-id>/ndr.json:
#   {scenario, loss_criterion, threads, ceiling_offered_pps, ndr_ratep_per_thread,
#    ndr_pps, confirm_kdrop_pct, confirm_offered_pps, iterations:[...]}
# and appends an "## NDR" section to results/<run-id>/summary.md.
set -euo pipefail

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
LT="$REPO/loadtest"
RESULTS="$LT/results"

log() { printf 'ndr: %s\n' "$*" >&2; }
die() { printf 'ndr: ERROR: %s\n' "$*" >&2; exit 1; }

SCEN=""; LOSS=0; PRECISION=2; TRIAL=20; CONFIRM=60; RUN_ID=""
while [ $# -gt 0 ]; do
    case "$1" in
        --loss)      LOSS=$2; shift 2 ;;
        --loss=*)    LOSS=${1#*=}; shift ;;
        --precision) PRECISION=$2; shift 2 ;;
        --precision=*) PRECISION=${1#*=}; shift ;;
        --trial)     TRIAL=$2; shift 2 ;;
        --trial=*)   TRIAL=${1#*=}; shift ;;
        --confirm)   CONFIRM=$2; shift 2 ;;
        --confirm=*) CONFIRM=${1#*=}; shift ;;
        --run-id)    RUN_ID=$2; shift 2 ;;
        --run-id=*)  RUN_ID=${1#*=}; shift ;;
        -*)          die "unknown flag $1" ;;
        *)           [ -z "$SCEN" ] && SCEN=$1 || die "extra arg $1"; shift ;;
    esac
done
[ -n "$SCEN" ] || die "usage: ndr.sh <scenario.json> [--loss 0|0.1] [--precision 2] [--trial 20] [--confirm 60] [--run-id X]"
[ -f "$SCEN" ] || die "scenario not found: $SCEN"
command -v jq >/dev/null || die "jq required"

NAME=$(jq -r '.name // empty' "$SCEN"); [ -n "$NAME" ] || die "scenario has no .name"
KIND=$(jq -r '.traffic.kind // "pktgen"' "$SCEN")
[ "$KIND" = pktgen ] || die "ndr.sh only supports pktgen scenarios (got kind=$KIND)"
THREADS=$(jq -r '(.traffic.cpus // [4,5,6,7,12,13,14,15]) | length' "$SCEN")
[ "$THREADS" -ge 1 ] || die "scenario has no pktgen cpus"
RUN_ID=${RUN_ID:-ndr-$(date +%Y%m%d-%H%M%S)}
mkdir -p "$RESULTS/$RUN_ID"

log "scenario=$NAME threads=$THREADS loss<=$LOSS% precision=$PRECISION% trial=${TRIAL}s confirm=${CONFIRM}s run-id=$RUN_ID"

# float helpers (awk; bash has no floats)
# fle A B -> exit 0 if A <= B
fle() { awk -v a="$1" -v b="$2" 'BEGIN{exit !(a<=b)}'; }
fdiv_pct() { awk -v a="$1" -v b="$2" 'BEGIN{ if(b>0) printf "%.4f", 100*a/b; else printf "0" }'; }

ITER_JSON="[]"     # accumulated iteration objects

# run_trial <ratep_per_thread> <secs> <label> : runs one scenario, sets globals
#   T_KDROP  steady-window kdrop_pct_win (falls back to whole-run kdrop_pct)
#   T_OFFER  offered_pps_win (aggregate)
#   T_CAP    captured_pps
#   T_SUSTAIN 1 if kdrop <= LOSS else 0
run_trial() {
    local ratep=$1 secs=$2 label=$3
    local tname="${NAME}-ndr-${label}"
    local tscen; tscen=$(mktemp "${TMPDIR:-/tmp}/ndr-scen.XXXXXX.json")
    jq --argjson pps "$ratep" --argjson dur "$secs" --arg nm "$tname" \
       '.name=$nm | .duration=$dur | .perf=false | .traffic.pps=$pps' "$SCEN" > "$tscen"
    log "trial $label: ratep=$ratep/thread secs=$secs -> $tname"
    RS_NO_ANALYZE=0 "$LT/run-scenario.sh" "$tscen" "$RUN_ID" >/dev/null 2>&1 || \
        log "  (run-scenario returned non-zero; reading whatever summary exists)"
    rm -f "$tscen"
    local sj="$RESULTS/$RUN_ID/$tname/summary.json"
    T_KDROP=""; T_OFFER=""; T_CAP=""
    if [ -s "$sj" ]; then
        T_KDROP=$(jq -r '(.kdrop_pct_win // .kdrop_pct // empty)' "$sj")
        T_OFFER=$(jq -r '(.offered_pps_win // empty)' "$sj")
        T_CAP=$(jq -r '(.captured_pps // empty)' "$sj")
    fi
    [ -n "$T_KDROP" ] || T_KDROP=100        # no data => treat as heavy drop
    [ -n "$T_OFFER" ] || T_OFFER=0
    [ -n "$T_CAP" ] || T_CAP=0
    if fle "$T_KDROP" "$LOSS"; then T_SUSTAIN=1; else T_SUSTAIN=0; fi
    log "  kdrop_win=$T_KDROP% offered=$T_OFFER pps captured=$T_CAP pps sustained=$T_SUSTAIN"
    # record the iteration
    ITER_JSON=$(jq -c \
        --argjson r "$ratep" --arg k "$T_KDROP" --arg o "$T_OFFER" --arg c "$T_CAP" \
        --argjson s "$T_SUSTAIN" --arg lbl "$label" --argjson secs "$secs" \
        '. += [{label:$lbl, ratep_per_thread:$r, secs:$secs,
                offered_pps_win:($o|tonumber), captured_pps:($c|tonumber),
                kdrop_pct_win:($k|tonumber), sustained:($s==1)}]' <<<"$ITER_JSON")
}

# ── 1. ceiling (unlimited) ───────────────────────────────────────────────────
run_trial 0 "$TRIAL" "ceil"
CEIL_OFFER=$T_OFFER
awk -v c="$CEIL_OFFER" 'BEGIN{exit !(c>0)}' || die "ceiling run produced no offered rate (is the rig up?)"
PER_THREAD_HI=$(awk -v o="$CEIL_OFFER" -v t="$THREADS" 'BEGIN{printf "%d", o/t}')

NDR_RATEP=0          # 0 = unlimited (ceiling sustains)
NDR_IS_CEIL=0
if [ "$T_SUSTAIN" = 1 ]; then
    log "ceiling sustains loss<=$LOSS%: NDR is the ceiling ($CEIL_OFFER pps)"
    NDR_IS_CEIL=1
    NDR_RATEP=0
else
    # ── 2. binary search on per-thread ratep ─────────────────────────────────
    lo=0; hi=$PER_THREAD_HI; best=0
    step=0
    while [ "$hi" -gt "$((lo+1))" ]; do
        # stop when the bracket is within PRECISION percent of hi
        local_width=$(fdiv_pct "$((hi-lo))" "$hi")
        fle "$local_width" "$PRECISION" && { log "bracket width ${local_width}% <= ${PRECISION}%, stop"; break; }
        step=$((step+1))
        [ "$step" -gt 24 ] && { log "iteration cap reached"; break; }
        mid=$(( (lo+hi) / 2 ))
        run_trial "$mid" "$TRIAL" "s${step}-${mid}"
        if [ "$T_SUSTAIN" = 1 ]; then
            lo=$mid; best=$mid
        else
            hi=$mid
        fi
    done
    NDR_RATEP=$best
    log "search done: highest sustaining per-thread ratep = $NDR_RATEP (bracket [$lo,$hi])"
fi

# ── 3. confirmation run ──────────────────────────────────────────────────────
if [ "$NDR_IS_CEIL" = 1 ]; then
    run_trial 0 "$CONFIRM" "confirm"
else
    if [ "$NDR_RATEP" -le 0 ]; then
        log "WARNING: no positive rate sustained the loss criterion; confirming at the lowest tried rate"
    fi
    run_trial "$NDR_RATEP" "$CONFIRM" "confirm"
fi
CONFIRM_KDROP=$T_KDROP
CONFIRM_OFFER=$T_OFFER
NDR_PPS=$CONFIRM_OFFER

# ── write ndr.json ───────────────────────────────────────────────────────────
jq -n \
    --arg scen "$NAME" --argjson loss "$LOSS" --argjson threads "$THREADS" \
    --arg ceil "$CEIL_OFFER" --argjson ndr_ratep "$NDR_RATEP" \
    --arg ndr_pps "$NDR_PPS" --arg ck "$CONFIRM_KDROP" --arg co "$CONFIRM_OFFER" \
    --argjson is_ceil "$([ "$NDR_IS_CEIL" = 1 ] && echo true || echo false)" \
    --argjson iters "$ITER_JSON" \
    '{scenario:$scen, loss_criterion:$loss, threads:$threads,
      ceiling_offered_pps:($ceil|tonumber),
      ndr_is_ceiling:$is_ceil,
      ndr_ratep_per_thread:$ndr_ratep,
      ndr_pps:($ndr_pps|tonumber),
      confirm_offered_pps:($co|tonumber),
      confirm_kdrop_pct:($ck|tonumber),
      iterations:$iters}' > "$RESULTS/$RUN_ID/ndr.json"
log "wrote $RESULTS/$RUN_ID/ndr.json  (ndr_pps=$NDR_PPS confirm_kdrop=$CONFIRM_KDROP%)"

# ── append a line/section to summary.md (analyze.py wrote the trial table) ──
SM="$RESULTS/$RUN_ID/summary.md"
{
    echo ""
    echo "## NDR search — \`$NAME\`"
    echo ""
    echo "- loss criterion: kdrop_pct_win <= **$LOSS%**  (threads: $THREADS, trial ${TRIAL}s, confirm ${CONFIRM}s)"
    echo "- ceiling offered: **$(printf '%.0f' "$CEIL_OFFER") pps** (unlimited run)"
    if [ "$NDR_IS_CEIL" = 1 ]; then
        echo "- **NDR = ceiling** (sustained at the max offered rate)"
    else
        echo "- NDR per-thread ratep: **$NDR_RATEP**"
    fi
    echo "- **NDR (confirmed): $(printf '%.0f' "$NDR_PPS") pps** at confirm kdrop_pct_win **$CONFIRM_KDROP%**"
    echo "- iterations: $(jq '.iterations | length' "$RESULTS/$RUN_ID/ndr.json") (see ndr.json)"
} >> "$SM" 2>/dev/null || log "warning: could not append to $SM"

log "done."
