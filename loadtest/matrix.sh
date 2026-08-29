#!/usr/bin/env bash
# loadtest/matrix.sh [--repeat N] <run-id> <scenario.json...>
#
# Run many scenarios sequentially under ONE run-id, continue past failures, and
# call analyze.py once at the end so summary.csv/summary.md cover the whole run.
# Each scenario's own manifest/summary.json is still written by run-scenario.sh.
#
#   --repeat N   run each scenario N times; the repeats are named <scenario>-r1
#                .. <scenario>-rN (distinct results dirs) and analyze.py then
#                also writes summary-median.md, one row per base scenario with
#                the median/min/max of captured_pps and kdrop_pct_win. N=1
#                (default) keeps the original names and writes no median table.
#
# Example:
#   loadtest/matrix.sh nightly loadtest/scenarios/A*.json
#   loadtest/matrix.sh --repeat 5 spread loadtest/scenarios/A2-pktgen64-8cpu-max.json
#   loadtest/matrix.sh smoke   loadtest/scenarios/S0-smoke.json
set -euo pipefail

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
LT="$REPO/loadtest"

REPEAT=1
declare -a POS=()
while [ $# -gt 0 ]; do
    case "$1" in
        --repeat)   REPEAT=$2; shift 2 ;;
        --repeat=*) REPEAT=${1#*=}; shift ;;
        *)          POS+=("$1"); shift ;;
    esac
done
set -- "${POS[@]}"
[ $# -ge 2 ] || { echo "usage: matrix.sh [--repeat N] <run-id> <scenario.json...>" >&2; exit 2; }
[[ $REPEAT =~ ^[0-9]+$ ]] && [ "$REPEAT" -ge 1 ] || { echo "matrix: --repeat must be a positive integer" >&2; exit 2; }
RUN_ID=$1; shift

echo "matrix: run-id=$RUN_ID  scenarios=$#  repeat=$REPEAT"
declare -a NAMES=() STATES=()

# run_one <scenario-file> <run-name> : run one scenario under $RUN_ID, possibly
# renamed to <run-name>; record status. A rename generates a temp scenario whose
# .name is <run-name> so run-scenario.sh writes to results/<run-id>/<run-name>/.
run_one() {
    local scen=$1 runname=$2 base status tscen
    base=$(jq -r '.name // empty' "$scen" 2>/dev/null || basename "$scen" .json)
    if [ "$runname" = "$base" ]; then
        tscen=$scen
    else
        tscen=$(mktemp "${TMPDIR:-/tmp}/matrix-scen.XXXXXX.json")
        jq --arg nm "$runname" '.name=$nm' "$scen" > "$tscen"
    fi
    # RS_NO_ANALYZE: analyze once at the end, not after every scenario
    if RS_NO_ANALYZE=1 "$LT/run-scenario.sh" "$tscen" "$RUN_ID"; then
        status=$(jq -r '.status // "unknown"' "$LT/results/$RUN_ID/$runname/manifest.json" 2>/dev/null || echo unknown)
    else
        status=$(jq -r '.status // "failed"' "$LT/results/$RUN_ID/$runname/manifest.json" 2>/dev/null || echo failed)
        echo "matrix: $runname exited non-zero (status=$status), continuing" >&2
    fi
    [ "$tscen" = "$scen" ] || rm -f "$tscen"
    NAMES+=("$runname"); STATES+=("$status")
}

i=0
for scen in "$@"; do
    i=$((i+1))
    if [ ! -f "$scen" ]; then
        echo "matrix: [$i/$#] SKIP (missing) $scen" >&2
        NAMES+=("$(basename "$scen" .json)"); STATES+=("missing")
        continue
    fi
    name=$(jq -r '.name // empty' "$scen" 2>/dev/null || basename "$scen" .json)
    if [ "$REPEAT" -eq 1 ]; then
        echo "matrix: [$i/$#] $name"
        run_one "$scen" "$name"
    else
        for r in $(seq 1 "$REPEAT"); do
            echo "matrix: [$i/$#] $name (repeat $r/$REPEAT)"
            run_one "$scen" "${name}-r${r}"
        done
    fi
done

echo "matrix: analyzing run $RUN_ID"
python3 "$LT/analyze.py" "$RUN_ID" || echo "matrix: analyze.py failed" >&2

echo "matrix: results:"
for j in "${!NAMES[@]}"; do
    printf '  %-44s %s\n' "${NAMES[$j]}" "${STATES[$j]}"
done
echo "matrix: summary -> $LT/results/$RUN_ID/summary.md"
[ "$REPEAT" -gt 1 ] && [ -f "$LT/results/$RUN_ID/summary-median.md" ] && \
    echo "matrix: median   -> $LT/results/$RUN_ID/summary-median.md"
exit 0
