#!/usr/bin/env bash
# loadtest/matrix.sh <run-id> <scenario.json...>
#
# Run many scenarios sequentially under ONE run-id, continue past failures, and
# call analyze.py once at the end so summary.csv/summary.md cover the whole run.
# Each scenario's own manifest/summary.json is still written by run-scenario.sh.
#
# Example:
#   loadtest/matrix.sh nightly loadtest/scenarios/A*.json
#   loadtest/matrix.sh smoke   loadtest/scenarios/S0-smoke.json
set -euo pipefail

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
LT="$REPO/loadtest"

[ $# -ge 2 ] || { echo "usage: matrix.sh <run-id> <scenario.json...>" >&2; exit 2; }
RUN_ID=$1; shift

echo "matrix: run-id=$RUN_ID  scenarios=$#"
declare -a NAMES=() STATES=()
i=0
for scen in "$@"; do
    i=$((i+1))
    if [ ! -f "$scen" ]; then
        echo "matrix: [$i/$#] SKIP (missing) $scen" >&2
        NAMES+=("$(basename "$scen" .json)"); STATES+=("missing")
        continue
    fi
    name=$(jq -r '.name // empty' "$scen" 2>/dev/null || basename "$scen" .json)
    echo "matrix: [$i/$#] $name"
    # RS_NO_ANALYZE: analyze once at the end, not after every scenario
    if RS_NO_ANALYZE=1 "$LT/run-scenario.sh" "$scen" "$RUN_ID"; then
        st=$(jq -r '.status // "unknown"' "$LT/results/$RUN_ID/$name/manifest.json" 2>/dev/null || echo unknown)
    else
        st=$(jq -r '.status // "failed"' "$LT/results/$RUN_ID/$name/manifest.json" 2>/dev/null || echo failed)
        echo "matrix: [$i/$#] $name exited non-zero (status=$st), continuing" >&2
    fi
    NAMES+=("$name"); STATES+=("$st")
done

echo "matrix: analyzing run $RUN_ID"
python3 "$LT/analyze.py" "$RUN_ID" || echo "matrix: analyze.py failed" >&2

echo "matrix: results:"
for j in "${!NAMES[@]}"; do
    printf '  %-40s %s\n' "${NAMES[$j]}" "${STATES[$j]}"
done
echo "matrix: summary -> $LT/results/$RUN_ID/summary.md"
