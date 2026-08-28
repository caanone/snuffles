#!/usr/bin/env bash
# http.sh — wrk HTTP load driver for the snuffles load-test rig.
#
#   http.sh --host IP --threads N --conns N --duration S [--url /] \
#           [--keepalive true|false] [--extra "..."]
#
# Runs: wrk -t<threads> -c<conns> -d<duration>s [-H 'Connection: close'] \
#            http://<host><url>
# Emits one JSON object as its last stdout line:
#   {"tool":"http","requests":N,"seconds":F,"rps":F,"transfer_bps":N,
#    "bytes":N,"errors":N,"threads":N,"conns":N,"url":"...","keepalive":B}
set -euo pipefail

HOST=10.77.0.5
THREADS=4
CONNS=256
DURATION=10
URL="/"
KEEPALIVE=true
EXTRA=""
WRK_BIN="${WRK_BIN:-wrk}"

die() { echo "http.sh: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --host) HOST=$2; shift 2;;
        --threads) THREADS=$2; shift 2;;
        --conns) CONNS=$2; shift 2;;
        --duration) DURATION=$2; shift 2;;
        --url) URL=$2; shift 2;;
        --keepalive) KEEPALIVE=$2; shift 2;;
        --extra) EXTRA=$2; shift 2;;
        *) die "unknown flag: $1";;
    esac
done

command -v "$WRK_BIN" >/dev/null 2>&1 || die "wrk not found ($WRK_BIN)"

hdr=()
[ "$KEEPALIVE" = "false" ] && hdr=(-H 'Connection: close')

out=$("$WRK_BIN" -t"$THREADS" -c"$CONNS" -d"${DURATION}s" "${hdr[@]}" \
        ${EXTRA} "http://${HOST}${URL}" 2>&1) || die "wrk failed:
$out"

echo "$out" >&2

# parse wrk output -> JSON (transfer units are binary K/M/G per wrk)
echo "$out" | awk -v threads="$THREADS" -v conns="$CONNS" -v url="$URL" \
    -v ka="$KEEPALIVE" -v dur="$DURATION" '
    function tobytes(s,   n, u) {
        n = s + 0
        u = s; gsub(/[0-9.]/, "", u)
        if (u == "KB") return n * 1024
        if (u == "MB") return n * 1024 * 1024
        if (u == "GB") return n * 1024 * 1024 * 1024
        if (u == "TB") return n * 1024 * 1024 * 1024 * 1024
        return n
    }
    /requests in/ {
        # "  1234567 requests in 10.00s, 1.23GB read"
        for (i = 1; i <= NF; i++) {
            if ($i == "requests") reqs = $(i-1) + 0
            if ($i == "in") { sec = $(i+1); sub(/s,?$/, "", sec); seconds = sec + 0 }
        }
        # bytes read = token before "read"
        for (i = 1; i <= NF; i++) if ($i == "read") totbytes = tobytes($(i-1))
    }
    /^Requests\/sec:/ { rps = $2 + 0 }
    /^Transfer\/sec:/ { xfer = tobytes($2) }
    /Socket errors:/ {
        # "Socket errors: connect 0, read 0, write 0, timeout 0"
        for (i = 1; i <= NF; i++) {
            g = $i; gsub(/[^0-9]/, "", g)
            if ($i ~ /,$|[0-9]$/ && g != "") errsum += g + 0
        }
    }
    /Non-2xx or 3xx responses:/ { non2xx = $(NF) + 0 }
    END {
        if (seconds == 0) seconds = dur
        printf "{\"tool\":\"http\",\"requests\":%d,\"seconds\":%.2f,\"rps\":%.2f,\"transfer_bps\":%d,\"bytes\":%d,\"errors\":%d,\"non_2xx\":%d,\"threads\":%d,\"conns\":%d,\"url\":\"%s\",\"keepalive\":%s}\n",
               reqs+0, seconds, rps+0, xfer+0, totbytes+0, errsum+0, non2xx+0, threads, conns, url, (ka=="false"?"false":"true")
    }'
