#!/usr/bin/env bash
# iperf.sh — iperf3 TCP throughput driver for the snuffles load-test rig.
#
#   iperf.sh --host IP --threads N --duration S [--port 5201] [--extra "..."]
#
# Runs: iperf3 -c <host> -P <threads> -t <duration> -J
# Emits one JSON object as its last stdout line:
#   {"tool":"iperf","bits_per_second":F,"bytes":N,"seconds":F,
#    "retransmits":N,"recv_bits_per_second":F,"threads":N,"error":null|"..."}
set -euo pipefail

HOST=10.77.0.5
THREADS=1
DURATION=10
PORT=5201
EXTRA=""
IPERF_BIN="${IPERF_BIN:-iperf3}"

die() { echo "iperf.sh: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --host) HOST=$2; shift 2;;
        --threads) THREADS=$2; shift 2;;
        --duration) DURATION=$2; shift 2;;
        --port) PORT=$2; shift 2;;
        --extra) EXTRA=$2; shift 2;;
        *) die "unknown flag: $1";;
    esac
done

command -v "$IPERF_BIN" >/dev/null 2>&1 || die "iperf3 not found ($IPERF_BIN)"
command -v jq >/dev/null 2>&1 || die "jq not found"

# iperf3 exits non-zero on a server error but still prints JSON with .error
set +e
out=$("$IPERF_BIN" -c "$HOST" -p "$PORT" -P "$THREADS" -t "$DURATION" -J ${EXTRA} 2>/dev/null)
rc=$?
set -e

if [ -z "$out" ]; then
    printf '{"tool":"iperf","bits_per_second":0,"bytes":0,"seconds":0,"retransmits":0,"recv_bits_per_second":0,"threads":%d,"error":"no output (rc=%d)"}\n' "$THREADS" "$rc"
    exit 0
fi

echo "$out" | jq -c --argjson th "$THREADS" '
    {
        tool: "iperf",
        bits_per_second: (.end.sum_sent.bits_per_second // 0),
        bytes: (.end.sum_sent.bytes // 0),
        seconds: (.end.sum_sent.seconds // 0),
        retransmits: (.end.sum_sent.retransmits // 0),
        recv_bits_per_second: (.end.sum_received.bits_per_second // 0),
        threads: $th,
        error: (.error // null)
    }'
