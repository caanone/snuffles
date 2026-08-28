#!/usr/bin/env bash
# frag.sh — IP-fragment flood driver for the snuffles load-test rig.
#
#   frag.sh -d IP -p PORT -t THREADS -T SECONDS [-s SIZE]
#
# Thin wrapper over udpflood with a large UDP payload so every datagram is IP
# fragmented (default -s 4000 => 3 fragments per datagram at MTU 1500). Emits
# udpflood's JSON with the "tool" field rewritten to "frag".
set -euo pipefail

UDPFLOOD_BIN="${UDPFLOOD_BIN:-/opt/gen/udpflood}"
SIZE=4000
ARGS=()
DST=""
PORT=""
THREADS=2
SECS=10

die() { echo "frag.sh: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        -d) DST=$2; shift 2;;
        -p) PORT=$2; shift 2;;
        -t) THREADS=$2; shift 2;;
        -T) SECS=$2; shift 2;;
        -s) SIZE=$2; shift 2;;
        -r) ARGS+=(-r); shift;;
        *) die "unknown flag: $1";;
    esac
done

[ -n "$DST" ] || die "need -d IP"
[ -n "$PORT" ] || die "need -p PORT"
[ -x "$UDPFLOOD_BIN" ] || command -v "$UDPFLOOD_BIN" >/dev/null 2>&1 || die "udpflood not found ($UDPFLOOD_BIN)"

out=$("$UDPFLOOD_BIN" -d "$DST" -p "$PORT" -s "$SIZE" -t "$THREADS" -T "$SECS" "${ARGS[@]}")
# rewrite tool field udpflood -> frag
echo "$out" | sed 's/"tool":"udpflood"/"tool":"frag"/'
