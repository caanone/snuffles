#!/usr/bin/env bash
# replay.sh — tcpreplay corpus driver for the snuffles load-test rig.
#
#   replay.sh -i IFACE --duration S [--pcap /opt/gen/corpus.pcap] [--mbps N]
#
# tcpreplay's --duration is not available in every build, so we loop the
# preloaded corpus forever at top speed and kill it after <duration> seconds,
# then parse the final "Actual:" / "Rated:" stats.
#   tcpreplay -i IFACE -K --loop=0 --topspeed --stats=1 <pcap>
# --mbps N (optional) replaces --topspeed with a rate cap (tcpreplay --mbps).
# --unique-ip (optional) adds tcpreplay --unique-ip: each loop iteration rewrites
#   the source/destination IPs so the corpus churns unique flows (real 5-tuple
#   turnover through a fixed corpus, for the session-table stress scenario).
# Emits one JSON object as its last stdout line:
#   {"tool":"replay","sent":N,"bytes":N,"seconds":F,"pps":F,"mbps":F,
#    "loops":N,"pcap":"..."}
set -euo pipefail

IFACE=eth0
DURATION=10
PCAP="${PCAP:-/opt/gen/corpus.pcap}"
MBPS=""
UNIQUE_IP=0
TR_BIN="${TCPREPLAY_BIN:-tcpreplay}"

die() { echo "replay.sh: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        -i|--iface) IFACE=$2; shift 2;;
        --duration) DURATION=$2; shift 2;;
        --pcap) PCAP=$2; shift 2;;
        --mbps) MBPS=$2; shift 2;;
        --unique-ip) UNIQUE_IP=1; shift;;
        *) die "unknown flag: $1";;
    esac
done

command -v "$TR_BIN" >/dev/null 2>&1 || die "tcpreplay not found ($TR_BIN)"
[ -r "$PCAP" ] || die "corpus not readable: $PCAP"

rate=(--topspeed)
[ -n "$MBPS" ] && rate=(--mbps="$MBPS")

extra=()
[ "$UNIQUE_IP" = 1 ] && extra+=(--unique-ip)

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

# run tcpreplay in the background, looping forever, then stop it after DURATION
"$TR_BIN" -i "$IFACE" -K --loop=0 "${rate[@]}" "${extra[@]}" --stats=1 "$PCAP" \
    >"$tmp" 2>&1 &
pid=$!

# let it run, then request a clean stop (tcpreplay prints Actual/Rated on TERM)
sleep "$DURATION"
kill -INT "$pid" 2>/dev/null || true
for _ in $(seq 1 20); do
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.1
done
kill -TERM "$pid" 2>/dev/null || true
wait "$pid" 2>/dev/null || true

cat "$tmp" >&2

# parse tcpreplay stats. "Actual:" is the authoritative final summary; if it is
# absent (killed mid-flight on some builds) fall back to the last periodic line.
awk -v dur="$DURATION" -v pcap="$PCAP" '
    function num(s) { gsub(/[^0-9.]/, "", s); return s + 0 }
    # "Actual: 830508 packets (395168184 bytes) sent in 1.81 seconds"
    # (repeated by --stats; the last one is the final cumulative total)
    /Actual:/ && /packets/ && /bytes/ {
        for (i = 1; i <= NF; i++) {
            if ($i == "packets") sent = num($(i-1))
            if ($i ~ /^\(/)      bytes = num($i)
            if ($i == "in")      seconds = num($(i+1))
        }
        have_actual = 1
    }
    # periodic fallback when no Actual line was emitted
    !have_actual && /packets/ && /bytes/ && /sent in/ {
        for (i = 1; i <= NF; i++) {
            if ($i == "packets") sent = num($(i-1))
            if ($i ~ /^\(/)      bytes = num($i)
            if ($i == "in")      seconds = num($(i+1))
        }
    }
    # "Rated: 217497152.5 Bps, 1739.97 Mbps, 457104.42 pps"
    /Rated:/ {
        for (i = 1; i <= NF; i++) {
            if ($i ~ /^pps/)  pps = num($(i-1))
            if ($i ~ /^Mbps/) mbps = num($(i-1))
        }
    }
    /Successful packets:/ { for (i=1;i<=NF;i++) if ($i=="packets:") sent2 = num($(i+1)) }
    END {
        if (sent == 0 && sent2 > 0) sent = sent2
        if (seconds == 0) seconds = dur
        if (pps == 0 && seconds > 0) pps = sent / seconds
        if (mbps == 0 && seconds > 0) mbps = bytes * 8 / 1e6 / seconds
        printf "{\"tool\":\"replay\",\"sent\":%d,\"bytes\":%d,\"seconds\":%.3f,\"pps\":%.1f,\"mbps\":%.2f,\"pcap\":\"%s\"}\n",
               sent+0, bytes+0, seconds, pps, mbps, pcap
    }' "$tmp"
