#!/usr/bin/env bash
# pktgen.sh — in-kernel pktgen driver for the snuffles load-test rig.
#
# Subcommands (SPEC contract):
#   start   program kpktgend_<cpu> + device, write "start" to pgctrl in the
#           background and return immediately (count 0 => runs until stop)
#   stop    write "stop" to pgctrl (counters are only final after this)
#   reset   write "reset" to pgctrl (clear devices + counters)
#   result  parse /proc/net/pktgen/<dev>@<cpu> for each cpu into one JSON object
#   run     convenience: start; sleep --secs; stop; result   (self-terminating)
#
# Flags (all subcommands accept the ones they need):
#   -d DEV            device (default eth0)
#   --cpus a,b,c      kpktgend CPUs to program (default 0)
#   --size N          wire size incl. Ethernet+FCS (pkt_size = N-4; default 64).
#                     May be a comma list mapped positionally onto --cpus for a
#                     per-thread size mix (IMIX), e.g. --cpus 4,5,6 --size
#                     64,570,1518; a single value applies to every cpu.
#   --dst-mac MAC     destination MAC
#   --dst-ip  IP      destination IP
#   --pps N           per-thread rate (0 = unlimited; sets ratep when >0). Like
#                     --size, may be a comma list mapped onto --cpus (per-thread
#                     rate weighting for IMIX); a single value applies to all.
#   --flows N         1 = fixed 5-tuple; N>1 => IPSRC_RND+UDPSRC_RND over N srcs
#   --src-ip IP       source IP when flows==1 (default 10.77.0.11)
#   --clone N         clone_skb (default 1000)
#   --secs N          run subcommand only: seconds of traffic (default 10)
#
# pktgen is per-netns: run this inside the generator container's netns; it
# programs that netns's /proc/net/pktgen/ and its own device.
set -euo pipefail

PG=/proc/net/pktgen

DEV=eth0
CPUS=0
SIZE=64
DST_MAC=""
DST_IP=""
PPS=0
FLOWS=1
SRC_IP=10.77.0.11
CLONE=1000
SECS=10

die() { echo "pktgen.sh: $*" >&2; exit 1; }

need_pktgen() {
    [ -e "$PG/pgctrl" ] || die "no $PG/pgctrl (is the pktgen module loaded and is this the right netns?)"
}

# write a value to a pktgen control file (root required)
pgw() { # pgw <file> <string>
    echo "$2" > "$1" || die "write '$2' -> $1 failed"
}

# soft write: return non-zero instead of dying (for optional/degradable knobs)
pgw_soft() { # pgw_soft <file> <string>
    echo "$2" > "$1" 2>/dev/null
}

parse_flags() {
    while [ $# -gt 0 ]; do
        case "$1" in
            -d) DEV=$2; shift 2;;
            --cpus) CPUS=$2; shift 2;;
            --size) SIZE=$2; shift 2;;
            --dst-mac) DST_MAC=$2; shift 2;;
            --dst-ip) DST_IP=$2; shift 2;;
            --pps) PPS=$2; shift 2;;
            --flows) FLOWS=$2; shift 2;;
            --src-ip) SRC_IP=$2; shift 2;;
            --clone) CLONE=$2; shift 2;;
            --secs) SECS=$2; shift 2;;
            *) die "unknown flag: $1";;
        esac
    done
}

cpu_list() { echo "$CPUS" | tr ',' ' '; }

# compute src_max IP for flows>1: 10.77.128.0 .. capped at 10.77.255.254
src_range_max() {
    local n=$1
    local base=$((128 * 256 + 0))          # 10.77.128.0 offset within /16
    local total=$((base + n - 1))
    local cap=$((255 * 256 + 254))         # 10.77.255.254
    [ "$total" -gt "$cap" ] && total=$cap
    echo "10.77.$((total / 256)).$((total % 256))"
}

do_reset() {
    need_pktgen
    pgw "$PG/pgctrl" reset
}

do_stop() {
    need_pktgen
    pgw "$PG/pgctrl" stop
}

# nth <index> <default> <csv> : echo the index-th comma field of <csv>, or the
# sole field if the list has one element, or <default> if empty. 0-based index.
nth() {
    local idx=$1 def=$2 csv=$3
    local IFS=,; set -- $csv
    [ $# -eq 0 ] && { echo "$def"; return; }
    [ $# -eq 1 ] && { echo "$1"; return; }
    idx=$(( idx + 1 ))
    [ "$idx" -le $# ] && eval "echo \${$idx}" || echo "$def"
}

do_start() {
    need_pktgen
    [ -n "$DST_MAC" ] || die "start needs --dst-mac"
    [ -n "$DST_IP" ] || die "start needs --dst-ip"

    local cpu dev i=0
    for cpu in $(cpu_list); do
        # per-cpu size/rate: SIZE/PPS may be comma lists mapped onto --cpus
        local wire pkt_size rate
        wire=$(nth "$i" "$SIZE" "$SIZE")
        rate=$(nth "$i" "$PPS" "$PPS")
        pkt_size=$((wire - 4))
        [ "$pkt_size" -ge 42 ] || die "size too small ($wire on cpu $cpu); pkt_size must be >= 42"
        [ -e "$PG/kpktgend_$cpu" ] || die "no $PG/kpktgend_$cpu (cpu $cpu not available to pktgen here)"
        dev="${DEV}@${cpu}"
        pgw "$PG/kpktgend_$cpu" "rem_device_all"
        pgw "$PG/kpktgend_$cpu" "add_device $dev"
        local f="$PG/$dev"
        [ -e "$f" ] || die "device file $f did not appear after add_device"
        pgw "$f" "count 0"
        # clone_skb > 0 needs IFF_TX_SKB_SHARING, which veth does not set
        # (pktgen returns ENOTSUPP/524). Fall back to 0 so veth paths work.
        if [ "$CLONE" -gt 0 ] && ! pgw_soft "$f" "clone_skb $CLONE"; then
            echo "pktgen.sh: clone_skb $CLONE rejected on $DEV (veth?); using clone_skb 0" >&2
            pgw "$f" "clone_skb 0"
        else
            [ "$CLONE" -gt 0 ] || pgw "$f" "clone_skb 0"
        fi
        pgw "$f" "pkt_size $pkt_size"
        pgw "$f" "delay 0"
        pgw "$f" "dst_mac $DST_MAC"
        pgw "$f" "dst $DST_IP"
        pgw "$f" "udp_dst_min 9"
        pgw "$f" "udp_dst_max 9"
        if [ "$FLOWS" -gt 1 ]; then
            pgw "$f" "src_min 10.77.128.0"
            pgw "$f" "src_max $(src_range_max "$FLOWS")"
            pgw "$f" "flag IPSRC_RND"
            pgw "$f" "udp_src_min 1024"
            pgw "$f" "udp_src_max 65535"
            pgw "$f" "flag UDPSRC_RND"
        else
            pgw "$f" "src_min $SRC_IP"
            pgw "$f" "src_max $SRC_IP"
        fi
        pgw "$f" "flag NO_TIMESTAMP"
        if [ "$rate" -gt 0 ] 2>/dev/null; then
            pgw "$f" "ratep $rate"
        fi
        i=$(( i + 1 ))
    done

    # "start" blocks until all threads finish; count 0 never finishes on its
    # own, so background the writer and return. `stop` (or SIGINT) ends it.
    # The writer MUST NOT inherit our stdio: `docker exec` lingers ~2 s (and
    # under load longer) until every holder of its stdout/stderr pipe exits,
    # which staggered the generators' starts by 2-3 s each and stretched a
    # "12 s" run to 23 s (measured: gens ran 15.3/17.7/20.0/22.5 s).
    ( echo start > "$PG/pgctrl" ) </dev/null >/dev/null 2>&1 &
    disown 2>/dev/null || true
    # give the threads a moment to actually begin
    sleep 0.2
}

# wait (<= ~3 s) until every device of the given cpus is listed as Stopped in
# its kpktgend thread file, so `result` reads FINAL counters (pktgen only
# prints "Result: OK: <elapsed>" once the device has stopped).
wait_stopped() {
    local cpu i ok
    for i in $(seq 1 30); do
        ok=1
        for cpu in $(cpu_list); do
            [ -e "$PG/kpktgend_$cpu" ] || continue
            # "Running: eth0@4 " lists devices still transmitting
            if grep -q "^Running: .*${DEV}@${cpu}\b" "$PG/kpktgend_$cpu" 2>/dev/null; then
                ok=0; break
            fi
        done
        [ "$ok" = 1 ] && return 0
        sleep 0.1
    done
    echo "pktgen.sh: warning: device(s) still running after stop; counters may be non-final" >&2
    return 0
}

# parse one device file into a JSON fragment on stdout (no trailing newline):
# {"cpu":C,"sofar":N,"pps":N,"bps":N,"errors":N,"seconds":F,"bytes":N}
parse_device() {
    local cpu=$1 file=$2
    [ -e "$file" ] || { echo "{\"cpu\":$cpu,\"sofar\":0,\"pps\":0,\"bps\":0,\"errors\":0,\"seconds\":0,\"bytes\":0,\"missing\":true}"; return; }
    awk -v cpu="$cpu" '
        /pkts-sofar:/ {
            for (i = 1; i <= NF; i++) if ($i == "pkts-sofar:") sofar = $(i+1)+0
        }
        /min_pkt_size:/ {
            for (i = 1; i <= NF; i++) if ($i == "min_pkt_size:") minsz = $(i+1)+0
        }
        # Result: OK: <elapsed>(...) nsec, <pkts> (<sz>byte,<n>frags)
        /^Result: OK:/ {
            n = $3            # e.g. 5000123(c...+d...)
            sub(/\(.*/, "", n)
            elapsed = n + 0
            unit = $4         # "nsec," or "usec,"
            sub(/,$/, "", unit)
        }
        # <pps>pps <x>Mb/sec (<bps>bps) errors: <e>
        /pps / && /bps\)/ {
            for (i = 1; i <= NF; i++) {
                if ($i ~ /pps$/)   { p = $i; sub(/pps$/, "", p); pps = p + 0 }
                if ($i ~ /bps\)$/) { b = $i; gsub(/[()]/, "", b); sub(/bps$/, "", b); bps = b + 0 }
                if ($i == "errors:") errors = $(i+1) + 0
            }
        }
        END {
            secs = 0
            if (unit == "nsec") secs = elapsed / 1e9
            else if (unit == "usec") secs = elapsed / 1e6
            wire = minsz + 4
            bytes = sofar * wire
            printf "{\"cpu\":%d,\"sofar\":%d,\"pps\":%d,\"bps\":%d,\"errors\":%d,\"seconds\":%.3f,\"bytes\":%d,\"final\":%s}",
                   cpu, sofar+0, pps+0, bps+0, errors+0, secs, bytes+0, (elapsed > 0 ? "true" : "false")
        }
    ' "$file"
}

do_result() {
    need_pktgen
    wait_stopped
    local cpu dev first=1
    local sum_sofar=0 sum_pps=0 sum_bps=0 sum_err=0 sum_bytes=0 max_secs=0
    local devices="["
    for cpu in $(cpu_list); do
        dev="${DEV}@${cpu}"
        local frag
        frag=$(parse_device "$cpu" "$PG/$dev")
        [ $first -eq 1 ] || devices+=","
        devices+="$frag"
        first=0
        # accumulate totals via a tiny awk on the fragment values
        eval "$(echo "$frag" | awk -F'[:,{}]' '
            {
                for (i = 1; i <= NF; i++) {
                    if ($i ~ /"sofar"/)   v_sofar = $(i+1)+0
                    if ($i ~ /"pps"/)     v_pps = $(i+1)+0
                    if ($i ~ /"bps"/)     v_bps = $(i+1)+0
                    if ($i ~ /"errors"/)  v_err = $(i+1)+0
                    if ($i ~ /"seconds"/) v_sec = $(i+1)+0
                    if ($i ~ /"bytes"/)   v_bytes = $(i+1)+0
                }
                printf "FRAG_SOFAR=%d FRAG_PPS=%d FRAG_BPS=%d FRAG_ERR=%d FRAG_SEC=%s FRAG_BYTES=%d",
                       v_sofar, v_pps, v_bps, v_err, v_sec, v_bytes
            }')"
        sum_sofar=$((sum_sofar + FRAG_SOFAR))
        sum_pps=$((sum_pps + FRAG_PPS))
        sum_bps=$((sum_bps + FRAG_BPS))
        sum_err=$((sum_err + FRAG_ERR))
        sum_bytes=$((sum_bytes + FRAG_BYTES))
        max_secs=$(awk -v a="$max_secs" -v b="$FRAG_SEC" 'BEGIN{print (b>a)?b:a}')
    done
    devices+="]"
    printf '{"tool":"pktgen","sent":%d,"bytes":%d,"pps":%d,"bps":%d,"errors":%d,"seconds":%s,"devices":%s}\n' \
        "$sum_sofar" "$sum_bytes" "$sum_pps" "$sum_bps" "$sum_err" "$max_secs" "$devices"
}

do_run() {
    do_start
    sleep "$SECS"
    do_stop
    # small settle so counters flush
    sleep 0.3
    do_result
}

main() {
    [ $# -ge 1 ] || die "usage: pktgen.sh start|stop|reset|result|run [flags]"
    local sub=$1; shift
    parse_flags "$@"
    case "$sub" in
        start)  do_start;;
        stop)   do_stop;;
        reset)  do_reset;;
        result) do_result;;
        run)    do_run;;
        *) die "unknown subcommand: $sub";;
    esac
}

main "$@"
