#!/bin/bash
# telemetry.sh <pid|pidfile> <outfile> — 1 Hz JSONL sampler (loadtest/SPEC.md,
# "Telemetry sampler"). Runs inside snf-sut; pure bash + one `ss` fork per sample.
#
# Each line:
#   {"t":epoch, "proc":{utime,stime,rss_kb,threads,nvcsw,nivcsw,minflt,majflt},
#    "threads":{comm:{utime,stime,nvcsw,nivcsw}}, "softnet":{processed,dropped,
#    time_squeeze}, "ifaces":{name:{rx_packets,rx_bytes,rx_dropped,tx_packets,
#    tx_bytes,tx_dropped}}, "pktsock":{rmem,rcvbuf,drops}, "mem_current":N,
#    "loadavg":[a,b,c]}
# utime/stime are raw clock ticks (CLK_TCK=100). proc/threads nvcsw/nivcsw are
# summed over all tasks. pktsock sums the packet sockets owned by <pid> (all
# packet sockets in the netns if none is owned by it). When the pid exits one
# last line with "proc":null,"threads":{} is written and the script exits 0.
# If the first argument is a file, it is polled (<= 15 s) for the pid.
set -euo pipefail

[[ $# -eq 2 ]] || { echo "usage: $0 <pid|pidfile> <outfile>" >&2; exit 2; }
target=$1
out=$2
IFACES=(br0 p1 p2 p3 p4 p5 mgmt0)
PAGE_KB=$(( $(getconf PAGESIZE 2>/dev/null || echo 4096) / 1024 ))

# SUT CPUs whose clock we sample for the cycles/packet estimate. Prefer the
# container's effective cpuset (so stand-in configs adapt); fall back to the
# SPEC's fixed SUT cpuset 2,3,10,11. Expand a "2-3,10-11" range list to
# "2 3 10 11".
expand_cpulist() {
    local part a b c out=""
    IFS=, read -ra _parts <<< "$1"
    for part in "${_parts[@]}"; do
        if [[ $part == *-* ]]; then
            a=${part%-*}; b=${part#*-}
            for ((c = a; c <= b; c++)); do out+="$c "; done
        elif [[ $part =~ ^[0-9]+$ ]]; then
            out+="$part "
        fi
    done
    printf '%s' "${out% }"
}
SUT_CPUS="2 3 10 11"
if _cs=$(cat /sys/fs/cgroup/cpuset.cpus.effective 2>/dev/null) && [[ -n $_cs ]]; then
    _exp=$(expand_cpulist "$_cs")
    [[ -n $_exp ]] && SUT_CPUS=$_exp
fi
read -ra SUT_CPU_ARR <<< "$SUT_CPUS"

pid=""
if [[ $target =~ ^[0-9]+$ ]]; then
    pid=$target
else
    for ((i = 0; i < 150; i++)); do
        if [[ -s $target ]] && read -r p < "$target" && [[ $p =~ ^[0-9]+$ ]]; then
            pid=$p; break
        fi
        sleep 0.1
    done
    [[ -n $pid ]] || { echo "telemetry: no pid found in $target" >&2; exit 1; }
fi

exec 3>>"$out"

stop=0
trap 'stop=1' INT TERM HUP

# proc_state <pid> -> prints the state letter, empty if gone.
proc_state() {
    local line
    { read -r line < "/proc/$1/stat"; } 2>/dev/null || { printf ''; return; }
    line=${line##*) }
    printf '%s' "${line%% *}"
}

json_str() {                       # minimal escaping for comm names
    local s=$1
    s=${s//\\/\\\\}; s=${s//\"/\\\"}
    printf '"%s"' "$s"
}

# ctxsw <statusfile> -> sets CS_V CS_NV (0 if unreadable)
ctxsw() {
    local k v
    CS_V=0; CS_NV=0
    while read -r k v _; do
        case $k in
            voluntary_ctxt_switches:)    CS_V=$v ;;
            nonvoluntary_ctxt_switches:) CS_NV=$v ;;
        esac
    done < "$1" 2>/dev/null || true
}

sample_proc() {                    # sets PROC_JSON THREADS_JSON ALIVE
    local line f comm rest t tid tj first=1
    local -a a
    local p_ut=0 p_st=0 p_rss=0 p_thr=0 p_min=0 p_maj=0 p_v=0 p_nv=0
    ALIVE=0
    { read -r line < "/proc/$pid/stat"; } 2>/dev/null || { PROC_JSON=null; THREADS_JSON='{}'; return; }
    rest=${line##*) }
    a=($rest)
    [[ ${a[0]} == Z || ${a[0]} == X ]] && { PROC_JSON=null; THREADS_JSON='{}'; return; }
    ALIVE=1
    p_min=${a[7]}; p_maj=${a[9]}; p_ut=${a[11]}; p_st=${a[12]}; p_thr=${a[17]}
    p_rss=$(( a[21] * PAGE_KB ))

    # per-thread: sum duplicates by comm (thread names are unique in snuffles)
    local -A t_ut=() t_st=() t_v=() t_nv=()
    local -a order=()
    for f in /proc/$pid/task/*/stat; do
        { read -r line < "$f"; } 2>/dev/null || continue
        comm=${line#*(}; comm=${comm%)*}
        rest=${line##*) }
        a=($rest)
        tid=${f%/stat}
        ctxsw "$tid/status"
        if [[ -z ${t_ut[$comm]+x} ]]; then
            order+=("$comm"); t_ut[$comm]=0; t_st[$comm]=0; t_v[$comm]=0; t_nv[$comm]=0
        fi
        t_ut[$comm]=$(( t_ut[$comm] + a[11] ))
        t_st[$comm]=$(( t_st[$comm] + a[12] ))
        t_v[$comm]=$(( t_v[$comm] + CS_V ))
        t_nv[$comm]=$(( t_nv[$comm] + CS_NV ))
        p_v=$(( p_v + CS_V )); p_nv=$(( p_nv + CS_NV ))
    done
    tj='{'
    for comm in "${order[@]}"; do
        (( first )) || tj+=','
        first=0
        tj+="$(json_str "$comm"):{\"utime\":${t_ut[$comm]},\"stime\":${t_st[$comm]},\"nvcsw\":${t_v[$comm]},\"nivcsw\":${t_nv[$comm]}}"
    done
    tj+='}'
    THREADS_JSON=$tj
    PROC_JSON="{\"utime\":$p_ut,\"stime\":$p_st,\"rss_kb\":$p_rss,\"threads\":$p_thr,\"nvcsw\":$p_v,\"nivcsw\":$p_nv,\"minflt\":$p_min,\"majflt\":$p_maj}"
}

sample_softnet() {                 # sets SOFTNET_JSON
    local a b c _ sp=0 sd=0 sq=0
    while read -r a b c _; do
        sp=$(( sp + 16#$a )); sd=$(( sd + 16#$b )); sq=$(( sq + 16#$c ))
    done < /proc/net/softnet_stat
    SOFTNET_JSON="{\"processed\":$sp,\"dropped\":$sd,\"time_squeeze\":$sq}"
}

sample_ifaces() {                  # sets IFACES_JSON (missing interfaces skipped)
    local n d j='{' first=1 rp rb rd tp tb td
    for n in "${IFACES[@]}"; do
        d=/sys/class/net/$n/statistics
        [[ -d $d ]] || continue
        read -r rp < "$d/rx_packets" 2>/dev/null || rp=0
        read -r rb < "$d/rx_bytes"   2>/dev/null || rb=0
        read -r rd < "$d/rx_dropped" 2>/dev/null || rd=0
        read -r tp < "$d/tx_packets" 2>/dev/null || tp=0
        read -r tb < "$d/tx_bytes"   2>/dev/null || tb=0
        read -r td < "$d/tx_dropped" 2>/dev/null || td=0
        (( first )) || j+=','
        first=0
        j+="\"$n\":{\"rx_packets\":$rp,\"rx_bytes\":$rb,\"rx_dropped\":$rd,\"tx_packets\":$tp,\"tx_bytes\":$tb,\"tx_dropped\":$td}"
    done
    IFACES_JSON="$j}"
}

sample_pktsock() {                 # sets PKTSOCK_JSON from `ss -0 -e -m -p -H`
    local line skm x r rb d match=0 haveown=0
    local a_r=0 a_rb=0 a_d=0 o_r=0 o_rb=0 o_d=0
    while IFS= read -r line; do
        if [[ $line == p_* ]]; then
            match=0
            [[ $line == *"pid=$pid,"* ]] && match=1
        fi
        [[ $line == *skmem:\(* ]] || continue
        skm=${line#*skmem:(}; skm=${skm%%)*}
        r=0; rb=0; d=0
        IFS=, read -ra kv <<< "$skm"
        for x in "${kv[@]}"; do
            case $x in
                rb*) rb=${x#rb} ;;
                r*)  r=${x#r} ;;
                d*)  d=${x#d} ;;
            esac
        done
        a_r=$(( a_r + r )); a_rb=$(( a_rb + rb )); a_d=$(( a_d + d ))
        if (( match )); then
            haveown=1
            o_r=$(( o_r + r )); o_rb=$(( o_rb + rb )); o_d=$(( o_d + d ))
        fi
    done < <(ss -0 -e -m -p -H 2>/dev/null || true)
    if (( haveown )); then
        PKTSOCK_JSON="{\"rmem\":$o_r,\"rcvbuf\":$o_rb,\"drops\":$o_d}"
    else
        PKTSOCK_JSON="{\"rmem\":$a_r,\"rcvbuf\":$a_rb,\"drops\":$a_d}"
    fi
}

sample_misc() {                    # sets MEM_JSON LOAD_JSON
    local m l1 l2 l3 _
    if read -r m < /sys/fs/cgroup/memory.current 2>/dev/null && [[ $m =~ ^[0-9]+$ ]]; then
        MEM_JSON=$m
    else
        MEM_JSON=null
    fi
    read -r l1 l2 l3 _ < /proc/loadavg
    LOAD_JSON="[$l1,$l2,$l3]"
}

sample_cpumhz() {                  # sets CPUMHZ_JSON = mean "cpu MHz" of SUT_CPUS
    # /proc/cpuinfo (host-wide in a privileged container) lists a "processor"
    # id and its "cpu MHz" per core. Average the SUT cores' current clock so
    # analyze.py can turn capture CPU% into cycles/packet. null if the field
    # is absent (some kernels/governors do not expose per-core MHz here).
    CPUMHZ_JSON=$(awk -v want="$SUT_CPUS" '
        BEGIN { n = split(want, a, " "); for (i = 1; i <= n; i++) sel[a[i]] = 1; cur = -1 }
        /^processor[ \t]*:/ { cur = $3 }
        /^cpu MHz[ \t]*:/   { if (cur in sel) { sum += $4; cnt++ } }
        END { if (cnt > 0) printf "%.3f", sum / cnt; else printf "null" }
    ' /proc/cpuinfo 2>/dev/null)
    [[ -n $CPUMHZ_JSON ]] || CPUMHZ_JSON=null
}

emit() {
    sample_proc
    sample_softnet
    sample_ifaces
    sample_pktsock
    sample_misc
    sample_cpumhz
    printf '{"t":%s,"proc":%s,"threads":%s,"softnet":%s,"ifaces":%s,"pktsock":%s,"mem_current":%s,"cpu_mhz":%s,"loadavg":%s}\n' \
        "$EPOCHREALTIME" "$PROC_JSON" "$THREADS_JSON" "$SOFTNET_JSON" "$IFACES_JSON" \
        "$PKTSOCK_JSON" "$MEM_JSON" "$CPUMHZ_JSON" "$LOAD_JSON" >&3
}

# interruptible sleep (trap fires immediately instead of after `sleep` ends)
nap() { sleep "$1" & wait $! 2>/dev/null || true; }

t_next=${EPOCHREALTIME%.*}
while (( ! stop )); do
    emit
    (( ALIVE )) || break                     # pid gone: last line written above
    t_next=$(( t_next + 1 ))
    now=$EPOCHREALTIME
    # sleep until t_next (integer seconds), never negative
    delay=$(( t_next - ${now%.*} ))
    if (( delay <= 0 )); then
        t_next=${now%.*}; delay=1
    fi
    frac=${now#*.}
    nap "$(( delay - 1 )).$(( 1000000 - 10#$frac ))"
done
exec 3>&-
exit 0
