#!/bin/bash
# run-snuffles.sh — start/stop snuffles inside snf-sut per the SPEC mode table.
#
#   run-snuffles.sh <mode> <build> <iface> <resultsdir> [extra snuffles args...]
#   run-snuffles.sh stop <resultsdir>
#
# mode  : quiet | headless | headless-pipe | jsonl | jsonl-latency | syslog |
#         stream-null | stream-disk | tui | tui-sessions
# build : pcap | raw   (binary: /opt/snuffles/<build>/snuffles)
#
# Always adds  -i <iface> --stats=<resultsdir>/snuffles.stats ; extra args are
# appended verbatim. Starts snuffles in the background under a detached
# supervisor and returns immediately. Files in <resultsdir>:
#   snuffles.pid      pid of the snuffles process (perf/telemetry target)
#   tui.pid           pid of tui.py (tui modes only)
#   snuffles.stderr   snuffles' stderr
#   snuffles.cmdline  exact argv, one arg per line;  snuffles.mode  the mode
#   out.count         headless-pipe: `wc -l` of stdout (complete after stop)
#   latency.json      jsonl-latency: capture-to-output p50/p95/p99 ms (latency.py)
#   latency.log       jsonl-latency: latency.py's own stderr
#   stream.pcap       stream-disk: written while running; deleted by `stop`
#                     after its size is recorded (keep it with SNF_KEEP_STREAM=1)
#   tui.log           tui modes: tui.py event log
#   exit.status       "<rc> <epoch_ms>" written by the supervisor when the
#                     process exits (rc = 128+N for signal N)
#   exit.json         written by `stop`:
#                     {"mode","pid","exit_code","exit_latency_ms","killed",
#                      "stop_signal","stream_bytes"}
# stop: tui modes -> SIGUSR1 to tui.py (it sends "q", then "q" again, then
# SIGINT); other modes -> SIGINT. Waits up to 30 s (SNF_STOP_TIMEOUT), then
# SIGKILL (killed=true). exit_code is null when the exit status was lost.
# Privileges: snuffles drops root after opening the capture (SUDO_UID/SUDO_GID,
# else "nobody") and only THEN opens --stats / -w files. The harness therefore
# runs it with SUDO_UID/SUDO_GID = owner of the /results mount (the host user;
# "nobody" if that is root) and chowns <resultsdir> to that uid, so the stats
# file, stream.pcap and -o exports are writable and land owned by the host user.
# Env: SNF_SYSLOG_TARGET (10.78.0.5:514), SNF_SNUFFLES_ROOT (/opt/snuffles),
# SNF_RUN_UID / SNF_RUN_GID (override the drop target), SNF_STOP_TIMEOUT (30).
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=${SNF_SNUFFLES_ROOT:-/opt/snuffles}
SYSLOG_TARGET=${SNF_SYSLOG_TARGET:-10.78.0.5:514}
STOP_TIMEOUT=${SNF_STOP_TIMEOUT:-30}
MODES="quiet headless headless-pipe jsonl jsonl-latency syslog stream-null stream-disk tui tui-sessions"

usage() {
    sed -n '2,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//' | sed '$d' >&2
    exit 2
}

now_ms() { local t=$EPOCHREALTIME; echo $(( ${t%.*} * 1000 + 10#${t#*.} / 1000 )); }

proc_state() {                       # state letter, empty when the pid is gone
    local line
    { read -r line < "/proc/$1/stat"; } 2>/dev/null || { printf ''; return; }
    line=${line##*) }
    printf '%s' "${line%% *}"
}
alive() { local s; s=$(proc_state "$1"); [[ -n $s && $s != Z && $s != X ]]; }

# chown_results <dir> <uid> <gid>: make <dir> (and root-owned ancestors below
# /results) owned by the unprivileged uid snuffles drops to.
chown_results() {
    local d=$1 uid=$2 gid=$3
    chown "$uid:$gid" "$d" 2>/dev/null || true
    chmod u+rwx "$d" 2>/dev/null || true
    d=$(dirname "$d")
    while [[ $d == /results/* ]]; do
        [[ $(stat -c %u "$d") == 0 ]] && chown "$uid:$gid" "$d" 2>/dev/null
        d=$(dirname "$d")
    done
    return 0
}

# ── supervisor (internal): runs in its own session, reaps snuffles, records exit
supervise() {
    local res=$1 mode=$2; shift 3
    local -a argv=("$@")
    local pid rc wcpid=""
    case $mode in
        headless-pipe)
            rm -f "$res/.out.fifo"; mkfifo "$res/.out.fifo"
            wc -l < "$res/.out.fifo" > "$res/out.count" & wcpid=$!
            "${argv[@]}" </dev/null >"$res/.out.fifo" 2>"$res/snuffles.stderr" & pid=$!
            echo "$pid" > "$res/snuffles.pid"
            ;;
        jsonl-latency)
            # snuffles --jsonl -> latency.py, which times now - packet.ts per
            # line and writes latency.json. Like headless-pipe: the fifo lets us
            # keep snuffles.pid = the snuffles process (perf/telemetry target).
            rm -f "$res/.out.fifo"; mkfifo "$res/.out.fifo"
            python3 "$HERE/latency.py" -o "$res/latency.json" \
                <"$res/.out.fifo" >"$res/latency.log" 2>&1 & wcpid=$!
            "${argv[@]}" </dev/null >"$res/.out.fifo" 2>"$res/snuffles.stderr" & pid=$!
            echo "$pid" > "$res/snuffles.pid"
            ;;
        tui|tui-sessions)
            local keys=""
            [[ $mode == tui-sessions ]] && keys="5:S,15:V,20:S"
            python3 "$HERE/tui.py" --pidfile "$res/snuffles.pid" --stderr "$res/snuffles.stderr" \
                --keys "$keys" --cols 200 --rows 50 -- "${argv[@]}" \
                </dev/null >"$res/tui.log" 2>&1 & pid=$!
            echo "$pid" > "$res/tui.pid"
            ;;
        *)
            "${argv[@]}" </dev/null >/dev/null 2>"$res/snuffles.stderr" & pid=$!
            echo "$pid" > "$res/snuffles.pid"
            ;;
    esac
    set +e
    wait "$pid"; rc=$?
    set -e
    [[ -n $wcpid ]] && { wait "$wcpid" || true; rm -f "$res/.out.fifo"; }
    printf '%s %s\n' "$rc" "$(now_ms)" > "$res/exit.status.tmp"
    mv -f "$res/exit.status.tmp" "$res/exit.status"
}

# ── stop
do_stop() {
    local res=$1 pid tuipid="" mode="" t0 t1 deadline rc="null" killed=false sig
    local stream_bytes=null
    [[ -s $res/snuffles.pid ]] || { echo "stop: $res/snuffles.pid missing" >&2; exit 1; }
    read -r pid < "$res/snuffles.pid"
    [[ -s $res/snuffles.mode ]] && read -r mode < "$res/snuffles.mode"
    [[ -s $res/tui.pid ]] && read -r tuipid < "$res/tui.pid"

    t0=$(now_ms)
    if [[ -n $tuipid ]] && alive "$tuipid"; then
        sig=SIGUSR1; kill -USR1 "$tuipid" 2>/dev/null || true
    elif alive "$pid"; then
        sig=SIGINT; kill -INT "$pid" 2>/dev/null || true
    else
        sig=none
    fi
    deadline=$(( t0 + STOP_TIMEOUT * 1000 ))
    while alive "$pid" && (( $(now_ms) < deadline )); do sleep 0.01; done
    if alive "$pid"; then
        killed=true
        kill -KILL "$pid" 2>/dev/null || true
        [[ -n $tuipid ]] && kill -KILL "$tuipid" 2>/dev/null || true
        while alive "$pid"; do sleep 0.01; done
    fi
    t1=$(now_ms)
    # give the supervisor a moment to reap and write the status
    for ((i = 0; i < 300; i++)); do [[ -s $res/exit.status ]] && break; sleep 0.01; done
    [[ -s $res/exit.status ]] && read -r rc _ < "$res/exit.status"
    if [[ $mode == stream-disk && -f $res/stream.pcap ]]; then
        stream_bytes=$(stat -c %s "$res/stream.pcap")
        [[ ${SNF_KEEP_STREAM:-0} == 1 ]] || rm -f "$res/stream.pcap"
    fi
    printf '{"mode":"%s","pid":%s,"exit_code":%s,"exit_latency_ms":%s,"killed":%s,"stop_signal":"%s","stream_bytes":%s}\n' \
        "$mode" "$pid" "$rc" "$(( t1 - t0 ))" "$killed" "$sig" "$stream_bytes" > "$res/exit.json"
    cat "$res/exit.json"
}

# ── start
do_start() {
    local mode=$1 build=$2 iface=$3 res=$4; shift 4
    local -a extra=("$@") argv
    [[ " $MODES " == *" $mode "* ]] || { echo "start: unknown mode '$mode' (one of: $MODES)" >&2; exit 2; }
    [[ $build == pcap || $build == raw ]] || { echo "start: build must be pcap|raw" >&2; exit 2; }
    local bin=$ROOT/$build/snuffles
    [[ -x $bin ]] || { echo "start: $bin missing — run build.sh first" >&2; exit 1; }
    mkdir -p "$res"
    res=$(cd "$res" && pwd)
    local run_uid run_gid
    run_uid=${SNF_RUN_UID:-$(stat -c %u /results 2>/dev/null || echo 0)}
    run_gid=${SNF_RUN_GID:-$(stat -c %g /results 2>/dev/null || echo 0)}
    if [[ $run_uid == 0 ]]; then
        run_uid=$(id -u nobody 2>/dev/null || echo 65534)
        run_gid=$(id -g nobody 2>/dev/null || echo 65534)
    fi
    chown_results "$res" "$run_uid" "$run_gid"
    if [[ -s $res/snuffles.pid ]]; then
        local old; read -r old < "$res/snuffles.pid"
        alive "$old" && { echo "start: snuffles already running in $res (pid $old)" >&2; exit 1; }
    fi
    rm -f "$res/snuffles.pid" "$res/tui.pid" "$res/exit.status" "$res/exit.json" \
          "$res/out.count" "$res/.out.fifo" "$res/tui.log" "$res/snuffles.stderr" \
          "$res/latency.json" "$res/latency.log"

    argv=("$bin" -i "$iface" "--stats=$res/snuffles.stats")
    case $mode in
        quiet)         argv+=(-q) ;;
        headless)      argv+=(--no-ui) ;;
        headless-pipe) argv+=(--no-ui) ;;
        jsonl)         argv+=(--jsonl) ;;
        jsonl-latency) argv+=(--jsonl) ;;
        syslog)        argv+=(-q --syslog "$SYSLOG_TARGET") ;;
        stream-null)   argv+=(-q -w /dev/null) ;;
        stream-disk)   argv+=(-q -w "$res/stream.pcap") ;;
        tui|tui-sessions) ;;
    esac
    argv+=("${extra[@]}")
    printf '%s\n' "${argv[@]}" > "$res/snuffles.cmdline"
    echo "$mode" > "$res/snuffles.mode"

    # detached: own session, no inherited stdio (docker exec must not hang on it)
    SUDO_UID=$run_uid SUDO_GID=$run_gid \
    setsid bash "$0" __supervise "$res" "$mode" -- "${argv[@]}" </dev/null >/dev/null 2>&1 &
    disown 2>/dev/null || true

    # wait (<= 5 s) for the pid file so callers can use it right away
    local i pid
    for ((i = 0; i < 500; i++)); do
        [[ -s $res/snuffles.pid ]] && break
        sleep 0.01
    done
    [[ -s $res/snuffles.pid ]] || { echo "start: snuffles did not start (see $res/snuffles.stderr)" >&2; exit 1; }
    read -r pid < "$res/snuffles.pid"
    echo "started mode=$mode build=$build iface=$iface pid=$pid uid=$run_uid results=$res"
}

[[ $# -ge 1 ]] || usage
case $1 in
    __supervise) shift; supervise "$@" ;;
    stop)        [[ $# -eq 2 ]] || usage; do_stop "$2" ;;
    -h|--help)   usage ;;
    *)           [[ $# -ge 4 ]] || usage; do_start "$@" ;;
esac
