#!/bin/bash
# perf.sh <pid> <resultsdir> — profile a running snuffles (loadtest/SPEC.md step 5).
#
#   perf stat   -p PID  (10 s, event list from SPEC)   -> <resultsdir>/perf-stat.txt
#   perf record -p PID -F 999 -g (8 s)                 -> <resultsdir>/perf.data
#   perf report --stdio --no-children | head -120      -> <resultsdir>/perf-report.txt
#
# Blocks for ~19 s; the caller backgrounds it (SPEC: stat at +8 s, record at
# +19 s). Tolerates a pid that exits early: each step is skipped/short-circuited
# and the reason is noted in <resultsdir>/perf.log. Exit status is 0 unless the
# arguments are wrong. Env: SNF_PERF_STAT_SECS (10), SNF_PERF_RECORD_SECS (8),
# SNF_PERF_FREQ (999).
set -euo pipefail

[[ $# -eq 2 ]] || { echo "usage: $0 <pid> <resultsdir>" >&2; exit 2; }
pid=$1
res=$2
[[ $pid =~ ^[0-9]+$ ]] || { echo "perf.sh: bad pid '$pid'" >&2; exit 2; }
mkdir -p "$res"

STAT_SECS=${SNF_PERF_STAT_SECS:-10}
REC_SECS=${SNF_PERF_RECORD_SECS:-8}
FREQ=${SNF_PERF_FREQ:-999}
EVENTS=task-clock,context-switches,cpu-migrations,page-faults,cycles,instructions
EVENTS+=,cache-misses,branch-misses,syscalls:sys_enter_write,syscalls:sys_enter_sendto
EVENTS+=,syscalls:sys_enter_getsockopt,syscalls:sys_enter_recvfrom,syscalls:sys_enter_select
EVENTS+=,syscalls:sys_enter_poll,syscalls:sys_enter_openat,syscalls:sys_enter_read
log=$res/perf.log

note() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$log" >&2; }

alive() {
    local line
    { read -r line < "/proc/$1/stat"; } 2>/dev/null || return 1
    line=${line##*) }
    [[ ${line%% *} != Z && ${line%% *} != X ]]
}

# Tracepoint events need tracefs. In a privileged container /sys/kernel/tracing
# is usually there already; if not, mount it in OUR mount namespace only.
if [[ ! -d /sys/kernel/tracing/events && ! -d /sys/kernel/debug/tracing/events ]]; then
    mount -t tracefs nodev /sys/kernel/tracing 2>/dev/null \
        && note "mounted tracefs at /sys/kernel/tracing" \
        || note "WARNING: tracefs unavailable; syscalls:* events will fail"
fi

note "perf.sh pid=$pid stat=${STAT_SECS}s record=${REC_SECS}s freq=$FREQ"

# perf-window.json: epoch bounds of the stat and record windows, so analyze.py
# can take the captured-packet delta over EXACTLY the perf stat window
# (syscalls per packet) instead of guessing from task-clock.
W_STAT0=null; W_STAT1=null; W_REC0=null; W_REC1=null
write_window() {
    printf '{"stat_start":%s,"stat_end":%s,"record_start":%s,"record_end":%s,"stat_secs":%s,"record_secs":%s}\n' \
        "$W_STAT0" "$W_STAT1" "$W_REC0" "$W_REC1" "$STAT_SECS" "$REC_SECS" > "$res/perf-window.json.tmp" \
        && mv -f "$res/perf-window.json.tmp" "$res/perf-window.json"
}

if alive "$pid"; then
    W_STAT0=$EPOCHREALTIME
    if perf stat -p "$pid" -e "$EVENTS" -o "$res/perf-stat.txt" -- sleep "$STAT_SECS" 2>>"$log"; then
        W_STAT1=$EPOCHREALTIME
        note "perf stat ok"
    else
        W_STAT1=$EPOCHREALTIME
        note "perf stat exited $? (see $log)"
    fi
    write_window
else
    note "pid $pid not alive before perf stat; skipped"
    echo "# perf stat skipped: pid $pid not alive" > "$res/perf-stat.txt"
fi

sleep 1

if alive "$pid"; then
    W_REC0=$EPOCHREALTIME
    if perf record -F "$FREQ" -g -p "$pid" -o "$res/perf.data" -- sleep "$REC_SECS" 2>>"$log"; then
        W_REC1=$EPOCHREALTIME
        note "perf record ok"
    else
        W_REC1=$EPOCHREALTIME
        note "perf record exited $? (see $log)"
    fi
    write_window
else
    note "pid $pid not alive before perf record; skipped"
fi

if [[ -s $res/perf.data ]]; then
    { perf report --stdio --no-children -i "$res/perf.data" 2>>"$log" || true; } \
        | head -120 > "$res/perf-report.txt" || true
    note "perf report -> $res/perf-report.txt ($(wc -l < "$res/perf-report.txt") lines)"
else
    echo "# perf report skipped: no perf.data (pid $pid exited early or perf record failed)" > "$res/perf-report.txt"
    note "no perf.data; wrote placeholder perf-report.txt"
fi
exit 0
