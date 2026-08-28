#!/usr/bin/env bash
# loadtest/tune-host.sh apply|restore|show — host-wide (non-namespaced) sysctls
# for the snuffles load-test rig. See loadtest/SPEC.md "Host tuning".
#
#   apply    save current values to loadtest/results/host-sysctl.before (only
#            if that file does not exist yet), then RAISE the listed keys to the
#            rig values (a key that is already >= target is left alone: the host
#            is shared, we never lower a limit), modprobe pktgen, and raise
#            vm.max_map_count to 262144 only if it is lower.
#   restore  write the saved values back (idempotent; leaves pktgen loaded).
#   show     print current / saved / target for every key.
#
# All writes go through `sudo sh -c 'echo V > /proc/sys/...'`.
set -euo pipefail

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BEFORE="$REPO/loadtest/results/host-sysctl.before"

# key=target, in the order they are applied
TARGETS=(
    net.core.rmem_max=536870912
    net.core.wmem_max=536870912
    net.core.netdev_max_backlog=250000
    net.core.netdev_budget=1200
    net.core.netdev_budget_usecs=20000
    net.core.optmem_max=4194304
    vm.max_map_count=262144
)

key_path() { printf '/proc/sys/%s' "${1//.//}"; }
get_val()  { cat "$(key_path "$1")"; }
set_val() { # set_val key value
    local p; p=$(key_path "$1")
    if [ "$(cat "$p")" != "$2" ]; then
        sudo sh -c "echo $2 > $p"
        echo "tune-host: $1 = $2"
    fi
}

load_pktgen() {
    if [ ! -d /proc/net/pktgen ]; then
        sudo modprobe pktgen
        echo "tune-host: modprobe pktgen"
    fi
}

cmd_show() {
    local kv key tgt cur saved
    printf '%-32s %14s %14s %14s\n' key current saved target
    for kv in "${TARGETS[@]}"; do
        key=${kv%%=*}; tgt=${kv#*=}
        cur=$(get_val "$key")
        saved="-"
        if [ -f "$BEFORE" ]; then
            saved=$(grep -E "^$key=" "$BEFORE" | tail -1 | cut -d= -f2 || true)
            saved=${saved:--}
        fi
        printf '%-32s %14s %14s %14s\n' "$key" "$cur" "$saved" "$tgt"
    done
    if [ -d /proc/net/pktgen ]; then echo "pktgen: loaded"; else echo "pktgen: NOT loaded"; fi
    if [ -f "$BEFORE" ]; then echo "saved originals: $BEFORE"; else echo "saved originals: (none, apply not run yet)"; fi
}

cmd_apply() {
    local kv key tgt cur
    mkdir -p "$(dirname "$BEFORE")"
    if [ ! -f "$BEFORE" ]; then
        {
            echo "# host sysctl values before tune-host.sh apply ($(date -Is))"
            for kv in "${TARGETS[@]}"; do
                key=${kv%%=*}
                echo "$key=$(get_val "$key")"
            done
        } > "$BEFORE"
        echo "tune-host: saved originals to $BEFORE"
    fi
    for kv in "${TARGETS[@]}"; do
        key=${kv%%=*}; tgt=${kv#*=}
        cur=$(get_val "$key")
        if [ "$cur" -lt "$tgt" ]; then
            set_val "$key" "$tgt"
        fi
    done
    load_pktgen
    echo "tune-host: apply done"
}

cmd_restore() {
    if [ ! -f "$BEFORE" ]; then
        echo "tune-host: nothing to restore ($BEFORE missing)"
        load_pktgen
        return 0
    fi
    local line key val
    while IFS= read -r line; do
        case "$line" in ''|'#'*) continue;; esac
        key=${line%%=*}; val=${line#*=}
        [ -e "$(key_path "$key")" ] || { echo "tune-host: skip unknown key $key" >&2; continue; }
        set_val "$key" "$val"
    done < "$BEFORE"
    load_pktgen
    echo "tune-host: restore done (originals kept in $BEFORE)"
}

case "${1:-}" in
    apply)   cmd_apply ;;
    restore) cmd_restore ;;
    show)    cmd_show ;;
    *) echo "usage: $0 apply|restore|show" >&2; exit 2 ;;
esac
