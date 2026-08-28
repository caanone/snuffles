#!/usr/bin/env bash
# loadtest/rig.sh — build / bring up / tear down the snuffles load-test rig.
# Contract: loadtest/SPEC.md. Run from anywhere (paths are resolved from the
# script location); idempotent: `up` twice is fine, `down` removes everything
# it created even if `up` failed halfway.
#
#   rig.sh build              docker build snuffles-sut / snuffles-gen / snuffles-sink
#   rig.sh up                 tune-host apply, containers, topology, neigh, tc drops,
#                             sink services, snuffles build in the sut
#   rig.sh down               remove containers (+ any host-side leftovers), tune-host restore
#   rig.sh status             containers, cpusets, interfaces, sysctls
#   rig.sh mtu N              br0 + every traffic veth (both ends) to N
#   rig.sh offloads on|off    tso/gso/gro/tx-checksumming on gen/sink eth0 and p1..p5
#   rig.sh rps on|off         rps_cpus 0c0c (SUT cpus 2,3,10,11) or 0 on br0,p1..p5
#   rig.sh build-sut          rebuild snuffles from /repo inside snf-sut
#   rig.sh exec <role> <cmd>  docker exec into sut | gen-1..4 | sink
#   rig.sh smoke              run scenarios/S0-smoke.json end to end
#
# Env overrides (for testing with stand-ins; the real rig uses the defaults):
#   RIG_PREFIX      container name/hostname prefix (default snf-)
#   RIG_IMAGE_SUT / RIG_IMAGE_GEN / RIG_IMAGE_SINK   image names
set -euo pipefail

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
LT="$REPO/loadtest"
RESULTS="$LT/results"
PREFIX="${RIG_PREFIX:-snf-}"
IMAGE_SUT="${RIG_IMAGE_SUT:-snuffles-sut}"
IMAGE_GEN="${RIG_IMAGE_GEN:-snuffles-gen}"
IMAGE_SINK="${RIG_IMAGE_SINK:-snuffles-sink}"

ROLES=(sut gen-1 gen-2 gen-3 gen-4 sink)
GENS=(1 2 3 4)

# fixed addressing (SPEC "Network topology")
BR_MAC=02:53:4e:46:00:01;   BR_IP=10.77.0.1
SINK_MAC=02:53:4e:46:00:05; SINK_IP=10.77.0.5
MGMT_SUT_MAC=02:53:4e:46:02:01;  MGMT_SUT_IP=10.78.0.1
MGMT_SINK_MAC=02:53:4e:46:02:05; MGMT_SINK_IP=10.78.0.5
gen_mac() { printf '02:53:4e:46:01:0%d' "$1"; }
gen_ip()  { printf '10.77.0.1%d' "$1"; }
SUT_RPS_MASK=0c0c

cpuset_of() {
    case "$1" in
        sut)   echo 2,3,10,11 ;;
        gen-1) echo 4,12 ;; gen-2) echo 5,13 ;; gen-3) echo 6,14 ;; gen-4) echo 7,15 ;;
        sink)  echo 0,8 ;;
        *) echo "rig: unknown role $1" >&2; return 1 ;;
    esac
}
image_of() {
    case "$1" in
        sut) echo "$IMAGE_SUT" ;; gen-*) echo "$IMAGE_GEN" ;; sink) echo "$IMAGE_SINK" ;;
    esac
}
cname() { printf '%s%s' "$PREFIX" "$1"; }
log()   { printf 'rig: %s\n' "$*"; }
die()   { printf 'rig: ERROR: %s\n' "$*" >&2; exit 1; }

# ── container helpers ───────────────────────────────────────────────────────
# note: a failing `docker inspect` prints an empty line on stdout, hence the
# explicit fallbacks instead of `|| echo`.
ctr_state() {
    local s
    s=$(docker inspect -f '{{.State.Status}}' "$(cname "$1")" 2>/dev/null) || s=absent
    echo "${s:-absent}"
}
pid_of() {
    local p
    p=$(docker inspect -f '{{.State.Pid}}' "$(cname "$1")" 2>/dev/null) || p=0
    [ "${p:-0}" -gt 0 ] 2>/dev/null || die "container $(cname "$1") is not running"
    echo "$p"
}
# Run CMD with the mount namespace of MNTROLE (its binaries: ip/tc/ethtool)
# and the network namespace of NETROLE. All topology work goes through here.
nsx() { # nsx <mntrole> <netrole> cmd...
    local mp np
    mp=$(pid_of "$1"); np=$(pid_of "$2"); shift 2
    sudo nsenter --mount="/proc/$mp/ns/mnt" --net="/proc/$np/ns/net" --wdns=/ -- "$@"
}
# ns <role> cmd...: the role's own binaries + netns
ns() { local r=$1; shift; nsx "$r" "$r" "$@"; }
# nsut <role> cmd...: SUT image binaries (has ethtool/tc) in <role>'s netns
nsut() { local r=$1; shift; nsx sut "$r" "$@"; }
has_link() { ns "$1" ip -o link show dev "$2" >/dev/null 2>&1; }

start_container() { # start_container <role>
    local role=$1 name state img cpus
    name=$(cname "$role"); img=$(image_of "$role"); cpus=$(cpuset_of "$role")
    state=$(ctr_state "$role")
    if [ "$state" != absent ]; then
        # never adopt a container somebody else created under our name
        local have; have=$(docker inspect -f '{{.Config.Image}}' "$name")
        [ "$have" = "$img" ] || die "container $name exists with image '$have' (expected '$img'): not ours, refusing to touch it"
    fi
    if [ "$state" = running ]; then log "$name already running"; return 0; fi
    if [ "$state" != absent ]; then
        log "$name is $state, recreating"
        docker rm -f "$name" >/dev/null
    fi
    docker image inspect "$img" >/dev/null 2>&1 || die "image $img missing (rig.sh build)"
    local -a sysctls=()
    case "$role" in
        gen-*|sink)
            sysctls=(--sysctl "net.ipv4.ip_local_port_range=1024 65535"
                     --sysctl net.ipv4.tcp_tw_reuse=1
                     --sysctl net.ipv4.tcp_fin_timeout=5
                     --sysctl net.core.somaxconn=65535
                     --sysctl net.ipv4.tcp_max_syn_backlog=65535) ;;
    esac
    docker run -d --privileged --network none \
        --ulimit nofile=1048576:1048576 --ulimit memlock=-1:-1 \
        --cpuset-cpus "$cpus" --name "$name" --hostname "$name" \
        --stop-signal SIGKILL \
        --sysctl net.ipv6.conf.all.disable_ipv6=1 --sysctl net.ipv6.conf.default.disable_ipv6=1 \
        -v "$RESULTS:/results" -v "$REPO:/repo:ro" \
        "${sysctls[@]}" \
        "$img" sleep infinity >/dev/null
    log "$name started (image $img, cpuset $cpus)"
}

# ── topology ────────────────────────────────────────────────────────────────
# veth pairs are created from the host with both ends placed directly into
# the two container netns (ip link add ... netns PID ... peer ... netns PID),
# so nothing ever exists in the host netns, not even transiently.
make_veth() { # make_veth <roleA> <ifA> <macA> <roleB> <ifB> [macB]
    local ra=$1 ifa=$2 maca=$3 rb=$4 ifb=$5 macb=${6:-}
    local pa pb
    pa=$(pid_of "$ra"); pb=$(pid_of "$rb")
    if has_link "$ra" "$ifa" && has_link "$rb" "$ifb"; then
        log "veth $ra:$ifa <-> $rb:$ifb exists"; return 0
    fi
    # half state (one container was recreated): drop the orphan end
    has_link "$ra" "$ifa" && ns "$ra" ip link del "$ifa"
    has_link "$rb" "$ifb" && ns "$rb" ip link del "$ifb"
    local -a peer=(peer name "$ifb" numtxqueues 8 numrxqueues 8 netns "$pb")
    [ -n "$macb" ] && peer+=(address "$macb")
    sudo ip link add "$ifa" address "$maca" numtxqueues 8 numrxqueues 8 netns "$pa" \
        type veth "${peer[@]}"
    log "veth $ra:$ifa <-> $rb:$ifb created"
}

neigh_add() { # neigh_add <role> <dev> <ip> <mac>
    ns "$1" ip neigh replace "$3" lladdr "$4" dev "$2" nud permanent
}

# Static + sticky fdb entries for the five fixed MACs. The bridge keeps
# learning for everything else (SPEC), but the sink's and the gens' MACs must
# never move: the replay corpus carries frames whose SOURCE is the sink MAC
# (responses), so a learned-only fdb ends up with the sink MAC on a gen port
# and every later dst=sink flood (synflood, udpflood, frag, pktgen) is
# forwarded to that gen instead of the sink (measured: p5 tx = 0, p4 tx =
# 19.5M in C6). Without any entry (sink silent for >300 s) the frames are
# flooded to every port instead. "sticky" = not moved by learning.
install_fdb() {
    local n
    for n in "${GENS[@]}"; do
        ns sut bridge fdb replace "$(gen_mac "$n")" dev "p$n" master static sticky
    done
    ns sut bridge fdb replace "$SINK_MAC" dev p5 master static sticky
    log "static sticky fdb entries: gen MACs on p1..p4, sink MAC on p5"
}

tc_drop_udp9() { # tc_drop_udp9 <role> <dev>   (ingress drop of ip dport 9)
    local role=$1 dev=$2
    nsut "$role" tc qdisc show dev "$dev" | grep -q clsact || nsut "$role" tc qdisc add dev "$dev" clsact
    nsut "$role" tc filter del dev "$dev" ingress pref 1 2>/dev/null || true
    nsut "$role" tc filter add dev "$dev" ingress pref 1 protocol ip u32 \
        match ip dport 9 0xffff action drop
}

build_topology() {
    local n role
    # no IPv6 in the rig netns: keeps ND/MLD/DAD chatter out of the capture
    for role in "${ROLES[@]}"; do
        ns "$role" sh -c 'echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6; echo 1 > /proc/sys/net/ipv6/conf/default/disable_ipv6'
    done
    # bridge in the sut
    if ! has_link sut br0; then
        ns sut ip link add br0 address "$BR_MAC" type bridge stp_state 0 mcast_snooping 0
        log "br0 created in sut"
    fi
    ns sut ip addr replace "$BR_IP/16" dev br0
    ns sut ip link set br0 up

    # gens: eth0 <-> pN
    for n in "${GENS[@]}"; do
        make_veth "gen-$n" eth0 "$(gen_mac "$n")" sut "p$n"
        ns "gen-$n" ip addr replace "$(gen_ip "$n")/16" dev eth0
        ns "gen-$n" ip link set eth0 up
        ns sut ip link set "p$n" master br0 up
    done
    # sink: eth0 <-> p5
    make_veth sink eth0 "$SINK_MAC" sut p5
    ns sink ip addr replace "$SINK_IP/16" dev eth0
    ns sink ip link set eth0 up
    ns sut ip link set p5 master br0 up
    # mgmt: sut mgmt0 <-> sink mgmt0 (not on br0; syslog target path)
    make_veth sut mgmt0 "$MGMT_SUT_MAC" sink mgmt0 "$MGMT_SINK_MAC"
    ns sut  ip addr replace "$MGMT_SUT_IP/24"  dev mgmt0
    ns sink ip addr replace "$MGMT_SINK_IP/24" dev mgmt0
    ns sut  ip link set mgmt0 up
    ns sink ip link set mgmt0 up
    log "topology up"

    # static neighbours everywhere (no ARP traffic in the capture)
    local m
    for n in "${GENS[@]}"; do
        neigh_add "gen-$n" eth0 "$SINK_IP" "$SINK_MAC"
        neigh_add "gen-$n" eth0 "$BR_IP" "$BR_MAC"
        for m in "${GENS[@]}"; do
            [ "$m" = "$n" ] || neigh_add "gen-$n" eth0 "$(gen_ip "$m")" "$(gen_mac "$m")"
        done
        neigh_add sink eth0 "$(gen_ip "$n")" "$(gen_mac "$n")"
        neigh_add sut  br0  "$(gen_ip "$n")" "$(gen_mac "$n")"
    done
    neigh_add sink eth0  "$BR_IP" "$BR_MAC"
    neigh_add sut  br0   "$SINK_IP" "$SINK_MAC"
    neigh_add sut  mgmt0 "$MGMT_SINK_IP" "$MGMT_SINK_MAC"
    neigh_add sink mgmt0 "$MGMT_SUT_IP" "$MGMT_SUT_MAC"
    # synflood / flows>1 use random sources in 10.77.128.0/17: the sink's
    # replies (SYN-ACK) must not trigger ARP storms, so route that block via
    # gen-1 (static neigh; gen-1 has ip_forward=0 and silently drops them).
    ns sink ip route replace 10.77.128.0/17 via "$(gen_ip 1)" dev eth0
    log "static neighbours installed"
    install_fdb

    # ingress drops for the UDP/9 floods
    tc_drop_udp9 sink eth0
    tc_drop_udp9 sut br0
    log "tc ingress drop (ip dport 9) on sink:eth0 and sut:br0"
}

# ── knobs ───────────────────────────────────────────────────────────────────
cmd_mtu() {
    local mtu=$1 n
    [[ "$mtu" =~ ^[0-9]+$ ]] || die "mtu must be a number"
    for n in "${GENS[@]}"; do
        ns "gen-$n" ip link set eth0 mtu "$mtu"
        ns sut ip link set "p$n" mtu "$mtu"
    done
    ns sink ip link set eth0 mtu "$mtu"
    ns sut ip link set p5 mtu "$mtu"
    ns sut ip link set br0 mtu "$mtu"
    log "mtu $mtu on br0, p1..p5 and gen/sink eth0"
}

cmd_offloads() {
    local v n
    case "$1" in on) v=on ;; off) v=off ;; *) die "offloads on|off" ;; esac
    for n in "${GENS[@]}"; do
        nsut "gen-$n" ethtool -K eth0 tso "$v" gso "$v" gro "$v" tx "$v" >/dev/null
        nsut sut ethtool -K "p$n" tso "$v" gso "$v" gro "$v" tx "$v" >/dev/null
    done
    nsut sink ethtool -K eth0 tso "$v" gso "$v" gro "$v" tx "$v" >/dev/null
    nsut sut ethtool -K p5 tso "$v" gso "$v" gro "$v" tx "$v" >/dev/null
    log "offloads $v (tso/gso/gro/tx) on gen/sink eth0 and p1..p5"
}

cmd_rps() {
    local mask
    case "$1" in on) mask=$SUT_RPS_MASK ;; off) mask=0 ;; *) die "rps on|off" ;; esac
    ns sut sh -c "for d in br0 p1 p2 p3 p4 p5; do for q in /sys/class/net/\$d/queues/rx-*; do echo $mask > \$q/rps_cpus; done; done"
    log "rps $1 (rps_cpus=$mask) on br0, p1..p5"
}

# ── commands ────────────────────────────────────────────────────────────────
cmd_build() {
    local role f built=0 missing=""
    if [ -x "$LT/docker/build.sh" ]; then exec "$LT/docker/build.sh"; fi
    for role in sut gen sink; do
        f="$LT/docker/$role.Dockerfile"
        [ -f "$f" ] || f="$LT/docker/Dockerfile.$role"
        if [ ! -f "$f" ]; then
            log "no Dockerfile for $role yet (loadtest/docker/$role.Dockerfile) — skipping"
            missing="$missing $role"
            continue
        fi
        log "building snuffles-$role from $f"
        docker build -f "$f" -t "snuffles-$role" "$REPO"
        built=$((built+1))
    done
    [ "$built" -gt 0 ] || die "no Dockerfiles found under loadtest/docker/"
    [ -z "$missing" ] || log "note: not built (Dockerfile absent):$missing"
}

start_sink_services() {
    if docker exec "$(cname sink)" test -x /opt/sink/start-services.sh 2>/dev/null; then
        docker exec "$(cname sink)" /opt/sink/start-services.sh | sed 's/^/rig: sink: /'
    elif docker exec "$(cname sink)" sh -c 'command -v nginx' >/dev/null 2>&1; then
        docker exec "$(cname sink)" sh -c 'pgrep -x nginx >/dev/null || nginx; pgrep -f "^iperf3 -s" >/dev/null || iperf3 -s -D'
        log "sink: nginx + iperf3 -s started"
    else
        log "sink: no nginx in image (stand-in?), services not started"
    fi
}

cmd_build_sut() {
    if docker exec "$(cname sut)" test -x /opt/snuffles/build.sh 2>/dev/null; then
        docker exec "$(cname sut)" /opt/snuffles/build.sh
        log "snuffles built in sut (/opt/snuffles/{pcap,raw}/snuffles)"
    else
        log "sut: /opt/snuffles/build.sh missing (stand-in?), snuffles not built"
    fi
}

cmd_up() {
    local role
    mkdir -p "$RESULTS"
    "$LT/tune-host.sh" apply
    for role in "${ROLES[@]}"; do start_container "$role"; done
    build_topology
    cmd_mtu 1500
    cmd_offloads on
    cmd_rps off
    start_sink_services
    cmd_build_sut
    log "up complete"
}

cmd_down() {
    local role name l
    for role in "${ROLES[@]}"; do
        name=$(cname "$role")
        if [ "$(ctr_state "$role")" != absent ]; then
            docker rm -f "$name" >/dev/null 2>&1 && log "removed $name" || log "could not remove $name"
        fi
    done
    # nothing is ever created in the host netns, but sweep defensively
    for l in $(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1 | grep -E "^${PREFIX}" || true); do
        sudo ip link del "$l" && log "removed host link $l" || true
    done
    "$LT/tune-host.sh" restore
    log "down complete"
}

cmd_status() {
    local role name state cpus
    echo "== containers (prefix $PREFIX)"
    for role in "${ROLES[@]}"; do
        name=$(cname "$role"); state=$(ctr_state "$role")
        if [ "$state" = running ]; then
            cpus=$(docker inspect -f '{{.HostConfig.CpusetCpus}}' "$name")
            printf '%-14s %-8s cpuset=%-10s image=%s\n' "$name" "$state" "$cpus" "$(docker inspect -f '{{.Config.Image}}' "$name")"
        else
            printf '%-14s %s\n' "$name" "$state"
        fi
    done
    for role in "${ROLES[@]}"; do
        [ "$(ctr_state "$role")" = running ] || continue
        echo "== $role interfaces"
        ns "$role" ip -br addr show 2>/dev/null | grep -v '^lo ' || true
    done
    if [ "$(ctr_state sut)" = running ]; then
        echo "== sut br0"
        ns sut ip -d link show br0 2>/dev/null | head -2 || true
        ns sut bridge link show 2>/dev/null || true
        echo "== sut fdb (non-permanent + static)"
        ns sut bridge fdb show br br0 2>/dev/null | grep -v ' permanent' || true
        echo "== tc drops"
        nsut sut tc filter show dev br0 ingress 2>/dev/null | grep -E 'match|drop' | head -2 || true
        [ "$(ctr_state sink)" = running ] && nsut sink tc filter show dev eth0 ingress 2>/dev/null | grep -E 'match|drop' | head -2 || true
        echo "== rps"
        ns sut cat /sys/class/net/br0/queues/rx-0/rps_cpus 2>/dev/null || true
    fi
    echo "== host sysctls"
    "$LT/tune-host.sh" show
    echo "== host links with prefix $PREFIX"
    ip -o link show | awk -F': ' '{print $2}' | grep -E "^${PREFIX}" || echo "(none)"
}

norm_role() {
    local r=$1
    r=${r#"$PREFIX"}; r=${r#snf-}
    case "$r" in sut|gen-[1-4]|sink) echo "$r" ;; gen[1-4]) echo "gen-${r#gen}" ;; *) die "role must be sut|gen-1..4|sink" ;; esac
}

cmd_exec() {
    [ $# -ge 2 ] || die "exec <role> <cmd...>"
    local role; role=$(norm_role "$1"); shift
    exec docker exec -i "$(cname "$role")" "$@"
}

cmd_smoke() {
    exec "$LT/run-scenario.sh" "$LT/scenarios/S0-smoke.json" "$@"
}

case "${1:-}" in
    build)     cmd_build ;;
    up)        cmd_up ;;
    down)      cmd_down ;;
    status)    cmd_status ;;
    mtu)       [ $# -eq 2 ] || die "mtu N"; cmd_mtu "$2" ;;
    offloads)  [ $# -eq 2 ] || die "offloads on|off"; cmd_offloads "$2" ;;
    rps)       [ $# -eq 2 ] || die "rps on|off"; cmd_rps "$2" ;;
    build-sut) cmd_build_sut ;;
    exec)      shift; cmd_exec "$@" ;;
    smoke)     shift; cmd_smoke "$@" ;;
    *) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
