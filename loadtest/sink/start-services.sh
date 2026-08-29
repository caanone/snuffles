#!/usr/bin/env bash
# Start the sink services inside the snuffles-sink container (snf-sink):
#   - nginx (daemon, /etc/nginx/nginx.conf)
#   - iperf3 -s -D  (TCP/UDP 5201)
# Idempotent: already-running services are left alone. Prints what listens.
# Usage: docker exec snf-sink /opt/sink/start-services.sh
set -euo pipefail

NGINX_CONF="${NGINX_CONF:-/etc/nginx/nginx.conf}"
IPERF_LOG="${IPERF_LOG:-/var/log/iperf3.log}"

wait_listen() { # wait_listen <port> <name>
    local port=$1 name=$2 i
    for i in $(seq 1 50); do
        if ss -ltnH "sport = :$port" | grep -q .; then
            return 0
        fi
        sleep 0.1
    done
    echo "start-services: $name is not listening on :$port after 5 s" >&2
    return 1
}

# --- nginx ---------------------------------------------------------------
if pgrep -x nginx >/dev/null 2>&1 && ss -ltnH 'sport = :80' | grep -q .; then
    echo "start-services: nginx already running (pid $(pgrep -o -x nginx))"
else
    if pgrep -x nginx >/dev/null 2>&1; then
        echo "start-services: nginx processes exist but :80 not listening, restarting" >&2
        pkill -x nginx || true
        sleep 0.5
    fi
    rm -f /run/nginx.pid
    nginx -t -c "$NGINX_CONF" >/dev/null
    nginx -c "$NGINX_CONF"
    wait_listen 80 nginx
    echo "start-services: nginx started (pid $(cat /run/nginx.pid))"
fi

# --- iperf3 servers ------------------------------------------------------
# A single iperf3 -s serves one client test at a time, so drive one server per
# generator on its own port (5201..5200+IPERF_SERVERS). run-scenario.sh points
# gen-N at port 5200+N, so up to 4 generators load snuffles concurrently.
IPERF_SERVERS="${IPERF_SERVERS:-4}"
for n in $(seq 1 "$IPERF_SERVERS"); do
    port=$((5200 + n))
    if pgrep -f "^iperf3 -s -p $port( |\$)" >/dev/null 2>&1 && ss -ltnH "sport = :$port" | grep -q .; then
        echo "start-services: iperf3 server on :$port already running (pid $(pgrep -o -f "^iperf3 -s -p $port"))"
        continue
    fi
    pkill -f "^iperf3 -s -p $port( |\$)" >/dev/null 2>&1 || true
    iperf3 -s -p "$port" -D --logfile "${IPERF_LOG%.log}-$port.log"
    wait_listen "$port" "iperf3:$port"
    echo "start-services: iperf3 server started on :$port (pid $(pgrep -o -f "^iperf3 -s -p $port"), log ${IPERF_LOG%.log}-$port.log)"
done

# --- what is listening ---------------------------------------------------
echo "start-services: listening sockets:"
ss -ltnup
