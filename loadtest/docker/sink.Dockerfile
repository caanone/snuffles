# snuffles-sink: traffic target for the load-test rig (nginx, iperf3 server, udpsink).
# Build from the REPO ROOT (paths below are repo-relative):
#   docker build -f loadtest/docker/sink.Dockerfile -t snuffles-sink .
FROM debian:trixie

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        nginx iperf3 iproute2 procps python3 gcc libc6-dev nftables jq curl \
 && rm -rf /var/lib/apt/lists/* \
 && rm -f /etc/nginx/sites-enabled/default

# udpsink (syslog counter)
COPY loadtest/sink/udpsink.c /opt/sink/udpsink.c
RUN gcc -O2 -Wall -Wextra -o /opt/sink/udpsink /opt/sink/udpsink.c

# nginx: config + document root (/ small page, /big 100 MiB random)
COPY loadtest/sink/nginx.conf /etc/nginx/nginx.conf
RUN mkdir -p /var/www/sink \
 && printf '<!doctype html>\n<html><head><title>snf-sink</title></head>\n<body><h1>snuffles load-test sink</h1><p>ok</p></body></html>\n' \
        > /var/www/sink/index.html \
 && head -c 104857600 /dev/urandom > /var/www/sink/big \
 && chown -R www-data:www-data /var/www/sink \
 && nginx -t

COPY loadtest/sink/start-services.sh /opt/sink/start-services.sh
RUN chmod 0755 /opt/sink/start-services.sh

CMD ["sleep", "infinity"]
