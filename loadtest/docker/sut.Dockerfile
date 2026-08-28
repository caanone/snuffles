# snuffles-sut: system-under-test image for the load-test rig (loadtest/SPEC.md).
#
# Build context does not matter (nothing is COPYed): the harness scripts are
# taken from the read-only /repo bind mount at run time, via thin wrappers in
# /opt/snuffles/, so editing loadtest/sut/* never requires an image rebuild.
#
#   docker build -f loadtest/docker/sut.Dockerfile -t snuffles-sut .
FROM debian:trixie

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential pkg-config libpcap-dev \
        linux-perf \
        iproute2 procps python3 ethtool nftables strace jq rsync \
        iputils-ping ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Harness entry points (SPEC: /opt/snuffles/build.sh etc.). Each execs the
# live copy under /repo/loadtest/sut/ so the image never goes stale.
RUN mkdir -p /opt/snuffles /src && \
    for f in build.sh telemetry.sh run-snuffles.sh perf.sh tui.py; do \
        printf '#!/bin/bash\nexec /repo/loadtest/sut/%s "$@"\n' "$f" > /opt/snuffles/$f; \
        chmod 0755 /opt/snuffles/$f; \
    done

ENV TERM=xterm-256color
WORKDIR /opt/snuffles
CMD ["sleep", "infinity"]
