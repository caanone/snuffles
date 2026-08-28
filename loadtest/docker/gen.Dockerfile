# snuffles-gen — traffic generator image for the load-test rig.
# Build:  docker build -f loadtest/docker/gen.Dockerfile -t snuffles-gen .
# (build context is the REPO ROOT, as rig.sh build does; paths are repo-relative)
# The .sh drivers in /opt/gen are thin wrappers that exec the live copies under
# /repo/loadtest/gen/ (the C generators and the corpus are baked).
FROM debian:trixie

ENV DEBIAN_FRONTEND=noninteractive

# SPEC package set. Notes:
#  - dnsutils is a removed transitional package in trixie -> bind9-dnsutils
#    (provides dig/nslookup/host).
#  - wrk IS packaged in trixie (4.1.0), so no source build / ab fallback needed.
#  - libc6-dev is required to compile the C generators with gcc.
RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 \
        ethtool \
        tcpreplay \
        iperf3 \
        wrk \
        hping3 \
        nmap \
        python3 \
        python3-scapy \
        gcc \
        libc6-dev \
        make \
        procps \
        nftables \
        curl \
        bind9-dnsutils \
        jq \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# MACs baked into the replay corpus (L2 gen -> sink so the bridge forwards).
ARG GEN_MAC=02:53:4e:46:01:01
ARG SINK_MAC=02:53:4e:46:00:05

COPY loadtest/gen/ /opt/gen-src/

# Build the C generators and the drivers into /opt/gen, then build the corpus.
RUN set -eux; \
    mkdir -p /opt/gen; \
    gcc -O2 -Wall -Wextra -pthread /opt/gen-src/udpflood.c -o /opt/gen/udpflood; \
    gcc -O2 -Wall -Wextra -fno-strict-aliasing -pthread /opt/gen-src/synflood.c -o /opt/gen/synflood; \
    for f in pktgen.sh http.sh iperf.sh replay.sh frag.sh; do \
        printf '#!/bin/bash\n# live wrapper: the driver is taken from the read-only /repo mount at\n# run time so editing loadtest/gen/*.sh never needs an image rebuild.\n[ -x /repo/loadtest/gen/%s ] && exec /repo/loadtest/gen/%s "$@"\nexec /opt/gen-src/%s "$@"\n' "$f" "$f" "$f" > /opt/gen/$f; \
    done; \
    cp /opt/gen-src/make-corpus.py /opt/gen/; \
    chmod +x /opt/gen/*.sh /opt/gen-src/*.sh /opt/gen/make-corpus.py; \
    python3 /opt/gen/make-corpus.py /opt/gen/corpus.pcap \
        --count 20000 --gen-mac "$GEN_MAC" --sink-mac "$SINK_MAC"; \
    test -s /opt/gen/corpus.pcap; \
    /opt/gen/udpflood -h 2>/dev/null || true; \
    ls -l /opt/gen

ENV PATH="/opt/gen:${PATH}"
WORKDIR /opt/gen

# containers run sleep infinity and receive work via `docker exec`
CMD ["sleep", "infinity"]
