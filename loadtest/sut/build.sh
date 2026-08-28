#!/bin/bash
# build.sh — (re)build snuffles inside the snf-sut container (loadtest/SPEC.md).
#
#   /opt/snuffles/build.sh            (wrapper -> /repo/loadtest/sut/build.sh)
#
# Copies /repo -> /src (excluding build/, .git, loadtest/results) and does a
# clean build of
#   /opt/snuffles/pcap/snuffles   (make          — libpcap backend)
#   /opt/snuffles/raw/snuffles    (make nopcap   — AF_PACKET backend)
# with CFLAGS="-g -fno-omit-frame-pointer" (the Makefile adds its own -O2).
# Re-runnable at any time. Env overrides: SNF_REPO (default /repo),
# SNF_SRC (/src), SNF_OUT (/opt/snuffles), SNF_CFLAGS.
set -euo pipefail

REPO=${SNF_REPO:-/repo}
SRC=${SNF_SRC:-/src}
OUT=${SNF_OUT:-/opt/snuffles}
CFLAGS=${SNF_CFLAGS:-"-g -fno-omit-frame-pointer"}
JOBS=$(nproc 2>/dev/null || echo 2)

[[ -f $REPO/Makefile && -d $REPO/src ]] || {
    echo "build.sh: $REPO does not look like the snuffles repo (Makefile/src missing)" >&2
    exit 1
}

mkdir -p "$SRC" "$OUT/pcap" "$OUT/raw"
echo "build.sh: syncing $REPO -> $SRC"
rsync -a --delete \
      --exclude build --exclude .git --exclude loadtest/results \
      --exclude build-win --exclude .claude \
      "$REPO/" "$SRC/"

cd "$SRC"
# Clean build every time: cheap (a dozen files) and immune to stale objects
# when an experiment edits headers or flags.
rm -rf "$SRC/build" "$SRC/snuffles"

echo "build.sh: make (pcap) CFLAGS=\"$CFLAGS\" -j$JOBS"
make -j"$JOBS" CFLAGS="$CFLAGS" all
install -m 0755 "$SRC/build/pcap/snuffles" "$OUT/pcap/snuffles"

echo "build.sh: make nopcap (raw) CFLAGS=\"$CFLAGS\" -j$JOBS"
make -j"$JOBS" CFLAGS="$CFLAGS" nopcap
install -m 0755 "$SRC/build/raw/snuffles" "$OUT/raw/snuffles"

{
    echo "built_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "cflags=$CFLAGS"
    echo "source=$REPO"
} > "$OUT/build-info.txt"

echo "== $OUT/pcap/snuffles -v"
"$OUT/pcap/snuffles" -v
echo "== $OUT/raw/snuffles -v"
"$OUT/raw/snuffles" -v
echo "build.sh: done"
