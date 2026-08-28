#!/bin/sh
# Cross-compile snuffles + unit tests for Windows and run them under Wine.
#
#   ./scripts/test-windows.sh            build the docker image and run inside it
#   ./scripts/test-windows.sh --inner    run directly (needs mingw-w64 + wine),
#                                        used inside the container and in CI
set -eu

if [ "${1:-}" != "--inner" ]; then
    IMG=snuffles-windows-test
    docker build -q -t "$IMG" docker/windows-test
    exec docker run --rm -v "$(pwd)":/src "$IMG"
fi

# ── inner: cross-compile and run ─────────────────────────────────
CC=x86_64-w64-mingw32-gcc
command -v "${CC}-posix" >/dev/null 2>&1 && CC="${CC}-posix"  # winpthreads flavor

CFLAGS="-std=c11 -Wall -Wextra -O1 -D_WIN32_WINNT=0x0601 -Iinclude -Isrc"
OUT=build-win
mkdir -p "$OUT"

echo "== cross-compiling snuffles.exe (NO_PCAP) with $CC"
$CC $CFLAGS -DNO_PCAP \
    src/main.c src/config.c src/capture_raw.c src/cbpf.c src/rawring.c src/dissect.c \
    src/filter.c src/ringbuf.c src/ui.c src/export_pcap.c src/export_json.c \
    src/stats.c src/session.c src/syslog_out.c \
    -o "$OUT/snuffles.exe" -static -lws2_32 -liphlpapi -lpthread

echo "== cross-compiling unit tests"
# test_ui is POSIX-only (drives ui_run() through a pipe): not built here.
for t in filter ringbuf session dissect cbpf rawring config syslog_out; do
    $CC $CFLAGS "tests/test_$t.c" "src/$t.c" -o "$OUT/test_$t.exe" \
        -static -lws2_32 -lpthread
done
# export_json.c also walks the ring through the display filter
$CC $CFLAGS tests/test_export_json.c src/export_json.c src/filter.c src/ringbuf.c \
    -o "$OUT/test_export_json.exe" -static -lws2_32 -lpthread

WINE=${WINE:-wine}
export WINEDEBUG=${WINEDEBUG:--all}

echo "== running unit tests under Wine"
rc=0
for t in filter ringbuf session dissect cbpf rawring config export_json syslog_out; do
    printf '%-10s ' "$t"
    if $WINE "$OUT/test_$t.exe"; then :; else
        echo "FAILED: test_$t.exe"
        rc=1
    fi
done

echo "== snuffles.exe smoke test"
$WINE "$OUT/snuffles.exe" -v
$WINE "$OUT/snuffles.exe" --help >/dev/null

if [ "$rc" -eq 0 ]; then
    echo "== windows tests: ALL PASS"
else
    echo "== windows tests: FAILURES"
fi
exit "$rc"
