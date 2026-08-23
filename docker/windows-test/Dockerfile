# Windows test environment: MinGW cross-compiler + Wine.
#
# Cross-compiles snuffles.exe and the unit tests for Windows, then runs
# them under Wine. This exercises the real Windows code paths (winsock,
# CreateThread, CRITICAL_SECTION, localtime_s, console I/O) without a
# Windows license or VM. Limits: raw-socket capture (SIO_RCVALL) and
# console-mode TUI behavior still need a real Windows box.
#
# Usage (from the repo root):
#   ./scripts/test-windows.sh

FROM debian:trixie-slim

RUN dpkg --add-architecture i386 && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc-mingw-w64-x86-64 \
        wine wine64 \
        make ca-certificates && \
    rm -rf /var/lib/apt/lists/*

ENV WINEDEBUG=-all \
    WINEPREFIX=/wine \
    WINEDLLOVERRIDES=mscoree,mshtml=

# Pre-create the Wine prefix so test runs don't pay the init cost
RUN wineboot --init >/dev/null 2>&1 || true; wineserver -w || true

WORKDIR /src
CMD ["./scripts/test-windows.sh", "--inner"]
