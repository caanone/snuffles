#!/usr/bin/env python3
"""latency.py — capture-to-output latency probe for snuffles --jsonl.

    snuffles --jsonl | latency.py -o latency.json

Reads snuffles' JSON-Lines packet stream from stdin, one object per captured
packet. Each object begins with a "ts":"<sec>.<usec>" field — the packet's
capture timestamp (wall clock, set by libpcap/AF_PACKET at capture time). For
every line we record  now - ts  (milliseconds): the time from a packet being
captured to its JSON line reaching this consumer through the ring buffer and the
pipe. This is the end-to-end capture-to-output latency of the headless/jsonl
path.

Samples are binned into a fixed-resolution histogram (default 20 us buckets up
to 2000 ms, plus one overflow bucket), so memory is O(buckets) regardless of
packet count. On EOF (snuffles exited / the pipe closed) or SIGINT/SIGTERM we
compute percentiles from the histogram and write:

    {"count":N,"p50_ms":..,"p95_ms":..,"p99_ms":..,"min_ms":..,"max_ms":..,
     "mean_ms":..,"neg_ms_clamped":N,"bucket_us":U,"max_ms_hist":M,"overflow":N}

`ts` is parsed with a cheap string scan (not json.loads) so the probe keeps up
with high packet rates; malformed lines are counted and skipped. The percentiles
are the low edge of the containing bucket (resolution = bucket_us). A value past
max_ms_hist lands in the overflow bucket and is reported via max_ms (tracked
exactly) but percentiles at/above it read as ">= max_ms_hist".
"""
import argparse
import os
import signal
import sys
import time

_stop = False


def _on_signal(signum, frame):
    global _stop
    _stop = True


def parse_ts(line):
    """Extract the leading "ts":"<float>" value from a JSON line, or None.
    Cheap and allocation-light: find the key, then the quoted number."""
    # snuffles emits ts first: {"ts":"1712345678.123456",...}
    k = line.find('"ts":')
    if k < 0:
        return None
    i = k + 5
    n = len(line)
    # skip spaces and an opening quote
    while i < n and line[i] in ' \t':
        i += 1
    if i < n and line[i] == '"':
        i += 1
    j = i
    while j < n:
        c = line[j]
        if (c >= '0' and c <= '9') or c == '.' or c == '-' or c == '+':
            j += 1
        else:
            break
    if j == i:
        return None
    try:
        return float(line[i:j])
    except ValueError:
        return None


def main():
    ap = argparse.ArgumentParser(description="snuffles --jsonl capture-to-output latency probe")
    ap.add_argument("-o", "--out", default="latency.json", help="output JSON path")
    ap.add_argument("--bucket-us", type=float, default=20.0, help="histogram resolution (microseconds)")
    ap.add_argument("--max-ms", type=float, default=2000.0, help="histogram ceiling (ms); larger -> overflow bucket")
    ap.add_argument("--flush-secs", type=float, default=2.0, help="rewrite the output file this often while running")
    args = ap.parse_args()

    signal.signal(signal.SIGINT, _on_signal)
    signal.signal(signal.SIGTERM, _on_signal)

    bucket_ms = args.bucket_us / 1000.0
    nbuckets = int(args.max_ms / bucket_ms) + 1
    hist = [0] * (nbuckets + 1)          # last cell = overflow
    overflow_idx = nbuckets

    count = 0
    bad = 0
    neg_clamped = 0
    total_ms = 0.0
    min_ms = None
    max_ms = None

    def percentile(frac):
        if count == 0:
            return None
        target = frac * count
        cum = 0
        for idx in range(nbuckets + 1):
            cum += hist[idx]
            if cum >= target:
                if idx == overflow_idx:
                    return args.max_ms      # ">= ceiling"
                return round(idx * bucket_ms, 4)
        return round((nbuckets - 1) * bucket_ms, 4)

    def snapshot():
        return {
            "count": count,
            "p50_ms": percentile(0.50),
            "p95_ms": percentile(0.95),
            "p99_ms": percentile(0.99),
            "min_ms": round(min_ms, 4) if min_ms is not None else None,
            "max_ms": round(max_ms, 4) if max_ms is not None else None,
            "mean_ms": round(total_ms / count, 4) if count else None,
            "bad_lines": bad,
            "neg_ms_clamped": neg_clamped,
            "bucket_us": args.bucket_us,
            "max_ms_hist": args.max_ms,
            "overflow": hist[overflow_idx],
        }

    def write_out():
        import json
        tmp = args.out + ".tmp"
        try:
            with open(tmp, "w") as f:
                json.dump(snapshot(), f)
                f.write("\n")
            os.replace(tmp, args.out)
        except Exception as e:
            print(f"latency.py: write failed: {e}", file=sys.stderr)

    next_flush = time.time() + args.flush_secs
    inp = sys.stdin
    while not _stop:
        line = inp.readline()
        if not line:                      # EOF: snuffles exited / pipe closed
            break
        ts = parse_ts(line)
        if ts is None:
            bad += 1
            continue
        d_ms = (time.time() - ts) * 1000.0
        if d_ms < 0.0:                     # clock skew / future ts: clamp to 0
            neg_clamped += 1
            d_ms = 0.0
        count += 1
        total_ms += d_ms
        if min_ms is None or d_ms < min_ms:
            min_ms = d_ms
        if max_ms is None or d_ms > max_ms:
            max_ms = d_ms
        idx = int(d_ms / bucket_ms)
        if idx >= nbuckets:
            idx = overflow_idx
        hist[idx] += 1
        if (count & 0x3FFF) == 0:          # periodic flush without a clock read per line
            now = time.time()
            if now >= next_flush:
                write_out()
                next_flush = now + args.flush_secs

    write_out()
    print(f"latency.py: {count} samples, {bad} bad lines -> {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
