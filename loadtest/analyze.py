#!/usr/bin/env python3
"""loadtest/analyze.py <run-id>

Reads loadtest/results/<run-id>/<scenario>/ for every scenario in the run and
writes, per scenario, summary.json (SPEC step 8 fields), and per run
summary.csv + summary.md (table sorted by scenario name). Tolerant of missing
inputs (writes null) and safe to run repeatedly.

CPU% of a thread = (delta (utime+stime) ticks / CLK_TCK) / delta wall seconds
* 100, measured over the steady-state traffic window (first..last telemetry
sample whose timestamp falls in [manifest.traffic_start + MARGIN,
manifest.traffic_end - MARGIN]; traffic_start = every generator running,
traffic_end = first stop issued). captured_pps and kdrop_pct_win are likewise
measured across the snuffles.stats lines inside that window (their relative
't' is mapped to epoch with manifest.stats_t0_epoch), not the whole run.
Totals (sent, captured, kdrop, bridge_in_pkts_total, ...) are whole-run.

Accounting chain (all whole-run, app-independent unless noted):
  sent_total            generator's own count, WIRE FRAMES (udpflood/frag
                        datagrams are multiplied by fragments-per-datagram)
  bridge_in_pkts_total  sum of rx_packets over p1..p5 = every frame that
                        entered the bridge (gens + sink replies)
  br0_rx_pkts_total     frames passed up to br0 (== bridge_in while promisc)
  captured+kdrop        what the packet socket saw (app counters)
  seen_pct              100*(captured+kdrop)/bridge_in_pkts_total
  sink_in/out           p5 tx / p5 rx = frames to / from the sink
"""
import sys, os, json, csv, glob, math

CLK_TCK = 100
MARGIN = 0.5          # seconds trimmed at both ends of the traffic window

def repo_results():
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(here, "results")

def load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None

def read_jsonl(path):
    rows = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except Exception:
                    pass
    except Exception:
        pass
    return rows

def parse_stats(path):
    """Return list of dicts for each 'stats'/'summary' line: {tag,t,captured,
    kdrop,ifdrop,ring,emitted,missed,syslog_sent,syslog_fail,streamed,sessions,
    rss_kb}. Fields are ints/floats where present."""
    out = []
    try:
        with open(path) as f:
            for line in f:
                parts = line.split()
                if not parts or parts[0] not in ("stats", "summary"):
                    continue
                rec = {"tag": parts[0]}
                for tok in parts[1:]:
                    if "=" not in tok:
                        continue
                    k, v = tok.split("=", 1)
                    try:
                        rec[k] = float(v) if k == "t" else int(v)
                    except ValueError:
                        try:
                            rec[k] = float(v)
                        except ValueError:
                            rec[k] = None
                out.append(rec)
    except Exception:
        pass
    return out

def gen_files(scen_dir):
    return sorted(glob.glob(os.path.join(scen_dir, "gen-*.json")))

def num(x):
    return x if isinstance(x, (int, float)) else None

def add(*vals):
    """Sum, ignoring None; return None if every value is None."""
    seen = [v for v in vals if isinstance(v, (int, float))]
    return sum(seen) if seen else None

def in_window(t, t0, t1):
    if t is None:
        return False
    if t0 is not None and t < t0:
        return False
    if t1 is not None and t > t1:
        return False
    return True

def analyze_scenario(scen_dir):
    name = os.path.basename(scen_dir)
    man = load_json(os.path.join(scen_dir, "manifest.json")) or {}
    tr = man.get("traffic", {}) or {}
    ts = man.get("traffic_start")     # epoch (telemetry.jsonl 't' is epoch too)
    te = man.get("traffic_end")
    # steady-state window: trim MARGIN at both ends (generator start skew,
    # 1 Hz sampling phase, stats-line mapping error)
    t0 = t1 = None
    if isinstance(ts, (int, float)) and isinstance(te, (int, float)) and te - ts > 2 * MARGIN + 1:
        t0, t1 = ts + MARGIN, te - MARGIN
    # snuffles.stats 't' is seconds since snuffles' stats-thread start, NOT an
    # epoch. stats_t0_epoch (first stats line epoch minus its t) pins that
    # origin to +-0.1 s; snuffles_start (docker exec return, before the
    # capture is opened) is the coarser fallback.
    snuf0 = man.get("stats_t0_epoch")
    if not isinstance(snuf0, (int, float)):
        snuf0 = man.get("snuffles_start")
    st0 = (t0 - snuf0) if isinstance(snuf0, (int, float)) and isinstance(t0, (int, float)) else None
    st1 = (t1 - snuf0) if isinstance(snuf0, (int, float)) and isinstance(t1, (int, float)) else None

    s = {
        "name": name,
        "build": man.get("build"),
        "mode": man.get("mode"),
        "traffic_kind": tr.get("kind"),
        "pkt_size": tr.get("pkt_size"),
        "status": man.get("status"),
    }

    # ── generators: sent totals + pps ──────────────────────────────────────
    sent_total = None
    sent_pps = None
    for gf in gen_files(scen_dir):
        g = load_json(gf) or {}
        sent_total = add(sent_total, num(g.get("sent_pkts")))
        sent_pps = add(sent_pps, num(g.get("pps")))
    s["sent_pps"] = sent_pps
    s["sent_total"] = sent_total
    # datagram view for udpflood/frag (sent_total is wire frames)
    sent_dg = None; fpd = None
    for gf in gen_files(scen_dir):
        g = load_json(gf) or {}
        sent_dg = add(sent_dg, num(g.get("sent_datagrams")))
        if isinstance(g.get("frames_per_datagram"), (int, float)):
            fpd = g["frames_per_datagram"]
    s["sent_datagrams"] = sent_dg
    s["frames_per_datagram"] = fpd
    s["window_secs"] = round(t1 - t0, 3) if (t0 is not None and t1 is not None) else None

    # ── snuffles.stats within the traffic window ───────────────────────────
    stats = parse_stats(os.path.join(scen_dir, "snuffles.stats"))
    summ = [r for r in stats if r["tag"] == "summary"]
    win = [r for r in stats if r["tag"] == "stats" and in_window(r.get("t"), st0, st1)]
    # captured_total: prefer the final summary line's captured, else last stats
    captured_total = None
    if summ and isinstance(summ[-1].get("captured"), (int, float)):
        captured_total = summ[-1]["captured"]
    elif stats:
        for r in reversed(stats):
            if isinstance(r.get("captured"), (int, float)):
                captured_total = r["captured"]
                break

    # captured_pps over the window: delta captured / delta t across window samples
    captured_pps = None
    kdrop_win = None
    if len(win) >= 2:
        c0, c1 = win[0].get("captured"), win[-1].get("captured")
        w0, w1 = win[0].get("t"), win[-1].get("t")
        if all(isinstance(x, (int, float)) for x in (c0, c1, w0, w1)) and w1 > w0:
            captured_pps = (c1 - c0) / (w1 - w0)
        k0, k1 = win[0].get("kdrop"), win[-1].get("kdrop")
        if all(isinstance(x, (int, float)) for x in (k0, k1)):
            kdrop_win = k1 - k0

    # final-run counters (kdrop/ifdrop/missed/emitted/streamed/sessions from last line)
    last = (summ[-1] if summ else (stats[-1] if stats else {})) or {}
    kdrop_total = last.get("kdrop")
    ifdrop = last.get("ifdrop")
    missed = last.get("missed")
    emitted = last.get("emitted")
    streamed = last.get("streamed")
    syslog_sent = last.get("syslog_sent")
    syslog_fail = last.get("syslog_fail")
    sessions_final = last.get("sessions")

    s["captured_total"] = captured_total
    s["captured_pps"] = round(captured_pps, 1) if captured_pps is not None else None
    s["kdrop_total"] = kdrop_total
    # kdrop_pct = kdrop/(captured+kdrop)
    if isinstance(kdrop_total, (int, float)) and isinstance(captured_total, (int, float)):
        denom = captured_total + kdrop_total
        s["kdrop_pct"] = round(100.0 * kdrop_total / denom, 4) if denom > 0 else 0.0
    else:
        s["kdrop_pct"] = None
    # steady-state kdrop% and rates over the window (deltas between the first
    # and last stats line inside the window)
    s["captured_win"] = None; s["kdrop_win"] = None; s["kdrop_pct_win"] = None
    s["offered_pps_win"] = None
    if len(win) >= 2:
        c0, c1 = win[0].get("captured"), win[-1].get("captured")
        w0, w1 = win[0].get("t"), win[-1].get("t")
        if all(isinstance(x, (int, float)) for x in (c0, c1, w0, w1)) and w1 > w0 and isinstance(kdrop_win, (int, float)):
            s["captured_win"] = c1 - c0
            s["kdrop_win"] = kdrop_win
            den = (c1 - c0) + kdrop_win
            s["kdrop_pct_win"] = round(100.0 * kdrop_win / den, 4) if den > 0 else 0.0
            s["offered_pps_win"] = round(den / (w1 - w0), 1)
    s["ifdrop"] = ifdrop
    s["missed"] = missed
    s["emitted"] = emitted
    s["streamed"] = streamed
    s["syslog_sent"] = syslog_sent
    s["syslog_fail"] = syslog_fail
    s["sessions_final"] = sessions_final

    # loss_pct_total = 1 - captured/sent (when sent known)
    if isinstance(captured_total, (int, float)) and isinstance(sent_total, (int, float)) and sent_total > 0:
        s["loss_pct_total"] = round(100.0 * (1.0 - captured_total / sent_total), 4)
    else:
        s["loss_pct_total"] = None

    # ── sink (syslog delivery) ─────────────────────────────────────────────
    sink = load_json(os.path.join(scen_dir, "sink.json")) or {}
    s["syslog_delivered"] = sink.get("received")
    s["syslog_rcvbuf_errors"] = sink.get("rcvbuf_errors_delta")
    s["syslog_in_errors"] = sink.get("in_errors_delta")
    if isinstance(sink.get("received"), (int, float)) and isinstance(syslog_sent, (int, float)) and syslog_sent > 0:
        s["syslog_delivery_pct"] = round(100.0 * sink["received"] / syslog_sent, 3)
    else:
        s["syslog_delivery_pct"] = None
    s["kdrop_source"] = ("libpcap ps_drop (TPACKET tp_drops; not in ss sk_drops)" if man.get("build") == "pcap"
                         else "PACKET_STATISTICS tp_drops (== ss sk_drops)" if man.get("build") == "raw" else None)

    # ── telemetry: rss_max, per-thread CPU% over the window ────────────────
    tel = read_jsonl(os.path.join(scen_dir, "telemetry.jsonl"))
    telwin = [r for r in tel if in_window(r.get("t"), t0, t1) and r.get("proc")]
    s["telemetry_samples_win"] = len(telwin)
    rss_max = None
    for r in tel:
        p = r.get("proc") or {}
        rk = p.get("rss_kb")
        if isinstance(rk, (int, float)):
            rss_max = rk if rss_max is None else max(rss_max, rk)
    s["rss_max_kb"] = rss_max
    la = [(r.get("loadavg") or [None])[0] for r in tel]
    la = [x for x in la if isinstance(x, (int, float))]
    s["host_loadavg1_max"] = max(la) if la else None

    def thread_cpu_pct(comm):
        pts = []
        for r in telwin:
            th = (r.get("threads") or {}).get(comm)
            if not th:
                continue
            u, st = th.get("utime"), th.get("stime")
            if isinstance(u, (int, float)) and isinstance(st, (int, float)):
                pts.append((r["t"], u + st))
        if len(pts) < 2:
            return None
        (wa, ta), (wb, tb) = pts[0], pts[-1]
        if wb <= wa:
            return None
        cpu_secs = (tb - ta) / CLK_TCK
        return round(100.0 * cpu_secs / (wb - wa), 2)

    s["cpu_capture_pct"] = thread_cpu_pct("snf-capture")
    s["cpu_stats_pct"] = thread_cpu_pct("snf-stats")
    # main/consumer thread: the process comm is "snuffles"
    s["cpu_main_pct"] = thread_cpu_pct("snuffles")
    # whole process (all threads) from proc utime+stime: cross-check against
    # perf stat's "CPUs utilized" (perf_cpus_utilized below)
    def proc_cpu_pct():
        pts = []
        for r in telwin:
            p = r.get("proc") or {}
            u, st = p.get("utime"), p.get("stime")
            if isinstance(u, (int, float)) and isinstance(st, (int, float)):
                pts.append((r["t"], u + st))
        if len(pts) < 2 or pts[-1][0] <= pts[0][0]:
            return None
        return round(100.0 * ((pts[-1][1] - pts[0][1]) / CLK_TCK) / (pts[-1][0] - pts[0][0]), 2)
    s["cpu_total_pct"] = proc_cpu_pct()

    # ctxsw_per_s: (nvcsw+nivcsw) delta over the window / wall
    def proc_field(getter):
        pts = []
        for r in telwin:
            p = r.get("proc") or {}
            v = getter(p)
            if isinstance(v, (int, float)):
                pts.append((r["t"], v))
        return pts

    csw = proc_field(lambda p: add(p.get("nvcsw"), p.get("nivcsw")))
    if len(csw) >= 2 and csw[-1][0] > csw[0][0]:
        s["ctxsw_per_s"] = round((csw[-1][1] - csw[0][1]) / (csw[-1][0] - csw[0][0]), 1)
    else:
        s["ctxsw_per_s"] = None

    # softnet + br0 rx deltas over the window
    def softnet_delta(key):
        pts = []
        for r in telwin:
            sn = r.get("softnet") or {}
            v = sn.get(key)
            if isinstance(v, (int, float)):
                pts.append(v)
        return (pts[-1] - pts[0]) if len(pts) >= 2 else None
    s["softnet_dropped_delta"] = softnet_delta("dropped")
    s["softnet_squeezed_delta"] = softnet_delta("time_squeeze")

    def iface_delta(dev, key, rows):
        pts = []
        for r in rows:
            i = (r.get("ifaces") or {}).get(dev) or {}
            v = i.get(key)
            if isinstance(v, (int, float)):
                pts.append(v)
        return (pts[-1] - pts[0]) if len(pts) >= 2 else None
    s["br0_rx_pkts_delta"] = iface_delta("br0", "rx_packets", telwin)
    # whole-run, app-independent frame accounting from the SUT-side veth ends
    # (telemetry starts before traffic and ends after snuffles exits)
    telall = [r for r in tel if r.get("ifaces")]
    s["br0_rx_pkts_total"] = iface_delta("br0", "rx_packets", telall)
    s["bridge_in_pkts_total"] = add(*[iface_delta(p, "rx_packets", telall) for p in ("p1", "p2", "p3", "p4", "p5")])
    s["gens_in_pkts_total"] = add(*[iface_delta(p, "rx_packets", telall) for p in ("p1", "p2", "p3", "p4")])
    s["sink_in_pkts_total"] = iface_delta("p5", "tx_packets", telall)
    s["sink_out_pkts_total"] = iface_delta("p5", "rx_packets", telall)
    s["gens_out_pkts_total"] = add(*[iface_delta(p, "tx_packets", telall) for p in ("p1", "p2", "p3", "p4")])
    s["veth_dropped_total"] = add(*[iface_delta(p, k, telall) for p in ("br0", "p1", "p2", "p3", "p4", "p5") for k in ("rx_dropped", "tx_dropped")])
    seen = add(captured_total, kdrop_total)
    bi = s["bridge_in_pkts_total"]
    s["seen_pct"] = round(100.0 * seen / bi, 3) if isinstance(seen, (int, float)) and isinstance(bi, (int, float)) and bi > 0 else None
    s["sent_vs_bridge_pct"] = round(100.0 * sent_total / s["gens_in_pkts_total"], 3) if isinstance(sent_total, (int, float)) and isinstance(s["gens_in_pkts_total"], (int, float)) and s["gens_in_pkts_total"] > 0 else None

    # packet_socket_drops: the socket's cumulative sk_drops (ss skmem d<N>);
    # monotonic and gone once snuffles exits, so take the max over ALL samples
    # (the last in-window sample would miss the final second of traffic)
    pktsock_drops = None
    for r in tel:
        ps = r.get("pktsock") or {}
        d = ps.get("drops")
        if isinstance(d, (int, float)):
            pktsock_drops = d if pktsock_drops is None else max(pktsock_drops, d)
    s["packet_socket_drops"] = pktsock_drops

    # ── perf stat: syscalls_per_pkt, ipc ───────────────────────────────────
    ps = parse_perf_stat(os.path.join(scen_dir, "perf-stat.txt"))
    ipc = None
    if ps.get("instructions") and ps.get("cycles"):
        ipc = round(ps["instructions"] / ps["cycles"], 3)
    s["ipc"] = ipc
    s["perf_stat_secs"] = ps.get("_elapsed_secs")
    tc = ps.get("_task_clock_secs"); el = ps.get("_elapsed_secs")
    s["perf_cpus_utilized"] = round(tc / el, 3) if isinstance(tc, (int, float)) and isinstance(el, (int, float)) and el > 0 else None
    s["perf_ctxsw_per_s"] = round(ps["context-switches"] / el, 1) if isinstance(ps.get("context-switches"), (int, float)) and isinstance(el, (int, float)) and el > 0 else None
    syscalls = add(ps.get("syscalls:sys_enter_write"), ps.get("syscalls:sys_enter_sendto"),
                   ps.get("syscalls:sys_enter_getsockopt"), ps.get("syscalls:sys_enter_recvfrom"),
                   ps.get("syscalls:sys_enter_select"), ps.get("syscalls:sys_enter_poll"))
    s["perf_syscalls"] = syscalls
    s["perf_syscalls_write"] = ps.get("syscalls:sys_enter_write")
    s["perf_syscalls_getsockopt"] = ps.get("syscalls:sys_enter_getsockopt")
    # packets captured during EXACTLY the perf stat window: stats-line delta
    # over [stat_start, stat_end] (perf-window.json, epoch -> stats t via
    # snuf0). Fallback: captured_pps * elapsed wall seconds. NEVER task-clock
    # seconds (CPU time, not wall time: a 45%-busy process would inflate
    # syscalls/pkt 2.2x).
    pw = load_json(os.path.join(scen_dir, "perf-window.json")) or {}
    pkts_stat = None
    s["perf_stat_window_pkts"] = None
    if isinstance(pw.get("stat_start"), (int, float)) and isinstance(pw.get("stat_end"), (int, float)) and isinstance(snuf0, (int, float)):
        # perf needs ~0.4 s to open its events before counting starts; the
        # counting window is the last `elapsed` seconds before stat_end.
        b = pw["stat_end"] - snuf0
        a = (b - el) if isinstance(el, (int, float)) and 0 < el < (pw["stat_end"] - pw["stat_start"]) else (pw["stat_start"] - snuf0)
        inside = [r for r in stats if r["tag"] == "stats" and isinstance(r.get("t"), (int, float)) and a <= r["t"] <= b]
        if len(inside) >= 2 and isinstance(inside[0].get("captured"), (int, float)) and isinstance(inside[-1].get("captured"), (int, float)):
            dt = inside[-1]["t"] - inside[0]["t"]
            if dt > 0:
                # scale the inside-samples delta to the full stat window length
                pkts_stat = (inside[-1]["captured"] - inside[0]["captured"]) * ((b - a) / dt)
                s["perf_stat_window_pkts"] = round(pkts_stat)
    if pkts_stat is None and isinstance(captured_pps, (int, float)) and isinstance(el, (int, float)) and el > 0:
        pkts_stat = captured_pps * el
    if isinstance(syscalls, (int, float)) and isinstance(pkts_stat, (int, float)) and pkts_stat > 0:
        s["syscalls_per_pkt"] = round(syscalls / pkts_stat, 5)
    else:
        s["syscalls_per_pkt"] = None

    # ── exit info: the manifest carries the FIRST stop's result; exit.json
    # can be rewritten by a second `stop` on an already-exited pid (latency
    # 2 ms, signal none), so it is only a fallback.
    exitj = load_json(os.path.join(scen_dir, "exit.json")) or {}
    s["exit_latency_ms"] = man.get("exit_latency_ms", exitj.get("exit_latency_ms"))
    s["exit_code"] = man.get("exit_code", exitj.get("exit_code"))
    s["killed"] = man.get("killed", exitj.get("killed"))
    if s["exit_latency_ms"] is None:
        s["exit_latency_ms"] = exitj.get("exit_latency_ms")
    if s["exit_code"] is None:
        s["exit_code"] = exitj.get("exit_code")
    if s["killed"] is None:
        s["killed"] = exitj.get("killed")

    with open(os.path.join(scen_dir, "summary.json"), "w") as f:
        json.dump(s, f, indent=2)
        f.write("\n")
    return s

def parse_perf_stat(path):
    """Parse `perf stat` default text output. Returns {event: count} for the
    counters we track, plus _task_clock_secs (task-clock ms / 1000)."""
    out = {}
    try:
        with open(path) as f:
            lines = f.readlines()
    except Exception:
        return out
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("Performance counter"):
            continue
        # format: "<count>  <event>   # ..." ; count may have commas or be "<not counted>"
        parts = line.split()
        if len(parts) < 2:
            continue
        count_s = parts[0].replace(",", "").replace(".", "")
        # event name is parts[1] unless it's a unit like "msec" (task-clock line)
        if parts[1] in ("msec", "seconds"):
            # e.g. "1234.56 msec task-clock ..." / "4.001 seconds time elapsed"
            try:
                val = float(parts[0].replace(",", ""))
            except ValueError:
                continue
            if "task-clock" in line:
                out["_task_clock_secs"] = val / 1000.0
            elif "time elapsed" in line:
                out["_elapsed_secs"] = val
            continue
        try:
            count = int(count_s)
        except ValueError:
            continue
        ev = parts[1]
        out[ev] = count
    return out

def fmt_pps(v):
    if not isinstance(v, (int, float)):
        return ""
    a = abs(v)
    if a >= 1e6:
        return f"{v/1e6:.3g}M"
    if a >= 1e3:
        return f"{v/1e3:.3g}k"
    return f"{v:.3g}"

def fmt_pct(v):
    return f"{v:.2f}" if isinstance(v, (int, float)) else ""

def write_run_tables(run_dir, rows):
    rows = sorted(rows, key=lambda r: r["name"])
    # summary.csv: every field, stable column order
    cols = ["name", "build", "mode", "traffic_kind", "pkt_size", "status",
            "sent_pps", "sent_total", "captured_total", "captured_pps",
            "kdrop_total", "kdrop_pct", "ifdrop", "missed", "emitted",
            "syslog_sent", "syslog_fail", "syslog_delivered", "streamed",
            "sessions_final", "loss_pct_total", "rss_max_kb",
            "cpu_capture_pct", "cpu_main_pct", "cpu_stats_pct", "ctxsw_per_s",
            "syscalls_per_pkt", "ipc", "exit_latency_ms", "exit_code", "killed",
            "softnet_dropped_delta", "softnet_squeezed_delta",
            "br0_rx_pkts_delta", "packet_socket_drops",
            # extras (not SPEC step-8): steady-state window + accounting chain
            "window_secs", "telemetry_samples_win", "offered_pps_win",
            "captured_win", "kdrop_win", "kdrop_pct_win", "cpu_total_pct",
            "perf_cpus_utilized", "perf_stat_secs", "perf_stat_window_pkts",
            "perf_syscalls", "perf_syscalls_write", "perf_syscalls_getsockopt",
            "perf_ctxsw_per_s", "sent_datagrams", "frames_per_datagram",
            "bridge_in_pkts_total", "br0_rx_pkts_total", "gens_in_pkts_total",
            "gens_out_pkts_total", "sink_in_pkts_total", "sink_out_pkts_total",
            "veth_dropped_total", "seen_pct", "sent_vs_bridge_pct",
            "syslog_delivery_pct", "syslog_rcvbuf_errors", "syslog_in_errors",
            "host_loadavg1_max", "kdrop_source"]
    with open(os.path.join(run_dir, "summary.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({c: ("" if r.get(c) is None else r.get(c)) for c in cols})

    # summary.md: compact human table
    md = []
    md.append(f"# Load-test summary — run `{os.path.basename(run_dir)}`\n")
    md.append(f"{len(rows)} scenario(s). pps in k/M (3 sig. figs); percentages 2 dp.\n")
    head = ["scenario", "mode", "kind", "sent", "bridge in", "seen%", "captured",
            "offered pps", "cap pps", "kdrop%", "kdrop% win", "rss MB",
            "cap%", "main%", "sys/pkt", "ipc", "win s", "status"]
    md.append("| " + " | ".join(head) + " |")
    md.append("|" + "|".join(["---"] * len(head)) + "|")
    for r in rows:
        rss = r.get("rss_max_kb")
        rss_mb = f"{rss/1024:.1f}" if isinstance(rss, (int, float)) else ""
        row = [
            r["name"], r.get("mode") or "", r.get("traffic_kind") or "",
            fmt_pps(r.get("sent_total")), fmt_pps(r.get("bridge_in_pkts_total")),
            fmt_pct(r.get("seen_pct")), fmt_pps(r.get("captured_total")),
            fmt_pps(r.get("offered_pps_win")), fmt_pps(r.get("captured_pps")),
            fmt_pct(r.get("kdrop_pct")), fmt_pct(r.get("kdrop_pct_win")), rss_mb,
            fmt_pct(r.get("cpu_capture_pct")), fmt_pct(r.get("cpu_main_pct")),
            (f"{r.get('syscalls_per_pkt'):.3g}" if isinstance(r.get("syscalls_per_pkt"), (int, float)) else ""),
            (f"{r.get('ipc'):.3g}" if isinstance(r.get("ipc"), (int, float)) else ""),
            (f"{r.get('window_secs'):.1f}" if isinstance(r.get("window_secs"), (int, float)) else ""),
            r.get("status") or "",
        ]
        md.append("| " + " | ".join(str(c) for c in row) + " |")
    md.append("")
    md.append("Columns: **sent** = generator's own count in wire frames (udpflood/frag "
              "datagrams x fragments; blank for http/iperf whose drivers count requests/bytes). "
              "**bridge in** = frames that entered the SUT bridge on p1..p5 during the whole "
              "run (app-independent; includes sink replies). **seen%** = (captured+kdrop)/bridge in: "
              "100 means every frame reached the packet socket, so kdrop is the ONLY loss point. "
              "**offered pps** / **cap pps** / **kdrop% win** are steady-state values over the "
              "trimmed traffic window (**win s**); **kdrop%** is whole-run. **sys/pkt** = "
              "write+sendto+getsockopt+recvfrom+select+poll syscalls per captured packet during "
              "the perf-stat window. CPU% are per-thread, % of one CPU. Note for the pcap build "
              "the packet-socket ring drops are visible only through the app's kdrop (libpcap's "
              "TPACKET ring counts drops in tp_drops, not sk_drops which `ss` shows); the raw "
              "build's plain socket shows them in `ss` too (packet_socket_drops).")
    with open(os.path.join(run_dir, "summary.md"), "w") as f:
        f.write("\n".join(md) + "\n")

def main():
    if len(sys.argv) != 2:
        print("usage: analyze.py <run-id>", file=sys.stderr)
        return 2
    run_id = sys.argv[1]
    run_dir = os.path.join(repo_results(), run_id)
    if not os.path.isdir(run_dir):
        print(f"analyze: no such run dir: {run_dir}", file=sys.stderr)
        return 1
    scen_dirs = [d for d in sorted(glob.glob(os.path.join(run_dir, "*")))
                 if os.path.isdir(d)]
    rows = []
    for d in scen_dirs:
        # a scenario dir has a manifest or snuffles.stats
        if not (os.path.exists(os.path.join(d, "manifest.json")) or
                os.path.exists(os.path.join(d, "snuffles.stats"))):
            continue
        try:
            rows.append(analyze_scenario(d))
        except Exception as e:
            print(f"analyze: {os.path.basename(d)}: {e}", file=sys.stderr)
            rows.append({"name": os.path.basename(d), "status": "analyze_error"})
    if not rows:
        print(f"analyze: no scenarios found under {run_dir}", file=sys.stderr)
        return 1
    write_run_tables(run_dir, rows)
    print(f"analyze: {len(rows)} scenario(s) -> {run_dir}/summary.{{csv,md}}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
