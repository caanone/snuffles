#!/usr/bin/env python3
"""tui.py — run snuffles' TUI under a pseudo-terminal for the load-test rig.

    tui.py [--pidfile F] [--stderr F] [--keys "5:S,15:V,20:S"]
           [--cols 200] [--rows 50] [--grace 3] -- /opt/snuffles/pcap/snuffles ...

* allocates a pty of --cols x --rows (default 200x50), TERM=xterm-256color
* spawns the command with stdin/stdout on the pty, stderr to --stderr (or ours)
* writes the child's pid to --pidfile immediately after the spawn
* discards everything the TUI draws (the master side is drained continuously,
  so snuffles never blocks on a full pty buffer)
* sends scripted keys at scripted times: "<seconds>:<key>[,<seconds>:<key>...]"
  (seconds since spawn; key is a literal character, or one of
   enter, esc, space, up, down, pgup, pgdn)
* graceful stop: on SIGUSR1 / SIGTERM / SIGINT / SIGHUP it sends "q"; if the
  child is still alive after --grace seconds it sends "q" again (an open
  overlay swallows the first one), and after another --grace seconds falls
  back to SIGINT on the child. Hard kills are the caller's job.
* exits with the child's exit status (128+N when the child died of signal N)

Events are logged to our stderr with monotonic timestamps.
"""
import argparse
import errno
import fcntl
import os
import select
import signal
import struct
import subprocess
import sys
import termios
import time

SPECIAL = {
    "enter": "\r", "esc": "\x1b", "space": " ",
    "up": "\x1b[A", "down": "\x1b[B", "pgup": "\x1b[5~", "pgdn": "\x1b[6~",
}


def parse_keys(spec):
    events = []
    if not spec:
        return events
    for item in spec.split(","):
        item = item.strip()
        if not item:
            continue
        t, _, key = item.partition(":")
        if not _:
            raise SystemExit("tui.py: bad key spec %r (want <seconds>:<key>)" % item)
        events.append((float(t), SPECIAL.get(key, key)))
    events.sort(key=lambda e: e[0])
    return events


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pidfile")
    ap.add_argument("--stderr")
    ap.add_argument("--keys", default="")
    ap.add_argument("--cols", type=int, default=200)
    ap.add_argument("--rows", type=int, default=50)
    ap.add_argument("--grace", type=float, default=3.0)
    ap.add_argument("cmd", nargs=argparse.REMAINDER)
    args = ap.parse_args()
    cmd = args.cmd
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        raise SystemExit("tui.py: no command given")
    keys = parse_keys(args.keys)

    t0 = time.monotonic()

    def log(msg):
        sys.stderr.write("[tui.py %7.3f] %s\n" % (time.monotonic() - t0, msg))
        sys.stderr.flush()

    master, slave = os.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", args.rows, args.cols, 0, 0))
    env = dict(os.environ, TERM="xterm-256color",
               COLUMNS=str(args.cols), LINES=str(args.rows))

    errf = open(args.stderr, "ab", buffering=0) if args.stderr else None

    def preexec():
        # become the session leader's controlling tty (fd 0 is the slave)
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)

    child = subprocess.Popen(cmd, stdin=slave, stdout=slave,
                             stderr=errf if errf else None, env=env,
                             start_new_session=True, preexec_fn=preexec,
                             close_fds=True)
    os.close(slave)
    if errf:
        errf.close()
    if args.pidfile:
        tmp = args.pidfile + ".tmp"
        with open(tmp, "w") as f:
            f.write("%d\n" % child.pid)
        os.replace(tmp, args.pidfile)
    log("spawned pid %d: %s (pty %dx%d)" % (child.pid, " ".join(cmd), args.cols, args.rows))

    # signal -> wakeup pipe so select() returns at once
    wr, wl = os.pipe()
    for fd in (wr, wl):
        fl = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
    signal.set_wakeup_fd(wl)
    quit_requested = []

    def on_signal(signum, _frame):
        quit_requested.append((signum, time.monotonic()))

    for s in (signal.SIGUSR1, signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(s, on_signal)

    def send(key, why):
        try:
            os.write(master, key.encode())
            log("sent %r (%s)" % (key, why))
        except OSError as e:
            log("send %r failed: %s" % (key, e))

    # stop sequence: list of (time, action) built when the first signal lands
    stop_plan = []
    stop_started = None
    pending = list(keys)
    master_open = True

    while child.poll() is None:
        now = time.monotonic() - t0
        # scripted keys
        while pending and pending[0][0] <= now:
            _, key = pending.pop(0)
            send(key, "scripted")
        # stop escalation
        if quit_requested and stop_started is None:
            signum, _ = quit_requested[0]
            stop_started = now
            log("stop requested (signal %d)" % signum)
            stop_plan = [(now, "q1"), (now + args.grace, "q2"), (now + 2 * args.grace, "sigint")]
        while stop_plan and stop_plan[0][0] <= now:
            _, action = stop_plan.pop(0)
            if action in ("q1", "q2"):
                send("q", action)
            elif action == "sigint":
                log("fallback: SIGINT -> %d" % child.pid)
                try:
                    os.kill(child.pid, signal.SIGINT)
                except OSError as e:
                    log("SIGINT failed: %s" % e)
        # next deadline
        deadlines = [t for t, _ in pending[:1]] + [t for t, _ in stop_plan[:1]]
        timeout = 0.5
        if deadlines:
            timeout = max(0.0, min(min(deadlines) - now, 0.5))
        rlist = [wr] + ([master] if master_open else [])
        try:
            r, _, _ = select.select(rlist, [], [], timeout)
        except InterruptedError:
            continue
        if wr in r:
            try:
                os.read(wr, 4096)
            except OSError:
                pass
        if master in r:
            try:
                data = os.read(master, 65536)
                if not data:
                    master_open = False
            except OSError as e:
                if e.errno == errno.EIO:      # slave side closed: child gone
                    master_open = False
                elif e.errno != errno.EAGAIN:
                    log("master read error: %s" % e)
                    master_open = False

    rc = child.wait()
    try:
        os.close(master)
    except OSError:
        pass
    if rc < 0:
        log("child killed by signal %d" % -rc)
        rc = 128 - rc
    else:
        log("child exited %d" % rc)
    sys.exit(rc)


if __name__ == "__main__":
    main()
