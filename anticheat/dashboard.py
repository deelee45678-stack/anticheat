#!/usr/bin/env python3
"""
Standalone UDP alert dashboard for the anti-cheat security runtime.

Listens on a UDP port for JSON alert payloads emitted by
`network_send_alert()` and renders an interactive, severity-colored
administration view using curses.

Payload schema (compact JSON, one datagram per alert):
    {"severity": <int 0..4>, "sev_label": <str>, "module": <str>,
     "message": <str>, "ts": <unix epoch seconds>,
     "sig": <hex HMAC-SHA256 over "sev|label|module|message|ts">}

Every datagram carries an HMAC-SHA256 signature ("sig") computed by the client
over the canonical field string "severity|sev_label|module|message|ts" using the
shared secret. When --network-key (or ANTICHEAT_NETWORK_KEY) is set the dashboard
verifies the signature and silently drops datagrams whose signature is missing or
invalid. Run without a key only for local, trusted testing.

Replay protection (only enforced when a key is configured):
  * Freshness: a datagram whose "ts" is more than 30s outside the dashboard's
    current clock is rejected, even with a valid signature.
  * Replay cache: the last 60s of seen signature values are remembered; an
    exact duplicate ("sig" already seen within the TTL) is rejected, so a
    captured datagram cannot be replayed inside the freshness window.

The shared secret MUST come from the ANTICHEAT_NETWORK_KEY environment variable
in production. Passing --network-key on the command line exposes the secret via
`ps` and shell history; a one-line warning is printed when it is used.

Usage:
    ./dashboard.py                 # listens on 0.0.0.0:9999 (no verification)
    ANTICHEAT_NETWORK_KEY=secret ./dashboard.py --host 127.0.0.1 --port 9999
    ./dashboard.py --no-curses    # plain colored line output (no TUI)

Keys (TUI): q = quit, c = clear, r = reset counters.
"""

import argparse
import curses
import hashlib
import hmac
import json
import os
import select
import socket
import sys
import time
from datetime import datetime

# HMAC shared secret (set from --network-key or ANTICHEAT_NETWORK_KEY). When
# None, the dashboard runs in legacy (unverified) mode and warns loudly.
NET_KEY = None

# Replay-protection tuning (only used when NET_KEY is set).
FRESHNESS_WINDOW = 30.0   # seconds; |now - ts| must be within this
REPLAY_TTL = 60.0         # seconds a seen signature stays in the replay cache
MAX_REPLAY = 200000       # cap on the replay cache size (defensive)

# Recently-seen signatures and their expiry epoch (float seconds).
_replay_cache = {}
# Drop counters, surfaced (throttled) to stderr so operators can see rejections.
_stats = {"parse": 0, "auth": 0, "freshness": 0, "replay": 0}
_last_log = [0.0]


def _log_drop(kind, detail=""):
    _stats[kind] = _stats.get(kind, 0) + 1
    now = time.time()
    if now - _last_log[0] >= 5.0:
        _last_log[0] = now
        msg = "[dashboard] dropped %s datagram (%d total)" % (
            kind, _stats[kind])
        if detail:
            msg += " " + detail
        print(msg, file=sys.stderr)


def _purge_replay(now):
    if len(_replay_cache) > MAX_REPLAY:
        _replay_cache.clear()
        return
    expired = [k for k, exp in _replay_cache.items() if exp <= now]
    for k in expired:
        del _replay_cache[k]


def check_freshness(obj):
    """Return True iff obj's `ts` is an integer within FRESHNESS_WINDOW of now."""
    ts = obj.get("ts")
    if isinstance(ts, bool) or not isinstance(ts, int):
        return False
    return abs(time.time() - ts) <= FRESHNESS_WINDOW


def check_replay(obj):
    """Return True iff `sig` is a string not already in the replay cache; on
    success the signature is recorded with a REPLAY_TTL expiry."""
    sig = obj.get("sig")
    if not isinstance(sig, str):
        return False
    now = time.time()
    _purge_replay(now)
    if sig in _replay_cache and _replay_cache[sig] > now:
        return False
    _replay_cache[sig] = now + REPLAY_TTL
    return True


SEV_NAMES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEV_COLORS = {
    0: curses.COLOR_GREEN,
    1: curses.COLOR_CYAN,
    2: curses.COLOR_YELLOW,
    3: curses.COLOR_RED,
    4: curses.COLOR_RED,
}


def parse_endpoint(host, port):
    return host, port


def make_socket(host, port):
    """Bind a UDP socket on `host`:`port`, resolving both IPv4 and IPv6 via
    getaddrinfo. Returns the first socket that successfully binds."""
    addrinfo = socket.getaddrinfo(host, port, socket.AF_UNSPEC,
                                 socket.SOCK_DGRAM)
    last_err = None
    for family, stype, proto, _canon, sockaddr in addrinfo:
        try:
            sock = socket.socket(family, stype, proto)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(sockaddr)
            sock.setblocking(False)
            return sock
        except OSError as e:
            last_err = e
            continue
    raise RuntimeError("could not bind any address for %s:%d (%s)" %
                       (host, port, last_err))


def verify_sig(obj):
    """Return True iff `obj` carries a valid HMAC-SHA256 signature under
    NET_KEY. Never raises: malformed or missing data is treated as invalid."""
    if NET_KEY is None:
        return True  # legacy / unverified mode
    try:
        sig = obj.get("sig")
        if not isinstance(sig, str):
            return False
        canon = "%s|%s|%s|%s|%s" % (
            obj.get("severity"),
            obj.get("sev_label"),
            obj.get("module"),
            obj.get("message"),
            obj.get("ts"),
        )
        expected = hmac.new(NET_KEY.encode(), canon.encode(),
                            hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, sig)
    except Exception:
        return False


def receive(sock, timeout=0.2):
    """Return a list of decoded, HMAC-verified, fresh, non-replayed alert dicts
    received within `timeout`. Malformed datagrams and datagrams failing
    authentication, freshness, or replay checks are logged and dropped rather
    than crashing the dashboard."""
    alerts = []
    ready, _, _ = select.select([sock], [], [], timeout)
    if not ready:
        return alerts
    while True:
        try:
            data, _ = sock.recvfrom(65535)
        except BlockingIOError:
            break
        except Exception:
            break
        text = data.decode("utf-8", "replace").strip()
        if not text:
            continue
        try:
            obj = json.loads(text)
        except json.JSONDecodeError:
            # Cannot parse: with a key configured we cannot verify, so reject;
            # in legacy mode keep it as a raw line for visibility.
            if NET_KEY is not None:
                _log_drop("parse")
                continue
            obj = {"severity": -1, "sev_label": "RAW",
                   "module": "network", "message": text,
                   "ts": int(time.time())}
        except Exception:
            _log_drop("parse")
            continue

        if not verify_sig(obj):
            _log_drop("auth")
            continue
        # Replay protection only matters once we trust the signature.
        if NET_KEY is not None:
            if not check_freshness(obj):
                _log_drop("freshness")
                continue
            if not check_replay(obj):
                _log_drop("replay")
                continue
        alerts.append(obj)
    return alerts


def color_for(stdscr, sev):
    pair = 1 + max(0, min(4, sev))
    return curses.color_pair(pair)


def run_tui(stdscr, sock):
    curses.curs_set(0)
    curses.start_color()
    for sev in range(5):
        fg = SEV_COLORS.get(sev, curses.COLOR_WHITE)
        bg = curses.COLOR_BLACK
        try:
            curses.init_pair(1 + sev, fg, bg)
        except curses.error:
            pass

    history = []
    counts = [0, 0, 0, 0, 0]

    def redraw():
        stdscr.erase()
        h, w = stdscr.getmaxyx()
        stdscr.attron(curses.A_BOLD)
        stdscr.addstr(0, 0, "Anti-Cheat UDP Alert Dashboard".ljust(w))
        stdscr.attroff(curses.A_BOLD)
        summary = "  ".join(
            f"{SEV_NAMES[i]}:{counts[i]}" for i in range(5)
        )
        stdscr.addstr(1, 0, summary.ljust(w))
        stdscr.addstr(2, 0, "-" * w)
        row = 3
        for alert in reversed(history[-(h - 5):]):
            if row >= h - 1:
                break
            sev = alert.get("severity", -1)
            label = alert.get("sev_label", SEV_NAMES[sev] if 0 <= sev <= 4 else "?")
            ts = alert.get("ts", 0)
            try:
                tstr = datetime.fromtimestamp(ts).strftime("%H:%M:%S")
            except Exception:
                tstr = "??:??:??"
            module = alert.get("module", "?")
            msg = alert.get("message", "")
            line = f"[{tstr}] {label:<8} {module}: {msg}"
            if len(line) > w:
                line = line[: w - 1]
            try:
                stdscr.addstr(row, 0, line, color_for(stdscr, sev))
            except curses.error:
                pass
            row += 1
        stdscr.addstr(h - 1, 0, "q=quit  c=clear  r=reset counts".ljust(w))
        stdscr.refresh()

    redraw()
    while True:
        alerts = receive(sock, timeout=0.2)
        for a in alerts:
            sev = a.get("severity", -1)
            if 0 <= sev <= 4:
                counts[sev] += 1
            history.append(a)
        if history:
            redraw()
        try:
            ch = stdscr.getkey()
        except Exception:
            ch = None
        if ch == "q":
            break
        elif ch == "c":
            history.clear()
            redraw()
        elif ch == "r":
            counts = [0, 0, 0, 0, 0]
            redraw()


def run_plain(sock):
    codes = {
        0: "\033[32m", 1: "\033[36m", 2: "\033[33m", 3: "\033[31m", 4: "\033[31m",
    }
    reset = "\033[0m"
    print("Anti-Cheat UDP Alert Dashboard (plain mode). Ctrl-C to quit.")
    while True:
        for a in receive(sock, timeout=0.5):
            sev = a.get("severity", -1)
            label = a.get("sev_label", "?")
            code = codes.get(sev, "")
            try:
                tstr = datetime.fromtimestamp(a.get("ts", 0)).strftime("%H:%M:%S")
            except Exception:
                tstr = "??:??:??"
            print(f"{code}[{tstr}] {label:<8} {a.get('module','?')}: "
                  f"{a.get('message','')}{reset}", flush=True)


def main():
    p = argparse.ArgumentParser(description="UDP alert dashboard")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=9999)
    p.add_argument("--network-key", default=os.environ.get("ANTICHEAT_NETWORK_KEY"),
                   help="HMAC-SHA256 shared secret (or set ANTICHEAT_NETWORK_KEY). "
                        "When omitted, signatures are NOT verified.")
    p.add_argument("--no-curses", action="store_true",
                   help="plain colored line output instead of the TUI")
    args = p.parse_args()

    global NET_KEY
    NET_KEY = args.network_key
    if NET_KEY:
        print("HMAC verification ENABLED", file=sys.stderr)
        # Key-hygiene warning: a command-line secret is visible via ps / shell
        # history. Prefer the ANTICHEAT_NETWORK_KEY environment variable.
        if any(a == "--network-key" or a.startswith("--network-key=")
               for a in sys.argv):
            print("WARNING: --network-key was passed on the command line; this "
                  "exposes the shared secret via `ps` and shell history. Prefer "
                  "the ANTICHEAT_NETWORK_KEY environment variable instead.",
                  file=sys.stderr)
    else:
        print("WARNING: no --network-key / ANTICHEAT_NETWORK_KEY set; "
              "datagrams are NOT authenticated", file=sys.stderr)

    sock = make_socket(args.host, args.port)
    print(f"Listening for UDP alerts on {args.host}:{args.port}", file=sys.stderr)

    try:
        if args.no_curses or not sys.stdout.isatty():
            run_plain(sock)
        else:
            curses.wrapper(run_tui, sock)
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()


if __name__ == "__main__":
    main()
