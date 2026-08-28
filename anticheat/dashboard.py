#!/usr/bin/env python3
"""
Standalone UDP alert dashboard for the anti-cheat security runtime.

Listens on a UDP port for JSON alert payloads emitted by
`network_send_alert()` and renders an interactive, severity-colored
administration view using curses.

Payload schema (compact JSON, one datagram per alert):
    {"severity": <int 0..4>, "sev_label": <str>, "module": <str>,
     "message": <str>, "ts": <unix epoch seconds>}

Usage:
    ./dashboard.py                 # listens on 0.0.0.0:9999
    ./dashboard.py --host 127.0.0.1 --port 9999
    ./dashboard.py --no-curses    # plain colored line output (no TUI)

Keys (TUI): q = quit, c = clear, r = reset counters.
"""

import argparse
import curses
import json
import select
import socket
import sys
import time
from datetime import datetime

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
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.setblocking(False)
    return sock


def receive(sock, timeout=0.2):
    """Return a list of decoded alert dicts received within `timeout`."""
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
            obj = {"severity": -1, "sev_label": "RAW",
                   "module": "network", "message": text, "ts": int(time.time())}
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
    p.add_argument("--no-curses", action="store_true",
                   help="plain colored line output instead of the TUI")
    args = p.parse_args()

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
