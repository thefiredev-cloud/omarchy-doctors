#!/usr/bin/env python3
"""Read-only digest of Quickshell crash reports.

Reads every <crashes>/<run>/report.txt (plus a loose <crashes>/report.txt) and
the matching log.qslog.log. Groups crashes by signal, first meaningful stack
frame and the last plugin id seen in the log tail. Never writes or deletes.
"""

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime

DEFAULT_DIR = os.path.expanduser("~/.cache/quickshell/crashes")
LOG_TAIL_BYTES = 262144

# Libraries whose frames are abort/allocator/FFI plumbing, never the culprit.
SKIP_MODULES = {"libc.so.6", "libstdc++.so.6", "libjemalloc.so.2", "libffi.so.8",
                "libgcc_s.so.1", "libm.so.6"}
# Symbols that are crash machinery rather than the fault site.
SKIP_SYMBOLS = {"raise", "abort", "__dynamic_cast", "std::terminate",
                "__cxa_pure_virtual", "__cxa_throw", "__cxa_call_terminate",
                "QDebug::~QDebug", "qt_message_fatal", "QMessageLogger::fatal"}

FRAME_RE = re.compile(r"^#(\d+)\s+0x[0-9a-fA-F]+(?: in (.*?))? at (\S+)\s*$")
PLUGIN_RE = re.compile(rb'/plugins/([A-Za-z0-9][A-Za-z0-9._@+-]*)/')
PREFIX_BYTES = 200


def _base(symbol):
    """Symbol without its argument list, so one function groups under one key."""
    return symbol.split("(", 1)[0]


def parse_report(text):
    """Return (signal, pid, frames) where frames is a list of (symbol, module)."""
    signal = None
    pid = None
    m = re.search(r"^Signal: (.*)$", text, re.M)
    if m:
        signal = m.group(1).strip()
    m = re.search(r"^Crashed process ID: (\d+)", text, re.M)
    if m:
        pid = int(m.group(1))
    frames = []
    if "===== Stacktrace =====" in text:
        body = text.split("===== Stacktrace =====", 1)[1].split("\n=====", 1)[0]
        for line in body.splitlines():
            fm = FRAME_RE.match(line)
            if fm:
                frames.append((fm.group(2), os.path.basename(fm.group(3))))
    return signal, pid, frames


def top_frame(frames):
    """First meaningful frame: the first symbolized one that is not plumbing.

    Quickshell frames carry no symbols, so a symbolized Qt or library frame is the
    best stable key. If no frame has a symbol, fall back to the first module that
    is not plumbing.
    """
    kept = []
    for symbol, module in frames:
        if module in SKIP_MODULES:
            continue
        if symbol and _base(symbol) in SKIP_SYMBOLS:
            continue
        kept.append((symbol, module))
    for symbol, module in kept:
        if symbol:
            return _base(symbol)
    for _, module in kept:
        if module != "quickshell":
            return module
    return "unknown"


def last_plugin(log_path):
    """Return (plugin_id, origin) for the last plugins/<id>/ path in the log tail."""
    try:
        size = os.path.getsize(log_path)
        with open(log_path, "rb") as fh:
            if size > LOG_TAIL_BYTES:
                fh.seek(size - LOG_TAIL_BYTES)
            tail = fh.read()
    except OSError:
        return None, None
    last = None
    for m in PLUGIN_RE.finditer(tail):
        last = m
    if last is None:
        return None, None
    prefix = tail[max(0, last.start() - PREFIX_BYTES):last.start()]
    prefix = re.split(rb'[\s"\\\x00-\x1f]', prefix)[-1]
    origin = "user" if b".config/omarchy" in prefix else "system"
    return last.group(1).decode("utf8", "replace"), origin


def find_reports(root):
    """Yield (run_id, report_path, log_path) for every report under root."""
    found = []
    try:
        names = sorted(os.listdir(root))
    except OSError as exc:
        raise SystemExit(f"cannot read {root}: {exc}")
    for name in names:
        sub = os.path.join(root, name)
        rep = os.path.join(sub, "report.txt")
        if os.path.isdir(sub) and os.path.isfile(rep):
            found.append((name, rep, os.path.join(sub, "log.qslog.log")))
    loose = os.path.join(root, "report.txt")
    if os.path.isfile(loose):
        found.append(("(loose)", loose, os.path.join(root, "log.qslog.log")))
    return found


def load_crashes(root, since_hours=None, now=None):
    now = time.time() if now is None else now
    crashes = []
    for run_id, rep, log in find_reports(root):
        mtime = os.path.getmtime(rep)
        if since_hours is not None and mtime < now - since_hours * 3600:
            continue
        with open(rep, errors="replace") as fh:
            signal, pid, frames = parse_report(fh.read())
        plugin, origin = last_plugin(log)
        crashes.append({
            "run_id": run_id,
            "time": datetime.fromtimestamp(mtime).astimezone().isoformat(timespec="seconds"),
            "mtime": mtime,
            "signal": signal or "unknown",
            "pid": pid,
            "frame": top_frame(frames),
            "plugin": plugin,
            "plugin_origin": origin,
        })
    return crashes


def group(crashes):
    groups = {}
    for c in crashes:
        key = (c["signal"], c["frame"], c["plugin"])
        g = groups.setdefault(key, {
            "signal": c["signal"], "frame": c["frame"], "plugin": c["plugin"],
            "plugin_origin": c["plugin_origin"], "count": 0, "runs": [],
            "first": c["time"], "last": c["time"], "_f": c["mtime"], "_l": c["mtime"],
        })
        g["count"] += 1
        g["runs"].append(c["run_id"])
        if c["mtime"] < g["_f"]:
            g["_f"], g["first"] = c["mtime"], c["time"]
        if c["mtime"] > g["_l"]:
            g["_l"], g["last"] = c["mtime"], c["time"]
    out = sorted(groups.values(), key=lambda g: (-g["count"], g["signal"], g["frame"], g["plugin"] or ""))
    for g in out:
        del g["_f"], g["_l"]
    return out


def render_table(groups, total):
    rows = [("COUNT", "SIGNAL", "TOP FRAME", "LAST PLUGIN", "FIRST", "LAST")]
    for g in groups:
        plugin = g["plugin"] or "-"
        if g["plugin"] and g["plugin_origin"] == "system":
            plugin += " (core)"
        rows.append((str(g["count"]), g["signal"], g["frame"], plugin,
                     g["first"].replace("T", " ")[:16], g["last"].replace("T", " ")[:16]))
    widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
    lines = ["  ".join(cell.ljust(widths[i]) for i, cell in enumerate(r)).rstrip() for r in rows]
    lines.append(f"{total} reports in {len(groups)} groups")
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Digest Quickshell crash reports (read-only).")
    ap.add_argument("--dir", default=DEFAULT_DIR, help="crashes directory (default %(default)s)")
    ap.add_argument("--since", type=float, metavar="HOURS", help="only reports newer than HOURS hours")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    crashes = load_crashes(args.dir, args.since)
    groups = group(crashes)
    if args.json:
        json.dump({"dir": args.dir, "total": len(crashes), "since_hours": args.since,
                   "groups": groups}, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        print(render_table(groups, len(crashes)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
