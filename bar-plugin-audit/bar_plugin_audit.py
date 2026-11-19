#!/usr/bin/env python3
"""Read-only audit of Omarchy shell plugins against the bar layout.

Reads the user plugin dir, the shell config, the stock shell plugin manifests
and the Quickshell crash reports. Never writes to any of them.
"""
import argparse
import collections
import json
import os
import re
import sys

HOME = os.path.expanduser("~")
DEFAULT_PLUGINS = os.path.join(HOME, ".config/omarchy/plugins")
DEFAULT_SHELL = os.path.join(HOME, ".config/omarchy/shell.json")
DEFAULT_BUILTIN = "/usr/share/omarchy/shell/plugins"
DEFAULT_CRASHES = os.path.join(HOME, ".cache/quickshell/crashes")
LOG_TAIL_BYTES = 400_000
PLUGIN_PATH_RE = re.compile(rb"plugins/([A-Za-z0-9_.\-]+)")


def load_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def entry_files(entry_points):
    """Return (kind, relative path) pairs from an entryPoints value."""
    if isinstance(entry_points, dict):
        out = []
        for kind, val in entry_points.items():
            if isinstance(val, str):
                out.append((kind, val))
            elif isinstance(val, list):
                out.extend((kind, v) for v in val if isinstance(v, str))
            else:
                out.append((kind, None))
        return out
    if isinstance(entry_points, list):
        return [("entry", v) if isinstance(v, str) else ("entry", None) for v in entry_points]
    if isinstance(entry_points, str):
        return [("entry", entry_points)]
    return None


def scan_user_plugins(plugins_dir):
    res = {
        "entries": 0, "plugins": {}, "invalid_manifests": [], "missing_entry_files": [],
        "duplicate_ids": {}, "backup_dirs": [], "non_dirs": [], "symlinks": {},
        "dir_id_mismatch": [], "skipped_dot": [],
    }
    ids = collections.defaultdict(list)
    for name in sorted(os.listdir(plugins_dir)):
        res["entries"] += 1
        path = os.path.join(plugins_dir, name)
        if name.startswith("."):
            res["skipped_dot"].append(name)
            if ".bak" in name:
                res["backup_dirs"].append(name)
            continue
        if ".bak" in name:
            res["backup_dirs"].append(name)
        if not os.path.isdir(path):
            res["non_dirs"].append(name)
            continue
        if os.path.islink(path):
            res["symlinks"][name] = os.readlink(path)
        mpath = os.path.join(path, "manifest.json")
        if not os.path.isfile(mpath):
            res["invalid_manifests"].append({"dir": name, "error": "manifest.json missing"})
            continue
        try:
            man = load_json(mpath)
        except (OSError, ValueError) as exc:
            res["invalid_manifests"].append({"dir": name, "error": "unreadable: %s" % exc})
            continue
        if not isinstance(man, dict):
            res["invalid_manifests"].append({"dir": name, "error": "manifest is not an object"})
            continue
        pid = man.get("id")
        if not isinstance(pid, str) or not pid:
            res["invalid_manifests"].append({"dir": name, "error": "missing or non-string id"})
            continue
        eps = entry_files(man.get("entryPoints"))
        if eps is None:
            res["invalid_manifests"].append({"dir": name, "id": pid, "error": "entryPoints missing"})
            eps = []
        kinds = man.get("kinds") if isinstance(man.get("kinds"), list) else []
        for kind, rel in eps:
            if rel is None:
                res["invalid_manifests"].append(
                    {"dir": name, "id": pid, "error": "entryPoints.%s is not a path" % kind})
            elif not os.path.isfile(os.path.join(path, rel)):
                res["missing_entry_files"].append({"dir": name, "id": pid, "kind": kind, "file": rel})
        ids[pid].append(name)
        if pid != name:
            res["dir_id_mismatch"].append({"dir": name, "id": pid})
        bw = man.get("barWidget") if isinstance(man.get("barWidget"), dict) else {}
        res["plugins"][pid] = {
            "dir": name, "kinds": kinds, "allow_multiple": bool(bw.get("allowMultiple")),
            "name": man.get("name"),
        }
    res["duplicate_ids"] = {k: v for k, v in ids.items() if len(v) > 1}
    return res


def scan_builtins(builtin_dir):
    """Map stock plugin id -> {dir, kinds, allow_multiple} from every manifest below builtin_dir."""
    out = {}
    if not os.path.isdir(builtin_dir):
        return out
    for root, _dirs, files in os.walk(builtin_dir):
        for fn in files:
            if fn != "manifest.json" and not fn.endswith(".manifest.json"):
                continue
            try:
                man = load_json(os.path.join(root, fn))
            except (OSError, ValueError):
                continue
            if isinstance(man, dict) and isinstance(man.get("id"), str):
                rel = os.path.relpath(root, builtin_dir)
                bw = man.get("barWidget") if isinstance(man.get("barWidget"), dict) else {}
                out[man["id"]] = {
                    "dir": rel.split(os.sep)[0], "kinds": man.get("kinds") or [],
                    "allow_multiple": bool(bw.get("allowMultiple")),
                }
    return out


def layout_ids(shell):
    bar = shell.get("bar") if isinstance(shell.get("bar"), dict) else {}
    layout = bar.get("layout") if isinstance(bar.get("layout"), dict) else {}
    items = []
    for section, lst in layout.items():
        if not isinstance(lst, list):
            continue
        for item in lst:
            if isinstance(item, dict) and isinstance(item.get("id"), str):
                items.append((section, item["id"]))
            elif isinstance(item, str):
                items.append((section, item))
    return bar, items


def scan_crashes(crash_dir):
    """Attribute each crash dir to the last plugins/<x> path in the log tail."""
    out = {"available": False, "reports": 0, "no_plugin_ref": 0, "by_plugin_dir": {}, "stray_files": []}
    if not os.path.isdir(crash_dir):
        return out
    out["available"] = True
    counts = collections.Counter()
    for name in sorted(os.listdir(crash_dir)):
        path = os.path.join(crash_dir, name)
        if not os.path.isdir(path):
            out["stray_files"].append(name)
            continue
        out["reports"] += 1
        log = os.path.join(path, "log.qslog.log")
        try:
            with open(log, "rb") as fh:
                fh.seek(0, os.SEEK_END)
                fh.seek(max(0, fh.tell() - LOG_TAIL_BYTES))
                tail = fh.read()
        except OSError:
            out["no_plugin_ref"] += 1
            continue
        refs = PLUGIN_PATH_RE.findall(tail)
        if refs:
            counts[refs[-1].decode("utf-8", "replace")] += 1
        else:
            out["no_plugin_ref"] += 1
    out["by_plugin_dir"] = dict(counts.most_common())
    return out


# Static QML hazards, each tied to failures observed on a real Omarchy desktop (2026-10-21):
# - color-subobject: unqualified `Color.popups.x` / `Color.notifications.x`
#   read undefined at runtime in some files (omarr DownloadToast, omaglimpse
#   WidgetDropdown: ~1600 journal TypeErrors a week) while other files using
#   the same form show no error; stock Ui files use `Commons.Color`. A risk
#   flag, not proof of a failure.
# - layer-effect: `layer.enabled: true`, MultiEffect, ShaderEffectSource or
#   OpacityMask; textures are rebuilt on window scale change, the path of the
#   QIOVectoredWriteOperation abort that crash-looped the shell (Arc Dock).
# - bar-theme-ref: `root.bar.foreground` style reads; `bar` is null while
#   delegates tear down on a bar rebuild (bluetooth-audio, ~4700 a week).
# - deferred-root: `Qt.callLater(function() { root.` / `Component.onDestruction:
#   root.` without a guard; root can be gone when they run (hyprmoncfg).
# - height-loop: `height: visible ? implicitHeight : 0` inside a positioner;
#   reported as "Binding loop detected for property height".
QML_HAZARDS = [
    ("color-subobject", re.compile(
        r"(?<![\w.])Color\.(popups|notifications|menu|tooltip|polkit|lock)\.")),
    ("layer-effect", re.compile(
        r"layer\.enabled:\s*true|\bMultiEffect\b|\bShaderEffectSource\b|\bOpacityMask\b")),
    ("bar-theme-ref", re.compile(r"\b(?:root|controller)\.bar\.(?:foreground|fontFamily|urgent)\b")),
    ("deferred-root", re.compile(
        r"Qt\.callLater\(function\s*\(\)\s*\{\s*root\.|Component\.onDestruction:\s*root\.")),
    ("height-loop", re.compile(r"height:\s*visible\s*\?\s*implicitHeight\s*:\s*0")),
]
QML_SKIP_PARTS = ("/.git/", "/test/", "/tests/", "/demo/", "/node_modules/")


def qml_hazards(plugins_dir, plugin_dirs):
    """Count QML hazard lines per plugin dir. plugin_dirs: {plugin id: dir name}."""
    out = {}
    for pid, dname in sorted(plugin_dirs.items()):
        root = os.path.join(plugins_dir, dname)
        found = collections.defaultdict(list)
        for base, dirs, files in os.walk(root):
            dirs[:] = sorted(d for d in dirs if not d.startswith("."))
            for name in sorted(files):
                if not name.endswith(".qml"):
                    continue
                path = os.path.join(base, name)
                if any(part in path + "/" for part in QML_SKIP_PARTS):
                    continue
                try:
                    with open(path, encoding="utf-8", errors="replace") as fh:
                        lines = fh.read().splitlines()
                except OSError:
                    continue
                rel = os.path.relpath(path, root)
                for no, line in enumerate(lines, 1):
                    if line.lstrip().startswith("//"):
                        continue
                    for kind, rx in QML_HAZARDS:
                        if rx.search(line):
                            found[kind].append("%s:%d" % (rel, no))
        if found:
            out[pid] = {k: v for k, v in sorted(found.items())}
    return out


def audit(plugins_dir, shell_path, builtin_dir, crash_dir, scan_qml=True):
    user = scan_user_plugins(plugins_dir)
    builtins = scan_builtins(builtin_dir)
    shell = load_json(shell_path)
    bar, items = layout_ids(shell)
    known = set(user["plugins"]) | set(builtins)
    enabled = {p["id"] for p in shell.get("plugins", []) if isinstance(p, dict) and "id" in p}
    disabled = set(shell.get("disabledPlugins", []))

    in_layout = collections.Counter(pid for _s, pid in items)
    dup_layout = {}
    for pid, n in in_layout.items():
        meta = user["plugins"].get(pid) or builtins.get(pid) or {}
        if n > 1 and not meta.get("allow_multiple"):
            dup_layout[pid] = n
    layout_unknown = sorted(pid for pid in in_layout if pid not in known)
    layout_disabled = sorted(pid for pid in in_layout if pid in disabled)

    bar_id = bar.get("id")
    bar_missing = bool(bar_id) and bar_id not in known

    not_in_layout = {pid: m for pid, m in user["plugins"].items() if pid not in in_layout}
    widgets_unplaced = sorted(
        pid for pid, m in not_in_layout.items()
        if "bar-widget" in m["kinds"] and pid not in enabled)
    enabled_not_in_layout = sorted(pid for pid in not_in_layout if pid in enabled)
    neither = sorted(pid for pid in not_in_layout if pid not in enabled)
    enabled_unknown = sorted(pid for pid in enabled if pid not in known)

    crashes = scan_crashes(crash_dir) if crash_dir else {"available": False}
    dir_to_id = {m["dir"]: pid for pid, m in user["plugins"].items()}
    for pid, m in builtins.items():
        dir_to_id.setdefault(m["dir"], "builtin:" + m["dir"])
    crash_rows = []
    if crashes.get("available"):
        for d, n in crashes["by_plugin_dir"].items():
            crash_rows.append({
                "dir": d, "count": n, "plugin": dir_to_id.get(d, "unknown:" + d),
                "installed": d in dir_to_id,
                "in_layout": dir_to_id.get(d) in in_layout,
            })
    crashes["rows"] = crash_rows

    active_dirs = {pid: m["dir"] for pid, m in user["plugins"].items()
                   if pid in in_layout or pid in enabled}
    hazards = qml_hazards(plugins_dir, active_dirs) if scan_qml else None

    return {
        "paths": {"plugins": plugins_dir, "shell": shell_path, "builtin": builtin_dir, "crashes": crash_dir},
        "total_entries": user["entries"],
        "total_plugin_dirs": len(user["plugins"]) + len(user["invalid_manifests"]),
        "valid_plugins": len(user["plugins"]),
        "builtin_ids": len(builtins),
        "layout_items": len(items),
        "layout_unique_ids": len(in_layout),
        "enabled_list": len(enabled),
        "invalid_manifests": user["invalid_manifests"],
        "missing_entry_files": user["missing_entry_files"],
        "duplicate_manifest_ids": user["duplicate_ids"],
        "duplicate_layout_ids": dup_layout,
        "layout_ids_without_plugin": layout_unknown,
        "layout_ids_disabled": layout_disabled,
        "bar_plugin_missing": bar_id if bar_missing else None,
        "installed_not_in_layout": len(not_in_layout),
        "bar_widgets_not_placed_or_enabled": widgets_unplaced,
        "enabled_not_in_layout": enabled_not_in_layout,
        "installed_not_in_layout_or_enabled": neither,
        "enabled_ids_without_plugin": enabled_unknown,
        "backup_dirs": user["backup_dirs"],
        "non_dir_entries": user["non_dirs"],
        "symlinked_plugins": user["symlinks"],
        "dir_id_mismatch": user["dir_id_mismatch"],
        "crashes": crashes,
        "qml_hazards": hazards,
    }


def fmt_list(title, rows, limit=None):
    lines = ["%s: %d" % (title, len(rows))]
    shown = rows if limit is None else rows[:limit]
    for r in shown:
        lines.append("  - %s" % (r if isinstance(r, str) else json.dumps(r, sort_keys=True)))
    if limit is not None and len(rows) > limit:
        lines.append("  ... %d more (use --json or --all)" % (len(rows) - limit))
    return lines


def render_text(rep, show_all=False):
    lim = None if show_all else 15
    out = [
        "Bar plugin audit",
        "Total entries in plugins dir: %d (valid plugins %d, plugin dirs %d)"
        % (rep["total_entries"], rep["valid_plugins"], rep["total_plugin_dirs"]),
        "Layout: %d items, %d unique ids; enabled list: %d; stock plugin ids: %d"
        % (rep["layout_items"], rep["layout_unique_ids"], rep["enabled_list"], rep["builtin_ids"]),
        "",
    ]
    out += fmt_list("Invalid manifests", rep["invalid_manifests"], lim)
    out += fmt_list("Missing entry files", rep["missing_entry_files"], lim)
    out += fmt_list("Duplicate manifest ids",
                    ["%s: %s" % (k, ", ".join(v)) for k, v in rep["duplicate_manifest_ids"].items()], lim)
    out += fmt_list("Duplicate layout ids (not allowMultiple)",
                    ["%s x%d" % (k, v) for k, v in rep["duplicate_layout_ids"].items()], lim)
    out += fmt_list("Layout ids with no plugin", rep["layout_ids_without_plugin"], lim)
    out += fmt_list("Layout ids that are also disabled", rep["layout_ids_disabled"], lim)
    if rep["bar_plugin_missing"]:
        out.append("Bar plugin id not installed: %s" % rep["bar_plugin_missing"])
    out += [""]
    out.append("Installed but not in any layout: %d" % rep["installed_not_in_layout"])
    out += fmt_list("  enabled in shell.json plugins list (services, overlays, panels)",
                    rep["enabled_not_in_layout"], lim)
    out += fmt_list("  bar-widget kind, not in layout and not enabled", rep["bar_widgets_not_placed_or_enabled"], lim)
    out += fmt_list("  neither in layout nor enabled", rep["installed_not_in_layout_or_enabled"], lim)
    out += fmt_list("Enabled ids with no plugin", rep["enabled_ids_without_plugin"], lim)
    out += [""]
    out += fmt_list(".bak entries", rep["backup_dirs"], lim)
    out += fmt_list("Non-directory entries", rep["non_dir_entries"], lim)
    out += fmt_list("Symlinked plugins",
                    ["%s -> %s" % kv for kv in rep["symlinked_plugins"].items()], lim)
    out += fmt_list("Dir name differs from manifest id", rep["dir_id_mismatch"], lim)
    out.append("")
    cr = rep["crashes"]
    if cr.get("available"):
        out.append("Crash reports: %d dirs, %d with no plugins/ path in log tail, %d stray files"
                   % (cr["reports"], cr["no_plugin_ref"], len(cr["stray_files"])))
        out.append("Crashes by last plugin path in log tail (attribution is a hint, not proof):")
        for row in cr["rows"]:
            out.append("  %3d  %s%s" % (row["count"], row["plugin"],
                                        "" if row["installed"] else " (not an installed plugin dir)"))
    else:
        out.append("Crash reports: directory not available")
    hz = rep.get("qml_hazards")
    if hz is not None:
        out.append("")
        totals = collections.Counter()
        for kinds in hz.values():
            for kind, where in kinds.items():
                totals[kind] += len(where)
        out.append("QML hazards in layout/enabled plugins: %d plugins; %s"
                   % (len(hz), ", ".join("%s %d" % kv for kv in sorted(totals.items())) or "none"))
        rows = sorted(hz.items(), key=lambda kv: -sum(len(v) for v in kv[1].values()))
        for pid, kinds in (rows if show_all else rows[:lim]):
            out.append("  %s: %s" % (pid, ", ".join(
                "%s %d (%s)" % (k, len(v), v[0]) for k, v in kinds.items())))
        if not show_all and len(rows) > lim:
            out.append("  ... %d more (use --json or --all)" % (len(rows) - lim))
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--plugins-dir", default=DEFAULT_PLUGINS)
    ap.add_argument("--shell-json", default=DEFAULT_SHELL)
    ap.add_argument("--builtin-dir", default=DEFAULT_BUILTIN)
    ap.add_argument("--crashes-dir", default=DEFAULT_CRASHES)
    ap.add_argument("--no-crashes", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--all", action="store_true", help="do not truncate text lists")
    ap.add_argument("--no-qml", action="store_true", help="skip the static QML hazard scan")
    args = ap.parse_args(argv)
    try:
        rep = audit(args.plugins_dir, args.shell_json, args.builtin_dir,
                    None if args.no_crashes else args.crashes_dir, scan_qml=not args.no_qml)
    except (OSError, ValueError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    if args.json:
        json.dump(rep, sys.stdout, indent=2, sort_keys=True)
        print()
    else:
        print(render_text(rep, args.all))
    return 0


if __name__ == "__main__":
    sys.exit(main())
