"""display-doctor: read-only Hyprland display lag diagnosis.

Collects monitor modes, a few render options, GPU busy percent and stale
Hyprland instance dirs, then ranks likely lag causes with plain hints.

Read-only by construction: the only hyprctl verbs it can run are `monitors`
and `getoption` (see READ_ONLY_VERBS). It never runs `keyword`, `reload`,
`dispatch` or anything else that changes state.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import socket
import subprocess
import sys
import time

READ_ONLY_VERBS = ("monitors", "getoption")
OPTIONS = (
    "animations:enabled",
    "decoration:blur:enabled",
    "decoration:blur:passes",
    "decoration:blur:size",
    "decoration:shadow:enabled",
    "misc:vrr",
)
MODE_RE = re.compile(r"^(\d+)x(\d+)@([\d.]+)Hz$")
SEVERITY_SCORE = {"high": 300, "medium": 200, "low": 100, "info": 0}
# pixels per second above which blur/shadow passes are a real GPU cost
HEAVY_PIXEL_RATE = 1.0e9
# refresh gap (Hz) below which a monitor counts as running its best mode
REFRESH_TOLERANCE_HZ = 1.0
GPU_BUSY_HIGH = 85
GPU_BUSY_MEDIUM = 60
GPU_TOOLS = {"nvidia": "nvidia-smi or nvtop", "amdgpu": "radeontop or nvtop", "i915": "intel_gpu_top", "xe": "intel_gpu_top"}


# ---------------------------------------------------------------- parsing


def parse_mode(text):
    """'3840x2160@239.99Hz' -> (3840, 2160, 239.99) or None."""
    m = MODE_RE.match(text.strip())
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), float(m.group(3))


def best_mode(available_modes):
    """Highest refresh at the native (largest pixel area) size, or None."""
    modes = [p for p in (parse_mode(t) for t in available_modes) if p]
    if not modes:
        return None
    native_w, native_h = max(((w, h) for w, h, _ in modes), key=lambda s: s[0] * s[1])
    hz = max(r for w, h, r in modes if (w, h) == (native_w, native_h))
    return native_w, native_h, hz


def parse_option(raw):
    """Parse `hyprctl getoption -j` output into a plain value, or None."""
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict):
        # `null`, `[]`, `"x"` or a bare number: no value to read, not a crash.
        return None
    for key in ("bool", "int", "float", "str", "custom"):
        if key in data:
            return data[key]
    return None


# ------------------------------------------------------------- collection


class HyprError(RuntimeError):
    pass


def socket_alive(path):
    """True when something accepts a connection on the unix socket."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(1.0)
    try:
        s.connect(path)
        return True
    except OSError:
        return False
    finally:
        s.close()


def scan_instances(hypr_dir, env_signature=None, alive=socket_alive):
    """List every instance dir with liveness. Sorted newest socket first."""
    rows = []
    for d in sorted(glob.glob(os.path.join(hypr_dir, "*"))):
        if not os.path.isdir(d):
            continue
        sock = os.path.join(d, ".socket.sock")
        has_sock = os.path.exists(sock)
        try:
            mtime = os.stat(sock).st_mtime if has_sock else os.stat(d).st_mtime
        except OSError:
            mtime = 0.0
        rows.append(
            {
                "signature": os.path.basename(d),
                "has_socket": has_sock,
                "live": bool(has_sock and alive(sock)),
                "mtime": mtime,
                "is_env_signature": os.path.basename(d) == env_signature,
            }
        )
    rows.sort(key=lambda r: r["mtime"], reverse=True)
    return rows


def pick_instance(instances, env_signature=None):
    """Env signature if live, else newest live instance, else None."""
    live = [r for r in instances if r["live"]]
    for r in live:
        if r["signature"] == env_signature:
            return r["signature"]
    return live[0]["signature"] if live else None


def make_hyprctl_runner(signature, timeout=5.0):
    """Return run(args)->stdout for one instance, restricted to read verbs."""

    def run(args):
        if not args or args[0] not in READ_ONLY_VERBS:
            raise HyprError("refusing non read-only hyprctl verb: %r" % (args,))
        proc = subprocess.run(
            ["hyprctl", "-i", signature, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if proc.returncode != 0:
            raise HyprError("hyprctl %s failed: %s" % (" ".join(args), proc.stderr.strip()))
        return proc.stdout

    return run


def read_gpus(drm_root="/sys/class/drm", samples=3, interval=0.1, sleep=time.sleep):
    """Per card: driver and gpu_busy_percent samples (None when not exposed)."""
    gpus = []
    for card_dir in sorted(glob.glob(os.path.join(drm_root, "card[0-9]*"))):
        name = os.path.basename(card_dir)
        if "-" in name:
            continue
        driver_link = os.path.join(card_dir, "device", "driver")
        driver = os.path.basename(os.path.realpath(driver_link)) if os.path.exists(driver_link) else None
        busy_path = os.path.join(card_dir, "device", "gpu_busy_percent")
        busy = None
        if os.path.exists(busy_path):
            busy = []
            for i in range(samples):
                try:
                    with open(busy_path) as f:
                        busy.append(int(f.read().strip()))
                except (OSError, ValueError):
                    break
                if i + 1 < samples:
                    sleep(interval)
            busy = busy or None
        gpus.append({"card": name, "driver": driver, "busy_samples": busy})
    return gpus


def connector_cards(drm_root="/sys/class/drm"):
    """Map connector name (DP-1) to the card that owns it (card1)."""
    out = {}
    for path in glob.glob(os.path.join(drm_root, "card[0-9]*-*")):
        base = os.path.basename(path)
        card, _, connector = base.partition("-")
        out[connector] = card
    return out


def collect(runtime_dir=None, drm_root="/sys/class/drm", env_signature=None, samples=3, interval=0.1, sleep=time.sleep, alive=socket_alive, runner_factory=make_hyprctl_runner):
    """Gather everything into one plain-dict snapshot. Never raises on a dead Hyprland."""
    runtime_dir = runtime_dir or os.environ.get("XDG_RUNTIME_DIR", "/run/user/%d" % os.getuid())
    env_signature = env_signature if env_signature is not None else os.environ.get("HYPRLAND_INSTANCE_SIGNATURE")
    instances = scan_instances(os.path.join(runtime_dir, "hypr"), env_signature, alive)
    chosen = pick_instance(instances, env_signature)
    snap = {
        "instance": chosen,
        "env_signature": env_signature,
        "instances": instances,
        "monitors": [],
        "options": {},
        "gpus": read_gpus(drm_root, samples, interval, sleep),
        "connector_cards": connector_cards(drm_root),
        "errors": [],
    }
    if chosen is None:
        snap["errors"].append("no live Hyprland socket under %s" % os.path.join(runtime_dir, "hypr"))
        return snap
    run = runner_factory(chosen)
    try:
        snap["monitors"] = json.loads(run(["monitors", "all", "-j"]))
    except (HyprError, ValueError, subprocess.SubprocessError, OSError) as e:
        snap["errors"].append("monitors: %s" % e)
    for opt in OPTIONS:
        try:
            snap["options"][opt] = parse_option(run(["getoption", opt, "-j"]))
        except (HyprError, subprocess.SubprocessError, OSError) as e:
            snap["errors"].append("getoption %s: %s" % (opt, e))
            snap["options"][opt] = None
    return snap


# --------------------------------------------------------------- analysis


def finding(fid, severity, title, detail, hint, extra=0):
    return {
        "id": fid,
        "severity": severity,
        "score": SEVERITY_SCORE[severity] + extra,
        "title": title,
        "detail": detail,
        "hint": hint,
    }


def monitor_report(mon):
    best = best_mode(mon.get("availableModes", []))
    cur = (mon.get("width"), mon.get("height"), float(mon.get("refreshRate", 0)))
    gap = (best[2] - cur[2]) if best else 0.0
    size_ok = bool(best) and (cur[0], cur[1]) == (best[0], best[1])
    return {
        "name": mon.get("name"),
        "description": mon.get("description"),
        "current": {"width": cur[0], "height": cur[1], "refresh_hz": round(cur[2], 2)},
        "best": None if not best else {"width": best[0], "height": best[1], "refresh_hz": round(best[2], 2)},
        "at_best_mode": bool(best) and size_ok and gap < REFRESH_TOLERANCE_HZ,
        "refresh_gap_hz": round(gap, 2),
        "scale": mon.get("scale"),
        "vrr_active": bool(mon.get("vrr")),
        "disabled": bool(mon.get("disabled")),
        "mirror_of": mon.get("mirrorOf"),
    }


def analyze(snap):
    """Turn a snapshot into per-monitor reports plus ranked findings."""
    findings = []
    reports = []
    opts = snap.get("options", {})
    gpus = snap.get("gpus", [])
    c2c = snap.get("connector_cards", {})

    if snap.get("errors") and not snap.get("monitors"):
        findings.append(
            finding(
                "hyprland_unreachable",
                "high",
                "Cannot read monitor state",
                "; ".join(snap["errors"]),
                "No live Hyprland socket answered. Check that Hyprland is running and that XDG_RUNTIME_DIR is correct.",
            )
        )

    heavy = False
    for mon in snap.get("monitors", []):
        rep = monitor_report(mon)
        reports.append(rep)
        if rep["disabled"] or not rep["best"]:
            continue
        name = rep["name"]
        cur, best = rep["current"], rep["best"]
        if rep["current"]["width"] * rep["current"]["height"] * rep["current"]["refresh_hz"] >= HEAVY_PIXEL_RATE:
            heavy = True
        if not rep["at_best_mode"]:
            if (cur["width"], cur["height"]) != (best["width"], best["height"]):
                title = "%s is not at its native size" % name
                detail = "Running %dx%d@%.2fHz; native size is %dx%d (best %.2fHz)." % (
                    cur["width"], cur["height"], cur["refresh_hz"], best["width"], best["height"], best["refresh_hz"])
            else:
                title = "%s is below its best refresh rate" % name
                detail = "Running %.2fHz at %dx%d; the monitor offers %.2fHz." % (
                    cur["refresh_hz"], cur["width"], cur["height"], best["refresh_hz"])
            findings.append(
                finding(
                    "mode_below_best:%s" % name,
                    "high",
                    title,
                    detail,
                    "This feels like lag and is the first thing to fix. Set the best mode in the Hyprland monitor config "
                    "(this tool changes nothing). Also check the cable and port can carry the mode.",
                    extra=int(min(rep["refresh_gap_hz"], 99)),
                )
            )
        scale = rep["scale"]
        if scale is not None and abs(float(scale) - round(float(scale))) > 0.01:
            findings.append(
                finding(
                    "fractional_scale:%s" % name,
                    "low",
                    "%s uses fractional scale %s" % (name, scale),
                    "Non-integer scale makes the compositor resample content and blurs XWayland apps.",
                    "Scale 1 or 2 avoids resampling. Only change it if text size allows.",
                )
            )
        vrr_opt = opts.get("misc:vrr")
        if vrr_opt not in (None, 0) and not rep["vrr_active"]:
            findings.append(
                finding(
                    "vrr_not_active:%s" % name,
                    "low",
                    "VRR requested but not active on %s" % name,
                    "misc:vrr=%s but the monitor reports vrr off." % vrr_opt,
                    "Check that adaptive sync is enabled in the monitor menu. At a fixed 240Hz it matters only when frame rate drops.",
                )
            )
        elif vrr_opt == 0 and not rep["vrr_active"]:
            findings.append(
                finding(
                    "vrr_off:%s" % name,
                    "info",
                    "VRR is off on %s" % name,
                    "misc:vrr=0.",
                    "Turning it on can smooth frame pacing when frames drop below the refresh rate.",
                )
            )

    blur = opts.get("decoration:blur:enabled")
    passes = opts.get("decoration:blur:passes")
    if blur:
        sev = "medium" if heavy else "low"
        findings.append(
            finding(
                "blur_enabled",
                sev,
                "Blur is on (%s passes)" % (passes if passes is not None else "?"),
                "decoration:blur:enabled is true%s." % (", on a display above 1e9 pixels per second" if heavy else ""),
                "Blur re-renders every window each frame; the cost grows with pixels and refresh rate. Try fewer passes or blur off if frames drop.",
                extra=int(passes) if isinstance(passes, int) else 0,
            )
        )
    if opts.get("decoration:shadow:enabled") and heavy:
        findings.append(
            finding(
                "shadow_enabled",
                "low",
                "Window shadows are on",
                "decoration:shadow:enabled is true on a high pixel rate display.",
                "Shadows are a smaller cost than blur. Disable them only after blur.",
            )
        )
    if opts.get("animations:enabled"):
        findings.append(
            finding(
                "animations_enabled",
                "info",
                "Animations are on",
                "animations:enabled is true.",
                "Long animation curves can feel like lag even at full refresh rate. Shorten them before disabling.",
            )
        )

    measurable = False
    display_cards = {c2c[r["name"]] for r in reports if r["name"] in c2c}
    for gpu in gpus:
        samples = gpu.get("busy_samples")
        if samples:
            measurable = True
            drives_display = not display_cards or gpu["card"] in display_cards
            peak, avg = max(samples), sum(samples) / len(samples)
            if peak >= GPU_BUSY_HIGH:
                sev = "high"
            elif peak >= GPU_BUSY_MEDIUM:
                sev = "medium"
            else:
                sev = "info"
            if not drives_display:
                sev = "info"
                hint = "This card drives no active monitor, so it says nothing about desktop lag."
            elif sev != "info":
                hint = "A busy GPU drops frames. Find the heavy app with the driver's tool (radeontop, nvtop)."
            else:
                hint = "This GPU is not the bottleneck right now."
            findings.append(
                finding(
                    "gpu_busy:%s" % gpu["card"],
                    sev,
                    "%s (%s) busy %d%% peak, %.0f%% avg" % (gpu["card"], gpu.get("driver"), peak, avg),
                    "gpu_busy_percent samples: %s" % samples,
                    hint,
                    extra=peak // 10,
                )
            )
    drivers_by_card = {g["card"]: g.get("driver") for g in gpus}
    for rep in reports:
        card = c2c.get(rep["name"])
        if card and not any(g["card"] == card and g.get("busy_samples") for g in gpus):
            findings.append(
                finding(
                    "gpu_busy_unavailable:%s" % rep["name"],
                    "info",
                    "No gpu_busy_percent for %s" % rep["name"],
                    "%s is wired to %s (%s), which does not expose gpu_busy_percent in sysfs."
                    % (rep["name"], card, drivers_by_card.get(card)),
                    "GPU load for this output cannot be read from sysfs. Use %s while the lag happens." % GPU_TOOLS.get(drivers_by_card.get(card), "nvtop"),
                )
            )
    if not gpus:
        findings.append(finding("no_gpus", "info", "No DRM cards found", "No card entries under /sys/class/drm.", "Check the drm path."))
    elif not measurable and not c2c:
        findings.append(finding("gpu_busy_unavailable", "info", "GPU busy percent unavailable", "No card exposes gpu_busy_percent.", "Use nvtop while the lag happens."))

    stale = [r for r in snap.get("instances", []) if not r["live"]]
    if stale:
        sev = "medium" if len(stale) >= 3 else "low"
        findings.append(
            finding(
                "stale_hypr_dirs",
                sev,
                "%d stale dir(s) in the Hyprland runtime dir" % len(stale),
                "Dead instances: %s" % ", ".join(r["signature"] for r in stale),
                "Each one is a Hyprland session that exited or crashed since boot. They do not slow rendering, but tools that keep an old "
                "HYPRLAND_INSTANCE_SIGNATURE fail with \"Couldn't connect\". Look at why Hyprland restarted.",
                extra=len(stale),
            )
        )
    env_sig = snap.get("env_signature")
    live_sig = snap.get("instance")
    if live_sig and env_sig and env_sig != live_sig:
        findings.append(
            finding(
                "env_signature_dead",
                "low",
                "HYPRLAND_INSTANCE_SIGNATURE points at a dead instance",
                "Env has %s but the live instance is %s." % (env_sig, live_sig),
                "Shells and services started before the last Hyprland restart keep the old signature. Restart them or pass `hyprctl -i`.",
            )
        )

    findings.sort(key=lambda f: (-f["score"], f["id"]))
    return {"monitors": reports, "findings": findings}


def build_result(snap):
    analysis = analyze(snap)
    return {
        "instance": snap.get("instance"),
        "env_signature": snap.get("env_signature"),
        "hypr_instances": [{k: r[k] for k in ("signature", "live", "has_socket")} for r in snap.get("instances", [])],
        "stale_dirs": sum(1 for r in snap.get("instances", []) if not r["live"]),
        "options": snap.get("options", {}),
        "gpus": snap.get("gpus", []),
        "monitors": analysis["monitors"],
        "findings": analysis["findings"],
        "errors": snap.get("errors", []),
    }


# -------------------------------------------------------------- rendering


def render_text(result):
    lines = ["display-doctor", "Instance: %s" % (result["instance"] or "none live")]
    for m in result["monitors"]:
        cur, best = m["current"], m["best"]
        state = "best mode" if m["at_best_mode"] else "NOT best mode"
        best_txt = "%dx%d@%.2fHz" % (best["width"], best["height"], best["refresh_hz"]) if best else "unknown"
        lines.append(
            "Monitor %s (%s): %dx%d@%.2fHz, best %s, %s, scale %s, vrr %s"
            % (m["name"], m["description"], cur["width"], cur["height"], cur["refresh_hz"], best_txt, state, m["scale"], "on" if m["vrr_active"] else "off")
        )
    o = result["options"]
    lines.append(
        "Options: animations=%s blur=%s (passes %s) shadow=%s vrr=%s"
        % (o.get("animations:enabled"), o.get("decoration:blur:enabled"), o.get("decoration:blur:passes"), o.get("decoration:shadow:enabled"), o.get("misc:vrr"))
    )
    for g in result["gpus"]:
        lines.append("GPU %s (%s): busy %s" % (g["card"], g["driver"], g["busy_samples"] if g["busy_samples"] else "not exposed"))
    lines.append("Hyprland dirs: %d total, %d stale" % (len(result["hypr_instances"]), result["stale_dirs"]))
    for e in result["errors"]:
        lines.append("Error: %s" % e)
    lines.append("")
    lines.append("Likely lag causes, most likely first:")
    for i, f in enumerate(result["findings"], 1):
        lines.append("%d. [%s] %s" % (i, f["severity"], f["title"]))
        lines.append("   %s" % f["detail"])
        lines.append("   Hint: %s" % f["hint"])
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="display-doctor", description="Read-only Hyprland display lag check.")
    ap.add_argument("--json", action="store_true", help="print machine readable JSON")
    ap.add_argument("--samples", type=int, default=3, help="gpu_busy_percent samples (default 3)")
    args = ap.parse_args(argv)
    snap = collect(samples=max(1, args.samples))
    result = build_result(snap)
    print(json.dumps(result, indent=2) if args.json else render_text(result))
    return 1 if snap["instance"] is None else 0


if __name__ == "__main__":
    sys.exit(main())
