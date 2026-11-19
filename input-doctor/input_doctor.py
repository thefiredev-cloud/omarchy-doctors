#!/usr/bin/env python3
"""input-doctor: read-only health check for Voxtype dictation, screenshots and paste.

Never injects keys, never changes binds, never restarts anything. Every check
returns an id, a status (pass, warn, fail), a one-line detail and a fix hint.
Python stdlib only.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import stat
import subprocess
import sys
import tomllib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

PASS, WARN, FAIL = "pass", "warn", "fail"

# Hyprland modmask bits. CAPS (2) and MOD2/NumLock (16) never matter for a bind.
MOD_SHIFT, MOD_CTRL, MOD_ALT, MOD_SUPER = 1, 4, 8, 64
MOD_IGNORED = 2 | 16

NUPHY_IDS = {("19f5", "1037"), ("19f5", "2620")}
RAPOO_IDS = {("24ae", "186a"), ("24ae", "186c"), ("24ae", "4510")}

Runner = Callable[[list[str], dict[str, str] | None, float], "tuple[int, str, str]"]


def default_run(cmd: list[str], env: dict[str, str] | None = None, timeout: float = 5.0) -> tuple[int, str, str]:
    """Run a command, return (returncode, stdout, stderr). rc 127 if missing, 124 on timeout."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", f"{cmd[0]}: not found"
    except subprocess.TimeoutExpired:
        return 124, "", f"{cmd[0]}: timed out after {timeout}s"


@dataclass
class Context:
    """Everything the checks read from the machine, so tests can swap it all out."""

    run: Runner = default_run
    environ: dict[str, str] = field(default_factory=lambda: dict(os.environ))
    home: Path = field(default_factory=Path.home)
    runtime_dir: Path | None = None
    usb_root: Path = Path("/sys/bus/usb/devices")
    proc_root: Path = Path("/proc")
    expect_tilt_screenshot: bool = False

    def __post_init__(self) -> None:
        if self.runtime_dir is None:
            self.runtime_dir = Path(self.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}")
        self._signature: str | None | bool = False
        self._binds: tuple[list[dict] | None, str] | None = None

    @property
    def hypr_dir(self) -> Path:
        return self.runtime_dir / "hypr"


@dataclass
class Check:
    id: str
    title: str
    status: str
    detail: str
    fix: str

    def as_dict(self) -> dict:
        return {"id": self.id, "title": self.title, "status": self.status, "detail": self.detail, "fix": self.fix}


# ---------------------------------------------------------------- Hyprland


def socket_accepts(path: Path) -> bool:
    """True when something is listening on the unix socket at path."""
    if not path.exists():
        return False
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(1.0)
    try:
        s.connect(str(path))
        return True
    except OSError:
        return False
    finally:
        s.close()


def live_signatures(ctx: Context) -> list[str]:
    """Instance dirs whose .socket.sock accepts a connect, newest first."""
    if not ctx.hypr_dir.is_dir():
        return []
    dirs = [d for d in ctx.hypr_dir.iterdir() if d.is_dir()]
    dirs.sort(key=lambda d: d.stat().st_mtime, reverse=True)
    return [d.name for d in dirs if socket_accepts(d / ".socket.sock")]


def resolve_signature(ctx: Context) -> str | None:
    """The signature of a live Hyprland. The environment value wins when it is live."""
    if ctx._signature is not False:
        return ctx._signature  # type: ignore[return-value]
    live = live_signatures(ctx)
    env_sig = ctx.environ.get("HYPRLAND_INSTANCE_SIGNATURE", "")
    if env_sig and env_sig in live:
        ctx._signature = env_sig
    else:
        ctx._signature = live[0] if live else None
    return ctx._signature  # type: ignore[return-value]


def hypr_env(ctx: Context) -> dict[str, str]:
    env = dict(ctx.environ)
    sig = resolve_signature(ctx)
    if sig:
        env["HYPRLAND_INSTANCE_SIGNATURE"] = sig
    return env


def read_binds(ctx: Context) -> tuple[list[dict] | None, str]:
    """Live binds from `hyprctl binds -j` against the live instance. Cached."""
    if ctx._binds is not None:
        return ctx._binds
    if resolve_signature(ctx) is None:
        ctx._binds = (None, "no live Hyprland socket")
        return ctx._binds
    rc, out, err = ctx.run(["hyprctl", "binds", "-j"], hypr_env(ctx), 5.0)
    if rc != 0:
        ctx._binds = (None, (err or out).strip() or f"hyprctl exit {rc}")
        return ctx._binds
    try:
        data = json.loads(out)
        if not isinstance(data, list):
            raise ValueError("not a list")
    except ValueError as e:
        ctx._binds = (None, f"hyprctl returned bad JSON: {e}")
        return ctx._binds
    ctx._binds = (data, "")
    return ctx._binds


def bind_mods(bind: dict) -> int:
    return int(bind.get("modmask", 0)) & ~MOD_IGNORED


def describe_bind(bind: dict) -> str:
    names = [n for bit, n in ((MOD_SUPER, "Super"), (MOD_CTRL, "Ctrl"), (MOD_ALT, "Alt"), (MOD_SHIFT, "Shift")) if bind_mods(bind) & bit]
    return "+".join(names + [str(bind.get("key", "?"))])


def check_hypr_signature(ctx: Context) -> Check:
    cid, title = "hypr.signature", "Hyprland signature matches a live socket"
    fix = "Open a new terminal, or `export HYPRLAND_INSTANCE_SIGNATURE=<live dir name in $XDG_RUNTIME_DIR/hypr>`."
    live = live_signatures(ctx)
    env_sig = ctx.environ.get("HYPRLAND_INSTANCE_SIGNATURE", "")
    if not live:
        return Check(cid, title, FAIL, f"no instance dir in {ctx.hypr_dir} accepts a connect (env: {env_sig or 'unset'})",
                     "Hyprland is not running, or it crashed. Log in again from the display manager.")
    if env_sig in live:
        return Check(cid, title, PASS, f"environment signature is live ({env_sig}); {len(live)} live instance(s)", fix)
    stale = "unset" if not env_sig else f"{env_sig} is stale"
    return Check(cid, title, WARN, f"environment signature {stale}; using live {live[0]}", fix)


# ---------------------------------------------------------------- Voxtype


def service_active(ctx: Context, unit: str) -> tuple[bool, str]:
    rc, out, err = ctx.run(["systemctl", "--user", "is-active", unit], None, 5.0)
    state = (out or err).strip() or f"exit {rc}"
    return rc == 0 and state == "active", state


def check_voxtype_service(ctx: Context) -> Check:
    cid, title = "voxtype.service", "voxtype.service is active"
    fix = "`systemctl --user restart voxtype.service` (it needs the live Hyprland session first)."
    ok, state = service_active(ctx, "voxtype.service")
    return Check(cid, title, PASS if ok else FAIL, f"voxtype.service is {state}", fix)


def check_voxtype_display(ctx: Context) -> Check:
    """A daemon started under an old compositor keeps a dead display (journal: 'Broken pipe')."""
    cid, title = "voxtype.display", "Voxtype runs inside the live Hyprland session"
    fix = "Restart Voxtype after any Hyprland restart: `systemctl --user restart voxtype.service`."
    rc, out, _ = ctx.run(["systemctl", "--user", "show", "voxtype.service", "-p", "MainPID", "--value"], None, 5.0)
    pid = out.strip()
    if rc != 0 or not pid.isdigit() or pid == "0":
        return Check(cid, title, FAIL, "voxtype.service has no running main process", fix)
    live = resolve_signature(ctx)
    if live is None:
        return Check(cid, title, FAIL, "no live Hyprland to compare against", "Start Hyprland first.")
    try:
        raw = (ctx.proc_root / pid / "environ").read_bytes().split(b"\0")
    except OSError as e:
        return Check(cid, title, WARN, f"cannot read environment of pid {pid}: {e.strerror}", fix)
    env = {k.decode(errors="replace"): v.decode(errors="replace") for k, _, v in (x.partition(b"=") for x in raw) if k}
    sig = env.get("HYPRLAND_INSTANCE_SIGNATURE", "")
    if sig == live:
        return Check(cid, title, PASS, f"pid {pid} uses live signature {live}", fix)
    return Check(cid, title, FAIL, f"pid {pid} uses signature {sig or 'none'}, live is {live}", fix)


def is_dictation_bind(bind: dict) -> bool:
    desc = str(bind.get("description", "")).lower()
    return "dictation" in desc or ("voxtype" in desc and "toggle" in desc)


def check_voxtype_hotkey(ctx: Context) -> Check:
    cid, title = "voxtype.hotkey", "Voxtype hotkey config matches live Hyprland binds"
    fix = "Hyprland owns dictation: keep `[hotkey] enabled = false` in ~/.config/voxtype/config.toml and keep a `voxtype record toggle` bind in ~/.config/hypr/bindings.lua."
    cfg_path = ctx.home / ".config/voxtype/config.toml"
    try:
        cfg = tomllib.loads(cfg_path.read_text())
    except (OSError, tomllib.TOMLDecodeError) as e:
        return Check(cid, title, FAIL, f"cannot read {cfg_path}: {e}", "Restore ~/.config/voxtype/config.toml from a .bak file.")
    evdev_on = bool(cfg.get("hotkey", {}).get("enabled", False))
    binds, why = read_binds(ctx)
    if binds is None:
        return Check(cid, title, FAIL, f"evdev hotkey enabled={evdev_on}; cannot read live binds: {why}", fix)
    toggles = [b for b in binds if is_dictation_bind(b)]
    names = ", ".join(sorted({describe_bind(b) for b in toggles})) or "none"
    if evdev_on and toggles:
        return Check(cid, title, WARN,
                     f"evdev hotkey AND Hyprland binds both enabled ({names}): one press can start and stop recording",
                     fix)
    if not evdev_on and not toggles:
        return Check(cid, title, FAIL, "evdev hotkey disabled and no dictation bind in Hyprland: nothing starts Voxtype (the Alt tap is a raw-key handler and does not show in binds)", fix)
    owner = "Hyprland binds" if toggles else "evdev hotkey"
    return Check(cid, title, PASS,
                 f"{owner} own dictation (evdev enabled={evdev_on}; live binds: {names}). The bare Alt tap is a Lua raw-key handler and is not listed by hyprctl",
                 fix)


# ---------------------------------------------------------------- Devices


def usb_devices(ctx: Context) -> list[tuple[str, str, str]]:
    found: list[tuple[str, str, str]] = []
    try:
        entries = sorted(ctx.usb_root.iterdir())
    except OSError:
        return found
    for d in entries:
        try:
            vid = (d / "idVendor").read_text().strip().lower()
            pid = (d / "idProduct").read_text().strip().lower()
        except OSError:
            continue
        try:
            name = (d / "product").read_text().strip()
        except OSError:
            name = ""
        found.append((vid, pid, name))
    return found


def check_device(ctx: Context, cid: str, title: str, ids: set[tuple[str, str]], fix: str) -> Check:
    hits = [f"{v}:{p} {n}".strip() for v, p, n in usb_devices(ctx) if (v, p) in ids]
    if hits:
        return Check(cid, title, PASS, "present: " + "; ".join(hits), fix)
    wanted = ", ".join(f"{v}:{p}" for v, p in sorted(ids))
    return Check(cid, title, WARN, f"no USB device with id {wanted} in {ctx.usb_root}", fix)


def check_keyboard(ctx: Context) -> Check:
    return check_device(ctx, "device.keyboard", "NuPhy Node100 keyboard is present", NUPHY_IDS,
                        "Replug the NuPhy dongle or switch the keyboard to 2.4G mode. Ignore if you use another keyboard.")


def check_mouse(ctx: Context) -> Check:
    return check_device(ctx, "device.mouse", "Rapoo MT760 mouse is present", RAPOO_IDS,
                        "Replug the Rapoo NearLink dongle. Ignore if you use another mouse.")


# ---------------------------------------------------------------- Screenshot binds


def root_binds(binds: list[dict]) -> list[dict]:
    return [b for b in binds if not b.get("submap")]


def check_screenshot_alt_z(ctx: Context) -> Check:
    cid, title = "binds.screenshot", "Alt+Z screenshot-and-paste bind is live"
    fix = "Re-add `o.bind(\"ALT + Z\", \"Fullscreen screenshot and paste\", \".../screenshot-paste\")` to ~/.config/hypr/bindings.lua, then `hyprctl reload` from your own shell."
    binds, why = read_binds(ctx)
    if binds is None:
        return Check(cid, title, FAIL, f"cannot read live binds: {why}", fix)
    hits = [b for b in root_binds(binds) if bind_mods(b) == MOD_ALT and str(b.get("key", "")).lower() == "z"]
    if hits:
        return Check(cid, title, PASS, f"Alt+Z bound: {hits[0].get('description') or 'no description'}", fix)
    return Check(cid, title, FAIL, "no Alt+Z bind in the live Hyprland", fix)


def check_screenshot_tilt(ctx: Context) -> Check:
    """By default wheel tilt should stay native horizontal scroll; --expect-tilt-screenshot flips the check."""
    cid, title = "binds.tilt", "Wheel tilt (mouse_left/mouse_right) binds"
    binds, why = read_binds(ctx)
    tilt = []
    if binds is not None:
        tilt = [b for b in root_binds(binds) if str(b.get("key", "")) in ("mouse_left", "mouse_right") and bind_mods(b) == 0]
    names = "; ".join(f"{b['key']}: {b.get('description') or b.get('arg')}" for b in tilt)
    if ctx.expect_tilt_screenshot:
        fix = "Restore the tilt binds in ~/.config/hypr/bindings.lua (tilt left = fullscreen screenshot, tilt right = cropped screenshot)."
        if binds is None:
            return Check(cid, title, FAIL, f"cannot read live binds: {why}", fix)
        if len(tilt) >= 2:
            return Check(cid, title, PASS, f"tilt screenshot binds live: {names}", fix)
        return Check(cid, title, FAIL, f"expected tilt screenshot binds, found {len(tilt)}", fix)
    fix = "Tilt should stay native horizontal scroll. Remove tilt binds if scroll is eaten; pass --expect-tilt-screenshot to require them instead."
    if binds is None:
        return Check(cid, title, FAIL, f"cannot read live binds: {why}", fix)
    if not tilt:
        return Check(cid, title, PASS, "no root-level tilt binds: tilt is native horizontal scroll", fix)
    return Check(cid, title, WARN, f"tilt is bound outside Game Mode, so it will not scroll: {names}", fix)


# ---------------------------------------------------------------- Paste plumbing


def which(ctx: Context, name: str) -> str | None:
    for d in ctx.environ.get("PATH", "").split(os.pathsep):
        p = Path(d) / name
        if d and p.is_file() and os.access(p, os.X_OK):
            return str(p)
    return None


def check_wtype(ctx: Context) -> Check:
    cid, title = "tool.wtype", "wtype is installed"
    fix = "`sudo pacman -S wtype`"
    p = which(ctx, "wtype")
    return Check(cid, title, PASS if p else FAIL, p or "wtype not on PATH", fix)


def check_ydotool_binary(ctx: Context) -> Check:
    cid, title = "tool.ydotool", "ydotool is installed"
    fix = "`sudo pacman -S ydotool`"
    p = which(ctx, "ydotool")
    return Check(cid, title, PASS if p else FAIL, p or "ydotool not on PATH", fix)


def ydotool_socket_candidates(ctx: Context) -> list[Path]:
    out = []
    if ctx.environ.get("YDOTOOL_SOCKET"):
        out.append(Path(ctx.environ["YDOTOOL_SOCKET"]))
    out += [ctx.runtime_dir / ".ydotool_socket", Path("/tmp/.ydotool_socket")]
    return out


def check_ydotoold(ctx: Context) -> Check:
    cid, title = "tool.ydotoold", "ydotoold is running and its socket exists"
    fix = "`systemctl --user enable --now ydotool.service`; the socket is $XDG_RUNTIME_DIR/.ydotool_socket."
    ok, state = service_active(ctx, "ydotool.service")
    sock = next((p for p in ydotool_socket_candidates(ctx) if p.exists() and stat.S_ISSOCK(p.stat().st_mode)), None)
    if ok and sock:
        return Check(cid, title, PASS, f"ydotool.service active; socket {sock}", fix)
    if sock:
        return Check(cid, title, WARN, f"socket {sock} exists but ydotool.service is {state}", fix)
    return Check(cid, title, FAIL, f"ydotool.service is {state}; no socket in {', '.join(str(p) for p in ydotool_socket_candidates(ctx))}", fix)


def wayland_display(ctx: Context) -> str | None:
    if ctx.environ.get("WAYLAND_DISPLAY"):
        return ctx.environ["WAYLAND_DISPLAY"]
    socks = sorted(p.name for p in ctx.runtime_dir.glob("wayland-*") if not p.name.endswith(".lock"))
    return socks[0] if socks else None


def check_clipboard(ctx: Context) -> Check:
    cid, title = "clipboard.types", "wl-paste can read the clipboard (MIME types)"
    fix = "Check the Wayland session: `echo $WAYLAND_DISPLAY`. Copy something, then run `wl-paste --list-types`."
    if which(ctx, "wl-paste") is None:
        return Check(cid, title, FAIL, "wl-paste not on PATH", "`sudo pacman -S wl-clipboard`")
    display = wayland_display(ctx)
    if display is None:
        return Check(cid, title, FAIL, f"no WAYLAND_DISPLAY and no wayland-* socket in {ctx.runtime_dir}", fix)
    env = dict(ctx.environ)
    env["WAYLAND_DISPLAY"] = display
    env.setdefault("XDG_RUNTIME_DIR", str(ctx.runtime_dir))
    rc, out, err = ctx.run(["wl-paste", "--list-types"], env, 5.0)
    types = [t for t in out.split() if t]
    if rc == 0 and types:
        image = [t for t in types if t.startswith("image/")]
        kind = f"image present ({', '.join(image)})" if image else "text only, no image on the clipboard"
        return Check(cid, title, PASS, f"{display}: {', '.join(types)}; {kind}", fix)
    msg = (err or out).strip()
    if rc == 1 and "nothing is copied" in msg.lower():
        return Check(cid, title, WARN, f"{display}: clipboard is empty", fix)
    return Check(cid, title, FAIL, f"wl-paste failed on {display} (exit {rc}): {msg or 'no output'}", fix)


def check_screenshot_scripts(ctx: Context) -> Check:
    cid, title = "screenshot.scripts", "screenshot-paste and screenshot-capture exist"
    fix = "Restore ~/.local/bin/screenshot-paste and ~/.local/bin/screenshot-capture from their .bak files."
    missing = []
    for name in ("screenshot-paste", "screenshot-capture"):
        p = ctx.home / ".local/bin" / name
        if not (p.is_file() and os.access(p, os.X_OK)):
            missing.append(name)
    if missing:
        return Check(cid, title, FAIL, "missing or not executable: " + ", ".join(missing), fix)
    return Check(cid, title, PASS, f"both executable in {ctx.home / '.local/bin'}", fix)


CHECKS: list[Callable[[Context], Check]] = [
    check_hypr_signature,
    check_voxtype_service,
    check_voxtype_display,
    check_voxtype_hotkey,
    check_keyboard,
    check_mouse,
    check_screenshot_alt_z,
    check_screenshot_tilt,
    check_screenshot_scripts,
    check_wtype,
    check_ydotool_binary,
    check_ydotoold,
    check_clipboard,
]


def run_checks(ctx: Context) -> list[Check]:
    results = []
    for fn in CHECKS:
        try:
            results.append(fn(ctx))
        except Exception as e:  # a broken check must still fill its row
            results.append(Check(fn.__name__.removeprefix("check_"), fn.__name__, FAIL, f"check crashed: {type(e).__name__}: {e}", "Report this bug."))
    return results


def summarize(results: list[Check]) -> dict[str, int]:
    return {s: sum(1 for r in results if r.status == s) for s in (PASS, WARN, FAIL)}


def render_text(results: list[Check]) -> str:
    lines = []
    for r in results:
        lines.append(f"[{r.status.upper():4}] {r.id:18} {r.detail}")
        if r.status != PASS:
            lines.append(f"       fix: {r.fix}")
    s = summarize(results)
    lines.append(f"\n{s[PASS]} pass, {s[WARN]} warn, {s[FAIL]} fail")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="input-doctor", description="Read-only check of Voxtype, screenshot and paste plumbing.")
    ap.add_argument("--json", action="store_true", help="print machine-readable JSON")
    ap.add_argument("--strict", action="store_true", help="exit 1 when any check fails (default exit 0 once all checks ran)")
    ap.add_argument("--expect-tilt-screenshot", action="store_true",
                    help="require wheel-tilt screenshot binds (left tilt = fullscreen, right tilt = crop)")
    args = ap.parse_args(argv)
    ctx = Context(expect_tilt_screenshot=args.expect_tilt_screenshot)
    results = run_checks(ctx)
    if args.json:
        print(json.dumps({
            "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "summary": summarize(results),
            "checks": [r.as_dict() for r in results],
        }, indent=2))
    else:
        print(render_text(results))
    if args.strict and any(r.status == FAIL for r in results):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
