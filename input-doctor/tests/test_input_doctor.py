import json
import os
import shutil
import socket
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import input_doctor as idr  # noqa: E402


def bind(key, mods=0, desc="", submap="", **kw):
    return {"key": key, "modmask": mods, "description": desc, "submap": submap, "arg": "0", "dispatcher": "__lua", **kw}


class FakeRun:
    """Stub for subprocess: maps a command tuple to (rc, out, err) and records every call."""

    def __init__(self, table=None):
        self.table = dict(table or {})
        self.calls = []

    def __call__(self, cmd, env=None, timeout=5.0):
        self.calls.append((tuple(cmd), env))
        return self.table.get(tuple(cmd), (127, "", f"{cmd[0]}: not found"))


class Env(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="idr"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.runtime = self.tmp / "run"
        (self.runtime / "hypr").mkdir(parents=True)
        self.home = self.tmp / "home"
        (self.home / ".local/bin").mkdir(parents=True)
        (self.home / ".config/voxtype").mkdir(parents=True)
        self.usb = self.tmp / "usb"
        self.usb.mkdir()
        self.proc = self.tmp / "proc"
        self.proc.mkdir()
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        self.socks = []
        self.addCleanup(self._close_socks)

    def _close_socks(self):
        for s in self.socks:
            s.close()

    def instance(self, name, listening, age=0):
        d = self.runtime / "hypr" / name
        d.mkdir()
        if listening:
            s = socket.socket(socket.AF_UNIX)
            s.bind(str(d / ".socket.sock"))
            s.listen(1)
            self.socks.append(s)
        t = time.time() - age
        os.utime(d, (t, t))
        return d

    def tool(self, name):
        p = self.bin / name
        p.write_text("#!/bin/sh\n")
        p.chmod(0o755)

    def usb_dev(self, name, vid, pid, product=""):
        d = self.usb / name
        d.mkdir()
        (d / "idVendor").write_text(vid + "\n")
        (d / "idProduct").write_text(pid + "\n")
        if product:
            (d / "product").write_text(product + "\n")

    def ctx(self, run=None, sig="", **kw):
        environ = {"PATH": str(self.bin), "XDG_RUNTIME_DIR": str(self.runtime), "HYPRLAND_INSTANCE_SIGNATURE": sig}
        environ.update(kw.pop("environ", {}))
        return idr.Context(run=run or FakeRun(), environ=environ, home=self.home, runtime_dir=self.runtime,
                           usb_root=self.usb, proc_root=self.proc, **kw)


class SignatureTests(Env):
    def test_env_signature_live(self):
        self.instance("live1", True)
        r = idr.check_hypr_signature(self.ctx(sig="live1"))
        self.assertEqual(r.status, idr.PASS)

    def test_stale_env_falls_back_to_newest_live(self):
        self.instance("dead", False, age=500)
        self.instance("old", True, age=300)
        self.instance("new", True, age=1)
        ctx = self.ctx(sig="dead")
        r = idr.check_hypr_signature(ctx)
        self.assertEqual(r.status, idr.WARN)
        self.assertIn("using live new", r.detail)
        self.assertEqual(idr.resolve_signature(ctx), "new")

    def test_no_live_socket_fails(self):
        self.instance("dead", False)
        r = idr.check_hypr_signature(self.ctx(sig="dead"))
        self.assertEqual(r.status, idr.FAIL)

    def test_hyprctl_gets_live_signature_not_stale(self):
        self.instance("dead", False, age=100)
        self.instance("new", True)
        run = FakeRun({("hyprctl", "binds", "-j"): (0, "[]", "")})
        ctx = self.ctx(run=run, sig="dead")
        idr.read_binds(ctx)
        self.assertEqual(run.calls[0][1]["HYPRLAND_INSTANCE_SIGNATURE"], "new")


class VoxtypeTests(Env):
    def write_cfg(self, enabled):
        (self.home / ".config/voxtype/config.toml").write_text(f"[hotkey]\nenabled = {str(enabled).lower()}\nkey = \"RIGHTALT\"\n")

    def binds_run(self, binds):
        return FakeRun({("hyprctl", "binds", "-j"): (0, json.dumps(binds), "")})

    def test_service_active_and_inactive(self):
        run = FakeRun({("systemctl", "--user", "is-active", "voxtype.service"): (0, "active\n", "")})
        self.assertEqual(idr.check_voxtype_service(self.ctx(run=run)).status, idr.PASS)
        run = FakeRun({("systemctl", "--user", "is-active", "voxtype.service"): (3, "inactive\n", "")})
        r = idr.check_voxtype_service(self.ctx(run=run))
        self.assertEqual(r.status, idr.FAIL)
        self.assertIn("inactive", r.detail)

    def _show(self, pid):
        return {("systemctl", "--user", "show", "voxtype.service", "-p", "MainPID", "--value"): (0, f"{pid}\n", "")}

    def test_display_matches_live(self):
        self.instance("live", True)
        (self.proc / "42").mkdir()
        (self.proc / "42/environ").write_bytes(b"A=1\0HYPRLAND_INSTANCE_SIGNATURE=live\0")
        r = idr.check_voxtype_display(self.ctx(run=FakeRun(self._show(42)), sig="live"))
        self.assertEqual(r.status, idr.PASS)

    def test_display_stale_after_compositor_restart(self):
        self.instance("live", True)
        (self.proc / "42").mkdir()
        (self.proc / "42/environ").write_bytes(b"HYPRLAND_INSTANCE_SIGNATURE=old\0")
        r = idr.check_voxtype_display(self.ctx(run=FakeRun(self._show(42)), sig="live"))
        self.assertEqual(r.status, idr.FAIL)
        self.assertIn("old", r.detail)

    def test_display_no_main_pid(self):
        self.instance("live", True)
        r = idr.check_voxtype_display(self.ctx(run=FakeRun(self._show(0)), sig="live"))
        self.assertEqual(r.status, idr.FAIL)

    def test_hotkey_hyprland_owns_it(self):
        self.instance("live", True)
        self.write_cfg(False)
        run = self.binds_run([bind("H", idr.MOD_SUPER, "Voxtype Dictation Toggle"), bind("E", idr.MOD_SUPER, "VoxType engine picker")])
        r = idr.check_voxtype_hotkey(self.ctx(run=run, sig="live"))
        self.assertEqual(r.status, idr.PASS)
        self.assertIn("Super+H", r.detail)
        self.assertNotIn("Super+E", r.detail)

    def test_hotkey_nothing_starts_voxtype(self):
        self.instance("live", True)
        self.write_cfg(False)
        r = idr.check_voxtype_hotkey(self.ctx(run=self.binds_run([bind("Z", idr.MOD_ALT, "x")]), sig="live"))
        self.assertEqual(r.status, idr.FAIL)

    def test_hotkey_double_owner_warns(self):
        self.instance("live", True)
        self.write_cfg(True)
        r = idr.check_voxtype_hotkey(self.ctx(run=self.binds_run([bind("H", idr.MOD_SUPER, "Voxtype Dictation Toggle")]), sig="live"))
        self.assertEqual(r.status, idr.WARN)

    def test_hotkey_evdev_only_passes(self):
        self.instance("live", True)
        self.write_cfg(True)
        r = idr.check_voxtype_hotkey(self.ctx(run=self.binds_run([]), sig="live"))
        self.assertEqual(r.status, idr.PASS)

    def test_hotkey_missing_config_fails(self):
        self.instance("live", True)
        r = idr.check_voxtype_hotkey(self.ctx(run=self.binds_run([]), sig="live"))
        self.assertEqual(r.status, idr.FAIL)

    def test_hotkey_no_hyprland_fails(self):
        self.write_cfg(False)
        r = idr.check_voxtype_hotkey(self.ctx())
        self.assertEqual(r.status, idr.FAIL)
        self.assertIn("no live Hyprland socket", r.detail)


class DeviceTests(Env):
    def test_both_present(self):
        self.usb_dev("1-1", "19F5", "1037", "Node 100 LP")
        self.usb_dev("1-2", "24ae", "186a", "Rapoo NearLink Mouse")
        self.assertEqual(idr.check_keyboard(self.ctx()).status, idr.PASS)
        r = idr.check_mouse(self.ctx())
        self.assertEqual(r.status, idr.PASS)
        self.assertIn("Rapoo", r.detail)

    def test_dongle_id_counts(self):
        self.usb_dev("1-5", "19f5", "2620")
        self.assertEqual(idr.check_keyboard(self.ctx()).status, idr.PASS)

    def test_absent_warns_with_hint(self):
        self.usb_dev("1-1", "046d", "c52b")
        r = idr.check_keyboard(self.ctx())
        self.assertEqual(r.status, idr.WARN)
        self.assertTrue(r.fix)

    def test_unreadable_usb_root(self):
        ctx = self.ctx()
        ctx.usb_root = self.tmp / "missing"
        self.assertEqual(idr.check_mouse(ctx).status, idr.WARN)


class BindTests(Env):
    def setUp(self):
        super().setUp()
        self.instance("live", True)

    def ctx_binds(self, binds, **kw):
        run = FakeRun({("hyprctl", "binds", "-j"): (0, json.dumps(binds), "")})
        return self.ctx(run=run, sig="live", **kw)

    def test_alt_z_present_ignoring_numlock(self):
        r = idr.check_screenshot_alt_z(self.ctx_binds([bind("Z", idr.MOD_ALT | 16, "Fullscreen screenshot and paste")]))
        self.assertEqual(r.status, idr.PASS)

    def test_alt_z_missing(self):
        r = idr.check_screenshot_alt_z(self.ctx_binds([bind("Z", idr.MOD_SUPER, "other"), bind("Z", idr.MOD_ALT, "game", submap="game")]))
        self.assertEqual(r.status, idr.FAIL)

    def test_tilt_native_by_default(self):
        self.assertEqual(idr.check_screenshot_tilt(self.ctx_binds([])).status, idr.PASS)

    def test_tilt_bound_outside_game_mode_warns(self):
        r = idr.check_screenshot_tilt(self.ctx_binds([bind("mouse_left", 0, "Rapoo tilt left: Fullscreen screenshot")]))
        self.assertEqual(r.status, idr.WARN)

    def test_tilt_in_game_submap_ignored(self):
        r = idr.check_screenshot_tilt(self.ctx_binds([bind("mouse_left", 0, "g", submap="game")]))
        self.assertEqual(r.status, idr.PASS)

    def test_tilt_expected_present(self):
        binds = [bind("mouse_left", 0, "Rapoo tilt left"), bind("mouse_right", 0, "Rapoo tilt right")]
        self.assertEqual(idr.check_screenshot_tilt(self.ctx_binds(binds, expect_tilt_screenshot=True)).status, idr.PASS)
        self.assertEqual(idr.check_screenshot_tilt(self.ctx_binds([], expect_tilt_screenshot=True)).status, idr.FAIL)

    def test_hyprctl_failure_reports_reason(self):
        run = FakeRun({("hyprctl", "binds", "-j"): (1, "", "Couldn't connect")})
        r = idr.check_screenshot_alt_z(self.ctx(run=run, sig="live"))
        self.assertEqual(r.status, idr.FAIL)
        self.assertIn("Couldn't connect", r.detail)

    def test_hyprctl_bad_json(self):
        run = FakeRun({("hyprctl", "binds", "-j"): (0, "not json", "")})
        r = idr.check_screenshot_alt_z(self.ctx(run=run, sig="live"))
        self.assertEqual(r.status, idr.FAIL)
        self.assertIn("bad JSON", r.detail)


class PasteToolTests(Env):
    def test_tools_present_and_absent(self):
        self.assertEqual(idr.check_wtype(self.ctx()).status, idr.FAIL)
        self.assertEqual(idr.check_ydotool_binary(self.ctx()).status, idr.FAIL)
        self.tool("wtype")
        self.tool("ydotool")
        self.assertEqual(idr.check_wtype(self.ctx()).status, idr.PASS)
        self.assertEqual(idr.check_ydotool_binary(self.ctx()).status, idr.PASS)

    def _ydo_run(self, state):
        return FakeRun({("systemctl", "--user", "is-active", "ydotool.service"): (0 if state == "active" else 3, state + "\n", "")})

    def make_sock(self, path):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        s.bind(str(path))
        self.socks.append(s)

    def test_ydotoold_ok(self):
        self.make_sock(self.runtime / ".ydotool_socket")
        self.assertEqual(idr.check_ydotoold(self.ctx(run=self._ydo_run("active"))).status, idr.PASS)

    def test_ydotoold_socket_but_service_down(self):
        self.make_sock(self.runtime / ".ydotool_socket")
        self.assertEqual(idr.check_ydotoold(self.ctx(run=self._ydo_run("inactive"))).status, idr.WARN)

    def test_ydotoold_regular_file_is_not_a_socket(self):
        (self.runtime / ".ydotool_socket").write_text("")
        self.assertEqual(idr.check_ydotoold(self.ctx(run=self._ydo_run("active"))).status, idr.FAIL)

    def test_ydotoold_env_socket(self):
        p = self.tmp / "custom.sock"
        self.make_sock(p)
        ctx = self.ctx(run=self._ydo_run("active"), environ={"YDOTOOL_SOCKET": str(p)})
        self.assertEqual(idr.check_ydotoold(ctx).status, idr.PASS)

    def wl(self, rc, out, err=""):
        self.tool("wl-paste")
        return FakeRun({("wl-paste", "--list-types"): (rc, out, err)})

    def test_clipboard_image(self):
        r = idr.check_clipboard(self.ctx(run=self.wl(0, "image/png\n"), environ={"WAYLAND_DISPLAY": "wayland-1"}))
        self.assertEqual(r.status, idr.PASS)
        self.assertIn("image present", r.detail)

    def test_clipboard_text_only(self):
        r = idr.check_clipboard(self.ctx(run=self.wl(0, "text/plain\nUTF8_STRING\n"), environ={"WAYLAND_DISPLAY": "wayland-1"}))
        self.assertEqual(r.status, idr.PASS)
        self.assertIn("no image", r.detail)

    def test_clipboard_empty_warns(self):
        r = idr.check_clipboard(self.ctx(run=self.wl(1, "", "Nothing is copied\n"), environ={"WAYLAND_DISPLAY": "wayland-1"}))
        self.assertEqual(r.status, idr.WARN)

    def test_clipboard_compositor_gone(self):
        r = idr.check_clipboard(self.ctx(run=self.wl(1, "", "Failed to connect to a Wayland server"), environ={"WAYLAND_DISPLAY": "wayland-1"}))
        self.assertEqual(r.status, idr.FAIL)

    def test_clipboard_display_from_runtime_socket(self):
        (self.runtime / "wayland-7").write_text("")
        (self.runtime / "wayland-7.lock").write_text("")
        run = self.wl(0, "image/png\n")
        r = idr.check_clipboard(self.ctx(run=run))
        self.assertEqual(r.status, idr.PASS)
        self.assertEqual(run.calls[0][1]["WAYLAND_DISPLAY"], "wayland-7")

    def test_clipboard_no_display(self):
        self.assertEqual(idr.check_clipboard(self.ctx(run=self.wl(0, "image/png\n"))).status, idr.FAIL)

    def test_clipboard_no_wl_paste(self):
        self.assertEqual(idr.check_clipboard(self.ctx()).status, idr.FAIL)

    def test_screenshot_scripts(self):
        self.assertEqual(idr.check_screenshot_scripts(self.ctx()).status, idr.FAIL)
        for n in ("screenshot-paste", "screenshot-capture"):
            p = self.home / ".local/bin" / n
            p.write_text("#!/bin/sh\n")
            p.chmod(0o755)
        self.assertEqual(idr.check_screenshot_scripts(self.ctx()).status, idr.PASS)


class RunnerTests(Env):
    def test_every_check_fills_a_row_and_never_injects(self):
        self.instance("live", True)
        run = FakeRun({("hyprctl", "binds", "-j"): (0, "[]", "")})
        results = idr.run_checks(self.ctx(run=run, sig="live"))
        self.assertEqual(len(results), len(idr.CHECKS))
        for r in results:
            self.assertIn(r.status, (idr.PASS, idr.WARN, idr.FAIL))
            self.assertTrue(r.detail and r.fix and r.title)
        ran = {c[0][0] for c in run.calls}
        self.assertTrue(ran <= {"hyprctl", "systemctl", "wl-paste"}, ran)
        for call, _ in run.calls:
            self.assertNotIn(call[0], ("wtype", "ydotool"))
            self.assertNotIn("keyword", call)
            self.assertNotIn("dispatch", call)

    def test_crashing_check_still_reports(self):
        orig = idr.CHECKS[:]
        self.addCleanup(lambda: idr.CHECKS.__setitem__(slice(None), orig))
        idr.CHECKS[:] = [lambda ctx: 1 / 0]
        results = idr.run_checks(self.ctx())
        self.assertEqual(results[0].status, idr.FAIL)
        self.assertIn("ZeroDivisionError", results[0].detail)

    def test_text_render_shows_fix_only_for_non_pass(self):
        text = idr.render_text([idr.Check("a", "t", idr.PASS, "ok", "FIXA"), idr.Check("b", "t", idr.FAIL, "bad", "FIXB")])
        self.assertNotIn("FIXA", text)
        self.assertIn("FIXB", text)
        self.assertIn("1 pass, 0 warn, 1 fail", text)


if __name__ == "__main__":
    unittest.main()
