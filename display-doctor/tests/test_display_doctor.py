import copy
import json
import os
import shutil
import socket
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import display_doctor as dd  # noqa: E402

# Captured from `hyprctl -i <live> monitors all -j` on a desktop with one 4K OLED monitor, 2026-10-21.
with open(os.path.join(HERE, "fixtures", "monitors-live-20261021.json")) as _f:
    LIVE = json.load(_f)

OPTS_ON = {
    "animations:enabled": True,
    "decoration:blur:enabled": True,
    "decoration:blur:passes": 2,
    "decoration:blur:size": 10,
    "decoration:shadow:enabled": True,
    "misc:vrr": 1,
}


def snap(monitors=None, options=None, gpus=None, connector_cards=None, instances=None, **kw):
    base = {
        "instance": "live",
        "env_signature": "live",
        "instances": instances if instances is not None else [{"signature": "live", "live": True, "has_socket": True}],
        "monitors": monitors if monitors is not None else copy.deepcopy(LIVE),
        "options": options if options is not None else dict(OPTS_ON),
        "gpus": gpus or [],
        "connector_cards": connector_cards or {},
        "errors": [],
    }
    base.update(kw)
    return base


def ids(result):
    return [f["id"] for f in result["findings"]]


class ModeTests(unittest.TestCase):
    def test_parse_mode(self):
        self.assertEqual(dd.parse_mode("3840x2160@239.99Hz"), (3840, 2160, 239.99))
        self.assertIsNone(dd.parse_mode("garbage"))

    def test_best_mode_is_highest_refresh_at_native_size(self):
        self.assertEqual(dd.best_mode(LIVE[0]["availableModes"]), (3840, 2160, 239.99))

    def test_best_mode_empty(self):
        self.assertIsNone(dd.best_mode([]))

    def test_parse_option(self):
        self.assertIs(dd.parse_option('{"option": "a", "bool": true, "set": true }'), True)
        self.assertEqual(dd.parse_option('{"option": "a", "int": 2, "set": true }'), 2)
        self.assertEqual(dd.parse_option('{"option": "a", "int": 0, "set": false }'), 0)
        self.assertIsNone(dd.parse_option("no such option"))

    def test_parse_option_non_object_json_is_none(self):
        # hyprctl can answer with valid JSON that is not an option object.
        for raw in ("null", "[]", '"x"', "5", "true"):
            self.assertIsNone(dd.parse_option(raw), raw)
        self.assertIsNone(dd.parse_option(None))


class AnalyzeTests(unittest.TestCase):
    def test_live_capture_is_at_best_mode(self):
        res = dd.analyze(snap())
        self.assertTrue(res["monitors"][0]["at_best_mode"])
        self.assertFalse([i for i in ids(res) if i.startswith("mode_below_best")])

    def test_sixty_hz_on_240_monitor_ranks_first(self):
        mons = copy.deepcopy(LIVE)
        mons[0]["refreshRate"] = 60.0  # derived from the live capture
        res = dd.analyze(snap(monitors=mons))
        self.assertEqual(ids(res)[0], "mode_below_best:DP-1")
        top = res["findings"][0]
        self.assertEqual(top["severity"], "high")
        self.assertIn("60.00Hz", top["detail"])
        self.assertIn("239.99Hz", top["detail"])
        self.assertFalse(res["monitors"][0]["at_best_mode"])

    def test_non_native_size_is_flagged(self):
        mons = copy.deepcopy(LIVE)
        mons[0].update(width=1920, height=1080, refreshRate=239.88)
        res = dd.analyze(snap(monitors=mons))
        self.assertEqual(ids(res)[0], "mode_below_best:DP-1")
        self.assertIn("native size", res["findings"][0]["title"])

    def test_disabled_monitor_is_skipped(self):
        mons = copy.deepcopy(LIVE)
        mons[0].update(refreshRate=60.0, disabled=True)
        self.assertFalse([i for i in ids(dd.analyze(snap(monitors=mons))) if i.startswith("mode_")])

    def test_blur_medium_on_heavy_display_low_otherwise(self):
        res = dd.analyze(snap())
        blur = next(f for f in res["findings"] if f["id"] == "blur_enabled")
        self.assertEqual(blur["severity"], "medium")
        mons = copy.deepcopy(LIVE)
        mons[0].update(width=1920, height=1080, refreshRate=60.0, availableModes=["1920x1080@60.00Hz"])
        blur = next(f for f in dd.analyze(snap(monitors=mons))["findings"] if f["id"] == "blur_enabled")
        self.assertEqual(blur["severity"], "low")

    def test_fractional_scale_and_vrr(self):
        res = dd.analyze(snap())
        self.assertIn("fractional_scale:DP-1", ids(res))
        self.assertIn("vrr_not_active:DP-1", ids(res))

    def test_integer_scale_no_finding(self):
        mons = copy.deepcopy(LIVE)
        mons[0]["scale"] = 2.0
        self.assertNotIn("fractional_scale:DP-1", ids(dd.analyze(snap(monitors=mons))))

    def test_gpu_busy_high_on_display_card(self):
        gpus = [{"card": "card1", "driver": "amdgpu", "busy_samples": [95, 90, 99]}]
        res = dd.analyze(snap(gpus=gpus, connector_cards={"DP-1": "card1"}))
        f = next(f for f in res["findings"] if f["id"] == "gpu_busy:card1")
        self.assertEqual(f["severity"], "high")
        self.assertEqual(ids(res)[0], "gpu_busy:card1")

    def test_gpu_busy_on_other_card_is_info(self):
        gpus = [
            {"card": "card0", "driver": "amdgpu", "busy_samples": [99, 99, 99]},
            {"card": "card1", "driver": "nvidia", "busy_samples": None},
        ]
        res = dd.analyze(snap(gpus=gpus, connector_cards={"DP-1": "card1"}))
        f = next(f for f in res["findings"] if f["id"] == "gpu_busy:card0")
        self.assertEqual(f["severity"], "info")
        self.assertIn("drives no active monitor", f["hint"])
        self.assertIn("gpu_busy_unavailable:DP-1", ids(res))

    def test_stale_dirs_counted(self):
        inst = [{"signature": "a", "live": True, "has_socket": True}] + [
            {"signature": s, "live": False, "has_socket": False} for s in ("b", "c", "d")
        ]
        res = dd.analyze(snap(instances=inst))
        f = next(f for f in res["findings"] if f["id"] == "stale_hypr_dirs")
        self.assertEqual(f["severity"], "medium")
        self.assertIn("3 stale", f["title"])
        self.assertEqual(dd.build_result(snap(instances=inst))["stale_dirs"], 3)

    def test_env_signature_dead(self):
        res = dd.analyze(snap(env_signature="old"))
        self.assertIn("env_signature_dead", ids(res))

    def test_unreachable_hyprland(self):
        s = snap(monitors=[], instance=None, errors=["no live Hyprland socket"])
        s["options"] = {}
        self.assertEqual(ids(dd.analyze(s))[0], "hyprland_unreachable")

    def test_result_is_json_and_text_renders(self):
        result = dd.build_result(snap())
        json.dumps(result)
        text = dd.render_text(result)
        self.assertIn("Likely lag causes", text)
        self.assertIn("DP-1", text)
        scores = [f["score"] for f in result["findings"]]
        self.assertEqual(scores, sorted(scores, reverse=True))


class FakeSys(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="dd", dir="/tmp")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_read_gpus_and_connectors(self):
        drm = os.path.join(self.tmp, "drm")
        for card, driver, busy in (("card0", "amdgpu", "42"), ("card1", "nvidia", None)):
            dev = os.path.join(drm, card, "device")
            os.makedirs(dev)
            drv = os.path.join(self.tmp, "drivers", driver)
            os.makedirs(drv, exist_ok=True)
            os.symlink(drv, os.path.join(dev, "driver"))
            if busy:
                with open(os.path.join(dev, "gpu_busy_percent"), "w") as f:
                    f.write(busy + "\n")
        os.makedirs(os.path.join(drm, "card1-DP-1"))
        os.makedirs(os.path.join(drm, "card0-HDMI-A-2"))
        sleeps = []
        gpus = dd.read_gpus(drm, samples=3, interval=0.5, sleep=sleeps.append)
        self.assertEqual(
            gpus,
            [
                {"card": "card0", "driver": "amdgpu", "busy_samples": [42, 42, 42]},
                {"card": "card1", "driver": "nvidia", "busy_samples": None},
            ],
        )
        self.assertEqual(sleeps, [0.5, 0.5])
        self.assertEqual(dd.connector_cards(drm), {"DP-1": "card1", "HDMI-A-2": "card0"})

    def test_scan_and_pick_instances(self):
        hypr = os.path.join(self.tmp, "hypr")
        live, dead_sock, no_sock = (os.path.join(hypr, n) for n in ("live", "deadsock", "nosock"))
        for d in (live, dead_sock, no_sock):
            os.makedirs(d)
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(os.path.join(live, ".socket.sock"))
        server.listen(1)
        self.addCleanup(server.close)
        gone = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        gone.bind(os.path.join(dead_sock, ".socket.sock"))
        gone.close()  # file stays, nothing listens

        rows = dd.scan_instances(hypr, env_signature="deadsock")
        by = {r["signature"]: r for r in rows}
        self.assertTrue(by["live"]["live"])
        self.assertFalse(by["deadsock"]["live"])
        self.assertTrue(by["deadsock"]["has_socket"])
        self.assertFalse(by["nosock"]["has_socket"])
        self.assertEqual(dd.pick_instance(rows, env_signature="deadsock"), "live")
        self.assertEqual(dd.pick_instance(rows, env_signature="live"), "live")
        self.assertIsNone(dd.pick_instance([r for r in rows if not r["live"]]))

    def test_collect_with_stub_runner(self):
        hypr = os.path.join(self.tmp, "run", "hypr", "sig1")
        os.makedirs(hypr)
        open(os.path.join(hypr, ".socket.sock"), "w").close()
        calls = []

        def factory(signature):
            def run(args):
                calls.append((signature, args))
                if args[0] == "monitors":
                    return json.dumps(LIVE)
                return json.dumps({"option": args[1], "int": 1, "set": True})

            return run

        s = dd.collect(
            runtime_dir=os.path.join(self.tmp, "run"),
            drm_root=os.path.join(self.tmp, "nodrm"),
            env_signature="sig1",
            alive=lambda p: True,
            runner_factory=factory,
        )
        self.assertEqual(s["instance"], "sig1")
        self.assertEqual(len(s["monitors"]), 1)
        self.assertEqual(set(s["options"]), set(dd.OPTIONS))
        self.assertEqual({c[1][0] for c in calls}, {"monitors", "getoption"})
        self.assertEqual(s["errors"], [])

    def test_collect_survives_null_getoption(self):
        hypr = os.path.join(self.tmp, "run", "hypr", "sig1")
        os.makedirs(hypr)
        open(os.path.join(hypr, ".socket.sock"), "w").close()

        def factory(signature):
            def run(args):
                if args[0] == "monitors":
                    return json.dumps(LIVE)
                return "null"

            return run

        s = dd.collect(
            runtime_dir=os.path.join(self.tmp, "run"),
            drm_root=os.path.join(self.tmp, "nodrm"),
            env_signature="sig1",
            alive=lambda p: True,
            runner_factory=factory,
        )
        self.assertEqual(set(s["options"]), set(dd.OPTIONS))
        self.assertEqual(set(s["options"].values()), {None})
        self.assertEqual(s["errors"], [])
        json.dumps(dd.build_result(s))

    def test_collect_without_live_instance(self):
        os.makedirs(os.path.join(self.tmp, "run", "hypr", "sig1"))
        open(os.path.join(self.tmp, "run", "hypr", "sig1", ".socket.sock"), "w").close()
        s = dd.collect(runtime_dir=os.path.join(self.tmp, "run"), drm_root=os.path.join(self.tmp, "nodrm"), alive=lambda p: False)
        self.assertIsNone(s["instance"])
        self.assertTrue(s["errors"])
        self.assertEqual(ids(dd.analyze(s))[0], "hyprland_unreachable")


class ReadOnlyTests(unittest.TestCase):
    def test_runner_refuses_state_changing_verbs(self):
        run = dd.make_hyprctl_runner("whatever")
        for args in (["keyword", "animations:enabled", "0"], ["reload"], ["dispatch", "exit"], [], ["setprop", "x", "y", "z"]):
            with self.assertRaises(dd.HyprError):
                run(args)

    def test_read_only_verbs_constant(self):
        self.assertEqual(set(dd.READ_ONLY_VERBS), {"monitors", "getoption"})


if __name__ == "__main__":
    unittest.main()
