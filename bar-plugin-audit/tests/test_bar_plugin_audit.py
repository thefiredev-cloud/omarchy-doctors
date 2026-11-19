import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import bar_plugin_audit as B  # noqa: E402


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb" if isinstance(text, bytes) else "w") as fh:
        fh.write(text)


def manifest(pid, kinds=("bar-widget",), entry="W.qml", extra=None):
    m = {"schemaVersion": 1, "id": pid, "kinds": list(kinds), "entryPoints": {"barWidget": entry}}
    m.update(extra or {})
    return json.dumps(m)


class AuditTree(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = self.tmp.name
        self.plugins = os.path.join(t, "plugins")
        self.builtin = os.path.join(t, "builtin")
        self.crashes = os.path.join(t, "crashes")
        self.shell = os.path.join(t, "shell.json")

        for pid in ("good.one", "good.two", "unplaced.widget", "svc.enabled", "dupeA", "multi.ok"):
            write(os.path.join(self.plugins, pid, "manifest.json"),
                  manifest(pid, kinds=("service",) if pid == "svc.enabled" else ("bar-widget",),
                           extra={"barWidget": {"allowMultiple": True}} if pid == "multi.ok" else None))
            write(os.path.join(self.plugins, pid, "W.qml"), "Item {}")
        # same id as dupeA under another dir
        write(os.path.join(self.plugins, "dupeB", "manifest.json"), manifest("dupeA"))
        write(os.path.join(self.plugins, "dupeB", "W.qml"), "Item {}")
        # broken json
        write(os.path.join(self.plugins, "broken", "manifest.json"), "{not json")
        # no manifest
        os.makedirs(os.path.join(self.plugins, "empty"))
        # missing entry file
        write(os.path.join(self.plugins, "noentry", "manifest.json"), manifest("noentry", entry="Gone.qml"))
        # no entryPoints key
        write(os.path.join(self.plugins, "noeps", "manifest.json"),
              json.dumps({"id": "noeps", "kinds": ["service"]}))
        # backups and dot dir
        os.makedirs(os.path.join(self.plugins, "good.one.bak-1"))
        os.makedirs(os.path.join(self.plugins, ".hidden.bak.2"))
        os.makedirs(os.path.join(self.plugins, ".hidden-plain"))
        write(os.path.join(self.plugins, "stray.txt"), "x")

        write(os.path.join(self.builtin, "clock", "manifest.json"),
              json.dumps({"id": "omarchy.clock", "kinds": ["bar-widget"]}))
        write(os.path.join(self.builtin, "bar", "widgets", "Spacer.manifest.json"),
              json.dumps({"id": "omarchy.spacer", "kinds": ["bar-widget"],
                          "barWidget": {"allowMultiple": True}}))

        write(self.shell, json.dumps({
            "bar": {"id": "good.one", "layout": {
                "left": [{"id": "good.one"}, {"id": "omarchy.spacer"}, {"id": "omarchy.spacer"}],
                "center": [{"id": "omarchy.clock"}, {"id": "ghost.widget"}, {"id": "good.two"},
                           {"id": "good.two"}],
                "right": [{"id": "multi.ok"}, {"id": "multi.ok"}, {"id": "off.widget"}]}},
            "plugins": [{"id": "svc.enabled"}, {"id": "stale.enabled"}],
            "disabledPlugins": ["off.widget"],
        }))
        write(os.path.join(self.plugins, "off.widget", "manifest.json"), manifest("off.widget"))
        write(os.path.join(self.plugins, "off.widget", "W.qml"), "Item {}")

        for name, line in (("run1", b"\x00log plugins/good.two/W.qml\x00 plugins/ghost.dir/x"),
                           ("run2", b"... plugins/good.one/W.qml"),
                           ("run3", b"plugins/good.one/W.qml ... plugins/good.one/Other.qml"),
                           ("run4", b"... plugins/bar/Bar.qml"),
                           ("run5", b"nothing here")):
            write(os.path.join(self.crashes, name, "log.qslog.log"), line)
            write(os.path.join(self.crashes, name, "report.txt"), "Signal: Aborted")
        write(os.path.join(self.crashes, "report.txt"), "stray")

        self.rep = B.audit(self.plugins, self.shell, self.builtin, self.crashes)

    def tearDown(self):
        self.tmp.cleanup()

    def test_counts(self):
        r = self.rep
        # 13 non-dot dirs + stray file + 2 dot dirs
        self.assertEqual(r["total_entries"], 16)
        self.assertEqual(r["non_dir_entries"], ["stray.txt"])
        self.assertEqual(r["layout_items"], 10)

    def test_invalid_manifests(self):
        errs = {m["dir"]: m["error"] for m in self.rep["invalid_manifests"]}
        self.assertIn("unreadable", errs["broken"])
        self.assertEqual(errs["empty"], "manifest.json missing")
        self.assertEqual(errs["noeps"], "entryPoints missing")
        self.assertEqual(set(errs), {"broken", "empty", "noeps", "good.one.bak-1"})

    def test_missing_entry_files(self):
        self.assertEqual([m["id"] for m in self.rep["missing_entry_files"]], ["noentry"])

    def test_duplicate_manifest_ids(self):
        self.assertEqual(self.rep["duplicate_manifest_ids"], {"dupeA": ["dupeA", "dupeB"]})

    def test_duplicate_layout_ids_respect_allow_multiple(self):
        self.assertEqual(self.rep["duplicate_layout_ids"], {"good.two": 2})

    def test_layout_ids_without_plugin(self):
        self.assertEqual(self.rep["layout_ids_without_plugin"], ["ghost.widget"])

    def test_layout_disabled_and_missing_bar(self):
        self.assertEqual(self.rep["layout_ids_disabled"], ["off.widget"])
        self.assertIsNone(self.rep["bar_plugin_missing"])

    def test_not_in_layout(self):
        r = self.rep
        self.assertEqual(r["enabled_not_in_layout"], ["svc.enabled"])
        self.assertIn("unplaced.widget", r["bar_widgets_not_placed_or_enabled"])
        self.assertNotIn("good.one", r["installed_not_in_layout_or_enabled"])
        self.assertIn("unplaced.widget", r["installed_not_in_layout_or_enabled"])
        self.assertEqual(r["enabled_ids_without_plugin"], ["stale.enabled"])

    def test_backups(self):
        self.assertEqual(sorted(self.rep["backup_dirs"]), [".hidden.bak.2", "good.one.bak-1"])

    def test_crashes(self):
        c = self.rep["crashes"]
        self.assertEqual(c["reports"], 5)
        self.assertEqual(c["no_plugin_ref"], 1)
        self.assertEqual(c["stray_files"], ["report.txt"])
        self.assertEqual(c["by_plugin_dir"], {"good.one": 2, "bar": 1, "ghost.dir": 1})
        rows = {r["dir"]: r for r in c["rows"]}
        self.assertEqual(rows["good.one"]["plugin"], "good.one")
        self.assertEqual(rows["bar"]["plugin"], "builtin:bar")
        self.assertFalse(rows["ghost.dir"]["installed"])

    def test_text_and_json_cli(self):
        cmd = [sys.executable, os.path.join(ROOT, "bar_plugin_audit.py"),
               "--plugins-dir", self.plugins, "--shell-json", self.shell,
               "--builtin-dir", self.builtin, "--crashes-dir", self.crashes]
        text = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
        self.assertIn("Total entries in plugins dir: 16", text)
        self.assertIn("ghost.widget", text)
        data = json.loads(subprocess.run(cmd + ["--json"], capture_output=True, text=True, check=True).stdout)
        self.assertEqual(data["total_entries"], 16)

    def test_never_writes(self):
        before = sorted(os.path.join(d, f) for d, _s, fs in os.walk(self.tmp.name) for f in fs + _s)
        B.audit(self.plugins, self.shell, self.builtin, self.crashes)
        after = sorted(os.path.join(d, f) for d, _s, fs in os.walk(self.tmp.name) for f in fs + _s)
        self.assertEqual(before, after)

    def test_bad_shell_json_exit_2(self):
        bad = os.path.join(self.tmp.name, "bad.json")
        write(bad, "{")
        p = subprocess.run([sys.executable, os.path.join(ROOT, "bar_plugin_audit.py"),
                            "--plugins-dir", self.plugins, "--shell-json", bad],
                           capture_output=True, text=True)
        self.assertEqual(p.returncode, 2)


class QmlHazards(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.plugins = os.path.join(self.tmp.name, "plugins")
        p = os.path.join(self.plugins, "risky.widget")
        write(os.path.join(p, "manifest.json"), manifest("risky.widget"))
        write(os.path.join(p, "W.qml"), "\n".join([
            "import qs.Commons",
            "Item {",
            "  color: Color.popups.background",
            "  property color ok: Commons.Color.popups.text",
            "  Rectangle { layer.enabled: true }",
            "  Text { color: root.bar.foreground; height: visible ? implicitHeight : 0 }",
            "  Component.onDestruction: root.unregister(this)",
            "  Component.onCompleted: Qt.callLater(function() { root.refresh() })",
            "  // layer.enabled: true in a comment is ignored",
            "}",
        ]))
        write(os.path.join(p, "test", "Harness.qml"), "Item { layer.enabled: true }")
        q = os.path.join(self.plugins, "clean.widget")
        write(os.path.join(q, "manifest.json"), manifest("clean.widget"))
        write(os.path.join(q, "W.qml"), "Item { color: Commons.Color.popups.background }")

    def tearDown(self):
        self.tmp.cleanup()

    def test_kinds_and_lines(self):
        hz = B.qml_hazards(self.plugins, {"risky.widget": "risky.widget", "clean.widget": "clean.widget"})
        self.assertEqual(sorted(hz), ["risky.widget"])
        self.assertEqual(hz["risky.widget"], {
            "bar-theme-ref": ["W.qml:6"],
            "color-subobject": ["W.qml:3"],
            "deferred-root": ["W.qml:7", "W.qml:8"],
            "height-loop": ["W.qml:6"],
            "layer-effect": ["W.qml:5"],
        })

    def test_only_active_plugins_scanned(self):
        self.assertEqual(B.qml_hazards(self.plugins, {"clean.widget": "clean.widget"}), {})


if __name__ == "__main__":
    unittest.main()
