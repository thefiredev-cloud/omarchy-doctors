import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import qs_crash_digest as qd  # noqa: E402

FIXTURES = os.path.join(HERE, "fixtures")
ABORT = "abort_pure_virtual"
SEGV = "segv_dynamic_cast"


def read(name, fname):
    with open(os.path.join(FIXTURES, name, fname), errors="replace") as fh:
        return fh.read()


def snapshot(root):
    """Map of relative path to (size, mtime_ns) for every file under root."""
    out = {}
    for base, _, files in os.walk(root):
        for f in files:
            p = os.path.join(base, f)
            st = os.stat(p)
            out[os.path.relpath(p, root)] = (st.st_size, st.st_mtime_ns)
    return out


class Tree(unittest.TestCase):
    """Temp crashes dir: one abort run, one segv run, one loose abort report."""

    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)
        shutil.copytree(os.path.join(FIXTURES, ABORT), os.path.join(self.root, "runabort1"))
        shutil.copytree(os.path.join(FIXTURES, ABORT), os.path.join(self.root, "runabort2"))
        shutil.copytree(os.path.join(FIXTURES, SEGV), os.path.join(self.root, "runsegv1"))
        self.now = time.time()
        for name, age_h in (("runabort1", 1), ("runabort2", 2), ("runsegv1", 100)):
            t = self.now - age_h * 3600
            for f in ("report.txt", "log.qslog.log"):
                os.utime(os.path.join(self.root, name, f), (t, t))
        # stray directory without a report must be ignored
        os.makedirs(os.path.join(self.root, "empty"))


class ParseTests(unittest.TestCase):
    def test_abort_report(self):
        signal, pid, frames = qd.parse_report(read(ABORT, "report.txt"))
        self.assertEqual(signal, "Aborted (6)")
        self.assertEqual(pid, 728737)
        self.assertEqual(frames[3], ("abort", "libc.so.6"))
        self.assertEqual(frames[10][0], "QIOVectoredWriteOperation::~QIOVectoredWriteOperation()")

    def test_top_frame_skips_abort_plumbing(self):
        _, _, frames = qd.parse_report(read(ABORT, "report.txt"))
        self.assertEqual(qd.top_frame(frames), "QIOVectoredWriteOperation::~QIOVectoredWriteOperation")

    def test_top_frame_skips_dynamic_cast_and_unsymbolized_quickshell(self):
        _, _, frames = qd.parse_report(read(SEGV, "report.txt"))
        self.assertEqual(qd.top_frame(frames), "QQmlObjectCreator::finalize")

    def test_top_frame_falls_back_to_module(self):
        frames = [(None, "libc.so.6"), (None, "quickshell"), (None, "libfoo.so.1")]
        self.assertEqual(qd.top_frame(frames), "libfoo.so.1")

    def test_top_frame_unknown_when_only_plumbing(self):
        self.assertEqual(qd.top_frame([("abort", "libc.so.6"), (None, "quickshell")]), "unknown")

    def test_report_without_stacktrace(self):
        signal, pid, frames = qd.parse_report("Signal: Killed (9)\n")
        self.assertEqual((signal, pid, frames), ("Killed (9)", None, []))


class PluginTests(unittest.TestCase):
    def test_user_plugin_is_last(self):
        plugin, origin = qd.last_plugin(os.path.join(FIXTURES, ABORT, "log.qslog.log"))
        self.assertEqual((plugin, origin), ("ssupt.bluetooth-audio", "user"))

    def test_system_plugin_is_last(self):
        plugin, origin = qd.last_plugin(os.path.join(FIXTURES, SEGV, "log.qslog.log"))
        self.assertEqual((plugin, origin), ("bar", "system"))

    def test_missing_log(self):
        self.assertEqual(qd.last_plugin("/nonexistent/log.qslog.log"), (None, None))

    def test_only_tail_is_read(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "log.qslog.log")
            with open(p, "wb") as fh:
                fh.write(b'"/home/u/.config/omarchy/plugins/old.plugin/X.qml"')
                fh.write(b"x" * (qd.LOG_TAIL_BYTES + 10))
            self.assertEqual(qd.last_plugin(p), (None, None))


class DigestTests(Tree):
    def test_groups_and_counts(self):
        crashes = qd.load_crashes(self.root)
        self.assertEqual(len(crashes), 3)
        groups = qd.group(crashes)
        self.assertEqual(len(groups), 2)
        self.assertEqual(sum(g["count"] for g in groups), 3)
        top = groups[0]
        self.assertEqual(top["count"], 2)
        self.assertEqual(top["signal"], "Aborted (6)")
        self.assertEqual(top["plugin"], "ssupt.bluetooth-audio")
        self.assertEqual(sorted(top["runs"]), ["runabort1", "runabort2"])
        self.assertEqual(groups[1]["plugin"], "bar")

    def test_since_filters_by_report_mtime(self):
        crashes = qd.load_crashes(self.root, since_hours=3, now=self.now)
        self.assertEqual(sorted(c["run_id"] for c in crashes), ["runabort1", "runabort2"])
        crashes = qd.load_crashes(self.root, since_hours=1.5, now=self.now)
        self.assertEqual([c["run_id"] for c in crashes], ["runabort1"])

    def test_loose_report_is_counted(self):
        shutil.copy(os.path.join(FIXTURES, ABORT, "report.txt"), os.path.join(self.root, "report.txt"))
        shutil.copy(os.path.join(FIXTURES, ABORT, "log.qslog.log"), os.path.join(self.root, "log.qslog.log"))
        crashes = qd.load_crashes(self.root)
        self.assertEqual(len(crashes), 4)
        self.assertIn("(loose)", [c["run_id"] for c in crashes])

    def test_table_lists_every_report(self):
        text = qd.render_table(qd.group(qd.load_crashes(self.root)), 3)
        self.assertIn("QIOVectoredWriteOperation::~QIOVectoredWriteOperation", text)
        self.assertIn("bar (core)", text)
        self.assertTrue(text.endswith("3 reports in 2 groups"))

    def run_cli(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = qd.main(["--dir", self.root, *args])
        return rc, out.getvalue()

    def test_cli_json_parses_and_totals(self):
        rc, text = self.run_cli("--json")
        self.assertEqual(rc, 0)
        data = json.loads(text)
        self.assertEqual(data["total"], 3)
        self.assertEqual(sum(g["count"] for g in data["groups"]), 3)

    def test_cli_since_json(self):
        _, text = self.run_cli("--json", "--since", "3")
        self.assertEqual(json.loads(text)["total"], 2)

    def test_read_only(self):
        before = snapshot(self.root)
        self.run_cli()
        self.run_cli("--json")
        self.assertEqual(snapshot(self.root), before)


if __name__ == "__main__":
    unittest.main()
