"""retention.py: only old run directories go, never the latest full run, a recheck's base, a link or anything outside runs/."""
import contextlib, datetime as dt, io, json, os, shutil, sys, tempfile, time, unittest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import retention as RT  # noqa: E402

NOW = dt.datetime.now(dt.timezone.utc)


def ago(days):
    return (NOW - dt.timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


class TestRetention(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.outside = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root, True)
        self.addCleanup(shutil.rmtree, self.outside, True)
        self.runs = os.path.join(self.root, "runs")
        os.makedirs(self.runs)
        self.mkrun("full-a", 90, {})
        self.mkrun("full-b", 60, {})                                     # the most recent full run, though old
        self.mkrun("recheck-r", 45, {"recheck": True, "base_run": "full-a"})
        self.mkrun("inv-i", 40, {"inventory_only": True})
        self.mkrun("recheck-s", 2, {"recheck": True, "base_run": "full-b"})
        self.mkrun("fresh-f", 1, {"inventory_only": True})
        os.makedirs(os.path.join(self.runs, "nomanifest"))             # a failed run: age from its own mtime
        old = time.time() - 50 * 86400
        os.utime(os.path.join(self.runs, "nomanifest"), (old, old))
        with open(os.path.join(self.outside, "keepme.txt"), "w") as f:
            f.write("outside the runs directory\n")
        os.utime(self.outside, (old, old))
        os.symlink(self.outside, os.path.join(self.runs, "linked"))  # never followed, never deleted
        with open(os.path.join(self.runs, "stray.txt"), "w") as f:
            f.write("x\n")

    def mkrun(self, name, days, extra):
        d = os.path.join(self.runs, name)
        os.makedirs(d)
        with open(os.path.join(d, "manifest.json"), "w") as f:
            json.dump({"run_id": name, "started": ago(days), "finished": ago(days), **extra}, f)
        with open(os.path.join(d, "nuclei_owned.jsonl"), "w") as f:
            f.write("{}\n")

    def main(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = RT.main(["--root", self.root, *args])
        return rc, out.getvalue(), err.getvalue()

    def present(self):
        return sorted(os.listdir(self.runs))

    def test_plan(self):
        delete, keep = RT.plan(self.root, 30)
        self.assertEqual(sorted(n for n, _, _ in delete), ["inv-i", "nomanifest", "recheck-r"])
        self.assertEqual(dict(keep), {"full-a": "base of recheck recheck-r", "full-b": "most recent full run",
                                      "linked": "symbolic link, not followed"})

    def test_dry_run_changes_nothing(self):
        before = self.present()
        rc, out, err = self.main()
        self.assertEqual((rc, err), (0, ""))
        self.assertEqual(self.present(), before)
        self.assertIn("would delete runs/recheck-r (recheck run, 45 days old)", out)
        self.assertIn("rerun with --apply", out)

    def test_apply_deletes_only_the_planned_runs(self):
        rc, out, err = self.main("--apply")
        self.assertEqual((rc, err), (0, ""))
        self.assertEqual(self.present(), ["fresh-f", "full-a", "full-b", "linked", "recheck-s", "stray.txt"])
        self.assertTrue(os.path.exists(os.path.join(self.outside, "keepme.txt")))
        self.assertIn("deleted runs/inv-i (inventory run, 40 days old)", out)

    def test_newest_run_without_manifest_is_kept(self):
        d = os.path.join(self.runs, "zz-newest")
        os.makedirs(d)
        with open(os.path.join(d, "manifest.json"), "w") as f:
            f.write("{not json")
        when = time.time() - 40 * 86400
        os.utime(d, (when, when))
        for name in os.listdir(self.runs):        # every other run is older still
            p = os.path.join(self.runs, name)
            if name != "zz-newest" and not os.path.islink(p) and os.path.isdir(p):
                old = time.time() - 120 * 86400
                with open(os.path.join(p, "manifest.json")) if os.path.exists(os.path.join(p, "manifest.json")) else open(os.devnull) as fh:
                    m = json.loads(fh.read() or "{}")
                if m:
                    m["started"] = m["finished"] = ago(120)
                    with open(os.path.join(p, "manifest.json"), "w") as fh:
                        json.dump(m, fh)
                os.utime(p, (old, old))
        delete, keep = RT.plan(self.root, 30)
        self.assertEqual(dict(keep)["zz-newest"], "newest run, manifest missing or unreadable")
        self.assertNotIn("zz-newest", [n for n, _, _ in delete])

    def test_days(self):
        delete, _ = RT.plan(self.root, 100)
        self.assertEqual(delete, [])
        rc, _, err = self.main("--days", "0")
        self.assertEqual(rc, 2)
        self.assertIn("1 or more", err)

    def test_runs_directory_that_is_a_link_is_refused(self):
        other = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, other, True)
        os.symlink(self.runs, os.path.join(other, "runs"))
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = RT.main(["--root", other, "--apply"])
        self.assertEqual(rc, 2)
        self.assertIn("symbolic link", err.getvalue())
        self.assertIn("full-a", self.present())

    def test_no_root(self):
        env = os.environ.pop("SCAN_ROOT", None)
        try:
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                self.assertEqual(RT.main([]), 2)
        finally:
            if env is not None:
                os.environ["SCAN_ROOT"] = env


if __name__ == "__main__":
    unittest.main()
