"""Unit tests for seed_input.py: the scanner's reader of the seeder's host list (untrusted input). No network.
Also checks that no seeding code or cloud SDK is left anywhere the host-run suite can import."""
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import seed_input as SI  # noqa: E402
import scope as S  # noqa: E402
from test_scope import Base  # noqa: E402

SCANNER = os.path.dirname(HERE)


def write(path, data, mode="w"):
    with open(path, mode) as fh:
        fh.write(data)


HOSTILE = [
    "www.example.test",                       # kept, passes the gate
    "old.legacy.example.test",                # kept by the reader, refused by the gate (excluded suffix)
    "skip.example.test",                      # kept by the reader, refused by the gate (excluded name)
    "www.outside.test",                       # kept by the reader, refused by the gate (outside the scope)
    "x$(id).example.test", "a;rm -rf /.example.test", "`id`.example.test", "a|b.example.test", "a b.example.test",
    "--help", "-oX.example.test", "192.0.2.7", "2001:db8::7", "9.9.9.9", "http://www.example.test/", "WWW.EXAMPLE.TEST",
    "www.example.test.", "*.example.test", "_dmarc.example.test", "café.example.test", "www.example.test\r",
]


class ReaderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = os.path.join(self.tmp.name, "seed")
        os.makedirs(self.dir)
        self.file = os.path.join(self.dir, SI.FILE)

    def tearDown(self):
        self.tmp.cleanup()

    def test_only_host_name_lines_are_kept(self):
        write(self.file, "\n".join(HOSTILE).encode("utf-8") + b"\n\xff\xfe.example.test\n", "wb")
        names, rec = SI.read_seed(self.dir)
        self.assertEqual(names, ["www.example.test", "old.legacy.example.test", "skip.example.test", "www.outside.test"])
        self.assertEqual(rec["status"], "read")
        self.assertEqual(rec["kept"], 4)
        self.assertEqual(rec["dropped"], len(HOSTILE) - 4 + 1)

    def test_missing_folder_or_file_is_absent(self):
        names, rec = SI.read_seed(self.dir)
        self.assertEqual((names, rec["status"]), ([], "absent"))
        names, rec = SI.read_seed(os.path.join(self.tmp.name, "nope"))
        self.assertEqual((names, rec["status"]), ([], "absent"))

    def test_symlinked_file_and_folder_are_skipped(self):
        target = os.path.join(self.tmp.name, "elsewhere.txt")
        write(target, "www.example.test\n")
        os.symlink(target, self.file)
        names, rec = SI.read_seed(self.dir)
        self.assertEqual((names, rec["status"]), ([], "skipped"))
        self.assertEqual(rec["reason"], "the seed file is a symlink or unreadable")
        real = os.path.join(self.tmp.name, "real")
        os.makedirs(real)
        write(os.path.join(real, SI.FILE), "www.example.test\n")
        link = os.path.join(self.tmp.name, "linked")
        os.symlink(real, link)
        names, rec = SI.read_seed(link)
        self.assertEqual((names, rec["status"]), ([], "skipped"))

    def test_not_a_regular_file(self):
        os.makedirs(self.file)
        names, rec = SI.read_seed(self.dir)
        self.assertEqual((names, rec["status"]), ([], "skipped"))

    def test_over_size_and_over_line_count_skip_the_whole_file(self):
        write(self.file, "www.example.test\n" * 10)
        names, rec = SI.read_seed(self.dir, max_bytes=100)
        self.assertEqual((names, rec["reason"]), ([], "the seed file is over the size limit"))
        names, rec = SI.read_seed(self.dir, max_lines=9)
        self.assertEqual((names, rec["reason"]), ([], "the seed file is over the line limit"))
        names, rec = SI.read_seed(self.dir, max_lines=10)
        self.assertEqual(names, ["www.example.test"])

    def test_limits_cover_what_the_seeder_may_write(self):
        self.assertGreaterEqual(SI.MAX_LINES, 50000)
        self.assertGreaterEqual(SI.MAX_BYTES, 50000 * 254)

    def test_cli_writes_list_and_record_and_prints_no_file_content(self):
        write(self.file, "www.example.test\nsecret-marker-in-a-bad-line here\n")
        out, record = os.path.join(self.tmp.name, "sub_seed.txt"), os.path.join(self.tmp.name, "seed_read.json")
        p = subprocess.run([sys.executable, "-I", "-B", os.path.join(HERE, "seed_input.py"), "--seed-dir", self.dir,
                            "--out", out, "--record", record], capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 0)
        self.assertNotIn("secret-marker", p.stdout + p.stderr)
        with open(out) as fh:
            self.assertEqual(fh.read(), "www.example.test\n")
        with open(record) as fh:
            self.assertEqual(json.load(fh), {"status": "read", "reason": None, "lines": 2, "kept": 1, "dropped": 1})


class SeedThroughTheGate(Base):
    """A seed name under an excluded suffix, outside the scope, or an address never passes the name gate."""

    def test_gate_drops_excluded_and_out_of_scope_seed_names(self):
        d = os.path.join(self.root, "seed")
        os.makedirs(d)
        write(os.path.join(d, SI.FILE), "\n".join(HOSTILE) + "\n")
        names, _ = SI.read_seed(d)
        keep, _ = S.filter_items(self.scope(), names, "names", "enumerate")
        self.assertEqual(keep, ["www.example.test"])


class NoSeedingCodeInTheScanner(unittest.TestCase):
    def test_nothing_under_scanner_imports_a_cloud_sdk_or_the_seeding_code(self):
        bad = re.compile(r"^\s*(?:import|from)\s+(?:boto3|botocore|seed_dns)\b", re.M)
        for top, _dirs, files in os.walk(SCANNER):
            for fn in files:
                if fn.endswith((".py", ".sh")):
                    with open(os.path.join(top, fn), errors="ignore") as fh:
                        self.assertIsNone(bad.search(fh.read()), os.path.join(top, fn))
        self.assertFalse(os.path.exists(os.path.join(HERE, "seed_dns.py")))
        self.assertFalse(os.path.exists(os.path.join(SCANNER, "config", "seed.env.example")))

    def test_recon_reads_the_seed_volume_not_the_scope_folder(self):
        with open(os.path.join(SCANNER, "recon.sh")) as fh:
            recon = fh.read()
        self.assertNotIn("$SCOPE/seed_hosts.txt", recon)
        self.assertIn('"$PIPE/seed_input.py" --seed-dir "$SEED_DIR"', recon)
        self.assertIn('"seed":seed,', recon)


if __name__ == "__main__":
    unittest.main()
