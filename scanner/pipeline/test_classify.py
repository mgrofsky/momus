"""End-to-end checks for classify.py on a synthetic run directory. Names are invented. Addresses that must be
public are well-known public resolvers: RFC 5737/3849 documentation ranges are deliberately NOT used because
ipaddress treats them as non-global, which is exactly what the internal rule keys on."""
import json, os, pathlib, subprocess, sys, tempfile, unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
CLASSIFY = ROOT / "pipeline" / "classify.py"


def _write(p, text):
    p.write_text(text)


class ClassifyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = pathlib.Path(self.tmp.name)
        self.run, self.scope = t / "run", t / "scope"
        self.run.mkdir(); self.scope.mkdir()
        _write(self.run / "apexes.txt", "example.test\n")
        hosts = {
            "cgnat.example.test": {"a": ["100.79.0.5"]},                       # CGNAT only -> internal
            "rfc1918.example.test": {"a": ["10.1.2.3"]},                       # -> internal
            "dual.example.test": {"a": ["172.31.0.9"], "aaaa": ["2001:4860:4860::8888"]},  # private next to public -> internal
            "plain.example.test": {"a": ["8.8.8.8"]},                     # no owned range, no provider -> unverified
            "ok.example.test": {"a": ["8.8.4.4"]},                        # in approved_hosts.txt -> owned
            "edge.example.test": {"a": ["208.67.220.220"], "cname": ["x.shipped-cdn.test"]},  # shipped cdn list -> cdn_fronted
            "dropip.example.test": {"a": ["94.140.15.15"]},               # address in an excluded CIDR -> excluded
            "mail.example.test": {"a": ["208.67.222.222"]},                      # in third_party_ranges -> third_party
            "www.example.test": {"a": ["8.8.4.4"], "cname": ["cdn.webflow.test"]},  # suffix -> third_party
            "drop.example.test": {"a": ["9.9.9.9"]},                      # excluded
            "range.example.test": {"a": ["94.140.14.14"]},                        # owned_ranges -> owned
        }
        _write(self.run / "dns.jsonl", "".join(json.dumps({"host": h, **v}) + "\n" for h, v in hosts.items()))
        _write(self.run / "subdomains.txt", "".join(h + "\n" for h in hosts) + "gone.example.test\n")
        _write(self.run / "httpx.jsonl", "")
        _write(self.scope / "exclude.txt", "# never touch\ndrop.example.test   # inline comment\n94.140.15.0/24\n")
        _write(self.scope / "approved_hosts.txt", "ok.example.test\n")
        self.config = t / "config"; self.config.mkdir()
        _write(self.config / "cdn_cnames.txt", "shipped-cdn.test   # provider\n")
        _write(self.scope / "owned_ranges.txt", "94.140.14.0/24  # owned\n")
        _write(self.scope / "third_party_ranges.txt", "208.67.222.0/24   # some provider\n")
        _write(self.scope / "third_party_cnames.txt", "cdn.webflow.test\n")
        _write(self.scope / "cdn_cnames.txt", "")

    def tearDown(self):
        self.tmp.cleanup()

    def classes(self):
        r = subprocess.run([sys.executable, "-I", "-B", str(CLASSIFY), "--run-dir", str(self.run), "--scope", str(self.scope),
                            "--config", str(self.config)],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("bad CIDR", r.stderr)
        return {json.loads(l)["hostname"]: json.loads(l) for l in (self.run / "assets.jsonl").read_text().splitlines()}

    def test_classes(self):
        a = self.classes()
        self.assertEqual(a["cgnat.example.test"]["class"], "internal")
        self.assertEqual(a["rfc1918.example.test"]["class"], "internal")
        self.assertEqual(a["dual.example.test"]["class"], "internal")
        self.assertEqual(a["plain.example.test"]["class"], "unverified")
        self.assertEqual(a["ok.example.test"]["class"], "owned")
        self.assertEqual(a["edge.example.test"]["class"], "cdn_fronted")
        self.assertNotIn("dropip.example.test", a)
        self.assertEqual(a["range.example.test"]["reason"], "ip in owned_ranges")
        self.assertEqual(a["mail.example.test"]["class"], "third_party")
        self.assertIn("third_party_ranges", a["mail.example.test"]["reason"])
        self.assertEqual(a["www.example.test"]["class"], "third_party")
        self.assertEqual(a["gone.example.test"]["class"], "dead")
        self.assertNotIn("drop.example.test", a)

    def test_owned_ips_public_only(self):
        self.classes()
        ips = (self.run / "owned_ips.txt").read_text().split()
        self.assertEqual(sorted(ips), sorted(["94.140.14.14", "8.8.4.4"]))
        self.assertEqual((self.run / "unverified_hosts.txt").read_text().split(), ["plain.example.test"])
        tp = (self.run / "tp_hosts.txt").read_text().split()
        self.assertEqual(sorted(tp), ["mail.example.test", "www.example.test"])


if __name__ == "__main__":
    unittest.main()
