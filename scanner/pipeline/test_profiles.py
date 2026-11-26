"""Check and rate profiles: recon.sh --print-config resolves the tables at the top of recon.sh into tool arguments."""
import json, os, pathlib, subprocess, tempfile, unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
RECON = ROOT / "recon.sh"
SEVEN = {"default-login", "sqli", "rce", "lfi", "ssrf", "xss", "injection"}
# the numbers recon.sh used before profiles existed ("normal" must equal them)
TODAY = {"DNSX_THREADS": 50, "DNSX_RETRY": 3, "HTTPX_RL": 200, "HTTPX_THREADS": 80, "HTTPX_TIMEOUT": 8, "HTTPX_RETRIES": 1,
         "NMAP_CHUNK": 64, "NMAP_MAX_RATE": 200, "NMAP_PARALLELISM": 32, "NMAP_PAUSE": 5, "NMAP_RETRIES": 2,
         "NMAP_HOST_TIMEOUT": "10m", "SSLSCAN_PARALLEL": 16, "SSLSCAN_CONNECT_TIMEOUT": 10,
         "NUC_GENERIC_RL": 300, "NUC_GENERIC_C": 50, "NUC_GENERIC_BS": 50, "NUC_TECH_RL": 150, "NUC_TECH_C": 25, "NUC_TECH_BS": 25,
         "NUC_TP_RL": 100, "NUC_TP_C": 20, "NUC_TP_BS": 20, "NUC_DNS_RL": 150, "NUC_DNS_C": 30,
         "NUC_FP_RL": 150, "NUC_FP_C": 30, "NUC_FP_BS": 30, "NUC_TIMEOUT": 8, "NUC_DNS_TIMEOUT": 5, "NUC_RETRIES": 1, "DIG_TIME": 5,
         "WHATWEB_THREADS": 25, "WHATWEB_OPEN_TIMEOUT": 15, "WHATWEB_READ_TIMEOUT": 30}
SAME_IN_EVERY_PROFILE = {"DNSX_RETRY", "HTTPX_TIMEOUT", "HTTPX_RETRIES", "NMAP_RETRIES", "NMAP_HOST_TIMEOUT", "SSLSCAN_CONNECT_TIMEOUT",
                         "NUC_TIMEOUT", "NUC_DNS_TIMEOUT", "NUC_RETRIES", "DIG_TIME", "WHATWEB_OPEN_TIMEOUT", "WHATWEB_READ_TIMEOUT"}


class Profiles(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        (pathlib.Path(self.tmp.name) / "scope").mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def config(self, env=None, profile=None, ok=True):
        if profile is not None:
            (pathlib.Path(self.tmp.name) / "scope" / "profile.json").write_text(json.dumps(profile))
        e = {k: v for k, v in os.environ.items() if not k.startswith("SCAN_")}
        e.update({"SCAN_ROOT": self.tmp.name, **(env or {})})
        r = subprocess.run(["bash", str(RECON), "--print-config"], capture_output=True, text=True, env=e)
        if not ok:
            self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
            return None
        self.assertEqual(r.returncode, 0, r.stderr)
        return dict(l.split("=", 1) for l in r.stdout.splitlines() if "=" in l)

    def test_evidence_level(self):
        # SCAN_EVIDENCE is validated with the profiles; the manifest records it (shim test)
        self.assertEqual(self.config()["EVIDENCE_LEVEL"], "minimal")
        self.assertEqual(self.config({"SCAN_EVIDENCE": "excerpt"})["EVIDENCE_LEVEL"], "excerpt")
        self.config({"SCAN_EVIDENCE": "everything"}, ok=False)

    def test_defaults_are_safe_and_low(self):
        c = self.config()
        self.assertEqual((c["CHECK_PROFILE"], c["RATE_PROFILE"]), ("safe", "low"))
        self.assertEqual(set(c["PROFILE_ETAGS"].split(",")), SEVEN)
        self.assertFalse(set(c["NUC_GENERIC_TAGS"].split(",")) & SEVEN)

    def test_active_from_env_and_from_profile_json(self):
        c = self.config({"SCAN_CHECK_PROFILE": "active"})
        self.assertEqual(c["PROFILE_ETAGS"], "")
        self.assertLessEqual(SEVEN, set(c["NUC_GENERIC_TAGS"].split(",")))
        c = self.config({"SCAN_CHECK_PROFILE": "safe", "SCAN_RATE_PROFILE": "fast"}, profile={"check_profile": "active"})
        self.assertEqual((c["CHECK_PROFILE"], c["RATE_PROFILE"], c["PROFILE_SOURCE"]), ("active", "fast", "scope/profile.json"))
        c = self.config(profile={"rate_profile": "normal"})
        self.assertEqual((c["CHECK_PROFILE"], c["RATE_PROFILE"]), ("safe", "normal"))

    def test_invalid_profiles_refused(self):
        self.config({"SCAN_CHECK_PROFILE": "aggressive"}, ok=False)
        self.config({"SCAN_RATE_PROFILE": "turbo"}, ok=False)
        self.config(profile={"check_profile": "active", "extra": 1}, ok=False)

    def test_rate_table(self):
        low, normal, fast = (self.config({"SCAN_RATE_PROFILE": p}) for p in ("low", "normal", "fast"))
        for k, v in TODAY.items():
            self.assertEqual(normal[k], str(v), k)
            if k == "NMAP_PAUSE":   # a pause, not a rate: low waits three times as long, fast keeps today's pause
                self.assertEqual((low[k], fast[k]), (str(v * 3), str(v)))
                continue
            if k in SAME_IN_EVERY_PROFILE:
                self.assertEqual((low[k], fast[k]), (str(v), str(v)), k)
                continue
            self.assertTrue(0.25 <= int(low[k]) / v <= 0.4, (k, low[k]))          # about a third
            self.assertEqual(int(fast[k]), int(v * 1.5), k)
        self.assertEqual(int(fast["NMAP_MAX_RATE"]), 300)

    def test_excluded_tags_file_holds_none_of_the_seven(self):
        tags = {l.strip() for l in (ROOT / "config" / "exclude_tags.txt").read_text().splitlines() if l.strip() and not l.startswith("#")}
        self.assertTrue(tags)
        self.assertFalse(tags & SEVEN)


if __name__ == "__main__":
    unittest.main()
