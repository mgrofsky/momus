import json, os, sys, tempfile, unittest
sys.path.insert(0, os.path.dirname(__file__))
import settings


class TestSettings(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "policy.json")

    def write(self, text):
        with open(self.path, "w", encoding="utf-8") as f:
            f.write(text)

    def test_defaults_with_no_file(self):
        p = settings.load(self.path)
        self.assertEqual(p["sla_days"], {"Critical": 30, "High": 90, "Medium": 180, "Low": 180})
        self.assertEqual(p["strict_sla_days"], {"High": 30})
        self.assertEqual(p["strict_sla_hosts_file"], "strict_sla_hosts.txt")
        self.assertEqual(p["noise_tags"], ["tech", "fingerprint", "detect"])
        self.assertEqual(p["noise_ids"], [
            "tech-detect", "ssl-dns-names", "ssl-issuer", "waf-detect", "favicon-detect", "fingerprinthub-web-fingerprints",
            "caa-fingerprint", "mx-fingerprint", "nameserver-fingerprint", "txt-fingerprint", "dns-saas-service-detection",
            "http-trace", "robots-txt-endpoint", "options-method", "tls-version", "spf-record-detect",
            "dmarc-detect", "dnssec-detection", "mx-service-detector", "wildcard-tls", "aws-detect", "azure-domain-tenant",
            "dns-internal-ip-disclosure", "dns-rebinding", "aaaa-fingerprint", "ec2-detection", "srv-service-detect",
            "dkim-record-detect", "wildcard-dns-detect"])
        self.assertEqual(set(p), {"sla_days", "strict_sla_days", "strict_sla_hosts_file", "noise_tags", "noise_ids"})
        p["sla_days"]["High"] = 1                      # a caller's change never leaks into the defaults
        self.assertEqual(settings.load(self.path)["sla_days"]["High"], 90)

    def test_override_file(self):
        self.write(json.dumps({"sla_days": {"Medium": 120}, "strict_sla_days": {"Critical": 14, "High": 14},
                               "strict_sla_hosts_file": "cde_hosts.txt", "noise_tags": ["tech"], "noise_ids": ["only-this"]}))
        p = settings.load(self.path)
        self.assertEqual(p["sla_days"], {"Critical": 30, "High": 90, "Medium": 120, "Low": 180})   # other bands keep defaults
        self.assertEqual(p["strict_sla_days"], {"Critical": 14, "High": 14})
        self.assertEqual(p["strict_sla_hosts_file"], "cde_hosts.txt")
        self.assertEqual((p["noise_tags"], p["noise_ids"]), (["tech"], ["only-this"]))

    def test_sla_days_bounds(self):
        for key in ("sla_days", "strict_sla_days"):
            for days in (1, 3650):
                with self.subTest(key=key, days=days):
                    self.write(json.dumps({key: {"High": days}}))
                    self.assertEqual(settings.load(self.path)[key]["High"], days)
            for days in (0, -1, 3651, 10 ** 6):
                with self.subTest(key=key, days=days):
                    self.write(json.dumps({key: {"High": days}}))
                    with self.assertRaises(settings.PolicyError) as cm:
                        settings.load(self.path)
                    self.assertIn(f"{key}.High must be a whole number of days from 1 to 3650", str(cm.exception))

    def test_malformed_file_fails_with_a_clear_error(self):
        cases = {
            "{not json": "not valid JSON",
            "[1, 2]": "top level must be a JSON object",
            '{"sla_dayz": {}}': "unknown key 'sla_dayz'",
            '{"sla_days": {"Urgent": 5}}': "unknown band 'Urgent'",
            '{"sla_days": {"High": "30"}}': "sla_days.High must be a whole number",
            '{"strict_sla_days": {"High": 0}}': "strict_sla_days.High must be a whole number",
            '{"noise_tags": "tech"}': "noise_tags must be a list",
            '{"strict_sla_hosts_file": "../etc/hosts"}': "strict_sla_hosts_file must be a plain file name",
        }
        for text, message in cases.items():
            with self.subTest(text=text):
                self.write(text)
                with self.assertRaises(settings.PolicyError) as cm:
                    settings.load(self.path)
                self.assertIn(message, str(cm.exception))
                self.assertIn(self.path, str(cm.exception))


if __name__ == "__main__":
    unittest.main()
