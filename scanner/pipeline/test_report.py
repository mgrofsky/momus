"""report.py policy text: the SLA numbers and the strict-host wording come from the policy in effect."""
import json, os, sys, tempfile, unittest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import report as RP  # noqa: E402
import settings  # noqa: E402


class TestPolicyText(unittest.TestCase):
    def load(self, override=None):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "policy.json")
            if override is not None:
                with open(p, "w", encoding="utf-8") as f:
                    json.dump(override, f)
            return settings.load(p)

    def test_defaults(self):
        pol = self.load()
        self.assertEqual(RP.sla_text(pol), "Critical 30d, High 30d on a strict-SLA host or 90d elsewhere, Medium 180d, Low 180d")
        self.assertEqual(RP.strict_hosts_text(pol),
                         "Hosts in scope/strict_sla_hosts.txt get the strict-SLA allowance and a higher impact floor: "
                         "a readable credential or personal data scores impact 5 there (4 elsewhere).")

    def test_override_changes_the_rendered_numbers(self):
        pol = self.load({"sla_days": {"Critical": 7, "Medium": 120}, "strict_sla_days": {"Critical": 3, "High": 14},
                         "strict_sla_hosts_file": "cde_hosts.txt"})
        self.assertEqual(RP.sla_text(pol), "Critical 3d on a strict-SLA host or 7d elsewhere, High 14d on a strict-SLA host or 90d elsewhere, "
                                           "Medium 120d, Low 180d")
        self.assertIn("scope/cde_hosts.txt", RP.strict_hosts_text(pol))

    def test_override_changes_the_rendered_report(self):
        import contextlib, io, shutil
        from unittest import mock
        import test_ingest as TI
        e2e = TI.TestFixedEndToEnd("test_no_coverage_data_keeps_old_rule")
        e2e.setUp()
        self.addCleanup(e2e.tearDown)
        e2e.make_run("2030-01-01", e2e.FINDINGS)
        e2e.ingest("2030-01-01")
        pol = os.path.join(e2e.root, "policy.json")
        with open(pol, "w", encoding="utf-8") as f:
            json.dump({"sla_days": {"Medium": 120}, "strict_sla_days": {"High": 14}, "strict_sla_hosts_file": "cde_hosts.txt"}, f)
        argv = sys.argv
        sys.argv = ["report.py", "--root", e2e.root, "--run-id", "2030-01-01"]
        try:
            with mock.patch.object(settings, "POLICY_FILE", pol), contextlib.redirect_stdout(io.StringIO()):
                RP.main()
        finally:
            sys.argv = argv
        with open(os.path.join(e2e.root, "reports", "2030-01-01.html"), encoding="utf-8") as f:
            page = f.read()
        want = "Critical 30d, High 14d on a strict-SLA host or 90d elsewhere, Medium 120d, Low 180d"
        self.assertEqual(page.count(want), 2)            # due-date note and methodology
        self.assertIn("<code>scope/cde_hosts.txt</code>", page)
        self.assertIn("Hosts in scope/cde_hosts.txt get the strict-SLA allowance and a higher impact floor", page)
        self.assertNotIn("High 30d on a strict-SLA host", page)

class TestOutputSafety(unittest.TestCase):
    """Spreadsheet formula injection and HTML context escaping."""
    def test_csv_cell(self):
        for v in ("=HYPERLINK(\"x\")", "+1+1", "-2+3", "@SUM(A1)", "\tx", "\rx"):
            self.assertEqual(RP.csv_cell(v), "'" + v)
        for v in ("plain", "a=b", -5, 3.5, None, ""):
            self.assertEqual(RP.csv_cell(v), v)
        import io as _io
        buf = _io.StringIO()
        RP.SafeWriter(buf).writerow(["=cmd|' /C calc'!A0", -1, "ok"])
        self.assertEqual(buf.getvalue(), "'=cmd|' /C calc'!A0,-1,ok\r\n")

    def test_links_and_escaping(self):
        self.assertIsNone(RP.safe_href("javascript:alert(1)"))
        self.assertIsNone(RP.safe_href("data:text/html,x"))
        self.assertIsNone(RP.safe_href("//evil.example/x"))
        self.assertEqual(RP.safe_href("https://a.example/?q='x'"), "https://a.example/?q=&#x27;x&#x27;")
        self.assertEqual(RP.esc("</script><b x='1'>"), "&lt;/script&gt;&lt;b x=&#x27;1&#x27;&gt;")
        self.assertEqual(RP.cve_link("CVE-2099-0001'><x"), "CVE-2099-0001&#x27;&gt;&lt;x")
        self.assertIn("href='https://nvd.nist.gov/vuln/detail/CVE-2099-0001'", RP.cve_link("CVE-2099-0001"))

if __name__ == "__main__":
    unittest.main()
