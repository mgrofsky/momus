import unittest, sys, os
sys.path.insert(0, os.path.dirname(__file__))
import scoring as S

class TestScoring(unittest.TestCase):
    def test_key_ignores_ip_and_case(self):
        a = S.finding_key("Www.Example.com", "nuclei", "tech-detect", 443)
        b = S.finding_key("www.example.com", "nuclei", "tech-detect", 443)
        self.assertEqual(a, b)
        self.assertNotEqual(a, S.finding_key("www.example.com", "nuclei", "tech-detect", 80))

    def test_impact_from_cvss_beats_severity(self):
        self.assertEqual(S.impact({"severity": "low", "cvss": 9.8}), 5)
        self.assertEqual(S.impact({"severity": "high", "cvss": 5.0}), 3)
        self.assertEqual(S.impact({"severity": "high"}), 4)
        self.assertEqual(S.impact({"severity": "info"}), 1)
        self.assertEqual(S.impact({"severity": "low", "tags": ["axfr"]}), 5)

    def test_kev_is_max_likelihood(self):
        f = {"severity": "medium", "cve_ids": ["CVE-2099-0007"], "asset_class": "third_party"}
        self.assertEqual(S.likelihood(f, {}, {"CVE-2099-0007"}), 5)

    def test_epss_bands(self):
        f = {"severity": "high", "cve_ids": ["CVE-1"], "asset_class": "owned"}
        self.assertEqual(S.likelihood(f, {"CVE-1": 0.9}), 4)
        self.assertEqual(S.likelihood(f, {"CVE-1": 0.2}), 3)
        self.assertEqual(S.likelihood(f, {"CVE-1": 0.01}), 2)
        self.assertEqual(S.likelihood(f, {}), 2)  # CVE with no EPSS record

    def test_exposure_owned_vs_third_party(self):
        self.assertEqual(S.likelihood({"severity": "high", "tags": ["takeover"], "asset_class": "owned"}), 4)
        self.assertEqual(S.likelihood({"severity": "high", "tags": ["takeover"], "asset_class": "third_party"}), 3)

    def test_info_is_one(self):
        self.assertEqual(S.likelihood({"severity": "info", "tags": ["tech"], "asset_class": "owned"}), 1)

    def test_score_bands(self):
        r = S.score({"severity": "critical", "cve_ids": ["CVE-X"], "asset_class": "owned"}, {}, {"CVE-X"})
        self.assertEqual((r["score"], r["band"], r["sla_days"]), (25, "Critical", 30))
        r = S.score({"severity": "medium", "tags": ["misconfig"], "asset_class": "owned"})
        self.assertEqual((r["score"], r["band"]), (9, "Medium"))
        r = S.score({"severity": "info", "tags": ["tech"], "asset_class": "third_party"})
        self.assertEqual((r["score"], r["band"]), (1, "Low"))

    def test_fix_by_days_follow_the_sla_policy(self):
        high = {"severity": "high", "tags": ["exposure"], "asset_class": "owned"}   # 4 x 4 = 16, High
        self.assertEqual(S.score(high)["sla_days"], 90)
        self.assertEqual(S.score(high, host="app1.alpha.example", pci_suffixes=["app1.alpha.example"])["sla_days"], 30)
        self.assertEqual(S.score(high, host="a.app1.alpha.example", pci_suffixes=["app1.alpha.example"])["sla_days"], 30)
        self.assertEqual(S.score(high, host="www.alpha.example", pci_suffixes=["app1.alpha.example"])["sla_days"], 90)
        self.assertEqual(S.sla_days("Medium"), 180)
        self.assertEqual(S.sla_days("Low"), 180)
        self.assertEqual(S.band(13), ("High", 90))

    def test_verdict_noise_drops_likelihood(self):
        listing = {"severity": "medium", "tags": ["config", "listing", "exposure"], "asset_class": "owned"}
        self.assertEqual(S.score(listing)["band"], "High")   # 3 x 4 = 12 by name alone
        for v in ("names_only", "empty", "redirect", "gone"):
            self.assertEqual(S.likelihood(listing, verdict=v), 1)
            self.assertEqual(S.score(listing, verdict=v)["band"], "Low")
        for v in ("confirmed", "unverified", None):
            self.assertEqual(S.likelihood(listing, verdict=v), 4)
            self.assertEqual(S.score(listing, verdict=v)["band"], "High")

    def test_verdict_does_not_touch_kev(self):
        f = {"severity": "high", "cve_ids": ["CVE-K"], "tags": ["exposure"], "asset_class": "owned"}
        self.assertEqual(S.likelihood(f, {}, {"CVE-K"}, verdict="confirmed"), 5)

    def test_exposure_credential_and_data(self):
        f = {"severity": "medium", "tags": ["config", "exposure"], "asset_class": "owned"}   # 3 x 4 = 12 High
        for e in ("credential", "data"):
            r = S.score(f, exposure=e)
            self.assertEqual((r["impact"], r["likelihood"], r["band"]), (4, 4, "High"))
            r = S.score(f, host="app2.bravo.example", pci_suffixes=["bravo.example"], exposure=e)
            self.assertEqual((r["impact"], r["score"], r["band"], r["sla_days"]), (5, 20, "Critical", 30))
        low = {"severity": "info", "tags": ["misc"], "asset_class": "owned"}             # 1 x 1
        self.assertEqual(S.score(low, exposure="credential")["band"], "High")

    def test_exposure_never_lowers(self):
        crit = {"severity": "critical", "cve_ids": ["CVE-K"], "asset_class": "owned"}
        for e in ("credential", "data", "source", "config", "internal", "names", "nothing", "unknown", None):
            r = S.score(crit, {}, {"CVE-K"}, exposure=e)
            self.assertEqual((r["impact"], r["likelihood"]), (5, 5))
        f = {"severity": "high", "tags": ["exposure"], "asset_class": "owned"}
        for e in ("config", "internal", "names", "unknown", None):
            self.assertEqual(S.score(f, verdict="confirmed", exposure=e)["score"], 16)
        self.assertEqual(S.score({"severity": "low", "tags": ["exposure"], "asset_class": "owned"}, exposure="source")["impact"], 3)

    def test_exposure_nothing_on_confirmed_drops(self):
        f = {"severity": "high", "tags": ["exposure"], "asset_class": "owned"}
        self.assertEqual(S.score(f, verdict="confirmed", exposure="nothing")["likelihood"], 1)
        self.assertEqual(S.score(f, verdict=None, exposure="nothing")["likelihood"], 4)   # e.g. a port that rejects the scanner

if __name__ == "__main__":
    unittest.main()
