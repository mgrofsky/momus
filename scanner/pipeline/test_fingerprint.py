import datetime as dt, os, subprocess, sys, tempfile, unittest
from unittest import mock
sys.path.insert(0, os.path.dirname(__file__))
import fingerprint as F

# Evidence shaped like real scan output. Hostnames, addresses and the AS number are synthetic.
OWN = (("example-colo", "Example colo"),)   # stands in for an entry in config/own_networks.txt
APACHE_PHP = {
    "endpoints": [{"url": "https://site.alpha.example:443", "status": 200, "title": "Index of /",
                   "server": "Apache/2.2.34 (Unix) mod_ssl/2.2.34 OpenSSL/1.0.2k PHP/5.4.45",
                   "tech": ["Apache HTTP Server:2.2.34", "OpenSSL:1.0.2k", "PHP:5.4.45", "UNIX", "mod_ssl:2.2.34"],
                   "cdn": False, "cdn_name": None, "cdn_type": None,
                   "tls": {"subject_cn": "site.alpha.example", "issuer_cn": "Sectigo Example DV Issuing CA 7",
                           "not_after": "2030-08-16T21:05:47Z", "tls_version": "tls12", "cipher": "x"}}],
    "whatweb": {"Apache": {"string": [], "version": ["2.2.34"]}, "PHP": {"string": [], "version": ["5.4.45"]},
                "OpenSSL": {"string": [], "version": ["1.0.2k"]}, "Index-Of": {"string": [], "version": []},
                "HTTPServer": {"string": ["Apache/2.2.34 (Unix) mod_ssl/2.2.34 OpenSSL/1.0.2k PHP/5.4.45"], "version": []},
                "IP": {"string": ["198.51.100.39"], "version": []}, "Country": {"string": ["UNITED STATES"], "version": []},
                "Via-Proxy": {"string": ["1.1 gw3.alpha.example"], "version": []}, "UNIX": {"string": [], "version": []}},
    "waf": None, "nuclei": [{"template": "aaaa-fingerprint", "name": "AAAA", "extracted": ["2001:db8:4:2::17"], "matcher": None}],
    "nmap": [{"port": 22, "service": "ssh", "product": "", "scripts": {"banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"}}],
    "sslscan": {"protocols": ["ssl3", "tls1.2"], "issuer": None},
    "cnames": [], "ips": ["198.51.100.39"], "asn": {"asn": "64500", "as_name": "EXAMPLE-COLO-TRANSIT Example Colo Hosting, US"},
}

CLOUDFRONT = {
    "endpoints": [{"url": "https://app.delta.example:443", "status": 301, "server": "CloudFront",
                   "tech": ["Amazon CloudFront", "Amazon S3", "Amazon Web Services"], "cdn": True, "cdn_name": "cloudfront", "cdn_type": "cdn",
                   "tls": {"issuer_cn": "Amazon RSA 2048 M02", "issuer_org": ["Amazon"], "not_after": "2030-03-01T23:59:59Z", "tls_version": "tls13"}}],
    "whatweb": {"Amazon-CloudFront": {"string": [], "version": []}, "HTTPServer": {"string": ["CloudFront"], "version": []}},
    "waf": "Cloudfront",
    "nuclei": [{"template": "dns-saas-service-detection", "name": "SaaS", "extracted": None, "matcher": "amazon-cloudfront"}],
    "cnames": ["d111111abcdef8.cloudfront.net"], "ips": ["203.0.113.221"], "asn": {"asn": "16509", "as_name": "AMAZON-02 - Amazon.com, Inc., US"},
    "owned_aws": ["d111111abcdef8.cloudfront.net"],
}

EOL_FIXTURE = {
    "php": [{"cycle": "8.4", "eol": "2028-12-31"}, {"cycle": "7.3", "eol": "2021-12-06"}, {"cycle": "5.6", "eol": "2018-12-31"}, {"cycle": "5.4", "eol": "2015-09-14"}],
    "apache": [{"cycle": "2.4", "eol": False}, {"cycle": "2.2", "eol": "2017-07-11"}],
    "openssl": [{"cycle": "3.0", "eol": "2026-09-07"}, {"cycle": "1.1.1", "eol": "2023-09-11"}, {"cycle": "1.0.2", "eol": "2019-12-31"}, {"cycle": "1.0.1", "eol": "2016-12-31"}],
    "debian": [{"cycle": "12", "eol": "2026-06-10"}, {"cycle": "11", "eol": "2024-08-14"}],
    "jquery": [{"cycle": "3", "eol": False}, {"cycle": "2", "eol": True}, {"cycle": "1", "eol": True}],
}
DAY = dt.date(2027, 1, 1)   # reference date between the public EOL dates above


def by(comps, category):
    return {(c["name"], c["version"]) for c in comps if c["category"] == category}


class TestNormalize(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(F, "OWN_NETWORKS", OWN)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_apache_php_stack_with_versions_and_os_from_banner(self):
        comps = F.normalize(APACHE_PHP)
        self.assertEqual(by(comps, "web_server"), {("Apache", "2.2.34")})
        self.assertEqual(by(comps, "language"), {("PHP", "5.4.45")})
        self.assertEqual(by(comps, "service"), {("OpenSSL", "1.0.2k"), ("mod_ssl", "2.2.34"), ("OpenSSH", "8.9p1")})
        self.assertEqual(by(comps, "os"), {("Unix", None), ("Ubuntu", None)})
        self.assertEqual(by(comps, "tls"), {("TLS 1.2", None), ("SSL 3.0", None), ("Issuer: Sectigo", None)})
        self.assertEqual(by(comps, "hosting"), {("Example colo", None)})

    def test_junk_is_dropped(self):
        names = {c["name"] for c in F.normalize(APACHE_PHP)}
        for junk in ("198.51.100.39", "2001:db8:4:2::17", "gw3.alpha.example", "Index-Of", "IP", "Country", "Via-Proxy", "UNITED STATES"):
            self.assertNotIn(junk, names)

    def test_sources_merge_per_component(self):
        comps = F.normalize(APACHE_PHP)
        php = next(c for c in comps if c["name"] == "PHP")
        self.assertEqual(set(php["source"].split("+")), {"httpx", "whatweb"})

    def test_cloudfront_edge(self):
        comps = F.normalize(CLOUDFRONT)
        self.assertEqual(by(comps, "cdn"), {("CloudFront", None)})
        self.assertEqual(by(comps, "waf"), set())                   # wafw00f calling CloudFront a WAF stays a CDN
        self.assertIn(("Amazon S3", None), by(comps, "hosting"))
        self.assertIn(("Issuer: Amazon", None), by(comps, "tls"))
        self.assertIn(("TLS 1.3", None), by(comps, "tls"))

    def test_catalog_names_are_not_split_on_slash_or_space(self):
        comps = F.normalize({"endpoints": [{"tech": ["HTTP/3", "Fly.io"], "server": "Google Frontend"}]})
        self.assertEqual({(c["name"], c["version"]) for c in comps}, {("HTTP/3", None), ("Fly.io", None), ("Google Frontend", None)})

    def test_server_header_parser(self):
        got = {(n, v) for n, v, _ in F.parse_server_header("nginx/1.18.0 (Ubuntu)")}
        self.assertEqual(got, {("nginx", "1.18.0"), ("Ubuntu", None)})
        got = {(n, v) for n, v, _ in F.parse_server_header("Microsoft-IIS/10.0")}
        self.assertEqual(got, {("IIS", "10.0")})
        self.assertEqual(F.parse_server_header("awselb/2.0")[0][:2], ("Amazon ELB", "2.0"))

    def test_unknown_names_land_in_other(self):
        comps = F.normalize({"endpoints": [{"tech": ["Frobnicator Deluxe", "Frobnicator:9.1"]}]})
        self.assertEqual([(c["category"], c["name"], c["version"]) for c in comps], [("other", "Frobnicator", "9.1"), ("other", "Frobnicator Deluxe", None)])


class TestHostingAndProfile(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(F, "OWN_NETWORKS", OWN)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_hosting_prefers_our_aws_inventory_then_cname_then_edge_then_asn(self):
        self.assertEqual(F.hosting(CLOUDFRONT), ("AWS CloudFront (an account in scope)", "owned_aws"))
        ev = dict(CLOUDFRONT, owned_aws=[])
        self.assertEqual(F.hosting(ev), ("AWS CloudFront", "cname"))
        ev = dict(ev, cnames=[])
        self.assertEqual(F.hosting(ev), ("AWS CloudFront", "httpx"))
        ev = dict(ev, endpoints=[{}])
        self.assertEqual(F.hosting(ev), ("AWS", "asn"))
        self.assertEqual(F.hosting(APACHE_PHP), ("Example colo", "asn"))
        self.assertEqual(F.hosting({"cnames": ["x.herokuapp.com"]}), ("Heroku", "cname"))
        self.assertEqual(F.hosting({"cnames": ["x.somevendor.example"], "third_party_suffixes": ["somevendor.example"]}), ("Somevendor", "cname"))

    def test_profile_row(self):
        comps = F.normalize(APACHE_PHP)
        p = F.profile(comps, APACHE_PHP)
        self.assertEqual((p["os"], p["web_server"], p["language"], p["framework"], p["cms"]), ("Ubuntu", "Apache 2.2.34", "PHP 5.4.45", None, None))
        self.assertEqual((p["tls_min"], p["tls_max"], p["cert_issuer"]), ("SSL 3.0", "TLS 1.2", "Sectigo"))
        self.assertEqual((p["hosting"], p["asn"]), ("Example colo", "64500"))
        self.assertEqual(p["cert_expiry"], "2030-08-16T21:05:47Z")

    def test_os_prefers_a_distro_over_generic_unix(self):
        comps = [{"category": "os", "name": "Unix", "version": None}, {"category": "os", "name": "Debian", "version": None}]
        self.assertEqual(F.profile(comps, {})["os"], "Debian")


class TestEol(unittest.TestCase):
    def test_longest_prefix_cycle(self):
        self.assertEqual(F.eol_cycle("1.0.2k", EOL_FIXTURE["openssl"])["cycle"], "1.0.2")
        self.assertEqual(F.eol_cycle("5.4.45", EOL_FIXTURE["php"])["cycle"], "5.4")
        self.assertEqual(F.eol_cycle("12.4", EOL_FIXTURE["debian"])["cycle"], "12")
        self.assertIsNone(F.eol_cycle("9.9", EOL_FIXTURE["php"]))

    def test_status(self):
        self.assertEqual(F.eol_status("PHP", "5.4.45", EOL_FIXTURE, DAY), (1, "2015-09-14"))
        self.assertEqual(F.eol_status("PHP", "8.4.27", EOL_FIXTURE, DAY), (0, "2028-12-31"))
        self.assertEqual(F.eol_status("Apache", "2.4.69", EOL_FIXTURE, DAY), (0, None))
        self.assertEqual(F.eol_status("jQuery", "1.10.2", EOL_FIXTURE, DAY), (1, None))
        self.assertEqual(F.eol_status("OpenSSL", "3.0.2", EOL_FIXTURE, DAY), (1, "2026-09-07"))
        self.assertEqual(F.eol_status("Frobnicator", "1", EOL_FIXTURE, DAY), (None, None))   # not tracked
        self.assertEqual(F.eol_status("PHP", None, EOL_FIXTURE, DAY), (None, None))          # no version

    def test_vm_product_list_matches_the_catalog(self):
        path = os.path.join(os.path.dirname(__file__), "..", "config", "eol_products.txt")
        with open(path) as fh:
            slugs = {l.split("#", 1)[0].strip() for l in fh if l.split("#", 1)[0].strip()}
        self.assertEqual(slugs, set(F.EOL_PRODUCTS.values()), "config/eol_products.txt must list exactly the slugs in fingerprint.EOL_PRODUCTS")


class TestOwnNetworksFile(unittest.TestCase):
    """load_own_networks() on real files, and loading on first use rather than at import."""
    def write(self, text):
        fd, p = tempfile.mkstemp(suffix=".txt")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        self.addCleanup(os.unlink, p)
        return p

    def test_valid_file(self):
        p = self.write("Example-Colo\tExample colo\nother net\tOther network\n")
        self.assertEqual(F.load_own_networks(p), (("example-colo", "Example colo"), ("other net", "Other network")))

    def test_comments_and_blank_lines(self):
        p = self.write("# own networks\n\n   \nexample-colo\tExample colo   # own colo\n#other\tignored\n")
        self.assertEqual(F.load_own_networks(p), (("example-colo", "Example colo"),))

    def test_missing_file(self):
        self.assertEqual(F.load_own_networks(os.path.join(tempfile.gettempdir(), "no-such-own-networks.txt")), ())

    def test_malformed_line_names_file_and_line(self):
        p = self.write("# header\nexample-colo\tExample colo\nexample-colo Example colo\n")
        with self.assertRaises(F.OwnNetworksError) as cm:
            F.load_own_networks(p)
        self.assertTrue(str(cm.exception).startswith(f"{p}:3: expected 'substring<TAB>label'"), str(cm.exception))
        self.assertIsInstance(cm.exception, ValueError)

    def test_loaded_on_first_use(self):
        p = self.write("example-colo\tExample colo\n")
        with mock.patch.object(F, "OWN_NETWORKS", None), mock.patch.object(F, "OWN_NETWORKS_FILE", p):
            self.assertEqual(F.provider_from_asn("EXAMPLE-COLO-AS, US"), "Example colo")
            self.assertEqual(F.OWN_NETWORKS, (("example-colo", "Example colo"),))
        bad = self.write("no tab\n")
        with mock.patch.object(F, "OWN_NETWORKS", None), mock.patch.object(F, "OWN_NETWORKS_FILE", bad):
            with self.assertRaises(F.OwnNetworksError):
                F.provider_from_asn("ANY-AS, US")

    def test_import_does_not_read_the_file(self):
        r = subprocess.run([sys.executable, "-I", "-B", "-c", "import sys; sys.path.insert(0, sys.argv[1]); import fingerprint as F; print(F.OWN_NETWORKS)",
                            os.path.dirname(os.path.abspath(__file__))], capture_output=True, text=True)
        self.assertEqual((r.returncode, r.stdout.strip()), (0, "None"), r.stderr)


if __name__ == "__main__":
    unittest.main()
