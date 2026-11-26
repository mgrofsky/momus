import os, sys, unittest
sys.path.insert(0, os.path.dirname(__file__))
import verify as V

# Two invented nuclei records for the recorded-response rules (the shape of finding_observations.raw_json),
# plus invented responses for the other rules. No test touches the network:
# every listing test passes a stub fetch.

# apache-mod-negotiation-listing: a 406 whose Alternates header and body offer only the default variant
NEGOTIATION_REQUEST = "GET /index HTTP/1.1\nHost: app1.alpha.example\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0\nAccept: fake/fake\n\n"
NEGOTIATION_RESPONSE = ("HTTP/1.1 406 Not Acceptable\nAlternates: {\"index.php\" 1 {type text/html}}\nContent-Type: text/html\nTcn: list\nVary: negotiate\n\n"
                        "<html><head><title>406 Not Acceptable</title></head><body>\n<h1>Not Acceptable</h1>\nAvailable variants:\n<ul>\n"
                        "<li><a href=\"index.php\">index.php</a> , type text/html</li>\n</ul>\n</body></html>\n")
# configuration-listing: an Apache index with sort links, a Parent Directory link and one file; the request carries
# the User-Agent nuclei chose, which the follow-up fetch must reuse
CONFLIST_REQUEST = "GET /config/ HTTP/1.1\nHost: app2.alpha.example\nUser-Agent: Mozilla/5.0 (CentOS; Linux i686) AppleWebKit/537.36 Chrome/120.0\nAccept: */*\n\n"
CONFLIST_RESPONSE = ("HTTP/1.1 200 OK\nContent-Type: text/html\n\n"
                     "<html><head><title>Index of /config</title></head><body><h1>Index of /config</h1>\n"
                     "<pre><a href=\"?C=N;O=D\">Name</a> <a href=\"?C=M;O=A\">Last modified</a><hr><a href=\"/\">Parent Directory</a>\n"
                     "<a href=\"config.php\">config.php</a>  01-Jan-2030 00:00  418\n<hr></pre></body></html>\n")

def resp(status_line, body, headers=()):
    return "HTTP/1.1 " + status_line + "\r\n" + "".join(h + "\r\n" for h in headers) + "\r\n" + body

def listing(path, *names):
    rows = "".join(f'<img src="/icons/unknown.gif" alt="[   ]"> <a href="{n}">{n}</a>   01-Jan-2030 00:00  1.2K\n' for n in names)
    return resp("200 OK", f'<html><head><title>Index of {path}</title></head><body><h1>Index of {path}</h1><pre>'
                f'<a href="?C=N;O=D">Name</a> <a href="?C=M;O=A">Last modified</a><hr>'
                f'<img src="/icons/back.gif" alt="[DIR]"> <a href="/">Parent Directory</a>\n{rows}<hr></pre></body></html>\n',
                ["Content-Type: text/html"])

def finding(tid, url, tags):
    return {"source": "nuclei", "check_id": tid, "tags": list(tags), "matched": url}

LISTING_TAGS = ("config", "listing", "exposure")

class Stub:
    """fetch(url, headers) -> (status, final_url, body); records every call; fails the test on an unknown URL."""
    def __init__(self, table):
        self.table, self.calls = table, []
    def __call__(self, url, headers):
        self.calls.append((url, headers))
        if url not in self.table:
            raise AssertionError(f"unexpected fetch {url}")
        r = self.table[url]
        if isinstance(r, Exception):
            raise r
        st, body = r
        return st, url, body

class TestNegotiation(unittest.TestCase):
    def test_index_only_default_variant(self):
        raw = {"template-id": "apache-mod-negotiation-listing", "matched-at": "https://app1.alpha.example:443/index",
               "request": NEGOTIATION_REQUEST, "response": NEGOTIATION_RESPONSE}
        v, ev = V.verify(finding("apache-mod-negotiation-listing", raw["matched-at"], ("apache", "misconfig", "exposure")), raw)
        self.assertEqual(v, "names_only")
        self.assertIn("index.php", ev)

    def test_backup_variant_confirms(self):
        r = resp("406 Not Acceptable", "Available variants:\n<ul>\n<li><a href=\"index.php.bak\">index.php.bak</a></li>\n</ul>",
                 ['Alternates: {"index.php" 1 {type text/html}}, {"index.php.bak" 1 {type application/x-trash}}'])
        raw = {"template-id": "apache-mod-negotiation-listing", "matched-at": "https://a.example.test/index", "response": r}
        v, ev = V.verify(finding("apache-mod-negotiation-listing", raw["matched-at"], ("exposure",)), raw)
        self.assertEqual(v, "confirmed")
        self.assertIn("index.php.bak", ev)
        self.assertNotIn("index.php,", ev)

    def test_body_variants_when_no_header(self):
        r = resp("406 Not Acceptable", 'Available variants:\n<ul>\n<li><a href="test.php">test.php</a> , type text/html</li>\n</ul>')
        raw = {"template-id": "apache-mod-negotiation-listing", "matched-at": "https://a.example.test/test", "response": r}
        self.assertEqual(V.verify(finding("apache-mod-negotiation-listing", raw["matched-at"], ("exposure",)), raw)[0], "names_only")

    def test_source_extension_is_not_default(self):
        r = resp("406 Not Acceptable", "", ['Alternates: {"config.rb" 1 {type application/x-ruby}}'])
        raw = {"template-id": "apache-mod-negotiation-listing", "matched-at": "https://a.example.test/config", "response": r}
        self.assertEqual(V.verify(finding("apache-mod-negotiation-listing", raw["matched-at"], ("exposure",)), raw), ("confirmed", "variants: config.rb"))

class TestListing(unittest.TestCase):
    def test_config_php_returns_nothing(self):
        raw = {"template-id": "configuration-listing", "matched-at": "https://app2.alpha.example:443/config/",
               "request": CONFLIST_REQUEST, "response": CONFLIST_RESPONSE}
        stub = Stub({"https://app2.alpha.example:443/config/config.php": (200, b"")})
        v, ev = V.verify(finding("configuration-listing", raw["matched-at"], LISTING_TAGS), raw, fetch=stub)
        self.assertEqual(v, "names_only")
        self.assertIn("config.php", ev)
        self.assertEqual(len(stub.calls), 1)
        self.assertIn("CentOS; Linux i686", stub.calls[0][1]["User-Agent"])   # nuclei's own User-Agent

    def test_listing_entries_skip_sort_and_parent(self):
        self.assertEqual(V.listing_entries(V.parse_response(CONFLIST_RESPONSE)[2]), ["config.php"])

    def test_backup_sql_confirms(self):
        raw = {"template-id": "configuration-listing", "matched-at": "https://b.example.test/backup/",
               "response": listing("/backup", "backup.sql", "readme.txt")}
        stub = Stub({"https://b.example.test/backup/backup.sql": (200, b"x" * 1200),
                     "https://b.example.test/backup/readme.txt": (404, b"")})
        v, ev = V.verify(finding("configuration-listing", raw["matched-at"], LISTING_TAGS), raw, fetch=stub)
        self.assertEqual(v, "confirmed")
        self.assertIn("backup.sql 200 1200 bytes", ev)
        self.assertNotIn("readme.txt", ev)

    def test_empty_listing(self):
        raw = {"template-id": "configuration-listing", "matched-at": "https://c.example.test/conf/", "response": listing("/conf")}
        self.assertEqual(V.verify(finding("configuration-listing", raw["matched-at"], LISTING_TAGS), raw, fetch=Stub({}))[0], "empty")

    def test_login_page_and_refresh_do_not_confirm(self):
        raw = {"template-id": "configuration-listing", "matched-at": "https://d.example.test/x/", "response": listing("/x", "a.html", "b.html")}
        stub = Stub({"https://d.example.test/x/a.html": (200, b'<html><meta http-equiv="refresh" content="0;url=/login"></html>'),
                     "https://d.example.test/x/b.html": (200, b'<html><form><input type="password" name="p"></form></html>')})
        self.assertEqual(V.verify(finding("configuration-listing", raw["matched-at"], LISTING_TAGS), raw, fetch=stub)[0], "names_only")

    def test_offhost_entries_are_never_fetched(self):
        raw = {"template-id": "drupal-directory-listing", "matched-at": "https://e.example.test/core/",
               "response": listing("/core", "https://elsewhere.example.org/evil.txt", "sub/")}
        stub = Stub({})
        v, _ = V.verify(finding("drupal-directory-listing:x", raw["matched-at"], ("drupal", "exposure")), raw, fetch=stub)
        self.assertEqual(stub.calls, [])
        self.assertEqual(v, "names_only")

    def test_at_most_ten_fetches(self):
        names = [f"f{i}.txt" for i in range(15)]
        raw = {"template-id": "configuration-listing", "matched-at": "https://f.example.test/d/", "response": listing("/d", *names)}
        stub = Stub({f"https://f.example.test/d/{n}": (200, b"") for n in names})
        v, ev = V.verify(finding("configuration-listing", raw["matched-at"], LISTING_TAGS), raw, fetch=stub)
        self.assertEqual(len(stub.calls), V.MAX_ENTRIES)
        self.assertEqual(v, "names_only")
        self.assertIn("5 more file(s) not fetched", ev)

    def test_all_fetches_fail_is_unverified(self):
        raw = {"template-id": "configuration-listing", "matched-at": "https://g.example.test/d/", "response": listing("/d", "a.txt")}
        stub = Stub({"https://g.example.test/d/a.txt": TimeoutError("timed out")})
        v, ev = V.verify(finding("configuration-listing", raw["matched-at"], LISTING_TAGS), raw, fetch=stub)
        self.assertEqual(v, "unverified")
        self.assertTrue(ev.startswith("unverified:"))

class TestExposure(unittest.TestCase):
    def check(self, tid, r, tags=("exposure", "config"), extra=None):
        raw = {"template-id": tid, "matched-at": "https://h.example.test/x", "response": r, **(extra or {})}
        return V.verify(finding(tid, raw["matched-at"], tags), raw, fetch=Stub({}))

    def test_302_is_redirect(self):
        self.assertEqual(self.check("dockerfile-hidden-disclosure", resp("302 Found", "", ["Location: /login"])), ("redirect", "302 -> /login"))

    def test_404_is_gone(self):
        self.assertEqual(self.check("web-config", resp("404 Not Found", "nope"))[0], "gone")

    def test_empty_200(self):
        self.assertEqual(self.check("prometheus-metrics", resp("200 OK", "")), ("empty", "200 0 bytes"))

    def test_small_html_shell(self):
        self.assertEqual(self.check("circleci-config", resp("200 OK", "<!doctype html><html><body><div id=app></div></body></html>"))[0], "empty")

    def test_soft_404_json(self):
        body = '{"error":"No static resource _debugbar/open."}'
        self.assertEqual(self.check("laravel-debugbar-exposure", resp("200 OK", body), ("laravel", "exposure"))[0], "gone")

    def test_git_config_core_confirms(self):
        body = '[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n'
        v, ev = self.check("git-config", resp("200 OK", body), ("config", "git", "exposure"))
        self.assertEqual(v, "confirmed")
        self.assertEqual(ev, f"200 {len(body)} bytes")

    def test_header_template_at_root_ignores_body(self):
        raw = {"template-id": "fastly-debug-headers", "matched-at": "https://h.example.test:443", "matcher-name": "fastly-debug-path",
               "response": resp("200 OK", "<html><body>hi</body></html>", ["Fastly-Debug-Path: (D cache-x 1)"])}
        self.assertEqual(V.verify(finding("fastly-debug-headers", raw["matched-at"], ("fastly", "exposure")), raw)[0], "confirmed")

    def test_no_response_is_unverified(self):
        self.assertEqual(self.check("git-config", None)[0], "unverified")

    def test_wants_verify(self):
        self.assertTrue(V.wants_verify({"source": "nuclei", "tags": ["vuln", "backup"]}))
        self.assertFalse(V.wants_verify({"source": "nuclei", "tags": ["xss", "generic"]}))
        self.assertFalse(V.wants_verify({"source": "nmap", "tags": ["network", "exposure"]}))


# ---------------------------------------------------------------- pinned follow-up fetches (safefetch.Pinned)
import safefetch as SF  # noqa: E402
from fakenet import FakeNet, http  # noqa: E402

HOST = "list.example.test"
LIST_RAW = {"template-id": "configuration-listing", "matched-at": f"http://{HOST}/backup/",
            "response": listing("/backup", "backup.sql")}


class TestPinnedFetch(unittest.TestCase):
    def pinned(self, net):
        return SF.Pinned(HOST, resolver=net.resolve, connect=net.connect)

    def test_reads_through_the_checked_address(self):
        net = FakeNet([["8.8.8.8"]], [http(200, body="x" * 1200)])
        v, ev = V.verify(finding("configuration-listing", LIST_RAW["matched-at"], LISTING_TAGS), LIST_RAW,
                         fetch=self.pinned(net), host=HOST)
        self.assertEqual(v, "confirmed")
        self.assertEqual(net.connects, [("8.8.8.8", 80)])
        self.assertIn(f"Host: {HOST}", net.requests[0])

    def test_redirect_to_another_host_is_refused(self):
        net = FakeNet([["8.8.8.8"]], [http(302, {"Location": "http://elsewhere.test/backup.sql"})])
        with self.assertRaises(SF.Refused):
            self.pinned(net)(f"http://{HOST}/backup/backup.sql", {})
        self.assertEqual(net.connects, [("8.8.8.8", 80)])          # elsewhere.test never resolved or reached
        self.assertEqual(net.lookups, [HOST])
        v, ev = V.verify(finding("configuration-listing", LIST_RAW["matched-at"], LISTING_TAGS), LIST_RAW,
                         fetch=self.pinned(FakeNet([["8.8.8.8"]], [http(302, {"Location": "http://elsewhere.test/"})])), host=HOST)
        self.assertEqual(v, "unverified")

    def test_host_resolving_to_a_private_address_is_refused(self):
        for addrs in (["10.0.0.5"], ["169.254.169.254"], ["8.8.8.8", "192.168.1.1"], ["::ffff:127.0.0.1"]):
            net = FakeNet([addrs], [http(200, body="x")])
            with self.assertRaises(SF.Refused):
                self.pinned(net)(f"http://{HOST}/backup/backup.sql", {})
            self.assertEqual(net.connects, [], addrs)

    def test_address_change_between_lookups_cannot_be_reached(self):
        # first lookup public, second (the redirect hop) the metadata address: the second connection never happens
        net = FakeNet([["8.8.8.8"], ["169.254.169.254"]],
                      [http(302, {"Location": f"http://{HOST}/next"}), http(200, body="secret")])
        with self.assertRaises(SF.Refused):
            self.pinned(net)(f"http://{HOST}/backup/backup.sql", {})
        self.assertEqual(net.connects, [("8.8.8.8", 80)])
        self.assertEqual(net.lookups, [HOST, HOST])

    def test_finding_host_anchors_not_matched_at(self):
        raw = dict(LIST_RAW, **{"matched-at": "http://other.example.test/backup/"})
        net = FakeNet([["8.8.8.8"]], [http(200, body="x")])
        v, ev = V.verify(finding("configuration-listing", raw["matched-at"], LISTING_TAGS), raw, fetch=self.pinned(net), host=HOST)
        self.assertEqual(v, "unverified")
        self.assertIn("not the finding's host", ev)
        self.assertEqual(net.connects, [])

    def test_no_host_no_live_fetch(self):
        v, ev = V.verify(finding("configuration-listing", LIST_RAW["matched-at"], LISTING_TAGS), LIST_RAW)
        self.assertEqual(v, "unverified")
        self.assertIn("no finding host", ev)

if __name__ == "__main__":
    unittest.main()
