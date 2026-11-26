"""Unit tests for version_watch.py. Ported from the earlier single-product module's tests (each kept, with the product
moved into a watch definition); new tests for the watch rules, the product table, one probe per host, this job's DNS
proof, the output's target-derived fields, and watch retention follow the ported ones."""
import datetime as dt
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import threading
import unittest
import unittest.mock
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
import version_watch as P

SAID = []   # the module's progress lines; kept here so a passing test run prints only the unittest summary


def setUpModule():
    patcher = unittest.mock.patch.object(P, "say", SAID.append)
    patcher.start()
    unittest.addModuleCleanup(patcher.stop)
    # live-probe tests must not ask a real resolver for CNAME chains: by default no target has a CNAME (the
    # ScopeGate tests below pass their own lookup)
    nocname = unittest.mock.patch.object(P.SC, "cname_lookup", lambda host: [])
    nocname.start()
    unittest.addModuleCleanup(nocname.stop)

# Every hostname here is under .test or .example (RFC 2606): nothing resolves, and the full-run tests send curl to the local
# fixture server through --connect-to, so no test can reach a real host.

DAY1 = dt.datetime(2030, 11, 12, 5, 30, tzinfo=dt.timezone.utc)
DAY2 = dt.datetime(2030, 11, 13, 5, 30, tzinfo=dt.timezone.utc)
# the example floors of the docs' PHP watch (the values the earlier module had built in)
PHP_FLOORS = {"8.2": 35, "8.3": 36, "8.4": 27, "8.5": 12}
PHP = P.PRODUCTS["php"]["pattern"]


def watch(wid="php-example", hosts=(), product="php", floors=None, cves=("CVE-2099-10001", "CVE-2099-10002")):
    return {"id": wid, "name": "PHP example", "product": product, "cves": list(cves),
            "floors": dict(PHP_FLOORS) if floors is None else floors, "hosts": list(hosts) if isinstance(hosts, (list, tuple)) else hosts}


def make_db(path, rows, runs=(("2030-11-03-inv", 1), ("2030-11-04", 3), ("2030-11-04-awstest", 2))):
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE runs(seq INTEGER PRIMARY KEY, run_id TEXT UNIQUE)")
    con.execute("CREATE TABLE components(hostname TEXT, category TEXT, name TEXT, version TEXT, first_seen_run TEXT, "
                "last_seen_run TEXT, last_source TEXT, status TEXT, gone_run TEXT)")
    con.executemany("INSERT INTO runs(run_id, seq) VALUES(?,?)", runs)
    con.executemany("INSERT INTO components VALUES(?,?,?,?,?,?,?,?,?)",
                    [(h, "language", n, v, "2030-11-03-inv", last, "nuclei", st, None) for h, n, v, last, st in rows])
    con.commit()
    con.close()


def verified_scope(scope_dir, *apexes):
    """ownership.json with a verified DNS proof for each apex (live probes need the scope's name gate)."""
    import scope as SC
    SC.save_ownership(str(scope_dir), {a: {"apex": a, "statement": SC.OWNERSHIP_STATEMENT, "attested_by": "Test Owner",
                                           "attested_at": "2030-01-01T00:00:00Z", "token": "ab" * 16, "state": "verified",
                                           "verified_at": "2030-11-01T00:00:00Z"} for a in apexes})


def proof_passed(run_dir, *apexes):
    """<run dir>/dns_verification.json as scope.py recheck-dns writes it: these apexes passed in this job."""
    os.makedirs(run_dir, exist_ok=True)
    with open(os.path.join(run_dir, "dns_verification.json"), "w") as fh:
        json.dump({"checked": sorted(apexes), "usable": sorted(apexes), "at": "2030-11-12T05:29:00Z"}, fh)


def args(root, watches=None, **kw):
    root = Path(root)
    wfile = root / "watches.json"
    wfile.write_text(json.dumps(watches if watches is not None else [watch()]))
    a = P.parse_args(["--root", str(root), "--run-dir", str(root / "runs" / "vw-1"), "--watches", str(wfile),
                      "--job-id", "vw-1", "--workers", "4", "--timeout", "3"])
    for k, v in kw.items():
        setattr(a, k, v)
    return a


def ok(headers=None, status=200):
    return {"status": status, "headers": {k.lower(): v for k, v in (headers or {}).items()}, "error": None}


DOWN = {"status": None, "headers": {}, "error": "no answer"}


class StubFetch:
    """url -> response dict; anything not in the table is DOWN."""
    def __init__(self, table):
        self.table, self.calls = table, []

    def __call__(self, url):
        self.calls.append(url)
        return self.table.get(url, DOWN)


def judge(target, fetch, w=None):
    return P.judge(P.probe_host(target["hostname"], fetch), target, w or watch())


def out_dir(root, wid="php-example"):
    return Path(root) / "version-watch" / wid


class Versions(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(P.parse_version(PHP, "PHP/5.4.45"), "5.4.45")
        self.assertEqual(P.parse_version(PHP, "Apache/2.2.34 (Unix) OpenSSL/1.0.2k PHP/5.4.45"), "5.4.45")
        self.assertEqual(P.parse_version(PHP, "php/8.3"), "8.3")
        self.assertEqual(P.parse_version(PHP, None, "", "nginx", "PHP/8.2.34-1ubuntu", "PHP/8.4.27"), "8.2.34")
        self.assertIsNone(P.parse_version(PHP, "nginx/1.24", "PHP", "Express"))

    def test_verdicts(self):
        cases = {
            "5.4.45": "FAIL", "7.4.33": "FAIL", "8.0.30": "FAIL", "8.1.99": "FAIL",
            "8.2.34": "FAIL", "8.2.35": "PASS", "8.2.40": "PASS",
            "8.3.35": "FAIL", "8.3.36": "PASS", "8.4.26": "FAIL", "8.4.27": "PASS",
            "8.5.11": "FAIL", "8.5.12": "PASS", "8.6.0": "PASS", "9.0.0": "PASS",
            "8.3": "FAIL",   # two-part version: patch counts as 0
            "8.6": "PASS",
        }
        for v, want in cases.items():
            self.assertEqual(P.verdict_for_version(v, PHP_FLOORS)[0], want, v)

    def test_reasons(self):
        # changed on purpose: the end-of-life text named the product's branches; the rule's text is now product-neutral
        self.assertIn("no fixed release on this branch", P.verdict_for_version("8.1.2", PHP_FLOORS)[1])
        self.assertEqual(P.verdict_for_version("8.2.34", PHP_FLOORS)[1], "8.2.34 is below 8.2.35")
        self.assertEqual(P.verdict_for_version("8.2.35", PHP_FLOORS)[1], "8.2.35 is at or above 8.2.35")
        self.assertIn("newer than the 8.5 branch", P.verdict_for_version("8.6.0", PHP_FLOORS)[1])
        self.assertEqual(P.branch_of("8.3"), "8.3")

    def test_header_dump(self):
        text = "HTTP/1.1 100 Continue\r\n\r\nHTTP/2 301\r\nServer: nginx\r\nX-Powered-By: PHP/7.4.3\r\nx-powered-by: ASP.NET\r\n\r\n"
        st, h = P.parse_head_dump(text)
        self.assertEqual(st, 301)
        self.assertEqual(h["x-powered-by"], "PHP/7.4.3, ASP.NET")
        self.assertEqual(P.parse_head_dump(""), (None, {}))

    def test_domain(self):
        ap = ["bravo.example", "charlie.example", "foxtrot.example"]
        self.assertEqual(P.domain_of("a.b.foxtrot.example", ap), "foxtrot.example")
        self.assertEqual(P.domain_of("app.web.charlie.example", ap), "charlie.example")
        self.assertEqual(P.domain_of("connect.vendor.test", ap), "vendor.test")


class Targets(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.db = self.tmp / "v.sqlite"
        make_db(self.db, [
            ("A.one.test", "PHP", "5.4.45", "2030-11-04", "present"),
            ("a.one.test", "PHP", None, "2030-11-04", "present"),          # same host, no version: loses
            ("b.one.test", "PHP", "7.4.1", "2030-11-03-inv", "present"),
            ("b.one.test", "PHP", "7.4.3", "2030-11-04", "present"),        # newer run wins
            ("c.one.test", "PHP", None, "2030-11-04", "present"),           # present, no version
            ("d.one.test", "PHP", "8.1.0", "2030-11-04", "gone"),           # not present
            ("e.one.test", "nginx", "1.2", "2030-11-04", "present"),        # not PHP
            ("*.one.test", "PHP", "8.1.0", "2030-11-04", "present"),        # not a hostname
        ])

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_build(self):
        con = P.open_db(self.db)
        self.addCleanup(con.close)
        db_hosts, run = P.scan_db_targets(con, "PHP")
        self.assertEqual(run, "2030-11-04")   # by seq, not by name
        self.assertEqual(db_hosts, {"a.one.test": "5.4.45", "b.one.test": "7.4.3", "c.one.test": None})
        # the watch's own hosts take the place of the earlier asset register (no asset ids any more)
        t = {x["hostname"]: x for x in P.build_targets(db_hosts, ["c.one.test", "r.two.test"])}
        self.assertEqual(sorted(t), ["a.one.test", "b.one.test", "c.one.test", "r.two.test"])
        self.assertEqual(t["c.one.test"]["source"], "both")
        self.assertEqual(t["a.one.test"]["source"], "scan_db")
        self.assertEqual(t["r.two.test"]["source"], "job")
        self.assertIsNone(t["r.two.test"]["scan_db_version"])
        # another product reads its own component rows
        self.assertEqual(P.scan_db_targets(con, "nginx")[0], {"e.one.test": "1.2"})

    def test_no_db(self):
        a = args(self.tmp, db=str(self.tmp / "missing.sqlite"))
        self.assertEqual(P.run(a, now=DAY1, fetch=StubFetch({})), P.EXIT_NOTHING)
        self.assertFalse((self.tmp / "version-watch").exists())

    def test_no_targets(self):
        empty = self.tmp / "e.sqlite"
        make_db(empty, [])
        a = args(self.tmp, db=str(empty))
        self.assertEqual(P.run(a, now=DAY1, fetch=StubFetch({})), P.EXIT_NOTHING)
        self.assertFalse((self.tmp / "version-watch").exists())

    def test_read_order(self):
        t = {"hostname": "h.one.test", "scan_db_version": None, "source": "scan_db"}
        all4 = StubFetch({"https://h.one.test/": ok({"X-Powered-By": "PHP/8.2.35", "Server": "Apache PHP/8.1.0"}),
                          "http://h.one.test/": ok({"X-Powered-By": "PHP/7.4.0", "Server": "PHP/5.6.0"})})
        r = judge(t, all4)
        self.assertEqual((r["version"], r["read_from"], r["verdict"]), ("8.2.35", "https x-powered-by", "PASS"))
        srv = StubFetch({"https://h.one.test/": ok({"Server": "Apache PHP/8.4.26"}),
                         "http://h.one.test/": ok({"X-Powered-By": "PHP/8.4.27"})})
        r = judge(t, srv)
        self.assertEqual((r["version"], r["read_from"], r["verdict"]), ("8.4.26", "https server", "FAIL"))

    def test_same_host_redirects_are_followed(self):
        t = {"hostname": "h.one.test", "scan_db_version": "7.3.31", "source": "scan_db"}
        f = StubFetch({"http://h.one.test/": ok({"Location": "https://h.one.test/"}, 301),
                       "https://h.one.test/": ok({"Location": "/login.php", "Server": "Apache"}, 302),
                       "https://h.one.test/login.php": ok({"X-Powered-By": "PHP/7.3.31"})})
        r = judge(t, f)
        self.assertEqual((r["version"], r["read_from"], r["verdict"]),
                         ("7.3.31", "https x-powered-by (after redirect)", "FAIL"))
        self.assertEqual((r["https_status"], r["http_status"]), (302, 301))      # the first answers
        self.assertEqual(sorted(f.calls), sorted(set(f.calls)))                  # each URL fetched once

    def test_redirects_to_another_host_are_not_followed(self):
        t = {"hostname": "h.one.test", "scan_db_version": None, "source": "scan_db"}
        f = StubFetch({"https://h.one.test/": ok({"Location": "https://sso.two.test/login"}, 302),
                       "https://sso.two.test/login": ok({"X-Powered-By": "PHP/5.4.45"})})
        r = judge(t, f)
        self.assertEqual((r["version"], r["verdict"]), (None, "UNKNOWN"))
        self.assertNotIn("https://sso.two.test/login", f.calls)

    def test_redirect_loops_and_long_chains_stop(self):
        t = {"hostname": "h.one.test", "scan_db_version": None, "source": "scan_db"}
        loop = StubFetch({"https://h.one.test/": ok({"Location": "/a"}, 302),
                          "https://h.one.test/a": ok({"Location": "/"}, 302)})
        self.assertEqual(judge(t, loop)["verdict"], "UNKNOWN")
        self.assertEqual(len(loop.calls), 3)                                     # /, /a, and http /
        chain = {f"https://h.one.test/{i}": ok({"Location": f"/{i + 1}"}, 302) for i in range(1, 9)}
        chain["https://h.one.test/"] = ok({"Location": "/1"}, 302)
        chain["https://h.one.test/5"] = ok({"X-Powered-By": "PHP/8.3.36"})      # beyond MAX_HOPS, never reached
        long = StubFetch(chain)
        self.assertIsNone(judge(t, long)["version"])
        self.assertEqual(sum(u.startswith("https://") for u in long.calls), 1 + P.MAX_HOPS)

# ---- the full run against a local http.server -------------------------------------------------------------

FIXTURE = {   # Host header -> (status, headers); None = close without answering
    "fail.one.test": (200, {"X-Powered-By": "PHP/5.4.45"}),
    "old.one.test": (200, {"Server": "Apache/2.4.6 (CentOS) PHP/8.2.34"}),
    "pass.one.test": (200, {"Server": "nginx", "X-Powered-By": "PHP/8.3.36"}),
    "redir.two.test": (301, {"Location": "http://fail.one.test/", "X-Powered-By": "PHP/8.4.27"}),
    "hidden.two.test": (200, {"Server": "nginx"}),
    "down.two.test": None,
}


class Handler(BaseHTTPRequestHandler):
    hits = []

    def do_GET(self):
        host = (self.headers.get("Host") or "").split(":")[0]
        Handler.hits.append((host, self.path, self.command, self.headers.get("User-Agent")))
        spec = FIXTURE.get(host)
        if spec is None:
            self.close_connection = True
            return   # empty reply: curl gets no status
        self.send_response(spec[0])
        for k, v in spec[1].items():
            self.send_header(k, v)
        self.send_header("Content-Length", "4")
        self.end_headers()
        self.wfile.write(b"body")

    def send_response(self, code, message=None):
        self.send_response_only(code, message)   # no automatic Server/Date: only the fixture's own headers

    def log_message(self, *a):
        pass

    def log_error(self, *a):
        pass


class QuietServer(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        pass   # curl's TLS attempts on this plain-HTTP port end in a parse error; the test checks the outcome, not this


@unittest.skipUnless(shutil.which("curl"), "curl not installed")
class FullRun(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = QuietServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def setUp(self):
        Handler.hits.clear()
        self.root = Path(tempfile.mkdtemp())
        (self.root / "data").mkdir()
        (self.root / "scope").mkdir()
        make_db(self.root / "data" / "scan.sqlite", [
            ("fail.one.test", "PHP", "5.4.45", "2030-11-04", "present"),
            ("old.one.test", "PHP", "8.2.30", "2030-11-04", "present"),
            ("pass.one.test", "PHP", None, "2030-11-04", "present"),
            ("hidden.two.test", "PHP", "7.4.33", "2030-11-04", "present"),
        ])
        (self.root / "scope" / "domains.txt").write_text("one.test\ntwo.test\n")
        verified_scope(self.root / "scope", "one.test", "two.test")
        proof_passed(self.root / "runs" / "vw-1", "one.test", "two.test")
        self.hosts = ["redir.two.test", "down.two.test", "pass.one.test"]      # what the asset register used to add

    def tearDown(self):
        shutil.rmtree(self.root)

    def a(self, hosts=None):
        return args(self.root, [watch(hosts=sorted(hosts if hosts is not None else self.hosts))],
                    connect_to=f"::127.0.0.1:{self.srv.server_address[1]}")

    def test_full_run(self):
        self.assertEqual(P.run(self.a(), now=DAY1), P.EXIT_OK)
        out = out_dir(self.root)
        doc = json.loads((out / "latest.json").read_text())
        self.assertEqual(doc, json.loads((out / "2030-11-12.json").read_text()))
        self.assertEqual(list(doc), ["schema", "watch", "job_id", "generated_at", "date", "cves", "floors", "method",
                                     "target_derived", "targets", "headline", "by_version", "by_domain", "hosts", "changes",
                                     "history"])
        self.assertEqual(doc["schema"], "version-watch-v1")
        self.assertEqual(doc["watch"], {"id": "php-example", "name": "PHP example", "product": "php", "product_name": "PHP"})
        self.assertEqual(doc["generated_at"], "2030-11-12T05:30:00Z")
        self.assertEqual(doc["floors"], {"8.2": "8.2.35", "8.3": "8.3.36", "8.4": "8.4.27", "8.5": "8.5.12"})
        self.assertEqual(doc["targets"], {"total": 6, "from_scan_db": 4, "from_job": 3, "carried": 0, "not_probed": 0,
                                          "scan_db_run": "2030-11-04"})
        self.assertEqual(doc["headline"], {"hosts": 6, "fail": 2, "pass": 2, "unknown": 1, "unreachable": 1})
        hosts = {h["hostname"]: h for h in doc["hosts"]}
        self.assertEqual([h["verdict"] for h in doc["hosts"]], ["FAIL", "FAIL", "UNKNOWN", "UNREACHABLE", "PASS", "PASS"])
        self.assertEqual([h["hostname"] for h in doc["hosts"]][:2], ["fail.one.test", "old.one.test"])
        f = hosts["fail.one.test"]
        self.assertEqual((f["version"], f["read_from"], f["http_status"], f["https_status"], f["domain"]),
                         ("5.4.45", "http x-powered-by", 200, None, "one.test"))
        self.assertEqual(hosts["old.one.test"]["read_from"], "http server")
        self.assertEqual(hosts["old.one.test"]["scan_db_version"], "8.2.30")
        self.assertEqual(hosts["old.one.test"]["version"], "8.2.34")
        r = hosts["redir.two.test"]
        self.assertEqual((r["verdict"], r["http_status"], r["source"], r["domain"]), ("PASS", 301, "job", "two.test"))
        hid = hosts["hidden.two.test"]
        self.assertIsNone(hid["version"])            # never copied from the scan db
        self.assertEqual(hid["scan_db_version"], "7.4.33")
        self.assertEqual(hid["server"], "nginx")
        self.assertIsNone(hosts["down.two.test"]["version"])
        self.assertEqual(hosts["pass.one.test"]["source"], "both")
        self.assertEqual(doc["by_version"][0]["hosts"], 1)
        self.assertEqual({v["version"] for v in doc["by_version"]}, {"5.4.45", "8.2.34", "8.3.36", "8.4.27"})
        self.assertEqual(doc["by_domain"][0], {"domain": "one.test", "hosts": 3, "fail": 2, "pass": 1, "unknown": 0, "unreachable": 0})
        self.assertEqual(doc["changes"], {"since": None, "items": []})
        self.assertEqual(doc["history"], [{"date": "2030-11-12", **doc["headline"]}])
        # the redirect was not followed: fail.one.test was asked once over http only (https fails the handshake)
        self.assertEqual([h for h in Handler.hits if h[0] == "fail.one.test"],
                         [("fail.one.test", "/", "GET", P.UA)])
        self.assertTrue(all(h[1] == "/" and h[2] == "GET" for h in Handler.hits))
        self.assertEqual([p.name for p in out.iterdir() if ".tmp" in p.name], [])

    def test_changes_and_history(self):
        self.assertEqual(P.run(self.a(), now=DAY1), P.EXIT_OK)
        FIXTURE["old.one.test"] = (200, {"Server": "Apache PHP/8.2.35"})
        try:
            self.assertEqual(P.run(self.a(["redir.two.test", "new.two.test"]), now=DAY2), P.EXIT_OK)
        finally:
            FIXTURE["old.one.test"] = (200, {"Server": "Apache/2.4.6 (CentOS) PHP/8.2.34"})
        doc = json.loads((out_dir(self.root) / "latest.json").read_text())
        self.assertEqual(doc["date"], "2030-11-13")
        self.assertEqual(doc["changes"]["since"], "2030-11-12")
        items = {i["hostname"]: i for i in doc["changes"]["items"]}
        self.assertEqual(items["old.one.test"], {"hostname": "old.one.test", "from_version": "8.2.34", "to_version": "8.2.35",
                                                 "from_verdict": "FAIL", "to_verdict": "PASS"})
        self.assertEqual(items["down.two.test"], {"hostname": "down.two.test", "from_version": None, "to_version": None,
                                                  "from_verdict": "UNREACHABLE", "to_verdict": None})
        self.assertEqual(items["new.two.test"]["from_verdict"], None)
        self.assertEqual(items["new.two.test"]["to_verdict"], "UNREACHABLE")
        self.assertNotIn("fail.one.test", items)
        self.assertEqual([h["date"] for h in doc["history"]], ["2030-11-12", "2030-11-13"])
        self.assertEqual(doc["history"][0]["fail"], 2)
        self.assertEqual(doc["history"][1], {"date": "2030-11-13", **doc["headline"]})


class Suspect(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        (self.root / "data").mkdir()
        make_db(self.root / "data" / "scan.sqlite",
                [(f"h{i}.one.test", "PHP", "8.3.36", "2030-11-04", "present") for i in range(4)])

    def tearDown(self):
        shutil.rmtree(self.root)

    def up(self, n):
        return StubFetch({f"https://h{i}.one.test/": ok({"X-Powered-By": "PHP/8.3.36"}) for i in range(n)})

    def test_suspect_keeps_latest(self):
        self.assertEqual(P.run(args(self.root), now=DAY1, fetch=self.up(4)), P.EXIT_OK)
        latest = (out_dir(self.root) / "latest.json").read_text()
        # 3 of 4 unreachable: more than half
        self.assertEqual(P.run(args(self.root), now=DAY2, fetch=self.up(1)), P.EXIT_SUSPECT)
        self.assertEqual((out_dir(self.root) / "latest.json").read_text(), latest)
        bad = json.loads((out_dir(self.root) / "2030-11-13.json").read_text())
        self.assertIs(bad["suspect"], True)
        self.assertEqual(bad["headline"]["unreachable"], 3)
        # the next day compares with the last good file, and history skips the suspect one
        day3 = DAY2 + dt.timedelta(days=1)
        self.assertEqual(P.run(args(self.root), now=day3, fetch=self.up(4)), P.EXIT_OK)
        doc = json.loads((out_dir(self.root) / "latest.json").read_text())
        self.assertNotIn("suspect", doc)
        self.assertEqual(doc["changes"], {"since": "2030-11-12", "items": []})
        self.assertEqual([h["date"] for h in doc["history"]], ["2030-11-12", "2030-11-14"])

    def test_exactly_half_is_not_suspect(self):
        self.assertEqual(P.run(args(self.root), now=DAY1, fetch=self.up(2)), P.EXIT_OK)
        self.assertTrue((out_dir(self.root) / "latest.json").exists())

    def test_suspect_is_per_watch(self):
        # new: a second watch whose hosts all answer is written normally while the first is suspect; the exit code says
        # that at least one watch was suspect
        w2 = watch("other", product="nginx", floors={"1.26": 0}, hosts=["x.two.test"])     # no nginx rows in the database
        fetch = self.up(1)
        fetch.table["https://x.two.test/"] = ok({"Server": "nginx/1.26.2"})
        self.assertEqual(P.run(args(self.root, [watch(), w2]), now=DAY1, fetch=fetch), P.EXIT_SUSPECT)
        self.assertFalse((out_dir(self.root) / "latest.json").exists())
        self.assertTrue((out_dir(self.root, "other") / "latest.json").exists())


class Carried(unittest.TestCase):
    """A host that stops advertising its version stays on the list: a hidden version must not read as a fix."""
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        (self.root / "data").mkdir()
        self.db = self.root / "data" / "scan.sqlite"
        self.set_db(["hide.one.test", "gone.one.test", "keep.one.test", "k2.one.test"])

    def tearDown(self):
        shutil.rmtree(self.root)

    def set_db(self, names):
        if self.db.exists():
            self.db.unlink()
        make_db(self.db, [(n, "PHP", "5.4.45", "2030-11-04", "present") for n in names])

    def doc(self, day):
        return json.loads((out_dir(self.root) / f"{day}.json").read_text())

    def test_carry_forward(self):
        day1 = StubFetch({"https://hide.one.test/": ok({"X-Powered-By": "PHP/5.4.45"}),
                          "https://gone.one.test/": ok({"X-Powered-By": "PHP/7.4.3"}),
                          "https://keep.one.test/": ok({"X-Powered-By": "PHP/8.3.36"}),
                          "https://k2.one.test/": ok({"X-Powered-By": "PHP/8.3.36"})})
        self.assertEqual(P.run(args(self.root), now=DAY1, fetch=day1), P.EXIT_OK)
        self.assertEqual(self.doc("2030-11-12")["headline"]["fail"], 2)

        # day 2: hide and gone left the scan database. hide answers without a version; gone does not answer.
        self.set_db(["keep.one.test", "k2.one.test"])
        day2 = StubFetch({"https://hide.one.test/": ok({"Server": "nginx"}),
                          "https://keep.one.test/": ok({"X-Powered-By": "PHP/8.3.36"}),
                          "https://k2.one.test/": ok({"X-Powered-By": "PHP/8.3.36"})})
        self.assertEqual(P.run(args(self.root), now=DAY2, fetch=day2), P.EXIT_OK)
        self.assertIn("https://gone.one.test/", day2.calls)          # carried hosts are probed
        d2 = self.doc("2030-11-13")
        self.assertEqual(d2["targets"], {"total": 4, "from_scan_db": 2, "from_job": 0, "carried": 2, "not_probed": 0,
                                         "scan_db_run": "2030-11-04"})
        hosts = {h["hostname"]: h for h in d2["hosts"]}
        self.assertEqual(sorted(hosts), ["hide.one.test", "k2.one.test", "keep.one.test"])
        self.assertEqual((hosts["hide.one.test"]["verdict"], hosts["hide.one.test"]["source"],
                          hosts["hide.one.test"]["scan_db_version"]), ("UNKNOWN", "carried", None))
        # the dropped carried host counts toward neither the headline nor the suspect rule
        self.assertEqual(d2["headline"], {"hosts": 3, "fail": 0, "pass": 2, "unknown": 1, "unreachable": 0})
        self.assertNotIn("suspect", d2)
        items = {i["hostname"]: i for i in d2["changes"]["items"]}
        self.assertEqual(items["hide.one.test"], {"hostname": "hide.one.test", "from_version": "5.4.45", "to_version": None,
                                                  "from_verdict": "FAIL", "to_verdict": "UNKNOWN"})
        self.assertEqual(items["gone.one.test"], {"hostname": "gone.one.test", "from_version": "7.4.3", "to_version": None,
                                                  "from_verdict": "FAIL", "to_verdict": None})

        # day 3: hide is carried again through the day 2 file; gone is not (it was dropped)
        day3 = StubFetch({"https://hide.one.test/": ok({"Server": "nginx"}),
                          "https://keep.one.test/": ok({"X-Powered-By": "PHP/8.3.36"}),
                          "https://k2.one.test/": ok({"X-Powered-By": "PHP/8.3.36"})})
        self.assertEqual(P.run(args(self.root), now=DAY2 + dt.timedelta(days=1), fetch=day3), P.EXIT_OK)
        self.assertNotIn("https://gone.one.test/", day3.calls)
        d3 = self.doc("2030-11-14")
        hosts = {h["hostname"]: h for h in d3["hosts"]}
        self.assertEqual((hosts["hide.one.test"]["verdict"], hosts["hide.one.test"]["source"]), ("UNKNOWN", "carried"))
        self.assertEqual(d3["targets"]["carried"], 1)
        self.assertEqual(d3["changes"]["items"], [])

    def test_carried_from_the_previous_file(self):
        prev = {"hosts": [{"hostname": "r.two.test"}, {"hostname": "a.one.test"}]}
        self.assertEqual(P.carried_targets(prev, {"a.one.test": "5.4.45"}, []),
                         [{"hostname": "r.two.test", "scan_db_version": None, "source": "carried"}])
        self.assertEqual(P.carried_targets(prev, {}, ["r.two.test", "a.one.test"]), [])
        self.assertEqual(P.carried_targets(None, {}, []), [])

    def test_dropped_carried_not_in_suspect(self):
        # day 2: 2 of 4 db hosts answer (exactly half: not suspect), plus 2 carried hosts that do not answer.
        # Counted before the drop that would be 4 of 6 unreachable; after it, 2 of 4.
        all4 = {f"https://{n}.one.test/": ok({"X-Powered-By": "PHP/8.3.36"}) for n in ("hide", "gone", "keep", "k2")}
        self.assertEqual(P.run(args(self.root), now=DAY1, fetch=StubFetch(all4)), P.EXIT_OK)
        self.set_db(["keep.one.test", "k2.one.test", "x.one.test", "y.one.test"])
        day2 = StubFetch({"https://keep.one.test/": ok({"X-Powered-By": "PHP/8.3.36"}),
                          "https://k2.one.test/": ok({"X-Powered-By": "PHP/8.3.36"})})
        self.assertEqual(P.run(args(self.root), now=DAY2, fetch=day2), P.EXIT_OK)
        d2 = json.loads((out_dir(self.root) / "latest.json").read_text())
        self.assertEqual(d2["date"], "2030-11-13")
        self.assertEqual(d2["headline"]["hosts"], 4)
        self.assertEqual(d2["headline"]["unreachable"], 2)
        self.assertEqual(d2["targets"]["carried"], 2)


class Retention(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        (self.root / "data").mkdir()
        make_db(self.root / "data" / "scan.sqlite", [("h.one.test", "PHP", "8.4.27", "2030-11-04", "present")])

    def tearDown(self):
        shutil.rmtree(self.root)

    def test_keep_newest(self):
        out = out_dir(self.root)
        out.mkdir(parents=True)
        start = dt.date(2030, 8, 1)
        for i in range(95):
            d = (start + dt.timedelta(days=i)).isoformat()
            (out / f"{d}.json").write_text(json.dumps({"schema": P.SCHEMA, "date": d, "hosts": [],
                                                       "headline": {"hosts": 1, "fail": 0, "pass": 1, "unknown": 0, "unreachable": 0}}))
        (out / "notes.json").write_text("{}")
        fetch = StubFetch({"https://h.one.test/": ok({"X-Powered-By": "PHP/8.4.27"})})
        self.assertEqual(P.run(args(self.root), now=DAY2, fetch=fetch), P.EXIT_OK)
        dated = [p for _, p in P.dated_files(out)]
        self.assertEqual(len(dated), 90)
        self.assertEqual(dated[-1].name, "2030-11-13.json")
        self.assertTrue((out / "notes.json").exists())
        self.assertTrue((out / "latest.json").exists())
        doc = json.loads((out / "latest.json").read_text())
        self.assertEqual(len(doc["history"]), 90)
        self.assertEqual(doc["history"][-1]["date"], "2030-11-13")
        self.assertEqual(doc["changes"]["since"], (start + dt.timedelta(days=94)).isoformat())

    def test_a_watch_removed_from_the_job_keeps_its_results_for_the_retention_period(self):
        # new: watch "old" ran on DAY1 and is then no longer in the job. Its folder stays while its newest file is
        # younger than KEEP days, then goes; the active watch is untouched.
        fetch = StubFetch({"https://h.one.test/": ok({"X-Powered-By": "PHP/8.4.27"})})
        self.assertEqual(P.run(args(self.root, [watch("old")]), now=DAY1, fetch=fetch), P.EXIT_OK)
        self.assertTrue((out_dir(self.root, "old") / "latest.json").exists())
        day89 = DAY1 + dt.timedelta(days=P.KEEP - 1)
        self.assertEqual(P.run(args(self.root, [watch("new")]), now=day89, fetch=fetch), P.EXIT_OK)
        self.assertTrue((out_dir(self.root, "old") / "latest.json").exists())
        day90 = DAY1 + dt.timedelta(days=P.KEEP)
        self.assertEqual(P.run(args(self.root, [watch("new")]), now=day90, fetch=fetch), P.EXIT_OK)
        self.assertFalse(out_dir(self.root, "old").exists())
        self.assertTrue((out_dir(self.root, "new") / "latest.json").exists())
        self.assertIn("retention: removed the folder of watch old", "\n".join(SAID))


class ScopeGate(unittest.TestCase):
    """Live probes (no injected fetch) only reach hosts in the approved scope, through a checked, pinned address."""
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        (self.root / "data").mkdir()
        (self.root / "scope").mkdir()
        make_db(self.root / "data" / "scan.sqlite", [("in.one.test", "PHP", "8.2.30", "2030-11-04", "present"),
                                                     ("out.other.test", "PHP", "8.2.30", "2030-11-04", "present")])
        (self.root / "scope" / "domains.txt").write_text("one.test\n")
        verified_scope(self.root / "scope", "one.test")
        proof_passed(self.root / "runs" / "vw-1", "one.test")
        self.cmds = []

    def tearDown(self):
        shutil.rmtree(self.root)

    def run_with(self, resolve, cname_lookup=None, watches=None):
        import subprocess
        def fake_run(cmd, **kw):
            self.cmds.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, "HTTP/1.1 200 OK\r\nX-Powered-By: PHP/8.2.35\r\n\r\n", "")
        with unittest.mock.patch.object(P.subprocess, "run", side_effect=fake_run), \
             unittest.mock.patch.object(P.SF, "system_resolve", side_effect=resolve):
            return P.run(args(self.root, watches), now=DAY1, cname_lookup=cname_lookup)

    def test_alias_of_an_excluded_name_is_not_probed(self):
        # the watch's hosts: two aliases of excluded names (one step and two steps) next to an allowed host with a
        # harmless CNAME; the scan database adds in.one.test (no CNAME)
        (self.root / "scope" / "exclude.txt").write_text("excluded.one.test\n")
        chains = {"alias.one.test": ["excluded.one.test"],
                  "twostep.one.test": ["hop.one.test", "deep.excluded.one.test"],
                  "fine.one.test": ["edge.one.test"]}
        asked = []
        def lookup(host):
            asked.append(host)
            return chains.get(host, [])
        SAID.clear()
        w = [watch(hosts=["alias.one.test", "fine.one.test", "twostep.one.test"])]
        self.assertEqual(self.run_with(lambda h: ["8.8.8.8"], lookup, w), P.EXIT_OK)
        hosts = {c[-1].split("://")[1].split("/")[0] for c in self.cmds}
        self.assertEqual(hosts, {"in.one.test", "fine.one.test"})
        self.assertEqual(sorted(asked), ["alias.one.test", "fine.one.test", "in.one.test", "twostep.one.test"])
        said = "\n".join(SAID)
        self.assertIn("alias.one.test (CNAME chain reaches excluded.one.test, excluded by exclude.txt (excluded.one.test))", said)
        self.assertIn("twostep.one.test (CNAME chain reaches deep.excluded.one.test, excluded by exclude.txt (excluded.one.test))", said)
        doc = json.loads((out_dir(self.root) / "latest.json").read_text())
        self.assertEqual(sorted(h["hostname"] for h in doc["hosts"]), ["fine.one.test", "in.one.test"])

    def test_a_chain_that_cannot_be_looked_up_is_not_probed(self):
        def lookup(host):
            raise OSError("no answer from the resolver")
        # nothing probed; the host is reported UNREACHABLE, so a lookup outage makes the file suspect (latest.json kept)
        self.assertEqual(self.run_with(lambda h: ["8.8.8.8"], lookup), P.EXIT_SUSPECT)
        self.assertEqual(self.cmds, [])
        doc = json.loads((out_dir(self.root) / "2030-11-12.json").read_text())
        self.assertTrue(doc["suspect"])
        self.assertEqual([(h["hostname"], h["verdict"]) for h in doc["hosts"]], [("in.one.test", "UNREACHABLE")])
        self.assertIn("CNAME chain could not be looked up", doc["hosts"][0]["reason"])

    def test_out_of_scope_host_is_never_probed_and_curl_is_pinned(self):
        self.assertEqual(self.run_with(lambda h: ["8.8.8.8"]), P.EXIT_OK)
        urls = [c[-1] for c in self.cmds]
        self.assertTrue(urls and all("in.one.test" in u for u in urls), urls)
        for c in self.cmds:
            i = c.index("--resolve")
            self.assertIn(c[i + 1], ("in.one.test:443:8.8.8.8", "in.one.test:80:8.8.8.8"))

    def test_private_address_is_never_reached(self):
        self.assertEqual(self.run_with(lambda h: ["169.254.169.254"]), P.EXIT_SUSPECT)
        self.assertEqual(self.cmds, [])

    def test_no_scope_no_probe(self):
        (self.root / "scope" / "domains.txt").unlink()
        self.assertEqual(self.run_with(lambda h: ["8.8.8.8"]), P.EXIT_INVALID)
        self.assertEqual(self.cmds, [])

    # ---- new: this job's DNS proof ---------------------------------------------------------------------------------
    def test_a_host_under_a_domain_that_did_not_pass_the_proof_in_this_job_is_not_probed(self):
        # two.test is in the scope and still "verified" on disk from an earlier check, but its proof did not pass in
        # this job (dns_verification.json lists only one.test): its host is not probed and reads UNREACHABLE
        (self.root / "scope" / "domains.txt").write_text("one.test\ntwo.test\n")
        verified_scope(self.root / "scope", "one.test", "two.test")
        w = [watch(hosts=["p.two.test"])]
        self.assertEqual(self.run_with(lambda h: ["8.8.8.8"], None, w), P.EXIT_OK)
        self.assertTrue(self.cmds)                                                       # control: in.one.test was probed
        self.assertFalse([c for c in self.cmds if "two.test" in " ".join(c)])
        doc = json.loads((out_dir(self.root) / "latest.json").read_text())
        p = {h["hostname"]: h for h in doc["hosts"]}["p.two.test"]
        self.assertEqual((p["verdict"], p["reason"]), ("UNREACHABLE", "no HTTP response on https or http "
                                                       "(not probed: its domain did not pass the DNS proof in this job)"))
        self.assertEqual(doc["targets"]["not_probed"], 1)

    def test_no_proof_file_means_nothing_is_probed(self):
        os.unlink(self.root / "runs" / "vw-1" / "dns_verification.json")
        self.assertEqual(self.run_with(lambda h: ["8.8.8.8"]), P.EXIT_SUSPECT)
        self.assertEqual(self.cmds, [])

    def test_a_carried_host_that_was_not_probed_is_kept(self):
        # a carried host whose domain is pending this job is not taken as decommissioned (only a host that was probed
        # and did not answer is): it stays, as UNREACHABLE, so the next good run can carry it again
        self.assertEqual(self.run_with(lambda h: ["8.8.8.8"], None, [watch(hosts=["h.one.test"])]), P.EXIT_OK)
        (self.root / "runs" / "vw-1" / "dns_verification.json").write_text(json.dumps({"usable": []}))
        day2 = args(self.root, [watch()])
        import subprocess
        with unittest.mock.patch.object(P.subprocess, "run", side_effect=lambda c, **k: subprocess.CompletedProcess(c, 0, "", "")):
            self.assertEqual(P.run(day2, now=DAY2), P.EXIT_SUSPECT)
        d2 = json.loads((out_dir(self.root) / "2030-11-13.json").read_text())
        self.assertEqual(sorted((h["hostname"], h["source"], h["verdict"]) for h in d2["hosts"]),
                         [("h.one.test", "carried", "UNREACHABLE"), ("in.one.test", "scan_db", "UNREACHABLE")])

    def test_lab_mode_probes_lab_targets_only(self):
        # lab.json in the run folder (written by the runner for a lab job): lab targets need no DNS proof, and a real
        # domain's host is not probed in a lab job (recon's phase 0 skips the proof in lab mode too)
        (self.root / "runs" / "vw-1" / "lab.json").write_text(json.dumps({"cidr": "10.89.47.0/24", "hosts": ["target.demo.test"]}))
        os.unlink(self.root / "runs" / "vw-1" / "dns_verification.json")
        with unittest.mock.patch.dict(os.environ, {"SCAN_LAB": "1"}):
            self.assertEqual(self.run_with(lambda h: ["10.89.47.10"], None, [watch(hosts=["target.demo.test"])]), P.EXIT_OK)
        hosts = {c[-1].split("://")[1].split("/")[0] for c in self.cmds}
        self.assertEqual(hosts, {"target.demo.test"})
        doc = json.loads((out_dir(self.root) / "latest.json").read_text())
        self.assertEqual({h["hostname"]: h["verdict"] for h in doc["hosts"]},
                         {"target.demo.test": "PASS", "in.one.test": "UNREACHABLE"})


# ---- new: the watch rules -------------------------------------------------------------------------------------------
class WatchRules(unittest.TestCase):
    def bad(self, w, contains, raw=None):
        with self.assertRaises(P.WatchError) as cm:
            P.validate_watches(raw if raw is not None else [w])
        self.assertIn(contains, str(cm.exception))
        return str(cm.exception)

    def test_a_good_watch_is_normalized(self):
        w = watch(hosts=["b.one.test", "a.one.test", "a.one.test"], floors={"8.10": 1, "8.2": 35, "10.0": 0})
        out = P.validate_watches([w])
        self.assertEqual(out[0]["hosts"], ["a.one.test", "b.one.test"])
        self.assertEqual(list(out[0]["floors"]), ["8.2", "8.10", "10.0"])            # numeric branch order
        self.assertEqual(P.validate_watches([{k: v for k, v in w.items() if k != "hosts"}])[0]["hosts"], [])

    def test_each_bad_field_is_rejected(self):
        self.bad(None, "at least one watch", raw=[])
        self.bad(None, "must be a list", raw={"id": "x"})
        self.bad(None, f"more than {P.MAX_WATCHES}", raw=[watch(f"w{i}") for i in range(P.MAX_WATCHES + 1)])
        self.bad("x", "must be an object")
        self.bad({**watch(), "extra": 1}, "unknown field 'extra'")
        self.bad({k: v for k, v in watch().items() if k != "cves"}, "missing field(s) cves")
        for wid in ("", "a", "-ab", "ab-", "AB", "a" * 33, "a_b", 7, None, "ab\n"):
            self.bad(watch(wid), ".id:")
        self.bad(None, "listed twice", raw=[watch(), watch()])
        for name in ("", " x", "x ", "a" * 81, "<b>x</b>", "x\ny", 5):
            self.bad({**watch(), "name": name}, ".name:")
        for prod in ("PHP", "iis", "", None, ["php"]):
            self.bad(watch(product=prod), ".product:")
        for cves in ([], "CVE-2099-1000", ["CVE-2099-12"], ["cve-2030-10001"], ["CVE-2099-10001 "], [1],
                     ["CVE-2099-10001", "CVE-2099-10001"], [f"CVE-2099-{10000 + i}" for i in range(P.MAX_CVES + 1)]):
            self.bad(watch(cves=cves), ".cves")
        for floors in ({}, [], {"8": 1}, {"8.2.1": 1}, {"08.2": 1}, {"8.02": 1}, {"8.2": -1}, {"8.2": True},
                       {"8.2": 1.5}, {"8.2": "35"}, {"8.2": P.MAX_PATCH + 1}, {f"1.{i}": 1 for i in range(P.MAX_FLOORS + 1)}):
            self.bad(watch(floors=floors), ".floors")
        self.bad(watch(product="openssl", floors={"1.1": 1}), "3.0 or newer")
        self.assertEqual(P.validate_watches([watch(product="openssl", floors={"3.0": 13})])[0]["floors"], {"3.0": 13})
        for hosts in ("a.one.test", ["A.one.test"], ["a.one.test."], ["one"], ["a b.test"], [None],
                      [f"h{i}.one.test" for i in range(P.MAX_HOSTS + 1)]):
            self.bad(watch(hosts=hosts), ".hosts")

    def test_no_field_can_carry_a_pattern_path_or_url(self):
        hostile = ["https://evil.test/x", "/etc/passwd", "../x", ".*", "PHP/(.*)", "[0-9]+", "a|b", "x-powered-by: x",
                   "{x}", "$(id)", "%2e%2e", "http:evil.test", "a\\b", "?x=1", "#frag"]
        for v in hostile:
            for field, w in (("id", watch(v)), ("name", {**watch(), "name": v}), ("product", watch(product=v)),
                             ("cves", watch(cves=[v])), ("floors", watch(floors={v: 1})), ("hosts", watch(hosts=[v]))):
                with self.assertRaises(P.WatchError, msg=f"{field}={v!r}") as cm:
                    P.validate_watches([w])
                self.assertNotIn(v, str(cm.exception).replace(f"options.watches[0].{field}", ""), (field, v))
        # and no key can name a header, a pattern, a path or a URL
        for k in ("pattern", "header", "headers", "path", "url", "regex", "method"):
            self.bad({**watch(), k: "x"}, "unknown field")


# ---- new: the product table ---------------------------------------------------------------------------------------
class Products(unittest.TestCase):
    CASES = {
        "php": {"PHP/8.2.34": "8.2.34", "PHP/8.3": "8.3", "Apache/2.4.6 (CentOS) PHP/7.4.3": "7.4.3", "php/5.6.40-0+deb8u12": "5.6.40",
                "PHP/8.2.34.1": None, "PHP/": None, "PHP": None, "PHP/x.y": None, "XPHP/8.2.1": None, "PHP/12345.1.1": None,
                "<script>PHP/8.2.1</script>": "8.2.1", "PHP/8.2.1<script>": "8.2.1", "PHP/8.2.9999999": None},
        "nginx": {"nginx/1.18.0": "1.18.0", "nginx/1.24.0 (Ubuntu)": "1.24.0", "nginx": None, "nginx/1.18": None,
                  "cloudflare-nginx": None, "cloudflare-nginx/1.2.3": None, "openresty/1.21.4.1": None, "nginx/1.2.3.400": None,
                  "Apache/2.4.1": None},
        "apache-httpd": {"Apache/2.4.58 (Unix)": "2.4.58", "Apache/2.2.34 (Unix) OpenSSL/1.0.2k PHP/5.4.45": "2.2.34",
                         "Apache": None, "Apache/2": None, "Apache-Coyote/1.1": None, "Apache/2.4": None,
                         "XApache/2.4.1": None, "Apache/2.4.58.1": None},
        "openssl": {"Apache/2.4.6 (CentOS) OpenSSL/3.0.13": "3.0.13", "OpenSSL/1.0.2k-fips": "1.0.2", "OpenSSL/1.1.1w": "1.1.1",
                    "OpenSSL/3.0": None, "LibreSSL/3.8.2": None, "openssl": None},
    }

    def test_each_pattern_on_good_odd_and_hostile_values(self):
        for prod, cases in self.CASES.items():
            pat = P.PRODUCTS[prod]["pattern"]
            for value, want in cases.items():
                self.assertEqual(P.parse_version(pat, value), want, (prod, value))

    def test_very_long_and_markup_values(self):
        for prod, spec in P.PRODUCTS.items():
            pat, tok = spec["pattern"], {"php": "PHP", "nginx": "nginx", "apache-httpd": "Apache", "openssl": "OpenSSL"}[prod]
            # a version beyond the first MAX_HEADER_VALUE characters is never read
            self.assertIsNone(P.parse_version(pat, "A" * P.MAX_HEADER_VALUE + f" {tok}/3.1.2"))
            self.assertEqual(P.parse_version(pat, f"{tok}/3.1.2 " + "A" * 100000), "3.1.2")
            self.assertIsNone(P.parse_version(pat, f"{tok}/" + "9" * 5000))
            self.assertIsNone(P.parse_version(pat, f"{tok}/" + "1." * 3000))
            # markup around the token: only the strict version is taken, never the markup
            got = P.parse_version(pat, f"<img src=x onerror=alert(1)>{tok}/3.1.2\"><script>")
            self.assertEqual(got, "3.1.2")
            self.assertTrue(P.VERSION_RE.fullmatch(got))

    def test_openssl_lettered_releases_never_pass_a_numeric_floor(self):
        w = P.validate_watches([watch(product="openssl", floors={"3.0": 13, "3.1": 5})])[0]
        for v in ("1.1.1w", "1.0.2k-fips", "1.1.0l"):
            got = P.parse_version(P.PRODUCTS["openssl"]["pattern"], f"OpenSSL/{v}")
            self.assertEqual(P.verdict_for_version(got, w["floors"])[0], "FAIL", v)


class VerdictRule(unittest.TestCase):
    F = {"1.20": 5, "1.24": 3, "1.26": 0}

    def test_branch_edges(self):
        cases = {"1.20.4": "FAIL", "1.20.5": "PASS", "1.20.6": "PASS", "1.24.2": "FAIL", "1.24.3": "PASS",
                 "1.26.0": "PASS", "1.26": "PASS",         # a floor of 0: every release of the branch passes
                 "1.22.9": "FAIL",                          # a gap branch between two listed ones: no fixed release
                 "1.19.99": "FAIL", "0.9.9": "FAIL",        # older than every listed branch
                 "1.27.0": "PASS", "1.100.0": "PASS", "2.0.0": "PASS"}     # newer than every listed branch (1.100 > 1.26)
        for v, want in cases.items():
            self.assertEqual(P.verdict_for_version(v, self.F)[0], want, v)
        self.assertEqual(P.verdict_for_version("1.22.9", self.F)[1], "1.22.9 is on branch 1.22: no fixed release on this branch")
        self.assertEqual(P.verdict_for_version("1.100.0", self.F)[1], "1.100.0 is newer than the 1.26 branch; released after the fix")

    def test_branches_compare_as_numbers(self):
        f = {"8.9": 1, "8.10": 1}
        self.assertEqual(P.verdict_for_version("8.10.0", f)[0], "FAIL")     # 8.10 is listed, below its floor
        self.assertEqual(P.verdict_for_version("8.11.0", f)[0], "PASS")     # newer than 8.10 (not "8.9" as text)


# ---- new: one probe per host, several watches -----------------------------------------------------------------------
class OneProbePerHost(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        (self.root / "data").mkdir()
        make_db(self.root / "data" / "scan.sqlite", [("both.one.test", "PHP", "8.2.30", "2030-11-04", "present"),
                                                     ("both.one.test", "nginx", "1.18.0", "2030-11-04", "present")])

    def tearDown(self):
        shutil.rmtree(self.root)

    def test_two_watches_on_the_same_host_send_one_request_set(self):
        f = StubFetch({"https://both.one.test/": ok({"Server": "nginx/1.18.0", "X-Powered-By": "PHP/8.2.34"}),
                       "http://both.one.test/": ok({"Server": "nginx/1.18.0", "X-Powered-By": "PHP/8.2.34"})})
        ws = [watch("php-w", hosts=["both.one.test"]), watch("nginx-w", product="nginx", floors={"1.24": 0, "1.26": 0}),
              watch("php-w2", floors={"8.2": 20})]
        self.assertEqual(P.run(args(self.root, ws), now=DAY1, fetch=f), P.EXIT_OK)
        self.assertEqual(sorted(f.calls), ["http://both.one.test/", "https://both.one.test/"])     # once per scheme, not 3x
        got = {wid: json.loads((out_dir(self.root, wid) / "latest.json").read_text())["hosts"][0] for wid in ("php-w", "nginx-w", "php-w2")}
        self.assertEqual((got["php-w"]["version"], got["php-w"]["verdict"]), ("8.2.34", "FAIL"))
        self.assertEqual((got["php-w2"]["version"], got["php-w2"]["verdict"]), ("8.2.34", "PASS"))
        self.assertEqual((got["nginx-w"]["version"], got["nginx-w"]["verdict"], got["nginx-w"]["read_from"]),
                         ("1.18.0", "FAIL", "https server"))
        self.assertIn("no fixed release on this branch", got["nginx-w"]["reason"])

    def test_live_probe_counts_curl_calls(self):
        # the same check through the real curl path (subprocess replaced): 2 watches, 1 host -> 2 curl calls
        root = self.root
        (root / "scope").mkdir()
        (root / "scope" / "domains.txt").write_text("one.test\n")
        verified_scope(root / "scope", "one.test")
        proof_passed(root / "runs" / "vw-1", "one.test")
        cmds = []
        import subprocess
        def fake_run(cmd, **kw):
            cmds.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, "HTTP/1.1 200 OK\r\nServer: nginx/1.26.1\r\nX-Powered-By: PHP/8.3.36\r\n\r\n", "")
        ws = [watch("a-w", hosts=["both.one.test"]), watch("b-w", product="nginx", floors={"1.26": 0}, hosts=["both.one.test"])]
        with unittest.mock.patch.object(P.subprocess, "run", side_effect=fake_run), \
             unittest.mock.patch.object(P.SF, "system_resolve", side_effect=lambda h: ["8.8.8.8"]):
            self.assertEqual(P.run(args(root, ws), now=DAY1), P.EXIT_OK)
        self.assertEqual(len(cmds), 2)
        self.assertTrue(all(c[0] == "curl" and c[-1] in ("https://both.one.test/", "http://both.one.test/") for c in cmds))
        self.assertTrue(all("-X" not in c and "--data" not in c and "-d" not in c and "-I" not in c for c in cmds))


# ---- new: what in the output came from a target -----------------------------------------------------------------------
class TargetDerived(unittest.TestCase):
    MARK = "zqxmark"

    def test_target_text_appears_only_at_the_declared_paths(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root)
        (root / "data").mkdir()
        m = self.MARK
        # the marker in every header value, the status line, the scan database's version and the run id
        make_db(root / "data" / "scan.sqlite", [("a.one.test", "PHP", f"8.2.1{m}", "2030-11-04", "present"),
                                                ("b.one.test", "PHP", f"<{m}>", "2030-11-04", "present")])
        hdrs = {"Server": f"nginx/1.2.3 {m} <script>{m}</script>", "X-Powered-By": f"PHP/8.2.34 {m}",
                "Location": f"https://a.one.test/{m}", f"X-{m}": m}
        f = StubFetch({"https://a.one.test/": ok(hdrs, 302), f"https://a.one.test/{m}": ok(hdrs, 200),
                       "http://a.one.test/": {"status": None, "headers": {}, "error": m},
                       "https://b.one.test/": ok({"Server": m * 300})})
        self.assertEqual(P.run(args(root), now=DAY1, fetch=f), P.EXIT_OK)
        doc = json.loads((out_dir(root) / "latest.json").read_text())
        self.assertEqual(doc["target_derived"], ["hosts[].server"])
        found = []

        def walk(v, path):
            if isinstance(v, dict):
                for k, x in v.items():
                    self.assertNotIn(m, k)
                    walk(x, f"{path}.{k}" if path else k)
            elif isinstance(v, list):
                for x in v:
                    walk(x, path + "[]")
            elif isinstance(v, str) and m in v:
                found.append(path)
        walk(doc, "")
        self.assertEqual(set(found), {"hosts[].server"})
        rows = {h["hostname"]: h for h in doc["hosts"]}
        self.assertLessEqual(max(len(h["server"] or "") for h in doc["hosts"]), P.SERVER_CAP)
        self.assertIsNone(rows["a.one.test"]["scan_db_version"])      # "8.2.1<marker>" is not a strict version
        self.assertEqual(rows["a.one.test"]["version"], "8.2.34")
        for h in doc["hosts"]:
            self.assertTrue(h["https_status"] is None or 100 <= h["https_status"] <= 599)

    def test_status_codes_are_parsed_strictly(self):
        self.assertEqual(P.parse_head_dump("HTTP/1.1 999 X\r\nServer: a\r\n")[0], None)
        self.assertEqual(P.parse_head_dump("HTTP/1.1 2000 X\r\n")[0], None)
        self.assertEqual(P.parse_head_dump("HTTP/1.1 20x X\r\n")[0], None)
        self.assertEqual(P.parse_head_dump("HTTP/1.1 204 X\r\nSet-Cookie: a=b\r\nServer: s\r\n")[1], {"server": "s"})

    def test_server_text_is_redacted_and_has_no_control_characters(self):
        key = "AKIA" + "IOSFODNN7" + "EXAMPLE"      # key-shaped, assembled at run time (never stored whole)
        v = P.clean_text("Apache\x1b[31m token=" + key + " " + "x" * 500)
        self.assertLessEqual(len(v), P.SERVER_CAP)
        self.assertNotIn("\x1b", v)
        self.assertNotIn(" ", v)
        self.assertNotIn(key, v)


if __name__ == "__main__":
    unittest.main()
