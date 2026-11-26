import json, os, shutil, sys, tempfile, unittest
sys.path.insert(0, os.path.dirname(__file__))
import ingest as I
import redact as R

# Synthetic nuclei JSONL records (invented hosts and addresses; nothing here is a real scan result).
def rec(tid, host, severity, tags=(), matched=None, cves=None):
    d = {"template-id": tid, "host": host, "matched-at": matched or host,
         "info": {"name": tid, "severity": severity, "tags": list(tags)}}
    if cves:
        d["info"]["classification"] = {"cve-id": cves}
    return d

class TestNormNuclei(unittest.TestCase):
    def run_dir(self, records, filename="nuclei_dns.jsonl"):
        d = tempfile.mkdtemp()
        with open(os.path.join(d, filename), "w") as f:
            for r in records:
                f.write(json.dumps(r) + "\n")
        return d

    def kinds(self, records):
        return [(k, h, p.get("template") or p.get("check_id")) for k, h, p in I.norm_nuclei(self.run_dir(records), {})]

    def test_dns_fingerprints_become_tech_not_findings(self):
        out = self.kinds([
            rec("dns-internal-ip-disclosure", "box1.example.test", "info", tags=("dns", "internal")),
            rec("aaaa-fingerprint", "box1.example.test", "info", tags=("dns", "aaaa")),
            rec("ec2-detection", "box1.example.test", "info", tags=("dns", "aws")),
        ])
        self.assertEqual([k for k, _, _ in out], ["tech", "tech", "tech"])

    def test_unknown_severity_noise_template_is_tech(self):
        # nuclei reports severity "unknown" for dns-rebinding; it used to slip past the info-only gate
        out = self.kinds([rec("dns-rebinding", "box2.example.test", "unknown", tags=("dns", "rebinding"))])
        self.assertEqual(out, [("tech", "box2.example.test", "dns-rebinding")])

    def test_fp_pass_output_is_read_and_routed_to_tech(self):
        # the nuclei "fp" pass (recon.sh, -tags tech -severity info) writes nuclei_fp.jsonl; every row is inventory
        d = self.run_dir([rec("tech-detect", "www.example.test", "info", tags=("tech",), matched="https://www.example.test")], "nuclei_fp.jsonl")
        out = list(I.norm_nuclei(d, {}))
        self.assertEqual([(k, h, p.get("template")) for k, h, p in out], [("tech", "www.example.test", "tech-detect")])

    def test_real_finding_still_a_finding(self):
        out = list(I.norm_nuclei(self.run_dir([
            rec("elasticbeanstalk-takeover", "shop.example.test", "high", tags=("dns", "takeover"),
                matched="shop.example.test"),
            rec("dns-rebinding", "shop.example.test", "unknown", tags=("dns",), cves=["CVE-2099-0001"]),
        ]), {"shop.example.test": "cdn_fronted"}))
        kinds = [(k, p.get("check_id")) for k, _, p in out]
        self.assertEqual(kinds, [("finding", "elasticbeanstalk-takeover"), ("finding", "dns-rebinding")])
        self.assertEqual(out[0][2]["asset_class"], "cdn_fronted")
        self.assertEqual(out[0][2]["severity"], "high")

class TestTriageStorage(unittest.TestCase):
    def db(self):
        import sqlite3
        db = sqlite3.connect(":memory:")
        self.addCleanup(db.close)
        db.executescript(I.SCHEMA)
        return db, db.cursor()

    def test_migrate_adds_exposure_once(self):
        import sqlite3
        db = sqlite3.connect(":memory:")
        self.addCleanup(db.close)
        db.execute("CREATE TABLE runs(seq INTEGER PRIMARY KEY, run_id TEXT, inventory_only INTEGER)")
        db.execute("CREATE TABLE finding_observations(run_id TEXT, finding_key TEXT, band TEXT)")
        cur = db.cursor(); I.migrate(cur); I.migrate(cur)
        cols = [r[1] for r in cur.execute("PRAGMA table_info(finding_observations)")]
        self.assertEqual(cols[-3:], ["verdict", "verification", "exposure"])

    def test_carry_triage_only_for_carried_keys(self):
        db, cur = self.db()
        for run in ("r1", "r2"):
            for k in ("a", "b"):
                cur.execute("INSERT INTO finding_observations(run_id, finding_key, band) VALUES(?,?,?)", (run, k, "High"))
        cur.execute("INSERT INTO finding_triage VALUES('r1','a','credential','old a','fix a','[]','[]',0,'t')")
        cur.execute("INSERT INTO finding_triage VALUES('r1','b','internal','old b','fix b','[]','[]',0,'t')")
        cur.execute("INSERT INTO finding_triage VALUES('r2','a','nothing','new a','fix a2','[]','[]',0,'t')")
        self.assertEqual(I.carry_triage(cur, "r2", "r1", {"a"}), 1)
        got = dict(cur.execute("SELECT finding_key, summary FROM finding_triage WHERE run_id='r2'").fetchall())
        self.assertEqual(got, {"a": "new a", "b": "old b"})


# ---------------------------------------------------------------- "fixed" needs coverage
class TestFixedRule(unittest.TestCase):
    COV = {"nuclei": {"a.example.test"}, "dns": set(), "http": set(), "nmap": set(), "sslscan": set()}

    def test_pure_rule(self):
        self.assertEqual(I.fixed_allowed("nuclei", "a.example.test", ["exposure"], self.COV, "safe"), (True, None))
        self.assertFalse(I.fixed_allowed("nuclei", "b.example.test", ["exposure"], self.COV, "safe")[0])   # skipped by a control
        self.assertFalse(I.fixed_allowed("nmap", "a.example.test", [], self.COV, "safe")[0])
        self.assertFalse(I.fixed_allowed("nuclei", "a.example.test", ["sqli", "cve"], self.COV, "safe")[0])
        self.assertTrue(I.fixed_allowed("nuclei", "a.example.test", ["sqli", "cve"], self.COV, "active")[0])
        self.assertTrue(I.fixed_allowed("nmap", "b.example.test", [], None, None)[0])          # no coverage data: old rule
        self.assertTrue(I.fixed_allowed("nuclei", "b.example.test", ["xss"], None, None)[0])

    def test_load_coverage(self):
        d = tempfile.mkdtemp()
        self.assertIsNone(I.load_coverage(d, {}))
        os.makedirs(os.path.join(d, "coverage"))
        with open(os.path.join(d, "coverage", "nuclei.txt"), "w") as f:
            f.write("a.example.test\n")
        cov = I.load_coverage(d, {"coverage": {"nuclei": 1}})
        self.assertEqual(cov["nuclei"], {"a.example.test"})
        self.assertEqual(cov["nmap"], set())
        with open(os.path.join(d, "coverage", "http.txt"), "w") as f:
            f.write("a.example.test\n")
        with open(os.path.join(d, "held_back.json"), "w") as f:
            json.dump({"hosts": {"a.example.test": "address-changed"}}, f)
        cov = I.load_coverage(d, {"coverage": {"nuclei": 1}})
        self.assertEqual(cov["nuclei"], set())                  # held back: not covered by any active source
        self.assertEqual(cov["http"], {"a.example.test"})       # the web inventory did look at it


class TestFixedEndToEnd(unittest.TestCase):
    """Two offline ingests: the first run observes findings, the second observes none."""
    HOSTS = ("a.example.test", "b.example.test")

    def setUp(self):
        self.root = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.root, "data"))
        os.makedirs(os.path.join(self.root, "scope"))

    def tearDown(self):
        R.set_scope_suffixes([])      # ingest registers the scope's domains process-wide
        shutil.rmtree(self.root, ignore_errors=True)

    def make_run(self, run_id, findings, coverage=None, profile=None):
        d = os.path.join(self.root, "runs", run_id)
        os.makedirs(d)
        with open(os.path.join(d, "assets.jsonl"), "w") as f:
            for h in self.HOSTS:
                f.write(json.dumps({"hostname": h, "apex": "example.test", "class": "unverified", "ips": ["8.8.8.8"],
                                    "cnames": [], "endpoints": [], "reason": "x"}) + "\n")
        with open(os.path.join(d, "apexes.txt"), "w") as f:
            f.write("example.test\n")
        with open(os.path.join(d, "nuclei_owned.jsonl"), "w") as f:
            for h, tid, tags in findings:
                f.write(json.dumps(rec(tid, h, "high", tags=tags, matched=f"https://{h}/")) + "\n")
        m = {"run_id": run_id, "inventory_only": False, "nuclei_passes": "generic,tech,tp,dns,fp",
             "started": run_id + "T00:00:00Z", "finished": run_id + "T01:00:00Z",
             "phases": [{"phase": n, "rc": 0, "start": "s", "end": "e"} for n in range(1, 9)]}
        if coverage is not None:
            m["coverage"] = {k: len(v) for k, v in coverage.items()}
            os.makedirs(os.path.join(d, "coverage"))
            for k, v in coverage.items():
                with open(os.path.join(d, "coverage", k + ".txt"), "w") as f:
                    f.write("".join(h + "\n" for h in v))
        if profile:
            m["check_profile"] = profile
        with open(os.path.join(d, "manifest.json"), "w") as f:
            json.dump(m, f)

    def ingest(self, run_id):
        import contextlib, io
        argv = sys.argv
        sys.argv = ["ingest.py", "--root", self.root, "--run-id", run_id, "--offline"]
        try:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                I.main()
        finally:
            sys.argv = argv

    def status(self):
        import sqlite3
        db = sqlite3.connect(os.path.join(self.root, "data", "scan.sqlite"))
        try:
            return dict(db.execute("SELECT hostname || ' ' || check_id, status FROM findings").fetchall())
        finally:
            db.close()

    FINDINGS = [("a.example.test", "exposed-panel", ("exposure", "panel")),
                ("b.example.test", "exposed-panel", ("exposure", "panel")),
                ("a.example.test", "sqli-error", ("sqli", "injection"))]

    def test_skipped_host_and_active_tags(self):
        self.make_run("2030-01-01", self.FINDINGS, coverage={"nuclei": self.HOSTS}, profile="active")
        self.ingest("2030-01-01")
        # second run: b was skipped by a scope control; safe profile
        self.make_run("2030-02-01", [], coverage={"nuclei": ["a.example.test"]}, profile="safe")
        self.ingest("2030-02-01")
        self.assertEqual(self.status(), {"a.example.test exposed-panel": "fixed", "b.example.test exposed-panel": "open",
                                         "a.example.test sqli-error": "open"})
        # an active run that tested a marks the active-only finding fixed
        self.make_run("2030-03-01", [], coverage={"nuclei": ["a.example.test"]}, profile="active")
        self.ingest("2030-03-01")
        self.assertEqual(self.status()["a.example.test sqli-error"], "fixed")
        self.assertEqual(self.status()["b.example.test exposed-panel"], "open")

    def test_held_back_hosts_are_not_covered(self):
        self.make_run("2030-01-01", self.FINDINGS[:2], coverage={"nuclei": self.HOSTS})
        self.ingest("2030-01-01")
        # second run: b is held back (not in the approved inventory); even if a coverage file named it, it was not tested
        self.make_run("2030-02-01", [], coverage={"nuclei": self.HOSTS})
        with open(os.path.join(self.root, "runs", "2030-02-01", "held_back.json"), "w") as f:
            json.dump({"inventory_run": "inv-1", "hosts": {"b.example.test": "new-since-approved-inventory"}}, f)
        self.ingest("2030-02-01")
        self.assertEqual(self.status(), {"a.example.test exposed-panel": "fixed", "b.example.test exposed-panel": "open"})

    def test_hosts_under_a_held_back_domain_are_not_covered(self):
        # the second run held back b's whole domain (added after the approved inventory); b is not in "hosts" (not
        # live, say) and a coverage file names it anyway: its finding still stays open
        self.make_run("2030-01-01", self.FINDINGS[:2], coverage={"nuclei": self.HOSTS})
        self.ingest("2030-01-01")
        self.make_run("2030-02-01", [], coverage={"nuclei": self.HOSTS})
        with open(os.path.join(self.root, "runs", "2030-02-01", "held_back.json"), "w") as f:
            json.dump({"inventory_run": "inv-1", "hosts": {},
                       "domains": {"scanned": ["a.example.test"], "held_back": ["b.example.test"], "pending": []}}, f)
        self.ingest("2030-02-01")
        self.assertEqual(self.status(), {"a.example.test exposed-panel": "fixed", "b.example.test exposed-panel": "open"})

    def test_dns_pass_coverage_does_not_fix_an_http_finding(self):
        # second run: the generic pass never got a or b (say httpx missed them), but the DNS-template pass looked at
        # both names; that is not a re-test of an HTTP finding
        self.make_run("2030-01-01", self.FINDINGS[:2], coverage={"nuclei": self.HOSTS})
        self.ingest("2030-01-01")
        self.make_run("2030-02-01", [], coverage={"nuclei": ["a.example.test"], "nuclei_dns": self.HOSTS, "nuclei_tp": [], "nuclei_fp": self.HOSTS})
        self.ingest("2030-02-01")
        self.assertEqual(self.status(), {"a.example.test exposed-panel": "fixed", "b.example.test exposed-panel": "open"})

    def test_failed_requests_keep_the_finding_open(self):
        self.make_run("2030-01-01", self.FINDINGS[:2], coverage={"nuclei": self.HOSTS})
        self.ingest("2030-01-01")
        self.make_run("2030-02-01", [], coverage={"nuclei": self.HOSTS, "nuclei_dns": self.HOSTS, "nuclei_tp": [], "nuclei_fp": []})
        d = os.path.join(self.root, "runs", "2030-02-01")
        with open(os.path.join(d, "nuclei_errors_generic.jsonl"), "w") as f:     # nuclei -elog: b's request for the check timed out
            f.write(json.dumps({"template": "/t/http/exposures/exposed-panel.yaml", "type": "http", "input": "https://b.example.test/.env",
                                "address": "b.example.test:443", "error": "cause=\"context deadline exceeded\"",
                                "kind": "network-temporary-error"}) + "\n")
            # another template failing on a (a TLS probe on a web port, as on every host) says nothing about this check
            f.write(json.dumps({"template": "/t/ssl/weak-cipher-suites.yaml", "type": "ssl", "input": "a.example.test:443",
                                "address": "a.example.test:443", "error": "cause=\"could not connect to host\""}) + "\n")
        with open(os.path.join(d, "nuclei_errors_dns.jsonl"), "w") as f:         # a DNS-pass error says nothing about HTTP
            f.write(json.dumps({"type": "dns", "input": "a.example.test", "address": "a.example.test", "error": "x"}) + "\n")
        self.ingest("2030-02-01")
        self.assertEqual(self.status(), {"a.example.test exposed-panel": "fixed", "b.example.test exposed-panel": "open"})

    def test_errors_on_a_representative_keep_its_siblings_open(self):
        self.make_run("2030-01-01", self.FINDINGS[:2], coverage={"nuclei": self.HOSTS})
        self.ingest("2030-01-01")
        self.make_run("2030-02-01", [], coverage={"nuclei": self.HOSTS, "nuclei_dns": [], "nuclei_tp": [], "nuclei_fp": []})
        d = os.path.join(self.root, "runs", "2030-02-01")
        with open(os.path.join(d, "nuclei_groups.json"), "w") as f:              # a represents b (same application)
            json.dump({"https://a.example.test/": ["https://a.example.test/", "https://b.example.test/"]}, f)
        with open(os.path.join(d, "nuclei_errors_tech.jsonl"), "w") as f:
            f.write(json.dumps({"template": "/t/http/exposed-panel.yaml", "type": "http", "input": "https://a.example.test/x",
                                "address": "a.example.test:443", "error": "reset"}) + "\n")
        self.ingest("2030-02-01")
        self.assertEqual(set(self.status().values()), {"open"})

    def test_a_clustered_request_failure_is_caught_by_its_path(self):
        # nuclei logged the failed GET of b's panel path under another template of the same cluster
        self.make_run("2030-01-01", self.FINDINGS[:2], coverage={"nuclei": self.HOSTS})
        self.ingest("2030-01-01")
        self.make_run("2030-02-01", [], coverage={"nuclei": self.HOSTS, "nuclei_dns": [], "nuclei_tp": [], "nuclei_fp": []})
        with open(os.path.join(self.root, "runs", "2030-02-01", "nuclei_errors_generic.jsonl"), "w") as f:
            f.write(json.dumps({"template": "/t/http/other-panel-check.yaml", "input": "https://b.example.test/",
                                "address": "b.example.test:443", "error": "timeout", "kind": "network-temporary-error"}) + "\n")
        self.ingest("2030-02-01")
        self.assertEqual(self.status(), {"a.example.test exposed-panel": "fixed", "b.example.test exposed-panel": "open"})
        self.assertEqual(I.url_path("http://h.test:80/.git/config?x=1"), "/.git/config")
        self.assertEqual(I.url_path("https://h.test"), "/")
        self.assertIsNone(I.url_path("h.test:443"))

    # -elog lines copied in shape from real lab runs (nuclei v3.11.1), host names invented. The finding fixtures match
    # at the root path ("https://<host>/").
    NON_HTTP_ERRORS = [
        {"template": "weak-cipher-suites", "type": "ssl", "input": "{h}:443", "address": "{h}:443",
         "error": "cause=\"could not connect to host\"", "kind": "unknown-error"},
        {"template": "/t/network/misconfig/ganglia-xml-grid-monitor.yaml", "type": "tcp", "input": "{h}:443", "address": "{h}:443",
         "error": "cause=\"EOF\"", "kind": "unknown-error"},
        {"template": "/t/network/detection/exposed-adb.yaml", "type": "tcp", "input": "{h}:443", "address": "{h}:443",
         "error": "cause=\"i/o timeout\"", "kind": "network-temporary-error"},
        {"template": "mDNS-enum", "type": "javascript", "input": "{h}:5353", "address": "{h}:5353", "error": "connection refused"},
    ]
    PROXY_UNREADABLE = {"template": "/t/http/misconfiguration/proxy/open-proxy-external.yaml", "type": "http",
                        "input": "https://{h}", "address": "{h}:443",
                        "error": "cause=\"ReadStatusLine: ReadVersion: expected 'H', got '<' at position 0\"", "kind": "unknown-error"}

    def write_errors(self, run_id, lines, host="b.example.test"):
        with open(os.path.join(self.root, "runs", run_id, "nuclei_errors_generic.jsonl"), "w") as f:
            for d in lines:
                f.write(json.dumps({k: v.replace("{h}", host) for k, v in d.items()}) + "\n")

    def two_runs(self, lines):
        shutil.rmtree(self.root, ignore_errors=True)      # a fresh findings store for each pair of runs
        self.setUp()
        self.make_run("2030-01-01", self.FINDINGS[:2], coverage={"nuclei": self.HOSTS})
        self.ingest("2030-01-01")
        self.make_run("2030-02-01", [], coverage={"nuclei": self.HOSTS, "nuclei_dns": [], "nuclei_tp": [], "nuclei_fp": []})
        self.write_errors("2030-02-01", lines)
        self.ingest("2030-02-01")
        return self.status()["b.example.test exposed-panel"]

    def test_root_finding_fixed_despite_non_http_errors_and_an_unreadable_answer_at_root(self):
        # every web host logs these on every run: non-HTTP templates against a web port, and open-proxy-external's own
        # odd request at "/" getting an answer nuclei cannot read as HTTP. None says the panel check went unanswered.
        self.assertEqual(self.two_runs(self.NON_HTTP_ERRORS + [self.PROXY_UNREADABLE]), "fixed")

    def test_root_finding_open_after_a_no_answer_error_at_root_from_another_template(self):
        # a clustered GET / that timed out, logged under another template of the cluster
        timeout = {"template": "/t/http/exposures/other-root-check.yaml", "type": "http", "input": "https://{h}",
                   "address": "{h}:443", "error": "cause=\"context deadline exceeded (Client.Timeout exceeded while awaiting headers)\"",
                   "kind": "network-temporary-error"}
        self.assertEqual(self.two_runs(self.NON_HTTP_ERRORS + [self.PROXY_UNREADABLE, timeout]), "open")
        refused = dict(timeout, error="port closed or filtered", kind="network-permanent-error")
        self.assertEqual(self.two_runs([refused]), "open")
        deadline = dict(timeout, error="cause=\"context deadline exceeded\"", kind="deadline-error")
        self.assertEqual(self.two_runs([deadline]), "open")

    def test_unknown_error_on_the_findings_own_template_keeps_it_open(self):
        own = dict(self.PROXY_UNREADABLE, template="/t/http/exposures/exposed-panel.yaml")
        self.assertEqual(self.two_runs([own]), "open")

    def test_a_line_without_a_kind_adds_no_path(self):
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "nuclei_errors_generic.jsonl"), "w") as f:
            f.write(json.dumps({"template": "/t/http/other-root-check.yaml", "type": "http", "input": "https://a.example.test/",
                                "address": "a.example.test:443", "error": "timeout"}) + "\n")
            f.write(json.dumps(dict(self.PROXY_UNREADABLE, input="https://a.example.test/x", address="a.example.test:443")) + "\n")
            f.write(json.dumps({"template": "/t/http/third.yaml", "type": "http", "input": "https://a.example.test/y",
                                "address": "a.example.test:443", "error": "timeout", "kind": "network-temporary-error"}) + "\n")
        e = I.load_nuclei_errors(d)
        self.assertEqual(e["http"], {"a.example.test": {"other-root-check", "open-proxy-external", "third", "path:/y"}})
        # and end to end: a no-kind failure at "/" from another template does not hold the root finding open
        self.assertEqual(self.two_runs([{"template": "/t/http/other-root-check.yaml", "type": "http", "input": "https://{h}/",
                                         "address": "{h}:443", "error": "timeout"}]), "fixed")

    def test_a_failed_pass_fixes_nothing_it_would_have_observed(self):
        self.make_run("2030-01-01", self.FINDINGS[:2], coverage={"nuclei": self.HOSTS})
        self.ingest("2030-01-01")
        self.make_run("2030-02-01", [], coverage={"nuclei": self.HOSTS, "nuclei_dns": self.HOSTS, "nuclei_tp": [], "nuclei_fp": []})
        mp = os.path.join(self.root, "runs", "2030-02-01", "manifest.json")
        with open(mp) as f:
            m = json.load(f)
        m["nuclei_failed_passes"] = ["tech"]
        with open(mp, "w") as f:
            json.dump(m, f)
        self.ingest("2030-02-01")
        self.assertEqual(set(self.status().values()), {"open"})

    def test_dns_finding_fixed_by_the_dns_pass_only(self):
        d0 = os.path.join(self.root, "runs", "2030-01-01")
        self.make_run("2030-01-01", [], coverage={"nuclei": [], "nuclei_dns": self.HOSTS, "nuclei_tp": [], "nuclei_fp": []})
        with open(os.path.join(d0, "nuclei_dns.jsonl"), "w") as f:
            f.write(json.dumps({**rec("dangling-cname", "a.example.test", "high", tags=["dns", "takeover"]), "type": "dns"}) + "\n")
        self.ingest("2030-01-01")
        self.assertEqual(self.status(), {"a.example.test dangling-cname": "open"})
        self.make_run("2030-02-01", [], coverage={"nuclei": self.HOSTS, "nuclei_dns": [], "nuclei_tp": [], "nuclei_fp": []})
        self.ingest("2030-02-01")
        self.assertEqual(self.status(), {"a.example.test dangling-cname": "open"})     # HTTP passes cannot fix it
        self.make_run("2030-03-01", [], coverage={"nuclei": [], "nuclei_dns": self.HOSTS, "nuclei_tp": [], "nuclei_fp": []})
        self.ingest("2030-03-01")
        self.assertEqual(self.status(), {"a.example.test dangling-cname": "fixed"})    # the DNS pass re-tested it (type kept)

    def test_template_id_read_from_the_template_file(self):
        t = tempfile.mkdtemp()
        os.makedirs(os.path.join(t, "http"))
        with open(os.path.join(t, "http", "odd-name.yaml"), "w") as f:
            f.write("# comment\nid: real-template-id\ninfo:\n  name: x\n")
        outside = os.path.join(tempfile.mkdtemp(), "other.yaml")
        with open(outside, "w") as f:
            f.write("id: should-not-be-read\n")
        cache = {}
        self.assertEqual(I.template_id(os.path.join(t, "http", "odd-name.yaml"), t, cache), "real-template-id")
        self.assertEqual(I.template_id(outside, t, cache), "other")                       # outside the folder: file name only
        self.assertEqual(I.template_id(os.path.join(t, "http", "gone.yaml"), t, cache), "gone")
        self.assertEqual(I.template_id(os.path.join(t, "http", "odd-name.yaml"), None, {}), "odd-name")
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "nuclei_errors_generic.jsonl"), "w") as f:
            f.write(json.dumps({"template": os.path.join(t, "http", "odd-name.yaml"), "address": "a.example.test:80"}) + "\n")
            f.write(json.dumps({"address": "b.example.test:80", "error": "no template"}) + "\n")
            f.write("not json\n")
        e = I.load_nuclei_errors(d, t)
        self.assertEqual(e["http"], {"a.example.test": {"real-template-id"}, "b.example.test": {"*"}})

    def test_nuclei_kind_and_old_runs(self):
        self.assertEqual(I.nuclei_kind(json.dumps({"type": "dns"}), "owned"), "dns")
        self.assertEqual(I.nuclei_kind(json.dumps({"type": "http"}), "third_party"), "tp")
        self.assertEqual(I.nuclei_kind(json.dumps({"type": "http"}), "unverified"), "http")
        self.assertEqual(I.nuclei_kind(None, "owned"), "http")
        old = {"nuclei": {"a.example.test"}}           # a run from before the per-pass coverage: everything under nuclei
        self.assertTrue(I.fixed_allowed("nuclei", "a.example.test", [], old, "safe", kind="dns")[0])
        new = {"nuclei": {"a.example.test"}, "nuclei_dns": set()}
        self.assertEqual(I.fixed_allowed("nuclei", "a.example.test", [], new, "safe", kind="dns"), (False, "nuclei_dns: host not tested"))
        err = {"http": {"a.example.test": {"exposed-panel"}}}
        self.assertEqual(I.fixed_allowed("nuclei", "a.example.test", [], old, "safe", errors=err, check_id="exposed-panel:matcher-1"),
                         (False, "nuclei http: requests for this check to this host failed this run"))
        self.assertTrue(I.fixed_allowed("nuclei", "a.example.test", [], old, "safe", errors=err, check_id="git-config")[0])
        self.assertFalse(I.fixed_allowed("nuclei", "a.example.test", [], old, "safe", errors={"http": {"a.example.test": {"*"}}},
                                         check_id="git-config")[0])       # an error without a template blocks every check

    def test_no_coverage_data_keeps_old_rule(self):
        self.make_run("2030-01-01", self.FINDINGS)
        self.ingest("2030-01-01")
        self.make_run("2030-02-01", [])
        self.ingest("2030-02-01")
        self.assertEqual(set(self.status().values()), {"fixed"})

    def test_malformed_own_networks_file_is_one_clear_error(self):
        import unittest.mock
        import fingerprint as F
        bad = os.path.join(self.root, "own_networks.txt")
        with open(bad, "w") as f:
            f.write("# own networks\nexample-colo Example colo\n")
        self.make_run("2030-01-01", [])
        with unittest.mock.patch.object(F, "OWN_NETWORKS", None), unittest.mock.patch.object(F, "OWN_NETWORKS_FILE", bad):
            with self.assertRaises(SystemExit) as cm:
                self.ingest("2030-01-01")
        self.assertEqual(str(cm.exception.code), f"error: {bad}:2: expected 'substring<TAB>label', got 'example-colo Example colo'")
        self.assertFalse(os.path.exists(os.path.join(self.root, "data", "scan.sqlite")))   # stopped before any database work

    def test_ingest_registers_scope_domains_for_hostnames(self):
        with open(os.path.join(self.root, "scope", "domains.txt"), "w") as f:
            f.write("example.test\nalpha.example\n")
        self.assertEqual(R.internal_names("db1.alpha.example"), [])
        self.make_run("2030-01-01", [])
        self.ingest("2030-01-01")
        self.assertEqual(sorted(R.scope_suffixes()), ["alpha.example", "example.test"])
        self.assertEqual(R.internal_names("see db1.alpha.example and a.example.test"), ["db1.alpha.example", "a.example.test"])

if __name__ == "__main__":
    unittest.main()
