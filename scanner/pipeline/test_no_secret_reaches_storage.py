"""End to end: canary secrets planted in every field of every tool's output never reach storage, reports or logs.

A synthetic run directory holds every file ingest reads. Distinct, obviously fake canaries (assembled at run time
so no key-shaped literal sits in this file) are planted across every field that can carry target text: response
body, request, replay command, extracted results, matcher output, page title, header values, cookie values,
redirect URLs with signed parameters, port-scanner script output, technology-fingerprint strings, DNS TXT values and
certificate fields. Verification and triage get injected fetch and probe functions whose responses carry canaries
too, so both stages run fully without the network. Then ingest, the report and the version probe run, and no
canary may appear, in any encoding checked here, in the database file, any column, the HTML report, any CSV, the
version-probe result file, or anything printed. The findings must still be there and useful. Both evidence levels.
"""
import base64, contextlib, glob, html, io, json, os, shutil, sqlite3, sys, tempfile, unittest
from unittest import mock
from urllib.parse import quote, quote_plus
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ingest as I  # noqa: E402
import report as RP  # noqa: E402
import version_watch as P  # noqa: E402
import redact as R  # noqa: E402

HOST = "app.alpha.example"
APEX = "alpha.example"
IP = "192.0.2.10"


def letters(n, width=4):
    s = ""
    for _ in range(width):
        s = chr(97 + n % 26) + s
        n //= 26
    return s


class Canaries:
    """One distinct canary per (format, field). Every value is fake and recorded with where it was planted."""
    HIGH = "x7Rq/Zp3Lw+Vb9Nm2Tt6Ys1Hd8Jc4Gf0Ka5Ue"

    def __init__(self):
        self.n = 0
        self.where = {}

    def _new(self, value, field, fmt):
        self.where[value] = f"{fmt} in {field}"
        return value

    def key_id(self, field):
        self.n += 1
        return self._new("AKIA" + "CANARYFAKE" + f"{self.n:06d}", field, "key id")

    def secret_key(self, field):
        self.n += 1
        return self._new((f"Ck{self.n:04d}" + self.HIGH)[:40], field, "secret key")

    def jwt(self, field):
        self.n += 1
        payload = base64.urlsafe_b64encode(json.dumps({"sub": f"canary-{self.n}"}).encode()).decode().rstrip("=")
        return self._new("eyJ" + "hbGciOiJIUzI1NiJ9" + "." + payload + ".Q2FuYXJ5U2lnRmFrZQ" + letters(self.n), field, "JWT")

    def session(self, field):
        self.n += 1
        return self._new(f"canarysess{self.n:04d}Q9z", field, "session cookie")

    def lower_pw(self, field):
        self.n += 1
        return self._new("canarylowpw" + letters(self.n), field, "lowercase password")

    def signature(self, field):
        self.n += 1
        return self._new(f"canarysig{self.n:04d}feedface", field, "URL signature")

    def basic(self, field):
        self.n += 1
        pw = self._new(f"canarybasicpw{self.n:04d}", field, "basic auth password")
        tok = base64.b64encode(f"canaryuser:{pw}".encode()).decode()
        return self._new(tok, field, "basic auth token"), pw

    def key_core(self, field):
        self.n += 1
        return self._new(f"MIICanaryKeyCore{self.n:04d}FakeFake", field, "private key block")

    def email_local(self, field):
        self.n += 1
        return self._new(f"canarymailbox{self.n:04d}", field, "email address")

    # composites
    def signed_url(self, field, host=HOST, path="/f.pdf"):
        return (f"https://{host}{path}?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential={self.key_id(field)}%2F20300101%2Fus-east-1"
                f"&X-Amz-Signature={self.signature(field)}&X-Amz-Expires=300")

    def env_file(self, field):
        tok, _ = self.basic(field)
        return (f"APP_ENV=production\nDB_PASSWORD={self.lower_pw(field)}\nAWS_ACCESS_KEY_ID={self.key_id(field)}\n"
                f"AWS_SECRET_ACCESS_KEY={self.secret_key(field)}\nJWT_SAMPLE={self.jwt(field)}\n"
                f"SESSION_COOKIE=PHPSESSID={self.session(field)}\nDOWNLOAD_URL={self.signed_url(field)}\n"
                f"UPSTREAM_AUTH=Basic {tok}\n-----BEGIN RSA PRIVATE KEY-----\n{self.key_core(field)}\n-----END RSA PRIVATE KEY-----\n"
                f"bare {self.secret_key(field)} value\n")

    def all_values(self):
        return list(self.where)


def forms(c):
    """The encodings a canary is looked for in: plain, lower case, URL, JSON, HTML, CSV and base64 at three alignments."""
    out = {c, c.lower(), quote(c, safe=""), quote_plus(c), json.dumps(c)[1:-1], html.escape(c), c.replace('"', '""')}
    raw = c.encode()
    for off in range(3):
        enc = base64.b64encode(b"\x00" * off + raw).decode()
        inner = enc[4 if off else 0:-4]
        if len(inner) >= 12:
            out.add(inner)
    return out


class Stub:
    """fetch(url, headers, data=None) -> (status, final_url, body) for verify and triage; every body carries canaries."""
    def __init__(self, cn):
        self.cn, self.calls, self.bodies = cn, [], {}

    def __call__(self, url, headers, data=None):
        self.calls.append(url)
        if url not in self.bodies:
            path = url.split("://", 1)[-1].split("/", 1)[-1]
            if path.endswith("HEAD") and "logs/" not in path:
                body = "ref: refs/heads/main\n"
            elif path.endswith("logs/HEAD"):
                body = ("0" * 40 + " " + "1" * 40 + f" Dev <{self.cn.email_local('git log')}@corp.example> 1900000000 +0000\t"
                        f"clone: from https://deploy:{self.cn.lower_pw('git log remote')}@git.alpha.example/app.git\n")
            elif path.endswith("index"):
                return 200, url, b"DIRC" + (2).to_bytes(4, "big") + (3).to_bytes(4, "big") + b"\x00" * 40
            else:
                body = self.cn.env_file(f"fetched {path}") + f"contact {self.cn.email_local('fetched body')}@corp.example\n"
            self.bodies[url] = body
        return 200, url, self.bodies[url].encode()


class TestNoSecretReachesStorage(unittest.TestCase):
    RUN = "2030-06-01"

    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root, True)
        self.cn = Canaries()
        self.out, self.err = io.StringIO(), io.StringIO()

    def tearDown(self):
        R.set_scope_suffixes([])

    # ------------------------------------------------------------ the synthetic run
    def write(self, name, text):
        p = os.path.join(self.run_dir, name)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(text)

    def jsonl(self, name, rows):
        self.write(name, "".join(json.dumps(r) + "\n" for r in rows))

    def build_run(self):
        cn = self.cn
        for d in ("data", "scope", "reports"):
            os.makedirs(os.path.join(self.root, d), exist_ok=True)
        with open(os.path.join(self.root, "scope", "domains.txt"), "w") as f:
            f.write(APEX + "\n")
        # the version watch: the example PHP watch with two extra hosts of its own (one that does not answer)
        self.watches = os.path.join(self.root, "watches.json")
        with open(self.watches, "w") as f:
            json.dump([{"id": "php-example", "name": "PHP example", "product": "php", "cves": ["CVE-2099-10001"],
                        "floors": {"8.2": 35, "8.3": 36}, "hosts": [HOST, "down.alpha.example"]}], f)
        self.run_dir = os.path.join(self.root, "runs", self.RUN)
        os.makedirs(self.run_dir)
        base = f"https://{HOST}"
        self.write("manifest.json", json.dumps({"run_id": self.RUN, "inventory_only": False, "nuclei_passes": "generic,tech,tp,dns,fp",
                                                "started": self.RUN + "T00:00:00Z", "finished": self.RUN + "T01:00:00Z",
                                                "tools": {"nuclei": "3.0.0"},
                                                "phases": [{"phase": n, "name": f"p{n}", "rc": 0, "start": "s", "end": "e"} for n in range(1, 10)]}))
        self.write("apexes.txt", APEX + "\n")
        # inventory: the host is live (owned) and its endpoint record carries canaries too
        self.jsonl("assets.jsonl", [{"hostname": HOST, "apex": APEX, "class": "owned", "ips": [IP], "cnames": [], "reason": "owned range",
                                     "endpoints": [{"url": base, "status": 200, "title": f"Welcome {cn.jwt('assets title')}",
                                                    "server": f"nginx {cn.key_id('assets server')}", "final_url": cn.signed_url("assets final_url"),
                                                    "tls": {"not_after": "2031-01-01T00:00:00Z"}}]},
                                    {"hostname": APEX, "apex": APEX, "class": "owned", "ips": [IP], "cnames": [], "reason": "apex", "endpoints": []}])
        # nuclei: an exposure (verify + triage), a listing (verify fetches), a git config (triage fetches), tech and DNS rows
        tok, _ = cn.basic("request Authorization")
        env_body = cn.env_file("recorded response body")
        self.jsonl("nuclei_tp.jsonl", [{"template-id": "wp-backup-file", "info": {"name": "WordPress backup", "severity": "low", "tags": ["wordpress", "backup"]},
                                        "host": base, "port": "443", "matched-at": f"{base}/wp-content/uploads/2023/01/backup-2023-01-15.sql",
                                        "response": "HTTP/1.1 404 Not Found\r\n\r\n"}])
        exposure = {
            "template-id": "exposed-env-file", "template-path": "/home/scanner/t.yaml",
            "info": {"name": f"Exposed env file {cn.key_id('template name')}", "severity": "high", "tags": ["exposure", "config"],
                     "reference": [cn.signed_url("reference", host="docs.example.test")],
                     "classification": {"cve-id": ["CVE-2099-0001"], "cvss-score": 7.5, "cvss-metrics": f"CVSS:3.1/{cn.secret_key('cvss metrics')}"}},
            "type": "http", "host": base, "port": "443", "scheme": "https", "ip": IP,
            "matched-at": f"{base}/.env?token={cn.session('matched-at token')}&sig={cn.signature('matched-at sig')}",
            "matcher-name": cn.jwt("matcher-name"), "matcher-status": True, "extractor-name": f"x-{cn.jwt('extractor-name')}",
            "extracted-results": [f"DB_PASSWORD={cn.lower_pw('extracted')}", cn.jwt("extracted"), cn.key_id("extracted"),
                                  cn.secret_key("extracted bare"), cn.signed_url("extracted url")],
            "request": (f"GET /.env HTTP/1.1\r\nHost: {HOST}\r\nAuthorization: Basic {tok}\r\n"
                        f"Cookie: PHPSESSID={cn.session('request cookie')}; theme=dark\r\nX-Api-Key: {cn.key_id('request header')}\r\n\r\n"),
            "response": (f"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nServer: nginx\r\nX-Powered-By: PHP/8.1.2\r\n"
                         f"Set-Cookie: sid={cn.session('response Set-Cookie')}; Path=/; HttpOnly\r\nX-Debug-Token: {cn.secret_key('response header')}\r\n"
                         f"Location: {cn.signed_url('response Location')}\r\n\r\n{env_body}"),
            "curl-command": f"curl -X 'GET' -H 'Cookie: PHPSESSID={cn.session('curl-command')}' -H 'Authorization: Bearer {cn.jwt('curl-command')}' '{base}/.env'",
            "timestamp": "2030-06-01T00:30:00Z", "metadata": {"note": cn.lower_pw("metadata")},
        }
        listing = {"template-id": "configuration-listing", "info": {"name": "Configuration listing", "severity": "medium", "tags": ["exposure", "listing", "config"]},
                   "host": base, "matched-at": f"{base}/config/", "port": "443",
                   "request": f"GET /config/ HTTP/1.1\r\nHost: {HOST}\r\nCookie: sid={cn.session('listing request')}\r\n\r\n",
                   "response": ("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><head><title>Index of /config</title></head><body><ul>"
                                "<li><a href=\".env\">.env</a></li><li><a href=\"settings.ini\">settings.ini</a></li></ul></body></html>")}
        git = {"template-id": "git-config", "info": {"name": "Git config", "severity": "medium", "tags": ["exposure", "git", "config"]},
               "host": base, "matched-at": f"{base}/.git/config", "port": "443",
               "response": f"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n[remote \"origin\"]\n\turl = https://deploy:{cn.lower_pw('git remote')}@git.alpha.example/app.git\n"}
        self.jsonl("nuclei_owned.jsonl", [exposure, listing, git])
        self.jsonl("nuclei_tech.jsonl", [{"template-id": "tech-detect", "info": {"name": "Tech", "severity": "info", "tags": ["tech"]},
                                          "host": base, "matched-at": base, "matcher-name": "php",
                                          "extracted-results": [f"PHP/8.1.2 {cn.jwt('tech extracted')}"]}])
        self.jsonl("nuclei_fp.jsonl", [])
        self.jsonl("nuclei_dns.jsonl", [{"template-id": "txt-fingerprint", "info": {"name": "TXT", "severity": "info", "tags": ["dns", "txt"]},
                                         "host": APEX, "matched-at": APEX,
                                         "extracted-results": [f"\"site-verification={cn.secret_key('nuclei TXT')}\"", "\"v=spf1 -all\""]}])
        self.write("nuclei_groups.json", json.dumps({base: [base, cn.signed_url("app group", host="www.alpha.example")]}))
        # httpx and whatweb: titles, headers, cookies, emails, redirects, TLS fields
        self.jsonl("httpx.jsonl", [{"url": base, "host": HOST, "port": "443", "scheme": "https", "status_code": 200,
                                    "title": f"Home {cn.key_id('httpx title')} {cn.jwt('httpx title')}", "webserver": f"nginx/1.25 {cn.secret_key('httpx webserver')}",
                                    "content_type": "text/html", "content_length": 10, "final_url": cn.signed_url("httpx final_url"),
                                    "chain_status_codes": [302, 200], "words": 1, "lines": 1, "time": "12ms",
                                    "header": {"set_cookie": f"sid={cn.session('httpx header')}"},
                                    "tls": {"subject_cn": HOST, "subject_an": [HOST], "issuer_org": [f"Canary CA {cn.key_id('httpx issuer')}"],
                                            "not_after": "2031-01-01T00:00:00Z", "serial": cn.lower_pw("httpx serial"),
                                            "fingerprint_hash": {"sha256": cn.jwt("httpx sha256")}}}])
        self.write("whatweb.json", json.dumps([{"target": base, "plugins": {
            "Cookies": {"string": [f"sid={cn.session('whatweb Cookies')}", "theme"]}, "HttpOnly": {"string": ["sid"]},
            "Email": {"string": [f"{cn.email_local('whatweb Email')}@corp.example"]},
            "UncommonHeaders": {"string": [f"x-debug-token,x-secret={cn.secret_key('whatweb UncommonHeaders')}"]},
            "RedirectLocation": {"string": [cn.signed_url("whatweb RedirectLocation")]},
            "MetaGenerator": {"string": [f"WordPress 6.4 {cn.jwt('whatweb MetaGenerator')}"]},
            "X-Powered-By": {"string": [f"PHP/8.1.2 {cn.key_id('whatweb X-Powered-By')}"]}, "PHP": {"version": ["8.1.2"]},
            "HTTPServer": {"string": [f"nginx {cn.secret_key('whatweb HTTPServer')}"]},
            "Title": {"string": [f"Home {cn.jwt('whatweb Title')}"]}}}]))
        self.write("waf.json", json.dumps([{"url": base, "detected": True, "firewall": f"GenericWAF {cn.key_id('waf name')}"}]))
        # nmap: a risky port with script output and a banner; a PTR name
        self.write("nmap.xml", f"""<?xml version="1.0"?><nmaprun><host><address addr="{IP}" addrtype="ipv4"/>
<hostnames><hostname name="ptr.alpha.example" type="PTR"/></hostnames><ports>
<port protocol="tcp" portid="3306"><state state="open" reason="syn-ack"/><service name="mysql" product="MySQL" version="8.0 {cn.key_id('nmap version')}"/>
<script id="mysql-info" output="Salt: {cn.secret_key('nmap script')} password={cn.lower_pw('nmap script')}"/>
<script id="http-cookie-flags" output="Set-Cookie: sid={cn.session('nmap script')}"/></port>
<port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/><service name="https" product="nginx"/>
<script id="http-title" output="{cn.jwt('nmap http-title')}"/></port></ports></host></nmaprun>""")
        # sslscan: certificate fields and a legacy protocol
        self.write("sslscan/app.xml", f"""<?xml version="1.0"?><document><ssltest host="{HOST}" port="443">
<protocol type="tls" version="1.0" enabled="1"/><protocol type="tls" version="1.2" enabled="1"/>
<cipher status="preferred" cipher="ECDHE-RSA-AES128-GCM-SHA256" bits="128" strength="strong"/>
<certificate type="short"><subject>CN={HOST}/OU={cn.key_id('cert subject')}</subject>
<altnames>DNS:{HOST}, URI:{html.escape(cn.signed_url('cert SAN'))}</altnames>
<issuer>O=Canary CA {cn.secret_key('cert issuer')}</issuer><pk type="RSA" bits="2048"/>
<signature-algorithm>sha256WithRSAEncryption</signature-algorithm><not-valid-before>Jan  1 00:00:00 2030 GMT</not-valid-before>
<not-valid-after>Jan  1 00:00:00 2031 GMT</not-valid-after><expired>false</expired><self-signed>false</self-signed></certificate></ssltest></document>""")
        os.rename(os.path.join(self.run_dir, "sslscan/app.xml"), os.path.join(self.run_dir, "sslscan_app.xml"))
        # dnsx: an A record and the apex's TXT records
        self.jsonl("dns.jsonl", [{"host": HOST, "all": [f"{HOST}.\t300\tIN\tA\t{IP}"]}])
        self.jsonl("dns_apex.jsonl", [{"host": APEX, "all": [f"{APEX}.\t300\tIN\tTXT\t\"verify={cn.jwt('dnsx TXT')}\"",
                                                            f"{APEX}.\t300\tIN\tTXT\t\"v=spf1 include:_spf.example.test -all\"",
                                                            f"{APEX}.\t300\tIN\tTXT\t\"api_key={cn.lower_pw('dnsx TXT')}\""]}])
        self.write("axfr.json", json.dumps([{"apex": APEX, "ns": "ns1.alpha.example", "ns_ip": "192.0.2.53", "success": True, "records": 7,
                                             "zone": f"secret.alpha.example TXT {cn.jwt('axfr extra key')}"}]))
        self.write("sources.json", json.dumps({HOST: ["subfinder", "crtsh"]}))
        self.write("asn.json", json.dumps({}))

    # ------------------------------------------------------------ running the pipeline
    def run_all(self, level):
        self.build_run()
        stub = Stub(self.cn)
        probes = []

        def probe(host, port):
            probes.append((host, port))
            return "banner", f"5.7.0 {self.cn.key_id('probe banner')} password={self.cn.lower_pw('probe banner')}"

        def php_fetch(url):
            if "down.alpha.example" in url:
                return {"status": None, "headers": {}, "error": f"curl: (35) failed ?token={self.cn.session('curl error')}"}
            return {"status": 200, "error": None,
                    "headers": {"server": f"Apache/2.4 PHP/8.1.2 {self.cn.jwt('probe Server')} {self.cn.key_id('probe Server')}",
                                "x-powered-by": "PHP/8.1.2", "set-cookie": f"sid={self.cn.session('probe Set-Cookie')}"}}

        env = {k: v for k, v in os.environ.items() if k != "SCAN_EVIDENCE"}
        if level != "minimal":
            env["SCAN_EVIDENCE"] = level
        argv = sys.argv
        with mock.patch.dict(os.environ, env, clear=True), contextlib.redirect_stdout(self.out), contextlib.redirect_stderr(self.err):
            I.main(["--root", self.root, "--run-id", self.RUN, "--offline"], offline_fetch=stub, offline_probe=probe)
            sys.argv = ["report.py", "--root", self.root, "--run-id", self.RUN]
            try:
                RP.main()
            finally:
                sys.argv = argv
            rc = P.run(P.parse_args(["--root", self.root, "--run-dir", self.run_dir, "--watches", self.watches,
                                     "--workers", "1"]), fetch=php_fetch)
        self.assertEqual(rc, 0)
        self.assertTrue(stub.calls, "verify/triage never fetched: the canary bodies were not exercised")
        self.assertTrue(probes, "the port triage never probed")
        return stub

    def sinks(self):
        """{name: text} of everything written: database bytes and every column, reports, CSVs, probe files, output."""
        out = {}
        for p in glob.glob(os.path.join(self.root, "data", "scan.sqlite*")):
            with open(p, "rb") as f:
                out[os.path.basename(p) + " (bytes)"] = f.read().decode("latin-1")
        db = sqlite3.connect(os.path.join(self.root, "data", "scan.sqlite"))
        try:
            for (t,) in db.execute("SELECT name FROM sqlite_master WHERE type='table'"):
                rows = db.execute(f"SELECT * FROM {t}").fetchall()
                out[f"table {t}"] = "\n".join(repr(r) for r in rows)
        finally:
            db.close()
        for p in sorted(glob.glob(os.path.join(self.root, "reports", "*"))) + sorted(glob.glob(os.path.join(self.root, "version-watch", "*", "*"))):
            with open(p, encoding="utf-8", errors="replace") as f:
                out[os.path.relpath(p, self.root)] = f.read()
        out["stdout"], out["stderr"] = self.out.getvalue(), self.err.getvalue()
        return out

    def leaks(self, sinks):
        found = []
        for c in self.cn.all_values():
            for name, text in sinks.items():
                for form in forms(c):
                    if form in text:
                        found.append(f"{self.cn.where[c]} -> {name}")
                        break
        return sorted(set(found))

    # ------------------------------------------------------------ the checks
    def check_level(self, level):
        self.run_all(level)
        sinks = self.sinks()
        self.assertGreater(len(self.cn.all_values()), 60)
        self.assertEqual(self.leaks(sinks), [])
        db = sqlite3.connect(os.path.join(self.root, "data", "scan.sqlite"))
        self.addCleanup(db.close)
        # still there and still useful
        rows = {r[0]: r[1:] for r in db.execute(
            "SELECT f.check_id, o.verdict, o.exposure, o.raw_json, o.matched FROM findings f JOIN finding_observations o ON o.finding_key=f.finding_key")}
        checks = set(rows)
        self.assertIn("configuration-listing", checks)
        self.assertIn("git-config", checks)
        self.assertIn("3306/tcp", checks)
        self.assertIn("legacy-protocol", checks)
        self.assertIn("axfr:ns1.alpha.example", checks)
        env_key = next(k for k in checks if k.startswith("exposed-env-file:"))
        self.assertEqual(rows["configuration-listing"][0], "confirmed")
        self.assertEqual(rows[env_key][0], "confirmed")
        self.assertEqual(rows[env_key][1], "credential")
        self.assertEqual(rows["3306/tcp"][1], "internal")
        for k, (_, _, raw, _) in rows.items():
            json.loads(raw)                                    # stored evidence is valid JSON
        ev = json.loads(rows[env_key][2])
        self.assertEqual(ev["template-id"], "exposed-env-file")
        self.assertEqual(ev["port"], 443)
        self.assertEqual(ev["info"]["classification"]["cve-id"], ["CVE-2099-0001"])
        self.assertTrue(rows[env_key][3].startswith(f"https://{HOST}/.env?token=REDACTED"))
        self.assertEqual(len(ev["extracted-results"]), 5)
        self.assertEqual(db.execute("SELECT evidence_level FROM runs").fetchone()[0], level)
        # ordinary values stay readable: a path with digits, a signature algorithm, a cipher, a title
        self.assertEqual(rows["wp-backup-file"][3], f"https://{HOST}/wp-content/uploads/2023/01/backup-2023-01-15.sql")
        self.assertEqual(db.execute("SELECT sig_alg FROM certificates").fetchone()[0], "sha256WithRSAEncryption")
        self.assertEqual(db.execute("SELECT preferred_cipher FROM tls_endpoints").fetchone()[0], "ECDHE-RSA-AES128-GCM-SHA256")
        self.assertEqual(json.loads(rows["git-config"][2])["matched-at"], f"https://{HOST}/.git/config")
        tri = db.execute("SELECT t.items_json, t.secrets_json FROM finding_triage t JOIN findings f ON f.finding_key=t.finding_key "
                         "WHERE f.check_id='configuration-listing'").fetchone()
        items, secrets = json.loads(tri[0]), json.loads(tri[1])
        self.assertTrue(any(it["url"].endswith("/config/.env") and it["kind"] == "credential" for it in items))
        self.assertTrue(secrets and all(set(s) == {"type", "masked", "where", "line"} for s in secrets))
        ep = db.execute("SELECT cookies, emails, title FROM endpoints").fetchone()
        self.assertEqual(json.loads(ep[0]), ["sid", "theme"])
        self.assertEqual(json.loads(ep[1]), {"count": 1, "domains": ["corp.example"]})
        self.assertIn("Home", ep[2])
        with open(os.path.join(self.root, "version-watch", "php-example", "latest.json")) as f:
            probe = {h["hostname"]: h for h in json.load(f)["hosts"]}
        self.assertEqual((probe[HOST]["version"], probe[HOST]["verdict"]), ("8.1.2", "FAIL"))
        self.assertIn("verify " + HOST, sinks["stderr"])        # the log line is still there, without evidence
        return ev

    def test_minimal(self):
        ev = self.check_level("minimal")
        self.assertNotIn("excerpt", ev)

    def test_excerpt(self):
        ev = self.check_level("excerpt")
        ex = ev["excerpt"]
        self.assertEqual(ex["status"], 200)
        self.assertIn("Set-Cookie", ex["header_names"])
        self.assertEqual(ex["headers"], {"content-type": "text/plain", "server": "nginx", "x-powered-by": "PHP/8.1.2"})
        self.assertIn("APP_ENV=production", ex["body"])
        self.assertLessEqual(len(ex["body"]), 2000)


if __name__ == "__main__":
    unittest.main()
