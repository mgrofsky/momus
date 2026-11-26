"""minimize.py: per-source allowlists, redaction per field, caps after redaction, valid JSON, the evidence level."""
import json, os, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import minimize as M  # noqa: E402

# made-up values, assembled at run time (nothing key-shaped sits in the file as one literal)
KEY_ID = "AKIA" + "FAKE" * 4
PW = "lower" + "case" + "fakepw"
JWT = "eyJ" + "hbGciOiJub25lIn0" + ".eyJ" + "zdWIiOiJmYWtlIn0" + ".ZmFrZXNpZ25hdHVyZQ"
SESSION = "fakeSession" + "Value0042"


def nuclei_record():
    body = (f"<html><title>t</title>\nDB_PASSWORD={PW}\n<p>{KEY_ID}</p>\n" + "x" * 5000)
    return {
        "template-id": "exposed-env", "template": "http/exposures/configs/exposed-env.yaml",
        "template-path": "/home/scanner/.local/nuclei-templates/http/exposures/configs/exposed-env.yaml",
        "info": {"name": "Exposed .env", "severity": "high", "tags": ["exposure", "config"], "author": ["someone"],
                 "description": "template text", "reference": ["https://example.test/ref", "javascript:alert(1)"],
                 "classification": {"cve-id": ["CVE-2099-0001", "not-a-cve"], "cwe-id": ["CWE-200"], "cvss-score": "7.5",
                                    "cvss-metrics": "CVSS:3.1/AV:N"}},
        "type": "http", "host": "https://app.alpha.example", "port": "443", "scheme": "https",
        "matched-at": f"https://u:{PW}@app.alpha.example/.env?X-Amz-Signature=fakesig1&a=1",
        "ip": "192.0.2.10", "timestamp": "2030-01-01T00:00:00Z", "matcher-name": "dbpass", "matcher-status": True,
        "extracted-results": [f"DB_PASSWORD={PW}", JWT] + [f"v{i}" for i in range(20)] + ["y" * 900],
        "request": f"GET /.env HTTP/1.1\r\nHost: app.alpha.example\r\nAuthorization: Bearer {JWT}\r\nCookie: sid={SESSION}\r\n\r\n",
        "response": ("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nServer: nginx\r\n"
                     f"Set-Cookie: sid={SESSION}; Path=/\r\nX-Api-Key: {KEY_ID}\r\nAuthorization: Basic ZmFrZTpmYWtl\r\n\r\n" + body),
        "curl-command": f"curl -X GET -H 'Cookie: sid={SESSION}' https://app.alpha.example/.env",
        "metadata": {"secret": PW}, "unknown-future-key": PW,
    }


class TestNuclei(unittest.TestCase):
    def test_allowlist_and_drops(self):
        out = M.minimize("nuclei", nuclei_record())
        self.assertEqual(set(out) - set(M.ALLOWED["nuclei"]), {"extracted-total"})
        for k in ("request", "response", "curl-command", "metadata", "template-path", "unknown-future-key", "excerpt"):
            self.assertNotIn(k, out)
        self.assertEqual(set(out["info"]), {"name", "severity", "tags", "reference", "classification"})
        self.assertEqual(out["info"]["classification"]["cve-id"], ["CVE-2099-0001"])
        self.assertEqual(out["info"]["classification"]["cvss-score"], 7.5)
        self.assertEqual((out["port"], out["ip"], out["matcher-name"], out["template-id"]), (443, "192.0.2.10", "dbpass", "exposed-env"))
        blob = M.to_json(out)
        for v in (PW, KEY_ID, JWT, SESSION, "fakesig1"):
            self.assertNotIn(v, blob)

    def test_matched_location_is_a_redacted_url(self):
        out = M.minimize("nuclei", nuclei_record())
        self.assertEqual(out["matched-at"], "https://app.alpha.example/.env?X-Amz-Signature=REDACTED&a=1")

    def test_extracted_values_capped(self):
        out = M.minimize("nuclei", nuclei_record())
        self.assertEqual(len(out["extracted-results"]), M.MAX_VALUES)
        self.assertEqual(out["extracted-total"], 23)
        self.assertTrue(all(len(v) <= M.MAX_VALUE_LEN for v in out["extracted-results"]))
        self.assertTrue(out["extracted-results"][0].startswith("DB_PASSWORD=<REDACTED"))

    def test_excerpt(self):
        out = M.minimize("nuclei", nuclei_record(), "excerpt")
        ex = out["excerpt"]
        self.assertEqual(ex["status"], 200)
        self.assertEqual(ex["header_names"], ["Content-Type", "Server", "Set-Cookie", "X-Api-Key", "Authorization"])
        self.assertEqual(ex["headers"], {"content-type": "text/plain", "server": "nginx"})   # only the safe list has values
        self.assertLessEqual(len(ex["body"]), M.MAX_BODY)
        self.assertIn("<title>t</title>", ex["body"])
        blob = M.to_json(out)
        for v in (PW, KEY_ID, SESSION, "ZmFrZTpmYWtl"):
            self.assertNotIn(v, blob)

    def test_excerpt_body_with_no_line_end_in_the_read_limit_is_dropped(self):
        r = nuclei_record()
        r["response"] = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n" + "<p>" + "z" * (M.MAX_BODY_READ + 50) + "\nend"
        ex = M.minimize("nuclei", r, "excerpt")["excerpt"]
        self.assertEqual(ex["status"], 200)
        self.assertEqual(ex["body"], "")
        r["response"] = "HTTP/1.1 200 OK\r\n\r\nfirst line\n" + "z" * (M.MAX_BODY_READ + 50)
        self.assertEqual(M.minimize("nuclei", r, "excerpt")["excerpt"]["body"], "first line")

    def test_matcher_name_is_cleaned_deterministically(self):
        r = nuclei_record(); r["matcher-name"] = JWT
        a, b = M.minimize("nuclei", r)["matcher-name"], M.ident(JWT, 100)
        self.assertEqual(a, b); self.assertNotIn(JWT, a)

    def test_unknown_level_refused(self):
        with self.assertRaises(M.EvidenceLevelError):
            M.minimize("nuclei", {}, "full")


class TestOtherSources(unittest.TestCase):
    def test_nmap_drops_script_output(self):
        raw = {"ip": "192.0.2.5", "port": 3306, "proto": "tcp", "service": "mysql", "product": f"MySQL 8.0 {KEY_ID}",
               "scripts": {"http-title": f"Set-Cookie: sid={SESSION}", "banner": PW}}
        out = M.minimize("nmap", raw)
        self.assertEqual(out["script_ids"], ["http-title", "banner"])
        blob = M.to_json(out)
        for v in (SESSION, PW, KEY_ID):
            self.assertNotIn(v, blob)
        self.assertEqual(M.minimize("nmap", {"ip": "192.0.2.5", "open_ports": ["21", "23", 80]})["open_ports"], [21, 23, 80])

    def test_sslscan_and_dns(self):
        self.assertEqual(M.minimize("sslscan", {"protocols": ["TLSv1.0", "<script>"], "ciphers": ["RC4-MD5", "a b"]}),
                         {"protocols": ["TLSv1.0"], "ciphers": ["RC4-MD5"]})
        self.assertEqual(M.minimize("dns", {"apex": "alpha.example", "ns": "ns1.alpha.example", "ns_ip": "192.0.2.53", "success": True,
                                            "records": 12, "zone": PW}),
                         {"apex": "alpha.example", "ns": "ns1.alpha.example", "ns_ip": "192.0.2.53", "success": True, "records": 12})
        self.assertEqual(M.minimize("http", {"body": PW}), {})
        self.assertEqual(M.minimize("other", {"x": PW}), {})


class TestJsonAndLevel(unittest.TestCase):
    def test_always_valid_json_and_bounded(self):
        r = nuclei_record()
        r["extracted-results"] = ["z" * 5000] * 100
        r["siblings"] = [f"h{i}.alpha.example" for i in range(1000)]
        r["info"]["reference"] = ["https://example.test/" + "r" * 400] * 100
        s = M.to_json(M.minimize("nuclei", r, "excerpt"))
        self.assertLessEqual(len(s), M.MAX_JSON)
        json.loads(s)
        big = {"template-id": "t", "excerpt": {"body": "b" * 40000}, "extracted-results": ["e" * 100] * 10}
        out = json.loads(M.to_json(big))
        self.assertNotIn("body", out["excerpt"]); self.assertEqual(out["dropped"], ["excerpt.body"])

    def test_evidence_level(self):
        self.assertEqual(M.evidence_level({}, env={}), "minimal")
        self.assertEqual(M.evidence_level({"evidence": "excerpt"}, env={}), "excerpt")
        self.assertEqual(M.evidence_level({"evidence": "excerpt"}, env={"SCAN_EVIDENCE": "minimal"}), "minimal")
        with self.assertRaises(M.EvidenceLevelError):
            M.evidence_level({}, env={"SCAN_EVIDENCE": "everything"})


class TestOrdinaryValuesSurvive(unittest.TestCase):
    """What is stored must stay useful: ordinary paths, algorithm and cipher names, versions and titles are not masked."""
    def test_urls(self):
        for u in ("https://www.alpha.example/wp-content/uploads/2023/01/backup.sql", "https://www.alpha.example/wp-json/wp/v2/users",
                  "https://nvd.nist.gov/vuln/detail/CVE-2099-0008", "https://app.alpha.example/static/js/main.c71e04ad5b.chunk.js",
                  "https://app.alpha.example/api/v1/Users/42/Orders?page=2&sort=desc",
                  "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/exposures/configs/laravel-env.yaml"):
            self.assertEqual(M.url(u), u)

    def test_vocabulary(self):
        c = M.certificate({"sig_alg": "sha256WithRSAEncryption", "key_type": "RSA", "sans": [], "subject": "cn=www.alpha.example",
                           "issuer": "C=US, O=Let's Encrypt, CN=R3"})
        self.assertEqual((c["sig_alg"], c["key_type"], c["issuer"]), ("sha256WithRSAEncryption", "RSA", "C=US, O=Let's Encrypt, CN=R3"))
        for t in ("ECDHE-RSA-AES128-GCM-SHA256", "TLS_AES_256_GCM_SHA384", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                  "Exposed Laravel Environment File (CVE-2099-12345)", "Apache/2.4.58 (Ubuntu) OpenSSL/3.0.2", "Jan  1 00:00:00 2031 GMT",
                  "backup-2023-01-15-full.sql.gz", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"):
            self.assertEqual(M.text(t), t)
        import fingerprint as F
        self.assertEqual([n for n in F.CATALOG if M.component({"name": n, "version": "1.2.3", "evidence": n})["name"] != n], [])

    def test_random_tokens_still_masked(self):
        for t in ("Fq39ZkLp2Vw8Rt6Yb1Nm4Hc7Js5", "Ck0042x7Rq/Zp3Lw+Vb9Nm2Tt6Ys1Hd8Jc4Gf0Ka5Ue", "abcd/EFGH/1234/ijkL/5mN6/oP7q/R8sT/9uVw"):
            self.assertEqual(M.text(f"v {t} w"), "v <REDACTED high-entropy string> w")


class TestRows(unittest.TestCase):
    def test_triage_record(self):
        tri = {"summary": f"readable at https://a.alpha.example/x?token={PW}; committer dev1@corp.example", "fix": "rotate",
               "items": [{"url": f"https://a.alpha.example/.env?sig={PW}", "status": 200, "bytes": 10, "kind": "credential",
                          "note": "3 committer emails: dev1@corp.example"}],
               "secrets": [{"type": "npm registry token", "where": "/.npmrc", "line": 2, "masked": "npm_...[40 chars]"},
                           {"type": "secret in PHP environment", "where": "DB_PASSWORD", "line": 0}]}
        st = M.triage_record(tri)
        blob = json.dumps(st)
        for v in (PW, "dev1@"):
            self.assertNotIn(v, blob)
        self.assertIn("<email at corp.example>", st["summary"])
        self.assertEqual(st["items"][0]["url"], "https://a.alpha.example/.env?sig=REDACTED")
        self.assertEqual([set(s) for s in st["secrets"]], [{"type", "masked", "where", "line"}] * 2)
        self.assertEqual(st["secrets"][1]["masked"], "(value not read)")

    def test_endpoint_row(self):
        r = {"url": f"https://a.alpha.example/?session={SESSION}", "final_url": None, "redirect_to": None, "title": f"Home {JWT}",
             "server": "nginx", "generator": None, "powered_by": None, "content_type": "text/html", "chain": [301, 200],
             "cookies": [f"sid={SESSION}", "theme"], "httponly_cookies": ["sid"], "emails": ["a@corp.example", "b@corp.example"],
             "uncommon_headers": ["x-debug-token: abc", "x-request-id"], "analytics": ["GA UA-0000-1"],
             "favicon_mmh3": "-12345", "favicon_md5": "0f" * 16}
        out = M.endpoint(r)
        self.assertEqual(out["cookies"], ["sid", "theme"])
        self.assertEqual(out["emails"], {"count": 2, "domains": ["corp.example"]})
        self.assertEqual(out["uncommon_headers"], ["x-debug-token", "x-request-id"])
        blob = json.dumps(out)
        for v in (SESSION, JWT):
            self.assertNotIn(v, blob)

    def test_certificate_and_dns(self):
        c = M.certificate({"subject": f"cn=x/ou={KEY_ID}", "issuer": "Example CA", "sans": ["www.alpha.example", f"URI:https://x.example/?sig={PW}"],
                           "serial": "0A:0B", "sha256": f"not-hex-{PW}", "key_type": "RSA", "sig_alg": "sha256WithRSAEncryption",
                           "not_before": None, "not_after": "2030-01-01T00:00:00Z"})
        self.assertEqual((c["serial"], c["sha256"]), ("0A:0B", None))
        self.assertEqual(c["sans"][0], "www.alpha.example")
        self.assertNotIn(KEY_ID, json.dumps(c)); self.assertNotIn(PW, json.dumps(c))
        d = M.dns_record({"hostname": "alpha.example", "rtype": "TXT", "name": "alpha.example", "value": f"verify={JWT}", "source": "dnsx", "ttl": 1})
        self.assertNotIn(JWT, d["value"])
        self.assertEqual(M.dns_record({"rtype": "A", "name": "a.alpha.example", "value": "192.0.2.1"})["value"], "192.0.2.1")


if __name__ == "__main__":
    unittest.main()
