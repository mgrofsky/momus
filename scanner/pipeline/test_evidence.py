import datetime as dt, json, os, sys, tempfile, unittest
import xml.etree.ElementTree as ET
sys.path.insert(0, os.path.dirname(__file__))
import evidence as E

DAY = dt.date(2030, 10, 25)

# Invented sslscan output (hostnames and addresses synthetic).
SSLTEST = """<document title="SSLScan Results"><ssltest host="www.bravo.example" sniname="www.bravo.example" port="443">
<protocol type="ssl" version="2" enabled="0" /><protocol type="ssl" version="3" enabled="0" /><protocol type="tls" version="1.0" enabled="1" />
<protocol type="tls" version="1.1" enabled="0" /><protocol type="tls" version="1.2" enabled="1" /><protocol type="tls" version="1.3" enabled="1" />
<fallback supported="1" /><renegotiation supported="1" secure="1" /><compression supported="0" /><heartbleed sslversion="TLSv1.2" vulnerable="0" />
<cipher status="preferred" sslversion="TLSv1.3" bits="128" cipher="TLS_AES_128_GCM_SHA256" id="0x1301" strength="strong" curve="25519" ecdhebits="253" />
<cipher status="accepted" sslversion="TLSv1.2" bits="128" cipher="ECDHE-RSA-AES128-GCM-SHA256" id="0xC02F" strength="strong" />
<cipher status="accepted" sslversion="TLSv1.0" bits="112" cipher="DES-CBC3-SHA" id="0x000A" strength="medium" />
<group sslversion="TLSv1.3" bits="128" name="secp256r1 (NIST P-256)" id="0x0017" />
<certificates><certificate type="short"><signature-algorithm>sha256WithRSAEncryption</signature-algorithm><pk error="false" type="RSA" bits="2048" />
<subject><![CDATA[*.bravo.example]]></subject><altnames><![CDATA[DNS:*.bravo.example, DNS:bravo.example, DNS:status.bravo.example]]></altnames>
<issuer><![CDATA[DigiCert Example TLS DV Issuing CA 3]]></issuer><self-signed>false</self-signed>
<not-valid-before>Feb 11 04:12:36 2030 GMT</not-valid-before><not-yet-valid>false</not-yet-valid><not-valid-after>Mar  9 04:12:36 2031 GMT</not-valid-after><expired>false</expired>
</certificate></certificates></ssltest>
<ssltest host="old.alpha.example" sniname="old.alpha.example" port="443"><protocol type="tls" version="1.2" enabled="1" />
<certificates><certificate type="short"><pk type="RSA" bits="1024" /><subject><![CDATA[old.alpha.example]]></subject><issuer><![CDATA[old.alpha.example]]></issuer>
<self-signed>true</self-signed><not-valid-before>Jan  1 00:00:00 2020 GMT</not-valid-before><not-valid-after>Oct  1 00:00:00 2030 GMT</not-valid-after><expired>true</expired></certificate></certificates></ssltest>
</document>"""

HTTPX = {"url": "https://app.delta.example:443", "input": "app.delta.example", "host": "app.delta.example", "host_ip": "203.0.113.137", "port": "443",
         "scheme": "https", "path": "/", "status_code": 403, "final_url": "https://app.delta.example/login", "chain_status_codes": [301, 403],
         "content_type": "text/html", "content_length": 146, "words": 9, "lines": 3, "time": "318.904217ms", "favicon": "-1234567890", "favicon_md5": "abc",
         "cdn": True, "cdn_name": "cloudfront", "cdn_type": "cdn", "tech": ["Amazon CloudFront"], "webserver": "CloudFront", "title": "Sign in",
         "tls": {"subject_cn": "app.delta.example", "subject_an": ["app.delta.example", "api.delta.example"], "issuer_org": ["Amazon"], "issuer_cn": "Amazon RSA 2048 M02",
                 "not_before": "2030-03-01T00:00:00Z", "not_after": "2031-03-01T23:59:59Z", "serial": "3A:96:0D", "fingerprint_hash": {"sha256": "ff00", "md5": "aa"}}}
WHATWEB = [{"target": "https://app.delta.example/", "http_status": 403, "plugins": {
    "Strict-Transport-Security": {"string": ["max-age=31536000"]}, "X-Frame-Options": {"string": ["SAMEORIGIN"]},
    "Cookies": {"string": ["session", "csrf"]}, "HttpOnly": {"string": ["session"]}, "Email": {"string": ["Support@Example.com"]},
    "Google-Analytics": {"version": ["Universal"], "account": ["UA-1-1"]}, "Google-Tag-Manager": {}, "PasswordField": {"string": ["password"]},
    "UncommonHeaders": {"string": ["x-amz-cf-pop,x-amz-cf-id"]}, "RedirectLocation": {"string": ["https://app.delta.example/login"]},
    "X-Powered-By": {"string": ["PHP/5.4.45"]}, "MetaGenerator": {"string": ["WordPress 6.4"]}}}]

NUCLEI_DNS = [
    {"template-id": "spf-record-detect", "host": "delta.example", "matched-at": "delta.example", "extracted-results": ["v=spf1 include:_spf.google.com ~all"]},
    {"template-id": "dmarc-detect", "host": "delta.example", "matched-at": "_dmarc.delta.example", "extracted-results": ["\"v=DMARC1; p=quarantine; adkim=s; rua=mailto:x@example.test\""]},
    {"template-id": "dkim-record-detect", "host": "e.delta.example", "matched-at": "s2._domainkey.e.delta.example", "extracted-results": ["v=DKIM1; k=rsa; p=MIGf"]},
    {"template-id": "mx-fingerprint", "host": "delta.example", "matched-at": "delta.example", "extracted-results": ["1 aspmx.l.google.com.", "5 alt1.aspmx.l.google.com."]},
    {"template-id": "caa-fingerprint", "host": "foxtrot.example", "matched-at": "foxtrot.example", "extracted-results": ["pki.goog\"foxtrot.example.\t86400\tIN\tCAA\t0 issue \"sectigo.com\"foxtrot.example.\t86400\tIN\tCAA\t0 issue \"pki.goog\""]},
    {"template-id": "nameserver-fingerprint", "host": "delta.example", "matched-at": "delta.example", "extracted-results": ["ns-111.awsdns-11.net.", "ns-1222.awsdns-22.co.uk."]},
    {"template-id": "srv-service-detect", "host": "mail.delta.example", "matched-at": "_imaps._tcp.mail.delta.example", "extracted-results": ["SRV\t0 1 993 ec2-198-51-100-174.compute-1.amazonaws.com."]},
    {"template-id": "txt-fingerprint", "host": "foxtrot.example", "matched-at": "foxtrot.example", "extracted-results": ["\"google-site-verification=abc\"", "\"v=spf1 -all\""]},
    {"template-id": "dmarc-detect", "host": "foxtrot.example", "matched-at": "_dmarc.foxtrot.example", "extracted-results": ["\"v=DMARC1; p=reject; sp=none; rua=mailto:x@example.test\""]},
    {"template-id": "wildcard-dns-detect", "host": "app2.echo.example", "matched-at": "random.app2.echo.example", "extracted-results": ["198.51.100.213"]},
    {"template-id": "dns-rebinding", "host": "x.foxtrot.example", "extracted-results": ["10.0.0.1"]},   # not an inventory record
]
DNSX = [{"host": "app1.alpha.example", "ttl": 60, "a": ["198.51.100.86"], "cname": ["gw3.alpha.example"],
         "all": ["app1.alpha.example.\t60\tIN\tCNAME\tgw3.alpha.example.", "gw3.alpha.example.\t60\tIN\tA\t198.51.100.86"], "status_code": "NOERROR"},
        {"host": "echo.example", "all": ["echo.example.\t300\tIN\tMX\t10 aspmx3.googlemail.com.", "echo.example.\t300\tIN\tTXT\t\"v=spf1 include:_spf.google.com -all\"",
                                        "_dmarc.echo.example.\t300\tIN\tTXT\t\"v=DMARC1; p=none\"", "echo.example.\t300\tIN\tNS\tns-517.awsdns-08.com."]}]
NMAP = """<nmaprun><host><status state="up" /><address addr="203.0.113.66" addrtype="ipv4" />
<hostnames><hostname name="ec2-203-0-113-66.compute-1.amazonaws.com" type="PTR" /></hostnames>
<ports><port protocol="tcp" portid="443"><state state="open" reason="syn-ack" /><service name="tcpwrapped" method="probed" conf="8" /></port>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack" /><service name="ssh" product="OpenSSH" version="8.9p1" /></port>
<port protocol="tcp" portid="3306"><state state="open" reason="syn-ack" /><service name="tcpwrapped" /></port>
<port protocol="tcp" portid="80"><state state="closed" reason="conn-refused" /></port></ports></host></nmaprun>"""


def write(dirpath, name, content):
    p = os.path.join(dirpath, name)
    with open(p, "w") as f:
        f.write(content if isinstance(content, str) else "\n".join(json.dumps(x) for x in content) + "\n")
    return p


class TestSslscan(unittest.TestCase):
    def test_certificate_and_tls_rows(self):
        certs, tls = E.sslscan_evidence(ET.fromstring(SSLTEST), DAY)
        c = certs[("www.bravo.example", 443)]
        self.assertEqual((c["subject"], c["issuer"], c["key_type"], c["key_bits"], c["sig_alg"]), ("*.bravo.example", "DigiCert Example TLS DV Issuing CA 3", "RSA", 2048, "sha256WithRSAEncryption"))
        self.assertEqual(c["sans"], ["*.bravo.example", "bravo.example", "status.bravo.example"])
        self.assertEqual((c["not_before"], c["not_after"]), ("2030-02-11T04:12:36Z", "2031-03-09T04:12:36Z"))   # space-padded day parsed
        self.assertEqual((c["days_left"], c["expired"], c["self_signed"], c["source"]), (135, 0, 0, "sslscan"))
        t = tls[("www.bravo.example", 443)]
        self.assertEqual(t["protocols"], ["tls1.0", "tls1.2", "tls1.3"])
        self.assertEqual((t["legacy"], t["weak_ciphers"], t["preferred_cipher"]), (1, 1, "TLS_AES_128_GCM_SHA256"))
        self.assertEqual((t["fallback_scsv"], t["secure_reneg"], t["compression"], t["heartbleed"]), (1, 1, 0, 0))
        old = certs[("old.alpha.example", 443)]
        self.assertEqual((old["expired"], old["self_signed"], old["key_bits"], old["sans"], old["days_left"]), (1, 1, 1024, [], -24))
        self.assertEqual(tls[("old.alpha.example", 443)]["legacy"], 0)

    def test_missing_document(self):
        self.assertEqual(E.sslscan_evidence(None, DAY), ({}, {}))


class TestHttpxAndWhatweb(unittest.TestCase):
    def test_httpx_cert_fills_what_sslscan_lacks(self):
        c = E.httpx_cert(HTTPX, DAY)
        self.assertEqual((c["hostname"], c["port"], c["subject"], c["issuer"], c["serial"], c["sha256"], c["source"]), ("app.delta.example", 443, "app.delta.example", "Amazon", "3A:96:0D", "ff00", "httpx"))
        self.assertEqual(c["sans"], ["api.delta.example", "app.delta.example"])
        self.assertIsNone(E.httpx_cert({"url": "http://x:80"}, DAY))

    def test_endpoint_row_joins_whatweb_signals(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "whatweb.json", json.dumps(WHATWEB))
            ww = E.whatweb_by_url(d)
        self.assertIn("https://app.delta.example", ww)
        r = E.endpoint_row(HTTPX, ww.get(E.norm_url(HTTPX["url"])))
        self.assertEqual((r["hostname"], r["port"], r["status"], r["final_url"], r["chain"]), ("app.delta.example", 443, 403, "https://app.delta.example/login", [301, 403]))
        self.assertEqual((r["hsts"], r["csp"], r["xfo"], r["xss_protection"], r["password_field"]), (1, 0, 1, 0, 1))
        self.assertEqual((r["cookies"], r["httponly_cookies"], r["emails"]), (["session", "csrf"], ["session"], ["support@example.com"]))
        self.assertEqual(r["analytics"], ["GA UA-1-1", "Google Tag Manager"])
        self.assertEqual((r["generator"], r["powered_by"], r["redirect_to"]), ("WordPress 6.4", "PHP/5.4.45", "https://app.delta.example/login"))
        self.assertEqual(r["uncommon_headers"], ["x-amz-cf-id", "x-amz-cf-pop"])
        self.assertEqual((r["response_ms"], r["favicon_mmh3"], r["server"]), (318.9, "-1234567890", "CloudFront"))

    def test_norm_url(self):
        self.assertEqual(E.norm_url("http://a.example.com:80"), "http://a.example.com")
        self.assertEqual(E.norm_url("https://a.example.com/"), "https://a.example.com")
        self.assertEqual(E.norm_url("https://A.example.com:8443/"), "https://a.example.com:8443")

    def test_httpx_records_dedupe_and_skip_failed(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "httpx.jsonl", [HTTPX, HTTPX, {"url": "http://dead.example.test:80", "failed": True}])
            self.assertEqual([r["url"] for r in E.httpx_records(d)], ["https://app.delta.example:443"])


class TestDnsRecords(unittest.TestCase):
    def records(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "nuclei_dns.jsonl", NUCLEI_DNS)
            n = E.dns_records_nuclei(d)
            x = E.dns_records_dnsx(write(d, "dns.jsonl", DNSX), "dnsx")
        return n, x

    def test_nuclei_records(self):
        n, _ = self.records()
        by = {}
        for r in n:
            by.setdefault(r["rtype"], []).append(r)
        self.assertEqual([r["value"] for r in by["SPF"]], ["v=spf1 include:_spf.google.com ~all", "v=spf1 -all"])   # TXT that is SPF is routed to SPF
        self.assertEqual({(r["hostname"], r["name"]) for r in by["DMARC"]}, {("delta.example", "_dmarc.delta.example"), ("foxtrot.example", "_dmarc.foxtrot.example")})
        self.assertEqual(by["DMARC"][0]["value"], "v=DMARC1; p=quarantine; adkim=s; rua=mailto:x@example.test")   # quotes stripped
        self.assertEqual((by["DKIM"][0]["hostname"], by["DKIM"][0]["name"]), ("e.delta.example", "s2._domainkey.e.delta.example"))
        self.assertEqual([r["value"] for r in by["MX"]], ["1 aspmx.l.google.com", "5 alt1.aspmx.l.google.com"])
        self.assertEqual(sorted(r["value"] for r in by["CAA"]), ["0 issue pki.goog", "0 issue sectigo.com"])
        self.assertEqual([r["value"] for r in by["NS"]], ["ns-111.awsdns-11.net", "ns-1222.awsdns-22.co.uk"])
        self.assertEqual((by["SRV"][0]["name"], by["SRV"][0]["value"]), ("_imaps._tcp.mail.delta.example", "0 1 993 ec2-198-51-100-174.compute-1.amazonaws.com"))
        self.assertEqual([r["value"] for r in by["TXT"]], ["google-site-verification=abc"])
        self.assertEqual(by["WILDCARD"][0]["name"], "random.app2.echo.example")
        self.assertNotIn("dns-rebinding", {r["rtype"] for r in n})

    def test_dnsx_records(self):
        _, x = self.records()
        self.assertEqual([(r["rtype"], r["name"], r["value"], r["ttl"]) for r in x[:2]],
                         [("CNAME", "app1.alpha.example", "gw3.alpha.example", 60), ("A", "gw3.alpha.example", "198.51.100.86", 60)])
        w = {r["rtype"]: r for r in x if r["hostname"] == "echo.example"}
        self.assertEqual((w["MX"]["value"], w["SPF"]["value"], w["DMARC"]["name"], w["NS"]["value"]),
                         ("10 aspmx3.googlemail.com", "v=spf1 include:_spf.google.com -all", "_dmarc.echo.example", "ns-517.awsdns-08.com"))

    def test_domain_posture(self):
        n, x = self.records()
        rows = {r["apex"]: r for r in E.domain_posture(["delta.example", "foxtrot.example", "echo.example", "charlie.example"], n + x)}
        s = rows["delta.example"]
        self.assertEqual((s["spf"], s["spf_policy"], s["dmarc"], s["dmarc_policy"], s["dmarc_sp"], s["dkim"]), (1, "soft", 1, "quarantine", "quarantine", 1))   # DKIM seen on e.delta.example
        self.assertEqual((s["mx_provider"], s["ns_provider"], s["coverage"], s["hosts_with_dkim"]), ("Google Workspace", "Amazon Route 53", "nuclei", 1))
        y = rows["foxtrot.example"]
        self.assertEqual((y["spf_policy"], y["dmarc_policy"], y["dmarc_sp"], y["caa"], y["caa_issuers"]), ("hard", "reject", "none", 1, ["pki.goog", "sectigo.com"]))
        w = rows["echo.example"]
        self.assertEqual((w["spf_policy"], w["dmarc_policy"], w["mx_provider"], w["coverage"]), ("hard", "none", "Google Workspace", "dnsx"))
        self.assertEqual((rows["charlie.example"]["spf"], rows["charlie.example"]["dmarc"], rows["charlie.example"]["coverage"]), (0, 0, "none"))

    def test_dnsx_apex_query_records_land_on_the_apex(self):
        with tempfile.TemporaryDirectory() as d:
            x = E.dns_records_dnsx(write(d, "dns_apex.jsonl", [
                {"host": "_dmarc.echo.example", "all": ["_dmarc.echo.example.\t300\tIN\tTXT\t\"v=DMARC1; p=none\""]},
                {"host": "s1._domainkey.echo.example", "all": ["s1._domainkey.echo.example.\t300\tIN\tTXT\t\"v=DKIM1; k=rsa; p=MIGf\""]},
                {"host": "charlie.example", "all": ["charlie.example.\t3600\tIN\tSOA\tns-1.awsdns-00.com. hostmaster. 1 7200 900 1209600 86400",
                                              "charlie.example.\t300\tIN\tMX\t10 mx.example.test."]}]), "dnsx")
        self.assertEqual([(r["hostname"], r["rtype"], r["name"]) for r in x][:2],
                         [("echo.example", "DMARC", "_dmarc.echo.example"), ("echo.example", "DKIM", "s1._domainkey.echo.example")])
        rows = {r["apex"]: r for r in E.domain_posture(["echo.example", "charlie.example"], x)}
        self.assertEqual((rows["echo.example"]["dmarc"], rows["echo.example"]["dmarc_policy"], rows["echo.example"]["dkim"], rows["echo.example"]["coverage"]), (1, "none", 1, "dnsx"))
        self.assertEqual((rows["charlie.example"]["coverage"], rows["charlie.example"]["mx"], rows["charlie.example"]["spf"], rows["charlie.example"]["dmarc"]), ("dnsx", ["10 mx.example.test"], 0, 0))

    def test_split_txt_strings_are_joined(self):
        self.assertEqual(E._unquote('"v=spf1 ip4:203.0.113." "64/26 -all"'), "v=spf1 ip4:203.0.113.64/26 -all")
        self.assertEqual(E._unquote('"v=DMARC1; p=none"'), "v=DMARC1; p=none")
        self.assertEqual(E._unquote("ns-1.example.test."), "ns-1.example.test.")
        rows = E.domain_posture(["x.test"], [{"hostname": "x.test", "rtype": "A", "name": "x.test", "value": "1.1.1.1", "source": "dnsx", "ttl": 60}])
        self.assertEqual(rows[0]["coverage"], "none")   # address records alone are not posture coverage

    def test_policy_parsers(self):
        self.assertEqual(E.spf_policy("v=spf1 ip4:192.0.2.0/24 -all"), "hard")
        self.assertEqual(E.spf_policy("v=spf1 include:x ~all"), "soft")
        self.assertEqual(E.spf_policy("v=spf1 include:x"), "none")
        self.assertEqual(E.dmarc_policy("v=DMARC1; p=reject; sp=quarantine"), ("reject", "quarantine"))
        self.assertEqual(E.dmarc_policy("v=DMARC1; p=none"), ("none", "none"))
        self.assertEqual(E.provider_of("10 mx.sendgrid.net.", E.MX_PROVIDERS), "SendGrid")
        self.assertIsNone(E.provider_of("mail.foxtrot.example", E.MX_PROVIDERS))


class TestNmapSourcesGroups(unittest.TestCase):
    def test_host_ports_fan_out_and_ptr(self):
        ports, ptr = E.host_ports(ET.fromstring(NMAP), {"203.0.113.66": ["a.foxtrot.example", "b.foxtrot.example"]}, {3306, 23}, {"ssh"}, {80, 443})
        self.assertEqual(len(ports), 6)   # three open ports x two hostnames; the closed port is not a row
        a = {p["port"]: p for p in ports if p["hostname"] == "a.foxtrot.example"}
        self.assertEqual((a[443]["service"], a[443]["risky"], a[443]["web"]), ("tcpwrapped", 0, 1))
        self.assertEqual((a[22]["product"], a[22]["risky"]), ("OpenSSH 8.9p1", 1))
        self.assertEqual((a[3306]["risky"], a[3306]["reason"]), (1, "syn-ack"))
        self.assertEqual((ptr[0]["rtype"], ptr[0]["name"], ptr[0]["value"]), ("PTR", "203.0.113.66", "ec2-203-0-113-66.compute-1.amazonaws.com"))

    def test_sources_and_groups(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "sources.json", json.dumps({"a.foxtrot.example": ["seed", "crtsh"], "B.foxtrot.example.": ["subfinder"]}))
            write(d, "nuclei_groups.json", json.dumps({"https://gw3.alpha.example:443": ["http://app3.alpha.example:80", "https://gw3.alpha.example:443"], "http://solo.foxtrot.example:80": ["http://solo.foxtrot.example:80"]}))
            src = E.asset_sources(d); groups = E.app_groups(d)
        self.assertEqual(src, {"a.foxtrot.example": ["crtsh", "seed"], "b.foxtrot.example": ["subfinder"]})
        self.assertEqual({(g["hostname"], g["group_host"], g["members"]) for g in groups},
                         {("app3.alpha.example", "gw3.alpha.example", 2), ("gw3.alpha.example", "gw3.alpha.example", 2), ("solo.foxtrot.example", "solo.foxtrot.example", 1)})

    def test_san_leads(self):
        certs = [{"hostname": "www.bravo.example", "sans": ["*.bravo.example", "bravo.example", "old.bravo.example", "vendor.example.test"]},
                 {"hostname": "x.bravo.example", "sans": ["old.bravo.example"]}]
        leads = E.san_leads(certs, ["bravo.example"], {"www.bravo.example", "bravo.example"})
        self.assertEqual(leads, {"old.bravo.example": ["www.bravo.example", "x.bravo.example"]})   # no wildcards, no out-of-scope names, no known names


if __name__ == "__main__":
    unittest.main()
