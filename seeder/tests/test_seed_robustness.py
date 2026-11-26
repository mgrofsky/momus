"""No input stops the seeder, a source adds names only under
the zone it was asked for and within its share, zone-file parsing and the PowerDNS request have overall limits, the
AWS clients take nothing from the environment but credentials, and the scanner's verified-domain list (not the
published folder) is the seeder's only input from the scanner. Run only by seeder/tests/run_tests.sh."""
import contextlib
import io
import json
import os
import struct
import subprocess
import sys
import tempfile
import time
import unittest
import unittest.mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
import seed_dns as sd  # noqa: E402
from test_seed_dns import (APEXES, CANARY, Captured, FakeOpener, FakeResponse, FakeRoute53, FakeSocket, PDNS, cfg,  # noqa: E402
                           dns_name, message, rd, rr, scope_status, soa, wr)

SEED_PY = os.path.join(os.path.dirname(HERE), "seed_dns.py")


def transfer(*names, question="example.test"):
    """One answer message: the zone's SOA, A records for names, the closing SOA."""
    return lambda qid: [message(qid, [rr("example.test", 6, soa())] + [rr(n, 1, b"\xc0\x00\x02\x01") for n in names]
                                + [rr("example.test", 6, soa())], question=question)]


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.scope, self.out, self.zones = os.path.join(d, "scope"), os.path.join(d, "seed"), os.path.join(d, "zones")
        os.makedirs(self.out)
        os.makedirs(self.zones)
        self.key = os.path.join(d, "key")
        wr(self.key, CANARY)
        scope_status(self.scope, {"example.test": "verified", "example-two.test": "verified"})
        wr(os.path.join(self.zones, "example-two.test.hosts"), "www\nmail\n")      # the source that works

    def tearDown(self):
        self.tmp.cleanup()

    def run_once(self, clients=None, **env):
        with Captured() as cap:
            st = sd.run_once(cfg(SEED_ZONE_FILES="1", **env), self.scope, self.out, self.zones, clients=clients or {})
        return st, cap.err.getvalue()

    def written(self):
        return rd(os.path.join(self.out, "seed_hosts.txt")).splitlines()

    def assert_clean_log(self, log, *absent):
        self.assertNotIn("Traceback", log)
        for a in absent:
            self.assertNotIn(a, log)


# =========================================================================================== decoding
class DecodeTests(unittest.TestCase):
    def test_text_form_is_decimal_and_never_raises(self):
        self.assertEqual(sd.decode_dns_name("Living\\032Room._airplay._tcp.example.test."), "living room._airplay._tcp.example.test")
        self.assertEqual(sd.decode_dns_name("a\\128b.example.test"), "a\x80b.example.test")      # decimal 128: not a host name
        self.assertFalse(sd.valid_host(sd.decode_dns_name("a\\128b.example.test")))
        for bad in ("a\\899b.example.test", "a\\256.example.test", "a\\12.example.test", "trailing\\", "a\\046b.example.test"):
            self.assertIsNone(sd.decode_dns_name(bad), bad)                                     # not valid for its form
        self.assertEqual(sd.decode_dns_name("a\\-b.example.test"), "a-b.example.test")         # an escaped character

    def test_route53_form_is_octal(self):
        self.assertEqual(sd.decode_dns_name("\\052.dev.example.test.", "route53"), "*.dev.example.test")
        for bad in ("a\\128.example.test", "a\\899.example.test", "a\\-b.example.test", "a\\056b.example.test"):
            self.assertIsNone(sd.decode_dns_name(bad, "route53"), bad)

    def test_an_undecodable_name_is_dropped_like_any_rejected_name(self):
        col = sd.Collector(APEXES)
        self.assertFalse(col.add("a\\899b.example.test", "axfr"))
        self.assertFalse(col.add("x\\128.example.test", "route53", form="route53"))
        self.assertEqual(col.hosts, {})


# ======================================================================================== one source fails
class OneSourceFails(Base):
    def test_a_zone_file_with_a_decimal_escape_through_main(self):
        """The seeder process itself, once, on a zone file holding a DNS-SD name with decimal escapes."""
        wr(os.path.join(self.out, "seed_hosts.txt"), "old.example.test\n")
        wr(os.path.join(self.out, "status.json"), '{"updated_at": "OLD"}\n')
        wr(os.path.join(self.zones, "example.test.zone"), "www IN A 192.0.2.1\nLiving\\032Room\\226\\128\\153s._airplay._tcp IN PTR x\n")
        env = {"PATH": os.environ["PATH"], "SEED_ZONE_FILES": "1"}
        p = subprocess.run([sys.executable, "-I", "-B", SEED_PY, "--scope", self.scope, "--out", self.out, "--zones", self.zones],
                           env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertNotIn("Traceback", p.stderr)
        self.assertEqual(self.written(), ["mail.example-two.test", "www.example-two.test", "www.example.test"])
        self.assertNotEqual(json.loads(rd(os.path.join(self.out, "status.json"))).get("updated_at"), "OLD")

    def test_a_transfer_with_an_impossible_escape(self):
        st, log = self.run_once({"axfr": lambda a: FakeSocket(transfer("good.example.test", "a\\899b.example.test"))},
                                SEED_AXFR="example.test@192.0.2.53")
        self.assertIn("good.example.test", self.written())
        self.assertIn("www.example-two.test", self.written())
        self.assertEqual(st["sources"]["axfr"]["errors"], [])
        self.assert_clean_log(log, "899")

    def pdns(self, answer):
        return self.run_once({"pdns": FakeOpener(answer)}, SEED_PDNS_URL="https://192.0.2.80", SEED_PDNS_ZONES="example.test",
                             SEED_PDNS_API_KEY_FILE=self.key)

    def test_pdns_answers_of_the_wrong_shape_are_a_fixed_code(self):
        for label, answer in (("rrsets is a number", {"rrsets": 5}),
                              ("records is a number", {"rrsets": [{"name": "a.example.test.", "type": "CNAME", "records": 7}]}),
                              ("an rrset is a list", {"rrsets": [["a.example.test."]]}),
                              ("a name is a number", {"rrsets": [{"name": 5, "type": "A"}]}),
                              ("the answer is a list", [PDNS]),
                              ("200,000 opening brackets", b"[" * 200000)):
            st, log = self.pdns(answer)
            self.assertEqual(st["sources"]["pdns"]["errors"], ["pdns-answer-invalid"], label)
            self.assertEqual(self.written(), ["mail.example-two.test", "www.example-two.test"], label)
            self.assertIn("pdns", st["failed_sources"], label)
            self.assert_clean_log(log, "rrsets", "[[[")

    def test_any_exception_inside_a_source_is_a_fixed_code_and_the_others_are_written(self):
        def boom(*a, **k):
            raise KeyError(CANARY + " answer text")
        with unittest.mock.patch.object(sd, "parse_axfr_message", boom):
            st, log = self.run_once({"axfr": lambda a: FakeSocket(transfer("good.example.test"))}, SEED_AXFR="example.test@192.0.2.53")
        self.assertEqual(st["sources"]["axfr"]["errors"], ["axfr-internal-error"])
        self.assertEqual(st["failed_sources"], ["axfr"])
        self.assertEqual(self.written(), ["mail.example-two.test", "www.example-two.test"])
        self.assertIn("seeder: source axfr failed: axfr-internal-error", log)
        self.assert_clean_log(log, CANARY, "KeyError", "answer text")

    def test_a_source_that_raised_contributes_no_names(self):
        calls = []

        def half(col, *a, **k):
            col.add("early.example.test", "pdns")
            calls.append(1)
            raise RuntimeError(CANARY)
        with unittest.mock.patch.object(sd, "ingest_pdns_zone", half):
            st, log = self.pdns(PDNS)
        self.assertEqual(calls, [1])
        self.assertEqual(st["sources"]["pdns"]["errors"], ["pdns-internal-error"])
        self.assertNotIn("early.example.test", self.written())
        self.assert_clean_log(log, CANARY)

    def test_status_is_rewritten_when_every_source_failed(self):
        wr(os.path.join(self.out, "seed_hosts.txt"), "old.example.test\n")
        wr(os.path.join(self.out, "status.json"), '{"updated_at": "OLD", "result": "written"}\n')
        os.unlink(os.path.join(self.zones, "example-two.test.hosts"))
        with unittest.mock.patch.object(sd, "collect_zone_files", lambda *a, **k: (_ for _ in ()).throw(MemoryError())):
            st, log = self.run_once({"axfr": lambda a: FakeSocket(lambda qid: [message(qid, [], rcode=5)])},
                                    SEED_AXFR="example.test@192.0.2.53")
        status = json.loads(rd(os.path.join(self.out, "status.json")))
        self.assertNotEqual(status["updated_at"], "OLD")
        self.assertEqual(status["result"], "kept-previous")
        self.assertEqual(status["failed_sources"], ["axfr", "zonefiles"])
        self.assertEqual(status["sources"]["zonefiles"]["errors"], ["zonefiles-internal-error"])
        self.assert_clean_log(log)

    def test_in_interval_mode_no_exception_ends_the_loop_and_the_next_run_is_on_time(self):
        runs, waits = [], []

        def run_once(*a, **k):
            runs.append(1)
            if len(runs) == 1:
                raise RuntimeError(CANARY)
            if len(runs) == 2:
                raise OSError(CANARY)
            sd._STOP = True
            return {}
        with Captured() as cap, unittest.mock.patch.object(sd, "run_once", run_once), \
                unittest.mock.patch.object(sd, "_wait_until", lambda t: waits.append(t - time.monotonic()), create=True), \
                unittest.mock.patch.dict(os.environ, {"SEED_ZONE_FILES": "1", "SEED_INTERVAL_MINUTES": "15"}):
            sd._STOP = False
            try:
                rc = sd.main(["--scope", self.scope, "--out", self.out, "--zones", self.zones])
            finally:
                sd._STOP = False
        self.assertEqual((rc, len(runs)), (0, 3))
        self.assertTrue(all(0 < w <= 15 * 60 for w in waits), waits)          # counted from the start of each run
        log = cap.err.getvalue()
        self.assertIn("seeder: the run failed (internal error); the next run is at the usual time", log)
        self.assertIn("seeder: could not write to the seed folder; the next run is at the usual time", log)
        self.assert_clean_log(log, CANARY)

    def test_once_mode_still_exits_non_zero_on_a_failed_run(self):
        with Captured(), unittest.mock.patch.object(sd, "run_once", lambda *a, **k: (_ for _ in ()).throw(RuntimeError(CANARY))), \
                unittest.mock.patch.dict(os.environ, {"SEED_ZONE_FILES": "1"}):
            self.assertEqual(sd.main(["--scope", self.scope, "--out", self.out, "--zones", self.zones]), 1)


# ======================================================================================== time limits
class Limits(Base):
    def test_a_400000_token_line_finishes_quickly(self):
        wr(os.path.join(self.zones, "example.test.zone"), "x " + "1 " * 400000 + "\nwww IN A 192.0.2.1\n")
        t0 = time.monotonic()
        st, log = self.run_once()
        self.assertLess(time.monotonic() - t0, 3)
        self.assertIn("www.example.test", self.written())
        self.assertIn("zonefile-line-too-long", st["sources"]["zonefiles"]["errors"])

    def test_tokens_are_walked_by_index(self):
        col = sd.Collector(APEXES)
        line = "www " + "300 " * 15000 + "IN A 192.0.2.1"                 # under the line cap, many tokens
        t0 = time.monotonic()
        sd.parse_zone_text(line + "\n", "example.test", col, "zonefiles")
        self.assertLess(time.monotonic() - t0, 0.5)
        self.assertIn("www.example.test", col.hosts)

    def test_the_zone_file_source_has_one_deadline(self):
        wr(os.path.join(self.zones, "example.test.zone"), "www IN A 192.0.2.1\n")
        with unittest.mock.patch.object(sd, "ZONE_FILES_DEADLINE_S", -1, create=True):
            st, log = self.run_once()
        self.assertIn("zonefiles-deadline", st["sources"]["zonefiles"]["errors"])
        self.assertEqual(st["failed_sources"], ["zonefiles"])

    def test_the_pdns_request_has_one_deadline(self):
        class Drip(FakeResponse):
            """An endpoint that sends one byte every 50 ms, never pausing long enough for the per-read timeout. read(n)
            behaves like a socket file's: it returns only when n bytes have arrived or the stream ended."""

            def read1(self, n=-1):
                time.sleep(0.05)
                return super().read1(1)

            def read(self, n=-1):
                out = b""
                while n < 0 or len(out) < n:
                    b = self.read1(1)
                    if not b:
                        break
                    out += b
                return out

        class SlowOpener(FakeOpener):
            def open(self, req, timeout=None):
                self.requests.append(timeout)
                return Drip(json.dumps(PDNS).encode())
        col = sd.Collector(["example.test"])
        c = cfg(SEED_PDNS_URL="https://192.0.2.80", SEED_PDNS_ZONES="example.test", SEED_PDNS_API_KEY_FILE=self.key)
        t0 = time.monotonic()
        with unittest.mock.patch.object(sd, "PDNS_DEADLINE_S", 1, create=True):
            sd.collect_pdns(col, c, opener=SlowOpener(None))
        self.assertLess(time.monotonic() - t0, 3)
        self.assertEqual(col.errors["pdns"], ["pdns-timeout"])
        self.assertEqual(col.hosts, {})


# ============================================================================================ zones, shares
class ZonesAndShares(Base):
    def test_a_transfer_keeps_only_names_under_its_zone(self):
        col = sd.Collector(APEXES)
        sd.collect_axfr(col, cfg(SEED_AXFR="example.test@192.0.2.53"),
                        connect=lambda a: FakeSocket(transfer("planted.example-two.test", "in.example.test",
                                                              question="something.else.invalid")))
        self.assertEqual(sorted(col.hosts), ["example.test", "in.example.test"])

    def test_names_from_a_transfer_that_failed_are_discarded(self):
        col = sd.Collector(APEXES)
        sd.collect_axfr(col, cfg(SEED_AXFR="example.test@192.0.2.53"), connect=lambda a: FakeSocket(lambda qid: [
            message(qid, [rr("example.test", 6, soa()), rr("early.example.test", 1)]), b"\x00" * 5]))
        self.assertEqual((sorted(col.hosts), col.errors["axfr"]), ([], ["axfr-malformed-answer"]))

    def test_a_pdns_zone_and_a_route53_zone_keep_only_their_own_names(self):
        col = sd.Collector(APEXES)
        answer = {"name": "example.test.", "rrsets": [{"name": "a.example.test.", "type": "A", "records": []},
                                                      {"name": "b.example-two.test.", "type": "A", "records": []},
                                                      {"name": "c.example.test.", "type": "CNAME",
                                                       "records": [{"content": "d.example-two.test."}]}]}
        sd.collect_pdns(col, cfg(SEED_PDNS_URL="https://192.0.2.80", SEED_PDNS_ZONES="example.test", SEED_PDNS_API_KEY_FILE=self.key),
                        opener=FakeOpener(answer))
        self.assertEqual(sorted(col.hosts), ["a.example.test", "c.example.test"])
        col = sd.Collector(APEXES)
        r53 = FakeRoute53([{"HostedZones": [{"Id": "Z2", "Name": "sub.example.test.", "Config": {}}]}],
                          {"Z2": [{"ResourceRecordSets": [{"Name": "x.sub.example.test.", "Type": "A"},
                                                          {"Name": "www.example.test.", "Type": "A"},
                                                          {"Name": "y.example-two.test.", "Type": "A"}]}]})
        sd.collect_route53(col, cfg(SEED_ROUTE53="1"), client=r53)
        self.assertEqual(sorted(col.hosts), ["x.sub.example.test"])

    def test_no_enabled_source_may_use_more_than_its_equal_share(self):
        wr(os.path.join(self.zones, "example.test.hosts"), "".join(f"h{i}\n" for i in range(8)))
        with unittest.mock.patch.object(sd, "MAX_NAMES", 10):
            st, log = self.run_once({"axfr": lambda a: FakeSocket(transfer(*[f"t{i}.example.test" for i in range(8)]))},
                                    SEED_AXFR="example.test@192.0.2.53")
        # each source's share (5) is split between its units: the two zone files get 2 each
        self.assertEqual((st["sources"]["zonefiles"]["names"], st["sources"]["axfr"]["names"]), (4, 5))
        self.assertIn("too-many-names", st["sources"]["zonefiles"]["errors"])
        self.assertIn("too-many-names", st["sources"]["axfr"]["errors"])
        self.assertEqual(st["failed_sources"], ["axfr", "zonefiles"])
        self.assertEqual(len(self.written()), 9)


# ====================================================================================== the AWS clients
class AwsClients(unittest.TestCase):
    PLANTED = {"AWS_ENDPOINT_URL": "http://endpoint-env-was-read.invalid", "AWS_ENDPOINT_URL_ROUTE53": "http://r53-env-was-read.invalid",
               "AWS_ENDPOINT_URL_STS": "http://sts-env-was-read.invalid", "HTTPS_PROXY": "http://proxy-env-was-read.invalid:3128",
               "https_proxy": "http://proxy-env-was-read.invalid:3128", "AWS_CA_BUNDLE": "/tmp/ca-env-was-read.pem",
               "REQUESTS_CA_BUNDLE": "/tmp/ca-env-was-read.pem", "AWS_USE_FIPS_ENDPOINT": "true",
               "BOTOCORE_EXPERIMENTAL__PLUGINS": "planted=planted_module", "AWS_DATA_PATH": "/tmp/planted-data"}

    def look(self, c):
        s = c._endpoint.http_session
        return c.meta.endpoint_url, s._proxy_config._proxies, s._verify

    def test_the_real_clients_take_no_endpoint_proxy_or_ca_bundle_from_the_environment(self):
        """Without the start-up step: real clients built in this container, no request made."""
        import boto3
        with unittest.mock.patch.dict(os.environ, self.PLANTED):
            r53 = sd.route53_client(cfg(SEED_ROUTE53="1"))
            self.assertEqual(self.look(r53)[:2], ("https://route53.amazonaws.com", {}))
            sts = sd.aws_client(boto3.session.Session(region_name="eu-west-1"), "sts", cfg(SEED_ROUTE53="1", SEED_ROUTE53_REGION="eu-west-1"))
        for c, url in ((r53, "https://route53.amazonaws.com"), (sts, "https://sts.eu-west-1.amazonaws.com")):
            endpoint, proxies, verify = self.look(c)
            self.assertEqual((endpoint, proxies), (url, {}))
            self.assertEqual(verify, sd.ca_bundle())
            self.assertTrue(os.path.isfile(verify))
            self.assertNotIn("env-was-read", json.dumps([endpoint, proxies, verify]))

    def test_requests_go_to_the_fixed_endpoints_signed_for_the_right_region(self):
        """The request each client would send, captured before it is sent (no socket): the URL and the credential
        scope of its signature. Route 53 is signed for us-east-1 whatever SEED_ROUTE53_REGION says."""
        import boto3

        class Stop(Exception):
            pass
        seen = []

        def grab(request, **kw):
            seen.append((request.url, request.headers.get("Authorization", b"").decode() if isinstance(
                request.headers.get("Authorization"), bytes) else request.headers.get("Authorization")))
            raise Stop()
        c = cfg(SEED_ROUTE53="1", SEED_ROUTE53_REGION="eu-west-1")
        with unittest.mock.patch.dict(os.environ, self.PLANTED):
            r53 = sd.route53_client(c)
            sts = sd.aws_client(boto3.session.Session(region_name="eu-west-1"), "sts", c)
        for client, call in ((r53, lambda: r53.list_hosted_zones()),
                             (sts, lambda: sts.assume_role(RoleArn="arn:aws:iam::000000000000:role/x", RoleSessionName="momus-seeder"))):
            client.meta.events.register("before-send", grab)
            with self.assertRaises(Stop):
                call()
        (u1, a1), (u2, a2) = seen
        self.assertTrue(u1.startswith("https://route53.amazonaws.com/"), u1)
        self.assertIn("/us-east-1/route53/aws4_request", a1)
        self.assertTrue(u2.startswith("https://sts.eu-west-1.amazonaws.com"), u2)
        self.assertIn("/eu-west-1/sts/aws4_request", a2)

    def test_the_start_up_step_removes_the_names_and_logs_names_only(self):
        env = dict(self.PLANTED, AWS_ACCESS_KEY_ID="kept", AWS_SECRET_ACCESS_KEY="kept", AWS_SESSION_TOKEN="kept",
                   AWS_SHARED_CREDENTIALS_FILE="/run/secrets/x", AWS_CONTAINER_CREDENTIALS_RELATIVE_URI="/v2/x",
                   AWS_WEB_IDENTITY_TOKEN_FILE="/x", AWS_ROLE_ARN="arn:aws:iam::000000000000:role/x", AWS_REGION="eu-west-1",
                   AWS_EC2_METADATA_DISABLED="true", NO_PROXY="*", AWS_CSM_ENABLED="true", SSLKEYLOGFILE="/tmp/k", PATH="/bin",
                   SEED_ROUTE53="1")
        with Captured() as cap:
            gone = sd.scrub_environment(env)
        self.assertEqual(sorted(gone), sorted(set(self.PLANTED) | {"NO_PROXY", "AWS_CSM_ENABLED", "SSLKEYLOGFILE"}))
        for kept in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_SHARED_CREDENTIALS_FILE",
                     "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN", "AWS_REGION",
                     "AWS_EC2_METADATA_DISABLED", "PATH", "SEED_ROUTE53"):
            self.assertIn(kept, env)
        log = cap.err.getvalue()
        self.assertIn("removed from the environment", log)
        self.assertIn("AWS_ENDPOINT_URL", log)
        self.assertNotIn("env-was-read", log)
        self.assertNotIn("planted_module", log)

    def test_main_runs_the_start_up_step_first(self):
        seen = []
        with tempfile.TemporaryDirectory() as d, Captured(), \
                unittest.mock.patch.dict(os.environ, {"SEED_ZONE_FILES": "1", "HTTPS_PROXY": "http://proxy-env-was-read.invalid:3128"}), \
                unittest.mock.patch.object(sd, "run_once", lambda *a, **k: seen.append(os.environ.get("HTTPS_PROXY"))):
            self.assertEqual(sd.main(["--scope", d, "--out", d, "--zones", d]), 0)
        self.assertEqual(seen, [None])


# ======================================================================================== the scanner's list
class VerifiedDomains(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def put(self, doc):
        wr(os.path.join(self.d, sd.VERIFIED_FILE), doc if isinstance(doc, str) else json.dumps(doc))

    def test_the_list_is_read_with_care(self):
        self.put({"schema": "momus-verified-domains-v1", "updated_at": "2030-01-01T00:00:00Z",
                  "domains": ["example.test", "Bad Name", "x;id.test", 5, "example-two.test"]})
        self.assertEqual(sd.read_verified_domains(self.d), (["example-two.test", "example.test"], 3, None))
        for doc, code in (({"schema": "momus-scope-status-v1", "domains": {}}, "verified-domains-invalid"),
                          ({"schema": "momus-verified-domains-v1", "domains": {"example.test": 1}}, "verified-domains-invalid"),
                          ("[" * 200000, "verified-domains-invalid"), ("\xff", "verified-domains-invalid")):
            self.put(doc)
            self.assertEqual(sd.read_verified_domains(self.d), ([], 0, code))
        os.unlink(os.path.join(self.d, sd.VERIFIED_FILE))
        self.assertEqual(sd.read_verified_domains(self.d)[2], "verified-domains-missing")
        other = os.path.join(self.d, "elsewhere.json")
        wr(other, json.dumps({"schema": "momus-verified-domains-v1", "domains": ["example.test"]}))
        os.symlink(other, os.path.join(self.d, sd.VERIFIED_FILE))
        self.assertEqual(sd.read_verified_domains(self.d)[2], "verified-domains-unreadable", "a link is never followed")
        os.unlink(os.path.join(self.d, sd.VERIFIED_FILE))
        with unittest.mock.patch.object(sd, "MAX_VERIFIED_BYTES", 10):
            self.put({"schema": "momus-verified-domains-v1", "domains": ["example.test"]})
            self.assertEqual(sd.read_verified_domains(self.d)[2], "verified-domains-unreadable")

    def test_the_seeder_no_longer_reads_the_published_folder(self):
        src = rd(sd.__file__)
        self.assertNotIn("scope_status.json", src)
        self.assertNotIn("/srv/published", src)
        self.assertEqual(sd.DEFAULT_SCOPE, "/srv/seed-scope")


# ======================================================================================== the log
class LogHoldsFixedLinesOnly(Base):
    """The seeder process silences library logging, Python warnings and tracebacks at start, so its log holds only
    its own fixed lines, and it warns once when the PowerDNS key would cross a network in clear text."""
    SECRET = "LEAKED-" + CANARY

    def seeder(self, code, **env):
        prog = ("import logging, sys, threading, warnings\n"
                f"sys.path.insert(0, {os.path.dirname(SEED_PY)!r})\n"
                "import seed_dns as sd\n" + code +
                f"\nsys.exit(sd.main(['--scope', {self.scope!r}, '--out', {self.out!r}, '--zones', {self.zones!r}]))\n")
        return subprocess.run([sys.executable, "-I", "-B", "-c", prog], env={"PATH": os.environ["PATH"], **env},
                              capture_output=True, text=True, timeout=60)

    def test_library_log_records_warnings_and_thread_tracebacks_never_reach_the_log(self):
        code = ("real = sd.run_once\n"
                "def noisy(*a, **k):\n"
                f"    logging.getLogger('botocore.credentials').warning({self.SECRET!r})\n"
                f"    logging.getLogger('urllib3.connectionpool').error({self.SECRET!r})\n"
                f"    warnings.warn({self.SECRET!r})\n"
                f"    def boom(): raise RuntimeError({self.SECRET!r})\n"
                "    t = threading.Thread(target=boom); t.start(); t.join()\n"
                "    return real(*a, **k)\n"
                "sd.run_once = noisy\n")
        p = self.seeder(code, SEED_ZONE_FILES="1")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assert_clean_log(p.stderr, self.SECRET, CANARY)
        self.assertTrue(p.stderr.strip())
        self.assertTrue(all(line.startswith("seeder: ") for line in p.stderr.splitlines()), p.stderr)
        self.assertIn("seeder: a background task failed (internal error)", p.stderr)
        self.assertEqual(self.written(), ["mail.example-two.test", "www.example-two.test"])

    def test_an_uncaught_exception_is_one_fixed_line(self):
        p = self.seeder("def bad(*a, **k):\n"
                        f"    raise KeyboardInterrupt({self.SECRET!r})\n"       # not an Exception: main does not catch it
                        "sd.run_once = bad\n", SEED_ZONE_FILES="1")
        self.assertNotEqual(p.returncode, 0)
        self.assert_clean_log(p.stderr, self.SECRET, CANARY)
        self.assertEqual(p.stderr.splitlines(), ["seeder: stopped (internal error)"])

    def test_plain_http_to_a_host_that_is_not_loopback_is_warned_about(self):
        for url, warned in (("http://pdns.internal.test:8081", True), ("http://192.0.2.5", True),
                            ("http://[2001:db8::1]:8081/api", True), ("http://127.0.0.1:8081", False),
                            ("http://localhost:8081", False), ("http://[::1]:8081", False),
                            ("https://pdns.internal.test", False)):
            c = cfg(SEED_PDNS_URL=url, SEED_PDNS_ZONES="example.test", SEED_PDNS_API_KEY_FILE=self.key)
            self.assertEqual(c.pdns_cleartext(), warned, url)
        p = self.seeder("", SEED_PDNS_URL="http://192.0.2.5:8081", SEED_PDNS_ZONES="example.test",
                        SEED_PDNS_API_KEY_FILE="/nonexistent/key")
        self.assertIn("seeder: " + sd.PDNS_CLEARTEXT_LINE + "\n", p.stderr)
        self.assertEqual(p.stderr.count("clear text"), 1)
        p = self.seeder("", SEED_PDNS_URL="https://192.0.2.5:8081", SEED_PDNS_ZONES="example.test",
                        SEED_PDNS_API_KEY_FILE="/nonexistent/key")
        self.assertNotIn("clear text", p.stderr)


if __name__ == "__main__":
    unittest.main()
