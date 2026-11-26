"""Unit tests for seeder/seed_dns.py. Run only by seeder/tests/run_tests.sh (the seeder image, --network none, dummy
credentials, outbound-socket guard in run.py). Every source is replaced by a stub: the Route 53 client object, the
socket of a zone transfer, the PowerDNS opener. The default credential chain and the role assumption never run for
real; the one test of route53_client() gives it a stand-in boto3 module."""
import contextlib
import io
import json
import os
import re
import struct
import sys
import tempfile
import types
import unittest
import unittest.mock
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
SEEDER = os.path.dirname(HERE)
REPO = os.path.dirname(SEEDER)
sys.path.insert(0, SEEDER)
import seed_dns as sd  # noqa: E402

CANARY = "CANARY-7f3a91c2-do-not-leak"
APEXES = ["example.test", "example-two.test"]


def rd(path):
    with open(path) as fh:
        return fh.read()


def wr(path, text, mode="w"):
    with open(path, mode) as fh:
        fh.write(text)


def scope_status(scope_dir, states):
    """The scanner's verified-domain list, as scanner/runner.py publish_seed_scope writes it: the domains of
    states whose state is "verified", and nothing else (the seeder does not read published/scope_status.json)."""
    os.makedirs(scope_dir, exist_ok=True)
    doc = {"schema": "momus-verified-domains-v1", "updated_at": "2030-10-01T09:00:12Z",
           "domains": sorted(d for d, s in states.items() if s == "verified")}
    wr(os.path.join(scope_dir, "verified_domains.json"), json.dumps(doc))


def cfg(**env):
    return sd.Config({k: v for k, v in env.items()})


# ---------------------------------------------------------------------------------------------- fixtures (moved)
ROUTE53 = [
    {"Name": "example.test.", "Type": "NS", "ResourceRecords": [{"Value": "ns-1.awsdns-00.com."}]},
    {"Name": "example.test.", "Type": "SOA", "ResourceRecords": [{"Value": "x"}]},
    {"Name": "example.test.", "Type": "A", "ResourceRecords": [{"Value": "192.0.2.1"}]},
    {"Name": "www.example.test.", "Type": "A", "AliasTarget": {"DNSName": "d111.cloudfront.net.", "HostedZoneId": "Z2"}},
    {"Name": "api.example.test.", "Type": "CNAME", "ResourceRecords": [{"Value": "test-lb-456.us-east-1.elb.amazonaws.com."}]},
    {"Name": "\\052.dev.example.test.", "Type": "A", "ResourceRecords": [{"Value": "192.0.2.2"}]},
    {"Name": "Mail.Example.Test.", "Type": "MX", "ResourceRecords": [{"Value": "10 mx.mailer.example"}]},
    {"Name": "alias.example.test.", "Type": "CNAME", "ResourceRecords": [{"Value": "target.example.test."}]},
    {"Name": "saas.example.test.", "Type": "CNAME", "ResourceRecords": [{"Value": "pages.vendor.example."}]},
]

ZONE = """$ORIGIN example-two.test.
$TTL 300
@       IN SOA ns1 hostmaster (
            2030102401 ; serial
            3600 600 86400 300 )
        IN NS  ns1
ns1     IN A   192.0.2.10
www     300 IN A 192.0.2.11
        IN AAAA 2001:db8::1
ftp     CNAME www
old     CNAME legacy.example-two.test.
ext     CNAME somewhere.else.example.
_dmarc  IN TXT "v=DMARC1; p=none"
*.wild  IN A   192.0.2.12
"""

PDNS = {"name": "example.test.", "rrsets": [
    {"name": "example.test.", "type": "SOA", "records": [{"content": "x"}]},
    {"name": "sip.example.test.", "type": "A", "records": [{"content": "192.0.2.20"}]},
    {"name": "cdn.example.test.", "type": "CNAME", "records": [{"content": "sip.example.test."}]},
]}


# -------------------------------------------------------------------------------------------------------- stubs
class FakePaginator:
    def __init__(self, pages, calls, name):
        self.pages, self.calls, self.name = pages, calls, name

    def paginate(self, **kw):
        self.calls.append((self.name, kw))
        if isinstance(self.pages, Exception):
            raise self.pages
        if callable(self.pages):
            return iter(self.pages(**kw))
        return iter(self.pages)


class FakeRoute53:
    """Stands in for a boto3 Route 53 client: get_paginator('list_hosted_zones' | 'list_resource_record_sets')."""

    def __init__(self, zones_pages, rrsets_by_zone):
        self.zones_pages, self.rrsets_by_zone, self.calls = zones_pages, rrsets_by_zone, []

    def get_paginator(self, name):
        if name == "list_hosted_zones":
            return FakePaginator(self.zones_pages, self.calls, name)
        if name == "list_resource_record_sets":
            return FakePaginator(lambda HostedZoneId: self.rrsets_by_zone[HostedZoneId], self.calls, name)
        raise AssertionError(name)


class ClientError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.response = {"Error": {"Code": code, "Message": message}}


def dns_name(name):
    return b"".join(bytes([len(x)]) + x.encode() for x in name.split(".")) + b"\x00"


def rr(owner, rtype, rdata=b"\x00\x00\x00\x00"):
    return dns_name(owner) + struct.pack("!HHIH", rtype, 1, 300, len(rdata)) + rdata


def message(qid, records, rcode=0, question="example.test"):
    q = dns_name(question) + struct.pack("!HH", 252, 1)
    return struct.pack("!HHHHHH", qid, 0x8400 | rcode, 1, len(records), 0, 0) + q + b"".join(records)


class FakeSocket:
    """A TCP connection to a DNS server that answers the AXFR question with prepared messages."""

    def __init__(self, build):
        self.build, self.sent, self.buf, self.closed, self.timeout = build, b"", b"", False, None

    def settimeout(self, t):
        self.timeout = t

    def sendall(self, data):
        self.sent += data
        qid = struct.unpack("!H", data[2:4])[0]
        for m in self.build(qid):
            self.buf += struct.pack("!H", len(m)) + m

    def recv(self, n):
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def close(self):
        self.closed = True


def soa():
    return dns_name("ns1.example.test") + dns_name("hostmaster.example.test") + struct.pack("!IIIII", 1, 2, 3, 4, 5)


def good_transfer(qid):
    return [message(qid, [rr("example.test", 6, soa()), rr("www.example.test", 1, b"\xc0\x00\x02\x01"),
                          rr("_sip._tcp.example.test", 33, b"\x00" * 8)]),
            message(qid, [rr("cname.example.test", 5, dns_name("target.example.test")),
                          rr("out.example.test", 5, dns_name("elsewhere.example")),
                          rr("Mixed.Example.Test", 1, b"\xc0\x00\x02\x02"),
                          rr("example.test", 6, soa())])]


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


class FakeOpener:
    def __init__(self, answer):
        self.answer, self.requests = answer, []

    def open(self, req, timeout=None):
        self.requests.append((req.full_url, dict(req.header_items()), timeout))
        if isinstance(self.answer, Exception):
            raise self.answer
        return FakeResponse(self.answer if isinstance(self.answer, bytes) else json.dumps(self.answer).encode())


class Captured:
    """stderr of the code under test, to check that logs carry no secret and no target text."""

    def __enter__(self):
        self.err = io.StringIO()
        self._cm = contextlib.redirect_stderr(self.err)
        self._cm.__enter__()
        return self

    def __exit__(self, *a):
        return self._cm.__exit__(*a)


# ============================================================================== moved from scanner/pipeline/test_seed_dns.py
class MovedTests(unittest.TestCase):
    def test_route53_names_and_targets(self):
        col = sd.Collector(APEXES)
        sd.ingest_route53_rrsets(col, ROUTE53)
        self.assertEqual(sorted(col.hosts), [
            "alias.example.test", "api.example.test", "dev.example.test", "example.test",
            "mail.example.test", "saas.example.test", "target.example.test", "www.example.test"])
        self.assertNotIn("pages.vendor.example", col.hosts)
        self.assertNotIn("test-lb-456.us-east-1.elb.amazonaws.com", col.hosts)
        self.assertEqual(col.counts(), {"route53": 8, "zonefiles": 0, "axfr": 0, "pdns": 0})

    def test_bind_zone_text(self):
        col = sd.Collector(APEXES)
        n = sd.parse_zone_text(ZONE, "ignored-when-origin-present", col, "zonefiles")
        self.assertEqual(sorted(col.hosts), [
            "example-two.test", "ext.example-two.test", "ftp.example-two.test",
            "legacy.example-two.test", "ns1.example-two.test", "old.example-two.test", "wild.example-two.test",
            "www.example-two.test"])
        self.assertNotIn("somewhere.else.example", col.hosts)
        self.assertNotIn("_dmarc.example-two.test", col.hosts, "underscore labels are not hosts (same rule as recon.sh)")
        self.assertEqual(n, 9)

    def test_plain_hostname_list(self):
        col = sd.Collector(APEXES)
        n = sd.parse_zone_text("www.example.test\nAPI.example.test.\nmail\n_dkim._domainkey.example.test\n# c\n\n192.0.2.7\n2001:db8::7\n",
                               "example.test", col, "zonefiles")
        self.assertEqual(sorted(col.hosts), ["api.example.test", "mail.example.test", "www.example.test"])
        self.assertEqual(n, 3)

    def test_pdns_zone(self):
        col = sd.Collector(APEXES)
        self.assertEqual(sd.ingest_pdns_zone(col, PDNS), 3)
        self.assertEqual(sorted(col.hosts), ["cdn.example.test", "example.test", "sip.example.test"])

    def test_out_of_scope_and_junk_rejected(self):
        col = sd.Collector(APEXES)
        for bad in ("other.example", "", "*.", "-bad.example.test", "bad-.example.test", "a..example.test", "example.test.evil.example",
                    "192.0.2.1", "a b.example.test", "x;id.example.test", "$(id).example.test", "a" * 64 + ".example.test"):
            col.add(bad, "zonefiles")
        self.assertEqual(col.hosts, {})

    def test_write_outputs_and_keep_previous_when_empty(self):
        with tempfile.TemporaryDirectory() as out:
            c = cfg(SEED_ROUTE53="1")
            col = sd.Collector(APEXES)
            sd.ingest_route53_rrsets(col, ROUTE53)
            st = sd.write_outputs(col, out, c, None, 2, 0)
            self.assertEqual(st["result"], "written")
            lines = rd(os.path.join(out, "seed_hosts.txt")).splitlines()
            self.assertEqual(lines, sorted(lines))
            self.assertIn("api.example.test", lines)
            self.assertTrue(all(sd.valid_host(x) for x in lines), "host names only: no header, no comment, no address")
            self.assertEqual(sorted(os.listdir(out)), ["seed_hosts.txt", "status.json"], "no provenance or inventory file")
            empty = sd.Collector(APEXES)
            st = sd.write_outputs(empty, out, c, None, 2, 0)
            self.assertEqual(st["result"], "kept-previous")
            self.assertIn("api.example.test", rd(os.path.join(out, "seed_hosts.txt")))
            self.assertIsNone(json.loads(rd(os.path.join(out, "status.json")))["count"])

    def test_env_example_lists_every_variable_the_module_reads(self):
        src = rd(sd.__file__)
        read = set(re.findall(r'env\.get\("(SEED_[A-Z0-9_]+)"', src)) | set(re.findall(r'switch\("(SEED_[A-Z0-9_]+)"\)', src))
        self.assertIn("SEED_PDNS_API_KEY_FILE", read)
        self.assertIn("SEED_ROUTE53", read)
        example = rd(os.path.join(REPO, ".env.example"))
        listed = set(re.findall(r"^#? ?(SEED_[A-Z0-9_]+)=$", example, re.M))
        self.assertEqual(listed, read)
        self.assertNotIn("SEED_PDNS_API_KEY=", example.replace("SEED_PDNS_API_KEY_FILE=", ""), "the key is read from a file only")
        lines = example.splitlines()
        for i, line in enumerate(lines):     # each setting has its description right above it (or above its group)
            if re.match(r"^SEED_[A-Z0-9_]+=$", line):
                j = i - 1
                while re.match(r"^SEED_[A-Z0-9_]+=$", lines[j]):
                    j -= 1
                self.assertTrue(lines[j].startswith("# "), line)

    def test_nothing_configured_says_so(self):
        with tempfile.TemporaryDirectory() as d, Captured() as cap:
            scope_status(os.path.join(d, "pub"), {"example.test": "verified"})
            os.makedirs(os.path.join(d, "seed"))
            with unittest.mock.patch.dict(os.environ, {k: v for k, v in os.environ.items() if not k.startswith("SEED_")}, clear=True):
                rc = sd.main(["--scope", os.path.join(d, "pub"), "--out", os.path.join(d, "seed"), "--zones", os.path.join(d, "z")])
        self.assertEqual(rc, 0)
        self.assertIn("no source is configured", cap.err.getvalue())
        self.assertIn(".env.example", cap.err.getvalue())

    def test_axfr_has_connect_and_read_timeouts(self):
        """Replaces the dig-flags test: the transfer is done in Python now (no dig in the seeder image)."""
        seen = []
        socks = []

        def connect(addr):
            seen.append(addr)
            socks.append(FakeSocket(good_transfer))
            return socks[-1]
        col = sd.Collector(APEXES)
        sd.axfr("example.test", "192.0.2.53", col, connect=connect)
        self.assertEqual(seen, [("192.0.2.53", 53)])
        self.assertEqual(socks[0].timeout, sd.AXFR_TIMEOUT_S)
        self.assertTrue(socks[0].closed)
        self.assertGreater(sd.AXFR_DEADLINE_S, sd.AXFR_TIMEOUT_S)


# ====================================================================================== removed paths are gone
class RemovedTests(unittest.TestCase):
    def test_organization_walk_sso_profiles_and_inventory_are_gone(self):
        for name in ("SsoSession", "aws", "aws_inventory", "assume_role_env", "account_id", "glob_json", "_refresh_sso_token",
                     "_aws_config_block", "route53_zones", "load_env", "read_apexes", "normalize_aws_name", "SEED_ENV_EXAMPLE"):
            self.assertFalse(hasattr(sd, name), name)
        self.assertFalse(hasattr(sd.Collector(APEXES), "owned_aws"))
        self.assertFalse(hasattr(sd.Collector, "add_aws_resource"))
        src = rd(sd.__file__).lower()
        for gone in ("sso", "organizations", "list-accounts", "list_accounts", "describe-load-balancers", "describe_load_balancers",
                     "cloudfront", "globalaccelerator", "owned_aws", ".aws/", "subprocess", "--profile", "profile_name"):
            self.assertNotIn(gone, src, gone)

    def test_the_scanner_has_no_seeding_code_left(self):
        pipe = os.path.join(REPO, "scanner", "pipeline")
        self.assertFalse(os.path.exists(os.path.join(pipe, "seed_dns.py")))
        self.assertFalse(os.path.exists(os.path.join(pipe, "test_seed_dns.py")))
        for fn in os.listdir(pipe):
            if fn.endswith(".py"):
                text = rd(os.path.join(pipe, fn))
                self.assertNotRegex(text, r"^\s*(import|from)\s+(boto3|botocore|seed_dns)\b", fn)

    def test_requirements_match_the_brain_for_every_shared_package(self):
        def blocks(path):
            text = rd(path)
            return {m.group(1): m.group(0) for m in re.finditer(r"^([a-z0-9-]+)==\S+(?: \\\n    --hash=sha256:[0-9a-f]{64})+$", text, re.M)}
        mine = blocks(os.path.join(SEEDER, "requirements.txt"))
        brain = blocks(os.path.join(REPO, "brain", "requirements.txt"))
        self.assertEqual(sorted(mine), ["boto3", "botocore", "jmespath", "python-dateutil", "s3transfer", "six", "urllib3"])
        for name, block in mine.items():
            self.assertEqual(block, brain.get(name), name)


# ================================================================================================= route 53
class Route53Tests(unittest.TestCase):
    def test_two_pages_of_zones_and_record_sets_private_and_unverified_zones_skipped(self):
        zones = [{"HostedZones": [{"Id": "/hostedzone/Z1", "Name": "example.test.", "Config": {"PrivateZone": False}},
                                  {"Id": "/hostedzone/ZP", "Name": "example.test.", "Config": {"PrivateZone": True}}]},
                 {"HostedZones": [{"Id": "/hostedzone/Z2", "Name": "sub.example.test.", "Config": {}},
                                  {"Id": "/hostedzone/ZX", "Name": "pending.test.", "Config": {}}]}]
        rrsets = {"/hostedzone/Z1": [{"ResourceRecordSets": ROUTE53[:4]}, {"ResourceRecordSets": ROUTE53[4:]}],
                  "/hostedzone/Z2": [{"ResourceRecordSets": [{"Name": "deep.sub.example.test.", "Type": "A"}]}]}
        client = FakeRoute53(zones, rrsets)
        col = sd.Collector(["example.test"])
        sd.collect_route53(col, cfg(SEED_ROUTE53="1"), client=client)
        self.assertIn("deep.sub.example.test", col.hosts)
        self.assertIn("alias.example.test", col.hosts, "second page of record sets read")
        listed = [kw.get("HostedZoneId") for name, kw in client.calls if name == "list_resource_record_sets"]
        self.assertEqual(listed, ["/hostedzone/Z1", "/hostedzone/Z2"], "private zone and the zone outside the verified domains not read")
        self.assertEqual(col.errors["route53"], [])

    def test_off_unless_configured(self):
        col = sd.Collector(APEXES)
        sd.collect_route53(col, cfg(), client=FakeRoute53(AssertionError("must not be called"), {}))
        self.assertEqual(col.hosts, {})

    def test_sdk_errors_become_fixed_codes_without_their_message(self):
        for code, want in (("AccessDenied", "route53-access-denied"), ("ExpiredToken", "route53-bad-credentials"),
                           ("SomethingNew", "route53-error")):
            col = sd.Collector(APEXES)
            client = FakeRoute53(ClientError(code, f"User arn:aws:iam::000000000000:user/{CANARY} is not authorized"), {})
            sd.collect_route53(col, cfg(SEED_ROUTE53="1"), client=client)
            self.assertEqual(col.errors["route53"], [want])
            self.assertNotIn(CANARY, json.dumps(col.errors))

    def test_route53_client_uses_the_chain_or_one_assumed_role_with_nothing_stored(self):
        """route53_client() with a stand-in boto3 module: the real chain and STS are never reached."""
        made, endpoints = [], []

        class Session:
            def __init__(self, **kw):
                self.kw = kw

            def client(self, service, config=None, **kw):
                made.append((service, dict(self.kw)))
                endpoints.append((service, kw.get("endpoint_url"), kw.get("verify"), config[1].get("proxies")))
                if service == "sts":
                    return types.SimpleNamespace(assume_role=lambda **kw: made.append(("assume_role", kw)) or {"Credentials": {
                        "AccessKeyId": "AKIA" + CANARY, "SecretAccessKey": CANARY, "SessionToken": CANARY}})
                return "route53-client"
        fake_boto3 = types.SimpleNamespace(session=types.SimpleNamespace(Session=Session))
        fake_botocore_config = types.SimpleNamespace(Config=lambda **kw: ("botocore-config", kw))
        with tempfile.TemporaryDirectory() as home, \
                unittest.mock.patch.dict(sys.modules, {"boto3": fake_boto3, "botocore": types.SimpleNamespace(),
                                                       "botocore.config": fake_botocore_config}), \
                unittest.mock.patch.object(sd, "ca_bundle", lambda: "/stand-in/cacert.pem"), \
                unittest.mock.patch.dict(os.environ, {"AWS_PROFILE": "someone", "AWS_CONFIG_FILE": "/elsewhere/config", "HOME": home}):
            self.assertEqual(sd.route53_client(cfg(SEED_ROUTE53="1")), "route53-client")
            self.assertEqual(os.environ["AWS_CONFIG_FILE"], "/nonexistent/aws-config")
            self.assertNotIn("AWS_PROFILE", os.environ)
            arn = "arn:aws:iam::000000000000:role/dns-read"
            self.assertEqual(sd.route53_client(cfg(SEED_ROUTE53="1", SEED_ROUTE53_ROLE_ARN=arn)), "route53-client")
            self.assertEqual(os.listdir(home), [], "nothing written to a home folder (no credential cache)")
        assume = [kw for name, kw in made if name == "assume_role"]
        self.assertEqual(assume, [{"RoleArn": arn, "RoleSessionName": "momus-seeder", "DurationSeconds": 900}])
        self.assertEqual(made[-1][0], "route53")
        self.assertEqual(made[-1][1]["aws_secret_access_key"], CANARY, "the assumed role's credentials, in memory only")
        # every client gets its endpoint, no proxy and the image's CA bundle explicitly
        self.assertEqual(endpoints, [("route53", "https://route53.amazonaws.com", "/stand-in/cacert.pem", {}),
                                     ("sts", "https://sts.us-east-1.amazonaws.com", "/stand-in/cacert.pem", {}),
                                     ("route53", "https://route53.amazonaws.com", "/stand-in/cacert.pem", {})])

    def test_role_arn_and_region_are_validated_with_fullmatch(self):
        good = "arn:aws:iam::000000000000:role/dns-read"
        cfg(SEED_ROUTE53="1", SEED_ROUTE53_ROLE_ARN=good)
        for bad in (good + " x", good + "\nx", "x" + good, "arn:aws:iam::00000000000:role/x", "arn:aws:iam::000000000000:user/x",
                    "arn:aws:sts::000000000000:assumed-role/x/y", CANARY):
            with self.assertRaises(sd.ConfigError, msg=bad) as cm:
                cfg(SEED_ROUTE53="1", SEED_ROUTE53_ROLE_ARN=bad)
            self.assertNotIn(CANARY, str(cm.exception))
        with self.assertRaises(sd.ConfigError):
            cfg(SEED_ROUTE53_ROLE_ARN=good)                     # a role without the source switched on
        with self.assertRaises(sd.ConfigError):
            cfg(SEED_ROUTE53="1", SEED_ROUTE53_REGION="us-east-1; x")
        with self.assertRaises(sd.ConfigError):
            cfg(SEED_ROUTE53="yes")


# ================================================================================================= zone files
class ZoneFileTests(unittest.TestCase):
    def test_folder_files_symlinks_oversize_and_unverified_origins(self):
        with tempfile.TemporaryDirectory() as d:
            z = os.path.join(d, "zones")
            os.makedirs(z)
            wr(os.path.join(z, "example-two.test.zone"), ZONE)
            wr(os.path.join(z, "example.test.hosts"), "www\napi.example.test\n")
            wr(os.path.join(z, "pending.test.zone"), "$ORIGIN pending.test.\nwww IN A 192.0.2.1\n")
            secret = os.path.join(d, "secret.txt")
            wr(secret, "leak.example.test\n")
            os.symlink(secret, os.path.join(z, "example.test.txt"))
            wr(os.path.join(z, "big.example.test.zone"), "x" * (len(ZONE) + 100))
            wr(os.path.join(z, ".hidden"), "hidden.example.test\n")
            col = sd.Collector(["example.test", "example-two.test"])
            with unittest.mock.patch.object(sd, "MAX_ZONE_FILE_BYTES", len(ZONE) + 50):
                sd.collect_zone_files(col, cfg(SEED_ZONE_FILES="1"), z)
            self.assertIn("www.example-two.test", col.hosts)
            self.assertIn("api.example.test", col.hosts)
            self.assertNotIn("leak.example.test", col.hosts, "a symlink is never followed")
            self.assertNotIn("hidden.example.test", col.hosts)
            self.assertFalse(any(h.endswith("pending.test") for h in col.hosts))
            self.assertIn("zonefile-origin-not-a-verified-domain", col.errors["zonefiles"])
            self.assertIn("zonefile-skipped-not-a-regular-file-or-too-large", col.errors["zonefiles"])

    def test_missing_folder_is_a_fixed_code(self):
        col = sd.Collector(APEXES)
        sd.collect_zone_files(col, cfg(SEED_ZONE_FILES="1"), "/nonexistent/zones")
        self.assertEqual(col.errors["zonefiles"], ["zonefiles-folder-unreadable"])


# ================================================================================================ zone transfer
class AxfrTests(unittest.TestCase):
    def test_transfer_names_and_cname_targets_in_scope_only(self):
        col = sd.Collector(["example.test"])
        sd.collect_axfr(col, cfg(SEED_AXFR="example.test@192.0.2.53"), connect=lambda a: FakeSocket(good_transfer))
        self.assertEqual(sorted(col.hosts), ["cname.example.test", "example.test", "mixed.example.test", "out.example.test",
                                             "target.example.test", "www.example.test"])
        self.assertEqual(col.errors["axfr"], [])

    def test_query_is_an_axfr_for_the_zone(self):
        q = sd.axfr_query("example.test", 0x1234)
        self.assertEqual(struct.unpack("!H", q[:2])[0], len(q) - 2)
        self.assertEqual(q[2:4], b"\x12\x34")
        self.assertTrue(q.endswith(dns_name("example.test") + struct.pack("!HH", 252, 1)))

    def test_refused_malformed_closed_and_unverified(self):
        cases = {
            "axfr-refused": lambda qid: [message(qid, [], rcode=5)],
            "axfr-malformed-answer": lambda qid: [message(qid ^ 1, [rr("example.test", 6, soa())])],
            "axfr-connection-closed": lambda qid: [message(qid, [rr("example.test", 6, soa())])],
        }
        for code, build in cases.items():
            col = sd.Collector(["example.test"])
            sd.collect_axfr(col, cfg(SEED_AXFR="example.test@192.0.2.53"), connect=lambda a, b=build: FakeSocket(b))
            self.assertEqual(col.errors["axfr"], [code], code)
        col = sd.Collector(["example.test"])
        sd.collect_axfr(col, cfg(SEED_AXFR="pending.test@192.0.2.53"), connect=lambda a: self.fail("connected"))
        self.assertEqual(col.errors["axfr"], ["axfr-zone-not-a-verified-domain"])

    def test_compression_loop_is_malformed_not_a_hang(self):
        def build(qid):
            head = struct.pack("!HHHHHH", qid, 0x8400, 0, 1, 0, 0)
            return [head + b"\xc0\x0c" + struct.pack("!HHIH", 6, 1, 1, 0)]
        col = sd.Collector(["example.test"])
        sd.collect_axfr(col, cfg(SEED_AXFR="example.test@192.0.2.53"), connect=lambda a: FakeSocket(build))
        self.assertEqual(col.errors["axfr"], ["axfr-malformed-answer"])

    def test_server_must_be_an_address_never_a_name(self):
        for bad in ("example.test@ns1.example.test", "example.test", "example.test@192.0.2.300", "@192.0.2.1",
                    "example.test@192.0.2.1:53", "bad zone@192.0.2.1"):
            with self.assertRaises(sd.ConfigError, msg=bad):
                cfg(SEED_AXFR=bad)
        c = cfg(SEED_AXFR="Example.Test.@2001:db8::53 example-two.test@192.0.2.9")
        self.assertEqual(c.axfr, [("example.test", "2001:db8::53"), ("example-two.test", "192.0.2.9")])


# ================================================================================================= PowerDNS
class PdnsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.key = os.path.join(self.tmp.name, "key")
        wr(self.key, CANARY + "\n")

    def tearDown(self):
        self.tmp.cleanup()

    def conf(self, **kw):
        env = {"SEED_PDNS_URL": "http://192.0.2.80:8081", "SEED_PDNS_ZONES": "example.test pending.test",
               "SEED_PDNS_API_KEY_FILE": self.key}
        env.update(kw)
        return cfg(**env)

    def test_zone_read_with_the_key_from_its_file(self):
        op = FakeOpener(PDNS)
        col = sd.Collector(["example.test"])
        sd.collect_pdns(col, self.conf(), opener=op)
        self.assertEqual(sorted(col.hosts), ["cdn.example.test", "example.test", "sip.example.test"])
        self.assertEqual(len(op.requests), 1, "the zone outside the verified domains is not requested")
        url, headers, timeout = op.requests[0]
        self.assertEqual(url, "http://192.0.2.80:8081/api/v1/servers/localhost/zones/example.test.")
        self.assertEqual(headers.get("X-api-key"), CANARY)
        self.assertEqual(col.errors["pdns"], ["pdns-zone-not-a-verified-domain"])

    def test_http_errors_redirects_size_and_bad_key_file(self):
        for answer, code in ((urllib.error.HTTPError("u", 401, CANARY, {}, None), "pdns-http-401"),
                             (urllib.error.HTTPError("u", 302, "redirect refused", {}, None), "pdns-redirect-refused"),
                             (OSError(CANARY), "pdns-unreachable"), (b"not json", "pdns-answer-invalid")):
            col = sd.Collector(["example.test"])
            sd.collect_pdns(col, self.conf(SEED_PDNS_ZONES="example.test"), opener=FakeOpener(answer))
            self.assertEqual(col.errors["pdns"], [code])
        col = sd.Collector(["example.test"])
        with unittest.mock.patch.object(sd, "MAX_PDNS_BYTES", 10):
            sd.collect_pdns(col, self.conf(SEED_PDNS_ZONES="example.test"), opener=FakeOpener(PDNS))
        self.assertEqual(col.errors["pdns"], ["pdns-answer-too-large"])
        col = sd.Collector(["example.test"])
        sd.collect_pdns(col, self.conf(SEED_PDNS_API_KEY_FILE="/nonexistent/key"), opener=FakeOpener(PDNS))
        self.assertEqual(col.errors["pdns"], ["pdns-key-file-unreadable"])

    def test_the_opener_refuses_redirects_and_ignores_proxy_variables(self):
        op = sd.pdns_opener()
        redirect = [h for h in op.handlers if isinstance(h, sd._NoRedirect)]
        self.assertEqual(len(redirect), 1)
        with self.assertRaises(urllib.error.HTTPError):
            redirect[0].redirect_request(types.SimpleNamespace(full_url="http://a.example.test/"), None, 302, "", {}, "http://b.example/")
        with unittest.mock.patch.dict(os.environ, {"http_proxy": "http://proxy.invalid:3128", "HTTPS_PROXY": "http://proxy.invalid:3128"}):
            op = sd.pdns_opener()
        self.assertFalse([h for h in op.handlers if isinstance(h, urllib.request.ProxyHandler)],
                         "no proxy handler: a proxy from the environment is never used")

    def test_url_server_and_zones_are_validated(self):
        for bad in ("ftp://192.0.2.80", "http://user:pw@192.0.2.80", "http://192.0.2.80/?x=1", "http://192.0.2.80#f",
                    "http://192.0.2.80/a b", "192.0.2.80:8081", "http://192.0.2.80\nx"):
            with self.assertRaises(sd.ConfigError, msg=bad):
                self.conf(SEED_PDNS_URL=bad)
        with self.assertRaises(sd.ConfigError):
            self.conf(SEED_PDNS_SERVER="../../x")
        with self.assertRaises(sd.ConfigError):
            self.conf(SEED_PDNS_ZONES="")
        with self.assertRaises(sd.ConfigError):
            cfg(SEED_PDNS_ZONES="example.test")


# ============================================================================================ the whole run
class RunTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.pub, self.out, self.zones = os.path.join(d, "pub"), os.path.join(d, "seed"), os.path.join(d, "zones")
        os.makedirs(self.out)
        os.makedirs(self.zones)
        self.key = os.path.join(d, "key")
        wr(self.key, CANARY)

    def tearDown(self):
        self.tmp.cleanup()

    def test_pending_domains_are_never_seeded(self):
        scope_status(self.pub, {"example.test": "verified", "pending.test": "pending", "nostmt.test": "no-statement",
                                "lapsed.test": "lapsed", "refused.test": "refused"})
        for dom in ("example.test", "pending.test", "nostmt.test", "lapsed.test", "refused.test"):
            wr(os.path.join(self.zones, dom + ".hosts"), "www\n")
        st = sd.run_once(cfg(SEED_ZONE_FILES="1"), self.pub, self.out, self.zones)
        self.assertEqual(rd(os.path.join(self.out, "seed_hosts.txt")), "www.example.test\n")
        # the scanner's list holds verified domains only (scanner test_runner JobDatesRecordsAndVerifiedDomains), so the seeder never
        # learns of the others; domains_refused counts list entries that are not host names
        self.assertEqual((st["domains_verified"], st["domains_refused"]), (1, 0))

    def test_no_scope_status_or_no_verified_domain_seeds_nothing(self):
        wr(os.path.join(self.zones, "example.test.hosts"), "www\n")
        st = sd.run_once(cfg(SEED_ZONE_FILES="1"), self.pub, self.out, self.zones)
        self.assertEqual((st["result"], st["errors"]), ("nothing-found", ["verified-domains-missing"]))
        scope_status(self.pub, {"example.test": "pending"})
        st = sd.run_once(cfg(SEED_ZONE_FILES="1"), self.pub, self.out, self.zones)
        self.assertEqual((st["result"], st["errors"]), ("nothing-found", ["no-verified-domain"]))
        self.assertFalse(os.path.exists(os.path.join(self.out, "seed_hosts.txt")))
        os.unlink(os.path.join(self.pub, "verified_domains.json"))
        os.symlink(self.key, os.path.join(self.pub, "verified_domains.json"))
        st = sd.run_once(cfg(SEED_ZONE_FILES="1"), self.pub, self.out, self.zones)
        self.assertEqual(st["errors"], ["verified-domains-unreadable"], "a symlink is never followed")

    def test_output_is_host_names_only_and_status_is_fixed_text(self):
        scope_status(self.pub, {"example.test": "verified", "example-two.test": "verified"})
        wr(os.path.join(self.zones, "example-two.test.zone"), ZONE)
        clients = {"route53": FakeRoute53([{"HostedZones": [{"Id": "Z1", "Name": "example.test."}]}],
                                          {"Z1": [{"ResourceRecordSets": ROUTE53}]}),
                   "axfr": lambda a: FakeSocket(good_transfer), "pdns": FakeOpener(PDNS)}
        c = cfg(SEED_ROUTE53="1", SEED_ZONE_FILES="1", SEED_AXFR="example.test@192.0.2.53",
                SEED_PDNS_URL="https://192.0.2.80", SEED_PDNS_ZONES="example.test", SEED_PDNS_API_KEY_FILE=self.key)
        st = sd.run_once(c, self.pub, self.out, self.zones, clients=clients)
        lines = rd(os.path.join(self.out, "seed_hosts.txt")).splitlines()
        self.assertEqual(lines, sorted(set(lines)))
        for line in lines:
            self.assertTrue(sd.valid_host(line), line)
            self.assertTrue(line.endswith((".example.test", ".example-two.test")) or line in ("example.test", "example-two.test"))
        text = rd(os.path.join(self.out, "seed_hosts.txt")) + rd(os.path.join(self.out, "status.json"))
        for absent in ("192.0.2", "2001:db8", "cloudfront", "elb.amazonaws", "vendor.example", "elsewhere.example", "DMARC",
                       "hostmaster", "route53:", "zonefile:"):
            self.assertNotIn(absent, text)
        self.assertEqual({s: st["sources"][s]["names"] > 0 for s in sd.SOURCES},
                         {"route53": True, "zonefiles": True, "axfr": True, "pdns": True})
        status = json.loads(rd(os.path.join(self.out, "status.json")))
        self.assertEqual(sorted(status), ["count", "domains_refused", "domains_verified", "errors", "failed_sources", "result",
                                          "schema", "sources", "updated_at"])
        self.assertEqual(status["schema"], "momus-seed-status-v1")
        self.assertEqual(sorted(os.listdir(self.out)), ["seed_hosts.txt", "status.json"], "no temporary file left behind")

    def test_credentials_never_reach_output_status_or_logs(self):
        scope_status(self.pub, {"example.test": "verified"})
        canary_env = {"AWS_ACCESS_KEY_ID": "AKIA" + CANARY, "AWS_SECRET_ACCESS_KEY": CANARY, "AWS_SESSION_TOKEN": CANARY,
                      "SEED_ROUTE53": "1", "SEED_PDNS_URL": "http://192.0.2.80:8081", "SEED_PDNS_ZONES": "example.test",
                      "SEED_PDNS_API_KEY_FILE": self.key, "SEED_AXFR": "example.test@192.0.2.53"}
        failing_r53 = FakeRoute53(ClientError("AccessDenied", f"denied for {CANARY}"), {})
        op = FakeOpener(urllib.error.HTTPError("http://192.0.2.80", 403, f"bad key {CANARY}", {}, None))
        with Captured() as cap, unittest.mock.patch.dict(os.environ, canary_env):
            st = sd.run_once(sd.Config(os.environ), self.pub, self.out, self.zones,
                             clients={"route53": failing_r53, "pdns": op, "axfr": lambda a: FakeSocket(good_transfer)})
        self.assertEqual(op.requests[0][1].get("X-api-key"), CANARY, "control: the key was really used")
        self.assertEqual(st["sources"]["route53"]["errors"], ["route53-access-denied"])
        self.assertEqual(st["sources"]["pdns"]["errors"], ["pdns-http-403"])
        for name in os.listdir(self.out):
            self.assertNotIn(CANARY, rd(os.path.join(self.out, name)), name)
        self.assertNotIn(CANARY, cap.err.getvalue())
        self.assertIn("written", cap.err.getvalue())

    def test_bad_configuration_names_the_variable_not_the_value(self):
        with Captured() as cap, unittest.mock.patch.dict(os.environ, {"SEED_PDNS_URL": "http://x.example.test/" + CANARY + "?q"}):
            rc = sd.main(["--scope", self.pub, "--out", self.out, "--zones", self.zones])
        self.assertEqual(rc, 2)
        self.assertIn("SEED_PDNS_URL", cap.err.getvalue())
        self.assertNotIn(CANARY, cap.err.getvalue())
        self.assertEqual(os.listdir(self.out), [])

    def test_interval_is_validated(self):
        self.assertEqual(cfg().interval_minutes, 0)
        self.assertEqual(cfg(SEED_INTERVAL_MINUTES="60").interval_minutes, 60)
        for bad in ("5", "10081", "-1", "1h", "060", " 60x"):
            with self.assertRaises(sd.ConfigError, msg=bad):
                cfg(SEED_INTERVAL_MINUTES=bad)

    def test_the_sdk_variables_are_dummies_in_this_container(self):
        self.assertEqual(os.environ.get("MOMUS_SEED_TEST_CONTAINER"), "1")
        self.assertEqual(os.environ["AWS_SECRET_ACCESS_KEY"], "dummy-not-a-key")
        self.assertEqual(os.environ["AWS_EC2_METADATA_DISABLED"], "true")
        self.assertTrue(os.environ["AWS_CONFIG_FILE"].startswith("/nonexistent/"))
        self.assertTrue(os.environ["AWS_SHARED_CREDENTIALS_FILE"].startswith("/nonexistent/"))
        self.assertEqual(os.environ["HOME"], "/nonexistent")
        self.assertNotIn("AWS_PROFILE", os.environ)
        self.assertFalse(os.path.exists(os.path.expanduser("~/.aws")))

    def test_the_socket_guard_is_active(self):
        import socket
        run = sys.modules["seed_test_guard"]          # the runner module that installed the guard
        before = len(run.OUTBOUND_ATTEMPTS)
        with self.assertRaises(OSError):
            socket.create_connection(("192.0.2.1", 53), timeout=1)
        self.assertEqual(len(run.OUTBOUND_ATTEMPTS), before + 1)
        del run.OUTBOUND_ATTEMPTS[before:]          # this test made the attempt on purpose


if __name__ == "__main__":
    unittest.main()
