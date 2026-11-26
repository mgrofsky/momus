"""scope.py and approve.py: name and address gates, ownership statements, the DNS proof, approvals, lab limits.
Names are invented (example.test); addresses that must be public are well-known resolver addresses."""
import contextlib, datetime as dt, io, json, os, sys, tempfile, unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import scope as S  # noqa: E402
import approve as A  # noqa: E402

NOW = dt.datetime(2030, 6, 1, 12, 0, tzinfo=dt.timezone.utc)
PUB = "8.8.8.8"


def read(path):
    with open(path) as f:
        return f.read()


def write(path, text):
    with open(path, "w") as f:
        f.write(text)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        self.sc = os.path.join(self.root, "scope"); os.makedirs(self.sc)
        self.run = os.path.join(self.root, "run"); os.makedirs(self.run)
        write(os.path.join(self.sc, "domains.txt"), "# apexes\nexample.test\nOther.Test.\n")
        write(os.path.join(self.sc, "exclude.txt"), "skip.example.test\n.legacy.example.test\n9.9.9.9\n208.67.222.0/24\n")
        write(os.path.join(self.sc, "owned_ranges.txt"), "94.140.14.0/24\n")
        write(os.path.join(self.sc, "approved_hosts.txt"), "approved.example.test\n")
        self.state_dir = os.path.join(self.root, "state")
        self.secret, _ = S.load_secret(self.state_dir, create=True)
        self.kid = S.key_id(self.secret)
        self.verified("example.test")

    def tearDown(self):
        self.tmp.cleanup()

    def verified(self, apex, state="verified", verified_at=None, key_id=None):
        """An ownership entry as the scanner stores it: no token (tokens are derived), the key id it was checked under."""
        ents = S.load_ownership(self.sc)
        ents[apex] = {"apex": apex, "statement": S.OWNERSHIP_STATEMENT, "attested_by": "Test Owner",
                      "attested_at": "2030-01-01T00:00:00Z", "state": state, "key_id": key_id or self.kid,
                      "verified_at": verified_at or ("2030-05-31T00:00:00Z" if state == "verified" else None)}
        S.save_ownership(self.sc, ents)

    def scope(self, **kw):
        return S.Scope(self.sc, self.run, now=NOW, **kw)


class NameGate(Base):
    def test_apex_and_label_boundary(self):
        s = self.scope()
        self.assertTrue(s.name_allowed("example.test")[0])
        self.assertTrue(s.name_allowed("a.b.example.test")[0])
        self.assertFalse(s.name_allowed("badexample.test")[0])        # not on a label boundary
        self.assertFalse(s.name_allowed("example.test.evil.test")[0])
        self.assertIn("not under any apex", s.name_allowed("unrelated.test")[1])

    def test_trailing_dot_and_case(self):
        s = self.scope()
        self.assertTrue(s.name_allowed("WWW.Example.TEST.")[0])
        self.assertFalse(s.name_allowed("Skip.Example.Test.")[0])

    def test_invalid_hostnames(self):
        s = self.scope()
        for bad in ("", ".", "a..example.test", "-a.example.test", "a-.example.test", "a b.example.test",
                    "x" * 64 + ".example.test", "8.8.8.8", "example", "http://www.example.test", "*.example.test",
                    "www.example.test/x", None, ("a." * 130) + "example.test"):
            self.assertFalse(s.name_allowed(bad)[0], bad)
        self.assertTrue(s.name_allowed("_dmarc.example.test")[0])

    def test_suffix_exclusions(self):
        s = self.scope()
        self.assertFalse(s.name_allowed("skip.example.test")[0])
        self.assertFalse(s.name_allowed("deep.skip.example.test")[0])
        self.assertFalse(s.name_allowed("a.legacy.example.test")[0])
        self.assertFalse(s.name_allowed("legacy.example.test")[0])
        self.assertTrue(s.name_allowed("noskip.example.test")[0])
        self.assertIn("exclude.txt", s.name_allowed("skip.example.test")[1])

    def test_bad_exclusions_fail_closed(self):
        for bad in ("10.0.0.0/33", "not a name", "single", "10.0.0.0/8/1", "x..example.test"):
            write(os.path.join(self.sc, "exclude.txt"), bad + "\n")
            with self.assertRaises(S.ScopeError, msg=bad):
                self.scope()
        write(os.path.join(self.sc, "exclude.txt"), "*.internal.example.test\n")
        s = self.scope()
        self.assertFalse(s.name_allowed("a.internal.example.test")[0])
        self.assertFalse(s.name_allowed("internal.example.test")[0])
        self.assertTrue(s.name_allowed("external.example.test")[0])

    def test_empty_or_missing_scope_is_an_error(self):
        write(os.path.join(self.sc, "domains.txt"), "# nothing\n\n")
        with self.assertRaises(S.ScopeError):
            self.scope()
        os.remove(os.path.join(self.sc, "domains.txt"))
        with self.assertRaises(S.ScopeError):
            self.scope()

    def test_invalid_domain_entry_is_an_error(self):
        write(os.path.join(self.sc, "domains.txt"), "example.test\nnot a domain\n")
        with self.assertRaises(S.ScopeError):
            self.scope()


class Ownership(Base):
    def test_missing_entry(self):
        ok, why = self.scope().name_allowed("www.other.test")
        self.assertFalse(ok)
        self.assertIn("approve.py attest other.test", why)

    def test_present_entry(self):
        self.verified("other.test")
        self.assertTrue(self.scope().name_allowed("www.other.test")[0])

    def test_entry_for_a_different_apex(self):
        write(os.path.join(self.sc, "domains.txt"), "other.test\n")
        # example.test has an entry, other.test (the only apex) does not
        self.assertFalse(self.scope().name_allowed("www.other.test")[0])
        self.assertFalse(self.scope().name_allowed("www.example.test")[0])   # not an apex any more

    def test_attest_requires_name_and_writes_pending_token(self):
        with self.assertRaises(S.ScopeError):
            A.attest(self.sc, "other.test", " ")
        ent = A.attest(self.sc, "Other.Test", "Pat Example", now=NOW, state_dir=self.state_dir)
        self.assertEqual((ent["apex"], ent["state"], ent["statement"]), ("other.test", "pending", S.OWNERSHIP_STATEMENT))
        self.assertRegex(ent["token"], r"^[0-9a-f]{32}$")
        # the token is derived from the install secret, and it is never stored
        self.assertEqual(ent["token"], S.derive_token(self.secret, "other.test"))
        self.assertNotIn("token", S.load_ownership(self.sc)["other.test"])
        ok, why = self.scope().name_allowed("www.other.test")
        self.assertFalse(ok)
        self.assertIn("_scan-verify.other.test shown in scope_status.json", why)

    def test_malformed_ownership_file(self):
        write(S.ownership_path(self.sc), json.dumps({"entries": [{"apex": "example.test", "statement": "maybe"}]}))
        with self.assertRaises(S.ScopeError):
            self.scope()


class AddressGate(Base):
    def test_non_global_classes(self):
        s = self.scope()
        for ip in ("10.1.2.3", "172.16.0.1", "192.168.1.1", "127.0.0.1", "169.254.169.254", "169.254.1.1",
                   "100.64.0.1", "100.127.255.254", "224.0.0.1", "239.1.1.1", "240.0.0.1", "255.255.255.255",
                   "0.0.0.0", "192.0.2.10", "198.51.100.1", "203.0.113.5", "198.18.0.1", "192.0.0.9",
                   "::", "::1", "fe80::1", "fd00::1", "fc00::5", "fd00:ec2::254", "ff02::1", "ff0e::1",
                   "2001:db8::1", "64:ff9b::a00:1", "2002:a00:1::1", "2001::1", "fec0::1"):
            ok, why = s.ip_allowed(ip)
            self.assertFalse(ok, f"{ip} allowed")
        self.assertIn("metadata", s.ip_allowed("169.254.169.254")[1])
        self.assertIn("multicast", s.ip_allowed("224.0.0.1")[1])

    def test_global_and_mapped(self):
        s = self.scope()
        self.assertTrue(s.ip_allowed(PUB)[0])
        self.assertTrue(s.ip_allowed("2001:4860:4860::8888")[0])
        self.assertTrue(s.ip_allowed("::ffff:8.8.8.8")[0])
        self.assertFalse(s.ip_allowed("::ffff:10.0.0.1")[0])
        self.assertFalse(s.ip_allowed("::ffff:169.254.169.254")[0])
        self.assertFalse(s.ip_allowed("[::1]")[0])
        self.assertFalse(s.ip_allowed("not-an-ip")[0])

    def test_address_and_cidr_exclusions(self):
        s = self.scope()
        self.assertFalse(s.ip_allowed("9.9.9.9")[0])
        self.assertFalse(s.ip_allowed("208.67.222.222")[0])
        self.assertFalse(s.ip_allowed("::ffff:208.67.222.1")[0])
        self.assertIn("exclude.txt", s.ip_allowed("208.67.222.222")[1])

    def test_ips_allowed_needs_every_address(self):
        s = self.scope()
        self.assertTrue(s.ips_allowed("a.example.test", [PUB, "8.8.4.4"])[0])
        self.assertFalse(s.ips_allowed("a.example.test", [PUB, "10.0.0.1"])[0])
        self.assertFalse(s.ips_allowed("a.example.test", [])[0])


class PortScan(Base):
    def test_owned_range_or_approved_host(self):
        s = self.scope()
        self.assertTrue(s.portscan_allowed("r.example.test", ["94.140.14.14"])[0])
        self.assertFalse(s.portscan_allowed("r.example.test", ["94.140.14.14", PUB])[0])   # one address outside
        self.assertFalse(s.portscan_allowed("plain.example.test", [PUB])[0])
        self.assertTrue(s.portscan_allowed("approved.example.test", [PUB])[0])
        self.assertFalse(s.portscan_allowed("approved.example.test", ["10.0.0.1"])[0])   # still needs ip_allowed
        self.assertFalse(s.portscan_allowed("skip.example.test", ["94.140.14.14"])[0])    # still needs the name gate

    def test_filter_portscan_and_coverage(self):
        write(os.path.join(self.run, "dns.jsonl"), "".join(json.dumps(d) + "\n" for d in (
            {"host": "r.example.test", "a": ["94.140.14.14"]}, {"host": "plain.example.test", "a": [PUB]},
            {"host": "approved.example.test", "a": ["8.8.4.4"]})))
        write(os.path.join(self.run, "in.txt"), "94.140.14.14\n8.8.8.8\n8.8.4.4\n10.0.0.1\n")
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = S.main(["filter", "--scope", self.sc, "--run-dir", self.run, "--stage", "nmap", "--kind", "portscan",
                         "--in", os.path.join(self.run, "in.txt"), "--out", os.path.join(self.run, "out.txt"), "--cover", "nmap"])
        self.assertEqual(rc, 0)
        self.assertEqual(err.getvalue(), "scope gate nmap: 2 allowed, 2 rejected\n")
        self.assertEqual(read(os.path.join(self.run, "out.txt")).split(), ["94.140.14.14", "8.8.4.4"])
        self.assertEqual(sorted(read(os.path.join(self.run, "coverage", "nmap.txt")).split()),
                         ["approved.example.test", "r.example.test"])
        rej = [json.loads(l) for l in read(os.path.join(self.run, "scope_rejected.jsonl")).splitlines()]
        self.assertEqual(sorted(r["what"] for r in rej), ["10.0.0.1", PUB])
        self.assertTrue(all(r["stage"] == "nmap" and r["reason"] for r in rej))

    def test_portscan_coverage_lists_every_name_on_the_address(self):
        write(os.path.join(self.run, "dns.jsonl"), "".join(json.dumps(d) + "\n" for d in (
            {"host": "approved.example.test", "a": ["8.8.4.4"]}, {"host": "aa.example.test", "a": ["8.8.4.4"]})))
        write(os.path.join(self.run, "in.txt"), "8.8.4.4\n")   # aa is not approved itself, but its address was scanned
        with contextlib.redirect_stderr(io.StringIO()):
            S.main(["filter", "--scope", self.sc, "--run-dir", self.run, "--stage", "nmap", "--kind", "portscan",
                    "--in", os.path.join(self.run, "in.txt"), "--out", os.path.join(self.run, "out.txt"), "--cover", "nmap"])
        self.assertEqual(sorted(read(os.path.join(self.run, "coverage", "nmap.txt")).split()), ["aa.example.test", "approved.example.test"])


class Filters(Base):
    def test_hosts_need_gated_resolution(self):
        write(os.path.join(self.run, "dns.jsonl"), "".join(json.dumps(d) + "\n" for d in (
            {"host": "ok.example.test", "a": [PUB]}, {"host": "meta.example.test", "a": ["169.254.169.254"]},
            {"host": "dual.example.test", "a": ["10.0.0.4"], "aaaa": ["2001:4860:4860::8888"]})))
        s = self.scope()
        keep, hosts = S.filter_items(s, ["https://ok.example.test:8443/x", "http://meta.example.test/", "https://dual.example.test",
                                         "https://unresolved.example.test/", "https://evil.test/", "ftp://ok.example.test/"],
                                     "urls", "probe", S.dns_map(self.run))
        self.assertEqual(keep, ["https://ok.example.test:8443/x"])
        self.assertEqual(list(hosts), ["ok.example.test"])
        keep, _ = S.filter_items(s, ["ok.example.test:443", "meta.example.test:443"], "hostports", "tls", S.dns_map(self.run))
        self.assertEqual(keep, ["ok.example.test:443"])


class Lab(Base):
    def test_limits(self):
        with mock.patch.dict(os.environ, {"SCAN_LAB": "1"}):
            for cidr in ("172.30.5.0/24", "10.9.9.0/28"):
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    self.assertEqual(S.main(["lab-check", "--cidr", cidr]), 0)
                self.assertEqual(out.getvalue(), cidr + "\n")      # recon.sh reads the network from stdout
            # public; larger than /24; link-local; CGNAT is not a private range
            for cidr in ("8.8.8.0/24", "10.9.0.0/23", "169.254.169.0/24", "100.64.0.0/24"):
                err = io.StringIO()
                with contextlib.redirect_stderr(err):
                    self.assertEqual(S.main(["lab-check", "--cidr", cidr]), 2)
                self.assertIn(f"lab mode refused: lab CIDR {cidr}", err.getvalue())
        with mock.patch.dict(os.environ, {"SCAN_LAB": "0"}):
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                self.assertEqual(S.main(["lab-check", "--cidr", "172.30.5.0/24"]), 2)
            self.assertIn("set SCAN_LAB=1", err.getvalue())

    def test_lab_addresses_only_for_lab_names(self):
        lab = {"cidr": "172.30.5.0/24", "hosts": ["target.lab.test"]}
        with mock.patch.dict(os.environ, {"SCAN_LAB": "1"}):
            s = self.scope(lab=lab)
            self.assertTrue(s.name_allowed("target.lab.test")[0])          # no apex, no DNS proof in lab mode
            self.assertTrue(s.ip_allowed("172.30.5.10", "target.lab.test")[0])
            self.assertFalse(s.ip_allowed("172.30.5.10", "www.example.test")[0])
            self.assertFalse(s.ip_allowed("172.30.5.10")[0])
            self.assertFalse(s.ip_allowed("172.30.6.10", "target.lab.test")[0])   # outside the lab CIDR
            self.assertFalse(s.ip_allowed("169.254.169.254", "target.lab.test")[0])
            self.assertFalse(s.ip_allowed("8.8.8.8", "target.lab.test")[0])        # no DNS proof: lab network only
            self.assertTrue(s.ip_allowed("8.8.8.8", "www.example.test")[0])       # other names keep the normal rules
            self.assertFalse(s.name_allowed("other.lab.test")[0])
        with mock.patch.dict(os.environ, {"SCAN_LAB": ""}):
            with self.assertRaises(S.ScopeError):
                self.scope(lab=lab)

    def test_lab_exclusions_still_apply(self):
        write(os.path.join(self.sc, "exclude.txt"), "target.lab.test\n")
        with mock.patch.dict(os.environ, {"SCAN_LAB": "1"}):
            s = self.scope(lab={"cidr": "172.30.5.0/24", "hosts": ["target.lab.test"]})
            self.assertFalse(s.name_allowed("target.lab.test")[0])


class DnsProof(Base):
    def setUp(self):
        super().setUp()
        self.verified("other.test", state="pending")
        self.lines = []
        self.TOKEN = S.derive_token(self.secret, "other.test")
        self.GOOD = ["scan-verify=" + self.TOKEN]

    def check(self, answers, apex="other.test", now=NOW):
        return S.verify_apexes(self.sc, [apex], lookup=lambda a: answers, now=now, log=self.lines.append, state_dir=self.state_dir)

    def state(self, apex="other.test"):
        return S.load_ownership(self.sc)[apex]

    def test_no_record(self):
        self.assertEqual(self.check([("ns1.other.test", PUB, []), ("ns2.other.test", "8.8.4.4", [])]), [])
        self.assertEqual(self.state()["state"], "pending")
        self.assertIn(f'_scan-verify.other.test = "scan-verify={self.TOKEN}"', self.lines[-1])

    def test_wrong_token(self):
        self.assertEqual(self.check([("ns1.other.test", PUB, ["scan-verify=" + "cd" * 16, "v=spf1 -all"])]), [])
        self.assertEqual(self.state()["state"], "pending")

    def test_right_token(self):
        self.assertEqual(self.check([("ns1.other.test", PUB, self.GOOD + ["other"]), ("ns2.other.test", "2001:4860:4860::8888", self.GOOD)]), ["other.test"])
        st = self.state()
        self.assertEqual((st["state"], st["verified_at"]), ("verified", "2030-06-01T12:00:00Z"))
        self.assertTrue(self.scope().name_allowed("www.other.test")[0])

    def test_nameservers_disagree(self):
        self.assertEqual(self.check([("ns1.other.test", PUB, self.GOOD), ("ns2.other.test", "8.8.4.4", [])]), [])
        self.assertIn("disagree", self.lines[-1])
        self.assertEqual(self.state()["state"], "pending")

    def test_nameserver_on_private_address(self):
        self.verified("other.test")          # start from verified: the refusal must undo it
        self.assertTrue(self.scope().name_allowed("www.other.test")[0])
        self.assertEqual(self.check([("ns1.other.test", PUB, self.GOOD), ("ns2.other.test", "10.0.0.53", self.GOOD)]), [])
        self.assertIn("10.0.0.53", self.lines[-1])
        self.assertEqual(self.state()["state"], "refused")
        self.assertFalse(self.scope().name_allowed("www.other.test")[0])
        self.verified("other.test")
        self.assertEqual(self.check([("ns1.other.test", "169.254.169.254", self.GOOD)]), [])
        self.assertNotEqual(self.state()["state"], "verified")

    def test_usable_equals_verified_on_disk(self):
        cases = [[("ns1.other.test", PUB, self.GOOD)], [("ns1.other.test", PUB, [])], [("ns1.other.test", PUB, None)],
                 [("ns1.other.test", "10.0.0.1", self.GOOD)], [("a", PUB, self.GOOD), ("b", "8.8.4.4", [])], []]
        for start in ("verified", "pending", "lapsed"):
            for answers in cases:
                for age in ("2030-05-31T00:00:00Z", "2030-01-01T00:00:00Z"):
                    self.verified("other.test", state=start, verified_at=age)
                    usable = self.check(answers)
                    self.assertEqual(usable == ["other.test"], self.state()["state"] == "verified", (start, answers, age))
        # without the install secret no token can be derived, so nothing is usable and nothing stays verified
        os.unlink(os.path.join(self.state_dir, S.SECRET_FILE))
        self.verified("other.test", state="verified")
        self.assertEqual(self.check([("ns1.other.test", PUB, self.GOOD)]), [])
        self.assertEqual(self.state()["state"], "pending")
        self.assertIn("install secret", " ".join(self.lines))

    def test_lookup_failure_inside_grace(self):
        self.verified("other.test", verified_at="2030-05-26T12:00:00Z")   # 6 days ago
        self.assertEqual(self.check([("ns1.other.test", PUB, None)]), ["other.test"])
        self.assertIn("still counts", self.lines[-1])
        self.assertEqual(self.check([]), ["other.test"])    # no nameserver found at all

    def test_lookup_failure_outside_grace(self):
        self.verified("other.test", verified_at="2030-05-24T12:00:00Z")   # 8 days ago
        self.assertEqual(self.check([("ns1.other.test", PUB, None)]), [])
        self.assertFalse(self.scope().name_allowed("www.other.test")[0])

    def test_lookup_failure_never_verified(self):
        self.assertEqual(self.check([("ns1.other.test", PUB, None)]), [])

    def test_record_later_removed(self):
        self.assertEqual(self.check([("ns1.other.test", PUB, self.GOOD)]), ["other.test"])
        later = NOW + dt.timedelta(days=1)
        self.assertEqual(self.check([("ns1.other.test", PUB, [])], now=later), [])
        self.assertEqual(self.state()["state"], "pending")
        self.assertFalse(self.scope().name_allowed("www.other.test")[0])

    def test_verified_apex_does_not_cover_a_sibling(self):
        write(os.path.join(self.sc, "domains.txt"), "app.other.test\nsibling.other.test\n")
        self.verified("app.other.test", state="pending")
        self.verified("sibling.other.test", state="pending")
        app_good = ["scan-verify=" + S.derive_token(self.secret, "app.other.test")]
        # the parent's record does not prove the child, and the child's does
        self.assertEqual(self.check([("ns1.other.test", PUB, self.GOOD)], apex="app.other.test"), [])
        self.assertEqual(self.check([("ns1.other.test", PUB, app_good)], apex="app.other.test"), ["app.other.test"])
        s = self.scope()
        self.assertTrue(s.name_allowed("www.app.other.test")[0])
        self.assertFalse(s.name_allowed("www.sibling.other.test")[0])
        self.assertFalse(s.name_allowed("other.test")[0])

    def test_lookup_exception_is_a_failure(self):
        def boom(a):
            raise OSError("x")
        self.assertEqual(S.verify_apexes(self.sc, ["other.test"], lookup=boom, now=NOW, log=self.lines.append, state_dir=self.state_dir), [])

    def test_verify_command_and_record_constant(self):
        self.assertEqual(S.record_for("other.test", self.TOKEN), ("_scan-verify.other.test", "scan-verify=" + self.TOKEN))
        self.assertTrue(A.verify(self.sc, "other.test", lookup=lambda a: [("ns1.other.test", PUB, self.GOOD)], now=NOW, log=self.lines.append,
                                 state_dir=self.state_dir))

    def test_real_lookup_never_asks_a_private_nameserver(self):
        asked = []
        with mock.patch.object(S, "dig_lookup", return_value=([("ns1.x", "10.0.0.1", None), ("ns2.x", PUB, None)], "_scan-verify.other.test")), \
             mock.patch.object(S, "query_txt", side_effect=lambda ip, name: asked.append(ip) or self.GOOD):
            out = S.real_lookup("other.test", S.strict_ip_check)
        self.assertEqual(asked, [PUB])
        self.assertEqual(S.check_proof("other.test", self.TOKEN, out, S.strict_ip_check)[0], "unsafe")

    def test_nameserver_names_from_the_answer_never_reach_dig_as_options(self):
        calls = []
        def fake_dig(args, timeout=20):
            calls.append(args)
            if "NS" in args:
                return 0, "-oevil.example.test.\n+short.example.test.\nns1.other.test.\n"
            return 0, PUB + "\n" if "A" in args else ""
        with mock.patch.object(S, "_dig", side_effect=fake_dig):
            answers, _ = S.dig_lookup("other.test")
        self.assertEqual(answers, [("ns1.other.test", PUB, None)])
        self.assertFalse([a for c in calls for a in c if "evil" in a or a.startswith("+short.")], calls)
        for c in calls:
            if "NS" not in c:       # every nameserver-name lookup passes the name after -q
                self.assertEqual(c[c.index("-q") + 1], "ns1.other.test")

    def test_query_txt_parses_dig(self):
        out = (";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n;; ANSWER SECTION:\n"
               f'_scan-verify.other.test. 300\tIN\tTXT\t"scan-verify={self.TOKEN}"\n')
        with mock.patch.object(S, "_dig", return_value=(0, out)):
            self.assertEqual(S.query_txt(PUB, "_scan-verify.other.test"), self.GOOD)
        with mock.patch.object(S, "_dig", return_value=(9, ";; no servers could be reached")):
            self.assertIsNone(S.query_txt(PUB, "_scan-verify.other.test"))
        with mock.patch.object(S, "_dig", return_value=(0, ";; ->>HEADER<<- status: REFUSED")):
            self.assertIsNone(S.query_txt(PUB, "_scan-verify.other.test"))


class NameserverGate(Base):
    """scope.nameservers_ok / scope.py ns-check: dnsrecon talks to the apex's nameservers, so every nameserver
    address must pass the DNS proof's address check again at the point of use."""
    def lookup(self, table):
        return lambda apex: ([(ns, ip, None) for ns, ip in table.get(apex, [])], f"_scan-verify.{apex}")

    def test_all_public(self):
        ok, why = S.nameservers_ok("example.test", self.lookup({"example.test": [("ns1.example.test", PUB), ("ns2.example.test", "2001:4860:4860::8888")]}))
        self.assertTrue(ok, why)
        self.assertEqual(why, "2 nameserver address(es) pass")

    def test_one_private_address_refuses_the_apex(self):
        for bad in ("10.0.0.53", "169.254.169.254", "127.0.0.1", "fd00::53", "100.64.0.1"):
            ok, why = S.nameservers_ok("example.test", self.lookup({"example.test": [("ns1.example.test", PUB), ("ns2.example.test", bad)]}))
            self.assertFalse(ok, bad)
            self.assertIn(f"nameserver ns2.example.test at {bad} refused", why)

    def test_nothing_found_or_lookup_error_refuses(self):
        self.assertEqual(S.nameservers_ok("example.test", self.lookup({})), (False, "no nameserver address found"))
        def boom(apex):
            raise RuntimeError("x")
        self.assertEqual(S.nameservers_ok("example.test", boom), (False, "nameserver lookup error RuntimeError"))

    def test_cli_prints_only_safe_apexes_and_logs_the_rest(self):
        self.verified("other.test")
        table = {"example.test": [("ns1.example.test", PUB)], "other.test": [("ns1.other.test", PUB), ("ns2.other.test", "10.0.0.53")]}
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(S, "dig_lookup", side_effect=lambda apex: self.lookup(table)(apex)), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = S.main(["ns-check", "--scope", self.sc, "--run-dir", self.run, "--stage", "dnsrecon", "example.test", "other.test", "outside.test"])
        self.assertEqual(rc, 0)
        self.assertEqual(out.getvalue(), "example.test\n")
        rej = {r["what"]: r for r in map(json.loads, read(os.path.join(self.run, "scope_rejected.jsonl")).splitlines())}
        self.assertEqual(sorted(rej), ["other.test", "outside.test"])
        self.assertTrue(all(r["stage"] == "dnsrecon" for r in rej.values()))
        self.assertIn("nameserver ns2.other.test at 10.0.0.53 refused", rej["other.test"]["reason"])
        self.assertIn("other.test skipped", err.getvalue())


def inventory_manifest(root, run_id, domains, hosts, lab_targets=(), rc=0):
    run = os.path.join(root, "runs", run_id)
    os.makedirs(run, exist_ok=True)
    write(os.path.join(run, "manifest.json"), json.dumps({"run_id": run_id, "rc": rc, "inventory": {
        "domains": list(domains), "lab_targets": list(lab_targets),
        "hosts": {h: {"ips": ips, "class": "owned"} for h, ips in hosts.items()}}}))
    return run


class Approval(Base):
    def test_needs_existing_inventory_run(self):
        with self.assertRaises(S.ScopeError):
            A.approve_inventory(self.root, "2030-01-01", "Pat")
        run = os.path.join(self.root, "runs", "2030-01-01"); os.makedirs(run)
        write(os.path.join(run, "manifest.json"), "{}")
        with self.assertRaises(S.ScopeError):
            A.approve_inventory(self.root, "2030-01-01", "Pat")      # no inventory recorded (did not get that far)
        inventory_manifest(self.root, "2030-01-01", ["example.test", "other.test"], {"www.example.test": ["8.8.8.8"]}, rc=1)
        with self.assertRaises(S.ScopeError):
            A.approve_inventory(self.root, "2030-01-01", "Pat")      # the run did not finish cleanly
        inventory_manifest(self.root, "2030-01-01", ["example.test", "other.test"], {"www.example.test": ["8.8.8.8"]})
        doc = A.approve_inventory(self.root, "2030-01-01", "Pat", now=NOW)
        self.assertEqual(json.loads(read(os.path.join(self.sc, "approval.json"))), doc)
        self.assertEqual(set(doc), {"approved_at", "inventory_run", "approved_by", "inventory"})
        self.assertEqual(doc["inventory"]["hosts"], {"www.example.test": {"ips": ["8.8.8.8"], "class": "owned"}})

    def test_approval_naming_another_domains_inventory_is_refused(self):
        inventory_manifest(self.root, "inv-other", ["unrelated.test"], {"www.unrelated.test": ["8.8.8.8"]})
        with self.assertRaises(S.ScopeError) as cm:
            A.approve_inventory(self.root, "inv-other", "Pat")
        self.assertIn("covers none of the scope's domains", str(cm.exception))
        self.assertFalse(os.path.exists(os.path.join(self.sc, "approval.json")))
        # an inventory of part of the scope is accepted: the domain it did not cover is held back at run time
        inventory_manifest(self.root, "inv-part", ["example.test"], {})
        A.approve_inventory(self.root, "inv-part", "Pat")
        self.assertEqual(A.bind_inventory(A.inventory_record(self.root, "inv-part"), ["example.test", "other.test"]), ["other.test"])

    def test_lab_and_non_lab_inventories_do_not_approve_each_other(self):
        inv = A.normalize_inventory({"domains": [], "lab_targets": ["target.demo.test"], "hosts": {}})
        A.bind_inventory(inv, [], ["target.demo.test"])
        with self.assertRaises(S.ScopeError):
            A.bind_inventory(inv, ["example.test"])
        with self.assertRaises(S.ScopeError):
            A.bind_inventory(inv, [], ["target.demo.test", "notice.demo.test"])
        inv2 = A.normalize_inventory({"domains": ["example.test"], "lab_targets": [], "hosts": {}})
        with self.assertRaises(S.ScopeError):
            A.bind_inventory(inv2, [], ["target.demo.test"])

    def test_load_approval_rechecks_the_scope_as_it_is_now(self):
        inventory_manifest(self.root, "inv-1", ["example.test", "other.test"], {})
        A.approve_inventory(self.root, "inv-1", "Pat", now=NOW)
        self.assertIsNotNone(A.load_approval(self.sc)[0])
        write(os.path.join(self.sc, "domains.txt"), "example.test\nother.test\nnew.test\n")   # a domain added later
        doc, why = A.load_approval(self.sc)
        self.assertIsNotNone(doc, why)                       # still valid: new.test is held back, not the whole scope
        write(os.path.join(self.sc, "domains.txt"), "new.test\n")                           # nothing left in common
        doc, why = A.load_approval(self.sc)
        self.assertIsNone(doc)
        self.assertIn("covers none", why)
        # an approval file without the inventory it was bound to is not valid
        write(os.path.join(self.sc, "approval.json"), json.dumps({"approved_at": "2030-01-01T00:00:00Z", "inventory_run": "inv-1", "approved_by": "Pat"}))
        self.assertIsNone(A.load_approval(self.sc)[0])


class HeldBack(Base):
    INV = {"www.example.test": {"ips": ["8.8.8.8"]}, "range.example.test": {"ips": ["94.140.14.14"]},
           "cdn.example.test": {"ips": ["8.8.4.4"]}}

    def held(self, assets, providers=()):
        import ipaddress
        return S.compute_held_back(self.INV, assets, [ipaddress.ip_network("94.140.14.0/24")],
                                   [ipaddress.ip_network(p) for p in providers])

    def test_new_host_is_held(self):
        self.assertEqual(self.held([{"hostname": "new.example.test", "ips": ["8.8.8.8"], "class": "unverified"}]),
                         {"new.example.test": S.HELD_NEW})

    def test_address_drift(self):
        a = [{"hostname": "www.example.test", "ips": ["1.1.1.1"], "class": "unverified"}]
        self.assertEqual(self.held(a), {"www.example.test": S.HELD_ADDRESS})        # moved to an unlisted public address
        a = [{"hostname": "www.example.test", "ips": ["94.140.14.99"], "class": "owned"}]
        self.assertEqual(self.held(a), {})                                           # moved inside an owned range
        a = [{"hostname": "www.example.test", "ips": ["1.1.1.1"], "class": "third_party"}]
        self.assertEqual(self.held(a, providers=["1.1.1.0/24"]), {})                 # moved inside a provider range
        a = [{"hostname": "www.example.test", "ips": ["8.8.8.8", "1.1.1.1"], "class": "unverified"}]
        self.assertEqual(self.held(a), {"www.example.test": S.HELD_ADDRESS})        # one new address is enough
        a = [{"hostname": "range.example.test", "ips": ["94.140.14.14"], "class": "owned"},
             {"hostname": "gone.example.test", "ips": [], "class": "dead"}]
        self.assertEqual(self.held(a), {})                                           # unchanged; dead hosts are not live

    def test_held_hosts_refused_by_every_gate_and_not_covered(self):
        write(os.path.join(self.run, "dns.jsonl"), json.dumps({"host": "range.example.test", "a": ["94.140.14.14"]}) + "\n"
              + json.dumps({"host": "alias.example.test", "a": ["94.140.14.14"]}) + "\n")
        write(os.path.join(self.run, S.HELD_BACK_FILE), json.dumps({"inventory_run": "inv-1", "hosts": {"alias.example.test": S.HELD_NEW}}))
        sc = self.scope()
        ok, why = sc.name_allowed("alias.example.test")
        self.assertFalse(ok)
        self.assertIn(S.HELD_NEW, why)
        dmap = S.dns_map(self.run)
        keep, hosts = S.filter_items(sc, ["94.140.14.14"], "portscan", "portscan", dmap)
        self.assertEqual(keep, ["94.140.14.14"])                 # the address is scanned for the approved host
        self.assertEqual(set(hosts), {"range.example.test"})     # but the held-back name on it is not covered
        keep, _ = S.filter_items(sc, ["https://alias.example.test/", "https://range.example.test/"], "urls", "nuclei", dmap)
        self.assertEqual(keep, ["https://range.example.test/"])

    def test_domain_not_in_the_approved_inventory_holds_every_host(self):
        apex = lambda h: "added.test" if h.endswith(".added.test") else "example.test"   # noqa: E731
        a = [{"hostname": "www.example.test", "ips": ["8.8.8.8"], "class": "owned"},
             {"hostname": "shop.added.test", "ips": ["8.8.8.8"], "class": "unverified"},
             {"hostname": "cdn.added.test", "ips": ["8.8.4.4"], "class": "cdn_fronted"}]
        import ipaddress
        held = S.compute_held_back(self.INV, a, [ipaddress.ip_network("94.140.14.0/24")], [], held_domains=["added.test"], apex_of=apex)
        self.assertEqual(held, {"shop.added.test": S.HELD_DOMAIN, "cdn.added.test": S.HELD_DOMAIN})

    def test_cdn_by_cname_is_not_held_for_edge_address_rotation(self):
        import ipaddress
        inv = {"cdn.example.test": {"ips": ["8.8.4.4"], "class": "cdn_fronted", "via_cname": "edge.provider.test"},
               "saas.example.test": {"ips": ["8.8.4.4"], "class": "third_party", "via_cname": "saas.provider.test"},
               "range.example.test": {"ips": ["8.8.4.4"], "class": "third_party"},           # classed by address range
               "www.example.test": {"ips": ["8.8.8.8"], "class": "unverified"}}               # direct A record
        held = lambda assets: S.compute_held_back(inv, assets, [], [ipaddress.ip_network("8.8.4.0/24")])  # noqa: E731
        rotated = [{"hostname": "cdn.example.test", "ips": ["1.1.1.1"], "class": "cdn_fronted", "cnames": ["d1.edge.provider.test"]},
                   {"hostname": "saas.example.test", "ips": ["1.0.0.1"], "class": "third_party", "cnames": ["x.saas.provider.test"]}]
        self.assertEqual(held(rotated), {})                                   # same provider suffix: no drift check
        moved = [{"hostname": "cdn.example.test", "ips": ["1.1.1.1"], "class": "cdn_fronted", "cnames": ["d1.other-cdn.test"]}]
        self.assertEqual(held(moved), {"cdn.example.test": S.HELD_ADDRESS})  # CNAME moved to another provider
        direct = [{"hostname": "cdn.example.test", "ips": ["1.1.1.1"], "class": "unverified", "cnames": []}]
        self.assertEqual(held(direct), {"cdn.example.test": S.HELD_ADDRESS}) # no CNAME any more
        owned_now = [{"hostname": "cdn.example.test", "ips": ["1.1.1.1"], "class": "owned", "cnames": ["d1.edge.provider.test"]}]
        self.assertEqual(held(owned_now), {"cdn.example.test": S.HELD_ADDRESS})   # now a class that gets a port scan
        same = [{"hostname": "cdn.example.test", "ips": ["8.8.4.4"], "class": "cdn_fronted", "cnames": ["d1.other-cdn.test"]}]
        self.assertEqual(held(same), {})                                      # moved provider but same listed address
        by_range = [{"hostname": "range.example.test", "ips": ["1.1.1.1"], "class": "third_party", "cnames": []}]
        self.assertEqual(held(by_range), {"range.example.test": S.HELD_ADDRESS})  # classed by range: unchanged rule
        www = [{"hostname": "www.example.test", "ips": ["1.1.1.1"], "class": "unverified", "cnames": []}]
        self.assertEqual(held(www), {"www.example.test": S.HELD_ADDRESS})     # direct address record: unchanged rule
        # an inventory written before via_cname existed keeps the address rule
        old = {"cdn.example.test": {"ips": ["8.8.4.4"], "class": "cdn_fronted"}}
        self.assertEqual(S.compute_held_back(old, rotated[:1], [], []), {"cdn.example.test": S.HELD_ADDRESS})

    def test_via_cname_survives_normalization_and_is_validated(self):
        inv = A.normalize_inventory({"domains": ["example.test"], "hosts": {
            "cdn.example.test": {"ips": ["8.8.4.4"], "class": "cdn_fronted", "via_cname": "Edge.Provider.Test."}}})
        self.assertEqual(inv["hosts"]["cdn.example.test"]["via_cname"], "edge.provider.test")
        for bad in ("not a name", 7, ""):
            with self.assertRaises(S.ScopeError):
                A.normalize_inventory({"domains": [], "hosts": {"c.example.test": {"ips": [], "class": "cdn_fronted", "via_cname": bad}}})

    def test_hold_back_with_an_added_and_a_pending_domain(self):
        write(os.path.join(self.sc, "domains.txt"), "example.test\nother.test\nadded.test\npending.test\n")
        inventory_manifest(self.root, "inv-1", ["example.test", "other.test"], {"www.example.test": ["8.8.8.8"]})
        A.approve_inventory(self.root, "inv-1", "Pat", now=NOW)
        write(os.path.join(self.run, "apexes.txt"), "example.test\nother.test\nadded.test\n")   # pending.test failed the proof
        assets = [{"hostname": "www.example.test", "ips": ["8.8.8.8"], "class": "owned", "cnames": []},
                  {"hostname": "shop.added.test", "ips": ["8.8.4.4"], "class": "unverified", "cnames": []},
                  {"hostname": "new.example.test", "ips": ["8.8.4.4"], "class": "unverified", "cnames": []}]
        write(os.path.join(self.run, "assets.jsonl"), "".join(json.dumps(x) + "\n" for x in assets))
        cfg = os.path.join(self.root, "config"); os.makedirs(cfg)
        held = A.hold_back(self.sc, self.run, cfg)
        self.assertEqual(held, {"shop.added.test": S.HELD_DOMAIN, "new.example.test": S.HELD_NEW})
        doc = json.loads(read(os.path.join(self.run, S.HELD_BACK_FILE)))
        self.assertEqual(doc["domains"], {"scanned": ["example.test", "other.test"], "held_back": ["added.test"], "pending": ["pending.test"]})
        self.assertEqual(doc["addresses"]["shop.added.test"], {"approved": [], "now": ["8.8.4.4"]})
        for d in ("added.test", "other.test"):
            self.verified(d)
        sc = self.scope()
        self.assertTrue(sc.name_allowed("www.example.test")[0])
        self.assertTrue(sc.name_allowed("api.other.test")[0])                 # covered domain, verified
        for h in ("shop.added.test", "added.test", "mail.added.test"):         # live or not: the whole domain is held
            ok, why = sc.name_allowed(h)
            self.assertFalse(ok, h)
            self.assertIn(S.HELD_DOMAIN, why)
        write(os.path.join(self.run, "dns.jsonl"), json.dumps({"host": "shop.added.test", "a": ["94.140.14.3"]}) + "\n")
        keep, _ = S.filter_items(sc, ["shop.added.test", "added.test"], "names", "nuclei-dns")
        self.assertEqual(keep, [])
        keep, _ = S.filter_items(sc, ["94.140.14.3"], "portscan", "portscan", S.dns_map(self.run))
        self.assertEqual(keep, [])                                             # its address in an owned range: still no

    def test_unreadable_held_back_file_fails_closed(self):
        write(os.path.join(self.run, S.HELD_BACK_FILE), "{not json")
        with self.assertRaises(S.ScopeError):
            self.scope()


class Tokens(Base):
    def test_derived_per_install_and_per_domain(self):
        other_state = os.path.join(self.root, "state-b")
        b, created = S.load_secret(other_state, create=True)
        self.assertTrue(created)
        self.assertEqual(S.load_secret(self.state_dir)[0], self.secret)                     # the same install keeps its secret
        t = S.derive_token(self.secret, "example.test")
        self.assertRegex(t, r"^[0-9a-f]{32}$")
        self.assertEqual(t, S.derive_token(self.secret, "example.test"))                   # stable
        self.assertNotEqual(t, S.derive_token(b, "example.test"))                          # two installs differ
        self.assertNotEqual(t, S.derive_token(self.secret, "other.test"))                  # two domains differ

    def test_token_copied_from_another_install_does_not_verify(self):
        # install A's record is public; a job on install B naming the same domain cannot use it
        a_state, b_state = os.path.join(self.root, "state-a"), os.path.join(self.root, "state-b")
        a, _ = S.load_secret(a_state, create=True)
        S.load_secret(b_state, create=True)
        published_by_a = ["scan-verify=" + S.derive_token(a, "example.test")]
        lines = []
        self.verified("example.test", state="pending")
        usable = S.verify_apexes(self.sc, ["example.test"], lookup=lambda x: [("ns1.example.test", PUB, published_by_a)],
                                 now=NOW, log=lines.append, state_dir=b_state)
        self.assertEqual(usable, [])
        self.assertNotEqual(S.load_ownership(self.sc)["example.test"]["state"], "verified")
        usable = S.verify_apexes(self.sc, ["example.test"], lookup=lambda x: [("ns1.example.test", PUB, published_by_a)],
                                 now=NOW, log=lines.append, state_dir=a_state)
        self.assertEqual(usable, ["example.test"])          # control: on install A it does verify

    def test_published_record_is_what_the_check_expects(self):
        tok = S.derive_token(self.secret, "example.test")
        name, value = S.record_for("example.test", tok)
        self.assertEqual(name, "_scan-verify.example.test")
        self.assertEqual(S.check_proof("example.test", tok, [("ns1", PUB, [value])], S.strict_ip_check)[0], "match")

    def test_secret_file_permissions_and_refusals(self):
        st_dir = os.stat(self.state_dir)
        st = os.stat(os.path.join(self.state_dir, S.SECRET_FILE))
        self.assertEqual(st_dir.st_mode & 0o777, 0o700)
        self.assertEqual(st.st_mode & 0o777, 0o600)
        with self.assertRaises(S.ScopeError):
            S.load_secret(os.path.join(self.root, "nowhere"))                  # missing and not asked to create
        os.chmod(os.path.join(self.state_dir, S.SECRET_FILE), 0o644)
        S.load_secret(self.state_dir)
        self.assertEqual(os.stat(os.path.join(self.state_dir, S.SECRET_FILE)).st_mode & 0o777, 0o600)   # tightened again
        link_dir = os.path.join(self.root, "state-link"); os.makedirs(link_dir)
        os.symlink(os.path.join(self.state_dir, S.SECRET_FILE), os.path.join(link_dir, S.SECRET_FILE))
        with self.assertRaises(S.ScopeError):
            S.load_secret(link_dir)                                              # never read through a link

    def test_lost_secret_returns_every_domain_to_pending(self):
        self.verified("example.test", state="verified")
        os.unlink(os.path.join(self.state_dir, S.SECRET_FILE))
        new, created = S.load_secret(self.state_dir, create=True)
        self.assertTrue(created)
        lines = []
        S.verify_apexes(self.sc, ["example.test"], lookup=lambda x: [("ns1", PUB, ["scan-verify=" + S.derive_token(self.secret, "example.test")])],
                        now=NOW, log=lines.append, state_dir=self.state_dir)
        e = S.load_ownership(self.sc)["example.test"]
        self.assertEqual((e["state"], e.get("token_reset"), e["key_id"]), ("pending", S.TOKEN_RESET_SECRET, S.key_id(new)))
        self.assertIn("install secret was replaced", " ".join(lines))


class CnameChain(Base):
    def setUp(self):
        super().setUp()
        recs = [{"host": "alias.example.test", "a": ["94.140.14.5"], "cname": ["skip.example.test"]},
                {"host": "two.example.test", "a": ["94.140.14.6"], "cname": ["hop.example.test", "x.legacy.example.test"]},
                {"host": "fine.example.test", "a": ["94.140.14.7"], "cname": ["cdn.provider.test"]}]
        write(os.path.join(self.run, "dns.jsonl"), "".join(json.dumps(r) + "\n" for r in recs))

    def test_alias_of_an_excluded_name_is_refused(self):
        sc = self.scope()
        dmap, chains = S.dns_records(self.run)
        self.assertEqual(chains["two.example.test"], ["hop.example.test", "x.legacy.example.test"])
        items = ["alias.example.test", "two.example.test", "fine.example.test"]
        for kind, its in (("hosts", items), ("urls", [f"https://{h}/" for h in items]), ("hostports", [f"{h}:443" for h in items])):
            keep, _ = S.filter_items(sc, its, kind, "t", dmap, chains)
            self.assertEqual(keep, [its[2]], kind)
        keep, _ = S.filter_items(sc, ["94.140.14.5", "94.140.14.6", "94.140.14.7"], "portscan", "t", dmap, chains)
        self.assertEqual(keep, ["94.140.14.7"])
        rej = [json.loads(l) for l in read(os.path.join(self.run, "scope_rejected.jsonl")).splitlines()]
        self.assertTrue(any("CNAME chain reaches skip.example.test" in r["reason"] for r in rej))
        self.assertTrue(any("CNAME chain reaches x.legacy.example.test" in r["reason"] for r in rej))   # second step

    def test_cli_filter_applies_the_chain(self):
        inp, out = os.path.join(self.run, "in.txt"), os.path.join(self.run, "out.txt")
        write(inp, "alias.example.test\nfine.example.test\n")
        with contextlib.redirect_stderr(io.StringIO()):
            S.main(["filter", "--scope", self.sc, "--run-dir", self.run, "--stage", "probe", "--kind", "hosts", "--in", inp, "--out", out])
        self.assertEqual(read(out), "fine.example.test\n")


class CnameLookup(Base):
    """scope.cname_lookup and Scope.cname_allowed: the CNAME check for gates outside recon (version watch)."""
    TWO = (";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 7\n;; ANSWER SECTION:\n"
           "two.example.test.\t300\tIN\tCNAME\thop.example.test.\n"
           "hop.example.test.\t300\tIN\tCNAME\tX.Legacy.example.test.\n"
           "x.legacy.example.test.\t300\tIN\tA\t94.140.14.6\n")

    def test_parses_every_step_of_the_chain(self):
        with mock.patch.object(S, "_dig", return_value=(0, self.TWO)) as dig:
            self.assertEqual(S.cname_lookup("two.example.test"), ["hop.example.test", "x.legacy.example.test"])
        self.assertIn("two.example.test", dig.call_args[0][0])
        plain = ";; ->>HEADER<<- status: NOERROR\nwww.example.test.\t300\tIN\tA\t8.8.8.8\n"
        with mock.patch.object(S, "_dig", return_value=(0, plain)):
            self.assertEqual(S.cname_lookup("www.example.test"), [])
        with mock.patch.object(S, "_dig", return_value=(0, ";; ->>HEADER<<- status: NXDOMAIN\n")):
            self.assertEqual(S.cname_lookup("gone.example.test"), [])

    def test_no_usable_answer_raises(self):
        for rc, out in ((9, ";; connection timed out; no servers could be reached"), (0, ";; ->>HEADER<<- status: SERVFAIL"),
                        (0, "")):
            with mock.patch.object(S, "_dig", return_value=(rc, out)):
                with self.assertRaises(OSError):
                    S.cname_lookup("two.example.test")

    def test_cname_allowed_uses_the_same_exclusion_check_as_recon(self):
        sc = self.scope()
        chains = {"alias.example.test": ["skip.example.test"], "two.example.test": ["hop.example.test", "x.legacy.example.test"],
                  "fine.example.test": ["cdn.provider.test"]}
        ok, why = sc.cname_allowed("alias.example.test", chains.get)
        self.assertEqual((ok, why), (False, "CNAME chain reaches skip.example.test, excluded by exclude.txt (skip.example.test)"))
        ok, why = sc.cname_allowed("two.example.test", chains.get)
        self.assertFalse(ok)
        self.assertIn("x.legacy.example.test", why)
        self.assertTrue(sc.cname_allowed("fine.example.test", chains.get)[0])
        self.assertTrue(sc.cname_allowed("www.example.test", lambda h: [])[0])
        def fail(h):
            raise OSError("no answer from the resolver")
        ok, why = sc.cname_allowed("www.example.test", fail)
        self.assertFalse(ok)
        self.assertIn("could not be looked up", why)
        with mock.patch.object(S, "_dig", return_value=(0, self.TWO)):       # default lookup goes through dig
            self.assertFalse(sc.cname_allowed("two.example.test")[0])


class UrlHost(unittest.TestCase):
    def test_no_whitespace_in_the_host_part(self):
        self.assertIsNone(S.host_of("https://www.example.test evil.test/", "urls"))
        self.assertIsNone(S.host_of("https://www .example.test/", "urls"))
        self.assertEqual(S.host_of("https://www.example.test/a b", "urls"), "www.example.test")   # path text is not the host


if __name__ == "__main__":
    unittest.main()
