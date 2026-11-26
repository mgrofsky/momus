"""Unit tests for scanner/runner.py (job validation, scope writing, status and publishing) and scanner/jobctl.py.
Host-side, standard library only: no containers, no network, no tools run."""
import contextlib
import hashlib
import io
import ipaddress
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import runner as R   # noqa: E402
import jobctl as J   # noqa: E402
import scope as S    # noqa: E402

LAB = ipaddress.ip_network("10.89.47.0/24")


def rd(path):
    with open(path) as fh:
        return fh.read()


def rj(path):
    with open(path) as fh:
        return json.load(fh)


def wr(path, text):
    with open(path, "w") as fh:
        fh.write(text)
TOKEN = "0123456789abcdef0123456789abcdef"


WATCH = {"id": "php-example", "name": "PHP example", "product": "php", "cves": ["CVE-2099-10001"],
         "floors": {"8.2": 35, "8.3": 36}, "hosts": ["www.example.test"]}


def good_job(jid="full-1", jtype="full", **over):
    if jtype == "version-watch" and "options" not in over:     # a version-watch job needs at least one watch
        over["options"] = {"watches": [dict(WATCH)]}
    # created_at: now (a job dated more than five minutes ahead is refused, so a fixed future date would not work)
    job = {"schema": R.SCHEMA, "id": jid, "type": jtype, "created_at": _iso_ago(0),
           "scope": {"domains": ["example.test"], "exclude": [".legacy.example.test", "192.0.2.0/28"],
                     "owned_ranges": ["198.51.100.0/24"], "approved_hosts": ["www.example.test"],
                     "strict_sla_hosts": ["pay.example.test"],
                     "ownership": [{"apex": "example.test", "statement": S.OWNERSHIP_STATEMENT, "attested_by": "Ada Owner",
                                    "attested_at": "2030-01-01T00:00:00Z"}],
                     "approval": None, "check_profile": "safe", "rate_profile": "low", "evidence": "minimal"}}
    job.update(over)
    return job


class Validation(unittest.TestCase):
    def ok(self, job, fid=None, lab=None):
        return R.validate_job(job, fid or job.get("id"), lab)

    def bad(self, job, fid=None, lab=None, contains=None, value=None):
        with self.assertRaises(R.Invalid) as cm:
            R.validate_job(job, fid or (job.get("id") if isinstance(job.get("id"), str) else "x1"), lab)
        msg = str(cm.exception)
        if contains:
            self.assertIn(contains, msg)
        if value:
            self.assertNotIn(value, msg)   # the offending value is never echoed
        return msg

    def test_good_job_normalized(self):
        j = self.ok(good_job())
        self.assertEqual(j["scope"]["domains"], ["example.test"])
        self.assertEqual(j["scope"]["exclude"], [".legacy.example.test", "192.0.2.0/28"])
        self.assertNotIn("token", j["scope"]["ownership"][0])
        self.assertNotIn("state", j["scope"]["ownership"][0])

    def test_every_type(self):
        for t in R.JOB_TYPES:
            self.assertEqual(self.ok(good_job(jid=f"{t}-1", jtype=t))["type"], t)

    def test_unknown_fields(self):
        self.bad(good_job(extra=1), contains="unknown field 'extra'")
        j = good_job(); j["scope"]["owner_note"] = "x"
        self.bad(j, contains="scope: unknown field 'owner_note'")
        j = good_job(); j["<script>"] = 1
        self.bad(j, contains="unknown field (unprintable name)", value="<script>")

    def test_ids(self):
        for bad_id in ("A-1", "a", "-ab", "ab-", "a_b", "a b", "a;b", "a/../b", "x" * 65, "", 7, None):
            j = good_job(jid=bad_id)
            self.bad(j, fid="x1", contains="id:")
        self.bad(good_job(jid="full-2"), fid="full-1", contains="does not match the file name")

    def test_schema_and_type(self):
        self.bad(good_job(schema="v0"), contains="schema")
        self.bad(good_job(type="exploit"), contains="type: must be one of", value="exploit")

    def test_domain_with_shell_characters(self):
        for d in ("example.test;rm -rf /", "$(id).example.test", "`x`.example.test", "Example.TEST", "example.test.", "a b.test", "x"):
            j = good_job(); j["scope"]["domains"] = [d]; j["scope"]["ownership"] = []
            self.bad(j, contains="scope.domains[0]: not a valid host name", value=d if len(d) > 3 else None)

    def test_oversized_lists(self):
        j = good_job(); j["scope"]["domains"] = [f"d{i}.example.test" for i in range(R.LIMITS["domains"] + 1)]
        self.bad(j, contains="more than 200 entries")
        j = good_job(); j["scope"]["approved_hosts"] = [f"h{i}.example.test" for i in range(5001)]
        self.bad(j, contains="scope.approved_hosts: more than")
        j = good_job(); j["scope"]["exclude"] = ["x." * 200 + "test"]
        self.bad(j, contains="longer than 253")

    def test_exclusions_and_ranges(self):
        for e in ("*.old.example.test", ".old.example.test", "old.example.test", "203.0.113.7", "2001:db8::/32"):
            j = good_job(); j["scope"]["exclude"] = [e]
            self.ok(j)
        for e in ("not a cidr/99", "10.0.0.0/33", "*.", "..x"):
            j = good_job(); j["scope"]["exclude"] = [e]
            self.bad(j, contains="scope.exclude[0]")
        j = good_job(); j["scope"]["owned_ranges"] = ["300.1.1.0/24"]
        self.bad(j, contains="scope.owned_ranges[0]: not an address or CIDR")

    def test_token_anywhere_in_ownership_is_rejected(self):
        # a TXT record is public: a job must never be able to hand the scanner a token
        for tok in (TOKEN, "", None, ["x"], {"a": 1}):
            j = good_job(); j["scope"]["ownership"][0]["token"] = tok
            self.bad(j, contains="field 'token' not allowed", value=TOKEN)
        j = good_job(); j["scope"]["domains"].append("other.test")
        j["scope"]["ownership"].append({"apex": "other.test", "statement": S.OWNERSHIP_STATEMENT, "attested_by": "Ada",
                                        "attested_at": "2030-01-01T00:00:00Z", "token": TOKEN})
        self.bad(j, contains="scope.ownership: field 'token' not allowed")

    def test_scope_sync_needs_a_domain_and_no_lab(self):
        j = good_job(jid="sync-1", jtype="scope-sync"); j["scope"]["domains"] = []; j["scope"]["ownership"] = []
        self.bad(j, contains="at least one domain")
        self.bad(good_job(jid="sync-1", jtype="scope-sync", lab={"targets": ["target.demo.test"], "cidr": "10.89.47.0/24"}),
                 lab=LAB, contains="only inventory and full jobs")

    def test_cannot_set_verification_state(self):
        for k, v in (("state", "verified"), ("verified_at", "2030-01-01T00:00:00Z"), ("last_checked_at", "2030-01-01T00:00:00Z"), ("verified", True)):
            j = good_job(); j["scope"]["ownership"][0][k] = v
            self.bad(j, contains="verification state is kept by the scanner")

    def test_ownership_rules(self):
        j = good_job(); j["scope"]["ownership"][0]["apex"] = "other.test"
        self.bad(j, contains="not one of scope.domains")
        j = good_job(); j["scope"]["ownership"][0]["token"] = "ABC"
        self.bad(j, contains="field 'token' not allowed", value="ABC")
        j = good_job(); j["scope"]["ownership"][0]["statement"] = "I think I own it"
        self.bad(j, contains="exactly the ownership statement")
        j = good_job(); j["scope"]["ownership"][0]["attested_by"] = "<b>x</b>"
        self.bad(j, contains="attested_by", value="<b>")
        j = good_job(); del j["scope"]["ownership"][0]["attested_at"]
        self.bad(j, contains="missing field(s) attested_at")
        j = good_job(); j["scope"]["ownership"].append(dict(j["scope"]["ownership"][0]))
        self.bad(j, contains="listed twice")

    def test_approval(self):
        j = good_job(); j["scope"]["approval"] = {"approved_at": "2030-01-01T00:00:00Z", "inventory_run": "inv-1", "approved_by": "Ada"}
        self.assertEqual(self.ok(j)["scope"]["approval"]["inventory_run"], "inv-1")
        j["scope"]["approval"]["inventory_run"] = "../../etc"
        self.bad(j, contains="scope.approval.inventory_run")
        j["scope"]["approval"] = {"approved_at": "2030-01-01T00:00:00Z", "inventory_run": "inv-1"}
        self.bad(j, contains="needs approved_at")

    def test_profiles_enumerated(self):
        for k, v in (("check_profile", "aggressive"), ("rate_profile", "max"), ("evidence", "full")):
            j = good_job(); j["scope"][k] = v
            self.bad(j, contains=f"scope.{k}: must be one of", value=v)

    def test_domains_required_outside_lab(self):
        j = good_job(); j["scope"]["domains"] = []; j["scope"]["ownership"] = []
        self.bad(j, contains="at least one domain")
        j = good_job(jid="ret-1", jtype="retention"); j["scope"]["domains"] = []; j["scope"]["ownership"] = []
        self.ok(j)

    def test_lab_fields(self):
        j = good_job(lab={"targets": ["target.demo.test"], "cidr": "10.89.47.0/24"})
        self.bad(j, contains="not started in lab mode")
        self.assertEqual(self.ok(j, lab=LAB)["lab"], {"targets": ["target.demo.test"], "cidr": "10.89.47.0/24"})
        j = good_job(lab={"targets": ["target.demo.test"], "cidr": "10.89.48.0/24"})
        self.bad(j, lab=LAB, contains="must equal the lab range")
        j = good_job(jid="rc-1", jtype="recheck", lab={"targets": ["target.demo.test"], "cidr": "10.89.47.0/24"})
        self.bad(j, lab=LAB, contains="only inventory and full")
        j = good_job(lab={"targets": [], "cidr": "10.89.47.0/24"})
        self.bad(j, lab=LAB, contains="at least one target")
        j = good_job(lab={"targets": ["target.demo.test"], "cidr": "10.89.47.0/24", "x": 1})
        self.bad(j, lab=LAB, contains="lab: unknown field")
        j = good_job(lab={"targets": ["target.demo.test"], "cidr": "10.89.47.0/24"}); j["scope"]["domains"] = []; j["scope"]["ownership"] = []
        self.ok(j, lab=LAB)   # a lab job needs no domain

    def test_options(self):
        j = good_job(jid="ret-1", jtype="retention", options={"retention_days": 7})
        self.assertEqual(self.ok(j)["options"], {"retention_days": 7})
        for v in (0, 3651, "7", True):
            self.bad(good_job(jid="ret-1", jtype="retention", options={"retention_days": v}), contains="retention_days")
        self.bad(good_job(options={"retention_days": 7}), contains="options: unknown field")


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="runner-test-")
        self.root, self.jobs, self.pub = (os.path.join(self.tmp, d) for d in ("root", "jobs", "pub"))
        os.makedirs(self.jobs)
        self.logs = []
        self.traces = []
        self.r = R.Runner(self.root, self.jobs, self.pub, lab_env=None, keep_snapshots=2, app=self.tmp, log=self.logs.append,
                          trace=self.traces.append)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def put(self, name, doc, mtime=None):
        p = os.path.join(self.jobs, name)
        with open(p, "w") as fh:
            fh.write(doc if isinstance(doc, str) else json.dumps(doc))
        if mtime:
            os.utime(p, (mtime, mtime))
        return p

    def status(self, key):
        with open(os.path.join(self.pub, "status", f"{key}.json")) as fh:
            return json.load(fh)

    def fake_steps(self, rcs):
        calls = []

        def run_step(self_, key, job, phase, argv, logname, extra_env=None, cwd=None):
            calls.append((phase, argv, self_.env(job, extra_env)))
            if phase == "ingest":
                make_db(os.path.join(self.root, "data", "scan.sqlite"), job["id"])
            if phase == "report":
                os.makedirs(os.path.join(self.root, "reports"), exist_ok=True)
                wr(os.path.join(self.root, "reports", f"{job['id']}.html"), "<html></html>")
            return rcs.get(phase, 0)
        return calls, run_step


class Scope(Base):
    def test_scope_written_atomically_by_link(self):
        self.r.write_scope(R.validate_job(good_job(), "full-1"))
        link = os.path.join(self.root, "scope")
        self.assertTrue(os.path.islink(link))
        self.assertTrue(os.readlink(link).startswith("scope.d/full-1-"))
        sc = S.Scope(link)
        self.assertEqual(sc.apexes, ["example.test"])
        self.assertEqual(rd(os.path.join(link, "strict_sla_hosts.txt")), "pay.example.test\n")
        self.assertEqual(rj(os.path.join(link, "profile.json")), {"check_profile": "safe", "rate_profile": "low"})
        self.assertFalse(os.path.exists(os.path.join(link, "approval.json")))
        first = os.readlink(link)
        self.r.write_scope(R.validate_job(good_job(jid="full-2"), "full-2"))
        self.assertNotEqual(os.readlink(link), first)
        self.assertEqual(os.listdir(os.path.join(self.root, "scope.d")), [os.path.basename(os.readlink(link))])   # old generation gone

    def test_verification_state_kept_only_while_the_install_secret_is_unchanged(self):
        self.r.write_scope(R.validate_job(good_job(), "full-1"))
        ents = S.load_ownership(os.path.join(self.root, "scope"))
        self.assertEqual(ents["example.test"]["state"], "pending")
        self.assertNotIn("token", ents["example.test"])
        # the scanner verified it (as verify_apexes would)
        ents["example.test"].update(state="verified", verified_at="2030-01-02T00:00:00Z", last_checked_at="2030-01-02T00:00:00Z")
        S.save_ownership(os.path.join(self.root, "scope"), ents)
        self.r.write_scope(R.validate_job(good_job(jid="full-2"), "full-2"))
        e = S.load_ownership(os.path.join(self.root, "scope"))["example.test"]
        self.assertEqual((e["state"], e["verified_at"]), ("verified", "2030-01-02T00:00:00Z"))
        # the secret file is lost: a new runner creates a new one, and every domain is pending with a new token
        old_tok = S.derive_token(self.r.secret, "example.test")
        os.unlink(os.path.join(self.root, "state", S.SECRET_FILE))
        logs = []
        r2 = R.Runner(self.root, self.jobs, self.pub, keep_snapshots=2, app=self.tmp, log=logs.append, trace=self.traces.append)
        e = S.load_ownership(os.path.join(self.root, "scope"))["example.test"]
        self.assertEqual((e["state"], e.get("token_reset")), ("pending", S.TOKEN_RESET_SECRET))
        self.assertNotIn("verified_at", e)
        self.assertTrue(any("new install secret" in l and "pending with a new token" in l for l in logs), logs)
        r2.publish_scope_status()
        ss = rj(os.path.join(self.pub, "scope_status.json"))
        self.assertEqual(ss["notice"], R.SECRET_NOTICE)
        self.assertEqual(ss["domains"]["example.test"]["token_reset"], S.TOKEN_RESET_SECRET)
        self.assertNotEqual(ss["domains"]["example.test"]["txt_value"], S.VERIFY_PREFIX + old_tok)
        r2.write_scope(R.validate_job(good_job(jid="full-3"), "full-3"))   # a later job keeps the reset visible
        self.assertEqual(S.load_ownership(os.path.join(self.root, "scope"))["example.test"]["token_reset"], S.TOKEN_RESET_SECRET)

    def test_secret_created_owner_only_and_never_published(self):
        p = os.path.join(self.root, "state", S.SECRET_FILE)
        self.assertEqual(os.stat(p).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(os.path.dirname(p)).st_mode & 0o777, 0o700)
        secret_hex = rd(p).strip()
        self.put("sync-1.json", good_job(jid="sync-1", jtype="scope-sync"))
        calls, fake = self.fake_steps({})
        with mock.patch.object(R.Runner, "run_step", fake):
            self.r.step()
        self.put("full-1.json", good_job())
        with mock.patch.object(R.Runner, "run_step", fake):
            self.r.step()
        self.r.heartbeat()
        for d, _, fs in os.walk(self.pub):
            for f in fs:
                self.assertNotEqual(f, S.SECRET_FILE)
                with open(os.path.join(d, f), "rb") as fh:
                    data = fh.read()
                self.assertNotIn(secret_hex.encode(), data, f)
                self.assertNotIn(bytes.fromhex(secret_hex), data, f)

    def test_scope_status_published(self):
        j = good_job(); j["scope"]["domains"] = ["example.test", "other.test"]
        self.r.write_scope(R.validate_job(j, "full-1"))
        ss = rj(os.path.join(self.pub, "scope_status.json"))["domains"]
        self.assertEqual(ss["example.test"]["state"], "pending")
        self.assertEqual(ss["example.test"]["txt_name"], f"{S.VERIFY_LABEL}.example.test")
        self.assertEqual(ss["example.test"]["txt_value"], f"{S.VERIFY_PREFIX}{S.derive_token(self.r.secret, 'example.test')}")
        self.assertEqual(ss["other.test"]["state"], "no-statement")
        # every domain gets its record, so the user can publish it before or after the statement
        self.assertEqual(ss["other.test"]["txt_value"], f"{S.VERIFY_PREFIX}{S.derive_token(self.r.secret, 'other.test')}")
        doc = rj(os.path.join(self.pub, "scope_status.json"))
        self.assertEqual((doc["install_key_id"], doc["notice"]), (S.key_id(self.r.secret), None))
        # the published record is exactly what the proof check expects
        tok = S.derive_token(self.r.secret, "example.test")
        self.assertEqual(S.check_proof("example.test", tok, [("ns1", "8.8.8.8", [ss["example.test"]["txt_value"]])], S.strict_ip_check)[0], "match")

    def inventory_run(self, run_id, domains=("example.test",), hosts=None, lab_targets=()):
        run = os.path.join(self.root, "runs", run_id)
        os.makedirs(run, exist_ok=True)
        R.write_json(os.path.join(run, "manifest.json"), {"run_id": run_id, "rc": 0, "inventory": {
            "domains": list(domains), "lab_targets": list(lab_targets),
            "hosts": hosts if hosts is not None else {"www.example.test": {"ips": ["8.8.8.8"], "class": "owned"}}}})

    def test_approval_needs_the_inventory_run(self):
        j = good_job(); j["scope"]["approval"] = {"approved_at": "2030-01-01T00:00:00Z", "inventory_run": "inv-1", "approved_by": "Ada"}
        job = R.validate_job(j, "full-1")
        with self.assertRaises(R.Invalid):
            self.r.write_scope(job)
        run = os.path.join(self.root, "runs", "inv-1")
        os.makedirs(run)
        for f in ("manifest.json", "assets.jsonl"):
            wr(os.path.join(run, f), "{}\n")
        with self.assertRaises(R.Invalid):          # a run folder is not enough: the run must have recorded an inventory
            self.r.write_scope(job)
        self.inventory_run("inv-1")
        self.r.write_scope(job)
        a = rj(os.path.join(self.root, "scope", "approval.json"))
        self.assertEqual({k: a[k] for k in ("approved_at", "inventory_run", "approved_by")},
                         {"approved_at": "2030-01-01T00:00:00Z", "inventory_run": "inv-1", "approved_by": "Ada"})
        self.assertEqual(a["inventory"]["hosts"], {"www.example.test": {"ips": ["8.8.8.8"], "class": "owned"}})

    def test_approval_naming_another_domains_inventory_is_refused(self):
        self.inventory_run("inv-other", domains=("unrelated.test",))
        j = good_job(); j["scope"]["approval"] = {"approved_at": "2030-01-01T00:00:00Z", "inventory_run": "inv-other", "approved_by": "Ada"}
        self.put("full-1.json", j)
        with mock.patch.object(R.Runner, "job_full") as jf:
            self.r.step()
            jf.assert_not_called()
        st = self.status("full-1")
        self.assertEqual(st["state"], "rejected")
        self.assertIn("covers none of this scope's domains", st["reason"])
        self.assertNotIn("unrelated", st["reason"])
        self.assertFalse(os.path.islink(os.path.join(self.root, "scope")))    # the scope was not switched

    def test_approval_only_written_for_active_jobs(self):
        self.inventory_run("inv-1")
        for jt in ("inventory", "scope-sync"):
            j = good_job(jid=f"{jt}-1", jtype=jt)
            j["scope"]["approval"] = {"approved_at": "2030-01-01T00:00:00Z", "inventory_run": "inv-gone", "approved_by": "Ada"}
            self.r.write_scope(R.validate_job(j, f"{jt}-1"))      # never refused for a stale approval: nothing active runs
            self.assertFalse(os.path.exists(os.path.join(self.root, "scope", "approval.json")))

    def test_lab_approval_bound_to_lab_targets(self):
        r = R.Runner(self.root, self.jobs, self.pub, lab_env=LAB, keep_snapshots=2, app=self.tmp, log=self.logs.append, trace=self.traces.append)
        self.inventory_run("inv-notice", domains=(), hosts={}, lab_targets=("notice.demo.test",))
        lab = {"targets": ["notice.demo.test", "target.demo.test"], "cidr": "10.89.47.0/24"}
        j = good_job(jid="full-1", lab=lab)
        j["scope"]["approval"] = {"approved_at": "2030-01-01T00:00:00Z", "inventory_run": "inv-notice", "approved_by": "Ada"}
        with self.assertRaises(R.Invalid):
            r.write_scope(R.validate_job(j, "full-1", LAB))
        self.inventory_run("inv-both", domains=(), hosts={}, lab_targets=("notice.demo.test", "target.demo.test"))
        j["scope"]["approval"]["inventory_run"] = "inv-both"
        r.write_scope(R.validate_job(j, "full-1", LAB))
        self.assertTrue(os.path.exists(os.path.join(self.root, "scope", "approval.json")))


class Queue(Base):
    def test_rejections_and_keys(self):
        self.put("bad-1.json", good_job(jid="bad-1", extra=1))
        self.put("Bad Name!.json", good_job(jid="x1"))
        self.put("big-1.json", "{" + " " * (R.MAX_JOB_BYTES + 1) + "}")
        self.put("notjson-1.json", "{nope")
        with mock.patch.object(R.Runner, "run_job") as rj:
            self.assertFalse(self.r.step())
            rj.assert_not_called()
        self.assertEqual(self.status("bad-1")["state"], "rejected")
        self.assertIn("unknown field 'extra'", self.status("bad-1")["reason"])
        key = "invalid-" + hashlib.sha256(b"Bad Name!.json").hexdigest()[:16]
        self.assertEqual(self.status(key)["state"], "rejected")
        self.assertIn("file name", self.status(key)["reason"])
        self.assertIn("larger than", self.status("big-1")["reason"])
        self.assertIn("not valid UTF-8 JSON", self.status("notjson-1")["reason"])
        for f in os.listdir(os.path.join(self.pub, "status")):   # no status text echoes job content
            self.assertNotIn("Bad Name", rd(os.path.join(self.pub, "status", f)))

    def test_oldest_first_and_final_skipped(self):
        now = time.time()
        self.put("job-b.json", good_job(jid="job-b"), mtime=now - 10)
        self.put("job-a.json", good_job(jid="job-a"), mtime=now - 5)
        self.put("job-c.json", good_job(jid="job-c"), mtime=now - 20)
        R.write_json(os.path.join(self.pub, "status", "job-c.json"), {"job_id": "job-c", "state": "done"})
        ran = []
        with mock.patch.object(R.Runner, "run_job", lambda self_, key, job: (ran.append(key), self_.set_status(key, state="done"))):
            while self.r.step():
                pass
        self.assertEqual(ran, ["job-b", "job-a"])

    def test_queued_status(self):
        self.put("job-a.json", good_job(jid="job-a"))
        self.put("job-b.json", good_job(jid="job-b"))
        with mock.patch.object(R.Runner, "run_job"):
            self.r.step()
        self.assertEqual(self.status("job-b")["state"], "queued")

    def test_recover_marks_running_interrupted(self):
        R.write_json(os.path.join(self.pub, "status", "job-a.json"), {"job_id": "job-a", "state": "running", "phase": "recon"})
        R.write_json(os.path.join(self.pub, "status", "job-b.json"), {"job_id": "job-b", "state": "done"})
        wr(os.path.join(self.pub, "status", ".job-c.json.tmp-1"), "{")
        self.assertEqual(self.r.recover(), 1)
        self.assertEqual(self.status("job-a")["state"], "interrupted")
        self.assertEqual(self.status("job-b")["state"], "done")
        self.assertFalse(os.path.exists(os.path.join(self.pub, "status", ".job-c.json.tmp-1")))

    def test_lab_job_refused_without_lab_mode(self):
        self.put("lab-1.json", good_job(jid="lab-1", lab={"targets": ["target.demo.test"], "cidr": "10.89.47.0/24"}))
        with mock.patch.object(R.Runner, "run_job") as rj:
            self.r.step()
            rj.assert_not_called()
        self.assertIn("not started in lab mode", self.status("lab-1")["reason"])


class Hostile(Base):
    """A hostile job file never stops the runner: each gets a status and the next valid job still runs."""

    def run_all(self):
        ran = []

        def fake_run_job(self_, key, job):
            ran.append(key)
            self_.set_status(key, state="done")
        with mock.patch.object(R.Runner, "run_job", fake_run_job):
            for _ in range(20):
                if not self.r.step():
                    break
        return ran

    def then_valid(self, name, content, reason, mtime=None):
        now = time.time()
        p = os.path.join(self.jobs, name)
        with open(p, "wb") as fh:
            fh.write(content)
        os.utime(p, (now - 100, now - 100))
        self.put("next-1.json", good_job(jid="next-1"), mtime=now - 50)
        ran = self.run_all()
        self.assertEqual(ran, ["next-1"])
        key = name[:-5]
        st = self.status(key)
        self.assertEqual(st["state"], "rejected")
        self.assertIn(reason, st["reason"])
        return st

    def test_deeply_nested_arrays_and_objects(self):
        self.then_valid("deep-a.json", b"[" * 200000 + b"]" * 200000, "not valid UTF-8 JSON")
        os.unlink(os.path.join(self.pub, "status", "next-1.json"))
        os.unlink(self.r.finished_path("next-1"))     # a finished id never runs again unless its private record goes too
        self.then_valid("deep-o.json", b'{"a":' * 150000 + b"1" + b"}" * 150000, "not valid UTF-8 JSON")

    def test_nested_inside_a_valid_job(self):
        j = json.dumps(good_job(jid="deep-v")).encode()
        j = j[:-1] + b', "options": ' + b"[" * 100000 + b"]" * 100000 + b"}"
        self.then_valid("deep-v.json", j, "")

    def test_multi_megabyte_file_rejected_before_reading(self):
        real_read = os.read
        reads = []

        def counting_read(fd, n):
            reads.append(n)
            return real_read(fd, n)
        with mock.patch.object(R.os, "read", counting_read):
            self.then_valid("huge-1.json", b'{"x": "' + b"a" * (5 << 20) + b'"}', "larger than")
        self.assertLessEqual(sum(reads), R.MAX_JOB_BYTES + 1)

    def test_invalid_utf8(self):
        self.then_valid("utf-1.json", b'{"schema": "\xff\xfe"}', "not valid UTF-8 JSON")

    def test_duplicate_keys(self):
        j = json.dumps(good_job(jid="dup-1"))
        j = j[:-1] + ', "type": "retention"}'        # a second "type": json.loads would silently keep the last one
        self.then_valid("dup-1.json", j.encode(), "a key appears twice")

    def test_top_level_not_an_object(self):
        for i, doc in enumerate((b"[]", b'"x"', b"1", b"null", b"true")):
            st = self.then_valid(f"top-{i}x.json", doc, "must be an object")
            os.unlink(os.path.join(self.pub, "status", "next-1.json"))
            os.unlink(self.r.finished_path("next-1"))     # as above

    def test_exception_in_a_job_step(self):
        now = time.time()
        self.put("boom-1.json", good_job(jid="boom-1"), mtime=now - 100)
        self.put("next-1.json", good_job(jid="next-1"), mtime=now - 50)
        calls, fake = self.fake_steps({})
        state = {"n": 0}

        def exploding(self_, key, job, phase, argv, logname, extra_env=None, cwd=None):
            if job["id"] == "boom-1":
                raise RuntimeError("target text from a tool")
            return fake(self_, key, job, phase, argv, logname, extra_env, cwd)
        with mock.patch.object(R.Runner, "run_step", exploding):
            self.assertTrue(self.r.step())
            self.assertTrue(self.r.step())
        self.assertEqual(self.status("boom-1")["state"], "failed")
        self.assertEqual(self.status("next-1")["state"], "done")
        self.assertNotIn("target text", json.dumps(self.status("boom-1")))
        self.assertTrue(any("RuntimeError" in t for t in self.traces))      # the traceback went to the container log

    def test_exception_outside_the_job_handlers(self):
        # heartbeat runs inside run_job but outside its try: the loop-level guard must catch it
        now = time.time()
        self.put("boom-2.json", good_job(jid="boom-2"), mtime=now - 100)
        self.put("next-1.json", good_job(jid="next-1"), mtime=now - 50)
        calls, fake = self.fake_steps({})
        real_hb = R.Runner.heartbeat

        def hb(self_, state="idle", refresh=True):
            if self_.current == "boom-2":
                raise ValueError("boom")
            return real_hb(self_, state, refresh)
        with mock.patch.object(R.Runner, "run_step", fake), mock.patch.object(R.Runner, "heartbeat", hb):
            self.r.step()
            self.r.step()
        self.assertEqual(self.status("boom-2")["state"], "failed")
        self.assertEqual(self.status("boom-2")["reason"], "the runner hit an unexpected error during this job")
        self.assertEqual(self.status("next-1")["state"], "done")

    def test_an_abandoned_job_id_is_never_run(self):
        self.put("lost-1.json", good_job(jid="lost-1"))
        wr(os.path.join(self.jobs, "lost-1.abandoned"), '{"abandoned_by": "Ada"}\n')
        self.put("next-1.json", good_job(jid="next-1"))
        ran = []
        with mock.patch.object(R.Runner, "run_job", lambda self_, key, job: (ran.append(key), self_.set_status(key, state="done"))):
            while self.r.step():
                pass
        self.assertEqual(ran, ["next-1"])
        self.assertFalse(os.path.exists(os.path.join(self.pub, "status", "lost-1.json")))   # ignored: no status written
        self.assertEqual([k for k, *_ in self.r.pending()], [])

    def test_heartbeat_stays_fresh_during_a_long_job(self):
        self.put("full-1.json", good_job())
        beats = []
        real_hb = R.Runner.heartbeat

        def hb(self_, state="idle", refresh=True):
            beats.append((state, refresh, self_.current))
            return real_hb(self_, state, refresh)
        clock = [1000.0]

        def slow_recon(self_, key, job, phase, argv, logname, extra_env=None, cwd=None):
            self_.set_status(key, phase=phase)
            if phase == "recon":
                for n, name in ((1, "enumerate"), (2, "resolve")):
                    self_.set_status(key, phase=f"recon:{n}-{name}")      # a phase change beats at once
                for _ in range(7):                                        # 7 waits of 10 s inside one phase
                    clock[0] += 10
                    self_.beat()
            return 0
        tool_calls = []
        real_tv = R.tool_versions
        with mock.patch.object(R.Runner, "run_step", slow_recon), mock.patch.object(R.Runner, "heartbeat", hb), \
                mock.patch.object(R.time, "monotonic", lambda: clock[0]), \
                mock.patch.object(R, "tool_versions", lambda: (tool_calls.append(1), real_tv())[1]):
            self.r.step()
        busy = [b for b in beats if b[0] == "busy"]
        self.assertGreaterEqual(len([b for b in busy if b[1] is False and b[2] == "full-1"]), 2 + 2)   # 2 phase changes + 70 s / 30 s
        self.assertEqual(beats[-1][0], "idle")
        self.assertEqual(len(tool_calls), 2)        # full beats only at the job's start and end; the busy beats are cheap
        sj = rj(os.path.join(self.pub, "scanner.json"))
        self.assertEqual(sj["state"], "idle")
        self.assertIn("tools", sj)

    def test_nesting_is_counted_before_parsing(self):
        deep = lambda n: b"[" * n + b"]" * n
        for raw in (deep(R.MAX_JOB_DEPTH + 1), deep(100000), b'{"a":' * 40 + b"1" + b"}" * 40):
            with self.assertRaises(R.Invalid) as cm:
                R.parse_job_bytes(raw)
            self.assertEqual(str(cm.exception), "file: not valid UTF-8 JSON (nested too deeply)")
        with mock.patch.object(R.json, "loads", side_effect=AssertionError("the parser must not be reached")):
            with self.assertRaises(R.Invalid):
                R.parse_job_bytes(deep(100000))
        self.assertEqual(R.parse_job_bytes(deep(R.MAX_JOB_DEPTH)), json.loads(deep(R.MAX_JOB_DEPTH)))
        brackets_in_a_string = json.dumps({"note": "[" * 500 + '\\"' + "{" * 500}).encode()
        self.assertEqual(R.parse_job_bytes(brackets_in_a_string)["note"][:1], "[")

    def test_validator_bug_is_a_rejection(self):
        real = R.validate_job

        def buggy(doc, fid, lab=None):
            if fid == "vbug-1":
                raise RecursionError()
            return real(doc, fid, lab)
        with mock.patch.object(R, "validate_job", buggy):
            self.then_valid("vbug-1.json", json.dumps(good_job(jid="vbug-1")).encode(), "could not be validated")


class HeldBackPublished(Base):
    def test_published_file_carries_names_and_fixed_codes_only(self):
        self.put("full-1.json", good_job())
        calls, fake = self.fake_steps({})

        def recon_writes_held(self_, key, job, phase, argv, logname, extra_env=None, cwd=None):
            if phase == "recon":
                run = os.path.join(self.root, "runs", job["id"])
                os.makedirs(run, exist_ok=True)
                R.write_json(os.path.join(run, S.HELD_BACK_FILE), {"inventory_run": "inv-1", "hosts": {
                    "new.example.test": S.HELD_NEW, "Bad Name;rm": S.HELD_NEW, "odd.example.test": "<script>x</script>"}})
            return fake(self_, key, job, phase, argv, logname, extra_env, cwd)
        with mock.patch.object(R.Runner, "run_step", recon_writes_held):
            self.r.step()
        hb = rj(os.path.join(self.pub, "held_back.json"))
        self.assertEqual(hb["schema"], "momus-held-back-v1")
        self.assertEqual((hb["run_id"], hb["inventory_run"]), ("full-1", "inv-1"))
        self.assertEqual(hb["hosts"], [{"host": "new.example.test", "reason": S.HELD_NEW, "approved_ips": [], "current_ips": []}])   # bad name, unknown code dropped
        self.assertEqual(hb["domains"], [])
        self.assertNotIn("script", json.dumps(hb))
        st = self.status("full-1")
        self.assertEqual(st["state"], "done")
        self.assertEqual(st["counts"]["held_back"], 1)              # survives the snapshot counts written later
        self.assertEqual(st["counts"]["findings_open"], 1)

    def three_domain_job(self, jid="full-1"):
        j = good_job(jid=jid)
        j["scope"]["domains"] = ["example.test", "other.test", "added.test"]
        j["scope"]["ownership"] = [dict(j["scope"]["ownership"][0], apex=d) for d in j["scope"]["domains"]]
        j["scope"]["approval"] = {"approved_at": "2030-01-01T00:00:00Z", "inventory_run": "inv-1", "approved_by": "Ada"}
        return j

    def test_added_domain_does_not_block_the_job_and_is_published_as_held_back(self):
        Scope.inventory_run(self, "inv-1", domains=("example.test", "other.test"))
        self.put("full-1.json", self.three_domain_job())
        calls, fake = self.fake_steps({})

        def recon(self_, key, job, phase, argv, logname, extra_env=None, cwd=None):
            if phase == "recon":
                run = os.path.join(self.root, "runs", job["id"])
                os.makedirs(run, exist_ok=True)
                R.write_json(os.path.join(run, S.HELD_BACK_FILE), {
                    "inventory_run": "inv-1",
                    "hosts": {"shop.added.test": S.HELD_DOMAIN, "www.example.test": S.HELD_ADDRESS},
                    "addresses": {"shop.added.test": {"approved": [], "now": ["8.8.4.4", "not-an-ip", "<b>"]},
                                  "www.example.test": {"approved": ["8.8.8.8"], "now": ["2001:db8::1", 5]}},
                    "domains": {"scanned": ["example.test"], "held_back": ["added.test", "Bad Name;x"], "pending": ["other.test"]}})
            return fake(self_, key, job, phase, argv, logname, extra_env, cwd)
        with mock.patch.object(R.Runner, "run_step", recon):
            self.r.step()
        st = self.status("full-1")
        self.assertEqual(st["state"], "done")
        self.assertEqual({k: st["counts"][k] for k in ("held_back", "domains_scanned", "domains_held_back", "domains_pending")},
                         {"held_back": 2, "domains_scanned": 1, "domains_held_back": 1, "domains_pending": 1})
        self.assertNotIn("added", json.dumps(st))                            # the status carries numbers only
        hb = rj(os.path.join(self.pub, "held_back.json"))
        self.assertEqual(hb["domains"], [{"domain": "added.test", "reason": S.HELD_DOMAIN}])
        self.assertEqual(hb["hosts"], [
            {"host": "shop.added.test", "reason": S.HELD_DOMAIN, "approved_ips": [], "current_ips": ["8.8.4.4"]},
            {"host": "www.example.test", "reason": S.HELD_ADDRESS, "approved_ips": ["8.8.8.8"], "current_ips": ["2001:db8::1"]}])
        self.assertNotIn("<b>", json.dumps(hb))

    def test_inventory_covering_none_of_the_scope_is_rejected(self):
        Scope.inventory_run(self, "inv-1", domains=("unrelated.test",))
        self.put("full-1.json", self.three_domain_job())
        with mock.patch.object(R.Runner, "job_full") as jf:
            self.r.step()
            jf.assert_not_called()
        st = self.status("full-1")
        self.assertEqual((st["state"], st["reason"]), ("rejected", "scope.approval.inventory_run: that inventory covers none of "
                                                                    "this scope's domains; approve an inventory of this scope"))

    def test_run_without_active_phases_counts_only_pending_domains(self):
        self.put("full-1.json", good_job())          # no approval: inventory-only
        calls, fake = self.fake_steps({})

        def recon(self_, key, job, phase, argv, logname, extra_env=None, cwd=None):
            if phase == "recon":
                run = os.path.join(self.root, "runs", job["id"])
                os.makedirs(run, exist_ok=True)
                wr(os.path.join(run, "apexes.txt"), "")       # example.test did not pass the DNS proof this run
            return fake(self_, key, job, phase, argv, logname, extra_env, cwd)
        with mock.patch.object(R.Runner, "run_step", recon):
            self.r.step()
        st = self.status("full-1")
        self.assertEqual({k: st["counts"][k] for k in ("domains_scanned", "domains_held_back", "domains_pending")},
                         {"domains_scanned": 0, "domains_held_back": 0, "domains_pending": 1})
        self.assertEqual(rj(os.path.join(self.pub, "held_back.json"))["domains"], [])

    def test_inventory_only_run_publishes_an_empty_list(self):
        self.put("full-1.json", good_job())
        calls, fake = self.fake_steps({})
        with mock.patch.object(R.Runner, "run_step", fake):
            self.r.step()
        hb = rj(os.path.join(self.pub, "held_back.json"))
        self.assertEqual((hb["hosts"], hb["inventory_run"]), ([], None))

    def test_approval_survives_retention_of_the_inventory_run(self):
        run = os.path.join(self.root, "runs", "inv-1")
        os.makedirs(run)
        R.write_json(os.path.join(run, "manifest.json"), {"rc": 0, "inventory": {"domains": ["example.test"], "lab_targets": [],
                                                                                  "hosts": {"www.example.test": {"ips": ["8.8.8.8"], "class": "owned"}}}})
        appr = {"approved_at": "2030-01-01T00:00:00Z", "inventory_run": "inv-1", "approved_by": "Ada"}
        j = good_job(); j["scope"]["approval"] = appr
        self.r.write_scope(R.validate_job(j, "full-1"))
        self.r.write_scope(R.validate_job(good_job(jid="inv-2", jtype="inventory"), "inv-2"))   # a job without approval between
        shutil.rmtree(run)                                       # retention removes the inventory's raw run folder
        j2 = good_job(jid="full-2"); j2["scope"]["approval"] = appr
        self.r.write_scope(R.validate_job(j2, "full-2"))         # still accepted, from the kept copy
        a = rj(os.path.join(self.root, "scope", "approval.json"))
        self.assertEqual(a["inventory"]["hosts"], {"www.example.test": {"ips": ["8.8.8.8"], "class": "owned"}})
        self.assertEqual(os.stat(os.path.join(self.root, "state", "approved_inventory.json")).st_mode & 0o777, 0o600)
        j3 = good_job(jid="full-3"); j3["scope"]["domains"] = ["new.test"]          # the kept copy is still re-bound
        j3["scope"]["ownership"] = []
        j3["scope"]["approval"] = appr
        with self.assertRaises(R.Invalid):
            self.r.write_scope(R.validate_job(j3, "full-3"))
        j4 = good_job(jid="full-4"); j4["scope"]["approval"] = dict(appr, inventory_run="inv-9")   # another id: not reused
        with self.assertRaises(R.Invalid):
            self.r.write_scope(R.validate_job(j4, "full-4"))


class JobFiles(Base):
    def test_symlink_fifo_and_dot_files(self):
        now = time.time()
        target = os.path.join(self.tmp, "elsewhere.json")
        wr(target, json.dumps(good_job(jid="link-1")))
        os.symlink(target, os.path.join(self.jobs, "link-1.json"))
        os.mkfifo(os.path.join(self.jobs, "fifo-1.json"))
        self.put(".hidden-1.json", good_job(jid="hidden-1"))
        self.put(".next-1.json.tmp-123", '{"schema": "momus-job-v1", "id": "next-1", "ty')    # partly written
        self.put("next-2.json", good_job(jid="next-2"), mtime=now + 10)
        opened = []
        real_open = os.open

        def tracking_open(path, flags, *a):
            opened.append(os.path.basename(path))
            return real_open(path, flags, *a)
        ran = []
        t0 = time.time()
        with mock.patch.object(R.os, "open", tracking_open), \
                mock.patch.object(R.Runner, "run_job", lambda self_, key, job: (ran.append(key), self_.set_status(key, state="done"))):
            while self.r.step():
                pass
        self.assertLess(time.time() - t0, 10)                       # nothing blocked on the FIFO
        self.assertEqual(ran, ["next-2"])
        self.assertEqual(self.status("link-1")["state"], "rejected")
        self.assertIn("symbolic link", self.status("link-1")["reason"])
        self.assertEqual(self.status("fifo-1")["state"], "rejected")
        self.assertIn("not a regular file", self.status("fifo-1")["reason"])
        self.assertFalse(os.path.exists(os.path.join(self.pub, "status", "hidden-1.json")))
        self.assertFalse(any(n.startswith(".") for n in opened if n.endswith((".json",)) or ".tmp-" in n), opened)

    def test_read_job_file_refuses_without_following(self):
        target = os.path.join(self.tmp, "t.json"); wr(target, "{}")
        link = os.path.join(self.jobs, "l-1.json"); os.symlink(target, link)
        with self.assertRaises(R.Invalid) as cm:
            R.read_job_file(link)
        self.assertIn("symbolic link", str(cm.exception))
        fifo = os.path.join(self.jobs, "f-1.json"); os.mkfifo(fifo)
        with self.assertRaises(R.Invalid):
            R.read_job_file(fifo)                                    # opens without blocking, then refused by fstat
        self.assertEqual(R.read_job_file(target), b"{}")

    def test_jobctl_writes_through_a_dot_file(self):
        names = []
        real_replace = os.replace

        def rec(src, dst):
            names.append((os.path.basename(src), os.path.basename(dst)))
            return real_replace(src, dst)
        with mock.patch.object(J.os, "replace", rec), contextlib.redirect_stdout(io.StringIO()):
            J.main(["--jobs", self.jobs, "--published", self.pub, "--state", os.path.join(self.tmp, "st"), "attest", "example.test", "--by", "Ada"])
            J.main(["--jobs", self.jobs, "--published", self.pub, "--state", os.path.join(self.tmp, "st"), "submit", "inventory", "--id", "inv-7"])
        self.assertIn((".inv-7.json.tmp-" + str(os.getpid()), "inv-7.json"), names)


class Published(Base):
    def test_unwritable_published_folder_is_one_line(self):
        ro = os.path.join(self.tmp, "ro-pub"); os.makedirs(ro); os.chmod(ro, 0o500)
        try:
            env = {"SCAN_ROOT": os.path.join(self.tmp, "r2"), "SCAN_JOBS": self.jobs, "SCAN_PUBLISHED": ro, "PATH": os.environ.get("PATH", "")}
            import subprocess
            p = subprocess.run([sys.executable, "-I", "-B", os.path.join(os.path.dirname(HERE), "runner.py")], env=env,
                               capture_output=True, text=True, timeout=60)
        finally:
            os.chmod(ro, 0o700)
        self.assertEqual(p.returncode, 75, p.stderr)
        self.assertEqual(len(p.stderr.strip().splitlines()), 1, p.stderr)
        self.assertIn("runner: FATAL: cannot write to the published folder", p.stderr)
        self.assertNotIn("Traceback", p.stderr)

    def test_published_folder_lost_while_running(self):
        self.put("full-1.json", good_job())
        calls, fake = self.fake_steps({})

        def failing_write(path, doc):
            raise PermissionError(13, "Permission denied", path)
        with mock.patch.object(R.Runner, "run_step", fake), mock.patch.object(R, "write_json", failing_write):
            with self.assertRaises(R.PublishError):
                self.r.step()


def make_db(path, run_id):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    db = sqlite3.connect(path)
    db.executescript("CREATE TABLE IF NOT EXISTS findings(finding_key TEXT, status TEXT);"
                     "CREATE TABLE IF NOT EXISTS finding_observations(run_id TEXT, finding_key TEXT, band TEXT);"
                     "CREATE TABLE IF NOT EXISTS asset_observations(run_id TEXT, hostname TEXT);")
    db.execute("INSERT INTO findings VALUES('k1','open')")
    db.execute("INSERT INTO finding_observations VALUES(?, 'k1', 'High')", (run_id,))
    db.execute("INSERT INTO asset_observations VALUES(?, 'www.example.test')", (run_id,))
    db.commit()
    db.close()


class Publishing(Base):
    def test_snapshot_latest_and_prune(self):
        src = os.path.join(self.root, "data", "scan.sqlite")
        for i, rid in enumerate(("run-1", "run-2", "run-3", "run-4")):
            make_db(src, rid)
            path, digest = self.r.publish_snapshot(rid, rid)
            os.utime(path, (1000 + i, 1000 + i))
            latest = rj(os.path.join(self.pub, "snapshots", "latest.json"))
            self.assertEqual((latest["file"], latest["sha256"]), (f"{rid}.sqlite", R.sha256_file(path)))
            db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
            self.assertEqual(db.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            db.close()
        self.r.prune_snapshots()
        self.assertEqual(sorted(f for f in os.listdir(os.path.join(self.pub, "snapshots")) if f.endswith(".sqlite")),
                         ["run-3.sqlite", "run-4.sqlite"])
        # the snapshot latest.json names is never pruned, even when it is not among the newest
        R.write_json(os.path.join(self.pub, "snapshots", "latest.json"), {"file": "run-3.sqlite"})
        os.utime(os.path.join(self.pub, "snapshots", "run-3.sqlite"), (1, 1))
        for rid, t in (("run-5", 2000), ("run-6", 2001)):
            p = os.path.join(self.pub, "snapshots", f"{rid}.sqlite")
            shutil.copyfile(os.path.join(self.pub, "snapshots", "run-4.sqlite"), p)
            os.utime(p, (t, t))
        self.r.prune_snapshots()
        left = sorted(f for f in os.listdir(os.path.join(self.pub, "snapshots")) if f.endswith(".sqlite"))
        self.assertIn("run-3.sqlite", left)
        self.assertEqual(left, ["run-3.sqlite", "run-6.sqlite"])

    def test_report_published_by_rename(self):
        rep = os.path.join(self.root, "reports")
        os.makedirs(rep)
        for f in ("run-1.html", "run-1-fixlist.csv", "run-1-ports.csv", "run-2.html", "latest.html"):
            wr(os.path.join(rep, f), f)
        self.assertEqual(self.r.publish_report("run-1"), 3)
        self.assertEqual(sorted(os.listdir(os.path.join(self.pub, "reports", "run-1"))), ["run-1-fixlist.csv", "run-1-ports.csv", "run-1.html"])
        self.assertEqual(self.r.publish_report("run-1"), 3)   # republishing replaces the folder
        self.assertEqual([f for f in os.listdir(os.path.join(self.pub, "reports")) if f.startswith(".")], [])

    def test_full_job_publishes_everything(self):
        self.put("full-1.json", good_job())
        calls, fake = self.fake_steps({})
        with mock.patch.object(R.Runner, "run_step", fake), mock.patch.dict(os.environ, {"HTTP_PROXY": "http://proxy.invalid:3128", "https_proxy": "x"}):
            self.assertTrue(self.r.step())
        st = self.status("full-1")
        self.assertEqual((st["state"], st["type"], st["run_id"]), ("done", "full", "full-1"))
        self.assertEqual(st["exit_codes"], {"recon": 0, "ingest": 0, "report": 0})
        self.assertEqual(st["counts"]["findings_open"], 1)
        self.assertEqual(st["counts"]["band_high"], 1)
        self.assertTrue(os.path.exists(os.path.join(self.pub, "snapshots", "full-1.sqlite")))
        self.assertTrue(os.path.exists(os.path.join(self.pub, "reports", "full-1", "full-1.html")))
        self.assertTrue(os.path.exists(os.path.join(self.pub, "scanner.json")))
        self.assertEqual([c[0] for c in calls], ["recon", "ingest", "report"])
        recon_argv = calls[0][1]
        self.assertEqual(recon_argv[2:4], ["--run-id", "full-1"])
        self.assertNotIn("--inventory-only", recon_argv)
        self.assertNotIn("--no-feeds", calls[1][1])
        for _, _, env in calls:   # clean environment: no proxy variables, nothing inherited
            self.assertFalse({k for k in env if "proxy" in k.lower()})
            self.assertEqual(env["SCAN_EVIDENCE"], "minimal")
            self.assertNotIn("SCAN_LAB", env)
        allowed = {"schema", "job_id", "type", "state", "phase", "run_id", "queued_at", "started_at", "ended_at", "updated_at",
                   "exit_codes", "counts", "snapshot", "snapshot_sha256", "report_files", "lab", "reason"}
        self.assertLessEqual(set(st), allowed)

    def test_inventory_and_lab_arguments(self):
        r = R.Runner(self.root, self.jobs, self.pub, lab_env=LAB, keep_snapshots=2, app=self.tmp, log=self.logs.append, trace=self.traces.append)
        j = good_job(jid="inv-1", jtype="inventory", lab={"targets": ["target.demo.test"], "cidr": "10.89.47.0/24"})
        self.put("inv-1.json", j)
        calls, fake = self.fake_steps({})
        with mock.patch.object(R.Runner, "run_step", fake):
            r.step()
        recon, ingest = calls[0][1], calls[1][1]
        self.assertIn("--inventory-only", recon)
        self.assertEqual(recon[recon.index("--lab-cidr") + 1], "10.89.47.0/24")
        tf = recon[recon.index("--targets-file") + 1]
        self.assertEqual(rd(tf), "target.demo.test\n")
        self.assertIn("--no-feeds", ingest)
        self.assertEqual(calls[0][2].get("SCAN_LAB"), "1")

    def test_failed_recon_publishes_nothing(self):
        self.put("full-1.json", good_job())
        calls, fake = self.fake_steps({"recon": 1})
        with mock.patch.object(R.Runner, "run_step", fake):
            self.r.step()
        st = self.status("full-1")
        self.assertEqual((st["state"], st["exit_codes"]), ("failed", {"recon": 1}))
        self.assertEqual([c[0] for c in calls], ["recon"])
        self.assertFalse(os.path.exists(os.path.join(self.pub, "snapshots", "full-1.sqlite")))

    def test_runner_error_is_type_only(self):
        self.put("full-1.json", good_job())
        with mock.patch.object(R.Runner, "job_full", side_effect=RuntimeError("secret target text")):
            self.r.step()
        st = self.status("full-1")
        self.assertEqual(st["state"], "failed")
        self.assertNotIn("secret target text", json.dumps(st) + "".join(self.logs))

    def test_retention_and_version_watch_jobs(self):
        calls = []

        def run_step(self_, key, job, phase, argv, logname, extra_env=None, cwd=None):
            calls.append((phase, argv))
            if phase == "version-watch":
                os.makedirs(os.path.join(self.root, "version-watch", "php-example"), exist_ok=True)
                wr(os.path.join(self.root, "version-watch", "php-example", "latest.json"), '{"schema": "version-watch-v1"}')
            return 0
        self.put("ret-1.json", good_job(jid="ret-1", jtype="retention", options={"retention_days": 9}))
        self.put("vw-1.json", good_job(jid="vw-1", jtype="version-watch"))
        with mock.patch.object(R.Runner, "run_step", run_step):
            while self.r.step():
                pass
        argv = dict(calls)
        self.assertIn("--apply", argv["retention"])
        self.assertEqual(argv["retention"][argv["retention"].index("--days") + 1], "9")
        self.assertTrue(argv["version-watch"][3].endswith("version_watch.py"))
        self.assertEqual((self.status("ret-1")["state"], self.status("vw-1")["state"]), ("done", "done"))
        self.assertEqual(rj(os.path.join(self.pub, "version-watch", "php-example", "latest.json")), {"schema": "version-watch-v1"})

    def test_update_templates_switches_only_on_a_real_set(self):
        def run_step(n):
            def f(self_, key, job, phase, argv, logname, extra_env=None, cwd=None):
                d = argv[argv.index("-update-template-dir") + 1]
                for i in range(n):
                    wr(os.path.join(d, f"t{i}.yaml"), "id: x\n")
                return 0
            return f
        self.put("ut-1.json", good_job(jid="ut-1", jtype="update-templates"))
        with mock.patch.object(R.Runner, "run_step", run_step(3)):
            self.r.step()
        self.assertEqual(self.status("ut-1")["state"], "failed")
        self.assertIsNone(self.r.templates_dir())
        self.put("ut-2.json", good_job(jid="ut-2", jtype="update-templates"))
        with mock.patch.object(R.Runner, "run_step", run_step(1001)):
            self.r.step()
        self.assertEqual(self.status("ut-2")["state"], "done")
        self.assertEqual(self.r.templates_dir(), os.path.join(self.root, "templates", "current"))
        self.assertEqual(self.r.env(R.validate_job(good_job(), "full-1"))["SCAN_NUCLEI_TEMPLATES"], self.r.templates_dir())

    def test_lab_env_from(self):
        self.assertIsNone(R.lab_env_from({}))
        self.assertEqual(R.lab_env_from({"SCAN_LAB": "1", "SCAN_LAB_CIDR": "10.89.47.0/24"}), LAB)
        for c in ("8.8.8.0/24", "10.0.0.0/16", ""):
            with self.assertRaises(SystemExit):
                R.lab_env_from({"SCAN_LAB": "1", "SCAN_LAB_CIDR": c})


class Jobctl(Base):
    def jc(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            rc = J.main(["--jobs", self.jobs, "--published", self.pub, "--state", os.path.join(self.tmp, "state"), *args])
        return rc, out.getvalue()

    def test_attest_submit_validates(self):
        rc, out = self.jc("attest", "example.test", "--by", "Ada Owner")
        self.assertEqual(rc, 0)
        self.assertIn("submit scope-sync", out)          # jobctl cannot make a token: the scanner shows the record
        self.assertNotIn("token", rd(os.path.join(self.tmp, "state", "brain.json")))
        rc, out = self.jc("submit", "scope-sync", "--id", "sync-1")
        self.assertEqual((rc, out.strip()), (0, "sync-1"))
        calls, fake = self.fake_steps({})
        with mock.patch.object(R.Runner, "run_step", fake):
            self.r.step()
        self.assertEqual(self.status("sync-1")["state"], "done")
        self.assertEqual([c[1][4:5] for c in calls], [["sync"]])     # scope.py sync, nothing else
        rc, out = self.jc("status")
        tok = S.derive_token(self.r.secret, "example.test")
        self.assertIn(f'{S.VERIFY_LABEL}.example.test. TXT "{S.VERIFY_PREFIX}{tok}"', out)
        rc, out = self.jc("submit", "full", "--id", "full-9", "--rate-profile", "normal")
        self.assertEqual((rc, out.strip()), (0, "full-9"))
        doc = rj(os.path.join(self.jobs, "full-9.json"))
        job = R.validate_job(doc, "full-9")         # what jobctl writes, the runner accepts
        self.assertEqual(job["scope"]["domains"], ["example.test"])
        self.assertEqual(job["scope"]["ownership"][0]["attested_by"], "Ada Owner")
        self.assertNotIn("state", doc["scope"]["ownership"][0])

    def test_approve_needs_finished_inventory(self):
        self.jc("attest", "example.test", "--by", "Ada")
        self.assertEqual(self.jc("approve", "inv-1", "--by", "Ada")[0], 2)
        R.write_json(os.path.join(self.pub, "status", "inv-1.json"), {"job_id": "inv-1", "type": "inventory", "state": "done", "run_id": "inv-1"})
        self.assertEqual(self.jc("approve", "inv-1", "--by", "Ada")[0], 0)
        self.jc("submit", "full", "--id", "full-2")
        doc = rj(os.path.join(self.jobs, "full-2.json"))
        self.assertEqual(doc["scope"]["approval"]["inventory_run"], "inv-1")

    def test_wait(self):
        R.write_json(os.path.join(self.pub, "status", "a-1.json"), {"job_id": "a-1", "state": "done"})
        R.write_json(os.path.join(self.pub, "status", "b-1.json"), {"job_id": "b-1", "state": "rejected"})
        self.assertEqual(self.jc("wait", "a-1", "--quiet")[0], 0)
        self.assertEqual(self.jc("wait", "b-1", "--quiet")[0], 1)
        self.assertEqual(self.jc("wait", "c-1", "--quiet", "--timeout", "0")[0], 3)

    def test_help_says_developer_tool(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit):
            J.main(["--help"])
        self.assertIn("DEVELOPER TOOL", out.getvalue())


if __name__ == "__main__":
    unittest.main()


class VersionWatchJobs(Base):
    """The version-watch job: watch validation, this job's DNS proof before any probe, lab runs, and the published copy."""

    def vw_job(self, jid="vw-1", watches=None, **over):
        return good_job(jid=jid, jtype="version-watch", options={"watches": watches if watches is not None else [dict(WATCH)]}, **over)

    def bad(self, job, contains, lab=None):
        with self.assertRaises(R.Invalid) as cm:
            R.validate_job(job, job["id"], lab)
        self.assertIn(contains, str(cm.exception))
        return str(cm.exception)

    def test_watches_are_validated_like_the_rest_of_the_job(self):
        j = R.validate_job(self.vw_job(), "vw-1")
        self.assertEqual(j["options"]["watches"][0]["floors"], {"8.2": 35, "8.3": 36})
        self.bad(good_job(jid="vw-1", jtype="version-watch", options={}), "needs at least one watch")
        self.bad(self.vw_job(watches=[]), "needs at least one watch")
        self.bad(self.vw_job(watches="php"), "options.watches: must be a list")
        self.bad(good_job(jid="vw-1", jtype="version-watch", options={"watches": [WATCH], "pattern": "x"}), "options: unknown field")
        for k, v, msg in (("id", "Bad Id", ".id:"), ("name", "https://evil.test/", ".name:"), ("product", "iis", ".product:"),
                          ("cves", ["CVE-1"], ".cves[0]"), ("floors", {"8.2": "35"}, ".floors"), ("floors", {".*": 1}, ".floors"),
                          ("hosts", ["Bad.Host"], "options.watches[0].hosts[0]: not a valid host name"),
                          ("hosts", ["http://x.example.test/"], "not a valid host name"), ("header", "server", "unknown field")):
            w = dict(WATCH); w[k] = v
            msg_out = self.bad(self.vw_job(watches=[w]), msg)
            self.assertNotIn("evil", msg_out)
        # watches belong to version-watch jobs only
        self.bad(good_job(jid="full-1", options={"watches": [WATCH]}), "options: unknown field")

    def test_a_version_watch_job_can_be_a_lab_run(self):
        lab = {"targets": ["target.demo.test"], "cidr": "10.89.47.0/24"}
        j = self.vw_job(lab=lab); j["scope"]["domains"] = []; j["scope"]["ownership"] = []
        self.assertEqual(R.validate_job(j, "vw-1", LAB)["lab"], lab)
        self.bad(self.vw_job(lab=lab), "not started in lab mode")

    def run_vw(self, job, rcs=None, make=None):
        calls = []

        def run_step(self_, key, job_, phase, argv, logname, extra_env=None, cwd=None):
            calls.append((phase, argv, self_.env(job_, extra_env)))
            if phase == "version-watch" and make:
                make()
            return (rcs or {}).get(phase, 0)
        self.put(f"{job['id']}.json", job)
        with mock.patch.object(R.Runner, "run_step", run_step):
            self.r.step()
        return calls

    def test_the_dns_proof_of_this_job_runs_first_and_its_failure_stops_the_probe(self):
        calls = self.run_vw(self.vw_job())
        self.assertEqual([c[0] for c in calls], ["dns-proof", "version-watch"])
        proof = calls[0][1]
        self.assertEqual(proof[3:5], [os.path.join(R.PIPE, "scope.py"), "recheck-dns"])     # recon's own phase-0 command
        self.assertEqual(proof[proof.index("--run-dir") + 1], os.path.join(self.root, "runs", "vw-1"))
        vw = calls[1][1]
        self.assertEqual(vw[vw.index("--run-dir") + 1], os.path.join(self.root, "runs", "vw-1"))
        self.assertEqual(rj(vw[vw.index("--watches") + 1]), R.validate_job(self.vw_job(), "vw-1")["options"]["watches"])
        self.assertFalse(os.path.exists(os.path.join(self.root, "runs", "vw-1", "lab.json")))
        st = self.status("vw-1")
        self.assertEqual((st["state"], st["exit_codes"]), ("done", {"dns_proof": 0, "version_watch": 0}))
        # the proof step failing to run: no probe at all
        calls = self.run_vw(self.vw_job("vw-2"), rcs={"dns-proof": 2})
        self.assertEqual([c[0] for c in calls], ["dns-proof"])
        self.assertEqual(self.status("vw-2")["state"], "failed")

    def test_a_lab_job_skips_the_proof_and_writes_lab_json(self):
        self.r.lab_env = LAB
        lab = {"targets": ["target.demo.test"], "cidr": "10.89.47.0/24"}
        j = self.vw_job(lab=lab); j["scope"]["domains"] = []; j["scope"]["ownership"] = []
        calls = self.run_vw(j)
        self.assertEqual([c[0] for c in calls], ["version-watch"])
        self.assertEqual(calls[0][2].get("SCAN_LAB"), "1")
        self.assertEqual(rj(os.path.join(self.root, "runs", "vw-1", "lab.json")), {"cidr": "10.89.47.0/24", "hosts": ["target.demo.test"]})

    def test_published_files_follow_the_state_folder_and_are_pruned(self):
        state = os.path.join(self.root, "version-watch")
        pubvw = os.path.join(self.pub, "version-watch")

        def make(files):
            def f():
                shutil.rmtree(state, ignore_errors=True)
                for rel, text in files.items():
                    os.makedirs(os.path.dirname(os.path.join(state, rel)), exist_ok=True)
                    wr(os.path.join(state, rel), text)
            return f
        # day 1: two watches; plus junk the runner must not publish (a bad folder name, a foreign file name, a link)
        files = {"php-example/2030-11-12.json": "{1}", "php-example/latest.json": "{1}", "other/2030-11-12.json": "{2}",
                 "Bad Name/latest.json": "x", "php-example/notes.txt": "x"}
        self.run_vw(self.vw_job(), make=make(files))
        os.symlink("/etc", os.path.join(state, "linked"))
        got = sorted(os.path.relpath(os.path.join(d, f), pubvw) for d, _, fs in os.walk(pubvw) for f in fs)
        self.assertEqual(got, ["other/2030-11-12.json", "php-example/2030-11-12.json", "php-example/latest.json"])
        self.assertEqual(self.status("vw-1")["counts"], {"watches": 1, "files_published": 3})
        # a flat file at the top of the folder (not in a watch folder) and a folder the state does not have are removed
        wr(os.path.join(pubvw, "2030-01-01.json"), "{}")
        # day 2: retention removed the old dated file, and watch "other" is gone from the state folder
        files2 = {"php-example/2030-11-13.json": "{3}", "php-example/latest.json": "{3}"}
        self.run_vw(self.vw_job("vw-2"), make=make(files2))
        got = sorted(os.path.relpath(os.path.join(d, f), pubvw) for d, _, fs in os.walk(pubvw) for f in fs)
        self.assertEqual(got, ["php-example/2030-11-13.json", "php-example/latest.json"])
        self.assertEqual(rd(os.path.join(pubvw, "php-example", "latest.json")), "{3}")
        self.assertTrue(os.path.isdir("/etc"))      # the link in the state folder was never followed or removed through

    def test_recover_removes_temporary_files_in_watch_folders(self):
        d = os.path.join(self.pub, "version-watch", "php-example")
        os.makedirs(d)
        wr(os.path.join(d, ".latest.json.tmp-123"), "x")
        wr(os.path.join(d, "latest.json"), "{}")
        self.r.recover()
        self.assertEqual(os.listdir(d), ["latest.json"])


class NoTrailingNewline(Base):
    """A pattern anchored with "$" and used with match() also matches before a final newline. Every validating pattern
    in the runner and the name rule now uses fullmatch."""

    def test_names_ids_times_and_people_refuse_a_final_newline(self):
        self.assertIsNone(S.norm_name("a\n.test"))
        self.assertIsNone(S.norm_name("www.a\n.example.test"))
        for mutate, where in ((lambda j: j.update(id="full-1\n"), "id:"),
                              (lambda j: j.update(created_at="2030-01-01T00:00:00Z\n"), "created_at"),
                              (lambda j: j["scope"]["ownership"][0].update(attested_by="Ada Owner\n"), "attested_by"),
                              (lambda j: j["scope"]["domains"].append("a\n.test"), "scope.domains[1]"),
                              (lambda j: j["scope"].update(approval={"approved_at": "2030-01-01T00:00:00Z", "inventory_run": "inv-1\n",
                                                                     "approved_by": "Ada"}), "inventory_run")):
            j = good_job()
            mutate(j)
            with self.assertRaises(R.Invalid, msg=where) as cm:
                R.validate_job(j, "full-1")
            self.assertIn(where, str(cm.exception))

    def test_a_job_file_name_with_a_newline_is_not_a_job_id(self):
        self.put("full-1\n.json", good_job())
        [(key, _, fid, _)] = self.r.pending()
        self.assertTrue(key.startswith("invalid-"))
        self.assertIsNone(fid)


class JobctlWatches(Base):
    def test_jobctl_version_watch_job_carries_the_watches_file(self):
        out = io.StringIO()
        wf = os.path.join(self.tmp, "watches.json")
        wr(wf, json.dumps([WATCH]))
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            J.main(["--jobs", self.jobs, "--published", self.pub, "--state", os.path.join(self.tmp, "state"),
                    "attest", "example.test", "--by", "Ada Owner"])
            rc = J.main(["--jobs", self.jobs, "--published", self.pub, "--state", os.path.join(self.tmp, "state"),
                         "submit", "version-watch", "--id", "vw-9", "--watches-file", wf])
        self.assertEqual(rc, 0)
        job = R.validate_job(rj(os.path.join(self.jobs, "vw-9.json")), "vw-9")
        self.assertEqual(job["options"]["watches"][0]["id"], "php-example")


class RetentionRetiresWatches(Base):
    def test_a_retention_job_retires_old_watch_folders_and_their_published_copy(self):
        # the last watch was removed, so no version-watch job runs any more: retention retires its folder after 90 days
        import datetime as dt
        import version_watch as VW
        state = os.path.join(self.root, "version-watch")
        old_day = (dt.date.today() - dt.timedelta(days=VW.KEEP + 1)).isoformat()
        new_day = (dt.date.today() - dt.timedelta(days=1)).isoformat()
        for wid, day in (("gone-watch", old_day), ("recent-watch", new_day)):
            os.makedirs(os.path.join(state, wid))
            wr(os.path.join(state, wid, f"{day}.json"), "{}")
            wr(os.path.join(state, wid, "latest.json"), "{}")
        self.r.publish_version_watch()
        self.assertTrue(os.path.isdir(os.path.join(self.pub, "version-watch", "gone-watch")))
        self.put("ret-1.json", good_job(jid="ret-1", jtype="retention"))
        with mock.patch.object(R.Runner, "run_step", lambda *a, **k: 0):
            self.r.step()
        self.assertEqual(self.status("ret-1")["state"], "done")
        self.assertEqual(sorted(os.listdir(state)), ["recent-watch"])
        self.assertEqual(sorted(os.listdir(os.path.join(self.pub, "version-watch"))), ["recent-watch"])


def _iso_ago(hours):
    import datetime as _dt
    return (_dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")


class FinishedJobs(Base):
    """A finished job never runs twice, an old job is refused, and an abandon marker
    written after the listing still stops the job."""

    def run_all(self):
        ran = []
        with mock.patch.object(R.Runner, "run_job", lambda self_, key, job: (ran.append(key), self_.set_status(key, state="done"))):
            while self.r.step():
                pass
        return ran

    def test_finished_jobs_do_not_run_again_when_their_status_files_are_lost(self):
        now = time.time()
        self.put("full-1.json", good_job(jid="full-1"), mtime=now - 20)
        self.put("full-2.json", good_job(jid="full-2"), mtime=now - 10)
        self.assertEqual(self.run_all(), ["full-1", "full-2"])
        for k in ("full-1", "full-2"):                         # the published volume replaced: status files gone
            os.unlink(os.path.join(self.pub, "status", f"{k}.json"))
        self.assertEqual([k for k, *_ in self.r.pending()], [])
        self.assertEqual(self.run_all(), [])                  # neither runs again
        self.assertEqual(self.status("full-1")["state"], "done")     # the final status is published again
        self.assertEqual(self.status("full-2")["state"], "done")

    def test_the_record_wins_over_a_published_status_that_is_not_final(self):
        self.put("full-1.json", good_job(jid="full-1"))
        self.assertEqual(self.run_all(), ["full-1"])
        R.write_json(os.path.join(self.pub, "status", "full-1.json"), {"job_id": "full-1", "state": "queued"})
        self.assertEqual(self.run_all(), [])
        self.assertEqual(self.status("full-1")["state"], "done")

    def test_the_record_is_kept_in_the_private_state_folder(self):
        self.put("full-1.json", good_job(jid="full-1"))
        self.run_all()
        self.assertTrue(os.path.isfile(os.path.join(self.root, "state", "finished", "full-1.json")))
        self.assertEqual(sorted(os.listdir(self.pub)), sorted(set(os.listdir(self.pub)) - {"finished"}))
        for dirpath, dirs, files in os.walk(self.pub):
            self.assertNotIn("finished", dirs)

    def test_a_rejected_job_is_recorded_too(self):
        self.put("bad-1.json", good_job(jid="bad-1", extra=1))
        self.assertEqual(self.run_all(), [])
        os.unlink(os.path.join(self.pub, "status", "bad-1.json"))
        self.assertEqual([k for k, *_ in self.r.pending()], [])
        self.assertEqual(self.status("bad-1")["state"], "rejected")

    def test_a_job_older_than_the_age_limit_is_refused_before_any_scope_is_written(self):
        self.put("old-1.json", good_job(jid="old-1", created_at=_iso_ago(73)))
        self.assertEqual(self.run_all(), [])
        st = self.status("old-1")
        self.assertEqual(st["state"], "rejected")
        self.assertIn("job age limit", st["reason"])
        self.assertFalse(os.path.exists(self.r.scope_dir()))
        self.put("new-1.json", good_job(jid="new-1", created_at=_iso_ago(71)))
        self.assertEqual(self.run_all(), ["new-1"])

    def test_the_age_limit_is_one_setting(self):
        r = R.Runner(self.root, self.jobs, self.pub, keep_snapshots=2, app=self.tmp, log=self.logs.append,
                     trace=self.traces.append, job_max_age_hours=2)
        self.put("old-1.json", good_job(jid="old-1", created_at=_iso_ago(3)))
        with mock.patch.object(R.Runner, "run_job") as run:
            r.step()
            run.assert_not_called()
        self.assertIn("job age limit", self.status("old-1")["reason"])
        self.assertEqual(R.job_max_age_from({"SCAN_JOB_MAX_AGE_HOURS": "24"}), 24)
        self.assertEqual(R.job_max_age_from({"SCAN_JOB_MAX_AGE_HOURS": "nonsense"}), 72)
        self.assertEqual(R.job_max_age_from({}), 72)

    def test_a_marker_written_after_the_listing_still_stops_the_job(self):
        self.put("full-1.json", good_job(jid="full-1"))
        real_load = R.Runner.load
        ran = []

        def load_then_abandon(self_, key, path, fid, st):
            job = real_load(self_, key, path, fid, st)
            wr(os.path.join(self.jobs, "full-1.abandoned"), '{"abandoned_by": "Ada"}\n')   # the admin, at this moment
            return job
        with mock.patch.object(R.Runner, "load", load_then_abandon), \
                mock.patch.object(R.Runner, "job_full", lambda self_, key, job, codes: ran.append(key) or "done"):
            self.r.step()
        self.assertEqual(ran, [])
        self.assertNotEqual(self.status("full-1")["state"], "running")
        self.assertFalse(os.path.exists(self.r.scope_dir()))


class JobDatesRecordsAndVerifiedDomains(Base):
    """A job with no usable created_at is refused like an old one; the finished-job
    record's two guards have tests; the verified-domain list for the seeder holds verified names only."""

    def run_all(self):
        ran = []
        with mock.patch.object(R.Runner, "run_job", lambda self_, key, job: (ran.append(key), self_.set_status(key, state="done"))):
            while self.r.step():
                pass
        return ran

    def refused(self, jid, reason_part):
        st = self.status(jid)
        self.assertEqual(st["state"], "rejected", st)
        self.assertIn(reason_part, st["reason"])
        self.assertFalse(os.path.exists(self.r.scope_dir()), "refused before any scope is written")

    def test_a_job_without_created_at_is_refused_before_any_scope_is_written(self):
        j = good_job(jid="nodate-1")
        del j["created_at"]
        self.put("nodate-1.json", j)
        self.assertEqual(self.run_all(), [])
        self.refused("nodate-1", "created_at: required")

    def test_a_created_at_that_is_not_a_valid_time_is_refused(self):
        self.put("baddate-1.json", good_job(jid="baddate-1", created_at="2026-13-45T25:61:00Z"))
        self.assertEqual(self.run_all(), [])
        self.refused("baddate-1", "created_at: not an ISO 8601 UTC time")     # the format check

    def test_a_job_dated_more_than_five_minutes_ahead_is_refused_and_four_minutes_is_accepted(self):
        self.put("future-1.json", good_job(jid="future-1", created_at=_iso_ago(-6 / 60)))
        self.assertEqual(self.run_all(), [])
        self.refused("future-1", "dated in the future")
        self.put("soon-1.json", good_job(jid="soon-1", created_at=_iso_ago(-4 / 60)))
        self.assertEqual(self.run_all(), ["soon-1"])

    def test_validate_job_requires_created_at(self):
        j = good_job()
        del j["created_at"]
        with self.assertRaises(R.Invalid) as cm:
            R.validate_job(j, "full-1")
        self.assertIn("created_at: required", str(cm.exception))

    # ---- the finished-job record
    def test_a_corrupt_record_counts_as_finished(self):
        os.makedirs(os.path.join(self.root, "state", "finished"), exist_ok=True)
        wr(os.path.join(self.root, "state", "finished", "full-1.json"), "{not json")
        self.put("full-1.json", good_job(jid="full-1"))
        self.assertEqual(self.run_all(), [])
        st = self.status("full-1")
        self.assertEqual((st["state"], st["reason"]), ("failed", "the scanner's record of this job is unreadable"))

    def test_the_record_is_never_read_through_a_link(self):
        os.makedirs(os.path.join(self.root, "state", "finished"), exist_ok=True)
        elsewhere = os.path.join(self.tmp, "elsewhere.json")
        wr(elsewhere, json.dumps({"job_id": "full-1", "state": "done"}))
        os.symlink(elsewhere, os.path.join(self.root, "state", "finished", "full-1.json"))
        self.assertIsNone(self.r.finished("full-1"))

    def test_run_job_checks_the_record_again(self):
        self.r.set_status("full-1", state="done")            # recorded as finished after the listing
        with mock.patch.object(R.Runner, "write_scope") as ws:
            self.r.run_job("full-1", R.validate_job(good_job(jid="full-1"), "full-1"))
        ws.assert_not_called()
        self.assertEqual(self.status("full-1")["state"], "done")

    # ---- the verified-domain list for the seeder
    def seed_scope_runner(self):
        d = os.path.join(self.tmp, "seed-scope")
        os.makedirs(d)
        r = R.Runner(self.root, self.jobs, self.pub, keep_snapshots=2, app=self.tmp, log=self.logs.append,
                     trace=self.traces.append, seed_scope=d)
        return r, os.path.join(d, R.SEED_SCOPE_FILE)

    def test_the_verified_domain_list_holds_only_verified_names(self):
        r, path = self.seed_scope_runner()
        j = good_job()
        j["scope"]["domains"] = ["example.test", "other.test", "third.test"]
        j["scope"]["ownership"].append({"apex": "third.test", "statement": S.OWNERSHIP_STATEMENT, "attested_by": "Ada Owner",
                                        "attested_at": "2030-01-01T00:00:00Z"})
        r.write_scope(R.validate_job(j, "full-1"))
        self.assertEqual(rj(path)["domains"], [])               # pending and no-statement domains are not listed
        ents = S.load_ownership(os.path.join(self.root, "scope"))
        ents["example.test"].update(state="verified", verified_at="2030-01-02T00:00:00Z", last_checked_at="2030-01-02T00:00:00Z")
        S.save_ownership(os.path.join(self.root, "scope"), ents)
        r.publish_scope_status()
        doc = rj(path)
        self.assertEqual(sorted(doc), ["domains", "schema", "updated_at"])
        self.assertEqual(doc["schema"], "momus-verified-domains-v1")
        self.assertEqual(doc["domains"], ["example.test"])
        text = rd(path)
        for absent in ("txt_", S.VERIFY_PREFIX, "other.test", "third.test", "pending", "Ada Owner", S.key_id(r.secret)):
            self.assertNotIn(absent, text)
        self.assertEqual(oct(os.stat(path).st_mode & 0o777), "0o644")

    def test_no_seed_scope_folder_means_no_file_and_no_error(self):
        self.r.write_scope(R.validate_job(good_job(), "full-1"))
        self.assertFalse(any("seed" in l for l in self.logs), self.logs)
