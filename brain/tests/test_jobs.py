"""Job building and the queue, checked against the scanner's own validation (scanner/runner.py)."""
import datetime as dt
import importlib.util
import ipaddress
import json
import os

import pytest

from helpers import said

import fixtures
from app import db as dbm, jobs
from conftest import make_settings, Browser, bootstrap_token, ORIGIN, PASSWORD
from app.web import create_app

_spec = importlib.util.spec_from_file_location("momus_runner", os.path.join(fixtures.REPO, "scanner", "runner.py"))
runner = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(runner)
LAB = ipaddress.ip_network("10.89.47.0/24")


def job_files(settings):
    return sorted(f for f in os.listdir(settings.jobs_dir) if not f.startswith("."))


def scanner_accepts(settings, name, lab_env=None):
    """Read and validate the file exactly as the scanner's runner does."""
    raw = runner.read_job_file(os.path.join(settings.jobs_dir, name))
    doc = runner.parse_job_bytes(raw)
    return runner.validate_job(doc, name[:-5], lab_env)


def finish(settings, job_id, state="done", jtype=None, lab=False):
    d = os.path.join(settings.published_dir, "status")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, f"{job_id}.json"), "w") as fh:
        json.dump({"schema": "momus-status-v1", "job_id": job_id, "state": state, "type": jtype, "lab": lab,
                   "run_id": job_id if jtype in ("inventory", "full", "recheck") else None, "ended_at": "2030-01-01T00:00:00Z",
                   "queued_at": "2030-01-01T00:00:00Z", "counts": {"assets": 2}}, fh)


def finish_all(settings):
    for f in job_files(settings):
        doc = json.load(open(os.path.join(settings.jobs_dir, f)))
        finish(settings, doc["id"], "done", doc["type"], "lab" in doc)


def add_domain(b, name="example.test", kind="domain"):
    r = b.post("/scope/domains", data={"name": name, "statement": "yes", "kind": kind})
    assert r.status_code == 303 and "err=" not in r.headers["location"], r.headers["location"]


WATCH_FORM = {"watch_id": "php-cgi", "name": "PHP CGI argument injection", "product": "php",
              "cves": "CVE-2099-0003, CVE-2099-0004", "floors": "8.1.29\n8.2.20\n8.3.8", "hosts": "WWW.Example.test.\nshop.example.test"}


def add_watch(b, **kw):
    r = b.post("/version-watch/watches", data={**WATCH_FORM, **kw})
    assert r.status_code == 303 and "err=" not in r.headers["location"], (r.status_code, r.text[:300])


def queue(b, jtype):
    r = b.post("/jobs", data={"type": jtype})
    assert r.status_code == 303
    return r.headers["location"]


def test_every_job_type_validates_with_the_scanner(admin, settings):
    # the brain removes a job file once its status is final, so each file is validated (and kept here) when
    # it is written, before the next job is queued; the checks below run on every file
    checked = {}

    def check_new():
        for f in job_files(settings):
            if f not in checked:
                checked[f] = (scanner_accepts(settings, f), open(os.path.join(settings.jobs_dir, f)).read())
    add_domain(admin)
    check_new()
    finish_all(settings)                                          # the scope-sync queued by the domain add
    first_sync = sorted(checked)[0]
    admin.post("/scope/entries", data={"kind": "exclusion", "value": "*.old.example.test"})
    admin.post("/scope/entries", data={"kind": "range", "value": "1.1.1.0/24"})
    admin.post("/scope/entries", data={"kind": "host", "value": "www.example.test"})
    admin.post("/scope/profile", data={"check_profile": "active", "rate_profile": "normal", "evidence": "excerpt"})
    queue(admin, "inventory")
    inv = None
    for f in job_files(settings):
        doc = json.load(open(os.path.join(settings.jobs_dir, f)))
        if doc["type"] == "inventory":
            inv = doc["id"]
    check_new()
    finish_all(settings)
    r = admin.post("/scope/approve", data={"inventory_run": inv})
    assert "err=" not in r.headers["location"]
    add_watch(admin)                     # a version-watch job carries the watches, and is refused without one
    seen = set()
    for jtype in ("full", "recheck", "version-watch", "retention", "update-templates", "scope-sync"):
        loc = queue(admin, jtype)
        assert "err=" not in loc, (jtype, loc)
        check_new()
        finish_all(settings)
    for f, (out, raw) in sorted(checked.items()):
        seen.add(out["type"])
        sc = out["scope"]
        if f == first_sync:                                       # written before the lists and profiles were set
            continue
        assert sc["domains"] == ["example.test"] and sc["ownership"][0]["statement"] == "I own this domain and the systems it points to."
        assert sc["exclude"] == ["*.old.example.test"] and sc["owned_ranges"] == ["1.1.1.0/24"]
        assert sc["check_profile"] == "active" and sc["rate_profile"] == "normal" and sc["evidence"] == "excerpt"
        assert "token" not in raw                                  # the scanner derives every DNS token
        if out["type"] in ("full", "recheck"):
            assert sc["approval"]["inventory_run"] == inv and sc["approval"]["approved_by"] == "admin"
        if out["type"] == "version-watch":
            assert out["options"]["watches"] == [{"id": "php-cgi", "name": "PHP CGI argument injection", "product": "php",
                                                  "cves": ["CVE-2099-0003", "CVE-2099-0004"], "floors": {"8.1": 29, "8.2": 20, "8.3": 8},
                                                  "hosts": ["shop.example.test", "www.example.test"]}]
    assert seen == set(jobs.TYPES)
    assert not [f for f in os.listdir(settings.jobs_dir) if f.startswith(".")]   # no temporary file left


def test_lab_jobs_validate_with_the_scanner_in_lab_mode(tmp_path):
    s = make_settings(tmp_path, lab=True, lab_cidr="10.89.47.0/24")
    app = create_app(s, start_background=False)
    b = Browser(app)
    tok = bootstrap_token(s)
    pre = b.pre_token("/bootstrap")
    b.c.post("/bootstrap", data={"token": tok, "username": "admin", "password": PASSWORD, "password2": PASSWORD, "owner_rule": "yes",
                                 "csrf": pre}, headers={"Origin": ORIGIN})
    b.refresh_csrf()
    add_domain(b, "target.demo.test", "lab")
    add_domain(b, "notice.demo.test", "lab")
    assert job_files(s) == []                                     # lab targets need no scope-sync
    queue(b, "inventory")
    (f,) = job_files(s)
    out = scanner_accepts(s, f, LAB)
    assert out["lab"] == {"targets": ["notice.demo.test", "target.demo.test"], "cidr": "10.89.47.0/24"} and out["scope"]["domains"] == []
    with pytest.raises(runner.Invalid):                           # and a scanner not in lab mode refuses it
        scanner_accepts(s, f, None)
    finish(s, f[:-5], "done", "inventory", lab=True)
    assert "err=" not in b.post("/scope/approve", data={"inventory_run": f[:-5]}).headers["location"]
    queue(b, "full")
    full = [x for x in job_files(s) if x.startswith("full-")][0]
    out = scanner_accepts(s, full, LAB)
    assert out["scope"]["approval"]["inventory_run"] == f[:-5] and out["lab"]["targets"] == ["notice.demo.test", "target.demo.test"]


def test_lab_targets_refused_outside_lab_mode(admin):
    r = admin.post("/scope/domains", data={"name": "target.demo.test", "statement": "yes", "kind": "lab"})
    assert "err=" in r.headers["location"]


def test_domain_without_ownership_statement_cannot_be_queued(admin, settings):
    r = admin.post("/scope/domains", data={"name": "example.test", "kind": "domain"})       # box not ticked
    assert "err=" in r.headers["location"]
    conn = dbm.connect(settings.db_path)
    conn.execute("INSERT INTO domains(name, kind, statement, attested_by, attested_at, created_by, created_at) VALUES(?,?,?,?,?,?,?)",
                 ("nostatement.test", "domain", "", "admin", dbm.iso(), "admin", dbm.iso()))
    conn.close()
    for jtype in ("inventory", "full", "scope-sync"):
        loc = queue(admin, jtype)
        assert "err=" in loc and "no ownership statement" in said(loc), loc
    assert job_files(settings) == []


def test_one_job_at_a_time(admin, settings):
    add_domain(admin)                                             # queues a scope-sync (no status yet: in flight)
    (sync,) = job_files(settings)
    loc = queue(admin, "inventory")
    assert "err=" in loc and "in flight" in said(loc)
    page = admin.get("/runs").text
    assert "A job is already queued or running" in page and sync[:-5] in page
    finish(settings, sync[:-5], "running", "scope-sync")
    assert "err=" in queue(admin, "inventory")
    finish(settings, sync[:-5], "done", "scope-sync")
    assert "err=" not in queue(admin, "inventory")
    # the finished scope-sync's file is removed when the next job is queued
    files = job_files(settings)
    assert len(files) == 1 and files[0].startswith("inv-") and sync not in files


def test_scanner_busy_heartbeat_blocks_queueing(admin, settings, published):
    add_domain(admin)
    finish_all(settings)
    with open(os.path.join(settings.published_dir, "scanner.json"), "w") as fh:
        # a heartbeat dated in the future is stale, so this busy heartbeat is dated now
        json.dump({"state": "busy", "current_job": "jobctl-x", "updated_at": dbm.iso()}, fh)
    assert "in flight" in said(queue(admin, "inventory"))


def test_domain_change_queues_scope_sync_when_idle_and_later_when_busy(admin, settings):
    add_domain(admin, "a.example.test")
    (first,) = job_files(settings)
    doc = json.load(open(os.path.join(settings.jobs_dir, first)))
    assert doc["type"] == "scope-sync" and doc["scope"]["domains"] == ["a.example.test"]
    add_domain(admin, "b.example.test")                           # busy: the sync stays pending
    assert len(job_files(settings)) == 1
    assert "A scope sync is waiting" in admin.get("/scope").text
    finish(settings, first[:-5], "done", "scope-sync")
    jobs.tick(settings, dt.datetime.now(dt.timezone.utc))
    files = job_files(settings)
    assert len(files) == 1 and first not in files      # the finished first sync's file is removed
    second = json.load(open(os.path.join(settings.jobs_dir, [f for f in files if f != first][0])))
    assert second["type"] == "scope-sync" and second["scope"]["domains"] == ["a.example.test", "b.example.test"]


def test_check_now_queues_scope_sync(admin, settings):
    add_domain(admin)
    (first,) = job_files(settings)
    finish_all(settings)
    r = admin.post("/scope/check-now")
    assert "err=" not in r.headers["location"]
    # the first, finished sync's file is removed when the next is queued
    syncs = [f for f in job_files(settings) if f.startswith("sync-")]
    assert len(syncs) == 1 and first not in syncs


def test_scope_page_shows_record_from_scanner_only(admin, settings):
    add_domain(admin)
    assert "waiting for the scanner" in admin.get("/scope").text
    os.makedirs(settings.published_dir, exist_ok=True)
    with open(os.path.join(settings.published_dir, "scope_status.json"), "w") as fh:
        json.dump({"schema": "momus-scope-status-v1", "updated_at": "2030-01-01T00:00:00Z", "notice": None, "domains": {
            "example.test": {"state": "pending", "txt_name": "_scan-verify.example.test", "txt_value": "scan-verify=" + "0f" * 16,
                             "last_checked_at": "2030-01-01T00:00:00Z", "last_result": "mismatch"}}}, fh)
    page = admin.get("/scope").text
    assert '_scan-verify.example.test. IN TXT "scan-verify=' + "0f" * 16 + '"' in page
    assert "<strong>pending</strong>" in page and "mismatch" in page


REFRESH = 'hx-get="/scope/live"'
TOKEN = "0f" * 16


def write_scope_status(settings, state="pending", name="example.test"):
    os.makedirs(settings.published_dir, exist_ok=True)
    with open(os.path.join(settings.published_dir, "scope_status.json"), "w") as fh:
        json.dump({"schema": "momus-scope-status-v1", "updated_at": "2030-01-01T00:00:00Z", "notice": None, "domains": {
            name: {"state": state, "txt_name": "_scan-verify." + name, "txt_value": "scan-verify=" + TOKEN,
                   "last_checked_at": "2030-01-01T00:00:00Z", "last_result": "ok" if state == "verified" else "missing"}}}, fh)


def live_part(page):
    """The element the Scope page refreshes: from its opening tag to the "Check DNS proof now" form after it."""
    start = page.index('<div id="scope-domains-live"')
    return page[start:page.index('action="/scope/check-now"', start)]


def test_scope_page_refreshes_itself_until_the_record_is_published(admin, settings):
    # the page as drawn right after "Add": the domain is in the database, the scanner has not published its record
    add_domain(admin)
    page = admin.get("/scope").text
    live = live_part(page)
    assert REFRESH in live and 'hx-trigger="every 3s"' in live
    assert "this page updates on its own" in live
    assert "waiting for the scanner to publish it (a scope-sync job)" not in page
    # the add form and "Check DNS proof now" are outside the refreshed element, so a refresh never wipes typing
    assert 'action="/scope/domains"' not in live and 'action="/scope/check-now"' not in live
    assert page.index('action="/scope/domains"') > page.index('action="/scope/check-now"')
    # the scanner publishes; the next poll of the fragment shows the record the way a DNS panel asks for it
    finish_all(settings)
    write_scope_status(settings)
    r = admin.get("/scope/live", headers={"HX-Request": "true"})
    assert r.status_code == 200
    frag = r.text
    assert frag.lstrip().startswith('<div id="scope-domains-live"') and "<html" not in frag
    assert "<dt>Type</dt><dd><code>TXT</code></dd>" in frag
    assert "<dt>Name</dt><dd><code>_scan-verify.example.test</code>" in frag
    assert "<code>_scan-verify</code>" in frag                                    # the short name
    assert f"<dt>Value</dt><dd><code>scan-verify={TOKEN}</code></dd>" in frag
    assert f'_scan-verify.example.test. IN TXT "scan-verify={TOKEN}"' in frag      # the zone-file line, secondary
    assert REFRESH not in frag and "hx-trigger" not in frag
    assert 'action="/scope/domains"' not in frag


def test_scope_live_is_refused_without_a_session(app, settings):
    b = Browser(app)
    for path in ("/scope", "/scope/live"):
        r = b.c.get(path)
        assert r.status_code == 303 and r.headers["location"].startswith("/login"), path
        r = b.c.get(path, headers={"HX-Request": "true"})
        assert r.status_code == 401 and r.headers.get("hx-redirect") == "/login", path
        assert "scope-domains-live" not in r.text


def test_settled_scope_page_makes_no_background_requests(admin, settings):
    add_domain(admin)
    finish_all(settings)
    write_scope_status(settings, "verified")
    page = admin.get("/scope").text
    assert REFRESH not in page and "hx-trigger" not in live_part(page)
    assert "<dt>Type</dt>" not in page                         # a verified domain needs no record block
    assert f'_scan-verify.example.test. IN TXT "scan-verify={TOKEN}"' in page


def test_scope_page_refreshes_while_check_now_runs(admin, settings):
    add_domain(admin)
    finish_all(settings)
    write_scope_status(settings, "verified")
    assert admin.post("/scope/check-now").status_code == 303
    assert REFRESH in admin.get("/scope").text                 # the scope-sync job is in flight
    finish_all(settings)
    assert REFRESH not in admin.get("/scope").text             # its status is final: the answer is in


def test_approval_needs_a_finished_inventory_of_this_mode(admin, settings):
    add_domain(admin)
    finish_all(settings)
    assert "err=" in admin.post("/scope/approve", data={"inventory_run": "inv-nope"}).headers["location"]
    finish(settings, "inv-running", "running", "inventory")
    assert "err=" in admin.post("/scope/approve", data={"inventory_run": "inv-running"}).headers["location"]
    finish(settings, "inv-lab", "done", "inventory", lab=True)
    assert "err=" in admin.post("/scope/approve", data={"inventory_run": "inv-lab"}).headers["location"]
    finish(settings, "inv-ok", "done", "inventory")
    assert "err=" not in admin.post("/scope/approve", data={"inventory_run": "inv-ok"}).headers["location"]


def test_awaiting_approval_from_held_back(admin, settings, published):
    # lab mode comes only from the brain's setting (off here), not from the fixture heartbeat's lab_mode
    finish(settings, "inv-1", "done", "inventory", lab=False)
    assert "err=" not in admin.post("/scope/approve", data={"inventory_run": "inv-1"}).headers["location"]
    with open(os.path.join(published, "held_back.json"), "w") as fh:
        json.dump({"schema": "momus-held-back-v1", "run_id": "full-2", "inventory_run": "inv-1",
                   "hosts": [{"host": "new.demo.test", "reason": "new-since-approved-inventory"},
                             {"host": "<script>x</script>", "reason": "address-changed"}, {"host": "z.demo.test", "reason": "bogus"}]}, fh)
    page = admin.get("/scope").text
    assert "Awaiting approval" in page and "new.demo.test" in page
    # the brain does not compare snapshots itself: shadow.demo.test changed address in the snapshot, but the scanner
    # did not hold it back, so it is not listed (the scanner's held_back.json is the one source)
    assert "shadow.demo.test" not in page.split("Awaiting approval")[1].split("</table>")[0]
    assert "&lt;script&gt;x" not in page                                                          # an invalid host name is dropped
    # a reason other than the fixed codes is shown as "unknown reason", not dropped
    assert "z.demo.test" in page and "unknown reason" in page.split("z.demo.test")[1].split("</tr>")[0]


def test_held_back_addresses_domains_and_counts_come_from_the_scanner(admin, settings, published):
    add_domain(admin, "example.test")
    add_domain(admin, "added.test")
    finish_all(settings)
    finish(settings, "inv-1", "done", "inventory", lab=False)
    with open(os.path.join(settings.published_dir, "scanner.json"), "w") as fh:     # not lab mode for this test
        json.dump({"schema": "momus-scanner-v1", "updated_at": "2030-01-01T00:00:00Z", "state": "idle", "lab_mode": False}, fh)
    r = admin.post("/scope/approve", data={"inventory_run": "inv-1"})
    assert "err=" not in r.headers["location"], r.headers["location"]
    with open(os.path.join(published, "held_back.json"), "w") as fh:
        json.dump({"schema": "momus-held-back-v1", "run_id": "full-2", "inventory_run": "inv-1",
                   "hosts": [{"host": "shop.added.test", "reason": "domain-not-in-approved-inventory", "approved_ips": [],
                              "current_ips": ["192.0.2.10", "<b>bad</b>", "2001:db8::5"]},
                             {"host": "www.example.test", "reason": "address-changed", "approved_ips": ["192.0.2.1"],
                              "current_ips": ["192.0.2.99", "999.1.1.1"]}],
                   "domains": [{"domain": "added.test", "reason": "domain-not-in-approved-inventory"},
                               {"domain": "<i>x</i>", "reason": "domain-not-in-approved-inventory"}]}, fh)
    st = os.path.join(settings.published_dir, "status", "full-2.json")
    with open(st, "w") as fh:
        json.dump({"schema": "momus-status-v1", "job_id": "full-2", "state": "done", "type": "full", "run_id": "full-2",
                   "queued_at": "2030-01-02T00:00:00Z", "ended_at": "2030-01-02T01:00:00Z",
                   "counts": {"held_back": 2, "domains_scanned": 1, "domains_held_back": 1, "domains_pending": 0}}, fh)
    page = admin.get("/scope").text
    assert "This domain was added after the inventory you approved. Approve a newer inventory to scan it." in page
    assert page.count("This domain was added after the inventory you approved.") == 1               # only added.test
    assert "its domain was added after the approved inventory" in page and "shop.added.test" in page
    assert "<code>192.0.2.10</code>" in page and "<code>2001:db8::5</code>" in page and "bad" not in page.split("Awaiting approval")[1]
    assert "<code>192.0.2.99</code>" in page and "(was 192.0.2.1)" in page and "999.1.1.1" not in page
    assert "<i>x</i>" not in page and "&lt;i&gt;" not in page
    assert "1 domain(s) scanned, 1 held back because they were added after the approved inventory, 0 pending" in page
    runs = admin.get("/runs").text
    assert "Domains: 1 scanned, 1 held back (added after the approved inventory), 0 pending (not verified)" in runs
    api = admin.get("/api/v1/scope").json()
    assert api["domain_counts"] == {"job_id": "full-2", "scanned": 1, "held_back": 1, "pending": 0}
    held = {h["host"]: h for h in api["held_back"]["hosts"]}
    assert held["shop.added.test"]["current_ips"] == ["192.0.2.10", "2001:db8::5"]
    assert api["held_back"]["domains"] == ["added.test"]


def test_scheduler_tick_queues_and_skips(admin, settings):
    add_domain(admin)
    finish_all(settings)
    s2 = make_settings(settings.data_dir.rsplit("/", 1)[0] and __import__("pathlib").Path(settings.data_dir).parent, scheduler_enabled=True)
    conn = dbm.connect(settings.db_path)
    conn.execute("UPDATE schedules SET enabled=1, hour=2, minute=0, last_slot=NULL WHERE kind='monthly-full'")
    conn.execute("UPDATE schedules SET day_of_month=1 WHERE kind='monthly-full'")
    conn.close()
    now = dt.datetime(2030, 3, 1, 2, 1, tzinfo=dt.timezone.utc)
    jobs.tick(s2, now)
    fulls = [f for f in job_files(settings) if f.startswith("full-")]
    assert len(fulls) == 1
    out = scanner_accepts(settings, fulls[0])
    assert out["type"] == "full"
    jobs.tick(s2, now + dt.timedelta(minutes=1))                  # same slot: nothing more
    assert len([f for f in job_files(settings) if f.startswith("full-")]) == 1
    conn = dbm.connect(settings.db_path)
    conn.execute("UPDATE schedules SET enabled=1, hour=2, minute=0, last_slot=NULL WHERE kind='daily-recheck'")
    conn.close()
    jobs.tick(s2, dt.datetime(2030, 3, 2, 2, 1, tzinfo=dt.timezone.utc))   # the full job is still in flight: skip
    conn = dbm.connect(settings.db_path)
    row = dict(conn.execute("SELECT * FROM schedules WHERE kind='daily-recheck'").fetchone())
    conn.close()
    assert row["last_slot"] == "2030-03-02T02:00:00Z" and row["last_outcome"].startswith("skipped: a job was still in flight")
    assert not [f for f in job_files(settings) if f.startswith("recheck-")]


def test_queue_and_refusal_each_write_one_audit_entry(admin, settings):
    add_domain(admin)
    conn = dbm.connect(settings.db_path)
    n0 = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    queue(admin, "inventory")                                     # refused: the scope-sync is in flight
    rows = [tuple(r) for r in conn.execute("SELECT action FROM audit_log WHERE id > (SELECT MAX(id) - ? FROM audit_log)", (0,))]
    n1 = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    assert n1 - n0 == 1 and conn.execute("SELECT action FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()[0] == "job-refused"
    finish_all(settings)
    queue(admin, "inventory")
    assert conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0] - n1 == 1
    assert conn.execute("SELECT action FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()[0] == "job-queue"
    inv = [f for f in job_files(settings) if f.startswith("inv-")][0][:-5]
    finish(settings, inv, "done", "inventory")
    n2 = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    admin.post("/scope/approve", data={"inventory_run": inv})
    assert conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0] - n2 == 1
    assert conn.execute("SELECT action FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()[0] == "inventory-approve"
    conn.close()


def test_job_file_write_is_atomic_and_never_overwrites(settings):
    os.makedirs(settings.jobs_dir, exist_ok=True)
    job = {"id": "inv-x1", "type": "inventory"}
    jobs.write_job_file(settings.jobs_dir, job)
    with pytest.raises(jobs.QueueError):
        jobs.write_job_file(settings.jobs_dir, job)
    assert os.listdir(settings.jobs_dir) == ["inv-x1.json"]


def test_domain_add_and_remove_audit_entries(admin, settings):
    conn = dbm.connect(settings.db_path)
    last = lambda: conn.execute("SELECT MAX(id) FROM audit_log").fetchone()[0]  # noqa: E731
    since = lambda i: [r[0] for r in conn.execute("SELECT action FROM audit_log WHERE id > ? ORDER BY id", (i,))]  # noqa: E731
    i = last()
    add_domain(admin)
    assert since(i) == ["domain-add", "job-queue"]                  # the scope-sync it queued
    finish_all(settings)
    i = last()
    assert "err=" not in admin.post("/scope/domains/remove", data={"name": "example.test"}).headers["location"]
    assert since(i) == ["domain-remove"]                            # no domains left: no sync to send
    conn.close()


def test_two_queue_calls_cannot_both_pass_the_check(admin, settings):
    """The in-flight check runs inside the write transaction: a second queue call made at once is refused."""
    import threading
    add_domain(admin)
    finish_all(settings)
    info = None
    results = []

    def go():
        c = dbm.connect(settings.db_path)
        try:
            jobs.queue(c, settings, info, "inventory", "admin", "user")
            results.append("queued")
        except jobs.QueueError:
            results.append("refused")
        finally:
            c.close()
    ts = [threading.Thread(target=go) for _ in range(4)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert sorted(results) == ["queued", "refused", "refused", "refused"]
    assert len([f for f in job_files(settings) if f.startswith("inv-")]) == 1


# ---------------------------------------------------------------- a job whose status file was lost can be marked abandoned
def _lost_job(admin, settings):
    add_domain(admin)                                            # queues a scope-sync job; no status ever appears for it
    jid = job_files(settings)[0][:-5]
    conn = dbm.connect(settings.db_path)
    conn.execute("UPDATE jobs SET created_at='2020-01-01T00:00:00Z' WHERE id=?", (jid,))   # written long ago
    conn.close()
    return jid


def test_lost_job_can_be_marked_abandoned_with_confirmation(admin, settings):
    jid = _lost_job(admin, settings)
    assert jobs.in_flight(settings) == jid
    page = admin.get("/runs").text
    assert "Jobs with no final status" in page and f'name="job_id" value="{jid}"' in page
    r = admin.post("/runs/abandon", data={"job_id": jid})                          # no confirmation
    assert "err=" in r.headers["location"]
    assert os.path.exists(os.path.join(settings.jobs_dir, jid + ".json"))
    r = admin.post("/runs/abandon", data={"job_id": jid, "confirm": "yes"})
    assert r.status_code == 303 and "err=" not in r.headers["location"], r.headers["location"]
    assert not os.path.exists(os.path.join(settings.jobs_dir, jid + ".json"))      # the brain removed the job file
    marker = os.path.join(settings.jobs_dir, jid + jobs.ABANDONED_SUFFIX)
    assert json.load(open(marker))["abandoned_by"] == "admin"
    assert jobs.in_flight(settings) is None                                         # new jobs can be queued again
    conn = dbm.connect(settings.db_path)
    rows = conn.execute("SELECT actor, target FROM audit_log WHERE action='job-abandon'").fetchall()
    ab = conn.execute("SELECT abandoned_by FROM jobs WHERE id=?", (jid,)).fetchone()[0]
    conn.close()
    assert [tuple(r) for r in rows] == [("admin", jid)] and ab == "admin"
    runs = admin.get("/runs").text
    assert "abandoned" in runs and "Jobs with no final status" not in runs
    assert "err=" in admin.post("/runs/abandon", data={"job_id": jid, "confirm": "yes"}).headers["location"]   # only once
    r = admin.post("/jobs", data={"type": "inventory"})
    assert "err=" not in r.headers["location"], r.headers["location"]
    assert any(f.startswith("inv-") for f in job_files(settings))


def test_the_scanner_never_runs_an_abandoned_job_id(admin, settings, tmp_path):
    jid = _lost_job(admin, settings)
    src = os.path.join(settings.jobs_dir, jid + ".json")
    keep = open(src).read()
    assert admin.post("/runs/abandon", data={"job_id": jid, "confirm": "yes"}).status_code == 303
    with open(src, "w") as fh:                                   # even if the job file came back
        fh.write(keep)
    pub = tmp_path / "scanner-pub"
    r = runner.Runner(str(tmp_path / "scanner-root"), settings.jobs_dir, str(pub), log=lambda *_: None, trace=lambda *_: None)
    assert [k for k, *_ in r.pending()] == []
    assert jobs.in_flight(settings) is None


def test_abandon_is_refused_for_a_running_or_finished_job(admin, settings):
    jid = _lost_job(admin, settings)
    os.makedirs(settings.published_dir, exist_ok=True)
    with open(os.path.join(settings.published_dir, "scanner.json"), "w") as fh:
        json.dump({"schema": "momus-scanner-v1", "updated_at": dbm.iso(), "state": "busy", "current_job": jid}, fh)
    r = admin.post("/runs/abandon", data={"job_id": jid, "confirm": "yes"})
    assert "err=" in r.headers["location"] and os.path.exists(os.path.join(settings.jobs_dir, jid + ".json"))
    finish(settings, jid, "done", "scope-sync")
    with open(os.path.join(settings.published_dir, "scanner.json"), "w") as fh:
        json.dump({"schema": "momus-scanner-v1", "updated_at": dbm.iso(), "state": "idle"}, fh)
    assert "err=" in admin.post("/runs/abandon", data={"job_id": jid, "confirm": "yes"}).headers["location"]
    r = admin.api_post("/api/v1/jobs/abandon", json={"job_id": "../etc", "confirm": True})
    assert r.status_code == 409


def test_a_busy_scanner_with_an_old_heartbeat_is_stale(admin, settings):
    from app import services
    old = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    fresh = dbm.iso()
    class C:
        pass
    c = C()
    c.scanner = {"updated_at": old, "state": "busy", "current_job": "full-1"}
    assert services.heartbeat(c)["stale"] is True            # the scanner beats during jobs now: old means stopped
    c.scanner = {"updated_at": fresh, "state": "busy", "current_job": "full-1"}
    assert services.heartbeat(c)["stale"] is False
