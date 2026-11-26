"""Every read of published data is bounded, long tables are paginated,
report downloads stream, and the scanner's held-back list, counts and heartbeat are read strictly."""
import datetime as dt
import json
import os
import re
import sqlite3

import anyio

import fixtures
from app import db as dbm, jobs, services
from app import published as pubm
from conftest import ORIGIN


def _status(pub, jid, t):
    p = os.path.join(pub, "status", f"{jid}.json")
    with open(p, "w") as fh:
        json.dump({"schema": "momus-status-v1", "job_id": jid, "type": "full", "state": "done", "run_id": None,
                   "queued_at": "2030-01-01T00:00:00Z", "counts": {}}, fh)
    os.utime(p, (t, t))


def test_thousands_of_status_files_are_capped_before_reading(admin, published, settings, monkeypatch):
    for i in range(3000):
        _status(published, f"many-{i:05d}", 1_000_000 + i)
    reads = []
    real = pubm.read_json

    def counting(path, *a, **kw):
        fd = kw.get("dir_fd")                                    # status files are read by name inside the open folder
        if fd is not None and os.readlink(f"/proc/self/fd/{fd}").endswith(os.sep + "status"):
            reads.append(os.path.basename(path))
        return real(path, *a, **kw)
    monkeypatch.setattr(pubm, "read_json", counting)
    sts = pubm.all_status(settings.published_dir)
    assert len(reads) == pubm.MAX_STATUS_FILES and len(sts) == pubm.MAX_STATUS_FILES
    assert "many-02999.json" in reads and "many-00000.json" not in reads          # the newest were chosen, by time
    reads.clear()
    r = admin.get("/runs")
    assert r.status_code == 200 and len(reads) <= 2 * pubm.MAX_STATUS_FILES + 10
    assert 'href="?jobs_page=2"' in r.text


def test_status_counts_are_clamped(published):
    p = os.path.join(published, "status", "full-9.json")
    with open(p, "w") as fh:
        json.dump({"job_id": "full-9", "type": "full", "state": "done", "counts": {"domains_scanned": -5, "domains_held_back": 10 ** 14,
                                                                                    "domains_pending": 2, "assets": "12"}}, fh)
    st = pubm.job_status(published, "full-9")
    assert pubm.domain_counts(st) == {"scanned": 0, "held_back": pubm.MAX_COUNT, "pending": 2}
    assert st["counts"]["assets"] == 12


def test_oversized_status_file_is_not_parsed(published):
    with open(os.path.join(published, "status", "full-8.json"), "w") as fh:
        fh.write('{"job_id": "full-8", "state": "done", "pad": "' + "x" * (pubm.MAX_STATUS_JSON + 10) + '"}')
    assert pubm.job_status(published, "full-8") is None


def test_too_many_job_files_counts_as_busy(settings):
    for i in range(jobs.MAX_JOB_FILES + 1):
        open(os.path.join(settings.jobs_dir, f"planted-{i:05d}.json"), "w").close()
    assert jobs.in_flight(settings) == jobs.TOO_MANY_JOB_FILES


def test_version_watch_shows_the_newest_files(published, settings):
    """In the per-watch layout (version-watch/<id>/<date>.json), the dated files are chosen newest first by the date
    in the name, never by modification time, and cut to 50 after that choice. Modification times run opposite to the
    dates here, so a listing by time would keep the oldest files."""
    d = os.path.join(published, "version-watch", fixtures.WATCH_ID)
    for f in os.listdir(d):
        os.unlink(os.path.join(d, f))
    day0 = dt.date(2030, 1, 1)
    dates = [(day0 + dt.timedelta(days=i)).isoformat() for i in range(80)]
    for i, day in enumerate(dates):
        fixtures.write_watch_result(published, fixtures.WATCH_ID, day, hostile=False, latest=(i == len(dates) - 1))
        p = os.path.join(d, f"{day}.json")
        os.utime(p, (3_000_000 - i, 3_000_000 - i))           # the newest date has the oldest modification time
    r = pubm.watch_result(published, fixtures.WATCH_ID)
    assert len(r["dates"]) == 50
    assert r["dates"] == sorted(dates, reverse=True)[:50]        # newest first, the 30 oldest left out
    assert r["dates"][0] == dates[-1] and dates[0] not in r["dates"]
    assert r["result"]["date"] == dates[-1] and r["suspect"] is None


# ---------------------------------------------------------------- held_back.json and scope_status.json
def test_held_back_is_read_strictly(published):
    hosts = [{"host": f"h{i}.demo.test", "reason": "new-since-approved-inventory", "current_ips": ["192.0.2.1"] * 3 + ["nope"]}
             for i in range(6000)]
    hosts += [{"host": "..", "reason": "address-changed"}, {"host": "a/b.test", "reason": "address-changed"},
              {"host": "ok.demo.test\n", "reason": "address-changed"}, {"host": "odd.demo.test", "reason": "<b>made up</b>"}]
    with open(os.path.join(published, "held_back.json"), "w") as fh:
        json.dump({"run_id": "full-2", "inventory_run": "inv-1", "hosts": hosts[-4:] + hosts[:6000],
                   "domains": [{"domain": "added.test", "reason": "domain-not-in-approved-inventory"},
                               {"domain": "../x", "reason": "domain-not-in-approved-inventory"},
                               {"domain": "other.test", "reason": "who-knows"}]}, fh)
    with open(os.path.join(published, "held_back.json")) as fh:
        doc = json.load(fh)
    doc["hosts"][4]["current_ips"] = ["192.0.2.%d" % (i % 250) for i in range(100)] + ["nope"]      # more than 64 addresses
    with open(os.path.join(published, "held_back.json"), "w") as fh:
        json.dump(doc, fh)
    hb = pubm.held_back(published)
    names = [h["host"] for h in hb["hosts"]]
    assert len(names) <= 5000 and ".." not in names and "a/b.test" not in names and "ok.demo.test\n" not in names
    odd = [h for h in hb["hosts"] if h["host"] == "odd.demo.test"][0]
    assert odd["why"] == "unknown reason" and odd["reason"] == "unknown"
    h0 = [h for h in hb["hosts"] if h["host"] == "h0.demo.test"][0]
    assert 0 < len(h0["current_ips"]) <= 64 and "nope" not in h0["current_ips"]
    assert hb["domains"] == ["added.test"] and hb["other_domains"] == ["other.test"]
    with open(os.path.join(published, "held_back.json"), "w") as fh:
        fh.write('{"hosts": [], "pad": "' + "x" * (4 * 1024 * 1024) + '"}')
    assert pubm.held_back(published) is None                                   # size cap before parsing


def test_scope_status_names_and_codes_are_checked(published):
    with open(os.path.join(published, "scope_status.json"), "w") as fh:
        json.dump({"domains": {"good.test": {"state": "verified", "last_result": "match", "txt_name": "_scan-verify.good.test"},
                               "odd.test": {"state": "<i>owned</i>", "last_result": "sure", "txt_name": "bad name"},
                               "../evil": {"state": "verified"}, "x\n.test": {"state": "verified"}}}, fh)
    ss = pubm.scope_status(published)
    assert set(ss["domains"]) == {"good.test", "odd.test"}
    assert ss["domains"]["odd.test"]["state"] == "unknown" and ss["domains"]["odd.test"]["last_result"] == "unknown"
    assert ss["domains"]["odd.test"]["txt_name"] is None and ss["domains"]["good.test"]["state"] == "verified"


# ---------------------------------------------------------------- heartbeat
def test_a_heartbeat_in_the_future_is_stale():
    now = dt.datetime.now(dt.timezone.utc)
    fmt = lambda t: t.strftime("%Y-%m-%dT%H:%M:%SZ")           # noqa: E731
    assert pubm.heartbeat_stale({"updated_at": fmt(now)}) is False
    assert pubm.heartbeat_stale({"updated_at": fmt(now - dt.timedelta(seconds=170))}) is False
    assert pubm.heartbeat_stale({"updated_at": fmt(now - dt.timedelta(seconds=200))}) is True
    assert pubm.heartbeat_stale({"updated_at": fmt(now + dt.timedelta(seconds=60))}) is True
    assert pubm.heartbeat_stale({"updated_at": "2099-01-01T00:00:00Z"}) is True
    assert pubm.heartbeat_stale({"updated_at": "garbage"}) is True and pubm.heartbeat_stale({}) is True
    assert jobs.heartbeat_stale is pubm.heartbeat_stale


def test_a_future_heartbeat_does_not_block_abandoning(admin, settings, published):
    with open(os.path.join(published, "scanner.json"), "w") as fh:
        json.dump({"updated_at": "2099-01-01T00:00:00Z", "state": "busy", "current_job": "sync-x1"}, fh)
    assert jobs.abandonable(settings, published_scanner(published), "sync-x1") is None
    page = admin.get("/").text
    assert "stale" in page.lower() or "stopped" in page.lower()


def published_scanner(pub):
    return pubm.scanner(pub)


# ---------------------------------------------------------------- long tables are paginated
def _more_runs(pub, n_runs, n_hist):
    p = os.path.join(pub, "snapshots", "full-2.sqlite")
    db = sqlite3.connect(p)
    for i in range(n_runs):
        db.execute("INSERT INTO runs(run_id, started, finished, kind) VALUES(?,?,?,?)", (f"old-{i:04d}", "2029-01-01T00:00:00Z",
                                                                                       "2029-01-01T01:00:00Z", "recheck"))
    for i in range(n_hist):
        db.execute("INSERT INTO finding_observations(run_id, finding_key, band, state, score) VALUES(?,?,?,?,?)",
                   (f"old-{i:04d}", fixtures.K["git"], "Medium", "persistent", 60))
    for i in range(120):
        db.execute("INSERT INTO certificates(run_id, hostname, port, subject) VALUES(?,?,?,?)", ("full-2", "target.demo.test", 10000 + i, f"CN=c{i}"))
    db.commit()
    db.close()
    fixtures.write_latest(pub, "full-2")


def test_runs_history_and_certificates_are_paginated(admin, published):
    _more_runs(published, 400, 130)
    r1 = admin.get("/runs").text
    runs1 = re.findall(r"<code>(old-\d{4})</code>", r1)
    assert len(runs1) == 50 and 'href="?runs_page=2"' in r1
    runs2 = re.findall(r"<code>(old-\d{4})</code>", admin.get("/runs?runs_page=2").text)
    assert len(runs2) == 50 and not set(runs1) & set(runs2)
    last = admin.get("/runs?runs_page=9").text
    assert 'href="?runs_page=10"' not in last
    api = admin.get("/api/v1/runs?runs_page=2").json()
    assert len(api["scan_runs"]) == 50 and api["runs_more"] is True
    f = admin.get("/findings/" + fixtures.K["git"]).text
    assert len(re.findall(r"<code>old-\d{4}</code>", f)) == 50 and 'href="?hist_page=2"' in f
    a = admin.get("/assets/target.demo.test").text
    assert a.count("CN=c") == 49 and 'href="?cert_page=2"' in a
    assert admin.get("/assets/target.demo.test?cert_page=3").text.count("CN=c") == 21


def test_audit_log_is_paginated(admin, settings):
    conn = dbm.connect(settings.db_path)
    for i in range(450):
        conn.execute("INSERT INTO audit_log(at, actor, action, target) VALUES(?,?,?,?)", (dbm.iso(), "admin", "note-add", f"entry-{i:04d}"))
    conn.close()
    p1 = admin.get("/audit").text
    assert p1.count("entry-") == 200 and "entry-0449" in p1
    nxt = re.search(r'href="/audit\?([^"]+)">Older entries', p1).group(1).replace("&amp;", "&")
    p2 = admin.get("/audit?" + nxt).text
    assert p2.count("entry-") == 200 and "entry-0249" in p2 and "entry-0449" not in p2
    api = admin.get("/api/v1/audit").json()
    assert len(api["entries"]) == 200 and api["next_before"]
    api2 = admin.get(f"/api/v1/audit?before={api['next_before']}").json()
    assert api2["entries"][0]["id"] < api["entries"][-1]["id"]


# ---------------------------------------------------------------- report downloads stream from the opened handle
def test_a_very_large_report_is_streamed_in_chunks(app, admin, published):
    p = os.path.join(published, "reports", "full-2", "full-2-big.csv")
    size = 48 * 1024 * 1024 + 7
    with open(p, "wb") as fh:
        fh.truncate(size)
    cookie = admin.c.cookies.get("momus_session")
    chunks = []

    async def run():
        scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "GET", "scheme": "http",
                 "path": "/runs/full-2/files/full-2-big.csv", "raw_path": b"/runs/full-2/files/full-2-big.csv", "query_string": b"",
                 "root_path": "", "headers": [(b"host", b"testserver"), (b"cookie", f"momus_session={cookie}".encode())],
                 "client": ("127.0.0.1", 1234), "server": ("testserver", 80)}
        sent = {"done": False}

        async def receive():
            if not sent["done"]:
                sent["done"] = True
                return {"type": "http.request", "body": b"", "more_body": False}
            await anyio.sleep(3600)

        async def send(msg):
            if msg["type"] == "http.response.start":
                chunks.append(("start", msg["status"], dict(msg["headers"])))
            elif msg["type"] == "http.response.body" and msg.get("body"):
                chunks.append(len(msg["body"]))
        await app(scope, receive, send)
    anyio.run(run)
    start, body = chunks[0], chunks[1:]
    assert start[1] == 200 and start[2][b"content-disposition"] == b'attachment; filename="full-2-big.csv"'
    assert start[2][b"content-security-policy"] == b"sandbox; default-src 'none'"
    assert sum(body) == size and len(body) >= 48 and max(body) <= 1024 * 1024


def test_small_report_download_is_unchanged(admin, published):
    r = admin.get("/runs/full-2/files/full-2.html")
    assert r.status_code == 200 and "<script>alert('report')</script>" in r.text
    assert r.headers["content-disposition"] == 'attachment; filename="full-2.html"'
    assert admin.get("/runs/full-2/files/full-2-nope.csv").status_code == 404
    assert ORIGIN


def test_a_held_back_domain_with_an_unknown_code_is_shown_as_unknown_reason(admin, settings, published):
    from test_jobs import add_domain, finish, finish_all
    add_domain(admin, "example.test")
    add_domain(admin, "other.test")
    finish_all(settings)
    finish(settings, "inv-1", "done", "inventory", lab=False)
    assert "err=" not in admin.post("/scope/approve", data={"inventory_run": "inv-1"}).headers["location"]
    with open(os.path.join(published, "held_back.json"), "w") as fh:
        json.dump({"run_id": "full-2", "inventory_run": "inv-1", "hosts": [],
                   "domains": [{"domain": "example.test", "reason": "domain-not-in-approved-inventory"},
                               {"domain": "other.test", "reason": "<script>new-code</script>"}]}, fh)
    page = admin.get("/scope").text
    assert "Held back by the scanner: unknown reason." in page and "new-code" not in page
    assert pubm.HELD_DOMAIN_TEXT in page


def test_only_a_fresh_busy_heartbeat_blocks_queueing(settings, published):
    old = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert jobs.in_flight(settings, {"state": "busy", "current_job": "full-7", "updated_at": dbm.iso()}) == "full-7"
    assert jobs.in_flight(settings, {"state": "busy", "current_job": "full-7", "updated_at": old}) is None
    assert jobs.in_flight(settings, {"state": "busy", "current_job": "full-7", "updated_at": "2099-01-01T00:00:00Z"}) is None
    open(os.path.join(settings.jobs_dir, "full-7" + jobs.ABANDONED_SUFFIX), "w").close()          # abandoned by the admin
    assert jobs.in_flight(settings, {"state": "busy", "current_job": "full-7", "updated_at": dbm.iso()}) is None


def test_a_jobs_folder_too_large_to_list_counts_as_busy(settings, monkeypatch):
    for i in range(30):
        open(os.path.join(settings.jobs_dir, f"junk{i:03d}"), "w").close()       # names that are not job files
    assert jobs.in_flight(settings) is None
    monkeypatch.setattr(pubm, "MAX_DIR_ENTRIES", 10)
    monkeypatch.setattr(pubm.newest_names, "__defaults__", (10, None))
    assert jobs.in_flight(settings) == jobs.TOO_MANY_JOB_FILES                     # a job file could hide among the rest
