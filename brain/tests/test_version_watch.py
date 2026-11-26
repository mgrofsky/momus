"""Version watch: watch definitions in the app database (forms, API, audit), the jobs that carry them, the
daily schedule, and the strict, bounded reader of published/version-watch/<watch id>/."""
import ast
import datetime as dt
import json
import os
import pathlib
import re

import pytest

import fixtures
from app import db as dbm, jobs, published as pubm, watches as W
from conftest import ORIGIN, PASSWORD, Browser, bootstrap_token, make_settings
from app.web import create_app
from helpers import routes, said
from test_jobs import LAB, add_domain, finish_all, job_files, runner, scanner_accepts

FORM = {"watch_id": "php-cgi", "name": "PHP CGI argument injection", "product": "php", "cves": "CVE-2099-0003\nCVE-2099-0004",
        "floors": "8.1.29\n8.2.20\n8.3.8", "hosts": "www.example.test"}


def db_state(settings):
    conn = dbm.connect(settings.db_path)
    try:
        rows = [tuple(r) for r in conn.execute("SELECT id, name, product, cves, floors, hosts FROM version_watches ORDER BY id")]
        audit_n = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    finally:
        conn.close()
    return rows, audit_n


def audit_since(settings, n):
    conn = dbm.connect(settings.db_path)
    try:
        return [tuple(r) for r in conn.execute("SELECT action, actor, target, detail FROM audit_log ORDER BY id")][n:]
    finally:
        conn.close()


def add(b, **kw):
    return b.post("/version-watch/watches", data={**FORM, **kw})


# ---------------------------------------------------------------- forms
BAD_FORMS = [
    ({"watch_id": "a"}, W.E_ID), ({"watch_id": "PHP"}, W.E_ID), ({"watch_id": "a" * 33}, W.E_ID), ({"watch_id": "../x"}, W.E_ID),
    ({"watch_id": "https://evil.test/x"}, W.E_ID), ({"watch_id": ".*"}, W.E_ID), ({"watch_id": "<script>"}, W.E_ID),
    ({"name": ""}, W.E_NAME), ({"name": "x" * 81}, W.E_NAME), ({"name": "PHP/(.*)"}, W.E_NAME), ({"name": "<script>alert(1)</script>"}, W.E_NAME),
    ({"name": "x" * 300}, W.E_TOO_LONG),
    ({"product": "php7"}, W.E_PRODUCT), ({"product": ""}, W.E_PRODUCT),
    ({"cves": ""}, W.E_CVES), ({"cves": "CVE-24-1"}, W.E_CVE), ({"cves": "<script>"}, W.E_CVE), ({"cves": "CVE-2099-0003, CVE-2099-0003"}, W.E_CVE_TWICE),
    ({"cves": ",".join(f"CVE-2099-{1000 + i}" for i in range(21))}, W.E_CVES),
    ({"floors": ""}, W.E_FLOORS), ({"floors": "8.3"}, W.E_RELEASE), ({"floors": "8.3.x"}, W.E_RELEASE), ({"floors": ".*"}, W.E_RELEASE),
    ({"floors": "8.3.8\n8.3.9"}, W.E_BRANCH_TWICE), ({"floors": "08.3.8"}, W.E_BRANCH), ({"floors": "8.3.100000"}, W.E_RELEASE),
    ({"floors": "\n".join(f"{i}.0.1" for i in range(1, 18))}, W.E_FLOORS),
    ({"product": "openssl", "floors": "1.1.1"}, W.E_OPENSSL),
    ({"hosts": "https://evil.test/x"}, W.E_HOST), ({"hosts": "*.example.test"}, W.E_HOST), ({"hosts": "192.0.2.1"}, W.E_HOST),
    ({"hosts": "<script>.test"}, W.E_HOST), ({"hosts": "\n".join(f"h{i}.example.test" for i in range(101))}, W.E_HOSTS),
]


@pytest.mark.parametrize("i", range(len(BAD_FORMS)))
def test_each_form_rule_is_refused_with_a_fixed_message_and_nothing_written(admin, settings, i):
    change, message = BAD_FORMS[i]
    before = db_state(settings)
    r = add(admin, **change)
    assert r.status_code == 400, (change, r.status_code)
    assert message.replace("'", "&#39;").replace('"', "&#34;") in r.text, (change, re.findall(r'flash err[^<]*<?[^<]*', r.text)[:2])
    assert db_state(settings) == before                       # no row, no audit entry
    if change.get("watch_id", "").startswith("<") or change.get("hosts", "").startswith("<") or change.get("name", "").startswith("<"):
        assert "<script>" not in r.text                        # what was typed is shown back escaped, in the form only


def test_add_edit_remove_each_write_one_audit_entry(admin, settings):
    _, n = db_state(settings)
    r = add(admin, hosts="WWW.Example.test.\nwww.example.test")
    assert r.status_code == 303 and r.headers["location"].startswith("/version-watch?msg=") and said(r.headers["location"]).startswith("Watch php-cgi added")
    new = audit_since(settings, n)
    assert [(a, actor, t) for a, actor, t, _ in new] == [("watch-add", "admin", "php-cgi")]
    assert new[0][3] == "php; 2 CVE(s); 3 branch(es); 1 extra host name(s)"
    w = W.get(dbm.connect(settings.db_path), "php-cgi")
    assert w["floors"] == {"8.1": 29, "8.2": 20, "8.3": 8} and w["hosts"] == ["www.example.test"] and w["created_by"] == "admin"
    assert add(admin).status_code == 400                                      # the add form never overwrites
    page = admin.get("/version-watch/php-cgi").text
    assert 'name="edit" value="1"' in page and "8.1.29\n8.2.20\n8.3.8</textarea>" in page
    _, n = db_state(settings)
    r = admin.post("/version-watch/watches", data={**FORM, "edit": "1", "floors": "8.1.29\n8.2.20\n8.3.9\n8.4.1"})
    assert r.status_code == 303 and said(r.headers["location"]).startswith("Watch php-cgi saved")
    assert [(a, t) for a, _, t, _ in audit_since(settings, n)] == [("watch-edit", "php-cgi")]
    _, n = db_state(settings)
    r = admin.post("/version-watch/watches", data={**FORM, "edit": "1", "floors": "8.1.29\n8.2.20\n8.3.9\n8.4.1"})
    assert "Nothing changed" in said(r.headers["location"]) and audit_since(settings, n) == []
    r = admin.post("/version-watch/watches", data={**FORM, "edit": "1", "name": "<b>"})          # a refused edit re-shows the page
    assert r.status_code == 400 and "<b>" not in r.text and 'value="&lt;b&gt;"' in r.text and W.E_NAME in r.text
    r = admin.post("/version-watch/watches/php-cgi/remove", data={})                              # not confirmed
    assert "err=" in r.headers["location"] and said(r.headers["location"]).startswith("Tick the box") and audit_since(settings, n) == []
    r = admin.post("/version-watch/watches/php-cgi/remove", data={"confirm": "yes"})
    assert r.status_code == 303 and r.headers["location"].startswith("/version-watch?msg=") and said(r.headers["location"]).startswith("Watch php-cgi removed")
    assert [(a, actor, t) for a, actor, t, _ in audit_since(settings, n)] == [("watch-remove", "admin", "php-cgi")]
    assert db_state(settings)[0] == []
    r = admin.post("/version-watch/watches/php-cgi/remove", data={"confirm": "yes"})
    assert "err=" in r.headers["location"] and said(r.headers["location"]) == "No such watch."
    r = admin.post("/version-watch/watches", data={**FORM, "edit": "1"})                         # editing a removed watch
    assert r.status_code == 400 and W.E_NO_SUCH in r.text


def test_at_most_twenty_watches(admin, settings):
    for i in range(20):
        assert add(admin, watch_id=f"w{i:02d}").status_code == 303
    page = admin.get("/version-watch").text
    assert "the most a version-watch job can carry" in page and 'action="/version-watch/watches" class="stack"' not in page
    before = db_state(settings)
    r = add(admin, watch_id="w20")
    assert r.status_code == 400 and W.E_FULL in r.text and db_state(settings) == before
    assert admin.api_post("/api/v1/version-watch/watches", {**_api_watch(), "id": "w20"}).status_code == 400


def test_new_routes_are_covered_by_the_session_and_anti_forgery_tests(app):
    posts = {t for m, t, _ in routes(app) if m == "POST"}
    gets = {t for m, t, _ in routes(app) if m == "GET"}
    for t in ("/version-watch/watches", "/version-watch/watches/{watch_id}/remove", "/api/v1/version-watch/watches",
              "/api/v1/version-watch/watches/{watch_id}/remove"):
        assert t in posts, t
    for t in ("/version-watch", "/version-watch/{watch_id}", "/docs/version-watch", "/api/v1/version-watch", "/api/v1/version-watch/{watch_id}"):
        assert t in gets, t


def test_forms_are_refused_without_token_or_origin(admin, settings):
    before = db_state(settings)
    assert admin.c.post("/version-watch/watches", data=FORM, headers={"Origin": ORIGIN}).status_code == 403
    assert admin.c.post("/version-watch/watches", data={**FORM, "csrf": admin.csrf}).status_code == 403
    assert admin.c.post("/version-watch/watches", data={**FORM, "csrf": admin.csrf}, headers={"Origin": "http://evil.test"}).status_code == 403
    assert db_state(settings) == before


def test_watch_changes_take_the_actor_from_the_session():
    """Every caller of watches.save and watches.remove passes the signed-in user (c.user) as the actor."""
    app_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app")
    seen = []
    for f in ("pages.py", "api.py"):
        for node in ast.walk(ast.parse(open(os.path.join(app_dir, f)).read())):
            if isinstance(node, ast.Call) and getattr(node.func, "attr", None) in ("save", "remove") and \
                    getattr(node.func.value, "id", None) == "watchesm":
                seen.append(ast.unparse(node.args[1]))
    assert seen and set(seen) == {"c.user"}


# ---------------------------------------------------------------- API
def _api_watch(**kw):
    return {"id": "nginx-x", "name": "nginx range", "product": "nginx", "cves": ["CVE-2099-0005"], "floors": {"1.20": 1, "1.21": 0},
            "hosts": [], **kw}


def test_api_add_edit_remove_with_the_same_rules_and_audit(admin, settings):
    _, n = db_state(settings)
    r = admin.api_post("/api/v1/version-watch/watches", _api_watch())
    assert r.status_code == 200 and r.json()["outcome"] == "added"
    assert r.json()["watch"]["floors"] == {"1.20": 1, "1.21": 0}
    r = admin.api_post("/api/v1/version-watch/watches", _api_watch(name="nginx range two"))
    assert r.json()["outcome"] == "edited"
    for bad in (_api_watch(floors={"1.20": True}), _api_watch(floors={"1.20": "1"}), _api_watch(hosts=["WWW.example.test"]),
                _api_watch(cves="CVE-2099-0005"), _api_watch(pattern=".*"), _api_watch(id="x"), _api_watch(product="openssl", floors={"1.1": 1})):
        r = admin.api_post("/api/v1/version-watch/watches", bad)
        assert r.status_code == 400 and r.json()["error"].endswith("."), bad
    assert admin.api_post("/api/v1/version-watch/watches/nginx-x/remove", {"confirm": "yes"}).status_code == 422   # strictly true
    assert admin.api_post("/api/v1/version-watch/watches/nginx-x/remove", {}).status_code == 400
    assert admin.api_post("/api/v1/version-watch/watches/nginx-x/remove", {"confirm": True}).status_code == 200
    assert admin.api_post("/api/v1/version-watch/watches/nginx-x/remove", {"confirm": True}).status_code == 404
    assert [a for a, _, _, _ in audit_since(settings, n)] == ["watch-add", "watch-edit", "watch-remove"]
    assert admin.api_post("/api/v1/version-watch/watches", _api_watch(), csrf=False).status_code == 403


def test_api_shows_definitions_and_checked_results(admin, settings, published):
    add(admin)
    d = admin.get("/api/v1/version-watch").json()
    assert [w["id"] for w in d["watches"]] == ["php-cgi"] and d["retired"] == []
    w = d["watches"][0]
    assert w["latest"]["headline"] == {"hosts": 2, "fail": 1, "pass": 0, "unknown": 1, "unreachable": 0} and w["latest"]["date"] == "2030-01-02"
    assert w["floors"] == {"8.1": 29, "8.2": 20, "8.3": 8} and w["product_name"] == "PHP" and d["probe"].startswith("One GET / per host")
    one = admin.get("/api/v1/version-watch/php-cgi").json()
    assert one["watched"] is True and one["result"]["hosts"][0]["hostname"] == "target.demo.test"
    assert admin.get("/api/v1/version-watch/nope-nope").status_code == 404
    assert admin.get("/api/v1/version-watch/..%2Fx").status_code in (404, 422)


# ---------------------------------------------------------------- jobs
def test_a_version_watch_job_carries_the_watches_and_is_refused_without_one(admin, settings):
    add_domain(admin)
    finish_all(settings)
    loc = admin.post("/jobs", data={"type": "version-watch"}).headers["location"]
    assert "err=" in loc and said(loc) == "Add a watch on the Version watch page first."
    assert "Add a watch on the Version watch page first." in admin.get("/runs").text       # the disabled reason
    add(admin, watch_id="zz-last")
    add(admin, watch_id="aa-first", product="openssl", floors="3.0.14\n3.1.6\n10.0.1", hosts="")
    loc = admin.post("/jobs", data={"type": "version-watch"}).headers["location"]
    assert "err=" not in loc, loc
    (f,) = [x for x in job_files(settings) if x.startswith("vw-")]
    out = scanner_accepts(settings, f)
    assert [w["id"] for w in out["options"]["watches"]] == ["aa-first", "zz-last"]          # sorted by id
    assert out["options"]["watches"][0]["floors"] == {"3.0": 14, "3.1": 6, "10.0": 1}
    raw = json.load(open(os.path.join(settings.jobs_dir, f)))
    assert raw["options"]["watches"][1]["hosts"] == ["www.example.test"]
    conn = dbm.connect(settings.db_path)
    summary = conn.execute("SELECT summary FROM jobs WHERE id=?", (f[:-5],)).fetchone()[0]
    detail = conn.execute("SELECT detail FROM audit_log WHERE action='job-queue' AND target=?", (f[:-5],)).fetchone()[0]
    conn.close()
    assert summary.endswith("2 watch(es)") and "2 watch(es)" in detail


def test_twenty_watches_of_every_product_validate_with_the_scanner(admin, settings):
    add_domain(admin)
    finish_all(settings)
    products = [("php", "8.1.29\n8.2.20"), ("nginx", "1.24.0\n1.25.3"), ("apache-httpd", "2.4.62"), ("openssl", "3.0.14\n3.3.2")]
    for i in range(20):
        p, fl = products[i % 4]
        hosts = "\n".join(f"h{j}.example.test" for j in range(100)) if i == 0 else ""
        assert add(admin, watch_id=f"w-{i:02d}", product=p, floors=fl, hosts=hosts).status_code == 303
    assert "err=" not in admin.post("/jobs", data={"type": "version-watch"}).headers["location"]
    (f,) = [x for x in job_files(settings) if x.startswith("vw-")]
    out = scanner_accepts(settings, f)
    assert len(out["options"]["watches"]) == 20 and len(out["options"]["watches"][0]["hosts"]) == 100


def test_a_lab_version_watch_job_carries_lab_targets_and_watches(tmp_path):
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
    assert "Queue a version-watch run" in b.get("/runs").text
    assert add(b, hosts="").status_code == 303
    loc = b.post("/jobs", data={"type": "version-watch"}).headers["location"]
    assert "err=" not in loc, loc
    (f,) = job_files(s)
    out = scanner_accepts(s, f, LAB)
    assert out["lab"] == {"targets": ["notice.demo.test", "target.demo.test"], "cidr": "10.89.47.0/24"}
    assert out["scope"]["domains"] == [] and out["options"]["watches"][0]["id"] == "php-cgi"
    with pytest.raises(runner.Invalid):
        scanner_accepts(s, f, None)
    assert jobs.LAB_TYPES == runner.LAB_TYPES


def test_the_daily_version_watch_schedule_queues_the_watches(admin, settings):
    add_domain(admin)
    finish_all(settings)
    r = admin.post("/schedules", data={"kind": "daily-version-watch", "enabled": "on", "hour": "5", "minute": "15"})
    assert r.status_code == 303 and "err=" not in r.headers["location"], r.headers["location"]
    assert "Daily version watch" in admin.get("/schedules").text
    row = [x for x in admin.get("/api/v1/schedules").json()["rows"] if x["kind"] == "daily-version-watch"][0]
    assert row["enabled"] == 1 and row["next_run"].endswith("T05:15:00Z")
    s2 = make_settings(pathlib.Path(os.path.dirname(settings.data_dir)), scheduler_enabled=True)
    conn = dbm.connect(settings.db_path)
    conn.execute("UPDATE schedules SET last_slot=NULL WHERE kind='daily-version-watch'")
    conn.close()
    jobs.tick(s2, dt.datetime(2030, 3, 1, 5, 16, tzinfo=dt.timezone.utc))          # no watch yet: recorded, not queued
    conn = dbm.connect(settings.db_path)
    out = conn.execute("SELECT last_outcome FROM schedules WHERE kind='daily-version-watch'").fetchone()[0]
    conn.close()
    assert out == "not queued: Add a watch on the Version watch page first."
    add(admin)
    jobs.tick(s2, dt.datetime(2030, 3, 2, 5, 16, tzinfo=dt.timezone.utc))
    (f,) = [x for x in job_files(settings) if x.startswith("vw-")]
    assert scanner_accepts(settings, f)["options"]["watches"][0]["id"] == "php-cgi"
    conn = dbm.connect(settings.db_path)
    trig = conn.execute("SELECT trigger, created_by FROM jobs WHERE id=?", (f[:-5],)).fetchone()
    conn.close()
    assert tuple(trig) == ("schedule", "scheduler")


def test_the_new_schedule_row_is_off_by_default(admin, settings):
    conn = dbm.connect(settings.db_path)
    row = dict(conn.execute("SELECT * FROM schedules WHERE kind='daily-version-watch'").fetchone())
    conn.close()
    assert row["enabled"] == 0 and row["day_of_month"] is None


# ---------------------------------------------------------------- the reader: bounds
def test_an_oversized_latest_json_is_not_parsed(published, settings, monkeypatch):
    d = os.path.join(published, "version-watch", fixtures.WATCH_ID)
    doc = fixtures.watch_doc(fixtures.WATCH_ID, "2030-01-03", hostile=False)
    doc["pad"] = "x" * (pubm.VW_MAX_JSON + 10)                     # valid JSON, over the cap
    with open(os.path.join(d, "latest.json"), "w") as fh:
        json.dump(doc, fh)
    os.unlink(os.path.join(d, "2030-01-02.json"))
    parsed = []
    real = pubm.json.loads
    monkeypatch.setattr(pubm.json, "loads", lambda t, *a, **kw: parsed.append(len(t)) or real(t, *a, **kw))
    r = pubm.watch_result(published, fixtures.WATCH_ID)
    assert r["folder"] and r["result"] is None and parsed == []    # refused on its size, before any parsing


def test_more_than_fifty_watch_folders_are_capped(published, settings):
    base = os.path.join(published, "version-watch")
    for i in range(70):
        p = os.path.join(base, f"w-{i:03d}")
        os.makedirs(p)
        os.utime(p, (4_000_000 + i, 4_000_000 + i))
    os.utime(os.path.join(base, fixtures.WATCH_ID), (1, 1))
    names = pubm.watch_folders(published)
    assert len(names) == pubm.VW_MAX_FOLDERS == 50
    assert names[0] == "w-069" and "w-000" not in names and fixtures.WATCH_ID not in names      # the newest by time
    for bad in ("UPPER", "a", "x" * 40, ".hidden", "with.dot"):
        os.makedirs(os.path.join(base, bad))
    assert all(pubm.is_watch_id(n) for n in pubm.watch_folders(published, limit=1000))


def test_a_symlinked_watch_folder_is_ignored(published, settings, tmp_path):
    fixtures.write_watch_result(str(tmp_path / "outside"), "evil-w", "2030-01-02")      # a valid result outside published/
    outside = tmp_path / "outside" / "version-watch" / "evil-w"
    os.symlink(str(outside), os.path.join(published, "version-watch", "evil-w"))
    assert "evil-w" not in pubm.watch_folders(published)
    r = pubm.watch_result(published, "evil-w")
    assert r == {"folder": False, "result": None, "suspect": None, "dates": []}
    # a symlinked latest.json inside a real folder is refused too
    d = os.path.join(published, "version-watch", fixtures.WATCH_ID)
    os.unlink(os.path.join(d, "latest.json"))
    os.unlink(os.path.join(d, "2030-01-02.json"))
    os.symlink(str(outside / "latest.json"), os.path.join(d, "latest.json"))
    assert pubm.watch_result(published, fixtures.WATCH_ID)["result"] is None


def test_too_many_entries_in_a_watch_folder_are_not_all_looked_at(published, settings, monkeypatch):
    d = os.path.join(published, "version-watch", fixtures.WATCH_ID)
    for i in range(60):
        open(os.path.join(d, (dt.date(2029, 1, 1) + dt.timedelta(days=i)).isoformat() + ".json"), "w").close()
    assert len(pubm.watch_result(published, fixtures.WATCH_ID)["dates"]) == pubm.VW_MAX_DATED
    monkeypatch.setattr(pubm, "MAX_DIR_ENTRIES", 10)
    assert len(pubm.watch_result(published, fixtures.WATCH_ID)["dates"]) <= 10


def test_too_many_entries_in_the_version_watch_folder_are_not_all_looked_at(published):
    base = os.path.join(published, "version-watch")
    for i in range(30):
        os.makedirs(os.path.join(base, f"w-{i:03d}"))
    assert len(pubm.watch_folders(published)) == 31
    assert len(pubm.watch_folders(published, max_entries=10)) <= 10


def test_the_suspect_marker(admin, published, settings):
    add(admin)
    fixtures.write_watch_result(published, fixtures.WATCH_ID, "2030-01-05", hostile=False, suspect=True)
    r = pubm.watch_result(published, fixtures.WATCH_ID)
    want = ("The latest run was suspect (more than half the hosts did not answer); the results below are from the last good "
            "run on 2030-01-02.")
    assert r["suspect"]["text"] == want and r["result"]["date"] == "2030-01-02" and r["dates"][:2] == ["2030-01-05", "2030-01-02"]
    assert want in admin.get("/version-watch/php-cgi").text and want in admin.get("/version-watch").text
    assert admin.get("/api/v1/version-watch/php-cgi").json()["suspect"]["good_date"] == "2030-01-02"
    fixtures.write_watch_result(published, fixtures.WATCH_ID, "2030-01-06", hostile=False)         # a good run again
    assert pubm.watch_result(published, fixtures.WATCH_ID)["suspect"] is None
    # a suspect run later on the same UTC day as the good run overwrites that day's dated file
    good = fixtures.watch_doc(fixtures.WATCH_ID, "2030-01-07", hostile=False)
    fixtures.write_watch_result(published, fixtures.WATCH_ID, "2030-01-07", doc=good)
    assert pubm.watch_result(published, fixtures.WATCH_ID)["suspect"] is None
    later = {"suspect": True, **fixtures.watch_doc(fixtures.WATCH_ID, "2030-01-07", hostile=False), "generated_at": "2030-01-07T09:00:00Z"}
    fixtures.write_watch_result(published, fixtures.WATCH_ID, "2030-01-07", doc=later, latest=False)
    r = pubm.watch_result(published, fixtures.WATCH_ID)
    assert r["suspect"]["text"] == want.replace("2030-01-02", "2030-01-07") and r["result"]["generated_at"] == "2030-01-07T04:00:00Z"
    # a suspect first run (no latest.json at all)
    fixtures.write_watch_result(published, "first-w", "2030-01-05", suspect=True)
    r = pubm.watch_result(published, "first-w")
    assert r["result"] is None and r["suspect"]["text"] == pubm.SUSPECT_NO_GOOD_TEXT


def test_results_of_removed_watches_are_listed_as_no_longer_watched(admin, published, settings):
    page = admin.get("/version-watch").text
    assert "No longer watched" in page and 'href="/version-watch/php-cgi"' in page
    detail = admin.get("/version-watch/php-cgi").text
    assert "No longer watched" in detail and 'name="edit"' not in detail
    add(admin)
    assert "No longer watched" not in admin.get("/version-watch").text
    assert admin.get("/version-watch/never-defined").status_code == 404
    assert "Not found" in admin.get("/version-watch/never-defined").text


# ---------------------------------------------------------------- hostile published values
def _hostile_doc():
    rows = [
        {"hostname": "evil.demo.test", "domain": "demo.test", "version": "8.2.1<b>", "verdict": "EVIL", "reason": "<script>alert('r')</script>",
         "read_from": "<i>x</i>", "https_status": 99999, "http_status": True, "server": "<script>alert('s')</script>" + "S" * 500,
         "scan_db_version": "<b>1</b>", "source": "<u>db</u>"},
        {"hostname": "<script>alert('h')</script>", "domain": "demo.test", "version": "8.1.2", "verdict": "FAIL", "reason": "r",
         "read_from": "http server", "https_status": 200, "http_status": 200, "server": "x", "scan_db_version": None, "source": "job"},
        {"hostname": "ok.demo.test", "domain": "../evil", "version": "8.1.2", "verdict": "FAIL"},
        {"hostname": "fine.demo.test", "domain": "demo.test", "version": "8.1.2", "verdict": "FAIL", "https_status": 200.0, "http_status": "200"},
    ]
    doc = fixtures.watch_doc(fixtures.WATCH_ID, "2030-01-03", hostile=False, hosts=rows)
    doc["headline"] = {"hosts": -5, "fail": 10 ** 15, "pass": "3", "unknown": True, "unreachable": 1.5}
    doc["cves"] = ["CVE-2099-0003", "<script>", "CVE-2099-0003\n"]
    doc["floors"] = {"8.1": "8.1.29", "<b>": "8.2.1", "8.3": "8.3.8<b>"}
    doc["watch"]["name"] = "<script>alert('n')</script>"
    doc["changes"]["items"].append({"hostname": "<b>h</b>", "from_verdict": "EVIL"})
    doc["changes"]["items"].append({"hostname": "chg.demo.test", "from_verdict": "<x>", "to_verdict": "PASS", "to_version": "1<b>"})
    doc["history"].append({"date": "<script>", "hosts": 1})
    return doc


def test_hostile_values_in_a_published_result_are_escaped_or_dropped(admin, published, settings):
    fixtures.write_watch_result(published, fixtures.WATCH_ID, "2030-01-03", doc=_hostile_doc())
    r = pubm.watch_result(published, fixtures.WATCH_ID)["result"]
    hosts = {h["hostname"]: h for h in r["hosts"]}
    assert set(hosts) == {"evil.demo.test", "fine.demo.test"}                 # bad host name or domain: the row is dropped
    e = hosts["evil.demo.test"]
    assert e["verdict"] == "unknown" and e["version"] is None and e["https_status"] is None and e["http_status"] is None
    assert e["read_from"] is None and e["scan_db_version"] is None and e["source"] == "unknown"
    assert e["server"].startswith("<script>") and len(e["server"]) <= pubm.VW_SERVER_CAP + 3
    assert hosts["fine.demo.test"]["https_status"] is None and hosts["fine.demo.test"]["http_status"] is None
    assert r["headline"] == {"hosts": 0, "fail": pubm.MAX_COUNT, "pass": None, "unknown": None, "unreachable": None}
    assert r["cves"] == ["CVE-2099-0003"] and r["floors"] == {"8.1": "8.1.29"} and r["watch"]["name"] is None
    items = {c["hostname"]: c for c in r["changes"]["items"]}
    assert "<b>h</b>" not in items and items["chg.demo.test"]["from_verdict"] == "unknown" and items["chg.demo.test"]["to_version"] is None
    assert items["notice.demo.test"]["from_verdict"] is None                    # a new host: None stays None
    assert [h["date"] for h in r["history"]] == ["2030-01-01", "2030-01-03"]
    page = admin.get("/version-watch/php-cgi")
    assert page.status_code == 200
    t = page.text
    for live in ("<script>alert(", "<b>", "<i>x</i>", "<u>db</u>"):
        assert live not in t, live
    assert "&lt;script&gt;alert(&#39;s&#39;)&lt;/script&gt;" in t and "&lt;script&gt;alert(&#39;r&#39;)&lt;/script&gt;" in t
    assert "EVIL" not in t and "99999" not in t and "8.2.1&lt;b&gt;" not in t
    api = admin.get("/api/v1/version-watch/php-cgi")
    assert "<" not in api.text and ">" not in api.text and "EVIL" not in api.text and "99999" not in api.text
    assert "\\u003cscript\\u003ealert('s')" in api.text


def test_a_result_whose_watch_id_differs_from_its_folder_is_refused(published):
    doc = fixtures.watch_doc("other-id", "2030-01-03")
    fixtures.write_watch_result(published, fixtures.WATCH_ID, "2030-01-03", doc=doc)
    r = pubm.watch_result(published, fixtures.WATCH_ID)
    # latest.json and the newest dated file now name another watch, so both are refused (the older 2030-01-02 file
    # is not read: only latest.json and the newest dated file ever are)
    assert r["folder"] and r["result"] is None and r["dates"][0] == "2030-01-03"


# ---------------------------------------------------------------- pages
def test_the_page_states_what_the_probe_sends_and_links_the_docs(admin):
    t = admin.get("/version-watch").text
    assert ("One GET / per host per run, over https and then http, response headers only. It follows at most three redirects, "
            "and only to the same host name; such a redirect may lead to another path or port on that host. It starts no request "
            "to any other path, and uses no other method and no request body. Hosts are probed only under domains whose DNS proof passed in that job. Hosts "
            "under a domain held back from active checks are still watched, because this probe is no more than the web inventory "
            "already sends.") in t
    assert 'href="/docs/version-watch"' in t
    d = admin.get("/docs/version-watch")
    assert d.status_code == 200 and "docs/version-watch.md" in d.text


def test_the_docs_page_says_not_found_when_the_file_is_missing(tmp_path):
    s = make_settings(tmp_path, docs_dir=str(tmp_path / "nodocs"))
    app = create_app(s, start_background=False)
    b = Browser(app)
    tok = bootstrap_token(s)
    pre = b.pre_token("/bootstrap")
    b.c.post("/bootstrap", data={"token": tok, "username": "admin", "password": PASSWORD, "password2": PASSWORD, "owner_rule": "yes",
                                 "csrf": pre}, headers={"Origin": ORIGIN})
    r = b.get("/docs/version-watch")
    assert r.status_code == 200 and "docs/version-watch.md is not in this image" in r.text


def test_the_documented_example_watch_is_valid(admin, settings):
    """docs/version-watch.md's example, typed into the form as the page asks for it, gives the documented job entry."""
    r = add(admin, watch_id="example-php-watch", name="Example PHP watch", product="php", cves="CVE-2099-0001, CVE-2099-0002",
            floors="8.2.35\n8.3.36\n8.4.27\n8.5.12", hosts="")
    assert r.status_code == 303 and "err=" not in r.headers["location"]
    conn = dbm.connect(settings.db_path)
    got = W.for_job(conn)
    conn.close()
    assert got == [{"id": "example-php-watch", "name": "Example PHP watch", "product": "php", "cves": ["CVE-2099-0001", "CVE-2099-0002"],
                    "floors": {"8.2": 35, "8.3": 36, "8.4": 27, "8.5": 12}, "hosts": []}]
    doc = open(os.path.join(fixtures.REPO, "docs", "version-watch.md"), encoding="utf-8").read()
    m = re.search(r"\[\{\"id\": \"example-php-watch\".*?\}\]", doc, re.S)
    assert m and json.loads(m.group(0)) == got
