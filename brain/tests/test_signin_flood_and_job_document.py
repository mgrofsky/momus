"""A sign-in flood that cannot hide which
account or which source was attacked, a stale trusted-proxy setting that says so, a length check that cannot raise,
and the job document kept by the brain."""
import datetime as dt
import hashlib
import json
import os
import re

import pytest

from app import auth, db as dbm, jobs
from app.web import create_app
from conftest import ORIGIN, Browser, make_settings
from test_job_file_cleanup import status
from test_signin_limits import Clock, attempt, clock, q  # noqa: F401  (clock is a fixture)


def flood_rows(settings):
    return q(settings, "SELECT target, detail FROM audit_log WHERE action='login-flood' ORDER BY id")


def junk_flood(settings, clock, n=31, prefix="junk"):
    """n made-up failures in the first seconds of a fresh minute, each its own address and name."""
    clock.t = clock.t.replace(second=0, microsecond=0) + dt.timedelta(minutes=1)
    for i in range(n):
        if i % 10 == 0:
            clock.advance(1)
        assert attempt(settings, f"{prefix}-{i}", "wrong password!!", address=f"198.18.{i // 200}.{i % 200 + 1}") == \
            "Wrong username or password."


# ---------------------------------------------------------------- the flood summary
def test_the_flood_summary_names_the_attacked_account_and_the_source_keys(app, admin, settings, clock):
    """31 made-up failures, then six attempts at the real account from fresh addresses. Individual
    entries stay suppressed; the minute's summary names the account with its count and lists the source keys."""
    junk_flood(settings, clock)
    got = [attempt(settings, "admin", f"guess-number-{i}!!", address=f"203.0.113.{i + 1}")
           for i in range(settings.login_max_failures + 1)]
    assert got[-1][0] == "wait" and got[:-1] == ["Wrong username or password."] * settings.login_max_failures
    assert q(settings, "SELECT COUNT(*) FROM audit_log WHERE action='login-failed' AND target='admin'") == [(0,)]
    clock.advance(120)
    jobs.tick(settings, dbm.now())                       # the scheduler tick writes the summary
    rows = flood_rows(settings)
    assert len(rows) == 1, rows
    detail = rows[0][1]
    print("flood entry:", rows[0][0], "|", detail)
    assert detail.startswith("36 failed sign-ins in the minute from ")
    # the account's entry carries the source keys that failed on it
    assert ('Existing accounts: "admin" 5 (sources "203.0.113.1" 1, "203.0.113.2" 1, "203.0.113.3" 1, "203.0.113.4" 1, '
            '"203.0.113.5" 1).') in detail
    keys = re.search(r"Source keys: (.*?)\.(?: |$)", detail).group(1)
    assert len(re.findall(r'"[^"]+" \d+', keys)) == 10 and keys.endswith("and 26 more"), keys
    assert re.search(r'Other usernames: ("junk-\d+" 1, ){9}"junk-\d+" 1, and 21 more\.', detail), detail
    assert len(detail) <= 1000


def test_a_padded_made_up_name_does_not_push_the_real_account_out(app, admin, settings, clock):
    clock.t = clock.t.replace(second=0, microsecond=0) + dt.timedelta(minutes=1)
    n = 0
    for name in [f"padding-name-{i:02d}-" + "x" * 40 for i in range(14)]:      # 14 made-up names, 3 failures each
        for _ in range(3):
            n += 1
            attempt(settings, name, "wrong password!!", address=f"198.18.1.{n}")
    assert attempt(settings, "admin", "wrong password!!", address="203.0.113.77") == "Wrong username or password."
    clock.advance(120)
    jobs.tick(settings, dbm.now())
    detail = flood_rows(settings)[0][1]
    assert detail.startswith("43 failed sign-ins in the minute from ")
    assert 'Existing accounts: "admin" 1 (sources "203.0.113.77" 1).' in detail, detail
    assert len(detail) <= 1000


def test_a_hostile_username_is_cleaned_and_cut_in_the_summary(app, admin, settings, clock):
    junk_flood(settings, clock, n=30)
    hostile = "evil\x1b[31m\r\nname" + "y" * 100
    assert attempt(settings, hostile, "wrong password!!", address="203.0.113.9") == "Wrong username or password."
    for i in range(3):                                   # the hostile name has the most failures, so it is listed
        attempt(settings, hostile, "wrong password!!", address=f"203.0.113.{10 + i}")
    clock.advance(120)
    jobs.tick(settings, dbm.now())
    detail = flood_rows(settings)[0][1]
    assert "\x1b" not in detail and "\r" not in detail and "\n" not in detail
    m = re.search(r'Other usernames: "([^"]*)" 4,', detail)
    assert m, detail
    assert m.group(1).startswith("evil[31mname") and len(json.dumps(m.group(1))) <= 72, m.group(1)
    assert "y" * 100 not in detail


def test_the_summary_fits_the_detail_limit_and_keeps_its_counts_line(app, admin, settings, clock):
    """Many long names and many accounts: the lists are shortened, never the counts line."""
    db = dbm.connect(settings.db_path)
    try:
        for i in range(25):
            auth.create_account(db, settings, "admin", f"account-number-{i:02d}-" + "z" * 30, "a long enough password", None)
    finally:
        db.close()
    clock.t = clock.t.replace(second=0, microsecond=0) + dt.timedelta(minutes=1)
    n = 0
    for i in range(25):
        n += 1
        attempt(settings, f"account-number-{i:02d}-" + "z" * 30, "wrong password!!", address=f"198.18.2.{n}")
    for i in range(30):
        n += 1
        attempt(settings, f"made-up-name-{i:02d}-" + "q" * 45, "wrong password!!", address=f"198.18.3.{n}")
    clock.advance(120)
    jobs.tick(settings, dbm.now())
    detail = flood_rows(settings)[0][1]
    assert len(detail) <= 1000, len(detail)
    assert detail.startswith("55 failed sign-ins in the minute from ")
    assert "Above 30 a minute no individual login-failed or login-delay entry is written" in detail
    assert re.search(r"Existing accounts: .*and \d+ more\.", detail), detail
    assert not detail.endswith("...")


def test_no_login_delay_entry_is_written_during_a_flood(app, admin, settings, clock):
    """The login-delay entry is suppressed above the rate."""
    junk_flood(settings, clock)
    for i in range(settings.login_max_failures):
        attempt(settings, "admin", "wrong password!!", address=f"203.0.113.{i + 1}")
    assert q(settings, "SELECT COUNT(*) FROM audit_log WHERE action='login-delay'") == [(0,)]


# ---------------------------------------------------------------- a stale trusted-proxy setting
STALE = "the header was ignored because the request did not come from MOMUS_TRUSTED_PROXY"


def test_a_trusted_proxy_setting_that_stopped_matching_is_logged_once(tmp_path, capsys):
    s = make_settings(tmp_path, allowed_origins=("https://momus.example.test",), cookie_secure=True, trusted_proxy="172.30.81.10")
    app = create_app(s, start_background=False)
    capsys.readouterr()
    from fastapi.testclient import TestClient
    c = TestClient(app, base_url="https://momus.example.test", client=("172.30.81.11", 50000))     # the proxy's new address
    for i in range(3):
        c.get("/login", headers={"X-Forwarded-For": f"198.51.100.{i}"})
    out = capsys.readouterr().out
    assert out.count(STALE) == 1, out
    assert "198.51.100" not in out and "172.30.81" not in out          # fixed text: no address from the request
    c.get("/login")
    TestClient(app, base_url="https://momus.example.test", client=("172.30.81.10", 50000)).get(
        "/login", headers={"X-Forwarded-For": "198.51.100.9"})
    assert STALE not in capsys.readouterr().out


def test_no_stale_proxy_line_without_the_setting_or_without_the_header(tmp_path, capsys):
    from fastapi.testclient import TestClient
    s = make_settings(tmp_path / "a")
    app = create_app(s, start_background=False)
    capsys.readouterr()
    TestClient(app, base_url=ORIGIN, client=("192.0.2.1", 50000)).get("/login", headers={"X-Forwarded-For": "198.51.100.1"})
    assert STALE not in capsys.readouterr().out                         # no trusted proxy configured
    s = make_settings(tmp_path / "b", allowed_origins=("https://momus.example.test",), cookie_secure=True, trusted_proxy="172.30.81.10")
    app = create_app(s, start_background=False)
    capsys.readouterr()
    TestClient(app, base_url="https://momus.example.test", client=("172.30.81.11", 50000)).get("/login")
    assert STALE not in capsys.readouterr().out                         # another peer, but no forwarded header


# ---------------------------------------------------------------- the Content-Length check
@pytest.mark.parametrize("cl", [b"\xb2", b"\xb9\xb2", b"9" * 5000, b"12345678"])
def test_a_length_that_is_not_seven_ascii_digits_is_411_never_500(app, cl):
    from fastapi.testclient import TestClient
    b = Browser(app)
    pre = b.pre_token("/login")
    c = TestClient(app, base_url=ORIGIN, follow_redirects=False, raise_server_exceptions=False)
    c.cookies = b.c.cookies
    body = ("username=admin&password=x&csrf=" + pre).encode()
    r = c.post("/login", content=body, headers={"Origin": ORIGIN, "Content-Type": "application/x-www-form-urlencoded",
                                               "Content-Length": cl})     # bytes: superscript digits as one byte each
    assert r.status_code == 411, (cl[:8], r.status_code)


# ---------------------------------------------------------------- the brain keeps the job document
def test_the_jobs_row_keeps_the_document_after_a_false_final_status(admin, settings):
    r = admin.api_post("/api/v1/jobs", json={"type": "retention", "retention_days": 30})
    assert r.status_code == 200, r.text
    jid = [f for f in os.listdir(settings.jobs_dir) if f.endswith(".json")][0][:-5]
    with open(os.path.join(settings.jobs_dir, jid + ".json"), "rb") as fh:
        on_disk = fh.read()
    status(settings, jid, "done")                        # the scanner says done although nothing ran
    admin.get("/runs")
    assert os.listdir(settings.jobs_dir) == []
    doc, sha = q(settings, "SELECT document, file_sha256 FROM jobs WHERE id=?", (jid,))[0]
    assert doc is not None and doc.encode("utf-8") == on_disk
    assert hashlib.sha256(doc.encode("utf-8")).hexdigest() == sha
    assert json.loads(doc)["id"] == jid


def test_a_job_file_written_before_the_migration_is_kept_when_it_is_removed(admin, settings):
    r = admin.api_post("/api/v1/jobs", json={"type": "retention", "retention_days": 30})
    jid = [f for f in os.listdir(settings.jobs_dir) if f.endswith(".json")][0][:-5]
    db = dbm.connect(settings.db_path)
    db.execute("UPDATE jobs SET document=NULL WHERE id=?", (jid,))        # as a row from before migration 0007
    db.close()
    status(settings, jid, "done")
    admin.get("/runs")
    doc, sha = q(settings, "SELECT document, file_sha256 FROM jobs WHERE id=?", (jid,))[0]
    assert doc is not None and hashlib.sha256(doc.encode("utf-8")).hexdigest() == sha


def test_a_job_file_that_no_longer_matches_its_hash_is_not_stored(admin, settings):
    r = admin.api_post("/api/v1/jobs", json={"type": "retention", "retention_days": 30})
    jid = [f for f in os.listdir(settings.jobs_dir) if f.endswith(".json")][0][:-5]
    db = dbm.connect(settings.db_path)
    db.execute("UPDATE jobs SET document=NULL WHERE id=?", (jid,))
    db.close()
    with open(os.path.join(settings.jobs_dir, jid + ".json"), "a") as fh:
        fh.write(" ")
    status(settings, jid, "done")
    admin.get("/runs")
    assert q(settings, "SELECT document FROM jobs WHERE id=?", (jid,)) == [(None,)]


def test_the_document_column_is_bounded_by_the_largest_job_file():
    sql = open(os.path.join(os.path.dirname(dbm.__file__), "migrations", "0007_job_document.sql")).read()
    assert f"length(CAST(document AS BLOB)) <= {jobs.JOB_MAX_BYTES}" in sql
    assert jobs.JOB_MAX_BYTES == 1 << 20                  # scanner/runner.py MAX_JOB_BYTES


def test_a_job_larger_than_the_scanner_accepts_is_refused_before_anything_is_written(admin, settings, monkeypatch):
    monkeypatch.setattr(jobs, "JOB_MAX_BYTES", 100)
    r = admin.api_post("/api/v1/jobs", json={"type": "retention", "retention_days": 30})
    assert r.status_code != 200
    assert os.listdir(settings.jobs_dir) == [] and q(settings, "SELECT COUNT(*) FROM jobs") == [(0,)]
