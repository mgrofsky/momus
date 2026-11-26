import sqlite3

import pytest

import fixtures
from helpers import shown
from app import db as dbm
from conftest import PASSWORD, Browser


def entries(settings, action=None):
    conn = dbm.connect(settings.db_path)
    q = "SELECT action, actor, target FROM audit_log" + (" WHERE action=?" if action else "")
    rows = [tuple(r) for r in conn.execute(q, (action,) if action else ())]
    conn.close()
    return rows


def count_delta(settings, fn):
    before = entries(settings)
    fn()
    after = entries(settings)
    return after[len(before):]


def test_each_action_writes_exactly_one_entry(app, admin, published, settings):
    b = Browser(app)
    cases = [
        ("login", lambda: b.login()),
        ("login-failed", lambda: Browser(app).login("admin", "wrong password!!")),
        ("profile-change", lambda: admin.post("/scope/profile", data={"check_profile": "active"})),
        ("exclusion-add", lambda: admin.post("/scope/entries", data={"kind": "exclusion", "value": "*.old.example.test"})),
        ("exclusion-remove", lambda: admin.post("/scope/entries", data={"kind": "exclusion", "value": "*.old.example.test", "action": "remove"})),
        ("range-add", lambda: admin.post("/scope/entries", data={"kind": "range", "value": "1.1.1.0/24"})),
        ("host-approve", lambda: admin.post("/scope/entries", data={"kind": "host", "value": "shadow.demo.test"})),
        ("mark-add", lambda: admin.post(f"/findings/{fixtures.K['env']}/mark", data={"kind": "duplicate", "reason": "same as git",
                                                                                     **shown(admin, f"/findings/{fixtures.K['env']}")})),
        ("mark-withdraw", lambda: admin.post(f"/findings/{fixtures.K['env']}/unmark")),
        ("schedule-change", lambda: admin.post("/schedules", data={"kind": "daily-recheck", "enabled": "on", "hour": "1", "minute": "0"})),
        ("account-create", lambda: admin.post("/settings/accounts", data={"username": "second", "password": "y" * 20})),
        ("logout", lambda: b.post("/logout")),
    ]
    for action, fn in cases:
        new = count_delta(settings, fn)
        assert [a for a, _, _ in new] == [action], (action, new)
    ex = entries(settings, "profile-change")[0]
    assert ex[1] == "admin" and ex[2] == "default"


def test_refused_login_is_audited(app, admin, settings):
    # the start of the sign-in delay is audited once; the refused attempts themselves write nothing
    b = Browser(app)
    for _ in range(settings.login_max_failures - 1):
        b.login("admin", "wrong password!!")
    new = count_delta(settings, lambda: b.login("admin", "wrong password!!"))
    assert [a for a, _, _ in new] == ["login-failed", "login-delay"]
    assert new[1][1] == "anonymous" and new[1][2] == "username:admin"
    new = count_delta(settings, lambda: b.login("admin", PASSWORD))
    assert new == []


def test_audit_log_is_append_only(admin, settings):
    conn = dbm.connect(settings.db_path)
    for sql in ("UPDATE audit_log SET actor='x'", "DELETE FROM audit_log"):
        with pytest.raises(sqlite3.DatabaseError):
            conn.execute(sql)
    conn.close()


def test_audit_page_filters(admin, published):
    admin.post("/scope/profile", data={"check_profile": "active"})
    r = admin.get("/audit?action=profile-change")
    assert "check_profile: safe -&gt; active" in r.text and "bootstrap" not in r.text.split("<tbody>")[1]
    assert admin.get("/api/v1/audit?action=bootstrap").json()["entries"][0]["actor"] == "admin"


def test_database_is_wal_with_schema_version(settings, admin):
    conn = dbm.connect(settings.db_path)
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert dbm.schema_version(conn) == 7          # 0007_job_document, the latest migration
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    for t in ("users", "sessions", "domains", "exclusions", "owned_ranges", "approved_hosts", "inventory_approvals", "scope_profiles",
              "schedules", "jobs", "finding_marks", "notes", "settings", "audit_log", "agent_runs", "agent_messages", "proposals",
              "schema_version", "version_watches", "agent_steps"):
        assert t in tables, t
    cols = {r[1] for r in conn.execute("PRAGMA table_info(domains)")}
    assert "token" not in " ".join(cols)            # the brain stores no DNS token (the scanner mints it)
    conn.close()
    assert dbm.migrate(settings.db_path) == []      # idempotent


def test_scope_inputs_are_validated(admin):
    for kind, bad in (("exclusion", "a b"), ("exclusion", "x.test;id"), ("range", "10.0.0.0/8"), ("range", "nonsense"),
                      ("host", "UPPER..test"), ("host", "-bad.test")):
        r = admin.post("/scope/entries", data={"kind": kind, "value": bad})
        assert "err=" in r.headers["location"], (kind, bad)
