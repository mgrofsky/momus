"""A snapshot with a correct hash cannot hang the application, and checking a snapshot never
repeats expensive work or leaves temporary files behind."""
import os
import sqlite3
import sys
import threading
import time

import pytest

import fixtures
from app import queries, snapshot
from app.web import create_app
from conftest import ORIGIN, PASSWORD, Browser, bootstrap_token, make_settings

sys.path.insert(0, os.path.join(fixtures.REPO, "scanner", "pipeline"))
import ingest  # noqa: E402

ENDLESS = "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c) SELECT x FROM c"


def admin_for(tmp_path, **kw):
    s = make_settings(tmp_path, **kw)
    app = create_app(s, start_background=False)
    b = Browser(app)
    tok = bootstrap_token(s)
    pre = b.pre_token("/bootstrap")
    r = b.c.post("/bootstrap", data={"token": tok, "username": "admin", "password": PASSWORD, "password2": PASSWORD,
                                     "owner_rule": "yes", "csrf": pre}, headers={"Origin": ORIGIN})
    assert r.status_code == 303
    b.refresh_csrf()
    return app, s, b


def tamper(pub, *sql, writable_schema=False):
    """Change the published snapshot with SQL, then re-publish its (correct) hash: the integrity check passes."""
    p = os.path.join(pub, "snapshots", "full-2.sqlite")
    db = sqlite3.connect(p)
    if writable_schema:
        db.execute("PRAGMA writable_schema=ON")
    for q in sql:
        db.execute(q)
    db.commit()
    db.close()
    fixtures.write_latest(pub, "full-2")


def assert_refused(admin, settings, kind="refused"):
    t0 = time.monotonic()
    for path in ("/", "/findings", "/assets", "/runs"):
        r = admin.get(path)
        assert r.status_code == 200, path
        assert "Snapshot refused." in r.text and snapshot.MESSAGES[kind].replace("'", "&#39;") in r.text, path
        assert "Env file exposed" not in r.text
    assert admin.get("/api/v1/overview").json()["snapshot"]["state"] == kind
    assert time.monotonic() - t0 < 10
    assert snapshot.current(settings.published_dir, settings.snapshot_cache).kind == kind
    assert not [f for f in os.listdir(settings.snapshot_cache) if f.endswith(".sqlite")]     # never cached


def test_recursive_view_named_as_a_table_the_brain_reads_is_refused(admin, published, settings):
    tamper(published, "DROP TABLE findings",
           f"CREATE VIEW findings AS SELECT x AS finding_key, 'h' AS hostname, 'a' AS apex, 'nuclei' AS source, 'c' AS check_id, "
           f"80 AS port, 't' AS title, 'high' AS severity, '' AS cve_ids, 'full-1' AS first_seen_run, 'full-2' AS last_seen_run, "
           f"'open' AS status, NULL AS fixed_run FROM ({ENDLESS})")
    assert_refused(admin, settings)


def test_trigger_is_refused(admin, published, settings):
    tamper(published, "CREATE TRIGGER t AFTER INSERT ON runs BEGIN SELECT 1; END")
    assert_refused(admin, settings)


def test_virtual_table_is_refused(admin, published, settings):
    try:
        tamper(published, "CREATE VIRTUAL TABLE notes USING fts5(body)")
    except sqlite3.OperationalError:
        tamper(published, "CREATE VIRTUAL TABLE notes USING rtree(id, x0, x1)")
    assert_refused(admin, settings)


def test_view_mislabelled_as_a_table_in_sqlite_master_is_refused(admin, published, settings):
    tamper(published, "DROP TABLE runs", f"CREATE VIEW runs AS SELECT x AS seq, 'r' AS run_id, '' AS started, '' AS finished FROM ({ENDLESS})")
    tamper(published, "UPDATE sqlite_master SET type='table' WHERE name='runs'", writable_schema=True)
    # SQLite itself rejects a schema row whose type does not match its statement, so this is refused as unreadable
    assert_refused(admin, settings, "unreadable")


def test_table_without_the_expected_columns_or_with_a_generated_column_is_refused(tmp_path):
    for sql in (("DROP TABLE run_summary", "CREATE TABLE run_summary(run_id TEXT)"),
                ("DROP TABLE run_summary", "CREATE TABLE run_summary(run_id TEXT, json TEXT, g TEXT GENERATED ALWAYS AS (json || json))")):
        pub = str(tmp_path / f"pub{len(sql[1])}")
        fixtures.build_published(pub)
        tamper(pub, *sql)
        assert snapshot.current(pub, str(tmp_path / "cache")).kind == "refused", sql


def test_missing_tables_are_still_allowed(published, settings):
    tamper(published, "DROP TABLE domain_posture", "DROP TABLE certificates")
    assert snapshot.current(published, settings.snapshot_cache).kind == "ok"


def test_every_required_column_is_in_the_scanner_schema():
    db = sqlite3.connect(":memory:")
    db.executescript(ingest.SCHEMA)
    ingest.migrate(db.cursor())
    for table, cols in snapshot.REQUIRED.items():
        have = {r[1] for r in db.execute(f"PRAGMA table_xinfo({table})")}
        assert cols <= have, (table, cols - have)
    assert snapshot.schema_problem(_ro(db)) is None


def _ro(db):
    db.row_factory = sqlite3.Row
    return db


def test_a_query_past_the_deadline_is_stopped(published, settings):
    st = snapshot.current(published, settings.snapshot_cache)
    c = snapshot.connect(st, 0.3)
    t0 = time.monotonic()
    with pytest.raises(snapshot.Timeout):
        queries._rows(c, ENDLESS + " LIMIT 1 OFFSET 1000000000000")
    assert time.monotonic() - t0 < 3 and c.timed_out
    c.close()
    c = snapshot.connect(st, 0.3)                       # a new connection (the next request) has its own deadline
    assert queries._rows(c, "SELECT COUNT(*) AS n FROM findings")[0]["n"] == 4
    c.close()


def test_a_slow_query_gives_an_error_page_and_the_next_request_is_served(tmp_path, monkeypatch):
    app, s, b = admin_for(tmp_path, snapshot_query_seconds=0.5)
    fixtures.build_published(s.published_dir)
    real = queries.band_counts
    monkeypatch.setattr(queries, "band_counts", lambda db: queries._rows(db, ENDLESS + " LIMIT 1 OFFSET 1000000000000"))
    t0 = time.monotonic()
    r = b.get("/")
    assert r.status_code == 503 and "took longer than 0.5 seconds" in r.text
    assert b.get("/api/v1/overview").status_code == 503
    assert time.monotonic() - t0 < 6
    monkeypatch.setattr(queries, "band_counts", real)
    r = b.get("/")
    assert r.status_code == 200 and "Env file exposed" in r.text


# ---------------------------------------------------------------- remembered refusals, temporary files, size cap
def _count_copies(monkeypatch):
    calls = []
    real = snapshot._copy

    def counting(*a):
        calls.append(a[0])
        return real(*a)
    monkeypatch.setattr(snapshot, "_copy", counting)
    return calls


def test_a_refusal_is_remembered_until_the_file_changes(admin, published, settings, monkeypatch):
    calls = _count_copies(monkeypatch)
    fixtures.write_latest(published, "full-2", digest="0" * 64)
    for _ in range(3):
        assert "Snapshot refused." in admin.get("/findings").text
    assert len(calls) == 1
    p = os.path.join(published, "snapshots", "full-2.sqlite")
    os.utime(p, ns=(os.stat(p).st_atime_ns, os.stat(p).st_mtime_ns + 10 ** 9))       # a new modification time
    admin.get("/findings")
    assert len(calls) == 2
    fixtures.write_latest(published, "full-2")                                        # a different hash in latest.json
    assert "Env file exposed" in admin.get("/findings").text
    assert len(calls) == 3
    admin.get("/findings")
    assert len(calls) == 3


def test_schema_refusal_is_remembered(admin, published, settings, monkeypatch):
    tamper(published, "CREATE TRIGGER t AFTER INSERT ON runs BEGIN SELECT 1; END")
    calls = _count_copies(monkeypatch)
    for _ in range(3):
        admin.get("/")
    assert len(calls) == 1


def _temporaries(settings):
    return [f for f in os.listdir(settings.snapshot_cache) if snapshot.TMP_MARK in f] if os.path.isdir(settings.snapshot_cache) else []


def test_a_failed_copy_leaves_no_temporary_file(published, settings, monkeypatch):
    real = snapshot.open_regular

    class Breaks:
        def __init__(self, fh):
            self.fh, self.n = fh, 0

        def read(self, k):
            self.n += 1
            if self.n > 1:
                raise OSError(5, "I/O error")
            return self.fh.read(k)

        def __enter__(self):
            return self

        def __exit__(self, *a):
            self.fh.close()
    monkeypatch.setattr(snapshot, "MIB", 4096)
    monkeypatch.setattr(snapshot, "open_regular", lambda p, m=None, **k: Breaks(real(p, m, **k)))
    assert snapshot.current(published, settings.snapshot_cache).kind == "bad-pointer"
    assert _temporaries(settings) == []
    monkeypatch.setattr(snapshot, "open_regular", real)
    fixtures.write_latest(published, "full-2", digest="1" * 64)                       # and after a mismatch
    assert snapshot.current(published, settings.snapshot_cache).kind == "mismatch"
    assert _temporaries(settings) == [] and not [f for f in os.listdir(settings.snapshot_cache) if f.endswith(".sqlite")]


def test_stale_temporary_copies_are_removed_at_start_up(tmp_path):
    s = make_settings(tmp_path)
    os.makedirs(s.snapshot_cache)
    stale = os.path.join(s.snapshot_cache, "." + "a" * 64 + snapshot.TMP_MARK + "123-456")
    keep = os.path.join(s.snapshot_cache, "b" * 64 + ".sqlite")
    for p in (stale, keep):
        open(p, "w").close()
    create_app(s, start_background=False)
    assert not os.path.exists(stale) and os.path.exists(keep)


def test_snapshot_size_cap(tmp_path, published, settings, monkeypatch):
    assert settings.snapshot_max_mb == 512 and snapshot.DEFAULT_MAX_MB == 512
    size = os.path.getsize(os.path.join(published, "snapshots", "full-2.sqlite"))
    st = snapshot.current(published, settings.snapshot_cache, max_bytes=size - 1)
    assert st.kind == "too-large" and "MOMUS_SNAPSHOT_MAX_MB" in st.message
    # the cap is counted while copying too, so a file that grows after it was opened is still cut off
    monkeypatch.setattr(snapshot, "open_regular", lambda p, m=None, **k: open(p, "rb"))
    with pytest.raises(snapshot.Unsafe):
        snapshot._copy((None, os.path.join(published, "snapshots", "full-2.sqlite")), str(tmp_path / ".x.tmp-1"), 1000)
    from app.config import from_env
    assert from_env({}).snapshot_max_mb == 512 and from_env({"MOMUS_SNAPSHOT_MAX_MB": "64"}).snapshot_max_mb == 64
    assert from_env({"MOMUS_SNAPSHOT_QUERY_SECONDS": "5"}).snapshot_query_seconds == 5.0


def test_too_large_snapshot_page(tmp_path):
    app, s, b = admin_for(tmp_path, snapshot_max_mb=16)
    fixtures.build_published(s.published_dir)
    p = os.path.join(s.published_dir, "snapshots", "full-2.sqlite")
    with open(p, "ab") as fh:
        fh.truncate(17 * 1024 * 1024)
    fixtures.write_latest(s.published_dir, "full-2")
    r = b.get("/findings")
    assert "Snapshot refused." in r.text and "larger than this brain accepts" in r.text


def test_parallel_requests_check_a_new_snapshot_once(admin, published, settings, monkeypatch):
    calls = _count_copies(monkeypatch)
    errors = []

    def go():
        try:
            assert snapshot.current(published, settings.snapshot_cache).kind == "ok"
        except Exception as e:      # noqa: BLE001
            errors.append(e)
    ts = [threading.Thread(target=go) for _ in range(8)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert not errors and len(calls) <= 1
