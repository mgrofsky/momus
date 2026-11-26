import json
import os
import sqlite3

import fixtures
from helpers import shown
from app import snapshot


def test_hash_mismatch_is_refused(admin, published, settings):
    fixtures.write_latest(published, "full-2", digest="0" * 64)
    for path in ("/", "/findings", "/assets"):
        r = admin.get(path)
        assert r.status_code == 200
        assert "Snapshot refused." in r.text and "does not match its recorded SHA-256" in r.text
        assert "Env file exposed" not in r.text
    r = admin.get("/api/v1/overview")
    assert r.json()["snapshot"]["state"] == "mismatch" and r.json()["counts"] is None


def test_snapshot_changed_after_hashing_is_refused(admin, published, settings):
    assert "Env file exposed" in admin.get("/findings").text
    p = os.path.join(published, "snapshots", "full-2.sqlite")
    with open(p, "ab") as fh:
        fh.write(b"tampered")
    r = admin.get("/findings")
    assert "Snapshot refused." in r.text and "Env file exposed" not in r.text


def test_missing_published_folder_is_a_clear_empty_state(admin, settings):
    assert not os.path.exists(settings.published_dir)
    r = admin.post("/version-watch/watches", data={"watch_id": "php-cgi", "name": "PHP CGI", "product": "php", "cves": "CVE-2099-0003",
                                                    "floors": "8.3.8"})
    assert r.status_code == 303 and "err=" not in r.headers["location"]
    for path in ("/", "/findings", "/assets", "/domains", "/runs", "/scope", "/version-watch", "/version-watch/php-cgi",
                 "/docs/version-watch", "/schedules", "/audit", "/settings"):
        r = admin.get(path)
        assert r.status_code == 200, path
    assert "The published folder is not there" in admin.get("/").text
    assert admin.get("/api/v1/overview").json()["snapshot"]["state"] == "missing"


def test_empty_and_half_written_published_folder(admin, settings):
    os.makedirs(settings.published_dir)
    assert "Nothing has been published yet" in admin.get("/").text
    os.makedirs(os.path.join(settings.published_dir, "snapshots"))
    with open(os.path.join(settings.published_dir, "snapshots", "latest.json"), "w") as fh:
        fh.write('{"file": "full-2.sql')                      # half-written
    r = admin.get("/findings")
    assert r.status_code == 200 and "Snapshot refused." in r.text
    with open(os.path.join(settings.published_dir, "scanner.json"), "w") as fh:
        fh.write("{not json")
    with open(os.path.join(settings.published_dir, "scope_status.json"), "w") as fh:
        fh.write("[1,2")
    for path in ("/", "/runs", "/scope"):
        assert admin.get(path).status_code == 200


def test_pointer_cannot_escape_the_snapshots_folder(admin, published, settings):
    for name in ("../scanner.json", "/etc/passwd", "full-2.sqlite/../../x", "FULL.sqlite", ".hidden.sqlite"):
        with open(os.path.join(published, "snapshots", "latest.json"), "w") as fh:
            json.dump({"file": name, "sha256": "0" * 64, "run_id": "full-2"}, fh)
        st = snapshot.current(published, settings.snapshot_cache)
        assert st.kind == "bad-pointer", name


def test_symlinked_snapshot_is_refused(published, settings):
    real = os.path.join(published, "snapshots", "full-2.sqlite")
    os.rename(real, real + ".real")
    os.symlink(real + ".real", real)
    fixtures.write_latest(published, "full-2", digest=fixtures.sha(real + ".real"))
    assert snapshot.current(published, settings.snapshot_cache).kind == "bad-pointer"


def test_snapshot_is_never_written(admin, published, settings):
    p = os.path.join(published, "snapshots", "full-2.sqlite")
    before = (fixtures.sha(p), os.stat(p).st_mtime_ns)
    for path in ("/", "/findings", "/findings/" + fixtures.K["env"], "/assets", "/domains", "/runs", "/scope"):
        admin.get(path)
    admin.post(f"/findings/{fixtures.K['env']}/mark", data={"kind": "false_positive", "reason": "lab", **shown(admin, f"/findings/{fixtures.K['env']}")})
    assert (fixtures.sha(p), os.stat(p).st_mtime_ns) == before
    assert not [f for f in os.listdir(os.path.join(published, "snapshots")) if f.endswith(("-wal", "-shm", "-journal"))]


def test_snapshot_connection_is_read_only(published, settings):
    st = snapshot.current(published, settings.snapshot_cache)
    c = snapshot.connect(st)
    for sql in ("DELETE FROM findings", "CREATE TABLE x(a)", "ATTACH DATABASE '/tmp/x.db' AS x", "INSERT INTO runs(run_id) VALUES('x')"):
        try:
            c.execute(sql)
            assert False, sql
        except sqlite3.Error:
            pass
    c.close()


def test_snapshot_with_missing_tables_and_bad_json(admin, published, settings):
    p = os.path.join(published, "snapshots", "full-2.sqlite")
    db = sqlite3.connect(p)
    db.execute("DROP TABLE domain_posture")
    db.execute("DROP TABLE certificates")
    db.execute("UPDATE run_summary SET json='{bad'")
    db.execute("UPDATE finding_observations SET raw_json='[[[', reference='nope', tags='{\"a\":'")
    db.execute("UPDATE asset_observations SET ips='not json', tech='[1, {\"x\": 2}]'")
    db.execute("UPDATE finding_triage SET secrets_json='\"str\"', items_json='42'")
    db.commit()
    db.close()
    fixtures.write_latest(published, "full-2")
    for path in ("/", "/findings", "/findings/" + fixtures.K["env"], "/assets", "/assets/target.demo.test", "/domains",
                 "/api/v1/overview", "/api/v1/findings/" + fixtures.K["env"], "/api/v1/domains"):
        r = admin.get(path)
        assert r.status_code == 200, (path, r.status_code)
