"""The crash log line, links built from snapshot values, lab mode from the brain's
own setting only, and abandoning a job under concurrency and failure."""
import json
import os
import sqlite3
import threading

import fixtures
from app import db as dbm, jobs
from conftest import make_settings
from test_jobs import _lost_job, finish
from test_snapshot_safety import admin_for


def test_crash_log_line_cannot_hold_a_line_break(app, admin, capsys):
    import anyio

    @app.get("/boom/{x}")
    def boom(x: str):
        raise RuntimeError("boom")
    cookie = admin.c.cookies.get("momus_session")
    path = "/boom/a\nbrain: FORGED LINE\r\nanother\u2028x"           # what percent-decoding %0A, %0D and %E2%80%A8 gives

    async def run():
        scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "GET", "scheme": "http",
                 "path": path, "raw_path": b"/boom/a%0Abrain:%20FORGED%20LINE%0D%0Aanother%E2%80%A8x", "query_string": b"",
                 "root_path": "", "headers": [(b"host", b"testserver"), (b"cookie", f"momus_session={cookie}".encode())],
                 "client": ("127.0.0.1", 1234), "server": ("testserver", 80)}
        msgs = []

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(m):
            msgs.append(m)
        try:
            await app(scope, receive, send)
        except RuntimeError:
            pass                                   # Starlette re-raises after the 500 response was sent
        return msgs
    capsys.readouterr()
    msgs = anyio.run(run)
    assert [m for m in msgs if m["type"] == "http.response.start"][0]["status"] == 500
    out = capsys.readouterr().out
    lines = [ln for ln in out.splitlines() if ln]
    assert len(lines) == 1, lines
    assert lines[0].startswith("brain: error on GET /boom/a\\nbrain: FORGED LINE\\r\\nanother\\u2028x")
    assert "RuntimeError" in lines[0]


def _hostile_values(pub):
    p = os.path.join(pub, "snapshots", "full-2.sqlite")
    db = sqlite3.connect(p)
    db.execute("INSERT INTO asset_observations(run_id, hostname, apex, class, title) VALUES('full-2', '../settings', 'demo.test', 'owned', 'dots')")
    db.execute("INSERT INTO asset_observations(run_id, hostname, apex, class, title) VALUES('full-2', 'ok-host.demo.test', 'demo.test', 'owned', 'fine')")
    db.execute("INSERT INTO findings VALUES('../../logout', 'h', 'demo.test', 'nuclei', 'evil-key', 80, 'Evil key', 'high', '', 'full-2', 'full-2', 'open', NULL)")
    db.execute("INSERT INTO finding_observations(run_id, finding_key, band, state, score) VALUES('full-2', '../../logout', 'High', 'new', 99)")
    db.commit()
    db.close()
    fixtures.write_latest(pub, "full-2")


def test_links_are_built_only_from_strict_values(admin, published):
    _hostile_values(published)
    a = admin.get("/assets").text
    assert 'href="/assets/ok-host.demo.test"' in a and 'href="/assets/target.demo.test"' in a
    assert "/assets/../settings" not in a and "/assets/..%2Fsettings" not in a and "<code>../settings</code>" in a
    f = admin.get("/findings?state=open").text
    assert "Evil key" in f and "/findings/../../logout" not in f and 'href="/findings/' + fixtures.K["env"] + '"' in f
    for path in ("/", "/findings", "/assets", "/runs"):
        hrefs = __import__("re").findall(r'href="([^"]+)"', admin.get(path).text)
        assert not [h for h in hrefs if ".." in h], (path, hrefs)


def test_lab_mode_comes_only_from_the_brain_setting(admin, published, settings):
    # the fixture heartbeat says lab_mode true with a lab range; the brain's own MOMUS_LAB is off
    page = admin.get("/scope").text
    assert "Lab mode: the scanner is limited" not in page
    assert "heartbeat says lab mode is on, but this brain&#39;s MOMUS_LAB setting says off" in page
    assert jobs.is_lab(settings, {"lab_mode": True}) is False
    r = admin.post("/scope/domains", data={"name": "target.demo.test", "statement": "yes", "kind": "lab"})
    assert "err=" in r.headers["location"]                              # no lab targets: the brain is not in lab mode
    assert admin.get("/api/v1/scope").json()["lab"] is False


def test_lab_range_comes_only_from_the_brain_setting(tmp_path):
    app, s, b = admin_for(tmp_path, lab=True, lab_cidr="10.89.47.0/24")
    fixtures.build_published(s.published_dir)
    with open(os.path.join(s.published_dir, "scanner.json"), "w") as fh:
        json.dump({"updated_at": dbm.iso(), "state": "idle", "lab_mode": True, "lab_cidr": "192.0.2.0/24"}, fh)
    page = b.get("/").text
    assert "(10.89.47.0/24)" in page and "(192.0.2.0/24)" not in page and "different lab range" in page
    assert jobs.lab_cidr(s, {"lab_mode": True, "lab_cidr": "192.0.2.0/24"}) == ("10.89.47.0/24", None)
    with open(os.path.join(s.published_dir, "scanner.json"), "w") as fh:
        json.dump({"updated_at": dbm.iso(), "state": "idle", "lab_mode": True, "lab_cidr": "10.89.47.0/24"}, fh)
    page = b.get("/").text
    assert "Lab mode: the scanner is limited" in page and "different lab range" not in page and "heartbeat says lab mode" not in page


def test_lab_mode_unset_brain_ignores_a_lab_heartbeat_for_jobs(tmp_path):
    s = make_settings(tmp_path, lab_cidr="")
    assert jobs.lab_cidr(s, {"lab_mode": True, "lab_cidr": "10.89.47.0/24"})[0] is None


# ---------------------------------------------------------------- abandoning a job
def test_two_abandon_requests_at_once_leave_one_consistent_result(admin, settings, app):
    jid = _lost_job(admin, settings)
    from conftest import Browser
    other = Browser(app)
    other.c.cookies.update(admin.c.cookies)
    other.csrf = admin.csrf
    results = []
    gate = threading.Barrier(2)

    def go(b):
        gate.wait()
        results.append(b.api_post("/api/v1/jobs/abandon", json={"job_id": jid, "confirm": True}).status_code)
    ts = [threading.Thread(target=go, args=(b,)) for b in (admin, other)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert sorted(results) == [200, 409]
    conn = dbm.connect(settings.db_path)
    n = conn.execute("SELECT COUNT(*) FROM audit_log WHERE action='job-abandon'").fetchone()[0]
    row = conn.execute("SELECT abandoned_by FROM jobs WHERE id=?", (jid,)).fetchone()[0]
    conn.close()
    assert n == 1 and row == "admin"
    assert os.path.exists(os.path.join(settings.jobs_dir, jid + jobs.ABANDONED_SUFFIX))
    assert not os.path.exists(os.path.join(settings.jobs_dir, jid + ".json"))
    assert not [f for f in os.listdir(settings.jobs_dir) if ".tmp-" in f]


def test_a_job_file_that_cannot_be_removed_after_the_commit_stays_behind_its_marker(admin, settings):
    # the order is marker, commit, then remove the job file. A job file that cannot be removed
    # (a directory at that name) does not undo the abandon: the commit came first, the marker keeps the scanner from
    # running the job, and the leftover is looked at again with the finished files.
    jid = _lost_job(admin, settings)
    p = os.path.join(settings.jobs_dir, jid + ".json")
    os.unlink(p)
    os.makedirs(os.path.join(p, "x"))                    # a directory where the job file was: unlink fails
    r = admin.post("/runs/abandon", data={"job_id": jid, "confirm": "yes"})
    assert "err=" not in r.headers["location"]
    assert os.path.lexists(os.path.join(settings.jobs_dir, jid + jobs.ABANDONED_SUFFIX))
    assert os.path.isdir(p)
    conn = dbm.connect(settings.db_path)
    assert conn.execute("SELECT abandoned_at FROM jobs WHERE id=?", (jid,)).fetchone()[0] is not None
    assert conn.execute("SELECT COUNT(*) FROM audit_log WHERE action='job-abandon'").fetchone()[0] == 1
    conn.close()
    assert jobs.in_flight(settings) is None
    assert not [f for f in os.listdir(settings.jobs_dir) if ".tmp-" in f]


def test_abandon_does_not_follow_planted_links(admin, settings, tmp_path):
    jid = _lost_job(admin, settings)
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / "victim.json"
    victim.write_text("keep")
    marker = os.path.join(settings.jobs_dir, jid + jobs.ABANDONED_SUFFIX)
    os.symlink(str(outside / "marker-target"), marker)                 # a link planted where the marker goes
    p = os.path.join(settings.jobs_dir, jid + ".json")
    os.unlink(p)
    os.symlink(str(victim), p)                                         # and the job file replaced by a link
    r = admin.post("/runs/abandon", data={"job_id": jid, "confirm": "yes"})
    assert "err=" not in r.headers["location"], r.headers["location"]
    assert victim.read_text() == "keep" and not (outside / "marker-target").exists()
    assert os.path.isfile(marker) and not os.path.islink(marker) and not os.path.lexists(p)


def test_abandon_validates_the_id_before_building_a_path(admin, settings):
    for bad in ("../x", "a/b", "x\n", "", ".hidden", "UP"):
        r = admin.api_post("/api/v1/jobs/abandon", json={"job_id": bad, "confirm": True})
        assert r.status_code in (409, 422), bad
    assert jobs.abandonable(settings, None, "ok-id\n") == "Not a job id."
    finish(settings, "done-1", "done", "full")
    assert "already ended" in jobs.abandonable(settings, None, "done-1")
