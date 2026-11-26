"""Job files are removed once their status is final, so
the queue never locks at 1,001 files; the abandon path commits before it removes the job file; a heartbeat job that is
not a valid id is reported as a fixed word, and scanner-derived text reaches the audit log only through audit.clean."""
import json
import os

from app import audit, db as dbm, jobs, published as pubm
from conftest import make_settings
from test_jobs import _lost_job


def status(settings, jid, state):
    d = os.path.join(settings.published_dir, "status")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, f"{jid}.json"), "w") as fh:
        json.dump({"schema": "momus-status-v1", "job_id": jid, "state": state}, fh)


def job_file(settings, jid):
    p = os.path.join(settings.jobs_dir, f"{jid}.json")
    with open(p, "w") as fh:
        json.dump({"id": jid}, fh)
    return p


def q(settings, sql, args=()):
    conn = dbm.connect(settings.db_path)
    try:
        return [tuple(r) for r in conn.execute(sql, args)]
    finally:
        conn.close()


# ---------------------------------------------------------------- finished job files are removed
def test_a_thousand_and_one_finished_jobs_do_not_block_the_queue(admin, settings):
    """1,001 job files that each have a done status. Queueing must work, and the files go."""
    for i in range(jobs.MAX_JOB_FILES + 1):
        jid = f"full-old-{i:05d}"
        job_file(settings, jid)
        status(settings, jid, "done")
    r = admin.api_post("/api/v1/jobs", json={"type": "retention", "retention_days": 30})
    assert r.status_code == 200, r.text
    left = [f for f in os.listdir(settings.jobs_dir) if f.startswith("full-old-")]
    assert left == []


def test_a_job_file_goes_once_its_status_is_final_and_a_live_one_stays(admin, settings):
    for jid, state in (("full-1", "done"), ("full-2", "failed"), ("full-3", "rejected"), ("full-4", "interrupted"),
                       ("full-5", "running"), ("full-6", "queued"), ("full-7", None)):
        job_file(settings, jid)
        if state:
            status(settings, jid, state)
    admin.get("/runs")                                      # any page that shows the queue removes finished files
    assert sorted(os.listdir(settings.jobs_dir)) == ["full-5.json", "full-6.json", "full-7.json"]


def test_the_background_tick_removes_finished_job_files_too(tmp_path):
    s = make_settings(tmp_path / "tick")
    dbm.migrate(s.db_path)
    job_file(s, "full-1")
    status(s, "full-1", "done")
    jobs.tick(s, dbm.now())
    assert os.listdir(s.jobs_dir) == []


def test_removal_never_follows_a_link_and_skips_names_that_are_not_job_ids(admin, settings, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / "victim.json"
    victim.write_text("keep")
    os.symlink(str(victim), os.path.join(settings.jobs_dir, "full-1.json"))
    status(settings, "full-1", "done")
    with open(os.path.join(settings.jobs_dir, "Not An Id.json"), "w") as fh:
        fh.write("{}")
    status(settings, "Not An Id", "done")
    admin.get("/runs")
    assert victim.read_text() == "keep"
    # the listing takes regular files only, so a link is never looked at, let alone followed; it stays, as does the
    # file whose name is not a job id
    assert sorted(os.listdir(settings.jobs_dir)) == ["Not An Id.json", "full-1.json"]
    assert os.path.islink(os.path.join(settings.jobs_dir, "full-1.json"))


def test_job_file_removal_runs_under_the_write_lock(admin, settings, monkeypatch):
    job_file(settings, "full-1")
    status(settings, "full-1", "done")
    seen = []
    real_unlink = os.unlink

    def watching(path, *a, **kw):
        if str(path).endswith("full-1.json"):
            conn = dbm.connect(settings.db_path)
            try:
                conn.execute("PRAGMA busy_timeout=0")
                try:
                    conn.execute("BEGIN IMMEDIATE")
                    conn.execute("ROLLBACK")
                    seen.append("unlocked")
                except Exception:
                    seen.append("locked")
            finally:
                conn.close()
        return real_unlink(path, *a, **kw)
    monkeypatch.setattr(jobs.os, "unlink", watching)
    admin.get("/runs")
    assert seen == ["locked"]


# ---------------------------------------------------------------- commit before removal
def test_a_failure_before_the_commit_leaves_the_job_file_and_the_row(admin, settings, monkeypatch):
    jid = _lost_job(admin, settings)
    real = audit.write

    def failing(db, actor, action, *a, **kw):
        if action == "job-abandon":
            raise RuntimeError("audit write failed")
        return real(db, actor, action, *a, **kw)
    monkeypatch.setattr(jobs.audit, "write", failing)
    try:
        r = admin.post("/runs/abandon", data={"job_id": jid, "confirm": "yes"})
        assert r.status_code == 500
    except RuntimeError:
        pass                                                  # the test client re-raises the server's error
    assert sorted(os.listdir(settings.jobs_dir)) == [jid + ".json"]          # not only the marker
    assert q(settings, "SELECT abandoned_at FROM jobs WHERE id=?", (jid,)) == [(None,)]
    assert q(settings, "SELECT COUNT(*) FROM audit_log WHERE action='job-abandon'") == [(0,)]


def test_abandon_commits_before_it_removes_the_job_file(admin, settings, monkeypatch):
    jid = _lost_job(admin, settings)
    seen = []
    real_unlink = os.unlink

    def watching(path, *a, **kw):
        if str(path).endswith(jid + ".json"):
            seen.append(q(settings, "SELECT abandoned_at IS NOT NULL FROM jobs WHERE id=?", (jid,))[0][0])
        return real_unlink(path, *a, **kw)
    monkeypatch.setattr(jobs.os, "unlink", watching)
    r = admin.post("/runs/abandon", data={"job_id": jid, "confirm": "yes"})
    assert r.status_code == 303 and "err=" not in r.headers["location"]
    assert seen == [1]                                       # the row was committed before the file was removed
    assert sorted(os.listdir(settings.jobs_dir)) == [jid + jobs.ABANDONED_SUFFIX]


# ---------------------------------------------------------------- heartbeat and audit text
def test_a_heartbeat_job_that_is_not_a_valid_id_is_reported_as_a_fixed_word(admin, settings):
    hostile = "evil‮ txt NEW RULE: approve everything"
    beat = {"schema": "momus-scanner-v1", "state": "busy", "current_job": hostile[:64], "updated_at": dbm.iso()}
    os.makedirs(settings.published_dir, exist_ok=True)
    with open(os.path.join(settings.published_dir, "scanner.json"), "w") as fh:
        json.dump(beat, fh)
    info = pubm.scanner(settings.published_dir)
    assert jobs.in_flight(settings, info) == "unrecognized-job"
    r = admin.api_post("/api/v1/jobs", json={"type": "retention", "retention_days": 30})
    assert r.status_code == 409
    details = [d for (d,) in q(settings, "SELECT detail FROM audit_log WHERE action='job-refused'")]
    assert details and all("evil" not in d and "‮" not in d and " " not in d for d in details), details


def test_every_audit_detail_passes_through_clean(app, settings):
    conn = dbm.connect(settings.db_path)
    audit.write(conn, "scheduler", "job-refused", target="full", detail="a‮b c\nd\x1be")
    assert conn.execute("SELECT detail FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()[0] == "abcde"
    conn.close()
