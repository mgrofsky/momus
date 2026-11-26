"""Inputs that must be read strictly: the listen port, the audit log's "before" cursor, and the API's confirmation
that a job may be abandoned."""
import os
import subprocess
import sys

import pytest

from app import audit, config, jobs
from app import db as dbm
from test_jobs import _lost_job

BRAIN = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ---------------------------------------------------------------- MOMUS_PORT
def test_an_empty_or_unset_port_means_the_default():
    assert config.listen_port({}) == 8080
    assert config.listen_port({"MOMUS_PORT": ""}) == 8080
    assert config.listen_port({"MOMUS_PORT": "  "}) == 8080
    assert config.listen_port({"MOMUS_PORT": "9090"}) == 9090


@pytest.mark.parametrize("bad", ["http", "80.5", "-1", "0", "65536", "١٢", "8080x"])
def test_a_port_that_is_not_a_port_number_is_refused_with_one_line(bad):
    with pytest.raises(ValueError) as e:
        config.listen_port({"MOMUS_PORT": bad})
    assert "\n" not in str(e.value) and "MOMUS_PORT" in str(e.value)


def test_run_py_stops_with_one_line_and_no_traceback_on_a_bad_port(tmp_path):
    env = {"PATH": os.environ.get("PATH", ""), "MOMUS_PORT": "eighty", "PYTHONDONTWRITEBYTECODE": "1",
           "HOME": str(tmp_path)}
    p = subprocess.run([sys.executable, "-B", os.path.join(BRAIN, "run.py")], env=env, cwd=str(tmp_path),
                       capture_output=True, text=True, timeout=60)
    out = (p.stdout + p.stderr).strip()
    assert p.returncode == 2, out
    assert out.splitlines() == ["brain: MOMUS_PORT must be a whole number from 1 to 65535, or empty for 8080"], out


# ---------------------------------------------------------------- the audit log's "before" cursor
@pytest.mark.parametrize("bad", ["²", "١", "1²", "9" * 19, "-1", " 5", "1e3"])
def test_a_before_cursor_that_is_not_ascii_digits_is_ignored(admin, bad):
    r = admin.get("/audit", params={"before": bad})
    assert r.status_code == 200
    assert audit.before_id(bad) is None


def test_a_valid_before_cursor_still_pages(admin, settings):
    conn = dbm.connect(settings.db_path)
    for i in range(3):
        conn.execute("INSERT INTO audit_log(at, actor, action, target) VALUES(?,?,?,?)", (dbm.iso(), "admin", "note-add", f"cur-{i}"))
    top = conn.execute("SELECT MAX(id) FROM audit_log").fetchone()[0]
    conn.close()
    assert audit.before_id(str(top)) == top and audit.before_id(top) == top
    page = admin.get("/audit", params={"before": str(top)}).text
    assert "cur-1" in page and "cur-2" not in page


def test_the_api_refuses_a_before_cursor_too_large_for_the_database(admin):
    assert admin.get("/api/v1/audit", params={"before": "9" * 19}).status_code == 422


# ---------------------------------------------------------------- abandon over the API
@pytest.mark.parametrize("loose", ["yes", "true", 1, "1", "on"])
def test_the_api_abandon_needs_a_real_true(admin, settings, loose):
    jid = _lost_job(admin, settings)
    r = admin.api_post("/api/v1/jobs/abandon", json={"job_id": jid, "confirm": loose})
    assert r.status_code == 422
    assert os.path.exists(os.path.join(settings.jobs_dir, jid + ".json"))
    r = admin.api_post("/api/v1/jobs/abandon", json={"job_id": jid, "confirm": True})
    assert r.status_code == 200 and not os.path.exists(os.path.join(settings.jobs_dir, jid + ".json"))
    assert jobs.in_flight(settings) is None


# ---------------------------------------------------------------- the ownership statement over the API
@pytest.mark.parametrize("loose", ["yes", "true", 1, "1", "on"])
def test_the_api_ownership_statement_needs_a_real_true(admin, settings, loose):
    r = admin.api_post("/api/v1/scope/domains", json={"name": "strict.example.test", "statement": loose})
    assert r.status_code == 422
    conn = dbm.connect(settings.db_path)
    n = conn.execute("SELECT COUNT(*) FROM domains WHERE name='strict.example.test'").fetchone()[0]
    conn.close()
    assert n == 0
    r = admin.api_post("/api/v1/scope/domains", json={"name": "strict.example.test", "statement": True})
    assert r.status_code == 200 and r.json()["name"] == "strict.example.test"
