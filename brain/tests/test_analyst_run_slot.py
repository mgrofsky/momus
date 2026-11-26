"""A run that never returns cannot hold the one-run slot for ever, the failure handler cannot
leave the slot held by raising, and every provider call has a hard overall deadline."""
import datetime as dt
import sqlite3
import time

import pytest

from analyst_helpers import app_db, final, mock, run
from app import db as dbm
from app.analyst import runner
from app.llm import base
from test_analyst_proposals import admin, app, settings  # noqa: F401  (fixtures)


def running_row(settings, age_seconds):
    db = app_db(settings)
    started = dbm.iso(dbm.now() - dt.timedelta(seconds=age_seconds))
    rid = db.execute("INSERT INTO agent_runs(started_at, trigger, provider, model, status, kind, requested_by) "
                     "VALUES(?, 'request', 'mock', 'mock-1', 'running', 'brief', 'admin')", (started,)).lastrowid
    return rid


def test_a_run_still_running_after_its_limit_and_one_timeout_is_abandoned_when_the_next_starts(settings, app):
    limit = settings.analyst_run_seconds + settings.analyst_timeout_seconds
    old = running_row(settings, limit + 30)
    r = run(settings, mock([final("brief")]))                          # not refused for ever
    assert r["outcome"] == "ok"
    st, outcome, err = app_db(settings).execute("SELECT status, outcome, error FROM agent_runs WHERE id=?", (old,)).fetchone()
    assert (st, outcome) == ("failed", "abandoned") and err == runner.OUTCOMES["abandoned"]


def test_a_run_within_its_limit_still_holds_the_slot(settings, app):
    running_row(settings, 5)
    with pytest.raises(runner.RunRefused):
        run(settings, mock([final("brief")]))


def test_a_late_finish_of_an_abandoned_run_changes_nothing(settings, app):
    limit = settings.analyst_run_seconds + settings.analyst_timeout_seconds
    old = running_row(settings, limit + 30)
    run(settings, mock([final("brief")]))                               # marks the old one abandoned
    r = runner._Run.__new__(runner._Run)                               # the old run's thread, finishing late
    r.db, r.id, r.tin, r.tout, r.tools_called = dbm.connect(settings.db_path), old, 7, 7, []
    r.finish("ok", result={"top": []})
    assert tuple(app_db(settings).execute("SELECT status, outcome FROM agent_runs WHERE id=?", (old,)).fetchone()) == ("failed", "abandoned")


def test_the_failure_handler_cannot_raise_out_of_a_run(settings, app, monkeypatch, capsys):
    """The loop fails, and so does every attempt to mark the run failed (the app database stays locked): execute()
    returns, logs, and the slot is freed by the next start after the run's limit (test above)."""
    import inspect
    real_connect = dbm.connect

    def connect(path):
        if any(f.function == "_fail" for f in inspect.stack()):
            raise sqlite3.OperationalError("database is locked")
        return real_connect(path)

    def boom(self):
        raise RuntimeError("a bug in the loop")
    monkeypatch.setattr(runner._Run, "loop", boom)
    monkeypatch.setattr(runner.dbm, "connect", connect)
    db = real_connect(settings.db_path)
    try:
        runner.start(settings, db, "brief", "admin", "request", provider=mock([final("brief")]), wait=True)   # must not raise
    finally:
        db.close()
    assert "could not be marked failed" in capsys.readouterr().out


def test_each_provider_call_has_a_hard_overall_deadline():
    class Dripping(base.Provider):
        name = "dripping"

        def _call(self, system, user, schema, max_tokens):
            time.sleep(6)                                              # an answer that keeps trickling in past the timeout
            return "{}", 1, 1
    p = Dripping("m", 1)
    t0 = time.monotonic()
    with pytest.raises(base.Timeout):
        p.chat_json("s", "u", {"type": "object"}, 10)
    assert time.monotonic() - t0 < 4
