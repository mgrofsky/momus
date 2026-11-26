"""Helpers for the analyst tests: lab settings with a test provider, the admin's confirmation, scripted answers, and
snapshots whose stored text is changed after they are built (to plant instructions or secrets)."""
import json
import os
import sqlite3

import fixtures
from conftest import make_settings
from app import db as dbm
from app.analyst import consent, prompts, runner
from app.llm.mock import MockProvider

KEYS = fixtures.K


def lab_settings(tmp_path, provider="mock", **kw):
    base = dict(lab=True, lab_cidr="10.89.47.0/24", analyst_provider=provider, analyst_model=f"{provider}-1")
    base.update(kw)
    return make_settings(tmp_path, **base)


def confirm(settings, actor="admin"):
    db = dbm.connect(settings.db_path)
    try:
        consent.confirm(db, settings, actor, "127.0.0.1")
    finally:
        db.close()


def tool(name, args=None, kind="brief"):
    return {"action": "tool", "tool": name, "arguments": json.dumps(args or {}), "final": prompts.EMPTY_FINAL[kind]}


def final(kind="brief", **kw):
    f = dict(prompts.EMPTY_FINAL[kind])
    f.update(kw)
    return {"action": "final", "tool": "none", "arguments": "{}", "final": f}


def run(settings, provider, kind="brief", question=None, actor="admin", **kw):
    """Start a run synchronously; return its row (dict) with steps."""
    db = dbm.connect(settings.db_path)
    try:
        rid = runner.start(settings, db, kind, actor, "request", question=question, provider=provider, wait=True, **kw)
        return row(settings, rid)
    finally:
        db.close()


def row(settings, rid):
    db = dbm.connect(settings.db_path)
    try:
        r = dict(db.execute("SELECT * FROM agent_runs WHERE id=?", (rid,)).fetchone())
        r["steps_rows"] = [dict(x) for x in db.execute("SELECT * FROM agent_steps WHERE agent_run_id=? ORDER BY id", (rid,))]
        r["proposals_rows"] = [dict(x) for x in db.execute("SELECT * FROM proposals WHERE agent_run_id=? ORDER BY id", (rid,))]
        for k in ("result_json", "facts_json", "dropped_json", "tools_json", "limits_json"):
            r[k] = json.loads(r[k]) if r[k] else None
        return r
    finally:
        db.close()


def app_db(settings):
    return dbm.connect(settings.db_path)


def edit_snapshot(pub, sql_args, run=None):
    """Change the published snapshot's stored text after it was built, then rewrite latest.json with the new hash.
    sql_args: [(sql, args)]."""
    run = run or "full-2"
    p = os.path.join(pub, "snapshots", f"{run}.sqlite")
    c = sqlite3.connect(p)
    for sql, args in sql_args:
        c.execute(sql, args)
    c.commit()
    c.close()
    fixtures.write_latest(pub, run)


def mock(script=None):
    return MockProvider("mock-1", script=script)
