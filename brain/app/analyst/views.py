"""Data for the analyst's pages and API, shared so both show the same thing. Every count and list shown as fact on
the brief comes from facts_json, which the application computed from the snapshot (queries.brief_facts); the model's
text is shown separately, labeled as the model's, as plain escaped text."""
import json

from .. import marks as marksm, queries
from ..llm import factory
from . import consent, proposals, runner

RUNS_PER_PAGE = 20


def _j(v, default):
    try:
        return json.loads(v) if v else default
    except ValueError:
        return default


def run_row(r):
    d = dict(r)
    d["result"] = _j(d.pop("result_json", None), None)
    d["facts"] = _j(d.pop("facts_json", None), None)
    d["dropped"] = _j(d.pop("dropped_json", None), [])
    d["tools"] = _j(d.pop("tools_json", None), [])
    d["limits"] = _j(d.pop("limits_json", None), {})
    d["outcome_text"] = runner.OUTCOMES.get(d.get("outcome") or "", "Running." if d.get("status") == "running" else "")
    return d


def state(c):
    s = c.settings
    return {"provider": s.analyst_provider, "provider_label": factory.label(s), "model": s.analyst_model or None,
            "problem": runner.readiness(c.db, s), "metadata_only": s.analyst_metadata_only, "auto_brief": s.analyst_auto_brief,
            "running": _running(c.db), "lab": s.lab}


def _running(db):
    r = db.execute("SELECT id, kind, started_at, steps FROM agent_runs WHERE status='running' ORDER BY id DESC LIMIT 1").fetchone()
    return dict(r) if r else None


def latest_brief(db):
    r = db.execute("SELECT * FROM agent_runs WHERE kind='brief' AND status='done' ORDER BY id DESC LIMIT 1").fetchone()
    return run_row(r) if r else None


def recent_chats(db, n=5):
    return [run_row(r) for r in db.execute("SELECT * FROM agent_runs WHERE kind='chat' ORDER BY id DESC LIMIT ?", (n,))]


def runs_page(db, page=1):
    p = queries.page_number(page)
    rows = [run_row(r) for r in db.execute("SELECT * FROM agent_runs ORDER BY id DESC LIMIT ? OFFSET ?",
                                           (RUNS_PER_PAGE + 1, (p - 1) * RUNS_PER_PAGE))]
    return rows[:RUNS_PER_PAGE], p, len(rows) > RUNS_PER_PAGE


def page(c, runs_page_no=1):
    rows, p, more = runs_page(c.db, runs_page_no)
    pend = proposals.pending(c.db)
    return {"state": state(c), "brief": latest_brief(c.db), "pending": pend, "decided": proposals.recent_decided(c.db),
            "chats": recent_chats(c.db), "runs": rows, "runs_page": p, "runs_more": more}


def run_detail(c, run_id):
    r = c.db.execute("SELECT * FROM agent_runs WHERE id=?", (run_id,)).fetchone()
    if not r:
        return None
    d = run_row(r)
    d["steps"] = [dict(x) for x in c.db.execute("SELECT step, kind, tool, arguments, result_bytes, tokens_in, tokens_out, error, created_at "
                                                "FROM agent_steps WHERE agent_run_id=? ORDER BY id LIMIT 200", (run_id,))]
    d["proposals"] = [dict(x) for x in c.db.execute("SELECT id, kind, finding_key, status FROM proposals WHERE agent_run_id=? ORDER BY id",
                                                    (run_id,))]
    d["messages"] = [dict(x) for x in c.db.execute("SELECT seq, role, content FROM agent_messages WHERE agent_run_id=? ORDER BY id LIMIT 200",
                                                   (run_id,))]
    return d


def current_sha(c):
    """The SHA-256 of the snapshot this request reads (the value an accept must have been shown)."""
    return (c.snap_state.info or {}).get("sha256") if c.snap_state.ok else None


def proposal_detail(c, pid):
    """One proposal with what the page shows and binds the accept to: the finding's current evidence, its fingerprint
    and the snapshot's SHA-256 (shown_*), whether it is out of date and why, and the run's instruction flag."""
    p = proposals.get(c.db, pid)
    if not p:
        return None
    out = {"proposal": p, "finding": None, "evidence_changed": False, "mark": None,
           "shown_evidence_fp": "", "shown_snapshot_sha256": current_sha(c) or "",
           "out_of_date": proposals.out_of_date(c.snap, p) if p["finding_key"] else None}
    r = c.db.execute("SELECT instruction_seen FROM agent_runs WHERE id=?", (p["agent_run_id"],)).fetchone()
    out["run_instruction_warning"] = bool(r and r["instruction_seen"])
    if p["finding_key"] and c.snap is not None:
        d = queries.finding(c.snap, p["finding_key"])
        if d:
            out["finding"] = d
            out["shown_evidence_fp"] = d["evidence_fp"]
            out["evidence_changed"] = bool(p["evidence_fp"]) and p["evidence_fp"] != d["evidence_fp"]
            out["mark"] = marksm.with_staleness(c.db, c.snap).get(p["finding_key"])
            # recomputed from the stored text now, so the hint also covers text that changed after the proposal
            out["instruction_warning"] = bool(p["instruction_warning"]) or proposals.reads_like_instructions(*proposals.finding_texts(d))
    elif p["finding_key"]:
        out["out_of_date"] = "there is no verified scan snapshot to compare it with"
    out.setdefault("instruction_warning", bool(p["instruction_warning"]))
    return out


def settings_info(c):
    """The Settings page's analyst section (read-only configuration, usage today, and the confirmation)."""
    s = c.settings
    return {"provider": s.analyst_provider, "provider_label": factory.label(s), "model": s.analyst_model or None,
            "region": s.analyst_region or None, "key": ("set (" + s.analyst_key_source + ")") if s.analyst_key else "not set",
            "problem": factory.problem(s), "limits": runner.limits(s), "auto_brief": s.analyst_auto_brief,
            "debug": s.analyst_debug and not s.lab, "debug_requested": s.analyst_debug, "memory_chars": s.analyst_memory_chars,
            "tokens_today": runner.tokens_today(c.db), "runs_today": c.db.execute(
                "SELECT COUNT(*) AS n FROM agent_runs WHERE started_at >= ?", (runner.today_start(),)).fetchone()["n"],
            "statement": consent.statement(s), "consent": consent.stored(c.db), "consent_current": consent.current(c.db, s)}
