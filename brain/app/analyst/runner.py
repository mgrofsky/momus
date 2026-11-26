"""The agent loop, and how runs start, record and end. A plain loop this project owns, built on the provider's JSON
call: each step the model returns one tool call or its final answer, both checked against schemas.

  - An invalid answer (not the JSON asked for, an unknown tool, bad tool arguments) gets a corrective note and
    another step, at most MOMUS_ANALYST_MAX_INVALID times in a row; then the run fails cleanly.
  - Limits, all checked in code and recorded with the run: steps per run, output tokens per call, tokens per run,
    tokens per UTC day across runs, and wall-clock time per run. Tokens are written after every step, so a run that
    crashes still counts toward the daily budget.
  - Every run is stored: trigger, requester, the snapshot (by SHA-256), each step (tool, arguments, size of the result,
    tokens, fixed error text), tokens, outcome. Prompts and responses only with MOMUS_ANALYST_DEBUG=1, never in lab mode.
  - One run at a time (checked and claimed under the database's write lock). Runs execute in a background thread;
    the pages poll a fixed path for status.
  - The snapshot is pinned when the run starts (its verified local copy); every tool call opens it again with its own
    query deadline. If that copy is gone or a query runs past its deadline, the run fails cleanly.
"""
import datetime as dt
import json
import sqlite3
import threading
import time

from .. import db as dbm, queries, snapshot
from ..llm import base as llm, factory, redaction
from . import consent, prompts, proposals, tools as toolsm

RUNNING = ("running",)
OUTCOMES = {
    "ok": "Finished.",
    "max-steps": "Stopped: the run used its maximum number of steps.",
    "run-budget": "Stopped: the run used its token budget.",
    "daily-budget": "Stopped: today's token budget is used up.",
    "wall-clock": "Stopped: the run reached its time limit.",
    "invalid-answers": "Stopped: the model gave too many invalid answers in a row.",
    "refused": "Stopped: the model declined to answer.",
    "provider-error": "Stopped: the model provider failed (see the step).",
    "snapshot-changed": "Stopped: the snapshot this run started with can no longer be read.",
    "interrupted": "Stopped: the brain was restarted during the run.",
    "abandoned": ("Stopped: the run was still marked running after its time limit plus one request timeout, so it was "
                  "treated as abandoned and the slot was freed."),
    "error": "Stopped: an unexpected error in the brain (logged by type only).",
}
_threads = []


class RunRefused(Exception):
    """Why a run cannot start (a fixed sentence)."""


def today_start(now=None):
    return dbm.iso(now or dbm.now()).split("T")[0] + "T00:00:00Z"


def tokens_today(db):
    r = db.execute("SELECT COALESCE(SUM(tokens_in + tokens_out), 0) AS n FROM agent_runs WHERE started_at >= ?", (today_start(),)).fetchone()
    return r["n"]


def limits(settings):
    s = settings
    return {"max_steps": s.analyst_max_steps, "max_tokens_per_call": s.analyst_max_tokens_per_call,
            "run_token_budget": s.analyst_run_token_budget, "daily_token_budget": s.analyst_daily_token_budget,
            "run_seconds": s.analyst_run_seconds, "max_proposals": s.analyst_max_proposals, "max_invalid": s.analyst_max_invalid,
            "timeout_seconds": s.analyst_timeout_seconds, "metadata_only": s.analyst_metadata_only}


def interrupt_stale(db):
    """At start-up: a run left 'running' by a stopped brain is marked interrupted."""
    db.execute("UPDATE agent_runs SET status='failed', outcome='interrupted', finished_at=?, error=? WHERE status='running'",
               (dbm.iso(), OUTCOMES["interrupted"]))


def readiness(db, settings):
    """None when a run may start, else the fixed sentence saying why not (no provider, no consent, ...)."""
    why = factory.problem(settings)
    if why:
        return why
    if not consent.current(db, settings):
        return "An admin must first confirm on the Settings page what the analyst sends and to whom."
    try:
        redaction.load()
    except redaction.RedactionUnavailable as e:
        return str(e)
    return None


def start(settings, db, kind, requested_by, trigger, question=None, address=None, provider=None, wait=False, store_prompts=None):
    """Claim the one run slot and start a run. Returns the agent run id. RunRefused with a fixed sentence when it
    cannot start. provider: tests pass one; otherwise the factory builds it from the settings (only here)."""
    assert kind in ("brief", "chat")
    why = readiness(db, settings)
    if why:
        raise RunRefused(why)
    if kind == "chat":
        question = (question or "").strip()
        if not 1 <= len(question) <= prompts.MAX_QUESTION:
            raise RunRefused(f"Type a question of 1 to {prompts.MAX_QUESTION} characters.")
    state = snapshot.current(settings.published_dir, settings.snapshot_cache, settings.snapshot_max_mb * snapshot.MIB)
    if not state.ok:
        raise RunRefused("There is no verified scan snapshot to analyse yet.")
    if tokens_today(db) >= settings.analyst_daily_token_budget:
        raise RunRefused("Today's token budget for the analyst is used up (MOMUS_ANALYST_DAILY_TOKEN_BUDGET).")
    try:
        prov = provider or factory.build(settings)
    except llm.LLMError as e:
        raise RunRefused(str(e)) from None
    from .. import audit
    db.execute("BEGIN IMMEDIATE")
    try:
        # a run still marked running after its time limit plus one request timeout never returned (a provider that
        # kept the answer open, a failure handler that could not write): it is abandoned and the slot freed
        stale = dbm.iso(dbm.now() - dt.timedelta(seconds=settings.analyst_run_seconds + settings.analyst_timeout_seconds))
        db.execute("UPDATE agent_runs SET status='failed', outcome='abandoned', finished_at=?, error=? "
                   "WHERE status='running' AND started_at < ?", (dbm.iso(), OUTCOMES["abandoned"], stale))
        busy = db.execute("SELECT id FROM agent_runs WHERE status='running' LIMIT 1").fetchone()
        if busy:
            raise RunRefused(f"Analyst run {busy['id']} is still running. One run at a time.")
        cur = db.execute("INSERT INTO agent_runs(started_at, trigger, scan_run_id, provider, model, status, kind, requested_by, "
                         "snapshot_sha256, metadata_only, limits_json, question) VALUES(?,?,?,?,?, 'running', ?,?,?,?,?,?)",
                         (dbm.iso(), trigger, state.info.get("run_id"), prov.name, prov.model, kind, requested_by,
                          state.info.get("sha256"), int(settings.analyst_metadata_only), json.dumps(limits(settings)), question))
        run_id = cur.lastrowid
        audit.write(db, requested_by, "analyst-run", target=f"analyst run {run_id}",
                    detail=f"{kind}; trigger {trigger}; provider {prov.name}; snapshot {str(state.info.get('sha256'))[:16]}", address=address)
        db.execute("COMMIT")
    except Exception:
        db.execute("ROLLBACK")
        raise
    store = (settings.analyst_debug and not settings.lab) if store_prompts is None else store_prompts
    args = (settings, run_id, kind, prov, state, question, store)
    if wait:
        execute(*args)
    else:
        t = threading.Thread(target=execute, args=args, name=f"momus-analyst-{run_id}", daemon=True)
        _threads.append(t)
        t.start()
    return run_id


# ---------------------------------------------------------------- one run
class _Run:
    def __init__(self, settings, run_id, kind, provider, state, question, store):
        self.s, self.id, self.kind, self.p, self.state, self.question, self.store = settings, run_id, kind, provider, state, question, store
        self.db = dbm.connect(settings.db_path)
        self.ro = toolsm.app_db_readonly(settings.db_path)
        self.ctx = toolsm.Ctx(state, self.ro, settings.published_dir, settings.analyst_metadata_only,
                              query_seconds=max(5.0, settings.snapshot_query_seconds))
        self.tin = self.tout = 0
        self.tools_called, self.transcript = [], []
        self.instruction_seen = False
        self.t0 = time.monotonic()

    def close(self):
        for c in (self.db, self.ro):
            try:
                c.close()
            except sqlite3.Error:
                pass

    def step_row(self, step, kind, tool=None, arguments=None, result_bytes=None, tin=0, tout=0, error=None):
        self.db.execute("INSERT INTO agent_steps(agent_run_id, step, kind, tool, arguments, result_bytes, tokens_in, tokens_out, error, "
                        "created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                        (self.id, step, kind, tool, None if arguments is None else json.dumps(arguments, ensure_ascii=False)[:2000],
                         result_bytes, tin, tout, error, dbm.iso()))
        self.db.execute("UPDATE agent_runs SET steps=?, tokens_in=?, tokens_out=?, tools_json=? WHERE id=?",
                        (step, self.tin, self.tout, json.dumps(self.tools_called), self.id))

    def message(self, step, role, content):
        if self.store:
            self.db.execute("INSERT INTO agent_messages(agent_run_id, seq, role, content, created_at) VALUES(?,?,?,?,?)",
                            (self.id, step, role, content, dbm.iso()))

    def finish(self, outcome, error=None, result=None, facts=None, drops=None, invalid=0):
        status = "done" if outcome == "ok" else "failed"
        # only while still running: a run abandoned by a later start keeps that outcome even if its thread ends late
        self.db.execute("UPDATE agent_runs SET status=?, outcome=?, finished_at=?, error=?, result_json=?, facts_json=?, dropped_json=?, "
                        "invalid_answers=?, tokens_in=?, tokens_out=?, tools_json=? WHERE id=? AND status='running'",
                        (status, outcome, dbm.iso(), error or (None if outcome == "ok" else OUTCOMES.get(outcome)),
                         None if result is None else json.dumps(result, ensure_ascii=False),
                         None if facts is None else json.dumps(facts, ensure_ascii=False),
                         json.dumps(drops or []), invalid, self.tin, self.tout, json.dumps(self.tools_called), self.id))

    def used(self):
        return self.tin + self.tout

    def loop(self):
        s = self.s
        facts = None
        if self.kind == "brief":
            c = self.ctx.snap()
            try:
                facts = queries.brief_facts(c)
            finally:
                c.close()
        # The outgoing redaction pass runs on each free-text segment: the chat question, each accepted
        # note, every untrusted part of a tool result, every corrective note. The data parts (strict identifiers,
        # vocabularies, dates, versions, addresses: test_analyst_redaction_segments proves it) and the application's own text
        # are not passed through it, so it cannot rewrite an identifier the model must quote back.
        notes = [] if s.analyst_metadata_only else [
            {**n, "body": redaction.outgoing(redaction.field(n["body"], cap=1000))}
            for n in proposals.accepted_notes(self.ro, s.analyst_memory_chars)]
        task = prompts.task_text(self.kind, facts, redaction.outgoing(self.question) if self.question else self.question)
        schema = prompts.turn_schema(self.kind)
        invalid_row = invalid_total = 0
        for step in range(1, s.analyst_max_steps + 1):
            elapsed = time.monotonic() - self.t0
            if elapsed >= s.analyst_run_seconds:
                return self.finish("wall-clock", facts=facts, invalid=invalid_total)
            if self.used() >= s.analyst_run_token_budget:
                return self.finish("run-budget", facts=facts, invalid=invalid_total)
            if tokens_today(self.db) >= s.analyst_daily_token_budget:
                return self.finish("daily-budget", facts=facts, invalid=invalid_total)
            user = prompts.user_text(self.kind, task, notes, self.transcript, s.analyst_metadata_only)
            self.p.timeout_seconds = max(1, int(min(s.analyst_timeout_seconds, s.analyst_run_seconds - elapsed)))
            max_out = max(1, min(s.analyst_max_tokens_per_call, s.analyst_run_token_budget - self.used()))
            self.message(step, "user", user)
            try:
                res = self.p.chat_json(prompts.SYSTEM_TEXT, user, schema, max_out)
            except llm.BadResponse as e:
                tin, tout = llm.tokens_of(e)
                self.tin += tin
                self.tout += tout
                invalid_row += 1
                invalid_total += 1
                self.step_row(step, "invalid", tin=tin, tout=tout, error=str(e))
                if invalid_row > s.analyst_max_invalid:
                    return self.finish("invalid-answers", facts=facts, invalid=invalid_total)
                why = "; ".join(getattr(e, "problems", []) or ["it was not one JSON object of the required form"])
                self.transcript.append({"type": "note", "step": step,
                                        "text": redaction.outgoing(f"Your previous answer was not valid ({why}). Answer again.")})
                continue
            except llm.Refused as e:
                tin, tout = llm.tokens_of(e)
                self.tin += tin
                self.tout += tout
                self.step_row(step, "error", tin=tin, tout=tout, error=str(e))
                return self.finish("refused", error=str(e), facts=facts, invalid=invalid_total)
            except llm.LLMError as e:
                tin, tout = llm.tokens_of(e)
                self.tin += tin
                self.tout += tout
                self.step_row(step, "error", tin=tin, tout=tout, error=str(e))
                return self.finish("provider-error", error=str(e), facts=facts, invalid=invalid_total)
            self.tin += res.tokens_in
            self.tout += res.tokens_out
            self.message(step, "assistant", res.text)
            d = res.data
            if self.used() > s.analyst_run_token_budget:
                self.step_row(step, "error", tin=res.tokens_in, tout=res.tokens_out, error="The run's token budget was exceeded by this answer.")
                return self.finish("run-budget", facts=facts, invalid=invalid_total)
            if d["action"] == "final":
                return self.final(step, d["final"], res, facts, invalid_total)
            # a tool call
            name = d["tool"]
            try:
                args = json.loads(d["arguments"] or "{}")
            except ValueError:
                args = None
            try:
                if not isinstance(args, dict):
                    raise toolsm.ToolError("The arguments must be a JSON object.")
                result = toolsm.call(self.ctx, name, args)
            except toolsm.ToolError as e:
                invalid_row += 1
                invalid_total += 1
                self.step_row(step, "invalid", tool=name if name in toolsm.TOOLS else None, arguments=args if name in toolsm.TOOLS else None,
                              tin=res.tokens_in, tout=res.tokens_out, error=str(e))
                if invalid_row > s.analyst_max_invalid:
                    return self.finish("invalid-answers", facts=facts, invalid=invalid_total)
                self.transcript.append({"type": "note", "step": step, "text": redaction.outgoing(f"Your tool call was refused: {e} Answer again.")})
                continue
            except toolsm.SnapshotGone:
                self.step_row(step, "error", tool=name, arguments=args, tin=res.tokens_in, tout=res.tokens_out,
                              error=OUTCOMES["snapshot-changed"])
                return self.finish("snapshot-changed", facts=facts, invalid=invalid_total)
            invalid_row = 0
            if not self.instruction_seen and proposals.untrusted_reads_like_instructions(result.get("untrusted")):
                self.instruction_seen = True       # recorded for the run; every proposal of the run shows the warning
                self.db.execute("UPDATE agent_runs SET instruction_seen=1 WHERE id=?", (self.id,))
            self.tools_called.append(name)
            size = len(json.dumps(result, ensure_ascii=False, default=str))
            self.step_row(step, "tool", tool=name, arguments=args, result_bytes=size, tin=res.tokens_in, tout=res.tokens_out)
            self.transcript.append({"type": "call", "step": step, "tool": name, "arguments": args})
            self.transcript.append({"type": "result", "step": step, "result": {**result, "untrusted": _outgoing(result.get("untrusted"))}})
        return self.finish("max-steps", facts=facts, invalid=invalid_total)

    def final(self, step, final, res, facts, invalid_total):
        c = self.ctx.snap()
        try:
            known = proposals.Known(queries.known_ids(c))
            cleaned, props, drops = proposals.validate_final(self.kind, final, known, self.s.analyst_max_proposals)
            self.db.execute("BEGIN IMMEDIATE")
            try:
                still = self.db.execute("SELECT status FROM agent_runs WHERE id=?", (self.id,)).fetchone()
                # an abandoned run stores no proposal
                ids = proposals.store(self.db, self.id, props, c, self.state.info.get("sha256")) if still and still[0] == "running" else []
                self.db.execute("COMMIT")
            except Exception:
                self.db.execute("ROLLBACK")
                raise
        except snapshot.Timeout:
            self.step_row(step, "error", tin=res.tokens_in, tout=res.tokens_out, error=OUTCOMES["snapshot-changed"])
            return self.finish("snapshot-changed", facts=facts, invalid=invalid_total)
        finally:
            c.close()
        cleaned["proposal_ids"] = ids
        self.step_row(step, "final", tin=res.tokens_in, tout=res.tokens_out)
        return self.finish("ok", result=cleaned, facts=facts, drops=drops, invalid=invalid_total)


def _outgoing(v, depth=0):
    """The outgoing redaction pass over every string value of an untrusted part (its keys are identifiers)."""
    if isinstance(v, str):
        return redaction.outgoing(v)
    if depth > 50:
        return v
    if isinstance(v, dict):
        return {k: _outgoing(x, depth + 1) for k, x in v.items()}
    if isinstance(v, list):
        return [_outgoing(x, depth + 1) for x in v]
    return v


def execute(settings, run_id, kind, provider, state, question, store):
    r = None
    try:
        r = _Run(settings, run_id, kind, provider, state, question, store)
        r.loop()
    except toolsm.SnapshotGone:
        _fail(settings, run_id, "snapshot-changed")
    except Exception as e:      # never leave a run "running"
        print(f"analyst: run {run_id} failed: {type(e).__name__}", flush=True)
        _fail(settings, run_id, "error")
    finally:
        if r is not None:
            r.close()


def _fail(settings, run_id, outcome):
    """Mark the run failed. It never raises: if the app database cannot be written (locked for its whole
    10 s wait, say), it tries twice more and then logs; the next start frees the slot once the run's time limit plus
    one request timeout has passed."""
    for attempt in range(3):
        db = None
        try:
            db = dbm.connect(settings.db_path)
            db.execute("UPDATE agent_runs SET status='failed', outcome=?, finished_at=?, error=? WHERE id=? AND status='running'",
                       (outcome, dbm.iso(), OUTCOMES[outcome], run_id))
            return
        except Exception as e:
            err = type(e).__name__
        finally:
            if db is not None:
                try:
                    db.close()
                except Exception:
                    pass
    print(f"analyst: run {run_id} could not be marked failed ({err}); the next run frees its slot after the time limit",
          flush=True)


def wait_all(timeout=30):
    """Tests: wait for background runs."""
    for t in list(_threads):
        t.join(timeout)
        if not t.is_alive():
            _threads.remove(t)


# ---------------------------------------------------------------- the automatic brief (scheduler tick)
def auto_brief(settings):
    """Called by the background tick: when MOMUS_ANALYST_AUTO_BRIEF=1 and the snapshot is new, start a brief."""
    if not settings.analyst_auto_brief:
        return None
    db = dbm.connect(settings.db_path)
    try:
        if readiness(db, settings):
            return None
        st = snapshot.current(settings.published_dir, settings.snapshot_cache, settings.snapshot_max_mb * snapshot.MIB)
        if not st.ok:
            return None
        seen = db.execute("SELECT 1 FROM agent_runs WHERE kind='brief' AND trigger='new-snapshot' AND snapshot_sha256=? LIMIT 1",
                          (st.info.get("sha256"),)).fetchone()
        if seen:
            return None
        try:
            return start(settings, db, "brief", "scheduler", "new-snapshot")
        except RunRefused:
            return None
    finally:
        db.close()
