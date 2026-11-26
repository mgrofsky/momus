"""The agent loop with scripted mock runs: a normal brief, an invalid answer then a valid one, too many invalid answers,
each limit, an unknown tool, bad tool arguments, and a provider error mid-run. Each ends in a recorded, clean state."""
import json
import threading

import pytest

import fixtures
from analyst_helpers import KEYS, app_db, confirm, final, lab_settings, mock, row, run, tool
from app import db as dbm
from app.analyst import prompts, runner
from app.llm import base
from app.web import create_app


@pytest.fixture
def settings(tmp_path):
    return lab_settings(tmp_path)


@pytest.fixture
def ready(settings, capsys):
    fixtures.build_published(settings.published_dir, hostile=False)
    create_app(settings, start_background=False)
    confirm(settings)
    return settings


def clean(r):
    """A run that ended: not running, an outcome, a finish time, every step recorded with its kind."""
    assert r["status"] in ("done", "failed") and r["outcome"] in runner.OUTCOMES and r["finished_at"]
    assert r["steps"] == (r["steps_rows"][-1]["step"] if r["steps_rows"] else 0)
    assert r["tokens_in"] == sum(s["tokens_in"] for s in r["steps_rows"])
    assert r["tokens_out"] == sum(s["tokens_out"] for s in r["steps_rows"])
    assert r["limits_json"]["max_steps"] >= 1 and r["snapshot_sha256"]
    return r


def test_a_normal_brief(ready):
    p = mock([tool("search_findings", {"state": "open"}), tool("diff_runs", {"run_a": "full-1", "run_b": "full-2"}),
              final("brief", top=[{"title": "Env file", "reason": "Credentials exposed.", "references": [{"kind": "finding", "id": KEYS["env"]}]}],
                    change_commentary="One new finding since the previous run.",
                    remediation=[{"cause": "Files served from the web root", "advice": "Remove them.",
                                  "references": [{"kind": "finding", "id": KEYS["env"]}, {"kind": "host", "id": "target.demo.test"},
                                                 {"kind": "run", "id": "full-2"}]}])])
    r = clean(run(ready, p))
    assert (r["status"], r["outcome"]) == ("done", "ok")
    assert [s["kind"] for s in r["steps_rows"]] == ["tool", "tool", "final"]
    assert [s["tool"] for s in r["steps_rows"][:2]] == ["search_findings", "diff_runs"] and r["tools_json"] == ["search_findings", "diff_runs"]
    assert json.loads(r["steps_rows"][0]["arguments"]) == {"state": "open"} and r["steps_rows"][0]["result_bytes"] > 100
    assert r["result_json"]["top"][0]["title"] == "Env file" and r["dropped_json"] == []
    assert r["facts_json"]["run_id"] == "full-2" and r["facts_json"]["previous_run_id"] == "full-1"
    assert r["trigger"] == "request" and r["requested_by"] == "admin" and r["kind"] == "brief"
    # three calls; each prompt is the system text plus the task, the tools and the transcript so far
    assert len(p.prompts) == 3 and all(s == prompts.SYSTEM_TEXT + "\n\n" + base.JSON_SYSTEM_SUFFIX for s, _ in p.prompts)
    assert "full-2" in p.prompts[0][1] and "[step 1] you called search_findings" in p.prompts[1][1]
    db = app_db(ready)
    assert db.execute("SELECT COUNT(*) FROM agent_messages").fetchone()[0] == 0          # debug is off
    a = db.execute("SELECT actor, target FROM audit_log WHERE action='analyst-run'").fetchall()
    assert [tuple(x) for x in a] == [("admin", f"analyst run {r['id']}")]


def test_an_invalid_answer_then_a_valid_one(ready):
    p = mock(["this is not JSON", {"action": "tool"}, final("brief", change_commentary="ok")])
    r = clean(run(ready, p))
    assert (r["status"], r["outcome"], r["invalid_answers"]) == ("done", "ok", 2)
    assert [s["kind"] for s in r["steps_rows"]] == ["invalid", "invalid", "final"]
    assert all(s["error"] == base.E_BAD for s in r["steps_rows"][:2])
    assert "Your previous answer was not valid" in p.prompts[1][1] and "$.tool: missing" in p.prompts[2][1]


def test_too_many_invalid_answers_end_the_run(ready):
    p = mock(["nope"] * 10)
    r = clean(run(ready, p))
    assert (r["status"], r["outcome"]) == ("failed", "invalid-answers")
    assert len(r["steps_rows"]) == ready.analyst_max_invalid + 1 and r["error"] == runner.OUTCOMES["invalid-answers"]


def test_an_unknown_tool_is_refused_and_counted(ready):
    p = mock([tool("delete_everything"), {"action": "tool", "tool": "none", "arguments": "{}", "final": prompts.EMPTY_FINAL["brief"]},
              final("brief")])
    r = clean(run(ready, p))
    assert r["outcome"] == "ok" and r["invalid_answers"] == 2
    assert r["steps_rows"][0]["kind"] == "invalid" and r["steps_rows"][1]["error"] == "There is no tool with that name."
    assert "Your tool call was refused: There is no tool with that name." in p.prompts[2][1]


def test_bad_tool_arguments_are_refused(ready):
    p = mock([tool("get_finding", {"finding_key": "../../etc"}), tool("get_finding", {}), tool("search_findings", {"limit": 5000}),
              {"action": "tool", "tool": "list_runs", "arguments": "[1]", "final": prompts.EMPTY_FINAL["brief"]},
              tool("get_finding", {"finding_key": KEYS["env"]}), final("brief")])
    s = lab_settings_like(ready, analyst_max_invalid=5)
    r = clean(run(s, p))
    assert r["outcome"] == "ok" and r["invalid_answers"] == 4
    errs = [x["error"] for x in r["steps_rows"][:4]]
    assert errs[0].startswith("Invalid arguments: finding_key: wrong form") and errs[1].startswith("Invalid arguments: finding_key: missing")
    assert errs[2].startswith("Invalid arguments: limit: too large") and errs[3] == "The arguments must be a JSON object."
    assert r["steps_rows"][4]["kind"] == "tool" and r["tools_json"] == ["get_finding"]


def lab_settings_like(s, **kw):
    import dataclasses
    return dataclasses.replace(s, **kw)


def test_a_provider_error_mid_run(ready):
    p = mock([tool("list_runs"), base.RateLimited()])
    r = clean(run(ready, p))
    assert (r["status"], r["outcome"], r["error"]) == ("failed", "provider-error", base.E_RATE)
    assert [s["kind"] for s in r["steps_rows"]] == ["tool", "error"]


def test_a_refusal_ends_the_run(ready):
    r = clean(run(ready, mock([base.Refused()])))
    assert (r["outcome"], r["error"]) == ("refused", base.E_REFUSED)


@pytest.mark.parametrize("limit", ["max_steps", "run_budget", "daily_budget", "wall_clock"])
def test_each_limit(ready, limit, monkeypatch):
    many = [tool("list_runs")] * 50
    if limit == "max_steps":
        s, p = lab_settings_like(ready, analyst_max_steps=3), mock(many)
        r = clean(run(s, p))
        assert (r["outcome"], r["steps"], len(p.prompts)) == ("max-steps", 3, 3)
    elif limit == "run_budget":
        s, p = lab_settings_like(ready, analyst_run_token_budget=5000), mock(many)
        r = clean(run(s, p))
        assert r["outcome"] == "run-budget" and r["tokens_in"] + r["tokens_out"] >= 5000
        assert r["steps"] < 50
    elif limit == "daily_budget":
        db = app_db(ready)
        db.execute("INSERT INTO agent_runs(started_at, trigger, status, tokens_in, tokens_out) VALUES(?, 'request', 'done', 900000, 99000)",
                   (dbm.iso(),))
        s, p = lab_settings_like(ready, analyst_daily_token_budget=1000000), mock(many)
        r = clean(run(s, p))
        assert r["outcome"] == "daily-budget" and runner.tokens_today(db) >= 1000000
        # and no new run starts once the day's budget is used
        with pytest.raises(runner.RunRefused) as e:
            run(s, mock(many))
        assert "Today's token budget" in str(e.value)
    else:
        clock = [1000.0]
        monkeypatch.setattr(runner.time, "monotonic", lambda: clock[0])

        def slow(system, user):
            clock[0] += 40
            return tool("list_runs")
        s, p = lab_settings_like(ready, analyst_run_seconds=100), mock([slow] * 10)
        r = clean(run(s, p))
        assert r["outcome"] == "wall-clock" and r["steps"] == 3


def test_tokens_per_call_and_the_request_timeout_are_passed_to_the_provider(ready):
    seen = []

    class P(type(mock())):
        def chat_json(self, system, user, schema, max_tokens):
            seen.append((max_tokens, self.timeout_seconds))
            return super().chat_json(system, user, schema, max_tokens)
    s = lab_settings_like(ready, analyst_max_tokens_per_call=777, analyst_timeout_seconds=33)
    clean(run(s, P("mock-1", script=[final("brief")])))
    assert seen == [(777, 33)]


def test_a_snapshot_that_disappears_mid_run_fails_cleanly(ready, monkeypatch):
    from app.analyst import tools as toolsm

    def gone(self):
        raise toolsm.SnapshotGone()
    p = mock([tool("list_runs")])
    monkeypatch.setattr(toolsm.Ctx, "snap", gone)
    db = app_db(ready)
    rid = runner.start(ready, db, "chat", "admin", "request", question="hi", provider=p, wait=True)
    r = clean(row(ready, rid))
    assert (r["status"], r["outcome"]) == ("failed", "snapshot-changed")


def test_one_run_at_a_time(ready):
    gate, entered = threading.Event(), threading.Event()

    def hold(system, user):
        entered.set()
        gate.wait(10)
        return final("brief")
    db = app_db(ready)
    rid = runner.start(ready, db, "brief", "admin", "request", provider=mock([hold]))
    assert entered.wait(10)
    with pytest.raises(runner.RunRefused) as e:
        runner.start(ready, db, "chat", "admin", "request", question="q", provider=mock([final("chat")]))
    assert "still running" in str(e.value)
    gate.set()
    runner.wait_all()
    assert row(ready, rid)["status"] == "done"
    assert db.execute("SELECT COUNT(*) FROM agent_runs").fetchone()[0] == 1


def test_a_run_left_running_by_a_restart_is_marked_interrupted(ready, settings):
    db = app_db(ready)
    db.execute("INSERT INTO agent_runs(started_at, trigger, status) VALUES(?, 'request', 'running')", (dbm.iso(),))
    create_app(settings, start_background=False)
    r = db.execute("SELECT status, outcome FROM agent_runs").fetchone()
    assert tuple(r) == ("failed", "interrupted")


def test_prompts_are_stored_only_with_debug_and_never_in_lab_mode(ready):
    db = app_db(ready)
    run(lab_settings_like(ready, analyst_debug=True), mock([final("brief")]))          # lab mode: debug ignored
    assert db.execute("SELECT COUNT(*) FROM agent_messages").fetchone()[0] == 0
    r = run(ready, mock([final("brief")]), store_prompts=True)                            # tests may switch it on explicitly
    roles = [x[0] for x in db.execute("SELECT role FROM agent_messages WHERE agent_run_id=? ORDER BY id", (r["id"],))]
    assert roles == ["user", "assistant"]


def test_the_chat_question_is_checked(ready):
    for q in ("", " ", "x" * 2001):
        with pytest.raises(runner.RunRefused):
            run(ready, mock([final("chat")]), kind="chat", question=q)
    r = run(ready, mock([final("chat", answer="Two.")]), kind="chat", question="How many open findings?")
    assert r["question"] == "How many open findings?" and r["result_json"]["answer"] == "Two."


def test_the_automatic_brief_runs_once_per_snapshot_and_only_when_enabled(ready, monkeypatch):
    from app.llm import factory
    monkeypatch.setattr(factory, "build", lambda s: mock([final("brief")]))
    db = app_db(ready)
    assert runner.auto_brief(ready) is None                                   # off by default
    on = lab_settings_like(ready, analyst_auto_brief=True)
    assert runner.auto_brief(on) is None          # turning the automatic brief on asks again
    confirm(on)                                   # the statement now says briefs go out for each new snapshot
    rid = runner.auto_brief(on)
    runner.wait_all()
    assert rid and runner.auto_brief(on) is None                              # the same snapshot: not again
    r = row(ready, rid)
    assert (r["trigger"], r["requested_by"], r["kind"], r["status"]) == ("new-snapshot", "scheduler", "brief", "done")
    a = dict(db.execute("SELECT actor FROM audit_log WHERE action='analyst-run'").fetchone())
    assert a["actor"] == "scheduler"
    fixtures.build_published(ready.published_dir, hostile=False, reopen=True)  # a new snapshot: one more brief
    rid2 = runner.auto_brief(on)
    runner.wait_all()
    assert rid2 and rid2 != rid
    db.execute("DELETE FROM settings WHERE key='analyst_consent'")            # without the confirmation: nothing
    fixtures.build_published(ready.published_dir, hostile=False, change_evidence=True)
    assert runner.auto_brief(on) is None
