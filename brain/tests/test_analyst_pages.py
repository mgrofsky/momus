"""The analyst's pages. With provider none the page says how to configure one and the rest of the app is unchanged.
Numbers on the brief come from the application, never from the model. The model's text is plain escaped text. Polling
the run status never keeps a session alive. The mock end to end through the pages."""
import datetime as dt
import re

import pytest

import fixtures
from analyst_helpers import KEYS, app_db, confirm, final, lab_settings, mock, row, tool
from app.analyst import runner
from app.llm import factory
from app.web import create_app
from conftest import Browser, ORIGIN, PASSWORD, bootstrap_token
from helpers import live_problems, shown


def browser(app, settings):
    b = Browser(app)
    tok = bootstrap_token(settings)
    pre = b.pre_token("/bootstrap")
    assert b.c.post("/bootstrap", data={"token": tok, "username": "admin", "password": PASSWORD, "password2": PASSWORD,
                                        "owner_rule": "yes", "csrf": pre}, headers={"Origin": ORIGIN}).status_code == 303
    b.refresh_csrf()
    return b


def test_with_no_provider_the_page_says_how_to_configure_one(admin, published):
    t = admin.get("/analyst").text
    assert "No model provider is configured" in t and "MOMUS_ANALYST_PROVIDER" in t and "MOMUS_ANALYST_API_KEY_FILE" in t
    assert 'action="/analyst/brief"' not in t and 'action="/analyst/chat"' not in t
    assert "err=" in admin.post("/analyst/brief").headers["location"]
    assert admin.api_post("/api/v1/analyst/chat", {"question": "hi"}).status_code == 409
    s = admin.get("/settings").text
    assert "No model provider is configured" in s and 'action="/settings/analyst/consent"' not in s
    assert admin.api_post("/api/v1/settings/analyst/consent", {"confirm": True}).status_code == 409
    # the rest of the app is unchanged
    for path in ("/", "/findings", "/findings/" + KEYS["env"], "/assets", "/runs", "/scope", "/version-watch", "/audit"):
        assert admin.get(path).status_code == 200, path
    assert admin.get("/api/v1/settings").json()["instance"]["model_provider"] == "none"


def test_the_analysts_documentation_page(admin):
    r = admin.get("/docs/analyst")
    assert r.status_code == 200 and "What a hostile scanned site can still make the analyst do" in r.text


@pytest.fixture
def lab(tmp_path, capsys):
    s = lab_settings(tmp_path)
    fixtures.build_published(s.published_dir, hostile=True)
    app = create_app(s, start_background=False)
    confirm(s)
    return s, app, browser(app, s)


def started_id(resp):
    return int(re.search(r"fp_n=(\d+)", resp.headers["location"]).group(1))    # the run number travels as a checked value


def test_wrong_counts_from_the_model_cannot_change_any_count_shown(lab, monkeypatch):
    s, app, b = lab
    lie = ("There are 999 critical findings, 0 open findings, 12345 new and 777 fixed since the last run. "
           "Counts: critical 999, high 0, medium 0, low 0.")
    p = mock([final("brief", change_commentary=lie, top=[{"title": "999 critical findings", "reason": lie,
                                                           "references": [{"kind": "finding", "id": KEYS["env"]}]}])])
    monkeypatch.setattr(factory, "build", lambda st: p)
    def app_counts():     # every count and list the overview and findings show (not the scanner heartbeat's age, which ticks)
        o = b.get("/api/v1/overview").json()
        return {"overview": {k: o[k] for k in ("counts", "latest", "trend", "top")}, "findings": b.get("/api/v1/findings").json()}
    before = app_counts()
    rid = started_id(b.post("/analyst/brief"))
    runner.wait_all()
    r = row(s, rid)
    assert r["status"] == "done"
    # the brief's numbers come from facts_json, computed by the application; the model's schema has no number in it
    f = r["facts_json"]
    assert f["counts"] == {"new": 1, "reopened": 0, "fixed": 1} and f["bands"]["Critical"] == 0
    page = b.get("/analyst").text
    shown = re.search(r"Latest scored run.*?Open now:[^<]*", page, re.S).group(0)
    assert "<strong>1</strong> new, <strong>0</strong> reopened, <strong>1</strong> fixed" in shown
    assert "Critical 0" in shown and "999" not in shown and "12345" not in shown
    assert lie.replace("'", "&#39;") in page                       # the model's words are shown, as the model's
    assert "written by the model" in page
    assert app_counts() == before                                         # every other count in the app is unchanged


def test_model_text_is_plain_escaped_text(lab, monkeypatch):
    s, app, b = lab
    evil = ('<script>alert(1)</script><a href="https://attacker.test/">x</a><img src="https://attacker.test/p.png">'
            '[md](https://attacker.test/md) ![i](https://attacker.test/i.png) {{ 7*7 }}')
    p = mock([final("chat", answer=evil, references=[{"kind": "finding", "id": KEYS["env"]}])])
    monkeypatch.setattr(factory, "build", lambda st: p)
    rid = started_id(b.post("/analyst/chat", data={"question": evil}))
    runner.wait_all()
    for path in ("/analyst", f"/analyst/runs/{rid}"):
        t = b.get(path).text
        assert live_problems(t) == [], path
        assert "&lt;script&gt;" in t and "{{ 7*7 }}" in t and "[md](https://attacker.test/md)" in t
        assert not re.search(r'(?:href|src)="https?://', t)
        assert f"<code>finding {KEYS['env']}</code>" in t and f'href="/findings/{KEYS["env"]}"' not in t   # references: text, not links
    j = b.get(f"/api/v1/analyst/runs/{rid}").text
    assert "<script>" not in j and "\\u003cscript\\u003e" in j


def test_each_answer_shows_which_tools_were_called(lab, monkeypatch):
    s, app, b = lab
    p = mock([tool("search_findings", {"state": "open"}, kind="chat"), tool("get_finding", {"finding_key": KEYS["env"]}, kind="chat"),
              final("chat", answer="Fix the env file.")])
    monkeypatch.setattr(factory, "build", lambda st: p)
    rid = started_id(b.post("/analyst/chat", data={"question": "What first?"}))
    runner.wait_all()
    t = b.get("/analyst").text
    assert "Fix the env file." in t, t[t.find("Ask the analyst"):][:3000]
    assert "Tools called: search_findings, get_finding." in t, t[t.find("Ask the analyst"):][:3000]
    rt = b.get(f"/analyst/runs/{rid}").text
    assert "search_findings" in rt and "get_finding" in rt and "Tokens in / out" in rt


def test_polling_the_status_does_not_keep_a_session_alive(lab):
    s, app, b = lab
    db = app_db(s)
    last = lambda: db.execute("SELECT last_seen_at FROM sessions").fetchone()[0]  # noqa: E731
    five_min = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    db.execute("UPDATE sessions SET last_seen_at=?", (five_min,))
    assert b.get("/analyst/live").status_code == 200
    assert last() == five_min                                       # polling did not move it
    b.get("/analyst")
    assert last() != five_min                                       # a page view does
    old = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=s.session_idle_minutes + 5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    db.execute("UPDATE sessions SET last_seen_at=?", (old,))
    assert b.get("/analyst/live", headers={"HX-Request": "true"}).status_code == 401


def test_the_mock_end_to_end_through_the_pages(lab):
    """The default mock agent: a brief appears, its proposal is accepted on its page and becomes a mark."""
    s, app, b = lab
    assert "msg=" in b.post("/analyst/brief").headers["location"]
    runner.wait_all()
    t = b.get("/analyst").text
    assert "Top three (written by the model)" in t and "Mock analyst" in t
    pid = int(re.search(r'href="/analyst/proposals/(\d+)"', t).group(1))
    assert "msg=" in b.post(f"/analyst/proposals/{pid}/accept", data=shown(b, f"/analyst/proposals/{pid}")).headers["location"]
    db = app_db(s)
    assert db.execute("SELECT COUNT(*) FROM finding_marks").fetchone()[0] == 1
    assert db.execute("SELECT COUNT(*) FROM audit_log WHERE action='proposal-accept' AND actor='admin'").fetchone()[0] == 1


def test_settings_shows_provider_model_limits_and_usage(lab):
    s, app, b = lab
    t = b.get("/settings").text
    for want in ("provider", "mock", "max steps", "run token budget", "daily token budget", "tokens used today (UTC)", "run seconds"):
        assert want in t, want
    j = b.get("/api/v1/settings").json()["analyst"]
    assert j["provider"] == "mock" and j["limits"]["max_steps"] == s.analyst_max_steps and j["consent_current"] is True
