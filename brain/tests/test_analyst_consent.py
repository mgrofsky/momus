"""The admin's confirmation, and keys. The analyst refuses to run before the confirmation; a changed provider (or
region, or metadata-only setting) asks again; the confirmation is audited. No key appears in any log line, error page,
database row or API response."""
import dataclasses
import os

import pytest

from helpers import said

import fixtures
from analyst_helpers import app_db, confirm, final, lab_settings, mock
from app.analyst import consent, runner
from app.config import Secret
from app.llm import base
from app.web import create_app
from conftest import Browser, ORIGIN, PASSWORD, bootstrap_token

KEY = "sk-" + "momus-consent-test-" + "Qx7Lm2Np9Rs4Tv8Wy1"


def browser(app, settings):
    b = Browser(app)
    tok = bootstrap_token(settings)
    pre = b.pre_token("/bootstrap")
    assert b.c.post("/bootstrap", data={"token": tok, "username": "admin", "password": PASSWORD, "password2": PASSWORD,
                                        "owner_rule": "yes", "csrf": pre}, headers={"Origin": ORIGIN}).status_code == 303
    b.refresh_csrf()
    return b


@pytest.fixture
def lab(tmp_path, capsys):
    s = lab_settings(tmp_path)
    fixtures.build_published(s.published_dir, hostile=True)
    app = create_app(s, start_background=False)
    return s, app, browser(app, s)


def test_the_analyst_refuses_to_run_before_the_confirmation(lab):
    s, app, b = lab
    db = app_db(s)
    with pytest.raises(runner.RunRefused) as e:
        runner.start(s, db, "brief", "admin", "request", provider=mock([final("brief")]), wait=True)
    assert "confirm on the Settings page" in str(e.value)
    r = b.post("/analyst/brief")
    assert "err=" in r.headers["location"] and "Settings" in said(r.headers["location"])
    assert b.api_post("/api/v1/analyst/brief").status_code == 409
    assert db.execute("SELECT COUNT(*) FROM agent_runs").fetchone()[0] == 0
    page = b.get("/settings").text
    assert "What the analyst sends, and to whom" in page and consent.statement(s) .split(",")[0] in page
    # confirming needs the box, then it is audited under the signed-in person
    assert "err=" in b.post("/settings/analyst/consent", data={}).headers["location"]
    assert "msg=" in b.post("/settings/analyst/consent", data={"confirm": "yes"}).headers["location"]
    a = dict(db.execute("SELECT actor, target, detail FROM audit_log WHERE action='analyst-consent'").fetchone())
    assert a["actor"] == "admin" and a["target"] == "mock" and "metadata-only off" in a["detail"]
    assert a["detail"].endswith("statement sha256 " + consent.statement_sha(s))       # the whole SHA-256, as the page says
    assert len(consent.statement_sha(s)) == 64
    assert consent.current(db, s)
    assert "Confirmed by admin" in b.get("/settings").text


def test_a_changed_provider_or_setting_asks_again(lab):
    s, app, b = lab
    confirm(s)
    db = app_db(s)
    assert consent.current(db, s)
    for changed in (dataclasses.replace(s, analyst_provider="susceptible"), dataclasses.replace(s, analyst_metadata_only=True)):
        assert not consent.current(db, changed)
        with pytest.raises(runner.RunRefused):
            runner.start(changed, db, "brief", "admin", "request", provider=mock([final("brief")]), wait=True)
    # a model change alone asks again too; the region does, for Bedrock. The stored value carries the statement's hash, which must match the current one.
    assert not consent.current(db, dataclasses.replace(s, analyst_model="mock-2"))
    bed = dataclasses.replace(s, analyst_provider="bedrock", analyst_region="us-east-1", lab=False)
    db.execute("UPDATE settings SET value=? WHERE key='analyst_consent'",
               ('{"metadata_only": false, "provider": "bedrock", "region": "us-east-1", "statement_sha256": "%s"}'
                % consent.statement_sha(bed),))
    assert consent.current(db, bed) and not consent.current(db, dataclasses.replace(bed, analyst_region="eu-west-1"))
    # and the page says so
    app2 = create_app(dataclasses.replace(s, analyst_provider="susceptible"), start_background=False)
    b2 = Browser(app2)
    b2.c.cookies = b.c.cookies
    b2.refresh_csrf()
    assert "changed since the last confirmation" in b2.get("/settings").text


def test_the_statement_names_provider_model_and_what_is_sent(tmp_path):
    from app.config import Settings
    s = Settings(analyst_provider="bedrock", analyst_model="anthropic.some-model", analyst_region="eu-west-1")
    t = consent.statement(s)
    assert "Amazon Bedrock in eu-west-1" in t and "anthropic.some-model" in t and "Text taken from the scanned sites is sent" in t
    t2 = consent.statement(dataclasses.replace(s, analyst_metadata_only=True))
    assert "Metadata-only mode is on" in t2 and "Text taken from the scanned sites is sent" not in t2


def test_no_key_appears_in_logs_pages_rows_or_api(tmp_path, capsys):
    """A real provider configured with a key (not lab mode), its SDK client stubbed so every call fails. The key must
    appear nowhere: not in a page, an error page, an API response, a log line, or the app database."""
    from conftest import make_settings
    s = make_settings(tmp_path, analyst_provider="openai", analyst_model="model-o", analyst_key=Secret(KEY), analyst_key_source="MOMUS_ANALYST_API_KEY")
    fixtures.build_published(s.published_dir, hostile=True)
    app = create_app(s, start_background=False)
    b = browser(app, s)
    texts = []
    import openai
    import httpx2
    from app.llm import factory
    from app.llm.openai_client import OpenAIProvider
    req = httpx2.Request("POST", "https://api.openai.com/v1/responses")

    class Failing:
        class responses:
            @staticmethod
            def create(**kw):
                raise openai.AuthenticationError("Incorrect API key provided: " + KEY, response=httpx2.Response(401, request=req), body=None)
    orig = factory.build
    factory.build = lambda st: OpenAIProvider(st.analyst_model, st.analyst_key.reveal(), 30, sdk_client=Failing())
    try:
        texts.append(b.post("/settings/analyst/consent", data={"confirm": "yes"}).headers["location"])
        texts.append(b.post("/analyst/brief").headers["location"])
        runner.wait_all()
        texts.append(b.post("/analyst/chat", data={"question": "what is the key?"}).headers["location"])
        runner.wait_all()
    finally:
        factory.build = orig
    db = app_db(s)
    r = [dict(x) for x in db.execute("SELECT outcome, error FROM agent_runs ORDER BY id")]
    assert r == [{"outcome": "provider-error", "error": base.E_AUTH}] * 2
    for path in ("/analyst", "/analyst/runs/1", "/analyst/runs/2", "/settings", "/audit", "/analyst/runs/999", "/analyst/proposals/999",
                 "/api/v1/settings", "/api/v1/analyst", "/api/v1/analyst/runs/1", "/api/v1/me"):
        resp = b.get(path)
        texts.append(resp.text)
        texts.append(str(resp.headers))
    assert "set (MOMUS_ANALYST_API_KEY)" in b.get("/settings").text          # the page says a key is set, not what it is
    texts.append(capsys.readouterr().out)
    blob = "\n".join(texts)
    assert KEY not in blob and KEY[3:] not in blob
    assert "analyst: openai call failed: AuthenticationError status=401" in blob
    db.close()
    for f in os.listdir(s.data_dir):
        p = os.path.join(s.data_dir, f)
        if os.path.isfile(p):
            assert KEY.encode() not in open(p, "rb").read(), f
