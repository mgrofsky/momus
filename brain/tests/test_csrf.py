import pytest

from conftest import ORIGIN, PASSWORD, Browser
from helpers import routes

FORMS = {   # a valid body for each page POST, so a refusal can only come from the anti-forgery checks
    "/findings/{key}/mark": {"kind": "false_positive", "reason": "test reason"},
    "/scope/entries": {"kind": "exclusion", "value": "x.example.test"},
    "/scope/profile": {"check_profile": "active"},
    "/schedules": {"kind": "daily-recheck", "enabled": "on", "hour": "2", "minute": "0"},
    "/settings/password": {"current": PASSWORD, "new": "y" * 20, "new2": "y" * 20},
    "/settings/accounts": {"username": "second", "password": "y" * 20},
    "/version-watch/watches": {"watch_id": "php-cgi", "name": "PHP CGI", "product": "php", "cves": "CVE-2099-0003", "floors": "8.3.8"},
    "/version-watch/watches/{watch_id}/remove": {"confirm": "yes"},
    "/analyst/chat": {"question": "What changed?"},
    "/settings/analyst/consent": {"confirm": "yes"},
}


def state_changing(app):
    return [(m, t, p) for m, t, p in routes(app) if m != "GET"]


@pytest.mark.parametrize("variant", ["no-token", "wrong-token", "foreign-origin", "no-origin"])
def test_state_changing_requests_need_token_and_origin(app, admin, published, variant):
    n = 0
    for method, tmpl, path in state_changing(app):
        if tmpl in ("/login", "/bootstrap"):
            continue
        data = dict(FORMS.get(tmpl, {}))
        if variant == "no-token":
            r = admin.c.post(path, data=data, headers={"Origin": ORIGIN})
        elif variant == "wrong-token":
            r = admin.c.post(path, data={**data, "csrf": "W" * 43}, headers={"Origin": ORIGIN, "X-CSRF-Token": "W" * 43})
        elif variant == "foreign-origin":
            r = admin.c.post(path, data={**data, "csrf": admin.csrf}, headers={"Origin": "http://evil.test", "X-CSRF-Token": admin.csrf})
        else:
            r = admin.c.post(path, data={**data, "csrf": admin.csrf}, headers={"X-CSRF-Token": admin.csrf})
        assert r.status_code == 403, (variant, path, r.status_code, r.text[:200])
        n += 1
    assert n >= 10
    assert admin.get("/").status_code == 200       # the session itself is untouched


def test_foreign_referer_refused_matching_referer_accepted(admin, published):
    r = admin.c.post("/scope/profile", data={"check_profile": "active", "csrf": admin.csrf}, headers={"Referer": "http://evil.test/page"})
    assert r.status_code == 403
    r = admin.c.post("/scope/profile", data={"check_profile": "active", "csrf": admin.csrf}, headers={"Referer": ORIGIN + "/scope"})
    assert r.status_code == 303


def test_api_post_needs_header_token(admin, published):
    assert admin.api_post("/api/v1/scope/profile", {"check_profile": "active"}, csrf=False).status_code == 403
    assert admin.api_post("/api/v1/scope/profile", {"check_profile": "active"}, origin="http://evil.test").status_code == 403
    r = admin.api_post("/api/v1/scope/profile", {"check_profile": "active"})
    assert r.status_code == 200 and r.json()["profile"]["check_profile"] == "active"


def test_login_needs_pre_session_token_and_origin(app, admin):
    b = Browser(app)
    pre = b.pre_token("/login")
    form = {"username": "admin", "password": PASSWORD, "next": "/"}
    assert b.c.post("/login", data=form, headers={"Origin": ORIGIN}).status_code == 403
    assert b.c.post("/login", data={**form, "csrf": "W" * 43}, headers={"Origin": ORIGIN}).status_code == 403
    assert b.c.post("/login", data={**form, "csrf": pre}, headers={"Origin": "http://evil.test"}).status_code == 403
    assert b.c.post("/login", data={**form, "csrf": pre}).status_code == 403
    assert b.c.post("/login", data={**form, "csrf": pre}, headers={"Origin": ORIGIN}).status_code == 303


def test_bootstrap_needs_pre_session_token(app, settings):
    from conftest import bootstrap_token
    b = Browser(app)
    tok = bootstrap_token(settings)
    b.pre_token("/bootstrap")
    form = {"token": tok, "username": "admin", "password": PASSWORD, "password2": PASSWORD, "owner_rule": "yes"}
    assert b.c.post("/bootstrap", data=form, headers={"Origin": ORIGIN}).status_code == 403
    assert b.c.post("/bootstrap", data={**form, "csrf": "W" * 43}, headers={"Origin": ORIGIN}).status_code == 403
