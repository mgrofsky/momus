"""Hostile published data: every page and API route that shows it escapes it, holds no live tag or handler, and
carries the content security policy. Report downloads are attachments with a sandboxing policy."""
import html
import json
import os
import re

import pytest

import fixtures
from helpers import live_problems, routes

CSP_NEEDLES = ("default-src 'none'", "script-src 'self'", "style-src 'self'", "frame-ancestors 'none'")


def common_headers(r):
    csp = r.headers.get("content-security-policy", "")
    for n in CSP_NEEDLES:
        assert n in csp, (r.url, csp)
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
    assert r.headers.get("x-content-type-options") == "nosniff"
    assert r.headers.get("x-frame-options") == "DENY"
    assert r.headers.get("referrer-policy") == "same-origin"


def page_gets(app):
    return [p for m, t, p in routes(app) if m == "GET" and not p.startswith("/api/") and "/files/" not in p
            and p not in ("/login", "/bootstrap")]


def test_every_page_escapes_hostile_data(app, admin, published):
    shown = 0
    for path in page_gets(app):
        r = admin.get(path)
        assert r.status_code in (200, 404), (path, r.status_code)
        common_headers(r)
        assert live_problems(r.text) == [], (path, live_problems(r.text)[:5])
        assert "<script>alert" not in r.text and "<img src=x" not in r.text, path
        assert "momus-xss" not in r.text or "&lt;script&gt;alert(&#39;momus-xss&#39;)&lt;/script&gt;" in r.text, path
        if "momus-xss" in r.text:
            shown += 1
            assert "{{ 7*7 }}" in r.text, path            # template syntax shown as text, never evaluated
            assert "{% if 1 %}tmpl{% endif %}" in r.text, path
            assert "DROP TABLE users" in r.text, path     # SQL fragments are just text
    assert shown >= 8, shown


def test_pages_with_hostile_data_listed(admin, published):
    """The pages that must show hostile text do show it (escaped), so the test above is not vacuous."""
    # the version-watch list shows only checked fields (names, counts, dates), so the hostile text is checked on the
    # detail page of the published result, which shows the target-derived Server text and the reason
    for path in ("/", "/findings?state=", "/findings/" + fixtures.K["env"], "/assets", "/assets/target.demo.test", "/domains",
                 "/runs", "/scope", "/version-watch/" + fixtures.WATCH_ID):
        r = admin.get(path)
        assert r.status_code == 200, path
        assert "&lt;script&gt;alert(" in r.text, path


def test_every_api_route_escapes_hostile_data(app, admin, published):
    shown = 0
    for method, tmpl, path in routes(app):
        if method != "GET" or not path.startswith("/api/") and path != "/api/docs":
            continue
        r = admin.get(path)
        assert r.status_code in (200, 404), (path, r.status_code)
        common_headers(r)
        if r.headers["content-type"].startswith("application/json"):
            assert "<" not in r.text and ">" not in r.text, path
            if "momus-xss" in r.text:
                shown += 1
                assert "\\u003cscript\\u003ealert('momus-xss')" in r.text, path
                json.loads(r.text)
        else:
            assert live_problems(r.text) == [], path
    assert shown >= 6, shown


def test_long_strings_do_not_break_pages(admin, published):
    r = admin.get("/findings/" + fixtures.K["env"])
    assert r.status_code == 200
    assert "L" * 2000 in r.text      # the stored long description is shown (as text), the page still renders


def test_links_from_scan_data_are_text(admin, published):
    for path in ("/assets/target.demo.test", "/findings/" + fixtures.K["env"]):
        r = admin.get(path)
        hrefs = re.findall(r'href="([^"]*)"', r.text)
        assert all(h.startswith("/") or h.startswith("?") for h in hrefs), [h for h in hrefs if not h.startswith("/")]
        assert "javascript:alert(5)" in r.text or "javascript:alert(6)" in r.text


def test_report_download_headers(admin, published):
    for name in ("full-2.html", "full-2-findings.csv"):
        r = admin.get(f"/runs/full-2/files/{name}")
        assert r.status_code == 200
        assert r.headers["content-disposition"] == f'attachment; filename="{name}"'
        assert r.headers["content-security-policy"].startswith("sandbox")
        assert r.headers["x-content-type-options"] == "nosniff"


def test_report_download_refuses_other_paths(admin, published, settings):
    os.symlink("/etc/passwd", os.path.join(settings.published_dir, "reports", "full-2", "full-2-link.csv"))
    for path in ("/runs/full-2/files/..%2F..%2Fscanner.json", "/runs/full-2/files/full-1.html", "/runs/full-2/files/full-2-link.csv",
                 "/runs/x/files/full-2.html", "/runs/full-2/files/.full-2.html"):
        r = admin.get(path)
        assert r.status_code in (404, 422), (path, r.status_code)
        assert "root:" not in r.text


def test_templates_never_mark_values_safe():
    tdir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app", "templates")
    for d, _, fs in os.walk(tdir):
        for f in fs:
            text = open(os.path.join(d, f), encoding="utf-8").read()
            assert "|safe" not in text.replace(" ", "") and "autoescape false" not in text, f
            assert not re.search(r"<script(?![^>]*\bsrc=)", text), f          # no inline script
            assert " style=" not in text and "<style" not in text, f          # no inline style
            assert not re.search(r"\son[a-z]+=", text), f                      # no event handler attributes
    src = os.path.join(os.path.dirname(tdir))
    for f in os.listdir(src):
        if f.endswith(".py"):
            text = open(os.path.join(src, f), encoding="utf-8").read()
            assert "Markup(" not in text and "autoescape=False" not in text, f
