"""Shared checks: route enumeration and the 'no live tag or handler' HTML check."""
import html.parser
import re

from fastapi.routing import APIRoute

SAMPLE = {"key": "a1b2c3d4e5f6a7b8c9d0", "host": "target.demo.test", "run_id": "full-2", "name": "full-2.html",
          "watch_id": "php-cgi",       # fixtures.py publishes version-watch/php-cgi/
          "agent_run_id": "1", "proposal_id": "1"}
PUBLIC = {"/login", "/bootstrap"}


def routes(app):
    """[(method, path template, concrete path)] for every API route of the app (not the static mount)."""
    out = []
    for r in app.routes:
        if not isinstance(r, APIRoute):
            continue
        concrete = re.sub(r"\{(\w+)\}", lambda m: SAMPLE[m.group(1)], r.path)
        for m in sorted(r.methods - {"HEAD"}):
            out.append((m, r.path, concrete))
    return out


class _Scan(html.parser.HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.problems = []

    def handle_starttag(self, tag, attrs):
        if tag == "script":
            src = dict(attrs).get("src")
            if src != "/static/vendor/htmx-2.0.7.min.js":
                self.problems.append(f"script tag {attrs}")
        if tag in ("img", "iframe", "object", "embed", "base", "meta") and tag != "meta":
            self.problems.append(f"{tag} tag")
        if tag == "meta" and dict(attrs).get("http-equiv"):
            self.problems.append("meta http-equiv")
        for k, v in attrs:
            if k.startswith("on"):
                self.problems.append(f"handler {k}")
            if k == "style":
                self.problems.append("style attribute")
            if k in ("href", "src", "action", "formaction", "hx-get", "hx-post") and v and re.match(r"\s*(javascript|data|vbscript):", v, re.I):
                self.problems.append(f"{k}={v[:40]}")
            if k in ("href", "action") and v and re.match(r"\s*(https?:)?//", v):
                self.problems.append(f"external {k}={v[:60]}")


def live_problems(text):
    p = _Scan()
    p.feed(text)
    p.close()
    return p.problems


def said(location):
    """The status line(s) a redirect's target page would show. The query string carries a code
    from the fixed table in app/flash.py (and strictly checked values), never the sentence itself."""
    from urllib.parse import parse_qs, urlsplit
    from app import flash
    q = {k: v[0] for k, v in parse_qs(urlsplit(location).query).items()}
    return " | ".join(x for x in (flash.render(q.get("msg"), q), flash.render(q.get("err"), q)) if x)


def shown(b, path):
    """The values a page binds its decision form to: the evidence fingerprint and, on a
    proposal page, the snapshot SHA-256 it was rendered from. A person's browser sends them with the form."""
    import re
    page = b.get(path).text
    out = {}
    for name in ("evidence_fp", "snapshot_sha256"):
        m = re.search(r'name="%s" value="([^"]*)"' % name, page)
        if m:
            out[name] = m.group(1)
    return out
