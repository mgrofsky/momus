#!/usr/bin/env python3
"""ui_driver.py - drives the brain over HTTP for tests/e2e/run_demo_ui.sh, like a browser would (session cookie,
anti-forgery token from the page, Origin header). Standard library only. Runs in a container on the brain's own
internal network; it never reaches the scanner or the demo target. Prints PASS/FAIL lines; exit 1 if any failed.

  ui_driver.py --base http://brain:8080 --canaries FILE   (BOOTSTRAP_TOKEN in the environment)
"""
import argparse
import html
import http.cookiejar
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

results = []
PASSWORD = "e2e lab password 1"


def check(name, ok, detail=""):
    results.append(bool(ok))
    print(f"{'PASS' if ok else 'FAIL'} {name}" + ("" if ok or not detail else f"  [{str(detail)[:300]}]"), flush=True)
    return ok


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


class Browser:
    def __init__(self, base):
        self.base = base.rstrip("/")
        self.jar = http.cookiejar.CookieJar()
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar), NoRedirect())
        self.seen = []          # (path, body) of every response, for the canary search

    def req(self, method, path, data=None, headers=None, json_body=None):
        h = {"Origin": self.base} if method != "GET" else {}
        h.update(headers or {})
        body = None
        if json_body is not None:
            body = json.dumps(json_body).encode()
            h["Content-Type"] = "application/json"
        elif data is not None:
            body = urllib.parse.urlencode(data).encode()
            h["Content-Type"] = "application/x-www-form-urlencoded"
        r = urllib.request.Request(self.base + path, data=body, method=method, headers=h)
        try:
            resp = self.op.open(r, timeout=30)
            status, hdrs, text = resp.status, resp.headers, resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            status, hdrs, text = e.code, e.headers, e.read().decode("utf-8", "replace")
        self.seen.append((path, text))
        return status, hdrs, text

    def get(self, path):
        return self.req("GET", path)

    def csrf_from(self, text):
        m = re.search(r'name="csrf" value="([^"]+)"', text)
        return m.group(1) if m else None

    def post_form(self, page, action, fields):
        """GET the page and POST the form with that action as a browser would: every hidden input of that form (the
        anti-forgery token and the evidence fingerprint and snapshot hash a decision is bound to),
        then the given fields."""
        _, _, text = self.get(page)
        hidden = {}
        m = re.search(r'<form[^>]*action="' + re.escape(action) + r'"[^>]*>(.*?)</form>', text, re.S)
        if m:
            for name, value in re.findall(r'<input type="hidden" name="([^"]+)" value="([^"]*)">', m.group(1)):
                hidden[name] = html.unescape(value)
        return self.req("POST", action, data={**hidden, **fields, "csrf": hidden.get("csrf") or self.csrf_from(text) or ""})

    def api(self, path):
        s, _, text = self.get(path)
        try:
            return s, json.loads(text)
        except ValueError:
            return s, None


def wait_job(b, job_id, timeout):
    deadline = time.time() + timeout
    st = None
    while time.time() < deadline:
        _, d = b.api("/api/v1/runs")
        for j in (d or {}).get("jobs", []):
            if j.get("job_id") == job_id:
                st = j
        if st and st.get("state") in ("done", "failed", "rejected", "interrupted"):
            return st
        time.sleep(3)
    return st


def wait_idle(b, timeout=600):
    """Wait until no job is in flight (a scope change may have queued a scope-sync job)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        _, d = b.api("/api/v1/runs")
        if d and not (d.get("queue") or {}).get("busy"):
            return True
        time.sleep(2)
    return False


def queue(b, jtype):
    s, h, _ = b.post_form("/runs", "/jobs", {"type": jtype})
    loc = h.get("Location", "") if h else ""
    m = re.search(r"job=([a-z0-9-]+)", loc)
    return s, (m.group(1) if m else None), loc


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--canaries", required=True)
    ap.add_argument("--targets", default="target.demo.test,notice.demo.test")
    ap.add_argument("--expect", default="generic-env,git-config,configuration-listing")
    a = ap.parse_args()
    canon = json.load(open(a.canaries))
    b = Browser(a.base)

    # 1. bootstrap the first admin with the one-time token
    s, _, text = b.get("/bootstrap")
    check("ui 1 the first-run page states the ownership rule", s == 200 and "explicitly owns" in text, s)
    s, h, _ = b.post_form("/bootstrap", "/bootstrap", {"token": os.environ.get("BOOTSTRAP_TOKEN", ""), "username": "e2e-admin",
                                                        "password": PASSWORD, "password2": PASSWORD, "owner_rule": "yes"})
    check("ui 1 bootstrap creates the admin and signs in", s == 303 and h.get("Location") == "/scope", s)
    s, _, _ = Browser(a.base).post_form("/bootstrap", "/bootstrap", {"token": os.environ.get("BOOTSTRAP_TOKEN", ""), "username": "second",
                                                                     "password": PASSWORD, "password2": PASSWORD, "owner_rule": "yes"})
    check("ui 1 the bootstrap token does not work a second time", s in (400, 403, 404), s)
    s, _, text = b.get("/")
    check("ui 1 the lab banner is shown", s == 200 and "Lab mode" in text, s)

    # 2. add the lab targets with the ownership statement
    for t in a.targets.split(","):
        s, h, _ = b.post_form("/scope", "/scope/domains", {"name": t, "statement": "yes", "kind": "lab"})
        check(f"ui 2 lab target {t} added with the ownership statement", s == 303 and "err=" not in h.get("Location", ""), h.get("Location"))
    s, _, text = b.get("/scope")
    check("ui 2 the scope page states the ownership rule, the due-care limit and links the data flows",
          "explicitly owns" in text and "due-care control, not a lock" in text and "/docs/data-flows" in text)

    # 3. inventory job
    check("ui 3 no job in flight before the inventory (scope syncs finished)", wait_idle(b))
    s, inv, loc = queue(b, "inventory")
    check(f"ui 3 inventory job queued ({inv})", s == 303 and inv, loc)
    s2, _, _ = b.post_form("/runs", "/jobs", {"type": "inventory"})
    _, _, text = b.get("/runs")
    check("ui 3 a second job is not queued while one is in flight, and the page says why",
          "in flight" in text, s2)
    st = wait_job(b, inv, 900)
    check("ui 3 inventory job ends done", st and st.get("state") == "done", st)

    # 4. approve the inventory, and the lab target for port scans
    s, h, _ = b.post_form("/scope", "/scope/approve", {"inventory_run": inv})
    check("ui 4 inventory approved", s == 303 and "err=" not in h.get("Location", ""), h.get("Location"))
    s, h, _ = b.post_form("/scope", "/scope/entries", {"kind": "host", "value": "target.demo.test"})
    check("ui 4 lab target approved for port scans", s == 303 and "err=" not in h.get("Location", ""), h.get("Location"))
    b.post_form("/scope", "/scope/profile", {"rate_profile": "fast"})

    # 5. full job
    check("ui 5 no job in flight before the full run", wait_idle(b))
    s, full, loc = queue(b, "full")
    check(f"ui 5 full job queued ({full})", s == 303 and full, loc)
    t0 = time.time()
    st = wait_job(b, full, 2400)
    check(f"ui 5 full job ends done ({int(time.time() - t0)}s)", st and st.get("state") == "done", st)

    # 5b. version watch: define the example PHP watch through the form, queue the job, see the demo host fail it
    s, _, text = b.get("/version-watch")
    check("ui 5b the version-watch page states the probe (one GET / per host per run, headers only)",
          s == 200 and "One GET / per host per run" in text, s)
    s, h, _ = b.post_form("/version-watch", "/version-watch/watches", {
        "watch_id": "php-example", "name": "PHP example", "product": "php",
        "cves": "CVE-2099-0001\nCVE-2099-0002", "floors": "8.2.35\n8.3.36\n8.4.27\n8.5.12",
        "hosts": "target.demo.test\nnotice.demo.test"})
    check("ui 5b watch php-example added through the form", s == 303 and "err=" not in (h.get("Location", "") if h else ""),
          (s, h.get("Location") if h else None))
    s, _, text = b.post_form("/version-watch", "/version-watch/watches", {
        "watch_id": "bad-one", "name": "x", "product": "php", "cves": "CVE-2099-10001", "floors": ".*"})
    check("ui 5b a floor that is not a version is refused, and nothing is written", s == 400 and "bad-one" not in
          json.dumps((b.api("/api/v1/version-watch")[1] or {}).get("watches")), s)
    check("ui 5b no job in flight before the version-watch run", wait_idle(b))
    s, vw, loc = queue(b, "version-watch")
    check(f"ui 5b version-watch job queued ({vw})", s == 303 and vw, loc)
    st = wait_job(b, vw, 600)
    check("ui 5b version-watch job ends done", st and st.get("state") == "done", st)
    s, _, text = b.get("/version-watch/php-example")
    row = re.search(r"target\.demo\.test.*?</tr>", text, re.S)
    row = row.group(0) if row else ""
    check("ui 5b the results page shows the demo host failing the watch: 8.2.20, below 8.2.35",
          s == 200 and "FAIL" in row and "8.2.20" in row and "8.2.20 is below 8.2.35" in row, row[:300] or text[:300])
    s, d = b.api("/api/v1/version-watch/php-example")
    hosts = {x.get("hostname"): x for x in ((d or {}).get("result") or (d or {})).get("hosts", [])} if isinstance(d, dict) else {}
    t = hosts.get("target.demo.test") or {}
    check("ui 5b the API carries the same result", (t.get("verdict"), t.get("version")) == ("FAIL", "8.2.20"), str(d)[:400])

    # 6. findings page lists the demo findings
    s, _, text = b.get("/findings?state=open&marked=any")
    s, d = b.api("/api/v1/findings?state=open")
    keys = [r["finding_key"] for r in (d or {}).get("rows", [])]
    ids = sorted({r["check_id"] for r in (d or {}).get("rows", [])})
    check("ui 6 the findings page lists every check id the API returns for the same snapshot (brain consistency)",
          ids and all(i in text for i in ids), f"API check ids: {ids}; missing on the page: {[i for i in ids if i not in text]}")
    for cid in a.expect.split(","):
        check(f"ui 6 the snapshot holds demo finding {cid} and the page lists it", cid in text, f"API check ids: {ids}")
    check("ui 6 findings API lists the demo findings", len(keys) >= len(a.expect.split(",")), len(keys))

    # 6b. the analyst, with the mock provider (lab mode): confirm what is sent, a brief appears, its proposal is
    # accepted on its own page and becomes a mark with an audit entry
    s, _, text = b.get("/settings")
    check("ui 6b the Settings page states what the analyst sends and to whom", s == 200 and "What the analyst sends, and to whom" in text
          and "built-in mock provider" in text, s)
    s, h, _ = b.post_form("/settings", "/settings/analyst/consent", {"confirm": "yes"})
    check("ui 6b an admin confirms the statement", s == 303 and "msg=" in (h.get("Location", "") if h else ""), h.get("Location") if h else s)
    s, h, _ = b.post_form("/analyst", "/analyst/brief", {})
    check("ui 6b a brief is requested", s == 303 and "msg=" in (h.get("Location", "") if h else ""), h.get("Location") if h else s)
    brief = None
    deadline = time.time() + 120
    while time.time() < deadline:
        _, d = b.api("/api/v1/analyst")
        brief = (d or {}).get("brief")
        if brief and not (d.get("state") or {}).get("running"):
            break
        time.sleep(2)
    check("ui 6b the brief finished", brief and brief.get("status") == "done" and brief.get("outcome") == "ok", str(brief)[:300])
    s, _, text = b.get("/analyst")
    check("ui 6b the brief appears on the analyst page, the counts labeled as the application's",
          s == 200 and "Top three (written by the model)" in text and "computed by the application from the snapshot" in text, s)
    m = re.search(r'href="/analyst/proposals/(\d+)"', text)
    pid = m.group(1) if m else None
    check("ui 6b the brief left a pending proposal in the queue", pid, text[text.find("Proposals waiting"):][:300])
    if pid:
        s, _, ptext = b.get(f"/analyst/proposals/{pid}")
        check("ui 6b the proposal page shows the finding's stored evidence beside the proposal", s == 200 and "Stored evidence" in ptext, s)
        fk = re.search(r'href="/findings/([0-9a-f]{8,64})"', ptext)
        s, h, _ = b.post_form(f"/analyst/proposals/{pid}", f"/analyst/proposals/{pid}/accept", {})
        check("ui 6b the proposal is accepted through the UI", s == 303 and "msg=" in (h.get("Location", "") if h else ""), h.get("Location") if h else s)
        _, fd = b.api(f"/api/v1/findings/{fk.group(1)}") if fk else (None, None)
        mk = (fd or {}).get("mark") or {}
        check("ui 6b it became a mark by the admin", mk.get("created_by") == "e2e-admin" and mk.get("kind") == "false_positive", str(mk)[:200])
        _, ad = b.api("/api/v1/audit?action=mark-add")
        e = ((ad or {}).get("entries") or [{}])[0]
        check("ui 6b the mark's audit entry names the person and the analyst run",
              e.get("actor") == "e2e-admin" and f"proposal {pid} of analyst run" in (e.get("detail") or ""), str(e)[:300])

    # 7. every page and API response, including every finding and host detail
    paths = ["/", "/findings", "/findings?state=&marked=any", "/assets", "/domains", "/runs", "/runs/live", "/scope", "/schedules",
             "/version-watch", "/version-watch/php-example", "/docs/version-watch", "/analyst", "/settings", "/audit",
             "/api/docs", "/docs/data-flows", "/api/v1/version-watch/php-example",
             "/api/v1/overview", "/api/v1/findings?state=", "/api/v1/assets", "/api/v1/domains", "/api/v1/runs", "/api/v1/scope",
             "/api/v1/schedules", "/api/v1/version-watch", "/api/v1/audit", "/api/v1/settings", "/api/v1/openapi.json",
             "/analyst/runs/1", "/api/v1/analyst", "/api/v1/analyst/runs/1", "/docs/analyst"]
    paths += [f"/analyst/proposals/{pid}", f"/api/v1/analyst/proposals/{pid}"] if pid else []
    paths += [f"/findings/{k}" for k in keys] + [f"/api/v1/findings/{k}" for k in keys]
    _, ad = b.api("/api/v1/assets")
    hosts = [r["hostname"] for r in (ad or {}).get("rows", [])]
    paths += [f"/assets/{h}" for h in hosts] + [f"/api/v1/assets/{h}" for h in hosts]
    bad = []
    for p in paths:
        s, hd, text = b.get(p)
        if s != 200 or "default-src 'none'" not in (hd.get("Content-Security-Policy") or ""):
            bad.append(f"{p}:{s}")
    check(f"ui 7 {len(paths)} pages and API responses load with the content security policy", not bad, bad)

    title = canon["script"]["title"]
    _, _, assets_page = b.get("/assets")
    def esc(t):   # Jinja writes ' as &#39; and " as &#34; (Python's html.escape writes &#x27; and &quot;): both are escapes
        return html.escape(t, quote=True).replace("&#x27;", "&#39;").replace("&quot;", "&#34;")
    check("ui 7 the script-tag title is shown escaped on the assets page", esc(title) in assets_page, esc(title))
    live = [p for p, t in b.seen if "<script>alert(" in t]
    check("ui 7 the script-tag title is never a live tag in any page or API response", not live, live)

    shown = sorted({p for p, t in b.seen if "momus-injection" in t})
    marked_up = sorted({p for p, t in b.seen if re.search(r"<[^>]*momus-injection", t)})
    check("ui 7 the demo target's text addressed to an AI model is shown on some page (so the next check is not vacuous)", shown, shown)
    check("ui 7 that text is never inside markup (a tag or an attribute) on any page or API response, analyst pages included",
          not marked_up, marked_up[:5])
    secrets = {k: "".join(v["parts"]) for k, v in canon["secrets"].items()}
    for k, v in sorted(secrets.items()):
        hits = sorted({p for p, t in b.seen if v in t or v.lower() in t.lower() or urllib.parse.quote(v, safe="") in t})
        check(f"ui 8 canary {k} appears in no page or API response", not hits, hits[:5])

    # 9. audit log
    _, d = b.api("/api/v1/audit")
    acts = [e["action"] for e in (d or {}).get("entries", [])]
    want = {"bootstrap": 1, "domain-add": len(a.targets.split(",")), "inventory-approve": 1, "host-approve": 1, "watch-add": 1,
            "analyst-consent": 1, "analyst-run": 1, "proposal-accept": 1}
    for act, n in want.items():
        check(f"ui 9 audit log has {n} '{act}' entr{'y' if n == 1 else 'ies'}", acts.count(act) == n, acts.count(act))
    check("ui 9 audit log has the queued jobs (inventory and full, plus scope syncs)", acts.count("job-queue") >= 2, acts.count("job-queue"))
    check("ui 9 audit log recorded the refused second job", "job-refused" in acts)
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
