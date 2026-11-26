"""Server-rendered pages. Every value is escaped by the templates (autoescape on, no |safe anywhere)."""
import os
import re
import urllib.parse

from fastapi import Depends, Form, Path, Request
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from starlette.exceptions import HTTPException

from . import audit, auth, flash as flashm, marks as marksm, published, scope as scopem, services, watches as watchesm
from .web import DOWNLOAD_CSP, Ctx, get_ctx, new_pre_token

NEXT_RE = re.compile(r"^/(?!/)[A-Za-z0-9/_.\-?=&%]{0,300}$")
KEY = Path(..., pattern=r"^[0-9a-f]{8,64}$")
HOST = Path(..., pattern=r"^[a-z0-9_.-]{1,253}$")
RUN = Path(..., pattern=r"^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$")
WATCH = Path(..., pattern=r"^[a-z0-9][a-z0-9-]{0,30}[a-z0-9]$")


def render(c: Ctx, name, nav=None, status=200, **kw):
    tpl = c.app.state.env.get_template(name)
    from .jobs import lab_disagreement
    html = tpl.render(user=c.user, csrf=(c.session or {}).get("csrf"), nav=nav, lab=c.lab, lab_cidr=c.settings.lab_cidr,
                      lab_warning=lab_disagreement(c.settings, c.scanner) if c.user else None, **kw)
    return HTMLResponse(html, status_code=status)


def _clear(resp, settings, name):
    """Delete a cookie with the same flags it was set with (a __Host- cookie is only cleared by a Secure deletion)."""
    resp.delete_cookie(name, path="/", secure=settings.cookie_secure, httponly=True, samesite="strict")


def back(url):
    return RedirectResponse(url, status_code=303)


def flash_url(url, msg=None, err=None):
    """The redirect target with the status line as a short code from the fixed table (app/flash.py)."""
    return flashm.url(url, msg=msg, err=err)


def flash(request):
    """The status line for this request, looked up in the fixed table; never the query string's own text."""
    return flashm.read(request)


MAX_REPORT = 512 * 1024 * 1024
CHUNK = 1024 * 1024


def _stream(fh, size):
    try:
        left = size
        while left > 0:
            chunk = fh.read(min(CHUNK, left))
            if not chunk:
                break
            left -= len(chunk)
            yield chunk
    finally:
        fh.close()


def register(app):
    # ---------------------------------------------------------------- sign in
    def login_page(c, request, error=None, status=200, next_url="/"):
        pre = request.cookies.get(c.settings.pre_cookie_name) or new_pre_token()
        resp = render(c, "login.html", status=status, pre=pre, error=error, next_url=next_url, bootstrap_open=auth.bootstrap_open(c.db))
        resp.set_cookie(c.settings.pre_cookie_name, pre, httponly=True, samesite="strict", secure=c.settings.cookie_secure, path="/")
        return resp

    @app.get("/login", response_class=HTMLResponse, include_in_schema=False)
    def login_get(request: Request, c: Ctx = Depends(get_ctx)):
        if c.session:
            return back("/")
        nxt = request.query_params.get("next") or "/"
        return login_page(c, request, next_url=nxt if NEXT_RE.fullmatch(nxt) else "/")

    @app.post("/login", response_class=HTMLResponse, include_in_schema=False)
    def login_post(request: Request, username: str = Form(""), password: str = Form(""), next: str = Form("/"),
                   c: Ctx = Depends(get_ctx)):
        try:
            u = auth.login(c.db, c.settings, username, password, c.address)
        except auth.AuthError as e:
            return login_page(c, request, error=str(e), status=429 if isinstance(e, auth.Throttled) else 503 if isinstance(e, auth.Busy) else 400,
                              next_url=next if NEXT_RE.fullmatch(next) else "/")
        tok = auth.create_session(c.db, u["id"], c.address, request.headers.get("user-agent"))
        resp = back(next if NEXT_RE.fullmatch(next) else "/")
        resp.set_cookie(c.settings.cookie_name, tok, httponly=True, samesite="strict", secure=c.settings.cookie_secure, path="/")
        _clear(resp, c.settings, c.settings.pre_cookie_name)
        return resp

    @app.post("/logout", include_in_schema=False)
    def logout(request: Request, c: Ctx = Depends(get_ctx)):
        auth.delete_session(c.db, request.cookies.get(c.settings.cookie_name) or "")
        audit.write(c.db, c.user, "logout", target=c.user, address=c.address)
        resp = back("/login")
        _clear(resp, c.settings, c.settings.cookie_name)
        return resp

    @app.get("/bootstrap", response_class=HTMLResponse, include_in_schema=False)
    def bootstrap_get(request: Request, c: Ctx = Depends(get_ctx)):
        if not auth.bootstrap_open(c.db):
            return render(c, "message.html", status=404, title="Already set up",
                          text="The first account exists, so the bootstrap token no longer works. Sign in instead.", link="/login")
        pre = request.cookies.get(c.settings.pre_cookie_name) or new_pre_token()
        resp = render(c, "bootstrap.html", pre=pre, error=None, min_len=c.settings.password_min_length)
        resp.set_cookie(c.settings.pre_cookie_name, pre, httponly=True, samesite="strict", secure=c.settings.cookie_secure, path="/")
        return resp

    @app.post("/bootstrap", response_class=HTMLResponse, include_in_schema=False)
    def bootstrap_post(request: Request, token: str = Form(""), username: str = Form(""), password: str = Form(""),
                       password2: str = Form(""), owner_rule: str = Form(""), c: Ctx = Depends(get_ctx)):
        pre = request.cookies.get(c.settings.pre_cookie_name) or new_pre_token()
        err = None
        if password != password2:
            err = "The two passwords differ."
        elif owner_rule != "yes":
            err = "Confirm that you will only scan systems you explicitly own."
        if not err:
            try:
                uid = auth.bootstrap(c.db, c.settings, token.strip(), username.strip(), password, c.address)
            except auth.AuthError as e:
                err = str(e)
        if err:
            return render(c, "bootstrap.html", status=400, pre=pre, error=err, min_len=c.settings.password_min_length)
        tok = auth.create_session(c.db, uid, c.address, request.headers.get("user-agent"))
        resp = back("/scope")
        resp.set_cookie(c.settings.cookie_name, tok, httponly=True, samesite="strict", secure=c.settings.cookie_secure, path="/")
        _clear(resp, c.settings, c.settings.pre_cookie_name)
        return resp

    # ---------------------------------------------------------------- read-only pages
    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    def overview(c: Ctx = Depends(get_ctx)):
        d = services.overview(c)
        return render(c, "overview.html", nav="overview", d=d, bars=services.trend_bars(d["trend"]))

    def finding_params(request):
        q = request.query_params
        if not any(k in q for k in ("band", "state", "domain", "class", "source", "marked", "sort", "page")):
            return {"state": "open", "marked": "unmarked", "sort": "priority", "page": 1, "default": True}
        try:
            page = max(1, min(int(q.get("page") or 1), 10000))
        except ValueError:
            page = 1
        return {"band": q.get("band") or None, "state": q.get("state") or None, "domain": (q.get("domain") or None),
                "klass": q.get("class") or None, "source": q.get("source") or None, "marked": q.get("marked") or None,
                "sort": q.get("sort") or "priority", "page": page, "default": False}

    @app.get("/findings", response_class=HTMLResponse, include_in_schema=False)
    def findings_page(request: Request, c: Ctx = Depends(get_ctx)):
        p = finding_params(request)
        return render(c, "findings.html", nav="findings", d=services.findings(c, p), p=p)

    @app.get("/findings/{key}", response_class=HTMLResponse, include_in_schema=False)
    def finding_page(request: Request, key: str = KEY, c: Ctx = Depends(get_ctx)):
        d = services.finding(c, key, request.query_params.get("hist_page"))
        if not d:
            raise HTTPException(404, "No such finding in the current snapshot.")
        return render(c, "finding.html", nav="findings", d=d, kinds=marksm.KINDS, f=flash(request))

    @app.post("/findings/{key}/mark", include_in_schema=False)
    def finding_mark(key: str = KEY, kind: str = Form(""), reason: str = Form(""), evidence_fp: str = Form(""),
                     c: Ctx = Depends(get_ctx)):
        try:
            # the form carries the evidence fingerprint the page showed; a mark is refused for evidence nobody saw
            marksm.add(c.db, c.snap, c.user, key, kind, reason, c.address, shown_fp=evidence_fp)
        except marksm.MarkError as e:
            return back(flash_url(f"/findings/{key}", err=str(e)))
        return back(flash_url(f"/findings/{key}", msg="Mark saved. It does not change the finding's score, verdict or status."))

    @app.post("/findings/{key}/unmark", include_in_schema=False)
    def finding_unmark(key: str = KEY, c: Ctx = Depends(get_ctx)):
        try:
            marksm.withdraw(c.db, c.user, key, c.address)
        except marksm.MarkError as e:
            return back(flash_url(f"/findings/{key}", err=str(e)))
        return back(flash_url(f"/findings/{key}", msg="Mark withdrawn."))

    @app.get("/assets", response_class=HTMLResponse, include_in_schema=False)
    def assets_page(c: Ctx = Depends(get_ctx)):
        return render(c, "assets.html", nav="assets", d=services.assets(c))

    @app.get("/assets/{host}", response_class=HTMLResponse, include_in_schema=False)
    def asset_page(request: Request, host: str = HOST, c: Ctx = Depends(get_ctx)):
        q = request.query_params
        d = services.asset(c, host, q.get("cert_page"), q.get("tls_page"))
        if not d:
            raise HTTPException(404, "No such host in the current snapshot.")
        return render(c, "asset.html", nav="assets", d=d, host=host)

    @app.get("/domains", response_class=HTMLResponse, include_in_schema=False)
    def domains_page(c: Ctx = Depends(get_ctx)):
        return render(c, "domains.html", nav="domains", d=services.domains(c))

    @app.get("/runs", response_class=HTMLResponse, include_in_schema=False)
    def runs_page(request: Request, c: Ctx = Depends(get_ctx)):
        from . import jobs
        q = request.query_params
        return render(c, "runs.html", nav="runs", d=services.runs(c, q.get("runs_page"), q.get("jobs_page")), q=jobs.queue_info(c), f=flash(request))

    @app.get("/runs/live", response_class=HTMLResponse, include_in_schema=False)
    def runs_live(request: Request, c: Ctx = Depends(get_ctx)):
        return render(c, "partials/jobs_table.html", d=services.runs(c, 1, request.query_params.get("jobs_page")))

    @app.get("/runs/{run_id}/files/{name}", include_in_schema=False)
    def report_download(run_id: str = RUN, name: str = Path(..., pattern=r"^[a-z0-9][a-z0-9_.-]{1,200}$"), c: Ctx = Depends(get_ctx)):
        try:
            fh = published.open_report(c.settings.published_dir, run_id, name, MAX_REPORT)
        except (OSError, published.Unsafe):
            fh = None
        if fh is None:
            raise HTTPException(404, "No such report file.")
        ctype = "text/csv; charset=utf-8" if name.endswith(".csv") else "text/html; charset=utf-8"
        # streamed from the handle opened above (no second open, so no swap in between), 1 MiB at a time, and never
        # more than the size the file had when it was opened; no Content-Length is promised
        return StreamingResponse(_stream(fh, os.fstat(fh.fileno()).st_size), media_type=ctype, headers={
            "Content-Disposition": f'attachment; filename="{name}"', "Content-Security-Policy": DOWNLOAD_CSP,
            "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"})

    # ---------------------------------------------------------------- version watch
    def watch_list(c, request, form=None, error=None, status=200):
        return render(c, "version_watch.html", nav="version-watch", status=status, d=services.version_watch(c), f=flash(request),
                      form=form or watchesm.form_values({}), error=error)

    def watch_detail(c, request, d, form=None, error=None, status=200):
        return render(c, "version_watch_detail.html", nav="version-watch", status=status, d=d, f=flash(request),
                      form=form or watchesm.form_values(d["definition"] or {}), error=error)

    @app.get("/version-watch", response_class=HTMLResponse, include_in_schema=False)
    def version_watch(request: Request, c: Ctx = Depends(get_ctx)):
        return watch_list(c, request)

    @app.get("/version-watch/{watch_id}", response_class=HTMLResponse, include_in_schema=False)
    def version_watch_one(request: Request, watch_id: str = WATCH, c: Ctx = Depends(get_ctx)):
        d = services.version_watch_one(c, watch_id)
        if not d:
            raise HTTPException(404, "No such watch, and no published results under that id.")
        return watch_detail(c, request, d)

    @app.post("/version-watch/watches", include_in_schema=False)
    def version_watch_save(request: Request, watch_id: str = Form(""), name: str = Form(""), product: str = Form(""),
                           cves: str = Form(""), floors: str = Form(""), hosts: str = Form(""), edit: str = Form(""),
                           c: Ctx = Depends(get_ctx)):
        editing = edit == "1"
        try:
            raw = watchesm.parse_form(watch_id, name, product, cves, floors, hosts)
            outcome, w = watchesm.save(c.db, c.user, raw, c.address, mode="edit" if editing else "add")
        except watchesm.WatchError as e:
            typed = watchesm.raw_form_values(watch_id, name, product, cves, floors, hosts)
            d = services.version_watch_one(c, watch_id.strip()) if editing else None
            if d and d["watched"]:
                return watch_detail(c, request, d, form=typed, error=str(e), status=400)
            return watch_list(c, request, form=typed, error=str(e), status=400)
        if outcome == "added":
            return back(flash_url("/version-watch", msg=f"Watch {w['id']} added. The next version-watch job carries it."))
        if outcome == "edited":
            return back(flash_url(f"/version-watch/{w['id']}", msg=f"Watch {w['id']} saved. The next version-watch job carries the change."))
        return back(flash_url(f"/version-watch/{w['id']}", msg="Nothing changed."))

    @app.post("/version-watch/watches/{watch_id}/remove", include_in_schema=False)
    def version_watch_remove(watch_id: str = WATCH, confirm: str = Form(""), c: Ctx = Depends(get_ctx)):
        try:
            watchesm.remove(c.db, c.user, watch_id, confirm == "yes", c.address)
        except watchesm.WatchError as e:
            known = published.is_watch_id(watch_id) and str(e) != watchesm.E_NO_SUCH
            here = f"/version-watch/{watch_id}" if known else "/version-watch"
            return back(flash_url(here, err=str(e)))
        return back(flash_url("/version-watch", msg=f"Watch {watch_id} removed. Its published results stay until the scanner's "
                                                    "retention removes them (90 days after its last result)."))

    @app.get("/audit", response_class=HTMLResponse, include_in_schema=False)
    def audit_page(request: Request, c: Ctx = Depends(get_ctx)):
        q = request.query_params
        action = q.get("action") if q.get("action") in audit.ACTIONS else None
        before = audit.before_id(q.get("before"))
        rows = audit.query(c.db, action=action, actor=(q.get("actor") or None)[:100] if q.get("actor") else None,
                           q=(q.get("q") or None)[:100] if q.get("q") else None, limit=audit.PER_PAGE + 1, before=before)
        more = len(rows) > audit.PER_PAGE
        rows = rows[:audit.PER_PAGE]
        sel = {"action": action or "", "actor": (q.get("actor") or "")[:100], "q": (q.get("q") or "")[:100]}
        older = {**{k: v for k, v in sel.items() if v}, "before": rows[-1]["id"]} if more and rows else None
        return render(c, "audit.html", nav="audit", rows=rows, actions=audit.ACTIONS, sel=sel, older=older, newest=bool(before))

    def doc_page(c, name, title):
        try:
            with open(os.path.join(c.settings.docs_dir, name), encoding="utf-8") as fh:
                text = fh.read()
        except OSError:
            text = f"docs/{name} is not in this image. Read it in the repository: docs/{name}"
        return render(c, "doc.html", nav=None, title=title, text=text, source=f"docs/{name}")

    @app.get("/docs/data-flows", response_class=HTMLResponse, include_in_schema=False)
    def data_flows(c: Ctx = Depends(get_ctx)):
        return doc_page(c, "data-flows.md", "What leaves the machine during a scan")

    @app.get("/docs/version-watch", response_class=HTMLResponse, include_in_schema=False)
    def version_watch_doc(c: Ctx = Depends(get_ctx)):
        return doc_page(c, "version-watch.md", "Version watch")

    @app.get("/docs/analyst", response_class=HTMLResponse, include_in_schema=False)
    def analyst_doc(c: Ctx = Depends(get_ctx)):
        return doc_page(c, "analyst.md", "The analyst")

    # ---------------------------------------------------------------- schedules
    @app.get("/schedules", response_class=HTMLResponse, include_in_schema=False)
    def schedules_page(request: Request, c: Ctx = Depends(get_ctx)):
        return render(c, "schedules.html", nav="schedules", d=services.schedules(c), f=flash(request))

    @app.post("/schedules", include_in_schema=False)
    def schedules_post(kind: str = Form(""), enabled: str = Form(""), hour: int = Form(...), minute: int = Form(...),
                       day_of_month: int = Form(1), c: Ctx = Depends(get_ctx)):
        try:
            services.set_schedule(c, kind, enabled == "on", hour, minute, day_of_month)
        except ValueError as e:
            return back(flash_url("/schedules", err=str(e)))
        return back(flash_url("/schedules", msg="Schedule saved."))

    # ---------------------------------------------------------------- settings
    @app.get("/settings", response_class=HTMLResponse, include_in_schema=False)
    def settings_page(request: Request, c: Ctx = Depends(get_ctx)):
        cur = auth.token_hash(request.cookies.get(c.settings.cookie_name) or "")
        sess = auth.list_sessions(c.db, c.session["user_id"])
        for s in sess:
            s["current"] = s["token_hash"] == cur
            s["id"] = s.pop("token_hash")[:16]
        users = [dict(r) for r in c.db.execute("SELECT username, role, created_at, password_changed_at FROM users ORDER BY username")]
        from .analyst import views as analyst_views
        return render(c, "settings.html", nav="settings", sessions=sess, users=users, inst=services.instance(c), f=flash(request),
                      proxy_warning=services.proxy_warning(c.settings),
                      min_len=c.settings.password_min_length, analyst=analyst_views.settings_info(c))

    @app.post("/settings/password", include_in_schema=False)
    def settings_password(request: Request, current: str = Form(""), new: str = Form(""), new2: str = Form(""), c: Ctx = Depends(get_ctx)):
        if new != new2:
            return back(flash_url("/settings", err="The two new passwords differ."))
        try:
            n = auth.change_password(c.db, c.settings, c.session, request.cookies.get(c.settings.cookie_name) or "", current, new, c.address)
        except auth.AuthError as e:
            return back(flash_url("/settings", err=str(e)))
        return back(flash_url("/settings", msg=f"Password changed. {n} other session(s) were signed out."))

    @app.post("/settings/sessions/revoke", include_in_schema=False)
    def settings_revoke(session_id: str = Form(""), c: Ctx = Depends(get_ctx)):
        try:
            auth.revoke_session(c.db, c.session, session_id, c.address)
        except auth.AuthError as e:
            return back(flash_url("/settings", err=str(e)))
        return back(flash_url("/settings", msg="Session signed out."))

    @app.post("/settings/accounts", include_in_schema=False)
    def settings_account(username: str = Form(""), password: str = Form(""), c: Ctx = Depends(get_ctx)):
        try:
            auth.create_account(c.db, c.settings, c.user, username.strip(), password, c.address)
        except auth.AuthError as e:
            return back(flash_url("/settings", err=str(e)))
        return back(flash_url("/settings", msg="Account created (admin)."))

    # ---------------------------------------------------------------- scope (domains and jobs: see jobs.py)
    @app.get("/scope", response_class=HTMLResponse, include_in_schema=False)
    def scope_page(request: Request, c: Ctx = Depends(get_ctx)):
        from . import jobs
        return render(c, "scope.html", nav="scope", d=services.scope_page(c), q=jobs.queue_info(c), f=flash(request))

    @app.post("/scope/entries", include_in_schema=False)
    def scope_entry(kind: str = Form(""), value: str = Form(""), action: str = Form("add"), c: Ctx = Depends(get_ctx)):
        if kind not in ("exclusion", "range", "host") or action not in ("add", "remove"):
            raise HTTPException(400, "Unknown scope list.")
        try:
            if action == "add":
                scopem.add_entry(c.db, c.user, kind, value, c.address)
            else:
                scopem.remove_entry(c.db, c.user, kind, value, c.address)
        except scopem.ScopeError as e:
            return back(flash_url("/scope", err=str(e)))
        return back(flash_url("/scope", msg="Scope saved. The next job carries it."))

    @app.post("/scope/profile", include_in_schema=False)
    def scope_profile(check_profile: str = Form(None), rate_profile: str = Form(None), evidence: str = Form(None), c: Ctx = Depends(get_ctx)):
        try:
            scopem.set_profile(c.db, c.user, c.address, check_profile=check_profile, rate_profile=rate_profile, evidence=evidence)
        except scopem.ScopeError as e:
            return back(flash_url("/scope", err=str(e)))
        return back(flash_url("/scope", msg="Profile saved. The next job carries it."))

    from . import jobs
    jobs.register_pages(app, render, back, flash_url)
    from .analyst import web as analyst_web
    analyst_web.register(app, render, back, flash_url)
