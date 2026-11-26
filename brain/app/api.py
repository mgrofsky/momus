"""The JSON API under /api/v1/. Same session and anti-forgery rules as the pages: a session cookie, and for every
state-changing call an X-CSRF-Token header with the session's token and an Origin from MOMUS_ALLOWED_ORIGINS. Responses
write <, > and & as \\u escapes. The schema and its documentation page are served to signed-in users only."""
from typing import Literal, Optional

from fastapi import Body, Depends, Path, Query, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field, StrictBool
from starlette.exceptions import HTTPException

from . import audit, auth, marks as marksm, scope as scopem, services, watches as watchesm
from .web import Ctx, get_ctx

KEY = Path(..., pattern=r"^[0-9a-f]{8,64}$")
HOST = Path(..., pattern=r"^[a-z0-9_.-]{1,253}$")
WATCH = Path(..., pattern=r"^[a-z0-9][a-z0-9-]{0,30}[a-z0-9]$")
V1 = "/api/v1"


class MarkIn(BaseModel):
    kind: Literal["false_positive", "accepted_risk", "duplicate"]
    reason: str = Field(min_length=3, max_length=2000)
    # the finding's evidence_fp as GET /api/v1/findings/{key} returned it: the mark is refused if the evidence changed
    evidence_fp: str = Field(min_length=1, max_length=64)


class EntryIn(BaseModel):
    kind: Literal["exclusion", "range", "host"]
    value: str = Field(min_length=1, max_length=300)
    action: Literal["add", "remove"] = "add"


class ProfileIn(BaseModel):
    check_profile: Optional[Literal["safe", "active"]] = None
    rate_profile: Optional[Literal["low", "normal", "fast"]] = None
    evidence: Optional[Literal["minimal", "excerpt"]] = None


class ScheduleIn(BaseModel):
    kind: Literal["daily-recheck", "monthly-full", "daily-version-watch"]
    enabled: bool
    hour: int = Field(ge=0, le=23)
    minute: int = Field(ge=0, le=59)
    day_of_month: int = Field(1, ge=1, le=31)


class AccountIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(max_length=1024)


class SessionIn(BaseModel):
    session_id: str = Field(min_length=16, max_length=16)


class WatchRemoveIn(BaseModel):
    confirm: StrictBool = False


class PasswordIn(BaseModel):
    current: str = Field(max_length=1024)
    new: str = Field(max_length=1024)


def register(app):
    @app.get(f"{V1}/me", summary="The signed-in account and this session's anti-forgery token")
    def me(c: Ctx = Depends(get_ctx)):
        return {"username": c.user, "role": c.session["role"], "csrf_token": c.session["csrf"]}

    @app.get(f"{V1}/overview", summary="Band counts, latest run changes, trend, top three open findings, scanner heartbeat")
    def overview(c: Ctx = Depends(get_ctx)):
        return services.overview(c)

    @app.get(f"{V1}/findings", summary="Findings with filters: band, state, domain, class, source, marked; sort; page")
    def findings(band: Optional[str] = None, state: Optional[str] = None, domain: Optional[str] = None,
                 klass: Optional[str] = Query(None, alias="class"), source: Optional[str] = None,
                 marked: Optional[Literal["any", "marked", "unmarked"]] = None,
                 sort: Literal["priority", "score", "host", "title", "first_seen", "last_seen", "source"] = "priority",
                 page: int = 1, c: Ctx = Depends(get_ctx)):
        p = {"band": band, "state": state, "domain": domain, "klass": klass, "source": source, "marked": marked, "sort": sort,
             "page": max(1, min(page, 10000))}
        return services.findings(c, p)

    @app.get(V1 + "/findings/{key}", summary="One finding: description, remediation, score, verdict, evidence, history, marks")
    def finding(key: str = KEY, hist_page: int = Query(1, ge=1, le=10000), c: Ctx = Depends(get_ctx)):
        d = services.finding(c, key, hist_page)
        if not d:
            raise HTTPException(404, "No such finding in the current snapshot.")
        return d

    @app.post(V1 + "/findings/{key}/mark", summary="Mark a finding (never changes its score, verdict or status)")
    def mark(body: MarkIn, key: str = KEY, c: Ctx = Depends(get_ctx)):
        try:
            marksm.add(c.db, c.snap, c.user, key, body.kind, body.reason, c.address, shown_fp=body.evidence_fp)
        except marksm.MarkError as e:
            raise HTTPException(400, str(e))
        return {"ok": True}

    @app.post(V1 + "/findings/{key}/unmark", summary="Withdraw a finding's mark")
    def unmark(key: str = KEY, c: Ctx = Depends(get_ctx)):
        try:
            marksm.withdraw(c.db, c.user, key, c.address)
        except marksm.MarkError as e:
            raise HTTPException(400, str(e))
        return {"ok": True}

    @app.get(f"{V1}/assets", summary="Inventory of the latest run with assets")
    def assets(c: Ctx = Depends(get_ctx)):
        return services.assets(c)

    @app.get(V1 + "/assets/{host}", summary="One host: profile, components, certificates, TLS, ports, endpoints, DNS, findings")
    def asset(host: str = HOST, cert_page: int = Query(1, ge=1, le=10000), tls_page: int = Query(1, ge=1, le=10000),
              c: Ctx = Depends(get_ctx)):
        d = services.asset(c, host, cert_page, tls_page)
        if not d:
            raise HTTPException(404, "No such host in the current snapshot.")
        return d

    @app.get(f"{V1}/domains", summary="Email and DNS posture per domain")
    def domains(c: Ctx = Depends(get_ctx)):
        return services.domains(c)

    @app.get(f"{V1}/runs", summary="Jobs with live status from the scanner's status files, scan runs, report files")
    def runs(runs_page: int = Query(1, ge=1, le=10000), jobs_page: int = Query(1, ge=1, le=10000), c: Ctx = Depends(get_ctx)):
        from . import jobs
        return {**services.runs(c, runs_page, jobs_page), "queue": jobs.queue_info(c)}

    @app.get(f"{V1}/scope", summary="Domains with the scanner's verification state, lists, profiles, approval, inventory")
    def scope(c: Ctx = Depends(get_ctx)):
        return services.scope_page(c)

    @app.post(f"{V1}/scope/entries", summary="Add or remove an exclusion, owned range or approved host")
    def scope_entry(body: EntryIn, c: Ctx = Depends(get_ctx)):
        try:
            if body.action == "add":
                v = scopem.add_entry(c.db, c.user, body.kind, body.value, c.address)
            else:
                v = scopem.remove_entry(c.db, c.user, body.kind, body.value, c.address)
        except scopem.ScopeError as e:
            raise HTTPException(400, str(e))
        return {"ok": True, "value": v}

    @app.post(f"{V1}/scope/profile", summary="Set the check profile (safe or active), rate profile and evidence level")
    def scope_profile(body: ProfileIn, c: Ctx = Depends(get_ctx)):
        try:
            changed = scopem.set_profile(c.db, c.user, c.address, **body.model_dump())
        except scopem.ScopeError as e:
            raise HTTPException(400, str(e))
        return {"ok": True, "changed": changed, "profile": scopem.profile(c.db)}

    @app.get(f"{V1}/schedules", summary="The daily recheck, daily version watch and monthly full run (UTC) and their next run")
    def schedules(c: Ctx = Depends(get_ctx)):
        return services.schedules(c)

    @app.post(f"{V1}/schedules", summary="Change a schedule")
    def schedule_set(body: ScheduleIn, c: Ctx = Depends(get_ctx)):
        try:
            services.set_schedule(c, body.kind, body.enabled, body.hour, body.minute, body.day_of_month)
        except ValueError as e:
            raise HTTPException(400, str(e))
        return services.schedules(c)

    @app.get(f"{V1}/version-watch", summary="Version-watch definitions, each with its latest result's counts; results no longer watched")
    def version_watch(c: Ctx = Depends(get_ctx)):
        return services.version_watch(c)

    @app.get(V1 + "/version-watch/{watch_id}", summary="One watch: its definition and its checked latest result (hosts, changes, history)")
    def version_watch_one(watch_id: str = WATCH, c: Ctx = Depends(get_ctx)):
        d = services.version_watch_one(c, watch_id)
        if not d:
            raise HTTPException(404, "No such watch, and no published results under that id.")
        return d

    @app.post(f"{V1}/version-watch/watches", summary="Add a watch, or edit the watch with that id: {id, name, product, cves, floors, hosts}")
    def version_watch_save(body: dict = Body(...), c: Ctx = Depends(get_ctx)):
        # the body is checked as it was sent (no type coercion), with the same rules as the scanner's
        try:
            outcome, w = watchesm.save(c.db, c.user, body, c.address, mode="upsert")
        except watchesm.WatchError as e:
            raise HTTPException(400, str(e))
        return {"ok": True, "outcome": outcome, "watch": w}

    @app.post(V1 + "/version-watch/watches/{watch_id}/remove", summary="Remove a watch (confirm: true); its results stay until the scanner's retention")
    def version_watch_remove(body: WatchRemoveIn, watch_id: str = WATCH, c: Ctx = Depends(get_ctx)):
        try:
            watchesm.remove(c.db, c.user, watch_id, body.confirm is True, c.address)
        except watchesm.WatchError as e:
            raise HTTPException(404 if str(e) == watchesm.E_NO_SUCH else 400, str(e))
        return {"ok": True}

    @app.get(f"{V1}/audit", summary="The audit log, newest first, 200 entries per call; pass before=<next_before> for older ones")
    def audit_log(action: Optional[str] = None, actor: Optional[str] = None, q: Optional[str] = None,
                  before: Optional[int] = Query(None, ge=1, le=10**18 - 1), c: Ctx = Depends(get_ctx)):
        rows = audit.query(c.db, action=action if action in audit.ACTIONS else None, actor=(actor or "")[:100] or None,
                           q=(q or "")[:100] or None, limit=audit.PER_PAGE + 1, before=before)
        more = len(rows) > audit.PER_PAGE
        rows = rows[:audit.PER_PAGE]
        return {"entries": rows, "next_before": rows[-1]["id"] if more and rows else None}

    @app.get(f"{V1}/settings", summary="How this instance is configured (read-only), the account's sessions")
    def settings(c: Ctx = Depends(get_ctx)):
        sess = auth.list_sessions(c.db, c.session["user_id"])
        from .analyst import views as analyst_views
        return {"instance": services.instance(c), "analyst": analyst_views.settings_info(c),
                "sessions": [{**{k: v for k, v in s.items() if k != "token_hash"}, "id": s["token_hash"][:16]} for s in sess]}

    @app.post(f"{V1}/settings/password", summary="Change the password; every other session is signed out")
    def password(body: PasswordIn, request: Request, c: Ctx = Depends(get_ctx)):
        try:
            n = auth.change_password(c.db, c.settings, c.session, request.cookies.get(c.settings.cookie_name) or "", body.current, body.new, c.address)
        except auth.AuthError as e:
            raise HTTPException(400, str(e))
        return {"ok": True, "other_sessions_signed_out": n}

    @app.post(f"{V1}/settings/accounts", summary="Create a local account (admin role)")
    def account(body: AccountIn, c: Ctx = Depends(get_ctx)):
        try:
            auth.create_account(c.db, c.settings, c.user, body.username.strip(), body.password, c.address)
        except auth.AuthError as e:
            raise HTTPException(400, str(e))
        return {"ok": True}

    @app.post(f"{V1}/settings/sessions/revoke", summary="Sign out one of your other sessions (id from GET /api/v1/settings)")
    def revoke(body: SessionIn, c: Ctx = Depends(get_ctx)):
        try:
            auth.revoke_session(c.db, c.session, body.session_id, c.address)
        except auth.AuthError as e:
            raise HTTPException(400, str(e))
        return {"ok": True}

    @app.get(f"{V1}/openapi.json", include_in_schema=False)
    def openapi(c: Ctx = Depends(get_ctx)):
        return app.openapi()

    @app.get("/api/docs", response_class=HTMLResponse, include_in_schema=False)
    def api_docs(c: Ctx = Depends(get_ctx)):
        from .pages import render
        spec = app.openapi()
        rows = []
        for path, ops in sorted(spec.get("paths", {}).items()):
            for method, op in ops.items():
                rows.append({"method": method.upper(), "path": path, "summary": op.get("summary") or ""})
        return render(c, "api_docs.html", nav=None, rows=rows)

    from . import jobs
    jobs.register_api(app)
