"""The FastAPI application: security plumbing shared by every page and API route.

Default deny: the middleware refuses every request without a valid session except the paths in PUBLIC_PATHS and
the static files; every state-changing request needs a matching Origin (or Referer) from MOMUS_ALLOWED_ORIGINS and,
through a dependency on the whole app, the anti-forgery token of its session (login and bootstrap: a pre-session
token bound to a cookie). Every response gets the security headers. Pages are in pages.py, the API in api.py."""
import hmac
import ipaddress
import json
import re
import secrets
import urllib.parse

import jinja2
from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import auth, db as dbm, published, scope as scopem, snapshot
from .audit import clean as audit_clean
from .config import Settings

PUBLIC_PATHS = ("/login", "/bootstrap")
# A POST to a public path must say how long its body is, and be short, before anything reads it: the largest real
# form (bootstrap: token, username, two passwords of at most 1,024 characters, flags, the anti-forgery token) is far
# below this, even fully percent-encoded.
PUBLIC_BODY_MAX = 16 * 1024
UNPARSABLE_FORWARDED = ("brain: a request from the trusted proxy (MOMUS_TRUSTED_PROXY) had a last X-Forwarded-For entry "
                        "that is not a plain IP address, so the proxy's own address was used for the sign-in limits. "
                        "Configure the proxy to append the bare client address. (Logged once per start.)")
_unparsable_logged = False
NOT_FROM_PROXY = ("brain: WARNING: a request carried X-Forwarded-For, but the header was ignored because the request did "
                  "not come from MOMUS_TRUSTED_PROXY. If the proxy's address changed, every client now shares one address "
                  "for the sign-in limits, so anyone who fails to sign in ten times delays every sign-in: set "
                  "MOMUS_TRUSTED_PROXY to the proxy's current address. (Logged once per start.)")
_not_from_proxy_logged = False
FINDING_KEY_RE = re.compile(r"[0-9a-f]{8,64}")
CONTENT_LENGTH_RE = re.compile(r"[0-9]{1,7}")        # always used with fullmatch
NO_TOUCH_PATHS = ("/runs/live", "/analyst/live", "/scope/live")
STATIC_PREFIX = "/static/"
SAFE_METHODS = ("GET", "HEAD")
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; "
       "form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
DOWNLOAD_CSP = "sandbox; default-src 'none'"
HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    # same-origin, not no-referrer: with no-referrer browsers send "Origin: null" on POST, which the Origin check refuses
    "Referrer-Policy": "same-origin",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
}


class SafeJSONResponse(JSONResponse):
    """JSON with <, > and & written as \\u escapes, so no API response can hold a live tag even if a client renders it."""

    def render(self, content):
        text = json.dumps(content, ensure_ascii=False, allow_nan=False, separators=(",", ":"), default=str)
        return text.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026").encode("utf-8")


def _origin_of(url):
    try:
        p = urllib.parse.urlsplit(url)
    except ValueError:
        return None
    if p.scheme not in ("http", "https") or not p.netloc:
        return None
    return f"{p.scheme}://{p.netloc}".lower()


def origin_ok(request, settings):
    allowed = {o.lower() for o in settings.allowed_origins}
    o = request.headers.get("origin")
    if o is not None:
        return o.strip().rstrip("/").lower() in allowed
    r = request.headers.get("referer")
    return bool(r) and _origin_of(r) in allowed


def is_api(path):
    return path.startswith("/api/")


def client_address(request, settings=None):
    """The address the login rate limit and the audit log use: the connection's peer address, except when the peer is
    the one trusted reverse proxy (MOMUS_TRUSTED_PROXY, off by default). Then the last X-Forwarded-For entry, the address
    that proxy itself appended, is used when it parses as an address. From any other peer the header is ignored."""
    peer = request.client.host if request.client else "unknown"
    s = settings if settings is not None else getattr(request.app.state, "settings", None)
    tp = getattr(s, "trusted_proxy", "") if s is not None else ""
    if tp and _same_address(peer, tp):
        entries = [x.strip() for h in request.headers.getlist("x-forwarded-for") for x in h.split(",") if x.strip()]
        if entries:
            try:
                return str(ipaddress.ip_address(entries[-1]))[:64]
            except ValueError:
                _log_unparsable()
    elif tp and "x-forwarded-for" in request.headers:
        _log_not_from_proxy()          # most likely the setting no longer matches the proxy
    return peer[:64]


def _log_unparsable():
    global _unparsable_logged
    if not _unparsable_logged:
        _unparsable_logged = True
        print(UNPARSABLE_FORWARDED, flush=True)


def _log_not_from_proxy():
    global _not_from_proxy_logged
    if not _not_from_proxy_logged:
        _not_from_proxy_logged = True
        print(NOT_FROM_PROXY, flush=True)


class StartupRefused(Exception):
    """A setting combination the brain refuses to start with (fixed message)."""


def _same_address(a, b):
    try:
        return ipaddress.ip_address(a) == ipaddress.ip_address(b)
    except ValueError:
        return False


def make_env(settings):
    loader = jinja2.PackageLoader("app", "templates")
    env = jinja2.Environment(loader=loader, autoescape=True, trim_blocks=True, lstrip_blocks=True,
                             undefined=jinja2.ChainableUndefined)

    def t(v):
        if not v or not isinstance(v, str):
            return "never" if v in (None, "") else str(v)
        try:
            d = dbm.parse_iso(v)
            return d.astimezone(dbm.dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        except (ValueError, TypeError, OverflowError):
            return v[:40]

    def n(v):
        return "-" if v is None else v

    env.filters["t"] = t
    env.filters["n"] = n
    # a link is built from a snapshot value only when the value matches the strict pattern for its kind (Jinja's
    # urlencode leaves "/" and ".." alone, so anything else could point a link at another page of the application)
    env.tests["finding_key"] = lambda v: isinstance(v, str) and bool(FINDING_KEY_RE.fullmatch(v))
    env.tests["hostname"] = published.is_hostname
    env.tests["job_id"] = published.is_id
    env.tests["watch_id"] = published.is_watch_id
    env.globals.update(OWNERSHIP_RULE=scopem.OWNERSHIP_RULE, OWNERSHIP_STATEMENT=scopem.OWNERSHIP_STATEMENT,
                       DUE_CARE=scopem.DUE_CARE)
    return env


def startup_checks(settings):
    """Refuse an https origin with an insecure session cookie; warn when an https origin (a reverse proxy, then) has
    no trusted proxy address, because every client would then share one address for the sign-in limits."""
    if any(o.lower().startswith("https://") for o in settings.allowed_origins) and not settings.cookie_secure:
        raise StartupRefused(auth.COOKIE_REFUSAL)
    from .services import proxy_warning
    w = proxy_warning(settings)
    if w:
        print("brain: WARNING: " + w, flush=True)


def create_app(settings: Settings, start_background=True):
    startup_checks(settings)
    global _unparsable_logged, _not_from_proxy_logged
    _unparsable_logged = _not_from_proxy_logged = False
    dbm.migrate(settings.db_path)
    snapshot.remove_stale_temporaries(settings.snapshot_cache)
    auth.prepare_dummy_hash(settings.scrypt_n)       # so the first unknown username costs one hash, like every other
    boot = dbm.connect(settings.db_path)
    try:
        tok = auth.ensure_bootstrap(boot)
        auth.prune_attempts(boot, settings)
        auth.write_flood_summaries(boot)
        for name in auth.reserved_accounts(boot):
            print(auth.RESERVED_WARNING.format(name=audit_clean(name)), flush=True)
        from .analyst import runner as analyst_runner
        analyst_runner.interrupt_stale(boot)
    finally:
        boot.close()
    if tok:
        print("=" * 78, flush=True)
        print("Momus brain: no account exists yet. One-time bootstrap token (it stops working once used,", flush=True)
        print("and a new one is printed at each start until the first account exists):", flush=True)
        print(f"  BOOTSTRAP TOKEN: {tok}", flush=True)
        print(f"Open {settings.allowed_origins[0]}/bootstrap and paste it to create the first admin account.", flush=True)
        print("=" * 78, flush=True)

    async def csrf_guard(request: Request):
        if request.method in SAFE_METHODS:
            return
        sent = request.headers.get("x-csrf-token")
        if sent is None and (request.headers.get("content-type") or "").split(";")[0].strip() in (
                "application/x-www-form-urlencoded", "multipart/form-data"):
            form = await request.form()
            v = form.get("csrf")
            sent = v if isinstance(v, str) else None
        if request.url.path in PUBLIC_PATHS:
            want = request.cookies.get(settings.pre_cookie_name)
        else:
            sess = getattr(request.state, "session", None)
            want = sess["csrf"] if sess else None
        if not sent or not want or len(want) < 20 or not hmac.compare_digest(sent.encode("utf-8", "replace"), want.encode()):
            raise StarletteHTTPException(403, "The anti-forgery token is missing or wrong. Reload the page and try again.")

    app = FastAPI(title="Momus brain API", version="1", docs_url=None, redoc_url=None, openapi_url=None,
                  default_response_class=SafeJSONResponse, dependencies=[Depends(csrf_guard)])
    app.state.settings = settings
    app.state.env = make_env(settings)
    app.mount("/static", StaticFiles(packages=[("app", "static")]), name="static")

    @app.middleware("http")
    async def guard(request: Request, call_next):
        path = request.url.path
        conn = None
        try:
            if request.method not in SAFE_METHODS and not origin_ok(request, settings):
                resp = _refuse(request, 403, "Cross-site request refused: the Origin is not one of this instance's addresses.")
                return _headers(resp)
            if request.method not in SAFE_METHODS and path in PUBLIC_PATHS:
                cl = request.headers.get("content-length")
                # ASCII digits only, at most 7 of them: str.isdigit() alone accepts superscript digits and any
                # length, and int() raises on both
                if cl is None or not CONTENT_LENGTH_RE.fullmatch(cl) or "transfer-encoding" in request.headers:
                    return _headers(_refuse(request, 411, "The request must state its length."))
                if int(cl) > PUBLIC_BODY_MAX:
                    return _headers(_refuse(request, 413, "The request is too large."))
            public = path in PUBLIC_PATHS or path.startswith(STATIC_PREFIX)
            request.state.session = None
            if not path.startswith(STATIC_PREFIX):
                conn = dbm.connect(settings.db_path)
                request.state.db = conn
                cookie = request.cookies.get(settings.cookie_name)
                # background polling (the Runs page's live table) must not keep a session alive past its idle timeout
                touch = path not in NO_TOUCH_PATHS
                request.state.session = auth.load_session(conn, settings, cookie, touch=touch) if cookie else None
            if not public and request.state.session is None:
                if is_api(path):
                    resp = SafeJSONResponse({"error": "sign in first"}, status_code=401)
                elif request.method in SAFE_METHODS and "hx-request" not in request.headers:
                    nxt = path if path.startswith("/") and not path.startswith("//") else "/"
                    resp = RedirectResponse("/login?next=" + urllib.parse.quote(nxt, safe="/"), status_code=303)
                else:
                    resp = Response("Sign in first.", status_code=401, media_type="text/plain")
                    resp.headers["HX-Redirect"] = "/login"
                return _headers(resp)
            resp = await call_next(request)
            return _headers(resp)
        finally:
            if conn is not None:
                conn.close()

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException):
        return _refuse(request, exc.status_code, str(exc.detail))

    @app.exception_handler(RequestValidationError)
    async def bad_input(request: Request, exc: RequestValidationError):
        return _refuse(request, 422, "The request had a missing or invalid value.")

    @app.exception_handler(snapshot.Timeout)
    async def snapshot_timeout(request: Request, exc: snapshot.Timeout):
        print(f"brain: snapshot query stopped at the {settings.snapshot_query_seconds:g} s deadline on {request.method} "
              f"{safe_path(request)}", flush=True)
        return _headers(_refuse(request, 503, f"Reading the scan snapshot took longer than {settings.snapshot_query_seconds:g} "
                                              "seconds, so this request was stopped. Try again; if it keeps happening, the "
                                              "published snapshot may be damaged or unusually large."))

    @app.exception_handler(Exception)
    async def crash(request: Request, exc: Exception):
        print(f"brain: error on {request.method} {safe_path(request)}: {type(exc).__name__}", flush=True)
        return _headers(_refuse(request, 500, "Something went wrong on the server. The error was logged (type only)."))

    def _refuse(request, status, message):
        if is_api(request.url.path):
            return SafeJSONResponse({"error": message}, status_code=status)
        env = app.state.env
        sess = getattr(request.state, "session", None)
        html = env.get_template("error.html").render(status=status, message=message, user=sess, csrf=(sess or {}).get("csrf"),
                                                     nav=None, lab=None)
        return HTMLResponse(html, status_code=status)

    from . import pages, api   # noqa: E402  (routes)
    pages.register(app)
    api.register(app)

    if start_background:   # pending scope syncs always; schedules only when MOMUS_SCHEDULER=1 (jobs.tick)
        from . import jobs
        jobs.start_scheduler(app)
    return app


def safe_path(request):
    """The request path for the log, as escaped ASCII: it cannot hold a line break or any other control character."""
    return ascii(str(request.scope.get("path") or "")[:100])[1:-1]


def _headers(resp):
    for k, v in HEADERS.items():
        if k not in resp.headers:
            resp.headers[k] = v
    if "cache-control" not in resp.headers:
        resp.headers["Cache-Control"] = "no-store"
    return resp


# ---------------------------------------------------------------- helpers shared by pages and API
class Ctx:
    """Per-request context: the app database, the signed-in user, settings, and lazy access to published data."""

    def __init__(self, request: Request):
        self.request = request
        self.app = request.app
        self.settings = request.app.state.settings
        self.db = request.state.db
        self.session = request.state.session
        self.user = self.session["username"] if self.session else None
        self.address = client_address(request)
        self._snap = None
        self._snapconn = None
        self._scanner = False

    @property
    def snap_state(self):
        if self._snap is None:
            self._snap = snapshot.current(self.settings.published_dir, self.settings.snapshot_cache,
                                      self.settings.snapshot_max_mb * snapshot.MIB)
        return self._snap

    @property
    def snap(self):
        """A read-only connection to the verified snapshot, or None."""
        if self._snapconn is None and self.snap_state.ok:
            self._snapconn = snapshot.connect(self.snap_state, self.settings.snapshot_query_seconds)
        return self._snapconn

    @property
    def scanner(self):
        if self._scanner is False:
            self._scanner = published.scanner(self.settings.published_dir)
        return self._scanner

    @property
    def lab(self):
        """Lab mode comes only from the brain's own MOMUS_LAB; the scanner's heartbeat can never switch it on."""
        return bool(self.settings.lab)

    def close(self):
        if self._snapconn is not None:
            self._snapconn.close()
            self._snapconn = None


def get_ctx(request: Request):
    c = Ctx(request)
    try:
        yield c
    finally:
        c.close()


def new_pre_token():
    return secrets.token_urlsafe(32)
