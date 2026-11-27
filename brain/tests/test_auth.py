import datetime as dt

from app import auth, db as dbm
from conftest import ORIGIN, PASSWORD, Browser, bootstrap_token
from helpers import PUBLIC, routes


def test_every_route_except_login_and_bootstrap_needs_a_session(app, anon, published):
    seen = 0
    for method, tmpl, path in routes(app):
        if tmpl in PUBLIC:
            continue
        if method == "GET":
            r = anon.get(path)
            if path.startswith("/api/"):
                assert r.status_code == 401, (path, r.status_code)
            else:
                assert r.status_code == 303 and r.headers["location"].startswith("/login"), (path, r.status_code)
        else:
            r = anon.post(path, data={"csrf": "x"})
            assert r.status_code in (401, 403), (method, path, r.status_code)
            assert "a1b2" not in r.text and "momus-xss" not in r.text
        seen += 1
    assert seen >= 30
    # static files are public assets, nothing else
    assert anon.get("/static/style.css").status_code == 200
    assert "import" not in anon.get("/static/../app/auth.py").text


def test_htmx_request_without_session_is_refused_not_redirected(anon):
    r = anon.get("/runs/live", headers={"HX-Request": "true"})
    assert r.status_code == 401 and r.headers["HX-Redirect"] == "/login"


def test_bootstrap_token_works_once(app, settings):
    b = Browser(app)
    tok = bootstrap_token(settings)
    pre = b.pre_token("/bootstrap")
    form = {"token": tok, "username": "admin", "password": PASSWORD, "password2": PASSWORD, "owner_rule": "yes", "csrf": pre}
    bad = b.c.post("/bootstrap", data={**form, "token": "wrong"}, headers={"Origin": ORIGIN})
    assert bad.status_code == 400
    r = b.c.post("/bootstrap", data=form, headers={"Origin": ORIGIN})
    assert r.status_code == 303 and r.headers["location"] == "/scope"
    c2 = Browser(app)
    pre2 = c2.pre_token("/login")
    again = c2.c.post("/bootstrap", data={**form, "username": "second", "csrf": pre2}, headers={"Origin": ORIGIN})
    assert again.status_code in (400, 403)
    assert c2.get("/bootstrap").status_code == 404
    conn = dbm.connect(settings.db_path)
    assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 1
    assert auth.ensure_bootstrap(conn) is None      # no new token once an account exists
    conn.close()


def test_bootstrap_token_printed_to_log_at_first_start(tmp_path, capsys):
    from conftest import make_settings
    from app.web import create_app
    create_app(make_settings(tmp_path), start_background=False)
    out = capsys.readouterr().out
    assert "BOOTSTRAP TOKEN:" in out


def test_login_rate_limit_per_account(app, admin):
    b = Browser(app)
    for _ in range(5):
        r = b.login("admin", "wrong password!!")
        assert r.status_code == 400
    r = b.login("admin", PASSWORD)          # right password, but the account is locked for the window
    assert r.status_code == 429
    assert "Too many failed attempts" in r.text


def test_login_rate_limit_per_address(app, admin, settings):
    b = Browser(app)
    for i in range(settings.login_max_failures * 2):
        b.login(f"nobody{i}", "wrong password!!")
    r = b.login("admin", PASSWORD)
    assert r.status_code == 429


def test_session_cookie_flags(app, settings):
    b = Browser(app)
    tok = bootstrap_token(settings)
    pre = b.pre_token("/bootstrap")
    r = b.c.post("/bootstrap", data={"token": tok, "username": "admin", "password": PASSWORD, "password2": PASSWORD,
                                     "owner_rule": "yes", "csrf": pre}, headers={"Origin": ORIGIN})
    sc = r.headers["set-cookie"].lower()
    assert "momus_session=" in sc and "httponly" in sc and "samesite=strict" in sc and "path=/" in sc


def test_secure_cookie_setting(tmp_path):
    from conftest import make_settings
    s = make_settings(tmp_path, cookie_secure=True)
    assert s.cookie_name == "__Host-momus_session"


def _age_sessions(settings, **delta):
    conn = dbm.connect(settings.db_path)
    old = dbm.iso(dbm.now() - dt.timedelta(**delta))
    conn.execute("UPDATE sessions SET last_seen_at=?", (old,))
    conn.close()


def test_idle_timeout(admin, settings):
    assert admin.get("/").status_code == 200
    _age_sessions(settings, minutes=settings.session_idle_minutes + 1)
    assert admin.get("/").status_code == 303
    conn = dbm.connect(settings.db_path)
    assert conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
    conn.close()


def test_absolute_timeout(admin, settings):
    conn = dbm.connect(settings.db_path)
    conn.execute("UPDATE sessions SET created_at=?", (dbm.iso(dbm.now() - dt.timedelta(hours=settings.session_max_hours, minutes=1)),))
    conn.close()
    assert admin.get("/").status_code == 303


def test_logout_deletes_session(admin, settings):
    r = admin.post("/logout")
    assert r.status_code == 303
    conn = dbm.connect(settings.db_path)
    assert conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
    conn.close()
    assert admin.get("/").status_code == 303


def test_password_change_signs_out_other_sessions(app, admin):
    other = Browser(app)
    assert other.login().status_code == 303
    assert other.get("/").status_code == 200
    new = "a different long password"
    r = admin.post("/settings/password", data={"current": PASSWORD, "new": new, "new2": new})
    assert r.status_code == 303 and "err=" not in r.headers["location"]
    assert other.get("/").status_code == 303          # signed out
    assert admin.get("/").status_code == 200          # this session stays
    assert Browser(app).login("admin", new).status_code == 303


def test_password_rules(admin):
    r = admin.post("/settings/password", data={"current": PASSWORD, "new": "short", "new2": "short"})
    assert "err=" in r.headers["location"]
    r = admin.post("/settings/password", data={"current": "wrong wrong wrong", "new": "x" * 20, "new2": "x" * 20})
    assert "err=" in r.headers["location"]


def test_password_hash_is_scrypt(settings, admin):
    conn = dbm.connect(settings.db_path)
    h = conn.execute("SELECT pw_hash FROM users").fetchone()[0]
    conn.close()
    assert h.startswith("scrypt$") and PASSWORD not in h


def test_session_token_stored_hashed(settings, admin):
    conn = dbm.connect(settings.db_path)
    stored = [r[0] for r in conn.execute("SELECT token_hash FROM sessions")]
    conn.close()
    cookie = admin.c.cookies.get("momus_session")
    assert cookie and cookie not in stored and auth.token_hash(cookie) in stored


def test_usernames_must_fit_the_scanner_person_rule(admin):
    for bad in ('a"b', "<x>", "a$b", "ab\\c", "x"):
        r = admin.post("/settings/accounts", data={"username": bad, "password": "y" * 20})
        assert "err=" in r.headers["location"], bad


def test_open_redirect_refused(app, admin):
    b = Browser(app)
    pre = b.pre_token("/login")
    r = b.c.post("/login", data={"username": "admin", "password": PASSWORD, "csrf": pre, "next": "//evil.test/x"}, headers={"Origin": ORIGIN})
    assert r.headers["location"] == "/"


def test_live_polling_does_not_keep_a_session_alive(admin, settings):
    _age_sessions(settings, minutes=10)
    conn = dbm.connect(settings.db_path)
    before = conn.execute("SELECT last_seen_at FROM sessions").fetchone()[0]
    assert admin.get("/runs/live", headers={"HX-Request": "true"}).status_code == 200
    assert conn.execute("SELECT last_seen_at FROM sessions").fetchone()[0] == before      # polling did not touch it
    admin.get("/runs")
    assert conn.execute("SELECT last_seen_at FROM sessions").fetchone()[0] != before      # a real page view does
    conn.close()
    _age_sessions(settings, minutes=settings.session_idle_minutes + 1)
    assert admin.get("/runs/live", headers={"HX-Request": "true"}).status_code == 401    # and it still expires


def test_scope_polling_does_not_keep_a_session_alive(admin, settings):
    """The Scope page's live part polls while a domain waits for its record, which can be indefinitely."""
    _age_sessions(settings, minutes=10)
    conn = dbm.connect(settings.db_path)
    before = conn.execute("SELECT last_seen_at FROM sessions").fetchone()[0]
    assert admin.get("/scope/live", headers={"HX-Request": "true"}).status_code == 200
    assert conn.execute("SELECT last_seen_at FROM sessions").fetchone()[0] == before
    conn.close()
    _age_sessions(settings, minutes=settings.session_idle_minutes + 1)
    assert admin.get("/scope/live", headers={"HX-Request": "true"}).status_code == 401


def test_secure_mode_cookie_flags(tmp_path):
    from conftest import make_settings
    from app.web import create_app
    s = make_settings(tmp_path, cookie_secure=True)
    app = create_app(s, start_background=False)
    b = Browser(app)
    tok = bootstrap_token(s)
    r = b.c.get("/bootstrap")
    pre_cookie = r.headers["set-cookie"].lower()
    assert pre_cookie.startswith("__host-momus_pre=") and "secure" in pre_cookie and "httponly" in pre_cookie
    import re as _re
    pre = _re.search(r'name="csrf" value="([^"]+)"', r.text).group(1)
    r = b.c.post("/bootstrap", data={"token": tok, "username": "admin", "password": PASSWORD, "password2": PASSWORD, "owner_rule": "yes",
                                     "csrf": pre}, headers={"Origin": ORIGIN, "Cookie": f"__Host-momus_pre={pre}"})
    assert r.status_code == 303
    cookies = [v.lower() for k, v in r.headers.multi_items() if k.lower() == "set-cookie"]
    sess = [c for c in cookies if c.startswith("__host-momus_session=")][0]
    assert "secure" in sess and "httponly" in sess and "samesite=strict" in sess and "path=/" in sess and "domain=" not in sess
    cleared = [c for c in cookies if c.startswith("__host-momus_pre=")][0]
    assert "secure" in cleared and ("max-age=0" in cleared or "expires=" in cleared)


# ---------------------------------------------------------------- MOMUS_TRUSTED_PROXY: X-Forwarded-For only from that one address
def _browser_from(app, peer):
    from fastapi.testclient import TestClient
    b = Browser(app)
    b.c = TestClient(app, base_url=ORIGIN, follow_redirects=False, client=(peer, 50000))
    b.peer = peer
    return b


def _admin_app(tmp_path, **kw):
    from conftest import make_settings
    from app.web import create_app
    s = make_settings(tmp_path, **kw)
    app = create_app(s, start_background=False)
    b = _browser_from(app, "192.0.2.200")
    tok = bootstrap_token(s)
    pre = b.pre_token("/bootstrap")
    r = b.c.post("/bootstrap", data={"token": tok, "username": "admin", "password": PASSWORD, "password2": PASSWORD,
                                     "owner_rule": "yes", "csrf": pre}, headers={"Origin": ORIGIN})
    assert r.status_code == 303
    return app, s


def _fail_logins(b, n, xff=None):
    for i in range(n):
        pre = b.pre_token("/login")
        h = {"Origin": ORIGIN, **({"X-Forwarded-For": xff(i) if callable(xff) else xff} if xff else {})}
        b.c.post("/login", data={"username": f"nobody{i}", "password": "wrong password!!", "csrf": pre, "next": "/"}, headers=h)


def _login_status(b, xff=None):
    b = _browser_from(b.c.app, b.peer)          # a fresh browser each time: no session from an earlier success
    pre = b.pre_token("/login")
    h = {"Origin": ORIGIN, **({"X-Forwarded-For": xff} if xff else {})}
    return b.c.post("/login", data={"username": "admin", "password": PASSWORD, "csrf": pre, "next": "/"}, headers=h).status_code


def test_forwarded_for_is_ignored_by_default(tmp_path):
    app, s = _admin_app(tmp_path)
    assert s.trusted_proxy == ""
    b = _browser_from(app, "10.0.0.5")
    _fail_logins(b, s.login_max_failures * 2, xff=lambda i: f"203.0.113.{i + 1}")   # a new forged address each time
    assert _login_status(b, xff="198.51.100.9") == 429                            # still limited by the real peer
    assert _login_status(_browser_from(app, "10.0.0.6")) == 303                   # another peer is not affected


def test_forwarded_for_from_the_trusted_proxy_only(tmp_path):
    app, s = _admin_app(tmp_path, trusted_proxy="10.0.0.5")
    proxy = _browser_from(app, "10.0.0.5")
    _fail_logins(proxy, s.login_max_failures * 2, xff="203.0.113.7")
    assert _login_status(proxy, xff="203.0.113.7") == 429                         # that client is limited
    assert _login_status(proxy, xff="203.0.113.8") == 303                         # another client behind the proxy is not
    assert _login_status(proxy, xff="198.51.100.1, 203.0.113.7") == 429           # the last entry (the proxy's) counts
    other = _browser_from(app, "10.0.0.6")                                         # not the proxy: header ignored
    _fail_logins(other, s.login_max_failures * 2, xff=lambda i: f"203.0.113.{i + 20}")
    assert _login_status(other, xff="198.51.100.77") == 429
    conn = dbm.connect(s.db_path)
    addrs = {r[0] for r in conn.execute("SELECT address FROM audit_log WHERE action='login-failed'")}
    conn.close()
    assert "203.0.113.7" in addrs and "10.0.0.6" in addrs and "203.0.113.20" not in addrs
    assert "10.0.0.5" not in addrs                                                 # the proxy's own address is not logged


def test_trusted_proxy_setting_accepts_one_address_only():
    from app.config import from_env
    assert from_env({"MOMUS_TRUSTED_PROXY": " 10.0.0.5 "}).trusted_proxy == "10.0.0.5"
    assert from_env({"MOMUS_TRUSTED_PROXY": "2001:DB8::1"}).trusted_proxy == "2001:db8::1"
    for bad in ("", "proxy.local", "10.0.0.0/24", "10.0.0.5,10.0.0.6", "*"):
        assert from_env({"MOMUS_TRUSTED_PROXY": bad}).trusted_proxy == ""


def test_unparsable_forwarded_for_falls_back_to_the_peer(tmp_path):
    from app.web import client_address

    class Req:
        def __init__(self, peer, xff):
            from starlette.datastructures import Headers
            self.client = type("C", (), {"host": peer})()
            self.headers = Headers(raw=[(b"x-forwarded-for", v.encode()) for v in xff])
    from conftest import make_settings
    s = make_settings(tmp_path, trusted_proxy="10.0.0.5")
    assert client_address(Req("10.0.0.5", ["not-an-ip"]), s) == "10.0.0.5"
    assert client_address(Req("10.0.0.5", ["198.51.100.1", "203.0.113.4"]), s) == "203.0.113.4"   # two header lines
    assert client_address(Req("10.0.0.5", []), s) == "10.0.0.5"
    assert client_address(Req("10.0.0.9", ["203.0.113.4"]), s) == "10.0.0.9"
