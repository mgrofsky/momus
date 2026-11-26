"""Sign-in limits that give real and unknown usernames the
same answers (except to a client holding a name at its limit, which sees other people's attempts on it),
a proxy deployment that cannot fall silently into the shared-address delay, IPv6 clients counted by
their /64, a flood that cannot fill the audit log one row per attempt, reserved actor names, and small hardening."""
import datetime as dt
import hashlib
import io

import pytest

from app import auth, config, db as dbm, web
from app.web import create_app
from conftest import ORIGIN, PASSWORD, Browser, bootstrap_token, make_settings
from tools import admin as admin_tool


class Clock:
    def __init__(self):
        self.t = dbm.now()

    def __call__(self):
        return self.t

    def advance(self, seconds):
        self.t = self.t + dt.timedelta(seconds=seconds)


@pytest.fixture
def clock(monkeypatch):
    c = Clock()
    monkeypatch.setattr(auth, "now", c)
    monkeypatch.setattr(dbm, "now", c)            # audit timestamps (db.iso) follow the same clock
    return c


def attempt(settings, username, password, address="192.0.2.50"):
    conn = dbm.connect(settings.db_path)
    try:
        auth.login(conn, settings, username, password, address)
        return "ok"
    except auth.Throttled as e:
        return ("wait", e.wait)
    except auth.AuthError as e:
        return str(e)
    finally:
        conn.close()


def q(settings, sql, args=()):
    conn = dbm.connect(settings.db_path)
    try:
        return [tuple(r) for r in conn.execute(sql, args)]
    finally:
        conn.close()


# ---------------------------------------------------------------- real and unknown names answer alike
def test_real_and_unknown_names_get_the_same_answers_after_the_owner_signs_in(app, admin, settings, clock):
    """Five failures each for a real and an unknown name, the owner signs in, then two
    probes per name one second apart. Both names must get exactly the same answers."""
    for i in range(settings.login_max_failures):
        assert attempt(settings, "admin", "wrong password!!", address=f"198.51.100.{i}") == "Wrong username or password."
        assert attempt(settings, "ghost", "wrong password!!", address=f"198.51.100.{100 + i}") == "Wrong username or password."
    clock.advance(20)                                         # the first delay (15 s) has run out
    assert attempt(settings, "admin", PASSWORD, address="192.0.2.10") == "ok"
    clock.advance(3600)
    answers = {}
    for name, net in (("admin", "203.0.113"), ("ghost", "233.252.0")):
        first = attempt(settings, name, "probe password", address=f"{net}.1")
        clock.advance(1)
        second = attempt(settings, name, "probe password", address=f"{net}.2")
        answers[name] = (first, second)
    assert answers["admin"] == answers["ghost"], answers
    assert answers["admin"][1][0] == "wait"                   # the owner's sign-in cleared nothing


def test_a_success_clears_nothing_and_failures_expire_only_with_the_lookback(app, admin, settings, clock):
    for i in range(settings.login_max_failures):
        attempt(settings, "admin", "wrong password!!", address=f"198.51.100.{i}")
    clock.advance(20)
    assert attempt(settings, "admin", PASSWORD, address="192.0.2.10") == "ok"
    assert attempt(settings, "admin", "typo password!", address="192.0.2.10") == "Wrong username or password."
    assert attempt(settings, "admin", PASSWORD, address="192.0.2.10")[0] == "wait"    # six failures still count
    clock.advance(24 * 3600 + 60)                             # all six are older than the lookback
    assert attempt(settings, "admin", PASSWORD, address="192.0.2.10") == "ok"


def test_the_delay_entry_is_once_per_lookback_and_does_not_depend_on_a_success(app, admin, settings, clock):
    for i in range(settings.login_max_failures):
        attempt(settings, "admin", "wrong password!!", address=f"198.51.100.{i}")
    clock.advance(20)
    assert attempt(settings, "admin", PASSWORD, address="192.0.2.10") == "ok"
    clock.advance(600)
    for i in range(settings.login_max_failures):                 # a second full streak after the success
        attempt(settings, "admin", "again wrong!!", address=f"192.0.2.{11 + i}")
        clock.advance(400)
    rows = q(settings, "SELECT COUNT(*) FROM audit_log WHERE action='login-delay' AND target='username:admin'")
    assert rows == [(1,)]                                     # no second entry after the success


# ---------------------------------------------------------------- deployments behind a proxy
def test_an_https_origin_with_an_insecure_cookie_refuses_to_start(tmp_path):
    s = make_settings(tmp_path, allowed_origins=("https://momus.example.test",), cookie_secure=False)
    with pytest.raises(getattr(web, "StartupRefused", ZeroDivisionError)) as e:
        create_app(s, start_background=False)
    assert str(e.value) == ("Refusing to start: MOMUS_ALLOWED_ORIGINS holds an https:// origin but MOMUS_COOKIE_SECURE is off, "
                            "so the session cookie would be sent without Secure. Set MOMUS_COOKIE_SECURE=1.")


def test_an_https_origin_without_a_trusted_proxy_warns_in_the_log_and_on_settings(tmp_path, capsys):
    origin = "https://momus.example.test"
    s = make_settings(tmp_path, allowed_origins=(origin,), cookie_secure=True)
    app = create_app(s, start_background=False)
    out = capsys.readouterr().out
    assert "MOMUS_TRUSTED_PROXY is empty: all clients will share one address" in out
    b = Browser(app)
    b.c.base_url = origin
    tok = bootstrap_token(s)
    r = b.c.get("/bootstrap")
    import re
    pre = re.search(r'name="csrf" value="([^"]+)"', r.text).group(1)
    r = b.c.post("/bootstrap", data={"token": tok, "username": "admin", "password": PASSWORD, "password2": PASSWORD,
                                     "owner_rule": "yes", "csrf": pre}, headers={"Origin": origin})
    assert r.status_code == 303, r.text
    page = b.get("/settings").text
    assert "MOMUS_TRUSTED_PROXY is empty: all clients will share one address" in page
    assert "proxy warning" not in page                          # shown as a warning, not as a configuration fact


def test_an_unparsable_forwarded_address_is_logged_once(tmp_path, capsys):
    s = make_settings(tmp_path, trusted_proxy="127.0.0.1")
    app = create_app(s, start_background=False)
    capsys.readouterr()
    from fastapi.testclient import TestClient
    c = TestClient(app, base_url=ORIGIN, client=("127.0.0.1", 50000))
    c.get("/login")                                               # no header at all: nothing to report
    assert "not a plain IP address" not in capsys.readouterr().out
    for bad in ("[2001:db8::1]:443", "unknown", "198.51.100.7:8080"):
        c.get("/login", headers={"X-Forwarded-For": bad})
    out = capsys.readouterr().out
    assert out.count("had a last X-Forwarded-For entry that is not a plain IP address") == 1, out


def test_clearing_one_username_says_what_remains_for_others(app, admin, settings, clock):
    for i in range(10):
        attempt(settings, f"made-up-{i}", "wrong password!!", address="192.0.2.99")
    out, err = io.StringIO(), io.StringIO()
    assert admin_tool.main(["clear-login-delays", "admin"], stdout=out, stderr=err, settings=settings) == 0
    text = out.getvalue()
    assert "10 failed sign-in attempt row(s) remain for other usernames" in text
    assert "without a username" in text


# ---------------------------------------------------------------- IPv6 clients and flood summaries
def test_ipv6_clients_are_counted_by_their_64_in_the_limits_only(app, admin, settings, clock):
    answers = []
    for i in range(1, 31):
        answers.append(attempt(settings, f"made-up-{i}", "wrong password!!", address=f"2001:db8:1:2::{i:x}"))
    refused = [a for a in answers if isinstance(a, tuple)]
    assert refused, "nothing was ever delayed"
    assert answers[settings.login_max_failures * 2][0] == "wait"
    rows = q(settings, "SELECT DISTINCT address FROM login_attempts WHERE address LIKE '2001:db8:1:2:%'")
    assert rows == [("2001:db8:1:2::/64",)]
    audited = {r[0] for r in q(settings, "SELECT address FROM audit_log WHERE action='login-failed'")}
    assert "2001:db8:1:2::1" in audited and "2001:db8:1:2::a" in audited      # the audit log keeps the full address


def test_an_ipv4_mapped_address_counts_as_the_ipv4_address(app, admin, settings, clock):
    answers = [attempt(settings, f"mapped-{i}", "wrong password!!", address="::ffff:192.0.2.7" if i % 2 else "192.0.2.7")
               for i in range(settings.login_max_failures * 2 + 1)]
    assert answers[-1][0] == "wait", answers                    # one address, whichever way it is written


def test_a_flood_writes_one_summary_entry_per_minute_instead_of_one_per_attempt(app, admin, settings, clock):
    clock.t = clock.t.replace(second=0, microsecond=0) + dt.timedelta(minutes=1)
    for i in range(45):                                       # 45 failures in one minute, each from its own address and name
        clock.advance(1)
        assert attempt(settings, f"flood-{i}", "wrong password!!", address=f"198.18.{i // 200}.{i % 200 + 1}") == \
            "Wrong username or password."
    assert q(settings, "SELECT COUNT(*) FROM login_attempts WHERE username LIKE 'flood-%'") == [(45,)]   # the limits still see every attempt
    individual = q(settings, "SELECT COUNT(*) FROM audit_log WHERE action='login-failed' AND target LIKE 'flood-%'")[0][0]
    assert individual == 30
    clock.advance(60)                                         # the minute is over; the next attempt writes its summary
    attempt(settings, "after-the-flood", "wrong password!!", address="192.0.2.200")
    rows = q(settings, "SELECT target, detail FROM audit_log WHERE action='login-flood'")
    assert len(rows) == 1 and rows[0][1].startswith("45 failed sign-ins in the minute from "), rows
    attempt(settings, "after-the-flood", "wrong password!!", address="192.0.2.201")
    assert len(q(settings, "SELECT 1 FROM audit_log WHERE action='login-flood'")) == 1             # once per minute


# ---------------------------------------------------------------- reserved actor names
@pytest.mark.parametrize("name", ["host-admin", "Scheduler", "ANALYST", "anonymous", "Smoke-Test"])
def test_actor_names_cannot_be_taken_as_accounts(admin, name):
    r = admin.post("/settings/accounts", {"username": name, "password": "another long password", "password2": "another long password"})
    assert r.status_code == 303
    page = admin.get("/settings").text
    assert name not in page.split("<h2>Accounts</h2>")[1].split("</ul>")[0]


def test_actor_names_cannot_be_taken_at_bootstrap(app, settings):
    b = Browser(app)
    tok = bootstrap_token(settings)
    pre = b.pre_token("/bootstrap")
    r = b.c.post("/bootstrap", data={"token": tok, "username": "Host-Admin", "password": PASSWORD, "password2": PASSWORD,
                                     "owner_rule": "yes", "csrf": pre}, headers={"Origin": ORIGIN})
    assert r.status_code == 400 and "reserved" in r.text
    assert q(settings, "SELECT COUNT(*) FROM users") == [(0,)]


def test_an_existing_account_with_an_actor_name_is_reported_at_start_and_left_alone(tmp_path, capsys):
    s = make_settings(tmp_path)
    create_app(s, start_background=False)
    conn = dbm.connect(s.db_path)
    conn.execute("INSERT INTO users(username, pw_hash, role, created_at, password_changed_at) VALUES('Analyst','x','admin','t','t')")
    conn.close()
    capsys.readouterr()
    create_app(s, start_background=False)
    out = capsys.readouterr().out
    assert "the account Analyst has a name the application uses for its own audit entries" in out
    assert q(s, "SELECT username FROM users") == [("Analyst",)]


# ---------------------------------------------------------------- the dummy hash
def test_the_dummy_hash_is_built_at_start_so_the_first_unknown_name_takes_one_hash(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "_DUMMY", None)                   # as in a freshly started process
    settings = make_settings(tmp_path)
    create_app(settings, start_background=False)
    calls = []
    real = hashlib.scrypt

    def counting(*a, **kw):
        calls.append(1)
        return real(*a, **kw)
    monkeypatch.setattr(auth.hashlib, "scrypt", counting)
    assert attempt(settings, "nobody-here", "wrong password!!") == "Wrong username or password."
    assert len(calls) == 1


# ---------------------------------------------------------------- delay entries after a clear
def test_after_a_clear_the_next_delay_is_audited_again(app, admin, settings, clock):
    """A delay, a clear, a second streak: two login-delay entries, not one."""
    for i in range(settings.login_max_failures):
        attempt(settings, "admin", "wrong password!!", address=f"198.51.100.{i}")
    clock.advance(5)
    assert admin_tool.clear_login_delays(dbm.connect(settings.db_path), "admin") == settings.login_max_failures
    clock.advance(5)
    for i in range(settings.login_max_failures):
        attempt(settings, "admin", "wrong password!!", address=f"198.51.100.{50 + i}")
    assert q(settings, "SELECT COUNT(*) FROM audit_log WHERE action='login-delay' AND target='username:admin'") == [(2,)]


def test_a_clear_leaves_a_young_pending_row_to_resolve(app, admin, settings, clock):
    conn = dbm.connect(settings.db_path)
    conn.execute("INSERT INTO login_attempts(username, address, at, ok) VALUES('admin','192.0.2.1',?,NULL)",
                 (dbm.iso(clock.t - dt.timedelta(seconds=30)),))
    conn.execute("INSERT INTO login_attempts(username, address, at, ok) VALUES('admin','192.0.2.1',?,NULL)",
                 (dbm.iso(clock.t - dt.timedelta(minutes=10)),))
    conn.execute("INSERT INTO login_attempts(username, address, at, ok) VALUES('admin','192.0.2.1',?,0)", (dbm.iso(clock.t),))
    assert admin_tool.clear_login_delays(conn, "admin") == 2
    assert q(settings, "SELECT ok FROM login_attempts WHERE username='admin' AND ok IS NOT 1") == [(None,)]
    conn.close()


# ---------------------------------------------------------------- a login-window variable is not a setting
def test_a_login_window_variable_is_ignored_and_logged(capsys):
    s = config.from_env({"MOMUS_LOGIN_WINDOW_MINUTES": "2000"})
    assert not hasattr(s, "login_window_minutes")
    assert "MOMUS_LOGIN_WINDOW_MINUTES is set but has no effect" in capsys.readouterr().out
    assert auth.LOOKBACK == dt.timedelta(hours=24)


# ---------------------------------------------------------------- small public posts
def test_public_posts_without_a_small_content_length_are_refused_before_the_body_is_read(anon):
    pre = anon.pre_token("/login")
    big = {"username": "admin", "password": "x", "csrf": pre, "next": "/", "pad": "a" * 20000}
    r = anon.c.post("/login", data=big, headers={"Origin": ORIGIN})
    assert r.status_code == 413
    r = anon.c.post("/bootstrap", data=big, headers={"Origin": ORIGIN})
    assert r.status_code == 413

    def chunks():
        yield b"username=admin&password=x&csrf=" + pre.encode()
    r = anon.c.post("/login", content=chunks(), headers={"Origin": ORIGIN, "Content-Type": "application/x-www-form-urlencoded"})
    assert r.status_code == 411
    body = b"username=admin&password=x&csrf=" + pre.encode()
    r = anon.c.post("/login", content=body, headers={"Origin": ORIGIN, "Content-Type": "application/x-www-form-urlencoded",
                                                     "Content-Length": str(len(body)), "Transfer-Encoding": "chunked"})
    assert r.status_code == 411                                  # a small length beside chunked framing is refused too
    r = anon.post("/login", {"username": "admin", "password": "wrong password!!", "csrf": pre, "next": "/"}, csrf=False)
    assert r.status_code == 400                                # an ordinary sign-in still works


def test_an_over_long_password_is_refused_inside_login_without_a_hash(app, admin, settings, monkeypatch):
    calls = []
    monkeypatch.setattr(auth, "check_password", lambda *a: calls.append(1) or False)
    assert attempt(settings, "admin", "x" * (auth.PASSWORD_MAX + 1)) == "Wrong username or password."
    assert calls == []
