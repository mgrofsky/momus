"""Sign-in limits that a user who is not signed in cannot use to fill
the database or to keep the admin out, attempts counted before the hash, and audit entries that never name a typed
username as the actor."""
import datetime as dt
import threading

import pytest

from app import auth, db as dbm
from conftest import ORIGIN, PASSWORD, Browser, bootstrap_token, make_settings
from app.web import create_app


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
    monkeypatch.setattr(auth, "now", c)          # auth imports now() by name
    return c


def counts(settings):
    conn = dbm.connect(settings.db_path)
    try:
        return (conn.execute("SELECT COUNT(*) FROM login_attempts").fetchone()[0],
                conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0])
    finally:
        conn.close()


def try_login(settings, username, password, address="192.0.2.50"):
    conn = dbm.connect(settings.db_path)
    try:
        auth.login(conn, settings, username, password, address)
        return "ok"
    except auth.AuthError as e:
        if "Too many failed attempts" in str(e):        # written without the new names, so the revert check fails on behaviour
            return ("wait", getattr(e, "wait", None))
        return str(e)
    finally:
        conn.close()


def test_thousands_of_attempts_against_a_delayed_account_add_no_rows(app, admin, settings, clock):
    for _ in range(settings.login_max_failures):
        assert try_login(settings, "admin", "wrong password!!") == "Wrong username or password."
    before = counts(settings)
    for i in range(3000):
        r = try_login(settings, "admin", "wrong password!!" if i % 2 else PASSWORD, address=f"198.51.100.{i % 250}")
        assert r[0] == "wait"
    assert counts(settings) == before
    b = Browser(app)                                       # and over HTTP
    for _ in range(200):
        r = b.login("admin", "wrong password!!")
        assert r.status_code == 429 and "Too many failed attempts" in r.text
    assert counts(settings) == before


def test_refused_attempts_do_not_extend_the_delay_and_the_admin_gets_in_after_the_cap(app, admin, settings, clock):
    cap = settings.login_max_delay_seconds
    # an attacker who keeps sending bad passwords from many addresses for an hour: whenever the delay has run out, one
    # attempt is let through and fails, which grows the delay; everything in between is refused and writes nothing
    let_through = 0
    for second in range(0, 3600, 5):
        r = try_login(settings, "admin", "bad guess", address=f"203.0.113.{second % 200}")
        if not (isinstance(r, tuple) and r[0] == "wait"):
            let_through += 1
        clock.advance(5)
    assert let_through < 30                                # about F + log2(cap/base) + cap-spaced ones per window
    # the admin is refused at most for the cap, and the wait does not move while only refused attempts arrive
    r = try_login(settings, "admin", PASSWORD, address="192.0.2.10")
    assert r[0] == "wait"
    deadline = r[1] if r[1] is not None else cap
    assert deadline <= cap
    for _ in range(50):                                    # the attacker keeps going during the wait: all refused
        assert try_login(settings, "admin", "bad guess", address="203.0.113.99")[0] == "wait"
        clock.advance(deadline / 50)
    clock.advance(1)
    assert try_login(settings, "admin", PASSWORD, address="192.0.2.10") == "ok"
    # the success clears nothing. The next attempt is let through only because the wait had run
    # out, and the one after it is delayed again at once, because every failure of the hour still counts.
    assert try_login(settings, "admin", "bad guess", address="203.0.113.99") == "Wrong username or password."
    assert try_login(settings, "admin", "bad guess", address="203.0.113.98")[0] == "wait"


def test_the_delay_grows_and_caps(settings):
    f = settings.login_max_failures
    assert [auth.delay_for(n, f, settings) for n in range(f - 1, f + 8)] == [0, 15, 30, 60, 120, 240, 300, 300, 300]
    assert auth.delay_for(10 ** 6, f, settings) == settings.login_max_delay_seconds


def test_per_address_limit_is_kept(app, admin, settings, clock):
    for i in range(settings.login_max_failures * 2):
        try_login(settings, f"nobody{i}", "wrong password!!", address="192.0.2.77")
    assert try_login(settings, "admin", PASSWORD, address="192.0.2.77")[0] == "wait"
    assert try_login(settings, "admin", PASSWORD, address="192.0.2.78") == "ok"


def test_unknown_usernames_are_limited_the_same_way(app, admin, settings, clock):
    for name in ("admin", "nosuchuser"):
        for _ in range(settings.login_max_failures):
            assert try_login(settings, name, "wrong password!!", address=f"192.0.2.{len(name)}") == "Wrong username or password."
        assert try_login(settings, name, "wrong password!!", address="198.51.100.1") == ("wait", 15), name


def test_old_attempt_rows_are_pruned(app, admin, settings, clock):
    conn = dbm.connect(settings.db_path)
    old = dbm.iso(dbm.now() - dt.timedelta(days=2))
    for i in range(500):
        conn.execute("INSERT INTO login_attempts(username, address, at, ok) VALUES(?,?,?,0)", (f"u{i}", "192.0.2.1", old))
    conn.close()
    try_login(settings, "admin", "wrong password!!")
    assert counts(settings)[0] == 1
    conn = dbm.connect(settings.db_path)
    conn.execute("INSERT INTO login_attempts(username, address, at, ok) VALUES('x', '192.0.2.1', ?, 0)", (old,))
    conn.close()
    create_app(settings, start_background=False)            # and at start-up
    assert counts(settings)[0] == 1


def test_a_parallel_burst_gets_no_more_guesses_than_the_limit(app, admin, settings, monkeypatch):
    lock = threading.Lock()
    state = {"hashes": 0, "now": 0, "max": 0}
    real = auth.check_password
    gate = threading.Event()

    def counting(pw, stored):
        with lock:
            state["hashes"] += 1
            state["now"] += 1
            state["max"] = max(state["max"], state["now"])
        gate.wait(0.2)                                      # keep hashes overlapping
        try:
            return real(pw, stored)
        finally:
            with lock:
                state["now"] -= 1
    monkeypatch.setattr(auth, "check_password", counting)
    monkeypatch.setattr(auth, "HASH_WAIT_SECONDS", 30, raising=False)     # nobody gives up waiting for a hash slot here
    results = []
    start = threading.Barrier(40)

    def one(i):
        start.wait()
        results.append(try_login(settings, "admin", "wrong password!!", address=f"198.51.100.{i}"))
    ts = [threading.Thread(target=one, args=(i,)) for i in range(40)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert state["hashes"] == settings.login_max_failures              # exactly the limit got a guess
    assert state["max"] <= settings.login_hash_concurrency               # and at most N hashes ran at once
    assert sum(1 for r in results if r == "Wrong username or password.") == settings.login_max_failures
    assert sum(1 for r in results if isinstance(r, tuple) and r[0] == "wait") == 40 - settings.login_max_failures
    assert counts(settings)[0] == settings.login_max_failures


def test_a_full_hash_queue_refuses_without_counting_a_guess(app, admin, settings, monkeypatch):
    slots = auth._hash_slots(settings)
    monkeypatch.setattr(auth, "HASH_WAIT_SECONDS", 0.05)
    held = [slots.acquire(timeout=1) for _ in range(settings.login_hash_concurrency)]
    try:
        assert try_login(settings, "admin", PASSWORD) == auth.BUSY
    finally:
        for h in held:
            if h:
                slots.release()
    assert counts(settings)[0] == 0                         # the pending row was removed
    assert try_login(settings, "admin", PASSWORD) == "ok"


# ---------------------------------------------------------------- the actor of an anonymous request
def test_failed_login_audit_names_no_typed_user_as_actor(app, admin, settings):
    typed = "admin\nFAKE ENTRY\x1b[31m " + "z" * 200
    b = Browser(app)
    b.login(typed, "wrong password!!")
    conn = dbm.connect(settings.db_path)
    actor, target = conn.execute("SELECT actor, target FROM audit_log WHERE action='login-failed'").fetchone()
    conn.close()
    assert actor == "anonymous"
    assert "\n" not in target and "\x1b" not in target and " " not in target and target.startswith("adminFAKE ENTRY[31m")
    assert len(target) <= 64 + 3


def test_no_audit_call_takes_its_actor_from_typed_input():
    """Every audit.write call site: the actor is a signed-in user, the scheduler, the anonymous constant, or (for a
    successful sign-in and the bootstrap) the account just checked or created. The host recovery command
    (tools/admin.py) writes the fixed actor "host-admin", and no other file may use that actor."""
    import ast
    import os
    allowed = {"c.user", "actor", "ANONYMOUS", "'scheduler'", "row['username']", "user['username']", "username"}
    brain = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    seen = {}
    # every Python file under app/ and tools/, including the packages app/llm and app/analyst
    for sub in ("app", "tools"):
        for dp, _, files in sorted(os.walk(os.path.join(brain, sub))):
            for f in sorted(files):
                if not f.endswith(".py"):
                    continue
                rel = os.path.relpath(os.path.join(dp, f), brain)
                tree = ast.parse(open(os.path.join(dp, f)).read())
                for node in ast.walk(tree):
                    if isinstance(node, ast.Call) and getattr(node.func, "attr", None) == "write" and getattr(node.func.value, "id", None) == "audit":
                        seen.setdefault(rel, []).append(ast.unparse(node.args[1]).replace('"', "'"))
    for f, actors in seen.items():
        for a in actors:
            if f == "tools/admin.py":
                assert a == "'host-admin'", (f, a)          # the host command never takes its actor from input
            elif f == "app/analyst/proposals.py" and a == "ANALYST":
                pass                                        # entries written on the analyst's behalf: one fixed actor
            elif f == "app/analyst/runner.py":
                assert a == "requested_by", (f, a)          # who asked for the run: c.user (pages, API) or "scheduler"
            else:
                assert a in allowed, (f, a)
    # "username" is used only by bootstrap, after valid_username() and inside the transaction that creates that account
    assert seen["app/auth.py"].count("username") == 1
    assert seen["tools/admin.py"].count("'host-admin'") == 2       # clear-login-delays and reset-password
    assert not [f for f, actors in seen.items() if f != "tools/admin.py" and "'host-admin'" in actors]
    # every audit.write in app/watches.py takes the signed-in user, passed in as `actor` (callers pass c.user)
    assert set(seen["app/watches.py"]) == {"actor"}
    # the analyst: the fixed actor is the constant "analyst", used only for stored proposals; decisions and the
    # consent take the signed-in user; a run's requester is c.user or "scheduler", never text from the model or a tool
    from app.analyst import proposals as P, runner as R, web as W
    import inspect
    assert P.ANALYST == "analyst"
    assert seen["app/analyst/proposals.py"].count("ANALYST") == 1
    assert set(seen["app/analyst/proposals.py"]) == {"ANALYST", "actor"} and set(seen["app/analyst/consent.py"]) == {"actor"}
    assert set(seen["app/marks.py"]) == {"actor"}
    assert "c.user" in inspect.getsource(W._start) and "requested_by" in inspect.signature(R.start).parameters
    assert '"scheduler", "new-snapshot"' in inspect.getsource(R.auto_brief)
    # every caller of proposals.accept/reject, consent.confirm and marks.add passes the signed-in user
    web_src = inspect.getsource(W)
    assert web_src.count("proposals.accept(c.db, c.snap, c.user,") == 2 and web_src.count("proposals.reject(c.db, c.user,") == 2
    assert web_src.count("consent.confirm(c.db, c.settings, c.user,") == 2


# ---------------------------------------------------------------- the address the limits use
def _browser_from(app, peer):
    from fastapi.testclient import TestClient
    b = Browser(app)
    b.c = TestClient(app, base_url=ORIGIN, follow_redirects=False, client=(peer, 50000))
    return b


def _app(tmp_path, **kw):
    s = make_settings(tmp_path, **kw)
    app = create_app(s, start_background=False)
    b = _browser_from(app, "192.0.2.200")
    tok = bootstrap_token(s)
    pre = b.pre_token("/bootstrap")
    assert b.c.post("/bootstrap", data={"token": tok, "username": "admin", "password": PASSWORD, "password2": PASSWORD,
                                        "owner_rule": "yes", "csrf": pre}, headers={"Origin": ORIGIN}).status_code == 303
    return app, s


def _post_login(b, user, pw, xff=None):
    pre = b.pre_token("/login")
    h = {"Origin": ORIGIN, **({"X-Forwarded-For": xff} if xff else {})}
    return b.c.post("/login", data={"username": user, "password": pw, "csrf": pre, "next": "/"}, headers=h).status_code


def test_the_account_delay_cannot_be_dodged_by_changing_the_forwarded_address(tmp_path):
    app, s = _app(tmp_path, trusted_proxy="10.0.0.5")
    proxy = _browser_from(app, "10.0.0.5")
    for i in range(s.login_max_failures):
        assert _post_login(proxy, "admin", "wrong password!!", xff=f"203.0.113.{i + 1}") == 400   # a new client address each time
    assert _post_login(proxy, "admin", PASSWORD, xff="198.51.100.200") == 429                      # the account waits anyway
    direct = _browser_from(app, "10.0.0.9")                                                          # not the proxy
    assert _post_login(direct, "admin", PASSWORD, xff="198.51.100.201") == 429


def test_the_address_delay_follows_the_peer_when_no_proxy_is_trusted(tmp_path):
    app, s = _app(tmp_path)
    b = _browser_from(app, "10.0.0.7")
    for i in range(s.login_max_failures * 2):
        _post_login(b, f"user{i}", "wrong password!!", xff=f"203.0.113.{i + 1}")
    conn = dbm.connect(s.db_path)
    addrs = {r[0] for r in conn.execute("SELECT address FROM login_attempts")}
    conn.close()
    assert addrs == {"10.0.0.7"}                                                                     # the forged header changed nothing
    assert _post_login(b, "admin", PASSWORD, xff="198.51.100.9") == 429
