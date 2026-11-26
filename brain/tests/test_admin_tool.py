"""The host recovery command (tools/admin.py): clear-login-delays and reset-password. Run on the host inside the
brain container; no route reaches it. Each writes one audit entry with the fixed actor "host-admin"; the password is
read from standard input only and never appears in arguments, output or the audit log."""
import dataclasses
import io
import os
import subprocess
import sys

from app import auth, db as dbm
from conftest import ORIGIN, PASSWORD, Browser
from tools import admin as tool

NEW = "a new long passphrase 42"
BRAIN = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run(settings, *argv, stdin=""):
    out, err = io.StringIO(), io.StringIO()
    rc = tool.main(list(argv), stdin=io.StringIO(stdin), stdout=out, stderr=err, settings=settings)
    return rc, out.getvalue(), err.getvalue()


def q(settings, sql, args=()):
    conn = dbm.connect(settings.db_path)
    try:
        return [tuple(r) for r in conn.execute(sql, args)]
    finally:
        conn.close()


def audit_rows(settings):
    return q(settings, "SELECT action, actor, target, detail, address FROM audit_log ORDER BY id")


def login_status(app, user, pw):
    b = Browser(app)
    pre = b.pre_token("/login")
    return b.c.post("/login", data={"username": user, "password": pw, "csrf": pre, "next": "/"}, headers={"Origin": ORIGIN}).status_code


def test_clear_login_delays_for_one_username(app, admin, settings):
    for _ in range(settings.login_max_failures):
        assert login_status(app, "Admin", "wrong password!!") == 400
    login_status(app, "someone", "wrong password!!")
    assert login_status(app, "admin", PASSWORD) == 429                       # the delay is on
    n = len(audit_rows(settings))
    rc, out, err = run(settings, "clear-login-delays", "ADMIN")
    assert rc == 0 and f"Removed {settings.login_max_failures} " in out and err == ""
    new = audit_rows(settings)[n:]
    assert [(a, actor, t) for a, actor, t, _, _ in new] == [("login-delay-clear", "host-admin", "username:admin")]
    assert q(settings, "SELECT COUNT(*) FROM login_attempts WHERE username='someone'") == [(1,)]     # others untouched
    assert login_status(app, "admin", PASSWORD) == 303


def test_clear_login_delays_for_everyone(app, admin, settings):
    assert login_status(app, "admin", PASSWORD) == 303
    for i in range(3):
        login_status(app, f"user{i}", "wrong password!!")
    n = len(audit_rows(settings))
    rc, out, _ = run(settings, "clear-login-delays")
    assert rc == 0 and "every username and address" in out
    assert q(settings, "SELECT COUNT(*) FROM login_attempts WHERE ok IS NULL OR ok=0") == [(0,)]
    assert q(settings, "SELECT COUNT(*) FROM login_attempts WHERE ok=1") == [(1,)]                  # successes are not delays
    assert [(a, actor, t) for a, actor, t, _, _ in audit_rows(settings)[n:]] == [("login-delay-clear", "host-admin", "all")]


def test_reset_password_sets_it_and_ends_every_session(app, admin, settings):
    assert admin.get("/api/v1/me").status_code == 200
    n = len(audit_rows(settings))
    rc, out, err = run(settings, "reset-password", "admin", stdin=NEW + "\n")
    assert rc == 0 and "1 session(s) ended" in out
    assert NEW not in out and NEW not in err
    assert admin.get("/api/v1/me").status_code == 401                       # the session is gone
    assert login_status(app, "admin", PASSWORD) == 400 and login_status(app, "admin", NEW) == 303
    new = audit_rows(settings)[n:n + 1]
    assert [(a, actor, t) for a, actor, t, _, _ in new] == [("password-reset", "host-admin", "admin")]
    assert all(NEW not in str(v) for row in audit_rows(settings) for v in row)
    (h,) = q(settings, "SELECT pw_hash FROM users WHERE username='admin'")[0]
    assert NEW not in h and auth.check_password(NEW, h)


def test_a_password_that_breaks_the_rules_is_refused(app, admin, settings):
    before = (q(settings, "SELECT pw_hash, password_changed_at FROM users"), audit_rows(settings), q(settings, "SELECT COUNT(*) FROM sessions"))
    for bad, why in (("short pw", "at least"), ("x" * (auth.PASSWORD_MAX + 1), "at most"), ("ADMIN", "at least"), ("", "at least")):
        rc, out, err = run(settings, "reset-password", "admin", stdin=bad + "\n")
        assert rc == 1 and why in err and "Nothing was changed" in err and out == "", (bad[:20], err)
        if bad:
            assert bad not in err and bad not in out
    s2 = dataclasses.replace(settings, password_min_length=5)
    rc, _, err = run(s2, "reset-password", "admin", stdin="Admin\n")                    # the password may not be the username
    assert rc == 1 and "must not be the username" in err
    after = (q(settings, "SELECT pw_hash, password_changed_at FROM users"), audit_rows(settings), q(settings, "SELECT COUNT(*) FROM sessions"))
    assert after == before
    assert admin.get("/api/v1/me").status_code == 200


def test_unknown_user_extra_arguments_and_bad_commands_are_refused(app, admin, settings):
    before = (q(settings, "SELECT pw_hash FROM users"), audit_rows(settings))
    rc, _, err = run(settings, "reset-password", "nobody", stdin=NEW + "\n")
    assert rc == 1 and "No such account" in err
    rc, _, err = run(settings, "reset-password", "admin", NEW, stdin=NEW + "\n")     # a password is never an argument
    assert rc == 2 and "usage" in err and NEW not in err
    for argv in ([], ["reset-password"], ["clear-login-delays", "a", "b"], ["drop-everything"]):
        assert run(settings, *argv)[0] == 2
    assert (q(settings, "SELECT pw_hash FROM users"), audit_rows(settings)) == before


def test_the_tool_reads_no_password_from_the_environment():
    src = open(os.path.join(BRAIN, "tools", "admin.py")).read()
    assert "os.environ" not in src and "getenv" not in src
    assert "sys.argv" in src and "read_password(stdin" in src


def test_the_real_invocation_reads_the_password_from_standard_input(app, admin, settings):
    """python -B -m tools.admin, as `docker compose exec brain` runs it (from the image's working directory)."""
    cmd = [sys.executable, "-B", "-m", "tools.admin", "reset-password", "admin"]
    env = {k: v for k, v in os.environ.items() if not k.startswith("MOMUS_")}
    env.update(MOMUS_DATA_DIR=settings.data_dir, PYTHONDONTWRITEBYTECODE="1")
    p = subprocess.run(cmd, input=NEW + "\n", capture_output=True, text=True, cwd=BRAIN, env=env, timeout=120)
    assert p.returncode == 0, p.stderr
    assert NEW not in " ".join(cmd) and NEW not in p.stdout and NEW not in p.stderr
    assert "Password set for admin" in p.stdout
    assert login_status(app, "admin", NEW) == 303
    assert q(settings, "SELECT actor FROM audit_log WHERE action='password-reset'") == [("host-admin",)]
    p = subprocess.run([sys.executable, "-B", "-m", "tools.admin", "clear-login-delays"], capture_output=True, text=True, cwd=BRAIN,
                       env=env, timeout=120)
    assert p.returncode == 0 and "Removed" in p.stdout
    assert not [d for d, _, fs in os.walk(os.path.join(BRAIN, "tools")) if "__pycache__" in d]
