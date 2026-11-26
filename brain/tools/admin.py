"""Host recovery commands for the brain. They run inside the brain's container, started by someone with shell access
to the host; no route of the web application reaches them and nothing is sent over the network:

    docker compose exec brain python -B -m tools.admin clear-login-delays [username]
    docker compose exec brain python -B -m tools.admin reset-password <username>
    (piping the password in instead of typing it: docker compose exec -T brain python -B -m tools.admin reset-password <username>)

clear-login-delays  removes the failed sign-in attempt rows the sign-in delay counts (app/auth.py), and pending rows
                    older than the pending timeout (5 minutes; a younger pending row is an attempt still being checked
                    and is left to resolve): for one username (as typed at sign-in, compared in lower case), or for
                    every username and address when none is given. With a username it also says how many failed rows
                    remain for other usernames: rows from made-up names still hold the per-address delay, and running
                    it without a username clears those too. The audit log is not touched except for the one entry
                    this command adds.
reset-password      sets a new password for an existing account and ends every session of that account. The new
                    password is read from standard input (twice, without echo, at a terminal; one line otherwise),
                    never from an argument or an environment variable, and must pass the app's own password rules
                    (auth.password_problem, with MOMUS_PASSWORD_MIN_LENGTH).

Each command writes one audit entry with the fixed actor "host-admin". The password never appears in the output,
the log or the audit entry. Exit codes: 0 done, 1 refused, 2 usage."""
import getpass
import os
import sys

from app import audit, auth, db as dbm
from app.config import from_env

USAGE = ("usage: python -B -m tools.admin clear-login-delays [username]\n"
         "       python -B -m tools.admin reset-password <username>   (the new password is read from standard input)")


class Refused(Exception):
    """A command refused with a fixed message (never the password)."""


def clear_login_delays(db, username=None):
    """Delete the failed attempt rows that the sign-in delay counts, and pending rows older than the pending timeout
    (a younger pending row is a sign-in still being checked; it is left to resolve, so that guess is still counted).
    Returns how many were removed."""
    key = username[:100].lower() if username else None       # auth.login keys attempts by the typed name, lower case
    stale = dbm.iso(auth.now() - auth.PENDING_EXPIRY)
    db.execute("BEGIN IMMEDIATE")
    try:
        if key is None:
            n = db.execute("DELETE FROM login_attempts WHERE ok=0 OR (ok IS NULL AND at<?)", (stale,)).rowcount
        else:
            n = db.execute("DELETE FROM login_attempts WHERE username=? AND (ok=0 OR (ok IS NULL AND at<?))", (key, stale)).rowcount
        audit.write(db, "host-admin", "login-delay-clear", target=f"username:{audit.clean(key, 64)}" if key else "all",
                    detail=f"{n} failed or stale pending sign-in attempt row(s) removed by the host recovery command")
        db.execute("COMMIT")
    except BaseException:
        if db.in_transaction:
            db.execute("ROLLBACK")
        raise
    return n


def failed_rows_of_others(db, username):
    """Failed attempt rows left for usernames other than this one (they can still hold the per-address delay)."""
    return db.execute("SELECT COUNT(*) FROM login_attempts WHERE ok=0 AND username!=?", (username[:100].lower(),)).fetchone()[0]


def find_user(db, username):
    row = db.execute("SELECT id, username FROM users WHERE lower(username)=lower(?)", ((username or "")[:100],)).fetchone()
    if row is None:
        raise Refused("No such account. Nothing was changed.")
    return row


def reset_password(db, settings, username, password):
    """Set a new password (the app's rules) and end all of that account's sessions; returns the sessions ended."""
    row = find_user(db, username)
    prob = auth.password_problem(password, row["username"], settings.password_min_length)
    if prob:
        raise Refused(prob + " Nothing was changed.")
    pw_hash = auth.hash_password(password, settings.scrypt_n)
    db.execute("BEGIN IMMEDIATE")
    try:
        db.execute("UPDATE users SET pw_hash=?, password_changed_at=? WHERE id=?", (pw_hash, dbm.iso(), row["id"]))
        n = db.execute("DELETE FROM sessions WHERE user_id=?", (row["id"],)).rowcount
        audit.write(db, "host-admin", "password-reset", target=row["username"],
                    detail=f"password set by the host recovery command; {n} session(s) ended")
        db.execute("COMMIT")
    except BaseException:
        if db.in_transaction:
            db.execute("ROLLBACK")
        raise
    return n


def read_password(stdin, stderr):
    """The new password from standard input: at a terminal twice without echo, otherwise the first line."""
    if stdin.isatty():
        first = getpass.getpass("New password: ", stream=stderr)
        second = getpass.getpass("New password again: ", stream=stderr)
        if first != second:
            raise Refused("The two passwords differ. Nothing was changed.")
        return first
    line = stdin.readline(auth.PASSWORD_MAX + 2)
    if line.endswith("\n"):
        line = line[:-1]
    if line.endswith("\r"):
        line = line[:-1]
    return line


def main(argv=None, stdin=None, stdout=None, stderr=None, settings=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    stdin, stdout, stderr = stdin or sys.stdin, stdout or sys.stdout, stderr or sys.stderr
    cmd, args = (argv[0], argv[1:]) if argv else (None, [])
    if cmd == "clear-login-delays" and len(args) <= 1:
        pass
    elif cmd == "reset-password" and len(args) == 1:      # an extra argument is refused: a password is never an argument
        pass
    else:
        print(USAGE, file=stderr)
        return 2
    settings = settings or from_env()
    if not os.path.isfile(settings.db_path):
        print(f"No app database at {settings.db_path}: start the brain once first. Nothing was changed.", file=stderr)
        return 1
    db = dbm.connect(settings.db_path)
    try:
        if cmd == "clear-login-delays":
            n = clear_login_delays(db, args[0] if args else None)
            who = f"username {audit.clean(args[0][:100].lower(), 64)}" if args else "every username and address"
            print(f"Removed {n} failed or stale pending sign-in attempt row(s) for {who}. Recorded in the audit log (host-admin).", file=stdout)
            if args:
                print(f"{failed_rows_of_others(db, args[0])} failed sign-in attempt row(s) remain for other usernames. They "
                      "can still hold the per-address delay (made-up usernames from one address count against it). Running "
                      "clear-login-delays without a username clears those too.", file=stdout)
            return 0
        find_user(db, args[0])                              # refuse an unknown account before asking for a password
        n = reset_password(db, settings, args[0], read_password(stdin, stderr))
        print(f"Password set for {audit.clean(find_user(db, args[0])['username'], 64)}; {n} session(s) ended. "
              "Recorded in the audit log (host-admin).", file=stdout)
        return 0
    except Refused as e:
        print(str(e), file=stderr)
        return 1
    except Exception as e:                                  # the type only: no value is printed
        print(f"Failed ({type(e).__name__}). Nothing was changed.", file=stderr)
        return 1
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
