"""Accounts, passwords, sessions, the bootstrap token and login rate limiting. Standard library only:
hashlib.scrypt for passwords, secrets for tokens, hmac.compare_digest for every comparison of secrets."""
import base64
import datetime as dt
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import threading

from . import audit
from .db import iso, now, parse_iso

# Usernames end up in job files as "attested_by" and "approved_by"; the scanner accepts 1-100 printable characters
# without quotes, <, >, $ or backslash. This rule is narrower, so every username is valid there too.
USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._@-]{1,62}[A-Za-z0-9]$")
PASSWORD_MAX = 1024
SCRYPT_R, SCRYPT_P = 8, 1
# The fixed actors of audit entries written by the application itself (tools/admin.py, the scheduler, the analyst,
# requests made without a session, tools/smoke_provider.py). No account may take one of these names, in any letter case,
# so an entry under one of them always means the application, never a person.
RESERVED_USERNAMES = ("host-admin", "scheduler", "analyst", "anonymous", "smoke-test")
RESERVED_MESSAGE = ("That username is reserved for the application's own audit entries "
                    "(host-admin, scheduler, analyst, anonymous, smoke-test). Choose another.")
RESERVED_WARNING = ("brain: WARNING: the account {name} has a name the application uses for its own audit entries; entries "
                    "under that name may be the account's or the application's. It was left unchanged. Create another "
                    "account and stop using this one.")
# start-up checks of the reverse-proxy settings (web.create_app)
COOKIE_REFUSAL = ("Refusing to start: MOMUS_ALLOWED_ORIGINS holds an https:// origin but MOMUS_COOKIE_SECURE is off, "
                  "so the session cookie would be sent without Secure. Set MOMUS_COOKIE_SECURE=1.")
PROXY_WARNING = ("MOMUS_ALLOWED_ORIGINS holds an https:// origin, so the brain is probably behind a reverse proxy, but "
                 "MOMUS_TRUSTED_PROXY is empty: all clients will share one address for the sign-in limits, so anyone who "
                 "fails to sign in ten times delays every sign-in. Set MOMUS_TRUSTED_PROXY to the proxy's fixed address "
                 "(see .env.example).")


class AuthError(Exception):
    pass


def _b64(b):
    return base64.b64encode(b).decode("ascii")


def hash_password(pw, n):
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(pw.encode("utf-8"), salt=salt, n=n, r=SCRYPT_R, p=SCRYPT_P, maxmem=256 * 1024 * 1024, dklen=32)
    return f"scrypt${n}${SCRYPT_R}${SCRYPT_P}${_b64(salt)}${_b64(dk)}"


def check_password(pw, stored):
    try:
        alg, n, r, p, salt, want = stored.split("$")
        if alg != "scrypt":
            return False
        dk = hashlib.scrypt(pw.encode("utf-8"), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p),
                            maxmem=256 * 1024 * 1024, dklen=32)
        return hmac.compare_digest(dk, base64.b64decode(want))
    except (ValueError, TypeError):
        return False


def token_hash(tok):
    return hashlib.sha256(tok.encode("utf-8")).hexdigest()


def valid_username(u):
    return isinstance(u, str) and bool(USERNAME_RE.fullmatch(u)) and "  " not in u


def reserved_username(u):
    return isinstance(u, str) and u.strip().lower() in RESERVED_USERNAMES


def reserved_accounts(db):
    """Existing accounts whose name is a reserved actor name (reported at start-up, never changed)."""
    marks = ",".join("?" * len(RESERVED_USERNAMES))
    return [r[0] for r in db.execute(f"SELECT username FROM users WHERE lower(username) IN ({marks}) ORDER BY id",
                                     RESERVED_USERNAMES)]


def password_problem(pw, username, min_len):
    if not isinstance(pw, str) or len(pw) < min_len:
        return f"The password must be at least {min_len} characters."
    if len(pw) > PASSWORD_MAX:
        return f"The password must be at most {PASSWORD_MAX} characters."
    if username and pw.lower() == username.lower():
        return "The password must not be the username."
    return None


# ---------------------------------------------------------------- bootstrap
def user_count(db):
    return db.execute("SELECT COUNT(*) FROM users").fetchone()[0]


def ensure_bootstrap(db):
    """While no account exists, make a fresh one-time token (only its hash is stored) and return it for the log.
    Returns None once an account exists."""
    if user_count(db):
        return None
    tok = secrets.token_urlsafe(24)
    db.execute("INSERT INTO bootstrap(id, token_hash, created_at, used_at) VALUES(1, ?, ?, NULL) "
               "ON CONFLICT(id) DO UPDATE SET token_hash=excluded.token_hash, created_at=excluded.created_at, used_at=NULL",
               (token_hash(tok), iso()))
    return tok


def bootstrap_open(db):
    if user_count(db):
        return False
    r = db.execute("SELECT used_at FROM bootstrap WHERE id=1").fetchone()
    return bool(r) and r["used_at"] is None


def bootstrap(db, settings, token, username, password, address):
    """Create the first admin with the one-time token. Everything happens in one transaction."""
    db.execute("BEGIN IMMEDIATE")
    try:
        r = db.execute("SELECT token_hash, used_at FROM bootstrap WHERE id=1").fetchone()
        ok = bool(r) and r["used_at"] is None and user_count(db) == 0 and isinstance(token, str) and bool(r["token_hash"]) \
            and hmac.compare_digest(r["token_hash"].encode(), token_hash(token).encode())
        if not ok:
            raise AuthError("That bootstrap token is not valid, or the first account already exists.")
        if not valid_username(username):
            raise AuthError("Usernames are 3 to 64 characters: letters, digits, space, dot, underscore, @ and hyphen.")
        if reserved_username(username):
            raise AuthError(RESERVED_MESSAGE)
        prob = password_problem(password, username, settings.password_min_length)
        if prob:
            raise AuthError(prob)
        uid = _insert_user(db, settings, username, password)
        db.execute("UPDATE bootstrap SET used_at=?, token_hash='' WHERE id=1", (iso(),))
        audit.write(db, username, "bootstrap", target=username, detail="first admin account created with the bootstrap token", address=address)
        db.execute("COMMIT")
        return uid
    except Exception:
        db.execute("ROLLBACK")
        raise


def _insert_user(db, settings, username, password):
    t = iso()
    cur = db.execute("INSERT INTO users(username, pw_hash, role, created_at, password_changed_at) VALUES(?,?,?,?,?)",
                     (username, hash_password(password, settings.scrypt_n), "admin", t, t))
    return cur.lastrowid


def create_account(db, settings, actor, username, password, address):
    if not valid_username(username):
        raise AuthError("Usernames are 3 to 64 characters: letters, digits, space, dot, underscore, @ and hyphen.")
    if reserved_username(username):
        raise AuthError(RESERVED_MESSAGE)
    prob = password_problem(password, username, settings.password_min_length)
    if prob:
        raise AuthError(prob)
    db.execute("BEGIN IMMEDIATE")
    try:
        if db.execute("SELECT 1 FROM users WHERE lower(username)=lower(?)", (username,)).fetchone():
            raise AuthError("That username is taken.")
        _insert_user(db, settings, username, password)
        audit.write(db, actor, "account-create", target=username, address=address)
        db.execute("COMMIT")
    except Exception:
        db.execute("ROLLBACK")
        raise


# ---------------------------------------------------------------- login
_DUMMY = None


def prepare_dummy_hash(n):
    """Build the hash an unknown username is checked against. web.create_app calls this at start-up, so the first
    unknown name after a start costs one hash like every other attempt (not two)."""
    global _DUMMY
    if _DUMMY is None or _DUMMY[0] != n:
        _DUMMY = (n, hash_password(secrets.token_urlsafe(16), n))
    return _DUMMY[1]


_dummy_hash = prepare_dummy_hash


# Sign-in limits. A failed attempt counts against the typed username (whether or not the account exists) and against
# the client address (web.client_address: the peer, or the trusted proxy's X-Forwarded-For entry; an IPv6 client is
# counted by its /64, limit_address). A failure counts for LOOKBACK (24 hours) and then expires; that is the only way a
# count goes down, apart from the host recovery command (tools/admin.py clear-login-delays). A successful sign-in
# clears nothing, so real and unknown usernames get the same answers, including after the owner has signed in, with one
# exception: a client that holds a username at its limit sees the effect of other people's failed attempts on that
# name (the wait grows), and of a sign-in on it being checked for a moment (it counts as a failure until it ends).
# Only a real account's owner produces those, so for that client a real name can differ from an unknown one
# (closing it needs a separate count for a browser that has signed in before, which is not built).
# From MOMUS_LOGIN_MAX_FAILURES failures for a username, or twice that for an
# address, every further attempt waits a delay after the last failure: DELAY_BASE seconds, doubling with each
# further failure, at most MOMUS_LOGIN_MAX_DELAY_SECONDS. An attempt refused for the delay writes nothing and hashes
# nothing, so refused attempts never extend the delay; only an attempt that was let through and failed does.
# An attempt is recorded as pending, inside BEGIN IMMEDIATE, before its password is hashed; a pending attempt counts
# as a failure, so a parallel burst gets no more guesses than the limit. At most MOMUS_LOGIN_HASH_CONCURRENCY hashes run
# at once.
ANONYMOUS = "anonymous"           # the audit actor of every request made without a session
LOOKBACK = dt.timedelta(hours=24)
# Above this many failed sign-ins in one calendar minute (UTC, all clients together) no individual login-failed or
# login-delay entry is written for the rest of that minute; once the minute is over, one login-flood entry records how
# many failed, which existing accounts were tried and how often, the other usernames and the source keys with the
# most failures (write_flood_summaries). The attempt rows are still written, because the limits need them. Nothing is
# refused for the rate itself: a global ceiling would make locking everyone out cheaper.
FLOOD_PER_MINUTE = 30
DELAY_BASE = 15
PENDING_EXPIRY = dt.timedelta(minutes=5)
HASH_WAIT_SECONDS = 1.0
TOO_MANY = "Too many failed attempts. Wait {wait} and try again."
BUSY = "The server is busy checking other sign-ins. Try again in a moment."
_slots_lock = threading.Lock()
_slots = {}


class Throttled(AuthError):
    """Refused for the sign-in delay; nothing was written."""

    def __init__(self, wait):
        self.wait = wait
        super().__init__(TOO_MANY.format(wait=_say_seconds(wait)))


class Busy(AuthError):
    pass


def _say_seconds(n):
    n = int(n)
    if n < 90:
        return f"{max(n, 1)} seconds"
    return f"about {round(n / 60)} minutes"


def _hash_slots(settings):
    n = max(1, settings.login_hash_concurrency)
    with _slots_lock:
        if n not in _slots:
            _slots[n] = threading.BoundedSemaphore(n)
        return _slots[n]


def delay_for(failures, threshold, settings):
    """Seconds to wait after the last failure, given the number of failures counted (0 below the threshold)."""
    if failures < threshold:
        return 0
    return min(DELAY_BASE * 2 ** min(failures - threshold, 20), settings.login_max_delay_seconds)


def lookback(settings=None):
    return LOOKBACK


def limit_address(address):
    """The key the sign-in limits count an address under: an IPv6 address by its /64 (one client easily holds a
    whole /64), an IPv4 or IPv4-mapped address as itself, anything else unchanged. Only the limits use this; the
    audit log and sessions keep the full address."""
    try:
        a = ipaddress.ip_address(address)
    except ValueError:
        return address
    if a.version == 6 and a.ipv4_mapped is not None:
        return str(a.ipv4_mapped)
    if a.version == 6:
        return str(ipaddress.ip_network(f"{a}/64", strict=False))
    return str(a)


def _counted(db, settings, col, value, t):
    since = iso(t - LOOKBACK)
    r = db.execute(f"SELECT COUNT(*), MAX(at) FROM login_attempts WHERE {col}=? AND (ok IS NULL OR ok=0) AND at>=?",
                   (value, since)).fetchone()
    return r[0], r[1]


def wait_seconds(db, settings, key, addr, t=None):
    """How long the next attempt for this username or from this address must still wait (0: it may go ahead).
    addr is the limit key (limit_address)."""
    t = t or now()
    waits = [0]
    for col, value, threshold in (("username", key, settings.login_max_failures),
                                  ("address", addr, settings.login_max_failures * 2)):
        n, last = _counted(db, settings, col, value, t)
        d = delay_for(n, threshold, settings)
        if d and last:
            waits.append((parse_iso(last) + dt.timedelta(seconds=d) - t).total_seconds())
    return max(0, int(max(waits) + 0.999))


def login(db, settings, username, password, address):
    """Return the user row, or raise AuthError with a message that does not say which part was wrong."""
    username = (username or "")[:100]
    key = username.lower()
    addr = (address or "unknown")[:64]
    lim = limit_address(addr)
    if not isinstance(password, str) or len(password) > PASSWORD_MAX:
        raise AuthError("Wrong username or password.")      # no password can be this long: nothing to check or count
    t = now()
    # decide and record the pending attempt in one immediate transaction: a refusal writes nothing
    db.execute("BEGIN IMMEDIATE")
    try:
        wait = wait_seconds(db, settings, key, lim, t)
        if not wait:
            attempt = db.execute("INSERT INTO login_attempts(username, address, at, ok) VALUES(?,?,?,NULL)", (key, lim, iso(t))).lastrowid
        db.execute("ROLLBACK" if wait else "COMMIT")
    except BaseException:
        if db.in_transaction:
            db.execute("ROLLBACK")
        raise
    if wait:
        raise Throttled(wait)
    slots = _hash_slots(settings)
    if not slots.acquire(timeout=HASH_WAIT_SECONDS):
        db.execute("DELETE FROM login_attempts WHERE id=?", (attempt,))      # no guess was made
        raise Busy(BUSY)
    try:
        row = db.execute("SELECT * FROM users WHERE lower(username)=?", (key,)).fetchone()
        ok = check_password(password or "", row["pw_hash"] if row else _dummy_hash(settings.scrypt_n)) and row is not None
    finally:
        slots.release()
    target = audit.clean(username, 64) or "-"
    db.execute("BEGIN IMMEDIATE")
    try:
        t2 = now()
        db.execute("UPDATE login_attempts SET ok=? WHERE id=?", (int(ok), attempt))
        if ok:
            audit.write(db, row["username"], "login", target=row["username"], address=addr)
        elif not flooding(db, t):
            audit.write(db, ANONYMOUS, "login-failed", target=target, address=addr)
            _audit_delay_start(db, settings, key, lim, addr, target, t2)
        write_flood_summaries(db, t2)
        db.execute("UPDATE login_attempts SET ok=0 WHERE ok IS NULL AND at<?", (iso(t2 - PENDING_EXPIRY),))
        prune_attempts(db, settings, t2)
        db.execute("COMMIT")
    except BaseException:
        if db.in_transaction:
            db.execute("ROLLBACK")
        raise
    if not ok:
        raise AuthError("Wrong username or password.")
    return row


def _audit_delay_start(db, settings, key, lim, addr, target, t):
    """One audit entry when a delay starts for a username or an address (not one per refused attempt). The entry is
    written once per lookback period for a label, counted from the newest clear of that label by the host recovery
    command (login-delay-clear for that username, or for all) when that is newer. A successful sign-in plays no part."""
    since = iso(t - LOOKBACK)
    for col, value, threshold, what in (
            ("username", key, settings.login_max_failures, f"username {target}"),
            ("address", lim, settings.login_max_failures * 2, "this address")):
        n, _ = _counted(db, settings, col, value, t)
        if n < threshold:
            continue
        label = f"{col}:{audit.clean(key, 64) if col == 'username' else lim}"
        if db.execute("SELECT 1 FROM audit_log WHERE action='login-delay' AND target=? AND at>=? AND id>? LIMIT 1",
                      (label, since, _newest_clear_id(db, label))).fetchone():
            continue
        audit.write(db, ANONYMOUS, "login-delay", target=label,
                    detail=f"{n} failed sign-ins for {what}: each further attempt "
                           f"waits {DELAY_BASE} s after the last failure, doubling up to {settings.login_max_delay_seconds} s",
                    address=addr)


def _newest_clear_id(db, label):
    return db.execute("SELECT COALESCE(MAX(id), 0) FROM audit_log WHERE action='login-delay-clear' AND (target=? OR target='all')",
                      (label,)).fetchone()[0]


def _minute(t):
    return iso(t)[:16]                     # "YYYY-MM-DDTHH:MM", the calendar minute (UTC) of an attempt


def flooding(db, t):
    """True when this minute already holds more than FLOOD_PER_MINUTE failed sign-ins (this one included)."""
    m = _minute(t)
    n = db.execute("SELECT COUNT(*) FROM login_attempts WHERE ok=0 AND at>=? AND at<?", (m + ":00Z", m + ":60Z")).fetchone()[0]
    return n > FLOOD_PER_MINUTE


FLOOD_ACCOUNTS_SHOWN = 20         # existing accounts named in a login-flood entry (then "and N more")
FLOOD_TOP_SHOWN = 10              # other usernames, and source keys, named in a login-flood entry (then "and N more")
FLOOD_ACCOUNT_SOURCES = 5         # source keys named in each existing account's entry (then "and N more")
FLOOD_QUOTED_MAX = 72             # a name as written (cleaned, cut, JSON-quoted); with its count, about 80 characters


def _flood_name(name):
    """A name as the entry writes it: cleaned (audit.clean) and JSON-quoted, so it cannot pose as a separator, a count
    or another entry, and at most FLOOD_QUOTED_MAX characters as written. A longer one is cut first (by characters of
    the name, so never inside an escape), then "..." is added, then it is quoted."""
    s = audit.clean(name, 1000) or "-"
    q = json.dumps(s)
    if len(q) <= FLOOD_QUOTED_MAX:
        return q
    s = s[:FLOOD_QUOTED_MAX]
    while s and len(json.dumps(s + "...")) > FLOOD_QUOTED_MAX:
        s = s[:-1]
    return json.dumps(s + "...")


class _FloodList:
    """One list of a login-flood entry: the ranked pairs, the entries kept (by rank), and its text."""

    def __init__(self, pairs, shown):
        self.total = len(pairs)
        self.kept = [f"{_flood_name(n)} {c}" for n, c in pairs[:shown]]

    def text(self):
        if not self.total:
            return "none"
        parts = list(self.kept)
        if self.total > len(self.kept):
            parts.append(f"and {self.total - len(self.kept)} more")
        return ", ".join(parts)


def _flood_detail(n, m, accounts, others, sources):
    """The login-flood detail: the counts line first, then the three lists. accounts: (name, failures, [(source key,
    failures)]). If the whole does not fit the audit log's detail limit (audit.DETAIL_MAX), the two lower lists give up
    their longest entry first, and a list gives up its last entry only when the other has none left; then each
    account's source keys, then accounts from the end. The counts line is never shortened."""
    head = (f"{n} failed sign-ins in the minute from {m.replace('T', ' ')} UTC, all clients together. "
            f"Above {FLOOD_PER_MINUTE} a minute no individual login-failed or login-delay entry is written; "
            "the sign-in limits still counted every attempt.")
    acc = [(f"{_flood_name(a)} {c}", _FloodList(srcs, FLOOD_ACCOUNT_SOURCES)) for a, c, srcs in accounts]
    acc_total, acc_kept = len(acc), min(len(acc), FLOOD_ACCOUNTS_SHOWN)
    lower = [_FloodList(others, FLOOD_TOP_SHOWN), _FloodList(sources, FLOOD_TOP_SHOWN)]

    def acc_text():
        if not acc_total:
            return "none"
        parts = [f"{e} (sources {s.text()})" if s.kept or s.total else e for e, s in acc[:acc_kept]]
        if acc_total > acc_kept:
            parts.append(f"and {acc_total - acc_kept} more")
        return "; ".join(parts)

    while True:
        text = (f"{head} Existing accounts: {acc_text()}. Other usernames: {lower[0].text()}. "
                f"Source keys: {lower[1].text()}.")
        if len(text) <= audit.DETAIL_MAX:
            return text
        # the longest entry of a lower list that may give one up (its last only when the other list is empty)
        cands = [(len(e), li, ei) for li, lst in enumerate(lower) for ei, e in enumerate(lst.kept)
                 if len(lst.kept) > 1 or not lower[1 - li].kept]
        if cands:
            _, li, ei = max(cands, key=lambda x: (x[0], x[1], x[2]))
            del lower[li].kept[ei]
            continue
        with_sources = [s for _, s in acc[:acc_kept] if s.kept]
        if with_sources:
            max(with_sources, key=lambda s: len(s.kept)).kept.pop()
            continue
        if acc_kept:
            acc_kept -= 1
            continue
        return text


def write_flood_summaries(db, t=None):
    """For every finished minute in the lookback that held more than FLOOD_PER_MINUTE failed sign-ins and has no
    summary yet, write one login-flood entry: the count; every username tried in that minute that is an existing
    account, with its failures and the source keys that failed on it; the other usernames and the source keys (the limit key stored in the attempt row) with
    the most failures. Read from that minute's attempt rows here, never on the path that decides a sign-in, and
    independent of the username of any request. Called after each sign-in, by the scheduler tick and at start-up,
    inside the caller's transaction (or as one autocommit statement each)."""
    t = t or now()
    last = db.execute("SELECT MAX(target) FROM audit_log WHERE action='login-flood'").fetchone()[0]
    since = max(iso(t - LOOKBACK), (last[len("minute:"):] + ":60Z") if last else "")
    rows = db.execute("SELECT substr(at, 1, 16) AS m, COUNT(*) FROM login_attempts WHERE ok=0 AND at>=? AND at<? "
                      "GROUP BY m HAVING COUNT(*) > ? ORDER BY m", (since, _minute(t) + ":00Z", FLOOD_PER_MINUTE)).fetchall()
    for m, n in rows:
        span = (m + ":00Z", m + ":60Z")
        names = db.execute("SELECT username, COUNT(*) AS c FROM login_attempts WHERE ok=0 AND at>=? AND at<? "
                           "GROUP BY username ORDER BY c DESC, username", span).fetchall()
        known = {r[0]: r[1] for r in db.execute(
            "SELECT lower(username), username FROM users WHERE lower(username) IN "
            "(SELECT DISTINCT username FROM login_attempts WHERE ok=0 AND at>=? AND at<?)", span)}
        per_account = {}
        for u, addr, c in db.execute("SELECT username, address, COUNT(*) AS c FROM login_attempts WHERE ok=0 AND at>=? "
                                     "AND at<? GROUP BY username, address ORDER BY c DESC, address", span):
            if u in known:
                per_account.setdefault(u, []).append((addr, c))
        accounts = [(known[u], c, per_account.get(u, [])) for u, c in names if u in known]
        others = [(u, c) for u, c in names if u not in known]
        sources = [tuple(r) for r in db.execute("SELECT address, COUNT(*) AS c FROM login_attempts WHERE ok=0 AND at>=? "
                                                "AND at<? GROUP BY address ORDER BY c DESC, address", span)]
        audit.write(db, ANONYMOUS, "login-flood", target=f"minute:{m}", detail=_flood_detail(n, m, accounts, others, sources))
    return len(rows)


def prune_attempts(db, settings=None, t=None):
    """Delete attempt rows that no limit reads any more (older than the lookback)."""
    t = t or now()
    return db.execute("DELETE FROM login_attempts WHERE at < ?", (iso(t - LOOKBACK - dt.timedelta(minutes=5)),)).rowcount


# ---------------------------------------------------------------- sessions
def create_session(db, user_id, address, user_agent):
    tok = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    t = iso()
    db.execute("INSERT INTO sessions(token_hash, user_id, csrf, created_at, last_seen_at, address, user_agent) VALUES(?,?,?,?,?,?,?)",
               (token_hash(tok), user_id, csrf, t, t, (address or "")[:64], (user_agent or "")[:200]))
    return tok


def load_session(db, settings, tok, touch=True):
    """The session and its user for a cookie value, or None. Expired sessions are deleted."""
    if not tok or len(tok) > 200:
        return None
    th = token_hash(tok)
    r = db.execute("SELECT s.*, u.username, u.role FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?", (th,)).fetchone()
    if not r:
        return None
    t = now()
    created, seen = parse_iso(r["created_at"]), parse_iso(r["last_seen_at"])
    if t - seen > dt.timedelta(minutes=settings.session_idle_minutes) or t - created > dt.timedelta(hours=settings.session_max_hours):
        db.execute("DELETE FROM sessions WHERE token_hash=?", (th,))
        return None
    if touch and (t - seen).total_seconds() >= 30:
        db.execute("UPDATE sessions SET last_seen_at=? WHERE token_hash=?", (iso(t), th))
    return dict(r)


def delete_session(db, tok):
    db.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash(tok),))


def list_sessions(db, user_id):
    return [dict(r) for r in db.execute("SELECT token_hash, created_at, last_seen_at, address, user_agent FROM sessions "
                                        "WHERE user_id=? ORDER BY last_seen_at DESC", (user_id,))]


def revoke_session(db, user, token_hash_prefix, address):
    """Delete one of the user's own sessions, named by the first 16 characters of its hash."""
    if not re.fullmatch(r"[0-9a-f]{16}", token_hash_prefix or ""):
        raise AuthError("Unknown session.")
    db.execute("BEGIN IMMEDIATE")
    cur = db.execute("DELETE FROM sessions WHERE user_id=? AND substr(token_hash,1,16)=?", (user["user_id"], token_hash_prefix))
    if cur.rowcount:
        audit.write(db, user["username"], "session-revoke", target=token_hash_prefix, address=address)
    db.execute("COMMIT")
    if not cur.rowcount:
        raise AuthError("Unknown session.")


def change_password(db, settings, user, current_token, old, new, address):
    row = db.execute("SELECT * FROM users WHERE id=?", (user["user_id"],)).fetchone()
    if not row or not check_password(old or "", row["pw_hash"]):
        raise AuthError("The current password is wrong.")
    prob = password_problem(new, row["username"], settings.password_min_length)
    if prob:
        raise AuthError(prob)
    if hmac.compare_digest(old.encode("utf-8"), new.encode("utf-8")):
        raise AuthError("The new password must differ from the current one.")
    db.execute("BEGIN IMMEDIATE")
    db.execute("UPDATE users SET pw_hash=?, password_changed_at=? WHERE id=?", (hash_password(new, settings.scrypt_n), iso(), row["id"]))
    n = db.execute("DELETE FROM sessions WHERE user_id=? AND token_hash!=?", (row["id"], token_hash(current_token))).rowcount
    audit.write(db, row["username"], "password-change", target=row["username"], detail=f"{n} other session(s) signed out", address=address)
    db.execute("COMMIT")
    return n
