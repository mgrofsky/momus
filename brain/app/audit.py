"""The append-only audit log. Callers write the entry inside the same transaction as the change it records."""
import re
import unicodedata

from .db import iso

ACTIONS = (
    "bootstrap", "login", "login-failed", "login-refused", "login-delay", "login-flood", "logout", "password-change", "session-revoke", "account-create",
    "domain-add", "domain-remove", "exclusion-add", "exclusion-remove", "range-add", "range-remove",
    "host-approve", "host-unapprove", "inventory-approve", "inventory-withdraw", "profile-change",
    "schedule-change", "job-queue", "job-refused", "job-abandon", "mark-add", "mark-withdraw", "note-add",
    "watch-add", "watch-edit", "watch-remove",
    # the analyst: consent and run requests by a signed-in person (or the scheduler); proposals stored by the
    # analyst itself under the fixed actor "analyst"; decisions by a signed-in person
    "analyst-consent", "analyst-run", "analyst-proposal", "proposal-accept", "proposal-reject",
    # written only by the host recovery command (tools/admin.py), with the fixed actor "host-admin"
    "login-delay-clear", "password-reset",
)


PER_PAGE = 200
DETAIL_MAX = 1000                 # the longest detail an entry keeps (write)


def clip(s, n=300):
    if s is None:
        return None
    s = str(s).replace("\x00", "")
    return s if len(s) <= n else s[:n] + "..."


def clean(s, n=300):
    """Text typed by someone who is not signed in (or any other untrusted text) for the audit log: control and format
    characters and line or paragraph separators removed, then capped."""
    if s is None:
        return None
    s = "".join(ch for ch in str(s) if unicodedata.category(ch)[0] != "C" and unicodedata.category(ch) not in ("Zl", "Zp"))
    return clip(s, n)


def write(db, actor, action, target=None, detail=None, address=None):
    """Every value passes through clean(): a detail can hold text derived from the scanner's files or from a model
    (a heartbeat's job, a reason), so no control, format or line-separator character reaches the log."""
    assert action in ACTIONS, action
    db.execute("INSERT INTO audit_log(at, actor, action, target, detail, address) VALUES(?,?,?,?,?,?)",
               (iso(), clean(actor, 100) or "-", action, clean(target), clean(detail, DETAIL_MAX), clean(address, 64)))


BEFORE_RE = re.compile(r"[0-9]{1,18}")


def before_id(v):
    """A "before" cursor as an int, or None: only 1 to 18 ASCII digits count (so it always fits SQLite's integer)."""
    if isinstance(v, int) and not isinstance(v, bool):
        v = str(v)
    return int(v) if isinstance(v, str) and BEFORE_RE.fullmatch(v) else None


def query(db, action=None, actor=None, q=None, limit=200, before=None):
    sql = "SELECT id, at, actor, action, target, detail, address FROM audit_log WHERE 1=1"
    args = []
    if action:
        sql += " AND action = ?"
        args.append(action)
    if actor:
        sql += " AND actor = ?"
        args.append(actor)
    if q:
        sql += " AND (instr(lower(COALESCE(target,'')), lower(?)) > 0 OR instr(lower(COALESCE(detail,'')), lower(?)) > 0)"
        args += [q, q]
    before = before_id(before)
    if before:
        sql += " AND id < ?"
        args.append(before)
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(max(1, min(int(limit), 1000)))
    return [dict(r) for r in db.execute(sql, args)]
