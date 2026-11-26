"""The scope as the brain keeps it: domains with their ownership statements, exclusions, owned ranges, approved hosts,
inventory approvals and the per-scope profiles. Every entry is checked on input with the same rules the scanner's
job validation applies (scanner/runner.py), because one bad value would get every later job rejected. The constants
below are copies of the scanner's; a test checks they are equal."""
import ipaddress
import re

from . import audit
from .db import iso

# copies of scanner/pipeline/scope.py (checked equal by tests/test_scanner_contract.py)
OWNERSHIP_RULE = "This project should only be run on systems the person running the project explicitly owns."
OWNERSHIP_STATEMENT = "I own this domain and the systems it points to."
CHECK_PROFILES, RATE_PROFILES, EVIDENCE_LEVELS = ("safe", "active"), ("low", "normal", "fast"), ("minimal", "excerpt")
LIMITS = {"domains": 200, "exclude": 1000, "owned_ranges": 256, "approved_hosts": 5000}
_LABEL = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")
DUE_CARE = ("The DNS check is a due-care control, not a lock: it stops honest mistakes such as a typo in a domain name, "
            "but anyone with the source code can remove it. Responsibility for scanning only what you own stays with you.")


class ScopeError(Exception):
    pass


def norm_name(host):
    """Same rule as scanner/pipeline/scope.py norm_name: lower case, one trailing dot removed, None if invalid."""
    if not isinstance(host, str):
        return None
    h = host.strip().lower()
    if h.endswith("."):
        h = h[:-1]
    if not h or len(h) > 253 or ".." in h:
        return None
    labels = h.split(".")
    if len(labels) < 2 or not all(_LABEL.fullmatch(x) for x in labels):
        return None
    if labels[-1].isdigit() or "_" in labels[-1]:
        return None
    return h


def clean_name(v, what="host name"):
    n = norm_name(v)
    if not n:
        raise ScopeError(f"Not a valid {what}: use lower-case labels of a-z, 0-9, '-' and '_', separated by dots.")
    return n


def clean_cidr(v):
    s = (v or "").strip()
    if not re.fullmatch(r"[0-9a-fA-F:.]+(/\d{1,3})?", s):
        raise ScopeError("Not an address or CIDR range.")
    try:
        net = ipaddress.ip_network(s, strict=False)
    except ValueError:
        raise ScopeError("Not an address or CIDR range.")
    if not net.is_global:
        raise ScopeError("Owned ranges must be public addresses; the scanner never scans private, loopback or link-local ranges.")
    return str(net)


def clean_exclusion(v):
    s = (v or "").strip().lower()
    if re.fullmatch(r"[0-9a-f:.]+(/\d{1,3})?", s) and (":" in s or re.fullmatch(r"[0-9./]+", s)):
        try:
            return str(ipaddress.ip_network(s, strict=False))
        except ValueError:
            raise ScopeError("Not an address or CIDR range.")
    body = s[2:] if s.startswith("*.") else (s[1:] if s.startswith(".") else s)
    clean_name(body, "exclusion (a host name, *.suffix, .suffix, or a CIDR range)")
    return s


# ---------------------------------------------------------------- reading
def domains(db):
    return [dict(r) for r in db.execute("SELECT * FROM domains ORDER BY kind, name")]


def lists(db):
    return {
        "exclusions": [dict(r) for r in db.execute("SELECT * FROM exclusions ORDER BY value")],
        "owned_ranges": [dict(r) for r in db.execute("SELECT * FROM owned_ranges ORDER BY cidr")],
        "approved_hosts": [dict(r) for r in db.execute("SELECT * FROM approved_hosts ORDER BY hostname")],
    }


def profile(db):
    return dict(db.execute("SELECT * FROM scope_profiles WHERE scope='default'").fetchone())


def approval(db):
    r = db.execute("SELECT * FROM inventory_approvals WHERE withdrawn_at IS NULL ORDER BY id DESC LIMIT 1").fetchone()
    return dict(r) if r else None


# ---------------------------------------------------------------- changing (each writes one audit entry in the same transaction)
def _tx(db, fn):
    db.execute("BEGIN IMMEDIATE")
    try:
        out = fn()
        db.execute("COMMIT")
        return out
    except Exception:
        db.execute("ROLLBACK")
        raise


def add_domain(db, actor, name, statement_confirmed, address, kind="domain"):
    n = clean_name(name, "domain name")
    if statement_confirmed is not True:
        raise ScopeError(f"Tick the ownership statement to add a domain: \"{OWNERSHIP_STATEMENT}\"")

    def go():
        if db.execute("SELECT COUNT(*) FROM domains").fetchone()[0] >= LIMITS["domains"]:
            raise ScopeError(f"At most {LIMITS['domains']} domains.")
        if db.execute("SELECT 1 FROM domains WHERE name=?", (n,)).fetchone():
            raise ScopeError("That domain is already in scope.")
        t = iso()
        db.execute("INSERT INTO domains(name, kind, statement, attested_by, attested_at, created_by, created_at) VALUES(?,?,?,?,?,?,?)",
                   (n, kind, OWNERSHIP_STATEMENT, actor, t, actor, t))
        audit.write(db, actor, "domain-add", target=n, detail=f"{kind}; statement: {OWNERSHIP_STATEMENT}", address=address)
        return n
    return _tx(db, go)


def remove_domain(db, actor, name, address):
    def go():
        if not db.execute("DELETE FROM domains WHERE name=?", (name,)).rowcount:
            raise ScopeError("No such domain.")
        audit.write(db, actor, "domain-remove", target=name, address=address)
    return _tx(db, go)


_LIST = {  # kind -> (table, column, cleaner, limit key, add action, remove action)
    "exclusion": ("exclusions", "value", clean_exclusion, "exclude", "exclusion-add", "exclusion-remove"),
    "range": ("owned_ranges", "cidr", clean_cidr, "owned_ranges", "range-add", "range-remove"),
    "host": ("approved_hosts", "hostname", clean_name, "approved_hosts", "host-approve", "host-unapprove"),
}


def add_entry(db, actor, kind, value, address):
    table, col, cleaner, lim, act, _ = _LIST[kind]
    v = cleaner(value)

    def go():
        if db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] >= LIMITS[lim]:
            raise ScopeError(f"At most {LIMITS[lim]} entries.")
        if db.execute(f"SELECT 1 FROM {table} WHERE {col}=?", (v,)).fetchone():
            raise ScopeError("Already listed.")
        db.execute(f"INSERT INTO {table}({col}, created_by, created_at) VALUES(?,?,?)", (v, actor, iso()))
        audit.write(db, actor, act, target=v, address=address)
        return v
    return _tx(db, go)


def remove_entry(db, actor, kind, value, address):
    table, col, _, _, _, act = _LIST[kind]

    def go():
        if not db.execute(f"DELETE FROM {table} WHERE {col}=?", (value,)).rowcount:
            raise ScopeError("Not listed.")
        audit.write(db, actor, act, target=value, address=address)
    return _tx(db, go)


def set_profile(db, actor, address, check_profile=None, rate_profile=None, evidence=None):
    cur = profile(db)
    new = {"check_profile": check_profile or cur["check_profile"], "rate_profile": rate_profile or cur["rate_profile"],
           "evidence": evidence or cur["evidence"]}
    if new["check_profile"] not in CHECK_PROFILES or new["rate_profile"] not in RATE_PROFILES or new["evidence"] not in EVIDENCE_LEVELS:
        raise ScopeError("Unknown profile value.")
    changed = {k: (cur[k], v) for k, v in new.items() if cur[k] != v}
    if not changed:
        return False

    def go():
        db.execute("UPDATE scope_profiles SET check_profile=?, rate_profile=?, evidence=?, updated_by=?, updated_at=? WHERE scope='default'",
                   (new["check_profile"], new["rate_profile"], new["evidence"], actor, iso()))
        audit.write(db, actor, "profile-change", target="default",
                    detail="; ".join(f"{k}: {a} -> {b}" for k, (a, b) in sorted(changed.items())), address=address)
        return True
    return _tx(db, go)
