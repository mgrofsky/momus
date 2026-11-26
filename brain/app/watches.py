"""Version-watch definitions: what every version-watch job carries as options.watches.

The rules are copies of the scanner's (scanner/pipeline/version_watch.py validate_watches, wrapped by
scanner/runner.py validate_job, which checks every host name with its own _name rule). One bad watch would get every
later version-watch job rejected, so a watch is checked here with exactly those rules before it is stored; a test
(tests/test_scanner_contract.py) runs a corpus of good and bad watches through both and requires the same answer.

Error messages are fixed texts: they name the field, never the value that was typed."""
import json
import re

from . import audit, scope as scopem
from .db import iso

# copies of scanner/pipeline/version_watch.py (checked equal by tests/test_scanner_contract.py)
PRODUCTS = {"php": "PHP", "nginx": "nginx", "apache-httpd": "Apache HTTP Server", "openssl": "OpenSSL"}
MIN_FLOOR_MAJOR = {"openssl": 3}
WATCH_KEYS = {"id", "name", "product", "cves", "floors", "hosts"}
WATCH_REQUIRED = {"id", "name", "product", "cves", "floors"}
MAX_WATCHES = 20
MAX_CVES = 20
MAX_FLOORS = 16
MAX_HOSTS = 100
MAX_PATCH = 99999
# always used with fullmatch
WATCH_ID_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,30}[a-z0-9]")
WATCH_NAME_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9 ._,-]{0,78}[A-Za-z0-9._])?")
CVE_RE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,7}")
BRANCH_RE = re.compile(r"(?:0|[1-9][0-9]{0,3})\.(?:0|[1-9][0-9]{0,3})")
# a fixed release as typed in the form: x.y.z (branch x.y, lowest fixed patch z)
RELEASE_RE = re.compile(r"([0-9]{1,4}\.[0-9]{1,4})\.([0-9]{1,5})")

# fixed texts (never the value)
E_NOT_LIST = "The watches must be a list."
E_NONE = "Add at least one watch."
E_TOO_MANY = f"At most {MAX_WATCHES} watches: a version-watch job carries all of them."
E_NOT_OBJECT = "A watch must be an object."
E_UNKNOWN = "A watch has a field that is not one of id, name, product, cves, floors and hosts."
E_MISSING = "A watch needs an id, a name, a product, CVE ids and fixed releases."
E_ID = "The id must be 2 to 32 characters: a-z, 0-9 and '-', starting and ending with a letter or digit."
E_ID_TWICE = "Two watches have the same id."
E_NAME = "The name must be 1 to 80 characters: letters, digits, spaces and . _ , - only, starting with a letter or digit."
E_PRODUCT = "Choose one of the listed products: " + ", ".join(PRODUCTS.values()) + "."
E_CVES = f"Give 1 to {MAX_CVES} CVE ids."
E_CVE = "A CVE id is not written CVE-YYYY-NNNN (for example CVE-2099-0003)."
E_CVE_TWICE = "A CVE id is listed twice."
E_FLOORS = f"Give 1 to {MAX_FLOORS} fixed releases, one per branch."
E_BRANCH = "A branch must be written x.y: numbers of up to four digits, without leading zeros."
E_PATCH = f"A fixed patch number must be a whole number from 0 to {MAX_PATCH}."
E_OPENSSL = "OpenSSL fixed releases must be on branch 3.0 or newer (older OpenSSL releases carry letters)."
E_HOSTS = f"Give at most {MAX_HOSTS} extra host names."
E_HOST = ("An extra host name is not valid: use lower-case labels of a-z, 0-9, '-' and '_', separated by dots, "
          "with no trailing dot.")
# form input only
E_RELEASE = "Write each fixed release as x.y.z (for example 8.3.12): one per line, the lowest fixed release of its branch."
E_BRANCH_TWICE = "Two fixed releases are given for the same branch: give one per branch."
E_TOO_LONG = "A field is too long."
E_EXISTS = "A watch with that id exists already. Edit it on its own page."
E_NO_SUCH = "No such watch."
E_FULL = f"At most {MAX_WATCHES} watches: remove one first."
E_CONFIRM = "Tick the box to confirm the removal."
NONE_FOR_JOB = "Add a watch on the Version watch page first."

FORM_CAPS = {"watch_id": 100, "name": 200, "product": 40, "cves": 4000, "floors": 2000, "hosts": 40000}


class WatchError(ValueError):
    """An invalid watch; the message is a fixed text."""


def branch_key(b):
    major, minor = b.split(".")
    return int(major), int(minor)


def _host(v):
    """The scanner runner's _name rule: a string of 1..253 characters already in scope.norm_name's exact form."""
    if not isinstance(v, str) or not v or len(v) > 253:
        raise WatchError(E_HOST)
    n = scopem.norm_name(v)
    if not n or n != v:
        raise WatchError(E_HOST)
    return n


def validate_watch(w):
    """One watch in the canonical structure -> the normalized watch, or WatchError. Same checks, in the same order,
    as the scanner's validate_watches for one entry."""
    if not isinstance(w, dict):
        raise WatchError(E_NOT_OBJECT)
    if any(k not in WATCH_KEYS for k in w):
        raise WatchError(E_UNKNOWN)
    if WATCH_REQUIRED - set(w):
        raise WatchError(E_MISSING)
    wid = w["id"]
    if not isinstance(wid, str) or not WATCH_ID_RE.fullmatch(wid):
        raise WatchError(E_ID)
    name = w["name"]
    if not isinstance(name, str) or not WATCH_NAME_RE.fullmatch(name):
        raise WatchError(E_NAME)
    product = w["product"]
    if not isinstance(product, str) or product not in PRODUCTS:
        raise WatchError(E_PRODUCT)
    cves = w["cves"]
    if not isinstance(cves, list) or not cves or len(cves) > MAX_CVES:
        raise WatchError(E_CVES)
    for c in cves:
        if not isinstance(c, str) or not CVE_RE.fullmatch(c):
            raise WatchError(E_CVE)
    if len(set(cves)) != len(cves):
        raise WatchError(E_CVE_TWICE)
    floors = w["floors"]
    if not isinstance(floors, dict) or not floors or len(floors) > MAX_FLOORS:
        raise WatchError(E_FLOORS)
    norm = {}
    for b, p in floors.items():
        if not isinstance(b, str) or not BRANCH_RE.fullmatch(b):
            raise WatchError(E_BRANCH)
        if isinstance(p, bool) or not isinstance(p, int) or not 0 <= p <= MAX_PATCH:
            raise WatchError(E_PATCH)
        if int(b.split(".")[0]) < MIN_FLOOR_MAJOR.get(product, 0):
            raise WatchError(E_OPENSSL)
        norm[b] = p
    hosts = w.get("hosts", [])
    if not isinstance(hosts, list) or len(hosts) > MAX_HOSTS:
        raise WatchError(E_HOSTS)
    norm_hosts = sorted({_host(h) for h in hosts})
    return {"id": wid, "name": name, "product": product, "cves": list(cves),
            "floors": {b: norm[b] for b in sorted(norm, key=branch_key)}, "hosts": norm_hosts}


def validate_watches(raw):
    """A whole options.watches list (what a job carries) -> the normalized list, or WatchError."""
    if raw is None or raw == []:
        raise WatchError(E_NONE)
    if not isinstance(raw, list):
        raise WatchError(E_NOT_LIST)
    if len(raw) > MAX_WATCHES:
        raise WatchError(E_TOO_MANY)
    out, seen = [], set()
    for w in raw:
        n = validate_watch(w)
        if n["id"] in seen:
            raise WatchError(E_ID_TWICE)
        seen.add(n["id"])
        out.append(n)
    return out


# ---------------------------------------------------------------- the HTML form
def _items(text, seps=r"[\s,]+"):
    return [x for x in re.split(seps, text.strip()) if x] if text and text.strip() else []


def parse_form(watch_id, name, product, cves, floors, hosts):
    """Form fields (strings) -> the canonical structure (not yet validated), or WatchError for a field that cannot
    be read at all. CVE ids and host names: one per line or separated by commas or spaces. Fixed releases: one x.y.z
    per line (or comma separated), meaning branch x.y is fixed from patch z; two for the same branch are refused."""
    vals = {"watch_id": watch_id, "name": name, "product": product, "cves": cves, "floors": floors, "hosts": hosts}
    for k, v in vals.items():
        if not isinstance(v, str):
            vals[k] = ""
        elif len(v) > FORM_CAPS[k]:
            raise WatchError(E_TOO_LONG)
    fl = {}
    for line in _items(vals["floors"], r"[\r\n,]+"):
        line = line.strip()
        if not line:
            continue
        m = RELEASE_RE.fullmatch(line)
        if not m:
            raise WatchError(E_RELEASE)
        branch = m.group(1)
        if branch in fl:
            raise WatchError(E_BRANCH_TWICE)
        fl[branch] = int(m.group(2))
    host_list = []
    for h in _items(vals["hosts"]):
        n = scopem.norm_name(h)          # a typed name is normalized (lower case, trailing dot removed) when valid
        host_list.append(n if n else h)
    return {"id": vals["watch_id"].strip(), "name": vals["name"].strip(), "product": vals["product"].strip(),
            "cves": _items(vals["cves"]), "floors": fl, "hosts": host_list}


def form_values(w):
    """A stored (or typed) watch shown back in the form's fields."""
    floors = w.get("floors") if isinstance(w.get("floors"), dict) else {}
    return {"watch_id": w.get("id") or "", "name": w.get("name") or "", "product": w.get("product") or "",
            "cves": "\n".join(str(c) for c in (w.get("cves") or [])),
            "floors": "\n".join(f"{b}.{p}" for b, p in floors.items()),
            "hosts": "\n".join(str(h) for h in (w.get("hosts") or []))}


def raw_form_values(watch_id, name, product, cves, floors, hosts):
    """What was typed, for re-showing the form after a refusal (escaped by the template; cut to the form caps)."""
    vals = {"watch_id": watch_id, "name": name, "product": product, "cves": cves, "floors": floors, "hosts": hosts}
    return {k: (v if isinstance(v, str) else "")[:FORM_CAPS[k]] for k, v in vals.items()}


# ---------------------------------------------------------------- the database
def _row(r):
    return {"id": r["id"], "name": r["name"], "product": r["product"], "cves": json.loads(r["cves"]),
            "floors": json.loads(r["floors"]), "hosts": json.loads(r["hosts"]),
            "created_at": r["created_at"], "created_by": r["created_by"], "updated_at": r["updated_at"], "updated_by": r["updated_by"]}


def all_watches(db):
    """Every stored watch with its metadata, sorted by id."""
    return [_row(r) for r in db.execute("SELECT * FROM version_watches ORDER BY id")]


def get(db, wid):
    if not isinstance(wid, str) or not WATCH_ID_RE.fullmatch(wid):
        return None
    r = db.execute("SELECT * FROM version_watches WHERE id=?", (wid,)).fetchone()
    return _row(r) if r else None


def for_job(db):
    """options.watches for a job: every stored watch in canonical form, sorted by id, checked again as a whole."""
    rows = [{k: w[k] for k in ("id", "name", "product", "cves", "floors", "hosts")} for w in all_watches(db)]
    if not rows:
        return []
    return validate_watches(rows)


def summary(w):
    hosts = len(w["hosts"])
    return (f"{w['product']}; {len(w['cves'])} CVE(s); {len(w['floors'])} branch(es); "
            f"{hosts} extra host name(s)")


def save(db, actor, raw, address, mode="upsert"):
    """Add or edit one watch from the canonical structure. mode: 'add' (refused if the id exists), 'edit' (refused if
    it does not) or 'upsert'. Returns ('added' | 'edited' | 'unchanged', the normalized watch). Validation happens
    before anything is written; the row and its audit entry commit together."""
    w = validate_watch(raw)
    db.execute("BEGIN IMMEDIATE")
    try:
        cur = db.execute("SELECT * FROM version_watches WHERE id=?", (w["id"],)).fetchone()
        if cur is None and mode == "edit":
            raise WatchError(E_NO_SUCH)
        if cur is not None and mode == "add":
            raise WatchError(E_EXISTS)
        t = iso()
        data = (w["name"], w["product"], json.dumps(w["cves"]), json.dumps(w["floors"]), json.dumps(w["hosts"]))
        if cur is None:
            if db.execute("SELECT COUNT(*) FROM version_watches").fetchone()[0] >= MAX_WATCHES:
                raise WatchError(E_FULL)
            db.execute("INSERT INTO version_watches(id, name, product, cves, floors, hosts, created_at, created_by, updated_at, updated_by) "
                       "VALUES(?,?,?,?,?,?,?,?,?,?)", (w["id"], *data, t, actor, t, actor))
            audit.write(db, actor, "watch-add", target=w["id"], detail=summary(w), address=address)
            outcome = "added"
        elif (cur["name"], cur["product"], cur["cves"], cur["floors"], cur["hosts"]) == data:
            outcome = "unchanged"
        else:
            db.execute("UPDATE version_watches SET name=?, product=?, cves=?, floors=?, hosts=?, updated_at=?, updated_by=? WHERE id=?",
                       (*data, t, actor, w["id"]))
            audit.write(db, actor, "watch-edit", target=w["id"], detail=summary(w), address=address)
            outcome = "edited"
        db.execute("COMMIT")
        return outcome, w
    except BaseException:
        if db.in_transaction:
            db.execute("ROLLBACK")
        raise


def remove(db, actor, wid, confirmed, address):
    if not confirmed:
        raise WatchError(E_CONFIRM)
    if not isinstance(wid, str) or not WATCH_ID_RE.fullmatch(wid):
        raise WatchError(E_NO_SUCH)
    db.execute("BEGIN IMMEDIATE")
    try:
        cur = db.execute("SELECT * FROM version_watches WHERE id=?", (wid,)).fetchone()
        if cur is None:
            raise WatchError(E_NO_SUCH)
        db.execute("DELETE FROM version_watches WHERE id=?", (wid,))
        audit.write(db, actor, "watch-remove", target=wid, detail=summary(_row(cur)), address=address)
        db.execute("COMMIT")
    except BaseException:
        if db.in_transaction:
            db.execute("ROLLBACK")
        raise
