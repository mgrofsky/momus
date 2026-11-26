"""The scan snapshot: only the file that published/snapshots/latest.json names, only after its SHA-256 matches and
its schema is the plain-table schema the brain expects.

The named file is copied, while hashing, into a temporary file in the brain's own cache. Only a copy whose SHA-256
equals the recorded one, whose schema holds nothing but plain tables and indexes (no view, trigger or virtual table,
and every table the brain reads has the columns it reads), and which passes SQLite's quick check, is renamed into the
cache and opened: read-only and immutable, with an authorizer that allows reading only, trusted_schema off, and a
progress handler that stops any query after the request's deadline. Hashing a copy closes the gap between "hash
checked" and "file opened" (the scanner may replace files in the published folder at any time); nothing is ever
written to the published folder.

Every outcome, refusals included, is remembered for the file's identity (path, inode, size, modification time and
the hash latest.json names), so a refused file is not copied and hashed again on every request."""
import collections
import hashlib
import json
import os
import re
import sqlite3
import threading
import time
import urllib.parse

from .published import open_dir_under, open_regular, read_json, Unsafe, ID_RE

SNAP_NAME_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,62}[a-z0-9]\.sqlite")     # always used with fullmatch
SHA_RE = re.compile(r"[0-9a-f]{64}")
MIB = 1024 * 1024
DEFAULT_MAX_MB = 512          # MOMUS_SNAPSHOT_MAX_MB; see config.py for why
KEEP_CACHED = 3
VERIFY_SECONDS = 120          # deadline for the one-time schema and quick check of a new snapshot
TMP_MARK = ".tmp-"
MEMO = 16

# The tables the brain reads and the columns it reads from each (queries.py). A snapshot in which one of these is
# present but is not a plain table with at least these columns is refused. A missing table is allowed (its page shows
# nothing). runs: kind, evidence_level and inventory_only are optional (queries.runs falls back without them).
REQUIRED = {
    "runs": {"seq", "run_id", "started", "finished"},
    "run_summary": {"run_id", "json"},
    "findings": {"finding_key", "hostname", "apex", "source", "check_id", "port", "title", "severity", "status", "cve_ids",
                 "first_seen_run", "last_seen_run", "fixed_run"},
    "finding_observations": {"run_id", "finding_key", "asset_class", "matched", "description", "remediation", "reference", "tags",
                             "cvss", "epss", "kev", "impact", "likelihood", "score", "band", "sla_days", "state", "raw_json",
                             "verdict", "verification", "exposure"},
    "finding_triage": {"run_id", "finding_key", "exposure", "summary", "fix", "items_json", "secrets_json", "pci"},
    "asset_observations": {"run_id", "hostname", "apex", "class", "reason", "ips", "cnames", "tech", "waf", "status_code", "title",
                           "server", "urls", "cert_expiry"},
    "asset_profiles": {"run_id", "hostname", "hosting", "cdn", "web_server", "cms", "framework", "tls_max", "cert_issuer"},
    "host_ports": {"run_id", "hostname", "ip", "port", "proto", "service", "product", "risky"},
    "endpoints": {"run_id", "hostname", "url", "status", "final_url", "title", "server", "content_type", "hsts", "csp", "xfo",
                  "emails", "generator", "powered_by"},
    "asset_components": {"run_id", "hostname", "category", "name", "version", "source", "eol", "eol_date"},
    "certificates": {"run_id", "hostname", "port", "subject", "sans", "issuer", "key_type", "key_bits", "sig_alg", "not_before",
                     "not_after", "days_left", "expired", "self_signed"},
    "tls_endpoints": {"run_id", "hostname", "port", "protocols", "legacy", "preferred_cipher", "weak_ciphers"},
    "dns_records": {"run_id", "hostname", "rtype", "name", "value", "ttl"},
    "domain_posture": {"run_id", "apex", "spf", "spf_policy", "dmarc", "dmarc_policy", "dmarc_sp", "dkim", "mx", "mx_provider",
                       "caa", "caa_issuers", "nameservers", "ns_provider", "hosts_with_spf", "hosts_with_dkim"},
}

_lock = threading.Lock()
_checked = collections.OrderedDict()   # (path, ino, size, mtime_ns, sha) -> (kind, cached copy path or None)


class Timeout(Exception):
    """A snapshot query ran past the request's deadline and was stopped."""


class SnapConn(sqlite3.Connection):
    """A snapshot connection that records whether its progress handler stopped a query (queries.py turns that into
    Timeout instead of an empty result)."""
    timed_out = False


class State:
    """What the brain can show: kind is ok, missing, empty, none, bad-pointer, mismatch, too-large, refused or unreadable."""

    def __init__(self, kind, message, info=None, path=None):
        self.kind, self.message, self.info, self.path = kind, message, info or {}, path

    @property
    def ok(self):
        return self.kind == "ok"


REFUSED_KINDS = ("bad-pointer", "mismatch", "too-large", "refused", "unreadable")
MESSAGES = {
    "missing": "The published folder is not there. Is the scanner's 'published' volume mounted into the brain?",
    "empty": "Nothing has been published yet. Results appear here after the scanner finishes its first job.",
    "none": "No scan snapshot has been published yet. Results appear here after the first inventory or full run.",
    "bad-pointer": "The snapshot pointer (snapshots/latest.json) is missing fields, half-written, or names an invalid file. "
                   "Nothing was opened.",
    "mismatch": "The snapshot named by snapshots/latest.json does not match its recorded SHA-256. It was refused and "
                "nothing from it is shown. The next finished run publishes a new one.",
    "too-large": "The snapshot named by snapshots/latest.json is larger than this brain accepts (MOMUS_SNAPSHOT_MAX_MB). It was "
                 "refused and nothing from it is shown.",
    "refused": "The snapshot's database schema is not the plain-table schema the scanner writes: it holds a view, trigger "
               "or virtual table, or a table the brain reads is not a plain table with the expected columns. It was "
               "refused and nothing from it is shown.",
    "unreadable": "The snapshot file could not be read as a database. Nothing from it is shown.",
}


def _authorizer(action, a1, a2, dbname, source):
    allowed = {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION, getattr(sqlite3, "SQLITE_RECURSIVE", 33)}
    if action in allowed:
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_PRAGMA and a1 in ("table_info", "table_xinfo", "table_list", "query_only", "quick_check",
                                                   "trusted_schema"):
        return sqlite3.SQLITE_OK
    return sqlite3.SQLITE_DENY


def schema_problem(c):
    """None when the database holds only plain tables and indexes and every table the brain reads (when present) is a
    plain table with the columns it reads; else a short fixed reason. Judged from what SQLite parsed (table_list,
    table_xinfo) and from the stored CREATE statements, which SQLite normalizes to start with their two keywords."""
    for typ, name, sql in c.execute("SELECT type, name, sql FROM sqlite_master"):
        if typ == "table":
            if not isinstance(sql, str) or not sql.startswith("CREATE TABLE "):
                return "an object that is not a plain table"
        elif typ == "index":
            if sql is not None and not (isinstance(sql, str) and (sql.startswith("CREATE INDEX ") or sql.startswith("CREATE UNIQUE INDEX "))):
                return "an index that is not a plain index"
        else:
            return "a view or trigger"
    for r in c.execute("PRAGMA table_list"):
        if r["type"] != "table":
            return "a view, virtual table or shadow table"
    for table, cols in REQUIRED.items():
        info = c.execute(f"PRAGMA table_xinfo({table})").fetchall()      # table names come from REQUIRED, never from input
        if not info:
            continue
        if any(r["hidden"] for r in info):
            return "a hidden or generated column"
        if not cols <= {r["name"] for r in info}:
            return "a table without the expected columns"
    return None


def _open(path, seconds=None):
    uri = "file:" + urllib.parse.quote(os.path.abspath(path)) + "?mode=ro&immutable=1"
    c = sqlite3.connect(uri, uri=True, check_same_thread=False, factory=SnapConn)
    c.row_factory = sqlite3.Row
    c.text_factory = text_value
    c.execute("PRAGMA trusted_schema=OFF")
    c.execute("PRAGMA query_only=ON")
    c.set_authorizer(_authorizer)
    if seconds:
        deadline = time.monotonic() + seconds

        def tick():
            if time.monotonic() > deadline:
                c.timed_out = True
                return 1          # non-zero: SQLite stops the statement ("interrupted")
            return 0
        c.set_progress_handler(tick, 1000)
    return c


def connect(state, seconds=None):
    """A read-only connection to a verified snapshot; every query on it stops once `seconds` have passed."""
    return _open(state.path, seconds)


def _copy(src, tmp, max_bytes):
    """Copy src, (open folder descriptor, file name), to tmp while hashing; at most max_bytes, counted while copying
    (the file may grow after fstat)."""
    h = hashlib.sha256()
    n = 0
    with open_regular(src[1], max_bytes, dir_fd=src[0]) as fin:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), 0o600)
        with os.fdopen(fd, "wb") as fout:
            for chunk in iter(lambda: fin.read(MIB), b""):
                n += len(chunk)
                if n > max_bytes:
                    raise Unsafe("file too large")
                h.update(chunk)
                fout.write(chunk)
    return h.hexdigest()


def _verify(src, cache_dir, want, max_bytes):
    """(kind, path, remember). Only a copy that passed every check is renamed into the cache; the temporary copy is
    always removed otherwise."""
    os.makedirs(cache_dir, exist_ok=True)
    tmp = os.path.join(cache_dir, f".{want}{TMP_MARK}{os.getpid()}-{threading.get_ident()}")
    try:
        try:
            digest = _copy(src, tmp, max_bytes)
        except Unsafe as e:
            return ("too-large" if "too large" in str(e) else "bad-pointer"), None, True
        except OSError:
            return "bad-pointer", None, False       # could be the brain's own disk: try again next time
        if digest != want:
            return "mismatch", None, True
        try:
            c = _open(tmp, VERIFY_SECONDS)
            try:
                if schema_problem(c):
                    return "refused", None, True
                ok = c.execute("PRAGMA quick_check").fetchone()[0] == "ok"
            finally:
                c.close()
        except sqlite3.Error:
            ok = False
        if not ok:
            return "unreadable", None, True
        os.chmod(tmp, 0o400)
        final = os.path.join(cache_dir, f"{want}.sqlite")
        os.replace(tmp, final)
        _prune(cache_dir, final)
        return "ok", final, True
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        except OSError:
            pass


def _prune(cache_dir, keep):
    cached = []
    for f in os.listdir(cache_dir):
        p = os.path.join(cache_dir, f)
        if f.endswith(".sqlite") and not f.startswith("."):
            try:
                cached.append((os.stat(p).st_mtime, p))
            except OSError:
                pass
    for _, p in sorted(cached, reverse=True)[KEEP_CACHED:]:
        if p != keep:
            try:
                os.unlink(p)
            except OSError:
                pass


def remove_stale_temporaries(cache_dir):
    """At start-up: remove temporary copies left by a crash or a kill during an earlier copy."""
    try:
        names = os.listdir(cache_dir)
    except OSError:
        return 0
    n = 0
    for f in names:
        if f.startswith(".") and TMP_MARK in f:
            try:
                os.unlink(os.path.join(cache_dir, f))
                n += 1
            except OSError:
                pass
    return n


def _remember(key, kind, path):
    _checked[key] = (kind, path)
    _checked.move_to_end(key)
    while len(_checked) > MEMO:
        _checked.popitem(last=False)


def current(pub, cache_dir, max_bytes=DEFAULT_MAX_MB * MIB):
    """Resolve latest.json to a verified local copy. Returns a State."""
    if not os.path.isdir(pub):
        return State("missing", MESSAGES["missing"])
    snapdir = os.path.join(pub, "snapshots")
    lp = os.path.join(snapdir, "latest.json")
    if not os.path.lexists(lp):
        try:
            anything = [n for n in os.listdir(pub) if not n.startswith(".")]
        except OSError:
            anything = []
        return State("none" if anything else "empty", MESSAGES["none" if anything else "empty"])
    # the snapshots folder is opened by descriptor without following a link, and both files are opened inside it
    sfd = open_dir_under(pub, ("snapshots",))
    if sfd is None:
        return State("bad-pointer", MESSAGES["bad-pointer"])
    try:
        return _current(sfd, snapdir, cache_dir, max_bytes)
    finally:
        os.close(sfd)


def _current(sfd, snapdir, cache_dir, max_bytes):
    doc = read_json("latest.json", 64 * 1024, dir_fd=sfd)
    if not isinstance(doc, dict):
        return State("bad-pointer", MESSAGES["bad-pointer"])
    name, want = doc.get("file"), doc.get("sha256")
    run_id = doc.get("run_id")
    if not isinstance(name, str) or not SNAP_NAME_RE.fullmatch(name) or not isinstance(want, str) or not SHA_RE.fullmatch(want):
        return State("bad-pointer", MESSAGES["bad-pointer"])
    info = {"file": name, "sha256": want, "run_id": run_id if isinstance(run_id, str) and ID_RE.fullmatch(run_id) else None,
            "created_at": doc.get("created_at") if isinstance(doc.get("created_at"), str) else None}
    src = os.path.join(snapdir, name)
    try:
        st = os.stat(name, dir_fd=sfd, follow_symlinks=False)
    except OSError:
        return State("bad-pointer", MESSAGES["bad-pointer"], info)
    key = (src, st.st_ino, st.st_size, st.st_mtime_ns, want)
    with _lock:
        hit = _checked.get(key)
        if hit and (hit[0] != "ok" or os.path.isfile(hit[1])):
            kind, path = hit
        elif st.st_size > max_bytes:
            kind, path = "too-large", None
            _remember(key, kind, path)
        else:
            kind, path, remember = _verify((sfd, name), cache_dir, want, max_bytes)
            if remember:
                _remember(key, kind, path)
    if kind != "ok":
        return State(kind, MESSAGES[kind], info)
    return State("ok", "", info, path)


SURROGATE = re.compile("[\ud800-\udfff]")


def no_surrogates(v, depth=0):
    """A parsed JSON value with every unpaired surrogate (a JSON escape such as \\ud800 that is not half of a pair)
    replaced by U+FFFD, so the text can always be encoded as UTF-8: on a page, in an API answer, in a prompt, in the app
    database. Pairs were already joined by the JSON parser."""
    if isinstance(v, str):
        return SURROGATE.sub("\ufffd", v)
    if depth > 200:
        return v
    if isinstance(v, dict):
        return {no_surrogates(k, depth + 1): no_surrogates(x, depth + 1) for k, x in v.items()}
    if isinstance(v, list):
        return [no_surrogates(x, depth + 1) for x in v]
    return v


def text_value(b):
    """SQLite text from a snapshot: invalid UTF-8 (an encoded surrogate included) becomes U+FFFD instead of an error."""
    return b.decode("utf-8", "replace")


def loads(v, default=None):
    """Tolerant JSON for a snapshot column. Unpaired surrogates are replaced (no_surrogates)."""
    if v is None:
        return default
    if not isinstance(v, (str, bytes)):
        return default
    try:
        return no_surrogates(json.loads(v))
    except (ValueError, RecursionError):
        return default
