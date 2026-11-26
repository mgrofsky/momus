"""Reading the published folder (written by the scanner, read-only here). Everything in it is untrusted: it holds
text taken from scan targets. Files are opened without following links, size-capped, and parsed tolerantly; only
known fields with the expected types are kept."""
import datetime as dt
import heapq
import json
import ipaddress
import os
import re
import stat

# Patterns are always used with fullmatch (re.match with "$" would accept a trailing newline).
ID_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,62}[a-z0-9]")
REPORT_FILE_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,62}[a-z0-9](\.html|-[a-z0-9][a-z0-9_-]{0,60}\.csv)")
INVALID_KEY_RE = re.compile(r"invalid-[0-9a-f]{16}")
# a host name: dot-separated labels of letters, digits, hyphen and underscore, no empty label, no leading or
# trailing hyphen, at most 253 characters ("." and ".." do not match)
HOSTNAME_RE = re.compile(r"(?=.{1,253}\Z)[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)*")
STATES = ("queued", "running", "done", "failed", "rejected", "interrupted")
FINAL = ("done", "failed", "rejected", "interrupted")
MAX_JSON = 4 * 1024 * 1024
MAX_STATUS_JSON = 64 * 1024        # a status file is well under 2 KB
MAX_STATUS_FILES = 300             # newest status files read per request; older ones are not parsed
MAX_DIR_ENTRIES = 50000            # directory entries looked at, at most, in one folder of published data
MAX_COUNT = 10 ** 9                # counts from status files are clamped to 0..MAX_COUNT
HEARTBEAT_STALE_SECONDS = 180      # the scanner beats at least every 30 s; older, or in the future, means stale


def is_hostname(v):
    return isinstance(v, str) and bool(HOSTNAME_RE.fullmatch(v))


def is_id(v):
    return isinstance(v, str) and bool(ID_RE.fullmatch(v))


def newest_names(d, accept, limit, max_entries=MAX_DIR_ENTRIES, report=None):
    """The names of at most `limit` regular files in d that `accept` (a name test), newest modification first. Only
    names and lstat results are looked at (no file is opened), at most max_entries directory entries, in bounded
    memory, so a folder filled with files cannot make a request read them all. When `report` (a dict) is given,
    report["truncated"] is set to True if the folder had more entries than were looked at."""
    heap = []
    try:
        with os.scandir(d) as it:
            for n, e in enumerate(it):
                if n >= max_entries:
                    if report is not None:
                        report["truncated"] = True
                    break
                name = e.name
                if name.startswith(".") or not accept(name):
                    continue
                try:
                    st = e.stat(follow_symlinks=False)
                except OSError:
                    continue
                if not stat.S_ISREG(st.st_mode):
                    continue
                item = (st.st_mtime_ns, name)
                if len(heap) < limit:
                    heapq.heappush(heap, item)
                elif item > heap[0]:
                    heapq.heapreplace(heap, item)
    except OSError:
        return []
    return [name for _, name in sorted(heap, reverse=True)]


class Unsafe(Exception):
    pass


def open_regular(path, max_bytes=None, dir_fd=None):
    """Open a regular file without following a symbolic link at the last component. Returns a binary file object.
    With dir_fd, path is a name inside that open directory."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), dir_fd=dir_fd)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise Unsafe("not a regular file")
        if max_bytes is not None and st.st_size > max_bytes:
            raise Unsafe("file too large")
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


def read_json(path, max_bytes=MAX_JSON, dir_fd=None):
    """Parsed JSON, or None when the file is missing, half-written, too large, not a regular file or not JSON. The
    size is checked on the open handle before anything is read or parsed."""
    try:
        with open_regular(path, max_bytes, dir_fd=dir_fd) as fh:
            raw = fh.read(max_bytes + 1)
        if len(raw) > max_bytes:
            return None
        from .snapshot import no_surrogates
        return no_surrogates(json.loads(raw.decode("utf-8")))     # the scanner's JSON files: same rule as the snapshot's
    except (OSError, ValueError, Unsafe, UnicodeDecodeError, RecursionError):
        return None


def open_dir_under(pub, parts):
    """An open descriptor of the folder pub/<parts...>, every folder below pub opened by descriptor without following
    a symbolic link (pub itself, the mount point, is trusted). None when a step is missing or not a real folder."""
    try:
        fd = os.open(pub, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0))
    except OSError:
        return None
    for p in parts:
        nxt = _open_dir(p, dir_fd=fd)
        os.close(fd)
        if nxt is None:
            return None
        fd = nxt
    return fd


def open_under(pub, parts, max_bytes=None):
    """open_regular for the file pub/<parts...>: no symbolic link is followed at any step below pub, so a folder
    link planted in the published folder is never followed. Raises OSError or Unsafe."""
    fd = open_dir_under(pub, parts[:-1])
    if fd is None:
        raise Unsafe("not a real folder")
    try:
        return open_regular(parts[-1], max_bytes, dir_fd=fd)
    finally:
        os.close(fd)


def read_json_under(pub, parts, max_bytes=MAX_JSON):
    """read_json for the file pub/<parts...>, opened as open_under does. None in the same cases as read_json."""
    fd = open_dir_under(pub, parts[:-1])
    if fd is None:
        return None
    try:
        return read_json(parts[-1], max_bytes, dir_fd=fd)
    finally:
        os.close(fd)


def s(v, n=300):
    """A display string from an untrusted value: str/int/float only, control characters dropped, capped."""
    if v is None or isinstance(v, bool):
        return None if v is None else ("yes" if v else "no")
    if isinstance(v, (int, float)):
        return str(v)
    if not isinstance(v, str):
        return None
    v = "".join(c for c in v if c >= " " or c in "\t")
    return v if len(v) <= n else v[:n] + "..."


def i(v):
    if isinstance(v, bool):
        return int(v)
    if isinstance(v, int):
        return v
    if isinstance(v, float) and v == v and abs(v) < 1e15:
        return int(v)
    if isinstance(v, str) and re.fullmatch(r"-?\d{1,15}", v.strip()):
        return int(v)
    return None


def folder_state(pub):
    """'missing' (no published folder), 'empty' (nothing published yet) or 'ok'."""
    if not os.path.isdir(pub):
        return "missing"
    try:
        names = [n for n in os.listdir(pub) if not n.startswith(".")]
    except OSError:
        return "missing"
    return "ok" if names else "empty"


# ---------------------------------------------------------------- scanner heartbeat
def heartbeat_age(s):
    """Seconds since the heartbeat's updated_at (negative when it is in the future), or None when unreadable."""
    try:
        t = dt.datetime.fromisoformat(str((s or {}).get("updated_at")).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if t.tzinfo is None:
        return None
    return (dt.datetime.now(dt.timezone.utc) - t).total_seconds()


def heartbeat_stale(s, limit=HEARTBEAT_STALE_SECONDS):
    """A heartbeat is fresh only when its time is in the last `limit` seconds: unreadable, older, or in the future
    (the scanner and the brain share the host's clock, and the scanner writes whole seconds rounded down) is stale."""
    age = heartbeat_age(s)
    return age is None or age < 0 or age > limit


def scanner(pub):
    d = read_json(os.path.join(pub, "scanner.json"), 256 * 1024)
    if not isinstance(d, dict):
        return None
    tools = d.get("tools") if isinstance(d.get("tools"), dict) else {}
    tmpl = d.get("templates") if isinstance(d.get("templates"), dict) else {}
    prof = d.get("profiles") if isinstance(d.get("profiles"), dict) else {}
    return {
        "updated_at": s(d.get("updated_at"), 40), "state": s(d.get("state"), 20), "current_job": s(d.get("current_job"), 64),
        "lab_mode": d.get("lab_mode") is True, "lab_cidr": s(d.get("lab_cidr"), 64),   # shown only; never used for lab mode
        "image_build_date": s(d.get("image_build_date"), 40),
        "tools": sorted((s(k, 40), s(v, 80)) for k, v in list(tools.items())[:40] if isinstance(k, str)),
        "templates": {"count": i(tmpl.get("count")), "version": s(tmpl.get("version"), 40), "date": s(tmpl.get("date"), 40),
                      "source": s(tmpl.get("source"), 60)},
        "profiles": {k: s(prof.get(k), 20) for k in ("check_profile", "rate_profile", "evidence")},
    }


# ---------------------------------------------------------------- job status
def _status(d, key):
    if not isinstance(d, dict):
        return None
    st = s(d.get("state"), 20)
    counts = d.get("counts") if isinstance(d.get("counts"), dict) else {}
    codes = d.get("exit_codes") if isinstance(d.get("exit_codes"), dict) else {}
    return {
        "job_id": key, "state": st if st in STATES else "unknown", "type": s(d.get("type"), 30), "phase": s(d.get("phase"), 60),
        "reason": s(d.get("reason"), 300), "queued_at": s(d.get("queued_at"), 40), "started_at": s(d.get("started_at"), 40),
        "ended_at": s(d.get("ended_at"), 40), "updated_at": s(d.get("updated_at"), 40),
        "run_id": d.get("run_id") if is_id(d.get("run_id")) else None,
        "lab": d.get("lab") is True,
        "counts": {s(k, 40): count(v) for k, v in list(counts.items())[:30] if isinstance(k, str) and count(v) is not None},
        "exit_codes": {s(k, 40): s(v, 40) for k, v in list(codes.items())[:20] if isinstance(k, str)},
        "report_files": i(d.get("report_files")),
    }


def count(v):
    """A count from published data: an integer clamped to 0..MAX_COUNT, or None."""
    n = i(v)
    return None if n is None else min(max(n, 0), MAX_COUNT)


def job_status(pub, job_id):
    if not is_id(job_id):
        return None
    return _status(read_json_under(pub, ("status", f"{job_id}.json"), MAX_STATUS_JSON), job_id)


def _status_name(f):
    return f.endswith(".json") and (is_id(f[:-5]) or bool(INVALID_KEY_RE.fullmatch(f[:-5])))


def all_status(pub, limit=MAX_STATUS_FILES):
    """The newest status files (by modification time; at most `limit`, chosen before any file is read), parsed."""
    out = []
    d = open_dir_under(pub, ("status",))
    if d is None:
        return out
    try:
        for f in newest_names(d, _status_name, min(limit, MAX_STATUS_FILES)):
            st = _status(read_json(f, MAX_STATUS_JSON, dir_fd=d), f[:-5])
            if st:
                out.append(st)
    finally:
        os.close(d)
    out.sort(key=lambda x: (x.get("queued_at") or x.get("updated_at") or ""), reverse=True)
    return out


# ---------------------------------------------------------------- scope status (published by the scanner)
SCOPE_STATES = ("no-statement", "pending", "verified", "refused", "lapsed")
LAST_RESULTS = ("match", "mismatch", "disagree", "unsafe", "failure")


def scope_status(pub):
    d = read_json(os.path.join(pub, "scope_status.json"), 1024 * 1024)
    if not isinstance(d, dict) or not isinstance(d.get("domains"), dict):
        return None
    out = {}
    for name, v in list(d["domains"].items())[:1000]:
        if not is_hostname(name) or not isinstance(v, dict):
            continue
        e = {k: s(v.get(k), 300) for k in ("txt_value", "last_checked_at", "verified_at", "attested_by", "token_reset")}
        e["state"] = v.get("state") if v.get("state") in SCOPE_STATES else "unknown"
        e["last_result"] = v.get("last_result") if v.get("last_result") in LAST_RESULTS else (None if v.get("last_result") is None else "unknown")
        e["txt_name"] = v.get("txt_name") if is_hostname(v.get("txt_name")) else None
        out[name] = e
    return {"updated_at": s(d.get("updated_at"), 40), "domains": out, "notice": s(d.get("notice"), 400),
            "install_key_id": s(d.get("install_key_id"), 40)}


# ---------------------------------------------------------------- reports
def report_files(pub, run_id, limit=20):
    if not is_id(run_id):
        return []
    out = []
    d = open_dir_under(pub, ("reports", run_id))
    if d is None:
        return out
    try:
        for f in sorted(newest_names(d, lambda f: bool(REPORT_FILE_RE.fullmatch(f)), limit)):
            if f == f"{run_id}.html" or f.startswith(f"{run_id}-"):
                try:
                    st = os.stat(f, dir_fd=d, follow_symlinks=False)
                except OSError:
                    continue
                if stat.S_ISREG(st.st_mode):
                    out.append({"name": f, "size": st.st_size})
    finally:
        os.close(d)
    return out


def is_report_name(run_id, name):
    return is_id(run_id) and isinstance(name, str) and bool(REPORT_FILE_RE.fullmatch(name)) and (
        name == f"{run_id}.html" or name.startswith(f"{run_id}-"))


def open_report(pub, run_id, name, max_bytes):
    """The report file reports/<run_id>/<name>, opened without following a link at any step; None when the name is not
    a report name of that run. Raises OSError or Unsafe when the file cannot be opened safely."""
    if not is_report_name(run_id, name):
        return None
    return open_under(pub, ("reports", run_id, name), max_bytes)


# ---------------------------------------------------------------- version watch
# published/version-watch/<watch id>/<YYYY-MM-DD>.json and latest.json (schema version-watch-v1, written by
# scanner/pipeline/version_watch.py). Every file is untrusted: the folder is listed with bounds (names, lstat only),
# folders and files are opened without following links, each file is size-checked on its open handle before it is
# parsed, and every field is checked for type and pattern (fullmatch); a value that fails is shown as "unknown" or
# not at all. hosts[].server is the only text taken from a target, and like reason it is only ever shown as text.
VW_DIR = "version-watch"
VW_SCHEMA = "version-watch-v1"
VW_MAX_JSON = 4 * 1024 * 1024
VW_MAX_FOLDERS = 50            # watch folders listed (newest by modification time)
VW_MAX_DATED = 50              # dated files listed per watch (newest by the date in the name)
VW_MAX_HOSTS = 5000
VW_MAX_CHANGES = 5000
VW_MAX_HISTORY = 100
VW_MAX_CVES = 20
VW_MAX_FLOORS = 16
VW_MAX_BY_VERSION = 200
VW_MAX_BY_DOMAIN = 1000
VW_REASON_CAP = 300
VW_SERVER_CAP = 100
VW_WATCH_ID_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,30}[a-z0-9]")
VW_NAME_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9 ._,-]{0,78}[A-Za-z0-9._])?")
VW_DATED_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}\.json")
VW_DATE_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
VW_TIME_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
VW_VERSION_RE = re.compile(r"[0-9]{1,4}\.[0-9]{1,4}(?:\.[0-9]{1,6})?")
VW_FLOOR_RE = re.compile(r"[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,6}")
VW_BRANCH_RE = re.compile(r"(?:0|[1-9][0-9]{0,3})\.(?:0|[1-9][0-9]{0,3})")
VW_CVE_RE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,7}")
VW_READ_FROM_RE = re.compile(r"(https|http) (x-powered-by|server)( \(after redirect\))?")
VW_VERDICTS = ("FAIL", "PASS", "UNKNOWN", "UNREACHABLE")
VW_SOURCES = ("scan_db", "job", "both", "carried")
VW_PRODUCTS = {"php": "PHP", "nginx": "nginx", "apache-httpd": "Apache HTTP Server", "openssl": "OpenSSL"}
VW_COUNT_KEYS = ("hosts", "fail", "pass", "unknown", "unreachable")
VW_TARGET_KEYS = ("total", "from_scan_db", "from_job", "carried", "not_probed")
SUSPECT_TEXT = ("The latest run was suspect (more than half the hosts did not answer); the results below are from the "
                "last good run on {date}.")
SUSPECT_NO_GOOD_TEXT = ("The latest run was suspect (more than half the hosts did not answer), and there is no earlier "
                        "good run to show.")


def is_watch_id(v):
    return isinstance(v, str) and bool(VW_WATCH_ID_RE.fullmatch(v))


def _vw_date(v):
    if not isinstance(v, str) or not VW_DATE_RE.fullmatch(v):
        return None
    try:
        dt.date.fromisoformat(v)
    except ValueError:
        return None
    return v


def _n(v):
    """A count: an int (not a bool) clamped to 0..MAX_COUNT, else None."""
    if isinstance(v, bool) or not isinstance(v, int):
        return None
    return min(max(v, 0), MAX_COUNT)


def _http_status(v):
    return v if isinstance(v, int) and not isinstance(v, bool) and 100 <= v <= 599 else None


def _pat(v, rx):
    return v if isinstance(v, str) and rx.fullmatch(v) else None


def _verdict(v, none_ok=False):
    if v is None and none_ok:
        return None
    return v if isinstance(v, str) and v in VW_VERDICTS else "unknown"


def _text(v, cap):
    return s(v, cap) if isinstance(v, str) else None


def _list(v, limit, tail=False):
    if not isinstance(v, list):
        return []
    return v[-limit:] if tail else v[:limit]


def _dict(v):
    return v if isinstance(v, dict) else {}


def _counts(d):
    d = _dict(d)
    return {k: _n(d.get(k)) for k in VW_COUNT_KEYS}


def clean_watch_doc(doc, watch_id):
    """A version-watch-v1 document reduced to known, checked fields, or None. The watch id must equal the folder's."""
    if not isinstance(doc, dict) or doc.get("schema") != VW_SCHEMA:
        return None
    w = _dict(doc.get("watch"))
    if w.get("id") != watch_id:
        return None
    product = w.get("product") if isinstance(w.get("product"), str) and w.get("product") in VW_PRODUCTS else None
    floors = {}
    for b, v in list(_dict(doc.get("floors")).items())[:VW_MAX_FLOORS]:
        if _pat(b, VW_BRANCH_RE) and _pat(v, VW_FLOOR_RE):
            floors[b] = v
    t = _dict(doc.get("targets"))
    by_version = []
    for r in _list(doc.get("by_version"), VW_MAX_BY_VERSION):
        if isinstance(r, dict) and _pat(r.get("version"), VW_VERSION_RE):
            by_version.append({"version": r["version"], "branch": _pat(r.get("branch"), VW_BRANCH_RE), "verdict": _verdict(r.get("verdict")),
                               "reason": _text(r.get("reason"), VW_REASON_CAP), "hosts": _n(r.get("hosts"))})
    by_domain = []
    for r in _list(doc.get("by_domain"), VW_MAX_BY_DOMAIN):
        if isinstance(r, dict) and is_hostname(r.get("domain")):
            by_domain.append({"domain": r["domain"], **_counts(r)})
    hosts = []
    for h in _list(doc.get("hosts"), VW_MAX_HOSTS):
        if not isinstance(h, dict) or not is_hostname(h.get("hostname")) or not is_hostname(h.get("domain")):
            continue
        hosts.append({"hostname": h["hostname"], "domain": h["domain"], "version": _pat(h.get("version"), VW_VERSION_RE),
                      "verdict": _verdict(h.get("verdict")), "reason": _text(h.get("reason"), VW_REASON_CAP),
                      "read_from": _pat(h.get("read_from"), VW_READ_FROM_RE), "https_status": _http_status(h.get("https_status")),
                      "http_status": _http_status(h.get("http_status")), "server": _text(h.get("server"), VW_SERVER_CAP),
                      "scan_db_version": _pat(h.get("scan_db_version"), VW_VERSION_RE),
                      "source": h.get("source") if isinstance(h.get("source"), str) and h.get("source") in VW_SOURCES else "unknown"})
    ch = _dict(doc.get("changes"))
    items = []
    for c in _list(ch.get("items"), VW_MAX_CHANGES):
        if isinstance(c, dict) and is_hostname(c.get("hostname")):
            items.append({"hostname": c["hostname"], "from_version": _pat(c.get("from_version"), VW_VERSION_RE),
                          "to_version": _pat(c.get("to_version"), VW_VERSION_RE),
                          "from_verdict": _verdict(c.get("from_verdict"), none_ok=True),
                          "to_verdict": _verdict(c.get("to_verdict"), none_ok=True)})
    history = []
    for r in _list(doc.get("history"), VW_MAX_HISTORY, tail=True):
        if isinstance(r, dict) and _vw_date(r.get("date")):
            history.append({"date": r["date"], **_counts(r)})
    return {
        "suspect": doc.get("suspect") is True,
        "watch": {"id": watch_id, "name": _pat(w.get("name"), VW_NAME_RE), "product": product or "unknown",
                  "product_name": VW_PRODUCTS.get(product, "unknown")},
        "job_id": doc.get("job_id") if is_id(doc.get("job_id")) else None,
        "generated_at": _pat(doc.get("generated_at"), VW_TIME_RE),
        "date": _vw_date(doc.get("date")),
        "cves": [c for c in _list(doc.get("cves"), VW_MAX_CVES) if _pat(c, VW_CVE_RE)],
        "floors": floors,
        "targets": {**{k: _n(t.get(k)) for k in VW_TARGET_KEYS}, "scan_db_run": t.get("scan_db_run") if is_id(t.get("scan_db_run")) else None},
        "headline": _counts(doc.get("headline")),
        "by_version": by_version,
        "by_domain": by_domain,
        "hosts": hosts,
        "changes": {"since": _vw_date(ch.get("since")), "items": items},
        "history": history,
    }


def _open_dir(name, dir_fd=None):
    """An open directory, never through a symbolic link at the last component; None if it is not a real directory."""
    try:
        return os.open(name, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                       dir_fd=dir_fd)
    except OSError:
        return None


def watch_folders(pub, limit=VW_MAX_FOLDERS, max_entries=None):
    """The names of at most `limit` watch result folders in published/version-watch/, newest modification first: names
    that fullmatch the watch id pattern and that lstat shows to be directories (a symbolic link is not followed and
    not listed). At most max_entries directory entries are looked at; nothing inside a folder is opened here."""
    max_entries = MAX_DIR_ENTRIES if max_entries is None else max_entries
    base = _open_dir(os.path.join(pub, VW_DIR))
    if base is None:
        return []
    heap = []
    try:
        with os.scandir(base) as it:
            for n, e in enumerate(it):
                if n >= max_entries:
                    break
                if not is_watch_id(e.name):
                    continue
                try:
                    st = e.stat(follow_symlinks=False)
                except OSError:
                    continue
                if not stat.S_ISDIR(st.st_mode):
                    continue
                item = (st.st_mtime_ns, e.name)
                if len(heap) < limit:
                    heapq.heappush(heap, item)
                elif item > heap[0]:
                    heapq.heapreplace(heap, item)
    except OSError:
        return []
    finally:
        os.close(base)
    return [name for _, name in sorted(heap, reverse=True)]


def _dated_names(dfd, limit=VW_MAX_DATED, max_entries=None):
    """The dated result files of one watch folder (an open directory), newest first BY THE DATE IN THE NAME, at most
    `limit`: the newest `limit` of at most max_entries entries (a bounded heap), regular files only (lstat)."""
    max_entries = MAX_DIR_ENTRIES if max_entries is None else max_entries
    heap = []
    try:
        with os.scandir(dfd) as it:
            for n, e in enumerate(it):
                if n >= max_entries:
                    break
                name = e.name
                if not VW_DATED_RE.fullmatch(name) or not _vw_date(name[:-5]):
                    continue
                try:
                    st = e.stat(follow_symlinks=False)
                except OSError:
                    continue
                if not stat.S_ISREG(st.st_mode):
                    continue
                if len(heap) < limit:
                    heapq.heappush(heap, name)
                elif name > heap[0]:
                    heapq.heapreplace(heap, name)
    except OSError:
        return []
    return sorted(heap, reverse=True)


def watch_result(pub, watch_id):
    """One watch's published results: {"folder": bool (a real results folder exists), "result": the checked document
    shown (latest.json; None when there is no good run), "suspect": None or {"date", "good_date", "text"}, "dates":
    the dated files' dates, newest first (at most VW_MAX_DATED)}. Only latest.json and the newest dated file are read."""
    out = {"folder": False, "result": None, "suspect": None, "dates": []}
    if not is_watch_id(watch_id):
        return out
    base = _open_dir(os.path.join(pub, VW_DIR))
    if base is None:
        return out
    try:
        dfd = _open_dir(watch_id, dir_fd=base)
    finally:
        os.close(base)
    if dfd is None:
        return out
    try:
        out["folder"] = True
        names = _dated_names(dfd)
        out["dates"] = [n[:-5] for n in names]
        latest = clean_watch_doc(read_json("latest.json", VW_MAX_JSON, dir_fd=dfd), watch_id)
        newest = clean_watch_doc(read_json(names[0], VW_MAX_JSON, dir_fd=dfd), watch_id) if names else None
    finally:
        os.close(dfd)
    shown = latest if latest and not latest["suspect"] else None
    if shown is None and newest and not newest["suspect"]:
        shown = newest
    out["result"] = shown
    if newest and newest["suspect"]:
        newest_date = names[0][:-5]
        good = shown["date"] if shown else None
        # a suspect run on the same UTC day as the good run overwrote that day's dated file: it is newer when it was
        # written later (generated_at is a strict UTC time stamp, so the text comparison is a time comparison)
        later_same_day = (good == newest_date and bool(newest["generated_at"]) and bool(shown["generated_at"])
                          and newest["generated_at"] > shown["generated_at"])
        if good is None or newest_date > good or later_same_day:
            out["suspect"] = {"date": newest_date, "good_date": good,
                              "text": SUSPECT_TEXT.format(date=good) if good else SUSPECT_NO_GOOD_TEXT}
    return out


# ---------------------------------------------------------------- hosts held back from active phases (latest full or recheck run)
HELD_REASONS = {"new-since-approved-inventory": "new since the approved inventory",
                "address-changed": "address changed since the approved inventory",
                "domain-not-in-approved-inventory": "its domain was added after the approved inventory"}
HELD_DOMAIN = "domain-not-in-approved-inventory"
HELD_DOMAIN_TEXT = "This domain was added after the inventory you approved. Approve a newer inventory to scan it."
UNKNOWN_REASON = "unknown reason"


def _ips(v, limit=64):
    """Addresses from the scanner's file, each one parsed (anything else is dropped), in a stable order."""
    out = set()
    for x in (v if isinstance(v, list) else [])[:limit]:
        if isinstance(x, str) and len(x) <= 45:
            try:
                out.add(str(ipaddress.ip_address(x)))
            except ValueError:
                pass
    return sorted(out)


def held_back(pub):
    d = read_json(os.path.join(pub, "held_back.json"), 4 * 1024 * 1024)
    if not isinstance(d, dict) or not isinstance(d.get("hosts"), list):
        return None
    hosts = []
    # hosts and domains must be host names; a reason other than the fixed codes is kept and shown as "unknown reason"
    for h in d["hosts"][:5000]:
        if isinstance(h, dict) and is_hostname(h.get("host")):
            known = h.get("reason") in HELD_REASONS
            hosts.append({"host": h["host"], "reason": h["reason"] if known else "unknown", "why": HELD_REASONS[h["reason"]] if known else UNKNOWN_REASON,
                          "approved_ips": _ips(h.get("approved_ips")), "current_ips": _ips(h.get("current_ips"))})
    domains, other_domains = [], []
    for x in (d.get("domains") if isinstance(d.get("domains"), list) else [])[:1000]:
        if isinstance(x, dict) and is_hostname(x.get("domain")):
            (domains if x.get("reason") == HELD_DOMAIN else other_domains).append(x["domain"])
    rid = d.get("run_id")
    inv = d.get("inventory_run")
    return {"updated_at": s(d.get("updated_at"), 40), "run_id": rid if is_id(rid) else None,
            "inventory_run": inv if is_id(inv) else None, "hosts": hosts, "domains": sorted(set(domains)),
            "other_domains": sorted(set(other_domains) - set(domains))}


DOMAIN_COUNT_KEYS = ("domains_scanned", "domains_held_back", "domains_pending")


def domain_counts(st):
    """{"scanned", "held_back", "pending"} from a full or recheck job's status counts (numbers only), or None."""
    c = (st or {}).get("counts") or {}
    if not all(isinstance(c.get(k), int) for k in DOMAIN_COUNT_KEYS):
        return None
    return {k[len("domains_"):]: min(max(c[k], 0), MAX_COUNT) for k in DOMAIN_COUNT_KEYS}
