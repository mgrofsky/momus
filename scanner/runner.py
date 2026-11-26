#!/usr/bin/env python3
"""runner.py - the scanner's job runner. Started by entrypoint.sh after the egress firewall is in place and the
process has dropped to uid 10001 with no capabilities. Standard library only.

Two folders connect the scanner to the brain, and nothing else does:
  $SCAN_JOBS       (read-only here) one JSON file per job, <job id>.json, written by the brain
  $SCAN_PUBLISHED  (written here, read-only in the brain) everything the brain may read:
      status/<job id>.json        state, phase, counts, times, exit codes (no target-derived text)
      snapshots/<run id>.sqlite   a consistent copy of the scan database after ingest (SQLite backup API)
      snapshots/latest.json       the newest snapshot and its SHA-256
      reports/<run id>/           the HTML report and CSVs
      scope_status.json           per domain: verification state, the exact TXT record to publish, last check
      held_back.json              hosts the latest full/recheck run kept from active phases, with reason codes
      version-watch/<watch id>/   results of version-watch jobs, one folder per watch (<date>.json, latest.json),
                                  a copy of the state folder: files gone there are removed here too
      scanner.json                heartbeat: tool versions, templates, image build date, profiles in effect; about every
                                  30 s while idle, and while a job runs at every phase change and at least every 30 s
Every file is written to a temporary name in the same folder and renamed into place. If the published folder
cannot be written, the runner exits with one line (exit 75) instead of a traceback.

Jobs run one at a time, oldest file first. A job whose ID already has a final status is skipped. Every job is
validated (validate_job) before anything acts on it; an invalid job gets a "rejected" status with a fixed reason
naming the field (the offending value is never echoed) and is never run. Job types: scope-sync, inventory, full,
recheck, version-watch, update-templates, retention. The job carries a full copy of the scope; the runner writes it
into $SCAN_ROOT/scope atomically (a new folder, then one rename of the "scope" link). Verification state stays with
the scanner and a job can never set it. DNS proof tokens are derived by the scanner from its install secret
($SCAN_ROOT/state/install_secret, created on first start, 0600, never published; see scope.py); a job that carries
a token is rejected. An approval in a full or recheck job is accepted only when the inventory run it names covers at
least one domain of the job's scope (lab jobs: every lab target); the approval then keeps that inventory's hosts. A
scope domain that inventory did not cover gets no active phase (held back as domain-not-in-approved-inventory).

Job files are untrusted. Writers put a job in place by writing a dot-prefixed temporary name in the jobs folder and
renaming it to <job id>.json; dot-files are never read. Each file is opened without following links and without
blocking, must be a regular file no larger than MAX_JOB_BYTES (checked with fstat before reading), and must parse as
UTF-8 JSON with no duplicate keys. Any failure of reading, parsing or validating rejects that job with a fixed
reason; any unexpected error while handling a job fails that job with a fixed reason (the traceback goes to the
container log only), and the loop goes on to the next job. A job id for which the brain wrote <job id>.abandoned in
the jobs folder (its status file was lost and the admin abandoned it) is never run, even if its job file is still there.
Lab fields are accepted only when the container was started with SCAN_LAB=1, and their CIDR must equal
SCAN_LAB_CIDR (the one range the firewall allows).

Settings (environment, passed through by entrypoint.sh): SCAN_ROOT, SCAN_JOBS, SCAN_PUBLISHED, SCAN_LAB,
SCAN_LAB_CIDR, SCAN_KEEP_SNAPSHOTS (default 10), SCAN_POLL_SECONDS (default 5), SCAN_JOB_MAX_AGE_HOURS (default 72:
a job whose created_at is older is refused with a final status and runs nothing; created_at is required, and a job
dated more than five minutes ahead is refused the same way), SCAN_SEED_SCOPE_DIR (default /srv/seed-scope).

The seeder's list: whenever scope_status.json is published, $SCAN_SEED_SCOPE_DIR/verified_domains.json is written
too (when that folder exists): the schema, the time and the DNS-verified domain names, nothing else. It is the only
file the optional seeder reads from the scanner (its own small volume, read-only there); the seeder never mounts
published/.

Finished jobs: every final status written for a job id is also kept in $SCAN_ROOT/state/finished/<id>.json (the
scanner's own data volume, never published/). A job whose id is there never runs again, whatever published/ says
(lost, restored from an older copy, or not final): the runner publishes the recorded final status again instead.
"""
import datetime as dt
import hashlib
import ipaddress
import json
import os
import re
import shutil
import signal
import sqlite3
import stat
import subprocess
import sys
import time
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
PIPE = os.path.join(HERE, "pipeline")
sys.path.insert(0, PIPE)
import scope as S     # noqa: E402  name rules, ownership file, DNS proof record
import approve as A   # noqa: E402  inventory approval
import version_watch as VW   # noqa: E402  the watch rules (validate_watches) and the state folder's file names

SCHEMA = "momus-job-v1"
STATUS_SCHEMA = "momus-status-v1"
JOB_TYPES = ("scope-sync", "inventory", "full", "recheck", "version-watch", "update-templates", "retention")
SCAN_TYPES = ("inventory", "full", "recheck")
LAB_TYPES = ("inventory", "full", "version-watch")
ACTIVE_TYPES = ("full", "recheck")      # job types whose approval is bound and written (active phases)
FINAL = ("done", "failed", "rejected", "interrupted")
STATES = ("queued", "running") + FINAL
CHECK_PROFILES, RATE_PROFILES, EVIDENCE_LEVELS = ("safe", "active"), ("low", "normal", "fast"), ("minimal", "excerpt")

ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$")
ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?(Z|[+-]\d{2}:\d{2})$")
KEY_RE = re.compile(r"^[a-z_]{1,32}$")
PERSON_RE = re.compile(r"^[^\x00-\x1f\x7f<>\"'`$\\]{1,100}$")

MAX_JOB_BYTES = 1 << 20
LIMITS = {"domains": 200, "exclude": 1000, "owned_ranges": 256, "approved_hosts": 5000, "ownership": 200,
          "strict_sla_hosts": 5000, "lab_targets": 64}
TOP_KEYS = {"schema", "id", "type", "created_at", "scope", "lab", "options"}
SCOPE_KEYS = {"domains", "exclude", "owned_ranges", "approved_hosts", "ownership", "approval", "check_profile",
              "rate_profile", "evidence", "strict_sla_hosts"}
OWNERSHIP_KEYS = {"apex", "statement", "attested_by", "attested_at"}
APPROVAL_KEYS = {"approved_at", "inventory_run", "approved_by"}
ABANDONED_SUFFIX = ".abandoned"         # <job id>.abandoned in the jobs folder: the brain abandoned that id; never run it
JOB_MAX_AGE_HOURS = 72                  # default for SCAN_JOB_MAX_AGE_HOURS (1 to 8760)
TOO_OLD = ("job: created longer ago than the scanner's job age limit (SCAN_JOB_MAX_AGE_HOURS); it was not run. "
           "Queue it again if it is still wanted.")
SEED_SCOPE_FILE = "verified_domains.json"
SEED_SCOPE_SCHEMA = "momus-verified-domains-v1"
TOO_NEW = ("job: dated in the future (more than five minutes ahead of the scanner's clock); it was not run. Check the "
           "brain's and the scanner's clocks, then queue it again.")
MAX_FUTURE = dt.timedelta(minutes=5)
HEARTBEAT_BUSY_SECONDS = 30            # scanner.json refresh while a job step runs (and at every phase change)
MAX_HELD_IPS = 64                       # addresses per host and per side in published/held_back.json
HELD_COUNT_KEYS = ("held_back", "domains_scanned", "domains_held_back", "domains_pending")   # status counts kept past ingest
LAB_KEYS = {"targets", "cidr"}
OPTION_KEYS = {"retention": {"retention_days"}, "version-watch": {"watches"}}
STRICT_SLA_FILE = "strict_sla_hosts.txt"


class Invalid(Exception):
    """A job failed validation. The message is a fixed text naming the field, never the value."""


class DuplicateKey(ValueError):
    pass


def _no_duplicates(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise DuplicateKey()
        d[k] = v
    return d


MAX_JOB_DEPTH = 32   # arrays and objects inside one another; a valid job needs far fewer


def _too_deep(text, limit=MAX_JOB_DEPTH):
    """True when arrays and objects in text are nested more than limit deep. Counted on the text before parsing, so the
    answer never depends on how much stack the parser happens to have."""
    depth = 0
    in_string = escaped = False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch in "[{":
            depth += 1
            if depth > limit:
                return True
        elif ch in "]}":
            depth -= 1
    return False


def parse_job_bytes(raw):
    """bytes -> the JSON document, or Invalid with a fixed reason. Nesting deeper than MAX_JOB_DEPTH is refused before
    parsing; every failure of the parser is caught here, including RecursionError and MemoryError."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise Invalid("file: not valid UTF-8 JSON (not UTF-8)")
    if _too_deep(text):
        raise Invalid("file: not valid UTF-8 JSON (nested too deeply)")
    try:
        return json.loads(text, object_pairs_hook=_no_duplicates)
    except DuplicateKey:
        raise Invalid("file: not valid UTF-8 JSON (a key appears twice in one object)")
    except RecursionError:
        raise Invalid("file: not valid UTF-8 JSON (nested too deeply)")
    except MemoryError:
        raise Invalid("file: not valid UTF-8 JSON (too large to parse)")
    except (ValueError, TypeError, OverflowError):
        raise Invalid("file: not valid UTF-8 JSON")


def read_job_file(path):
    """Open a job file without following a symbolic link and without blocking (a FIFO opens at once and is then
    refused), confirm with fstat that it is a regular file no larger than MAX_JOB_BYTES before reading, and read at
    most MAX_JOB_BYTES + 1 bytes. Returns bytes or raises Invalid with a fixed reason."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError as e:
        if e.errno == getattr(__import__("errno"), "ELOOP", -1):
            raise Invalid("file: a symbolic link (job files are never followed through links)")
        raise Invalid("file: cannot be opened")
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise Invalid("file: not a regular file")
        if st.st_size > MAX_JOB_BYTES:
            raise Invalid(f"file: larger than {MAX_JOB_BYTES} bytes")
        chunks, n = [], 0
        while n <= MAX_JOB_BYTES:
            try:
                b = os.read(fd, min(65536, MAX_JOB_BYTES + 1 - n))
            except BlockingIOError:
                raise Invalid("file: not a regular file")
            if not b:
                break
            chunks.append(b)
            n += len(b)
        if n > MAX_JOB_BYTES:
            raise Invalid(f"file: larger than {MAX_JOB_BYTES} bytes")
        return b"".join(chunks)
    finally:
        os.close(fd)


def now():
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def iso(t=None):
    return (t or now()).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(s):
    return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))


# ---------------------------------------------------------------- validation
def _key_label(k):
    return f"'{k}'" if isinstance(k, str) and KEY_RE.fullmatch(k) else "(unprintable name)"


def _only(d, allowed, where, extra_msg=None):
    if not isinstance(d, dict):
        raise Invalid(f"{where}: must be an object")
    for k in d:
        if k not in allowed:
            raise Invalid(extra_msg(k) if extra_msg and extra_msg(k) else f"{where}: unknown field {_key_label(k)}")


def _list(v, where, limit):
    if not isinstance(v, list):
        raise Invalid(f"{where}: must be a list")
    if len(v) > limit:
        raise Invalid(f"{where}: more than {limit} entries")
    return v


def _str(v, where, maxlen=253):
    if not isinstance(v, str):
        raise Invalid(f"{where}: must be a string")
    if not v or len(v) > maxlen:
        raise Invalid(f"{where}: empty or longer than {maxlen} characters")
    return v


def _name(v, where):
    """A hostname in the exact form scope.py uses (lower case, no trailing dot); anything else is refused."""
    s = _str(v, where)
    n = S.norm_name(s)
    if not n or n != s:
        raise Invalid(f"{where}: not a valid host name (lower case, labels a-z 0-9 - _, no trailing dot)")
    return n


def _cidr(v, where):
    s = _str(v, where, 64)
    if not re.fullmatch(r"[0-9a-fA-F:.]+(/\d{1,3})?", s):
        raise Invalid(f"{where}: not an address or CIDR")
    try:
        return str(ipaddress.ip_network(s, strict=False))
    except ValueError:
        raise Invalid(f"{where}: not an address or CIDR")


def _exclusion(v, where):
    s = _str(v, where)
    if re.fullmatch(r"[0-9a-fA-F:.]+(/\d{1,3})?", s) and (":" in s or re.fullmatch(r"[0-9./]+", s)):
        return _cidr(s, where)
    body = s[2:] if s.startswith("*.") else (s[1:] if s.startswith(".") else s)
    _name(body, where)
    return s


def _iso(v, where):
    s = _str(v, where, 40)
    if not ISO_RE.fullmatch(s):
        raise Invalid(f"{where}: not an ISO 8601 UTC time")
    try:
        parse_iso(s)
    except ValueError:
        raise Invalid(f"{where}: not an ISO 8601 UTC time")
    return s


def _person(v, where):
    s = _str(v, where, 100)
    if not PERSON_RE.fullmatch(s) or not s.strip():
        raise Invalid(f"{where}: a name of 1 to 100 printable characters without quotes, <, >, $ or backslash")
    return s.strip()


def _ownership_extra(k):
    if k in ("state", "verified_at", "last_checked_at", "verified", "last_result", "key_id", "token_reset"):
        return (f"scope.ownership: field {_key_label(k)} not allowed: verification state is kept by the scanner "
                "and a job can never set it")
    if k == "token":
        return ("scope.ownership: field 'token' not allowed: the scanner derives every DNS proof token itself "
                "(see scope_status.json after a scope-sync job)")
    return None


def validate_job(doc, file_id, lab_env=None):
    """Return the normalized job, or raise Invalid. lab_env: None (not started in lab mode) or the lab network the
    firewall allows (ipaddress network)."""
    _only(doc, TOP_KEYS, "job", lambda k: f"job: unknown field {_key_label(k)}")
    if doc.get("schema") != SCHEMA:
        raise Invalid(f"schema: must be {SCHEMA}")
    jid = doc.get("id")
    if not isinstance(jid, str) or not ID_RE.fullmatch(jid):
        raise Invalid("id: 2 to 64 characters, a-z 0-9 and '-', starting and ending with a letter or digit")
    if jid != file_id:
        raise Invalid("id: does not match the file name")
    jtype = doc.get("type")
    if jtype not in JOB_TYPES:
        raise Invalid("type: must be one of " + ", ".join(JOB_TYPES))
    out = {"schema": SCHEMA, "id": jid, "type": jtype}
    if "created_at" not in doc:
        raise Invalid("created_at: required (the time the brain wrote the job)")      # no undated job
    out["created_at"] = _iso(doc["created_at"], "created_at")
    sc = doc.get("scope")
    if sc is None:
        raise Invalid("scope: required (every job carries a full copy of the scope)")
    _only(sc, SCOPE_KEYS, "scope", lambda k: f"scope: unknown field {_key_label(k)}")
    o = {}
    o["domains"] = sorted({_name(x, f"scope.domains[{i}]") for i, x in enumerate(_list(sc.get("domains", []), "scope.domains", LIMITS["domains"]))})
    o["exclude"] = [_exclusion(x, f"scope.exclude[{i}]") for i, x in enumerate(_list(sc.get("exclude", []), "scope.exclude", LIMITS["exclude"]))]
    o["owned_ranges"] = [_cidr(x, f"scope.owned_ranges[{i}]") for i, x in enumerate(_list(sc.get("owned_ranges", []), "scope.owned_ranges", LIMITS["owned_ranges"]))]
    o["approved_hosts"] = sorted({_name(x, f"scope.approved_hosts[{i}]") for i, x in enumerate(_list(sc.get("approved_hosts", []), "scope.approved_hosts", LIMITS["approved_hosts"]))})
    o["strict_sla_hosts"] = sorted({_name(x, f"scope.strict_sla_hosts[{i}]") for i, x in enumerate(_list(sc.get("strict_sla_hosts", []), "scope.strict_sla_hosts", LIMITS["strict_sla_hosts"]))})
    own = []
    seen = set()
    for i, e in enumerate(_list(sc.get("ownership", []), "scope.ownership", LIMITS["ownership"])):
        w = f"scope.ownership[{i}]"
        _only(e, OWNERSHIP_KEYS, w, _ownership_extra)
        missing = OWNERSHIP_KEYS - set(e)
        if missing:
            raise Invalid(f"{w}: missing field(s) " + ", ".join(sorted(missing)))
        apex = _name(e["apex"], f"{w}.apex")
        if apex not in o["domains"]:
            raise Invalid(f"{w}.apex: not one of scope.domains")
        if apex in seen:
            raise Invalid(f"{w}.apex: listed twice")
        seen.add(apex)
        if e["statement"] != S.OWNERSHIP_STATEMENT:
            raise Invalid(f"{w}.statement: must be exactly the ownership statement")
        own.append({"apex": apex, "statement": S.OWNERSHIP_STATEMENT, "attested_by": _person(e["attested_by"], f"{w}.attested_by"),
                    "attested_at": _iso(e["attested_at"], f"{w}.attested_at")})
    o["ownership"] = own
    appr = sc.get("approval")
    if appr is not None:
        _only(appr, APPROVAL_KEYS, "scope.approval")
        if set(appr) != APPROVAL_KEYS:
            raise Invalid("scope.approval: needs approved_at, inventory_run and approved_by")
        if not isinstance(appr["inventory_run"], str) or not ID_RE.fullmatch(appr["inventory_run"]):
            raise Invalid("scope.approval.inventory_run: not a valid run id")
        appr = {"approved_at": _iso(appr["approved_at"], "scope.approval.approved_at"), "inventory_run": appr["inventory_run"],
                "approved_by": _person(appr["approved_by"], "scope.approval.approved_by")}
    o["approval"] = appr
    for key, allowed, default in (("check_profile", CHECK_PROFILES, "safe"), ("rate_profile", RATE_PROFILES, "low"),
                                  ("evidence", EVIDENCE_LEVELS, "minimal")):
        v = sc.get(key, default)
        if v not in allowed:
            raise Invalid(f"scope.{key}: must be one of " + ", ".join(allowed))
        o[key] = v
    out["scope"] = o
    if "lab" in doc:
        if lab_env is None:
            raise Invalid("lab: lab fields are refused: the scanner was not started in lab mode (SCAN_LAB=1)")
        if jtype not in LAB_TYPES:
            raise Invalid("lab: only inventory and full jobs, and version-watch jobs, can be lab runs")
        lab = doc["lab"]
        _only(lab, LAB_KEYS, "lab")
        if set(lab) != LAB_KEYS:
            raise Invalid("lab: needs targets and cidr")
        targets = sorted({_name(x, f"lab.targets[{i}]") for i, x in enumerate(_list(lab["targets"], "lab.targets", LIMITS["lab_targets"]))})
        if not targets:
            raise Invalid("lab.targets: at least one target")
        if _cidr(lab["cidr"], "lab.cidr") != str(lab_env):
            raise Invalid("lab.cidr: must equal the lab range the scanner was started with (SCAN_LAB_CIDR)")
        out["lab"] = {"targets": targets, "cidr": str(lab_env)}
    elif jtype in SCAN_TYPES + ("version-watch", "scope-sync") and not o["domains"]:
        raise Invalid("scope.domains: at least one domain is needed for this job type")
    opts = doc.get("options", {})
    _only(opts, OPTION_KEYS.get(jtype, set()), "options")
    if jtype == "retention":
        days = opts.get("retention_days", 30)
        if isinstance(days, bool) or not isinstance(days, int) or not 1 <= days <= 3650:
            raise Invalid("options.retention_days: a whole number from 1 to 3650")
        out["options"] = {"retention_days": days}
    if jtype == "version-watch":
        # what to watch comes only as these fixed fields; how a version is read is fixed in code per product
        try:
            out["options"] = {"watches": VW.validate_watches(opts.get("watches"), name_check=_name)}
        except VW.WatchError as e:
            raise Invalid(str(e))
    return out


# ---------------------------------------------------------------- atomic files
def write_atomic(path, data, mode=0o644):
    d = os.path.dirname(path)
    os.makedirs(d, exist_ok=True)
    tmp = os.path.join(d, f".{os.path.basename(path)}.tmp-{os.getpid()}")
    with open(tmp, "wb") as fh:
        fh.write(data if isinstance(data, bytes) else data.encode())
        fh.flush()
        os.fsync(fh.fileno())
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def parse_created(v):
    """A validated created_at (ISO_RE) as an aware datetime."""
    return dt.datetime.fromisoformat(v.replace("Z", "+00:00"))


def job_max_age_from(env):
    try:
        return min(max(int(env.get("SCAN_JOB_MAX_AGE_HOURS", "") or JOB_MAX_AGE_HOURS), 1), 8760)
    except ValueError:
        return JOB_MAX_AGE_HOURS


def write_json(path, doc):
    write_atomic(path, json.dumps(doc, indent=1, sort_keys=True) + "\n")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------- the runner
TOOL_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
SECRET_NOTICE = ("The install secret was replaced (the earlier one was lost), so every domain's DNS proof token changed: "
                 "each affected domain is pending until its new TXT record is published and checked.")


class PublishError(Exception):
    """The published folder cannot be written. main() turns this into one line and exit 75."""


class Runner:
    def __init__(self, root, jobs, published, lab_env=None, keep_snapshots=10, app=HERE, log=None, tool_path=TOOL_PATH,
                 trace=None, job_max_age_hours=JOB_MAX_AGE_HOURS, seed_scope=None):
        self.root, self.jobs, self.pub = root, jobs, published
        self.seed_scope = seed_scope            # the folder for the seeder's verified-domain list, or None
        self.max_age = dt.timedelta(hours=job_max_age_hours)
        self.lab_env = lab_env
        self.keep = keep_snapshots
        self.app = app
        self.tool_path = tool_path
        self.log = log or (lambda s: print(f"runner: {s}", flush=True))
        # tracebacks go to the container log (stderr) only, never into a published file
        self.trace = trace or (lambda text: print(text, file=sys.stderr, end="", flush=True))
        self.child = None
        self.current = None
        self.profiles = None
        self._hb_static, self._hb_at = None, 0.0     # heartbeat content that changes only between jobs; last beat time
        try:
            for sub in ("status", "snapshots", "reports", "version-watch"):
                os.makedirs(os.path.join(self.pub, sub), exist_ok=True)
            probe = os.path.join(self.pub, "status", f".write-probe-{os.getpid()}")
            with open(probe, "w") as fh:
                fh.write("ok\n")
            os.unlink(probe)
        except OSError as e:
            raise PublishError(f"cannot write to the published folder {self.pub} ({e.strerror or type(e).__name__})")
        os.makedirs(os.path.join(self.root, "runs"), exist_ok=True)
        os.makedirs(os.path.join(self.root, "data"), exist_ok=True)
        # the install secret: created on first start, owner-only, in the scanner's own state folder (never published)
        self.state_dir = os.path.join(self.root, "state")
        self.secret, created = S.load_secret(self.state_dir, create=True)
        self.kid = S.key_id(self.secret)
        if created:
            n = self.reconcile_scope()
            self.log("created a new install secret (first start, or the earlier one was lost)"
                     + (f"; {n} domain(s) checked under the earlier secret are pending with a new token" if n else ""))

    def reconcile_scope(self):
        """Entries of the current scope checked under another install secret return to pending (token_reset)."""
        cur = self.scope_dir()
        if not os.path.isdir(cur):
            return 0
        try:
            ents = S.load_ownership(cur)
        except S.ScopeError:
            return 0
        n = sum(1 for e in ents.values() if S.reconcile_key(e, self.kid))
        if ents:
            S.save_ownership(cur, ents)
        return n

    # ---- status
    def status_path(self, key):
        return os.path.join(self.pub, "status", f"{key}.json")

    def read_status(self, key):
        try:
            with open(self.status_path(key)) as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return None

    def set_status(self, key, **kw):
        st = self.read_status(key) or {"schema": STATUS_SCHEMA, "job_id": key, "queued_at": iso()}
        phase_changed = "phase" in kw and kw["phase"] != st.get("phase")
        st.update(kw)
        st["updated_at"] = iso()
        assert st.get("state") in STATES
        if st["state"] in FINAL and ID_RE.fullmatch(key):
            write_json(self.finished_path(key), st)       # first: a job recorded as finished never runs again
        write_json(self.status_path(key), st)
        if phase_changed and st.get("state") == "running":
            self.beat(force=True)
        return st

    def recover(self):
        """A status left 'running' by an earlier process becomes 'interrupted'."""
        n = 0
        for f in sorted(os.listdir(os.path.join(self.pub, "status"))):
            if not f.endswith(".json") or f.startswith("."):
                continue
            key = f[:-5]
            st = self.read_status(key)
            if st and st.get("state") == "running":
                self.set_status(key, state="interrupted", ended_at=iso(), reason="the scanner stopped during this job")
                n += 1
        vw = os.path.join(self.pub, "version-watch")
        dirs = [os.path.join(self.pub, d) for d in ("status", "snapshots", "version-watch")]
        dirs += [os.path.join(vw, d) for d in os.listdir(vw) if os.path.isdir(os.path.join(vw, d)) and not os.path.islink(os.path.join(vw, d))]
        for p in dirs:   # temporary files of an interrupted write
            for f in os.listdir(p):
                if f.startswith(".") and ".tmp-" in f:
                    os.unlink(os.path.join(p, f))
        if n:
            self.log(f"{n} job(s) left running by an earlier process marked interrupted")
        return n

    # ---- finished jobs (private record, never in published/)
    def finished_path(self, key):
        return os.path.join(self.state_dir, "finished", f"{key}.json")

    def finished(self, key):
        """The recorded final status of a job id this scanner finished, or None. Not following links."""
        if not ID_RE.fullmatch(key):
            return None
        try:
            fd = os.open(self.finished_path(key), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except OSError:
            return None
        try:
            with os.fdopen(fd) as fh:
                doc = json.load(fh)
        except (OSError, ValueError):
            doc = None
        if isinstance(doc, dict) and doc.get("state") in FINAL:
            return doc
        return {"schema": STATUS_SCHEMA, "job_id": key, "state": "failed", "reason": "the scanner's record of this job is unreadable"}

    def republish(self, key, rec):
        cur = self.read_status(key)
        if not (cur and cur.get("state") in FINAL):
            write_json(self.status_path(key), rec)
            self.log(f"job {key} finished earlier on this scanner: its final status was published again; it does not run again")

    # ---- discovery
    def pending(self):
        """Job files not yet final, oldest first: [(key, path, file_id or None)]."""
        out = []
        try:
            names = os.listdir(self.jobs)
        except OSError:
            return out
        for f in names:
            if not f.endswith(".json") or f.startswith("."):
                continue
            path = os.path.join(self.jobs, f)
            try:
                st = os.lstat(path)
            except OSError:
                continue
            stem = f[:-5]
            key = stem if ID_RE.fullmatch(stem) else "invalid-" + hashlib.sha256(f.encode("utf-8", "surrogateescape")).hexdigest()[:16]
            if ID_RE.fullmatch(stem) and os.path.lexists(os.path.join(self.jobs, stem + ABANDONED_SUFFIX)):
                continue    # the brain abandoned this job id (its status was lost): never run it, whatever the file says
            rec = self.finished(key)
            if rec is not None:
                self.republish(key, rec)
                continue    # finished on this scanner: never again, whatever published/ says
            cur = self.read_status(key)
            if cur and cur.get("state") in FINAL:
                continue
            out.append((st.st_mtime, f, key, path, stem if ID_RE.fullmatch(stem) else None, st))
        out.sort(key=lambda x: (x[0], x[1]))
        return [(k, p, fid, st) for _, _, k, p, fid, st in out]

    def load(self, key, path, file_id, st):
        """Read and validate one job file. Returns the job or None (rejected)."""
        try:
            if file_id is None:
                raise Invalid("file name: must be <job id>.json with a valid job id")
            if not stat.S_ISREG(st.st_mode):
                raise Invalid("file: a symbolic link (job files are never followed through links)" if stat.S_ISLNK(st.st_mode)
                              else "file: not a regular file")
            if st.st_size > MAX_JOB_BYTES:       # the size is checked again on the opened file (read_job_file)
                raise Invalid(f"file: larger than {MAX_JOB_BYTES} bytes")
            doc = parse_job_bytes(read_job_file(path))
            try:
                job = validate_job(doc, file_id, self.lab_env)
                age = dt.datetime.now(dt.timezone.utc) - parse_created(job["created_at"])     # required (validate_job)
                if age > self.max_age:
                    raise Invalid(TOO_OLD)
                if -age > MAX_FUTURE:
                    raise Invalid(TOO_NEW)
                return job
            except Invalid:
                raise
            except (RecursionError, MemoryError, Exception):   # a validator bug is a rejection, never a crash
                self.log(f"job {key}: validation error")
                self.trace(traceback.format_exc())
                raise Invalid("job: could not be validated")
        except Invalid as e:
            self.set_status(key, state="rejected", reason=str(e), ended_at=iso(), phase=None)
            self.log(f"job {key} rejected: {e}")
            return None

    # ---- scope
    def scope_dir(self):
        return os.path.join(self.root, "scope")

    def write_scope(self, job):
        """Write the job's scope into a new folder and switch the 'scope' link to it in one rename."""
        sc = job["scope"]
        cur = self.scope_dir()
        old = {}
        if os.path.isdir(cur):
            try:
                old = S.load_ownership(cur)
            except S.ScopeError:
                old = {}
        # approval first: for a full or recheck job it must be bound to an inventory that covers this scope; that is
        # decided before anything is written, so a refused approval leaves the scope as it was
        approval = None
        if sc["approval"] and job["type"] in ACTIVE_TYPES:
            a = sc["approval"]
            try:
                inv = A.inventory_record(self.root, a["inventory_run"])
            except S.ScopeError:
                # retention may have removed the run folder since it was approved: the approval in force keeps a
                # copy of that inventory, which is used (and re-bound below) when it names the same run
                inv = self.kept_inventory(a["inventory_run"])
                if inv is None:
                    raise Invalid("scope.approval.inventory_run: no finished inventory run with that id on this scanner")
            lab_targets = (job.get("lab") or {}).get("targets")
            try:
                A.bind_inventory(inv, sc["domains"], lab_targets)
            except S.ScopeError:
                if lab_targets:
                    raise Invalid("scope.approval.inventory_run: that inventory does not cover every lab target of this job; "
                                  "approve an inventory of these lab targets")
                raise Invalid("scope.approval.inventory_run: that inventory covers none of this scope's domains; "
                              "approve an inventory of this scope")
            approval = A.approval_doc(a["inventory_run"], a["approved_by"], a["approved_at"], inv)
        entries = {}
        for e in sc["ownership"]:
            prev = old.get(e["apex"])
            ent = dict(e, key_id=self.kid)
            if prev:
                p2 = dict(prev)
                if S.reconcile_key(p2, self.kid):
                    ent["token_reset"] = p2["token_reset"]
                else:   # same install secret, so the same token: the state found by the scanner stays
                    for k in ("state", "verified_at", "last_checked_at", "last_result", "token_reset"):
                        if p2.get(k):
                            ent[k] = p2[k]
            ent.setdefault("state", "pending")
            entries[e["apex"]] = ent
        base = os.path.join(self.root, "scope.d")
        os.makedirs(base, exist_ok=True)
        gen = f"{job['id']}-{int(time.time() * 1000)}"
        tmp = os.path.join(base, f".tmp-{gen}")
        shutil.rmtree(tmp, ignore_errors=True)
        os.makedirs(tmp)
        lines = lambda xs: "".join(x + "\n" for x in xs)  # noqa: E731
        files = {"domains.txt": lines(sc["domains"]), "exclude.txt": lines(sc["exclude"]),
                 "owned_ranges.txt": lines(sc["owned_ranges"]), "approved_hosts.txt": lines(sc["approved_hosts"]),
                 STRICT_SLA_FILE: lines(sc["strict_sla_hosts"]),
                 "profile.json": json.dumps({"check_profile": sc["check_profile"], "rate_profile": sc["rate_profile"]}) + "\n"}
        for name, text in files.items():
            with open(os.path.join(tmp, name), "w") as fh:
                fh.write(text)
        S.save_ownership(tmp, entries)
        if approval:
            with open(os.path.join(tmp, "approval.json"), "w") as fh:
                json.dump(approval, fh, indent=1)
            write_atomic(os.path.join(self.state_dir, "approved_inventory.json"), json.dumps(approval, indent=1) + "\n", mode=0o600)
        final = os.path.join(base, gen)
        os.rename(tmp, final)
        if os.path.isdir(cur) and not os.path.islink(cur):   # a plain folder from before the runner: keep it aside
            os.rename(cur, os.path.join(base, f"legacy-{gen}"))
        link_tmp = os.path.join(self.root, f".scope-link-{gen}")
        os.symlink(os.path.join("scope.d", gen), link_tmp)
        os.replace(link_tmp, cur)
        for d in os.listdir(base):    # older generations are no longer referenced
            if d != gen and not d.startswith("legacy-"):
                shutil.rmtree(os.path.join(base, d), ignore_errors=True)
        self.publish_scope_status()

    def kept_inventory(self, run_id):
        """The inventory copy kept from the last accepted approval ($SCAN_ROOT/state/approved_inventory.json), when it
        names run_id; else None. Kept outside the scope generations, so jobs without an approval do not drop it."""
        try:
            with open(os.path.join(self.state_dir, "approved_inventory.json")) as fh:
                d = json.load(fh)
            if isinstance(d, dict) and d.get("inventory_run") == run_id and isinstance(d.get("inventory"), dict):
                return A.normalize_inventory(d["inventory"])
        except (OSError, ValueError, S.ScopeError):
            pass
        return None

    def publish_scope_status(self):
        """published/scope_status.json: for every domain of the current scope, the exact TXT record to publish (its
        token derived from the install secret), the verification state and the last check. Nothing secret."""
        cur = self.scope_dir()
        try:
            ents = S.load_ownership(cur)
            domains = S.read_list(os.path.join(cur, "domains.txt"))
        except (S.ScopeError, OSError):
            ents, domains = {}, []
        out = {}
        reset = False
        for d in domains:
            e = dict(ents.get(d) or {})
            if e:
                S.reconcile_key(e, self.kid)
            name, value = S.record_for(d, S.derive_token(self.secret, d))
            out[d] = {"state": e.get("state", "pending") if e else "no-statement", "txt_name": name, "txt_value": value,
                      "attested_by": e.get("attested_by"), "attested_at": e.get("attested_at"),
                      "verified_at": e.get("verified_at"), "last_checked_at": e.get("last_checked_at"),
                      "last_result": e.get("last_result"), "token_reset": e.get("token_reset")}
            reset = reset or bool(e.get("token_reset"))
        write_json(os.path.join(self.pub, "scope_status.json"),
                   {"schema": "momus-scope-status-v1", "updated_at": iso(), "install_key_id": self.kid,
                    "notice": SECRET_NOTICE if reset else None, "domains": out})
        self.publish_seed_scope(sorted(d for d, e in out.items() if e["state"] == "verified"))

    def publish_seed_scope(self, verified):
        """$SCAN_SEED_SCOPE_DIR/verified_domains.json for the optional seeder: the schema, the time and
        the verified domain names. No token, no other domain's state, no scan data. Skipped when the folder does not
        exist; a write error is one fixed log line (the seeder is optional, so the job goes on)."""
        if not self.seed_scope or not os.path.isdir(self.seed_scope):
            return
        try:
            write_json(os.path.join(self.seed_scope, SEED_SCOPE_FILE),
                       {"schema": SEED_SCOPE_SCHEMA, "updated_at": iso(), "domains": verified})
        except OSError:
            self.log(f"could not write {SEED_SCOPE_FILE} for the seeder (is the seed_scope volume writable by this user?)")

    # ---- child processes
    def env(self, job, extra=None):
        """The clean environment every pipeline step gets: no proxy variables, nothing inherited."""
        e = {"PATH": self.tool_path, "HOME": os.environ.get("HOME", "/home/scanner"),
             "LANG": "C.UTF-8", "TMPDIR": "/tmp", "SCAN_ROOT": self.root, "SCAN_EVIDENCE": job["scope"]["evidence"],
             # the seeder's volume, read-only here (recon phase 1 reads seed_hosts.txt from it as untrusted input)
             "SCAN_SEED_DIR": os.environ.get("SCAN_SEED_DIR", "/srv/seed")}
        if "lab" in job:
            e["SCAN_LAB"] = "1"
        tdir = self.templates_dir()
        if tdir:
            e["SCAN_NUCLEI_TEMPLATES"] = tdir
        e.update(extra or {})
        return e

    def run_step(self, key, job, phase, argv, logname, extra_env=None, cwd=None):
        self.set_status(key, phase=phase)
        logp = os.path.join(self.root, "runs", job["id"], f"runner-{logname}.log")
        os.makedirs(os.path.dirname(logp), exist_ok=True)
        with open(logp, "ab") as lf:
            self.child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=lf, stderr=subprocess.STDOUT,
                                          env=self.env(job, extra_env), cwd=cwd or self.root, start_new_session=True)
            while True:
                try:
                    rc = self.child.wait(timeout=10)
                    break
                except subprocess.TimeoutExpired:
                    self.progress(key, job, phase)
                    self.beat()
        self.child = None
        return rc

    def progress(self, key, job, phase):
        """While recon runs, name the recon phase from its own phases.jsonl (fixed names, no target text)."""
        if phase != "recon":
            return
        try:
            with open(os.path.join(self.root, "runs", job["id"], "recon.log"), errors="ignore") as fh:
                started = re.findall(r"=== phase (\d+) ([a-z]+) start", fh.read())
            if started:
                n, name = started[-1]
                self.set_status(key, phase=f"recon:{int(n)}-{name}")
        except OSError:
            pass

    def py(self, script, *args):
        return ["python3", "-I", "-B", os.path.join(PIPE, script), *args]

    # ---- publishing
    def publish_snapshot(self, run_id, job_id):
        src = os.path.join(self.root, "data", "scan.sqlite")
        snapdir = os.path.join(self.pub, "snapshots")
        tmp = os.path.join(snapdir, f".{run_id}.sqlite.tmp-{os.getpid()}")
        if os.path.exists(tmp):
            os.unlink(tmp)
        s = sqlite3.connect(f"file:{src}?mode=ro", uri=True)
        d = sqlite3.connect(tmp)
        try:
            s.backup(d)
        finally:
            d.close()
            s.close()
        chk = sqlite3.connect(f"file:{tmp}?mode=ro", uri=True)
        try:
            ok = chk.execute("PRAGMA integrity_check").fetchone()[0]
        finally:
            chk.close()
        if ok != "ok":
            os.unlink(tmp)
            raise RuntimeError("snapshot integrity check failed")
        os.chmod(tmp, 0o644)
        final = os.path.join(snapdir, f"{run_id}.sqlite")
        os.replace(tmp, final)
        digest = sha256_file(final)
        write_json(os.path.join(snapdir, "latest.json"), {"schema": "momus-snapshot-v1", "run_id": run_id, "job_id": job_id,
                                                          "file": f"{run_id}.sqlite", "sha256": digest, "created_at": iso()})
        self.prune_snapshots()
        return final, digest

    def prune_snapshots(self):
        snapdir = os.path.join(self.pub, "snapshots")
        try:
            with open(os.path.join(snapdir, "latest.json")) as fh:
                keep_name = json.load(fh).get("file")
        except (OSError, ValueError):
            keep_name = None
        snaps = sorted((f for f in os.listdir(snapdir) if f.endswith(".sqlite") and not f.startswith(".")),
                       key=lambda f: (os.stat(os.path.join(snapdir, f)).st_mtime, f), reverse=True)
        # the count includes the snapshot latest.json names, which is kept whatever its age
        keep = {keep_name} if keep_name in snaps else set()
        for f in snaps:
            if len(keep) >= self.keep:
                break
            keep.add(f)
        removed = []
        for f in snaps:
            if f not in keep:
                os.unlink(os.path.join(snapdir, f))
                removed.append(f)
        return removed

    def publish_report(self, run_id):
        src = os.path.join(self.root, "reports")
        dst_base = os.path.join(self.pub, "reports")
        tmp = os.path.join(dst_base, f".{run_id}.tmp-{os.getpid()}")
        shutil.rmtree(tmp, ignore_errors=True)
        os.makedirs(tmp)
        n = 0
        for f in sorted(os.listdir(src)):
            if f == f"{run_id}.html" or (f.startswith(f"{run_id}-") and f.endswith(".csv")):
                p = os.path.join(src, f)
                if os.path.isfile(p) and not os.path.islink(p):
                    shutil.copyfile(p, os.path.join(tmp, f))
                    os.chmod(os.path.join(tmp, f), 0o644)
                    n += 1
        os.chmod(tmp, 0o755)
        final = os.path.join(dst_base, run_id)
        if os.path.isdir(final):
            old = os.path.join(dst_base, f".{run_id}.old-{os.getpid()}")
            os.rename(final, old)
            os.rename(tmp, final)
            shutil.rmtree(old, ignore_errors=True)
        else:
            os.rename(tmp, final)
        return n

    def counts(self, snapshot, run_id):
        out = {}
        try:
            db = sqlite3.connect(f"file:{snapshot}?mode=ro", uri=True)
        except sqlite3.Error:
            return out
        q = {"assets": ("SELECT COUNT(*) FROM asset_observations WHERE run_id=?", (run_id,)),
             "findings_observed": ("SELECT COUNT(*) FROM finding_observations WHERE run_id=?", (run_id,)),
             "findings_open": ("SELECT COUNT(*) FROM findings WHERE status='open'", ()),
             "findings_fixed": ("SELECT COUNT(*) FROM findings WHERE status='fixed'", ())}
        for k, (sql, args) in q.items():
            try:
                out[k] = int(db.execute(sql, args).fetchone()[0])
            except (sqlite3.Error, TypeError, ValueError):
                pass
        try:
            for band, n in db.execute("SELECT band, COUNT(*) FROM finding_observations WHERE run_id=? GROUP BY band", (run_id,)):
                if band in ("Critical", "High", "Medium", "Low"):
                    out[f"band_{band.lower()}"] = int(n)
        except sqlite3.Error:
            pass
        db.close()
        return out

    def templates_dir(self):
        """An updated template folder (from an update-templates job) when it holds a real template set."""
        p = os.path.join(self.root, "templates", "current")
        if os.path.isdir(p) and os.path.exists(os.path.join(p, ".momus-ok")):
            return p
        return None

    def heartbeat(self, state="idle", refresh=True):
        """published/scanner.json. refresh=False reuses the tool versions and template details of the last full beat
        (they change only between jobs): the cheap beat written during a job."""
        if refresh or self._hb_static is None:
            static = {"image_build_date": None, "tools": tool_versions(), "templates": template_info(self.templates_dir())}
            try:
                with open(os.path.join(self.app, "BUILD_DATE")) as fh:
                    static["image_build_date"] = fh.read().strip()[:40]
            except OSError:
                pass
            self._hb_static = static
        doc = {"schema": "momus-scanner-v1", "updated_at": iso(), "state": state, "current_job": self.current,
               "lab_mode": self.lab_env is not None, "lab_cidr": str(self.lab_env) if self.lab_env else None,
               "profiles": self.profiles, **self._hb_static, "keep_snapshots": self.keep}
        write_json(os.path.join(self.pub, "scanner.json"), doc)
        self._hb_at = time.monotonic()

    def beat(self, force=False):
        """During a job: refresh scanner.json at every phase change and at least every HEARTBEAT_BUSY_SECONDS while a
        step runs, so a busy scanner's heartbeat stays fresh and a stopped one goes stale."""
        if self.current is not None and self._hb_static is not None and (force or time.monotonic() - self._hb_at >= HEARTBEAT_BUSY_SECONDS):
            self.heartbeat("busy", refresh=False)

    # ---- jobs
    def run_job(self, key, job):
        jid, jtype = job["id"], job["type"]
        if os.path.lexists(os.path.join(self.jobs, jid + ABANDONED_SUFFIX)):
            self.log(f"job {jid} was abandoned by the brain after it was listed; not run")   # checked again here
            return
        if self.finished(jid) is not None:
            return
        self.current = jid
        self.profiles = {k: job["scope"][k] for k in ("check_profile", "rate_profile", "evidence")}
        self.set_status(key, state="running", type=jtype, run_id=jid if jtype in SCAN_TYPES else None, started_at=iso(),
                        phase="scope", exit_codes={}, counts={}, lab=("lab" in job))
        self.heartbeat("busy")
        self.log(f"job {jid} ({jtype}) started")
        codes = {}
        try:
            try:
                self.write_scope(job)
            except Invalid as e:   # only the approval check can fail here, before anything ran
                self.set_status(key, state="rejected", reason=str(e), ended_at=iso(), phase=None)
                self.log(f"job {jid} rejected: {e}")
                return
            state = getattr(self, "job_" + jtype.replace("-", "_"))(key, job, codes)
        except PublishError:
            raise
        except OSError as e:
            if _under(getattr(e, "filename", None), self.pub):
                raise PublishError(f"cannot write to the published folder {self.pub} ({e.strerror or type(e).__name__})")
            self.log(f"job {jid} failed: {type(e).__name__}")
            self.trace(traceback.format_exc())
            state = "failed"
            codes.setdefault("runner", type(e).__name__)
        except Exception as e:  # a runner bug fails the job; the message is the exception type only
            self.log(f"job {jid} failed: {type(e).__name__}")
            self.trace(traceback.format_exc())    # the container log only, never a published file
            state = "failed"
            codes.setdefault("runner", type(e).__name__)
        finally:
            self.current = None
        self.publish_scope_status()
        self.set_status(key, state=state, ended_at=iso(), exit_codes=codes, phase=None if state == "done" else self.read_status(key).get("phase"))
        self.heartbeat("idle")
        self.log(f"job {jid} {state}")

    def job_scan(self, key, job, codes, mode):
        jid = job["id"]
        root = self.root
        argv = ["bash", os.path.join(self.app, "recon.sh"), "--run-id", jid]
        if mode == "inventory":
            argv.append("--inventory-only")
        if mode == "recheck":
            rc = self.run_step(key, job, "recheck-targets", self.py("recheck_targets.py", "--root", root), "recheck-targets")
            codes["recheck_targets"] = rc
            if rc != 0:
                return "failed"
            with open(os.path.join(self.scope_dir(), "recheck_base.txt")) as fh:
                base = fh.read().strip()
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", base):
                return "failed"
            argv += ["--recheck", base]
        if "lab" in job:
            tf = os.path.join(root, "runs", jid, "lab_targets.txt")
            os.makedirs(os.path.dirname(tf), exist_ok=True)
            with open(tf, "w") as fh:
                fh.write("".join(t + "\n" for t in job["lab"]["targets"]))
            argv += ["--targets-file", tf, "--lab-cidr", job["lab"]["cidr"]]
        rc = self.run_step(key, job, "recon", argv, "recon")
        codes["recon"] = rc
        if mode != "inventory":
            self.publish_held_back(key, jid)
        if rc != 0:
            return "failed"
        ingest = self.py("ingest.py", "--root", root, "--run-id", jid)
        if "lab" in job:
            ingest.append("--no-feeds")   # lab runs never need the internet: the EPSS and KEV feeds are skipped
        rc = self.run_step(key, job, "ingest", ingest, "ingest")
        codes["ingest"] = rc
        if rc != 0:
            return "failed"
        self.set_status(key, phase="snapshot")
        snap, digest = self.publish_snapshot(jid, jid)
        cnt = self.counts(snap, jid)
        prev = (self.read_status(key) or {}).get("counts") or {}
        for k in HELD_COUNT_KEYS:
            if k in prev:
                cnt[k] = prev[k]
        self.set_status(key, snapshot=os.path.basename(snap), snapshot_sha256=digest, counts=cnt)
        rc = self.run_step(key, job, "report", self.py("report.py", "--root", root, "--run-id", jid), "report")
        codes["report"] = rc
        if rc != 0:
            return "failed"
        self.set_status(key, phase="publish-report")
        self.set_status(key, report_files=self.publish_report(jid))
        return "done"

    def publish_held_back(self, key, run_id):
        """published/held_back.json from <run>/held_back.json: host names, fixed reason codes and addresses (each
        validated), and the scope domains held back, so the UI can show them as awaiting approval. Written after every
        full or recheck run (empty lists when none). The status gets the counts only (numbers, never names)."""
        hosts, domains, inv_run, doms = [], [], None, None
        try:
            with open(os.path.join(self.root, "runs", run_id, S.HELD_BACK_FILE)) as fh:
                d = json.load(fh)
            inv_run = d.get("inventory_run") if isinstance(d.get("inventory_run"), str) and ID_RE.fullmatch(d["inventory_run"]) else None
            addrs = d.get("addresses") if isinstance(d.get("addresses"), dict) else {}

            def ips(v):
                v = v if isinstance(v, list) else []
                return sorted({str(o) for o in (S.parse_ip(x) for x in v[:MAX_HELD_IPS] if isinstance(x, str)) if o is not None})
            for h, r in sorted((d.get("hosts") or {}).items()):
                n = S.norm_name(h)
                if n and r in S.HELD_REASONS:
                    a = addrs.get(h) if isinstance(addrs.get(h), dict) else {}
                    hosts.append({"host": n, "reason": r, "approved_ips": ips(a.get("approved")), "current_ips": ips(a.get("now"))})
            dd = d.get("domains") if isinstance(d.get("domains"), dict) else None
            if dd is not None:
                doms = {k: sorted({n for n in (S.norm_name(x) for x in (dd.get(k) or []) if isinstance(x, str)) if n})
                        for k in ("scanned", "held_back", "pending")}
                domains = [{"domain": n, "reason": S.HELD_DOMAIN} for n in doms["held_back"]]
        except (OSError, ValueError, AttributeError, TypeError):
            pass
        if doms is None:   # no approval (inventory-only) or stopped before phase 6: nothing scanned, nothing held
            doms = self.unapproved_domain_summary(run_id)
        write_json(os.path.join(self.pub, "held_back.json"),
                   {"schema": "momus-held-back-v1", "updated_at": iso(), "run_id": run_id, "inventory_run": inv_run,
                    "hosts": hosts, "domains": domains})
        st = self.read_status(key) or {}
        counts = dict(st.get("counts") or {})
        counts["held_back"] = len(hosts)
        counts.update({f"domains_{k}": len(v) for k, v in doms.items()})
        self.set_status(key, counts=counts)

    def unapproved_domain_summary(self, run_id):
        """Domain summary for a run that reached no active phase: none scanned or held back; pending = the scope's
        domains that did not pass this run's DNS proof (<run>/apexes.txt)."""
        try:
            scope_domains = {n for n in (S.norm_name(x) for x in S.read_list(os.path.join(self.scope_dir(), "domains.txt"))) if n}
            verified = {n for n in (S.norm_name(x) for x in S.read_list(os.path.join(self.root, "runs", run_id, "apexes.txt"))) if n}
        except (OSError, S.ScopeError):
            scope_domains, verified = set(), set()
        return {"scanned": [], "held_back": [], "pending": sorted(scope_domains - verified)}

    def job_scope_sync(self, key, job, codes):
        """Write the scope (done by run_job), check the DNS proof of every domain, publish scope_status.json. No scan
        tool runs: scope.py sync asks only dig, for the nameservers and the TXT record."""
        rc = self.run_step(key, job, "dns-proof", self.py("scope.py", "sync", "--scope", self.scope_dir(), "--state", self.state_dir),
                           "scope-sync")
        codes["scope_sync"] = rc
        try:
            ents = S.load_ownership(self.scope_dir())
        except S.ScopeError:
            ents = {}
        self.set_status(key, counts={"domains": len(job["scope"]["domains"]),
                                     "verified": sum(1 for e in ents.values() if e.get("state") == "verified")})
        return "done" if rc == 0 else "failed"

    def job_inventory(self, key, job, codes):
        return self.job_scan(key, job, codes, "inventory")

    def job_full(self, key, job, codes):
        return self.job_scan(key, job, codes, "full")

    def job_recheck(self, key, job, codes):
        return self.job_scan(key, job, codes, "recheck")

    def job_version_watch(self, key, job, codes):
        """1. This job's DNS proof: recon's own phase-0 command (scope.py recheck-dns), which writes
        <run>/dns_verification.json; version_watch.py probes only hosts under the domains it lists as usable. A lab job
        skips it, as recon does, and probes only its lab targets (<run>/lab.json). 2. version_watch.py with the job's
        validated watches. 3. The state folder is copied to published/version-watch/ (and pruned to match)."""
        rdir = os.path.join(self.root, "runs", job["id"])
        os.makedirs(rdir, exist_ok=True)
        for stale in ("dns_verification.json", "lab.json"):
            if os.path.lexists(os.path.join(rdir, stale)):
                os.unlink(os.path.join(rdir, stale))
        wfile = os.path.join(rdir, "watches.json")
        with open(wfile, "w") as fh:
            json.dump(job["options"]["watches"], fh, indent=1)
        if "lab" in job:
            with open(os.path.join(rdir, "lab.json"), "w") as fh:
                json.dump({"cidr": job["lab"]["cidr"], "hosts": job["lab"]["targets"]}, fh, indent=1)
        else:
            rc = self.run_step(key, job, "dns-proof", self.py("scope.py", "recheck-dns", "--scope", self.scope_dir(), "--run-dir", rdir,
                                                              "--state", self.state_dir), "dns-proof")
            codes["dns_proof"] = rc
            if rc != 0:      # fail closed: without this job's proof nothing is probed
                self.set_status(key, counts={"watches": len(job["options"]["watches"]), "files_published": 0})
                return "failed"
        rc = self.run_step(key, job, "version-watch", self.py("version_watch.py", "--root", self.root, "--run-dir", rdir,
                                                              "--watches", wfile, "--job-id", job["id"]), "version-watch")
        codes["version_watch"] = rc
        n = self.publish_version_watch()
        self.set_status(key, counts={"watches": len(job["options"]["watches"]), "files_published": n})
        return "done" if rc == 0 else "failed"

    def publish_version_watch(self):
        """published/version-watch/<watch id>/ = $SCAN_ROOT/version-watch/<watch id>/, file for file: every result file
        there is copied, and every published file or folder that no longer exists there is removed, so the published
        folder never grows beyond the state folder (which version_watch.py keeps to 90 dated files per watch, and drops a
        watch no longer in the job after 90 days). Only watch-id folders and result file names are copied; links and
        anything else are skipped. Returns the number of files published."""
        src, dst = os.path.join(self.root, VW.STATE_DIR), os.path.join(self.pub, "version-watch")
        os.makedirs(dst, exist_ok=True)
        want = {}
        if os.path.isdir(src) and not os.path.islink(src):
            for wid in sorted(os.listdir(src)):
                d = os.path.join(src, wid)
                if not VW.WATCH_ID_RE.fullmatch(wid) or os.path.islink(d) or not os.path.isdir(d):
                    continue
                want[wid] = sorted(f for f in os.listdir(d) if VW.FILE_RE.fullmatch(f)
                                   and os.path.isfile(os.path.join(d, f)) and not os.path.islink(os.path.join(d, f)))
        n = 0
        for wid, files in want.items():
            os.makedirs(os.path.join(dst, wid), exist_ok=True)
            for f in files:
                with open(os.path.join(src, wid, f), "rb") as fh:
                    data = fh.read()
                target = os.path.join(dst, wid, f)
                try:
                    with open(target, "rb") as fh:
                        same = fh.read() == data
                except OSError:
                    same = False
                if not same:
                    write_atomic(target, data)
                n += 1
        for name in os.listdir(dst):        # prune: whatever the state folder no longer holds
            p = os.path.join(dst, name)
            if name in want and os.path.isdir(p) and not os.path.islink(p):
                for f in os.listdir(p):
                    if f not in want[name]:
                        fp = os.path.join(p, f)
                        shutil.rmtree(fp) if os.path.isdir(fp) and not os.path.islink(fp) else os.unlink(fp)
            elif os.path.isdir(p) and not os.path.islink(p):
                shutil.rmtree(p)
            else:
                os.unlink(p)
        return n

    def job_retention(self, key, job, codes):
        days = str(job["options"]["retention_days"])
        rc = self.run_step(key, job, "retention", self.py("retention.py", "--root", self.root, "--days", days, "--apply"), "retention")
        codes["retention"] = rc
        self.prune_snapshots()
        # version-watch folders are retired by version_watch.py when a version-watch job runs; a watch removed last (no
        # version-watch job can run with no watch) is retired here instead, on the same rule: a folder whose newest
        # dated file is older than the retention period (90 days) goes, from the state folder and the published copy
        for gone in VW.retire_watches(VW.Path(self.root) / VW.STATE_DIR, set(), now().date(), VW.KEEP):
            self.log(f"retention: removed the version-watch folder of {gone} (newest result older than {VW.KEEP} days)")
        self.publish_version_watch()
        return "done" if rc == 0 else "failed"

    def job_update_templates(self, key, job, codes):
        """Download templates into $SCAN_ROOT/templates (the image's own copy is read-only) and switch to them
        only when the download holds a real template set. Needs outbound network."""
        base = os.path.join(self.root, "templates")
        new = os.path.join(base, f"new-{job['id']}")
        home = os.path.join(base, "home")
        shutil.rmtree(new, ignore_errors=True)
        os.makedirs(new)
        if not os.path.isdir(os.path.join(home, ".config", "nuclei")):
            src = os.path.join(os.environ.get("HOME", "/home/scanner"), ".config", "nuclei")
            shutil.copytree(src, os.path.join(home, ".config", "nuclei"), dirs_exist_ok=True) if os.path.isdir(src) else os.makedirs(os.path.join(home, ".config", "nuclei"), exist_ok=True)
        rc = self.run_step(key, job, "update-templates", ["nuclei", "-update-templates", "-update-template-dir", new, "-nc"],
                           "update-templates", extra_env={"HOME": home})
        codes["update_templates"] = rc
        count = sum(1 for _, _, fs in os.walk(new) for f in fs if f.endswith(".yaml"))
        self.set_status(key, counts={"templates": count})
        if rc != 0 or count <= 1000:
            shutil.rmtree(new, ignore_errors=True)
            return "failed"
        with open(os.path.join(new, ".momus-ok"), "w") as fh:
            fh.write(iso() + "\n")
        cur = os.path.join(base, "current")
        if os.path.isdir(cur):
            shutil.rmtree(cur + ".old", ignore_errors=True)
            os.rename(cur, cur + ".old")
        os.rename(new, cur)
        shutil.rmtree(cur + ".old", ignore_errors=True)
        return "done"

    # ---- loop
    def guarded(self, key, what, fn, final_state, reason):
        """Run fn(); an unexpected exception gives this job a final status with a fixed reason (the traceback goes to
        the container log only) and returns None, so one hostile or broken job never stops the loop. A published
        folder that cannot be written is not a job problem: it stops the runner (PublishError)."""
        try:
            return fn()
        except PublishError:
            raise
        except (Exception, RecursionError, MemoryError) as e:
            if isinstance(e, OSError) and _under(getattr(e, "filename", None), self.pub):
                raise PublishError(f"cannot write to the published folder {self.pub} ({e.strerror or type(e).__name__})")
            self.log(f"job {key}: unexpected {type(e).__name__} while {what}; marked {final_state}")
            self.trace(traceback.format_exc())
            self.child = None
            self.current = None
            try:
                self.set_status(key, state=final_state, reason=reason, ended_at=iso(), phase=None)
            except OSError as e2:
                raise PublishError(f"cannot write to the published folder {self.pub} ({e2.strerror or type(e2).__name__})")
            return None

    def step(self):
        """Mark new jobs queued (or rejected), then run the oldest valid one. Returns True if a job ran."""
        valid = []
        for key, path, fid, st in self.pending():
            def one():
                cur = self.read_status(key)
                job = self.load(key, path, fid, st)
                if job is not None and not cur:
                    self.set_status(key, state="queued", type=job["type"])
                return job
            job = self.guarded(key, "reading the job file", one, "rejected", "file: could not be read or validated")
            if job is not None:
                valid.append((key, job))
        if not valid:
            return False
        key, job = valid[0]
        self.guarded(key, "running the job", lambda: self.run_job(key, job), "failed",
                     "the runner hit an unexpected error during this job")
        return True

    def stop(self, signum, frame):
        if self.child and self.child.poll() is None:
            try:
                os.killpg(self.child.pid, signal.SIGTERM)
            except OSError:
                pass
        if self.current:
            self.set_status(self.current, state="interrupted", ended_at=iso(), reason="the scanner was stopped during this job")
        self.log(f"stopping on signal {signum}")
        sys.exit(128 + signum)


def _under(path, folder):
    if not path or not folder:
        return False
    p, f = os.path.abspath(str(path)), os.path.abspath(folder)
    return p == f or p.startswith(f + os.sep)


def tool_versions():
    pk = ["nmap", "subfinder", "assetfinder", "dnsx", "dnsrecon", "httpx-toolkit", "whatweb", "wafw00f", "sslscan",
          "nuclei", "dnsutils", "curl", "python3", "iptables"]
    try:
        p = subprocess.run(["dpkg-query", "-W", "-f", "${Package}\t${Version}\n", *pk], capture_output=True, text=True, timeout=20)
        return {a: b for a, b in (l.split("\t", 1) for l in p.stdout.splitlines() if "\t" in l)}
    except (OSError, subprocess.TimeoutExpired):
        return {}


def template_info(override=None):
    tdir = override
    version = None
    try:
        with open(os.path.join(os.environ.get("HOME", "/home/scanner"), ".config", "nuclei", ".templates-config.json")) as fh:
            cfg = json.load(fh)
        tdir = tdir or cfg.get("nuclei-templates-directory")
        version = cfg.get("nuclei-templates-version") if not override else None
    except (OSError, ValueError):
        pass
    if not tdir or not os.path.isdir(tdir):
        return {"dir": tdir, "count": 0, "version": version, "date": None}
    n, newest = 0, 0.0
    for d, _, fs in os.walk(tdir):
        for f in fs:
            if f.endswith(".yaml"):
                n += 1
    try:
        newest = os.stat(tdir).st_mtime
    except OSError:
        pass
    return {"dir": tdir, "count": n, "version": version,
            "date": dt.datetime.fromtimestamp(newest, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if newest else None,
            "source": "update-templates job" if override else "baked into the image"}


def lab_env_from(environ):
    if environ.get("SCAN_LAB") != "1":
        return None
    net, why = S.private_lab_net(environ.get("SCAN_LAB_CIDR", ""))
    if net is None:
        raise SystemExit(f"runner: lab mode refused: {why}")
    return net


def main():
    env = os.environ
    root = env.get("SCAN_ROOT", "/var/lib/scan")
    pub = env.get("SCAN_PUBLISHED", "/srv/published")
    try:
        r = Runner(root, env.get("SCAN_JOBS", "/srv/jobs"), pub,
                   lab_env=lab_env_from(env), keep_snapshots=max(1, int(env.get("SCAN_KEEP_SNAPSHOTS", "10") or 10)),
                   job_max_age_hours=job_max_age_from(env), seed_scope=env.get("SCAN_SEED_SCOPE_DIR", "/srv/seed-scope"))
        signal.signal(signal.SIGTERM, r.stop)
        signal.signal(signal.SIGINT, r.stop)
        poll = max(1, int(env.get("SCAN_POLL_SECONDS", "5") or 5))
        r.log(f"started as uid {os.getuid()}; jobs {r.jobs} (read-only), published {r.pub}"
              + (f"; lab mode {r.lab_env}" if r.lab_env else ""))
        r.recover()
        r.publish_scope_status()
        last_beat = 0.0
        while True:
            if time.time() - last_beat > 30:
                r.heartbeat("idle")
                last_beat = time.time()
            if not r.step():
                time.sleep(poll)
            else:
                last_beat = 0.0
    except PublishError as e:
        print(f"runner: FATAL: {e}; is the published volume mounted and writable by uid {os.getuid()}?", file=sys.stderr, flush=True)
        sys.exit(75)
    except OSError as e:
        if _under(getattr(e, "filename", None), pub):
            print(f"runner: FATAL: cannot write to the published folder {pub} ({e.strerror or type(e).__name__}); "
                  f"is the published volume mounted and writable by uid {os.getuid()}?", file=sys.stderr, flush=True)
            sys.exit(75)
        raise


if __name__ == "__main__":
    main()
