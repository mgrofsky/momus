"""Job files (format: momus-job-v1, validated by scanner/runner.py validate_job) and the queue.

- Every job carries the full current scope from the app database (the scanner replaces its scope with each job's).
- No DNS token is ever sent: the scanner derives tokens and publishes the TXT record in scope_status.json.
- A job is written to a dot-prefixed temporary file in the jobs folder, flushed, then renamed to <job id>.json. The
  row in the jobs table and the audit entry are written in the same transaction as the file.
- One job at a time: nothing is queued while a job file has no final status yet, or the scanner says it is busy.
- A domain change sets a "scope sync pending" flag; the background tick queues a scope-sync job as soon as nothing
  is in flight (and "check now" does the same at once when it can).
- The brain never decides that a domain is verified; it shows scope_status.json."""
import datetime as dt
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import stat

from fastapi import Depends, Form, Request
from pydantic import BaseModel, Field, StrictBool
from starlette.exceptions import HTTPException
from typing import Literal, Optional

from . import audit, db as dbm, published, scheduler, scope as scopem, watches as watchesm
from .web import Ctx, get_ctx

SCHEMA = "momus-job-v1"
TYPES = ("scope-sync", "inventory", "full", "recheck", "version-watch", "update-templates", "retention")
PREFIX = {"scope-sync": "sync", "inventory": "inv", "full": "full", "recheck": "recheck", "version-watch": "vw",
          "update-templates": "tpl", "retention": "ret"}
LAB_TYPES = ("inventory", "full", "version-watch")     # scanner/runner.py LAB_TYPES
NEEDS_DOMAIN = ("scope-sync", "inventory", "full", "recheck", "version-watch")
ID_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,62}[a-z0-9]")      # always used with fullmatch
LABELS = {"inventory": "Queue an inventory run", "full": "Queue a full run", "recheck": "Queue a recheck",
          "version-watch": "Queue a version-watch run", "scope-sync": "Check DNS proof now",
          "retention": "Queue retention clean-up", "update-templates": "Update the scanner's templates"}
SCHEDULE_TYPE = {"daily-recheck": "recheck", "monthly-full": "full", "daily-version-watch": "version-watch"}
ABANDONED_SUFFIX = ".abandoned"   # scanner/runner.py ABANDONED_SUFFIX: <job id>.abandoned means "never run this id"
MAX_JOB_FILES = 1000              # job files looked at in the jobs folder; more than this counts as busy (fail closed)
TOO_MANY_JOB_FILES = "too-many-job-files"
UNRECOGNIZED_JOB = "unrecognized-job"   # a busy heartbeat whose current_job is not a valid job id is reported as this
REAP_LIMIT = 50000                # job files looked at per removal pass (the listing bound of published.newest_names)
TOO_LARGE = ("The job would be larger than the scanner accepts (1 MiB). Shorten the scope (domains, exclusions, approved "
             "hosts or watches).")
JOB_MAX_BYTES = 1 << 20           # scanner/runner.py MAX_JOB_BYTES: the largest job file the scanner reads, so the largest
                                  # the brain writes; also the bound of the jobs.document column (migration 0007)


class QueueError(Exception):
    pass


# ---------------------------------------------------------------- state
def lab_cidr(settings, scanner_info=None):
    """The lab range for lab jobs: the brain's own MOMUS_LAB_CIDR only (the heartbeat is shown, never used)."""
    cidr = settings.lab_cidr or None
    if not cidr:
        return None, "no lab range is known (MOMUS_LAB_CIDR)"
    try:
        return str(ipaddress.ip_network(cidr, strict=False)), None
    except ValueError:
        return None, "the lab range is not a valid CIDR"


def remove_finished_job_files(db, settings):
    """Remove each job file whose job has a final status in published/ (or that the admin marked abandoned). The brain
    is the only writer of the jobs folder, and nothing reads a job file after its final status: the scanner lists job
    files only to find work and skips final ones; the brain reads status files, never job files, for every page and
    approval. So the MAX_JOB_FILES count covers live jobs only. Same care as the abandon path: only names that are
    <valid id>.json, unlink (which removes a link itself and never follows one), under the app database's write lock.
    Returns how many were removed."""
    own = not db.in_transaction
    if own:
        db.execute("BEGIN IMMEDIATE")
    n = 0
    try:
        names = published.newest_names(settings.jobs_dir, lambda f: f.endswith(".json") and bool(ID_RE.fullmatch(f[:-5])),
                                       REAP_LIMIT)
        for f in names:
            jid = f[:-5]
            if not ID_RE.fullmatch(jid):
                continue
            st = published.job_status(settings.published_dir, jid)
            done = st is not None and st["state"] in published.FINAL
            if not done and not os.path.lexists(os.path.join(settings.jobs_dir, jid + ABANDONED_SUFFIX)):
                continue
            _keep_document(db, settings, jid)
            try:
                os.unlink(os.path.join(settings.jobs_dir, f))
                n += 1
            except FileNotFoundError:
                pass
            except OSError:
                pass       # left in place (for example a directory at that name); it is looked at again next time
        if own:
            db.execute("COMMIT")
    except BaseException:
        if own and db.in_transaction:
            db.execute("ROLLBACK")
        raise
    return n


def _keep_document(db, settings, jid):
    """Before a job file is removed: if its row holds no copy of the document yet (a row from before migration 0007),
    store the file's text, but only when the file is a regular file no larger than JOB_MAX_BYTES (opened without
    following a link) whose SHA-256 still equals the row's file_sha256. Otherwise nothing is stored."""
    r = db.execute("SELECT file_sha256 FROM jobs WHERE id=? AND document IS NULL", (jid,)).fetchone()
    if not r:
        return
    try:
        fd = os.open(os.path.join(settings.jobs_dir, jid + ".json"), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | os.O_NONBLOCK)
    except OSError:
        return
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > JOB_MAX_BYTES:
            return
        data = os.read(fd, JOB_MAX_BYTES + 1)
    except OSError:
        return
    finally:
        os.close(fd)
    if len(data) > JOB_MAX_BYTES or not hmac.compare_digest(hashlib.sha256(data).hexdigest(), r[0] or ""):
        return
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return
    db.execute("UPDATE jobs SET document=? WHERE id=? AND document IS NULL", (text, jid))


def in_flight(settings, scanner_info=None):
    """The id of a job that is written but not final, or that the scanner reports running; None when idle."""
    # the jobs folder is shared with the scanner, so it is read with the same bounds as published data
    seen = {}
    names = published.newest_names(settings.jobs_dir, lambda f: f.endswith(".json") and bool(ID_RE.fullmatch(f[:-5])),
                                   MAX_JOB_FILES + 1, report=seen)
    if len(names) > MAX_JOB_FILES or seen.get("truncated"):
        return TOO_MANY_JOB_FILES          # fail closed: a job file could be hidden among the entries not looked at
    for f in names:
        if os.path.lexists(os.path.join(settings.jobs_dir, f[:-5] + ABANDONED_SUFFIX)):
            continue      # abandoned by the admin: the scanner never runs it
        st = published.job_status(settings.published_dir, f[:-5])
        if st is None or st["state"] not in published.FINAL:
            return f[:-5]
    s = scanner_info or {}
    # a busy heartbeat counts only while it is fresh (not older than 180 s, not dated in the future), and not for a
    # job the admin marked abandoned
    cur = s.get("current_job")
    if s.get("state") == "busy" and cur and not published.heartbeat_stale(s):
        if not (isinstance(cur, str) and ID_RE.fullmatch(cur)):
            return UNRECOGNIZED_JOB        # never the scanner's own text: it reaches pages and audit details
        if not os.path.lexists(os.path.join(settings.jobs_dir, cur + ABANDONED_SUFFIX)):
            return cur
    return None


def is_lab(settings, scanner_info=None):
    """Lab mode comes only from the brain's own MOMUS_LAB; the scanner's heartbeat cannot switch it on."""
    return bool(settings.lab)


def lab_disagreement(settings, scanner_info):
    """A warning when the scanner's heartbeat disagrees with the brain's lab setting (the brain's setting is used)."""
    s = scanner_info or {}
    if not s:
        return None
    if bool(s.get("lab_mode")) != bool(settings.lab):
        return ("The scanner's heartbeat says lab mode is " + ("on" if s.get("lab_mode") else "off") + ", but this brain's MOMUS_LAB "
                "setting says " + ("on" if settings.lab else "off") + ". The brain uses its own setting.")
    if settings.lab and s.get("lab_cidr") and settings.lab_cidr and s.get("lab_cidr") != settings.lab_cidr:
        return "The scanner's heartbeat names a different lab range than this brain's MOMUS_LAB_CIDR. The brain uses its own setting."
    return None


# ---------------------------------------------------------------- building
def build_scope(db):
    rows = scopem.domains(db)
    doms = [r for r in rows if r["kind"] == "domain"]
    lists = scopem.lists(db)
    prof = scopem.profile(db)
    appr = scopem.approval(db)
    return {
        "domains": sorted(r["name"] for r in doms),
        "exclude": [r["value"] for r in lists["exclusions"]],
        "owned_ranges": [r["cidr"] for r in lists["owned_ranges"]],
        "approved_hosts": sorted(r["hostname"] for r in lists["approved_hosts"]),
        "strict_sla_hosts": [],
        "ownership": [{"apex": r["name"], "statement": r["statement"], "attested_by": r["attested_by"], "attested_at": r["attested_at"]}
                      for r in sorted(doms, key=lambda r: r["name"])],
        "approval": {"approved_at": appr["approved_at"], "inventory_run": appr["inventory_run"], "approved_by": appr["approved_by"]}
        if appr else None,
        "check_profile": prof["check_profile"], "rate_profile": prof["rate_profile"], "evidence": prof["evidence"],
    }


def new_id(jtype, now=None):
    t = (now or dt.datetime.now(dt.timezone.utc)).strftime("%Y%m%d-%H%M%S")
    return f"{PREFIX[jtype]}-{t}-{secrets.token_hex(3)}"


def build_job(db, settings, scanner_info, jtype, retention_days=30, job_id=None):
    """The job document, or QueueError saying why it cannot be queued (before anything is written)."""
    if jtype not in TYPES:
        raise QueueError("Unknown job type.")
    rows = scopem.domains(db)
    for r in rows:
        if r["statement"] != scopem.OWNERSHIP_STATEMENT or not r["attested_by"] or not r["attested_at"]:
            raise QueueError(f"{r['name']} has no ownership statement. Remove it and add it again with the statement.")
    scope = build_scope(db)
    lab = is_lab(settings, scanner_info)
    targets = sorted(r["name"] for r in rows if r["kind"] == "lab")
    job = {"schema": SCHEMA, "id": job_id or new_id(jtype), "type": jtype,
           "created_at": dbm.iso(), "scope": scope}
    if lab and jtype in LAB_TYPES:
        if not targets:
            raise QueueError("Lab mode: add a lab target on the Scope page first.")
        cidr, why = lab_cidr(settings, scanner_info)
        if not cidr:
            raise QueueError(f"Lab mode: {why}.")
        job["lab"] = {"targets": targets, "cidr": cidr}
    elif jtype in NEEDS_DOMAIN and not scope["domains"]:
        raise QueueError("Add a domain (with the ownership statement) on the Scope page first."
                         + (" In lab mode only inventory, full and version-watch runs of lab targets are possible." if lab else ""))
    if jtype == "recheck" and not scope["approval"]:
        raise QueueError("A recheck needs an approved inventory (Scope page).")
    if jtype == "retention":
        if isinstance(retention_days, bool) or not isinstance(retention_days, int) or not 1 <= retention_days <= 3650:
            raise QueueError("Retention days: a whole number from 1 to 3650.")
        job["options"] = {"retention_days": retention_days}
    if jtype == "version-watch":
        # every stored watch, sorted by id, in canonical form (checked again as a whole with the scanner's rules)
        try:
            ws = watchesm.for_job(db)
        except watchesm.WatchError:
            raise QueueError("A stored watch is not valid any more; edit it on the Version watch page.")
        if not ws:
            raise QueueError(watchesm.NONE_FOR_JOB)
        job["options"] = {"watches": ws}
    return job


def summarize(job):
    sc = job["scope"]
    parts = [f"{len(sc['domains'])} domain(s)", f"check {sc['check_profile']}", f"rate {sc['rate_profile']}",
             f"evidence {sc['evidence']}", "approved inventory " + (sc["approval"]["inventory_run"] if sc["approval"] else "none")]
    if "lab" in job:
        parts.append(f"lab targets {', '.join(job['lab']['targets'])}")
    if "watches" in job.get("options", {}):
        parts.append(f"{len(job['options']['watches'])} watch(es)")
    return "; ".join(parts)


# ---------------------------------------------------------------- writing
def job_bytes(job):
    """The exact bytes of a job file (and of the jobs.document copy)."""
    return (json.dumps(job, indent=1, sort_keys=True) + "\n").encode("utf-8")


def write_job_file(jobs_dir, job):
    """Dot-prefixed temporary file, fsync, rename to <id>.json (never overwrites an existing job file)."""
    jid = job["id"]
    if not ID_RE.fullmatch(jid):
        raise QueueError("Invalid job id.")
    final = os.path.join(jobs_dir, f"{jid}.json")
    if os.path.lexists(final):
        raise QueueError("A job file with that id exists.")
    data = job_bytes(job)
    tmp = os.path.join(jobs_dir, f".{jid}.json.tmp-{os.getpid()}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o644)
        os.rename(tmp, final)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return hashlib.sha256(data).hexdigest()


def queue(db, settings, scanner_info, jtype, actor, trigger, address=None, retention_days=30):
    """Queue one job or raise QueueError. Every outcome writes one audit entry (job-queue or job-refused).
    The in-flight check, the jobs row and the audit entry happen inside one write transaction (so two requests, or a
    request and the scheduler, cannot both pass the check); the file is renamed into place last, just before COMMIT,
    and removed again if anything fails before the commit."""
    written = None
    db.execute("BEGIN IMMEDIATE")
    try:
        remove_finished_job_files(db, settings)
        busy = in_flight(settings, scanner_info)
        if busy:
            raise QueueError(f"A job is in flight ({busy}). The scanner runs one job at a time; queue this after it ends.")
        if not os.path.isdir(settings.jobs_dir) or not os.access(settings.jobs_dir, os.W_OK):
            raise QueueError("The jobs folder is not writable by the brain.")
        job = build_job(db, settings, scanner_info, jtype, retention_days)
        data = job_bytes(job)
        if len(data) > JOB_MAX_BYTES:
            raise QueueError(TOO_LARGE)
        # the row keeps the document itself: the job file is removed once its status is final
        db.execute("INSERT INTO jobs(id, type, created_at, created_by, trigger, file_sha256, summary, document) "
                   "VALUES(?,?,?,?,?,?,?,?)",
                   (job["id"], jtype, job["created_at"], actor, trigger, hashlib.sha256(data).hexdigest(), summarize(job),
                    data.decode("utf-8")))
        audit.write(db, actor, "job-queue", target=job["id"], detail=f"{jtype} ({trigger}): {summarize(job)}", address=address)
        written = write_job_file(settings.jobs_dir, job)
        db.execute("COMMIT")
        return job
    except Exception as e:
        db.execute("ROLLBACK")
        if written is not None:
            try:
                os.unlink(os.path.join(settings.jobs_dir, f"{job['id']}.json"))
            except OSError:
                pass
        if isinstance(e, QueueError):
            audit.write(db, actor, "job-refused", target=jtype, detail=str(e), address=address)
        raise


# ---------------------------------------------------------------- scope changes that need a scope-sync
def request_sync(db):
    db.execute("INSERT INTO settings(key, value, updated_at) VALUES('scope_sync_pending', '1', ?) "
               "ON CONFLICT(key) DO UPDATE SET value='1', updated_at=excluded.updated_at", (dbm.iso(),))


def sync_pending(db):
    r = db.execute("SELECT value FROM settings WHERE key='scope_sync_pending'").fetchone()
    return bool(r and r["value"] == "1")


def try_sync(db, settings, scanner_info, actor, trigger, address=None):
    """Queue the pending scope-sync now if possible. Returns the job, or None (it stays pending)."""
    if not any(r["kind"] == "domain" for r in scopem.domains(db)):
        db.execute("UPDATE settings SET value='0' WHERE key='scope_sync_pending'")
        return None
    if in_flight(settings, scanner_info):
        return None
    try:
        build_job(db, settings, scanner_info, "scope-sync", job_id="preview-job")   # a scope that cannot be sent stays pending, silently
    except QueueError:
        return None
    if not os.path.isdir(settings.jobs_dir) or not os.access(settings.jobs_dir, os.W_OK):
        return None
    try:
        job = queue(db, settings, scanner_info, "scope-sync", actor, trigger, address)
    except QueueError:
        return None
    db.execute("UPDATE settings SET value='0' WHERE key='scope_sync_pending'")
    return job


# ---------------------------------------------------------------- inventory approval
def approvable(c):
    """Finished inventory jobs that match the current mode (lab or not), newest first, from the status files."""
    lab = c.lab
    out = []
    for s in published.all_status(c.settings.published_dir):
        if s["type"] == "inventory" and s["state"] == "done" and s["run_id"] and s["lab"] == lab:
            out.append(s)
    return out


def approve(c, run_id):
    # looked up by id (not through the capped list of newest status files), so an older inventory stays approvable
    st = published.job_status(c.settings.published_dir, run_id) if isinstance(run_id, str) and ID_RE.fullmatch(run_id) else None
    if not st or st["type"] != "inventory" or st["state"] != "done" or st["run_id"] != run_id or st["lab"] != c.lab:
        raise QueueError("Not a finished inventory run of this scope (lab mode must match).")
    c.db.execute("BEGIN IMMEDIATE")
    try:
        t = dbm.iso()
        c.db.execute("UPDATE inventory_approvals SET withdrawn_at=?, withdrawn_by=? WHERE withdrawn_at IS NULL", (t, c.user))
        c.db.execute("INSERT INTO inventory_approvals(inventory_run, approved_by, approved_at) VALUES(?,?,?)", (run_id, c.user, t))
        audit.write(c.db, c.user, "inventory-approve", target=run_id,
                    detail="active phases (port scans, TLS scan, templates) approved for the hosts and addresses this inventory listed",
                    address=c.address)
        c.db.execute("COMMIT")
    except Exception:
        c.db.execute("ROLLBACK")
        raise


def withdraw_approval(c):
    c.db.execute("BEGIN IMMEDIATE")
    n = c.db.execute("UPDATE inventory_approvals SET withdrawn_at=?, withdrawn_by=? WHERE withdrawn_at IS NULL", (dbm.iso(), c.user)).rowcount
    if n:
        audit.write(c.db, c.user, "inventory-withdraw", target="approval", address=c.address)
    c.db.execute("COMMIT")
    if not n:
        raise QueueError("No approval to withdraw.")


# ---------------------------------------------------------------- abandoning a job whose status file was lost
def abandonable(settings, scanner_info, job_id):
    """None when job_id may be marked abandoned, else why not: it must have no final status, and the scanner must
    not report it as the job it is running now (with a fresh heartbeat)."""
    if not isinstance(job_id, str) or not ID_RE.fullmatch(job_id):
        return "Not a job id."
    st = published.job_status(settings.published_dir, job_id)
    if st is not None and st["state"] in published.FINAL:
        return f"Job {job_id} already ended ({st['state']})."
    s = scanner_info or {}
    if s.get("state") == "busy" and s.get("current_job") == job_id and not heartbeat_stale(s):
        return f"The scanner reports that it is running {job_id} now."
    return None


heartbeat_stale = published.heartbeat_stale


def abandon(c, job_id, confirmed):
    """Mark a job abandoned: <id>.abandoned is written first (so the scanner can never pick the job up in between),
    then the row and the audit entry are committed together, and only then is the job file removed. A failure before
    the commit removes the marker again and leaves the job file and the row as they were. A job file that cannot be
    removed after the commit stays, harmless: the marker keeps the scanner from running it, and it is removed later
    with the finished ones (remove_finished_job_files)."""
    if not confirmed:
        raise QueueError("Confirm that the scanner is not running this job.")
    why = abandonable(c.settings, c.scanner, job_id)      # validates the id before any path is built
    if why:
        raise QueueError(why)
    path = os.path.join(c.settings.jobs_dir, job_id + ".json")
    marker = os.path.join(c.settings.jobs_dir, job_id + ABANDONED_SUFFIX)
    tmp = os.path.join(c.settings.jobs_dir, f".{job_id}{ABANDONED_SUFFIX}.tmp-{secrets.token_hex(8)}")
    # the checks, the files and the row all happen under the app database's write lock, so two requests at once
    # cannot both pass the "already abandoned" check
    marker_written = False
    c.db.execute("BEGIN IMMEDIATE")
    try:
        row = c.db.execute("SELECT id, abandoned_at FROM jobs WHERE id=?", (job_id,)).fetchone()
        if row is None and not os.path.lexists(path):
            raise QueueError(f"No job {job_id} was written by this brain.")
        if row is not None and row["abandoned_at"]:
            raise QueueError(f"Job {job_id} is already marked abandoned.")
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), 0o644)
            with os.fdopen(fd, "w") as fh:
                json.dump({"job_id": job_id, "abandoned_at": dbm.iso(), "abandoned_by": c.user}, fh)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, marker)        # rename replaces a link at the destination; it never follows one
        except OSError:
            raise QueueError("The abandoned marker could not be written in the jobs folder; nothing was changed.")
        marker_written = True
        if row is not None:
            c.db.execute("UPDATE jobs SET abandoned_at=?, abandoned_by=? WHERE id=?", (dbm.iso(), c.user, job_id))
            _keep_document(c.db, c.settings, job_id)        # a row from before migration 0007
        audit.write(c.db, c.user, "job-abandon", target=job_id,
                    detail="marked abandoned after confirmation (no final status); job file removed", address=c.address)
        c.db.execute("COMMIT")
    except BaseException:
        if c.db.in_transaction:
            c.db.execute("ROLLBACK")
        for p in ((tmp, marker) if marker_written else (tmp,)):
            try:
                os.unlink(p)               # nothing committed: the marker goes again, the job file was never touched
            except OSError:
                pass
        raise
    try:
        os.unlink(path)                    # after the commit; unlink removes a link itself and never follows one
    except FileNotFoundError:
        pass
    except OSError:
        print(f"brain: job {job_id} is marked abandoned, but its job file could not be removed now; the marker keeps "
              "the scanner from running it", flush=True)


# ---------------------------------------------------------------- what the pages show
def queue_info(c):
    remove_finished_job_files(c.db, c.settings)
    busy = in_flight(c.settings, c.scanner)
    lab = c.lab
    types = list(LAB_TYPES) if lab else ["inventory", "full", "recheck", "version-watch", "retention", "update-templates"]
    forms = []
    for t in types:
        note, ok = None, True
        try:
            build_job(c.db, c.settings, c.scanner, t, job_id="preview-job")
        except QueueError as e:
            ok, note = False, str(e)
        if ok and t == "full" and not scopem.approval(c.db):
            note = "No approved inventory: a full run does discovery and web checks only (no port scan, TLS scan or templates)."
        if ok and t == "update-templates":
            note = "Downloads the scanner's template set from the internet."
        forms.append({"type": t, "label": LABELS[t], "enabled": ok and not busy, "note": note})
    unverified = []
    ss = published.scope_status(c.settings.published_dir)
    for r in scopem.domains(c.db):
        if r["kind"] == "domain":
            st = (ss or {}).get("domains", {}).get(r["name"]) if ss else None
            if not st or st.get("state") != "verified":
                unverified.append(r["name"])
    why = None
    if unverified and not lab:
        why = ("Not verified by the scanner yet: " + ", ".join(unverified[:10]) + ". The scanner sends nothing to an unverified "
               "domain; the other domains are still scanned. A verified domain that the approved inventory did not cover gets "
               "inventory checks only until a newer inventory that covers it is approved.")
    return {"ready": not busy, "busy": busy, "why": why, "forms": forms, "lab": lab, "sync_pending": sync_pending(c.db)}


# ---------------------------------------------------------------- the background tick (scheduler and pending syncs)
def tick(settings, now):
    db = dbm.connect(settings.db_path)
    try:
        from . import auth
        auth.write_flood_summaries(db)          # a flood's last minute is recorded even if no sign-in follows it
        remove_finished_job_files(db, settings)
        info = published.scanner(settings.published_dir)
        if sync_pending(db):
            try_sync(db, settings, info, "scheduler", "scope-change")
        try:          # the analyst's automatic brief for a new snapshot (MOMUS_ANALYST_AUTO_BRIEF; off by default)
            from .analyst import runner as analyst_runner
            analyst_runner.auto_brief(settings)
        except Exception as e:
            print(f"analyst: automatic brief not started: {type(e).__name__}", flush=True)
        if not settings.scheduler_enabled:
            return
        for row in [dict(r) for r in db.execute("SELECT * FROM schedules ORDER BY kind")]:
            d = scheduler.decide(row, now, in_flight(settings, info))
            if not d:
                continue
            if d[0] == "run":
                try:
                    job = queue(db, settings, info, SCHEDULE_TYPE[row["kind"]], "scheduler", "schedule")
                    outcome = f"queued {job['id']}"
                except QueueError as e:
                    outcome = f"not queued: {e}"
            else:
                outcome = f"skipped: {d[2]}"
                audit.write(db, "scheduler", "job-refused", target=row["kind"], detail=f"slot {d[1]} {outcome}")
            db.execute("UPDATE schedules SET last_slot=?, last_outcome=? WHERE kind=?", (d[1], outcome[:300], row["kind"]))
    finally:
        db.close()


def start_scheduler(app):
    settings = app.state.settings
    t = scheduler.Scheduler(lambda now: tick(settings, now), interval=30)
    t.start()
    app.state.scheduler = t
    return t


# ---------------------------------------------------------------- routes
class JobIn(BaseModel):
    type: Literal["inventory", "full", "recheck", "version-watch", "retention", "update-templates", "scope-sync"]
    retention_days: int = Field(30, ge=1, le=3650)


class DomainIn(BaseModel):
    name: str = Field(min_length=1, max_length=253)
    statement: StrictBool
    kind: Literal["domain", "lab"] = "domain"


class AbandonIn(BaseModel):
    job_id: str = Field(min_length=2, max_length=64)
    confirm: StrictBool = False


class ApproveIn(BaseModel):
    inventory_run: str = Field(min_length=2, max_length=64)


class NameIn(BaseModel):
    name: str = Field(min_length=1, max_length=253)


def _add_domain(c, name, confirmed, kind):
    if kind == "lab" and not c.lab:
        raise scopem.ScopeError("Lab targets can only be added in lab mode.")
    n = scopem.add_domain(c.db, c.user, name, confirmed, c.address, kind=kind)
    if kind == "domain":
        request_sync(c.db)
        try_sync(c.db, c.settings, c.scanner, c.user, "scope-change", c.address)
    return n


def _remove_domain(c, name):
    row = c.db.execute("SELECT kind FROM domains WHERE name=?", (name,)).fetchone()
    scopem.remove_domain(c.db, c.user, name, c.address)
    if row and row["kind"] == "domain":
        request_sync(c.db)
        try_sync(c.db, c.settings, c.scanner, c.user, "scope-change", c.address)


def register_pages(app, render, back, flash_url):
    @app.post("/jobs", include_in_schema=False)
    def queue_job(type: str = Form(""), retention_days: int = Form(30), c: Ctx = Depends(get_ctx)):
        if type not in TYPES:
            raise HTTPException(400, "Unknown job type.")
        try:
            job = queue(c.db, c.settings, c.scanner, type, c.user, "user", c.address, retention_days)
        except QueueError as e:
            return back(flash_url("/runs", err=str(e)))
        return back(flash_url("/runs", msg=f"Queued {type} job {job['id']}.") + f"&job={job['id']}")

    @app.post("/runs/abandon", include_in_schema=False)
    def abandon_page(job_id: str = Form(""), confirm: str = Form(""), c: Ctx = Depends(get_ctx)):
        try:
            abandon(c, job_id, confirm == "yes")
        except QueueError as e:
            return back(flash_url("/runs", err=str(e)))
        return back(flash_url("/runs", msg=f"Job {job_id} marked abandoned: the scanner will not run it, and new jobs can be queued."))

    @app.post("/scope/domains", include_in_schema=False)
    def add_domain(name: str = Form(""), statement: str = Form(""), kind: str = Form("domain"), c: Ctx = Depends(get_ctx)):
        if kind not in ("domain", "lab"):
            raise HTTPException(400, "Unknown kind.")
        try:
            n = _add_domain(c, name, statement == "yes", kind)
        except scopem.ScopeError as e:
            return back(flash_url("/scope", err=str(e)))
        msg = (f"Added lab target {n}." if kind == "lab" else
               f"Added {n}. A scope-sync job asks the scanner for its TXT record; it appears below once the scanner has published it.")
        return back(flash_url("/scope", msg=msg))

    @app.post("/scope/domains/remove", include_in_schema=False)
    def remove_domain(name: str = Form(""), c: Ctx = Depends(get_ctx)):
        try:
            _remove_domain(c, name)
        except scopem.ScopeError as e:
            return back(flash_url("/scope", err=str(e)))
        return back(flash_url("/scope", msg=f"Removed {name}."))

    @app.post("/scope/check-now", include_in_schema=False)
    def check_now(c: Ctx = Depends(get_ctx)):
        try:
            job = queue(c.db, c.settings, c.scanner, "scope-sync", c.user, "user", c.address)
        except QueueError as e:
            return back(flash_url("/scope", err=str(e)))
        c.db.execute("UPDATE settings SET value='0' WHERE key='scope_sync_pending'")
        return back(flash_url("/scope", msg=f"Queued scope-sync job {job['id']}: the scanner checks every domain's TXT record."))

    @app.post("/scope/approve", include_in_schema=False)
    def approve_page(inventory_run: str = Form(""), c: Ctx = Depends(get_ctx)):
        try:
            approve(c, inventory_run)
        except QueueError as e:
            return back(flash_url("/scope", err=str(e)))
        return back(flash_url("/scope", msg=f"Approved inventory {inventory_run}. The next full run carries this approval."))

    @app.post("/scope/approve/withdraw", include_in_schema=False)
    def withdraw_page(c: Ctx = Depends(get_ctx)):
        try:
            withdraw_approval(c)
        except QueueError as e:
            return back(flash_url("/scope", err=str(e)))
        return back(flash_url("/scope", msg="Approval withdrawn: full runs do discovery and web checks only until an inventory is approved."))


def register_api(app):
    V1 = "/api/v1"

    @app.post(f"{V1}/jobs", summary="Queue a job (one at a time; every job carries the full current scope)")
    def api_queue(body: JobIn, c: Ctx = Depends(get_ctx)):
        try:
            job = queue(c.db, c.settings, c.scanner, body.type, c.user, "user", c.address, body.retention_days)
        except QueueError as e:
            raise HTTPException(409, str(e))
        return {"ok": True, "job_id": job["id"], "type": job["type"]}

    @app.post(f"{V1}/jobs/abandon", summary="Mark a job with no final status abandoned (confirm: true); the scanner never runs it")
    def api_abandon(body: AbandonIn, c: Ctx = Depends(get_ctx)):
        try:
            abandon(c, body.job_id, body.confirm)
        except QueueError as e:
            raise HTTPException(409, str(e))
        return {"ok": True, "job_id": body.job_id}

    @app.post(f"{V1}/scope/domains", summary="Add a domain (or, in lab mode, a lab target) with the ownership statement")
    def api_add_domain(body: DomainIn, c: Ctx = Depends(get_ctx)):
        try:
            n = _add_domain(c, body.name, body.statement, body.kind)
        except scopem.ScopeError as e:
            raise HTTPException(400, str(e))
        return {"ok": True, "name": n, "scope_sync_pending": sync_pending(c.db)}

    @app.post(f"{V1}/scope/domains/remove", summary="Remove a domain or lab target")
    def api_remove_domain(body: NameIn, c: Ctx = Depends(get_ctx)):
        try:
            _remove_domain(c, body.name)
        except scopem.ScopeError as e:
            raise HTTPException(400, str(e))
        return {"ok": True}

    @app.post(f"{V1}/scope/check-now", summary="Queue a scope-sync job: the scanner checks every domain's DNS proof")
    def api_check_now(c: Ctx = Depends(get_ctx)):
        try:
            job = queue(c.db, c.settings, c.scanner, "scope-sync", c.user, "user", c.address)
        except QueueError as e:
            raise HTTPException(409, str(e))
        c.db.execute("UPDATE settings SET value='0' WHERE key='scope_sync_pending'")
        return {"ok": True, "job_id": job["id"]}

    @app.post(f"{V1}/scope/approve", summary="Approve active phases after reviewing a finished inventory run")
    def api_approve(body: ApproveIn, c: Ctx = Depends(get_ctx)):
        try:
            approve(c, body.inventory_run)
        except QueueError as e:
            raise HTTPException(400, str(e))
        return {"ok": True}

    @app.post(f"{V1}/scope/approve/withdraw", summary="Withdraw the inventory approval")
    def api_withdraw(c: Ctx = Depends(get_ctx)):
        try:
            withdraw_approval(c)
        except QueueError as e:
            raise HTTPException(400, str(e))
        return {"ok": True}
