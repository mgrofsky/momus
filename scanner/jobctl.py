#!/usr/bin/env python3
"""jobctl.py - DEVELOPER TOOL for tests and debugging: a command-line stand-in for the brain.

It does what the brain does through the two shared folders and nothing else: it writes job files into the
jobs folder and reads status and scope status from the published folder. It never talks to the scanner over a
network and never runs a scan itself. Its own state (the scope it hands to every job) lives in --state.

  jobctl.py attest APEX --by NAME        record the ownership statement for APEX (no token: the scanner derives
                                         every DNS proof token itself); then submit a scope-sync job and read
                                         the TXT record to publish with "jobctl.py status"
  jobctl.py approve JOB_ID --by NAME     approve active phases after reviewing the inventory of a finished
                                         inventory job; later jobs carry the approval record
  jobctl.py submit TYPE [options]        write one job file (TYPE: scope-sync, inventory, full, recheck,
                                         version-watch, update-templates, retention); prints the job id.
                                         version-watch needs --watches-file FILE (a JSON list of watches)
  jobctl.py status [JOB_ID]              print one job's status, or every job's state and the scope status
  jobctl.py wait JOB_ID [--timeout S]    wait until the job has a final state; exit 0 only for "done"

Folders: --jobs (default $SCAN_JOBS or /srv/jobs), --published (default $SCAN_PUBLISHED or /srv/published),
--state (default $JOBCTL_STATE or ./jobctl-state).

Writing a job (the rule for every writer, the brain included): write the JSON to a dot-prefixed temporary name in
the jobs folder itself (".<job id>.json.tmp-<pid>"), flush and fsync it, then rename it to "<job id>.json". The
scanner never reads a dot-file, so it only ever sees complete files.

jobctl has no access to the scanner's install secret, so it never makes a DNS proof token: it uses the scanner's
derivation by reading the record the scanner published (scope_status.json).
"""
import argparse
import datetime as dt
import json
import os
import secrets
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "pipeline"))
import scope as S     # noqa: E402

SCHEMA = "momus-job-v1"
JOB_TYPES = ("scope-sync", "inventory", "full", "recheck", "version-watch", "update-templates", "retention")
FINAL = ("done", "failed", "rejected", "interrupted")


def iso():
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_atomic(path, text):
    d, base = os.path.split(path)
    tmp = os.path.join(d, f".{base}.tmp-{os.getpid()}")   # dot-names are ignored by the runner
    with open(tmp, "w") as fh:
        fh.write(text)
        fh.flush()
        os.fsync(fh.fileno())
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


class State:
    """The brain-side scope: brain.json (domains, ownership statements, approval). No tokens."""

    def __init__(self, path):
        self.path = path
        os.makedirs(path, exist_ok=True)
        self.file = os.path.join(path, "brain.json")
        try:
            with open(self.file) as fh:
                self.doc = json.load(fh)
        except (OSError, ValueError):
            self.doc = {}
        self.doc.setdefault("domains", [])
        self.doc.setdefault("approval", None)
        self.doc.setdefault("ownership", {})

    def save(self):
        write_atomic(self.file, json.dumps(self.doc, indent=1, sort_keys=True) + "\n")

    def ownership(self):
        return [{k: e[k] for k in ("apex", "statement", "attested_by", "attested_at")}
                for _, e in sorted(self.doc["ownership"].items())]


def read_json(path):
    try:
        with open(path) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def cmd_attest(a, st):
    ax = S.norm_name(a.apex)
    if not ax:
        raise S.ScopeError(f"{a.apex!r} is not a valid domain name")
    if not (a.by or "").strip():
        raise S.ScopeError("--by NAME is required: the person making the ownership statement")
    ent = {"apex": ax, "statement": S.OWNERSHIP_STATEMENT, "attested_by": a.by.strip(), "attested_at": iso()}
    st.doc["ownership"][ax] = ent
    st.doc["domains"] = sorted(set(st.doc["domains"]) | {ax})
    st.save()
    print(f"{S.OWNERSHIP_RULE}\nRecorded for {ax}: \"{ent['statement']}\" (by {ent['attested_by']}).")
    print("The scanner makes the DNS proof token. Next: jobctl.py submit scope-sync, wait for it, then jobctl.py status "
          "shows the TXT record to publish; submit scope-sync again to check it.")
    return 0


def cmd_approve(a, st):
    s = read_json(os.path.join(a.published, "status", f"{a.job_id}.json"))
    if not s:
        print(f"error: no status for job {a.job_id} in {a.published}/status", file=sys.stderr)
        return 2
    if s.get("type") != "inventory" or s.get("state") != "done" or not s.get("run_id"):
        print(f"error: job {a.job_id} is not a finished inventory job (type {s.get('type')}, state {s.get('state')})", file=sys.stderr)
        return 2
    if not (a.by or "").strip():
        print("error: --by NAME is required", file=sys.stderr)
        return 2
    st.doc["approval"] = {"approved_at": iso(), "inventory_run": s["run_id"], "approved_by": a.by.strip()}
    st.save()
    print(f"approved active phases after inventory run {s['run_id']} ({a.by.strip()}); the next jobs carry this approval")
    return 0


def build_job(a, st):
    jid = a.id or f"{a.type}-{dt.datetime.now(dt.timezone.utc).strftime('%Y%m%d-%H%M%S')}-{secrets.token_hex(3)}"
    scope = {"domains": sorted(set(st.doc.get("domains", [])) | set(a.domain or [])),
             "exclude": a.exclude or [], "owned_ranges": a.owned_range or [], "approved_hosts": a.approved_host or [],
             "strict_sla_hosts": a.strict_sla_host or [], "ownership": st.ownership(),
             "approval": st.doc.get("approval"), "check_profile": a.check_profile, "rate_profile": a.rate_profile,
             "evidence": a.evidence}
    job = {"schema": SCHEMA, "id": jid, "type": a.type, "created_at": iso(), "scope": scope}
    if a.lab_target or a.lab_cidr:
        job["lab"] = {"targets": a.lab_target or [], "cidr": a.lab_cidr or ""}
    if a.type == "retention":
        job["options"] = {"retention_days": a.retention_days}
    if a.type == "version-watch":
        # the watch definitions, as a JSON list (see docs/version-watch.md); the runner validates them
        watches = []
        if a.watches_file:
            with open(a.watches_file, encoding="utf-8") as fh:
                watches = json.load(fh)
        job["options"] = {"watches": watches}
    return job


def cmd_submit(a, st):
    os.makedirs(a.jobs, exist_ok=True)
    if a.raw:
        # tests only: hand a job file to the scanner exactly as given, unchecked (the scanner must reject bad ones)
        with open(a.raw, "rb") as fh:
            data = fh.read()
        name = a.file_name or os.path.basename(a.raw)
        if "/" in name or name.startswith("."):
            print("error: --file-name must be a plain file name", file=sys.stderr)
            return 2
        write_atomic(os.path.join(a.jobs, name), data.decode("utf-8", "surrogateescape"))
        print(name[:-5] if name.endswith(".json") else name)
        return 0
    if not a.type:
        print("error: TYPE is required (or --raw FILE)", file=sys.stderr)
        return 2
    job = build_job(a, st)
    write_atomic(os.path.join(a.jobs, f"{job['id']}.json"), json.dumps(job, indent=1) + "\n")
    print(job["id"])
    return 0


def cmd_status(a, st):
    if a.job_id:
        s = read_json(os.path.join(a.published, "status", f"{a.job_id}.json"))
        if not s:
            print(f"no status for {a.job_id} yet")
            return 1
        print(json.dumps(s, indent=1, sort_keys=True))
        return 0
    sdir = os.path.join(a.published, "status")
    for f in sorted(os.listdir(sdir)) if os.path.isdir(sdir) else []:
        if f.endswith(".json") and not f.startswith("."):
            s = read_json(os.path.join(sdir, f)) or {}
            print(f"{f[:-5]:<48} {s.get('type') or '-':<16} {s.get('state') or '-':<12} {s.get('phase') or ''}")
    ss = read_json(os.path.join(a.published, "scope_status.json"))
    if ss:
        print("\nscope status:")
        for d, v in sorted(ss.get("domains", {}).items()):
            rec = f"{v['txt_name']}. TXT \"{v['txt_value']}\"" if v.get("txt_name") else "no ownership statement (jobctl attest)"
            print(f"  {d:<40} {v.get('state'):<14} last check {v.get('last_checked_at') or 'never'}  expects {rec}")
    return 0


def cmd_wait(a, st):
    deadline = time.time() + a.timeout
    p = os.path.join(a.published, "status", f"{a.job_id}.json")
    last = None
    while time.time() < deadline:
        s = read_json(p)
        if s:
            cur = (s.get("state"), s.get("phase"))
            if cur != last and not a.quiet:
                print(f"{a.job_id}: {cur[0]}{' (' + cur[1] + ')' if cur[1] else ''}", flush=True)
                last = cur
            if s.get("state") in FINAL:
                print(json.dumps(s, indent=1, sort_keys=True))
                return 0 if s["state"] == "done" else 1
        time.sleep(a.interval)
    print(f"timeout: {a.job_id} has no final state after {a.timeout}s", file=sys.stderr)
    return 3


def main(argv=None):
    env = os.environ
    ap = argparse.ArgumentParser(description="DEVELOPER TOOL (tests and debugging): a stand-in for the brain. Writes job "
                                 "files and reads published status; it never scans and never talks to the scanner.")
    ap.add_argument("--jobs", default=env.get("SCAN_JOBS", "/srv/jobs"))
    ap.add_argument("--published", default=env.get("SCAN_PUBLISHED", "/srv/published"))
    ap.add_argument("--state", default=env.get("JOBCTL_STATE", "jobctl-state"))
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("attest", help="record the ownership statement and a DNS token for a domain")
    p.add_argument("apex"); p.add_argument("--by", required=True)
    p = sub.add_parser("approve", help="approve active phases after a finished inventory job")
    p.add_argument("job_id"); p.add_argument("--by", required=True)
    p = sub.add_parser("submit", help="write a job file")
    p.add_argument("type", nargs="?", choices=JOB_TYPES)
    p.add_argument("--id")
    p.add_argument("--domain", action="append"); p.add_argument("--exclude", action="append")
    p.add_argument("--owned-range", action="append"); p.add_argument("--approved-host", action="append")
    p.add_argument("--strict-sla-host", action="append")
    p.add_argument("--check-profile", default="safe", choices=("safe", "active"))
    p.add_argument("--rate-profile", default="low", choices=("low", "normal", "fast"))
    p.add_argument("--evidence", default="minimal", choices=("minimal", "excerpt"))
    p.add_argument("--lab-target", action="append", help="lab mode only: a target name on the lab network")
    p.add_argument("--lab-cidr", help="lab mode only: the scanner's SCAN_LAB_CIDR")
    p.add_argument("--retention-days", type=int, default=30)
    p.add_argument("--watches-file", help="version-watch: a JSON file holding the list of watch definitions")
    p.add_argument("--raw", help="tests only: copy this file into the jobs folder unchecked")
    p.add_argument("--file-name", help="with --raw: the file name to use in the jobs folder")
    p = sub.add_parser("status", help="print job status and scope status")
    p.add_argument("job_id", nargs="?")
    p = sub.add_parser("wait", help="wait for a job's final state")
    p.add_argument("job_id"); p.add_argument("--timeout", type=int, default=3600); p.add_argument("--interval", type=float, default=3)
    p.add_argument("--quiet", action="store_true")
    a = ap.parse_args(argv)
    st = State(a.state)
    try:
        return {"attest": cmd_attest, "approve": cmd_approve, "submit": cmd_submit, "status": cmd_status, "wait": cmd_wait}[a.cmd](a, st)
    except S.ScopeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
