"""Data for each page, shared by the HTML pages and the JSON API so both show the same thing."""
import datetime as dt
import os
import re

from . import audit, marks as marksm, published, queries, scheduler, scope as scopem, watches as watchesm

KEY_RE = re.compile(r"[0-9a-f]{8,64}")           # always used with fullmatch
JOBS_PER_PAGE = 50


def heartbeat(c):
    s = c.scanner
    if not s:
        return None
    age = published.heartbeat_age(s)
    # the scanner refreshes its heartbeat about every 30 s while idle and while a job runs, so an old one means
    # stopped; one dated in the future is stale too (published.heartbeat_stale)
    return {**s, "age_seconds": int(age) if age is not None else None, "stale": published.heartbeat_stale(s)}


def snap_info(c):
    st = c.snap_state
    return {"state": st.kind, "message": st.message, "run_id": st.info.get("run_id"), "created_at": st.info.get("created_at"),
            "sha256": st.info.get("sha256"), "folder": published.folder_state(c.settings.published_dir)}


def overview(c):
    out = {"snapshot": snap_info(c), "scanner": heartbeat(c), "counts": None, "latest": None, "trend": [], "top": []}
    if c.snap is None:
        return out
    out["counts"] = queries.band_counts(c.snap)
    sums = queries.summaries(c.snap, 30)
    scored = [s for s in sums if s.get("kind") != "inventory"]
    out["latest"] = scored[-1] if scored else None
    out["trend"] = scored[-20:]
    m = marksm.with_staleness(c.db, c.snap)
    out["top"] = [{**f, "mark": m.get(f["finding_key"])} for f in queries.top_open(c.snap, 3)]
    return out


def trend_bars(trend, width=600, height=120):
    """Bar geometry for the trend chart (numbers only; drawn with SVG attributes, no inline style)."""
    if not trend:
        return []
    top = max(1, max(t["total"] for t in trend))
    bw = width / max(len(trend), 1)
    bars = []
    for i, t in enumerate(trend):
        y = height
        segs = []
        for band in ("Low", "Medium", "High", "Critical"):
            h = round(t["bands"].get(band, 0) / top * (height - 10), 1)
            y -= h
            if h > 0:
                segs.append({"band": band, "y": round(y, 1), "h": h})
        bars.append({"x": round(i * bw + 2, 1), "w": round(max(bw - 4, 2), 1), "segs": segs, "run_id": t["run_id"], "total": t["total"]})
    return bars


def findings(c, p):
    out = {"snapshot": snap_info(c), "rows": [], "total": 0, "facets": {"domains": [], "classes": []}, "filters": p}
    if c.snap is None:
        return out
    m = marksm.with_staleness(c.db, c.snap)
    current = {k for k, v in m.items() if not v["stale"]}
    rows, total = queries.findings(c.snap, band=p.get("band"), state=p.get("state"), domain=p.get("domain"), klass=p.get("klass"),
                                   source=p.get("source"), marked=p.get("marked"), marked_keys=current, sort=p.get("sort") or "priority",
                                   limit=100, offset=100 * max(0, (p.get("page") or 1) - 1))
    for r in rows:
        r["mark"] = m.get(r["finding_key"])
    out.update(rows=rows, total=total, facets=queries.facets(c.snap))
    return out


def finding(c, key, hist_page=1):
    if not isinstance(key, str) or not KEY_RE.fullmatch(key) or c.snap is None:
        return None
    d = queries.finding(c.snap, key, hist_page)
    if not d:
        return None
    d["mark"] = marksm.with_staleness(c.db, c.snap).get(key)
    d["mark_history"] = marksm.history(c.db, key)
    return d


def assets(c):
    out = {"snapshot": snap_info(c), "run_id": None, "rows": []}
    if c.snap is not None:
        out["run_id"], out["rows"] = queries.assets(c.snap)
    return out


def asset(c, host, cert_page=1, tls_page=1):
    if not published.is_hostname(host) or c.snap is None:
        return None
    return queries.asset(c.snap, host, cert_page, tls_page)


def domains(c):
    out = {"snapshot": snap_info(c), "run_id": None, "rows": []}
    if c.snap is not None:
        out["run_id"], out["rows"] = queries.domains(c.snap)
    return out


def runs(c, runs_page=1, jobs_page=1):
    sts = published.all_status(c.settings.published_dir)
    mine = {r["id"]: dict(r) for r in c.db.execute("SELECT * FROM jobs ORDER BY created_at DESC LIMIT 500")}
    for s in sts:
        j = mine.get(s["job_id"])
        s["domains"] = published.domain_counts(s) if s.get("type") in ("full", "recheck") else None
        s["created_by"] = j["created_by"] if j else None
        s["trigger"] = j["trigger"] if j else None
    seen = {s["job_id"] for s in sts}
    waiting = [{"job_id": k, "state": "abandoned" if j["abandoned_at"] else "written", "type": j["type"], "created_by": j["created_by"],
                "trigger": j["trigger"], "queued_at": j["created_at"], "reports": [],
                "reason": f"marked abandoned by {j['abandoned_by']}" if j["abandoned_at"] else None} for k, j in mine.items() if k not in seen]
    scan_runs, runs_more = queries.runs(c.snap, runs_page) if c.snap is not None else ([], False)
    from . import jobs as jobsm
    # jobs that never reached a final status (for example, their status file was lost): the admin may mark them
    # abandoned after confirming that the scanner is not running them
    stuck = [j for j in waiting + sts if j["state"] not in published.FINAL and j["state"] != "abandoned" and _older_than(j.get("queued_at"), 600)
             and not (mine.get(j["job_id"]) or {}).get("abandoned_at")
             and jobsm.abandonable(c.settings, c.scanner, j["job_id"]) is None]
    jobs_all = waiting + sts
    jp = queries.page_number(jobs_page)
    page_jobs = jobs_all[(jp - 1) * JOBS_PER_PAGE:jp * JOBS_PER_PAGE]
    for j in page_jobs:        # report folders are listed only for the jobs on this page
        j["reports"] = published.report_files(c.settings.published_dir, j.get("run_id")) if j["state"] == "done" and j.get("run_id") else []
    return {"jobs": page_jobs, "jobs_page": jp, "jobs_more": len(jobs_all) > jp * JOBS_PER_PAGE,
            "scan_runs": scan_runs, "runs_page": queries.page_number(runs_page), "runs_more": runs_more,
            "snapshot": snap_info(c), "scanner": heartbeat(c), "abandonable": [j["job_id"] for j in stuck]}


def _older_than(stamp, seconds):
    """True when the ISO time stamp is more than seconds ago (a job just written is not offered for abandoning)."""
    try:
        t = dt.datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return True
    if t.tzinfo is None:
        t = t.replace(tzinfo=dt.timezone.utc)
    return (dt.datetime.now(dt.timezone.utc) - t).total_seconds() > seconds


def scope_page(c):
    from . import jobs
    pub = c.settings.published_dir
    ss = published.scope_status(pub)
    doms = scopem.domains(c.db)
    for d in doms:
        d["published"] = (ss or {}).get("domains", {}).get(d["name"]) if ss else None
    appr = scopem.approval(c.db)
    out = {"domains": doms, "scope_status_at": ss["updated_at"] if ss else None, "notice": ss["notice"] if ss else None,
           **scopem.lists(c.db), "profile": scopem.profile(c.db), "approval": appr, "approvable": jobs.approvable(c)[:5],
           "inventory_run": None, "inventory": [], "awaiting": [], "held_back": published.held_back(pub), "unverified": [],
           "snapshot": snap_info(c), "scanner": heartbeat(c), "sync_pending": jobs.sync_pending(c.db), "lab": c.lab}
    # what the scanner held back in its latest full or recheck run, when that run used the approval in force: the
    # scanner's own comparison (hosts, the addresses the approved inventory listed and the addresses seen now)
    awaiting = {}
    hb = out["held_back"]
    current = bool(hb and appr and hb["inventory_run"] == appr["inventory_run"])
    if current:
        for h in hb["hosts"]:
            awaiting[h["host"]] = {"hostname": h["host"], "why": h["why"] + f" (held back by the scanner in run {hb['run_id']})",
                                   "ips": h["current_ips"], "before": h["approved_ips"] if h["reason"] == "address-changed" else []}
    held_domains = set(hb["domains"]) if current else set()
    other_domains = set(hb.get("other_domains") or ()) if current else set()
    for d in doms:
        d["held_back"] = (published.HELD_DOMAIN_TEXT if d["name"] in held_domains else
                          "Held back by the scanner: " + published.UNKNOWN_REASON + "." if d["name"] in other_domains else None)
    out["domain_counts"] = latest_domain_counts(pub)
    if c.snap is not None:
        inv = queries.latest_run(c.snap, ("inventory",))
        if inv:
            out["inventory_run"] = inv["run_id"]
            out["inventory"] = queries.inventory(c.snap, inv["run_id"])
        run_id, rows = queries.assets(c.snap)
        approved = set(x["hostname"] for x in out["approved_hosts"])
        out["unverified"] = [r for r in rows if r.get("class") == "unverified" and r["hostname"] not in approved]
        for r in rows:
            if r["hostname"] in awaiting:
                awaiting[r["hostname"]]["class"] = r.get("class")
    out["awaiting"] = sorted(awaiting.values(), key=lambda x: x["hostname"])
    return out


def latest_domain_counts(pub):
    """The domain counts of the newest full or recheck job that has them: {"job_id", "scanned", "held_back", "pending"}."""
    for st in published.all_status(pub):
        if st.get("type") in ("full", "recheck"):
            dc = published.domain_counts(st)
            if dc is not None:
                return {"job_id": st["job_id"], **dc}
    return None


def schedules(c):
    now = dt.datetime.now(dt.timezone.utc)
    rows = [dict(r) for r in c.db.execute("SELECT * FROM schedules ORDER BY kind")]
    for r in rows:
        r["next_run"] = scheduler.slot_key(scheduler.next_run(r, now)) if r["enabled"] else None
    return {"rows": rows, "now": scheduler.slot_key(now.replace(second=0, microsecond=0))}


def set_schedule(c, kind, enabled, hour, minute, day_of_month):
    if kind not in scheduler.KINDS:
        raise ValueError("Unknown schedule.")
    if not (0 <= hour <= 23 and 0 <= minute <= 59) or (kind == "monthly-full" and not 1 <= (day_of_month or 0) <= 31):
        raise ValueError("Hour 0-23, minute 0-59, day of month 1-31.")
    cur = dict(c.db.execute("SELECT * FROM schedules WHERE kind=?", (kind,)).fetchone())
    new = {"enabled": int(bool(enabled)), "hour": hour, "minute": minute, "day_of_month": day_of_month if kind == "monthly-full" else None}
    changed = {k: (cur[k], v) for k, v in new.items() if cur[k] != v}
    if not changed:
        return False
    # last_slot moves to "now" so that turning a schedule on, or moving its time to the past, never fires a slot
    # that is already past; the first run is the next slot after this change
    now_key = scheduler.slot_key(dt.datetime.now(dt.timezone.utc))
    c.db.execute("BEGIN IMMEDIATE")
    try:
        c.db.execute("UPDATE schedules SET enabled=?, hour=?, minute=?, day_of_month=?, last_slot=?, updated_by=?, updated_at=? WHERE kind=?",
                     (new["enabled"], hour, minute, new["day_of_month"], now_key, c.user, now_key, kind))
        audit.write(c.db, c.user, "schedule-change", target=kind,
                    detail="; ".join(f"{k}: {a} -> {b}" for k, (a, b) in sorted(changed.items())) + " (times in UTC)", address=c.address)
        c.db.execute("COMMIT")
    except Exception:
        c.db.execute("ROLLBACK")
        raise
    return True


def instance(c):
    s = c.settings
    from .db import schema_version
    return {
        "data_dir": s.data_dir, "jobs_dir": s.jobs_dir, "published_dir": s.published_dir,
        "allowed_origins": list(s.allowed_origins), "cookie_secure": s.cookie_secure,
        "session_idle_minutes": s.session_idle_minutes, "session_max_hours": s.session_max_hours,
        "password_min_length": s.password_min_length, "login_max_failures": s.login_max_failures,
        "login_lookback_hours": 24, "login_max_delay_seconds": s.login_max_delay_seconds,
        "login_hash_concurrency": s.login_hash_concurrency, "snapshot_query_seconds": s.snapshot_query_seconds,
        "snapshot_max_mb": s.snapshot_max_mb, "trusted_proxy": s.trusted_proxy or None, "scheduler_enabled": s.scheduler_enabled,
        "lab": s.lab, "lab_cidr": s.lab_cidr or None, "schema_version": schema_version(c.db),
        "jobs_dir_writable": os.access(s.jobs_dir, os.W_OK), "published_dir_state": published.folder_state(s.published_dir),
        "model_provider": s.analyst_provider, "model": s.analyst_model or None,
    }


def proxy_warning(s):
    """The start-up warning of auth.PROXY_WARNING, also shown on the Settings page, or None."""
    from . import auth
    https = any(o.lower().startswith("https://") for o in s.allowed_origins)
    return auth.PROXY_WARNING if https and not s.trusted_proxy else None


# ---------------------------------------------------------------- version watch
PROBE_STATEMENT = ("One GET / per host per run, over https and then http, response headers only. It follows at most three "
                   "redirects, and only to the same host name; such a redirect may lead to another path or port on that host. "
                   "It starts no request to any other path, and uses no other method and no request body. Hosts are probed only under domains whose DNS proof "
                   "passed in that job. Hosts under a domain held back from active checks are still watched, because this probe "
                   "is no more than the web inventory already sends.")


def _definition(w):
    return {**w, "product_name": watchesm.PRODUCTS.get(w["product"], "unknown"),
            "floor_texts": [f"{b}.{p}" for b, p in w["floors"].items()]}


def version_watch(c):
    """The watch definitions, each with its latest published result's headline (or the suspect marker), and the
    result folders of watches that are no longer defined."""
    pub = c.settings.published_dir
    defs = watchesm.all_watches(c.db)
    rows = []
    for w in defs:
        r = published.watch_result(pub, w["id"])
        res = r["result"]
        rows.append({**_definition(w), "latest": {"date": res["date"], "generated_at": res["generated_at"], "job_id": res["job_id"],
                                                  "headline": res["headline"]} if res else None,
                     "suspect": r["suspect"]})
    ids = {w["id"] for w in defs}
    retired = [f for f in published.watch_folders(pub) if f not in ids]
    return {"watches": rows, "retired": retired, "folder": published.folder_state(pub), "max_watches": watchesm.MAX_WATCHES,
            "full": len(defs) >= watchesm.MAX_WATCHES, "probe": PROBE_STATEMENT,
            "products": [{"id": k, "name": v} for k, v in watchesm.PRODUCTS.items()]}


def version_watch_one(c, wid):
    """One watch: its definition (None when it is no longer defined) and its checked published result, or None when
    there is neither a definition nor a results folder."""
    if not published.is_watch_id(wid):
        return None
    w = watchesm.get(c.db, wid)
    r = published.watch_result(c.settings.published_dir, wid)
    if w is None and not r["folder"]:
        return None
    return {"id": wid, "watched": w is not None, "definition": _definition(w) if w else None, **r, "probe": PROBE_STATEMENT,
            "products": [{"id": k, "name": v} for k, v in watchesm.PRODUCTS.items()]}
