"""The analyst's tools: typed, read-only views of the scan snapshot and the app database, built on the brain's own
query layer (queries.py, published.py, marks.py, watches.py). Nothing here writes, and nothing reaches the network,
a shell, the file system beyond those readers, the jobs folder, the scope or the settings.

Every tool:
  - checks its arguments against its schema (unknown fields, wrong types, values outside fixed lists or patterns are
    refused with a fixed message);
  - caps rows and field lengths;
  - returns {"data": ..., "untrusted": ...}. "data" holds only identifiers that fullmatch their strict pattern,
    numbers, and values from fixed vocabularies. "untrusted" holds every piece of text that came from a scanned site or
    other target (titles, descriptions, evidence, banners, page titles, DNS values...), keyed by the identifier it
    belongs to, each value redacted with the scanner's redaction module (strict field mode) and capped. In
    metadata-only mode the "untrusted" part is omitted entirely and replaced by {"omitted": "metadata-only"}.

The registry (TOOLS) is the complete list; test_analyst_tools enumerates it."""
import json
import re
import sqlite3
import urllib.parse

from .. import marks as marksm, published, queries, snapshot, watches as watchesm
from ..llm import redaction
from ..llm.schema import validate

FINDING_KEY_RE = re.compile(r"[0-9a-f]{8,64}")
CHECK_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,99}")
CVE_RE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,7}")
VERSION_RE = re.compile(r"[0-9]{1,6}(?:\.[0-9]{1,6}){0,3}[a-z]?")
DATE_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}(?:[T ][0-9]{2}:[0-9]{2}(?::[0-9]{2})?(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:?[0-9]{2})?)?")
SECRET_TYPE_RE = re.compile(r"[a-z0-9_]{1,40}")
CATEGORY_RE = re.compile(r"[a-z_]{1,40}")
CLASSES = ("owned", "unverified", "cdn_fronted", "third_party", "unknown", "parked", "internal", "lab")
VERDICTS = ("confirmed", "likely", "possible", "unconfirmed", "not_vulnerable", "unknown", "suspect", "error")
MAX_ROWS = 50
# The record types the scanner's pipeline writes to dns_records (scanner/pipeline/evidence.py: dnsx answers for
# A/AAAA/CNAME and MX/TXT/NS/CAA/SOA, TXT split into SPF/DMARC/DKIM, the nuclei DNS templates, PTR from nmap).
# Any other value is shown as "record": it is a key of the untrusted part, so it is never free text.
DNS_RTYPES = frozenset(("A", "AAAA", "CNAME", "MX", "TXT", "SPF", "DMARC", "DKIM", "NS", "CAA", "SOA", "SRV", "PTR",
                        "WILDCARD"))
MAX_TEXT = 500
MAX_EVIDENCE = 2000
MAX_RESULT_CHARS = 24000
METADATA_ONLY = {"omitted": "metadata-only"}
VW_REASON_RES = [re.compile(p) for p in (
    r"[0-9.]{1,20} is below [0-9.]{1,20}",
    r"[0-9.]{1,20} is at or above [0-9.]{1,20}",
    r"[0-9.]{1,20} is newer than the [0-9.]{1,12} branch; released after the fix",
    r"[0-9.]{1,20} is on branch [0-9.]{1,12}: no fixed release on this branch",
    r"HTTP (?:[0-9]{3}|-) \(https\) / (?:[0-9]{3}|-) \(http\), no (PHP|nginx|Apache HTTP Server|OpenSSL) version in the headers "
    r"\(hidden or not \1\)",
    r"no HTTP response on https or http \((?:the address check refused it|timed out|no answer|not probed: its CNAME chain "
    r"could not be looked up|not probed: its domain did not pass the DNS proof in this job)\)")]


class ToolError(Exception):
    """A fixed message about the call (never about the data): returned to the model as the tool's result."""


class SnapshotGone(Exception):
    """The snapshot the run started with cannot be read any more (or a query ran past its deadline)."""


class Ctx:
    """What a tool may read. Built by the loop: the verified snapshot State the run pinned at its start, a read-only
    connection to the app database, the published folder (read through published.py's bounded readers), and the
    metadata-only switch."""

    def __init__(self, snap_state, app_db, published_dir, metadata_only, query_seconds=10):
        self.snap_state, self.app_db, self.published_dir = snap_state, app_db, published_dir
        self.metadata_only, self.query_seconds = metadata_only, query_seconds

    def snap(self):
        try:
            return snapshot.connect(self.snap_state, self.query_seconds)
        except sqlite3.Error:
            raise SnapshotGone() from None


def app_db_readonly(db_path):
    """A connection to the app database that cannot write: opened read-only, query_only on."""
    uri = "file:" + urllib.parse.quote(db_path) + "?mode=ro"
    c = sqlite3.connect(uri, uri=True, check_same_thread=False, timeout=10)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA query_only=ON")
    return c


# ---------------------------------------------------------------- value helpers
def key(v):
    return v if isinstance(v, str) and FINDING_KEY_RE.fullmatch(v) else None


def host(v):
    return v if published.is_hostname(v) else None


def run(v):
    return v if published.is_id(v) else None


def vocab(v, allowed):
    return v if isinstance(v, str) and v in allowed else ("other" if v not in (None, "") else None)


def pat(v, rx):
    return v if isinstance(v, str) and rx.fullmatch(v) else None


def num(v):
    if isinstance(v, bool):
        return int(v)
    if isinstance(v, int):
        return v
    if isinstance(v, float) and v == v and abs(v) < 1e12:
        return round(v, 4)
    return None


def text(v, cap=MAX_TEXT):
    """Target-derived text for the untrusted part: redacted (strict field mode) and capped. None and "" stay out."""
    if v is None or v == "":
        return None
    if not isinstance(v, str):
        v = json.dumps(v, ensure_ascii=False, default=str)
    return redaction.field(v[:cap * 4], cap=cap)


def put(untrusted, ident, field, value, cap=MAX_TEXT):
    t = text(value, cap)
    if t:
        untrusted.setdefault(ident, {})[field] = t


def _snap_call(ctx, fn):
    c = ctx.snap()
    try:
        return fn(c)
    except snapshot.Timeout:
        raise SnapshotGone() from None
    finally:
        c.close()


def finding_row(r, untrusted):
    """The data part of one finding row; its title goes to untrusted."""
    k = key(r.get("finding_key"))
    if not k:
        return None
    put(untrusted, k, "title", r.get("title"))
    cid = pat(r.get("check_id"), CHECK_ID_RE)
    if r.get("check_id") and not cid:
        put(untrusted, k, "check_id", r.get("check_id"), 100)
    h = host(r.get("hostname"))
    if r.get("hostname") and not h:
        put(untrusted, k, "hostname", r.get("hostname"), 253)
    return {"finding_key": k, "hostname": h, "domain": host(r.get("apex")), "source": vocab(r.get("source"), queries.SOURCES),
            "check_id": cid, "port": num(r.get("port")), "band": vocab(r.get("band"), queries.BANDS),
            "score": num(r.get("score")), "status": vocab(r.get("status"), ("open", "fixed")),
            "state": vocab(r.get("state"), queries.STATES), "asset_class": vocab(r.get("asset_class"), CLASSES),
            "verdict": vocab(r.get("verdict"), VERDICTS), "kev": num(r.get("kev")), "epss": num(r.get("epss")),
            "cvss": num(r.get("cvss")), "first_seen_run": run(r.get("first_seen_run")),
            "last_seen_run": run(r.get("last_seen_run")), "fixed_run": run(r.get("fixed_run")),
            "cves": [c for c in queries.listish(r.get("cve_ids"), 20) if CVE_RE.fullmatch(c)]}


# ---------------------------------------------------------------- the tools
def t_list_runs(ctx, a):
    rows, more = _snap_call(ctx, lambda c: queries.runs(c, a.get("page", 1), per=MAX_ROWS))
    return {"runs": [{"run_id": run(r.get("run_id")), "seq": num(r.get("seq")), "kind": vocab(r.get("kind"), ("inventory", "full", "recheck")),
                      "started": pat(r.get("started"), DATE_RE), "finished": pat(r.get("finished"), DATE_RE),
                      "inventory_only": num(r.get("inventory_only"))} for r in rows if run(r.get("run_id"))],
            "more": more}, {}


def t_run_summary(ctx, a):
    def go(c):
        seq = queries.run_seq(c, a["run_id"])
        if seq is None:
            raise ToolError("No run with that id in the snapshot.")
        s = next((x for x in queries.summaries(c, 1000) if x["run_id"] == a["run_id"]), None)
        return seq, s
    seq, s = _snap_call(ctx, go)
    d = {"run_id": a["run_id"], "seq": seq}
    if s:
        d.update(kind=vocab(s.get("kind"), ("inventory", "full", "recheck")), started=pat(s.get("started"), DATE_RE),
                 open_by_band=s["bands"], new=s["new"], reopened=s["reopened"], fixed=s["fixed"], total=s["total"])
    return d, {}


def t_search_findings(ctx, a):
    lim = a.get("limit", 20)
    untrusted = {}

    def go(c):
        return queries.findings(c, band=a.get("band"), state=a.get("state"), domain=a.get("domain"), source=a.get("source"),
                                sort=a.get("sort", "priority"), limit=lim, offset=a.get("offset", 0), host=a.get("hostname"))
    rows, total = _snap_call(ctx, go)
    out = [x for x in (finding_row(r, untrusted) for r in rows) if x]
    return {"total_matching": total, "returned": len(out), "findings": out}, untrusted


def t_get_finding(ctx, a):
    d = _snap_call(ctx, lambda c: queries.finding(c, a["finding_key"]))
    if not d:
        raise ToolError("No finding with that key in the snapshot.")
    untrusted = {}
    k = a["finding_key"]
    row = finding_row(d["finding"], untrusted)
    for f in ("description", "remediation", "matched", "verification"):
        put(untrusted, k, f, d.get(f))
    put(untrusted, k, "evidence", d.get("evidence_text"), MAX_EVIDENCE)
    if d.get("tags"):
        put(untrusted, k, "tags", ", ".join(d["tags"][:20]), 300)
    tri = d.get("triage") or {}
    for f in ("summary", "fix"):
        put(untrusted, k, "triage_" + f, tri.get(f))
    if tri.get("exposed"):
        put(untrusted, k, "triage_exposed", "; ".join(tri["exposed"][:20]), 1000)
    secrets = [{"type": pat(s.get("type"), SECRET_TYPE_RE) or "other", "line": num(s.get("line"))} for s in tri.get("secrets", [])[:20]]
    sc = d.get("score") or {}
    hist = [{"run_id": run(h.get("run_id")), "state": vocab(h.get("state"), queries.STATES), "band": vocab(h.get("band"), queries.BANDS),
             "score": num(h.get("score"))} for h in d.get("history", [])[:20]]
    return {"finding": row, "score": {k2: num(sc.get(k2)) for k2 in ("impact", "likelihood", "score", "sla_days", "cvss", "epss", "kev")},
            "triage_exposure": vocab(tri.get("exposure"), ("credential", "data", "source", "config", "internal", "nothing")) if tri else None,
            "secrets_found": secrets, "history": hist,
            "references_count": len(d.get("references") or [])}, untrusted


def t_get_asset(ctx, a):
    d = _snap_call(ctx, lambda c: queries.asset(c, a["hostname"]))
    if not d:
        raise ToolError("No host with that name in the snapshot.")
    h = a["hostname"]
    untrusted = {}
    o = d["asset"]
    for f in ("title", "server", "reason", "waf"):
        put(untrusted, h, f, o.get(f))
    put(untrusted, h, "technology", ", ".join(o.get("tech") or [])[:1000], 500)
    prof = d.get("profile") or {}
    for f in ("hosting", "cdn", "web_server", "cms", "framework", "cert_issuer"):
        put(untrusted, h, "profile_" + f, prof.get(f), 200)
    comps = []
    for i, cpt in enumerate(d.get("components", [])[:MAX_ROWS]):
        put(untrusted, f"{h}#component{i}", "name", cpt.get("name"), 100)
        comps.append({"index": i, "category": pat(cpt.get("category"), CATEGORY_RE),
                      "version": pat(cpt.get("version"), VERSION_RE), "eol": num(cpt.get("eol")),
                      "eol_date": pat(cpt.get("eol_date"), DATE_RE)})
    for i, e in enumerate(d.get("endpoints", [])[:20]):
        put(untrusted, f"{h}#endpoint{i}", "url", e.get("url"), 300)
        put(untrusted, f"{h}#endpoint{i}", "title", e.get("title"), 200)
    for i, r in enumerate(d.get("dns", [])[:30]):
        rtype = r.get("rtype")
        put(untrusted, f"{h}#dns{i}", rtype if isinstance(rtype, str) and rtype in DNS_RTYPES else "record", r.get("value"), 300)
    ports = [{"port": num(p.get("port")), "proto": vocab(p.get("proto"), ("tcp", "udp")), "risky": num(p.get("risky"))}
             for p in d.get("ports", [])[:MAX_ROWS]]
    certs = [{"port": num(x.get("port")), "not_after": pat(x.get("not_after"), DATE_RE), "days_left": num(x.get("days_left")),
              "expired": num(x.get("expired")), "self_signed": num(x.get("self_signed")), "key_bits": num(x.get("key_bits"))}
             for x in d.get("certificates", [])[:20]]
    fnd = [x for x in (finding_row(r, untrusted) for r in d.get("findings", [])[:MAX_ROWS]) if x]
    return {"hostname": h, "run_id": run(d.get("run_id")), "domain": host(o.get("apex")), "class": vocab(o.get("class"), CLASSES),
            "status_code": num(o.get("status_code")), "addresses": published._ips(o.get("ips"), 20),
            "ports": ports, "certificates": certs, "components": comps, "findings": fnd}, untrusted


def t_list_components(ctx, a):
    run_id, rows = _snap_call(ctx, lambda c: queries.components(c, a.get("hostname"), a.get("limit", 50)))
    untrusted, out = {}, []
    for i, r in enumerate(rows):
        h = host(r.get("hostname"))
        if not h:
            continue
        put(untrusted, f"{h}#component{i}", "name", r.get("name"), 100)
        out.append({"index": i, "hostname": h, "category": pat(r.get("category"), CATEGORY_RE),
                    "version": pat(r.get("version"), VERSION_RE), "eol": num(r.get("eol")), "eol_date": pat(r.get("eol_date"), DATE_RE)})
    return {"run_id": run(run_id), "components": out}, untrusted


def t_expiring_certificates(ctx, a):
    run_id, rows = _snap_call(ctx, lambda c: queries.expiring_certificates(c, a.get("days", 30), MAX_ROWS))
    untrusted, out = {}, []
    for i, r in enumerate(rows):
        h = host(r.get("hostname"))
        if not h:
            continue
        put(untrusted, f"{h}#cert{i}", "issuer", r.get("issuer"), 200)
        put(untrusted, f"{h}#cert{i}", "subject", r.get("subject"), 200)
        out.append({"index": i, "hostname": h, "port": num(r.get("port")), "not_after": pat(r.get("not_after"), DATE_RE),
                    "days_left": num(r.get("days_left")), "expired": num(r.get("expired")), "self_signed": num(r.get("self_signed"))})
    return {"run_id": run(run_id), "within_days": a.get("days", 30), "certificates": out}, untrusted


def t_domain_posture(ctx, a):
    run_id, rows = _snap_call(ctx, queries.domains)
    untrusted, out = {}, []
    for r in rows[:MAX_ROWS]:
        d = host(r.get("apex"))
        if not d:
            continue
        for f in ("spf_policy", "dmarc_policy", "dmarc_sp", "mx_provider", "ns_provider"):
            put(untrusted, d, f, r.get(f), 200)
        put(untrusted, d, "mx", ", ".join(r.get("mx") or []), 300)
        put(untrusted, d, "nameservers", ", ".join(r.get("nameservers") or []), 300)
        put(untrusted, d, "caa_issuers", ", ".join(r.get("caa_issuers") or []), 300)
        out.append({"domain": d, **{f: num(r.get(f)) for f in ("spf", "dmarc", "dkim", "caa", "hosts_with_spf", "hosts_with_dkim")}})
    return {"run_id": run(run_id), "domains": out}, untrusted


def t_diff_runs(ctx, a):
    def go(c):
        if not (queries.run_exists(c, a["run_a"]) and queries.run_exists(c, a["run_b"])):
            raise ToolError("Both runs must exist in the snapshot.")
        return queries.diff_runs(c, a["run_a"], a["run_b"], MAX_ROWS)
    d = _snap_call(ctx, go)
    return {"run_a": a["run_a"], "run_b": a["run_b"], **{k: [x for x in v if key(x)] for k, v in d.items()}}, {}


def _vw_reason(v):
    return v if isinstance(v, str) and any(rx.fullmatch(v) for rx in VW_REASON_RES) else ("unrecognized reason" if v else None)


def t_version_watch_status(ctx, a):
    """Through published.watch_result, the brain's own reader (4 MiB per file, 5,000 hosts, 5,000 changes, 100 history
    rows). The only target-derived field of version-watch-v1, hosts[].server, goes to the untrusted part."""
    wid = a.get("watch_id")
    if not wid:
        defined = {w["id"]: w for w in watchesm.all_watches(ctx.app_db)}
        ids = sorted(set(defined) | set(published.watch_folders(ctx.published_dir)))[:MAX_ROWS]
        out = []
        for i in ids:
            r = published.watch_result(ctx.published_dir, i)
            res = r["result"]
            out.append({"watch_id": i, "defined": i in defined, "product": res["watch"]["product"] if res else None,
                        "date": res["date"] if res else None, "headline": res["headline"] if res else None,
                        "suspect": bool(r["suspect"])})
        return {"watches": out}, {}
    r = published.watch_result(ctx.published_dir, wid)
    res = r["result"]
    if not r["folder"] or not res:
        raise ToolError("No published result for that watch.")
    untrusted, hosts = {}, []
    for h in res["hosts"][:a.get("limit", 50)]:
        put(untrusted, h["hostname"], "server", h.get("server"), 100)
        hosts.append({k: h.get(k) for k in ("hostname", "domain", "version", "verdict", "read_from", "https_status", "http_status",
                                             "scan_db_version", "source")} | {"reason": _vw_reason(h.get("reason"))})
    return {"watch_id": wid, "product": res["watch"]["product"], "cves": res["cves"], "floors": res["floors"],
            "date": res["date"], "headline": res["headline"], "suspect": bool(r["suspect"]),
            "hosts_total": len(res["hosts"]), "hosts": hosts,
            "changes": res["changes"]["items"][:MAX_ROWS], "history": res["history"][-20:]}, untrusted


def t_hosts_held_back(ctx, a):
    hb = published.held_back(ctx.published_dir)
    if not hb:
        return {"held_back": None}, {}
    return {"run_id": hb["run_id"], "inventory_run": hb["inventory_run"], "domains": hb["domains"][:MAX_ROWS],
            "hosts": [{"hostname": h["host"], "reason": h["reason"], "approved_ips": h["approved_ips"][:10],
                       "current_ips": h["current_ips"][:10]} for h in hb["hosts"][:MAX_ROWS]],
            "hosts_total": len(hb["hosts"])}, {}


def t_existing_marks(ctx, a):
    def go(c):
        return marksm.with_staleness(ctx.app_db, c)
    m = _snap_call(ctx, go)
    untrusted, out = {}, []
    for k, v in list(m.items())[:MAX_ROWS]:
        if not key(k):
            continue
        from_proposal = bool(v.get("proposal_id"))
        if not from_proposal:      # a reason a person typed; never the model's own text from an accepted proposal
            put(untrusted, k, "mark_reason", v.get("reason"), 500)
        out.append({"finding_key": k, "kind": vocab(v.get("kind"), tuple(marksm.KINDS)), "run_id": run(v.get("run_id")),
                    "stale": bool(v.get("stale")), "created_at": pat(v.get("created_at"), DATE_RE),
                    "from_accepted_analyst_proposal": from_proposal})
    return {"marks": out, "total": len(m)}, untrusted


def t_accepted_notes(ctx, a):
    rows = [dict(r) for r in ctx.app_db.execute("SELECT id, finding_key, body, source, created_at FROM notes ORDER BY id DESC LIMIT ?",
                                                (MAX_ROWS,))]
    untrusted, out = {}, []
    for r in rows:
        put(untrusted, f"note{r['id']}", "body", r["body"], 1000)
        out.append({"note_id": r["id"], "finding_key": key(r["finding_key"]), "source": vocab(r["source"], ("human", "agent")),
                    "created_at": pat(r["created_at"], DATE_RE)})
    return {"notes": out}, untrusted


# ---------------------------------------------------------------- argument schemas (validated by llm.schema.validate)
def _obj(props, required=()):
    return {"type": "object", "properties": props, "required": list(required), "additionalProperties": False}


S_KEY = {"type": "string", "pattern": FINDING_KEY_RE.pattern}
S_HOST = {"type": "string", "pattern": published.HOSTNAME_RE.pattern, "maxLength": 253}
S_RUN = {"type": "string", "pattern": published.ID_RE.pattern}


def _int(lo, hi):
    return {"type": "integer", "minimum": lo, "maximum": hi}


TOOLS = {
    "list_runs": (t_list_runs, "Scan runs in the snapshot, newest first, 50 per page.", _obj({"page": _int(1, 1000)})),
    "run_summary": (t_run_summary, "One run's open findings by band and its new, reopened and fixed counts.", _obj({"run_id": S_RUN}, ["run_id"])),
    "search_findings": (t_search_findings, "Findings matching filters, highest priority first (at most 50).", _obj({
        "band": {"type": "string", "enum": list(queries.BANDS)}, "state": {"type": "string", "enum": list(queries.STATES)},
        "domain": S_HOST, "hostname": S_HOST, "source": {"type": "string", "enum": list(queries.SOURCES)},
        "sort": {"type": "string", "enum": list(queries.SORTS)}, "limit": _int(1, MAX_ROWS), "offset": _int(0, 10000)})),
    "get_finding": (t_get_finding, "One finding: facts, score, history, and its stored text (untrusted).", _obj({"finding_key": S_KEY}, ["finding_key"])),
    "get_asset": (t_get_asset, "One host from its latest run: class, ports, certificates, components, findings.", _obj({"hostname": S_HOST}, ["hostname"])),
    "list_components": (t_list_components, "Software components and versions from the latest run, optionally for one host.",
                        _obj({"hostname": S_HOST, "limit": _int(1, MAX_ROWS)})),
    "expiring_certificates": (t_expiring_certificates, "Certificates that expire within N days (default 30) or have expired.",
                              _obj({"days": _int(0, 365)})),
    "domain_posture": (t_domain_posture, "SPF, DMARC, DKIM, CAA and mail and name servers per domain.", _obj({})),
    "diff_runs": (t_diff_runs, "Findings seen only in run_b, only in run_a, reopened in run_b, and fixed in run_b.",
                  _obj({"run_a": S_RUN, "run_b": S_RUN}, ["run_a", "run_b"])),
    "version_watch_status": (t_version_watch_status, "Version watches (no watch_id) or one watch's latest published result.",
                             _obj({"watch_id": {"type": "string", "pattern": published.VW_WATCH_ID_RE.pattern}, "limit": _int(1, MAX_ROWS)})),
    "hosts_held_back": (t_hosts_held_back, "Hosts and domains the latest full or recheck run kept from active checks.", _obj({})),
    "existing_marks": (t_existing_marks, "Marks people have put on findings, and whether each is stale. The reason is "
                       "included only for marks a person wrote by hand.", _obj({})),
    "accepted_notes": (t_accepted_notes, "Notes a person has accepted.", _obj({})),
}

# What each tool's untrusted part may hold (for the documentation and the registry test)
UNTRUSTED_FIELDS = {
    "list_runs": (), "run_summary": (), "diff_runs": (), "hosts_held_back": (),
    "search_findings": ("title", "check_id (when not a plain id)", "hostname (when not a valid host name)"),
    "get_finding": ("title", "description", "remediation", "matched", "verification", "evidence", "tags", "triage_summary",
                    "triage_fix", "triage_exposed"),
    "get_asset": ("title", "server", "reason", "waf", "technology", "profile_*", "component name", "endpoint url and title",
                  "DNS record values", "finding titles"),
    "list_components": ("component name",), "expiring_certificates": ("issuer", "subject"),
    "domain_posture": ("spf_policy", "dmarc_policy", "dmarc_sp", "mx_provider", "ns_provider", "mx", "nameservers", "caa_issuers"),
    "version_watch_status": ("hosts[].server",), "existing_marks": ("mark_reason (manual marks only)",), "accepted_notes": ("body",),
}


def describe():
    """The tool list as shown to the model."""
    return [{"name": n, "description": d, "arguments": s} for n, (_, d, s) in TOOLS.items()]


def call(ctx, name, args):
    """Run one tool. Returns the result dict {"tool", "data", "untrusted"}; raises ToolError for an unknown tool or
    bad arguments (fixed messages), SnapshotGone when the pinned snapshot cannot be read."""
    if name not in TOOLS:
        raise ToolError("There is no tool with that name.")
    fn, _, schema = TOOLS[name]
    if not isinstance(args, dict):
        raise ToolError("The arguments must be a JSON object.")
    problems = validate(args, schema)
    if problems:
        raise ToolError("Invalid arguments: " + "; ".join(p.replace("$.", "").replace("$:", "arguments:") for p in problems[:3]) + ".")
    data, untrusted = fn(ctx, args)
    res = {"tool": name, "data": data, "untrusted": METADATA_ONLY if ctx.metadata_only else untrusted}
    text_ = json.dumps(res, ensure_ascii=False, default=str)
    if len(text_) > MAX_RESULT_CHARS:
        # cut the untrusted part first, then rows; the result says so
        res["untrusted"] = METADATA_ONLY if ctx.metadata_only else {"omitted": "too large; ask for fewer rows"}
        res["truncated"] = True
        text_ = json.dumps(res, ensure_ascii=False, default=str)
        if len(text_) > MAX_RESULT_CHARS:
            res["data"] = {"omitted": "too large; ask for fewer rows"}
    return res
