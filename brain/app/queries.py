"""Read-only queries over a verified snapshot. Every query is parameterized; sort and filter inputs are checked
against fixed lists. Values come back as plain Python data for the templates (which escape everything) and the
API. A table or column missing from the snapshot gives an empty result, never an error page. A query stopped at the
request's deadline (snapshot.connect's progress handler) raises snapshot.Timeout, which the app shows as an error
page: never as an empty result. Every query has a row limit; lists a page shows are paginated (PER_PAGE rows, one
more fetched to know whether there is a next page)."""
import hashlib
import json
import sqlite3

from .snapshot import Timeout, loads

BANDS = ("Critical", "High", "Medium", "Low", "Info")
STATES = ("open", "fixed", "new", "reopened", "persistent")
SOURCES = ("dns", "http", "nmap", "sslscan", "nuclei")
MARK_FILTERS = ("any", "unmarked", "marked")
SORTS = {   # name -> ORDER BY expression (fixed text, never from input)
    "priority": "COALESCE(o.score, -1) DESC, f.finding_key",
    "score": "COALESCE(o.score, -1) DESC, f.finding_key",
    "host": "f.hostname, f.finding_key",
    "title": "f.title, f.finding_key",
    "first_seen": "f.first_seen_run, f.finding_key",
    "last_seen": "f.last_seen_run DESC, f.finding_key",
    "source": "f.source, f.check_id, f.finding_key",
}
VOLATILE_EVIDENCE_KEYS = {"timestamp", "ip", "epss-score", "epss-percentile", "epss_score", "epss_percentile"}


PER_PAGE = 50
MAX_PAGE = 10000


def _rows(db, sql, args=()):
    try:
        return [dict(r) for r in db.execute(sql, args)]
    except sqlite3.Error:
        if getattr(db, "timed_out", False):
            raise Timeout()
        return []


def page_number(v):
    try:
        return max(1, min(int(v or 1), MAX_PAGE))
    except (TypeError, ValueError):
        return 1


def _page(db, sql, args, page, per=PER_PAGE):
    """(rows of this page, whether there is a next page)."""
    rows = _rows(db, sql + " LIMIT ? OFFSET ?", tuple(args) + (per + 1, (page_number(page) - 1) * per))
    return rows[:per], len(rows) > per


def _one(db, sql, args=()):
    r = _rows(db, sql, args)
    return r[0] if r else None


def listish(v, n=50):
    """A list of display strings from a column that may hold JSON, a comma list, or anything else."""
    if v is None:
        return []
    if isinstance(v, (int, float)):
        return [str(v)]
    if not isinstance(v, str):
        return []
    d = loads(v) if v[:1] in "[{\"" else None
    if isinstance(d, list):
        return [x if isinstance(x, str) else json.dumps(x, ensure_ascii=False, default=str) for x in d[:n]]
    if isinstance(d, dict):
        return [f"{k}: {x}" for k, x in list(d.items())[:n]]
    return [p.strip() for p in v.split(",") if p.strip()][:n]


def runs(db, page=1, per=PER_PAGE):
    """(one page of scan runs, newest first; whether there is a next page)."""
    rows, more = _page(db, "SELECT seq, run_id, started, finished, kind, evidence_level, inventory_only FROM runs ORDER BY seq DESC", (), page, per)
    if rows:
        return rows, more
    return _page(db, "SELECT seq, run_id, started, finished FROM runs ORDER BY seq DESC", (), page, per)


def run_seq(db, run_id):
    r = _one(db, "SELECT seq FROM runs WHERE run_id=?", (run_id,))
    return r["seq"] if r and isinstance(r["seq"], int) else None


def latest_run(db, kinds=None):
    if kinds is None:
        return _one(db, "SELECT seq, run_id, started, finished FROM runs ORDER BY seq DESC LIMIT 1")
    return _one(db, "SELECT seq, run_id, started, finished, kind, evidence_level, inventory_only FROM runs "
                    "WHERE kind IN (SELECT value FROM json_each(?)) ORDER BY seq DESC LIMIT 1", (json.dumps(list(kinds)),))


def summaries(db, limit=30):
    out = []
    for r in _rows(db, "SELECT r.seq, r.run_id, r.kind, r.started, s.json FROM run_summary s JOIN runs r ON r.run_id=s.run_id "
                       "ORDER BY r.seq DESC LIMIT ?", (limit,)):
        d = loads(r.pop("json"), {})
        d = d if isinstance(d, dict) else {}
        bands = d.get("bands") if isinstance(d.get("bands"), dict) else {}
        num = lambda x: x if isinstance(x, int) and not isinstance(x, bool) else 0  # noqa: E731
        r.update({"bands": {b: num(bands.get(b)) for b in BANDS[:4]}, "new": num(d.get("new")), "reopened": num(d.get("reopened")),
                  "fixed": num(d.get("fixed")), "total": num(d.get("total"))})
        out.append(r)
    return list(reversed(out))


FINDING_COLS = ("f.finding_key, f.hostname, f.apex, f.source, f.check_id, f.port, f.title, f.severity, f.status, f.cve_ids, "
                "f.first_seen_run, f.last_seen_run, f.fixed_run, o.band, o.score, o.state, o.asset_class, o.verdict, o.exposure, "
                "o.kev, o.epss, o.cvss")
FINDING_JOIN = "FROM findings f LEFT JOIN finding_observations o ON o.finding_key=f.finding_key AND o.run_id=f.last_seen_run"


def band_counts(db):
    """Open findings by band from the snapshot alone (marks never enter this)."""
    out = {b: 0 for b in BANDS}
    for r in _rows(db, f"SELECT o.band AS band, COUNT(*) AS n {FINDING_JOIN} WHERE f.status='open' GROUP BY o.band"):
        if r["band"] in out:
            out[r["band"]] = r["n"]
    return out


def findings(db, band=None, state=None, domain=None, klass=None, source=None, marked=None, marked_keys=(), sort="priority",
             limit=200, offset=0, host=None):
    """marked: None/'any', 'unmarked' or 'marked'; marked_keys: finding keys with a current (not stale) mark."""
    where, args = ["1=1"], []
    if band in BANDS:
        where.append("o.band = ?"); args.append(band)
    if state in ("open", "fixed"):
        where.append("f.status = ?"); args.append(state)
    elif state in ("new", "reopened", "persistent"):
        where.append("f.status = 'open' AND o.state = ?"); args.append(state)
    if domain:
        where.append("f.apex = ?"); args.append(str(domain)[:253])
    if klass:
        where.append("o.asset_class = ?"); args.append(str(klass)[:40])
    if source in SOURCES:
        where.append("f.source = ?"); args.append(source)
    if host:
        where.append("f.hostname = ?"); args.append(str(host)[:253])
    if marked in ("marked", "unmarked"):
        where.append(("" if marked == "marked" else "NOT ") + "f.finding_key IN (SELECT value FROM json_each(?))")
        args.append(json.dumps(sorted(marked_keys)))
    order = SORTS.get(sort, SORTS["priority"])
    sql = f"SELECT {FINDING_COLS} {FINDING_JOIN} WHERE {' AND '.join(where)} ORDER BY {order} LIMIT ? OFFSET ?"
    rows = _rows(db, sql, args + [max(1, min(int(limit), 1000)), max(0, int(offset))])
    total = _one(db, f"SELECT COUNT(*) AS n {FINDING_JOIN} WHERE {' AND '.join(where)}", args)
    return rows, (total or {}).get("n", 0)


def facets(db):
    return {"domains": [r["apex"] for r in _rows(db, "SELECT DISTINCT apex FROM findings WHERE apex IS NOT NULL AND apex != '' ORDER BY apex LIMIT 500")],
            "classes": [r["c"] for r in _rows(db, "SELECT DISTINCT asset_class AS c FROM finding_observations WHERE asset_class IS NOT NULL ORDER BY c LIMIT 50")]}


def top_open(db, n=3):
    return _rows(db, f"SELECT {FINDING_COLS} {FINDING_JOIN} WHERE f.status='open' ORDER BY {SORTS['priority']} LIMIT ?", (n,))


def finding(db, key, hist_page=1):
    f = _one(db, f"SELECT {FINDING_COLS} {FINDING_JOIN} WHERE f.finding_key=?", (key,))
    if not f:
        return None
    obs = _one(db, "SELECT * FROM finding_observations WHERE finding_key=? AND run_id=?", (key, f["last_seen_run"])) or {}
    tri = _one(db, "SELECT * FROM finding_triage WHERE finding_key=? AND run_id=?", (key, f["last_seen_run"]))
    hist, hist_more = _page(db, "SELECT o.run_id, r.seq, r.started, r.kind, o.state, o.band, o.score, o.verdict, o.exposure "
                                "FROM finding_observations o LEFT JOIN runs r ON r.run_id=o.run_id WHERE o.finding_key=? "
                                "ORDER BY r.seq DESC", (key,), hist_page)
    evidence = loads(obs.get("raw_json"), None)
    refs = loads(obs.get("reference"), [])
    triage = None
    if tri:
        items = loads(tri.get("items_json"), [])
        secrets = loads(tri.get("secrets_json"), [])
        triage = {"exposure": tri.get("exposure"), "summary": tri.get("summary"), "fix": tri.get("fix"), "pci": tri.get("pci"),
                  "exposed": [json.dumps(x, ensure_ascii=False, default=str) if not isinstance(x, str) else x for x in (items if isinstance(items, list) else [])[:50]],
                  "secrets": [{k: (str(x.get(k)) if x.get(k) is not None else None) for k in ("type", "masked", "where", "line")}
                              for x in (secrets if isinstance(secrets, list) else [])[:50] if isinstance(x, dict)]}
    return {
        "finding": f, "description": obs.get("description"), "remediation": obs.get("remediation"),
        "matched": obs.get("matched"), "verification": obs.get("verification"), "tags": listish(obs.get("tags")),
        "references": [x for x in (refs if isinstance(refs, list) else []) if isinstance(x, str)][:10],
        "score": {k: obs.get(k) for k in ("impact", "likelihood", "score", "band", "sla_days", "cvss", "epss", "kev")},
        "evidence_text": json.dumps(evidence, indent=1, sort_keys=True, ensure_ascii=False, default=str)[:20000] if evidence is not None
        else (str(obs.get("raw_json"))[:20000] if obs.get("raw_json") else None),
        "triage": triage, "history": hist, "history_page": page_number(hist_page), "history_more": hist_more,
        "evidence_fp": evidence_fingerprint(obs, tri),
    }


def _strip_volatile(v, depth=0):
    if depth > 20:
        return None
    if isinstance(v, dict):
        return {k: _strip_volatile(x, depth + 1) for k, x in v.items() if k not in VOLATILE_EVIDENCE_KEYS}
    if isinstance(v, list):
        return [_strip_volatile(x, depth + 1) for x in v]
    return v


def evidence_fingerprint(obs, tri=None):
    """A hash of what the finding's evidence says, without per-run fields (timestamps, addresses, EPSS), so the same
    evidence in two runs has the same fingerprint and changed evidence has a different one."""
    obs = obs or {}
    ev = loads(obs.get("raw_json"), obs.get("raw_json"))
    doc = {"matched": obs.get("matched"), "verification": obs.get("verification"), "verdict": obs.get("verdict"),
           "exposure": obs.get("exposure"), "evidence": _strip_volatile(ev),
           "items": loads((tri or {}).get("items_json"), None), "secrets": loads((tri or {}).get("secrets_json"), None)}
    return hashlib.sha256(json.dumps(doc, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def current_fingerprints(db, keys):
    """{finding_key: (evidence_fp, last_seen_run)} for the given keys, from each finding's latest observation."""
    out = {}
    if not keys:
        return out
    q = ("SELECT f.finding_key AS k, f.last_seen_run AS run, o.matched, o.verification, o.verdict, o.exposure, o.raw_json, "
         "t.items_json, t.secrets_json FROM findings f LEFT JOIN finding_observations o ON o.finding_key=f.finding_key AND o.run_id=f.last_seen_run "
         "LEFT JOIN finding_triage t ON t.finding_key=f.finding_key AND t.run_id=f.last_seen_run "
         "WHERE f.finding_key IN (SELECT value FROM json_each(?))")
    for r in _rows(db, q, (json.dumps(sorted(keys)),)):
        out[r["k"]] = (evidence_fingerprint(r, r), r["run"])
    return out


def reopened_after(db, keys_seqs):
    """{finding_key} reopened in a run later than the given run seq: [(key, seq)]."""
    out = set()
    for key, seq in list(keys_seqs)[:5000]:
        r = _one(db, "SELECT 1 AS x FROM finding_observations o JOIN runs r ON r.run_id=o.run_id WHERE o.finding_key=? AND "
                     "o.state='reopened' AND r.seq>? LIMIT 1", (key, seq))
        if r:
            out.add(key)
    return out


def _latest_run_with(db, table):
    r = _one(db, f"SELECT t.run_id AS run_id FROM (SELECT DISTINCT run_id FROM {table}) t JOIN runs r ON r.run_id=t.run_id "
                 "ORDER BY r.seq DESC LIMIT 1")
    return r["run_id"] if r else None


def assets(db, run_id=None):
    run_id = run_id or _latest_run_with(db, "asset_observations")
    if not run_id:
        return None, []
    rows = _rows(db, "SELECT a.hostname, a.apex, a.class, a.reason, a.ips, a.cnames, a.tech, a.waf, a.status_code, a.title, a.server, "
                     "a.cert_expiry, p.hosting, p.cdn, p.web_server, p.cms, p.framework, p.tls_max, p.cert_issuer "
                     "FROM asset_observations a LEFT JOIN asset_profiles p ON p.run_id=a.run_id AND p.hostname=a.hostname "
                     "WHERE a.run_id=? ORDER BY a.class, a.hostname LIMIT 5000", (run_id,))
    ports = {}
    for r in _rows(db, "SELECT hostname, port, proto FROM host_ports WHERE run_id=? ORDER BY hostname, port LIMIT 20000", (run_id,)):
        ports.setdefault(r["hostname"], []).append(f"{r['port']}/{r['proto']}")
    for r in rows:
        r["ips"] = listish(r.get("ips"))
        r["tech"] = listish(r.get("tech"), 12)
        r["ports"] = ports.get(r["hostname"], [])[:30]
    return run_id, rows


def asset(db, host, cert_page=1, tls_page=1):
    run_id = None
    r = _one(db, "SELECT a.run_id AS run_id FROM asset_observations a JOIN runs r ON r.run_id=a.run_id WHERE a.hostname=? "
                 "ORDER BY r.seq DESC LIMIT 1", (host,))
    if r:
        run_id = r["run_id"]
    if not run_id:
        return None
    obs = _one(db, "SELECT * FROM asset_observations WHERE run_id=? AND hostname=?", (run_id, host)) or {}
    obs["ips"], obs["cnames"], obs["tech"], obs["urls"] = listish(obs.get("ips")), listish(obs.get("cnames")), listish(obs.get("tech")), listish(obs.get("urls"))
    endpoints = _rows(db, "SELECT url, status, final_url, title, server, content_type, hsts, csp, xfo, emails, generator, powered_by "
                          "FROM endpoints WHERE run_id=? AND hostname=? ORDER BY url LIMIT 200", (run_id, host))
    for e in endpoints:
        em = loads(e.get("emails"), None)
        e["emails"] = (f"{em.get('count')} address(es) at {', '.join(str(x) for x in (em.get('domains') or [])[:10])}"
                       if isinstance(em, dict) and em.get("count") else None)
    certs, certs_more = _page(db, "SELECT port, subject, sans, issuer, key_type, key_bits, sig_alg, not_before, not_after, days_left, "
                                  "expired, self_signed FROM certificates WHERE run_id=? AND hostname=? ORDER BY port", (run_id, host), cert_page)
    tls, tls_more = _page(db, "SELECT port, protocols, legacy, preferred_cipher, weak_ciphers FROM tls_endpoints WHERE run_id=? AND hostname=? "
                              "ORDER BY port", (run_id, host), tls_page)
    return {
        "run_id": run_id, "asset": obs,
        "profile": _one(db, "SELECT * FROM asset_profiles WHERE run_id=? AND hostname=?", (run_id, host)),
        "components": _rows(db, "SELECT category, name, version, source, eol, eol_date FROM asset_components WHERE run_id=? AND hostname=? "
                                "ORDER BY category, name LIMIT 200", (run_id, host)),
        "certificates": certs, "certificates_page": page_number(cert_page), "certificates_more": certs_more,
        "tls": tls, "tls_page": page_number(tls_page), "tls_more": tls_more,
        "ports": _rows(db, "SELECT ip, port, proto, service, product, risky FROM host_ports WHERE run_id=? AND hostname=? ORDER BY port LIMIT 500", (run_id, host)),
        "endpoints": endpoints,
        "dns": _rows(db, "SELECT rtype, name, value, ttl FROM dns_records WHERE run_id=? AND hostname=? ORDER BY rtype, value LIMIT 200", (run_id, host)),
        "findings": _rows(db, f"SELECT {FINDING_COLS} {FINDING_JOIN} WHERE f.hostname=? ORDER BY {SORTS['priority']} LIMIT 200", (host,)),
    }


def domains(db):
    run_id = _latest_run_with(db, "domain_posture")
    if not run_id:
        return None, []
    rows = _rows(db, "SELECT apex, spf, spf_policy, dmarc, dmarc_policy, dmarc_sp, dkim, mx, mx_provider, caa, caa_issuers, nameservers, "
                     "ns_provider, hosts_with_spf, hosts_with_dkim FROM domain_posture WHERE run_id=? ORDER BY apex LIMIT 1000", (run_id,))
    for r in rows:
        r["mx"], r["nameservers"], r["caa_issuers"] = listish(r.get("mx"), 10), listish(r.get("nameservers"), 10), listish(r.get("caa_issuers"), 10)
    return run_id, rows


def inventory(db, run_id):
    """Hosts of one inventory run with class and addresses, for review before approval."""
    rows = _rows(db, "SELECT hostname, apex, class, reason, ips, title, server FROM asset_observations WHERE run_id=? ORDER BY class, hostname LIMIT 5000", (run_id,))
    for r in rows:
        r["ips"] = listish(r.get("ips"))
    return rows


# ---------------------------------------------------------------- for the analyst's tools and the run brief
def components(db, host=None, limit=200):
    """Components (software, version, end of life) of the latest run that has them, optionally for one host."""
    run_id = _latest_run_with(db, "asset_components")
    if not run_id:
        return None, []
    sql = ("SELECT hostname, category, name, version, source, eol, eol_date FROM asset_components WHERE run_id=?"
           + (" AND hostname=?" if host else "") + " ORDER BY hostname, category, name LIMIT ?")
    args = (run_id, host, limit) if host else (run_id, limit)
    return run_id, _rows(db, sql, args)


def expiring_certificates(db, days=30, limit=200):
    """Certificates of the latest run that has them, expiring within `days` (or already expired), soonest first."""
    run_id = _latest_run_with(db, "certificates")
    if not run_id:
        return None, []
    return run_id, _rows(db, "SELECT hostname, port, issuer, subject, not_after, days_left, expired, self_signed FROM certificates "
                             "WHERE run_id=? AND (expired=1 OR (days_left IS NOT NULL AND days_left <= ?)) "
                             "ORDER BY COALESCE(days_left, -100000), hostname, port LIMIT ?", (run_id, int(days), limit))


def run_exists(db, run_id):
    return run_seq(db, run_id) is not None


def diff_runs(db, run_a, run_b, limit=200):
    """What changed between two runs, from the observations each run recorded: findings seen in b and not in a, seen
    in a and not in b, observed as reopened in b, and marked fixed in b."""
    def keys(sql, args):
        return [r["k"] for r in _rows(db, sql, args)]
    obs = "SELECT DISTINCT finding_key AS k FROM finding_observations WHERE run_id=?"
    only_b = keys(f"{obs} AND finding_key NOT IN ({obs.replace('DISTINCT finding_key AS k', 'finding_key')}) ORDER BY k LIMIT ?",
                  (run_b, run_a, limit))
    only_a = keys(f"{obs} AND finding_key NOT IN ({obs.replace('DISTINCT finding_key AS k', 'finding_key')}) ORDER BY k LIMIT ?",
                  (run_a, run_b, limit))
    reopened = keys("SELECT finding_key AS k FROM finding_observations WHERE run_id=? AND state='reopened' ORDER BY k LIMIT ?", (run_b, limit))
    fixed = keys("SELECT finding_key AS k FROM findings WHERE fixed_run=? ORDER BY k LIMIT ?", (run_b, limit))
    return {"seen_only_in_b": only_b, "seen_only_in_a": only_a, "reopened_in_b": reopened, "fixed_in_b": fixed}


def brief_facts(db, limit=200):
    """The numbers and lists a run brief page shows as fact, computed from the snapshot alone (never from the model):
    the latest scored run, the run before it, open findings by band, and the findings new, reopened and fixed in the
    latest scored run."""
    runs_ = _rows(db, "SELECT seq, run_id, kind, started FROM runs WHERE COALESCE(kind, 'full') != 'inventory' ORDER BY seq DESC LIMIT 2")
    out = {"run_id": None, "previous_run_id": None, "bands": band_counts(db), "new": [], "reopened": [], "fixed": [],
           "counts": {"new": 0, "reopened": 0, "fixed": 0}}
    if not runs_:
        return out
    rid = runs_[0]["run_id"]
    out["run_id"] = rid
    out["previous_run_id"] = runs_[1]["run_id"] if len(runs_) > 1 else None
    cols = "f.finding_key, f.hostname, f.title, o.band"
    for state in ("new", "reopened"):
        out[state] = _rows(db, f"SELECT {cols} FROM finding_observations o JOIN findings f ON f.finding_key=o.finding_key "
                               "WHERE o.run_id=? AND o.state=? ORDER BY f.finding_key LIMIT ?", (rid, state, limit))
        n = _one(db, "SELECT COUNT(*) AS n FROM finding_observations WHERE run_id=? AND state=?", (rid, state))
        out["counts"][state] = (n or {}).get("n", 0)
    out["fixed"] = _rows(db, f"SELECT {cols} FROM findings f LEFT JOIN finding_observations o ON o.finding_key=f.finding_key "
                             "AND o.run_id=f.last_seen_run WHERE f.fixed_run=? ORDER BY f.finding_key LIMIT ?", (rid, limit))
    n = _one(db, "SELECT COUNT(*) AS n FROM findings WHERE fixed_run=?", (rid,))
    out["counts"]["fixed"] = (n or {}).get("n", 0)
    return out


def known_ids(db):
    """Every finding key, host name and run id in the snapshot: what the validator checks references against."""
    return {"finding": {r["k"] for r in _rows(db, "SELECT finding_key AS k FROM findings LIMIT 200000")},
            "host": {r["h"] for r in _rows(db, "SELECT hostname AS h FROM findings UNION SELECT hostname FROM asset_observations LIMIT 200000")},
            "run": {r["r"] for r in _rows(db, "SELECT run_id AS r FROM runs LIMIT 100000")}}
