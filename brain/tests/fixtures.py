"""Build a published folder for tests: a snapshot made with the scanner's own schema (scanner/pipeline/ingest.py),
latest.json with its SHA-256, status files, a report, scanner.json, scope_status.json and a version-watch result
(version-watch/php-cgi/<date>.json and latest.json, schema version-watch-v1).
With hostile=True every free-text field carries HOSTILE (script tags, attribute-breaking quotes, javascript: URLs,
template syntax, SQL fragments) and some carry a very long string."""
import hashlib
import json
import os
import sqlite3
import sys

REPO = os.environ.get("MOMUS_REPO") or os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "scanner", "pipeline"))
import ingest  # noqa: E402  the scanner's schema and its column migration

HOSTILE = ("<script>alert('momus-xss')</script>\"'><img src=x onerror=alert(1)><a href=\"javascript:alert(2)\">x</a>"
           " javascript:alert(3) {{ 7*7 }} {% if 1 %}tmpl{% endif %} '; DROP TABLE users; -- \" OR 1=1 --")
LONG = "L" * 50000
K = {"env": "a1b2c3d4e5f6a7b8c9d0", "git": "b1b2c3d4e5f6a7b8c9d0", "cfg": "c1b2c3d4e5f6a7b8c9d0", "fixed": "d1b2c3d4e5f6a7b8c9d0"}


def _t(day, hour=1):
    return f"2030-01-{day:02d}T{hour:02d}:00:00Z"


def build_snapshot(path, hostile=True, extra_runs=False, reopen=False, change_evidence=False):
    """A scan database with an inventory run and two full runs. Options make a third run that reopens the 'fixed'
    finding (reopen) or changes the evidence of the 'env' finding (change_evidence)."""
    if os.path.exists(path):
        os.unlink(path)
    txt = (lambda s: s + " " + HOSTILE) if hostile else (lambda s: s)
    db = sqlite3.connect(path)
    cur = db.cursor()
    db.executescript(ingest.SCHEMA)
    ingest.migrate(cur)
    host = "target.demo.test"
    runs = [("inv-1", "inventory", 1), ("full-1", "full", 2), ("full-2", "full", 3)]
    if reopen or change_evidence:
        runs.append(("full-3", "full", 4))
    for rid, kind, d in runs:
        cur.execute("INSERT INTO runs(run_id, started, finished, inventory_only, kind, snapshot, evidence_level, ingested_at) VALUES(?,?,?,?,?,?,?,?)",
                    (rid, _t(d), _t(d, 2), int(kind == "inventory"), kind, 1, "minimal", _t(d, 3)))
        cur.execute("INSERT INTO asset_observations(run_id, hostname, apex, class, reason, ips, cnames, tech, waf, status_code, title, server, urls, cert_expiry) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (rid, host, "demo.test", "owned", txt("lab target"), json.dumps(["10.89.47.10"]), "[]", json.dumps([txt("Tidewater-httpd 1.4.2")]),
                     txt("none"), 200, txt("Demo shop"), txt("Tidewater-httpd/1.4.2"), json.dumps(["http://target.demo.test/", "javascript:alert(4)"]), "2031-01-01"))
        cur.execute("INSERT INTO asset_observations(run_id, hostname, apex, class, reason, ips, title, server) VALUES(?,?,?,?,?,?,?,?)",
                    (rid, "shadow.demo.test", "demo.test", "unverified", "no owned address", json.dumps(["10.89.47.11" if rid != "full-2" else "10.89.47.12"]),
                     txt("Shadow"), txt("nginx")))
        cur.execute("INSERT INTO asset_profiles(run_id, hostname, hosting, cdn, web_server, cert_issuer, cert_expiry) VALUES(?,?,?,?,?,?,?)",
                    (rid, host, txt("lab"), None, txt("Tidewater-httpd"), txt("Demo CA"), "2031-01-01"))
        cur.execute("INSERT INTO host_ports(run_id, hostname, ip, port, proto, service, product, risky, web) VALUES(?,?,?,?,?,?,?,?,?)",
                    (rid, host, "10.89.47.10", 80, "tcp", "http", txt("Tidewater"), 0, 1))
        cur.execute("INSERT INTO asset_components(run_id, hostname, category, name, version, source, evidence) VALUES(?,?,?,?,?,?,?)",
                    (rid, host, "web_server", txt("Tidewater-httpd"), "1.4.2", "header", txt("Server header")))
        cur.execute("INSERT INTO certificates(run_id, hostname, port, subject, sans, issuer, key_type, key_bits, sig_alg, not_after, days_left, expired, self_signed) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", (rid, host, 443, txt("CN=target"), json.dumps([host]), txt("Demo CA"), "RSA", 2048, "sha256WithRSAEncryption", "2031-01-01", 365, 0, 1))
        cur.execute("INSERT INTO endpoints(run_id, url, hostname, scheme, port, status, final_url, title, server, emails) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (rid, "http://target.demo.test/", host, "http", 80, 200, "javascript:alert(5)", txt("Demo shop"), txt("Tidewater"), json.dumps({"count": 2, "domains": [txt("demo.test")]})))
        cur.execute("INSERT INTO dns_records(run_id, hostname, rtype, name, value, source, ttl) VALUES(?,?,?,?,?,?,?)",
                    (rid, host, "TXT", host, txt("v=spf1 -all"), "dnsx", 300))
        cur.execute("INSERT INTO domain_posture(run_id, apex, spf, spf_policy, dmarc, dmarc_policy, mx, nameservers) VALUES(?,?,?,?,?,?,?,?)",
                    (rid, "demo.test", 1, txt("-all"), 0, None, json.dumps([txt("mx.demo.test")]), json.dumps(["ns1.demo.test"])))

    def finding(key, check, title, band, score, first, last, status, fixed_run=None, port=80):
        cur.execute("INSERT INTO findings VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (key, host, "demo.test", "nuclei", check, port, txt(title), band.lower(), "", first, last, status, fixed_run))

    def obs(rid, key, band, score, state, matched="/.env", ev_extra=None, ts="2030-01-01T00:00:00Z"):
        raw = {"template-id": "generic-env", "matched-at": matched, "timestamp": ts, "ip": "10.89.47.10",
               "extracted-results": [txt("DB_PASSWORD=<REDACTED>")], "info": {"name": txt("Env file")}}
        if ev_extra:
            raw.update(ev_extra)
        cur.execute("INSERT INTO finding_observations(run_id, finding_key, asset_class, matched, description, remediation, reference, tags, cvss, epss, kev, "
                    "impact, likelihood, score, band, sla_days, state, raw_json, verdict, verification, exposure) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (rid, key, "owned", matched, txt("Description") + LONG[:3000], txt("Remove the file"), json.dumps(["javascript:alert(6)", "https://example.test/ref"]),
                     json.dumps(["exposure", txt("tag")]), 7.5, 0.1, 0, 4, 4, score, band, 7, state, json.dumps(raw), "confirmed", txt("matched"), "credential"))

    last_full = "full-3" if (reopen or change_evidence) else "full-2"
    finding(K["env"], "generic-env", "Env file exposed", "High", 80, "full-1", last_full, "open")
    finding(K["git"], "git-config", "Git config exposed", "Medium", 60, "full-1", last_full, "open")
    finding(K["cfg"], "configuration-listing", "Config listing", "Medium", 55, "full-2", last_full, "open")
    if reopen:
        finding(K["fixed"], "http-missing-security-headers", "Missing headers", "Low", 20, "full-1", "full-3", "open")
    else:
        finding(K["fixed"], "http-missing-security-headers", "Missing headers", "Low", 20, "full-1", "full-1", "fixed", fixed_run="full-2")
    obs("full-1", K["env"], "High", 80, "new", ts="2030-01-02T00:00:00Z")
    obs("full-1", K["git"], "Medium", 60, "new", matched="/.git/config")
    obs("full-1", K["fixed"], "Low", 20, "new", matched="/")
    obs("full-2", K["env"], "High", 80, "persistent", ts="2030-01-03T00:00:00Z")
    obs("full-2", K["git"], "Medium", 60, "persistent", matched="/.git/config")
    obs("full-2", K["cfg"], "Medium", 55, "new", matched="/config/")
    if reopen or change_evidence:
        obs("full-3", K["env"], "High", 80, "persistent", ts="2030-01-04T00:00:00Z",
            ev_extra={"extracted-results": ["DIFFERENT"]} if change_evidence else None)
        obs("full-3", K["git"], "Medium", 60, "persistent", matched="/.git/config")
        obs("full-3", K["cfg"], "Medium", 55, "persistent", matched="/config/")
        if reopen:
            obs("full-3", K["fixed"], "Low", 20, "reopened", matched="/")
    cur.execute("INSERT INTO finding_triage VALUES(?,?,?,?,?,?,?,?,?)",
                ("full-2", K["env"], "credential", txt("Env file holds credentials"), txt("Rotate"), json.dumps([txt("/.env")]),
                 json.dumps([{"type": "aws_key", "masked": "AKIA...[20 chars]", "where": txt("/.env"), "line": 3}]), 0, _t(3)))
    for rid, *_ in runs:
        if rid == "inv-1":
            continue
        n = cur.execute("SELECT band, COUNT(*) FROM finding_observations WHERE run_id=? GROUP BY band", (rid,)).fetchall()
        bands = {b: 0 for b in ("Critical", "High", "Medium", "Low")}
        bands.update(dict(n))
        cur.execute("INSERT INTO run_summary VALUES(?,?)", (rid, json.dumps({"run_id": rid, "bands": bands, "total": sum(bands.values()),
                                                                             "new": 1, "reopened": 1 if rid == "full-3" and reopen else 0,
                                                                             "fixed": 1 if rid == "full-2" else 0, "kind": "full"})))
    db.commit()
    db.close()


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        h.update(fh.read())
    return h.hexdigest()


def build_published(pub, hostile=True, **kw):
    os.makedirs(os.path.join(pub, "snapshots"), exist_ok=True)
    os.makedirs(os.path.join(pub, "status"), exist_ok=True)
    os.makedirs(os.path.join(pub, "version-watch"), exist_ok=True)
    run = "full-3" if kw.get("reopen") or kw.get("change_evidence") else "full-2"
    snap = os.path.join(pub, "snapshots", f"{run}.sqlite")
    build_snapshot(snap, hostile=hostile, **kw)
    write_latest(pub, run)
    h = HOSTILE if hostile else "ok"
    for jid, typ, state in (("inv-1", "inventory", "done"), ("full-1", "full", "done"), ("full-2", "full", "done"), ("bad-1", "full", "rejected")):
        doc = {"schema": "momus-status-v1", "job_id": jid, "type": typ, "state": state, "run_id": jid if state == "done" else None,
               "queued_at": "2030-01-01T00:00:00Z", "updated_at": "2030-01-01T00:00:00Z", "phase": None,
               "reason": f"rejected: {h}" if state == "rejected" else None, "counts": {"assets": 2, h[:30]: 1}, "exit_codes": {}}
        with open(os.path.join(pub, "status", f"{jid}.json"), "w") as fh:
            json.dump(doc, fh)
    rep = os.path.join(pub, "reports", "full-2")
    os.makedirs(rep, exist_ok=True)
    with open(os.path.join(rep, "full-2.html"), "w") as fh:
        fh.write(f"<html><body><script>alert('report')</script>{h}</body></html>")
    with open(os.path.join(rep, "full-2-findings.csv"), "w") as fh:
        fh.write(f"title\n\"{h}\"\n")
    with open(os.path.join(pub, "scanner.json"), "w") as fh:
        json.dump({"schema": "momus-scanner-v1", "updated_at": "2030-01-01T00:00:00Z", "state": "idle", "current_job": None,
                   "lab_mode": True, "lab_cidr": "10.89.47.0/24", "tools": {"nuclei": h}, "profiles": {"check_profile": "safe"},
                   "templates": {"count": 14000, "date": "2030-01-01T00:00:00Z", "version": h[:40], "source": "baked into the image"}}, fh)
    with open(os.path.join(pub, "scope_status.json"), "w") as fh:
        json.dump({"schema": "momus-scope-status-v1", "updated_at": "2030-01-01T00:00:00Z", "domains": {
            "example.test": {"state": "pending", "txt_name": "_scan-verify.example.test", "txt_value": f"scan-verify={h}", "last_checked_at": None}}}, fh)
    write_watch_result(pub, "php-cgi", "2030-01-02", hostile=hostile)
    return run


WATCH_ID = "php-cgi"


def watch_doc(watch_id, date, hostile=True, suspect=False, hosts=None):
    """A version-watch-v1 result as scanner/pipeline/version_watch.py build_doc writes it. With hostile=True the
    target-derived Server text and the reason carry HOSTILE."""
    h = HOSTILE if hostile else "Apache"
    rows = hosts if hosts is not None else [
        {"hostname": "target.demo.test", "domain": "demo.test", "version": "8.1.2", "verdict": "FAIL",
         "reason": "8.1.2 is below 8.1.29" + (" " + HOSTILE if hostile else ""), "read_from": "http x-powered-by",
         "https_status": None, "http_status": 200, "server": h, "scan_db_version": "8.1.2", "source": "both"},
        {"hostname": "notice.demo.test", "domain": "demo.test", "version": None, "verdict": "UNKNOWN",
         "reason": "HTTP - (https) / 200 (http), no PHP version in the headers (hidden or not PHP)", "read_from": None,
         "https_status": None, "http_status": 200, "server": "nginx", "scan_db_version": None, "source": "job"}]
    head = {"hosts": len(rows), "fail": sum(r.get("verdict") == "FAIL" for r in rows), "pass": sum(r.get("verdict") == "PASS" for r in rows),
            "unknown": sum(r.get("verdict") == "UNKNOWN" for r in rows), "unreachable": sum(r.get("verdict") == "UNREACHABLE" for r in rows)}
    doc = {"schema": "version-watch-v1", "watch": {"id": watch_id, "name": "PHP CGI argument injection", "product": "php", "product_name": "PHP"},
           "job_id": "vw-20300102-040000-abcdef", "generated_at": f"{date}T04:00:00Z", "date": date, "cves": ["CVE-2099-0003"],
           "floors": {"8.1": "8.1.29", "8.2": "8.2.20", "8.3": "8.3.8"},
           "method": "GET / over https and http (same-host redirects followed, at most 3), response headers only (X-Powered-By, Server); no crafted request",
           "target_derived": ["hosts[].server"],
           "targets": {"total": len(rows), "from_scan_db": 1, "from_job": 1, "carried": 0, "not_probed": 0, "scan_db_run": "full-2"},
           "headline": head,
           "by_version": [{"version": "8.1.2", "branch": "8.1", "verdict": "FAIL", "reason": "8.1.2 is below 8.1.29", "hosts": 1}],
           "by_domain": [{"domain": "demo.test", **head}],
           "hosts": rows,
           "changes": {"since": "2030-01-01", "items": [{"hostname": "target.demo.test", "from_version": "8.1.1", "to_version": "8.1.2",
                                                         "from_verdict": "FAIL", "to_verdict": "FAIL"},
                                                        {"hostname": "notice.demo.test", "from_version": None, "to_version": None,
                                                         "from_verdict": None, "to_verdict": "UNKNOWN"}]},
           "history": [{"date": "2030-01-01", "hosts": 1, "fail": 1, "pass": 0, "unknown": 0, "unreachable": 0}, {"date": date, **head}]}
    return {"suspect": True, **doc} if suspect else doc


def write_watch_result(pub, watch_id, date, hostile=True, suspect=False, latest=True, doc=None):
    """Write <date>.json (and latest.json unless the run was suspect or latest=False), as the scanner does."""
    d = os.path.join(pub, "version-watch", watch_id)
    os.makedirs(d, exist_ok=True)
    doc = doc if doc is not None else watch_doc(watch_id, date, hostile=hostile, suspect=suspect)
    text = json.dumps(doc, indent=1) + "\n"
    with open(os.path.join(d, f"{date}.json"), "w") as fh:
        fh.write(text)
    if latest and not suspect:
        with open(os.path.join(d, "latest.json"), "w") as fh:
            fh.write(text)
    return doc


def write_latest(pub, run, digest=None):
    snap = os.path.join(pub, "snapshots", f"{run}.sqlite")
    with open(os.path.join(pub, "snapshots", "latest.json"), "w") as fh:
        json.dump({"schema": "momus-snapshot-v1", "run_id": run, "job_id": run, "file": f"{run}.sqlite",
                   "sha256": digest or sha(snap), "created_at": "2030-01-05T00:00:00Z"}, fh)
