#!/usr/bin/env python3
"""check_demo.py - assertions for tests/e2e/run_demo.sh over the published folder (read-only), standard library only.
Runs inside a container with no network. Prints PASS/FAIL lines; exit 1 if any check failed.

  check_demo.py results  --published DIR --job JOB_ID --expect ID[,ID...]
  check_demo.py canaries --published DIR --canaries FILE --logs DIR
  check_demo.py scope    --published DIR --canaries FILE --domain NAME [--raw DIR]   (DIR: the scanner's data volume)
  check_demo.py watch    --published DIR --canaries FILE --job ID --watch ID     (the lab version-watch job)
"""
import argparse
import base64
import hashlib
import hmac
import html
import re
import json
import os
import sqlite3
import sys
from urllib.parse import quote, quote_plus

results = []


def check(name, ok, detail=""):
    results.append(bool(ok))
    print(f"{'PASS' if ok else 'FAIL'} {name}" + ("" if ok or not detail else f"  [{detail}]"), flush=True)


def load_json(p):
    with open(p) as fh:
        return json.load(fh)


def results_checks(a):
    st = load_json(os.path.join(a.published, "status", f"{a.job}.json"))
    check(f"3 full job {a.job} ends done", st.get("state") == "done", f"state={st.get('state')} codes={st.get('exit_codes')}")
    latest = load_json(os.path.join(a.published, "snapshots", "latest.json"))
    snap = os.path.join(a.published, "snapshots", latest.get("file", "missing"))
    check("3 latest.json names this job's snapshot", latest.get("run_id") == st.get("run_id") and os.path.basename(snap) == st.get("snapshot"),
          f"latest={latest.get('file')} status={st.get('snapshot')}")
    h = hashlib.sha256()
    with open(snap, "rb") as fh:
        h.update(fh.read())
    check("3 latest.json SHA-256 matches the snapshot file", h.hexdigest() == latest.get("sha256"))
    db = sqlite3.connect(f"file:{snap}?mode=ro", uri=True)
    check("3 snapshot opens as a valid SQLite database (integrity_check ok)", db.execute("PRAGMA integrity_check").fetchone()[0] == "ok")
    rows = db.execute("SELECT f.check_id, o.verdict, o.exposure, o.band FROM findings f JOIN finding_observations o USING(finding_key) "
                      "WHERE o.run_id=?", (st.get("run_id"),)).fetchall()
    by = {r[0]: r for r in rows}
    for cid in a.expect.split(","):
        r = by.get(cid)
        check(f"3 demo finding {cid} present with a verdict", r is not None and r[1] is not None,
              f"found={sorted(by)}" if r is None else f"verdict={r[1]}")
    db.close()
    rep = os.path.join(a.published, "reports", st.get("run_id", "x"))
    page = open(os.path.join(rep, f"{st.get('run_id')}.html"), encoding="utf-8").read()
    canon = load_json(a.canaries)
    title = canon["script"]["title"]
    escaped = html.escape(title[:60], quote=True)
    check("5 the script-tag title appears escaped in the HTML report", escaped in page, escaped)
    check("5 the script-tag title never appears as a live tag in the HTML report",
          "<script>alert(" not in page and title not in page)
    check("5 the CSV export carries the title as text", any(title in open(os.path.join(rep, f), encoding="utf-8").read()
                                                            for f in os.listdir(rep) if f.endswith(".csv")))


def variants(v):
    out = {v, v.lower(), quote(v, safe=""), quote_plus(v), json.dumps(v)[1:-1], html.escape(v, quote=True)}
    for i in range(3):   # base64 at the three alignments (middle of the encoding of the value)
        b = base64.b64encode(("x" * i + v).encode()).decode()
        out.add(b[4:-4])
    return {x for x in out if len(x) >= 8}


def watch_checks(a):
    st = load_json(os.path.join(a.published, "status", f"{a.job}.json"))
    check(f"3b version-watch job {a.job} ends done", st.get("state") == "done", f"state={st.get('state')} codes={st.get('exit_codes')}")
    d = os.path.join(a.published, "version-watch", a.watch)
    names = sorted(os.listdir(d)) if os.path.isdir(d) else []
    check("3b the watch's results are published as <date>.json and latest.json in its own folder",
          len(names) == 2 and "latest.json" in names and all(n == "latest.json" or n[:4].isdigit() for n in names), str(names))
    doc = load_json(os.path.join(d, "latest.json")) if "latest.json" in names else {}
    check("3b schema version-watch-v1, not suspect, the target-derived list is exactly hosts[].server",
          doc.get("schema") == "version-watch-v1" and "suspect" not in doc and doc.get("target_derived") == ["hosts[].server"],
          json.dumps({k: doc.get(k) for k in ("schema", "suspect", "target_derived")}))
    rows = {h.get("hostname"): h for h in doc.get("hosts") or []}
    t = rows.get("target.demo.test") or {}
    check("3b the demo target fails the example watch: PHP 8.2.20 is below 8.2.35, read from X-Powered-By over http",
          (t.get("verdict"), t.get("version"), t.get("reason"), t.get("read_from")) == ("FAIL", "8.2.20", "8.2.20 is below 8.2.35", "http x-powered-by"),
          json.dumps(t))
    n = rows.get("notice.demo.test") or {}
    check("3b the other lab target answers without a PHP version: UNKNOWN", n.get("verdict") == "UNKNOWN", json.dumps(n))


def canary_checks(a):
    doc = load_json(a.canaries)
    secrets = {k: "".join(v["parts"]) for k, v in doc["secrets"].items()}
    sinks = []
    snapdir = os.path.join(a.published, "snapshots")
    for f in sorted(os.listdir(snapdir)):
        p = os.path.join(snapdir, f)
        if f.endswith(".sqlite"):
            with open(p, "rb") as fh:
                sinks.append((f"snapshot {f} (bytes)", fh.read().decode("latin-1")))
            db = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
            dump = []
            for (t,) in db.execute("SELECT name FROM sqlite_master WHERE type='table'"):
                for row in db.execute(f'SELECT * FROM "{t}"'):
                    dump.append(repr(row))
            db.close()
            sinks.append((f"snapshot {f} (every row)", "\n".join(dump)))
    groups = {"report": ["reports"], "status": ["status", "scope_status.json", "scanner.json", "snapshots/latest.json", "version-watch",
                                                "held_back.json"]}
    for label, rels in groups.items():
        for rel in rels:
            base = os.path.join(a.published, rel)
            files = [base] if os.path.isfile(base) else [os.path.join(d, f) for d, _, fs in os.walk(base) for f in fs]
            for p in files:
                with open(p, "rb") as fh:
                    sinks.append((f"{label} {os.path.relpath(p, a.published)}", fh.read().decode("utf-8", "replace")))
    for f in sorted(os.listdir(a.logs)):
        with open(os.path.join(a.logs, f), "rb") as fh:
            sinks.append((f"container log {f}", fh.read().decode("utf-8", "replace")))
    if a.control:   # positive control: the raw tool output on the scanner's own volume holds canaries (those nuclei
                    # recorded; the files only triage fetched are not kept raw), so a clean result below is not vacuous
        raw = []
        for d, _, fs in os.walk(a.control):
            for f in fs:
                with open(os.path.join(d, f), "rb") as fh:
                    raw.append(fh.read().decode("utf-8", "replace"))
        raw = "\n".join(raw)
        found = sorted(k for k, v in secrets.items() if any(x in raw for x in variants(v)))
        check(f"4 control: the same search finds canaries in the raw run output ({len(found)} of {len(secrets)})",
              len(found) >= 1, ", ".join(found))
    n_watch = sum(1 for name, _ in sinks if name.startswith("status version-watch/") and name.count("/") >= 2)
    check("4 control: the canary search read the version-watch result files in their watch folders", n_watch >= 2, str(n_watch))
    kinds = {"snapshot": 0, "report": 0, "status": 0, "container log": 0}
    for name, _ in sinks:
        for k in kinds:
            if name.startswith(k):
                kinds[k] += 1
    check("4 every sink kind was read (snapshot, report and CSVs, status files, container logs)", all(kinds.values()), str(kinds))
    for key, value in sorted(secrets.items()):
        hits = sorted({name for name, text in sinks for v in variants(value) if v in text})
        check(f"4 canary {key} appears in no snapshot, report, CSV, status file or container log", not hits, ", ".join(hits[:5]))


def scope_checks(a):
    """After a scope-sync job: the published record is the one derived from this install's secret, the domain is
    pending (its TXT record is not published anywhere), it was checked, and the secret is in no published file."""
    ss = load_json(os.path.join(a.published, "scope_status.json"))
    e = (ss.get("domains") or {}).get(a.domain) or {}
    check(f"2 scope_status.json lists {a.domain} with the TXT record to publish",
          e.get("txt_name") == f"_scan-verify.{a.domain}" and re.fullmatch(r"scan-verify=[0-9a-f]{32}", e.get("txt_value") or ""), json.dumps(e))
    check(f"2 {a.domain} is pending and was checked by the scope-sync job (last result {e.get('last_result')})",
          e.get("state") == "pending" and e.get("last_checked_at") and e.get("last_result") in ("failure", "mismatch"), json.dumps(e))
    check("2 scope_status.json carries the install key id and no notice (the secret was never replaced)",
          re.fullmatch(r"[0-9a-f]{16}", ss.get("install_key_id") or "") and ss.get("notice") is None, json.dumps({k: ss.get(k) for k in ("install_key_id", "notice")}))
    with open(os.path.join(a.raw, "state", "install_secret")) as fh:
        secret_hex = fh.read().strip()
    secret = bytes.fromhex(secret_hex)
    token = hmac.new(secret, b"momus-dns-proof-v1\n" + a.domain.encode(), hashlib.sha256).hexdigest()[:32]
    check("2 the published record is exactly the one the proof check expects (HMAC of the install secret and the domain)",
          e.get("txt_value") == "scan-verify=" + token)
    leaked = []
    for d, _, fs in os.walk(a.published):
        for f in fs:
            with open(os.path.join(d, f), "rb") as fh:
                data = fh.read()
            if f == "install_secret" or secret_hex.encode() in data or secret in data:
                leaked.append(os.path.relpath(os.path.join(d, f), a.published))
    check("2 the install secret is in no published file", not leaked, ", ".join(leaked[:5]))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=("results", "canaries", "scope", "watch"))
    ap.add_argument("--domain")
    ap.add_argument("--raw", default="/raw", help="scope mode: the scanner's data volume (read-only)")
    ap.add_argument("--published", required=True)
    ap.add_argument("--canaries", required=True)
    ap.add_argument("--job")
    ap.add_argument("--watch", help="watch mode: the watch id")
    ap.add_argument("--expect", default="")
    ap.add_argument("--logs")
    ap.add_argument("--control", help="canaries mode: a folder that must contain canaries (proves the search works)")
    a = ap.parse_args()
    try:
        {"results": results_checks, "canaries": canary_checks, "scope": scope_checks, "watch": watch_checks}[a.mode](a)
    except Exception as e:   # a missing file is a failure, not a crash
        check(f"{a.mode} checks ran to the end", False, f"{type(e).__name__}: {e}")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
