#!/usr/bin/env python3
"""report.py - render reports/<RUN_ID>.html from data/scan.sqlite (stdlib only, self-contained HTML)."""
import argparse, csv, datetime as dt, html, json, os, re, sqlite3, sys
from urllib.parse import quote, urlsplit
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from triage import LEGACY_FIX
import settings

CATEGORY_LABEL = {"os": "Operating system", "web_server": "Web server", "language": "Language / runtime", "framework": "Framework",
                  "cms": "Application / CMS", "js_library": "Front-end library", "cdn": "CDN", "waf": "WAF", "load_balancer": "Load balancer / proxy",
                  "hosting": "Hosting", "service": "Service / module", "tls": "TLS", "analytics": "Analytics / tags", "other": "Other"}
CATEGORY_ORDER = list(CATEGORY_LABEL)
PROFILE_COLS = ["hostname", "apex", "class", "hosting", "hosting_source", "asn", "as_name", "cdn", "waf", "load_balancer", "os", "web_server",
                "language", "framework", "cms", "tls_min", "tls_max", "cert_issuer", "cert_expiry", "eol_count"]

BAND_ORDER = ["Critical", "High", "Medium", "Low"]
BAND_COLOR = {"Critical": "#d03b3b", "High": "#ec835a", "Medium": "#fab219", "Low": "#0ca30c"}
BAND_ICON = {"Critical": "&#9632;", "High": "&#9650;", "Medium": "&#9679;", "Low": "&#9671;"}
# verify.py verdicts that mean the finding exposes nothing readable (the same set scoring.py scores down)
NOISE_VERDICTS = {"names_only", "empty", "redirect", "gone"}
# triage.py exposures, strongest first; the Fix list groups by these within each domain
EXPOSURE_ORDER = ["credential", "data", "source", "config", "internal", "names", "nothing", "unknown"]
EXPOSURE_LABEL = {"credential": "Credentials readable", "data": "Customer or personal data readable", "source": "Source code readable",
                  "config": "Configuration readable", "internal": "Internal names and versions", "names": "File names only",
                  "nothing": "Nothing readable", "unknown": "Not triaged"}
FIXLIST_COLS = ["apex", "hostname", "port", "band", "score", "exposure", "summary", "fix", "due", "finding_key", "check_id", "title", "matched", "items"]
CLASS_LABEL = {"owned": "Owned", "unverified": "Unverified", "cdn_fronted": "CDN-fronted", "third_party": "Third-party", "internal": "Internal IP", "dead": "Unresolved", "excluded": "Excluded"}

def sla_text(policy):
    """Fix-by days per band from the SLA policy in effect (settings.py / config/policy.json), never hard-coded."""
    parts = []
    for b in BAND_ORDER:
        d, s = policy["sla_days"].get(b), policy["strict_sla_days"].get(b)
        parts.append(f"{b} {s}d on a strict-SLA host or {d}d elsewhere" if s and s != d else f"{b} {d}d")
    return ", ".join(parts)

def strict_hosts_text(policy):
    """What the strict-SLA host list does (scoring.py): the shorter allowance, and a higher impact floor."""
    return (f"Hosts in scope/{policy['strict_sla_hosts_file']} get the strict-SLA allowance and a higher impact floor: "
            "a readable credential or personal data scores impact 5 there (4 elsewhere).")

def esc(x):
    """Text and attribute values (every attribute in this page is quoted): & < > " ' escaped."""
    return html.escape("" if x is None else str(x))

def safe_href(u):
    """A link target taken from data: only http(s) URLs become links (no javascript:, data: or relative tricks)."""
    try:
        ok = urlsplit(str(u or "")).scheme.lower() in ("http", "https")
    except ValueError:
        ok = False
    return esc(u) if ok else None

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)

def cve_link(c):
    if not CVE_RE.fullmatch(c or ""):
        return esc(c)
    return f"<a href='https://nvd.nist.gov/vuln/detail/{esc(quote(c))}' target='_blank' rel='noopener'>{esc(c)}</a>"

FORMULA_LEAD = ("=", "+", "-", "@", "\t", "\r")

def csv_cell(v):
    """A string cell a spreadsheet would read as a formula (= + - @ tab CR first) gets a leading apostrophe.
    Numbers stay numbers (a negative days_left is not text)."""
    if isinstance(v, str) and v.startswith(FORMULA_LEAD):
        return "'" + v
    return v

class SafeWriter:
    """csv.writer with every cell through csv_cell."""
    def __init__(self, fh):
        self.w = csv.writer(fh)
    def writerow(self, row):
        self.w.writerow([csv_cell(v) for v in row])

def q(db, sql, *args):
    cur = db.execute(sql, args)
    cols = [c[0] for c in cur.description]
    return [dict(zip(cols, r)) for r in cur.fetchall()]

# ---------------------------------------------------------------- charts (inline SVG)
def chart_bands_by_run(runs, series):
    """Stacked bars: open findings per run, one segment per band. runs: [run_id], series: {band: [count per run]}"""
    if not runs:
        return "<p class='muted'>No scored runs yet.</p>"
    W, H, L, B, T, R = 760, 260, 44, 40, 16, 16
    pw, ph = W - L - R, H - T - B
    totals = [sum(series[b][i] for b in BAND_ORDER) for i in range(len(runs))]
    ymax = max(totals + [1])
    n = len(runs); slot = pw / n; bw = min(48, slot * 0.6)
    out = [f"<svg class='chart' viewBox='0 0 {W} {H}' role='img' aria-label='Open findings by severity band per run'>"]
    for k in range(5):
        y = T + ph - ph * k / 4; v = round(ymax * k / 4)
        out.append(f"<line x1='{L}' y1='{y:.1f}' x2='{W-R}' y2='{y:.1f}' class='grid'/><text x='{L-6}' y='{y+4:.1f}' class='tick' text-anchor='end'>{v}</text>")
    for i, r in enumerate(runs):
        x = L + slot * i + (slot - bw) / 2; ybase = T + ph
        for b in reversed(BAND_ORDER):  # Low at bottom, Critical on top
            c = series[b][i]
            if not c: continue
            h = ph * c / ymax; ybase -= h
            out.append(f"<rect x='{x:.1f}' y='{ybase+1:.1f}' width='{bw:.1f}' height='{max(h-2,0):.1f}' rx='2' fill='{BAND_COLOR[b]}'><title>{esc(r)}: {c} {b}</title></rect>")
        out.append(f"<text x='{x+bw/2:.1f}' y='{T+ph-ph*totals[i]/ymax-6:.1f}' class='val' text-anchor='middle'>{totals[i]}</text>")
        out.append(f"<text x='{x+bw/2:.1f}' y='{H-B+16}' class='tick' text-anchor='middle'>{esc(r)}</text>")
    out.append("</svg>")
    leg = "".join(f"<span class='lg'><i style='background:{BAND_COLOR[b]}'></i>{b}</span>" for b in BAND_ORDER)
    return "".join(out) + f"<div class='legend'>{leg}</div>"

def chart_line(runs, values, label, color="#2a78d6"):
    if not runs:
        return ""
    W, H, L, B, T, R = 760, 200, 44, 40, 16, 16
    pw, ph = W - L - R, H - T - B
    ymax = max(values + [1]); n = len(runs)
    xs = [L + (pw * (i + 0.5) / n) for i in range(n)]
    ys = [T + ph - ph * v / ymax for v in values]
    out = [f"<svg class='chart' viewBox='0 0 {W} {H}' role='img' aria-label='{esc(label)} per run'>"]
    for k in range(5):
        y = T + ph - ph * k / 4
        out.append(f"<line x1='{L}' y1='{y:.1f}' x2='{W-R}' y2='{y:.1f}' class='grid'/><text x='{L-6}' y='{y+4:.1f}' class='tick' text-anchor='end'>{round(ymax*k/4)}</text>")
    if n > 1:
        out.append("<polyline fill='none' stroke='%s' stroke-width='2' points='%s'/>" % (color, " ".join(f"{x:.1f},{y:.1f}" for x, y in zip(xs, ys))))
    for i in range(n):
        out.append(f"<circle cx='{xs[i]:.1f}' cy='{ys[i]:.1f}' r='4.5' fill='{color}' stroke='var(--surface)' stroke-width='2'><title>{esc(runs[i])}: {values[i]}</title></circle>")
        out.append(f"<text x='{xs[i]:.1f}' y='{ys[i]-10:.1f}' class='val' text-anchor='middle'>{values[i]}</text>")
        out.append(f"<text x='{xs[i]:.1f}' y='{H-B+16}' class='tick' text-anchor='middle'>{esc(runs[i])}</text>")
    out.append("</svg>")
    return "".join(out)

# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True); ap.add_argument("--run-id", required=True)
    a = ap.parse_args()
    db = sqlite3.connect(os.path.join(a.root, "data", "scan.sqlite"))
    run = q(db, "SELECT * FROM runs WHERE run_id=?", a.run_id)
    if not run:
        sys.exit(f"run {a.run_id} not ingested")
    run = run[0]
    seq = run["seq"]
    # a full run compares with the previous full run; a daily recheck with the full run it refines (its base)
    kind = run.get("kind") or ("inventory" if run["inventory_only"] else "full")
    if kind == "recheck":
        prev = q(db, "SELECT * FROM runs WHERE run_id=?", run["base_run"])
    else:
        prev = q(db, "SELECT * FROM runs WHERE COALESCE(kind,'full')='full' AND inventory_only=0 AND seq<? ORDER BY seq DESC LIMIT 1", seq)
    prev = prev[0] if prev else None
    scored_runs = q(db, "SELECT run_id FROM runs WHERE inventory_only=0 AND seq<=? ORDER BY seq", seq)
    scored_ids = [r["run_id"] for r in scored_runs]
    summaries = {r["run_id"]: json.loads(r["json"]) for r in q(db, "SELECT run_id, json FROM run_summary")} if q(db, "SELECT 1 FROM sqlite_master WHERE name='run_summary'") else {}
    retested = {r["hostname"] for r in q(db, "SELECT hostname FROM recheck_hosts WHERE run_id=?", a.run_id)} if kind == "recheck" else set()

    # verify.py verdict columns exist once ingest.py has migrated the database (NULL for runs ingested before)
    has_verdict = any(r["name"] == "verdict" for r in q(db, "PRAGMA table_info(finding_observations)"))
    vcols = "o.verdict, o.verification" if has_verdict else "NULL verdict, NULL verification"
    # triage.py: the exposure column and the finding_triage table exist once ingest.py has migrated the database
    has_exposure = any(r["name"] == "exposure" for r in q(db, "PRAGMA table_info(finding_observations)"))
    has_triage = bool(q(db, "SELECT 1 FROM sqlite_master WHERE type='table' AND name='finding_triage'"))
    vcols += ", o.exposure" if has_exposure else ", NULL exposure"
    tcols, tjoin = ((", t.summary triage_summary, t.fix triage_fix, t.items_json triage_items, t.secrets_json triage_secrets",
                     " LEFT JOIN finding_triage t ON t.run_id=o.run_id AND t.finding_key=o.finding_key") if has_triage else
                    (", NULL triage_summary, NULL triage_fix, NULL triage_items, NULL triage_secrets", ""))
    findings = q(db, f"""SELECT f.*, o.asset_class,o.matched,o.description,o.remediation,o.reference,o.tags,o.cvss,o.epss,o.kev,o.impact,o.likelihood,o.score,o.band,o.sla_days,o.state,{vcols}{tcols}
                        FROM finding_observations o JOIN findings f ON f.finding_key=o.finding_key{tjoin} WHERE o.run_id=? ORDER BY o.score DESC, o.impact DESC, f.hostname""", a.run_id)
    fixed = q(db, "SELECT * FROM findings WHERE status='fixed' AND fixed_run=? ORDER BY hostname", a.run_id)
    assets = q(db, "SELECT * FROM asset_observations WHERE run_id=? ORDER BY apex, class, hostname", a.run_id)
    profiles = {r["hostname"]: r for r in q(db, "SELECT * FROM asset_profiles WHERE run_id=?", a.run_id)}
    components = q(db, "SELECT * FROM asset_components WHERE run_id=? ORDER BY hostname, category, name, version", a.run_id)
    comp_track = {(r["hostname"], r["category"], r["name"], r["version"]): r for r in q(db, "SELECT * FROM components")}
    first_seen = {r["hostname"]: r["first_seen_run"] for r in q(db, "SELECT hostname, first_seen_run FROM assets")}
    prev_assets = {r["hostname"]: r for r in q(db, "SELECT hostname,class FROM asset_observations WHERE run_id=?", prev["run_id"])} if prev else {}

    band_counts = {b: sum(1 for f in findings if f["band"] == b) for b in BAND_ORDER}
    state_counts = {s: sum(1 for f in findings if f["state"] == s) for s in ("new", "persistent", "reopened")}
    kev_hits = [f for f in findings if f["kev"]]
    verified_noise = sum(1 for f in findings if f["verdict"] in NOISE_VERDICTS)
    class_counts = {}
    for x in assets:
        class_counts[x["class"]] = class_counts.get(x["class"], 0) + 1
    # "new" = not present in the previous scored run (inventory-only runs may have seen a host earlier; that does not count)
    new_assets = [x for x in assets if prev and x["hostname"] not in prev_assets and x["class"] != "dead"]
    new_tp = [x for x in new_assets if x["class"] == "third_party"]
    gone_assets = sorted(set(prev_assets) - {x["hostname"] for x in assets}) if prev else []

    # trend series
    trend = {b: [] for b in BAND_ORDER}; asset_trend = []
    for rid in scored_ids:
        # a recheck's carried rows are pruned once two newer snapshots exist; its counts live in run_summary
        if rid in summaries:
            for b in BAND_ORDER: trend[b].append(summaries[rid]["bands"].get(b, 0))
            asset_trend.append(summaries[rid]["hosts_live"]); continue
        rows = q(db, "SELECT band, COUNT(*) c FROM finding_observations WHERE run_id=? GROUP BY band", rid)
        d = {r["band"]: r["c"] for r in rows}
        for b in BAND_ORDER: trend[b].append(d.get(b, 0))
        asset_trend.append(q(db, "SELECT COUNT(*) c FROM asset_observations WHERE run_id=? AND class!='dead'", rid)[0]["c"])
    all_runs = q(db, "SELECT run_id, inventory_only, finished, COALESCE(kind,'') kind FROM runs WHERE seq<=? ORDER BY seq", seq)

    # MTTR (fixed findings: days between first_seen run finish and fixed run finish)
    mttr_rows = q(db, """SELECT f.severity, COUNT(*) n, AVG(julianday(r2.finished)-julianday(r1.finished)) d FROM findings f
                         JOIN runs r1 ON r1.run_id=f.first_seen_run JOIN runs r2 ON r2.run_id=f.fixed_run WHERE f.status='fixed' GROUP BY f.severity""")

    tools = json.loads(run["tools_json"] or "{}") or {}; counts = json.loads(run["counts_json"] or "{}") or {}; phases = json.loads(run["phases_json"] or "[]") or []
    gen = dt.datetime.now().strftime("%Y-%m-%d %H:%M")
    run_date = (run["finished"] or run["ingested_at"] or "")[:10]
    run_dates = {r["run_id"]: (r["finished"] or r["ingested_at"] or "")[:10] for r in q(db, "SELECT run_id, finished, ingested_at FROM runs")}
    policy = settings.load(settings.POLICY_FILE)   # read now, so the text matches config/policy.json as it is

    def due(f):   # first seen + the band's allowance under the SLA policy (scoring.py sla_days)
        start = run_dates.get(f["first_seen_run"]) or run_date
        return (dt.date.fromisoformat(start) + dt.timedelta(days=f["sla_days"])).isoformat() if start else ""

    def state_badge(s):
        return {"new": "<span class='tag new'>new</span>", "reopened": "<span class='tag new'>reopened</span>", "persistent": "<span class='tag'>persistent</span>"}.get(s, "")

    def verdict_chip(v):
        if not v:
            return ""
        cls = "vok" if v == "confirmed" else ("vnoise" if v in NOISE_VERDICTS else "")
        return f" <span class='tag {cls}' title='content check (verify.py)'>{esc(v.replace('_', ' '))}</span>"

    def exposure_chip(e):
        if not e:
            return ""
        cls = "vok" if e in ("credential", "data") else ("vnoise" if e in ("nothing", "names") else "")
        return f" <span class='tag {cls}' title='what is actually exposed (triage.py)'>{esc(e)}</span>"

    def contains_block(f):
        """'What it contains' and 'Fix' for one finding's detail block (items with status and bytes, secrets as type and place)."""
        if not f["triage_summary"]:
            return ""
        items = json.loads(f["triage_items"] or "[]"); secrets = json.loads(f["triage_secrets"] or "[]")
        li = "".join(f"<li><code>{esc(it.get('url'))}</code> {esc(it.get('status') if it.get('status') is not None else '')}"
                     f"{(' &middot; ' + esc(it.get('bytes')) + ' bytes') if it.get('bytes') is not None else ''} &middot; <b>{esc(it.get('kind'))}</b>"
                     f"{(' &middot; ' + esc(it.get('note'))) if it.get('note') else ''}</li>" for it in items)
        sl = "".join(f"<li>{esc(x.get('type'))}{(' <code>' + esc(x.get('masked')) + '</code>') if x.get('masked') else ''} in <code>{esc(x.get('where'))}</code>{(' line ' + esc(x.get('line'))) if x.get('line') else ''}</li>" for x in secrets)
        return (f"<p><b>What it contains:</b> {esc(f['triage_summary'])}</p>" + (f"<ul class='small'>{li}</ul>" if li else "")
                + (f"<p class='small'><b>Secrets</b> (type, masked form and place only; values are never stored):</p><ul class='small'>{sl}</ul>" if sl else "")
                + f"<p><b>Fix:</b> {esc(f['triage_fix'])}</p>")

    def finding_rows(rows):
        out = []
        for i, f in enumerate(rows):
            refs = json.loads(f["reference"] or "[]"); tags = json.loads(f["tags"] or "[]")
            cves = [c for c in (f["cve_ids"] or "").split(",") if c]
            cve_html = ", ".join(cve_link(c) for c in cves) or "<span class='muted'>-</span>"
            epss = f"{f['epss']*100:.1f}%" if f["epss"] is not None else "-"
            kev = "<span class='tag kev'>KEV</span>" if f["kev"] else ""
            det = []
            if f["description"]: det.append(f"<p>{esc(f['description'])}</p>")
            if f["triage_summary"]: det.append(contains_block(f))
            if f["remediation"]: det.append(f"<p><b>Remediation:</b> {esc(f['remediation'])}</p>")
            det.append(f"<p class='muted'>Matched: <code>{esc(f['matched'])}</code> &middot; Source: {esc(f['source'])} / <code>{esc(f['check_id'])}</code> &middot; Tags: {esc(', '.join(tags))} &middot; Impact {esc(f['impact'])} &times; Likelihood {esc(f['likelihood'])}"
                       + (f" &middot; CVSS {esc(f['cvss'])}" if f["cvss"] else "") + f" &middot; First seen {esc(f['first_seen_run'])}</p>")
            if f["verdict"]: det.append(f"<p class='muted'>Verified: <b>{esc(f['verdict'].replace('_', ' '))}</b> &middot; {esc(f['verification'] or '')}</p>")
            if refs: det.append("<p class='muted'>Refs: " + " ".join((f"<a href='{safe_href(r)}' target='_blank' rel='noopener noreferrer'>[{j+1}]</a>" if safe_href(r) else f"[{j+1}] <code>{esc(r)}</code>") for j, r in enumerate(refs[:6])) + "</p>")
            out.append(f"""<tr class='r {esc(str(f['band']).lower())}' data-band='{esc(f['band'])}' data-apex='{esc(f['apex'])}' data-class='{esc(f['asset_class'])}' data-state='{esc(f['state'])}'>
<td class='num'><span class='score' style='--c:{BAND_COLOR.get(f['band'], "#888")}'>{esc(f['score'])}</span></td>
<td><span class='band' style='color:{BAND_COLOR.get(f['band'], "#888")}'>{BAND_ICON.get(f['band'], "")}</span> {esc(f['band'])}{verdict_chip(f['verdict'])}{exposure_chip(f['exposure'])}</td>
<td class='host'>{esc(f['hostname'])}{(':' + esc(f['port'])) if f['port'] and f['port'] not in (80, 443) else ''}<div class='muted small'>{esc(f['apex'])} &middot; {esc(CLASS_LABEL.get(f['asset_class'], f['asset_class']))}</div></td>
<td><details><summary>{esc(f['title'])} {state_badge(f['state'])} {kev}</summary>{''.join(det)}</details></td>
<td>{cve_html}</td><td class='num'>{epss}</td><td class='num'>{esc(due(f))}</td></tr>""")
        return "\n".join(out)

    apexes = sorted({x["apex"] for x in assets} | {f["apex"] for f in findings})
    apex_sections = []
    for ax in apexes:
        fa = [f for f in findings if f["apex"] == ax]; aa = [x for x in assets if x["apex"] == ax]
        bc = {b: sum(1 for f in fa if f["band"] == b) for b in BAND_ORDER}
        apex_sections.append(f"""<details class='apex'><summary><b>{esc(ax)}</b> &mdash; {len([x for x in aa if x['class']!='dead'])} live hosts, {len(fa)} findings
<span class='pills'>{''.join(f"<span class='pill' style='--c:{BAND_COLOR[b]}'>{bc[b]} {b}</span>" for b in BAND_ORDER if bc[b])}</span></summary>
<table class='ft'><thead><tr><th>Score</th><th>Band</th><th>Host</th><th>Finding</th><th>CVE</th><th>EPSS</th><th>Due</th></tr></thead><tbody>{finding_rows(fa) or "<tr><td colspan=7 class='muted'>No findings</td></tr>"}</tbody></table></details>""")

    asset_rows = []
    for x in assets:
        pr = profiles.get(x["hostname"]) or {}
        stack = " &middot; ".join(esc(pr[k]) for k in ("os", "web_server", "language", "framework", "cms") if pr.get(k))
        eol_flag = f" <span class='tag eol'>EOL&times;{esc(pr['eol_count'])}</span>" if pr.get("eol_count") else ""
        tls_txt = esc(pr.get("tls_min") or "") + (f"&ndash;{esc(pr['tls_max'])}" if pr.get("tls_max") and pr.get("tls_max") != pr.get("tls_min") else "")
        edge = " / ".join(esc(pr[k]) for k in ("cdn", "waf") if pr.get(k)) or esc(x["waf"] or "")
        flag = ""
        if prev and x["hostname"] not in prev_assets: flag = "<span class='tag new'>new</span>"
        if prev and x["hostname"] in prev_assets and prev_assets[x["hostname"]]["class"] != x["class"]: flag += f"<span class='tag'>was {CLASS_LABEL.get(prev_assets[x['hostname']]['class'])}</span>"
        asset_rows.append(f"<tr data-class='{esc(x['class'])}' data-apex='{esc(x['apex'])}'><td class='host'>{esc(x['hostname'])} {flag}</td><td>{esc(CLASS_LABEL.get(x['class'], x['class']))}<div class='muted small'>{esc(x['reason'])}</div></td>"
                          f"<td class='small'>{esc(x['ips'])}<div class='muted'>{esc(x['cnames'])}</div></td><td class='num'>{esc(x['status_code'] or '')}</td><td class='small'>{esc((x['title'] or '')[:60])}</td>"
                          f"<td class='small'>{esc(pr.get('hosting') or '')}<div class='muted'>{esc(pr.get('as_name') or '')}</div></td><td class='small'>{edge}</td><td class='small'>{stack}{eol_flag}</td>"
                          f"<td class='small'>{tls_txt}<div class='muted'>{esc(pr.get('cert_issuer') or '')}</div></td><td class='small'>{esc((x['cert_expiry'] or '')[:10])}</td></tr>")

    # technology inventory: rollup per component/version, changes since the previous scored run, per-host stack columns
    rollup = {}
    for c in components:
        k = (c["category"], c["name"], c["version"] or "")
        r = rollup.setdefault(k, {"category": c["category"], "name": c["name"], "version": c["version"] or "", "hosts": 0, "eol": c["eol"], "eol_date": c["eol_date"]})
        r["hosts"] += 1
    rollup_rows = sorted(rollup.values(), key=lambda r: (0 if r["eol"] == 1 else 1, CATEGORY_ORDER.index(r["category"]) if r["category"] in CATEGORY_ORDER else 99, -r["hosts"], r["name"].lower(), r["version"]))
    eol_hosts = sum(1 for p in profiles.values() if (p["eol_count"] or 0) > 0)
    # the previous run must have an inventory of its own, or every component would read as "new" (the first run after component tracking was added)
    prev_has_inv = bool(prev) and q(db, "SELECT COUNT(*) c FROM asset_components WHERE run_id=?", prev["run_id"])[0]["c"] > 0
    comp_new = [c for c in components if comp_track.get((c["hostname"], c["category"], c["name"], c["version"] or ""), {}).get("first_seen_run") == a.run_id] if prev_has_inv else []
    comp_gone = q(db, "SELECT * FROM components WHERE status='gone' AND gone_run=? ORDER BY hostname, category, name", a.run_id) if prev_has_inv else []
    gone_keys = {(g["hostname"], g["category"], g["name"]) for g in comp_gone}
    comp_changed = []
    for c in comp_new:
        if (c["hostname"], c["category"], c["name"]) in gone_keys:
            old = next(g for g in comp_gone if (g["hostname"], g["category"], g["name"]) == (c["hostname"], c["category"], c["name"]))
            comp_changed.append({"hostname": c["hostname"], "category": c["category"], "name": c["name"], "old": old["version"], "new": c["version"] or ""})
    changed_keys = {(x["hostname"], x["category"], x["name"]) for x in comp_changed}
    comp_new = [c for c in comp_new if (c["hostname"], c["category"], c["name"]) not in changed_keys]
    comp_gone = [g for g in comp_gone if (g["hostname"], g["category"], g["name"]) not in changed_keys]

    # ---- asset inventory evidence (per-run tables from evidence.py)
    host_class = {x["hostname"]: x["class"] for x in assets}
    certs = q(db, "SELECT * FROM certificates WHERE run_id=? ORDER BY days_left, hostname, port", a.run_id)
    tls = {(r["hostname"], r["port"]): r for r in q(db, "SELECT * FROM tls_endpoints WHERE run_id=?", a.run_id)}
    posture = q(db, "SELECT * FROM domain_posture WHERE run_id=? ORDER BY apex", a.run_id)
    ports = q(db, "SELECT * FROM host_ports WHERE run_id=? ORDER BY risky DESC, port, hostname", a.run_id)
    sources = q(db, "SELECT hostname, source FROM asset_sources WHERE run_id=?", a.run_id)
    groups = q(db, "SELECT * FROM app_groups WHERE run_id=? ORDER BY members DESC, group_host, hostname", a.run_id)
    endpoints = q(db, "SELECT * FROM endpoints WHERE run_id=? ORDER BY hostname, url", a.run_id)
    cert_ids = {c["sha256"] or f"{c['subject']}|{c['issuer']}|{c['not_after']}" for c in certs}
    cert_expiring = [c for c in certs if c["days_left"] is not None and c["days_left"] <= 30]
    legacy_hosts = sorted({k[0] for k, t in tls.items() if t["legacy"]})
    weak_key = [c for c in certs if c["key_type"] == "RSA" and (c["key_bits"] or 0) and c["key_bits"] < 2048]
    san_leads = {}
    for c in certs:
        for sn in json.loads(c["sans"] or "[]"):
            if not sn.startswith("*") and sn not in host_class and any(sn == ax or sn.endswith("." + ax) for ax in apexes):
                san_leads.setdefault(sn, []).append(c["hostname"])
    def cert_flags(c):
        t = tls.get((c["hostname"], c["port"]))
        out = []
        if c["expired"]: out.append("<span class='tag eol'>expired</span>")
        elif c["days_left"] is not None and c["days_left"] <= 30: out.append("<span class='tag new'>expires soon</span>")
        if c["self_signed"]: out.append("<span class='tag'>self-signed</span>")
        if t and t["legacy"]: out.append("<span class='tag'>legacy TLS</span>")
        if t and t["weak_ciphers"]: out.append("<span class='tag'>weak ciphers</span>")
        return " ".join(out)
    cert_rows = "".join(f"<tr><td class='host'>{esc(c['hostname'])}:{esc(c['port'])}</td><td>{esc(c['subject'])}</td><td>{esc(c['issuer'])}</td><td>{esc(c['key_type'] or '')} {esc(c['key_bits'] or '')}</td>"
                        f"<td>{esc((c['not_after'] or '')[:10])}</td><td class='num'>{esc(c['days_left'])}</td><td>{cert_flags(c)}</td></tr>"
                        for c in [x for x in certs if x['expired'] or (x['days_left'] is not None and x['days_left'] <= 90) or x['self_signed'] or tls.get((x['hostname'], x['port']), {}).get('legacy')][:300])
    issuers = {}
    for c in certs:
        r = issuers.setdefault(c["issuer"] or "(unknown)", {"endpoints": 0, "certs": set()}); r["endpoints"] += 1; r["certs"].add(c["sha256"] or c["subject"])
    issuer_rows = "".join(f"<tr><td>{esc(k)}</td><td class='num'>{v['endpoints']}</td><td class='num'>{len(v['certs'])}</td></tr>" for k, v in sorted(issuers.items(), key=lambda kv: -kv[1]['endpoints'])[:40])
    leads_html = ("<ul class='small'>" + "".join(f"<li><code>{esc(k)}</code> <span class='muted'>on {esc(', '.join(v[:3]))}{' and more' if len(v) > 3 else ''}</span></li>" for k, v in sorted(san_leads.items())[:100]) + "</ul>") if san_leads else "<p class='muted small'>Every in-scope certificate name is already in the asset list.</p>"
    certs_html = f"""
<h2>Certificates ({len(certs)} TLS endpoints, {len(cert_ids)} distinct certificates, {len(cert_expiring)} expired or expiring within 30 days)</h2>
<p class='muted'>Every certificate the scan saw, from sslscan (subject, names, issuer, key, signature, validity) with httpx filling serial and fingerprint and covering the endpoints sslscan could not reach. Legacy TLS = SSLv2/3 or TLS 1.0/1.1 still enabled: {len(legacy_hosts)} hosts. Weak RSA keys (under 2048 bits): {len(weak_key)}. Self-signed: {sum(1 for c in certs if c['self_signed'])}. Spreadsheet: <code>reports/{esc(a.run_id)}-certificates.csv</code>.</p>
<details class='apex' open><summary><b>Needs attention</b> (expired, expiring within 90 days, self-signed or legacy TLS; {len(cert_rows.split('<tr>')) - 1} shown)</summary>
<table><thead><tr><th>Endpoint</th><th>Subject</th><th>Issuer</th><th>Key</th><th>Expires</th><th>Days</th><th></th></tr></thead><tbody>{cert_rows or "<tr><td colspan=7 class='muted'>Nothing to show.</td></tr>"}</tbody></table></details>
<details class='apex'><summary><b>Issuers</b> ({len(issuers)})</summary><table><thead><tr><th>Issuer</th><th>Endpoints</th><th>Certificates</th></tr></thead><tbody>{issuer_rows}</tbody></table></details>
<details class='apex'><summary><b>Certificate names not in DNS</b> ({len(san_leads)}): discovery leads</summary>{leads_html}</details>"""

    def yn(v, good=None):
        if v is None: return "<span class='muted'>?</span>"
        return "<span class='ok'>yes</span>" if v else "<span class='bad'>no</span>"
    def pol(v, good):
        if not v: return "<span class='muted'>&mdash;</span>"
        return f"<span class='{'ok' if v in good else 'bad'}'>{esc(v)}</span>"
    posture_rows = "".join(
        f"<tr><td class='host'>{esc(r['apex'])}</td><td>{yn(r['spf']) if r['coverage'] != 'none' else yn(None)} {pol(r['spf_policy'], ('hard', 'soft'))}</td>"
        f"<td>{yn(r['dmarc']) if r['coverage'] != 'none' else yn(None)} {pol(r['dmarc_policy'], ('reject', 'quarantine'))}{(' / sp=' + esc(r['dmarc_sp'])) if r['dmarc_sp'] and r['dmarc_sp'] != r['dmarc_policy'] else ''}</td>"
        f"<td>{yn(r['dkim']) if r['coverage'] != 'none' else yn(None)} <span class='muted small'>{esc(r['hosts_with_dkim'])} subdomains</span></td>"
        f"<td>{esc(r['mx_provider'] or '')} <span class='muted small'>{len(json.loads(r['mx'] or '[]'))} MX</span></td><td>{esc(r['ns_provider'] or '')} <span class='muted small'>{len(json.loads(r['nameservers'] or '[]'))} NS</span></td>"
        f"<td>{esc(', '.join(json.loads(r['caa_issuers'] or '[]'))) or '<span class=muted>none</span>'}</td><td class='num'>{esc(r['hosts_with_spf'])}</td><td class='small muted'>{esc(r['coverage'])}</td></tr>" for r in posture)
    covered = [r for r in posture if r["coverage"] != "none"]
    domains_html = f"""
<h2>Domains ({sum(1 for r in covered if r['dmarc_policy'] in ('reject', 'quarantine'))} of {len(covered)} checked domains enforce DMARC, {sum(1 for r in covered if r['spf'])} publish SPF; {len(posture)} in scope)</h2>
<p class='muted'>Email and DNS posture per apex: SPF (and its all qualifier), DMARC (p= and sp=), DKIM selectors seen, mail and DNS providers, CAA. Coverage "nuclei" means the records came from the nuclei DNS templates, which only query names that resolve, so an apex without an address record reads "not checked" until the dedicated dnsx query (added to the next run) covers it. Spreadsheet: <code>reports/{esc(a.run_id)}-domains.csv</code>.</p>
<table><thead><tr><th>Domain</th><th>SPF</th><th>DMARC</th><th>DKIM</th><th>Mail (MX)</th><th>DNS (NS)</th><th>CAA issuers</th><th>Subdomains with SPF</th><th>Coverage</th></tr></thead><tbody>{posture_rows or "<tr><td colspan=9 class='muted'>No posture rows (re-ingest the run).</td></tr>"}</tbody></table>"""

    port_roll = {}
    for r in ports:
        k = (r["port"], r["proto"], r["service"] or "")
        x = port_roll.setdefault(k, {"port": r["port"], "proto": r["proto"], "service": r["service"] or "", "ips": set(), "hosts": set(), "risky": r["risky"]})
        x["ips"].add(r["ip"]); x["hosts"].add(r["hostname"])
    port_rows = "".join(f"<tr><td class='num'>{esc(x['port'])}/{esc(x['proto'])}</td><td>{esc(x['service'])}</td><td class='num'>{len(x['ips'])}</td><td class='num'>{len(x['hosts'])}</td><td>{'<span class=tag>risky</span>' if x['risky'] else ''}</td></tr>"
                        for x in sorted(port_roll.values(), key=lambda x: (-x['risky'], -len(x['ips']), x['port'])))
    prev_ports = q(db, "SELECT DISTINCT ip, port, proto, service FROM host_ports WHERE run_id=?", prev["run_id"]) if prev else []
    prev_has_ports = bool(prev_ports)
    cur_set = {(r["ip"], r["port"], r["proto"]) for r in ports}; prev_set = {(r["ip"], r["port"], r["proto"]) for r in prev_ports}
    ip_names = {}
    for r in ports: ip_names.setdefault(r["ip"], set()).add(r["hostname"])
    opened = sorted(cur_set - prev_set); closed = sorted(prev_set - cur_set)
    def port_change_rows(items):
        return "".join(f"<tr><td>{esc(ip)}</td><td class='num'>{esc(port)}/{esc(proto)}</td><td class='small'>{esc(', '.join(sorted(ip_names.get(ip, []))[:4]))}</td></tr>" for ip, port, proto in items[:200])
    ports_html = f"""
<h2>Open ports ({len(cur_set)} open ports on {len({r['ip'] for r in ports})} owned addresses, {sum(1 for k, x in port_roll.items() if x['risky'] for _ in x['ips'])} risky)</h2>
<p class='muted'>Every open TCP port nmap found on owned addresses (top 1000), not only the risky ones that become findings. Service names are what nmap could tell: behind NAT or a filtering firewall the probes often come back "tcpwrapped", so banners can be absent and the port number is the evidence. Spreadsheet: <code>reports/{esc(a.run_id)}-ports.csv</code> (one row per hostname sharing the address).</p>
<table><thead><tr><th>Port</th><th>Service</th><th>Addresses</th><th>Hostnames</th><th></th></tr></thead><tbody>{port_rows or "<tr><td colspan=5 class='muted'>No open ports recorded (re-ingest the run).</td></tr>"}</tbody></table>
{(f"<details class='apex'><summary><b>Opened since {esc(prev['run_id'])}</b> ({len(opened)})</summary><table><thead><tr><th>Address</th><th>Port</th><th>Names</th></tr></thead><tbody>{port_change_rows(opened)}</tbody></table></details>"
  f"<details class='apex'><summary><b>Closed since {esc(prev['run_id'])}</b> ({len(closed)})</summary><table><thead><tr><th>Address</th><th>Port</th><th>Names</th></tr></thead><tbody>{port_change_rows(closed)}</tbody></table></details>") if prev_has_ports else "<p class='muted small'>Opened / closed appear from the next scored run (the previous run has no port inventory to compare with).</p>"}"""

    src_roll = {}; host_src = {}
    for r in sources:
        src_roll.setdefault(r["source"], {"names": 0, "live": 0}); src_roll[r["source"]]["names"] += 1
        if host_class.get(r["hostname"]) not in (None, "dead"): src_roll[r["source"]]["live"] += 1
        host_src.setdefault(r["hostname"], set()).add(r["source"])
    only = {src: sorted(h for h, ss in host_src.items() if ss == {src}) for src in ("crtsh", "subfinder", "assetfinder", "dnsrecon")}
    src_rows = "".join(f"<tr><td>{esc(k)}</td><td class='num'>{v['names']}</td><td class='num'>{v['live']}</td><td class='num'>{len(only.get(k, []))}</td></tr>" for k, v in sorted(src_roll.items(), key=lambda kv: -kv[1]['names']))
    only_html = "".join(f"<details class='apex'><summary><b>Only {esc(k)} knows</b> ({len(v)})</summary><p class='small'>{esc(', '.join(v[:150]))}{' and more' if len(v) > 150 else ''}</p></details>" for k, v in only.items() if v)
    discovery_html = f"""
<h2>Discovery ({len(host_src)} names, {len(src_roll)} sources)</h2>
<p class='muted'>Where each name came from: the seed list, the apex itself, subfinder (passive sources), crt.sh (certificate transparency), assetfinder, dnsrecon. A name only certificate transparency knows is one nobody told the scan about.</p>
<table><thead><tr><th>Source</th><th>Names</th><th>Live</th><th>Only this source</th></tr></thead><tbody>{src_rows or "<tr><td colspan=4 class='muted'>No discovery sources recorded (re-ingest the run).</td></tr>"}</tbody></table>{only_html}"""

    clusters = {}
    for g in groups:
        if g["members"] > 1: clusters.setdefault(g["group_host"], []).append(g["hostname"])
    cluster_rows = "".join(f"<tr><td class='host'>{esc(k)}</td><td class='num'>{len(v)}</td><td class='small'>{esc(', '.join(sorted(set(v))[:12]))}{' and more' if len(set(v)) > 12 else ''}</td></tr>" for k, v in sorted(clusters.items(), key=lambda kv: -len(kv[1]))[:150])
    apps_html = f"""
<h2>Applications ({len(clusters)} clusters serving the same application on more than one host, {len({g['group_url'] for g in groups})} groups in all)</h2>
<p class='muted'>nuclei's URL clustering: hosts whose responses match are one application behind several names (a load balancer, a wildcard, a CDN). One fix covers the cluster; one exposure is live on every member.</p>
<table><thead><tr><th>Representative host</th><th>Hosts</th><th>Members</th></tr></thead><tbody>{cluster_rows or "<tr><td colspan=3 class='muted'>No clusters recorded (re-ingest the run).</td></tr>"}</tbody></table>"""

    def eol_cell(eol, eol_date):
        if eol == 1: return f"<span class='tag eol'>EOL{(' ' + esc(eol_date)) if eol_date else ''}</span>"
        if eol == 0: return "<span class='muted small'>supported</span>"
        return ""
    rollup_html = "".join(f"<tr data-cat='{esc(r['category'])}' data-eol='{'1' if r['eol']==1 else '0'}'><td>{esc(CATEGORY_LABEL.get(r['category'], r['category']))}</td><td>{esc(r['name'])}</td>"
                          f"<td>{esc(r['version'])}</td><td class='num'>{r['hosts']}</td><td>{eol_cell(r['eol'], r['eol_date'])}</td></tr>" for r in rollup_rows)
    def comp_row(c, extra=""):
        return f"<tr><td class='host'>{esc(c['hostname'])}</td><td>{esc(CATEGORY_LABEL.get(c['category'], c['category']))}</td><td>{esc(c['name'])}</td><td>{extra or esc(c['version'] or '')}</td></tr>"
    changes_html = ""
    if prev_has_inv:
        changes_html = (f"<details class='apex'><summary><b>Changed version</b> ({len(comp_changed)})</summary><table><thead><tr><th>Host</th><th>Category</th><th>Component</th><th>Version</th></tr></thead><tbody>"
                        + "".join(comp_row(x, f"{esc(x['old'])} &rarr; {esc(x['new'])}") for x in comp_changed[:400]) + "</tbody></table></details>"
                        f"<details class='apex'><summary><b>New</b> ({len(comp_new)})</summary><table><thead><tr><th>Host</th><th>Category</th><th>Component</th><th>Version</th></tr></thead><tbody>"
                        + "".join(comp_row(x) for x in comp_new[:400]) + "</tbody></table></details>"
                        f"<details class='apex'><summary><b>Gone</b> ({len(comp_gone)})</summary><table><thead><tr><th>Host</th><th>Category</th><th>Component</th><th>Version</th></tr></thead><tbody>"
                        + "".join(comp_row(x) for x in comp_gone[:400]) + "</tbody></table></details>")
        if len(comp_changed) > 400 or len(comp_new) > 400 or len(comp_gone) > 400:
            changes_html += "<p class='muted small'>Lists capped at 400 rows each; the full set is in the components CSV.</p>"
    prof_hosts = sum(1 for x in assets if x["hostname"] in profiles)

    fixed_rows = "".join(f"<tr><td class='host'>{esc(f['hostname'])}</td><td>{esc(f['title'])}</td><td>{esc(f['severity'])}</td><td>{esc(f['first_seen_run'])}</td></tr>" for f in fixed)
    mttr_html = "".join(f"<tr><td>{esc(r['severity'])}</td><td class='num'>{esc(r['n'])}</td><td class='num'>{(r['d'] or 0):.0f}</td></tr>" for r in mttr_rows) or "<tr><td colspan=3 class='muted'>No fixed findings yet (needs at least two runs).</td></tr>"
    phase_html = "".join(f"<tr><td>{esc(p.get('phase'))}</td><td>{esc(p.get('name'))}</td><td>{esc(p.get('start'))}</td><td>{esc(p.get('end'))}</td><td class='{'ok' if p.get('rc')==0 else 'bad'}'>{esc(p.get('rc'))}</td></tr>" for p in phases)
    run_list = "".join(f"<li>{esc(r['run_id'])}{' (inventory only)' if r['inventory_only'] else (' (daily recheck)' if r['kind'] == 'recheck' else '')} &middot; {esc((r['finished'] or '')[:16])}</li>" for r in all_runs)
    delta_txt = (f"vs {esc(prev['run_id'])}: <b>{state_counts['new'] + state_counts['reopened']}</b> new, <b>{state_counts['persistent']}</b> persistent, <b>{len(fixed)}</b> fixed"
                 if prev else "first scored run &mdash; every finding is new; trends start next month")
    if kind == "recheck":
        delta_txt = (f"daily recheck of <b>{len(retested)}</b> hosts on top of run {esc(run['base_run'])}; every other host keeps its last observation. "
                     + delta_txt)

    # ---- Fix list: every High and Critical finding, by domain then by what is exposed, with the triage summary and fix
    def fix_summary(f):
        return f["triage_summary"] or f["title"] or ""
    def fix_text(f):
        return f["triage_fix"] or f["remediation"] or "See the finding detail."
    fixrows = [f for f in findings if f["band"] in ("Critical", "High")]
    erank = {e: i for i, e in enumerate(EXPOSURE_ORDER)}
    fixrows.sort(key=lambda f: (f["apex"] or "", erank.get(f["exposure"] or "unknown", 99), -f["score"], f["hostname"]))
    fix_html_parts = []
    for ax in sorted({f["apex"] or "" for f in fixrows}):
        rows = [f for f in fixrows if (f["apex"] or "") == ax]
        body = []
        for e in EXPOSURE_ORDER:
            grp = [f for f in rows if (f["exposure"] or "unknown") == e]
            if not grp:
                continue
            body.append(f"<tr class='grp'><td colspan=5><b>{esc(EXPOSURE_LABEL[e])}</b> ({len(grp)})</td></tr>")
            body += [f"<tr><td class='host'>{esc(f['hostname'])}{(':' + esc(f['port'])) if f['port'] and f['port'] not in (80, 443) else ''}"
                     f"<div class='muted small'>{esc(f['check_id'])}</div></td><td><span class='band' style='color:{BAND_COLOR.get(f['band'], '#888')}'>{BAND_ICON.get(f['band'], '')}</span> {esc(f['band'])}{exposure_chip(f['exposure'])}</td>"
                     f"<td>{esc(fix_summary(f))}</td><td>{esc(fix_text(f))}</td><td class='num'>{esc(due(f))}</td></tr>" for f in grp]
        fix_html_parts.append(f"<details class='apex' open><summary><b>{esc(ax)}</b> &mdash; {len(rows)} to fix</summary><table class='fl'><thead><tr><th>Host</th><th>Band</th>"
                              f"<th>What is exposed</th><th>Fix</th><th>Due</th></tr></thead><tbody>{''.join(body)}</tbody></table></details>")
    legacy = {}
    for f in findings:
        if f["check_id"] == "legacy-protocol" and f["band"] in ("Medium", "High", "Critical"):
            legacy.setdefault(f["apex"] or "", []).append(f["hostname"])
    legacy_html = "".join(f"<details class='apex'><summary><b>{esc(ax)}</b> &mdash; legacy TLS on {len(hs)} hosts (Medium, one fix)</summary>"
                          f"<p class='small'>{esc(', '.join(sorted(set(hs))[:200]))}</p><p class='small'><b>Fix:</b> {esc(LEGACY_FIX)}</p></details>"
                          for ax, hs in sorted(legacy.items()))
    fixlist_html = f"""<h2 style='border-top:0;margin-top:20px'>Fix list ({len(fixrows)} High and Critical findings)</h2>
<p class='muted'>Each finding was followed past the first hit: every file it names was fetched from the same host (at most 12 per finding), each open database or file-share port got one handshake, and every response was classified. "What is exposed" says what anyone on the internet can read today; secrets are listed by type and place only, their values are never stored. Grouped by domain, then by what is exposed. Spreadsheet: <code>reports/{esc(a.run_id)}-fixlist.csv</code>.</p>
{''.join(fix_html_parts) or "<p class='muted'>No High or Critical findings.</p>"}
{("<h3 class='small muted' style='margin-top:18px'>Legacy TLS (Medium), grouped per domain</h3>" + legacy_html) if legacy_html else ""}"""

    page = f"""<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>Scan report {esc(a.run_id)}</title>
<style>
:root{{--surface:#fcfcfb;--surface-2:#f3f2ef;--text:#0b0b0b;--text-2:#52514e;--muted:#7a7974;--line:#e4e2dc;--accent:#2a78d6;color-scheme:light}}
@media (prefers-color-scheme: dark){{:root:not([data-theme="light"]){{--surface:#1a1a19;--surface-2:#242423;--text:#f0efec;--text-2:#c3c2b7;--muted:#8f8e86;--line:#383835;--accent:#3987e5;color-scheme:dark}}}}
:root[data-theme="dark"]{{--surface:#1a1a19;--surface-2:#242423;--text:#f0efec;--text-2:#c3c2b7;--muted:#8f8e86;--line:#383835;--accent:#3987e5;color-scheme:dark}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--surface);color:var(--text);font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}}
main{{max-width:1200px;margin:0 auto;padding:24px 16px 64px}}h1{{font-size:26px;margin:0 0 4px}}h2{{font-size:19px;margin:40px 0 12px;padding-top:8px;border-top:1px solid var(--line)}}
.sub{{color:var(--text-2);margin-bottom:20px}}.muted{{color:var(--muted)}}.small{{font-size:12.5px}}code{{font-size:12.5px;background:var(--surface-2);padding:1px 4px;border-radius:3px}}
.tiles{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:16px 0}}.tile{{background:var(--surface-2);border-radius:8px;padding:12px 14px}}
.tile .n{{font-size:28px;font-weight:600;line-height:1.1}}.tile .l{{color:var(--text-2);font-size:12.5px;margin-top:2px}}.tile.band{{border-left:4px solid var(--c)}}
table{{width:100%;border-collapse:collapse;font-size:13.5px}}th{{text-align:left;color:var(--text-2);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.03em;padding:8px 8px;border-bottom:2px solid var(--line);position:sticky;top:0;background:var(--surface)}}
td{{padding:7px 8px;border-bottom:1px solid var(--line);vertical-align:top}}td.num{{text-align:right;white-space:nowrap;font-variant-numeric:tabular-nums}}td.host{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;word-break:break-all;min-width:160px}}
.score{{display:inline-block;min-width:34px;text-align:center;padding:2px 6px;border-radius:5px;font-weight:700;color:#fff;background:var(--c)}}
.tag{{display:inline-block;font-size:10.5px;padding:0 6px;border-radius:9px;background:var(--surface-2);color:var(--text-2);margin-left:4px;vertical-align:middle}}.tag.new{{background:var(--accent);color:#fff}}.tag.kev{{background:#d03b3b;color:#fff}}.tag.eol{{background:#ec835a;color:#fff}}.tag.vok{{background:#d03b3b;color:#fff}}.tag.vnoise{{background:var(--surface-2);color:var(--muted);border:1px dashed var(--line)}}
details summary{{cursor:pointer}}details p{{margin:6px 0}}.apex{{margin:10px 0;padding:10px 12px;background:var(--surface-2);border-radius:8px}}.apex table{{margin-top:10px}}.apex th{{background:var(--surface-2)}}
.pills{{margin-left:8px}}.pill{{display:inline-block;font-size:11.5px;padding:0 7px;border-radius:9px;border:1px solid var(--c);color:var(--text);margin-left:4px}}
.chart{{width:100%;height:auto;max-width:760px;display:block}}.grid{{stroke:var(--line);stroke-width:1}}.tick{{font-size:11px;fill:var(--muted)}}.val{{font-size:11px;fill:var(--text-2)}}
.legend{{font-size:12.5px;color:var(--text-2);margin:4px 0 12px}}.lg{{margin-right:14px}}.lg i{{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:5px;vertical-align:-1px}}
.filters{{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0}}.filters select,.filters input{{font:inherit;font-size:13px;padding:4px 8px;border:1px solid var(--line);border-radius:6px;background:var(--surface);color:var(--text)}}
.ok{{color:#0ca30c}}.bad{{color:#d03b3b;font-weight:600}}.twocol{{display:grid;grid-template-columns:1fr 1fr;gap:24px}}@media (max-width:800px){{.twocol{{grid-template-columns:1fr}}}}
.method td{{font-size:13px}}tr.grp td{{background:var(--surface);padding-top:12px}}table.fl td{{font-size:13px}}
</style></head><body><main>
<h1>External Vulnerability Scan &mdash; {esc(a.run_id)}</h1>
<div class='sub'>Scope: {esc(', '.join(apexes))} &middot; run finished {esc(run['finished'] or '')} &middot; report generated {gen} &middot; {delta_txt}</div>
{fixlist_html}

<div class='tiles'>
{''.join(f"<div class='tile band' style='--c:{BAND_COLOR[b]}'><div class='n'>{band_counts[b]}</div><div class='l'>{b} ({'score 20-25' if b=='Critical' else 'score 12-19' if b=='High' else 'score 6-11' if b=='Medium' else 'score 1-5'})</div></div>" for b in BAND_ORDER)}
<div class='tile'><div class='n'>{len(kev_hits)}</div><div class='l'>On CISA KEV (actively exploited)</div></div>
<div class='tile'><div class='n'>{verified_noise}</div><div class='l'>Verified noise (listings and exposures whose content is empty or default)</div></div>
<div class='tile'><div class='n'>{sum(v for k,v in class_counts.items() if k!='dead')}</div><div class='l'>Live hosts ({class_counts.get('owned',0)} owned / {class_counts.get('unverified',0)} unverified / {class_counts.get('cdn_fronted',0)} CDN / {class_counts.get('third_party',0)} 3rd-party)</div></div>
<div class='tile'><div class='n'>{len(new_assets) if prev else '&ndash;'}</div><div class='l'>{'New hosts vs last run' if prev else 'New hosts (baseline run)'}{(' &middot; ' + str(len(new_tp)) + ' third-party need review') if new_tp else ''}</div></div>
</div>
{"<p><b>Review needed:</b> new third-party-hosted names appeared this run: " + ", ".join(f"<code>{esc(x['hostname'])}</code>" for x in new_tp) + ". Confirm each is a sanctioned vendor; dangling CNAMEs are takeover candidates.</p>" if new_tp else ""}
{"<p class='muted'>Hosts seen last run but not this run: " + ", ".join(f"<code>{esc(h)}</code>" for h in gone_assets[:30]) + ("…" if len(gone_assets) > 30 else "") + "</p>" if gone_assets else ""}

<h2>Prioritized patch list</h2>
<p class='muted'>Sorted by score = impact &times; likelihood. Expand a row for description, remediation and evidence. Due date = first seen + the SLA policy allowance for the band ({esc(sla_text(policy))}; strict-SLA hosts from <code>scope/{esc(policy['strict_sla_hosts_file'])}</code>).</p>
<div class='filters'>
<select id='fband'><option value=''>All bands</option>{''.join(f"<option>{b}</option>" for b in BAND_ORDER)}</select>
<select id='fapex'><option value=''>All domains</option>{''.join(f"<option>{esc(x)}</option>" for x in apexes)}</select>
<select id='fclass'><option value=''>All host classes</option><option value='owned'>Owned</option><option value='unverified'>Unverified</option><option value='cdn_fronted'>CDN-fronted</option><option value='third_party'>Third-party</option></select>
<select id='fstate'><option value=''>All states</option><option value='new'>New</option><option value='persistent'>Persistent</option></select>
<input id='fq' placeholder='search host / finding' type='search'>
<span class='muted' id='fcount'></span>
</div>
<table class='ft' id='main'><thead><tr><th>Score</th><th>Band</th><th>Host</th><th>Finding</th><th>CVE</th><th>EPSS</th><th>Due</th></tr></thead>
<tbody>{finding_rows(findings) or "<tr><td colspan=7 class='muted'>No findings recorded for this run.</td></tr>"}</tbody></table>

<h2>Fixed since last run ({len(fixed)})</h2>
<table><thead><tr><th>Host</th><th>Finding</th><th>Severity</th><th>First seen</th></tr></thead><tbody>{fixed_rows or "<tr><td colspan=4 class='muted'>None</td></tr>"}</tbody></table>

<h2>Per-domain breakdown</h2>
{''.join(apex_sections)}

<h2>Technology inventory ({prof_hosts} hosts profiled, {eol_hosts} on end-of-life software)</h2>
<p class='muted'>What each live host runs, as seen from outside: httpx and whatweb fingerprints, Server headers, nuclei technology templates, wafw00f, sslscan, CNAME targets and the ASN of the address (Team Cymru). OS is inferred from banners only (no active OS detection), so many hosts have none. End-of-life status comes from endoflife.date for the products that carry a version; it is inventory, not a finding. Spreadsheets: <code>reports/{esc(a.run_id)}-inventory.csv</code> (one row per host) and <code>reports/{esc(a.run_id)}-components.csv</code> (one row per host and component).</p>
<div class='filters'><select id='rcat'><option value=''>All categories</option>{''.join(f"<option value='{k}'>{v}</option>" for k,v in CATEGORY_LABEL.items())}</select>
<select id='reol'><option value=''>Supported and EOL</option><option value='1'>EOL only</option></select><input id='rq' placeholder='search component' type='search'><span class='muted' id='rcount'></span></div>
<table id='rollup'><thead><tr><th>Category</th><th>Component</th><th>Version</th><th>Hosts</th><th>Lifecycle</th></tr></thead><tbody>{rollup_html or "<tr><td colspan=5 class='muted'>No technology components recorded (re-ingest the run).</td></tr>"}</tbody></table>
{("<h3 class='small muted' style='margin-top:18px'>Changes since " + esc(prev['run_id']) + "</h3>" + changes_html) if prev_has_inv else "<p class='muted small'>Changes appear from the next scored run (the previous run has no technology inventory to compare with).</p>"}

{certs_html}
{domains_html}
{ports_html}
{discovery_html}
{apps_html}

<h2>Asset inventory ({len(assets)} names, {sum(v for k,v in class_counts.items() if k!='dead')} live)</h2>
<p class='muted'>Owned = direct A record, fully scanned. CDN-fronted = behind Cloudflare/Akamai/etc.; web checks only, edge IPs not port-scanned. Third-party = CNAME to a SaaS/hosting vendor; passive + takeover/misconfig checks only. Unresolved names are tracked for trend but never probed.</p>
<div class='filters'><select id='aclass'><option value=''>All classes</option>{''.join(f"<option value='{k}'>{v}</option>" for k,v in CLASS_LABEL.items())}</select>
<select id='aapex'><option value=''>All domains</option>{''.join(f"<option>{esc(x)}</option>" for x in apexes)}</select><input id='aq' placeholder='search' type='search'></div>
<table id='assets'><thead><tr><th>Host</th><th>Class</th><th>IPs / CNAME</th><th>HTTP</th><th>Title</th><th>Hosting</th><th>CDN / WAF</th><th>Stack</th><th>TLS</th><th>Cert exp.</th></tr></thead><tbody>{''.join(asset_rows)}</tbody></table>

<h2>Trends</h2>
<div class='twocol'>
<div><h3 class='small muted'>Open findings by band per scored run</h3>{chart_bands_by_run(scored_ids, trend)}</div>
<div><h3 class='small muted'>Live hosts per scored run</h3>{chart_line(scored_ids, asset_trend, 'Live hosts')}
<h3 class='small muted'>Mean time to fix (days, all runs)</h3><table><thead><tr><th>Severity</th><th>Fixed</th><th>Avg days</th></tr></thead><tbody>{mttr_html}</tbody></table></div>
</div>

<h2>Methodology and run manifest</h2>
<div class='twocol'><div>
<table class='method'><thead><tr><th>Impact</th><th>Rule</th></tr></thead><tbody>
<tr><td>5</td><td>nuclei critical, CVSS &ge; 9.0, or zone transfer allowed</td></tr><tr><td>4</td><td>nuclei high or CVSS 7.0&ndash;8.9</td></tr>
<tr><td>3</td><td>nuclei medium, CVSS 4.0&ndash;6.9, SSLv3/TLS1.0/1.1 enabled, exposed admin/db service</td></tr><tr><td>2</td><td>nuclei low, CVSS &lt; 4.0, weak ciphers, missing headers</td></tr><tr><td>1</td><td>informational</td></tr></tbody></table>
<table class='method' style='margin-top:12px'><thead><tr><th>Likelihood</th><th>Rule (first match)</th></tr></thead><tbody>
<tr><td>5</td><td>CVE listed in CISA KEV</td></tr><tr><td>4</td><td>EPSS &ge; 40%, or exposure/takeover/default-login class finding on an owned host</td></tr>
<tr><td>3</td><td>EPSS 10&ndash;40%, exposure finding on third-party host, or medium+ misconfig on owned host</td></tr><tr><td>2</td><td>CVE with EPSS &lt; 10%, low misconfig, or any misconfig on a third-party host</td></tr><tr><td>1</td><td>informational, no exploitation path</td></tr></tbody></table>
<p class='small muted'>Score = impact &times; likelihood (1&ndash;25). Bands: Critical 20&ndash;25, High 12&ndash;19, Medium 6&ndash;11, Low 1&ndash;5. Fix-by days (SLA policy): {esc(sla_text(policy))}. {esc(strict_hosts_text(policy))} Finding identity = host + source + check + port, so rotating cloud IPs do not create false "new" findings. Excluded nuclei tags: dos, fuzz, intrusive, bruteforce. Interactsh (out-of-band) checks disabled. Port scan: top 1000 TCP, owned IPs only. EPSS data {esc(run['epss_date'])}; KEV catalog {esc(run['kev_version'])}.</p>
</div><div>
<table class='method'><tbody>
<tr><td>OS</td><td>{esc(tools.get('os') or tools.get('kali'))}</td></tr><tr><td>nuclei</td><td>{esc(tools.get('nuclei'))} &middot; templates {esc(run['template_version'])} ({esc(run['template_count'])} files)</td></tr>
<tr><td>Evidence stored</td><td>{esc(run.get('evidence_level') or 'not recorded for this run')}</td></tr>
<tr><td>nmap</td><td>{esc(tools.get('nmap'))}</td></tr><tr><td>httpx</td><td>{esc(tools.get('httpx'))}</td></tr><tr><td>subfinder</td><td>{esc(tools.get('subfinder'))}</td></tr><tr><td>sslscan</td><td>{esc(tools.get('sslscan'))}</td></tr>
<tr><td>Counts</td><td class='small'>{esc(json.dumps(counts))}</td></tr></tbody></table>
<table class='method' style='margin-top:12px'><thead><tr><th>#</th><th>Phase</th><th>Start</th><th>End</th><th>rc</th></tr></thead><tbody>{phase_html}</tbody></table>
{("<p class='small'><b>Run notes / coverage caveats:</b> " + esc(run['notes']) + "</p>") if run.get('notes') and not str(run['notes']).startswith('prev_run=') else ''}
<p class='small muted'>Runs in database:</p><ul class='small muted'>{run_list}</ul>
</div></div>
</main>
<script>
(function(){{
 function filt(tbl,sels,qid,cnt){{var rows=[].slice.call(document.querySelectorAll('#'+tbl+' tbody tr'));function run(){{var q=(document.getElementById(qid).value||'').toLowerCase();var n=0;rows.forEach(function(r){{var ok=true;sels.forEach(function(s){{var v=document.getElementById(s[0]).value;if(v&&r.dataset[s[1]]!==v)ok=false;}});if(ok&&q&&r.textContent.toLowerCase().indexOf(q)<0)ok=false;r.style.display=ok?'':'none';if(ok)n++;}});if(cnt)document.getElementById(cnt).textContent=n+' of '+rows.length+' shown';}}sels.forEach(function(s){{document.getElementById(s[0]).addEventListener('change',run)}});document.getElementById(qid).addEventListener('input',run);run();}}
 filt('main',[['fband','band'],['fapex','apex'],['fclass','class'],['fstate','state']],'fq','fcount');
 filt('assets',[['aclass','class'],['aapex','apex']],'aq',null);
 filt('rollup',[['rcat','cat'],['reol','eol']],'rq','rcount');
}})();
</script></body></html>"""
    os.makedirs(os.path.join(a.root, "reports"), exist_ok=True)
    out = os.path.join(a.root, "reports", f"{a.run_id}.html")
    with open(out, "w") as fh:
        fh.write(page)
    inv_csv = os.path.join(a.root, "reports", f"{a.run_id}-inventory.csv")
    with open(inv_csv, "w", newline="") as f:
        w = SafeWriter(f); w.writerow(PROFILE_COLS)
        for x in assets:
            pr = profiles.get(x["hostname"])
            if not pr: continue
            w.writerow([x["hostname"], x["apex"], x["class"]] + [pr.get(k) for k in PROFILE_COLS[3:]])
    comp_csv = os.path.join(a.root, "reports", f"{a.run_id}-components.csv")
    with open(comp_csv, "w", newline="") as f:
        w = SafeWriter(f); w.writerow(["hostname", "apex", "class", "category", "name", "version", "source", "evidence", "eol", "eol_date", "first_seen_run", "last_seen_run"])
        cls = {x["hostname"]: (x["apex"], x["class"]) for x in assets}
        for c in components:
            t = comp_track.get((c["hostname"], c["category"], c["name"], c["version"] or ""), {})
            ax, cl = cls.get(c["hostname"], ("", ""))
            w.writerow([c["hostname"], ax, cl, c["category"], c["name"], c["version"], c["source"], c["evidence"], c["eol"], c["eol_date"], t.get("first_seen_run"), t.get("last_seen_run")])
    def dump_csv(name, cols, rows):
        path = os.path.join(a.root, "reports", f"{a.run_id}-{name}.csv")
        with open(path, "w", newline="") as f:
            w = SafeWriter(f); w.writerow(cols)
            for r in rows: w.writerow([r.get(k) for k in cols])
        return path
    for c in certs:
        t = tls.get((c["hostname"], c["port"]), {})
        c.update({"protocols": t.get("protocols"), "legacy": t.get("legacy"), "weak_ciphers": t.get("weak_ciphers"), "apex": next((x["apex"] for x in assets if x["hostname"] == c["hostname"]), ""), "class": host_class.get(c["hostname"], "")})
    cert_csv = dump_csv("certificates", ["hostname", "port", "apex", "class", "subject", "sans", "issuer", "key_type", "key_bits", "sig_alg", "not_before", "not_after", "days_left", "expired", "self_signed", "serial", "sha256", "source", "protocols", "legacy", "weak_ciphers"], certs)
    for r in ports: r["class"] = host_class.get(r["hostname"], "")
    ports_csv = dump_csv("ports", ["hostname", "class", "ip", "port", "proto", "service", "product", "reason", "risky", "web"], ports)
    domains_csv = dump_csv("domains", ["apex", "coverage", "spf", "spf_policy", "dmarc", "dmarc_policy", "dmarc_sp", "dkim", "mx", "mx_provider", "nameservers", "ns_provider", "caa", "caa_issuers", "hosts_with_spf", "hosts_with_dkim"], posture)
    endpoints_csv = dump_csv("endpoints", [k for k in (endpoints[0].keys() if endpoints else ["run_id", "url", "hostname"]) if k != "run_id"], endpoints)
    fixlist_csv = os.path.join(a.root, "reports", f"{a.run_id}-fixlist.csv")
    with open(fixlist_csv, "w", newline="") as fh:
        w = SafeWriter(fh); w.writerow(FIXLIST_COLS)
        for f in fixrows:
            w.writerow([f["apex"], f["hostname"], f["port"], f["band"], f["score"], f["exposure"] or "", fix_summary(f), fix_text(f), due(f),
                        f["finding_key"], f["check_id"], f["title"], f["matched"], f["triage_items"] or "[]"])
    for link, target in (("latest.html", f"{a.run_id}.html"), ("latest-fixlist.csv", f"{a.run_id}-fixlist.csv"), ("latest-inventory.csv", f"{a.run_id}-inventory.csv"), ("latest-components.csv", f"{a.run_id}-components.csv"),
                         ("latest-certificates.csv", f"{a.run_id}-certificates.csv"), ("latest-ports.csv", f"{a.run_id}-ports.csv"), ("latest-domains.csv", f"{a.run_id}-domains.csv"), ("latest-endpoints.csv", f"{a.run_id}-endpoints.csv")):
        latest = os.path.join(a.root, "reports", link)
        try:
            if os.path.islink(latest) or os.path.exists(latest): os.remove(latest)
            os.symlink(target, latest)
        except OSError:
            pass
    print(f"report: {out}  (findings={len(findings)} critical={band_counts['Critical']} high={band_counts['High']} medium={band_counts['Medium']} low={band_counts['Low']} verified_noise={verified_noise} fixlist={len(fixrows)}; "
          f"inventory: {prof_hosts} hosts profiled, {len(components)} components, {eol_hosts} hosts on EOL software -> {inv_csv}, {comp_csv}; "
          f"evidence: {len(certs)} certificates ({len(cert_expiring)} expiring/expired, {len(legacy_hosts)} legacy-TLS hosts), {len(cur_set)} open ports, {len(covered)}/{len(posture)} domains checked, {len(clusters)} app clusters -> {cert_csv}, {ports_csv}, {domains_csv}, {endpoints_csv})")
    db.close()


if __name__ == "__main__":
    main()
