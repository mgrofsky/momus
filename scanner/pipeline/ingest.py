#!/usr/bin/env python3
"""ingest.py - normalize one run's raw tool output into data/scan.sqlite, enrich with EPSS/KEV, score.

  python3 -I -B scanner/pipeline/ingest.py --root "$SCAN_ROOT" --run-id <RUN_ID> [--offline | --no-feeds]

--offline   nothing leaves the machine: no EPSS/KEV download and no live verify/triage follow-ups.
--no-feeds  only the public vulnerability feeds (EPSS, KEV) are not downloaded; the newest cached copy under
            data/epss and data/kev is used if there is one. Live follow-ups still go to the scanned hosts.
            Lab runs use this: they need no internet.

Idempotent per run_id: re-ingesting replaces that run's observations and recomputes delta state.
"""
import argparse, csv, datetime as dt, glob, gzip, io, json, os, re, shutil, sqlite3, sys, urllib.request
import xml.etree.ElementTree as ET


def _readlines(path, **kw):
    """The file's lines, as iterating the open file would give them, with the file closed afterwards."""
    with open(path, **kw) as fh:
        return fh.readlines()
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import scoring as S
import settings
import fingerprint as F
import evidence as E
import verify as V
import triage as T
import scope as SC
import safefetch as SF
import redact as R
import minimize as M
CONFIG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config")

EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
# nuclei templates that describe what is there rather than what is wrong -> stored as asset tech, not findings
# (lists from settings.py; override them in config/policy.json)
POLICY = settings.load()
NOISE_TAGS = set(POLICY["noise_tags"])
NOISE_IDS = set(POLICY["noise_ids"])
RISKY_SERVICES = {"telnet", "ftp", "microsoft-ds", "netbios-ssn", "ms-wbt-server", "rdp", "vnc", "mysql", "postgresql", "ms-sql-s",
                  "redis", "mongodb", "elasticsearch", "memcached", "snmp", "ldap", "rpcbind", "nfs", "x11", "docker", "kubernetes",
                  "couchdb", "cassandra", "oracle-tns", "winrm", "smb"}
WEB_PORTS = {80, 443, 8080, 8443, 8000, 8008, 8888}
RISKY_PORTS = {21, 23, 135, 137, 139, 445, 1433, 1521, 2375, 2376, 3306, 3389, 5432, 5900, 5984, 6379, 6443, 9200, 9300, 11211, 27017}

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs(seq INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT UNIQUE, started TEXT, finished TEXT,
  inventory_only INTEGER, nuclei_version TEXT, template_version TEXT, template_count INTEGER, tools_json TEXT,
  counts_json TEXT, phases_json TEXT, epss_date TEXT, kev_version TEXT, ingested_at TEXT, notes TEXT);
CREATE TABLE IF NOT EXISTS assets(hostname TEXT PRIMARY KEY, apex TEXT, class TEXT, first_seen_run TEXT, last_seen_run TEXT);
CREATE TABLE IF NOT EXISTS asset_observations(run_id TEXT, hostname TEXT, apex TEXT, class TEXT, reason TEXT, ips TEXT, cnames TEXT,
  tech TEXT, waf TEXT, status_code INTEGER, title TEXT, server TEXT, urls TEXT, cert_expiry TEXT, PRIMARY KEY(run_id, hostname));
CREATE TABLE IF NOT EXISTS findings(finding_key TEXT PRIMARY KEY, hostname TEXT, apex TEXT, source TEXT, check_id TEXT, port INTEGER,
  title TEXT, severity TEXT, cve_ids TEXT, first_seen_run TEXT, last_seen_run TEXT, status TEXT, fixed_run TEXT);
CREATE TABLE IF NOT EXISTS finding_observations(run_id TEXT, finding_key TEXT, asset_class TEXT, matched TEXT, description TEXT,
  remediation TEXT, reference TEXT, tags TEXT, cvss REAL, epss REAL, kev INTEGER, impact INTEGER, likelihood INTEGER, score INTEGER,
  band TEXT, sla_days INTEGER, state TEXT, raw_json TEXT, verdict TEXT, verification TEXT, exposure TEXT, PRIMARY KEY(run_id, finding_key));
-- triage.py: what each High/Medium/confirmed finding actually exposes (items and secrets never carry a value)
CREATE TABLE IF NOT EXISTS finding_triage(run_id TEXT, finding_key TEXT, exposure TEXT, summary TEXT, fix TEXT, items_json TEXT,
  secrets_json TEXT, pci INTEGER, triaged_at TEXT, PRIMARY KEY(run_id, finding_key));
CREATE INDEX IF NOT EXISTS fo_run ON finding_observations(run_id);
CREATE INDEX IF NOT EXISTS ao_run ON asset_observations(run_id);
-- technology inventory (fingerprint.py): per-run components, one profile row per host, and cross-run tracking
CREATE TABLE IF NOT EXISTS asset_components(run_id TEXT, hostname TEXT, category TEXT, name TEXT, version TEXT, source TEXT,
  evidence TEXT, eol INTEGER, eol_date TEXT, PRIMARY KEY(run_id, hostname, category, name, version));
CREATE INDEX IF NOT EXISTS ac_run ON asset_components(run_id);
CREATE TABLE IF NOT EXISTS asset_profiles(run_id TEXT, hostname TEXT, hosting TEXT, hosting_source TEXT, asn TEXT, as_name TEXT, cdn TEXT,
  waf TEXT, load_balancer TEXT, os TEXT, web_server TEXT, language TEXT, framework TEXT, cms TEXT, tls_min TEXT, tls_max TEXT,
  cert_issuer TEXT, cert_expiry TEXT, eol_count INTEGER, PRIMARY KEY(run_id, hostname));
CREATE INDEX IF NOT EXISTS ap_run ON asset_profiles(run_id);
CREATE TABLE IF NOT EXISTS components(hostname TEXT, category TEXT, name TEXT, version TEXT, first_seen_run TEXT, last_seen_run TEXT,
  last_source TEXT, status TEXT, gone_run TEXT, PRIMARY KEY(hostname, category, name, version));
-- asset inventory evidence (evidence.py), per run: nothing here is a finding
CREATE TABLE IF NOT EXISTS certificates(run_id TEXT, hostname TEXT, port INTEGER, subject TEXT, sans TEXT, issuer TEXT, key_type TEXT,
  key_bits INTEGER, sig_alg TEXT, not_before TEXT, not_after TEXT, days_left INTEGER, expired INTEGER, self_signed INTEGER, serial TEXT,
  sha256 TEXT, source TEXT, PRIMARY KEY(run_id, hostname, port));
CREATE INDEX IF NOT EXISTS cert_run ON certificates(run_id);
CREATE TABLE IF NOT EXISTS tls_endpoints(run_id TEXT, hostname TEXT, port INTEGER, protocols TEXT, legacy INTEGER, preferred_cipher TEXT,
  weak_ciphers INTEGER, fallback_scsv INTEGER, secure_reneg INTEGER, compression INTEGER, heartbleed INTEGER, PRIMARY KEY(run_id, hostname, port));
CREATE INDEX IF NOT EXISTS tlse_run ON tls_endpoints(run_id);
CREATE TABLE IF NOT EXISTS dns_records(run_id TEXT, hostname TEXT, rtype TEXT, name TEXT, value TEXT, source TEXT, ttl INTEGER,
  PRIMARY KEY(run_id, hostname, rtype, name, value));
CREATE INDEX IF NOT EXISTS dnsr_run ON dns_records(run_id);
CREATE TABLE IF NOT EXISTS domain_posture(run_id TEXT, apex TEXT, spf INTEGER, spf_policy TEXT, dmarc INTEGER, dmarc_policy TEXT, dmarc_sp TEXT,
  dkim INTEGER, mx TEXT, mx_provider TEXT, caa INTEGER, caa_issuers TEXT, nameservers TEXT, ns_provider TEXT, hosts_with_spf INTEGER,
  hosts_with_dkim INTEGER, coverage TEXT, PRIMARY KEY(run_id, apex));
CREATE TABLE IF NOT EXISTS host_ports(run_id TEXT, hostname TEXT, ip TEXT, port INTEGER, proto TEXT, service TEXT, product TEXT, reason TEXT,
  risky INTEGER, web INTEGER, PRIMARY KEY(run_id, hostname, ip, port, proto));
CREATE INDEX IF NOT EXISTS hp_run ON host_ports(run_id);
CREATE TABLE IF NOT EXISTS asset_sources(run_id TEXT, hostname TEXT, source TEXT, PRIMARY KEY(run_id, hostname, source));
CREATE INDEX IF NOT EXISTS as_run ON asset_sources(run_id);
CREATE TABLE IF NOT EXISTS app_groups(run_id TEXT, url TEXT, hostname TEXT, group_url TEXT, group_host TEXT, members INTEGER, PRIMARY KEY(run_id, url));
CREATE INDEX IF NOT EXISTS ag_run ON app_groups(run_id);
CREATE TABLE IF NOT EXISTS endpoints(run_id TEXT, url TEXT, hostname TEXT, scheme TEXT, port INTEGER, status INTEGER, final_url TEXT, chain TEXT,
  content_type TEXT, content_length INTEGER, title TEXT, server TEXT, favicon_mmh3 TEXT, favicon_md5 TEXT, words INTEGER, lines INTEGER,
  response_ms REAL, hsts INTEGER, csp INTEGER, xfo INTEGER, xss_protection INTEGER, cookies TEXT, httponly_cookies TEXT, emails TEXT,
  analytics TEXT, generator TEXT, powered_by TEXT, password_field INTEGER, redirect_to TEXT, uncommon_headers TEXT, PRIMARY KEY(run_id, url));
CREATE INDEX IF NOT EXISTS ep_run ON endpoints(run_id);
-- daily rechecks (recon.sh --recheck): which hosts a recheck run actually re-tested, and the headline counts of every
-- scored run at ingest time (the trend reads these, because a recheck's carried-forward rows are pruned later)
CREATE TABLE IF NOT EXISTS recheck_hosts(run_id TEXT, hostname TEXT, PRIMARY KEY(run_id, hostname));
CREATE TABLE IF NOT EXISTS run_summary(run_id TEXT PRIMARY KEY, json TEXT);
"""
EVIDENCE_TABLES = ("certificates", "tls_endpoints", "dns_records", "domain_posture", "host_ports", "asset_sources", "app_groups", "endpoints")
# Per-host, per-run tables a recheck carries forward from the previous snapshot for the hosts it did not re-test.
CARRY_TABLES = ("asset_observations", "asset_profiles", "asset_components", "certificates", "tls_endpoints", "host_ports",
                "endpoints", "asset_sources", "app_groups", "dns_records")
# Which recon phase produces each finding source. A source whose phase did not run (or failed) this run cannot mark
# anything fixed: "not observed" then means "not looked at". Nuclei additionally needs every pass it normally runs.
SOURCE_PHASE = {"dns": 2, "http": 3, "nmap": 6, "sslscan": 7, "nuclei": 8}
NUCLEI_PASSES_FOR_FIXED = {"generic", "tech", "tp", "dns"}

def migrate(cur):
    """Columns added after the first runs were ingested. CREATE TABLE IF NOT EXISTS cannot add them, so ALTER in place
    and backfill: every run ingested before these columns existed was a full snapshot (kind full) or an inventory-only run."""
    have = {r[1] for r in cur.execute("PRAGMA table_info(runs)").fetchall()}
    for col, typ in (("kind", "TEXT"), ("base_run", "TEXT"), ("snapshot", "INTEGER"), ("evidence_level", "TEXT")):
        if col not in have:
            cur.execute(f"ALTER TABLE runs ADD COLUMN {col} {typ}")
    cur.execute("UPDATE runs SET kind = CASE WHEN COALESCE(inventory_only, 0) = 1 THEN 'inventory' ELSE 'full' END WHERE kind IS NULL")
    cur.execute("UPDATE runs SET snapshot = CASE WHEN kind = 'inventory' THEN 0 ELSE 1 END WHERE snapshot IS NULL")
    # verify.py content verdicts; runs ingested before the columns existed keep NULL
    have = {r[1] for r in cur.execute("PRAGMA table_info(finding_observations)").fetchall()}
    for col in ("verdict", "verification", "exposure"):   # exposure: triage.py
        if col not in have:
            cur.execute(f"ALTER TABLE finding_observations ADD COLUMN {col} TEXT")

def phases_ok(manifest):
    """Phase numbers that ran and exited 0 this run, or None when the manifest carries no phase records (older runs:
    treat every phase as run, which is what ingest always assumed before the gate existed)."""
    phases = manifest.get("phases") or []
    if not phases:
        return None
    return {int(p.get("phase")) for p in phases if p.get("rc") == 0}

COVERAGE_SOURCES = ("dns", "http", "nmap", "sslscan", "nuclei")
# nuclei coverage per pass (recon.sh): "nuclei" = the generic and technology passes (representatives and
# their siblings), nuclei_tp = third-party pass, nuclei_dns = DNS templates, nuclei_fp = fingerprint pass. When a
# manifest records no per-pass source, "nuclei" is used for every kind.
NUCLEI_PASS_SOURCES = ("nuclei_tp", "nuclei_dns", "nuclei_fp")
ACTIVE_COVERAGE_SOURCES = ("nmap", "sslscan", "nuclei") + NUCLEI_PASS_SOURCES   # phases 6-8: held-back hosts never reach them
NUCLEI_KIND_COVERAGE = {"http": "nuclei", "tp": "nuclei_tp", "dns": "nuclei_dns"}
NUCLEI_PASS_KIND = {"generic": "http", "tech": "http", "tp": "tp", "dns": "dns"}   # fp yields technology only, never findings
NUCLEI_ERROR_FILES = {"http": ("nuclei_errors_generic.jsonl", "nuclei_errors_tech.jsonl"), "tp": ("nuclei_errors_tp.jsonl",),
                      "dns": ("nuclei_errors_dns.jsonl",)}
# -elog "kind" values that mean no answer came back (nuclei v3.11.1; the four kinds its binary holds are these three
# and "unknown-error"): a timeout, deadline, refused, reset or closed port. Only such a line puts its URL path in the
# failed set. "unknown-error" also marks answers nuclei could not read (e.g. open-proxy-external's request at "/"),
# so it, like a line with no kind, counts against its own template only.
NO_ANSWER_KINDS = frozenset({"network-temporary-error", "network-permanent-error", "deadline-error"})

def load_coverage(run_dir, manifest):
    """{source: set of hosts actually handed to that source's tool this run}, or None when the manifest has no
    "coverage" key: then the phase rule alone decides (every in-scope host of a phase that ran and exited 0)."""
    if "coverage" not in manifest:
        return None
    cov = {}
    recorded = manifest.get("coverage") if isinstance(manifest.get("coverage"), dict) else {}
    for src in COVERAGE_SOURCES + tuple(x for x in NUCLEI_PASS_SOURCES if x in recorded):
        cov[src] = set(read_list(os.path.join(run_dir, "coverage", src + ".txt")))
    # hosts held back from active phases (not in the approved inventory, or their address moved) were not looked at
    # by any active tool this run, whatever a coverage file says: their findings stay open
    held, held_domains = set(), set()
    try:
        with open(os.path.join(run_dir, SC.HELD_BACK_FILE)) as fh:
            hd = json.load(fh)
        held = set((hd.get("hosts") or {}).keys())
        held_domains = {d for d in ((hd.get("domains") or {}).get("held_back") or []) if isinstance(d, str) and d}
    except (OSError, ValueError, AttributeError, TypeError):
        pass
    def under_held_domain(h):   # every name under a domain the approved inventory did not cover is held back too
        return any(h == d or h.endswith("." + d) for d in held_domains)
    for src in ACTIVE_COVERAGE_SOURCES:
        if src in cov:
            cov[src] = {h for h in cov[src] - held if not under_held_domain(h)}
    return cov

def template_id(path, templates_dir, cache):
    """The id of the nuclei template at path (its first "id:" line), read only from a regular .yaml file inside the
    run's templates folder; otherwise the file name without .yaml (nuclei's convention, true for most templates)."""
    if path in cache:
        return cache[path]
    base = os.path.basename(path)
    tid = base[:-5] if base.endswith(".yaml") else base
    try:
        real, root = os.path.realpath(path), os.path.realpath(templates_dir) if templates_dir else None
        if root and real.startswith(root + os.sep) and real.endswith(".yaml") and os.path.isfile(real) and os.path.getsize(real) < 1 << 20:
            with open(real, errors="ignore") as fh:
                for line in fh:
                    m = re.match(r"^id:\s*['\"]?([A-Za-z0-9._-]+)", line)
                    if m:
                        tid = m.group(1)
                        break
    except OSError:
        pass
    cache[path] = M.ident(tid, 100) or "*"
    return cache[path]

def url_path(u):
    """The path of a URL ("/" when it has none), or None when u is not an http(s) URL."""
    if not isinstance(u, str) or not re.match(r"^https?://", u, re.I):
        return None
    rest = re.sub(r"^https?://[^/?#]*", "", u, flags=re.I)
    path = rest.split("?", 1)[0].split("#", 1)[0]
    return path or "/"

def load_nuclei_errors(run_dir, templates_dir=None):
    """{kind: {host: {template id, ...}}} from the -elog files recon.sh asks nuclei for: one line per request nuclei
    could not complete (timeout, reset, refused, unreadable answer), with its template and host. The template id is
    read from the template file (template_id). A line whose kind says no answer came (NO_ANSWER_KINDS) also adds
    "path:<its URL path>". For the generic and technology passes an error
    on a representative counts for its siblings too: their findings come from the representative's requests."""
    out = {k: {} for k in NUCLEI_ERROR_FILES}
    cache = {}
    for kind, files in NUCLEI_ERROR_FILES.items():
        for fn in files:
            for d in jsonl(os.path.join(run_dir, fn)):
                if not isinstance(d, dict):
                    continue
                h = hostname_of(d.get("address") or d.get("input") or "")
                t = str(d.get("template") or "")
                tid = template_id(t, templates_dir, cache) if t else "*"
                if h:
                    out[kind].setdefault(h, set()).add(tid)
                    # nuclei sends one request for a cluster of templates that ask the same thing and logs a failure
                    # under one of them: the failed request's path catches every template of the cluster. That holds
                    # only when no answer came (NO_ANSWER_KINDS). Any other kind (one template's own odd request got an
                    # unreadable answer), or no kind, counts against that template only.
                    p = url_path(d.get("input"))
                    if p is not None and d.get("kind") in NO_ANSWER_KINDS:
                        out[kind][h].add("path:" + p)
    try:
        groups = json.load(open(os.path.join(run_dir, "nuclei_groups.json")))
    except (OSError, ValueError):
        groups = {}
    for rep, urls in (groups.items() if isinstance(groups, dict) else []):
        tids = out["http"].get(hostname_of(rep))
        if tids:
            for u in urls if isinstance(urls, list) else []:
                sib = hostname_of(u)
                if sib:
                    out["http"].setdefault(sib, set()).update(tids)
    return out

def nuclei_kind(raw_json, asset_class):
    """Which nuclei pass observes a finding: "dns" for a DNS template, "tp" for a third-party host, else "http"."""
    try:
        t = (json.loads(raw_json) or {}).get("type") if raw_json else None
    except (ValueError, AttributeError):
        t = None
    if t == "dns":
        return "dns"
    return "tp" if asset_class == "third_party" else "http"

def fixed_allowed(src, host, tags, coverage, check_profile, kind="http", errors=None, check_id=None, matched=None):
    """May an open finding that this run did not observe be marked fixed? (True, None) or (False, reason).
    Applied on top of the scope and phase rules: the host must have been handed to the finding's source this run (for
    nuclei: to the pass that observes it, kind http/tp/dns); nuclei must not have reported a failed request for that
    host and the finding's own template, or a request that got no answer at the URL path it matched at, in that pass (errors: load_nuclei_errors;
    a run whose requests for the check failed is no evidence that the issue is gone); and a finding raised by an active-only check is only fixed by a run
    that ran active checks."""
    cov_key = src
    if src == "nuclei" and coverage is not None:
        cov_key = NUCLEI_KIND_COVERAGE.get(kind, "nuclei")
        if cov_key not in coverage:      # a run from before the per-pass coverage: every pass was under "nuclei"
            cov_key = "nuclei"
    if coverage is not None and host not in coverage.get(cov_key, set()):
        return False, f"{cov_key}: host not tested"
    if src == "nuclei" and errors:
        if errors.get(kind, {}).get("*all*"):
            return False, f"nuclei {kind}: the pass exited with an error this run"
        failed = errors.get(kind, {}).get(host) or set()
        tid = (check_id or "").split(":", 1)[0]
        mp = url_path(matched)
        if "*" in failed or (tid and tid in failed) or (not tid and failed) or (mp is not None and "path:" + mp in failed):
            return False, f"nuclei {kind}: requests for this check to this host failed this run"
    if check_profile == "safe" and {t.lower() for t in (tags or [])} & set(SC.ACTIVE_TAGS):
        return False, "active-only check, safe run"
    return True, None

def _retested_table(cur, hosts_retested):
    cur.execute("CREATE TEMP TABLE IF NOT EXISTS _retested(hostname TEXT PRIMARY KEY)")
    cur.execute("DELETE FROM _retested")
    cur.executemany("INSERT OR IGNORE INTO _retested VALUES(?)", [(h,) for h in hosts_retested])

def carry_tables(cur, run_id, from_run, hosts_retested):
    """Copy the previous snapshot's per-host rows for every host NOT re-tested into this run, so the run's rows are the
    complete current state (every reader selects WHERE run_id = ?). Fresh rows for re-tested hosts are already in place
    and win (INSERT OR IGNORE on the per-run primary keys)."""
    _retested_table(cur, hosts_retested)
    carried = {}
    for t in CARRY_TABLES:
        cols = [r[1] for r in cur.execute(f"PRAGMA table_info({t})").fetchall() if r[1] != "run_id"]
        cl = ", ".join(cols)
        before = cur.execute(f"SELECT COUNT(*) FROM {t} WHERE run_id=?", (run_id,)).fetchone()[0]
        cur.execute(f"INSERT OR IGNORE INTO {t}(run_id, {cl}) SELECT ?, {cl} FROM {t} WHERE run_id=? "
                    f"AND hostname NOT IN (SELECT hostname FROM _retested)", (run_id, from_run))
        carried[t] = cur.execute(f"SELECT COUNT(*) FROM {t} WHERE run_id=?", (run_id,)).fetchone()[0] - before
    return carried

def carry_findings(cur, run_id, from_run):
    """Every finding still open after this run's fixed-marking that this run has no observation of: hosts not
    re-tested, plus findings on re-tested hosts whose phase did not run. Still open as far as this run knows, so
    they carry the previous snapshot's row and read as persistent here. Runs after fixed-marking."""
    cols = [r[1] for r in cur.execute("PRAGMA table_info(finding_observations)").fetchall() if r[1] != "run_id"]
    sel = ", ".join("'persistent'" if c == "state" else f"o.{c}" for c in cols)
    before = cur.execute("SELECT COUNT(*) FROM finding_observations WHERE run_id=?", (run_id,)).fetchone()[0]
    cur.execute(f"INSERT OR IGNORE INTO finding_observations(run_id, {', '.join(cols)}) SELECT ?, {sel} FROM finding_observations o "
                "JOIN findings f ON f.finding_key = o.finding_key WHERE o.run_id=? AND f.status='open' "
                "AND NOT EXISTS (SELECT 1 FROM finding_observations x WHERE x.run_id=? AND x.finding_key=o.finding_key)", (run_id, from_run, run_id))
    return cur.execute("SELECT COUNT(*) FROM finding_observations WHERE run_id=?", (run_id,)).fetchone()[0] - before

def carry_triage(cur, run_id, from_run, observed):
    """The triage of every carried finding comes along with its observation (a finding this run observed has its own)."""
    keys = [r[0] for r in cur.execute("SELECT finding_key FROM finding_observations WHERE run_id=?", (run_id,)).fetchall() if r[0] not in observed]
    n = 0
    for k in keys:
        n += cur.execute("INSERT OR IGNORE INTO finding_triage SELECT ?, finding_key, exposure, summary, fix, items_json, secrets_json, pci, triaged_at "
                         "FROM finding_triage WHERE run_id=? AND finding_key=?", (run_id, from_run, k)).rowcount
    return n

def prune_snapshots(cur, run_id):
    """A recheck run holds a full snapshot (its own rows plus the carried ones) only while it is the latest or the one
    before it; older rechecks keep just what they re-tested, so the database grows by what was observed, not by a
    copy of the whole estate per day. Full runs are never pruned. run_summary keeps each run's headline counts."""
    holders = [r[0] for r in cur.execute("SELECT run_id FROM runs WHERE kind='recheck' AND snapshot=1 AND run_id!=? ORDER BY seq DESC", (run_id,)).fetchall()]
    pruned = []
    for old in holders[1:]:
        for t in CARRY_TABLES:
            cur.execute(f"DELETE FROM {t} WHERE run_id=? AND hostname NOT IN (SELECT hostname FROM recheck_hosts WHERE run_id=?)", (old, old))
        cur.execute("DELETE FROM finding_observations WHERE run_id=? AND finding_key IN (SELECT finding_key FROM findings WHERE hostname NOT IN "
                    "(SELECT hostname FROM recheck_hosts WHERE run_id=?))", (old, old))
        cur.execute("DELETE FROM finding_triage WHERE run_id=? AND finding_key NOT IN (SELECT finding_key FROM finding_observations WHERE run_id=?)", (old, old))
        cur.execute("UPDATE runs SET snapshot=0 WHERE run_id=?", (old,))
        pruned.append(old)
    return pruned

def write_summary(cur, run_id, extra=None):
    """Headline counts of a scored run, taken while its rows are complete. The report's trends read this row for
    runs whose carried rows were pruned since."""
    q = lambda sql, *a: cur.execute(sql, a).fetchone()[0]  # noqa: E731
    bands = {b: q("SELECT COUNT(*) FROM finding_observations WHERE run_id=? AND band=?", run_id, b) for b in ("Critical", "High", "Medium", "Low")}
    s = {"run_id": run_id, "bands": bands, "total": sum(bands.values()), "critical_high": bands["Critical"] + bands["High"],
         "new": q("SELECT COUNT(*) FROM finding_observations WHERE run_id=? AND state='new'", run_id),
         "reopened": q("SELECT COUNT(*) FROM finding_observations WHERE run_id=? AND state='reopened'", run_id),
         "persistent": q("SELECT COUNT(*) FROM finding_observations WHERE run_id=? AND state='persistent'", run_id),
         "fixed": q("SELECT COUNT(*) FROM findings WHERE fixed_run=?", run_id),
         "kev": q("SELECT COUNT(*) FROM finding_observations WHERE run_id=? AND kev=1", run_id),
         "hosts_live": q("SELECT COUNT(*) FROM asset_observations WHERE run_id=? AND class!='dead'", run_id),
         "hosts_owned": q("SELECT COUNT(*) FROM asset_observations WHERE run_id=? AND class='owned'", run_id),
         "hosts_unverified": q("SELECT COUNT(*) FROM asset_observations WHERE run_id=? AND class='unverified'", run_id),
         "hosts_eol": q("SELECT COUNT(*) FROM asset_profiles WHERE run_id=? AND COALESCE(eol_count,0)>0", run_id),
         "legacy_tls_hosts": q("SELECT COUNT(DISTINCT hostname) FROM tls_endpoints WHERE run_id=? AND legacy=1", run_id),
         **(extra or {})}
    cur.execute("INSERT OR REPLACE INTO run_summary VALUES(?,?)", (run_id, json.dumps(s)))
    return s

def jsonl(path):
    if not os.path.exists(path):
        return
    for line in _readlines(path, errors="ignore"):
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except Exception:
            continue

def read_list(path):
    """Scope-file style list: one entry per line, # comments (whole-line or trailing), blanks ignored."""
    if not os.path.exists(path):
        return []
    out = []
    for line in _readlines(path, errors="ignore"):
        line = line.split("#", 1)[0].strip()
        if line:
            out.append(line)
    return out

def hostname_of(s):
    s = (s or "").strip().lower()
    s = re.sub(r"^[a-z]+://", "", s)
    s = s.split("/")[0]
    if s.startswith("["):
        return s.split("]")[0].lstrip("[")
    return s.split(":")[0].rstrip(".")

def port_of(url, default=None):
    m = re.match(r"^(https?)://[^/]*?(?::(\d+))?(?:/|$)", url or "")
    if not m:
        return default
    if m.group(2):
        return int(m.group(2))
    return 443 if m.group(1) == "https" else 80

# ------------------------------------------------------------------ enrichment
def fetch_cached(url, cache_dir, prefix, ext, offline, max_age_days=1):
    os.makedirs(cache_dir, exist_ok=True)
    today = dt.date.today().isoformat()
    target = os.path.join(cache_dir, f"{prefix}-{today}{ext}")
    if not os.path.exists(target) and not offline:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "momus-ingest/0.1.0"})
            with urllib.request.urlopen(req, timeout=120) as r, open(target, "wb") as f:
                f.write(r.read())
        except Exception as e:
            print(f"warn: could not fetch {url}: {e}", file=sys.stderr)
    files = sorted(glob.glob(os.path.join(cache_dir, f"{prefix}-*{ext}")))
    return files[-1] if files else None

def load_epss(path):
    scores, date = {}, None
    if not path:
        return scores, date
    with gzip.open(path, "rt", errors="ignore") as f:
        first = f.readline()
        m = re.search(r"score_date:(\S+)", first)
        date = m.group(1) if m else os.path.basename(path)
        rest = f if first.startswith("#") else io.StringIO(first + f.read())
        for row in csv.DictReader(rest):
            try:
                scores[row["cve"].upper()] = float(row["epss"])
            except Exception:
                pass
    return scores, date

def load_kev(path):
    if not path:
        return set(), None
    try:
        d = json.load(open(path))
        return {v["cveID"].upper() for v in d.get("vulnerabilities", [])}, d.get("catalogVersion")
    except Exception:
        return set(), None

def load_eol(run_dir, cache_dir, run_day):
    """{product_slug: [cycle dicts]}. The enrich step (enrich.py) fetches endoflife.date into runs/<id>/eol/;
    this copies those files into data/eol/<slug>-<run date>.json and otherwise uses the newest cached copy per
    product. Ingest itself downloads nothing from endoflife.date."""
    os.makedirs(cache_dir, exist_ok=True)
    fetched = 0
    for p in glob.glob(os.path.join(run_dir, "eol", "*.json")):
        slug = os.path.basename(p)[:-5]
        try:
            json.load(open(p))
        except Exception:
            continue
        target = os.path.join(cache_dir, f"{slug}-{run_day.isoformat()}.json")
        if not os.path.exists(target):
            shutil.copyfile(p, target)
        fetched += 1
    out = {}
    for slug in sorted(set(F.EOL_PRODUCTS.values())):
        files = sorted(glob.glob(os.path.join(cache_dir, f"{slug}-*.json")))
        if files:
            try:
                out[slug] = json.load(open(files[-1]))
            except Exception:
                pass
    if not fetched:
        print(f"warn: no eol/ files in the run directory (older run, or enrich.py did not run); using cached copies for {len(out)} product(s)", file=sys.stderr)
    return out

def load_asn(run_dir):
    """{ip: {asn, as_name, prefix, cc}} as written by the enrich step (runs/<id>/asn.json); empty for older runs."""
    p = os.path.join(run_dir, "asn.json")
    if not os.path.exists(p):
        print("warn: no asn.json in the run directory (older run, or enrich.py did not run); hosting falls back to CNAME/CDN evidence", file=sys.stderr)
        return {}
    try:
        return json.load(open(p))
    except Exception as e:
        print(f"warn: asn.json unreadable: {e}", file=sys.stderr)
        return {}

# ------------------------------------------------------------------ normalizers
def norm_nuclei(run_dir, asset_class):
    # representative URL -> every sibling URL that is the same app (see dedupe.py)
    gp = os.path.join(run_dir, "nuclei_groups.json")
    groups = json.load(open(gp)) if os.path.exists(gp) else {}
    sib_by_host = {}
    for rep, urls in groups.items():
        sib_by_host[hostname_of(rep)] = sorted({hostname_of(u) for u in urls} - {hostname_of(rep)})
    for fn in ("nuclei_owned.jsonl", "nuclei_tech.jsonl", "nuclei_tp.jsonl", "nuclei_dns.jsonl", "nuclei_fp.jsonl"):
        for d in jsonl(os.path.join(run_dir, fn)):
            info = d.get("info") or {}
            # template id and matcher name become part of the finding key: cleaned deterministically (minimize.ident)
            tid = M.ident(d.get("template-id") or d.get("templateID") or "", 100)
            matcher = M.ident(d.get("matcher-name"), 64) if d.get("matcher-name") else None
            tags = [t.lower() for t in (info.get("tags") or [])]
            host = hostname_of(d.get("host") or d.get("matched-at") or d.get("input"))
            cls = asset_class.get(host, "unverified")
            sev = (info.get("severity") or "info").lower()
            classification = info.get("classification") or {}
            cves = classification.get("cve-id") or []
            if isinstance(cves, str):
                cves = [cves]
            cvss = classification.get("cvss-score")
            # severity "unknown" is what nuclei reports for templates without one (dns-rebinding), treat it like info
            if sev in ("info", "unknown") and (tid in NOISE_IDS or (set(tags) & NOISE_TAGS)) and not cves:
                yield ("tech", host, {"template": tid, "name": info.get("name"), "extracted": d.get("extracted-results"), "matcher": matcher})
                continue
            port = d.get("port")
            try:
                port = int(port) if port else port_of(d.get("matched-at") or d.get("host"))
            except Exception:
                port = port_of(d.get("matched-at") or d.get("host"))
            check = tid + (f":{matcher}" if matcher else "")
            sibs = sib_by_host.get(host, [])
            desc = (info.get("description") or "").strip()
            if sibs:
                desc += f"\n\nAlso applies to {len(sibs)} other hostname(s) serving the same application: " + ", ".join(sibs[:25]) + (" ..." if len(sibs) > 25 else "")
            yield ("finding", host, {
                "source": "nuclei", "check_id": check, "port": port, "title": info.get("name") or tid,
                "severity": sev, "cvss": float(cvss) if cvss else None, "cve_ids": [c.upper() for c in cves],
                "tags": tags, "asset_class": cls, "matched": d.get("matched-at"),
                "description": desc, "remediation": (info.get("remediation") or "").strip(),
                "reference": info.get("reference") or [], "raw": {**d, "siblings": sibs},
            })

def norm_nmap(run_dir, ip_to_host, asset_class):
    p = os.path.join(run_dir, "nmap.xml")
    if not os.path.exists(p):
        return
    try:
        root = ET.parse(p).getroot()
    except ET.ParseError as e:
        print(f"warn: nmap.xml unparsable: {e}", file=sys.stderr); return
    for h in root.iter("host"):
        ip = next((a.get("addr") for a in h.findall("address") if a.get("addrtype") in ("ipv4", "ipv6")), None)
        if not ip:
            continue
        host = ip_to_host.get(ip, ip)
        # Anycast/edge proxies (Fly.io, some WAFs) accept the TCP handshake on every port, so nmap reports
        # dozens of "open" tcpwrapped ports that say nothing about real services. Collapse those to one note.
        open_ports = [p for p in h.iter("port") if p.find("state") is not None and p.find("state").get("state") == "open"]
        wrapped = [p for p in open_ports if (p.find("service") is not None and p.find("service").get("name") == "tcpwrapped")]
        risky_wrapped = [p for p in wrapped if int(p.get("portid")) in RISKY_PORTS or (p.find("service").get("name") or "").lower() in RISKY_SERVICES]
        if len(risky_wrapped) >= 5:
            yield ("finding", host, {
                "source": "nmap", "check_id": "catch-all-proxy", "port": None, "title": f"Accepts connections on every probed port ({len(open_ports)} open, all tcpwrapped) - proxy/anycast front",
                "severity": "low", "cvss": None, "cve_ids": [], "tags": ["network"], "asset_class": asset_class.get(host, "unverified"), "matched": ip,
                "description": f"{ip} completes the TCP handshake on all probed ports including {', '.join(str(p.get('portid')) for p in risky_wrapped[:8])}, then closes without a banner. "
                               "This is the behaviour of an edge proxy (e.g. Fly.io, a WAF) rather than real exposed services; confirm with the hosting provider what is actually routed.",
                "remediation": "No action if this is a known edge proxy. If it is a real host, restrict the listening services by firewall.", "reference": [],
                "raw": {"ip": ip, "open_ports": [p.get("portid") for p in open_ports]}})
            continue
        for prt in h.iter("port"):
            st = prt.find("state")
            if st is None or st.get("state") != "open":
                continue
            port = int(prt.get("portid")); proto = prt.get("protocol")
            svc = prt.find("service")
            name = (svc.get("name") if svc is not None else "") or ""
            product = " ".join(x for x in [svc.get("product") if svc is not None else None, svc.get("version") if svc is not None else None] if x)
            scripts = {s.get("id"): (s.get("output") or "")[:2000] for s in prt.findall("script")}
            risky = name.lower() in RISKY_SERVICES or port in RISKY_PORTS
            if not risky and (port in WEB_PORTS or "http" in name.lower()):
                continue  # httpx/nuclei already cover web endpoints; an open 443 is not a finding
            sev = "medium" if risky else "info"
            tags = ["network", "exposure"] if risky else ["network"]
            title = f"Open port {port}/{proto} {name} {product}".strip()
            if risky:
                title = f"Exposed service: {name or port}/{proto} {product}".strip()
            yield ("finding", host, {
                "source": "nmap", "check_id": f"{port}/{proto}", "port": port, "title": title, "severity": sev, "cvss": None,
                "cve_ids": [], "tags": tags, "asset_class": asset_class.get(host, "unverified"), "matched": f"{ip}:{port}",
                "description": f"Service {name} ({product or 'unknown version'}) is reachable from the internet on {ip}:{port}/{proto}."
                               + (" This service class should not be internet-exposed; restrict by firewall or VPN." if risky else ""),
                "remediation": "Confirm the service must be public; otherwise firewall it. Keep the daemon patched." if risky else "",
                "reference": [], "raw": {"ip": ip, "port": port, "proto": proto, "service": name, "product": product, "scripts": scripts},
            })

def _nmap_root(run_dir):
    p = os.path.join(run_dir, "nmap.xml")
    if not os.path.exists(p):
        return None
    try:
        return ET.parse(p).getroot()
    except ET.ParseError:
        return None

def nmap_services(run_dir, ip_to_host):
    """{host: [{port, service, product, scripts}]} for every open port, including web ports (fingerprint evidence only)."""
    p = os.path.join(run_dir, "nmap.xml")
    out = {}
    if not os.path.exists(p):
        return out
    try:
        root = ET.parse(p).getroot()
    except ET.ParseError:
        return out
    for h in root.iter("host"):
        ip = next((a.get("addr") for a in h.findall("address") if a.get("addrtype") in ("ipv4", "ipv6")), None)
        if not ip:
            continue
        host = ip_to_host.get(ip, ip)
        for prt in h.iter("port"):
            st = prt.find("state")
            if st is None or st.get("state") != "open":
                continue
            svc = prt.find("service")
            out.setdefault(host, []).append({
                "port": int(prt.get("portid")), "service": (svc.get("name") if svc is not None else "") or "",
                "product": " ".join(x for x in [svc.get("product") if svc is not None else None, svc.get("version") if svc is not None else None] if x),
                "scripts": {sc.get("id"): (sc.get("output") or "")[:500] for sc in prt.findall("script")}})
    return out

def _sslscan_root(run_dir):
    root = None
    for p in sorted(glob.glob(os.path.join(run_dir, "sslscan*.xml"))):
        if os.path.getsize(p) == 0:
            continue
        txt = open(p, errors="ignore").read()
        try:
            r = ET.fromstring(txt)
        except ET.ParseError:
            # killed by timeout -> unclosed document; drop the partial last <ssltest> and close it
            cut = txt.rfind("<ssltest")
            try:
                r = ET.fromstring(txt[:cut] + "</document>")
                print(f"warn: {os.path.basename(p)} was truncated; recovered the complete hosts", file=sys.stderr)
            except ET.ParseError as e:
                print(f"warn: {os.path.basename(p)} unparsable: {e}", file=sys.stderr); continue
        if root is None:
            root = ET.Element("document")
        root.extend(list(r.iter("ssltest")))
    return root

def sslscan_summary(run_dir):
    """{host: {protocols: [enabled labels], issuer}} from sslscan, fingerprint evidence only."""
    root = _sslscan_root(run_dir)
    out = {}
    if root is None:
        return out
    for t in root.iter("ssltest"):
        host = hostname_of(t.get("host"))
        enabled = [f"{pr.get('type','')}{pr.get('version')}" for pr in t.findall("protocol") if pr.get("enabled") == "1"]
        cert = t.find("certificate")
        issuer = (cert.findtext("issuer") or "").strip() if cert is not None else ""
        m = re.search(r"O\s*=\s*([^,/]+)", issuer)
        rec = out.setdefault(host, {"protocols": [], "issuer": None})
        rec["protocols"] = sorted(set(rec["protocols"]) | set(enabled))
        if m and not rec["issuer"]:
            rec["issuer"] = m.group(1).strip()
    return out

def norm_sslscan(run_dir, asset_class):
    root = _sslscan_root(run_dir)
    if root is None:
        return
    now = dt.datetime.now(dt.timezone.utc)
    for t in root.iter("ssltest"):
        host = hostname_of(t.get("host")); port = int(t.get("port") or 443)
        cls = asset_class.get(host, "unverified")
        base = {"source": "sslscan", "port": port, "cvss": None, "cve_ids": [], "asset_class": cls, "matched": f"{host}:{port}", "reference": [], "raw": {}}
        legacy = [f"{pr.get('type','').upper()}{pr.get('version')}" for pr in t.findall("protocol")
                  if pr.get("enabled") == "1" and (pr.get("type") == "ssl" or pr.get("version") in ("1.0", "1.1"))]
        if legacy:
            yield ("finding", host, {**base, "check_id": "legacy-protocol", "title": "Legacy TLS/SSL protocol enabled: " + ", ".join(legacy),
                   "severity": "medium" if any(l.startswith("SSL") for l in legacy) else "low", "tags": ["tls-legacy", "ssl"],
                   "description": "The server negotiates deprecated protocol versions (" + ", ".join(legacy) + "). PCI DSS and modern browsers require TLS 1.2+.",
                   "remediation": "Disable SSLv2/SSLv3/TLS 1.0/TLS 1.1 in the TLS terminator configuration.", "raw": {"protocols": legacy}})
        weak = sorted({c.get("cipher") for c in t.findall("cipher") if c.get("status") in ("accepted", "preferred")
                       and (c.get("strength", "").lower() in ("weak", "null", "anonymous", "medium") or (c.get("bits") or "999").isdigit() and int(c.get("bits")) < 128)})
        if weak:
            yield ("finding", host, {**base, "check_id": "weak-ciphers", "title": f"Weak cipher suites accepted ({len(weak)})", "severity": "low",
                   "tags": ["weak-cipher", "ssl"], "description": "Accepted: " + ", ".join(weak[:15]) + ("..." if len(weak) > 15 else ""),
                   "remediation": "Restrict cipher suites to AEAD suites (AES-GCM, CHACHA20) with ECDHE key exchange.", "raw": {"ciphers": weak}})
        hb = [x for x in t.findall("heartbleed") if x.get("vulnerable") == "1"]
        if hb:
            yield ("finding", host, {**base, "check_id": "heartbleed", "title": "Heartbleed (CVE-2014-0160)", "severity": "critical", "cvss": 7.5,
                   "cve_ids": ["CVE-2014-0160"], "tags": ["cve", "ssl"], "description": "OpenSSL heartbeat extension leaks server memory.",
                   "remediation": "Upgrade OpenSSL and rotate the certificate/private key.", "raw": {}})
        ren = t.find("renegotiation")
        if ren is not None and ren.get("supported") == "1" and ren.get("secure") == "0":
            yield ("finding", host, {**base, "check_id": "insecure-renegotiation", "title": "Insecure TLS renegotiation supported", "severity": "medium",
                   "cve_ids": ["CVE-2009-3555"], "tags": ["cve", "ssl"], "description": "Client-initiated insecure renegotiation is enabled.",
                   "remediation": "Disable client-initiated renegotiation.", "raw": {}})
        for cert in t.findall("certificate"):
            exp_txt = (cert.findtext("not-valid-after") or "").strip()
            expired = (cert.findtext("expired") or "").strip().lower() == "true"
            selfsigned = (cert.findtext("self-signed") or "").strip().lower() == "true"
            sig = (cert.findtext("signature-algorithm") or "").strip()
            exp = None
            for fmt in ("%b %d %H:%M:%S %Y GMT", "%b %d %H:%M:%S %Y %Z"):
                try:
                    exp = dt.datetime.strptime(exp_txt, fmt).replace(tzinfo=dt.timezone.utc); break
                except Exception:
                    pass
            if expired or (exp and exp < now):
                yield ("finding", host, {**base, "check_id": "cert-expired", "title": f"TLS certificate expired ({exp_txt})", "severity": "high",
                       "tags": ["cert-expired", "ssl"], "description": "Clients will show a security error; monitoring may already be failing.",
                       "remediation": "Renew and deploy the certificate; automate renewal.", "raw": {"not_after": exp_txt}})
            elif exp and (exp - now).days <= 30:
                yield ("finding", host, {**base, "check_id": "cert-expiring", "title": f"TLS certificate expires in {(exp - now).days} days ({exp_txt})",
                       "severity": "medium", "tags": ["cert-expiring", "ssl"], "description": "Certificate nearing expiry.", "remediation": "Renew now.", "raw": {"not_after": exp_txt}})
            if selfsigned:
                yield ("finding", host, {**base, "check_id": "cert-self-signed", "title": "Self-signed TLS certificate", "severity": "low", "tags": ["ssl"],
                       "description": "Certificate is not issued by a trusted CA.", "remediation": "Issue from a public CA (e.g. Let's Encrypt).", "raw": {}})
            if sig and ("sha1" in sig.lower() or "md5" in sig.lower()):
                yield ("finding", host, {**base, "check_id": "cert-weak-sig", "title": f"Certificate uses weak signature algorithm ({sig})", "severity": "medium",
                       "tags": ["ssl"], "description": "SHA-1/MD5 signed certificates are rejected by modern clients.", "remediation": "Reissue with SHA-256.", "raw": {}})
            break  # first (leaf) certificate only

def norm_axfr(run_dir, asset_class):
    p = os.path.join(run_dir, "axfr.json")
    if not os.path.exists(p):
        return
    for a in json.load(open(p)):
        if a.get("success"):
            yield ("finding", a["apex"], {"source": "dns", "check_id": f"axfr:{M.host(a['ns'])}", "port": 53, "title": f"DNS zone transfer (AXFR) allowed from {a['ns']}",
                   "severity": "high", "cvss": None, "cve_ids": [], "tags": ["axfr", "dns", "exposure"], "asset_class": "owned", "matched": a["ns"],
                   "description": f"The authoritative server {a['ns']} returned the full zone for {a['apex']} ({a.get('records')} records) to an unauthenticated client.",
                   "remediation": "Restrict zone transfers (allow-transfer) to secondary nameservers only.", "reference": [], "raw": a})

def norm_internal(assets):
    for a in assets:
        if a["class"] == "internal":
            yield ("finding", a["hostname"], {"source": "dns", "check_id": "internal-ip-disclosure", "port": None, "title": f"Public DNS exposes internal IP ({', '.join(a['ips'])})",
                   "severity": "low", "cvss": None, "cve_ids": [], "tags": ["dns", "info-leak"], "asset_class": "owned", "matched": a["hostname"],
                   "description": "A public DNS record resolves to RFC1918/private space. It leaks internal addressing and naming to anyone who enumerates the zone.",
                   "remediation": "Move the record to an internal (split-horizon) zone, or remove it if unused.", "reference": [], "raw": {"ips": a["ips"], "cnames": a["cnames"]}})

def norm_http_only(assets):
    for a in assets:
        if a["class"] == "dead" or not a["endpoints"]:
            continue
        has_https = any((e.get("url") or "").startswith("https://") for e in a["endpoints"])
        http_ok = [e for e in a["endpoints"] if (e.get("url") or "").startswith("http://") and (e.get("status") or 0) < 300 and not (e.get("final_url") or "").startswith("https://")]
        if not has_https and http_ok:
            yield ("finding", a["hostname"], {"source": "http", "check_id": "http-only", "port": 80, "title": "Served over plaintext HTTP only (no HTTPS)",
                   "severity": "low", "cvss": None, "cve_ids": [], "tags": ["headers", "misconfig"], "asset_class": a["class"], "matched": http_ok[0].get("url"),
                   "description": "No HTTPS endpoint answered and HTTP does not redirect to HTTPS.", "remediation": "Enable TLS and redirect HTTP to HTTPS.", "reference": [], "raw": {}})

# ------------------------------------------------------------------ main
def main(argv=None, offline_fetch=None, offline_probe=None):
    """offline_fetch / offline_probe: tests only. With --offline they stand in for the network in verify and triage
    (production offline ingests never fetch: without them every follow-up gets the 'offline' stub)."""
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True); ap.add_argument("--run-id", required=True); ap.add_argument("--offline", action="store_true")
    ap.add_argument("--no-feeds", action="store_true", help="do not download the EPSS and KEV feeds (lab runs)")
    a = ap.parse_args(argv)
    run_dir = os.path.join(a.root, "runs", a.run_id)
    if not os.path.isdir(run_dir):
        sys.exit(f"run dir not found: {run_dir}")
    try:
        F.own_networks()      # checked before any database work: a bad line is one error naming file and line
    except F.OwnNetworksError as e:
        sys.exit(f"error: {e}")
    manifest = json.load(open(os.path.join(run_dir, "manifest.json"))) if os.path.exists(os.path.join(run_dir, "manifest.json")) else {}
    try:
        level = M.evidence_level(manifest)   # what is stored of each finding's evidence (minimize.py)
    except M.EvidenceLevelError as e:
        sys.exit(f"error: {e}")
    inventory_only = bool(manifest.get("inventory_only"))
    recheck = bool(manifest.get("recheck")) and not inventory_only
    base_run = manifest.get("base_run") if recheck else None
    run_kind = "inventory" if inventory_only else ("recheck" if recheck else "full")
    # a recheck re-tests this host list (written by recheck_targets.py from the database to scope/recheck_hosts.txt,
    # copied into the run directory by recon.sh) and nothing else
    retested = set(read_list(os.path.join(run_dir, "recheck_hosts.txt"))) if recheck else set()
    if recheck and (not retested or not base_run):
        sys.exit("recheck run without recheck_hosts.txt or base_run in manifest.json; nothing to ingest")

    assets = list(jsonl(os.path.join(run_dir, "assets.jsonl")))
    asset_class = {x["hostname"]: x["class"] for x in assets}
    ip_to_host = {}
    if recheck:
        # keep the full run's address -> hostname choice (shortest name among EVERY host on the address), so an nmap
        # finding on a shared address stays keyed to the same host it was first seen on
        base_assets = list(jsonl(os.path.join(a.root, "runs", base_run, "assets.jsonl")))
        for x in sorted(base_assets, key=lambda r: (len(r["hostname"]), r["hostname"])):
            for ip in x["ips"]:
                ip_to_host.setdefault(ip, x["hostname"])
    for x in sorted(assets, key=lambda r: (len(r["hostname"]), r["hostname"])):
        for ip in x["ips"]:
            ip_to_host.setdefault(ip, x["hostname"])

    no_download = a.offline or a.no_feeds
    epss_path = fetch_cached(EPSS_URL, os.path.join(a.root, "data", "epss"), "epss", ".csv.gz", no_download)
    kev_path = fetch_cached(KEV_URL, os.path.join(a.root, "data", "kev"), "kev", ".json", no_download)
    if a.no_feeds:
        print("enrichment: --no-feeds, EPSS and KEV not downloaded" + ("" if (epss_path or kev_path) else " (no cached copy: scores without them)"))
    epss, epss_date = load_epss(epss_path); kev, kev_ver = load_kev(kev_path)
    print(f"enrichment: EPSS {len(epss)} cves ({epss_date}), KEV {len(kev)} cves ({kev_ver})")

    db = sqlite3.connect(os.path.join(a.root, "data", "scan.sqlite"))
    db.executescript(SCHEMA)
    cur = db.cursor()
    migrate(cur)
    now = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")

    # previous run for delta: a full run compares with the previous full run; a recheck with the full run it refines
    latest_full = (cur.execute("SELECT run_id FROM runs WHERE kind='full' AND run_id!=? ORDER BY seq DESC LIMIT 1", (a.run_id,)).fetchone() or [None])[0]
    prev_run = base_run if recheck else latest_full
    carry_from = None
    if recheck:
        if base_run != latest_full:
            sys.exit(f"recheck {a.run_id} was built on run {base_run} but the latest full run is {latest_full}; regenerate the targets (recheck_targets.py) and rerun")
        latest_scored = (cur.execute("SELECT run_id FROM runs WHERE kind IN ('full','recheck') ORDER BY seq DESC LIMIT 1").fetchone() or [None])[0]
        if cur.execute("SELECT 1 FROM runs WHERE run_id=?", (a.run_id,)).fetchone() and latest_scored != a.run_id:
            sys.exit(f"recheck {a.run_id} is already ingested and {latest_scored} came after it; re-ingesting an older recheck is not supported")
        # the previous complete snapshot: the latest full run or the latest recheck that still holds its carried rows
        carry_from = (cur.execute("SELECT run_id FROM runs WHERE kind IN ('full','recheck') AND snapshot=1 AND run_id!=? ORDER BY seq DESC LIMIT 1", (a.run_id,)).fetchone() or [None])[0]
        if not carry_from:
            sys.exit("no previous snapshot to carry forward from")

    cur.execute("INSERT OR REPLACE INTO runs(run_id,started,finished,inventory_only,nuclei_version,template_version,template_count,tools_json,counts_json,phases_json,epss_date,kev_version,ingested_at,notes,kind,base_run,snapshot,evidence_level) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (a.run_id, manifest.get("started"), manifest.get("finished"), int(inventory_only), (manifest.get("tools") or {}).get("nuclei"),
                 manifest.get("nuclei_templates_version"), manifest.get("nuclei_template_count"), json.dumps(manifest.get("tools")),
                 json.dumps(manifest.get("counts")), json.dumps(manifest.get("phases")), epss_date, kev_ver, now,
                 (cur.execute("SELECT notes FROM runs WHERE run_id=?", (a.run_id,)).fetchone() or [None])[0],  # keep hand-written notes across re-ingests
                 run_kind, base_run, 0 if inventory_only else 1, level))
    cur.execute("DELETE FROM asset_observations WHERE run_id=?", (a.run_id,))
    cur.execute("DELETE FROM finding_observations WHERE run_id=?", (a.run_id,))
    cur.execute("DELETE FROM finding_triage WHERE run_id=?", (a.run_id,))
    cur.execute("DELETE FROM recheck_hosts WHERE run_id=?", (a.run_id,))
    cur.executemany("INSERT OR IGNORE INTO recheck_hosts VALUES(?,?)", [(a.run_id, h) for h in sorted(retested)])

    # whatweb plugins per host (names, versions and the informative string values; merged across the host's URLs)
    whatweb, waf = {}, {}
    ww = os.path.join(run_dir, "whatweb.json")
    if os.path.exists(ww):
        try:
            for e in json.load(open(ww, errors="ignore")):
                h = hostname_of(e.get("target"))
                for k, v in (e.get("plugins") or {}).items():
                    slot = whatweb.setdefault(h, {}).setdefault(k, {"string": [], "version": []})
                    for kk in ("string", "version"):
                        for x in (v or {}).get(kk) or []:
                            if x not in slot[kk]:
                                slot[kk].append(x)
        except Exception as e:
            print(f"warn: whatweb.json: {e}", file=sys.stderr)
    wf = os.path.join(run_dir, "waf.json")
    if os.path.exists(wf):
        try:
            for e in json.load(open(wf, errors="ignore")):
                if e.get("detected"):
                    waf[hostname_of(e.get("url"))] = e.get("firewall")
        except Exception as e:
            print(f"warn: waf.json: {e}", file=sys.stderr)

    nuclei_tech = {}
    findings = []
    for kind, host, payload in list(norm_nuclei(run_dir, asset_class)) + list(norm_nmap(run_dir, ip_to_host, asset_class)) \
            + list(norm_sslscan(run_dir, asset_class)) + list(norm_axfr(run_dir, asset_class)) + list(norm_http_only(assets)) + list(norm_internal(assets)):
        if kind == "tech":
            nuclei_tech.setdefault(host, []).append(payload)
        else:
            findings.append((host, payload))

    # fingerprint evidence that is not per-asset yet: nmap banners, sslscan protocols, ASN, scope lists
    LIVE = ("owned", "cdn_fronted", "third_party", "unverified")
    nmap_svc = nmap_services(run_dir, ip_to_host)
    ssl_sum = sslscan_summary(run_dir)
    live_ips = sorted({ip for x in assets if x["class"] in LIVE for ip in x["ips"] if F._is_public(ip)})
    run_day = dt.date.fromisoformat((manifest.get("finished") or manifest.get("started") or now)[:10])
    asn_map = load_asn(run_dir)
    eol_data = load_eol(run_dir, os.path.join(a.root, "data", "eol"), run_day)
    owned_aws = read_list(os.path.join(a.root, "scope", "owned_aws.txt"))
    # hosts on the stricter SLA clock (settings.py strict_sla_hosts_file; scoring.py and triage.py call them pci)
    pci_hosts = read_list(os.path.join(a.root, "scope", POLICY["strict_sla_hosts_file"]))
    tp_suffixes = list(dict.fromkeys(read_list(os.path.join(CONFIG_DIR, "third_party_cnames.txt"))
                                     + read_list(os.path.join(a.root, "scope", "third_party_cnames.txt"))))
    print(f"fingerprint: whatweb {len(whatweb)} hosts, waf {len(waf)}, nmap {len(nmap_svc)}, sslscan {len(ssl_sum)}, ASN {len(asn_map)}/{len(live_ips)} ips, EOL {len(eol_data)} products")
    cur.execute("DELETE FROM asset_components WHERE run_id=?", (a.run_id,))
    cur.execute("DELETE FROM asset_profiles WHERE run_id=?", (a.run_id,))

    # assets
    apex_of = {x["hostname"]: x["apex"] for x in assets}
    seen_components = {}   # (host, category, name, version) -> source string
    for x in assets:
        h = x["hostname"]
        ep = x["endpoints"][0] if x["endpoints"] else {}
        expiry = next((e["tls"]["not_after"] for e in x["endpoints"] if e.get("tls") and e["tls"].get("not_after")), None)
        comps = []
        if x["class"] in LIVE:
            asn = next((asn_map[ip] for ip in x["ips"] if ip in asn_map), None)
            ev = {"endpoints": x["endpoints"], "whatweb": whatweb.get(h, {}), "waf": waf.get(h), "nuclei": nuclei_tech.get(h, []),
                  "nmap": nmap_svc.get(h, []), "sslscan": ssl_sum.get(h), "cnames": x["cnames"], "ips": x["ips"], "asn": asn,
                  "owned_aws": owned_aws, "third_party_suffixes": tp_suffixes}
            comps = [M.component(c) for c in F.normalize(ev)]   # names, versions and evidence as they are stored
            for c in comps:
                c["eol"], c["eol_date"] = F.eol_status(c["name"], c["version"], eol_data, run_day)
                cur.execute("INSERT OR REPLACE INTO asset_components VALUES(?,?,?,?,?,?,?,?,?)",
                            (a.run_id, h, c["category"], c["name"], c["version"] or "", c["source"], c["evidence"], c["eol"], c["eol_date"]))
                seen_components[(h, c["category"], c["name"], c["version"] or "")] = c["source"]
            pr = M.profile(F.profile(comps, ev))
            if comps or pr["hosting"]:   # a live name with nothing observed (no HTTP, no ASN) gets no profile row
                cur.execute("INSERT OR REPLACE INTO asset_profiles VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                            (a.run_id, h, pr["hosting"], pr["hosting_source"], pr["asn"], pr["as_name"], pr["cdn"], pr["waf"], pr["load_balancer"],
                             pr["os"], pr["web_server"], pr["language"], pr["framework"], pr["cms"], pr["tls_min"], pr["tls_max"],
                             pr["cert_issuer"], pr["cert_expiry"] or expiry, pr["eol_count"]))
        tech = sorted({c["name"] + (f" {c['version']}" if c["version"] else "") for c in comps if c["category"] != "tls"})
        cur.execute("INSERT OR REPLACE INTO asset_observations VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (a.run_id, h, x["apex"], x["class"], x.get("reason"), ",".join(x["ips"]), ",".join(x["cnames"]), json.dumps(tech),
                     M.text(waf.get(h), 100), ep.get("status"), M.text(ep.get("title"), 200), M.text(ep.get("server"), 100),
                     json.dumps([M.url(e.get("url")) for e in x["endpoints"] if e.get("url")]), M.text(expiry, 40)))
        row = cur.execute("SELECT first_seen_run FROM assets WHERE hostname=?", (h,)).fetchone()
        if row:
            cur.execute("UPDATE assets SET apex=?,class=?,last_seen_run=? WHERE hostname=?", (x["apex"], x["class"], a.run_id, h))
        else:
            cur.execute("INSERT INTO assets VALUES(?,?,?,?,?)", (h, x["apex"], x["class"], a.run_id, a.run_id))

    apexes_scanned = {l.strip().lower() for l in open(os.path.join(run_dir, "apexes.txt")) if l.strip()} if os.path.exists(os.path.join(run_dir, "apexes.txt")) else {x["apex"] for x in assets}

    # ---- asset inventory evidence (evidence.py): certificates, TLS configuration, DNS and email posture, open ports,
    # discovery sources, application clusters, per-endpoint HTTP detail. Inventory only; nothing here scores or finds.
    for t in EVIDENCE_TABLES:
        cur.execute(f"DELETE FROM {t} WHERE run_id=?", (a.run_id,))
    live_hosts = {x["hostname"] for x in assets if x["class"] in LIVE}
    certs, tls_cfg = E.sslscan_evidence(_sslscan_root(run_dir), run_day)
    hx = E.httpx_records(run_dir)
    for rec in hx:
        c = E.httpx_cert(rec, run_day)
        if not c or c["hostname"] not in live_hosts:
            continue
        k = (c["hostname"], c["port"])
        if k not in certs:
            certs[k] = c
        else:   # sslscan saw it too: httpx adds what sslscan's short form lacks
            for f in ("serial", "sha256", "not_before"):
                certs[k][f] = certs[k].get(f) or c.get(f)
            if not certs[k]["sans"]:
                certs[k]["sans"] = c["sans"]
    for c in map(M.certificate, certs.values()):
        cur.execute("INSERT OR REPLACE INTO certificates VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (a.run_id, c["hostname"], c["port"], c["subject"], json.dumps(c["sans"]), c["issuer"], c["key_type"], c["key_bits"], c["sig_alg"],
                     c["not_before"], c["not_after"], c["days_left"], c["expired"], c["self_signed"], c["serial"], c["sha256"], c["source"]))
    for t in map(M.tls_endpoint, tls_cfg.values()):
        cur.execute("INSERT OR REPLACE INTO tls_endpoints VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (a.run_id, t["hostname"], t["port"], json.dumps(t["protocols"]), t["legacy"], t["preferred_cipher"], t["weak_ciphers"],
                     t["fallback_scsv"], t["secure_reneg"], t["compression"], t["heartbleed"]))
    ww_url = E.whatweb_by_url(run_dir)
    n_ep = 0
    for rec in hx:
        if E.host_of(rec.get("url")) not in live_hosts:
            continue
        r = M.endpoint(E.endpoint_row(rec, ww_url.get(E.norm_url(rec["url"]))))
        cur.execute("INSERT OR REPLACE INTO endpoints VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (a.run_id, r["url"], r["hostname"], r["scheme"], r["port"], r["status"], r["final_url"], json.dumps(r["chain"]), r["content_type"],
                     r["content_length"], r["title"], r["server"], r["favicon_mmh3"], r["favicon_md5"], r["words"], r["lines"], r["response_ms"],
                     r["hsts"], r["csp"], r["xfo"], r["xss_protection"], json.dumps(r["cookies"]), json.dumps(r["httponly_cookies"]), json.dumps(r["emails"]),
                     json.dumps(r["analytics"]), r["generator"], r["powered_by"], r["password_field"], r["redirect_to"], json.dumps(r["uncommon_headers"])))
        n_ep += 1
    ip_hosts = {}
    for x in assets:
        if x["class"] in LIVE:
            for ip in x["ips"]:
                ip_hosts.setdefault(ip, []).append(x["hostname"])
    ports, ptr = E.host_ports(_nmap_root(run_dir), ip_hosts, RISKY_PORTS, RISKY_SERVICES, WEB_PORTS)
    for r in map(M.host_port, ports):
        cur.execute("INSERT OR REPLACE INTO host_ports VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (a.run_id, r["hostname"], r["ip"], r["port"], r["proto"], r["service"], r["product"], r["reason"], r["risky"], r["web"]))
    dns = (E.dns_records_nuclei(run_dir) + E.dns_records_dnsx(os.path.join(run_dir, "dns.jsonl"), "dnsx")
           + E.dns_records_dnsx(os.path.join(run_dir, "dns_apex.jsonl"), "dnsx") + ptr)
    for r in map(M.dns_record, dns):
        cur.execute("INSERT OR IGNORE INTO dns_records VALUES(?,?,?,?,?,?,?)", (a.run_id, r["hostname"], r["rtype"], r["name"], r["value"], r["source"], r["ttl"]))
    sources = E.asset_sources(run_dir)
    n_src = 0
    for x in assets:
        for src in sources.get(x["hostname"], []):
            cur.execute("INSERT OR IGNORE INTO asset_sources VALUES(?,?,?)", (a.run_id, x["hostname"], src)); n_src += 1
    groups = E.app_groups(run_dir)
    for g in map(M.app_group, groups):
        cur.execute("INSERT OR REPLACE INTO app_groups VALUES(?,?,?,?,?,?)", (a.run_id, g["url"], g["hostname"], g["group_url"], g["group_host"], g["members"]))
    if recheck:
        # everything the recheck did not re-test keeps yesterday's rows; from here on this run's rows are the whole estate
        carried = carry_tables(cur, a.run_id, carry_from, retested)
        print(f"recheck: {len(retested)} hosts re-tested ({len(assets)} in assets.jsonl); carried from {carry_from}: "
              + ", ".join(f"{t} {n}" for t, n in carried.items()))
        dns = [{"hostname": r[0], "rtype": r[1], "name": r[2], "value": r[3], "source": r[4], "ttl": r[5]} for r in
               cur.execute("SELECT hostname, rtype, name, value, source, ttl FROM dns_records WHERE run_id=?", (a.run_id,)).fetchall()]
    posture = E.domain_posture(apexes_scanned, dns)
    for r in map(M.posture, posture):
        cur.execute("INSERT OR REPLACE INTO domain_posture VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (a.run_id, r["apex"], r["spf"], r["spf_policy"], r["dmarc"], r["dmarc_policy"], r["dmarc_sp"], r["dkim"], json.dumps(r["mx"]), r["mx_provider"],
                     r["caa"], json.dumps(r["caa_issuers"]), json.dumps(r["nameservers"]), r["ns_provider"], r["hosts_with_spf"], r["hosts_with_dkim"], r["coverage"]))
    leads = E.san_leads(list(certs.values()), apexes_scanned, {x["hostname"] for x in assets})
    rtypes = {}
    for r in dns:
        rtypes[r["rtype"]] = rtypes.get(r["rtype"], 0) + 1
    print(f"evidence: certificates {len(certs)} ({sum(1 for c in certs.values() if c['source']=='httpx')} httpx-only), tls endpoints {len(tls_cfg)}, "
          f"endpoints {n_ep}, open ports {len(ports)} rows, dns records {len(dns)} ({', '.join(f'{k} {v}' for k, v in sorted(rtypes.items()) if k not in ('A','AAAA','CNAME'))}), "
          f"posture {sum(1 for r in posture if r['coverage'] != 'none')}/{len(posture)} apexes covered, sources {n_src}, app groups {len({g['group_url'] for g in groups})}, "
          f"certificate names not in DNS {len(leads)}")

    if inventory_only:
        db.commit()
        print(f"ingested inventory-only run {a.run_id}: {len(assets)} assets, {len(seen_components)} technology components (no findings/delta/component tracking)")
        db.close()
        return

    # cross-run component tracking (like findings): present rows get last_seen; a row is "gone" only when its host's apex
    # was scanned this run AND at least one of the sources that saw it produced output this run (a rerun that skipped
    # nuclei fp / nmap / sslscan must not mark their components gone: "not seen" would only mean "not looked at").
    source_ran = {"httpx": os.path.exists(os.path.join(run_dir, "httpx.jsonl")), "whatweb": os.path.exists(os.path.join(run_dir, "whatweb.json")),
                  "wafw00f": os.path.exists(os.path.join(run_dir, "waf.json")), "nuclei": any(os.path.exists(os.path.join(run_dir, f)) for f in ("nuclei_fp.jsonl", "nuclei_dns.jsonl")),
                  "nmap": os.path.exists(os.path.join(run_dir, "nmap.xml")), "sslscan": bool(ssl_sum), "cname": True, "dns": True, "asn": bool(asn_map)}
    comp_stats = {"new": 0, "present": 0, "gone": 0}
    for (h, cat, name, ver), src in seen_components.items():
        row = cur.execute("SELECT first_seen_run, status FROM components WHERE hostname=? AND category=? AND name=? AND version=?", (h, cat, name, ver)).fetchone()
        if row:
            cur.execute("UPDATE components SET last_seen_run=?, last_source=?, status='present', gone_run=NULL WHERE hostname=? AND category=? AND name=? AND version=?", (a.run_id, src, h, cat, name, ver))
            comp_stats["present" if row[1] == "present" and row[0] != a.run_id else "new"] += 1
        else:
            cur.execute("INSERT INTO components VALUES(?,?,?,?,?,?,?,?,?)", (h, cat, name, ver, a.run_id, a.run_id, src, "present", None))
            comp_stats["new"] += 1
    for (h, cat, name, ver, src, first) in cur.execute(
            "SELECT hostname, category, name, version, last_source, first_seen_run FROM components WHERE status='present'").fetchall():
        if (h, cat, name, ver) in seen_components:
            continue
        if recheck:
            if h not in retested:
                continue
        elif (apex_of.get(h) or "") not in apexes_scanned:
            continue
        if not any(source_ran.get(s2, False) for s2 in (src or "").split("+")):
            continue
        if first == a.run_id:   # re-ingest of this same run after a phase was redone: it never really existed
            cur.execute("DELETE FROM components WHERE hostname=? AND category=? AND name=? AND version=?", (h, cat, name, ver))
            continue
        cur.execute("UPDATE components SET status='gone', gone_run=? WHERE hostname=? AND category=? AND name=? AND version=?", (a.run_id, h, cat, name, ver))
        comp_stats["gone"] += 1
    print(f"components: {len(seen_components)} observed, new={comp_stats['new']} present={comp_stats['present']} gone={comp_stats['gone']}")

    # findings
    seen_keys = set()
    stats = {"new": 0, "persistent": 0, "fixed": 0, "total": 0}
    verdicts, exposures = {}, {}
    def no_fetch(url, headers, data=None):
        raise RuntimeError("offline")
    def no_probe(host, port):
        return "nothing", "offline: not probed"
    # Live follow-ups (verify.py, triage.py) go only to a host this run inventoried as live and that passes the
    # scope's name gate now; every connection is pinned and checked by safefetch.py with the same scope.
    gate = None
    if not a.offline:
        try:
            gate = SC.Scope(os.path.join(a.root, "scope"), run_dir)
            SF.configure(gate)
        except SC.ScopeError as e:
            print(f"warn: scope not loaded ({e}); no live verify/triage fetches this ingest", file=sys.stderr)
    # hostnames under the scope's own domains count as internal names in triage notes, whatever their top-level domain
    # (offline, the scope is read only for this; no fetch is enabled)
    names_scope = gate
    if names_scope is None:
        try:
            names_scope = SC.Scope(os.path.join(a.root, "scope"), run_dir, require_domains=False)
        except SC.ScopeError:
            names_scope = None
    R.set_scope_suffixes(names_scope.apexes if names_scope else [])
    live_hosts = {h for h, c in asset_class.items() if c in LIVE}
    refused_hosts = {}
    def may_touch(host):
        if gate is None:
            return False
        if host in refused_hosts:
            return False
        if host not in live_hosts:
            why = "not a live host in this run's inventory"
        else:
            ok, why = gate.name_allowed(host)
            if ok:
                return True
        refused_hosts[host] = why
        gate.reject(host, "ingest-followup", why)   # logged once per host to <run>/scope_rejected.jsonl
        return False
    def fetch_for(host):
        if may_touch(host):
            return None
        return offline_fetch if (a.offline and offline_fetch) else no_fetch
    def probe_for(host):
        if may_touch(host):
            return None
        return offline_probe if (a.offline and offline_probe) else no_probe
    t_start = dt.datetime.now()
    for host, f in findings:
        key = S.finding_key(host, f["source"], f["check_id"], f.get("port"))
        if key in seen_keys:
            continue
        seen_keys.add(key)
        verdict = evidence = None
        if V.wants_verify(f):
            # content check (verify.py): recorded response first; directory listings fetch up to 10 listed files
            verdict, evidence = V.verify(f, f.get("raw") or {}, fetch=fetch_for(host), host=host)
            print(f"verify {host} {f['check_id']} {verdict}", file=sys.stderr)   # never the evidence text
            verdicts[verdict] = verdicts.get(verdict, 0) + 1
        sc = S.score(f, epss, kev, host=host, pci_suffixes=pci_hosts, verdict=verdict)
        tri = None
        if T.wants_triage(f, sc["band"], verdict):
            # deep triage (triage.py): follow what the finding points to, on its own host only, and score what is exposed
            tri = T.triage({**f, "hostname": host, "pci": S.is_pci(host, pci_hosts)}, f.get("raw") or {}, verdict,
                           fetch=fetch_for(host), probe=probe_for(host))
            print(f"triage {host} {f['check_id']} {tri['exposure']}", file=sys.stderr)   # never the summary
            exposures[tri["exposure"]] = exposures.get(tri["exposure"], 0) + 1
            sc = S.score(f, epss, kev, host=host, pci_suffixes=pci_hosts, verdict=verdict, exposure=tri["exposure"])
        best_epss = max((epss.get(c, 0.0) for c in f["cve_ids"]), default=None)
        in_kev = int(any(c in kev for c in f["cve_ids"]))
        row = cur.execute("SELECT first_seen_run,status FROM findings WHERE finding_key=?", (key,)).fetchone()
        if row and row[0] == a.run_id:
            state = "new"          # re-ingest of this same run
        elif row:
            state = "persistent" if row[1] == "open" else "reopened"
            cur.execute("UPDATE findings SET last_seen_run=?,status='open',fixed_run=NULL,title=?,severity=?,cve_ids=? WHERE finding_key=?",
                        (a.run_id, M.text(f["title"], 300), f["severity"], ",".join(f["cve_ids"]), key))
        else:
            state = "new"
            cur.execute("INSERT INTO findings VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (key, host, apex_of.get(host) or next((ax for ax in {x["apex"] for x in assets} if host.endswith(ax)), ""), f["source"], f["check_id"], f.get("port"),
                         M.text(f["title"], 300), f["severity"], ",".join(f["cve_ids"]), a.run_id, a.run_id, "open", None))
        stats[state if state != "reopened" else "new"] += 1; stats["total"] += 1
        cur.execute("INSERT OR REPLACE INTO finding_observations(run_id, finding_key, asset_class, matched, description, remediation, reference, tags, "
                    "cvss, epss, kev, impact, likelihood, score, band, sla_days, state, raw_json, verdict, verification, exposure) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (a.run_id, key, f["asset_class"], M.hostport(f.get("matched")), M.text(f.get("description"), 2000), (f.get("remediation") or "")[:2000],
                     json.dumps([M.url(r, 300) for r in (f.get("reference") if isinstance(f.get("reference"), list) else [f.get("reference")] if f.get("reference") else [])[:10]]),
                     json.dumps(f.get("tags") or []), f.get("cvss"), best_epss, in_kev, sc["impact"], sc["likelihood"], sc["score"], sc["band"], sc["sla_days"],
                     state, M.to_json(M.minimize(f["source"], f.get("raw"), level)), verdict, M.text(evidence, 300), tri["exposure"] if tri else None))
        if tri:
            st = M.triage_record(tri)   # summary, fix, items and secrets as stored: redacted per field, secrets masked
            cur.execute("INSERT OR REPLACE INTO finding_triage VALUES(?,?,?,?,?,?,?,?,?)",
                        (a.run_id, key, tri["exposure"], st["summary"], st["fix"], json.dumps(st["items"]), json.dumps(st["secrets"]), int(tri["pci"]), now))
    # Anything open that this run looked at and did not observe is fixed. "Looked at" means: the host is in scope (a
    # full run: its apex was scanned; a recheck: the host was re-tested) AND the phase that produces the finding's
    # source ran and exited 0 (a run that skipped nmap must not mark port findings fixed), and for nuclei every pass
    # that can observe a finding ran (--nuclei-passes tech alone would otherwise "fix" every generic finding).
    # Coverage (recon.sh writes coverage/<source>.txt): a host skipped by a scope control inside a phase that
    # exited 0 was not looked at, so its findings stay open. A run without coverage data uses the phase rule alone.
    coverage = load_coverage(run_dir, manifest)
    nuclei_errors = load_nuclei_errors(run_dir, manifest.get("nuclei_templates_dir"))
    # a nuclei pass that exited non-zero may have stopped part-way: nothing it would have observed is fixed this run
    for p in manifest.get("nuclei_failed_passes") or []:
        kind = NUCLEI_PASS_KIND.get(p)
        if kind:
            nuclei_errors.setdefault(kind, {})["*all*"] = {"*"}
    check_profile = manifest.get("check_profile")
    ok_phases = phases_ok(manifest)
    passes = {p.strip() for p in (manifest.get("nuclei_passes") or "generic,tech,tp,dns,fp").split(",")}
    def source_ok(src):
        if ok_phases is not None and SOURCE_PHASE.get(src, 0) not in ok_phases:
            return False
        return src != "nuclei" or NUCLEI_PASSES_FOR_FIXED <= passes
    gated = {}
    for (k, apex, host, src) in cur.execute("SELECT finding_key, apex, hostname, source FROM findings WHERE status='open'").fetchall():
        if k in seen_keys:
            continue
        if (host not in retested) if recheck else (apex not in apexes_scanned):
            continue
        if not source_ok(src):
            gated[src] = gated.get(src, 0) + 1
            continue
        tags_row = cur.execute("SELECT o.tags, o.asset_class, o.raw_json FROM finding_observations o JOIN findings f ON f.finding_key=o.finding_key "
                               "AND o.run_id=f.last_seen_run WHERE f.finding_key=?", (k,)).fetchone()
        kind = nuclei_kind(tags_row[2], tags_row[1]) if src == "nuclei" and tags_row else "http"
        check_id = cur.execute("SELECT check_id FROM findings WHERE finding_key=?", (k,)).fetchone()[0]
        matched = None
        if src == "nuclei" and tags_row and tags_row[2]:
            try:
                matched = (json.loads(tags_row[2]) or {}).get("matched-at")
            except (ValueError, AttributeError):
                matched = None
        ok, why = fixed_allowed(src, host, json.loads(tags_row[0]) if tags_row and tags_row[0] else [], coverage, check_profile,
                                kind, nuclei_errors, check_id, matched)
        if not ok:
            gated[why] = gated.get(why, 0) + 1
            continue
        first = cur.execute("SELECT first_seen_run FROM findings WHERE finding_key=?", (k,)).fetchone()[0]
        if first == a.run_id:
            # re-ingest of this same run after a phase was redone: the finding never really existed
            cur.execute("DELETE FROM findings WHERE finding_key=?", (k,))
            cur.execute("DELETE FROM finding_observations WHERE finding_key=?", (k,))
            cur.execute("DELETE FROM finding_triage WHERE finding_key=?", (k,))
            continue
        cur.execute("UPDATE findings SET status='fixed',fixed_run=? WHERE finding_key=?", (a.run_id, k))
        stats["fixed"] += 1
    if verdicts:
        print("verify: " + ", ".join(f"{k} {n}" for k, n in sorted(verdicts.items())))
    if exposures:
        print("triage: " + ", ".join(f"{k} {n}" for k, n in sorted(exposures.items())) + f" ({(dt.datetime.now() - t_start).seconds} s for findings)")
    if gated:
        print("not marked fixed (phase did not run, host not tested, requests failed, or active-only check in a safe run): " + ", ".join(f"{s} {n}" for s, n in sorted(gated.items())))
    if recheck:
        stats["carried"] = carry_findings(cur, a.run_id, carry_from)
        carry_triage(cur, a.run_id, carry_from, seen_keys)
    db.commit()
    summary = write_summary(cur, a.run_id, {"kind": run_kind, "base_run": base_run, "rechecked_hosts": len(retested)} if recheck else {"kind": run_kind})
    pruned = prune_snapshots(cur, a.run_id)
    db.commit()
    db.close()
    print(f"ingested {run_kind} run {a.run_id} (evidence {level}): assets={len(assets)} findings={stats['total']} new={stats['new']} persistent={stats['persistent']} fixed={stats['fixed']}"
          + (f" carried={stats['carried']} open_now={summary['total']} base={base_run}" if recheck else "") + f" prev_run={prev_run}"
          + (f"; pruned carried rows of {', '.join(pruned)}" if pruned else ""))

if __name__ == "__main__":
    main()
