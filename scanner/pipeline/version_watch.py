#!/usr/bin/env python3
"""version_watch.py - which hosts run a product version below the lowest fixed release of its branch.

    python3 -I -B scanner/pipeline/version_watch.py --root "$SCAN_ROOT" --run-dir RUN_DIR --watches FILE [--workers 16]

A watch is defined by the user and arrives in the job (options.watches, validated by validate_watches below, the one
implementation of the rules): an id, a display name, a product from the fixed PRODUCTS table, the CVE ids it is about,
the floors (for each branch "x.y", the lowest fixed patch number) and optional extra host names. A job can never
supply a pattern, a header name, a path or a URL: how a version is read is fixed in code, per product.

THE PROBE (the only traffic this module sends; it does not change with the watches):
  one plain `GET /` per host per run, over https and then http, with curl (-k, 10 s), response headers only (the body
  is discarded). It follows at most three redirects, and only to the same host name (never to another host); such a
  redirect may lead to another path or port on that host. It starts no request to any other path, and uses no other
  method and no request body. One request set per host per run however many watches list the
  host: the host is probed once, then the answer is judged against each watch.

Before any probe, every host must pass, in this order:
  1. the DNS proof of its domain, checked in THIS job: the runner runs recon's own phase-0 command first
     (scope.py recheck-dns, the same verify_apexes call), which writes <run dir>/dns_verification.json; a host under
     a domain that is not in its "usable" list (pending, refused, lapsed, or the check failed) is not probed and is
     reported UNREACHABLE with a fixed reason. In lab mode (<run dir>/lab.json) only lab targets are probed, as in recon.
  2. the scope's name gate (scope.Scope.name_allowed: under an approved apex, not excluded);
  3. the CNAME exclusion check (scope.Scope.cname_allowed): every name in its CNAME chain passes the exclusions; a chain
     that cannot be looked up is not probed and is reported UNREACHABLE;
  4. the address check, with the connection pinned to the checked address (safefetch.checked_address, curl --resolve).
Hosts held back from active checks (held_back.json) are still watched: this probe is no more than the web inventory
already sends.

Targets of each watch (de-duplicated by lowercase host name):
  a. every host name the scan database holds a present component of the watch's product for (read-only);
  b. the watch's extra host names from the job;
  c. carried: every host of the watch's newest earlier non-suspect dated file that a and b no longer name. A carried
     host that was probed and did not answer is dropped (decommissioned; it shows in changes as gone); one that answers
     stays, so a host that starts hiding its version reads FAIL -> UNKNOWN, never as a fix.

Verdicts (the same rule for every product):
  PASS         on a branch with a floor: at or above it; or a branch newer than every listed branch
  FAIL         on a branch with a floor: below it; any other branch: "no fixed release on this branch"
  UNKNOWN      answered on https or http, but no version of this product in the headers (hidden, or not this product)
  UNREACHABLE  no HTTP status on either scheme, or not probed (domain not verified in this job, CNAME chain unknown)

Output, per watch: version-watch/<watch id>/<UTC date>.json and latest.json under --root (schema version-watch-v1,
written atomically); the newest 90 dated files are kept. A watch that is no longer in the job keeps its folder until
its newest dated file is older than the retention period (90 days), then the folder goes. Everything in a file that
came from a target is either parsed into a strict form (version, HTTP status) or listed in TARGET_DERIVED (cut short
and passed through the redaction module).

Exit codes: 0 written; 2 nothing to probe (no watch has a target), nothing written; 3 at least one watch was suspect:
more than half of its hosts were UNREACHABLE, so its dated file was written with "suspect": true and its latest.json
was left as it was (the other watches' files were written normally); 4 the watches file or the scope is invalid.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import safefetch as SF  # noqa: E402
import minimize as M  # noqa: E402
import scope as SC  # noqa: E402


# Two small file helpers, kept here because the DNS seeding code runs in its own container (seeder/), not in the
# scanner.
def _readlines(path):
    with open(path, encoding="utf-8") as fh:
        return fh.readlines()


def read_apexes(path):
    out = []
    for raw in _readlines(path):
        line = raw.strip().lower()
        if line and not line.startswith("#"):
            out.append(line.rstrip("."))
    return sorted(set(out))


def apex_of(name, apexes):
    for a in apexes:
        if name == a or name.endswith("." + a):
            return a
    return None


SCHEMA = "version-watch-v1"
STATE_DIR = "version-watch"
# a fixed, recognizable User-Agent so WAF and access logs can match the probes; SCAN_USER_AGENT overrides it
UA = os.environ.get("SCAN_USER_AGENT", "").strip() or "momus-version-watch"
TIMEOUT_S = 10
MAX_HOPS = 3            # same-host redirects followed from each scheme's GET /
KEEP = 90               # dated files kept per watch; also the days a watch no longer in the job keeps its folder
VERDICTS = ("FAIL", "UNKNOWN", "UNREACHABLE", "PASS")
VERDICT_ORDER = {v: i for i, v in enumerate(VERDICTS)}
SOURCES = ("scan_db", "job", "both", "carried")
EXIT_OK, EXIT_NOTHING, EXIT_SUSPECT, EXIT_INVALID = 0, 2, 3, 4
MAX_HEADER_VALUE = 1024        # a header value is cut to this before any pattern looks at it
MAX_HEAD_DUMP = 256 * 1024     # curl's header output read, at most
SERVER_CAP = 100               # the stored Server text (target-derived, redacted)
# Fields of a version-watch-v1 file that hold text taken from a target. Everything else is fixed text, a number, a
# strict version string, a validated host name, or the watch definition from the job.
TARGET_DERIVED = ("hosts[].server",)

# ---- the fixed product table ---------------------------------------------------------------------------------------
# id -> name shown, component name in the scan database (fingerprint.py's canonical name), headers read (in order;
# https before http, then each header in this order), and ONE strict pattern whose group 1 is the numeric version.
# The lookbehind refuses a match inside a longer token ("cloudflare-nginx", "XApache"); the lookahead refuses a
# version that continues with a fourth number (a four-part version is not read as its first three parts). Each component
# has 1 to 4 digits (patch 6).
_PRE = r"(?<![A-Za-z0-9_.-])"
_END = r"(?!\.?[0-9])"
PRODUCTS = {
    "php": {"name": "PHP", "component": "PHP", "headers": ("x-powered-by", "server"),
            "pattern": re.compile(_PRE + r"PHP/([0-9]{1,4}\.[0-9]{1,4}(?:\.[0-9]{1,6})?)" + _END, re.I)},
    "nginx": {"name": "nginx", "component": "nginx", "headers": ("server",),
              "pattern": re.compile(_PRE + r"nginx/([0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,6})" + _END, re.I)},
    "apache-httpd": {"name": "Apache HTTP Server", "component": "Apache", "headers": ("server",),
                     "pattern": re.compile(_PRE + r"Apache/([0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,6})" + _END, re.I)},
    # OpenSSL 1.x releases carry a letter (1.1.1w); only the numeric part is read, and floors must be on 3.x or newer
    # (validate_watches), so a lettered 1.x release always lands on a branch without a floor and fails.
    "openssl": {"name": "OpenSSL", "component": "OpenSSL", "headers": ("server",),
                "pattern": re.compile(_PRE + r"OpenSSL/([0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,6})" + _END, re.I),
                "min_floor_major": 3},
}
PROBE_HEADERS = tuple(sorted({h for p in PRODUCTS.values() for h in p["headers"]}))
VERSION_RE = re.compile(r"[0-9]{1,4}\.[0-9]{1,4}(?:\.[0-9]{1,6})?")     # the strict stored form, fullmatch

# ---- watch definitions (the rules the brain mirrors; brain/app/watches.py) -------------------------------------------
WATCH_KEYS = {"id", "name", "product", "cves", "floors", "hosts"}
WATCH_REQUIRED = {"id", "name", "product", "cves", "floors"}
MAX_WATCHES = 20
MAX_CVES = 20
MAX_FLOORS = 16
MAX_HOSTS = 100                 # extra host names per watch
MAX_PATCH = 99999
WATCH_ID_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,30}[a-z0-9]")            # the job id character set, 2 to 32 characters
# letters, digits, space and . _ , - only: no quote, slash, colon or pattern character can appear in a name
WATCH_NAME_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9 ._,-]{0,78}[A-Za-z0-9._])?")
CVE_RE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,7}")
BRANCH_RE = re.compile(r"(?:0|[1-9][0-9]{0,3})\.(?:0|[1-9][0-9]{0,3})")
DATED_RE = re.compile(r"([0-9]{4}-[0-9]{2}-[0-9]{2})\.json")             # fullmatch
FILE_RE = re.compile(r"(?:[0-9]{4}-[0-9]{2}-[0-9]{2}|latest)\.json")       # the only names written in a watch folder


class WatchError(ValueError):
    """An invalid watch definition. The message is a fixed text naming the field, never the value."""


def validate_watches(raw, name_check=None):
    """The job's options.watches -> a normalized list, or WatchError with a fixed reason. name_check(value, where)
    returns the normalized host name or raises (the runner passes its own _name, so a watch's host names follow the
    exact rule of every other host name in a job)."""
    if raw is None or raw == []:
        raise WatchError("options.watches: a version-watch job needs at least one watch")
    if not isinstance(raw, list):
        raise WatchError("options.watches: must be a list")
    if not raw:
        raise WatchError("options.watches: a version-watch job needs at least one watch")
    if len(raw) > MAX_WATCHES:
        raise WatchError(f"options.watches: more than {MAX_WATCHES} entries")
    out, seen = [], set()
    for i, w in enumerate(raw):
        where = f"options.watches[{i}]"
        if not isinstance(w, dict):
            raise WatchError(f"{where}: must be an object")
        for k in w:
            if k not in WATCH_KEYS:
                raise WatchError(f"{where}: unknown field" + (f" '{k}'" if isinstance(k, str) and re.fullmatch(r"[a-z_]{1,32}", k) else ""))
        missing = WATCH_REQUIRED - set(w)
        if missing:
            raise WatchError(f"{where}: missing field(s) " + ", ".join(sorted(missing)))
        wid = w["id"]
        if not isinstance(wid, str) or not WATCH_ID_RE.fullmatch(wid):
            raise WatchError(f"{where}.id: 2 to 32 characters, a-z 0-9 and '-', starting and ending with a letter or digit")
        if wid in seen:
            raise WatchError(f"{where}.id: listed twice")
        seen.add(wid)
        name = w["name"]
        if not isinstance(name, str) or not WATCH_NAME_RE.fullmatch(name):
            raise WatchError(f"{where}.name: 1 to 80 characters: letters, digits, spaces and . _ , - only")
        product = w["product"]
        if not isinstance(product, str) or product not in PRODUCTS:
            raise WatchError(f"{where}.product: must be one of " + ", ".join(PRODUCTS))
        cves = w["cves"]
        if not isinstance(cves, list) or not cves or len(cves) > MAX_CVES:
            raise WatchError(f"{where}.cves: a list of 1 to {MAX_CVES} CVE ids")
        for j, c in enumerate(cves):
            if not isinstance(c, str) or not CVE_RE.fullmatch(c):
                raise WatchError(f"{where}.cves[{j}]: not a CVE id (CVE-YYYY-NNNN)")
        if len(set(cves)) != len(cves):
            raise WatchError(f"{where}.cves: a CVE id is listed twice")
        floors = w["floors"]
        if not isinstance(floors, dict) or not floors or len(floors) > MAX_FLOORS:
            raise WatchError(f"{where}.floors: an object of 1 to {MAX_FLOORS} branches")
        norm_floors = {}
        for b, p in floors.items():
            if not isinstance(b, str) or not BRANCH_RE.fullmatch(b):
                raise WatchError(f"{where}.floors: a branch is not of the form x.y (numbers, no leading zeros)")
            if isinstance(p, bool) or not isinstance(p, int) or not 0 <= p <= MAX_PATCH:
                raise WatchError(f"{where}.floors: a fixed patch number is not a whole number from 0 to {MAX_PATCH}")
            if int(b.split(".")[0]) < PRODUCTS[product].get("min_floor_major", 0):
                raise WatchError(f"{where}.floors: this product's floors must be on branch "
                                 f"{PRODUCTS[product]['min_floor_major']}.0 or newer (older releases carry letters)")
            norm_floors[b] = p
        hosts = w.get("hosts", [])
        if not isinstance(hosts, list) or len(hosts) > MAX_HOSTS:
            raise WatchError(f"{where}.hosts: a list of at most {MAX_HOSTS} host names")
        norm_hosts = []
        for j, h in enumerate(hosts):
            n = name_check(h, f"{where}.hosts[{j}]") if name_check else _plain_name(h, f"{where}.hosts[{j}]")
            if n not in norm_hosts:
                norm_hosts.append(n)
        out.append({"id": wid, "name": name, "product": product, "cves": list(cves),
                    "floors": {b: norm_floors[b] for b in sorted(norm_floors, key=branch_key)}, "hosts": sorted(norm_hosts)})
    return out


def _plain_name(v, where):
    n = SC.norm_name(v) if isinstance(v, str) else None
    if not n or n != v:
        raise WatchError(f"{where}: not a valid host name (lower case, labels a-z 0-9 - _, no trailing dot)")
    return n


def branch_key(b: str) -> tuple:
    major, minor = b.split(".")
    return int(major), int(minor)


def floor_texts(floors: dict) -> dict:
    return {b: f"{b}.{p}" for b, p in floors.items()}


def say(msg: str) -> None:
    print(f"[version-watch] {msg}", flush=True)


# ---- versions and verdicts -----------------------------------------------------------------------------------------

def parse_version(pattern, *values) -> str | None:
    """The first version the product's pattern finds in the given header values, in order (each cut first)."""
    for v in values:
        if v and isinstance(v, str):
            m = pattern.search(v[:MAX_HEADER_VALUE])
            if m:
                return m.group(1)
    return None


def branch_of(version: str) -> str:
    major, minor = version.split(".")[:2]
    return f"{int(major)}.{int(minor)}"


def verdict_for_version(version: str, floors: dict) -> tuple[str, str]:
    """(PASS|FAIL, reason) under floors {branch: lowest fixed patch}. A missing patch level counts as 0."""
    parts = version.split(".")
    major, minor = int(parts[0]), int(parts[1])
    patch = int(parts[2]) if len(parts) > 2 else 0
    branch = f"{major}.{minor}"
    need = floors.get(branch)
    if need is None:
        newest = max(floors, key=branch_key)
        if (major, minor) > branch_key(newest):
            return "PASS", f"{version} is newer than the {newest} branch; released after the fix"
        return "FAIL", f"{version} is on branch {branch}: no fixed release on this branch"
    if patch >= need:
        return "PASS", f"{version} is at or above {branch}.{need}"
    return "FAIL", f"{version} is below {branch}.{need}"


# ---- targets -------------------------------------------------------------------------------------------------------

def clean_host(raw) -> str | None:
    if not isinstance(raw, str):
        return None
    n = SC.norm_name(raw)
    return n if n and n == raw.strip().lower().rstrip(".") else None


def strict_version(v) -> str | None:
    """A version string in the strict stored form, else None (scan database values are target-derived)."""
    return v if isinstance(v, str) and VERSION_RE.fullmatch(v) else None


def open_db(path: Path) -> sqlite3.Connection:
    if not Path(path).is_file():
        raise sqlite3.OperationalError("no database")
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    con.execute("SELECT 1 FROM components LIMIT 1")
    return con


def scan_db_targets(con: sqlite3.Connection, component: str) -> tuple[dict, str | None]:
    """{hostname: strict version or None}, newest run_id. Several rows per host are possible (the components key
    includes the version): a row with a version beats one without, then the newest last_seen_run wins."""
    seq = {r[0]: r[1] for r in con.execute("SELECT run_id, seq FROM runs")}
    newest = con.execute("SELECT run_id FROM runs ORDER BY seq DESC LIMIT 1").fetchone()
    best: dict[str, tuple] = {}
    for host, version, last in con.execute(
            "SELECT hostname, version, last_seen_run FROM components WHERE name=? AND status='present'", (component,)):
        h = clean_host(host)
        if not h:
            continue
        v = strict_version((version or "").strip() or None)
        key = (v is not None, seq.get(last, -1), last if isinstance(last, str) else "", v or "")
        if h not in best or key > best[h][0]:
            best[h] = (key, v)
    run = newest[0] if newest and isinstance(newest[0], str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", newest[0]) else None
    return {h: kv[1] for h, kv in best.items()}, run


def build_targets(db_hosts: dict, job_hosts: list) -> list[dict]:
    out, job = [], set(job_hosts)
    for h in sorted(set(db_hosts) | job):
        in_db, in_job = h in db_hosts, h in job
        out.append({"hostname": h, "scan_db_version": db_hosts.get(h),
                    "source": "both" if in_db and in_job else ("scan_db" if in_db else "job")})
    return out


def carried_targets(prev: dict | None, db_hosts: dict, job_hosts: list) -> list[dict]:
    """Hosts of the newest earlier good file that neither the scan database nor the job names any more. A host that
    stops advertising its version must stay on the list until it advertises a passing version or stops answering;
    otherwise a hidden version would read as a fix."""
    out, seen = [], set(db_hosts) | set(job_hosts)
    for h in (prev or {}).get("hosts") or []:
        name = clean_host((h or {}).get("hostname")) if isinstance(h, dict) else None
        if name and name not in seen:
            seen.add(name)
            out.append({"hostname": name, "scan_db_version": None, "source": "carried"})
    return sorted(out, key=lambda t: t["hostname"])


def domain_of(hostname: str, apexes: list[str]) -> str:
    """Registrable domain: the scope apex when the host is under one, else the last two labels."""
    return apex_of(hostname, apexes) or ".".join(hostname.split(".")[-2:])


# ---- probing (the one GET / per scheme; see the module header) --------------------------------------------------------

def parse_head_dump(text: str) -> tuple[int | None, dict]:
    """curl -D output -> (status, {lowercase header: value, repeats joined with ', '}) of the last response block.
    Only the headers some product reads, and Location, are kept; a status outside 100..599 is no status."""
    status, headers = None, {}
    for line in text[:MAX_HEAD_DUMP].splitlines():
        line = line.rstrip("\r")
        if line.upper().startswith("HTTP/"):
            parts = line.split()
            code = int(parts[1]) if len(parts) > 1 and re.fullmatch(r"[0-9]{3}", parts[1]) else None
            status = code if code is not None and 100 <= code <= 599 else None
            headers = {}
        elif ":" in line and status is not None:
            k, v = line.split(":", 1)
            k, v = k.strip().lower(), v.strip()
            if k not in PROBE_HEADERS and k != "location":
                continue
            v = (f"{headers[k]}, {v}" if k in headers else v)[:MAX_HEADER_VALUE * 4]
            headers[k] = v
    return status, headers


# fixed error classes: nothing a target or a tool prints reaches the output
ERR_REFUSED = "the address check refused it"
ERR_TIMEOUT = "timed out"
ERR_NONE = "no answer"
ERR_CNAME = "not probed: its CNAME chain could not be looked up"
ERR_PENDING = "not probed: its domain did not pass the DNS proof in this job"
ERRORS = (ERR_REFUSED, ERR_TIMEOUT, ERR_NONE, ERR_CNAME, ERR_PENDING)


def curl_fetch(url: str, connect_to: str | None = None, timeout: int = TIMEOUT_S, gate=None) -> dict:
    """One plain GET, headers to stdout, body to /dev/null; curl follows nothing (probe_host follows same-host
    redirects itself). No shell. With a scope (gate), the host is resolved once here, every address is checked
    with gate.ip_allowed, and curl is pinned to that address with --resolve, so it never re-resolves the name."""
    cmd = ["curl", "-sS", "-k", "-m", str(timeout), "-A", UA, "--proto", "=http,https",
           "-D", "-", "-o", os.devnull, url]
    if connect_to:  # tests only: every name and port goes to the local fixture server
        cmd[1:1] = ["--noproxy", "*", "--connect-to", connect_to]
    elif gate is not None:
        u = urlsplit(url)
        host, port = (u.hostname or "").lower(), u.port or (443 if u.scheme == "https" else 80)
        try:
            ip = SF.checked_address(host, host, ip_check=gate.ip_allowed)
        except SF.Refused:
            return {"status": None, "headers": {}, "error": ERR_REFUSED}
        cmd[1:1] = ["--noproxy", "*", "--resolve", f"{host}:{port}:{'[' + ip + ']' if ':' in ip else ip}"]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout + 5)
        status, headers = parse_head_dump(p.stdout)
        err = ERR_TIMEOUT if p.returncode == 28 else ERR_NONE
    except subprocess.TimeoutExpired:
        status, headers, err = None, {}, ERR_TIMEOUT
    return {"status": status, "headers": headers, "error": None if status else err}


def same_host_redirect(url: str, resp: dict, host: str) -> str | None:
    """The Location of a 3xx answer when it stays on this hostname over http or https, else None. A redirect to
    another host is never followed: its headers would say nothing about this one."""
    if not (resp["status"] and 300 <= resp["status"] < 400):
        return None
    loc = (resp["headers"].get("location") or "").strip()
    if not loc:
        return None
    try:
        nxt = urljoin(url, loc)
        p = urlsplit(nxt)
        if p.scheme in ("http", "https") and (p.hostname or "").lower() == host:
            return urlunsplit((p.scheme, p.netloc, p.path or "/", p.query, ""))
    except ValueError:
        pass
    return None


def probe_host(hostname: str, fetch) -> dict:
    """GET / on https and http, then up to MAX_HOPS same-host redirects from each. Each URL is fetched once. Returns
    the answers only; judge() reads them for each watch."""
    cache: dict[str, dict] = {}

    def get(url):
        if url not in cache:
            cache[url] = fetch(url)
        return cache[url]

    res, hops = {}, {}
    for scheme in ("https", "http"):
        url = f"{scheme}://{hostname}/"
        res[scheme] = r = get(url)
        hops[scheme], seen = [r], {url}
        for _ in range(MAX_HOPS):
            url = same_host_redirect(url, r, hostname)
            if not url or url in seen:
                break
            seen.add(url)
            r = get(url)
            hops[scheme].append(r)
    return {"hostname": hostname, "probed": True, "res": res, "hops": hops}


def not_probed(hostname: str, why: str) -> dict:
    down = {"status": None, "headers": {}, "error": why}
    return {"hostname": hostname, "probed": False, "res": {"https": down, "http": down},
            "hops": {"https": [down], "http": [down]}}


def clean_text(v, cap=SERVER_CAP):
    """Target-derived header text: cut, control characters replaced, then redacted (minimize.text) and capped."""
    if not isinstance(v, str) or not v:
        return None
    v = re.sub(r"[\x00-\x1f\x7f\u0080-\u009f  ]", " ", v[:MAX_HEADER_VALUE])
    return M.text(v, cap)


def judge(probe: dict, target: dict, watch: dict) -> dict:
    """One host row of one watch, from the shared probe."""
    prod = PRODUCTS[watch["product"]]
    version, read_from = None, None
    for scheme in ("https", "http"):
        for i, r in enumerate(probe["hops"][scheme]):
            for hdr in prod["headers"]:
                v = parse_version(prod["pattern"], r["headers"].get(hdr))
                if v and not version:
                    version, read_from = v, f"{scheme} {hdr}" + (" (after redirect)" if i else "")
    res = probe["res"]
    hs, ht = res["https"]["status"], res["http"]["status"]
    if version:
        verdict, reason = verdict_for_version(version, watch["floors"])
    elif hs or ht:
        verdict = "UNKNOWN"
        reason = (f"HTTP {hs or '-'} (https) / {ht or '-'} (http), no {prod['name']} version in the headers "
                  f"(hidden or not {prod['name']})")
    else:
        verdict = "UNREACHABLE"
        err = res["https"]["error"] if res["https"]["error"] in ERRORS else res["http"]["error"]
        reason = f"no HTTP response on https or http ({err if err in ERRORS else ERR_NONE})"
    server = res["https"]["headers"].get("server") or res["http"]["headers"].get("server")
    return {"hostname": target["hostname"], "version": version, "verdict": verdict, "reason": reason,
            "read_from": read_from, "https_status": hs, "http_status": ht, "server": clean_text(server),
            "scan_db_version": target["scan_db_version"], "source": target["source"], "probed": probe["probed"]}


# ---- the result files ----------------------------------------------------------------------------------------------

def _vkey(v: str):
    return tuple(int(x) for x in v.split("."))


def count(rows) -> dict:
    c = {"hosts": len(rows), "fail": 0, "pass": 0, "unknown": 0, "unreachable": 0}
    for r in rows:
        c[r["verdict"].lower()] += 1
    return c


def dated_files(outdir: Path) -> list[tuple[str, Path]]:
    if not outdir.is_dir():
        return []
    return sorted((m.group(1), p) for p in outdir.iterdir()
                  if (m := DATED_RE.fullmatch(p.name)) and p.is_file() and not p.is_symlink())


def _clean_prev(doc: dict) -> dict | None:
    """An earlier file of this watch, reduced to what the next run uses, every value checked again."""
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA or doc.get("suspect"):
        return None
    date = doc.get("date") if isinstance(doc.get("date"), str) and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", doc["date"]) else None
    if not date:
        return None
    hosts = []
    for h in (doc.get("hosts") if isinstance(doc.get("hosts"), list) else [])[:5000]:
        if isinstance(h, dict) and clean_host(h.get("hostname")):
            hosts.append({"hostname": clean_host(h["hostname"]), "version": strict_version(h.get("version")),
                          "verdict": h.get("verdict") if h.get("verdict") in VERDICTS else None})
    head = doc.get("headline") if isinstance(doc.get("headline"), dict) else {}
    headline = {k: head[k] if isinstance(head.get(k), int) and not isinstance(head.get(k), bool) and 0 <= head[k] <= 10 ** 6 else 0
                for k in ("hosts", "fail", "pass", "unknown", "unreachable")}
    return {"date": date, "hosts": hosts, "headline": headline}


def load_earlier(outdir: Path, before: str) -> list[dict]:
    """Earlier dated files of one watch that are not suspect, oldest first."""
    out = []
    for d, p in dated_files(outdir):
        if d >= before:
            continue
        try:
            doc = _clean_prev(json.loads(p.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            continue
        if doc and doc["date"] == d:
            out.append(doc)
    return out


def diff(prev: dict | None, hosts: list[dict]) -> dict:
    if not prev:
        return {"since": None, "items": []}
    old = {h["hostname"]: h for h in prev.get("hosts") or []}
    new = {h["hostname"]: h for h in hosts}
    items = []
    for name in sorted(set(old) | set(new)):
        a, b = old.get(name), new.get(name)
        fv, tv = (a or {}).get("version"), (b or {}).get("version")
        fd, td = (a or {}).get("verdict"), (b or {}).get("verdict")
        if a is None or b is None or fv != tv or fd != td:
            items.append({"hostname": name, "from_version": fv, "to_version": tv, "from_verdict": fd, "to_verdict": td})
    return {"since": prev.get("date"), "items": items}


HOST_KEYS = ("hostname", "domain", "version", "verdict", "reason", "read_from", "https_status", "http_status", "server",
             "scan_db_version", "source")


def method_text(product: str) -> str:
    hdrs = ", ".join({"x-powered-by": "X-Powered-By", "server": "Server"}[h] for h in PRODUCTS[product]["headers"])
    return ("GET / over https and http (same-host redirects followed, at most 3), response headers only "
            f"({hdrs}); no crafted request")


def build_doc(watch: dict, hosts: list[dict], targets_info: dict, apexes: list[str], earlier: list[dict],
              now: dt.datetime, job_id: str | None) -> dict:
    day = now.date().isoformat()
    for h in hosts:
        h["domain"] = domain_of(h["hostname"], apexes)
    hosts = sorted(hosts, key=lambda r: (VERDICT_ORDER[r["verdict"]], r["hostname"]))
    head = count(hosts)

    by_v: dict[str, int] = {}
    for h in hosts:
        if h["version"]:
            by_v[h["version"]] = by_v.get(h["version"], 0) + 1
    by_version = []
    for v, n in sorted(by_v.items(), key=lambda kv: (-kv[1], _vkey(kv[0]))):
        verdict, reason = verdict_for_version(v, watch["floors"])
        by_version.append({"version": v, "branch": branch_of(v), "verdict": verdict, "reason": reason, "hosts": n})

    doms: dict[str, list] = {}
    for h in hosts:
        doms.setdefault(h["domain"], []).append(h)
    by_domain = [{"domain": d, **count(rows)} for d, rows in sorted(doms.items(), key=lambda kv: (-len(kv[1]), kv[0]))]

    host_rows = [{k: h[k] for k in HOST_KEYS} for h in hosts]
    history = [{"date": d["date"], **d["headline"]} for d in earlier]
    history = (history + [{"date": day, **head}])[-KEEP:]
    prod = PRODUCTS[watch["product"]]
    return {"schema": SCHEMA, "watch": {"id": watch["id"], "name": watch["name"], "product": watch["product"],
                                        "product_name": prod["name"]},
            "job_id": job_id, "generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "date": day,
            "cves": list(watch["cves"]), "floors": floor_texts(watch["floors"]), "method": method_text(watch["product"]),
            "target_derived": list(TARGET_DERIVED), "targets": targets_info, "headline": head, "by_version": by_version,
            "by_domain": by_domain, "hosts": host_rows, "changes": diff(earlier[-1] if earlier else None, host_rows),
            "history": history}


def write_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp-vw")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def retain(outdir: Path, keep: int = KEEP) -> list[str]:
    files = dated_files(outdir)
    gone = []
    for _, p in files[:-keep] if len(files) > keep else []:
        p.unlink()
        gone.append(p.name)
    return gone


def retire_watches(base: Path, active: set, today: dt.date, keep_days: int = KEEP) -> list[str]:
    """Folders of watches that are no longer in the job: kept while their newest dated file is younger than
    keep_days, then removed (only the files this module writes; a folder holding anything else is left)."""
    gone = []
    if not base.is_dir():
        return gone
    for d in sorted(base.iterdir()):
        if d.name in active or not WATCH_ID_RE.fullmatch(d.name) or d.is_symlink() or not d.is_dir():
            continue
        dated = dated_files(d)
        newest = dt.date.fromisoformat(dated[-1][0]) if dated else None
        if newest is not None and (today - newest).days < keep_days:
            continue
        for p in d.iterdir():
            if FILE_RE.fullmatch(p.name) and p.is_file() and not p.is_symlink():
                p.unlink()
        try:
            d.rmdir()
            gone.append(d.name)
        except OSError:
            pass
    return gone


# ---- main ----------------------------------------------------------------------------------------------------------

def load_watches(path: Path) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        return validate_watches(json.load(fh))


def usable_domains(run_dir: Path) -> set:
    """The domains whose DNS proof passed in this job: <run dir>/dns_verification.json "usable", written by
    scope.py recheck-dns at the start of this job. Missing or unreadable: none."""
    try:
        with open(run_dir / "dns_verification.json", encoding="utf-8") as fh:
            d = json.load(fh)
        return {n for n in (SC.norm_name(x) for x in (d.get("usable") or []) if isinstance(x, str)) if n}
    except (OSError, ValueError, AttributeError, TypeError):
        return set()


def gate_targets(names: list[str], gate, usable: set, cname_lookup, workers: int) -> tuple[set, dict]:
    """(names to probe, {name: fixed reason for not probing it}). Names refused by the name gate or the CNAME
    exclusion check are dropped from the result altogether (logged); the others are reported UNREACHABLE."""
    allowed, unprobed, dropped = [], {}, []
    for h in names:
        lab_host = gate.lab_net is not None and h in gate.lab_hosts
        ok, why = gate.name_allowed(h)
        ax = gate.apex_of(h)
        if not lab_host and ax is not None and not gate.name_excluded(h) and ax not in usable:
            unprobed[h] = ERR_PENDING          # under a scope domain that did not pass the DNS proof in this job
        elif ok:
            allowed.append(h)
        else:
            dropped.append(f"{h} ({why})")
    if dropped:
        say(f"not probed, outside the approved scope: {len(dropped)} host(s): {', '.join(dropped[:20])}"
            + (" ..." if len(dropped) > 20 else ""))
    if unprobed:
        say(f"not probed, domain not verified in this job: {len(unprobed)} host(s) reported UNREACHABLE: "
            + ", ".join(sorted(unprobed)[:20]) + (" ..." if len(unprobed) > 20 else ""))
    # the resolver follows CNAMEs, so an allowed alias of an excluded name would reach the excluded server: every
    # name in each target's CNAME chain goes through the same exclusion check recon applies
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        verdicts = list(pool.map(lambda h: gate.cname_allowed(h, cname_lookup), allowed))
    probe, chain_refused, unchecked = set(), [], []
    for h, (ok, why) in zip(allowed, verdicts):
        if ok:
            probe.add(h)
        elif why.startswith("CNAME chain reaches"):
            chain_refused.append(f"{h} ({why})")
        else:
            unprobed[h] = ERR_CNAME
            unchecked.append(h)
    if chain_refused:
        say(f"not probed, CNAME chain refused: {len(chain_refused)} host(s): {', '.join(chain_refused[:20])}"
            + (" ..." if len(chain_refused) > 20 else ""))
    if unchecked:
        say(f"not probed, CNAME chain could not be looked up: {len(unchecked)} host(s) reported UNREACHABLE: "
            + ", ".join(sorted(unchecked)[:20]) + (" ..." if len(unchecked) > 20 else ""))
    return probe, unprobed


def run(args, now: dt.datetime | None = None, fetch=None, cname_lookup=None) -> int:
    now = now or dt.datetime.now(dt.timezone.utc)
    root = Path(args.root)
    run_dir = Path(args.run_dir)
    db = Path(args.db) if args.db else root / "data" / "scan.sqlite"
    base = root / STATE_DIR
    try:
        watches = load_watches(Path(args.watches))
    except (OSError, ValueError) as e:
        say(f"watches file unreadable or invalid ({e if isinstance(e, WatchError) else type(e).__name__}); nothing written")
        return EXIT_INVALID
    gate = None
    if fetch is None:
        # live probes need the scope: the name gate, this job's DNS proof, the CNAME check and the address check
        try:
            gate = SC.Scope(str(root / "scope"), str(run_dir))
        except (SC.ScopeError, OSError, ValueError) as e:
            say(f"scope not loaded ({e}); nothing probed, nothing written")
            return EXIT_INVALID
    usable = usable_domains(run_dir)
    say(f"watches {len(watches)}; domains verified in this job: {len(usable)}"
        + (f"; lab targets {len(gate.lab_hosts)}" if gate is not None and gate.lab_net is not None else ""))
    day = now.date().isoformat()
    con = None
    try:
        con = open_db(db)
    except sqlite3.Error:
        say("no readable scan database: only the watches' own hosts and carried hosts are watched")
    plans = []
    try:
        for w in watches:
            db_hosts, scan_run = scan_db_targets(con, PRODUCTS[w["product"]]["component"]) if con else ({}, None)
            earlier = load_earlier(base / w["id"], day)
            targets = build_targets(db_hosts, w["hosts"]) + carried_targets(earlier[-1] if earlier else None, db_hosts, w["hosts"])
            plans.append((w, targets, earlier, scan_run))
    finally:
        if con:
            con.close()
    names = sorted({t["hostname"] for _, targets, _, _ in plans for t in targets})
    if not names:
        say("no targets in any watch (scan database, the watches' hosts, nothing to carry); nothing written")
        return EXIT_NOTHING

    if fetch is None:
        # live probes: the scope's address check on every connection
        SF.configure(gate)
        to_probe, unprobed = gate_targets(names, gate, usable, cname_lookup, args.workers)

        def fetch(url):
            return curl_fetch(url, connect_to=args.connect_to, timeout=args.timeout, gate=gate)
    else:
        to_probe, unprobed = set(names), {}
    # ONE probe per host, however many watches list it
    order = sorted(to_probe)
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        probes = dict(zip(order, pool.map(lambda h: probe_host(h, fetch), order)))
    probes.update({h: not_probed(h, why) for h, why in unprobed.items()})
    say(f"hosts probed {len(order)}, not probed {len(unprobed)}")

    dom = root / "scope" / "domains.txt"
    apexes = sorted(read_apexes(str(dom)), key=len, reverse=True) if dom.is_file() else []
    any_written = any_suspect = False
    for w, targets, earlier, scan_run in plans:
        targets = [t for t in targets if t["hostname"] in probes]
        if not targets:
            say(f"watch {w['id']}: no target passes the scope; nothing written for it")
            continue
        hosts = [judge(probes[t["hostname"]], t, w) for t in targets]
        # a carried host that was probed and no longer answers is taken as decommissioned: dropped here (so the list
        # cannot grow forever), it shows in changes as gone, and it counts toward neither the headline nor the
        # suspect rule. A host that was not probed (domain not verified, CNAME unknown) is kept as UNREACHABLE.
        dropped = [x["hostname"] for x in hosts if x["source"] == "carried" and x["verdict"] == "UNREACHABLE" and x["probed"]]
        hosts = [x for x in hosts if x["hostname"] not in dropped]
        if dropped:
            say(f"watch {w['id']}: dropped {len(dropped)} carried host(s) that no longer answer: {', '.join(dropped[:20])}"
                + (" ..." if len(dropped) > 20 else ""))
        info = {"total": len(targets), "from_scan_db": sum(t["source"] in ("scan_db", "both") for t in targets),
                "from_job": sum(t["source"] in ("job", "both") for t in targets),
                "carried": sum(t["source"] == "carried" for t in targets),
                "not_probed": sum(1 for t in targets if t["hostname"] in unprobed), "scan_db_run": scan_run}
        doc = build_doc(w, hosts, info, apexes, earlier, now, args.job_id)
        h = doc["headline"]
        suspect = h["unreachable"] * 2 > h["hosts"]
        if suspect:
            doc = {"suspect": True, **doc}
        text = json.dumps(doc, indent=1) + "\n"
        outdir = base / w["id"]
        write_atomic(outdir / f"{day}.json", text)
        any_written = True
        say(f"watch {w['id']}: hosts={h['hosts']} fail={h['fail']} pass={h['pass']} unknown={h['unknown']} "
            f"unreachable={h['unreachable']}; changes since {doc['changes']['since']}: {len(doc['changes']['items'])}")
        for name in retain(outdir, args.keep):
            say(f"watch {w['id']}: retention removed {name}")
        if suspect:
            any_suspect = True
            say(f"watch {w['id']}: SUSPECT: {h['unreachable']} of {h['hosts']} hosts unreachable; wrote "
                f"{STATE_DIR}/{w['id']}/{day}.json with suspect=true and left latest.json as it was")
            continue
        write_atomic(outdir / "latest.json", text)
        say(f"watch {w['id']}: wrote {STATE_DIR}/{w['id']}/{day}.json and latest.json")
    for gone in retire_watches(base, {w["id"] for w in watches}, now.date(), args.keep):
        say(f"retention: removed the folder of watch {gone} (no longer in the job, newest result older than {args.keep} days)")
    if not any_written:
        return EXIT_NOTHING
    return EXIT_SUSPECT if any_suspect else EXIT_OK


def parse_args(argv=None):
    ap = argparse.ArgumentParser(description="Version watch: the headers of GET / only, judged against each watch.")
    ap.add_argument("--root", default=os.environ.get("SCAN_ROOT", "/var/lib/scan"),
                    help="scan root (default $SCAN_ROOT, else /var/lib/scan)")
    ap.add_argument("--run-dir", required=True,
                    help="this job's run folder: dns_verification.json (this job's DNS proof) and, in lab mode, lab.json")
    ap.add_argument("--watches", required=True, help="the job's watch definitions (JSON list, as validated by the runner)")
    ap.add_argument("--job-id", default=None, help="recorded in each file")
    ap.add_argument("--db", help="scan database (default ROOT/data/scan.sqlite, opened read-only)")
    ap.add_argument("--workers", type=int, default=16, help="hosts probed in parallel (default 16)")
    ap.add_argument("--timeout", type=int, default=TIMEOUT_S, help=f"curl -m seconds (default {TIMEOUT_S})")
    ap.add_argument("--keep", type=int, default=KEEP, help=f"dated files kept per watch (default {KEEP})")
    ap.add_argument("--connect-to", help=argparse.SUPPRESS)  # tests: curl --connect-to ::127.0.0.1:PORT
    a = ap.parse_args(argv)
    if a.job_id is not None and not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}[a-z0-9]", a.job_id):
        ap.error("--job-id: not a job id")
    return a


def main(argv=None) -> int:
    return run(parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
