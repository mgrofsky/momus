"""minimize.py - turn a raw tool record into the small structured record that is stored, and clean every other
target-derived field before it is written.

  minimize(source, raw, level="minimal") -> dict    the stored evidence for one finding (always JSON-serializable)
  to_json(record)                       -> str     valid JSON, size controlled by dropping fields, never by cutting
  evidence_level(manifest=None)         -> "minimal" | "excerpt"   from SCAN_EVIDENCE, else the manifest, else minimal

Store less, then redact. Each source has an explicit allowlist of keys (ALLOWED); anything not on it is dropped.
Dropped for every source: response bodies, request dumps, replay (curl) commands, cookie values, authorization
headers and port-scanner script output. Kept: identifiers and metadata needed to understand and re-test a finding
(template or check id, name, severity, tags, references, CVE/CVSS data, matcher name, host, port, matched location,
timestamps) and extracted values after redaction, at most MAX_VALUES of them and MAX_VALUE_LEN characters each.

SCAN_EVIDENCE=excerpt also keeps a redacted excerpt of a recorded HTTP response: every response header name, the
values of the short SAFE_HEADERS list only, and at most MAX_BODY characters of body after redaction.

Verification and triage still read the full raw record in memory; this module applies to what is written. The
field helpers below (text, url, host, ...) are what ingest.py and version_watch.py use for every other stored column.
Every text value is redacted as a field (redact.py), before serialization, and capped after redaction.
"""
import ipaddress, json, os, re, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import redact as R  # noqa: E402

LEVELS = ("minimal", "excerpt")
DEFAULT_LEVEL = "minimal"
MAX_VALUES = 10          # extracted values kept per finding
MAX_VALUE_LEN = 200      # characters per kept value, after redaction
MAX_BODY = 2000          # characters of body in an excerpt, after redaction
MAX_BODY_READ = 20000    # characters of body redacted to produce the excerpt (cut at a line end)
MAX_JSON = 16000         # stored evidence above this size loses its largest optional parts first
SAFE_HEADERS = ("content-type", "content-length", "content-encoding", "content-language", "server", "x-powered-by",
                "cache-control", "date", "last-modified", "vary", "allow", "accept-ranges", "strict-transport-security",
                "x-frame-options", "x-content-type-options", "referrer-policy", "x-xss-protection")

# per-source allowlists: the only raw keys that can reach storage
ALLOWED = {
    "nuclei": ("template-id", "template", "template-url", "type", "host", "port", "scheme", "url", "path", "matched-at",
               "ip", "timestamp", "matcher-name", "matcher-status", "extractor-name", "extracted-results", "info", "siblings"),
    "nmap": ("ip", "port", "proto", "service", "product", "scripts", "open_ports"),
    "sslscan": ("protocols", "ciphers", "not_after"),
    "dns": ("apex", "ns", "ns_ip", "success", "records", "ips", "cnames"),
    "http": (),
}
INFO_KEYS = ("name", "severity", "tags", "reference", "classification")
CLASSIFICATION_KEYS = ("cve-id", "cwe-id", "cvss-score", "cvss-metrics", "epss-score", "epss-percentile", "cpe")
DROPPED_ALWAYS = ("request", "response", "curl-command", "interaction", "metadata", "template-path", "scripts output",
                  "cookie values", "authorization headers")

_HOST_RE = re.compile(r"^(?=.{1,253}$)(?:\*\.)?[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)*$")
_TOKEN_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}$")     # an HTTP header or cookie name
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
_CWE_RE = re.compile(r"^CWE-\d{1,6}$", re.I)
_HEX_RE = re.compile(r"^[0-9A-Fa-f:]{2,200}$")


class EvidenceLevelError(ValueError):
    pass


def evidence_level(manifest=None, env=None):
    """SCAN_EVIDENCE when set, else the run manifest's "evidence", else minimal. Anything else is refused."""
    env = os.environ if env is None else env
    v = (env.get("SCAN_EVIDENCE") or "").strip() or str((manifest or {}).get("evidence") or "").strip() or DEFAULT_LEVEL
    if v not in LEVELS:
        raise EvidenceLevelError(f"SCAN_EVIDENCE must be one of {', '.join(LEVELS)}, got {v!r}")
    return v


# ---------------------------------------------------------------- field helpers (one stored value each)
def text(v, cap=MAX_VALUE_LEN, strict=True):
    """Target-derived free text: redacted as a field, then capped. None stays None."""
    if v is None:
        return None
    return R.redact_text(v if isinstance(v, str) else str(v), strict=strict, cap=cap)


def ident(v, cap=100):
    """An identifier that becomes part of a key (template id, matcher name): patterns only (no entropy masking, which
    could rewrite a legitimate id), then capped. Deterministic, so the same input always gives the same key."""
    if v is None:
        return None
    return R.redact_text(str(v), strict=False, cap=cap)


def url(v, cap=500):
    if v is None:
        return None
    s = str(v)
    return R.redact_text(R.redact_url(s), strict=True, cap=cap) if s else s


def host(v, cap=253):
    """A hostname as is when it is hostname-shaped, else treated as text."""
    if v is None:
        return None
    s = str(v).strip().lower().rstrip(".")
    return s if _HOST_RE.fullmatch(s) else text(v, cap)


def ip(v):
    try:
        return str(ipaddress.ip_address(str(v).strip().strip("[]")))
    except ValueError:
        return None


def hostport(v, cap=300):
    """'address:port', 'host:port', a bare name or address, or a URL: the matched location of a finding."""
    if v is None:
        return None
    s = str(v)
    if "://" in s or "?" in s or "@" in s:
        return url(s, cap)
    h, sep, p = s.rpartition(":")
    if sep and p.isdigit() and (ip(h) or _HOST_RE.fullmatch(h.lower())):
        return f"{h.lower()}:{p}"
    return ip(s) or host(s, cap)


def port(v):
    try:
        n = int(v)
    except (TypeError, ValueError):
        return None
    return n if 0 <= n <= 65535 else None


def number(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def token(v, pattern=r"^[A-Za-z0-9_.+/ -]+$", cap=80):
    """A short vocabulary value (service name, cipher, protocol): kept only when it matches the pattern."""
    if v is None:
        return None
    s = str(v)[:cap]
    return s if re.fullmatch(pattern, s) else None


def hexid(v):
    s = str(v).strip() if v is not None else ""
    return s if _HEX_RE.fullmatch(s) else None


def header_names(names, cap=40):
    out = []
    for n in names or ():
        n = str(n).split(":", 1)[0].split("=", 1)[0].strip()
        if _TOKEN_RE.fullmatch(n) and n not in out:
            out.append(n)
    return out[:cap]


def cookie_names(values, cap=40):
    """Cookie names only: whatever follows '=' (a value) is never kept."""
    return header_names([str(v).split("=", 1)[0] for v in values or ()], cap)


def emails(values):
    return R.email_summary([v for v in values or () if isinstance(v, str)])


def text_list(values, cap_each=MAX_VALUE_LEN, max_items=MAX_VALUES, fn=None):
    fn = fn or (lambda x: text(x, cap_each))
    vals = values if isinstance(values, list) else ([values] if values not in (None, "") else [])
    return [fn(x) for x in vals[:max_items]]


# ---------------------------------------------------------------- raw records
def _parse_response(resp):
    """(status, [(name, value)], body) of a recorded HTTP response."""
    if not isinstance(resp, str) or not resp:
        return None, [], ""
    head, sep, body = resp.partition("\r\n\r\n")
    if not sep:
        head, sep, body = resp.partition("\n\n")
    lines = head.replace("\r\n", "\n").split("\n")
    m = re.match(r"HTTP/\S+\s+(\d{3})", lines[0] if lines else "")
    hdrs = []
    for ln in lines[1:]:
        k, s, v = ln.partition(":")
        if s:
            hdrs.append((k.strip(), v.strip()))
    return (int(m.group(1)) if m else None), hdrs, body


def excerpt(resp):
    """The redacted excerpt of a recorded response (SCAN_EVIDENCE=excerpt): header names, safe header values, body."""
    status, hdrs, body = _parse_response(resp)
    if status is None and not hdrs and not body:
        return None
    safe = {}
    for k, v in hdrs:
        lk = k.lower()
        if lk in SAFE_HEADERS and lk not in safe:
            safe[lk] = text(v, MAX_VALUE_LEN)
    if len(body) > MAX_BODY_READ:
        cut = body.rfind("\n", 0, MAX_BODY_READ)
        body = body[:cut] if cut > 0 else ""   # a value cut in half is dropped with its line, not kept as a head
    return {"status": status, "header_names": header_names([k for k, _ in hdrs]), "headers": safe,
            "body": text(body, MAX_BODY) if body else ""}


def _nuclei(raw, level):
    out = {}
    for k in ALLOWED["nuclei"]:
        if k not in raw or raw[k] in (None, "", [], {}):
            continue
        v = raw[k]
        if k in ("host", "url", "path", "matched-at"):
            out[k] = url(v, 500)
        elif k == "ip":
            out[k] = ip(v)
        elif k == "port":
            out[k] = port(v)
        elif k == "matcher-status":
            out[k] = bool(v)
        elif k in ("template-id", "matcher-name", "extractor-name"):
            out[k] = ident(v, 100)
        elif k == "extracted-results":
            vals = v if isinstance(v, list) else [v]
            out[k] = text_list(vals)
            if len(vals) > MAX_VALUES:
                out["extracted-total"] = len(vals)
        elif k == "siblings":
            out[k] = [host(h) for h in (v or [])[:25]]
        elif k == "info":
            out[k] = _info(v)
        else:   # template, template-url, type, scheme, timestamp
            out[k] = text(v, 200)
    if level == "excerpt":
        ex = excerpt(raw.get("response"))
        if ex:
            out["excerpt"] = ex
    return {k: v for k, v in out.items() if v not in (None, "", [], {})}


def _info(info):
    if not isinstance(info, dict):
        return {}
    out = {}
    for k in INFO_KEYS:
        v = info.get(k)
        if v in (None, "", [], {}):
            continue
        if k == "name":
            out[k] = text(v, 300)
        elif k == "severity":
            out[k] = token(str(v).lower(), r"^[a-z]+$", 20)
        elif k == "tags":
            vals = v if isinstance(v, list) else str(v).split(",")
            out[k] = [t for t in (token(str(x).strip().lower(), r"^[a-z0-9_.:-]+$", 50) for x in vals[:40]) if t]
        elif k == "reference":
            vals = v if isinstance(v, list) else [v]
            out[k] = [url(x, 300) for x in vals[:10] if x]
        elif k == "classification" and isinstance(v, dict):
            c = {}
            for ck in CLASSIFICATION_KEYS:
                cv = v.get(ck)
                if cv in (None, "", []):
                    continue
                if ck == "cve-id":
                    c[ck] = [x.upper() for x in (cv if isinstance(cv, list) else [cv]) if isinstance(x, str) and _CVE_RE.fullmatch(x)][:20]
                elif ck == "cwe-id":
                    c[ck] = [x.upper() for x in (cv if isinstance(cv, list) else [cv]) if isinstance(x, str) and _CWE_RE.fullmatch(x)][:20]
                elif ck in ("cvss-score", "epss-score", "epss-percentile"):
                    c[ck] = number(cv)
                else:
                    c[ck] = text(cv, 200)
            out[k] = {ck: cv for ck, cv in c.items() if cv not in (None, "", [])}
    return {k: v for k, v in out.items() if v not in (None, "", [], {})}


def _nmap(raw):
    out = {"ip": ip(raw.get("ip")), "port": port(raw.get("port")), "proto": token(raw.get("proto"), r"^[a-z]+$", 10),
           "service": token(raw.get("service"), r"^[A-Za-z0-9_.+/-]+$", 50), "product": text(raw.get("product"), 100)}
    if isinstance(raw.get("scripts"), dict):   # which scripts ran, never what they printed
        out["script_ids"] = [s for s in (token(k, r"^[A-Za-z0-9_.-]+$", 60) for k in list(raw["scripts"])[:20]) if s]
    if isinstance(raw.get("open_ports"), list):
        out["open_ports"] = [p for p in (port(x) for x in raw["open_ports"][:200]) if p is not None]
    return {k: v for k, v in out.items() if v not in (None, "", [])}


def _sslscan(raw):
    out = {}
    if isinstance(raw.get("protocols"), list):
        out["protocols"] = [p for p in (token(x, r"^[A-Za-z0-9. ]+$", 20) for x in raw["protocols"][:10]) if p]
    if isinstance(raw.get("ciphers"), list):
        out["ciphers"] = [c for c in (token(x, r"^[A-Za-z0-9_-]+$", 80) for x in raw["ciphers"][:50]) if c]
    if raw.get("not_after"):
        out["not_after"] = text(raw["not_after"], 40)
    return out


def _dns(raw):
    out = {}
    for k in ("apex", "ns"):
        if raw.get(k):
            out[k] = host(raw[k])
    if raw.get("ns_ip"):
        out["ns_ip"] = ip(raw["ns_ip"])
    if "success" in raw:
        out["success"] = bool(raw["success"])
    if isinstance(raw.get("records"), int):
        out["records"] = raw["records"]
    if isinstance(raw.get("ips"), list):
        out["ips"] = [x for x in (ip(i) for i in raw["ips"][:50]) if x]
    if isinstance(raw.get("cnames"), list):
        out["cnames"] = [host(c) for c in raw["cnames"][:20]]
    return {k: v for k, v in out.items() if v not in (None, "", [])}


def minimize(source, raw, level=DEFAULT_LEVEL):
    """The stored evidence for one finding. Unknown sources store nothing."""
    if level not in LEVELS:
        raise EvidenceLevelError(f"unknown evidence level {level!r}")
    raw = raw if isinstance(raw, dict) else {}
    if source == "nuclei":
        return _nuclei(raw, level)
    if source == "nmap":
        return _nmap(raw)
    if source == "sslscan":
        return _sslscan(raw)
    if source == "dns":
        return _dns(raw)
    return {}


def to_json(record):
    """Valid JSON always. Over MAX_JSON, the excerpt body, then the excerpt, then extracted values, then references
    are dropped until it fits; a serialized string is never cut."""
    rec = json.loads(json.dumps(record or {}, default=str))
    s = json.dumps(rec, sort_keys=True)
    steps = (("excerpt", "body"), ("excerpt",), ("extracted-results",), ("info", "reference"), ("siblings",))
    for path in steps:
        if len(s) <= MAX_JSON:
            break
        d = rec
        for p in path[:-1]:
            d = d.get(p) if isinstance(d, dict) else None
        if isinstance(d, dict) and path[-1] in d:
            del d[path[-1]]
            rec.setdefault("dropped", []).append(".".join(path))
        s = json.dumps(rec, sort_keys=True)
    if len(s) > MAX_JSON:
        rec = {k: rec[k] for k in ("template-id", "matcher-name", "host", "port", "matched-at", "ip", "proto", "service") if k in rec}
        rec["dropped"] = ["over size"]
        s = json.dumps(rec, sort_keys=True)
    return s


# ---------------------------------------------------------------- other stored rows
def triage_record(tri):
    """finding_triage fields: summary and fix redacted again; items with redacted URL and note; secrets as type,
    masked form and location only."""
    items = []
    for it in (tri.get("items") or []):
        items.append({"url": url(it.get("url"), 500), "status": port(it.get("status")) if it.get("status") is not None else None,
                      "bytes": it.get("bytes") if isinstance(it.get("bytes"), int) else None,
                      "kind": token(it.get("kind"), r"^[a-z]+$", 20), "note": text(it.get("note"), 300)})
    secrets = []
    for s in (tri.get("secrets") or []):
        where = str(s.get("where") or "")
        secrets.append({"type": text(s.get("type"), 100), "masked": text(s.get("masked") or "(value not read)", 60),
                        "where": url(where, 300) if ("/" in where or "?" in where) else text(where, 300),
                        "line": s.get("line") if isinstance(s.get("line"), int) else None})
    return {"summary": text(tri.get("summary"), 600), "fix": text(tri.get("fix"), 600), "items": items, "secrets": secrets[:50]}


def component(c):
    """asset_components / components: name and version are part of the key, so they are cleaned the same way every run."""
    return {**c, "name": text(c.get("name"), 100), "version": text(c.get("version"), 60) if c.get("version") else c.get("version"),
            "evidence": text(c.get("evidence"), 200)}


def profile(pr):
    out = dict(pr)
    for k, v in pr.items():
        if isinstance(v, str):
            out[k] = text(v, 100)
    return out


def endpoint(r):
    return {**r, "url": url(r.get("url")), "final_url": url(r.get("final_url")), "redirect_to": url(r.get("redirect_to")),
            "title": text(r.get("title"), 200), "server": text(r.get("server"), 100), "generator": text(r.get("generator"), 100),
            "powered_by": text(r.get("powered_by"), 100), "content_type": text(r.get("content_type"), 100),
            "cookies": cookie_names(r.get("cookies")), "httponly_cookies": cookie_names(r.get("httponly_cookies")),
            "emails": emails(r.get("emails")), "uncommon_headers": header_names(r.get("uncommon_headers")),
            "analytics": text_list(r.get("analytics"), 100, 20),
            "chain": [p for p in (port(x) for x in (r.get("chain") or [])[:20]) if p is not None],
            "favicon_mmh3": token(r.get("favicon_mmh3"), r"^-?\d+$", 20), "favicon_md5": hexid(r.get("favicon_md5"))}


def certificate(c):
    sans = []
    for s in c.get("sans") or []:
        s = str(s)
        sans.append(host(s) if _HOST_RE.fullmatch(s.lower().rstrip(".")) else (url(s, 300) if "://" in s else text(s, 200)))
    return {**c, "subject": text(c.get("subject"), 200), "issuer": text(c.get("issuer"), 200), "sans": sans[:200],
            "key_type": token(c.get("key_type"), r"^[A-Za-z0-9_.-]+$", 40), "sig_alg": token(c.get("sig_alg"), r"^[A-Za-z0-9_.-]+$", 60),
            "serial": hexid(c.get("serial")),
            "sha256": hexid(c.get("sha256")), "not_before": text(c.get("not_before"), 40), "not_after": text(c.get("not_after"), 40)}


def tls_endpoint(t):
    return {**t, "protocols": [p for p in (token(x, r"^[A-Za-z0-9. ]+$", 20) for x in t.get("protocols") or []) if p],
            "preferred_cipher": token(t.get("preferred_cipher"), r"^[A-Za-z0-9_-]+$", 80)}


TEXT_RTYPES = {"TXT", "SPF", "DMARC", "DKIM", "WILDCARD"}


def dns_record(r):
    v = r.get("value")
    if r.get("rtype") in TEXT_RTYPES:
        v = text(v, 500)
    elif r.get("rtype") in ("A", "AAAA"):
        v = ip(v) or text(v, 100)
    else:   # names, MX/SRV/CAA/SOA lines: short structured lines; cleaned as text without entropy masking
        v = text(v, 300, strict=False)
    return {**r, "name": host(r.get("name")) or "", "value": v if v is not None else ""}


def host_port(r):
    return {**r, "service": token(r.get("service"), r"^[A-Za-z0-9_.+/-]+$", 50), "product": text(r.get("product"), 100),
            "reason": token(r.get("reason"), r"^[a-z-]+$", 30), "proto": token(r.get("proto"), r"^[a-z]+$", 10)}


def posture(r):
    return {**r, "spf_policy": token(r.get("spf_policy"), r"^[a-z]+$", 20), "dmarc_policy": text(r.get("dmarc_policy"), 20),
            "dmarc_sp": text(r.get("dmarc_sp"), 20), "mx": [text(x, 300, strict=False) for x in (r.get("mx") or [])[:20]],
            "nameservers": [host(x) for x in (r.get("nameservers") or [])[:20]],
            "caa_issuers": [text(x, 100) for x in (r.get("caa_issuers") or [])[:20]]}


def app_group(g):
    return {**g, "url": url(g.get("url")), "group_url": url(g.get("group_url"))}
