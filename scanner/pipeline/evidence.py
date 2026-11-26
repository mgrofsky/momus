"""evidence.py - the asset-inventory side of ingest: everything the scan observes that is not a finding.

Pure functions over the raw files a scan run already wrote (nothing here touches the network):

  sslscan_evidence(root, run_day)   -> certificates and TLS configuration per host:port (sslscan XML)
  httpx_records(run_dir)            -> the raw httpx records (one per URL)
  httpx_cert(rec, run_day)          -> the certificate httpx saw (fills the endpoints sslscan could not reach)
  whatweb_by_url(run_dir)           -> whatweb plugins keyed by normalised URL, for the endpoint join
  endpoint_row(rec, plugins)        -> one endpoints row: HTTP detail plus page signals (headers, cookies, emails...)
  dns_records_nuclei(run_dir)       -> SPF / DMARC / DKIM / MX / CAA / NS / SRV / TXT / WILDCARD from nuclei_dns.jsonl
  dns_records_dnsx(path, source)    -> A / AAAA / CNAME (and MX / NS / TXT / CAA / SOA when the apex pass wrote dns_apex.jsonl)
  domain_posture(apexes, records)   -> one email / DNS posture row per apex
  host_ports(root, ip_hosts, ...)   -> every open port per hostname sharing the address (nmap XML), plus PTR names
  asset_sources(run_dir)            -> which discovery sources found each name (sources.json)
  app_groups(run_dir)               -> which hostnames serve the same application (nuclei_groups.json)
  san_leads(certs, apexes, known)   -> certificate names under the scoped apexes that DNS does not know

Tables these feed (ingest.py SCHEMA): certificates, tls_endpoints, dns_records, domain_posture, host_ports,
asset_sources, app_groups, endpoints. All per run, additive, inventory only: nothing here scores or finds.
"""
import datetime as dt, json, os, re
from urllib.parse import urlsplit


def _readlines(path, **kw):
    """The file's lines, as iterating the open file would give them, with the file closed afterwards."""
    with open(path, **kw) as fh:
        return fh.readlines()

def _read_json(path, **kw):
    with open(path, **kw) as fh:
        return json.load(fh)

SSL_DATE = "%b %d %H:%M:%S %Y"
LEGACY_PROTOCOLS = {("ssl", "2"), ("ssl", "3"), ("tls", "1.0"), ("tls", "1.1")}
WEAK_STRENGTH = {"weak", "null", "anonymous", "medium"}
CERT_EXPIRING_DAYS = 30

# mail and DNS providers by hostname suffix (lower-case, no trailing dot); first match wins
MX_PROVIDERS = [
    ("aspmx.l.google.com", "Google Workspace"), ("googlemail.com", "Google Workspace"), ("google.com", "Google Workspace"),
    ("protection.outlook.com", "Microsoft 365"), ("outlook.com", "Microsoft 365"), ("sendgrid.net", "SendGrid"),
    ("mimecast.com", "Mimecast"), ("mimecast.co.uk", "Mimecast"), ("pphosted.com", "Proofpoint"), ("zoho.com", "Zoho Mail"),
    ("amazonaws.com", "Amazon SES"), ("mailgun.org", "Mailgun"), ("secureserver.net", "GoDaddy"), ("zendesk.com", "Zendesk"),
    ("hubspot.net", "HubSpot"), ("mail.protection.outlook.com", "Microsoft 365"),
]
NS_PROVIDERS = [
    ("awsdns-", "Amazon Route 53"), ("dnsmadeeasy.com", "DNS Made Easy"), ("cloudflare.com", "Cloudflare"), ("uberns.com", "UberNS"),
    ("uberns.org", "UberNS"), ("ultradns", "UltraDNS"), ("azure-dns", "Azure DNS"), ("domaincontrol.com", "GoDaddy"),
    ("googledomains.com", "Google Domains"), ("nsone.net", "NS1"), ("akam.net", "Akamai"), ("dynect.net", "Dyn"),
    ("registrar-servers.com", "Namecheap"), ("worldnic.com", "Network Solutions"), ("gandi.net", "Gandi"),
]
NUCLEI_RTYPE = {"spf-record-detect": "SPF", "dmarc-detect": "DMARC", "dkim-record-detect": "DKIM", "mx-fingerprint": "MX",
                "caa-fingerprint": "CAA", "nameserver-fingerprint": "NS", "srv-service-detect": "SRV", "txt-fingerprint": "TXT",
                "wildcard-dns-detect": "WILDCARD"}
CAA_RE = re.compile(r'(\d+)\s+(issue|issuewild|iodef)\s+"([^"]+)"')


# ---------------------------------------------------------------- small helpers

def host_of(url):
    try:
        h = urlsplit(url if "://" in (url or "") else "//" + (url or "")).hostname
    except ValueError:
        return (url or "").lower()
    return (h or url or "").lower().rstrip(".")


def norm_url(u):
    """Scheme, host and non-default port, lower-case, no trailing slash: the key the httpx / whatweb join uses."""
    u = (u or "").strip().lower().rstrip("/")
    if u.startswith("http://") and u.endswith(":80"):
        u = u[:-3]
    elif u.startswith("https://") and u.endswith(":443"):
        u = u[:-4]
    return u


def port_of_url(url):
    try:
        p = urlsplit(url).port
    except ValueError:
        p = None
    if p:
        return p
    return 443 if (url or "").startswith("https://") else 80


def parse_ssl_date(s):
    """'Jan  5 13:48:20 2031 GMT' -> '2031-01-05T13:48:20Z' (sslscan pads single-digit days with a space)."""
    s = " ".join((s or "").replace("GMT", "").split())
    if not s:
        return None
    try:
        return dt.datetime.strptime(s, SSL_DATE).strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return None


def days_left(not_after, run_day):
    if not not_after:
        return None
    try:
        return (dt.date.fromisoformat(not_after[:10]) - run_day).days
    except ValueError:
        return None


def _bool(s):
    return 1 if (s or "").strip().lower() in ("true", "1", "yes") else 0


def _parse_ms(s):
    """httpx 'time': '264.08113ms', '1.2s', '2m0.5s' -> milliseconds."""
    if not s:
        return None
    total, num = 0.0, ""
    for m in re.finditer(r"([\d.]+)(ms|s|m|h)", str(s)):
        v, unit = float(m.group(1)), m.group(2)
        total += v * {"ms": 1, "s": 1000, "m": 60000, "h": 3600000}[unit]
        num = v
    return round(total, 1) if num != "" else None


def provider_of(name, table):
    n = (name or "").lower().rstrip(".")
    n = re.sub(r"^\d+\s+", "", n)   # MX priority prefix
    for suffix, label in table:
        if suffix.endswith("-"):
            if suffix in n:
                return label
        elif n == suffix or n.endswith("." + suffix):
            return label
    return None


def _unquote(v):
    """A TXT value as dig prints it: one or more quoted strings ("abc" "def") that the resolver concatenates.
    Long SPF records come split at 255 characters and nuclei keeps the split, so the pieces are joined without a separator."""
    v = (v or "").strip()
    parts = re.findall(r'"((?:[^"\\]|\\.)*)"', v)
    if parts and v.startswith('"'):
        return "".join(parts)
    return v.strip('"')


# ---------------------------------------------------------------- sslscan

def sslscan_evidence(root, run_day):
    """(certs, tls): dicts keyed by (hostname, port) from the merged sslscan document (ingest._sslscan_root)."""
    certs, tls = {}, {}
    if root is None:
        return certs, tls
    for t in root.iter("ssltest"):
        host = (t.get("host") or "").lower().rstrip(".")
        if not host:
            continue
        port = int(t.get("port") or 443)
        enabled = [(pr.get("type") or "", pr.get("version") or "") for pr in t.findall("protocol") if pr.get("enabled") == "1"]
        ciphers = [c for c in t.findall("cipher") if c.get("status") in ("accepted", "preferred")]
        weak = sorted({c.get("cipher") for c in ciphers if (c.get("strength") or "").lower() in WEAK_STRENGTH
                       or ((c.get("bits") or "999").isdigit() and int(c.get("bits")) < 128)})
        preferred = next((c.get("cipher") for c in ciphers if c.get("status") == "preferred"), None)
        fb, rn, cp = t.find("fallback"), t.find("renegotiation"), t.find("compression")
        tls[(host, port)] = {
            "hostname": host, "port": port, "protocols": [f"{ty}{ver}" for ty, ver in enabled],
            "legacy": int(any((ty, ver) in LEGACY_PROTOCOLS for ty, ver in enabled)),
            "preferred_cipher": preferred, "weak_ciphers": len(weak),
            "fallback_scsv": int(fb.get("supported") == "1") if fb is not None else None,
            "secure_reneg": (int(rn.get("secure") == "1") if rn.get("supported") == "1" else 1) if rn is not None else None,
            "compression": int(cp.get("supported") == "1") if cp is not None else None,
            "heartbleed": int(any(x.get("vulnerable") == "1" for x in t.findall("heartbleed"))),
        }
        cert = next(iter(t.iter("certificate")), None)
        if cert is None:
            continue
        pk = cert.find("pk")
        alt = (cert.findtext("altnames") or "").strip()
        sans = []
        for part in alt.split(","):
            part = part.strip()
            if ":" in part:
                part = part.split(":", 1)[1].strip()
            if part:
                sans.append(part.lower().rstrip("."))
        not_after = parse_ssl_date(cert.findtext("not-valid-after"))
        certs[(host, port)] = {
            "hostname": host, "port": port, "subject": (cert.findtext("subject") or "").strip().lower() or None, "sans": sans,
            "issuer": (cert.findtext("issuer") or "").strip() or None,
            "key_type": (pk.get("type") if pk is not None else None) or None,
            "key_bits": int(pk.get("bits")) if pk is not None and (pk.get("bits") or "").isdigit() else None,
            "sig_alg": (cert.findtext("signature-algorithm") or "").strip() or None,
            "not_before": parse_ssl_date(cert.findtext("not-valid-before")), "not_after": not_after,
            "days_left": days_left(not_after, run_day), "expired": _bool(cert.findtext("expired")),
            "self_signed": _bool(cert.findtext("self-signed")), "serial": None, "sha256": None, "source": "sslscan",
        }
    return certs, tls


# ---------------------------------------------------------------- httpx and whatweb

def httpx_records(run_dir):
    """One record per URL from httpx.jsonl (the first wins when httpx reports a URL twice)."""
    p = os.path.join(run_dir, "httpx.jsonl")
    out, seen = [], set()
    if not os.path.exists(p):
        return out
    for line in _readlines(p, errors="ignore"):
        try:
            d = json.loads(line)
        except ValueError:
            continue
        u = d.get("url")
        if not u or u in seen or d.get("failed"):
            continue
        seen.add(u)
        out.append(d)
    return out


def httpx_cert(rec, run_day):
    """The certificate httpx recorded for one URL, in the certificates-row shape, or None."""
    t = rec.get("tls") or {}
    if not t.get("not_after") and not t.get("subject_cn"):
        return None
    fp = t.get("fingerprint_hash") or {}
    issuer_org = t.get("issuer_org")
    issuer = (issuer_org[0] if isinstance(issuer_org, list) and issuer_org else None) or t.get("issuer_cn") or t.get("issuer_dn")
    host = host_of(rec.get("url"))
    return {
        "hostname": host, "port": port_of_url(rec.get("url")), "subject": (t.get("subject_cn") or "").lower() or None,
        "sans": sorted({(s or "").lower().rstrip(".") for s in (t.get("subject_an") or []) if s}),
        "issuer": issuer, "key_type": None, "key_bits": None, "sig_alg": None,
        "not_before": t.get("not_before"), "not_after": t.get("not_after"), "days_left": days_left(t.get("not_after"), run_day),
        "expired": int(bool(t.get("expired"))), "self_signed": int(bool(t.get("self_signed"))),
        "serial": t.get("serial"), "sha256": (fp.get("sha256") if isinstance(fp, dict) else None), "source": "httpx",
    }


def whatweb_by_url(run_dir):
    p = os.path.join(run_dir, "whatweb.json")
    out = {}
    if not os.path.exists(p):
        return out
    try:
        entries = _read_json(p, errors="ignore")
    except ValueError:
        return out
    for e in entries:
        plugins = e.get("plugins") or {}
        key = norm_url(e.get("target"))
        slot = out.setdefault(key, {})
        for k, v in plugins.items():
            s = slot.setdefault(k, {"string": [], "version": [], "account": []})
            for kk in ("string", "version", "account"):
                for x in (v or {}).get(kk) or []:
                    if x not in s[kk]:
                        s[kk].append(x)
    return out


def _strings(plugins, name):
    return [x for x in ((plugins.get(name) or {}).get("string") or []) if x]


def endpoint_row(rec, plugins):
    """One endpoints row from an httpx record and the whatweb plugins for the same URL."""
    plugins = plugins or {}
    url = rec.get("url")
    chain = rec.get("chain_status_codes") or []
    analytics = []
    ga = plugins.get("Google-Analytics") or {}
    analytics += [f"GA {x}" for x in (ga.get("account") or [])]
    if "Google-Tag-Manager" in plugins:
        analytics.append("Google Tag Manager")
    if "Facebook-Pixel" in plugins or "Facebook" in plugins:
        analytics.append("Facebook")
    uncommon = []
    for s in _strings(plugins, "UncommonHeaders"):
        uncommon += [x.strip() for x in s.split(",") if x.strip()]
    port = rec.get("port")
    try:
        port = int(port)
    except (TypeError, ValueError):
        port = port_of_url(url)
    return {
        "url": url, "hostname": host_of(url), "scheme": rec.get("scheme") or url.split(":", 1)[0], "port": port,
        "status": rec.get("status_code"), "final_url": rec.get("final_url"), "chain": chain,
        "content_type": rec.get("content_type"), "content_length": rec.get("content_length"), "title": (rec.get("title") or "")[:200] or None,
        "server": rec.get("webserver"), "favicon_mmh3": str(rec.get("favicon")) if rec.get("favicon") not in (None, "") else None,
        "favicon_md5": rec.get("favicon_md5"), "words": rec.get("words"), "lines": rec.get("lines"), "response_ms": _parse_ms(rec.get("time")),
        "hsts": int("Strict-Transport-Security" in plugins), "csp": int("Content-Security-Policy" in plugins),
        "xfo": int("X-Frame-Options" in plugins), "xss_protection": int("X-XSS-Protection" in plugins),
        "cookies": _strings(plugins, "Cookies"), "httponly_cookies": _strings(plugins, "HttpOnly"),
        "emails": sorted({e.lower() for e in _strings(plugins, "Email")}), "analytics": analytics,
        "generator": (_strings(plugins, "MetaGenerator") or [None])[0], "powered_by": (_strings(plugins, "X-Powered-By") or [None])[0],
        "password_field": int("PasswordField" in plugins), "redirect_to": (_strings(plugins, "RedirectLocation") or [None])[0],
        "uncommon_headers": sorted(set(uncommon)),
    }


# ---------------------------------------------------------------- DNS

def _rec(host, rtype, name, value, source, ttl=None):
    return {"hostname": host, "rtype": rtype, "name": (name or host).lower().rstrip("."), "value": value, "source": source, "ttl": ttl}


def dns_records_nuclei(run_dir):
    """SPF, DMARC, DKIM, MX, CAA, NS, SRV, TXT and WILDCARD records from the nuclei DNS pass."""
    p = os.path.join(run_dir, "nuclei_dns.jsonl")
    out = []
    if not os.path.exists(p):
        return out
    for line in _readlines(p, errors="ignore"):
        try:
            d = json.loads(line)
        except ValueError:
            continue
        rtype = NUCLEI_RTYPE.get(d.get("template-id"))
        if not rtype:
            continue
        host = (d.get("host") or "").lower().rstrip(".")
        name = (d.get("matched-at") or host).split("://")[-1].split(":")[0]
        for raw in d.get("extracted-results") or []:
            raw = str(raw)
            if rtype == "CAA":
                for flags, tag, val in CAA_RE.findall(raw):
                    out.append(_rec(host, "CAA", host, f"{flags} {tag} {val}", "nuclei"))
                continue
            if rtype == "SRV":
                raw = raw.split("\t", 1)[1] if raw.startswith("SRV\t") else raw
            v = _unquote(raw).rstrip(".") if rtype in ("MX", "NS", "SRV") else _unquote(raw)
            if rtype == "TXT" and v.lower().startswith("v=spf1"):
                rtype_row = "SPF"
            elif rtype == "TXT" and v.lower().startswith("v=dmarc1"):
                rtype_row = "DMARC"
            else:
                rtype_row = rtype
            out.append(_rec(host, rtype_row, name if rtype in ("DMARC", "DKIM", "SRV", "WILDCARD") else host, v, "nuclei"))
    return out


def classify_txt(name, value):
    v = (value or "").lower()
    if v.startswith("v=spf1"):
        return "SPF"
    if v.startswith("v=dmarc1") or name.startswith("_dmarc."):
        return "DMARC"
    if v.startswith("v=dkim1") or "._domainkey." in name:
        return "DKIM"
    return "TXT"


def dns_records_dnsx(path, source="dnsx"):
    """A / AAAA / CNAME (and MX, NS, TXT, CAA, SOA when asked for) from a dnsx -resp -json file, via its `all` answer lines."""
    out = []
    if not os.path.exists(path):
        return out
    for line in _readlines(path, errors="ignore"):
        try:
            d = json.loads(line)
        except ValueError:
            continue
        host = (d.get("host") or "").lower().rstrip(".")
        # a queried policy name (_dmarc.<apex>, <selector>._domainkey.<apex>) belongs to the domain it is under
        host = re.sub(r"^_dmarc\.", "", host)
        host = re.sub(r"^[^.]+\._domainkey\.", "", host)
        for ln in d.get("all") or []:
            parts = ln.split("\t")
            if len(parts) < 5:
                continue
            name, ttl, _cls, rtype, value = parts[0], parts[1], parts[2], parts[3].upper(), "\t".join(parts[4:])
            name = name.lower().rstrip(".")
            value = _unquote(value)
            if rtype in ("CNAME", "NS", "MX", "PTR"):
                value = value.rstrip(".")
            if rtype == "TXT":
                rtype = classify_txt(name, value)
            if rtype == "MX":
                value = re.sub(r"^(\d+)\s+", r"\1 ", value)
            out.append(_rec(host, rtype, name, value, source, int(ttl) if ttl.isdigit() else None))
    return out


def spf_policy(value):
    m = re.search(r"(?:^|\s)([-~?+]?)all(?:\s|$)", value or "")
    if not m:
        return "none"
    return {"-": "hard", "~": "soft", "?": "neutral", "+": "pass", "": "pass"}[m.group(1)]


def dmarc_policy(value):
    tags = dict(re.findall(r"(\w+)\s*=\s*([^;]+)", value or ""))
    p = (tags.get("p") or "").strip().lower() or None
    sp = (tags.get("sp") or "").strip().lower() or p
    return p, sp


POSTURE_RTYPES = {"SPF", "DMARC", "MX", "NS", "CAA", "TXT", "SOA"}


def domain_posture(apexes, records):
    """One row per apex from the DNS records: SPF, DMARC, DKIM, MX, CAA, nameservers, providers, coverage."""
    by_host = {}
    for r in records:
        by_host.setdefault(r["hostname"], []).append(r)
    rows = []
    for apex in sorted(apexes):
        apex = apex.lower()
        own = by_host.get(apex, [])
        sources = {r["source"] for r in own if r["rtype"] in POSTURE_RTYPES}   # A/AAAA/CNAME from dnsx do not count as posture coverage
        spf = [r for r in own if r["rtype"] == "SPF"]
        dmarc = [r for r in own if r["rtype"] == "DMARC"]
        dkim_names = {r["name"] for h, rs in by_host.items() if h == apex or h.endswith("." + apex) for r in rs if r["rtype"] == "DKIM"}
        mx = sorted({r["value"] for r in own if r["rtype"] == "MX"}, key=lambda v: (int(v.split()[0]) if v.split() and v.split()[0].isdigit() else 999, v))
        ns = sorted({r["value"].lower() for r in own if r["rtype"] == "NS"})
        caa = sorted({r["value"] for r in own if r["rtype"] == "CAA"})
        sub_spf = {h for h, rs in by_host.items() if h != apex and h.endswith("." + apex) and any(r["rtype"] == "SPF" for r in rs)}
        sub_dkim = {h for h, rs in by_host.items() if h != apex and h.endswith("." + apex) and any(r["rtype"] == "DKIM" for r in rs)}
        p, sp = dmarc_policy(dmarc[0]["value"]) if dmarc else (None, None)
        rows.append({
            "apex": apex, "spf": int(bool(spf)), "spf_policy": spf_policy(spf[0]["value"]) if spf else None,
            "dmarc": int(bool(dmarc)), "dmarc_policy": p, "dmarc_sp": sp, "dkim": int(bool(dkim_names)),
            "mx": mx, "mx_provider": next((provider_of(m, MX_PROVIDERS) for m in mx if provider_of(m, MX_PROVIDERS)), ("self-hosted" if mx else None)),
            "caa": int(bool(caa)), "caa_issuers": sorted({c.split(" ", 2)[2] for c in caa if len(c.split(" ", 2)) == 3}),
            "nameservers": ns, "ns_provider": next((provider_of(n, NS_PROVIDERS) for n in ns if provider_of(n, NS_PROVIDERS)), ("self-hosted" if ns else None)),
            "hosts_with_spf": len(sub_spf), "hosts_with_dkim": len(sub_dkim),
            "coverage": "dnsx" if "dnsx" in sources else ("nuclei" if "nuclei" in sources else "none"),
        })
    return rows


# ---------------------------------------------------------------- nmap

def host_ports(root, ip_hosts, risky_ports, risky_services, web_ports):
    """(ports, ptr): every open port per hostname that shares the address, and PTR names per address."""
    ports, ptr = [], []
    if root is None:
        return ports, ptr
    for h in root.iter("host"):
        ip = next((a.get("addr") for a in h.findall("address") if a.get("addrtype") in ("ipv4", "ipv6")), None)
        if not ip:
            continue
        hosts = ip_hosts.get(ip) or [ip]
        for hn in h.iter("hostname"):
            if hn.get("type") == "PTR" and hn.get("name"):
                ptr.append(_rec(hosts[0], "PTR", ip, hn.get("name").lower().rstrip("."), "nmap"))
        for prt in h.iter("port"):
            st = prt.find("state")
            if st is None or st.get("state") != "open":
                continue
            svc = prt.find("service")
            name = ((svc.get("name") if svc is not None else "") or "").lower()
            product = " ".join(x for x in [svc.get("product") if svc is not None else None, svc.get("version") if svc is not None else None] if x) or None
            port, proto = int(prt.get("portid")), prt.get("protocol") or "tcp"
            risky = int(name in risky_services or port in risky_ports)
            for host in hosts:
                ports.append({"hostname": host, "ip": ip, "port": port, "proto": proto, "service": name or None, "product": product,
                              "reason": st.get("reason"), "risky": risky, "web": int(port in web_ports or "http" in name)})
    return ports, ptr


# ---------------------------------------------------------------- discovery and clusters

def asset_sources(run_dir):
    p = os.path.join(run_dir, "sources.json")
    if not os.path.exists(p):
        return {}
    try:
        d = _read_json(p, errors="ignore")
    except ValueError:
        return {}
    return {(h or "").lower().rstrip("."): sorted({str(s) for s in (srcs or [])}) for h, srcs in d.items()}


def app_groups(run_dir):
    """Rows (url, hostname, group_url, group_host, members) from nuclei_groups.json: the representative URL per application."""
    p = os.path.join(run_dir, "nuclei_groups.json")
    out = []
    if not os.path.exists(p):
        return out
    try:
        d = _read_json(p, errors="ignore")
    except ValueError:
        return out
    for rep, members in d.items():
        members = sorted(set(members or []) | {rep})
        for u in members:
            out.append({"url": u, "hostname": host_of(u), "group_url": rep, "group_host": host_of(rep), "members": len(members)})
    return out


def san_leads(certs, apexes, known_hosts):
    """Certificate names under the scoped apexes, not wildcards, that DNS does not know: discovery leads."""
    known = {h.lower() for h in known_hosts}
    apexes = [a.lower() for a in apexes]
    leads = {}
    for c in certs:
        for s in c.get("sans") or []:
            if s.startswith("*") or s in known or not any(s == a or s.endswith("." + a) for a in apexes):
                continue
            leads.setdefault(s, set()).add(c["hostname"])
    return {s: sorted(v) for s, v in sorted(leads.items())}
