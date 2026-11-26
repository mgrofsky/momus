"""scoring.py - likelihood x impact scoring for normalized findings.

Score = impact (1-5) x likelihood (1-5) -> 1..25
Bands: 20-25 Critical, 12-19 High, 6-11 Medium, 1-5 Low
Fix-by days per band follow the SLA policy (settings.py; override in config/policy.json). Defaults:
Critical 30, High 30 on a host in the strict-SLA host list (scope/strict_sla_hosts.txt suffixes) or 90 elsewhere,
Medium 180, Low 180.
A host in the strict-SLA list also has a higher impact floor: a readable credential or personal data scores
impact 5 there instead of 4 (apply_exposure).

A normalized finding is a dict with (at least):
  source      nuclei | nmap | sslscan | dns | http
  severity    critical|high|medium|low|info   (as reported by the tool, or assigned by the normalizer)
  cvss        float or None
  cve_ids     list[str]
  tags        list[str]   (nuclei tags, or normalizer-assigned tags like 'tls-legacy', 'axfr', 'headers')
  asset_class owned | cdn_fronted | third_party
Enrichment is passed in: epss (dict cve->float), kev (set of cve ids).
"""
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import settings  # noqa: E402

POLICY = settings.load()
SEV_IMPACT = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "unknown": 1}
BANDS = [(20, "Critical"), (12, "High"), (6, "Medium"), (1, "Low")]
SLA_DAYS = POLICY["sla_days"]                 # ordinary hosts
STRICT_SLA_DAYS = POLICY["strict_sla_days"]   # hosts in the strict-SLA list; other bands fall back to SLA_DAYS
POLICY_DAYS = {**SLA_DAYS, **STRICT_SLA_DAYS}  # per band on a strict-SLA host
HIGH_NON_PCI_DAYS = SLA_DAYS["High"]
EXPOSURE_TAGS = {"takeover", "exposure", "default-login", "exposed-panel", "panel", "config", "backup", "creds", "token", "disclosure", "axfr", "rce", "sqli", "lfi", "ssrf", "xss"}
MISCONFIG_TAGS = {"misconfig", "tls-legacy", "weak-cipher", "cert-expired", "cert-expiring", "headers", "cors", "redirect", "ssl", "tls", "dns", "cve"}

def finding_key(hostname, source, check_id, port):
    """Stable identity across runs: hostname (not IP) + source + check id + port."""
    raw = f"{hostname.lower()}|{source}|{check_id}|{port if port is not None else ''}"
    return hashlib.sha1(raw.encode()).hexdigest()[:20]

def impact(f):
    cvss = f.get("cvss")
    if "axfr" in (f.get("tags") or []):
        return 5
    if cvss is not None:
        try:
            c = float(cvss)
            if c >= 9.0: return 5
            if c >= 7.0: return 4
            if c >= 4.0: return 3
            if c > 0: return 2
        except (TypeError, ValueError):
            pass
    return SEV_IMPACT.get((f.get("severity") or "unknown").lower(), 1)

# verify.py verdicts that mean the finding exposes nothing readable: verified noise, likelihood 1
NOISE_VERDICTS = {"names_only", "empty", "redirect", "gone"}

def likelihood(f, epss=None, kev=None, verdict=None):
    if verdict in NOISE_VERDICTS:
        return 1
    epss = epss or {}
    kev = kev or set()
    cves = [c.upper() for c in (f.get("cve_ids") or [])]
    tags = {t.lower() for t in (f.get("tags") or [])}
    cls = f.get("asset_class") or "owned"
    if cls == "unverified":   # scored like owned; shown under its own name
        cls = "owned"
    sev = (f.get("severity") or "info").lower()
    if any(c in kev for c in cves):
        return 5
    best_epss = max((epss.get(c, 0.0) for c in cves), default=None)
    if best_epss is not None and cves:
        if best_epss >= 0.4: return 4
        if best_epss >= 0.1: return 3
        return 2
    if sev == "info" and not (tags & EXPOSURE_TAGS):
        return 1
    if tags & EXPOSURE_TAGS:
        return 4 if cls in ("owned", "cdn_fronted") else 3
    if cls in ("owned", "cdn_fronted"):
        return 3 if sev in ("critical", "high", "medium") else 2
    return 2

def band(score):
    """(band name, fix-by days for a host outside the strict-SLA list)."""
    for lo, name in BANDS:
        if score >= lo:
            return name, sla_days(name)
    return "Low", sla_days("Low")

def is_pci(host, pci_suffixes=()):
    h = (host or "").strip().lower().rstrip(".")
    return bool(h) and any(h == s or h.endswith("." + s) for s in (x.strip().lower().lstrip(".") for x in pci_suffixes) if s)

def sla_days(band_name, host=None, pci_suffixes=()):
    """Fix-by days for a band; pci_suffixes is the strict-SLA host list."""
    if band_name in STRICT_SLA_DAYS and is_pci(host, pci_suffixes):
        return STRICT_SLA_DAYS[band_name]
    return SLA_DAYS.get(band_name, SLA_DAYS["Low"])

# triage.py exposures: what a finding actually lets anyone read. Floors only; an exposure never lowers a score,
# except "nothing" on a finding whose verdict said confirmed (the content check saw something, triage found it empty).
def apply_exposure(i, l, exposure, verdict=None, pci=False):
    if exposure in ("credential", "data"):
        return max(i, 5 if pci else 4), max(l, 4)
    if exposure == "source":
        return max(i, 3), l
    if exposure == "nothing" and verdict == "confirmed":
        return i, 1
    return i, l

def score(f, epss=None, kev=None, host=None, pci_suffixes=(), verdict=None, exposure=None):
    i, l = impact(f), likelihood(f, epss, kev, verdict)
    i, l = apply_exposure(i, l, exposure, verdict, is_pci(host, pci_suffixes))
    s = i * l
    b, _ = band(s)
    return {"impact": i, "likelihood": l, "score": s, "band": b, "sla_days": sla_days(b, host, pci_suffixes)}
