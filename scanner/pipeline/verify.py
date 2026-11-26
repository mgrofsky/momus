"""verify.py - check what an exposure/listing finding actually exposes, by content, not by template name.

  verdict, evidence = verify(finding, raw, fetch=None, host=None)

finding: the normalized finding dict from ingest.py (check_id, tags, matched); raw: nuclei's JSON record (request,
response, matched-at, template-id). Verdicts:
  confirmed   the response (or a file the listing names) has readable content
  names_only  only file names are revealed (a default-extension negotiation variant, a listing whose files return nothing)
  empty       a listing with no entries, or a 200 with an empty body / a bare HTML shell
  redirect    the recorded response is a 30x
  gone        the recorded response is a 40x/50x (or a 200 whose short body says "not found")
  unverified  nothing recorded and the live fetch failed (scoring leaves the finding as it was)
names_only, empty, redirect and gone lower the likelihood to 1 in scoring.py (they stay in the report as verified
noise). Rule 2 (directory listings) fetches at most MAX_ENTRIES listed files, sequentially, TIMEOUT s each, on the
finding's own host only (host=, from the asset inventory, never from nuclei's matched-at), through safefetch.Pinned:
resolved once, checked with the scope, connected to that address, same-host redirects only. Nothing else touches
the network. fetch(url, headers) -> (status, final_url, body_bytes) is a parameter so tests pass a stub.
"""
import os, re, sys, urllib.parse, urllib.request
from html import unescape

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import safefetch as SF  # noqa: E402

VERIFY_TAGS = {"exposure", "listing", "config", "disclosure", "backup"}
NOISE_VERDICTS = {"names_only", "empty", "redirect", "gone"}
DEFAULT_EXTS = {"php", "html", "htm", "asp", "aspx", "jsp", "cgi", "pl", "shtml"}
MAX_ENTRIES = 10
TIMEOUT = 10
MAX_REDIRECTS = 3
MAX_BODY = 1 << 20

def wants_verify(f):
    return f.get("source") == "nuclei" and bool({t.lower() for t in (f.get("tags") or [])} & VERIFY_TAGS)

# ---------------------------------------------------------------- recorded HTTP
def parse_response(resp):
    """(status or None, {header-lower: value}, body str) from nuclei's raw response text."""
    if not resp:
        return None, {}, ""
    head, sep, body = resp.partition("\r\n\r\n")
    if not sep:
        head, sep, body = resp.partition("\n\n")
    lines = head.replace("\r\n", "\n").split("\n")
    m = re.match(r"HTTP/\S+\s+(\d{3})", lines[0] if lines else "")
    headers = {}
    for ln in lines[1:]:
        k, s, v = ln.partition(":")
        if s:
            headers[k.strip().lower()] = v.strip()
    return (int(m.group(1)) if m else None), headers, body

def user_agent(raw):
    m = re.search(r"(?im)^User-Agent:\s*(.+?)\s*$", (raw or {}).get("request") or "")
    return m.group(1) if m else None

def _url(f, raw):
    return (raw or {}).get("matched-at") or f.get("matched") or ""

def _template(f, raw):
    return (raw or {}).get("template-id") or (f.get("check_id") or "").split(":")[0]

def is_html(body):
    b = body.lstrip()[:200].lower()
    return b.startswith("<!doctype html") or b.startswith("<html") or "<html" in b

SOFT_404 = re.compile(r"\b404\b|not found|no static resource|does not exist", re.I)

# ---------------------------------------------------------------- live fetch (rule 2 only)
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None

def fetch_for(host):
    """The live fetch for one finding: pinned to host (see safefetch.py)."""
    return SF.Pinned(host, timeout=TIMEOUT, max_redirects=MAX_REDIRECTS)

# ---------------------------------------------------------------- rules
def _variants(headers, body):
    names = re.findall(r'\{"([^"]+)"', headers.get("alternates", ""))
    if not names:
        m = re.search(r"Available variants:(.*?)</ul>", body, re.S | re.I)
        if m:
            names = re.findall(r'<a href="([^"]+)"', m.group(1))
    return list(dict.fromkeys(unescape(n) for n in names))

def rule_negotiation(f, raw):
    status, headers, body = parse_response((raw or {}).get("response"))
    if status is None:
        return "unverified", "unverified: no response recorded"
    base = urllib.parse.urlsplit(_url(f, raw)).path.rstrip("/").rsplit("/", 1)[-1]
    names = _variants(headers, body)
    if not names:
        return "empty", f"{status}, no variants listed"
    other = [n for n in names if not (n.rsplit(".", 1)[0] == base and "." in n and n.rsplit(".", 1)[1].lower() in DEFAULT_EXTS)]
    if other:
        return "confirmed", "variants: " + ", ".join(other[:8])
    return "names_only", "only default variants: " + ", ".join(names[:8])

def listing_entries(body):
    out = []
    for href, text in re.findall(r'<a\s[^>]*?href="([^"]*)"[^>]*>(.*?)</a>', body, re.S | re.I):
        h = unescape(href).strip()
        t = re.sub(r"<[^>]+>", "", text).strip()
        if not h or h == "/" or h.startswith("?") or h.startswith("#") or "parent directory" in t.lower():
            continue
        if h in out:
            continue
        out.append(h)
    return out

def _entry_confirms(status, final_url, wanted, body):
    if status != 200 or not body:
        return False
    if final_url != wanted:
        return False
    txt = body[:4096].decode("latin-1", "replace").lower()
    if re.search(r"<meta[^>]+http-equiv=[\"']?refresh", txt) or re.search(r"<input[^>]+type=[\"']?password", txt):
        return False
    return True

def rule_listing(f, raw, fetch, host=None):
    status, headers, body = parse_response((raw or {}).get("response"))
    if status is None:
        return "unverified", "unverified: no response recorded"
    if 300 <= status < 400:
        return "redirect", f"{status} -> {headers.get('location', '')}"[:200]
    if status >= 400:
        return "gone", f"{status}"
    base = _url(f, raw)
    if not base.endswith("/"):
        base += "/"
    url_host = (urllib.parse.urlsplit(base).hostname or "").lower()
    # the anchor is the finding's own host; only a test stub may stand in for it with the URL's host
    anchor = host_of_finding(f, host) or (url_host if fetch is not None else None)
    if not anchor:
        return "unverified", "unverified: no finding host to anchor the fetch to"
    if url_host != anchor:
        return "unverified", f"unverified: matched URL is on {url_host}, not the finding's host {anchor}"
    host = anchor
    entries = listing_entries(body)
    if not entries:
        return "empty", f"{status}, listing has no entries"
    files, dirs, offhost = [], [], []
    for e in entries:
        u = urllib.parse.urljoin(base, e)
        if urllib.parse.urlsplit(u).hostname != host:
            offhost.append(e)      # never followed
        elif e.endswith("/"):
            dirs.append(e)         # a subdirectory is another listing, not file content
        else:
            files.append((e, u))
    hdrs = {"User-Agent": user_agent(raw) or "Mozilla/5.0"}
    confirmed, seen, errors = [], [], []
    fetch = fetch or fetch_for(anchor)
    for name, u in files[:MAX_ENTRIES]:
        try:
            st, final, data = fetch(u, hdrs)
        except Exception as ex:
            errors.append(f"{name} {type(ex).__name__}")
            continue
        n = len(data or b"")
        seen.append(f"{name} {st} {n}")
        if _entry_confirms(st, final, u, data):
            confirmed.append(f"{name} {st} {n} bytes")
    extra = (f"; {len(dirs)} dir(s)" if dirs else "") + (f"; {len(files) - MAX_ENTRIES} more file(s) not fetched" if len(files) > MAX_ENTRIES else "")
    if confirmed:
        return "confirmed", ("; ".join(confirmed) + extra)[:300]
    if files and not seen:
        return "unverified", ("unverified: " + "; ".join(errors))[:300]
    if not files:
        return "names_only", (f"{len(dirs)} dir(s) only: " + ", ".join(dirs[:8]))[:300]
    return "names_only", ("names only: " + "; ".join(seen) + extra + (("; errors: " + "; ".join(errors)) if errors else ""))[:300]

def rule_exposure(f, raw):
    status, headers, body = parse_response((raw or {}).get("response"))
    if status is None:
        return "unverified", "unverified: no response recorded"
    if 300 <= status < 400:
        return "redirect", f"{status} -> {headers.get('location', '')}"[:200]
    if status >= 400:
        return "gone", f"{status}"
    n = len(body.encode("utf-8", "replace"))
    if urllib.parse.urlsplit(_url(f, raw)).path in ("", "/"):
        # matched on the site root: a header/banner template (fastly-debug-headers); the body is not what it found
        return "confirmed", f"{status} {n} bytes, matched at site root"
    if not body.strip():
        return "empty", f"{status} 0 bytes"
    if n < 300 and SOFT_404.search(body) and not (raw or {}).get("extracted-results"):
        return "gone", f"{status} {n} bytes, body says not found"
    if n < 300 and is_html(body) and not (raw or {}).get("extracted-results"):
        return "empty", f"{status} {n} bytes, HTML shell"
    return "confirmed", f"{status} {n} bytes"

def host_of_finding(f, host=None):
    return ((host or f.get("hostname") or "").lower().rstrip(".")) or None

def verify(finding, raw, fetch=None, host=None):
    """(verdict, evidence) for one nuclei finding; see the module docstring. host: the finding's own host; without it
    (and without a test stub) no live fetch is made."""
    tid = _template(finding, raw)
    tags = {t.lower() for t in (finding.get("tags") or [])}
    try:
        if tid == "apache-mod-negotiation-listing":
            return rule_negotiation(finding, raw)
        if tid.endswith("-listing") or "listing" in tags:
            return rule_listing(finding, raw, fetch, host)
        return rule_exposure(finding, raw)
    except Exception as ex:   # a verifier bug must not lose the finding
        print(f"warn: verify {tid}: {type(ex).__name__}", file=sys.stderr)   # the message can quote content
        return "unverified", f"unverified: {type(ex).__name__}"
