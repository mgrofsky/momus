"""redact.py - find secrets in fetched content, classify what the content is, and redact values before anything is stored.

  find_secrets(text, where="")  -> [{type, where, line, masked}]  never any part of a value (masked: public prefix and length)
  redact(text)                  -> text with every secret value, card number and phone number replaced
  redact_url(url)               -> the URL without user-info and with credential and signature parameters masked
  redact_text(text, strict)     -> redact() plus every URL through redact_url, email addresses reduced to their domain,
                                   and (strict) long high-entropy tokens masked: what storage uses for one field
  mask(value)                   -> the masked form of one secret value
  classify(text, name="")       -> (kind, note)                   credential | data | source | config | internal | nothing

Redaction here is best-effort pattern matching. It will miss secrets in formats it has no pattern for, values split
across lines or fields, and encodings it does not decode (base64, compression, URL-encoded JSON). The main control
is minimization (minimize.py): target content that is not needed is never stored. This module is the second line,
applied field by field to what is kept, before serialization.

Shared by triage.py, minimize.py and ingest.py. The rule is simple: a value that matches a secret pattern never
leaves this module; only its type, location and masked form do.
"""
import json, math, re
from urllib.parse import urlsplit, urlunsplit

# ---------------------------------------------------------------- secret patterns
# (type, compiled regex). The regex's group "v" is the value; when it has no "v" group the whole match is the value.
# key names that hold a secret (secret_key() also requires the keyword to stand alone in the name: not "tokenizer")
_KEYWORDS = r"(?:pass(?:word|wd)?|pwd|secret|api[_-]?key|apikey|access[_-]?key|secret[_-]?key|auth[_-]?key|app[_-]?key|signing[_-]?key|encryption[_-]?key|private[_-]?key|client[_-]?secret|auth[_-]?token|access[_-]?token|token|credentials?)"

def secret_key(name):
    """True when a key name holds a secret: DB_PASSWORD, api-key, clientSecret; not tokenizer, passport, author."""
    n = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name or "")
    return bool(re.search(r"(?:^|[^A-Za-z])" + _KEYWORDS + r"(?:$|[^A-Za-z])", n, re.I))

# query-string and cookie names whose value is a credential, a signature or a session (lower case)
SIGNED_PARAMS = ("x-amz-signature", "x-amz-credential", "x-amz-security-token", "awsaccesskeyid", "x-goog-signature",
                 "x-goog-credential", "googleaccessid", "signature", "sig", "policy", "key-pair-id")
SESSION_NAMES = ("phpsessid", "jsessionid", "asp.net_sessionid", "aspsessionid", "connect.sid", "sessionid", "session_id",
                 "session", "sid", "_session", "laravel_session", "ci_session", "csrftoken", "xsrf-token", "_csrf")
_AUTH_SCHEMES = r"(?:basic|bearer|digest|negotiate|ntlm|token|aws4-hmac-sha256|hoba|mutual|vapid|scram-sha-256)"
_PARAM_NAMES = "|".join(re.escape(p) for p in SIGNED_PARAMS + SESSION_NAMES)

SECRET_PATTERNS = [
    ("npm registry token", re.compile(r"(?im)^\s*(?:\S*:)?_authToken\s*=\s*(?P<v>[^\s\"'#;]+)")),
    ("npm basic auth", re.compile(r"(?im)^\s*(?:\S*:)?_auth\s*=\s*(?P<v>[^\s\"'#;]+)")),
    ("npm password", re.compile(r"(?im)^\s*(?:\S*:)?_password\s*=\s*(?P<v>[^\s\"'#;]+)")),
    ("private key", re.compile(r"(?P<v>-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|$))")),
    ("bearer token", re.compile(r"(?i)\bbearer\s+(?P<v>[A-Za-z0-9._~+/-]{16,}=*)")),
    ("basic auth", re.compile(r"(?i)\bbasic\s+(?P<v>[A-Za-z0-9+/]{8,}={0,2})(?![A-Za-z0-9+/=])")),
    # other Authorization forms: the whole value after the scheme is the credential (Digest, AWS4, a bare token)
    ("authorization header", re.compile(r"(?im)^[ \t]*(?:proxy-)?authorization[ \t]*:[ \t]*(?:" + _AUTH_SCHEMES + r"[ \t]+)?(?P<v>[^\r\n]*[^\s])")),
    ("authorization header", re.compile(r"(?i)[\"'](?:proxy-)?authorization[\"']\s*[:=]\s*[\"'](?:" + _AUTH_SCHEMES + r"\s+)?(?P<v>[^\"'\r\n]+)")),
    # inside a quoted argument: curl -H 'Authorization: Token abc'
    ("authorization header", re.compile(r"(?i)(?<=[\"'])(?:proxy-)?authorization\s*:\s*(?:" + _AUTH_SCHEMES + r"\s+)?(?P<v>[^\"'\r\n]+)")),
    ("cookie", re.compile(r"(?im)(?:^|[\s\"'{,])(?:set-)?cookie[\"']?\s*[:=]\s*[\"']?(?P<v>[^\"'\r\n]+)")),
    ("JSON Web Token", re.compile(r"(?P<v>\beyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*)")),
    # signed-URL and session parameters, in a URL, a query string or a Cookie-style list (S3 / CloudFront / GCS / Azure SAS)
    ("signed URL parameter", re.compile(r"(?i)(?<![A-Za-z0-9_.-])(?:" + _PARAM_NAMES + r")=(?P<v>[^&;#\s\"'<>]+)")),
    # case-insensitive: certificate subjects and host names are stored lower-cased, and a lower-cased key id still names the key
    ("AWS access key id", re.compile(r"(?i)(?P<v>\b(?:AKIA|ASIA)[0-9A-Z]{16}\b)")),
    ("npm access token", re.compile(r"(?P<v>\bnpm_[A-Za-z0-9]{30,}\b)")),
    ("GitHub token", re.compile(r"(?P<v>\bgh[pousr]_[A-Za-z0-9]{30,}\b)")),
    ("Slack token", re.compile(r"(?P<v>\bxox[abprs]-[A-Za-z0-9-]{10,})")),
    ("Stripe live key", re.compile(r"(?P<v>\b[sr]k_live_[A-Za-z0-9]{16,})")),
    ("Google API key", re.compile(r"(?P<v>\bAIza[0-9A-Za-z_-]{35})")),
    ("password in URL", re.compile(r"(?i)\b[a-z][a-z0-9+.-]{1,15}://[^\s:/@\"'<>]{1,64}:(?P<v>[^\s@/\"'<>]{1,128})@[A-Za-z0-9.-]+")),
    ("password in connection string", re.compile(r"(?i)(?:^|[;\"'\s])(?:password|pwd)\s*=\s*(?P<v>[^;\"'\s<>]{3,})")),
    # JSON inside a JSON string: {\"password\": \"value\"} (the escaped quotes hide the pair from the pattern below)
    ("secret in config", re.compile(r"(?i)\\+[\"'](?P<k>[A-Za-z0-9_.-]*" + _KEYWORDS + r"[A-Za-z0-9_.-]*)\\+[\"']\s*:\s*\\+[\"']"
                                    r"(?P<v>(?:[^\"\\]|\\+[^\"'\\])+?)\\+[\"']")),
    # key = value / key: value / "key": "value" / 'key' => 'value' / define('KEY', 'value') with a secret-looking key
    # (the key starts where a run of key characters starts: the same matches, in linear time on long tokens)
    ("secret in config", re.compile(r"(?im)[\"']?(?<![A-Za-z0-9_.-])(?P<k>[A-Za-z0-9_.-]*" + _KEYWORDS + r"[A-Za-z0-9_.-]*)[\"']?\s*(?:=>|=|:|,)\s*"
                                    r"(?P<q>[\"']?)(?P<v>[^\s\"',;#<>{}()\[\]]{4,})(?P=q)")),
]
# values that are references, placeholders or plain words, not secrets
_NOT_A_VALUE = re.compile(r"""(?ix)^(?:
      \$\{?[A-Za-z_][A-Za-z0-9_]*\}?.*   # $VAR, ${VAR}
    | %[A-Za-z_]+%                        # %VAR%
    | \{\{.*\}\} | <<.*>>                 # templates, CircleCI parameters
    | true|false|null|none|nil|yes|no|on|off|required|optional|string|boolean|object|number|integer|undefined|empty
    | enabled|disabled|active|inactive|supported|present|missing|latest|next|\*
    | [\^~>=<v*]*\d+(?:\.[\w*-]+)+\S*     # a version or semver range ("jsonwebtoken": "^8.5.1")
    | (?:npm|file|link|github|git\+\w+):\S*  # a dependency source
    | (?:\*+|x{4,}|\.{3,}|-+|_+|changeme|change_me|password|secret|example|your[_-].*|<.*>)
    | env\(.*|getenv\(.*|process\.env.*|os\.environ.*|config\(.*|ENV\[.*
    | [a-z]+\(.*                          # a function call
    | (?:~|\.{1,2})?/[\w./-]*             # a file path
    )$""")
# An identifier made of lowercase words (a key name, a setting: "driver: mysql"). Not a value under a key that
# stands for a secret on its own: "DB_PASSWORD=hunter" or "password: correcthorse" is a lowercase password.
_LOWER_WORDS = re.compile(r"^[a-z]+(?:[._-][a-z]+)*$")
_COOKIE_PAIR = re.compile(r"(?P<n>[^=;,\s]+)\s*=\s*(?P<v>[^;\r\n]*)")
_COOKIE_ATTRS = {"path", "domain", "expires", "max-age", "samesite", "priority", "version", "comment"}

def _cookie_spans(text, s, e):
    """Value spans of every name=value pair in a Cookie / Set-Cookie value (attributes such as Path stay)."""
    out = []
    for m in _COOKIE_PAIR.finditer(text, s, e):
        if m.group("n").lower() in _COOKIE_ATTRS or not m.group("v").strip():
            continue
        vs, ve = m.span("v")
        while ve > vs and text[ve - 1] in " \t":
            ve -= 1
        out.append((vs, ve))
    return out

def _secret_matches(text):
    """[(type, start, end)] of secret values, overlaps removed (first pattern wins)."""
    out = []
    def overlaps(s, e):
        return any(not (e <= a or s >= b) for _, a, b in out)
    for typ, rx in SECRET_PATTERNS:
        for m in rx.finditer(text):
            if "v" in rx.groupindex and m.group("v") is not None:
                s, e = m.span("v")
            else:
                s, e = m.span()
            v = text[s:e]
            if v.startswith("REDACTED") or v.startswith("<REDACTED"):
                continue
            if typ == "cookie":
                for cs, ce in _cookie_spans(text, s, e):
                    if not overlaps(cs, ce) and text[cs:ce] != "REDACTED":
                        out.append((typ, cs, ce))
                continue
            if typ == "authorization header" and (_NOT_A_VALUE.fullmatch(v.strip()) or len(v.strip()) < 4):
                continue
            if typ in ("secret in config", "password in connection string"):
                if _NOT_A_VALUE.fullmatch(v) or len(set(v)) < 3:
                    continue
                k = (m.group("k") or "") if "k" in rx.groupindex else "password"
                if _LOWER_WORDS.fullmatch(v) and not secret_key(k):
                    continue
                if typ == "secret in config":
                    k = k.lower()
                    # "password_reset_url: /reset", "token_ttl: 3600": a key ABOUT a secret, not one holding it
                    if re.search(r"(?:url|uri|path|ttl|expir|length|min|max|field|name|label|type|placeholder|hint|reset|policy|header|endpoint|file|route|validation|rule|confirm|lifetime|timeout|enabled|required)", k):
                        continue
                    if v.isdigit() and len(v) < 6:
                        continue
            if overlaps(s, e):
                continue
            out.append((typ, s, e))
    return sorted(out, key=lambda t: t[1])

_PUBLIC_PREFIX = re.compile(r"^(?:-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|AKIA|ASIA|gh[pousr]_|npm_|xox[abprs]-|[sr]k_live_|AIza|eyJ)")

def mask(value):
    """The masked form of one secret value: a well-known public prefix (AKIA, ghp_, eyJ, the PEM header) if it has
    one, and the length. Nothing else of the value."""
    v = value or ""
    m = _PUBLIC_PREFIX.match(v)
    return f"{m.group(0) if m else ''}...[{len(v)} chars]"

def find_secrets(text, where=""):
    """[{type, where, line, masked}] for every secret value in text; the value itself is never returned."""
    if not text:
        return []
    return [{"type": typ, "where": where, "line": text.count("\n", 0, s) + 1, "masked": mask(text[s:e])}
            for typ, s, e in _secret_matches(text)]

# ---------------------------------------------------------------- personal data
_CARD = re.compile(r"(?<![\d.])(?:\d[ -]?){12,18}\d(?![\d.])")
_PHONE = re.compile(r"(?<![\w+])\+[1-9]\d{7,14}\b")
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

def luhn_ok(digits):
    d = [int(c) for c in digits if c.isdigit()]
    if not 13 <= len(d) <= 19 or len(set(d)) < 2:
        return False
    total = 0
    for i, x in enumerate(reversed(d)):
        if i % 2:
            x *= 2
            if x > 9:
                x -= 9
        total += x
    return total % 10 == 0

def cards(text):
    return [m for m in _CARD.finditer(text or "") if luhn_ok(m.group())]

def phones(text):
    return list(_PHONE.finditer(text or ""))

def emails(text):
    return sorted(set(_EMAIL.findall(text or "")))

def redact(text):
    """Every secret value -> <REDACTED type>; card numbers that pass Luhn -> <REDACTED card>; E.164 numbers -> <REDACTED phone>."""
    if not text:
        return text or ""
    spans = [(s, e, f"<REDACTED {typ}>") for typ, s, e in _secret_matches(text)]
    spans += [(m.start(), m.end(), "<REDACTED card>") for m in cards(text)]
    spans += [(m.start(), m.end(), "<REDACTED phone>") for m in phones(text)]
    out, pos = [], 0
    for s, e, rep in sorted(spans):
        if s < pos:
            continue
        out.append(text[pos:s]); out.append(rep); pos = e
    out.append(text[pos:])
    return "".join(out)

# ---------------------------------------------------------------- URLs and stored fields
# query / fragment parameter names whose value is masked in a URL (besides SIGNED_PARAMS, SESSION_NAMES and any
# name secret_key() accepts): OAuth codes and tokens, generic keys
_URL_SECRET_NAMES = {"code", "access_token", "id_token", "refresh_token", "auth", "key", "apikey", "api_key", "token", "jwt",
                     "password", "passwd", "pwd", "pass", "secret", "client_secret", "credential", "credentials", "otp", "ticket"}
_URL_IN_TEXT = re.compile(r"(?i)\b[a-z][a-z0-9+.-]{1,15}://[^\s\"'<>`]+")

def _url_name_is_secret(name):
    from urllib.parse import unquote_plus
    n = unquote_plus(name or "").strip().lower()
    return n in _URL_SECRET_NAMES or n in SIGNED_PARAMS or n in SESSION_NAMES or secret_key(n)

def _mask_params(q, depth):
    """name=value pairs separated by & or ; with the value of every credential-named parameter replaced, and URLs
    nested inside a value (a redirect target) redacted in turn. The rest of the string is kept byte for byte."""
    from urllib.parse import quote, unquote
    parts = re.split(r"([&;])", q)
    for i in range(0, len(parts), 2):
        name, sep, value = parts[i].partition("=")
        if not sep:
            continue
        if _url_name_is_secret(name):
            parts[i] = f"{name}=REDACTED"
        elif depth < 3 and "://" in unquote(value):
            parts[i] = f"{name}=" + quote(_redact_url(unquote(value), depth + 1), safe=":/?&=;#<>[]@")
    return "".join(parts)

def _redact_url(url, depth=0):
    s = str(url)
    try:
        p = urlsplit(s)
    except ValueError:
        return redact(s)
    netloc = p.netloc.rsplit("@", 1)[-1]          # user-info (user:password@) never kept
    path = re.sub(r"(?i);(" + "|".join(re.escape(n) for n in SESSION_NAMES) + r")=[^/;?#]*", r";\1=REDACTED", p.path)
    query = _mask_params(p.query, depth) if p.query else p.query
    frag = _mask_params(p.fragment, depth) if "=" in p.fragment else p.fragment
    if p.scheme or p.netloc:
        out = urlunsplit((p.scheme, netloc, path, query, frag))
    else:   # a relative URL or a bare query string: keep its shape
        out = path + (("?" + query) if p.query or s.split("#", 1)[0].endswith("?") else "") + (("#" + frag) if p.fragment else "")
    return redact(out)

def redact_url(url):
    """The URL with user-info removed, the values of credential, signature and session parameters (query string,
    fragment, ;jsessionid path parameters) masked, URLs nested in parameter values redacted too, and then the
    secret patterns applied to what is left. Use it for matched locations, final URLs, redirect chains, item URLs."""
    if url is None:
        return None
    if not str(url):
        return ""
    return _redact_url(url)

_TOKEN = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{20,}={0,2}(?![A-Za-z0-9+/=_-])")

def _entropy(s):
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in (s.count(x) for x in set(s)))

def _cls(c):
    return "u" if c.isupper() else "l" if c.islower() else "d" if c.isdigit() else "s"

def _random(s, min_len, min_switch=0.3):
    """Looks machine-made: upper, lower and digits all present, high entropy, and the character class changes often
    (sha256WithRSAEncryption, ECDHE-RSA-AES128-GCM-SHA256 or a path have long runs of one class; a key does not)."""
    if len(s) < min_len or not (any(c.isupper() for c in s) and any(c.islower() for c in s) and any(c.isdigit() for c in s)):
        return False
    switches = sum(1 for a, b in zip(s, s[1:]) if _cls(a) != _cls(b))
    return _entropy(s) >= 3.3 and switches / len(s) >= min_switch

def high_entropy(tok):
    """A long token that looks random. A token with '/' is judged per segment (a URL path is a list of words), and
    as a whole only when its classes switch very often (base64 with several slashes)."""
    core = tok.rstrip("=")
    if "/" not in core:
        return _random(core, 20)
    if any(_random(seg, 16) for seg in core.split("/")):
        return True
    return _random(core.replace("/", ""), 20, min_switch=0.45)

def redact_text(text, strict=False, cap=None):
    """One target-derived text field, ready to store: every URL through redact_url, the secret patterns, cards and
    phone numbers (redact), email addresses reduced to their domain, and with strict=True every long high-entropy
    token masked as well. The cap applies after redaction, so a cut never exposes the head of a value."""
    if text is None:
        return None
    t = str(text)
    if not t:
        return t
    t = _URL_IN_TEXT.sub(lambda m: redact_url(m.group(0)), t)
    t = redact(t)
    t = _EMAIL.sub(lambda m: f"<email at {m.group(0).rsplit('@', 1)[1].lower()}>", t)
    if strict:
        t = _TOKEN.sub(lambda m: "<REDACTED high-entropy string>" if high_entropy(m.group(0)) else m.group(0), t)
    if cap is not None and len(t) > cap:
        t = t[:cap]
    return t

def email_summary(addresses):
    """{"count": n, "domains": [...]}: what is stored of email addresses scraped from a target page."""
    doms = sorted({a.rsplit("@", 1)[1].lower().rstrip(".") for a in addresses or () if isinstance(a, str) and "@" in a})
    return {"count": len({a.lower() for a in addresses or () if isinstance(a, str)}), "domains": doms[:20]}

# ---------------------------------------------------------------- classification
_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# A hostname is one or more labels and then either a built-in top-level domain or a suffix registered at run time
# with set_scope_suffixes() (the scanned organization's own domains, whatever their top-level domain). Built-ins
# are neutral on purpose: "example" and "test" are not among them, so .env.example or app.test.js are file names.
BUILTIN_TLDS = ("com", "net", "org", "io", "internal", "local", "aws", "cloud", "dev")
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_SUFFIX_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)*$")
_scope_suffixes = ()

def _hostname_re(suffixes):
    alts = [rf"(?:{_LABEL}\.)+(?:{'|'.join(BUILTIN_TLDS)})"]
    if suffixes:
        # a registered suffix matches on its own (the apex) or under further labels, never inside a longer label
        alts.append(rf"(?:{_LABEL}\.)*(?:{'|'.join(re.escape(s) for s in suffixes)})")
    return re.compile(r"(?<![\w-])(?:" + "|".join(alts) + r")(?![\w-])", re.I)

def set_scope_suffixes(suffixes):
    """Register extra hostname suffixes (the approved scope domains) for internal_names(); an empty list clears them."""
    global _scope_suffixes, _HOSTNAME
    out = []
    for s in suffixes or ():
        n = (s or "").strip().lower().rstrip(".")
        n = n[2:] if n.startswith("*.") else n.lstrip(".")
        if not n:
            continue
        if not _SUFFIX_RE.fullmatch(n):
            raise ValueError(f"not a domain suffix: {s!r}")
        if n not in out:
            out.append(n)
    _scope_suffixes = tuple(sorted(out, key=lambda x: (-len(x), x)))
    _HOSTNAME = _hostname_re(_scope_suffixes)

def scope_suffixes():
    return _scope_suffixes

_HOSTNAME = _hostname_re(())
_ACCOUNT = re.compile(r"\b\d{12}\b")
_SOURCE = [re.compile(p, re.M) for p in (
    r"<\?php", r"^\s*(?:def|class|module)\s+[A-Za-z_]\w*", r"^\s*(?:import|from)\s+[\w.]+", r"^\s*require(?:_once)?\s*[\('\"]",
    r"^#!\s*/(?:usr/)?bin/(?:env\s+)?(?:ba|z)?sh\b", r"^\s*(?:function\s+\w+\s*\(|const\s+\w+\s*=|let\s+\w+\s*=|var\s+\w+\s*=)",
    r"^\s*(?:if|for|while)\s*\(.*\)\s*\{", r"^\s*(?:public|private|protected)\s+(?:static\s+)?function\b", r"\$\w+\s*=\s*.+;\s*$",
    r"^\s*(?:echo|set -e|export\s+\w+=|cd\s+\S+|npm\s+\w+|if \[)")]

HTML_EXTS = {"", "html", "htm", "php", "asp", "aspx", "jsp", "cgi", "shtml", "md"}

def looks_html(text):
    b = (text or "").lstrip()[:400].lower()
    return b.startswith("<!doctype html") or b.startswith("<html") or "<html" in b or "<body" in b

def html_kind(text):
    """'error', 'login' or 'page' for an HTML body."""
    t = (text or "")[:20000].lower()
    title = re.search(r"<title[^>]*>(.*?)</title>", t, re.S)
    title = title.group(1) if title else ""
    if re.search(r"<input[^>]+type=[\"']?password", t) or "do=login" in t or "mode_denied" in t or "permission denied" in title:
        return "login"
    if re.search(r"\b(?:40[0-9]|50[0-9])\b|not found|forbidden|error|unavailable|does not exist", title):
        return "error"
    return "page"

def _config_like(text):
    s = text.strip()
    if not s:
        return False
    if s[0] in "{[":
        try:
            json.loads(s)
            return True
        except Exception:
            pass
    lines = [l for l in s.splitlines() if l.strip() and not l.strip().startswith(("#", ";", "//"))]
    if not lines:
        return False
    kv = sum(1 for l in lines if re.match(r"^\s*[\w.\"'/-]+\s*(?:=|:)\s*\S", l) or re.match(r"^\s*-\s+\S", l) or re.match(r"^\s*\[[^\]]+\]\s*$", l) or re.match(r"^\s*<\w+[^>]*>", l))
    return kv >= max(1, len(lines) * 0.5)

def internal_names(text, limit=8):
    """Hostnames, private/public IPs and 12-digit account ids named in the text (internal facts, not secrets)."""
    out = []
    for rx in (_HOSTNAME, _IP, _ACCOUNT):
        for x in rx.findall(text or ""):
            if x not in out:
                out.append(x)
            if len(out) >= limit:
                return out
    return out

def classify(text, name=""):
    """(kind, note) for one readable body. kind: credential | data | source | config | internal | nothing."""
    text = text or ""
    if not text.strip():
        return "nothing", "empty"
    sec = find_secrets(text)
    if sec:
        types = {}
        for s in sec:
            types[s["type"]] = types.get(s["type"], 0) + 1
        return "credential", ", ".join(f"{n} {t}" + ("s" if n > 1 and not t.endswith("s") else "") for t, n in types.items())
    nc, np_, ne = len(cards(text)), len(phones(text)), len(emails(text))
    if nc or np_ > 20 or ne > 20:
        return "data", ", ".join(x for x in (f"{nc} card numbers" if nc else "", f"{np_} phone numbers" if np_ > 20 else "", f"{ne} email addresses" if ne > 20 else "") if x)
    if looks_html(text):
        hk = html_kind(text)
        if hk in ("login", "error"):
            return "nothing", f"HTML {hk} page"
        base = name.lower().rstrip("/").rsplit("/", 1)[-1]
        ext = base.rsplit(".", 1)[-1] if "." in base.lstrip(".") else ""
        if "/." in "/" + name.lower() or ext not in HTML_EXTS:
            # a dotfile, a .json or .sh answered with an HTML page: the site's catch-all, not the file
            return "nothing", "an HTML page, not the file"
    hits = sum(1 for rx in _SOURCE if rx.search(text[:50000]))
    ext = name.lower().rsplit(".", 1)[-1] if "." in name else ""
    if hits >= 2 or (hits and ext in ("php", "rb", "py", "sh", "js", "pl", "inc")) or "<?php" in text:
        return "source", f"program source ({ext or 'code'})"
    if _config_like(text):
        return "config", "configuration without secrets"
    names = internal_names(text)
    if names:
        return "internal", "names " + ", ".join(names[:4])
    return "internal" if len(text) > 200 else "nothing", f"{len(text)} bytes of text"
