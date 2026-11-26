#!/usr/bin/env python3
"""scope.py - the one place that decides whether a name or an address may be touched. Standard library only.

Scope directory ($SCAN_ROOT/scope/):
  domains.txt         approved apexes (a subdomain you control is also allowed as an entry); required, never empty
  exclude.txt         names, name suffixes (".example.test"), single addresses or CIDRs; never touched
  owned_ranges.txt    CIDRs approved for port scans
  approved_hosts.txt  hosts approved for port scans after a human reviewed the inventory
  ownership.json      one entry per apex: the owner's statement plus the DNS proof (see approve.py)
  approval.json       inventory approval for active phases (read by recon.sh, written by approve.py)

Rules:
  name_allowed(host)            under an approved, owned, DNS-verified apex on a label boundary, and not excluded
  ip_allowed(ip, host=None)     globally routable and not excluded; in lab mode, addresses in the lab CIDR are
                                allowed for names in the lab targets file only
  portscan_allowed(host, ips)   every address passes ip_allowed and sits in owned_ranges.txt, or the host is in
                                approved_hosts.txt
Each returns (ok, reason). Scope.reject() appends a rejection to <run dir>/scope_rejected.jsonl.

Command line (used by recon.sh):
  scope.py check   --scope DIR [--run-dir DIR]                  load and validate the scope; print the apexes
  scope.py recheck-dns --scope DIR --run-dir DIR                re-verify every apex's DNS proof; print the usable ones
  scope.py filter  --scope DIR --run-dir DIR --stage S --kind K --in F --out F [--cover SOURCE]
       kinds: names (name gate), hosts (name gate + every address in dns.jsonl passes ip_allowed),
              urls (same, on the URL's host), hostports (host:port, same), ips (ip_allowed),
              portscan (addresses whose hosts pass portscan_allowed)
  scope.py lab-check --cidr CIDR                                lab mode limits (SCAN_LAB=1, private, <= /24)
  scope.py ns-check --scope DIR --run-dir DIR --stage S APEX... print the apexes whose every nameserver address
                                passes the DNS proof's address check now; log a rejection for the others
  scope.py sync --scope DIR                                     the scope-sync job: re-check the DNS proof of every
                                domain in the scope (dig only, no scan tool); print the usable ones
  recheck-dns and sync take --state DIR (default $SCAN_ROOT/state, else <scope dir>/../state): the install secret.

DNS proof tokens are minted by the scanner, never taken from outside: token = HMAC-SHA-256(install secret, domain),
first 32 hex characters (derive_token). The install secret is created once per install by the job runner
(load_secret(create=True)) in its own state folder with owner-only permissions and is never published. A TXT record
is public, so a token supplied by a job could be copied from another domain's DNS; a derived one cannot be reused
on another install or for another domain. Each ownership entry records the key id (a fingerprint of the secret, not
the secret) it was checked under; an entry whose key id differs from the current one (the secret was lost and a new
one created) returns to pending with a new token, and says so (token_reset).
"""
import argparse, datetime as dt, hashlib, hmac, ipaddress, json, os, re, stat, subprocess, sys

OWNERSHIP_RULE = "This project should only be run on systems the person running the project explicitly owns."
OWNERSHIP_STATEMENT = "I own this domain and the systems it points to."
# The DNS proof: a TXT record at <VERIFY_LABEL>.<apex> whose value is <VERIFY_PREFIX><token>. Rename here only.
VERIFY_LABEL, VERIFY_PREFIX = "_scan-verify", "scan-verify="
GRACE_DAYS = 7
HELD_BACK_FILE = "held_back.json"
# fixed reason codes for hosts held back from active phases (published in held_back.json)
HELD_NEW, HELD_ADDRESS = "new-since-approved-inventory", "address-changed"
HELD_DOMAIN = "domain-not-in-approved-inventory"   # the host's domain was added to the scope after that inventory
HELD_REASONS = (HELD_NEW, HELD_ADDRESS, HELD_DOMAIN)
NO_PORTSCAN_CNAME_CLASSES = ("cdn_fronted", "third_party")   # classes that never get a port scan
ACTIVE_TAGS = ("default-login", "sqli", "rce", "lfi", "ssrf", "xss", "injection")

_LABEL = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")
# address blocks refused even where ipaddress calls them global
_EXTRA_BLOCKED = [ipaddress.ip_network(n) for n in (
    "100.64.0.0/10",      # carrier-grade NAT
    "169.254.0.0/16",     # link-local, incl. the cloud metadata address 169.254.169.254
    "192.0.0.0/24",       # IETF protocol assignments
    "64:ff9b::/96", "64:ff9b:1::/48",   # NAT64: an embedded IPv4 address reached through a translator
    "2002::/16",          # 6to4: an embedded IPv4 address
    "2001::/32",          # Teredo
    "fd00:ec2::/32",      # cloud metadata over IPv6 (inside fc00::/7 too)
)]


class ScopeError(Exception):
    pass


def now_utc():
    return dt.datetime.now(dt.timezone.utc)


def iso(t):
    return t.astimezone(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_iso(s):
    try:
        return dt.datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def norm_name(host):
    """Lower case, one trailing dot removed; None when not a syntactically valid hostname."""
    if not isinstance(host, str):
        return None
    h = host.strip().lower()
    if h.endswith("."):
        h = h[:-1]
    if not h or len(h) > 253 or ".." in h:
        return None
    labels = h.split(".")
    if len(labels) < 2 or not all(_LABEL.fullmatch(x) for x in labels):
        return None
    if labels[-1].isdigit() or "_" in labels[-1]:   # an address or a nonsense top-level label
        return None
    return h


def parse_ip(ip):
    """ipaddress object (IPv4-mapped IPv6 unwrapped to IPv4) or None."""
    try:
        o = ipaddress.ip_address(str(ip).strip().strip("[]"))
    except ValueError:
        return None
    if o.version == 6 and o.ipv4_mapped is not None:
        return o.ipv4_mapped
    return o


def non_global_reason(o):
    """Why an address may never be scanned, or None when it is globally routable."""
    if o.is_unspecified:
        return "unspecified address"
    if o.is_loopback:
        return "loopback address"
    if o.is_link_local or (o.version == 4 and o in ipaddress.ip_network("169.254.0.0/16")):
        return "link-local address (includes the cloud metadata address)"
    if o.is_multicast:
        return "multicast address"
    if o.version == 6 and o.is_site_local:
        return "IPv6 site-local address"
    if o.version == 6 and o in ipaddress.ip_network("fc00::/7"):
        return "IPv6 unique-local address"
    if o.version == 4 and o in ipaddress.ip_network("100.64.0.0/10"):
        return "carrier-grade NAT address"
    if o.is_private:
        return "private address"
    if o.is_reserved:
        return "reserved address"
    for n in _EXTRA_BLOCKED:
        if o.version == n.version and o in n:
            return f"address in {n} (not directly routable)"
    if not o.is_global:
        return "not a globally routable address"
    return None


def read_list(path):
    out = []
    if not os.path.exists(path):
        return out
    with open(path, errors="ignore") as fh:
        for line in fh:
            s = line.split("#", 1)[0].strip().lower()
            if s:
                out.append(s)
    return out


def private_lab_net(cidr):
    """(network, None) when cidr is an acceptable lab network, else (None, reason)."""
    try:
        n = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return None, f"lab CIDR {cidr!r} is not a network"
    allowed = [ipaddress.ip_network(x) for x in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")]
    if not any(n.version == a.version and n.subnet_of(a) for a in allowed):
        return None, f"lab CIDR {n} is not inside a private range (10/8, 172.16/12, 192.168/16, fc00::/7)"
    if n.num_addresses > 256:
        return None, f"lab CIDR {n} is larger than a /24 (at most 256 addresses)"
    return n, None


class Scope:
    """Loaded scope. lab: None, or {"cidr": "...", "hosts": [...]} (only honoured when SCAN_LAB=1)."""

    def __init__(self, scope_dir, run_dir=None, lab=None, now=None, require_domains=None):
        self.dir, self.run_dir = scope_dir, run_dir
        self.now = now or now_utc()
        if lab is None and run_dir and os.path.exists(os.path.join(run_dir, "lab.json")):
            with open(os.path.join(run_dir, "lab.json")) as fh:
                lab = json.load(fh)
        self.lab_net, self.lab_hosts = None, set()
        if lab:
            if os.environ.get("SCAN_LAB") != "1":
                raise ScopeError("lab mode needs SCAN_LAB=1 in the environment")
            net, why = private_lab_net(lab.get("cidr", ""))
            if net is None:
                raise ScopeError(why)
            self.lab_net = net
            self.lab_hosts = {h for h in (norm_name(x) for x in lab.get("hosts") or []) if h}
        dpath = os.path.join(scope_dir, "domains.txt")
        self.apexes = []
        for d in read_list(dpath):
            n = norm_name(d)
            if not n:
                raise ScopeError(f"{dpath}: {d!r} is not a valid domain name")
            self.apexes.append(n)
        self.apexes = sorted(set(self.apexes), key=len, reverse=True)
        if require_domains is None:
            require_domains = not self.lab_net
        if require_domains and not self.apexes:
            raise ScopeError(f"{dpath} is missing or empty: list the apex domains you own, one per line "
                             "(an empty scope never means 'allow everything')")
        self.ex_names, self.ex_nets = [], []
        for e in read_list(os.path.join(scope_dir, "exclude.txt")):
            o = parse_ip(e)
            if o is not None:
                self.ex_nets.append(ipaddress.ip_network(o))
                continue
            if "/" in e:
                try:
                    self.ex_nets.append(ipaddress.ip_network(e, strict=False))
                except ValueError:
                    raise ScopeError(f"exclude.txt: {e!r} is not a valid CIDR")
                continue
            # a name excludes itself and everything under it; ".suffix" and "*.suffix" mean the same
            n = norm_name(e[2:] if e.startswith("*.") else e.lstrip("."))
            if not n:
                raise ScopeError(f"exclude.txt: {e!r} is not a name, .suffix, *.suffix, address or CIDR")
            self.ex_names.append(n)
        self.owned_nets = []
        for c in read_list(os.path.join(scope_dir, "owned_ranges.txt")):
            try:
                self.owned_nets.append(ipaddress.ip_network(c, strict=False))
            except ValueError:
                raise ScopeError(f"owned_ranges.txt: {c!r} is not a CIDR")
        self.approved_hosts = {h for h in (norm_name(x) for x in read_list(os.path.join(scope_dir, "approved_hosts.txt"))) if h}
        self.ownership = load_ownership(scope_dir)
        # hosts held back from active phases this run (written by approve.py hold-back after phase 5); every gate
        # from then on refuses them
        self.held, self.held_domains = {}, set()
        hp = os.path.join(run_dir, HELD_BACK_FILE) if run_dir else None
        if hp and os.path.exists(hp):
            try:
                with open(hp) as fh:
                    hd = json.load(fh)
                self.held = {norm_name(h): r for h, r in (hd.get("hosts") or {}).items() if norm_name(h)}
                # domains of the scope the approved inventory did not cover: every name under them is held back
                self.held_domains = {norm_name(d) for d in ((hd.get("domains") or {}).get("held_back") or []) if norm_name(d)}
            except (OSError, ValueError, AttributeError, TypeError):
                raise ScopeError(f"{hp}: unreadable; refusing to guess which hosts are held back")

    # ---- names
    def apex_of(self, h):
        for ax in self.apexes:
            if h == ax or h.endswith("." + ax):
                return ax
        return None

    def name_excluded(self, h):
        for e in self.ex_names:
            if h == e or h.endswith("." + e):
                return e
        return None

    def name_allowed(self, host):
        h = norm_name(host)
        if not h:
            return False, f"not a valid hostname: {str(host)[:80]!r}"
        e = self.name_excluded(h)
        if e:
            return False, f"excluded by exclude.txt ({e})"
        if h in self.held:
            return False, f"held back from active phases ({self.held[h]}): awaiting approval of a newer inventory"
        if self.held_domains and self.apex_of(h) in self.held_domains:
            return False, f"held back from active phases ({HELD_DOMAIN}): awaiting approval of a newer inventory"
        if self.lab_net is not None and h in self.lab_hosts:
            return True, "lab target (no DNS proof needed in lab mode)"
        ax = self.apex_of(h)
        if ax is None:
            return False, "not under any apex in domains.txt"
        ent = self.ownership.get(ax)
        if not ent:
            return False, (f"no ownership statement for {ax} in ownership.json; add one with: "
                           f"approve.py attest {ax} --by 'Your Name'")
        if ent.get("state") != "verified":
            return False, (f"{ax} is not DNS-verified (state {ent.get('state') or 'none'}); publish the TXT record "
                           f"{VERIFY_LABEL}.{ax} shown in scope_status.json (a scope-sync job) or by approve.py attest, "
                           f"then run a scope-sync job or approve.py verify {ax}")
        return True, f"under verified apex {ax}"

    # ---- addresses
    def ip_excluded(self, o):
        for n in self.ex_nets:
            if o.version == n.version and o in n:
                return n
        return None

    def ip_allowed(self, ip, host=None):
        o = parse_ip(ip)
        if o is None:
            return False, f"not an IP address: {str(ip)[:60]!r}"
        n = self.ip_excluded(o)
        if n is not None:
            return False, f"excluded by exclude.txt ({n})"
        if self.lab_net is not None:
            h = norm_name(host) if host else None
            inside = o.version == self.lab_net.version and o in self.lab_net
            if inside and h and h in self.lab_hosts:
                return True, "inside the lab CIDR, for a lab target"
            if inside:
                return False, "inside the lab CIDR but not for a name in the lab targets file"
            if h and h in self.lab_hosts:
                # lab names carry no DNS proof, so they may only ever reach the lab network
                return False, f"lab target outside the lab CIDR {self.lab_net}"
        why = non_global_reason(o)
        if why:
            return False, why
        return True, "globally routable"

    def chain_excluded(self, chain):
        """The first name in a CNAME chain that an exclusion covers, or None."""
        for c in chain or ():
            n = norm_name(c)
            if n:
                e = self.name_excluded(n)
                if e:
                    return n, e
        return None

    def chain_refusal(self, chain):
        """The refusal text for a CNAME chain that reaches an excluded name, or None (one wording for every gate)."""
        hit = self.chain_excluded(chain)
        return f"CNAME chain reaches {hit[0]}, excluded by exclude.txt ({hit[1]})" if hit else None

    def cname_allowed(self, host, lookup=None):
        """(ok, why) for gates outside recon, which has no dnsx answers to read (version watch): look host's CNAME
        chain up (cname_lookup) and refuse it when any name in it is excluded, as filter_items does for recon. A
        lookup that gets no answer refuses too: an unchecked chain is never probed."""
        try:
            chain = (lookup or cname_lookup)(host)
        except OSError as e:
            return False, f"CNAME chain could not be looked up ({e}); not probed"
        why = self.chain_refusal(chain)
        return (False, why) if why else (True, "no excluded name in the CNAME chain")

    def ips_allowed(self, host, ips):
        if not ips:
            return False, "no addresses"
        for ip in ips:
            ok, why = self.ip_allowed(ip, host)
            if not ok:
                return False, f"{ip}: {why}"
        return True, "every address allowed"

    def portscan_allowed(self, host, ips):
        ok, why = self.name_allowed(host)
        if not ok:
            return False, why
        ok, why = self.ips_allowed(host, ips)
        if not ok:
            return False, why
        if norm_name(host) in self.approved_hosts:
            return True, "host in approved_hosts.txt"
        for ip in ips:
            o = parse_ip(ip)
            if not any(o.version == n.version and o in n for n in self.owned_nets):
                return False, f"{ip} is not in owned_ranges.txt and the host is not in approved_hosts.txt"
        return True, "every address in owned_ranges.txt"

    # ---- logging
    def reject(self, what, stage, reason):
        if not self.run_dir:
            return
        with open(os.path.join(self.run_dir, "scope_rejected.jsonl"), "a") as f:
            f.write(json.dumps({"at": iso(now_utc()), "stage": stage, "what": str(what)[:300], "reason": reason}) + "\n")


# ---------------------------------------------------------------- ownership and DNS proof
def ownership_path(scope_dir):
    return os.path.join(scope_dir, "ownership.json")


def load_ownership(scope_dir):
    p = ownership_path(scope_dir)
    if not os.path.exists(p):
        return {}
    try:
        with open(p) as fh:
            data = json.load(fh)
    except (OSError, ValueError) as e:
        raise ScopeError(f"{p}: unreadable ({e})")
    entries = data.get("entries", []) if isinstance(data, dict) else data
    out = {}
    for ent in entries:
        ax = norm_name(ent.get("apex", "")) if isinstance(ent, dict) else None
        if not ax or ent.get("statement") != OWNERSHIP_STATEMENT or not ent.get("attested_by") or not ent.get("attested_at"):
            raise ScopeError(f"{p}: malformed entry {str(ent)[:120]}")
        out[ax] = ent
    return out


def save_ownership(scope_dir, entries):
    p = ownership_path(scope_dir)
    tmp = p + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"entries": [entries[k] for k in sorted(entries)]}, f, indent=1)
        f.write("\n")
    os.replace(tmp, p)


def record_for(apex, token):
    return f"{VERIFY_LABEL}.{apex}", f"{VERIFY_PREFIX}{token}"


# ---------------------------------------------------------------- the install secret and derived tokens
SECRET_FILE = "install_secret"
TOKEN_RESET_SECRET = "install-secret-replaced"   # fixed reason code: the entry was checked under an earlier secret


def default_state_dir(scope_dir=None):
    root = os.environ.get("SCAN_ROOT")
    if root:
        return os.path.join(root, "state")
    if scope_dir:   # <root>/scope (a link into scope.d) -> <root>/state; the link itself is not resolved
        return os.path.join(os.path.dirname(os.path.abspath(scope_dir)), "state")
    return os.path.join("/var/lib/scan", "state")


def load_secret(state_dir, create=False):
    """(secret bytes, created) from <state_dir>/install_secret. The folder is 0700 and the file 0600, owned by the
    scanner user; neither is ever under the published folder. create=True makes a new 32-byte secret when the file
    is missing (O_EXCL, never following a link). Raises ScopeError when it is missing and create is False, or when
    it is not a regular file of the right size."""
    if create:
        os.makedirs(state_dir, mode=0o700, exist_ok=True)
        os.chmod(state_dir, 0o700)
    p = os.path.join(state_dir, SECRET_FILE)
    created = False
    try:
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0))
    except FileNotFoundError:
        if not create:
            raise ScopeError(f"install secret {p} missing: start the scanner's job runner once (it creates it)")
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, os.urandom(32).hex().encode() + b"\n")
            os.fsync(fd)
        finally:
            os.close(fd)
        created = True
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as e:
        raise ScopeError(f"install secret {p} unreadable ({e.strerror})")
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > 200:
            raise ScopeError(f"install secret {p} is not a small regular file")
        if st.st_mode & 0o077:
            os.fchmod(fd, 0o600)    # owner-only, whatever happened to it
        raw = os.read(fd, 201).strip()
    finally:
        os.close(fd)
    if not re.fullmatch(rb"[0-9a-f]{64}", raw):
        raise ScopeError(f"install secret {p} is malformed")
    return bytes.fromhex(raw.decode()), created


def derive_token(secret, domain):
    """The DNS proof token for domain on this install: HMAC-SHA-256(secret, domain), 32 hex characters."""
    return hmac.new(secret, b"momus-dns-proof-v1\n" + domain.encode(), hashlib.sha256).hexdigest()[:32]


def key_id(secret):
    """A public fingerprint of the install secret (it reveals nothing about the secret or any token)."""
    return hmac.new(secret, b"momus-key-id-v1", hashlib.sha256).hexdigest()[:16]


def reconcile_key(ent, kid):
    """An entry checked under another install secret (or before secrets existed) returns to pending: its token
    changed. Returns True when the entry was reset."""
    if ent.get("key_id") == kid:
        return False
    had = bool(ent.get("key_id") or ent.get("state") in ("verified", "lapsed", "refused") or ent.get("token"))
    ent.pop("token", None)   # tokens are derived, never stored
    for k in ("verified_at", "last_checked_at", "last_result"):
        ent.pop(k, None)
    ent["state"] = "pending"
    ent["key_id"] = kid
    if had:
        ent["token_reset"] = TOKEN_RESET_SECRET
    return had


def check_proof(apex, token, answers, ip_check):
    """Decide one apex from the nameserver answers.
    answers: [(ns_name, ns_ip, txts)] where txts is a list of TXT strings, or None when that server gave no answer.
    Returns (outcome, detail): outcome is match | mismatch | disagree | unsafe | failure."""
    if not answers:
        return "failure", "no nameserver found"
    for ns, ip, _ in answers:
        ok, why = ip_check(ip)
        if not ok:
            return "unsafe", f"nameserver {ns} at {ip} refused: {why}"
    want = (VERIFY_PREFIX + token).encode()
    results = []
    for ns, ip, txts in answers:
        if txts is None:
            continue
        hit = False
        for t in txts:
            if hmac.compare_digest(t.strip().encode(), want):
                hit = True
        results.append((ns, ip, hit))
    if not results:
        return "failure", "no nameserver answered"
    hits = {h for _, _, h in results}
    if len(hits) > 1:
        return "disagree", "nameservers disagree: " + ", ".join(f"{ns}({ip})={'match' if h else 'no match'}" for ns, ip, h in results)
    if hits == {True}:
        return "match", f"{len(results)} nameserver(s) agree"
    return "mismatch", f"record missing or wrong at {len(results)} nameserver(s)"


def apply_proof(ent, outcome, detail, now, token):
    """Update one ownership entry from check_proof's outcome. Returns (usable, log line)."""
    ax = ent["apex"]
    ent["last_checked_at"] = iso(now)
    ent["last_result"] = outcome
    if outcome == "match":
        ent["state"], ent["verified_at"] = "verified", iso(now)
        ent.pop("token_reset", None)
        return True, f"dns proof {ax}: verified ({detail})"
    if outcome in ("mismatch", "disagree"):
        ent["state"] = "pending"
        name, value = record_for(ax, token)
        return False, f"dns proof {ax}: REFUSED, {detail}; state set to pending. Publish TXT {name} = \"{value}\""
    if outcome == "unsafe":
        ent["state"] = "refused"
        return False, f"dns proof {ax}: REFUSED, {detail}; state set to refused (fix the nameserver, then approve.py verify {ax})"
    # failure: a recent verification still counts
    last = parse_iso(ent.get("verified_at"))
    if ent.get("state") == "verified" and last and now - last <= dt.timedelta(days=GRACE_DAYS):
        return True, f"dns proof {ax}: lookup failed ({detail}); last verified {ent['verified_at']}, within {GRACE_DAYS} days, so it still counts"
    if ent.get("state") == "verified":
        ent["state"] = "lapsed"
    return False, f"dns proof {ax}: REFUSED, lookup failed ({detail}) and no verification within {GRACE_DAYS} days"


def _dig(args, timeout=20):
    try:
        p = subprocess.run(["dig"] + args, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout
    except (OSError, subprocess.TimeoutExpired):
        return 1, ""


def cname_lookup(name):
    """The CNAME names the system resolver follows from name, in order (every step of the chain, as one A query
    answers it). [] when name has no CNAME or does not exist. Raises OSError when the resolver gives no usable
    answer, so a caller can refuse instead of treating an unknown chain as empty."""
    rc, out = _dig(["+noall", "+answer", "+comments", "+timeout=5", "+tries=2", name, "A"])
    if rc != 0:
        raise OSError("no answer from the resolver")
    m = re.search(r"status: (\w+)", out)
    if not m or m.group(1) not in ("NOERROR", "NXDOMAIN"):
        raise OSError(f"resolver status {m.group(1) if m else 'missing'}")
    chain = []
    for line in out.splitlines():
        f = line.split()
        if line.startswith(";") or len(f) < 5 or f[3].upper() != "CNAME":
            continue
        t = norm_name(f[4])
        if t and t not in chain:
            chain.append(t)
    return chain


def nameserver_names(out):
    """The host names in dig's +short NS output, normalized; anything that is not a valid host name is dropped, so
    a name such as "-x" or "+y" from a hostile answer can never reach dig as an option."""
    return sorted({n for n in (norm_name(x) for x in out.split()) if n})


def ns_addresses(ns):
    """The A and AAAA addresses of one nameserver name (system resolver). The name goes after -q, so dig reads it as
    the query name whatever it starts with."""
    ips = []
    for rr in ("A", "AAAA"):
        _, out = _dig(["+short", "+timeout=5", "+tries=2", "-t", rr, "-q", ns])
        ips += [x.strip() for x in out.split() if parse_ip(x.strip()) is not None]
    return sorted(set(ips))


def zone_nameservers(name):
    """NS names of the zone that holds name: walk up from name until a NS answer appears (system resolver)."""
    labels = name.split(".")
    for i in range(len(labels) - 1):
        z = ".".join(labels[i:])
        rc, out = _dig(["+short", "+timeout=5", "+tries=2", "NS", z])
        ns = nameserver_names(out)
        if rc == 0 and ns:
            return z, ns
    return None, []


def dig_lookup(apex):
    """[(ns_name, ns_ip, txts or None)] for the proof record, asked of the zone's own authoritative servers
    directly (+norecurse) so a local resolver or cache cannot supply the answer."""
    _, ns_names = zone_nameservers(apex)
    name, _ = record_for(apex, "")
    answers = []
    for ns in ns_names:
        for ip in ns_addresses(ns):
            answers.append((ns, ip, None))
    return answers, name


def query_txt(ip, name):
    """TXT strings at name from server ip (no recursion); None when the server does not answer usefully."""
    rc, out = _dig(["+norecurse", "+timeout=5", "+tries=1", "+noall", "+answer", "+comments", "@" + ip, name, "TXT"])
    if rc != 0:
        return None
    m = re.search(r"status: (\w+)", out)
    if not m or m.group(1) not in ("NOERROR", "NXDOMAIN"):
        return None
    txts = []
    for line in out.splitlines():
        if line.startswith(";") or "\tTXT\t" not in line.replace(" ", "\t"):
            continue
        txts.append("".join(re.findall(r'"((?:[^"\\]|\\.)*)"', line)))
    return txts


def real_lookup(apex, ip_check):
    """The default lookup: find the nameservers, refuse any on a non-routable address before asking it."""
    answers, name = dig_lookup(apex)
    out = []
    for ns, ip, _ in answers:
        ok, _ = ip_check(ip)
        out.append((ns, ip, query_txt(ip, name) if ok else None))
    return out


def strict_ip_check(ip):
    """ip_allowed with no scope: globally routable only (nameservers are never lab targets)."""
    o = parse_ip(ip)
    if o is None:
        return False, "not an IP address"
    why = non_global_reason(o)
    return (False, why) if why else (True, "globally routable")


def nameservers_ok(apex, lookup=None, ip_check=strict_ip_check):
    """(ok, reason): every address of every nameserver of the apex's zone passes the address check the DNS proof
    uses. Asked again at the point of use (dnsrecon talks to these servers itself), so an address that changed
    since the proof is caught. No nameserver address found is not ok: nothing could be checked."""
    try:
        answers, _ = (lookup or dig_lookup)(apex)
    except Exception as e:  # a lookup bug is a refusal, never a pass
        return False, f"nameserver lookup error {type(e).__name__}"
    if not answers:
        return False, "no nameserver address found"
    for ns, ip, _ in answers:
        ok, why = ip_check(ip)
        if not ok:
            return False, f"nameserver {ns} at {ip} refused: {why}"
    return True, f"{len(answers)} nameserver address(es) pass"


def verify_apexes(scope_dir, apexes, lookup=None, now=None, log=print, secret=None, state_dir=None):
    """Re-check the DNS proof of each apex and save ownership.json. Returns the usable apexes. The token each apex
    must publish is derived here from the install secret (secret, else read from state_dir); a token stored
    anywhere else is never used. Without the secret nothing is usable."""
    now = now or now_utc()
    entries = load_ownership(scope_dir)
    if secret is None:
        try:
            secret, _ = load_secret(state_dir or default_state_dir(scope_dir))
        except ScopeError as e:
            log(f"dns proof: REFUSED for every apex, {e}")
            secret = None
    usable = []
    kid = key_id(secret) if secret is not None else None
    for ax in apexes:
        ent = entries.get(ax)
        if not ent:
            log(f"dns proof {ax}: REFUSED, no ownership statement; add one with: approve.py attest {ax} --by 'Your Name'")
            continue
        if kid is None:
            ent["state"] = "pending"
            continue
        if reconcile_key(ent, kid):
            log(f"dns proof {ax}: the install secret was replaced since this domain was last checked; it is pending "
                "with a new token (publish the new TXT record shown in scope_status.json)")
        token = derive_token(secret, ax)
        try:
            answers = (lookup or (lambda a: real_lookup(a, strict_ip_check)))(ax)
        except Exception as e:  # a lookup bug is a lookup failure, never a pass
            answers = []
            log(f"dns proof {ax}: lookup error {type(e).__name__}")
        outcome, detail = check_proof(ax, token, answers, strict_ip_check)
        ok, line = apply_proof(ent, outcome, detail, now, token)
        log(line)
        if ok:
            usable.append(ax)
    for ax in apexes:   # invariant: an apex refused this run is never left "verified" on disk
        if ax in entries and ax not in usable and entries[ax].get("state") == "verified":
            entries[ax]["state"] = "pending"
    save_ownership(scope_dir, entries)
    return usable


# ---------------------------------------------------------------- filters for recon.sh
def dns_records(run_dir):
    """(host -> addresses, host -> CNAME chain) from this run's dns.jsonl (the gated resolver's answers). The chain
    is every name dnsx reported in the record's "cname" field, in order; each one is checked against the
    exclusions (an allowed alias of an excluded server is refused)."""
    addrs, chains = {}, {}
    p = os.path.join(run_dir, "dns.jsonl")
    if not os.path.exists(p):
        return addrs, chains
    with open(p, errors="ignore") as fh:
        lines = fh.readlines()
    for line in lines:
        try:
            d = json.loads(line)
        except ValueError:
            continue
        if not isinstance(d, dict):
            continue
        h = norm_name(d.get("host", ""))
        if h:
            addrs.setdefault(h, set()).update(x for x in (d.get("a") or []) + (d.get("aaaa") or []) if isinstance(x, str))
            cn = d.get("cname") or []
            if isinstance(cn, str):
                cn = [cn]
            ch = chains.setdefault(h, [])
            for c in cn:
                if isinstance(c, str) and c not in ch:
                    ch.append(c)
    return addrs, chains


def dns_map(run_dir):
    """host -> addresses from this run's dns.jsonl (the gated resolver's answers)."""
    return dns_records(run_dir)[0]


def suffix_of(cnames, suffix):
    """True when one of cnames is suffix or a name under it."""
    sfx = (suffix or "").lower().rstrip(".")
    return bool(sfx) and any(isinstance(c, str) and (c.lower().rstrip(".") == sfx or c.lower().rstrip(".").endswith("." + sfx))
                             for c in cnames or ())


def compute_held_back(inv_hosts, assets, owned_nets, provider_nets, held_domains=(), apex_of=None):
    """{host: reason code} for live hosts of this run that may not reach active phases:
      HELD_DOMAIN   its domain (apex_of(host)) is in held_domains: the approved inventory did not cover it;
      HELD_NEW      absent from the approved inventory;
      HELD_ADDRESS  an address the approved inventory did not list for it that is in neither the owned ranges nor the
                    provider ranges. Not applied to a host the inventory classed cdn_fronted or third_party by its
                    CNAME target ("via_cname") that is still in one of those classes with a CNAME under the same
                    provider suffix: edge addresses rotate, and those classes never get a port scan.
    inv_hosts: {host: {"ips": [...], "class": ..., "via_cname": suffix (optional)}}; assets: assets.jsonl records
    ({"hostname", "ips", "class", "cnames"})."""
    out = {}
    held_domains = set(held_domains or ())
    for a in assets:
        h = norm_name(a.get("hostname", ""))
        if not h or a.get("class") not in ("owned", "cdn_fronted", "third_party", "unverified"):
            continue
        if held_domains and apex_of and apex_of(h) in held_domains:
            out[h] = HELD_DOMAIN
            continue
        rec = inv_hosts.get(h)
        if rec is None:
            out[h] = HELD_NEW
            continue
        if (rec.get("class") in NO_PORTSCAN_CNAME_CLASSES and rec.get("via_cname")
                and a.get("class") in NO_PORTSCAN_CNAME_CLASSES and suffix_of(a.get("cnames"), rec["via_cname"])):
            continue
        known = {str(parse_ip(x)) for x in rec.get("ips", []) if parse_ip(x) is not None}
        for ip in a.get("ips") or []:
            o = parse_ip(ip)
            if o is None or str(o) in known:
                continue
            if not any(o.version == n.version and o in n for n in list(owned_nets) + list(provider_nets)):
                out[h] = HELD_ADDRESS
                break
    return out


def host_of(item, kind):
    if kind == "urls":
        m = re.fullmatch(r"https?://([^/:?#\s]+)(?::\d+)?(?:[/?#].*)?", item, re.I)
        return m.group(1) if m else None
    if kind == "hostports":
        return item.rsplit(":", 1)[0] if ":" in item else item
    return item


def filter_items(sc, items, kind, stage, dmap=None, chains=None):
    """(allowed items, {host: [addresses]} of the allowed ones). Every rejection is logged. chains: host -> CNAME
    chain; a host whose chain contains an excluded name is refused like the excluded name itself."""
    keep, hosts = [], {}
    chains = chains or {}

    def chain_ok(h):
        why = sc.chain_refusal(chains.get(norm_name(h) or "", []))
        return (False, why) if why else (True, "")
    if kind == "portscan":
        owners = {}
        for h, ips in (dmap or {}).items():
            for ip in ips:
                owners.setdefault(str(parse_ip(ip) or ip), []).append(h)
    for it in items:
        it = it.strip()
        if not it:
            continue
        if kind in ("ips", "portscan"):
            ok, why = sc.ip_allowed(it)
            if ok and kind == "portscan":
                ok, why = False, "no approved host on this address"
                names_here = owners.get(str(parse_ip(it) or it), [])
                for h in names_here:
                    cok, cwhy = chain_ok(h)
                    if not cok:   # an alias of an excluded server: the address is never scanned for it
                        ok, why = False, f"{h}: {cwhy}"
                        break
                    pok, pwhy = sc.portscan_allowed(h, sorted(dmap[h]))
                    if pok:
                        ok, why = True, pwhy
                    else:
                        why = f"{h}: {pwhy}"
                if ok:   # coverage: every name on a scanned address that the gate allows (ingest keys a port
                    # finding to one of them); a held-back or excluded name was not looked at
                    for h in names_here:
                        if sc.name_allowed(h)[0]:
                            hosts.setdefault(h, sorted(dmap[h]))
            if ok:
                keep.append(it)
            else:
                sc.reject(it, stage, why)
            continue
        h = host_of(it, kind)
        ok, why = sc.name_allowed(h) if h else (False, "no host in item")
        if ok and kind in ("hosts", "urls", "hostports"):
            ok, why = chain_ok(h)
        if ok and kind in ("hosts", "urls", "hostports"):
            ips = sorted((dmap or {}).get(norm_name(h), []))
            ok, why = sc.ips_allowed(h, ips) if ips else (False, "not resolved by this run's gated resolver")
            if ok:
                hosts[norm_name(h)] = ips
        elif ok:
            hosts[norm_name(h)] = []
        if ok:
            keep.append(it)
        else:
            sc.reject(it, stage, why)
    return keep, hosts


def main(argv=None):
    ap = argparse.ArgumentParser(description="scope checks for recon.sh")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check"); c.add_argument("--scope", required=True); c.add_argument("--run-dir")
    r = sub.add_parser("recheck-dns"); r.add_argument("--scope", required=True); r.add_argument("--run-dir", required=True)
    r.add_argument("--state", help="the install secret's folder (default $SCAN_ROOT/state)")
    sy = sub.add_parser("sync"); sy.add_argument("--scope", required=True); sy.add_argument("--state")
    f = sub.add_parser("filter")
    for k in ("--scope", "--run-dir", "--stage", "--kind", "--in", "--out"):
        f.add_argument(k, required=True)
    f.add_argument("--cover", help="append the hosts handed on to <run dir>/coverage/<SOURCE>.txt")
    lc = sub.add_parser("lab-check"); lc.add_argument("--cidr", required=True)
    nc = sub.add_parser("ns-check")
    for k in ("--scope", "--run-dir", "--stage"):
        nc.add_argument(k, required=True)
    nc.add_argument("apexes", nargs="*")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "lab-check":
            if os.environ.get("SCAN_LAB") != "1":
                raise ScopeError("lab mode refused: set SCAN_LAB=1 in the environment to use --targets-file/--lab-cidr")
            net, why = private_lab_net(a.cidr)
            if net is None:
                raise ScopeError("lab mode refused: " + why)
            print(net)
            return 0
        sc = Scope(a.scope, getattr(a, "run_dir", None))
        if a.cmd == "check":
            for ax in sorted(sc.apexes):
                print(ax)
            return 0
        if a.cmd == "sync":
            # scope-sync: the DNS proof check of every domain in the scope, nothing else (dig is the only tool)
            usable = verify_apexes(a.scope, sorted(sc.apexes), log=lambda s: print(s, file=sys.stderr),
                                   state_dir=a.state or default_state_dir(a.scope))
            for ax in usable:
                print(ax)
            return 0
        if a.cmd == "recheck-dns":
            usable = verify_apexes(a.scope, sorted(sc.apexes), log=lambda s: print(s, file=sys.stderr),
                                   state_dir=a.state or default_state_dir(a.scope))
            with open(os.path.join(a.run_dir, "dns_verification.json"), "w") as fh:
                json.dump({"checked": sorted(sc.apexes), "usable": usable, "at": iso(now_utc())}, fh, indent=1)
            for ax in sorted(sc.apexes):
                if ax not in usable:
                    sc.reject(ax, "dns-proof", "apex refused by the DNS proof check (see recon.log)")
            for ax in usable:
                print(ax)
            return 0
        if a.cmd == "ns-check":
            for ax in a.apexes:
                ok, why = sc.name_allowed(ax)
                if ok:
                    ok, why = nameservers_ok(ax)
                if ok:
                    print(ax)
                else:
                    sc.reject(ax, a.stage, why)
                    print(f"scope gate {a.stage}: {ax} skipped, {why}", file=sys.stderr)
            return 0
        if a.cmd == "filter":
            if a.kind not in ("names", "hosts", "urls", "hostports", "ips", "portscan"):
                raise ScopeError(f"unknown kind {a.kind}")
            items = []
            if os.path.exists(a.__dict__["in"]):
                with open(a.__dict__["in"], errors="ignore") as fh:
                    items = fh.read().splitlines()
            dmap, chains = dns_records(a.run_dir) if a.kind in ("hosts", "urls", "hostports", "portscan") else (None, None)
            keep, hosts = filter_items(sc, items, a.kind, a.stage, dmap, chains)
            with open(a.out, "w") as fh:
                fh.write("".join(x + "\n" for x in keep))
            if a.cover:
                os.makedirs(os.path.join(a.run_dir, "coverage"), exist_ok=True)
                with open(os.path.join(a.run_dir, "coverage", a.cover + ".txt"), "a") as fh:
                    fh.write("".join(h + "\n" for h in sorted(hosts)))
            print(f"scope gate {a.stage}: {len(keep)} allowed, {len([x for x in items if x.strip()]) - len(keep)} rejected", file=sys.stderr)
            return 0
    except ScopeError as e:
        print(f"scope error: {e}", file=sys.stderr)
        return 2
    return 1


if __name__ == "__main__":
    sys.exit(main())
