#!/usr/bin/env python3
"""seed_dns.py - the seeder: host names straight from the DNS sources you control, for DNS-verified domains only.

Runs in its own optional container (Compose profile "seed"), never in the scanner: DNS sources often sit on private
addresses and need credentials, and the scanner must have neither. It reads which domains are DNS-verified from the
scanner's list <scope>/verified_domains.json (/srv/seed-scope, a small volume of its own, read-only here; it never
mounts the scanner's published folder), reads the configured sources, and writes:

  <out>/seed_hosts.txt   host names only, one per line, sorted (no addresses, no record values, no source details)
  <out>/status.json      time, names per source, fixed-text error codes (schema momus-seed-status-v1)

The scanner reads seed_hosts.txt from its read-only mount of the same volume as untrusted input and passes every
name through its own name gate (scanner/pipeline/seed_input.py). The seeder contacts only the DNS services you
configure. A transfer server is usually the zone's own name server, which can be a host in scope, and the scanner's
firewall and exclusions do not apply to the seeder. Nothing taken from an answer is ever contacted.

Sources, each off unless configured (environment variables, normally from seed.env; see .env.example):
  route53     SEED_ROUTE53=1: public hosted zones under a verified domain, through the default AWS credential chain
              (environment, a credentials file given as a Docker secret, container or instance role); optionally
              one role to assume first, SEED_ROUTE53_ROLE_ARN. No profile, no config file, no credential cache.
  zonefiles   SEED_ZONE_FILES=1: zone files or plain host lists in the read-only folder <zones> (/srv/seed-zones).
  axfr        SEED_AXFR="zone@address ...": zone transfers from servers given as IP addresses. A server is never
              looked up by name.
  pdns        SEED_PDNS_URL, SEED_PDNS_ZONES, optional SEED_PDNS_SERVER (default localhost): the PowerDNS HTTP API,
              with the key read from SEED_PDNS_API_KEY_FILE (default /run/secrets/momus_seed_pdns_api_key).
  SEED_INTERVAL_MINUTES: 0 or unset runs once and exits; 15 to 10080 runs again after that many minutes.

Logs and status.json hold fixed text, counts and error codes only: never a credential, an exception message, a
record value or other text taken from a DNS answer. boto3 is imported only when the Route 53 source is on.

No input stops the seeder: a name that cannot be decoded is not a host name; an answer of the wrong
shape is a fixed error code; any exception inside one source becomes "<source>-internal-error", that source adds no
names in that run, and the other sources are still collected and written. status.json is rewritten on every run and
lists the sources that failed; seed_hosts.txt holds the names of the sources that succeeded (when no source found a
name, the earlier file is kept and the status says "kept-previous"). In interval mode a failed run is one fixed log
line and the next run starts on time. Each source may add names only under the zone it was asked for (a transfer,
a PowerDNS zone, a Route 53 hosted zone) and at most its equal share of MAX_NAMES (MAX_NAMES divided by the number of
enabled sources); a transfer that ends in an error adds nothing.

At start-up the endpoint, proxy, CA-bundle and plugin variables the AWS SDK would read are removed from the
environment (names logged, never values; scrub_environment), and every AWS client gets its endpoint, no proxy and the
CA bundle that ships with the pinned botocore explicitly. The AWS credential variables and files are kept: the
default credential chain is how the seeder gets credentials. Only the standard AWS partition is supported.
"""
from __future__ import annotations

import argparse
import datetime as dt
import http.client
import ipaddress
import json
import os
import re
import secrets
import signal
import socket
import stat
import struct
import sys
import threading
import time
import urllib.error
import urllib.request

SCHEMA_STATUS = "momus-seed-status-v1"
VERIFIED_SCHEMA = "momus-verified-domains-v1"   # scanner/runner.py SEED_SCOPE_SCHEMA
VERIFIED_FILE = "verified_domains.json"            # scanner/runner.py SEED_SCOPE_FILE
DEFAULT_SCOPE = "/srv/seed-scope"
DEFAULT_OUT = "/srv/seed"
DEFAULT_ZONES = "/srv/seed-zones"
DEFAULT_PDNS_KEY_FILE = "/run/secrets/momus_seed_pdns_api_key"
OUT_FILE = "seed_hosts.txt"
STATUS_FILE = "status.json"
SOURCES = ("route53", "zonefiles", "axfr", "pdns")

MAX_NAMES = 50000                 # names written; the scanner reads at most this many lines (seed_input.py); each
                                  # enabled source may use at most its equal share of it
MAX_VERIFIED_BYTES = 1 << 20
MAX_NAME_CHARS = 1024             # a name in text form longer than this is not a host name (253 characters, escaped)
MAX_ZONE_FILE_BYTES = 16 << 20    # bounded memory while the file is parsed
MAX_ZONE_LINE_CHARS = 1 << 16     # one zone-file line, or one record joined across lines by parentheses
ZONE_FILES_DEADLINE_S = 300       # the whole zone-file source
MAX_ZONE_FILES = 1000
MAX_AXFR_BYTES = 64 << 20
MAX_PDNS_BYTES = 8 << 20          # json.loads needs many times the bytes
MAX_ERRORS = 20
AXFR_TIMEOUT_S = 10               # each connect and read
AXFR_DEADLINE_S = 300             # a whole transfer
AXFR_SOURCE_DEADLINE_S = 900      # every transfer of a run together
PDNS_TIMEOUT_S = 60               # each connect and read
PDNS_DEADLINE_S = 300             # one whole PowerDNS request: status line, headers, chunk sizes, body
PDNS_SOURCE_DEADLINE_S = 900      # every PowerDNS request of a run together

# The host name rule (the scanner's own, scanner/recon.sh): lower-case letters, digits and hyphens, at least two
# labels, no label starting or ending with a hyphen. Every pattern in this module is applied with fullmatch.
HOST_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+")
# The pattern accepts any partition (arn:aws:, arn:aws-cn:, arn:aws-us-gov:, ...), but only the standard partition
# (arn:aws:) is supported: the STS and Route 53 endpoints the seeder uses are the standard partition's.
ROLE_ARN_RE = re.compile(r"arn:aws(?:-[a-z]+)*:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}")
REGION_RE = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]{1,2}")
PDNS_URL_RE = re.compile(r"https?://(?:[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?|\[[0-9A-Fa-f:.]{2,45}\])"
                         r"(?::[0-9]{1,5})?(?:/[A-Za-z0-9._~/-]{0,200})?")
PDNS_SERVER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
PDNS_KEY_RE = re.compile(r"[\x21-\x7e]{1,1024}")
INTERVAL_RE = re.compile(r"0|[1-9][0-9]{1,4}")
SWITCH_RE = re.compile(r"[01]")
ZONE_FILE_NAME_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]{0,127}")
AXFR_ENTRY_RE = re.compile(r"([^@\s]{1,253})@([0-9A-Fa-f:.]{2,45})")


class ConfigError(Exception):
    """A setting is invalid. The message names the variable, never its value."""


# ---------------------------------------------------------------------------------------------------------- helpers
def log(msg: str) -> None:
    print(f"seeder: {msg}", file=sys.stderr, flush=True)


PDNS_CLEARTEXT_LINE = ("warning: SEED_PDNS_URL is http:// to a host that is not loopback, so the PowerDNS API key "
                       "crosses the network in clear text; use https:// unless that network is private and trusted")


def quiet_libraries() -> None:
    """The log holds the seeder's own fixed lines only: no library log record (botocore, urllib3), no Python warning,
    and no traceback from an exception nothing caught (main thread or another thread), any of which could carry a
    credential, an exception message or answer text."""
    import logging  # noqa: PLC0415
    import warnings  # noqa: PLC0415
    logging.disable(logging.CRITICAL)
    logging.raiseExceptions = False
    warnings.simplefilter("ignore")
    sys.excepthook = lambda *_: log("stopped (internal error)")
    threading.excepthook = lambda *_: log("a background task failed (internal error)")


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def split_list(val: str | None) -> list[str]:
    return [x for x in re.split(r"[\s,]+", (val or "").strip()) if x]


def decode_dns_name(name, form: str = "text") -> str | None:
    """A name with its escapes undone, lower-cased, without the trailing dot; None when it is not valid for its form
    (then it is not a host name). Never raises. form "text": RFC 1035 text form, as zone files, transfer answers and
    the PowerDNS API use it: \\DDD is a decimal byte value (0 to 255) and \\X any other character X. form "route53":
    Route 53 writes \\NNN with three octal digits and nothing else. An escaped dot is inside a label, so the name is
    not a host name either. Nothing is repaired after decoding: no trimming (outer whitespace makes it
    not a host name), only ASCII letters are lower-cased (a Kelvin sign stays what it is), and only one final dot is
    removed."""
    if not isinstance(name, str) or len(name) > MAX_NAME_CHARS:
        return None
    if "\\" in name:
        out, i, n = [], 0, len(name)
        while i < n:
            c = name[i]
            if c != "\\":
                out.append(c)
                i += 1
                continue
            d = name[i + 1:i + 4]
            if form == "route53":
                if len(d) != 3 or any(x not in "01234567" for x in d):
                    return None
                v, i = int(d, 8), i + 4
            elif len(d) == 3 and all(x in "0123456789" for x in d):
                v, i = int(d, 10), i + 4
                if v > 255:
                    return None
            elif i + 1 < n and name[i + 1] not in "0123456789":
                v, i = ord(name[i + 1]), i + 2
            else:
                return None
            if v == 0x2E:
                return None
            out.append(chr(v))
        name = "".join(out)
    if name.endswith("."):
        name = name[:-1]
    return ascii_lower(name)


_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


def ascii_lower(s: str) -> str:
    """Lower-case A-Z only: str.lower() would fold other characters (the Kelvin sign) into ASCII letters."""
    return s.translate(_ASCII_LOWER)


def apex_of(name: str, apexes) -> str | None:
    for a in apexes:
        if name == a or name.endswith("." + a):
            return a
    return None


def valid_host(name: str) -> bool:
    """The scanner's host name rule, plus length limits; an address is not a host name."""
    if len(name) > 253 or not HOST_RE.fullmatch(name):
        return False
    labels = name.split(".")
    if any(len(x) > 63 for x in labels) or labels[-1].isdigit():
        return False
    return True


class Collector:
    """host name -> sources that listed it, for the verified domains only; error codes per source; the sources that
    failed. Each source may add at most `share` names (run_once: MAX_NAMES divided by the number of enabled sources)."""

    def __init__(self, apexes, share: int | None = None) -> None:
        self.apexes = sorted(set(apexes), key=len, reverse=True)
        self.hosts: dict[str, set[str]] = {}
        self.errors: dict[str, list[str]] = {s: [] for s in SOURCES}
        self.share = MAX_NAMES if share is None else share
        self.used: dict[str, int] = {s: 0 for s in SOURCES}
        self.failed: set[str] = set()

    def error(self, source: str, code: str) -> None:
        errs = self.errors.setdefault(source, [])
        if code not in errs and len(errs) < MAX_ERRORS:
            errs.append(code)

    def fail(self, source: str, code: str) -> None:
        """An error that cost the source names in this run (its unit's names were discarded, or it could not run)."""
        self.error(source, code)
        self.failed.add(source)

    def accept(self, name, form: str = "text", zone: str | None = None) -> str | None:
        """The host name to keep for name, or None: decoded for its form, a wildcard's parent, the scanner's host name
        rule, under a verified domain, and (when zone is given) equal to the zone or under it."""
        n = decode_dns_name(name, form)
        if n is None:
            return None
        while n.startswith("*."):          # a wildcard is not a host; its parent is
            n = n[2:]
        if not n or not valid_host(n) or not apex_of(n, self.apexes):
            return None
        if zone is not None and n != zone and not n.endswith("." + zone):
            return None
        return n

    def put(self, n: str, source: str) -> bool:
        srcs = self.hosts.get(n)
        if srcs is not None and source in srcs:
            return True
        if self.used.get(source, 0) >= self.share or (srcs is None and len(self.hosts) >= MAX_NAMES):
            self.fail(source, "too-many-names")      # names were dropped: the source is listed as failed
            return False
        self.hosts.setdefault(n, set()).add(source)
        self.used[source] = self.used.get(source, 0) + 1
        return True

    def add(self, name, source: str, form: str = "text", zone: str | None = None) -> bool:
        n = self.accept(name, form, zone)
        return n is not None and self.put(n, source)

    def add_target(self, target, source: str, form: str = "text", zone: str | None = None) -> None:
        """A CNAME or alias target that is itself under a verified domain (and the zone) is a host too."""
        self.add(target, source, form, zone)

    def batch(self, source: str, zone: str | None = None, form: str = "text", units: int = 1) -> "Batch":
        """A batch for one unit of a source that has `units` units in this run (zones, transfers, hosted zones, files):
        each unit may add at most the source's share divided by its number of units."""
        return Batch(self, source, zone, form, max(1, self.share // max(1, units)))

    def drop_source(self, source: str) -> None:
        """Everything a source added in this run goes (it raised)."""
        for n in list(self.hosts):
            self.hosts[n].discard(source)
            if not self.hosts[n]:
                del self.hosts[n]
        self.used[source] = 0

    def counts(self) -> dict[str, int]:
        c = {s: 0 for s in SOURCES}
        for srcs in self.hosts.values():
            for s in srcs:
                c[s] = c.get(s, 0) + 1
        return c


class Batch:
    """The names of one unit of a source (one transfer, one PowerDNS zone, one Route 53 hosted zone, one zone file),
    kept apart until the unit ends well: commit() adds them to the collector; a unit that fails is dropped with them.
    It offers the collector's add, add_target and error, so the parsers take either."""

    def __init__(self, col: Collector, source: str, zone: str | None, form: str, cap: int | None = None) -> None:
        self.col, self.source, self.zone, self.form = col, source, zone, form
        self.cap = col.share if cap is None else cap
        self.apexes = col.apexes
        self.names: list[str] = []
        self._seen: set[str] = set()
        self.over = False

    def add(self, name, source: str | None = None, form: str | None = None, zone: str | None = None) -> bool:
        n = self.col.accept(name, form or self.form, self.zone)
        if n is None:
            return False
        if n not in self._seen:
            if len(self._seen) >= self.cap:            # this unit's part of the source's share (bounded memory)
                self.over = True
                return False
            self._seen.add(n)
            self.names.append(n)
        return True

    def add_target(self, target, source: str | None = None, form: str | None = None, zone: str | None = None) -> None:
        self.add(target, source, form, zone)

    def error(self, source: str, code: str) -> None:
        self.col.error(self.source, code)

    def commit(self) -> None:
        for n in self.names:
            self.col.put(n, self.source)
        if self.over:
            self.col.fail(self.source, "too-many-names")


# ------------------------------------------------------------------------------------------------------ the scope
def read_verified_domains(scope_dir: str) -> tuple[list[str], int, str | None]:
    """(verified domains, number of list entries refused, error code) from the scanner's list
    <scope_dir>/verified_domains.json (scanner/runner.py publish_seed_scope: the DNS-verified domains only). Opened
    without following a link, a regular file of at most MAX_VERIFIED_BYTES, schema checked, every name passed
    through valid_host. Never raises."""
    path = os.path.join(scope_dir, VERIFIED_FILE)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return [], 0, "verified-domains-missing"
    except OSError:
        return [], 0, "verified-domains-unreadable"
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_VERIFIED_BYTES:
            return [], 0, "verified-domains-unreadable"
        with os.fdopen(fd, "rb") as fh:
            fd = -1
            raw = fh.read(MAX_VERIFIED_BYTES + 1)
    except OSError:
        return [], 0, "verified-domains-unreadable"
    finally:
        if fd >= 0:
            os.close(fd)
    if len(raw) > MAX_VERIFIED_BYTES:
        return [], 0, "verified-domains-unreadable"
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError, MemoryError):
        return [], 0, "verified-domains-invalid"
    if not isinstance(doc, dict) or doc.get("schema") != VERIFIED_SCHEMA or not isinstance(doc.get("domains"), list):
        return [], 0, "verified-domains-invalid"
    verified, refused = set(), 0
    for d in doc["domains"]:
        if isinstance(d, str) and valid_host(d):
            verified.add(d)
        else:
            refused += 1
    return sorted(verified), refused, None


# -------------------------------------------------------------------------------------------------- configuration
class Config:
    def __init__(self, env) -> None:
        def switch(name):
            v = env.get(name, "").strip()
            if v and not SWITCH_RE.fullmatch(v):
                raise ConfigError(f"{name}: use 1 (on) or 0 (off)")
            return v == "1"

        iv = env.get("SEED_INTERVAL_MINUTES", "").strip() or "0"
        if not INTERVAL_RE.fullmatch(iv) or (iv != "0" and not 15 <= int(iv) <= 10080):
            raise ConfigError("SEED_INTERVAL_MINUTES: 0 (run once) or a whole number of minutes from 15 to 10080")
        self.interval_minutes = int(iv)

        self.route53 = switch("SEED_ROUTE53")
        self.role_arn = env.get("SEED_ROUTE53_ROLE_ARN", "").strip() or None
        if self.role_arn and not ROLE_ARN_RE.fullmatch(self.role_arn):
            raise ConfigError("SEED_ROUTE53_ROLE_ARN: not an IAM role ARN (arn:aws:iam::<12 digits>:role/<name>)")
        if self.role_arn and not self.route53:
            raise ConfigError("SEED_ROUTE53_ROLE_ARN: set SEED_ROUTE53=1 as well, or remove it")
        self.region = env.get("SEED_ROUTE53_REGION", "").strip() or "us-east-1"
        if not REGION_RE.fullmatch(self.region):
            raise ConfigError("SEED_ROUTE53_REGION: not a region name (for example us-east-1)")

        self.zone_files = switch("SEED_ZONE_FILES")

        self.axfr: list[tuple[str, str]] = []
        for spec in split_list(env.get("SEED_AXFR")):
            m = AXFR_ENTRY_RE.fullmatch(spec)
            zone = (decode_dns_name(m.group(1)) or "") if m else ""
            if not m or not valid_host(zone):
                raise ConfigError("SEED_AXFR: each entry is zone@address, the zone a host name")
            try:
                ip = ipaddress.ip_address(m.group(2))
            except ValueError:
                raise ConfigError("SEED_AXFR: each server is an IP address (a server is never looked up by name)") from None
            self.axfr.append((zone, str(ip)))
        if len(self.axfr) > 100:
            raise ConfigError("SEED_AXFR: at most 100 entries")

        self.pdns_url = env.get("SEED_PDNS_URL", "").strip().rstrip("/") or None
        self.pdns_server = env.get("SEED_PDNS_SERVER", "").strip() or "localhost"
        self.pdns_zones: list[str] = []
        self.pdns_key_file = env.get("SEED_PDNS_API_KEY_FILE", "").strip() or DEFAULT_PDNS_KEY_FILE
        if self.pdns_url:
            if not PDNS_URL_RE.fullmatch(self.pdns_url):
                raise ConfigError("SEED_PDNS_URL: http:// or https:// with a host, an optional port and path; "
                                  "no user name, password, query or fragment")
            if not PDNS_SERVER_RE.fullmatch(self.pdns_server):
                raise ConfigError("SEED_PDNS_SERVER: letters, digits, dot, underscore and hyphen only")
            for z in split_list(env.get("SEED_PDNS_ZONES")):
                z = decode_dns_name(z) or ""
                if not valid_host(z):
                    raise ConfigError("SEED_PDNS_ZONES: each zone is a host name")
                self.pdns_zones.append(z)
            if not self.pdns_zones:
                raise ConfigError("SEED_PDNS_ZONES: required when SEED_PDNS_URL is set")
            if len(self.pdns_zones) > 200:
                raise ConfigError("SEED_PDNS_ZONES: at most 200 zones")
            if not os.path.isabs(self.pdns_key_file):
                raise ConfigError("SEED_PDNS_API_KEY_FILE: an absolute path")
        elif env.get("SEED_PDNS_ZONES", "").strip() or env.get("SEED_PDNS_SERVER", "").strip():
            raise ConfigError("SEED_PDNS_URL: required when SEED_PDNS_ZONES or SEED_PDNS_SERVER is set")

    def pdns_cleartext(self) -> bool:
        """True when the PowerDNS API key would cross a network in clear text: an http:// URL to a host that is not
        loopback (localhost, 127.0.0.0/8, ::1)."""
        if not self.pdns_url or not self.pdns_url.lower().startswith("http://"):
            return False
        host = self.pdns_url[len("http://"):].split("/", 1)[0]
        host = host[1:].split("]", 1)[0] if host.startswith("[") else host.rsplit(":", 1)[0] if host.count(":") == 1 else host
        if host.lower() == "localhost":
            return False
        try:
            return not ipaddress.ip_address(host).is_loopback
        except ValueError:
            return True

    def enabled(self) -> dict[str, bool]:
        return {"route53": self.route53, "zonefiles": self.zone_files, "axfr": bool(self.axfr), "pdns": bool(self.pdns_url)}


# ------------------------------------------------------------------------------------------------------- route 53
def ingest_route53_rrsets(col: Collector, rrsets, source: str = "route53") -> int:
    """Record names (Route 53's octal escapes) and in-scope alias and CNAME targets. col is the collector or the
    batch of one hosted zone (which keeps only names under that zone)."""
    added = 0
    for rr in rrsets or []:
        if not isinstance(rr, dict):
            continue
        if col.add(str(rr.get("Name", "")), source, form="route53"):
            added += 1
        alias = rr.get("AliasTarget")
        if isinstance(alias, dict):
            col.add_target(str(alias.get("DNSName", "")), source, form="route53")
        if rr.get("Type") == "CNAME":
            for v in rr.get("ResourceRecords") or []:
                if isinstance(v, dict):
                    col.add_target(str(v.get("Value", "")), source, form="route53")
    return added


# The variables the AWS SDK (and Python's HTTP stack) would read for an endpoint, a proxy, a CA bundle, TLS key
# logging, plugins or extra data, or client-side monitoring. Removed at start-up (scrub_environment), any letter case.
# The clients pass endpoint, proxies and CA bundle explicitly as well, so a variable missed here still has no effect
# on them. Kept on purpose: the AWS credential variables and files (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY,
# AWS_SESSION_TOKEN, AWS_SHARED_CREDENTIALS_FILE, the container and web-identity variables, the instance metadata
# settings) and AWS_REGION / AWS_DEFAULT_REGION (the clients pass their region explicitly).
SCRUB_EXACT = (
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "BOTO_EXPERIMENTAL__ADD_PROXY_HOST_HEADER",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "AWS_CA_BUNDLE", "SSLKEYLOGFILE",
    "BOTOCORE_EXPERIMENTAL__PLUGINS", "AWS_DATA_PATH",
    "AWS_IGNORE_CONFIGURED_ENDPOINT_URLS", "AWS_USE_FIPS_ENDPOINT", "AWS_USE_DUALSTACK_ENDPOINT", "AWS_STS_REGIONAL_ENDPOINTS",
)
SCRUB_PREFIXES = ("AWS_ENDPOINT_URL", "AWS_CSM_")     # AWS_ENDPOINT_URL and every AWS_ENDPOINT_URL_<SERVICE>
ROUTE53_ENDPOINT = "https://route53.amazonaws.com"     # the standard AWS partition only
ROUTE53_SIGNING_REGION = "us-east-1"


def scrub_environment(env=None) -> list[str]:
    """Remove SCRUB_EXACT and SCRUB_PREFIXES from env (os.environ by default); log the names removed, never a value."""
    env = os.environ if env is None else env
    gone = sorted(n for n in list(env) if n.upper() in SCRUB_EXACT or n.upper().startswith(SCRUB_PREFIXES))
    for n in gone:
        env.pop(n, None)
    if gone:
        log("removed from the environment at start-up (endpoint, proxy, CA bundle and plugin settings are never taken "
            "from it): " + ", ".join(gone))
    return gone


def ca_bundle() -> str:
    """The CA bundle that ships with the pinned botocore (the seeder image has no other)."""
    import botocore  # noqa: PLC0415
    return os.path.join(os.path.dirname(botocore.__file__), "cacert.pem")


def aws_client(session, service: str, cfg: Config):
    """A Route 53 or STS client with its endpoint, no proxy and the CA bundle given explicitly, so
    no variable or file can move a signed request elsewhere. Route 53 is global (signed for us-east-1); STS uses its
    regional endpoint in cfg.region."""
    from botocore.config import Config as BotoConfig  # noqa: PLC0415
    bc = BotoConfig(connect_timeout=10, read_timeout=60, retries={"max_attempts": 3, "mode": "standard"},
                    proxies={})                        # never None: None would read the proxy variables
    if service == "route53":
        url, region = ROUTE53_ENDPOINT, ROUTE53_SIGNING_REGION
    elif service == "sts":
        url, region = f"https://sts.{cfg.region}.amazonaws.com", cfg.region
    else:
        raise ValueError("unsupported service")
    return session.client(service, config=bc, endpoint_url=url, verify=ca_bundle(), region_name=region)


def isolate_aws_environment(env=os.environ) -> None:
    """The default credential chain with the configuration file pointed at nothing and no named profile, so no
    single sign-on or assume-role profile from a configuration file is used and no credential cache is written. The
    credentials file (for example a Docker secret named by AWS_SHARED_CREDENTIALS_FILE) is the operator's own and the
    SDK honors what it says, including a credential_process line, which would run inside the seeder container."""
    env["AWS_CONFIG_FILE"] = "/nonexistent/aws-config"
    for k in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_SDK_LOAD_CONFIG"):
        env.pop(k, None)


def route53_client(cfg: Config):
    """A Route 53 client from the default credential chain, or from one assumed role (credentials kept in memory
    only). Never called by the tests: they pass a stub client to collect_route53."""
    isolate_aws_environment()
    import boto3  # noqa: PLC0415 - only when the Route 53 source is on
    session = boto3.session.Session(region_name=cfg.region)
    if not cfg.role_arn:
        return aws_client(session, "route53", cfg)
    c = aws_client(session, "sts", cfg).assume_role(RoleArn=cfg.role_arn, RoleSessionName="momus-seeder",
                                                    DurationSeconds=900)["Credentials"]
    return aws_client(boto3.session.Session(aws_access_key_id=c["AccessKeyId"], aws_secret_access_key=c["SecretAccessKey"],
                                            aws_session_token=c["SessionToken"], region_name=cfg.region), "route53", cfg)


def _aws_error_code(e: BaseException) -> str:
    """A fixed code for an SDK error; the SDK's own message (which can name accounts or resources) is never kept."""
    name = type(e).__name__
    if name in ("NoCredentialsError", "PartialCredentialsError", "CredentialRetrievalError", "NoRegionError"):
        return "route53-no-credentials"
    code = ""
    resp = getattr(e, "response", None)
    if isinstance(resp, dict):
        code = str((resp.get("Error") or {}).get("Code") or "")
    if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation"):
        return "route53-access-denied"
    if code in ("InvalidClientTokenId", "ExpiredToken", "ExpiredTokenException", "SignatureDoesNotMatch"):
        return "route53-bad-credentials"
    if code in ("Throttling", "ThrottlingException", "PriorRequestNotComplete"):
        return "route53-throttled"
    if name in ("EndpointConnectionError", "ConnectTimeoutError", "ReadTimeoutError", "ConnectionClosedError"):
        return "route53-unreachable"
    return "route53-error"


def collect_route53(col: Collector, cfg: Config, client=None) -> None:
    """Every public hosted zone that is a verified domain or under one: its record names and in-scope alias and
    CNAME targets. Both listings are paginated (100 zones, 300 record sets per page)."""
    if not cfg.route53:
        return
    try:
        r53 = client if client is not None else route53_client(cfg)
        zones = []
        for page in r53.get_paginator("list_hosted_zones").paginate():
            for z in page.get("HostedZones") or []:
                if not isinstance(z, dict) or (z.get("Config") or {}).get("PrivateZone"):
                    continue
                zname = decode_dns_name(str(z.get("Name", "")), "route53") or ""
                if valid_host(zname) and apex_of(zname, col.apexes):
                    zones.append((str(z.get("Id", "")), zname))
    except Exception as e:  # noqa: BLE001 - one fixed code, never the SDK's message
        col.fail("route53", _aws_error_code(e))
        return
    for zid, zname in zones:
        b = col.batch("route53", zone=zname, form="route53", units=len(zones))   # only names under this hosted zone
        try:
            for page in r53.get_paginator("list_resource_record_sets").paginate(HostedZoneId=zid):
                ingest_route53_rrsets(b, page.get("ResourceRecordSets"))
        except Exception as e:  # noqa: BLE001
            col.fail("route53", _aws_error_code(e))
            continue
        b.commit()


# ---------------------------------------------------------------------------------------- zone text (zone files)
class ZoneDeadline(Exception):
    """The zone-file source ran past ZONE_FILES_DEADLINE_S."""


def _split_parens(lines, on_long=None):
    """Join BIND multi-line records (parentheses) and drop comments. Yields one record at a time. A line, or a record
    joined across lines, longer than MAX_ZONE_LINE_CHARS is skipped (on_long() is called) and parsing goes on at the
    next line with no parenthesis open, so an unbalanced "(" cannot glue the rest of a file into one record."""
    buf, depth, size = [], 0, 0
    for raw in lines:
        if len(raw) > MAX_ZONE_LINE_CHARS:
            if on_long:
                on_long()
            buf, depth, size = [], 0, 0
            continue
        line = re.sub(r"(?<!\\);.*$", "", raw).rstrip()
        if not line.strip() and depth == 0:
            continue
        size += len(line) + 1
        if size > MAX_ZONE_LINE_CHARS:
            if on_long:
                on_long()
            buf, depth, size = [], 0, 0
            continue
        depth += line.count("(") - line.count(")")
        buf.append(line.replace("(", " ").replace(")", " "))
        if depth <= 0:
            yield " ".join(buf)
            buf, depth, size = [], 0, 0
    if buf:
        yield " ".join(buf)


TTL_RE = re.compile(r"[0-9]+[smhdwSMHDW]")
RR_TYPES = {"A", "AAAA", "CNAME", "MX", "TXT", "SRV", "NS", "SOA", "PTR", "CAA", "ALIAS", "ANAME", "HTTPS", "SVCB",
            "TLSA", "DS", "DNSKEY", "NAPTR", "SPF"}


def parse_zone_text(text: str, origin: str, col: Collector, source: str, deadline: float | None = None) -> int:
    """Owner names (and in-scope CNAME targets) from BIND zone text, or from a plain one-name-per-line list
    (relative names get the origin appended). Returns the number of names added. Tokens are walked by index (linear
    in the length of a line); lines are capped (_split_parens); past deadline (time.monotonic()) ZoneDeadline."""
    origin = ascii_lower(origin.strip()).rstrip(".")
    last_owner = origin
    added = 0

    def absolute(name: str) -> str:
        name = name.strip()
        if name in ("@", ""):
            return origin
        if name.endswith("."):
            return ascii_lower(name[:-1])
        low = ascii_lower(name)
        if origin and (low == origin or low.endswith("." + origin)):
            return low                    # exports often list full names without the trailing dot
        return f"{low}.{origin}" if origin else low

    for count, line in enumerate(_split_parens(text.splitlines(), lambda: col.error(source, "zonefile-line-too-long"))):
        if deadline is not None and count % 64 == 0 and time.monotonic() > deadline:
            raise ZoneDeadline()
        if line.startswith("$ORIGIN"):
            parts = line.split()
            if len(parts) > 1:
                origin = ascii_lower(parts[1]).rstrip(".")
                last_owner = origin
            continue
        if line.startswith("$"):
            continue
        toks = line.split()
        if not toks:
            continue
        i = 0                             # tokens are walked by index, never popped from the front
        if line[0] in " \t":
            owner = last_owner
        else:
            owner, i = absolute(toks[0]), 1
        last_owner = owner
        if i >= len(toks):                # a plain host list (an address on its own line is not a name)
            if _is_address(line.strip()):
                continue
            if col.add(owner, source):
                added += 1
            continue
        while i < len(toks) and (toks[i].isdigit() or toks[i].upper() in ("IN", "CH", "HS") or TTL_RE.fullmatch(toks[i])):
            i += 1
        if i >= len(toks):
            continue
        rtype = toks[i].upper()
        i += 1
        if rtype not in RR_TYPES:
            continue
        if col.add(owner, source):
            added += 1
        if rtype in ("CNAME", "ALIAS", "ANAME") and i < len(toks):
            col.add_target(absolute(toks[i]), source)
    return added


def _is_address(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def _read_regular_file(dir_fd: int, name: str, cap: int) -> bytes | None:
    """The file's bytes, without following a symlink, if it is a regular file no larger than cap; else None."""
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > cap:
            return None
        chunks, total = [], 0
        while True:
            b = os.read(fd, 1 << 20)
            if not b:
                break
            total += len(b)
            if total > cap:
                return None
            chunks.append(b)
        return b"".join(chunks)
    except OSError:
        return None
    finally:
        os.close(fd)


def collect_zone_files(col: Collector, cfg: Config, zdir: str) -> None:
    """Every zone file or host list in zdir, each as one unit (a file stopped by the source's deadline adds nothing).
    The operator's own files: names under any verified domain are kept."""
    if not cfg.zone_files:
        return
    deadline = time.monotonic() + ZONE_FILES_DEADLINE_S
    try:
        dir_fd = os.open(zdir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        col.error("zonefiles", "zonefiles-folder-unreadable")
        return
    try:
        names = sorted(os.listdir(dir_fd))
        if len(names) > MAX_ZONE_FILES:
            col.error("zonefiles", "zonefiles-too-many-files")
            names = names[:MAX_ZONE_FILES]
        names = [fn for fn in names
                 if not fn.startswith(".") and ZONE_FILE_NAME_RE.fullmatch(fn) and not fn.endswith((".md", ".example"))]
        for fn in names:
            if time.monotonic() > deadline:
                col.fail("zonefiles", "zonefiles-deadline")
                break
            raw = _read_regular_file(dir_fd, fn, MAX_ZONE_FILE_BYTES)
            if raw is None:
                col.error("zonefiles", "zonefile-skipped-not-a-regular-file-or-too-large")
                continue
            text = raw.decode("utf-8", errors="ignore")
            m = re.search(r"^\$ORIGIN[ \t]+(\S+)", text, re.M)
            origin = decode_dns_name(m.group(1) if m else re.sub(r"\.(zone|txt|db|hosts)$", "", fn)) or ""
            if not valid_host(origin) or not apex_of(origin, col.apexes):
                col.error("zonefiles", "zonefile-origin-not-a-verified-domain")
                continue
            b = col.batch("zonefiles", units=len(names))
            try:
                parse_zone_text(text, origin, b, "zonefiles", deadline)
            except ZoneDeadline:
                col.fail("zonefiles", "zonefiles-deadline")
                break
            b.commit()
    finally:
        os.close(dir_fd)


# -------------------------------------------------------------------------------------------- zone transfer (AXFR)
class AxfrError(Exception):
    """A transfer failed; the argument is a fixed code."""


def _encode_name(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        out += bytes([len(label)]) + label.encode("ascii")
    return out + b"\x00"


def axfr_query(zone: str, qid: int) -> bytes:
    """One AXFR question (type 252, class IN), as sent over TCP (two-byte length first)."""
    msg = struct.pack("!HHHHHH", qid, 0, 1, 0, 0, 0) + _encode_name(zone) + struct.pack("!HH", 252, 1)
    return struct.pack("!H", len(msg)) + msg


def _read_name(msg: bytes, off: int) -> tuple[str | None, int]:
    """A domain name at off (with compression pointers). (name or None when it is not a plain host-like name, the
    offset after the name in the record)."""
    labels: list[str] = []
    end = None
    jumps = 0
    ok = True
    total = 0
    while True:
        if off >= len(msg):
            raise AxfrError("axfr-malformed-answer")
        n = msg[off]
        if n & 0xC0 == 0xC0:
            if off + 1 >= len(msg):
                raise AxfrError("axfr-malformed-answer")
            ptr = ((n & 0x3F) << 8) | msg[off + 1]
            if end is None:
                end = off + 2
            jumps += 1
            if jumps > 64 or ptr >= len(msg):
                raise AxfrError("axfr-malformed-answer")
            off = ptr
            continue
        if n & 0xC0:
            raise AxfrError("axfr-malformed-answer")
        off += 1
        if n == 0:
            break
        if off + n > len(msg):
            raise AxfrError("axfr-malformed-answer")
        raw = msg[off:off + n]
        off += n
        total += n + 1
        if total > 255:
            raise AxfrError("axfr-malformed-answer")
        try:
            label = raw.decode("ascii")
        except UnicodeDecodeError:
            ok = False
            continue
        if "." in label or "\\" in label or not label:
            ok = False                     # wire labels are bytes, not text escapes: a backslash is not a host name
        labels.append(label.lower())
    return (".".join(labels) if ok else None), (end if end is not None else off)


def parse_axfr_message(msg: bytes, qid: int, col: Collector, source: str) -> int:
    """Owner names and in-scope CNAME targets from one answer message; returns the number of SOA records seen."""
    if len(msg) < 12:
        raise AxfrError("axfr-malformed-answer")
    rid, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", msg[:12])
    if rid != qid or not flags & 0x8000:
        raise AxfrError("axfr-malformed-answer")
    rcode = flags & 0x000F
    if rcode == 5:
        raise AxfrError("axfr-refused")
    if rcode == 9:
        raise AxfrError("axfr-not-authoritative")
    if rcode != 0:
        raise AxfrError("axfr-server-error")
    off = 12
    for _ in range(qd):
        _, off = _read_name(msg, off)
        off += 4
    soas = 0
    for _ in range(an):
        owner, off = _read_name(msg, off)
        if off + 10 > len(msg):
            raise AxfrError("axfr-malformed-answer")
        rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", msg[off:off + 10])
        off += 10
        rdata_off = off
        off += rdlen
        if off > len(msg):
            raise AxfrError("axfr-malformed-answer")
        if rtype == 6:
            soas += 1
        if owner:
            col.add(owner, source)
        if rtype == 5:                                   # CNAME: an in-scope target is a host too
            target, _ = _read_name(msg, rdata_off)
            if target:
                col.add_target(target, source)
    return soas


def _recv_exact(sock, n: int, deadline: float) -> bytes:
    buf = b""
    while len(buf) < n:
        left = deadline - time.monotonic()
        if left <= 0:
            raise AxfrError("axfr-timeout")
        try:
            sock.settimeout(min(AXFR_TIMEOUT_S, left))       # a read never outlasts the deadline
            chunk = sock.recv(n - len(buf))
        except socket.timeout:
            raise AxfrError("axfr-timeout") from None
        except OSError:
            raise AxfrError("axfr-connection-failed") from None
        if not chunk:
            raise AxfrError("axfr-connection-closed")
        buf += chunk
    return buf


def axfr(zone: str, server: str, col: Collector, connect=None, source: str = "axfr",
         deadline: float | None = None) -> None:
    """One zone transfer over TCP port 53 from the address the user typed. Ends at the closing SOA record, or with
    axfr-timeout at AXFR_DEADLINE_S or at the given deadline (the source's), whichever comes first."""
    qid = secrets.randbelow(65536)
    own = time.monotonic() + AXFR_DEADLINE_S
    deadline = own if deadline is None else min(own, deadline)
    opener = connect or (lambda addr: socket.create_connection(addr, timeout=AXFR_TIMEOUT_S))
    try:
        sock = opener((server, 53))
    except OSError:
        raise AxfrError("axfr-connection-failed") from None
    try:
        try:
            sock.settimeout(AXFR_TIMEOUT_S)
            sock.sendall(axfr_query(zone, qid))
        except OSError:
            raise AxfrError("axfr-connection-failed") from None
        soas, total, messages = 0, 0, 0
        while soas < 2:
            (n,) = struct.unpack("!H", _recv_exact(sock, 2, deadline))
            total += n + 2
            messages += 1
            if total > MAX_AXFR_BYTES or messages > 100000:
                raise AxfrError("axfr-too-large")
            msg = _recv_exact(sock, n, deadline)
            got = parse_axfr_message(msg, qid, col, source)
            if messages == 1 and got == 0:
                raise AxfrError("axfr-malformed-answer")     # a transfer starts with the zone's SOA record
            soas += got
    finally:
        try:
            sock.close()
        except OSError:
            pass


def collect_axfr(col: Collector, cfg: Config, connect=None) -> None:
    """Each transfer is one unit: only names equal to its zone or under it are kept, and a transfer that ends in an
    error adds nothing."""
    source_deadline = time.monotonic() + AXFR_SOURCE_DEADLINE_S       # every transfer together
    units = sum(1 for zone, _ in cfg.axfr if apex_of(zone, col.apexes))
    for zone, server in cfg.axfr:
        if not apex_of(zone, col.apexes):
            col.error("axfr", "axfr-zone-not-a-verified-domain")
            continue
        if time.monotonic() > source_deadline:
            col.fail("axfr", "axfr-source-deadline")
            break
        b = col.batch("axfr", zone=zone, units=units)
        try:
            axfr(zone, server, b, connect=connect, deadline=source_deadline)
        except AxfrError as e:
            col.fail("axfr", str(e.args[0]))
            continue
        b.commit()


# ----------------------------------------------------------------------------------------------- PowerDNS API
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """The key is never sent anywhere but the configured address: a redirect is an error."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401, PLR0913
        raise urllib.error.HTTPError(req.full_url, code, "redirect refused", headers, fp)


class _Watch:
    """The socket of the PowerDNS request in progress. At the request's deadline a timer shuts it down, which ends any
    read in progress (status line, headers, a chunk-size line or the body): the whole request is under one deadline.
    A socket connected after the deadline is shut down at once."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.sock = None
        self.expired = False

    @staticmethod
    def _shut(sock) -> None:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def register(self, sock) -> None:
        with self.lock:
            self.sock, expired = sock, self.expired
        if expired:
            self._shut(sock)

    def expire(self) -> None:
        with self.lock:
            self.expired, sock = True, self.sock
        if sock is not None:
            self._shut(sock)


_WATCH: "_Watch | None" = None          # the request in progress (requests are made one at a time)


def _tracked(conn_cls):
    """conn_cls, registering its socket with the request in progress as soon as it is connected."""
    class Tracked(conn_cls):
        def connect(self):
            super().connect()
            w = _WATCH
            if w is not None:
                w.register(self.sock)
    return Tracked


def pdns_opener(http_connection=None, https_connection=None):
    """No proxy from the environment, no redirects, and connections whose sockets the request's deadline can shut
    down. The connection classes can be given (the tests' loopback connection)."""
    plain = _tracked(http_connection or http.client.HTTPConnection)
    tls = _tracked(https_connection or http.client.HTTPSConnection)

    class Plain(urllib.request.HTTPHandler):
        def http_open(self, req):
            return self.do_open(plain, req)

    class Tls(urllib.request.HTTPSHandler):
        def https_open(self, req):
            return self.do_open(tls, req, context=self._context)

    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect(), Plain(), Tls())


def read_key_file(path: str) -> str | None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > 4096:
            return None
        raw = os.read(fd, 4097)
    except OSError:
        return None
    finally:
        os.close(fd)
    try:
        key = raw.decode("ascii").strip()
    except UnicodeDecodeError:
        return None
    return key if PDNS_KEY_RE.fullmatch(key) else None


class PdnsShapeError(Exception):
    """The PowerDNS answer is not the shape of a zone (pdns-answer-invalid)."""


def ingest_pdns_zone(col: Collector, zone, source: str = "pdns") -> int:
    """Owner names and in-scope CNAME and ALIAS targets of one zone answer. The shape is checked at every level before
    use (an object; "rrsets" a list of objects; each "name" a string; "records" a list of objects whose "content" is a
    string); anything else raises PdnsShapeError. col is the collector or the batch of that zone."""
    if not isinstance(zone, dict) or not isinstance(zone.get("rrsets"), list):
        raise PdnsShapeError()
    added = 0
    for rr in zone["rrsets"]:
        if not isinstance(rr, dict) or not isinstance(rr.get("name"), str) or not isinstance(rr.get("records", []), list):
            raise PdnsShapeError()
        records = rr.get("records", [])
        if any(not isinstance(rec, dict) or not isinstance(rec.get("content", ""), str) for rec in records):
            raise PdnsShapeError()
        if col.add(rr["name"], source):
            added += 1
        if rr.get("type") in ("CNAME", "ALIAS"):
            for rec in records:
                col.add_target(rec.get("content", ""), source)
    return added


class PdnsTimeout(Exception):
    """The answer did not arrive within PDNS_DEADLINE_S."""


def _read_bounded(resp, cap: int, deadline: float) -> bytes | None:
    """The body in chunks against one deadline: read1 returns after a single receive, so an endpoint
    that sends a byte now and then cannot hold the run past the deadline. None when the body is larger than cap."""
    read = getattr(resp, "read1", None) or resp.read
    chunks, total = [], 0
    while True:
        if time.monotonic() > deadline:
            raise PdnsTimeout()
        b = read(1 << 16)
        if not b:
            return b"".join(chunks)
        total += len(b)
        if total > cap:
            return None
        chunks.append(b)


def collect_pdns(col: Collector, cfg: Config, opener=None) -> None:
    """GET {url}/api/v1/servers/{server}/zones/{zone}. with X-API-Key; rrsets -> names."""
    if not cfg.pdns_url:
        return
    key = read_key_file(cfg.pdns_key_file)
    if key is None:
        col.fail("pdns", "pdns-key-file-unreadable")
        return
    global _WATCH
    op = opener or pdns_opener()
    source_deadline = time.monotonic() + PDNS_SOURCE_DEADLINE_S       # every request together
    units = sum(1 for zone in cfg.pdns_zones if apex_of(zone, col.apexes))
    for zone in cfg.pdns_zones:
        if not apex_of(zone, col.apexes):
            col.error("pdns", "pdns-zone-not-a-verified-domain")
            continue
        if time.monotonic() > source_deadline:
            col.fail("pdns", "pdns-source-deadline")
            break
        url = f"{cfg.pdns_url}/api/v1/servers/{cfg.pdns_server}/zones/{zone}."
        req = urllib.request.Request(url, headers={"X-API-Key": key, "Accept": "application/json"})
        deadline = min(time.monotonic() + PDNS_DEADLINE_S, source_deadline)
        watch = _WATCH = _Watch()
        timer = threading.Timer(max(0.0, deadline - time.monotonic()), watch.expire)
        timer.daemon = True
        timer.start()
        try:
            with op.open(req, timeout=PDNS_TIMEOUT_S) as resp:  # noqa: S310 - the operator's own address
                body = _read_bounded(resp, MAX_PDNS_BYTES, deadline)
            if watch.expired:
                raise PdnsTimeout()
        except PdnsTimeout:
            col.fail("pdns", "pdns-timeout")
            continue
        except urllib.error.HTTPError as e:
            code = int(e.code) if isinstance(e.code, int) else 0
            col.fail("pdns", "pdns-timeout" if watch.expired else
                     "pdns-redirect-refused" if 300 <= code < 400 else f"pdns-http-{code}")
            continue
        except Exception:  # noqa: BLE001 - one fixed code, never the message
            col.fail("pdns", "pdns-timeout" if watch.expired else "pdns-unreachable")
            continue
        finally:
            timer.cancel()
            _WATCH = None
        if body is None:
            col.fail("pdns", "pdns-answer-too-large")
            continue
        try:
            data = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError, MemoryError):
            col.fail("pdns", "pdns-answer-invalid")
            continue
        b = col.batch("pdns", zone=zone, units=units)     # only names under this zone
        try:
            ingest_pdns_zone(b, data)
        except PdnsShapeError:
            col.fail("pdns", "pdns-answer-invalid")
            continue
        b.commit()


# ---------------------------------------------------------------------------------------------------------- output
def _write_atomic(out_dir: str, name: str, text: str) -> None:
    tmp = os.path.join(out_dir, f".{name}.tmp-{os.getpid()}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
    try:
        with os.fdopen(fd, "w", encoding="ascii") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o644)
        os.replace(tmp, os.path.join(out_dir, name))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def write_outputs(col: Collector, out_dir: str, cfg: Config, scope_error: str | None, verified: int, refused: int) -> dict:
    """seed_hosts.txt (only when names were found; otherwise an earlier file stays) and status.json (always): the
    sources that failed are listed, so an old healthy status never outlives a failed run."""
    hosts = sorted(col.hosts)
    existing = os.path.lexists(os.path.join(out_dir, OUT_FILE))
    if hosts:
        _write_atomic(out_dir, OUT_FILE, "".join(h + "\n" for h in hosts))
        result = "written"
    else:
        result = "kept-previous" if existing else "nothing-found"
    counts = col.counts()
    enabled = cfg.enabled()
    status = {
        "schema": SCHEMA_STATUS, "updated_at": now_iso(), "result": result,
        "count": len(hosts) if hosts else None,
        "domains_verified": verified, "domains_refused": refused,
        "errors": [scope_error] if scope_error else [],
        "failed_sources": sorted(col.failed),
        "sources": {s: {"enabled": enabled[s], "names": counts.get(s, 0), "errors": list(col.errors.get(s, []))}
                    for s in SOURCES},
    }
    _write_atomic(out_dir, STATUS_FILE, json.dumps(status, indent=1, sort_keys=True) + "\n")
    return status


def run_once(cfg: Config, scope_dir: str, out_dir: str, zones_dir: str, clients=None) -> dict:
    """One run. Any exception inside a source becomes the fixed code "<source>-internal-error": that source adds no
    names in this run, one fixed line is logged (no traceback, no exception text), and the other sources go on."""
    clients = clients or {}
    verified, refused, scope_error = read_verified_domains(scope_dir)
    enabled = cfg.enabled()
    col = Collector(verified, share=MAX_NAMES // max(1, sum(enabled.values())))
    if verified:
        for source, collect in (("route53", lambda: collect_route53(col, cfg, client=clients.get("route53"))),
                                ("zonefiles", lambda: collect_zone_files(col, cfg, zones_dir)),
                                ("axfr", lambda: collect_axfr(col, cfg, connect=clients.get("axfr"))),
                                ("pdns", lambda: collect_pdns(col, cfg, opener=clients.get("pdns")))):
            if not enabled[source]:
                continue
            try:
                collect()
            except Exception:  # noqa: BLE001 - one fixed code per source, never the exception's text
                col.drop_source(source)
                col.fail(source, f"{source}-internal-error")
                log(f"source {source} failed: {source}-internal-error")
    status = write_outputs(col, out_dir, cfg, scope_error or (None if verified else "no-verified-domain"), len(verified), refused)
    per = ", ".join(f"{s}={status['sources'][s]['names']}" for s in SOURCES if status["sources"][s]["enabled"]) or "none enabled"
    errs = [e for s in SOURCES for e in status["sources"][s]["errors"]] + status["errors"]
    log(f"{status['result']}: {len(col.hosts)} names for {len(verified)} verified domain(s); "
        f"per source: {per}" + (f"; errors: {' '.join(errs)}" if errs else ""))
    return status


_STOP = False


def _on_stop(signum, frame):  # noqa: ARG001
    global _STOP
    _STOP = True


def _wait_until(t: float) -> None:
    while not _STOP and time.monotonic() < t:
        time.sleep(min(1.0, max(0.0, t - time.monotonic())))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="List host names from your own DNS sources for DNS-verified domains.")
    ap.add_argument("--scope", default=DEFAULT_SCOPE, help="the folder of the scanner's verified-domain list (read only)")
    ap.add_argument("--out", default=DEFAULT_OUT, help="the seed folder (written)")
    ap.add_argument("--zones", default=DEFAULT_ZONES, help="zone files folder (read only)")
    a = ap.parse_args(argv)
    quiet_libraries()
    scrub_environment()                   # before any setting is read or any SDK is loaded
    try:
        cfg = Config(os.environ)
    except ConfigError as e:
        log(f"configuration error: {e}")
        return 2
    if cfg.pdns_cleartext():
        log(PDNS_CLEARTEXT_LINE)
    if not any(cfg.enabled().values()):
        log("no source is configured (SEED_ROUTE53, SEED_ZONE_FILES, SEED_AXFR, SEED_PDNS_URL); see .env.example")
    signal.signal(signal.SIGTERM, _on_stop)
    signal.signal(signal.SIGINT, _on_stop)
    once = cfg.interval_minutes == 0
    while True:
        started = time.monotonic()
        try:
            run_once(cfg, a.scope, a.out, a.zones)
        except OSError:
            if once:
                log("could not write to the seed folder")
                return 1
            log("could not write to the seed folder; the next run is at the usual time")
        except Exception:  # noqa: BLE001 - in interval mode nothing ends the loop; never the exception's text
            if once:
                log("the run failed (internal error)")
                return 1
            log("the run failed (internal error); the next run is at the usual time")
        if once or _STOP:
            return 0
        _wait_until(started + cfg.interval_minutes * 60)     # counted from the start of the run
        if _STOP:
            return 0


if __name__ == "__main__":
    sys.exit(main())
