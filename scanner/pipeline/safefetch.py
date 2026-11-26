"""safefetch.py - follow-up connections from verify.py, triage.py and version_watch.py, pinned to one approved host.

Every request:
  - goes to the anchor host only (the finding's own host, never a name taken from tool output or a response);
  - resolves that host once, checks every address with the scope's ip_allowed, and connects to that same address
    (Host header and TLS SNI carry the name), so a DNS answer that changes between check and use cannot redirect it;
  - follows at most MAX_REDIRECTS redirects, each one on the anchor host, each one resolved and checked again;
  - never uses a proxy from the environment (http.client is used directly, not urllib's opener).

Resolver and connector are parameters so tests can observe the address each connection was made to.
configure(scope) installs a scope.Scope's ip_allowed; until then only globally routable addresses pass.
"""
import http.client, ipaddress, socket, ssl, urllib.parse

import scope as SC

TIMEOUT = 10
MAX_REDIRECTS = 3
MAX_BODY = 1 << 20

_POLICY = {"ip_check": lambda ip, host=None: SC.strict_ip_check(ip)}


class Refused(Exception):
    """A request the scope does not allow (another host, a refused address, an unsupported scheme)."""


def configure(scope):
    """Use this scope's rules (exclusions, lab mode) for every later request; None restores the strict default."""
    _POLICY["ip_check"] = scope.ip_allowed if scope is not None else (lambda ip, host=None: SC.strict_ip_check(ip))


def system_resolve(host):
    infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(i[4][0] for i in infos))


def system_connect(ip, port, timeout):
    return socket.create_connection((ip, port), timeout=timeout)


def checked_address(target, host=None, resolver=None, ip_check=None):
    """One address for target (a name or an address) that passed ip_check; Refused otherwise. A name must have
    every address allowed (the same rule the pipeline uses to carry a host forward)."""
    check = ip_check or _POLICY["ip_check"]
    try:
        ipaddress.ip_address(str(target).strip("[]"))
        ips = [str(target).strip("[]")]
    except ValueError:
        try:
            ips = (resolver or system_resolve)(target)
        except OSError as e:
            raise Refused(f"{target} does not resolve ({type(e).__name__})")
    if not ips:
        raise Refused(f"{target} has no address")
    for ip in ips:
        ok, why = check(ip, host or target)
        if not ok:
            raise Refused(f"{target} -> {ip} refused: {why}")
    return ips[0]


class Pinned:
    """fetch(url, headers[, data]) -> (status, final_url, body_bytes), anchored to host."""

    def __init__(self, host, resolver=None, connect=None, ip_check=None, timeout=TIMEOUT, max_redirects=MAX_REDIRECTS):
        self.host = (host or "").lower().rstrip(".")
        self.resolver, self.connect = resolver, connect or system_connect
        self.ip_check = ip_check
        self.timeout, self.max_redirects = timeout, max_redirects

    def _target(self, url):
        p = urllib.parse.urlsplit(url)
        if p.scheme not in ("http", "https"):
            raise Refused(f"scheme {p.scheme!r} not fetched")
        if not self.host or (p.hostname or "").lower().rstrip(".") != self.host:
            raise Refused(f"{p.hostname} is not {self.host or 'the finding host'}")
        port = p.port or (443 if p.scheme == "https" else 80)
        path = (p.path or "/") + (("?" + p.query) if p.query else "")
        return p.scheme, port, path

    def request(self, method, url, headers, data=None):
        scheme, port, path = self._target(url)
        ip = checked_address(self.host, self.host, self.resolver, self.ip_check)
        sock = self.connect(ip, port, self.timeout)
        try:
            if scheme == "https":
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE   # nuclei does not verify either; this reads, it does not trust
                sock = ctx.wrap_socket(sock, server_hostname=self.host)
            conn = http.client.HTTPConnection(self.host, port, timeout=self.timeout)
            conn.sock = sock
            default = 443 if scheme == "https" else 80
            hdrs = {k: v for k, v in (headers or {}).items() if k.lower() != "host"}
            hdrs["Host"] = self.host if port == default else f"{self.host}:{port}"
            conn.request(method, path, body=data, headers=hdrs)
            r = conn.getresponse()
            return r.status, r.getheader("Location"), r.read(MAX_BODY)
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def __call__(self, url, headers, data=None):
        cur = url
        for _ in range(self.max_redirects + 1):
            st, loc, body = self.request("POST" if data is not None else "GET", cur, headers, data)
            if data is None and st in (301, 302, 303, 307, 308) and loc:
                nxt = urllib.parse.urljoin(cur, loc)
                if (urllib.parse.urlsplit(nxt).hostname or "").lower().rstrip(".") != self.host:
                    raise Refused(f"redirect leaves {self.host}: {nxt}")
                cur = nxt
                continue
            return st, cur, body
        return 310, cur, b""   # still redirecting after max_redirects
