"""triage.py - deep triage of one finding: follow what it points to and say what is actually exposed.

  t = triage(finding, raw, verdict, fetch=None, probe=None)

finding: the normalized finding dict from ingest.py plus "hostname" and "pci"; raw: the nuclei record (request,
response, matched-at, template-id) or the nmap raw dict (ip, port, service, product); verdict: verify.py's verdict.
Returns {exposure, summary, fix, items, secrets, pci}:
  exposure  credential | data | source | config | internal | names | nothing | unknown
  summary   one plain line: what is readable and what is not
  fix       one or two plain sentences for this host and family
  items     [{url, status, bytes, kind, note}], at most MAX_ITEMS, same host only
  secrets   [{type, where, line}], never any part of a value
  pci       bool

Bounds (the same rules as verify.py): at most MAX_FETCHES fetches per finding, TIMEOUT s each and DEADLINE s in
all, GET only (one POST for a GraphiQL introspection query), on the finding's own host only (finding["hostname"],
from the asset inventory; never a host taken from the matched URL), through safefetch.Pinned (resolved once, checked
with the scope, connected to that address, same-host redirects only), User-Agent from the recorded request. Ports get one protocol handshake each (probe), PROBE_TIMEOUT s, no credentials ever sent.
fetch(url, headers[, data]) -> (status, final_url, body_bytes) and probe(host, port) -> (kind, detail) are parameters
so tests pass stubs. Every string that leaves this module has been through redact.py.
"""
import json, os, re, socket, sqlite3, struct, sys, tempfile, time, urllib.parse, urllib.request
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import redact as R
import verify as V
import safefetch as SF

EXPOSURES = ["credential", "data", "source", "config", "internal", "names", "nothing", "unknown"]
RANK = {e: len(EXPOSURES) - i for i, e in enumerate(EXPOSURES)}
RANK["unknown"] = 0
TRIAGE_PORTS = {3306, 5432, 445, 1433, 27017, 6379, 9200, 5900, 3389, 23, 21}
MAX_FETCHES = 12
MAX_ITEMS = 12
DEADLINE = 90
PROBE_TIMEOUT = 5
DOCKER_PROBES = [".npmrc", ".env", ".env.php", ".env.local", ".git/config", "composer.json", "package.json", ".dockerignore", "docker-compose.yml"]
SECRET_NAME = [re.compile(p, re.I) for p in (
    r"^\.env", r"\.dist$", r"\.bak$|~$|\.old$|\.orig$|\.save$", r"\.sql(\.gz)?$|\.dump$", r"\.key$|\.pem$|\.p12$|\.pfx$|id_rsa",
    r"credential|secret|passw|token|auth", r"config|conf|settings|\.ini$", r"\.rb$", r"\.log$", r"\.json$", r"\.ya?ml$")]
SECRET_DIRS = re.compile(r"^(?:config|conf|configs|settings|backup|backups|bak|db|database|sql|dump|private|secret|secrets|keys|certs|\.git|\.svn)/$", re.I)

def wants_triage(f, band, verdict):
    """Every nmap open-port finding on a database/file/remote-admin port; anything else scored High, Medium or
    Critical, or with a confirmed verdict."""
    if f.get("source") == "nmap":
        return f.get("check_id") != "catch-all-proxy" and (f.get("port") in TRIAGE_PORTS or band in ("Critical", "High"))
    return band in ("Critical", "High", "Medium") or verdict == "confirmed"

# ---------------------------------------------------------------- fetch context
def fetch_for(host):
    """GETs and the one POST (GraphiQL introspection, never redirected) for one finding, pinned to its host."""
    pinned = V.fetch_for(host)
    def fetch(url, headers, data=None):
        if data is None:
            return pinned(url, headers)
        return pinned(url, {**headers, "Content-Type": "application/json"}, data)
    return fetch

class Ctx:
    def __init__(self, finding, raw, fetch):
        self.f, self.raw = finding, raw or {}
        self.url = V._url(finding, raw) or ""
        # the finding's own host only: a missing hostname means nothing is fetched, not "use the matched URL's host"
        self.host = (finding.get("hostname") or "").lower().rstrip(".")
        self.fetch = fetch or fetch_for(self.host)
        self.hdrs = {"User-Agent": V.user_agent(raw) or "Mozilla/5.0"}
        self.items, self.secrets, self.internal = [], [], []
        self.fetches, self.t0 = 0, time.monotonic()
        self.status, self.headers, self.body = V.parse_response(self.raw.get("response"))

    def on_host(self, url):
        return (urllib.parse.urlsplit(url).hostname or "").lower() == self.host

    def resolve(self, ref, base=None):
        return urllib.parse.urljoin(base or self.url, ref)

    def add(self, url, status, nbytes, kind, note):
        if len(self.items) < 3 * MAX_ITEMS:
            self.items.append({"url": url, "status": status, "bytes": nbytes, "kind": kind, "note": R.redact(note or "")[:300]})

    def note_internal(self, *facts):
        for x in facts:
            if x and x not in self.internal:
                self.internal.append(x)

    def get(self, url, data=None, binary=False, record=True):
        """(status, text-or-bytes) or (None, None). Off-host URLs and anything past the budget are never fetched."""
        if not self.on_host(url):
            if record:
                self.add(url, None, None, "skipped", f"not fetched: {urllib.parse.urlsplit(url).hostname} is not {self.host}")
            return None, None
        if self.fetches >= MAX_FETCHES or time.monotonic() - self.t0 > DEADLINE:
            if record:
                self.add(url, None, None, "skipped", "not fetched: per-finding fetch budget used")
            return None, None
        self.fetches += 1
        try:
            st, final, body = self.fetch(url, self.hdrs, data) if data is not None else self.fetch(url, self.hdrs)
        except Exception as ex:
            if record:
                self.add(url, None, None, "error", f"fetch failed: {type(ex).__name__}")
            return None, None
        body = body or b""
        if final and final != url:
            if record:
                self.add(url, st, len(body), "nothing", f"redirects to {urllib.parse.urlsplit(final).path or '/'}")
            return st, None
        return st, (body if binary else body.decode("utf-8", "replace"))

    def take(self, url, label=None):
        """Fetch url, classify a readable body, record item and secrets. Returns (kind, text or None)."""
        st, text = self.get(url)
        if st is None or text is None:
            return None, None
        path = urllib.parse.urlsplit(url).path
        label = label or path
        if st != 200:
            self.add(url, st, len(text.encode("utf-8", "replace")), "nothing", f"{st}")
            return "nothing", None
        if V.SOFT_404.search(text[:300]) and len(text) < 300:
            self.add(url, st, len(text), "nothing", "200 but the body says not found")
            return "nothing", None
        kind, note = R.classify(text, path)
        sec = R.find_secrets(text, path)
        self.secrets.extend(sec)
        if kind in ("internal", "config", "source"):
            names = R.internal_names(text, 4)
            if names:
                note += "; names " + ", ".join(names)
        self.add(url, st, len(text.encode("utf-8", "replace")), kind, note)
        return kind, (text if kind != "nothing" else None)

    def recorded(self, kind, note):
        """The matched URL itself, from the recorded response."""
        self.add(self.url, self.status, len((self.body or "").encode("utf-8", "replace")), kind, note)

    def elapsed_ok(self):
        return self.fetches < MAX_FETCHES and time.monotonic() - self.t0 <= DEADLINE

# ---------------------------------------------------------------- result helpers
def _plural(n, word):
    return f"{n} {word}" + ("" if n == 1 or word.endswith("s") else "s")

def _secret_counts(secrets):
    by = {}
    for s in secrets:
        k = (s["where"].lstrip("/") or s["where"], s["type"])
        by[k] = by.get(k, 0) + 1
    return by

def overall(ctx, base="nothing"):
    """The strongest exposure among the items (and the base the family decided)."""
    best = base
    for it in ctx.items:
        k = it["kind"]
        if k in RANK and k not in ("nothing", "unknown") and RANK[k] > RANK.get(best, 0):
            best = k
    if ctx.secrets and RANK["credential"] > RANK.get(best, 0):
        best = "credential"
    return best

def readable_line(ctx):
    """'.npmrc (2 npm registry tokens), build.sh (source) readable; package.json 403, .env 404 not readable'"""
    good, empty, bad = [], [], []
    sc = _secret_counts(ctx.secrets)
    for it in ctx.items:
        name = urllib.parse.urlsplit(it["url"]).path.lstrip("/") or it["url"]
        if it["url"] == ctx.url:
            continue
        if it["kind"] in ("credential", "data", "source", "config", "internal"):
            secs = [f"{_plural(n, t)}" for (w, t), n in sc.items() if w == name]
            good.append(f"{name} ({'; '.join(secs) if secs else it['kind']}, {it['bytes']} bytes)")
        elif it["kind"] != "skipped" and it["status"] == 200:
            empty.append(f"{name} ({it['bytes']} bytes)")   # served, but empty, an error page or nothing of note
        elif it["kind"] != "skipped":
            bad.append(f"{name} {it['status'] if it['status'] is not None else it['note']}")
    out = []
    if good:
        out.append("readable: " + ", ".join(good))
    if empty:
        out.append("served but nothing of note: " + ", ".join(empty[:6]) + (" and more" if len(empty) > 6 else ""))
    if bad:
        out.append("not readable: " + ", ".join(bad[:8]) + (" and more" if len(bad) > 8 else ""))
    return "; ".join(out)

def trim_items(items):
    """At most MAX_ITEMS, in their original order; when there are more, items that showed nothing go first."""
    if len(items) <= MAX_ITEMS:
        return items
    keep = set(range(len(items)))
    for i in reversed(range(len(items))):
        if len(keep) <= MAX_ITEMS:
            break
        if items[i]["kind"] in ("nothing", "skipped", "error"):
            keep.discard(i)
    return [it for i, it in enumerate(items) if i in keep][:MAX_ITEMS]

def result(ctx, exposure, summary, fix):
    pci = bool(ctx.f.get("pci"))
    return {"exposure": exposure, "summary": R.redact(summary)[:600], "fix": R.redact(fix)[:600],
            "items": trim_items(ctx.items), "secrets": ctx.secrets[:50], "pci": pci}

def rotate_fix(ctx):
    sc = _secret_counts(ctx.secrets)
    if not sc:
        return ""
    parts = [f"the {_plural(n, t)} in {w}" for (w, t), n in sc.items()]
    return "Revoke and reissue " + ", ".join(parts) + " now (they were readable by anyone). "

def path_of(url):
    return urllib.parse.urlsplit(url).path or "/"

def dir_url(url):
    p = urllib.parse.urlsplit(url)
    d = p.path.rsplit("/", 1)[0] + "/"
    return urllib.parse.urlunsplit((p.scheme, p.netloc, d, "", ""))

# ---------------------------------------------------------------- 1. Dockerfile
_ECR = re.compile(r"(\d{12})\.dkr\.ecr\.([a-z0-9-]+)\.amazonaws\.com/([^\s:@]+)")

def _dockerfile_refs(text):
    stages, copies, scripts, moved, images = set(), [], [], [], []
    for raw_line in re.sub(r"\\\s*\n", " ", text).splitlines():
        line = raw_line.strip()
        m = re.match(r"(?i)FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?", line)
        if m:
            images.append(m.group(1))
            if m.group(2):
                stages.add(m.group(2).lower())
            continue
        m = re.match(r"(?i)(COPY|ADD)\s+(.*)", line)
        if m:
            args = m.group(2).split()
            if any(a.lower().startswith("--from") for a in args):
                continue
            args = [a for a in args if not a.startswith("--")]
            if args and args[0].startswith("["):
                try:
                    args = json.loads(" ".join(args))
                except Exception:
                    args = []
            for s in args[:-1]:
                s = s.strip("\"'")
                if s in (".", "./", "*") or s.startswith(("http://", "https://", "/")) or s.endswith("/"):
                    continue
                if s == "package*.json":
                    copies += ["package.json", "package-lock.json"]
                elif "*" not in s:
                    copies.append(s[2:] if s.startswith("./") else s)
            continue
        m = re.match(r"(?i)RUN\s+(.*)", line)
        if m:
            cmd = m.group(1)
            for sm in re.finditer(r"(?:^|[\s;&|(])(?:(?:ba)?sh\s+)?\.?/?((?:[\w.-]+/)*[\w.-]+\.sh)\b", cmd):
                scripts.append(sm.group(1))
            for mm in re.finditer(r"\b(?:mv|cp)\s+(?:-\w+\s+)*([\w./-]+)\s+([\w./-]+)", cmd):
                for p in mm.groups():
                    if "." in p and not p.startswith(("/", "$")) and not p.endswith("/") and p not in (".", "./"):
                        moved.append(p[2:] if p.startswith("./") else p)
    return images, copies, scripts, moved

def fam_dockerfile(ctx):
    images, copies, scripts, moved = _dockerfile_refs(ctx.body or "")
    facts = []
    for img in images:
        m = _ECR.search(img)
        if m:
            facts.append(f"base image {m.group(3)} from ECR registry account {m.group(1)} ({m.group(2)})")
        elif img.lower() not in ("scratch",):
            facts.append(f"base image {img}")
    ctx.note_internal(*facts)
    ctx.recorded("internal", "Dockerfile readable; " + "; ".join(facts[:4]))
    base = dir_url(ctx.url)
    wanted = list(dict.fromkeys(copies + scripts + moved + DOCKER_PROBES))
    for name in wanted:
        if not ctx.elapsed_ok():
            break
        ctx.take(ctx.resolve(name, base))
    exp = overall(ctx, "internal")
    named = ", ".join(dict.fromkeys(copies + scripts)) or "no local files"
    final_copy = re.search(r"(?i)COPY\s+--from=\S+\s+(\S+)\s+\.", ctx.body or "")
    summary = f"Dockerfile is public and names {named}; " + (readable_line(ctx) or "nothing it names is readable")
    if facts:
        summary += "; " + facts[0]
    fix = rotate_fix(ctx)
    fix += ("Stop serving the build context from the web root: the final stage copies the whole builder directory "
            f"({final_copy.group(1)}) into the document root, so build-only files (Dockerfile, .npmrc, *.sh, package*.json) are downloadable; "
            "copy only the built output, delete the build files in the image, or deny dotfiles and build files in the web server.") if final_copy else \
           ("Remove the Dockerfile and the build files it names from the document root (or deny them in the web server).")
    return result(ctx, exp, summary, fix)

# ---------------------------------------------------------------- 2. docker-compose
def fam_compose(ctx):
    body = ctx.body or ""
    env_files, vols, images, inline = [], [], [], []
    section = None
    for i, line in enumerate(body.splitlines(), 1):
        s = line.strip()
        m = re.match(r"^(\s*)([\w.-]+):\s*(.*)$", line)
        if m and not s.startswith("-"):
            key, val = m.group(2), m.group(3).strip()
            section = key if not val else None
            if key == "env_file" and val:
                env_files.append(val.strip("\"'"))
            elif key == "image" and val:
                images.append(val.strip("\"'"))
            elif section is None and val and R.secret_key(key) and R.find_secrets(f"{key}={val}"):
                inline.append(i)
            continue
        if s.startswith("-"):
            item = s[1:].strip().strip("\"'")
            if section == "env_file":
                env_files.append(item)
            elif section == "volumes":
                vols.append(item)
            elif section == "environment":
                k, sep, v = item.partition("=")
                if sep and v and R.find_secrets(f"{k}={v}"):
                    inline.append(i)
    for ln in inline:
        ctx.secrets.append({"type": "inline secret in environment", "where": path_of(ctx.url), "line": ln})
    host_paths = [v.split(":", 1)[0] for v in vols if ":" in v]
    sensitive = [h for h in host_paths if re.search(r"\.aws|\.ssh|credential|secret|\.env|docker\.sock|\.kube", h, re.I)]
    ctx.note_internal(*(f"image {x}" for x in images), *(f"mounts {h}" for h in host_paths))
    ctx.recorded("credential" if inline else "internal",
                 "docker-compose.yml readable; " + "; ".join(x for x in (f"images {', '.join(images)}" if images else "",
                                                                         f"host mounts {', '.join(host_paths[:6])}" if host_paths else "",
                                                                         f"env_file {', '.join(env_files)}" if env_files else "") if x))
    base = dir_url(ctx.url)
    for p in env_files:
        ctx.take(ctx.resolve(p, base))
    exp = overall(ctx, "internal")
    summary = "docker-compose.yml is public" + (f"; it mounts {', '.join(sensitive)} into the container" if sensitive else "") + \
              (f"; env_file {', '.join(env_files)}" if env_files else "") + (f"; {len(inline)} inline secret(s) in environment" if inline else "")
    rl = readable_line(ctx)
    if rl:
        summary += "; " + rl
    fix = rotate_fix(ctx) + "Remove docker-compose.yml (and the env files and mounts it names) from the document root or deny it in the web server" + \
          (f"; it also shows that the container mounts {', '.join(sensitive)}, so treat those credentials as known to an attacker and check what they can reach." if sensitive else ".")
    return result(ctx, exp, summary, fix)

# ---------------------------------------------------------------- 3. CI configuration
def fam_ci(ctx):
    body = ctx.body or ""
    sec = R.find_secrets(body, path_of(ctx.url))
    ctx.secrets.extend(sec)
    arns = sorted(set(re.findall(r"arn:aws:[a-z0-9-]+:[a-z0-9-]*:(\d{12}):", body)))
    buckets = sorted(set(re.findall(r"s3://([a-z0-9.-]{3,63})", body)))
    hosts = [h for h in R.internal_names(body, 12) if not re.fullmatch(r"\d{12}", h)]
    orbs = sorted(set(re.findall(r"^\s+\w+:\s*([\w-]+/[\w-]+@[\d.]+)", body, re.M)))
    ctx.note_internal(*(f"AWS account {a}" for a in arns), *(f"bucket {b}" for b in buckets), *hosts[:6], *(f"orb {o}" for o in orbs))
    facts = [x for x in (f"AWS accounts {', '.join(arns)}" if arns else "", f"buckets {', '.join(buckets)}" if buckets else "",
                         f"orbs {', '.join(orbs)}" if orbs else "", f"hosts {', '.join(hosts[:4])}" if hosts else "") if x]
    ctx.recorded("credential" if sec else "internal", "CI config readable; " + ("; ".join(facts) or "deploy pipeline layout"))
    base = urllib.parse.urljoin(ctx.url, "/")
    scripts = list(dict.fromkeys(m for m in re.findall(r"(?:^|\s)(?:bash\s+|sh\s+)?\.?/?((?:[\w.-]+/)*[\w.-]+\.sh)\b", body)))
    for s in scripts[:MAX_FETCHES]:
        ctx.take(ctx.resolve(s, base))
    exp = overall(ctx, "internal")
    summary = f"{path_of(ctx.url)} is public: the deploy pipeline" + (f" ({'; '.join(facts)})" if facts else "") + \
              (f"; {_plural(len(sec), 'inline secret')}" if sec else "; no inline secrets")
    rl = readable_line(ctx)
    if rl:
        summary += "; " + rl
    fix = rotate_fix(ctx) + f"Remove {path_of(ctx.url)} from the document root (it ships with the repository checkout) or deny the CI directories in the web server."
    return result(ctx, exp, summary, fix)

# ---------------------------------------------------------------- 4. .git
def fam_git(ctx):
    body = ctx.body or ""
    remotes = re.findall(r"(?im)^\s*url\s*=\s*(\S+)", body)
    for i, line in enumerate(body.splitlines(), 1):
        if re.match(r"(?i)^\s*url\s*=", line):
            u = line.split("=", 1)[1].strip()
            if re.match(r"(?i)^[a-z+]+://[^/@\s]+@", u):
                ctx.secrets.append({"type": "credential in git remote URL", "where": path_of(ctx.url), "line": i})
    safe_remotes = [re.sub(r"(?i)^([a-z+]+://)[^/@\s]+@", r"\1", u) for u in remotes]
    ctx.note_internal(*(f"git remote {u}" for u in safe_remotes))
    ctx.recorded("credential" if ctx.secrets else "internal", "git config readable; remote " + ", ".join(safe_remotes[:3]))
    gitdir = dir_url(ctx.url)
    st_head, head = ctx.get(ctx.resolve("HEAD", gitdir))
    ref = None
    if st_head == 200 and head and (head.startswith("ref:") or re.match(r"^[0-9a-f]{40}\s*$", head)):
        ref = head.strip().replace("ref: ", "")
        ctx.add(ctx.resolve("HEAD", gitdir), 200, len(head), "source", f"HEAD -> {ref}")
    else:
        ctx.add(ctx.resolve("HEAD", gitdir), st_head, len(head or ""), "nothing", f"{st_head}")
    st_idx, idx = ctx.get(ctx.resolve("index", gitdir), binary=True)
    index_ok = st_idx == 200 and idx and idx[:4] == b"DIRC"
    nfiles = struct.unpack(">I", idx[8:12])[0] if index_ok and len(idx) >= 12 else None
    ctx.add(ctx.resolve("index", gitdir), st_idx, len(idx or b""), "source" if index_ok else "nothing",
            f"index readable, {nfiles} tracked files" if index_ok else f"{st_idx}")
    st_pr, pr = ctx.get(ctx.resolve("packed-refs", gitdir))
    if st_pr == 200 and pr and re.search(r"^[0-9a-f]{40} refs/", pr, re.M):
        refs = re.findall(r"^[0-9a-f]{40} (refs/\S+)", pr, re.M)
        ctx.add(ctx.resolve("packed-refs", gitdir), 200, len(pr), "internal", f"{len(refs)} refs")
    else:
        ctx.add(ctx.resolve("packed-refs", gitdir), st_pr, len(pr or ""), "nothing", f"{st_pr}")
    st_lg, lg = ctx.get(ctx.resolve("logs/HEAD", gitdir))
    if st_lg == 200 and lg and re.search(r"^[0-9a-f]{40} [0-9a-f]{40} ", lg, re.M):
        authors = sorted(set(re.findall(r"<([^<>@\s]+@[^<>\s]+)>", lg)))
        ctx.note_internal(*(f"committer {a}" for a in authors))
        ctx.add(ctx.resolve("logs/HEAD", gitdir), 200, len(lg), "internal", f"{len(authors)} committer emails: " + ", ".join(authors[:5]))
    else:
        ctx.add(ctx.resolve("logs/HEAD", gitdir), st_lg, len(lg or ""), "nothing", f"{st_lg}")
    dumpable = bool(ref) and index_ok
    exp = "credential" if ctx.secrets else ("source" if dumpable else "internal")
    summary = ("The .git directory is public and the repository can be downloaded (HEAD " + ref + f", index of {nfiles} files)" if dumpable
               else "The .git config is public (remote " + ", ".join(safe_remotes[:2]) + ")" + ("; HEAD and index are not both readable, so the source cannot be rebuilt from here" if not dumpable else ""))
    if ctx.secrets:
        summary += "; the remote URL carries a credential"
    fix = ("Revoke the credential in the git remote URL. " if ctx.secrets else "") + \
          "Delete the .git directory from the deployed document root (deploy an export, not a checkout) or deny /.git in the web server" + \
          (", and assume the source code and its history are known to an attacker." if dumpable else ".")
    return result(ctx, exp, summary, fix)

# ---------------------------------------------------------------- 5. .svn/wc.db
def wcdb_parse(data):
    """(repository root URLs, [(local_relpath, checksum)]) from wc.db bytes; ([], []) when not SQLite."""
    if not data or not data.startswith(b"SQLite format 3"):
        return [], []
    fd, tmp = tempfile.mkstemp(suffix=".wcdb")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        db = sqlite3.connect(f"file:{tmp}?mode=ro", uri=True)
        try:
            roots = [r[0] for r in db.execute("SELECT root FROM REPOSITORY")]
        except sqlite3.Error:
            roots = []
        try:
            files = db.execute("SELECT local_relpath, checksum FROM NODES WHERE kind='file' ORDER BY local_relpath").fetchall()
        except sqlite3.Error:
            files = []
        db.close()
        return roots, files
    finally:
        os.unlink(tmp)

def rank_names(names):
    def score(n):
        b = n.rstrip("/").rsplit("/", 1)[-1]
        for i, rx in enumerate(SECRET_NAME):
            if rx.search(b):
                return i
        return len(SECRET_NAME)
    return sorted(names, key=lambda n: (score(n), n))

def fam_svn(ctx):
    st, data = ctx.get(ctx.url, binary=True, record=False)
    roots, files = wcdb_parse(data if st == 200 else b"")
    if not files and not roots:
        ctx.recorded("nothing" if st not in (None, 200) else "unknown", f"wc.db {'not readable' if st != 200 else 'not a readable SQLite database'} ({st})")
        return result(ctx, "unknown" if st is None else "nothing", f"{path_of(ctx.url)} could not be read as a Subversion database ({st})",
                      "Delete the .svn directory from the document root or deny /.svn in the web server.")
    safe_roots = [re.sub(r"(?i)^([a-z+]+://)[^/@\s]+@", r"\1", r) for r in roots]
    ctx.note_internal(*(f"svn repository {r}" for r in safe_roots))
    names = [f for f, _ in files]
    top = rank_names(names)[:6]
    ctx.add(ctx.url, 200, len(data), "internal", f"wc.db lists {len(files)} files from {', '.join(safe_roots[:2]) or 'an unnamed repository'}; e.g. {', '.join(top)}")
    first = next(((p, c) for p, c in sorted(files, key=lambda x: rank_names(names).index(x[0])) if c and c.startswith("$sha1$")), None)
    readable_source = False
    if first:
        sha = first[1][6:]
        purl = ctx.resolve(f"pristine/{sha[:2]}/{sha}.svn-base", dir_url(ctx.url))
        kind, text = ctx.take(purl)
        if kind in ("credential", "source", "config", "data", "internal"):
            readable_source = True
            ctx.items[-1]["note"] = R.redact(f"pristine copy of {first[0]}: " + ctx.items[-1]["note"])[:300]
    exp = overall(ctx, "source" if readable_source else "names")
    summary = f"The Subversion working-copy database is public: {len(files)} file names from {', '.join(safe_roots[:1]) or 'the repository'}" + \
              ("; pristine copies are downloadable, so the source can be rebuilt" if readable_source else "; the pristine copies were not readable")
    if ctx.secrets:
        summary += "; " + readable_line(ctx)
    fix = rotate_fix(ctx) + "Delete the .svn directory from the deployed document root (deploy an export, not a working copy) or deny /.svn in the web server" + \
          (", and assume the source code is known to an attacker." if readable_source else ".")
    return result(ctx, exp, summary, fix)

# ---------------------------------------------------------------- 6. listings
def _listing_targets(ctx, body, base):
    files, dirs = [], []
    for e in V.listing_entries(body):
        u = urllib.parse.urljoin(base, e)
        if not ctx.on_host(u):
            continue
        (dirs if e.endswith("/") else files).append((e, u))
    return files, dirs

def fam_listing(ctx, negotiation=False):
    base = ctx.url if ctx.url.endswith("/") else ctx.url + "/"
    if negotiation:
        names = V._variants(ctx.headers, ctx.body or "")
        stem = path_of(ctx.url).rstrip("/").rsplit("/", 1)[-1]
        base = dir_url(ctx.url)
        files = [(n, ctx.resolve(n, base)) for n in names if n.rsplit(".", 1)[-1].lower() not in V.DEFAULT_EXTS or n.rsplit(".", 1)[0] != stem]
        dirs = []
        ctx.recorded("names", "variants: " + ", ".join(names[:8]))
    else:
        files, dirs = _listing_targets(ctx, ctx.body or "", base)
        ctx.recorded("names", f"listing of {len(files)} files and {len(dirs)} directories")
    order = {n: i for i, n in enumerate(rank_names([n for n, _ in files]))}
    files.sort(key=lambda x: order[x[0]])
    for n, u in files:
        if not ctx.elapsed_ok():
            break
        ctx.take(u)
    # one level down into directories whose names suggest configuration, backups or keys
    for d, du in rank_names_pairs(dirs):
        if not ctx.elapsed_ok() or not SECRET_DIRS.fullmatch(d.rstrip("/").rsplit("/", 1)[-1] + "/"):
            continue
        st, sub = ctx.get(du)
        if st != 200 or not sub:
            ctx.add(du, st, len(sub or ""), "nothing", f"{st}")
            continue
        sf, sd = _listing_targets(ctx, sub, du)
        ctx.add(du, st, len(sub), "names", f"subdirectory listing: {len(sf)} files, {len(sd)} directories: " + ", ".join(rank_names([n for n, _ in sf])[:6]))
        sorder = {n: i for i, n in enumerate(rank_names([n for n, _ in sf]))}
        for n, u in sorted(sf, key=lambda x: sorder[x[0]]):
            if not ctx.elapsed_ok():
                break
            ctx.take(u)
    exp = overall(ctx, "names")
    unfetched = max(0, len(files) - sum(1 for it in ctx.items if it["url"] in {u for _, u in files}))
    what = "negotiation variants" if negotiation else "directory listing"
    summary = f"{path_of(ctx.url)} {what} is public ({len(files)} files" + (f", {len(dirs)} directories" if dirs else "") + ")"
    rl = readable_line(ctx)
    summary += ("; " + rl) if rl else "; no listed file was readable"
    if unfetched:
        summary += f"; {unfetched} more not fetched"
    fix = rotate_fix(ctx)
    if negotiation:
        fix += "Turn off MultiViews (Options -MultiViews) so Apache stops offering file variants, and move non-public files such as " + \
               ", ".join(n for n, _ in files[:3]) + " out of the document root."
    else:
        fix += f"Turn off directory indexes (Options -Indexes) for {path_of(ctx.url)} and move the files it lists out of the document root" + \
               (" (this is a PCI / strict-SLA host: the shorter SLA clock applies)." if ctx.f.get("pci") else ".")
    return result(ctx, exp, summary, fix)

def rank_names_pairs(pairs):
    order = {n: i for i, n in enumerate(rank_names([n for n, _ in pairs]))}
    return sorted(pairs, key=lambda x: order[x[0]])

# ---------------------------------------------------------------- 7. Claude Code files
def fam_claude(ctx):
    body = ctx.body or ""
    kind, note = R.classify(body, path_of(ctx.url))
    if kind == "nothing":
        ctx.recorded("nothing", note)
        return result(ctx, "nothing", f"{path_of(ctx.url)} does not return the file: the server answers with {note}",
                      "Nothing readable; no change needed beyond keeping .claude/ out of the document root.")
    perms, envs, mcps = [], [], []
    try:
        d = json.loads(body)
        perms = list(((d.get("permissions") or {}).get("allow") or []))
        envs = list((d.get("env") or {}).keys())
        mcps = list((d.get("mcpServers") or {}).keys())
        for name, srv in (d.get("mcpServers") or {}).items():
            blob = json.dumps(srv)
            for s in R.find_secrets(blob):
                ctx.secrets.append({"type": f"{s['type']} in MCP server {name}", "where": path_of(ctx.url), "line": 0})
    except Exception:
        pass
    for s in R.find_secrets(body, path_of(ctx.url)):
        if not any(x["line"] == s["line"] and x["line"] for x in ctx.secrets):
            ctx.secrets.append(s)
    paths = sorted(set(re.findall(r"(/(?:Users|home|opt|srv|var/www)/[\w./-]+)", body)))[:6]
    ctx.note_internal(*paths)
    ctx.recorded("credential" if ctx.secrets else "internal",
                 "; ".join(x for x in (f"{len(perms)} allowed tool permissions" if perms else "", f"env keys {', '.join(envs[:6])}" if envs else "",
                                        f"MCP servers {', '.join(mcps[:6])}" if mcps else "", f"paths {', '.join(paths[:3])}" if paths else "") if x) or note)
    exp = "credential" if ctx.secrets else "internal"
    summary = f"{path_of(ctx.url)} (Claude Code settings) is public" + (f"; {_plural(len(ctx.secrets), 'secret')} " + ", ".join(sorted({s['type'] for s in ctx.secrets})) if ctx.secrets else "") + \
              (f"; it names {len(perms)} allowed commands and internal paths {', '.join(paths[:3])}" if perms or paths else "")
    fix = rotate_fix(ctx) + "Remove the .claude/ directory and CLAUDE.md from the deployed document root and add them to the deploy ignore list."
    return result(ctx, exp, summary, fix)

# ---------------------------------------------------------------- 8. metrics
def fam_metrics(ctx):
    body = ctx.body or ""
    series = [l for l in body.splitlines() if l and not l.startswith("#")]
    jobs = sorted(set(re.findall(r'\bjob="([^"]+)"', body)))
    insts = sorted(set(re.findall(r'\binstance="([^"]+)"', body)))
    infos = []
    for m in re.finditer(r"^(\w+_(?:build|version)_info)\{([^}]*)\}", body, re.M):
        ver = re.search(r'version="([^"]+)"', m.group(2))
        infos.append(f"{m.group(1).replace('_build_info', '').replace('_version_info', '')} {ver.group(1) if ver else ''}".strip())
    labels = " ".join(re.findall(r'="([^"]*)"', body))
    for s in R.find_secrets(labels):
        ctx.secrets.append({"type": f"{s['type']} in a metric label", "where": path_of(ctx.url), "line": 0})
    prefix = sorted({l.split("_", 1)[0] for l in series if "_" in l})[:5]
    ctx.note_internal(*infos[:8], *(f"job {j}" for j in jobs[:8]), *(f"instance {i}" for i in insts[:8]))
    ctx.recorded("credential" if ctx.secrets else "internal",
                 f"{len(series)} series; " + "; ".join(x for x in (f"versions {', '.join(infos[:6])}" if infos else "", f"jobs {', '.join(jobs[:6])}" if jobs else "",
                                                                      f"instances {', '.join(insts[:6])}" if insts else "") if x))
    exp = "credential" if ctx.secrets else "internal"
    summary = f"{path_of(ctx.url)} serves {len(series)} metric series without authentication" + \
              (f" ({', '.join(infos[:4])})" if infos else (f" (prefixes {', '.join(prefix)})" if prefix else "")) + \
              (f"; {len(jobs)} jobs and {len(insts)} instances named" if jobs or insts else "") + \
              (f"; a label carries a secret" if ctx.secrets else "; no secrets in labels")
    fix = rotate_fix(ctx) + f"Put {path_of(ctx.url)} behind authentication or bind it to the internal network only; it tells an attacker the exact software versions and internal layout."
    return result(ctx, exp, summary, fix)

# ---------------------------------------------------------------- 9. single-response families
_PHPINFO_ROW = re.compile(r'<tr><td class="e">\s*([^<]+?)\s*</td><td class="v">\s*(.*?)\s*</td>', re.S)

def fam_phpinfo(ctx):
    body = ctx.body or ""
    hits = []
    for k, v in _PHPINFO_ROW.findall(body):
        key = re.sub(r"^\$_(?:SERVER|ENV)\['|'\]$", "", k.strip())
        val = re.sub(r"<[^>]+>", "", v).strip()
        if val and val.lower() not in ("no value", "") and R.secret_key(key) and not R._NOT_A_VALUE.fullmatch(val) and len(val) >= 4:
            hits.append(key)
    for k in dict.fromkeys(hits):
        ctx.secrets.append({"type": "secret in PHP environment", "where": k, "line": 0})
    ver = re.search(r"PHP Version\s*(?:</[^>]+>\s*<[^>]+>\s*)?([\d.]+)", body)
    docroot = re.search(r"DOCUMENT_ROOT\s*</td><td class=\"v\">\s*([^<]+)", body)
    facts = [x for x in (f"PHP {ver.group(1)}" if ver else "", f"document root {docroot.group(1).strip()}" if docroot else "") if x]
    ctx.note_internal(*facts)
    ctx.recorded("credential" if ctx.secrets else "internal", "phpinfo output; " + "; ".join(facts) + (f"; secret-looking keys with values: {', '.join(dict.fromkeys(hits))}" if hits else ""))
    exp = "credential" if ctx.secrets else "internal"
    summary = f"{path_of(ctx.url)} prints phpinfo()" + (f" ({'; '.join(facts)})" if facts else "") + \
              (f"; environment keys holding secrets: {', '.join(list(dict.fromkeys(hits))[:6])}" if hits else "; no secret-looking environment values")
    fix = ("Rotate the values of " + ", ".join(list(dict.fromkeys(hits))[:6]) + " (they were printed to anyone). " if hits else "") + \
          f"Delete {path_of(ctx.url)}; phpinfo pages must not be deployed."
    return result(ctx, exp, summary, fix)

def fam_laravel_debug(ctx):
    body = ctx.body or ""
    can = re.search(r'"can_execute_commands"\s*:\s*(true|false)', body)
    ctx.recorded("config", "Ignition health check answers" + (f"; can_execute_commands={can.group(1)}" if can else ""))
    for s in R.find_secrets(body, path_of(ctx.url)):
        ctx.secrets.append(s)
    exp = "credential" if ctx.secrets else "config"
    summary = "Laravel runs with debug mode on (Ignition answers at " + path_of(ctx.url) + ")" + \
              ("; Ignition reports it can execute commands, the precondition for CVE-2021-3129 on old Ignition versions" if can and can.group(1) == "true" else "") + \
              "; error pages will print the environment, including database and app keys"
    fix = rotate_fix(ctx) + "Set APP_DEBUG=false in production and remove facade/ignition from production dependencies; then rotate APP_KEY and the database password if any error page was ever served."
    return result(ctx, exp, summary, fix)

def fam_horizon(ctx):
    body = ctx.body or ""
    try:
        d = json.loads(body)
    except Exception:
        d = {}
    keys = ", ".join(f"{k}={d[k]}" for k in list(d)[:6]) if isinstance(d, dict) else ""
    ctx.recorded("internal", "Horizon stats readable" + (f": {keys}" if keys else ""))
    summary = "Laravel Horizon's dashboard API answers without login (" + path_of(ctx.url) + ")" + (f": {keys}" if keys else "") + \
              "; the dashboard can also show job payloads and retry or delete jobs"
    fix = "Restrict Horizon with the viewHorizon gate (or remove the route) in production; job payloads often carry customer data."
    return result(ctx, "internal", summary, fix)

def fam_graphiql(ctx):
    ctx.recorded("internal", "GraphiQL page served")
    gql = ctx.resolve("/graphql")
    st, text = ctx.get(gql, data=json.dumps({"query": "{__schema{types{name}}}"}).encode())
    ntypes = None
    if st == 200 and text:
        try:
            ntypes = len(json.loads(text)["data"]["__schema"]["types"])
        except Exception:
            ntypes = None
    ctx.add(gql, st, len(text or ""), "internal" if ntypes else "nothing",
            f"introspection answered: {ntypes} types" if ntypes else f"introspection not answered ({st})")
    exp = "internal"
    summary = f"GraphiQL is public at {path_of(ctx.url)}" + (f"; schema introspection answers ({ntypes} types), so the whole API surface is listed" if ntypes
                                                              else "; introspection did not answer on /graphql")
    fix = "Disable GraphiQL in production and turn off schema introspection for unauthenticated clients."
    return result(ctx, exp, summary, fix)

def fam_google_key(ctx):
    body = ctx.body or ""
    for s in R.find_secrets(body, path_of(ctx.url)):
        if s["type"] == "Google API key":
            ctx.secrets.append({**s, "where": "page source of " + path_of(ctx.url)})
    ctx.recorded("credential" if ctx.secrets else "internal", f"{_plural(len(ctx.secrets), 'Google API key')} in the page")
    summary = f"{_plural(len(ctx.secrets) or 1, 'Google API key')} sits in the page source of {path_of(ctx.url)}"
    fix = "In the Google Cloud console restrict the key to this site's HTTP referrers and to the APIs the page uses (or rotate it if it is unrestricted); browser keys cannot be hidden, only restricted."
    return result(ctx, "credential" if ctx.secrets else "internal", summary, fix)

def ds_store_names(data):
    names = []
    for m in re.finditer(rb"\x00\x00\x00([\x01-\xff])((?:\x00[\x20-\x7e]){1,255})(Iloc|bwsp|lsvp|lsvP|icvp|dscl|fwi0|fwsw|fwvh|glvp|GRP0|icgo|icsp|icvo|icvt|info|logS|lg1S|lssp|lsvo|lsvt|modD|moDD|ph1S|pict|vSrn|BKGD|cmmt|dilc|extn|ptbL|ptbN|vstl)", data or b""):
        n = m.group(1)[0]
        s = m.group(2)
        if len(s) == 2 * n:
            name = s.decode("utf-16-be", "replace")
            if name not in names and name not in (".", ".."):
                names.append(name)
    return names

def fam_ds_store(ctx):
    st, data = ctx.get(ctx.url, binary=True, record=False)
    names = ds_store_names(data if st == 200 else b"")
    ctx.add(ctx.url, st, len(data or b""), "names" if names else "nothing", f".DS_Store names {len(names)} entries: " + ", ".join(rank_names(names)[:8]))
    base = dir_url(ctx.url)
    for n in rank_names(names):
        if not ctx.elapsed_ok():
            break
        if "." not in n:   # most likely a directory
            continue
        ctx.take(ctx.resolve(urllib.parse.quote(n), base))
    exp = overall(ctx, "names" if names else "nothing")
    summary = f".DS_Store at {path_of(ctx.url)} names {len(names)} entries" + ((": " + ", ".join(rank_names(names)[:6])) if names else "")
    rl = readable_line(ctx)
    if rl:
        summary += "; " + rl
    fix = rotate_fix(ctx) + "Delete .DS_Store files from the deployed assets and add them to the deploy ignore list."
    return result(ctx, exp, summary, fix)

def fam_package_json(ctx):
    body = ctx.body or ""
    facts = []
    try:
        d = json.loads(body)
        if d.get("name"):
            facts.append(f"package {d['name']} {d.get('version', '')}".strip())
        deps = len(d.get("dependencies") or {}) + len(d.get("devDependencies") or {}) + len(d.get("packages") or {})
        if deps:
            facts.append(f"{deps} dependencies")
        scoped = sorted({k.split("/")[0] for k in list((d.get("dependencies") or {})) + list((d.get("packages") or {})) if k.startswith("@") or "node_modules/@" in k})
        regs = sorted(set(re.findall(r'"resolved"\s*:\s*"https?://([^/"]+)', body)) - {"registry.npmjs.org"})
        if regs:
            facts.append("private registries " + ", ".join(regs[:4]))
    except Exception:
        pass
    for s in R.find_secrets(body, path_of(ctx.url)):
        ctx.secrets.append(s)
    ctx.note_internal(*facts)
    ctx.recorded("credential" if ctx.secrets else "internal", "; ".join(facts) or "package manifest")
    exp = "credential" if ctx.secrets else "internal"
    summary = f"{path_of(ctx.url)} is public" + (f" ({'; '.join(facts)})" if facts else "") + ": the exact dependency versions an attacker can match to known CVEs"
    fix = rotate_fix(ctx) + f"Remove {path_of(ctx.url)} from the document root (serve only the built bundle) or deny it in the web server."
    return result(ctx, exp, summary, fix)

def fam_recorded(ctx, fix_default):
    """web-config, node-express-dev-env, and anything else: classify the recorded response."""
    body = ctx.body or ""
    if ctx.status is None:
        ctx.recorded("unknown", "no response recorded")
        return result(ctx, "unknown", ctx.f.get("title") or "no response recorded", fix_default)
    kind, note = R.classify(body, path_of(ctx.url))
    ctx.secrets.extend(R.find_secrets(body, path_of(ctx.url)))
    names = R.internal_names(body, 6)
    stack = sorted(set(re.findall(r"(?:at\s+\S+\s+\()?(/(?:app|usr|home|var|srv|opt)/[\w./-]+\.(?:js|ts|php|py|rb))", body)))[:4]
    if stack:
        names = stack + names
    if kind == "nothing" and urllib.parse.urlsplit(ctx.url).path in ("", "/"):
        kind, note = "internal", "header or banner match at the site root"
    ctx.recorded(kind, note + ("; names " + ", ".join(names[:5]) if names and kind in ("internal", "config", "source") else ""))
    exp = "credential" if ctx.secrets else kind
    summary = f"{path_of(ctx.url)}: {note}" + (f"; reveals {', '.join(names[:4])}" if names else "")
    return result(ctx, exp, summary, rotate_fix(ctx) + fix_default)

def fam_debug_headers(ctx):
    names = sorted(k for k in ctx.headers if k.startswith("fastly-debug") or k in ("x-served-by", "x-cache", "fastly-debug-path"))
    ctx.recorded("internal", "response headers " + ", ".join(names[:6]) if names else "debug headers")
    summary = "The CDN returns its debug headers (" + (", ".join(names[:4]) or "Fastly-Debug-*") +               ") to anyone who asks with Fastly-Debug: 1: internal cache node path, TTLs and cache keys; no data or secrets"
    fix = "Ignore the Fastly-Debug request header for public traffic (unset req.http.Fastly-Debug in vcl_recv) or strip the Fastly-Debug-* response headers in vcl_deliver."
    return result(ctx, "internal", summary, fix)

# ---------------------------------------------------------------- 10. xss
XSS_MARKERS = ["<svg/onload=confirm(", "<svg/onload=alert(", "<svg onload=alert(", "<script>alert(", "onerror=alert("]

def fam_xss(ctx):
    body = ctx.body or ""
    ctype = (ctx.headers.get("content-type") or "").lower()
    q = urllib.parse.parse_qs(urllib.parse.urlsplit(ctx.url).query)
    hits = []
    for marker in XSS_MARKERS:
        for m in re.finditer(re.escape(marker), body, re.I):
            tail = body[m.end():m.end() + 40]
            pm = re.match(r"'xss-([\w-]+)'", tail)
            param = pm.group(1) if pm else next((k for k, vs in q.items() if any(marker.lower() in v.lower() for v in vs)), "?")
            close = body.find(">", m.end())
            before = body[max(0, m.start() - 60):m.start()]
            after = body[close + 1:close + 1 + 60] if close >= 0 else ""
            # the payload is cut out of the excerpt: what stays is where the parameter lands in the page
            hits.append((param, re.sub(r"\s+", " ", (before + "[payload]" + after)).strip()))
    confirmed = bool(hits) and "html" in ctype
    if confirmed:
        for p, ex in hits[:6]:
            ctx.add(ctx.url, ctx.status, len(body), "source", f"parameter {p} reflected unescaped: {ex}")
        params = list(dict.fromkeys(p for p, _ in hits))
        summary = f"Reflected XSS confirmed: parameter{'s' if len(params) > 1 else ''} {', '.join(params)} on {path_of(ctx.url)} {'come' if len(params) > 1 else 'comes'} back unescaped in an HTML page" + \
                  (" (a login page, so a crafted link can capture credentials)" if re.search(r"type=[\"']?password", body, re.I) else "")
        fix = f"HTML-encode {', '.join(params)} where the page writes {'them' if len(params) > 1 else 'it'} back (attribute and body context), and add a Content-Security-Policy that blocks inline script."
        return result(ctx, "source", summary, fix)
    ctx.recorded("nothing", "payload marker not found unescaped in an HTML response" if body else "no response body recorded")
    summary = "Not confirmed: the recorded response does not contain the payload unescaped in HTML" if body else "Not confirmed: no response body recorded"
    return result(ctx, "nothing" if body else "unknown", summary, "Re-test the parameters by hand; no change is needed if the payload is encoded.")

# ---------------------------------------------------------------- 11. open ports
def mysql_parse(data):
    if not data or len(data) < 5:
        return "nothing", "no greeting"
    payload = data[4:4 + int.from_bytes(data[:3], "little")]
    if payload[:1] == b"\xff":
        code = int.from_bytes(payload[1:3], "little")
        msg = payload[3:].decode("latin-1", "replace")
        msg = msg[6:] if msg.startswith("#") else msg
        if code == 1130:
            return "rejected", f"MySQL error 1130: {msg.strip()[:120]}"
        return "auth", f"MySQL error {code}: {msg.strip()[:120]}"
    if payload[:1] == b"\x0a":
        ver = payload[1:payload.index(b"\x00", 1)].decode("latin-1", "replace")
        plugin = re.findall(rb"([a-z_]+_password|caching_sha2_password|mysql_native_password|auth_[a-z_]+)\x00", payload)
        return "auth", f"MySQL {ver} greeting" + (f", auth plugin {plugin[-1].decode()}" if plugin else "") + "; asks for a password"
    return "banner", f"unexpected MySQL reply ({len(data)} bytes)"

def pg_startup():
    body = struct.pack(">I", 196608) + b"user\x00scan\x00database\x00scan\x00\x00"
    return struct.pack(">I", len(body) + 4) + body

def pg_parse(data):
    if not data:
        return "nothing", "no answer to StartupMessage"
    t = data[:1]
    if t == b"R" and len(data) >= 9:
        code = struct.unpack(">I", data[5:9])[0]
        names = {0: "trust (no password)", 3: "cleartext password", 5: "MD5 password", 10: "SCRAM-SHA-256", 7: "GSSAPI", 9: "SSPI"}
        if code == 0:
            return "open", "PostgreSQL admitted the scanner without a password (trust)"
        return "auth", f"PostgreSQL asks for {names.get(code, f'auth type {code}')}"
    if t == b"E":
        fields = dict((f[:1].decode("latin-1"), f[1:].decode("latin-1", "replace")) for f in data[5:].split(b"\x00") if f)
        msg = fields.get("M", "")
        if "pg_hba.conf" in msg:
            return "rejected", f"PostgreSQL error: {re.sub(r'host \"[^\"]+\"', 'host <scanner>', msg)[:160]}"
        return "auth", f"PostgreSQL error {fields.get('C', '')}: {msg[:160]}"
    return "banner", f"unexpected PostgreSQL reply ({len(data)} bytes)"

def smb_negotiate():
    dialects = [0x0202, 0x0210, 0x0300, 0x0302]
    hdr = b"\xfeSMB" + struct.pack("<H", 64) + b"\x00" * 2 + b"\x00" * 4 + struct.pack("<H", 0) + struct.pack("<H", 1) + b"\x00" * 4 + b"\x00" * 4 + \
          struct.pack("<Q", 0) + b"\x00" * 4 + b"\x00" * 4 + b"\x00" * 8 + b"\x00" * 16
    body = struct.pack("<HHHH", 36, len(dialects), 1, 0) + b"\x00" * 4 + b"\x11" * 16 + b"\x00" * 8 + b"".join(struct.pack("<H", d) for d in dialects)
    msg = hdr + body
    return b"\x00" + len(msg).to_bytes(3, "big") + msg

def smb_parse(data):
    if not data or len(data) < 4 + 64 + 6:
        return "nothing", "no SMB negotiate reply"
    smb = data[4:]
    if smb[:4] == b"\xffSMB":
        return "auth", "SMB1 only (answers the negotiate in SMB1)"
    if smb[:4] != b"\xfeSMB":
        return "banner", "not an SMB reply"
    status = struct.unpack("<I", smb[8:12])[0]
    body = smb[64:]
    if status != 0 or len(body) < 6:
        return "auth", f"SMB negotiate status 0x{status:08x}"
    sec_mode, dialect = struct.unpack("<HH", body[2:6])
    d = {0x0202: "2.0.2", 0x0210: "2.1", 0x0300: "3.0", 0x0302: "3.0.2", 0x0311: "3.1.1", 0x02ff: "2.x"}.get(dialect, hex(dialect))
    return "auth", f"SMB {d} negotiated, signing {'required' if sec_mode & 0x02 else 'not required'}; asks for a login"

def default_probe(host, port):
    """One handshake, PROBE_TIMEOUT s, no credentials. (kind, detail): auth | rejected | open | banner | nothing."""
    try:
        with socket.create_connection((host, port), timeout=PROBE_TIMEOUT) as s:
            s.settimeout(PROBE_TIMEOUT)
            if port == 5432:
                s.sendall(pg_startup())
                return pg_parse(_recv(s))
            if port == 445:
                s.sendall(smb_negotiate())
                return smb_parse(_recv(s))
            data = _recv(s)
            if port == 3306:
                return mysql_parse(data)
            if not data:
                return "nothing", "connected, no banner within 5 s"
            return "banner", R.redact(data.decode("latin-1", "replace").strip())[:200]   # redact, then cut
    except socket.timeout:
        return "nothing", "no answer within 5 s"
    except OSError as e:
        return "nothing", f"connection failed: {type(e).__name__}"

def _recv(s, n=4096):
    try:
        return s.recv(n)
    except socket.timeout:
        return b""

PORT_NAME = {3306: "MySQL", 5432: "PostgreSQL", 445: "SMB", 1433: "SQL Server", 27017: "MongoDB", 6379: "Redis", 9200: "Elasticsearch",
             5900: "VNC", 3389: "RDP", 23: "Telnet", 21: "FTP"}

def fam_port(ctx, probe):
    raw = ctx.raw
    port = ctx.f.get("port") or raw.get("port")
    target = raw.get("ip") or ctx.host
    try:
        if probe is None:
            # resolve once, check with the scope, connect to that address (never a name re-resolved later)
            addr = SF.checked_address(target, ctx.host)
            kind, detail = default_probe(addr, port)
        else:
            kind, detail = probe(target, port)
    except SF.Refused as ex:
        kind, detail = "nothing", f"not probed: {ex}"
    except Exception as ex:
        kind, detail = "nothing", f"probe failed: {type(ex).__name__}"
    detail = R.redact(detail or "")
    exp = {"auth": "internal", "banner": "internal", "rejected": "nothing", "open": "credential", "nothing": "nothing"}.get(kind, "unknown")
    svc = PORT_NAME.get(port, f"port {port}")
    ctx.add(f"tcp://{target}:{port}", None, None, exp, detail)
    if kind == "open":
        ctx.secrets.append({"type": f"{svc} admits without authentication", "where": f"{target}:{port}", "line": 0})
    summary = {"auth": f"{svc} on {target}:{port} answers from the internet and asks for a login ({detail})",
               "banner": f"{svc} on {target}:{port} answers from the internet ({detail})",
               "rejected": f"{svc} on {target}:{port} accepts the TCP connection but rejects the scanner's address ({detail})",
               "open": f"{svc} on {target}:{port} admits a client WITHOUT authentication ({detail})",
               "nothing": f"{svc} on {target}:{port}: {detail}"}.get(kind, f"{svc} on {target}:{port}: {detail}")
    fix = (f"Close {port}/tcp to the internet at the security group or firewall; if remote access is needed, allow only the office/VPN ranges. "
           + ("It admits without a password: lock it down today and check it for tampering." if kind == "open"
              else "Even with a login in front, an internet-facing database or file share invites password guessing and protocol exploits."
              if kind in ("auth", "banner") else "The service already filters by source address, so this is defence in depth: close the port anyway."))
    return result(ctx, exp, summary, fix)

# ---------------------------------------------------------------- 12. legacy TLS
LEGACY_FIX = "Disable SSLv3, TLS 1.0 and TLS 1.1 on the TLS terminator (load balancer, CDN or web server) and keep TLS 1.2 and 1.3; PCI DSS requires it."

def fam_legacy(ctx):
    protos = (ctx.raw or {}).get("protocols") or []
    port = ctx.f.get("port") or 443
    summary = f"{', '.join(protos) or 'Legacy TLS'} still offered on port {port}; no data is exposed, but old protocol versions weaken every connection"
    ctx.add(f"tls://{ctx.host}:{port}", None, None, "nothing", ", ".join(protos))
    return result(ctx, "nothing", summary, LEGACY_FIX)

# ---------------------------------------------------------------- dispatch
def family(f, raw):
    tid = V._template(f, raw or {})
    src = f.get("source")
    url = (V._url(f, raw) or "").lower()
    if src == "nmap":
        return "port"
    if src == "sslscan" and f.get("check_id") == "legacy-protocol":
        return "legacy"
    if src != "nuclei":
        return "generic"
    if "dockerfile" in tid:
        return "dockerfile"
    if "docker-compose" in tid:
        return "compose"
    if "circleci" in tid or "gitlab-ci" in tid or "travis" in tid or "github-workflow" in tid or "/.github/workflows" in url:
        return "ci"
    if tid == "git-config" or url.endswith("/.git/config"):
        return "git"
    if "svn" in tid and "wc" in tid:
        return "svn"
    if tid == "apache-mod-negotiation-listing":
        return "negotiation"
    if tid.endswith("-listing") or "listing" in {t.lower() for t in f.get("tags") or []}:
        return "listing"
    if tid.startswith("claude-") or "/.claude/" in url or url.endswith("/claude.md"):
        return "claude"
    if "metrics" in tid:
        return "metrics"
    if tid.startswith("phpinfo"):
        return "phpinfo"
    if tid == "laravel-debug-enabled":
        return "laravel-debug"
    if tid == "laravel-horizon-unauth":
        return "horizon"
    if "graphiql" in tid or "graphql-playground" in tid:
        return "graphiql"
    if tid == "google-api-key":
        return "google-key"
    if tid == "ds-store-file":
        return "ds-store"
    if tid == "package-json":
        return "package-json"
    if tid.startswith("fastly-debug"):
        return "debug-headers"
    if tid == "xss-fuzz" or ("xss" in {t.lower() for t in f.get("tags") or []} and "fuzz" in tid):
        return "xss"
    return "recorded"

FIX_DEFAULT = {
    "web-config": "Remove web.config from what the server returns (it is a server file; on IIS it is never served, so this host is not IIS and the file was copied by mistake).",
    "node-express-dev-env": "Run Express with NODE_ENV=production so error pages stop printing stack traces and file paths.",
}

def triage(finding, raw, verdict=None, fetch=None, probe=None):
    """See the module docstring. Never raises: a triage bug yields exposure 'unknown' and the finding keeps its score."""
    ctx = Ctx(finding, raw or {}, fetch)
    fam = family(finding, raw)
    try:
        if fam == "port":
            return fam_port(ctx, probe)
        if fam == "legacy":
            return fam_legacy(ctx)
        if fam == "dockerfile":
            return fam_dockerfile(ctx)
        if fam == "compose":
            return fam_compose(ctx)
        if fam == "ci":
            return fam_ci(ctx)
        if fam == "git":
            return fam_git(ctx)
        if fam == "svn":
            return fam_svn(ctx)
        if fam == "negotiation":
            return fam_listing(ctx, negotiation=True)
        if fam == "listing":
            return fam_listing(ctx)
        if fam == "claude":
            return fam_claude(ctx)
        if fam == "metrics":
            return fam_metrics(ctx)
        if fam == "phpinfo":
            return fam_phpinfo(ctx)
        if fam == "laravel-debug":
            return fam_laravel_debug(ctx)
        if fam == "horizon":
            return fam_horizon(ctx)
        if fam == "graphiql":
            return fam_graphiql(ctx)
        if fam == "google-key":
            return fam_google_key(ctx)
        if fam == "ds-store":
            return fam_ds_store(ctx)
        if fam == "package-json":
            return fam_package_json(ctx)
        if fam == "xss":
            return fam_xss(ctx)
        if fam == "debug-headers":
            return fam_debug_headers(ctx)
        tid = V._template(finding, raw or {})
        default = FIX_DEFAULT.get(tid) or finding.get("remediation") or "Remove the exposed file or endpoint from the internet-facing server."
        if fam == "generic":
            ctx.add(finding.get("matched") or ctx.host, None, None, "unknown", finding.get("title") or "")
            return result(ctx, "unknown", finding.get("title") or finding.get("check_id") or "", default)
        return fam_recorded(ctx, default)
    except Exception as ex:
        print(f"warn: triage {fam} {finding.get('check_id')}: {type(ex).__name__}", file=sys.stderr)   # the message can quote content
        return result(ctx, "unknown", f"triage failed ({type(ex).__name__}); see the finding description",
                      finding.get("remediation") or "Review by hand.")
