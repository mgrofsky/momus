#!/usr/bin/env python3
"""Shim test driver: runs the real recon.sh end to end with recording shims first on PATH, inside the scanner image
with --network none (see ../run_shim_tests.sh), and checks what reached each tool.

Every "never reaches" check is paired with a positive control in the same run, so a run that dies early cannot pass
by sending nothing. Names are invented (example.test); public addresses are well-known resolver addresses."""
import datetime, json, os, shutil, subprocess, sys, tempfile
# every job carries created_at (required; more than five minutes ahead is refused)
JOB_TIME = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

SRC = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))   # scanner/
SHIM_BIN = os.path.join(SRC, "tests", "shim", "bin")
sys.path.insert(0, os.path.join(SRC, "pipeline"))
import scope as S  # noqa: E402  the token derivation, exactly as the scanner uses it
SEVEN = ["default-login", "sqli", "rce", "lfi", "ssrf", "xss", "injection"]
NS_ADDR = "208.67.222.222"
HOSTILE_NS_DASH, HOSTILE_NS_PLUS = "-ohostile.example.test", "+hostile.example.test"
FLIP_NS = "10.0.0.54"

ENUM = ["www.example.test", "range.example.test", "excluded.example.test", "deep.excluded.example.test",
        "outside.test", "meta.example.test", "priv.example.test", "mixed.example.test",
        "unproven.test", "sub.unproven.test", "evil.example.test.outside.test", "www.badns.test",
        "alias.example.test", "twostep.example.test", "moved.example.test", "movedown.example.test",
        "www.flip.test", "www.added.test", "cdn.example.test", "cdnmoved.example.test", "mail.example.test"]
DNS = {
    "example.test": {"a": ["8.8.4.4"]},
    "www.example.test": {"a": ["8.8.8.8"]},                       # unverified: web checks, no port scan
    "range.example.test": {"a": ["94.140.14.14"]},                # in owned_ranges.txt: port scanned
    "excluded.example.test": {"a": ["94.140.14.20"]},
    "deep.excluded.example.test": {"a": ["94.140.14.21"]},
    "outside.test": {"a": ["94.140.14.22"]},
    "meta.example.test": {"a": ["169.254.169.254"]},
    "priv.example.test": {"a": ["10.1.2.3"]},
    "mixed.example.test": {"a": ["94.140.14.30", "10.0.0.9"]},
    "sub.unproven.test": {"a": ["94.140.14.40"]},
    "www.badns.test": {"a": ["94.140.14.50"]},
    "target.lab.test": {"a": ["172.30.5.10"]},
    # CNAME chains: an allowed alias of an excluded server, directly and in two steps
    "alias.example.test": {"a": ["94.140.14.70"], "cname": ["excluded.example.test"]},
    "twostep.example.test": {"a": ["94.140.14.71"], "cname": ["hop.example.test", "deep.excluded.example.test"]},
    # address drift (scenario H): moved to an unlisted public address / moved inside the owned range
    "moved.example.test": {"a": ["1.0.0.1"]},
    "movedown.example.test": {"a": ["94.140.14.61"]},
    # scenario P: a host under each further verified domain (flip.test is in every scope; added.test only in P)
    "mail.example.test": {"a": ["94.140.14.33"]},                  # resolves, serves no HTTP: DNS templates only
    "www.flip.test": {"a": ["94.140.14.80"]},
    "www.added.test": {"a": ["94.140.14.90"]},
    # scenario N: CDN-fronted by CNAME; the edge address rotated / the CNAME moved to another CDN
    "cdn.example.test": {"a": ["1.1.1.1"], "cname": ["d1.edge-cdn.test"]},
    "cdnmoved.example.test": {"a": ["1.0.0.2"], "cname": ["d2.other-cdn.test"]},
}
HTTP = ["example.test", "www.example.test", "range.example.test", "excluded.example.test", "outside.test", "meta.example.test",
        "priv.example.test", "mixed.example.test", "sub.unproven.test", "www.badns.test", "target.lab.test",
        "alias.example.test", "twostep.example.test", "moved.example.test", "movedown.example.test",
        "www.flip.test", "www.added.test", "cdn.example.test", "cdnmoved.example.test"]
APEXES = ["example.test", "unproven.test", "badns.test", "flip.test"]


def inventory(skip=(), ips=None):
    """An approved inventory as approve.py records it: every canned host with its canned addresses."""
    hosts = {h: {"ips": (ips or {}).get(h, d.get("a", [])), "class": "owned"} for h, d in DNS.items()
             if h not in skip and h != "target.lab.test"}
    return {"domains": APEXES, "lab_targets": [], "hosts": hosts}

results = []


def check(name, cond, detail=""):
    results.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name + (("  -- " + detail) if detail and not cond else ""))


class Run:
    def __init__(self, label, approval=True, profile=None, exclude_tags="keep", classify_fails=False, recheck_of=None,
                 inv=None, extra_domains=(), scope_files=None):
        self.label = label
        self.work = tempfile.mkdtemp(prefix=f"shim-{label}-")
        self.root = recheck_of.root if recheck_of else os.path.join(self.work, "root")
        self.scanner = os.path.join(self.work, "scanner")
        shutil.copytree(SRC, self.scanner, ignore=shutil.ignore_patterns("__pycache__", "out"))
        if exclude_tags == "missing":
            os.remove(os.path.join(self.scanner, "config", "exclude_tags.txt"))
        elif exclude_tags == "empty":
            open(os.path.join(self.scanner, "config", "exclude_tags.txt"), "w").write("# nothing\n\n")
        if classify_fails:
            open(os.path.join(self.scanner, "pipeline", "classify.py"), "w").write("import sys\nsys.exit('forced failure')\n")
        self.log = os.path.join(self.work, "log"); os.makedirs(self.log)
        self.canned = os.path.join(self.work, "canned.json")
        # the install secret the scanner would have created; the TXT records carry the tokens derived from it
        self.secret, _ = S.load_secret(os.path.join(self.root, "state"), create=True)
        tok = lambda apex: S.derive_token(self.secret, apex)  # noqa: E731
        json.dump({"enum": ENUM, "dns": DNS, "http": HTTP,
                   # the two odd names model a hostile NS answer: neither may reach dig as an argument
                   "ns": {"example.test": ["ns1.example.test", HOSTILE_NS_DASH, HOSTILE_NS_PLUS], "unproven.test": ["ns1.unproven.test"],
                          "badns.test": ["ns1.badns.test"], "flip.test": ["ns1.flip.test"]},
                   "ns_addr": {"ns1.example.test": [NS_ADDR], "ns1.unproven.test": [NS_ADDR], "ns1.badns.test": ["10.0.0.53"]},
                   # flip.test passes the DNS proof at a public nameserver address, which is private by phase 1
                   "ns_addr_seq": {"ns1.flip.test": [[NS_ADDR], [FLIP_NS]]},
                   "txt": {"_scan-verify.example.test": ["scan-verify=" + tok("example.test")],
                           "_scan-verify.flip.test": ["scan-verify=" + tok("flip.test")],
                           # unproven.test publishes example.test's token: a record valid for another domain
                           "_scan-verify.unproven.test": ["scan-verify=" + tok("example.test")],
                           # further domains (extra_domains) publish their own valid record
                           **{f"_scan-verify.{d}": ["scan-verify=" + tok(d)] for d in extra_domains}}}, open(self.canned, "w"))
        if extra_domains:
            c = json.load(open(self.canned))
            for d in extra_domains:
                c["ns"][d] = [f"ns1.{d}"]
                c["ns_addr"][f"ns1.{d}"] = [NS_ADDR]
            json.dump(c, open(self.canned, "w"))
        if recheck_of:
            return
        sc = os.path.join(self.root, "scope")
        os.makedirs(sc)
        open(os.path.join(sc, "domains.txt"), "w").write("example.test\nunproven.test\nbadns.test\nflip.test\n"
                                                         + "".join(d + "\n" for d in extra_domains))
        for name, text in (scope_files or {}).items():
            open(os.path.join(sc, name), "w").write(text)
        open(os.path.join(sc, "exclude.txt"), "w").write("excluded.example.test\n")
        open(os.path.join(sc, "owned_ranges.txt"), "w").write("94.140.14.0/24\n")
        ent = lambda apex, state, at=None: {"apex": apex, "statement": "I own this domain and the systems it points to.",
                                            "attested_by": "Test Owner", "attested_at": "2030-01-01T00:00:00Z",
                                            "key_id": S.key_id(self.secret), "state": state, "verified_at": at}
        # unproven.test has the ownership statement but no DNS proof (its TXT record carries another token);
        # badns.test was verified before, but its nameserver now sits on a private address
        import datetime as _dt
        recent = (_dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(days=1)).isoformat(timespec="seconds")
        json.dump({"entries": [ent("example.test", "pending"), ent("unproven.test", "pending"),
                               ent("badns.test", "verified", recent), ent("flip.test", "pending")]
                              + [ent(d, "pending") for d in extra_domains]},
                  open(os.path.join(sc, "ownership.json"), "w"))
        if approval:
            os.makedirs(os.path.join(self.root, "runs", "inv-0"))
            json.dump({"approved_at": "2030-01-02T00:00:00Z", "inventory_run": "inv-0", "approved_by": "Test Owner",
                       "inventory": inv or inventory()}, open(os.path.join(sc, "approval.json"), "w"))
        if profile:
            json.dump(profile, open(os.path.join(sc, "profile.json"), "w"))

    def run(self, *args, env=None):
        e = {"PATH": SHIM_BIN + ":" + os.environ["PATH"], "HOME": os.environ["HOME"], "SCAN_ROOT": self.root,
             "SHIM_LOG": self.log, "SHIM_CANNED": self.canned, "SCAN_RATE_PROFILE": "normal",
             "PYTHONDONTWRITEBYTECODE": "1", **(env or {})}
        p = subprocess.run(["bash", os.path.join(self.scanner, "recon.sh"), *args], env=e, stdin=subprocess.DEVNULL,
                           capture_output=True, text=True, timeout=900)
        self.rc, self.out = p.returncode, p.stdout + p.stderr
        self.calls = []
        cl = os.path.join(self.log, "calls.jsonl")
        if os.path.exists(cl):
            # the manifest asks each tool for its version (no target): not an invocation against anything
            self.calls = [c for c in (json.loads(l) for l in open(cl) if l.strip())
                          if not (c["argv"] and set(c["argv"]) <= {"-version", "--version", "-V"})]
        return self

    def recon_log(self, run_id):
        p = os.path.join(self.root, "runs", run_id, "recon.log")
        return open(p).read() if os.path.exists(p) else ""

    def manifest(self, run_id):
        p = os.path.join(self.root, "runs", run_id, "manifest.json")
        return json.load(open(p)) if os.path.exists(p) else {}

    def tools(self):
        return {c["tool"] for c in self.calls}

    def of(self, tool):
        return [c for c in self.calls if c["tool"] == tool]


def text_of(call):
    """Everything a tool received, minus the value of nuclei's -eh (that is the exclusion list itself)."""
    argv = list(call["argv"])
    if call["tool"] == "nuclei" and "-eh" in argv:
        i = argv.index("-eh"); argv[i + 1] = "<exclusions>"
    return "\n".join(argv) + "\n" + call["stdin"] + "\n" + "\n".join(call["files"].values())


def reached(run, token, tools=None):
    """Tools whose input contained token as a whole name or address."""
    import re
    pat = re.compile(r"(?<![A-Za-z0-9.-])" + re.escape(token) + r"(?![A-Za-z0-9-]|\.[A-Za-z0-9])")
    return sorted({c["tool"] for c in run.calls if (tools is None or c["tool"] in tools) and pat.search(text_of(c))})


def argval(call, flag):
    a = call["argv"]
    return a[a.index(flag) + 1] if flag in a else None


# ================================================================ scenario A: full run, approval, safe profile
print("== A: full run, approval present, check profile safe, rate profile normal")
A = Run("full").run("--run-id", "r-full")
check("A runs to completion (rc 0)", A.rc == 0, A.out[-2000:] + A.recon_log("r-full")[-3000:])
log = A.recon_log("r-full")
check("A prints the ownership rule at the start", "rule: This project should only be run on systems the person running the project explicitly owns." in log)
check("A logs the profiles in effect and how to change them", "profiles: checks=safe rates=normal" in log and "scope/profile.json" in log)
man = A.manifest("r-full")
check("A manifest records profiles and coverage", man.get("check_profile") == "safe" and man.get("rate_profile") == "normal"
      and set(man.get("coverage", {})) == {"dns", "http", "nmap", "sslscan", "nuclei", "nuclei_tp", "nuclei_dns", "nuclei_fp"},
      json.dumps(man.get("coverage")))
check("A manifest records the evidence level (default minimal)", man.get("evidence") == "minimal", str(man.get("evidence")))
# positive controls
check("A control: www.example.test reaches dnsx, httpx, whatweb, sslscan and nuclei",
      {"dnsx", "httpx-toolkit", "whatweb", "sslscan", "nuclei"} <= set(reached(A, "www.example.test")), str(reached(A, "www.example.test")))
check("A control: the owned-range address reaches nmap", reached(A, "94.140.14.14", {"nmap"}) == ["nmap"])
# 1. excluded names
for n in ("excluded.example.test", "deep.excluded.example.test"):
    check(f"1 excluded name {n} reaches no tool, not even the resolver", reached(A, n) == [], str(reached(A, n)))
check("1 nuclei -eh carries the exclusion list", all(argval(c, "-eh") == "excluded.example.test" for c in A.of("nuclei")) and A.of("nuclei"))
# 2. outside every apex
for n in ("outside.test", "evil.example.test.outside.test"):
    check(f"2 out-of-scope name {n} reaches no tool", reached(A, n) == [], str(reached(A, n)))
# 3. private / metadata answers
active_tools = {"httpx-toolkit", "sslscan", "nmap", "nuclei", "whatweb", "wafw00f"}
for n, ip in (("meta.example.test", "169.254.169.254"), ("priv.example.test", "10.1.2.3"), ("mixed.example.test", "10.0.0.9")):
    check(f"3 {n} ({ip}) reaches dnsx (control)", "dnsx" in reached(A, n))
    check(f"3 {n} never reaches the HTTP probe, TLS scan, port scan, nuclei or fingerprinting", reached(A, n, active_tools) == [], str(reached(A, n, active_tools)))
    check(f"3 address {ip} is never handed to any tool", reached(A, ip) == [], str(reached(A, ip)))
# 5. unverified host
check("5 www.example.test (no owned range, not approved) never reaches nmap", reached(A, "8.8.8.8", {"nmap"}) == [] and reached(A, "www.example.test", {"nmap"}) == [])
check("5 www.example.test does reach the web checks", {"httpx-toolkit", "whatweb", "nuclei"} <= set(reached(A, "www.example.test")))
# apex with a statement but no DNS proof
for n in ("unproven.test", "sub.unproven.test"):
    got = reached(A, n)
    check(f"DNS proof: {n} reaches only dig (the TXT lookup)", set(got) <= {"dig"}, str(got))
dig_unproven = [c for c in A.of("dig") if "unproven.test" in text_of(c)]
check("DNS proof: the only dig queries about unproven.test are NS, nameserver address and TXT lookups",
      dig_unproven and all(any(t in c["argv"] for t in ("NS", "A", "AAAA", "TXT")) and "axfr" not in c["argv"] for c in dig_unproven),
      str([c["argv"] for c in dig_unproven]))
check("DNS proof: the TXT question goes to the nameserver address without recursion",
      any("+norecurse" in c["argv"] and "@" + NS_ADDR in c["argv"] and "TXT" in c["argv"] for c in A.of("dig")))
check("DNS proof: the unproven apex is logged as refused and set to pending", "dns proof unproven.test: REFUSED" in log)
own = {e["apex"]: e for e in json.load(open(os.path.join(A.root, "scope", "ownership.json")))["entries"]}
check("DNS proof: a previously verified apex whose nameserver is now private is refused and no longer verified",
      "dns proof badns.test: REFUSED" in log and own["badns.test"]["state"] != "verified", own["badns.test"]["state"])
check("DNS proof: a name under that apex, arriving through another apex's enumeration, reaches no tool",
      reached(A, "www.badns.test") == [], str(reached(A, "www.badns.test")))
check("DNS proof: the private nameserver address is never asked", not any("@10.0.0.53" in c["argv"] for c in A.of("dig")))
check("DNS proof: example.test was verified at its own nameserver during the run", own["example.test"]["state"] == "verified")
# dnsrecon asks the apex's nameservers itself: it runs only when every nameserver address passes the check again
check("dnsrecon control: example.test reaches dnsrecon", any(argval(c, "-d") == "example.test" for c in A.of("dnsrecon")))
check("dnsrecon control: flip.test passed the DNS proof and reaches subfinder, assetfinder and crt.sh",
      own["flip.test"]["state"] == "verified" and {"subfinder", "assetfinder"} <= set(reached(A, "flip.test"))
      and any("%25.flip.test&" in c["argv"][-1] for c in A.of("curl")), str(reached(A, "flip.test")))
check("dnsrecon: an apex whose nameserver now sits on a private address never reaches dnsrecon",
      not any(argval(c, "-d") == "flip.test" for c in A.of("dnsrecon")) and "dnsrecon" not in reached(A, "flip.test"))
rej = [json.loads(l) for l in open(os.path.join(A.root, "runs", "r-full", "scope_rejected.jsonl")) if l.strip()]
check("dnsrecon: the skipped apex is logged in scope_rejected.jsonl with the nameserver address",
      any(r["what"] == "flip.test" and r["stage"] == "dnsrecon" and FLIP_NS in r["reason"] for r in rej),
      str([r for r in rej if r["what"] == "flip.test"]))
check("dnsrecon: the private nameserver address is never asked", not any("@" + FLIP_NS in c["argv"] for c in A.of("dig")))
# 7. safe profile tags
nuc = A.of("nuclei")
check("7 safe: every nuclei invocation excludes all seven active-only tags",
      nuc and all(set(SEVEN) <= set((argval(c, "-etags") or "").split(",")) for c in nuc), str([argval(c, "-etags") for c in nuc]))
check("7 safe: no nuclei invocation asks for an active-only tag",
      all(not (set(SEVEN) & set((argval(c, "-tags") or "").split(","))) for c in nuc))
check("7 interactsh off in every nuclei invocation", all("-ni" in c["argv"] for c in nuc))
# 8. redirect and rate options (normal profile)
hx = A.of("httpx-toolkit")
check("8 httpx: same-host redirects only, private addresses excluded, normal rates",
      hx and all("-fhr" in c["argv"] and "-follow-redirects" not in c["argv"] and argval(c, "-e") == "private-ips"
                 and argval(c, "-rl") == "200" and argval(c, "-t") == "80" and argval(c, "-timeout") == "8" for c in hx))
ww = A.of("whatweb")
check("8 whatweb: redirects off (--follow-redirect=never), threads and timeouts set",
      ww and all("--follow-redirect=never" in c["argv"] and argval(c, "--max-threads") == "25" and argval(c, "--open-timeout") == "15" for c in ww))
wf = A.of("wafw00f")
check("8 wafw00f: redirects off (-r)", wf and all("-r" in c["argv"] for c in wf))
check("8 nuclei: same-host redirects, local network refused, no update check, rate options",
      nuc and all("-fhr" in c["argv"] and "-lna" in c["argv"] and "-duc" in c["argv"] and argval(c, "-rl") and argval(c, "-c")
                  and argval(c, "-timeout") and argval(c, "-retries") == "1" for c in nuc))
check("8 httpx keeps its own resolvers outside lab mode (no -r)", hx and all("-r" not in c["argv"] for c in hx))
check("8 nuclei keeps its own resolvers outside lab mode: no pass gets -r (control: generic, tech, dns, fp ran; no shim "
      "scenario has a third-party host, so tp never runs here)",
      sorted(os.path.basename(argval(c, "-elog") or "?") for c in nuc) == sorted(f"nuclei_errors_{p}.jsonl" for p in ("generic", "tech", "dns", "fp"))
      and all("-r" not in c["argv"] and "-resolvers" not in c["argv"] for c in nuc),
      str([(argval(c, "-elog"), "-r" in c["argv"]) for c in nuc]))
check("8 dnsx keeps its own resolvers outside lab mode (no -r)", A.of("dnsx") and all("-r" not in c["argv"] for c in A.of("dnsx")))
covH = set(open(os.path.join(A.root, "runs", "r-full", "coverage", "http.txt")).read().split())
check("8 http coverage lists only the hosts httpx answered for (mail.example.test resolves but serves no HTTP)",
      "www.example.test" in covH and "mail.example.test" not in covH and "httpx-toolkit" in reached(A, "mail.example.test"),
      str(sorted(covH)))
check("8 every nuclei pass writes its own error log (-elog nuclei_errors_<pass>.jsonl)",
      nuc and all((argval(c, "-elog") or "") == "nuclei_errors_" + {"nuclei_owned.jsonl": "generic", "nuclei_tech.jsonl": "tech",
                  "nuclei_tp.jsonl": "tp", "nuclei_dns.jsonl": "dns", "nuclei_fp.jsonl": "fp"}.get(argval(c, "-o"), "?") + ".jsonl" for c in nuc),
      str([(argval(c, "-o"), argval(c, "-elog")) for c in nuc]))
covA = {x: set(open(os.path.join(A.root, "runs", "r-full", "coverage", x + ".txt")).read().split()) for x in ("nuclei", "nuclei_dns")}
check("8 nuclei coverage is per pass: the DNS-template pass is recorded apart from the HTTP passes",
      "www.example.test" in covA["nuclei"] and "mail.example.test" in covA["nuclei_dns"] and "mail.example.test" not in covA["nuclei"], str(covA))
gen = [c for c in nuc if argval(c, "-o") == "nuclei_owned.jsonl"]
check("8 nuclei generic pass uses the normal table (-rl 300 -c 50 -bs 50)", gen and argval(gen[0], "-rl") == "300" and argval(gen[0], "-c") == "50")
nm = A.of("nmap")
check("8 nmap: rate options from the table, addresses only", nm and all(argval(c, "--max-rate") == "200" and argval(c, "--max-parallelism") == "32"
      for c in nm))
check("8 sslscan: connect timeout set", A.of("sslscan") and all(any(a.startswith("--connect-timeout=") for a in c["argv"]) for c in A.of("sslscan")))
dx = [c for c in A.of("dnsx") if "-a" in c["argv"]]
check("8 dnsx: threads and retries from the table", dx and argval(dx[0], "-t") == "50" and argval(dx[0], "-retry") == "3")
check("8 AXFR asked of the checked nameserver address, never a name", all(any(a == "@" + NS_ADDR for a in c["argv"]) for c in A.of("dig") if "axfr" in c["argv"]) and any("axfr" in c["argv"] for c in A.of("dig")))
check("8 nameserver names that are not host names (leading - or +) never reach dig, in the DNS proof or the AXFR step",
      not any(a.startswith(("-ohostile", "+hostile")) for c in A.of("dig") for a in c["argv"]),
      str([c["argv"] for c in A.of("dig") if any("hostile" in a for a in c["argv"])])[:400])
rej = [json.loads(l) for l in open(os.path.join(A.root, "runs", "r-full", "scope_rejected.jsonl"))]
check("scope_rejected.jsonl records stage and reason for each rejection", rej and all(r.get("stage") and r.get("reason") for r in rej)
      and {"excluded.example.test", "outside.test"} <= {r["what"] for r in rej})

# CNAME chains: an allowed alias whose chain reaches an excluded name is refused like the excluded name
for n, ip in (("alias.example.test", "94.140.14.70"), ("twostep.example.test", "94.140.14.71")):
    check(f"CNAME {n} reaches dnsx (control: it was resolved)", "dnsx" in reached(A, n))
    check(f"CNAME {n} (chain reaches an excluded name) never reaches an HTTP, TLS, port or nuclei tool",
          reached(A, n, active_tools) == [], str(reached(A, n, active_tools)))
    check(f"CNAME {n}: its address {ip} is never handed to nmap", reached(A, ip, {"nmap"}) == [], str(reached(A, ip)))
check("CNAME: both refusals are logged with the excluded name in the chain",
      any(r["what"] == "alias.example.test" and "CNAME chain reaches excluded.example.test" in r["reason"] for r in rej)
      and any(r["what"] == "twostep.example.test" and "CNAME chain reaches deep.excluded.example.test" in r["reason"] for r in rej),
      str([r for r in rej if "CNAME" in r["reason"]]))
check("A: with an inventory listing every host, nothing is held back", man.get("held_back", {}).get("count") == 0, str(man.get("held_back")))
check("A manifest records the inventory it found (domains covered, hosts with addresses and class)",
      set((man.get("inventory") or {}).get("domains", [])) == {"example.test", "flip.test"}
      and (man.get("inventory") or {}).get("hosts", {}).get("www.example.test", {}).get("ips") == ["8.8.8.8"],
      json.dumps(man.get("inventory"))[:400])

# ================================================================ scenario D: recheck with planted entries
print("== D: recheck with unapproved entries planted in the recheck list")
open(os.path.join(A.root, "scope", "recheck_hosts.txt"), "w").write(
    "www.example.test\nexcluded.example.test\noutside.test\nsub.unproven.test\nplanted.elsewhere.test\n")
D = Run("recheck", recheck_of=A).run("--run-id", "r-recheck", "--recheck", "r-full")
check("D recheck runs (rc 0)", D.rc == 0, D.out[-1500:] + D.recon_log("r-recheck")[-2000:])
check("D control: www.example.test reaches dnsx and httpx", {"dnsx", "httpx-toolkit"} <= set(reached(D, "www.example.test")))
for n in ("excluded.example.test", "outside.test", "planted.elsewhere.test"):
    check(f"4 planted recheck entry {n} reaches no tool", reached(D, n) == [], str(reached(D, n)))
check("4 planted recheck entry sub.unproven.test reaches only dig (the TXT lookup)", set(reached(D, "sub.unproven.test")) <= {"dig"})

# ================================================================ scenario B: no approval
print("== B: no approval.json (rate profile low from the environment)")
B = Run("noapproval", approval=False).run("--run-id", "r-noappr", env={"SCAN_RATE_PROFILE": "low"})
check("B exits 0 as an inventory-only run", B.rc == 0 and B.manifest("r-noappr").get("inventory_only") is True
      and "approval.json" in (B.manifest("r-noappr").get("inventory_only_reason") or ""), B.out[-1500:])
check("B control: httpx and whatweb ran", {"httpx-toolkit", "whatweb"} <= B.tools())
check("6 without approval.json the port scanner and nuclei are never invoked", not ({"nmap", "nuclei"} & B.tools()), str(B.tools()))
check("8 low profile: httpx at a third of the normal rate", all(argval(c, "-rl") == "66" and argval(c, "-t") == "26" for c in B.of("httpx-toolkit")))
check("B log says inventory-only because approval is missing", "inventory-only: scope/approval.json is missing" in B.recon_log("r-noappr"))

# ================================================================ scenario C: active via profile.json
print("== C: check profile active from scope/profile.json (environment says safe)")
C = Run("active", profile={"check_profile": "active"}).run("--run-id", "r-active", env={"SCAN_CHECK_PROFILE": "safe", "SCAN_EVIDENCE": "excerpt"})
cn = C.of("nuclei")
check("C runs (rc 0)", C.rc == 0, C.out[-1500:])
check("7 active: no nuclei invocation excludes any of the seven tags",
      cn and all(not (set(SEVEN) & set((argval(c, "-etags") or "").split(","))) for c in cn), str([argval(c, "-etags") for c in cn]))
check("7 active: the generic pass asks for all seven", any(set(SEVEN) <= set((argval(c, "-tags") or "").split(",")) for c in cn))
check("7 active: the excluded-tags file still applies", all("intrusive" in (argval(c, "-etags") or "") for c in cn))
check("C manifest records check_profile active from scope/profile.json",
      C.manifest("r-active").get("check_profile") == "active" and C.manifest("r-active").get("profile_source") == "scope/profile.json")
check("C manifest records SCAN_EVIDENCE=excerpt", C.manifest("r-active").get("evidence") == "excerpt")

# ================================================================ fail closed
print("== F: excluded-tags file missing / empty; classification forced to fail")
for mode in ("missing", "empty"):
    F = Run("tags-" + mode, exclude_tags=mode).run("--run-id", "r-tags")
    check(f"excluded-tags file {mode}: run exits non-zero", F.rc != 0, F.out[-800:])
    check(f"excluded-tags file {mode}: nuclei is never invoked", "nuclei" not in F.tools())
G = Run("classify-fails", classify_fails=True).run("--run-id", "r-cls")
check("classification fails: run exits non-zero", G.rc != 0)
check("classification fails: control, httpx ran before it", "httpx-toolkit" in G.tools())
check("classification fails: no later tool is invoked", not ({"whatweb", "wafw00f", "nmap", "sslscan", "nuclei"} & G.tools()), str(G.tools()))

# ================================================================ 9. lab mode limits
print("== L: lab mode")
# the approval in a lab run must be bound to an inventory of the lab targets (approve.py bind_inventory)
L = Run("lab", inv={"domains": APEXES, "lab_targets": ["target.lab.test"],
                    "hosts": {"target.lab.test": {"ips": ["172.30.5.10"], "class": "owned"}}})
tf = os.path.join(L.work, "targets.txt"); open(tf, "w").write("target.lab.test\n")
for label, env, cidr in (("without SCAN_LAB=1", {}, "172.30.5.0/24"), ("with a public CIDR", {"SCAN_LAB": "1"}, "8.8.8.0/24"),
                         ("with a CIDR larger than /24", {"SCAN_LAB": "1"}, "172.30.0.0/23")):
    L.run("--run-id", "r-lab", "--targets-file", tf, "--lab-cidr", cidr, env=env)
    check(f"9 lab mode refuses to start {label}", L.rc != 0 and L.calls == [], f"rc={L.rc} tools={L.tools()}")
L.run("--run-id", "r-lab", "--targets-file", tf, "--lab-cidr", "172.30.5.0/24", env={"SCAN_LAB": "1"})
check("lab control: a valid lab run probes the lab target", L.rc == 0 and "httpx-toolkit" in reached(L, "target.lab.test"), L.out[-1500:])
check("lab: no enumeration tool runs", not ({"subfinder", "assetfinder", "curl", "dnsrecon"} & L.tools()))
ns_lab = next((l.split()[1] for l in open("/etc/resolv.conf") if l.split()[:1] == ["nameserver"] and len(l.split()) > 1), None) \
    if os.path.exists("/etc/resolv.conf") else None
check("lab: httpx asks the container's own resolver (-r, as dnsx does in lab mode)",
      L.of("httpx-toolkit") and all(argval(c, "-r") == ns_lab for c in L.of("httpx-toolkit")) if ns_lab
      else all("-r" not in c["argv"] for c in L.of("httpx-toolkit")), f"resolver {ns_lab}: " + str([c["argv"] for c in L.of("httpx-toolkit")]))
lab_nuc = L.of("nuclei")
lab_passes = sorted(os.path.basename(argval(c, "-elog") or "?") for c in lab_nuc)
check("lab: the nuclei passes that run in lab (control: generic, tech, dns, fp; no third-party hosts, so no tp)",
      lab_passes == ["nuclei_errors_dns.jsonl", "nuclei_errors_fp.jsonl", "nuclei_errors_generic.jsonl", "nuclei_errors_tech.jsonl"],
      str(lab_passes))
check("lab: every nuclei pass gets -r with a file holding exactly the container's resolver",
      bool(ns_lab) and lab_nuc and all(argval(c, "-r") and c["files"].get(argval(c, "-r")) == ns_lab + "\n" for c in lab_nuc),
      f"resolver {ns_lab}: " + str([(argval(c, "-r"), c["files"].get(argval(c, "-r") or "")) for c in lab_nuc]))
check("lab: dnsx asks the container's own resolver (-r)",
      L.of("dnsx") and all(argval(c, "-r") == ns_lab for c in L.of("dnsx") if "-a" in c["argv"]), str([c["argv"] for c in L.of("dnsx")]))
check("lab: the manifest records a lab run", (L.manifest("r-lab").get("lab") or {}).get("lab") is True)
check("lab: nuclei does not get -lna (the lab target is private) and still gets -fhr",
      L.of("nuclei") and all("-lna" not in c["argv"] and "-fhr" in c["argv"] for c in L.of("nuclei")))
lab_assets = [json.loads(l) for l in open(os.path.join(L.root, "runs", "r-lab", "assets.jsonl")) if l.strip()] \
    if os.path.exists(os.path.join(L.root, "runs", "r-lab", "assets.jsonl")) else []
check("lab: the lab target is classified (it stands as its own apex) and reaches nuclei",
      any(a.get("hostname") == "target.lab.test" for a in lab_assets) and "nuclei" in reached(L, "target.lab.test"),
      str([(a.get("hostname"), a.get("class")) for a in lab_assets]) + " " + str(reached(L, "target.lab.test")))

# ================================================================ H: active phases only for hosts the approved inventory listed
print("== H: approval bound to an inventory: new host, address moved out, address moved inside the owned range")
H = Run("held", inv=inventory(skip=("www.example.test",),
                              ips={"moved.example.test": ["94.140.14.60"], "movedown.example.test": ["94.140.14.62"]})).run("--run-id", "r-held")
check("H runs (rc 0, not inventory-only)", H.rc == 0 and H.manifest("r-held").get("inventory_only") is False, H.out[-1500:])
held = json.load(open(os.path.join(H.root, "runs", "r-held", "held_back.json")))["hosts"]
check("H held_back.json names the new host and the moved host with fixed reason codes",
      held == {"moved.example.test": "address-changed", "www.example.test": "new-since-approved-inventory"}, str(held))
web, active = {"httpx-toolkit", "whatweb"}, {"nmap", "sslscan", "nuclei"}
check("H a host absent from the approved inventory reaches the web inventory tools (control)", web <= set(reached(H, "www.example.test")))
check("H a host absent from the approved inventory reaches no active tool", reached(H, "www.example.test", active) == [],
      str(reached(H, "www.example.test", active)))
check("H a host whose address moved to an unlisted public address reaches no active tool",
      reached(H, "moved.example.test", active) == [] and reached(H, "1.0.0.1", active) == [], str(reached(H, "moved.example.test")))
check("H the same move inside an owned range is allowed: reaches nmap (by address) and nuclei",
      reached(H, "94.140.14.61", {"nmap"}) == ["nmap"] and "nuclei" in reached(H, "movedown.example.test"),
      str(reached(H, "movedown.example.test")) + str(reached(H, "94.140.14.61")))
check("H control: a listed, unchanged host still reaches nmap", reached(H, "94.140.14.14", {"nmap"}) == ["nmap"])
cov = {s: set(open(os.path.join(H.root, "runs", "r-held", "coverage", s + ".txt")).read().split())
       for s in ("nmap", "sslscan", "nuclei", "nuclei_tp", "nuclei_dns", "nuclei_fp")}
check("H held-back hosts are in no active coverage file (so nothing on them is marked fixed)",
      not ({"www.example.test", "moved.example.test"} & set().union(*cov.values())), str(cov))
check("H manifest records the held-back count", H.manifest("r-held").get("held_back", {}).get("count") == 2)
Hb = Run("held-other", inv={"domains": ["unrelated.test"], "lab_targets": [], "hosts": {}}).run("--run-id", "r-other")
check("H an approval bound to another domain's inventory is not valid: inventory-only, no nmap or nuclei",
      Hb.rc == 0 and Hb.manifest("r-other").get("inventory_only") is True and not ({"nmap", "nuclei", "sslscan"} & Hb.tools()),
      str(Hb.tools()) + Hb.out[-500:])

# ================================================================ P: a pending or added domain does not block the others
print("== P: approved inventory covers example.test and flip.test; a pending domain; a verified domain added later")
web, active = {"httpx-toolkit", "whatweb"}, {"nmap", "sslscan", "nuclei"}
P1 = Run("pending", inv=dict(inventory(skip=("www.added.test",)), domains=["example.test", "flip.test"])).run("--run-id", "r-pending")
hb1 = json.load(open(os.path.join(P1.root, "runs", "r-pending", "held_back.json"))) \
    if os.path.exists(os.path.join(P1.root, "runs", "r-pending", "held_back.json")) else {}
check("P1 the full run runs its active phases (rc 0, not inventory-only)",
      P1.rc == 0 and P1.manifest("r-pending").get("inventory_only") is False, P1.out[-1500:])
check("P1 both approved domains reach active tools (www.example.test: nuclei; www.flip.test: nmap by address and nuclei)",
      "nuclei" in reached(P1, "www.example.test") and "nuclei" in reached(P1, "www.flip.test")
      and reached(P1, "94.140.14.80", {"nmap"}) == ["nmap"], str(reached(P1, "www.flip.test")))
for n in ("unproven.test", "sub.unproven.test"):
    check(f"P1 the pending domain's name {n} reaches nothing but dig's proof lookup", set(reached(P1, n)) <= {"dig"}, str(reached(P1, n)))
check("P1 held_back.json counts the domains: 2 scanned, none held back, the 2 unverified ones pending",
      hb1.get("domains") == {"scanned": ["example.test", "flip.test"], "held_back": [], "pending": ["badns.test", "unproven.test"]},
      str(hb1.get("domains")))
check("P1 manifest carries the domain counts", (P1.manifest("r-pending").get("held_back") or {}).get("domains")
      == {"scanned": 2, "held_back": 0, "pending": 2}, str(P1.manifest("r-pending").get("held_back")))

P2 = Run("added", extra_domains=("added.test",),
         inv=dict(inventory(skip=("www.added.test",)), domains=["example.test", "flip.test"])).run("--run-id", "r-added")
hb2 = json.load(open(os.path.join(P2.root, "runs", "r-added", "held_back.json"))) \
    if os.path.exists(os.path.join(P2.root, "runs", "r-added", "held_back.json")) else {}
own2 = {e["apex"]: e for e in json.load(open(os.path.join(P2.root, "scope", "ownership.json")))["entries"]}
check("P2 the added domain passed the DNS proof this run (control)", own2["added.test"]["state"] == "verified")
check("P2 the full run runs its active phases (rc 0, not inventory-only)",
      P2.rc == 0 and P2.manifest("r-added").get("inventory_only") is False, P2.out[-1500:])
check("P2 the approved domains still reach active tools", "nuclei" in reached(P2, "www.example.test")
      and reached(P2, "94.140.14.80", {"nmap"}) == ["nmap"])
check("P2 the added domain's host reaches the inventory tools (dnsx, httpx, whatweb)",
      {"dnsx"} | web <= set(reached(P2, "www.added.test")), str(reached(P2, "www.added.test")))
check("P2 the added domain's host reaches no active tool, and its owned-range address never reaches nmap",
      reached(P2, "www.added.test", active) == [] and reached(P2, "94.140.14.90", {"nmap"}) == [], str(reached(P2, "www.added.test")))
check("P2 the added domain's names reach no nuclei pass (not even the DNS templates)",
      reached(P2, "added.test", {"nuclei"}) == [] and reached(P2, "www.added.test", {"nuclei"}) == [])
check("P2 held_back.json holds its host back with the domain reason and counts the domains",
      hb2.get("hosts") == {"www.added.test": "domain-not-in-approved-inventory"}
      and hb2.get("domains") == {"scanned": ["example.test", "flip.test"], "held_back": ["added.test"], "pending": ["badns.test", "unproven.test"]},
      str(hb2))
cov2 = {x: set(open(os.path.join(P2.root, "runs", "r-added", "coverage", x + ".txt")).read().split()) for x in ("nmap", "sslscan", "nuclei")}
check("P2 the held-back host is in no active coverage file (nothing on it can be marked fixed)",
      "www.added.test" not in cov2["nmap"] | cov2["sslscan"] | cov2["nuclei"] and "www.example.test" in cov2["nuclei"], str(cov2))

# ================================================================ N: CDN-fronted by CNAME: edge rotation is not drift
print("== N: hosts the approved inventory classed cdn_fronted by their CNAME")
N = Run("cdn", scope_files={"cdn_cnames.txt": "edge-cdn.test\nother-cdn.test\n"},
        inv=dict(inventory(), hosts={**inventory()["hosts"],
                 "cdn.example.test": {"ips": ["1.0.0.9"], "class": "cdn_fronted", "via_cname": "edge-cdn.test"},
                 "cdnmoved.example.test": {"ips": ["1.0.0.9"], "class": "cdn_fronted", "via_cname": "edge-cdn.test"},
                 "moved.example.test": {"ips": ["1.0.0.9"], "class": "unverified"}})).run("--run-id", "r-cdn")
hbn = json.load(open(os.path.join(N.root, "runs", "r-cdn", "held_back.json"))).get("hosts") \
    if os.path.exists(os.path.join(N.root, "runs", "r-cdn", "held_back.json")) else None
check("N runs (rc 0, not inventory-only)", N.rc == 0 and N.manifest("r-cdn").get("inventory_only") is False, N.out[-1500:])
check("N a CDN-fronted host whose edge address changed (same CNAME suffix) still reaches nuclei, never nmap",
      "nuclei" in reached(N, "cdn.example.test") and reached(N, "1.1.1.1", {"nmap"}) == [], str(reached(N, "cdn.example.test")))
check("N the same host after its CNAME moved to another provider is held back (address-changed) and reaches no active tool",
      (hbn or {}).get("cdnmoved.example.test") == "address-changed" and reached(N, "cdnmoved.example.test", active) == [],
      str(hbn) + str(reached(N, "cdnmoved.example.test")))
check("N a directly addressed host whose address changed is held back",
      (hbn or {}).get("moved.example.test") == "address-changed" and reached(N, "moved.example.test", active) == [], str(hbn))
check("N held_back.json holds back exactly those two", set(hbn or {}) == {"cdnmoved.example.test", "moved.example.test"}, str(hbn))
ninv = (N.manifest("r-cdn").get("inventory") or {}).get("hosts", {})
check("N this run's inventory records the CNAME suffix a CDN host was classed by (via_cname)",
      ninv.get("cdn.example.test", {}).get("via_cname") == "edge-cdn.test" and "via_cname" not in ninv.get("www.example.test", {}),
      json.dumps(ninv.get("cdn.example.test")))

# ================================================================ V: a version-watch job through the runner
print("== V: a version-watch job: this job's DNS proof, the name gate, CNAME exclusions, one GET / per scheme per host")
sys.path.insert(0, SRC)
import runner as RUN  # noqa: E402
V = Run("vw", approval=False)
# every V name resolves inside the shim container (run_shim_tests.sh --add-host), so a name that slipped past a gate
# would reach curl: the "never" checks below are not vacuous
VW_HOSTS = {"vw.example.test": "94.140.14.91",                 # allowed: example.test passes the proof in this job
            "vwalias.example.test": "94.140.14.92",            # CNAME -> excluded.example.test
            "vwtwo.example.test": "94.140.14.93",              # CNAME -> hop.example.test -> deep.excluded.example.test
            "vwx.excluded.example.test": "94.140.14.94",       # excluded by name
            "www.unproven.test": "94.140.14.95"}               # unproven.test: "verified" on disk, fails the proof now
vc = json.load(open(V.canned))
vc["dns"].update({"vw.example.test": {"a": ["94.140.14.91"]},
                  "vwalias.example.test": {"a": ["94.140.14.92"], "cname": ["excluded.example.test"]},
                  "vwtwo.example.test": {"a": ["94.140.14.93"], "cname": ["hop.example.test", "deep.excluded.example.test"]}})
vc["vw_http"] = {h: "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nX-Powered-By: PHP/8.1.2\r\n\r\n" for h in VW_HOSTS}
json.dump(vc, open(V.canned, "w"))
own_v = json.load(open(os.path.join(V.root, "scope", "ownership.json")))
for e in own_v["entries"]:
    if e["apex"] == "unproven.test":       # a stale "verified" from an earlier check: only this job's proof may count
        e["state"], e["verified_at"] = "verified", "2030-01-01T00:00:00Z"
json.dump(own_v, open(os.path.join(V.root, "scope", "ownership.json"), "w"))
vbin = os.path.join(V.work, "bin"); os.makedirs(vbin)
for t in os.listdir(SHIM_BIN):     # the runner gives its steps a clean environment: these wrappers carry the shim's
    with open(os.path.join(vbin, t), "w") as fh:
        fh.write(f'#!/bin/sh\nSHIM_LOG={V.log} SHIM_CANNED={V.canned} exec python3 -B {os.path.join(SRC, "tests", "shim", "shim.py")} {t} "$@"\n')
    os.chmod(os.path.join(vbin, t), 0o755)
vjobs, vpub = os.path.join(V.work, "jobs"), os.path.join(V.work, "pub")
os.makedirs(vjobs)
vlog = []
vrun = RUN.Runner(V.root, vjobs, vpub, app=os.path.join(SRC), log=vlog.append, trace=vlog.append,
                  tool_path=vbin + ":" + os.environ["PATH"])
vstmt = "I own this domain and the systems it points to."
watch_hosts = sorted(VW_HOSTS)
json.dump({"schema": "momus-job-v1", "id": "vw-1", "created_at": JOB_TIME, "type": "version-watch", "scope": {
    "domains": ["example.test", "unproven.test"], "exclude": ["excluded.example.test"],
    "ownership": [{"apex": a, "statement": vstmt, "attested_by": "Test Owner", "attested_at": "2030-01-01T00:00:00Z"}
                  for a in ("example.test", "unproven.test")]},
    "options": {"watches": [
        {"id": "php-example", "name": "PHP example", "product": "php", "cves": ["CVE-2099-10001"],
         "floors": {"8.2": 35, "8.3": 36, "8.4": 27, "8.5": 12}, "hosts": watch_hosts},
        {"id": "nginx-example", "name": "nginx example", "product": "nginx", "cves": ["CVE-2099-10003"],
         "floors": {"1.24": 0, "1.26": 0}, "hosts": watch_hosts}]}}, open(os.path.join(vjobs, "vw-1.json"), "w"))
vrun.step()
V.calls = [json.loads(l) for l in open(os.path.join(V.log, "calls.jsonl")) if l.strip()] if os.path.exists(os.path.join(V.log, "calls.jsonl")) else []
vst = json.load(open(os.path.join(vpub, "status", "vw-1.json")))
vdocs = {}
for w in ("php-example", "nginx-example"):
    p_ = os.path.join(vpub, "version-watch", w, "latest.json")
    vdocs[w] = json.load(open(p_)) if os.path.exists(p_) else {}
vrows = {w: {h["hostname"]: h for h in d.get("hosts", [])} for w, d in vdocs.items()}
curls = V.of("curl")
check("V the job ends done, with the DNS proof step and the version-watch step", vst.get("state") == "done"
      and set(vst.get("exit_codes", {})) == {"dns_proof", "version_watch"}, json.dumps(vst) + " | ".join(vlog)[-600:])
check("V control: this job re-checked the DNS proof at the nameservers (dig TXT)",
      any("+norecurse" in c["argv"] and "TXT" in c["argv"] for c in V.of("dig")), str([c["argv"] for c in V.of("dig")])[:400])
check("V control: the allowed host was probed and fails both watches (PHP 8.1.2, nginx 1.18.0)",
      vrows["php-example"].get("vw.example.test", {}).get("verdict") == "FAIL"
      and vrows["nginx-example"].get("vw.example.test", {}).get("version") == "1.18.0"
      and vrows["nginx-example"]["vw.example.test"]["verdict"] == "FAIL", json.dumps(vdocs)[:800])
check("V one request set per host: two watches on vw.example.test, exactly one GET / per scheme",
      sorted(c["argv"][-1] for c in curls) == ["http://vw.example.test/", "https://vw.example.test/"],
      str([c["argv"] for c in curls]))
check("V every curl call is a plain GET / of headers only, pinned to the checked address",
      curls and all(c["argv"][-1].endswith("://vw.example.test/") and "--resolve" in c["argv"] and "-o" in c["argv"]
                    and not {"-X", "-d", "--data", "-I", "-T", "-F"} & set(c["argv"]) for c in curls), str([c["argv"] for c in curls]))
check("V no scan tool runs: only dig (the DNS proof and the CNAME lookups) and the one fetch (curl)",
      V.tools() == {"dig", "curl"}, str(V.tools()))
never = ["vwx.excluded.example.test", "www.unproven.test", "excluded.example.test", "deep.excluded.example.test"]
check("V excluded names and names under a domain that failed this job's proof appear in no command at all",
      all(reached(V, n) == [] for n in never), str({n: reached(V, n) for n in never}))
alias_calls = {n: [[c["tool"]] + c["argv"] for c in V.calls if n in text_of(c)] for n in ("vwalias.example.test", "vwtwo.example.test")}
check("V names behind an excluded CNAME appear only in their own CNAME lookup (dig +answer A, the local resolver), never in curl",
      all(cs and all(a[0] == "dig" and "+answer" in a and not any(x.startswith("@") for x in a) for a in cs) for cs in alias_calls.values()),
      str(alias_calls))
vasked = {c["argv"][-2] for c in V.of("dig") if "+answer" in c["argv"] and c["argv"][-1] == "A"
          and not any(a.startswith("@") for a in c["argv"])}     # the CNAME lookups (local resolver), not the proof's TXT
check("V control: the CNAME chain of every watch host that passed the proof and the name gate was looked up",
      vasked == {"vw.example.test", "vwalias.example.test", "vwtwo.example.test"}, str(vasked))
vwlog = open(os.path.join(V.root, "runs", "vw-1", "runner-version-watch.log"), errors="replace").read()
check("V both CNAME refusals are logged with the excluded name in the chain",
      "vwalias.example.test (CNAME chain reaches excluded.example.test" in vwlog
      and "vwtwo.example.test (CNAME chain reaches deep.excluded.example.test" in vwlog, vwlog[-800:])
check("V the host under the failed domain is reported UNREACHABLE (not probed); the excluded ones are not in the result",
      vrows["php-example"].get("www.unproven.test", {}).get("reason", "").endswith("(not probed: its domain did not pass the DNS proof in this job)")
      and not {"vwalias.example.test", "vwtwo.example.test", "vwx.excluded.example.test"} & set(vrows["php-example"]),
      json.dumps(vrows["php-example"])[:800])
check("V the published files are exactly the two watches' dated file and latest.json",
      sorted(os.path.relpath(os.path.join(d, f), os.path.join(vpub, "version-watch")) for d, _, fs in os.walk(os.path.join(vpub, "version-watch")) for f in fs)
      == sorted(f"{w}/{n}" for w in ("nginx-example", "php-example") for n in (vdocs["php-example"].get("date", "?") + ".json", "latest.json")))

# ================================================================ R: an approval covering none of the scope is rejected
print("== R: a full job whose approval names an inventory covering none of the scope's domains")
sys.path.insert(0, SRC)
import runner as RUN  # noqa: E402
Rx = Run("reject", approval=False)
os.makedirs(os.path.join(Rx.root, "runs", "inv-other"))
json.dump({"run_id": "inv-other", "rc": 0, "inventory": {"domains": ["unrelated.test"], "lab_targets": [], "hosts": {}}},
          open(os.path.join(Rx.root, "runs", "inv-other", "manifest.json"), "w"))
rjobs, rpub = os.path.join(Rx.work, "jobs"), os.path.join(Rx.work, "pub")
os.makedirs(rjobs)
rlog2 = []
rrun = RUN.Runner(Rx.root, rjobs, rpub, app=os.path.join(SRC), log=rlog2.append, trace=rlog2.append)
json.dump({"schema": "momus-job-v1", "id": "full-r", "created_at": JOB_TIME, "type": "full", "scope": {
    "domains": ["example.test", "flip.test"],
    "ownership": [{"apex": a, "statement": "I own this domain and the systems it points to.", "attested_by": "Test Owner",
                   "attested_at": "2030-01-01T00:00:00Z"} for a in ("example.test", "flip.test")],
    "approval": {"approved_at": "2030-01-02T00:00:00Z", "inventory_run": "inv-other", "approved_by": "Test Owner"}}},
    open(os.path.join(rjobs, "full-r.json"), "w"))
rrun.step()
rst = json.load(open(os.path.join(rpub, "status", "full-r.json")))
check("R the job is rejected with the fixed reason", rst.get("state") == "rejected" and "covers none of this scope's domains" in (rst.get("reason") or ""),
      json.dumps(rst))
check("R nothing ran (no tool call, no run folder)", not os.path.exists(os.path.join(Rx.log, "calls.jsonl"))
      and not os.path.exists(os.path.join(Rx.root, "runs", "full-r")))

# ================================================================ S: scope-sync runs the DNS proof check and no scan tool
print("== S: a scope-sync job through the runner")
Sx = Run("sync", approval=False)
sbin = os.path.join(Sx.work, "bin"); os.makedirs(sbin)
for t in os.listdir(SHIM_BIN):     # the runner gives its steps a clean environment: these wrappers carry the shim's
    with open(os.path.join(sbin, t), "w") as fh:
        fh.write(f'#!/bin/sh\nSHIM_LOG={Sx.log} SHIM_CANNED={Sx.canned} exec python3 -B {os.path.join(SRC, "tests", "shim", "shim.py")} {t} "$@"\n')
    os.chmod(os.path.join(sbin, t), 0o755)
jobs, pub = os.path.join(Sx.work, "jobs"), os.path.join(Sx.work, "pub")
os.makedirs(jobs)
rlog = []
runner = RUN.Runner(Sx.root, jobs, pub, app=os.path.join(SRC), log=rlog.append, trace=rlog.append,
                    tool_path=sbin + ":" + os.environ["PATH"])
stmt = "I own this domain and the systems it points to."
json.dump({"schema": "momus-job-v1", "id": "sync-1", "created_at": JOB_TIME, "type": "scope-sync", "scope": {
    "domains": ["example.test", "unproven.test"],
    "ownership": [{"apex": a, "statement": stmt, "attested_by": "Test Owner", "attested_at": "2030-01-01T00:00:00Z"}
                  for a in ("example.test", "unproven.test")]}}, open(os.path.join(jobs, "sync-1.json"), "w"))
runner.step()
Sx.calls = [json.loads(l) for l in open(os.path.join(Sx.log, "calls.jsonl")) if l.strip()] if os.path.exists(os.path.join(Sx.log, "calls.jsonl")) else []
st = json.load(open(os.path.join(pub, "status", "sync-1.json")))
check("S scope-sync ends done", st.get("state") == "done", json.dumps(st) + " " + " | ".join(rlog)[-800:])
check("S control: the DNS proof check asked dig for the TXT record at the nameserver address",
      any("+norecurse" in c["argv"] and "TXT" in c["argv"] for c in Sx.of("dig")), str([c["argv"] for c in Sx.calls])[:500])
check("S scope-sync invokes no scan tool (dig only)", Sx.tools() == {"dig"}, str(Sx.tools()))
ss = json.load(open(os.path.join(pub, "scope_status.json")))["domains"]
check("S scope_status.json publishes the exact record the check expects (derived token)",
      ss["example.test"]["txt_name"] == "_scan-verify.example.test"
      and ss["example.test"]["txt_value"] == "scan-verify=" + S.derive_token(runner.secret, "example.test"))
check("S the domain whose record matches is verified; the one publishing another domain's token is not",
      ss["example.test"]["state"] == "verified" and ss["unproven.test"]["state"] == "pending"
      and ss["unproven.test"]["last_result"] == "mismatch", json.dumps(ss)[:600])
secret_hex = open(os.path.join(Sx.root, "state", S.SECRET_FILE)).read().strip()
leaked = [os.path.join(d, f) for d, _, fs in os.walk(pub) for f in fs if secret_hex in open(os.path.join(d, f), errors="ignore").read()]
check("S the install secret is in no published file", leaked == [] and not os.path.exists(os.path.join(pub, S.SECRET_FILE)), str(leaked))

# ================================================================ W: the seeder's host list is untrusted input
print("== W: seed names from the seeder's volume: only host names, only through the name gate")
DNS["seed.example.test"] = {"a": ["94.140.14.95"]}                 # a name only the seed knows: the positive control
DNS["seedx.excluded.example.test"] = {"a": ["94.140.14.96"]}       # would resolve if it slipped past the gate
DNS["seed.outside-scope.test"] = {"a": ["94.140.14.97"]}
PWN = "/tmp/shim-seed-pwned"
SEED_HOSTILE = ["seed.example.test", "seedx.excluded.example.test", "seed.outside-scope.test",
                "x$(touch${IFS}" + PWN + ").example.test", "a;touch " + PWN + ".example.test", "`touch " + PWN + "`.example.test",
                "-oseedopt.example.test", "94.140.14.98", "2001:db8::98", "SEEDUPPER.example.test"]
W_DROPPED = ["seedx.excluded.example.test", "seed.outside-scope.test", "94.140.14.98", "2001:db8::98", "seedopt.example.test",
             "seedupper.example.test", "SEEDUPPER.example.test"]


def seed_run(label, setup):
    r = Run(label, approval=False)
    json.dump({**json.load(open(r.canned)), "dns": DNS}, open(r.canned, "w"))
    sdir = os.path.join(r.work, "seed")
    os.makedirs(sdir)
    setup(sdir, r.work)
    return r.run("--run-id", f"r-{label}", env={"SCAN_SEED_DIR": sdir})


def hostile(sdir, work):
    open(os.path.join(sdir, "seed_hosts.txt"), "w").write("\n".join(SEED_HOSTILE) + "\n")


W = seed_run("seed", hostile)
check("W runs to completion (rc 0)", W.rc == 0, W.out[-1500:] + W.recon_log("r-seed")[-2000:])
check("W control: the seed-only name seed.example.test reaches dnsx", reached(W, "seed.example.test", {"dnsx"}) == ["dnsx"],
      str(reached(W, "seed.example.test")))
for tok in W_DROPPED:
    check(f"W seed line {tok!r} reaches no tool", reached(W, tok) == [], str(reached(W, tok)))
check("W no seed line with shell characters reaches any tool's arguments, input or files",
      not any(x in text_of(c) for c in W.calls for x in ("$(", "${IFS}", ";touch", "`touch", "touch ", "seedopt")),
      str([c["tool"] for c in W.calls if "touch" in text_of(c)]))
check("W nothing in a seed line was executed", not os.path.exists(PWN))
wm = W.manifest("r-seed").get("seed") or {}
check("W manifest: lines read, host names kept, names that passed the gate",
      wm == {"status": "read", "lines": len(SEED_HOSTILE), "read": 3, "passed_gate": 1}, json.dumps(wm))


def oversize(sdir, work):
    with open(os.path.join(sdir, "seed_hosts.txt"), "w") as fh:
        fh.write("seedbig.example.test\n")
        fh.write("a" * (17 << 20))


def symlinked(sdir, work):
    target = os.path.join(work, "elsewhere.txt")
    open(target, "w").write("seedlink.example.test\n")
    os.symlink(target, os.path.join(sdir, "seed_hosts.txt"))


for label, setup, tok, reason in (("seedbig", oversize, "seedbig.example.test", "over the size limit"),
                                  ("seedlink", symlinked, "seedlink.example.test", "symlink")):
    DNS[tok] = {"a": ["94.140.14.94"]}
    X = seed_run(label, setup)
    check(f"W {label}: the run goes on with passive enumeration (rc 0)", X.rc == 0, X.out[-1500:])
    check(f"W {label}: control: passive names still reach dnsx", reached(X, "www.example.test", {"dnsx"}) == ["dnsx"])
    check(f"W {label}: the file is skipped with a fixed reason and none of it reaches a tool",
          reached(X, tok) == [] and reason in X.recon_log(f"r-{label}"), str(reached(X, tok)))
    xm = X.manifest(f"r-{label}").get("seed") or {}
    check(f"W {label}: manifest records the skip", xm == {"status": "skipped", "lines": 0, "read": 0, "passed_gate": 0}, json.dumps(xm))
check("W a run with no seed folder records nothing read", (A.manifest("r-full").get("seed") or {}).get("status") == "absent",
      json.dumps(A.manifest("r-full").get("seed")))

# ================================================================ U: no update check by any tool of the one publisher
print("== U: every subfinder, dnsx, httpx-toolkit and nuclei call in every scenario carries -duc")
all_runs = [r for r in globals().values() if isinstance(r, Run)]
pd_calls = [c for r in all_runs for c in getattr(r, "calls", []) if c["tool"] in ("subfinder", "dnsx", "httpx-toolkit", "nuclei")]
check("U control: each of the four tools was called in these scenarios",
      {c["tool"] for c in pd_calls} == {"subfinder", "dnsx", "httpx-toolkit", "nuclei"}, str({c["tool"] for c in pd_calls}))
check("U every call of those tools passes -duc (no update check)", all("-duc" in c["argv"] for c in pd_calls),
      str([(c["tool"], c["argv"][:4]) for c in pd_calls if "-duc" not in c["argv"]][:5]))

failed = [n for n, ok in results if not ok]
print(f"\nSUMMARY: {len(results) - len(failed)} passed, {len(failed)} failed")
sys.exit(1 if failed else 0)
