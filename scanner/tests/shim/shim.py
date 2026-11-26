#!/usr/bin/env python3
"""Recording stand-in for every external tool recon.sh runs. Each call appends one JSON line to
$SHIM_LOG/calls.jsonl: the tool name, its arguments, its standard input, and the content of every file named in
its arguments (target lists). Output is canned from $SHIM_CANNED (JSON written by driver.py). No network."""
import json, os, re, sys

tool, argv = sys.argv[1], sys.argv[2:]
canned = json.load(open(os.environ["SHIM_CANNED"]))
stdin = "" if sys.stdin is None or sys.stdin.isatty() else sys.stdin.read()


def files_in(args):
    out = {}
    for a in args:
        for cand in (a, a.split("=", 1)[1] if a.startswith("-") and "=" in a else None):
            if cand and os.path.isfile(cand):
                try:
                    out[cand] = open(cand, errors="replace").read()[:1_000_000]
                except OSError:
                    pass
    return out


with open(os.path.join(os.environ["SHIM_LOG"], "calls.jsonl"), "a") as f:
    f.write(json.dumps({"tool": tool, "argv": argv, "stdin": stdin, "files": files_in(argv), "cwd": os.getcwd()}) + "\n")


def opt(*names):
    for i, a in enumerate(argv):
        for n in names:
            if a == n and i + 1 < len(argv):
                return argv[i + 1]
            if a.startswith(n + "="):
                return a.split("=", 1)[1]
    return None


def lines(path):
    return [l.strip() for l in open(path) if l.strip()] if path and os.path.exists(path) else []


def write(path, text):
    if path:
        with open(path, "w") as fh:
            fh.write(text)


VERSIONS = {"subfinder": "[INF] Current Version: v2.17.0", "dnsx": "[INF] Current Version: 1.3.1",
            "httpx-toolkit": "[INF] Current Version: v1.9.0", "nuclei": "[INF] Nuclei Engine Version: v3.11.1",
            "nmap": "Nmap version 7.991", "sslscan": "2.1.5", "whatweb": "WhatWeb version 0.6.4"}
if any(a in ("-version", "--version", "-V") for a in argv):
    print(VERSIONS.get(tool, "0.0"))
    sys.exit(0)

enum, dns = canned.get("enum", []), canned.get("dns", {})

if tool == "subfinder":
    write(opt("-o"), "".join(n + "\n" for n in enum))
elif tool == "assetfinder":
    print("\n".join(enum))
elif tool == "curl":
    url = argv[-1]
    if "crt.sh" in url:
        print(json.dumps([{"name_value": "\n".join(enum)}]))
    elif "-D" in argv:      # version watch: the canned response headers of GET / (curl -D - prints them)
        from urllib.parse import urlsplit
        head = canned.get("vw_http", {}).get((urlsplit(url).hostname or "").lower())
        if head:
            sys.stdout.write(head)
elif tool == "dnsrecon":
    write(opt("-j"), "[]")
elif tool == "dnsx":
    out = []
    if "-mx" not in argv:
        for h in lines(opt("-l")):
            if h in dns:
                d = {"host": h, **{k: v for k, v in dns[h].items() if v}}
                out.append(json.dumps(d))
    write(opt("-o"), "".join(l + "\n" for l in out))
elif tool == "dig":
    pos = [a for a in argv if not a.startswith(("+", "@", "-"))]
    server = next((a[1:] for a in argv if a.startswith("@")), None)
    types = {"NS", "A", "AAAA", "TXT", "AXFR"}
    qtype = next((p for p in pos if p.upper() in types), "A").upper()
    name = next((p for p in pos if p.upper() not in types), "").rstrip(".").lower()
    if qtype == "AXFR":
        print("; Transfer failed.")
    elif qtype == "NS":
        print("\n".join(n + "." for n in canned.get("ns", {}).get(name, [])))
    elif qtype == "A" and server is None and "+answer" in argv:
        # a full answer section (scope.cname_lookup): every CNAME step of the canned record, then its addresses
        d = dns.get(name)
        print(f";; ->>HEADER<<- opcode: QUERY, status: {'NOERROR' if d else 'NXDOMAIN'}, id: 1\n;; ANSWER SECTION:")
        if d:
            prev = name
            for c in d.get("cname") or []:
                print(f"{prev}.\t300\tIN\tCNAME\t{c}.")
                prev = c
            for a in d.get("a") or []:
                print(f"{prev}.\t300\tIN\tA\t{a}")
    elif qtype in ("A", "AAAA") and server is None:
        addrs = canned.get("ns_addr", {}).get(name, []) if name in canned.get("ns_addr", {}) else []
        seq = canned.get("ns_addr_seq", {}).get(name)
        if seq:
            # [first, later]: the first A lookup of this name (and the AAAA that follows it) gets the first list,
            # every later lookup the second; models an address that changes after the DNS proof
            counter = os.path.join(os.environ["SHIM_LOG"], "addr_count_" + name)
            n = int(open(counter).read()) if os.path.exists(counter) else 0
            if qtype == "A":
                n += 1
                write(counter, str(n))
            addrs = seq[0] if n <= 1 else seq[1]
        print("\n".join(a for a in addrs if (":" in a) == (qtype == "AAAA")))
    elif qtype == "TXT":
        vals = canned.get("txt", {}).get(name, [])
        print(";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n;; ANSWER SECTION:")
        for v in vals:
            print(f'{name}.\t300\tIN\tTXT\t"{v}"')
elif tool == "httpx-toolkit":
    out = []
    for h in lines(opt("-l")):
        if h in canned.get("http", []):
            ip = (dns.get(h, {}).get("a") or [""])[0]
            out.append(json.dumps({"input": h, "host": h, "host_ip": ip, "url": f"https://{h}", "status_code": 200,
                                   "title": "canned", "webserver": "canned"}))
    write(opt("-o"), "".join(l + "\n" for l in out))
elif tool == "whatweb":
    write(opt("--log-json"), "[]\n")
elif tool == "wafw00f":
    write(opt("-o"), "[]\n")
elif tool == "nmap":
    write(opt("-oX"), '<?xml version="1.0"?>\n<nmaprun></nmaprun>\n')
    write(opt("-oN"), "")
elif tool == "sslscan":
    write(opt("--xml"), "<document></document>\n")
elif tool == "nuclei":
    write(opt("-o"), "")
sys.exit(0)
