#!/usr/bin/env python3
"""classify.py - build the asset inventory for one run and split hosts into scan classes.

Inputs (in --run-dir):  dns.jsonl (dnsx), httpx.jsonl (httpx-toolkit), apexes.txt
Inputs (in --scope):    exclude.txt, owned_ranges.txt, approved_hosts.txt, third_party_cnames.txt, third_party_ranges.txt,
                        cdn_cnames.txt, owned_aws.txt (all optional)
Inputs (in --config):   the shipped generic provider lists (cdn_cnames.txt, third_party_cnames.txt,
                        third_party_ranges.txt); the scope directory's own lists are merged with them
Outputs (in --run-dir): assets.jsonl plus target lists:
   owned_hosts / owned_ips / cdn_hosts / tp_hosts / unverified_hosts / dead_hosts      (.txt)
   owned_urls / cdn_urls / tp_urls / unverified_urls / all_urls / https_hosts          (.txt)

Classes:
  owned        an address in owned_ranges.txt, or the host is in approved_hosts.txt -> full non-intrusive scan; the
               port scan still needs scope.portscan_allowed (recon.sh applies it to owned_ips.txt)
  cdn_fronted  behind Cloudflare/Akamai/etc. edge IPs -> web checks (the app is yours), NO port scan of edge IPs
  third_party  CNAME chain ends at a SaaS/hosting provider, or the A record sits in a provider range listed in
               third_party_ranges.txt -> passive + HTTP fingerprint + takeover/misconfig only, no port scan
  (cdn_fronted and third_party hosts classed by a CNAME suffix carry "via_cname": that suffix. The approved
  inventory keeps it, and such a host is not held back for an edge address change while its CNAME stays under the
  same suffix: see scope.compute_held_back.)
  unverified   matches no provider list and no owned range: unknown is not owned -> web checks, NO port scan
  internal     an address that may never be scanned (RFC1918, CGNAT 100.64/10, loopback, link-local, ...), alone or
               next to public ones -> never probed; reported as an information-disclosure finding
  dead         enumerated but does not resolve -> recorded for trend, never touched
Hosts/IPs in exclude.txt (names, suffixes, addresses, CIDRs; see scope.py) are dropped before anything else.
"""
import argparse, ipaddress, json, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import scope as SC  # noqa: E402
CONFIG = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config")

LIVE = ("owned", "cdn_fronted", "third_party", "unverified")


def read_list(path):
    out = []
    if not os.path.exists(path):
        return out
    for line in open(path, errors="ignore"):
        s = line.split("#", 1)[0].strip().lower()   # whole-line and trailing comments
        if s:
            out.append(s)
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--scope", required=True)
    ap.add_argument("--config", default=CONFIG, help="shipped provider lists (default scanner/config)")
    a = ap.parse_args()
    rd, sc = a.run_dir, a.scope
    gate = SC.Scope(sc, rd, require_domains=False)   # exclusions, address rules and lab mode come from scope.py

    apexes = sorted(read_list(os.path.join(rd, "apexes.txt")), key=len, reverse=True)
    def merged(name):   # shipped list first, then the user's own; duplicates dropped
        return list(dict.fromkeys(read_list(os.path.join(a.config, name)) + read_list(os.path.join(sc, name))))
    tp_suffixes = [s.lstrip(".") for s in merged("third_party_cnames.txt")]
    cdn_suffixes = [s.lstrip(".") for s in merged("cdn_cnames.txt")]
    def read_nets(name, lst=None):
        nets = []
        for c in (lst if lst is not None else read_list(os.path.join(sc, name))):
            try:
                nets.append(ipaddress.ip_network(c, strict=False))
            except ValueError:
                print(f"warn: bad CIDR in {name}: {c}", file=sys.stderr)
        return nets
    owned_nets = read_nets("owned_ranges.txt")
    tp_nets = read_nets("third_party_ranges.txt", merged("third_party_ranges.txt"))

    def apex_of(h):
        for ax in apexes:
            if h == ax or h.endswith("." + ax):
                return ax
        return None

    def excluded(h, ips):
        if gate.name_excluded(h):
            return True
        return any(not gate.ip_allowed(ip, h)[0] and "exclude.txt" in gate.ip_allowed(ip, h)[1] for ip in ips)

    def net_match(ips, nets):
        """first network in nets that contains one of ips, else None"""
        for ip in ips:
            try:
                ipo = ipaddress.ip_address(ip)
            except ValueError:
                continue
            for n in nets:
                if ipo in n:
                    return str(n)
        return None

    def in_owned_ranges(ips):
        return net_match(ips, owned_nets) is not None

    def scannable(h, ip):
        return gate.ip_allowed(ip, h)[0]

    def suffix_match(cnames, suffixes):
        for c in cnames:
            c = c.lower().rstrip(".")
            for s in suffixes:
                if c == s or c.endswith("." + s):
                    return s
        return None

    def blocked(h, ips):
        """addresses that may never be scanned (scope.ip_allowed: private, CGNAT, link-local, metadata, ...)"""
        return [ip for ip in ips if not scannable(h, ip)]

    # ---- DNS
    hosts = {}
    for line in open(os.path.join(rd, "dns.jsonl"), errors="ignore"):
        try:
            d = json.loads(line)
        except Exception:
            continue
        h = d.get("host", "").lower().rstrip(".")
        if not h:
            continue
        rec = hosts.setdefault(h, {"hostname": h, "ips": [], "cnames": [], "endpoints": []})
        rec["ips"] = sorted(set(rec["ips"] + (d.get("a") or []) + (d.get("aaaa") or [])))
        rec["cnames"] = list(dict.fromkeys(rec["cnames"] + [c.rstrip(".").lower() for c in (d.get("cname") or [])]))
    # names that never made it into dns.jsonl (dnsx drops NXDOMAIN) are dead
    for line in open(os.path.join(rd, "subdomains.txt"), errors="ignore"):
        h = line.strip().lower()
        if h and h not in hosts:
            hosts[h] = {"hostname": h, "ips": [], "cnames": [], "endpoints": []}

    # ---- HTTP
    hx = os.path.join(rd, "httpx.jsonl")
    if os.path.exists(hx):
        for line in open(hx, errors="ignore"):
            try:
                d = json.loads(line)
            except Exception:
                continue
            h = (d.get("input") or d.get("host") or "").lower().split(":")[0]
            if h not in hosts:
                continue
            ep = {
                "url": d.get("url"), "final_url": d.get("final_url"),
                "status": d.get("status_code"), "title": (d.get("title") or "")[:200],
                "server": d.get("webserver") or d.get("server"), "tech": d.get("tech") or [],
                "cdn": bool(d.get("cdn")), "cdn_name": d.get("cdn_name"), "cdn_type": d.get("cdn_type"),
                # httpx v1.9: "host" is the hostname, the address is "host_ip"
                "ip": d.get("host_ip") or d.get("ip"), "a": d.get("a") or [], "aaaa": d.get("aaaa") or [], "jarm": d.get("jarm"),
                "favicon": d.get("favicon"), "favicon_md5": d.get("favicon_md5"), "cpe": d.get("cpe") or [],
                "content_type": d.get("content_type"), "content_length": d.get("content_length"),
                "tls": {k: (d.get("tls") or {}).get(k) for k in ("subject_cn", "subject_an", "issuer_cn", "issuer_org", "issuer_dn", "not_after", "tls_version", "cipher")} if d.get("tls") else None,
            }
            hosts[h]["endpoints"].append(ep)

    # ---- classify
    out = {"owned": [], "cdn_fronted": [], "third_party": [], "unverified": [], "internal": [], "dead": [], "excluded": []}
    assets = []
    for h in sorted(hosts):
        r = hosts[h]
        ax = apex_of(h)
        if ax is None and h in gate.lab_hosts:
            ax = h          # lab mode: a lab target has no DNS-verified apex; it stands as its own
        if ax is None:
            continue
        r["apex"] = ax
        if excluded(h, r["ips"]):
            r["class"] = "excluded"; out["excluded"].append(h); continue
        # httpx tags every AWS/GCP/Azure IP as cdn_type "cloud"; only real CDN/WAF edges count as fronted
        edge = sorted({e["cdn_name"] for e in r["endpoints"] if e["cdn"] and (e.get("cdn_type") or "") in ("cdn", "waf") and e["cdn_name"]})
        if not r["ips"]:
            r["class"] = "dead"; r["reason"] = "no A/AAAA"
        elif len(blocked(h, r["ips"])) == len(r["ips"]):
            r["class"] = "internal"; r["reason"] = "private/internal IP in public DNS"
        elif blocked(h, r["ips"]):
            # a host is carried forward only if every address may be scanned
            r["class"] = "internal"; r["reason"] = "private/internal IP next to public ones: " + ",".join(blocked(h, r["ips"]))
        elif in_owned_ranges(r["ips"]):
            r["class"] = "owned"; r["reason"] = "ip in owned_ranges"
        elif h in gate.approved_hosts:
            r["class"] = "owned"; r["reason"] = "host in approved_hosts"
        elif (m := suffix_match(r["cnames"], cdn_suffixes)):
            r["class"] = "cdn_fronted"; r["reason"] = f"cname -> {m}"; r["via_cname"] = m
        elif (m := suffix_match(r["cnames"], tp_suffixes)):
            r["class"] = "third_party"; r["reason"] = f"cname -> {m}"; r["via_cname"] = m
        elif (m := net_match(r["ips"], tp_nets)):
            r["class"] = "third_party"; r["reason"] = f"ip in third_party_ranges ({m})"
        elif edge:
            r["class"] = "cdn_fronted"; r["reason"] = "cdn/waf edge: " + ",".join(edge)
        else:
            # unknown is not owned: web checks only, never a port scan, until a human approves it
            r["class"] = "unverified"; r["reason"] = "no owned range or provider match: " + ("direct A record" if not r["cnames"] else "cname -> " + r["cnames"][-1])
        out[r["class"]].append(h)
        assets.append(r)

    with open(os.path.join(rd, "assets.jsonl"), "w") as f:
        for r in assets:
            f.write(json.dumps(r) + "\n")

    def write(name, items):
        with open(os.path.join(rd, name), "w") as f:
            for i in items:
                f.write(i + "\n")

    def urls_for(cls):
        u = []
        for r in assets:
            if r["class"] == cls:
                u += [e["url"] for e in r["endpoints"] if e.get("url")]
        return sorted(set(u))

    # nmap candidates: addresses of owned hosts that may be scanned; recon.sh still applies scope.portscan_allowed
    owned_ips = sorted({ip for r in assets if r["class"] == "owned" for ip in r["ips"] if scannable(r["hostname"], ip)})
    https_hosts = sorted({
        (e["url"].split("://", 1)[1].split("/")[0] + ("" if ":" in e["url"].split("://", 1)[1].split("/")[0] else ":443"))
        for r in assets if r["class"] in LIVE for e in r["endpoints"] if (e.get("url") or "").startswith("https://")
    })
    write("owned_hosts.txt", out["owned"]); write("owned_ips.txt", owned_ips)
    write("cdn_hosts.txt", out["cdn_fronted"]); write("tp_hosts.txt", out["third_party"]); write("unverified_hosts.txt", out["unverified"])
    write("dead_hosts.txt", out["dead"]); write("excluded_hosts.txt", out["excluded"]); write("internal_hosts.txt", out["internal"])
    ou, cu, tu, uu = urls_for("owned"), urls_for("cdn_fronted"), urls_for("third_party"), urls_for("unverified")
    write("owned_urls.txt", ou); write("cdn_urls.txt", cu); write("tp_urls.txt", tu); write("unverified_urls.txt", uu)
    write("all_urls.txt", sorted(set(ou + cu + tu + uu))); write("https_hosts.txt", https_hosts)

    # human-readable inventory for the review gate
    with open(os.path.join(rd, "inventory.txt"), "w") as f:
        for cls in ("owned", "cdn_fronted", "unverified", "third_party", "internal", "dead", "excluded"):
            f.write(f"\n== {cls} ({len(out[cls])})\n")
            for r in assets:
                if r["class"] == cls:
                    ep = r["endpoints"][0] if r["endpoints"] else {}
                    f.write(f"{r['hostname']:<45} {','.join(r['ips'])[:40]:<40} {r.get('reason',''):<35} {ep.get('status') or '':<4} {ep.get('title') or ''}\n")
    # CNAME-fronted hosts versus scope/owned_aws.txt (nothing in this project writes that file: the seeder does not read
    # cloud resource inventories, so this report section appears only if an operator puts such a file there; it would
    # list the load balancers, CloudFront distributions and Global Accelerators in their AWS accounts). Reporting only, classes are unchanged: this shows which ELB/EC2-fronted hosts are in your accounts
    # without deciding whether they count as "owned". Route 53 ALIAS records resolve as plain A records, not CNAMEs, so
    # alias-fronted hosts cannot appear here; the list covers CNAME-fronted hosts only.
    aws_path = os.path.join(sc, "owned_aws.txt")
    if os.path.exists(aws_path):
        def _norm(n):
            n = n.lower().rstrip(".")
            return n[len("dualstack."):] if n.startswith("dualstack.") else n
        ours = {_norm(n) for n in read_list(aws_path)}
        aws_sfx = (".elb.amazonaws.com", ".cloudfront.net", ".awsglobalaccelerator.com")
        fronted = [r for r in assets if any(_norm(c).endswith(aws_sfx) for c in r["cnames"])]
        in_acct = [r for r in fronted if any(_norm(c) in ours for c in r["cnames"])]
        with open(os.path.join(rd, "inventory.txt"), "a") as f:
            f.write(f"\n== cname-fronted by AWS ({len(fronted)}): {len(in_acct)} point at a load balancer/distribution that exists "
                    f"in the AWS accounts read ({len(ours)} known), {len(fronted) - len(in_acct)} at one that does not. "
                    f"Alias-fronted hosts resolve as A records and are not listed.\n")
            for r in fronted:
                mark = "in an account in scope" if r in in_acct else "not in accounts read"
                f.write(f"{r['hostname']:<45} {r['class']:<12} {mark:<22} {r['cnames'][-1][:70]}\n")
    print({k: len(v) for k, v in out.items()}, "owned_ips:", len(owned_ips))

if __name__ == "__main__":
    main()
