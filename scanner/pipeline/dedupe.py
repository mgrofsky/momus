#!/usr/bin/env python3
"""dedupe.py - collapse owned, cdn_fronted and unverified endpoints that are the same application into one representative URL.

Many hostnames point at the same load balancer and serve the same app; scanning each with the full nuclei set
multiplies runtime for no new information. Group key = (first IP, scheme:port, status, title, content-length,
server). Representative = shortest hostname, then alphabetical (deterministic, so trends stay stable).
Writes nuclei_targets.txt (one URL per group) and nuclei_groups.json {representative_url: [all urls in group]}.
"""
import json, os, sys
rd = sys.argv[1]
groups = {}
for line in open(os.path.join(rd, "assets.jsonl")):
    a = json.loads(line)
    if a["class"] not in ("owned", "cdn_fronted", "unverified"):   # unverified: web checks like owned, no port scan
        continue
    for e in a["endpoints"]:
        u = e.get("url")
        if not u:
            continue
        scheme_port = u.split("://")[0] + ":" + (u.split("://")[1].split("/")[0].split(":")[1] if ":" in u.split("://")[1].split("/")[0] else "")
        key = (a["ips"][0] if a["ips"] else a["hostname"], scheme_port, e.get("status"), (e.get("title") or "")[:40], e.get("content_length"), e.get("server"))
        groups.setdefault(key, []).append(u)
reps = {}
for key, urls in groups.items():
    if (key[2] or 0) >= 500:
        continue  # 5xx application: nothing behind it to test; headers/TLS are already covered by httpx/sslscan
    urls = sorted(set(urls), key=lambda x: (len(x.split("://")[1].split("/")[0]), x))
    reps[urls[0]] = urls
# when a host has both an http and an https representative, keep only https (http normally just redirects)
def hostof(u): return u.split("://")[1].split("/")[0].split(":")[0]
https_hosts = {hostof(r) for r in reps if r.startswith("https://")}
for r in list(reps):
    if r.startswith("http://") and hostof(r) in https_hosts:
        https_rep = next(x for x in reps if x.startswith("https://") and hostof(x) == hostof(r))
        reps[https_rep] = sorted(set(reps[https_rep] + reps.pop(r)))
with open(os.path.join(rd, "nuclei_targets.txt"), "w") as f:
    for r in sorted(reps):
        f.write(r + "\n")
json.dump(reps, open(os.path.join(rd, "nuclei_groups.json"), "w"), indent=1)
print(f"endpoints {sum(len(v) for v in reps.values())} -> representatives {len(reps)}")
