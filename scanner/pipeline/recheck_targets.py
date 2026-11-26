#!/usr/bin/env python3
"""recheck_targets.py - decide what tonight's daily recheck re-tests, from the database alone.

  python3 -I -B scanner/pipeline/recheck_targets.py --root "$SCAN_ROOT"

Writes scope/recheck_hosts.txt and scope/recheck_base.txt; the daily recheck starts recon.sh --recheck from
them. Nobody maintains the list: a host is on it while the scan still sees something wrong with it, and drops
off once a recheck sees it clean.

  - every host with an open finding (any source: nuclei, nmap, sslscan, http, dns)
  - every host running an end-of-life component in the latest snapshot
  - every host still offering a legacy TLS protocol in the latest snapshot

The base run is the latest full run: the recheck reuses its nuclei representatives (recon.sh --recheck) and
ingest refuses a recheck built on anything else. The latest snapshot is that run or the newest recheck after it.
"""
import argparse, datetime as dt, os, sqlite3, sys


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    a = ap.parse_args()
    db = sqlite3.connect(f"file:{os.path.join(a.root, 'data', 'scan.sqlite')}?mode=ro", uri=True)
    cols = {r[1] for r in db.execute("PRAGMA table_info(runs)").fetchall()}
    if "kind" in cols:   # base: the newest full run; snapshot: the newest full or recheck run that wrote a snapshot
        base = db.execute("SELECT run_id FROM runs WHERE kind='full' ORDER BY seq DESC LIMIT 1").fetchone()
        snap = db.execute("SELECT run_id FROM runs WHERE kind IN ('full','recheck') AND snapshot=1 ORDER BY seq DESC LIMIT 1").fetchone()
    else:                # databases from before ingest.py added run kinds: every scored run is a full snapshot
        base = snap = db.execute("SELECT run_id FROM runs WHERE COALESCE(inventory_only,0)=0 ORDER BY seq DESC LIMIT 1").fetchone()
    if not base:
        sys.exit("no full run in the database; nothing to recheck")
    base, snap = base[0], (snap or base)[0]
    reasons = {}
    def add(host, why):
        reasons.setdefault(host, set()).add(why)
    for (h,) in db.execute("SELECT DISTINCT hostname FROM findings WHERE status='open'"):
        add(h, "open finding")
    for (h,) in db.execute("SELECT hostname FROM asset_profiles WHERE run_id=? AND COALESCE(eol_count,0)>0", (snap,)):
        add(h, "end-of-life software")
    for (h,) in db.execute("SELECT DISTINCT hostname FROM tls_endpoints WHERE run_id=? AND legacy=1", (snap,)):
        add(h, "legacy TLS")
    hosts = sorted(h for h in reasons if h)
    scope = os.path.join(a.root, "scope")
    os.makedirs(scope, exist_ok=True)
    counts = {}
    for h in hosts:
        for why in reasons[h]:
            counts[why] = counts.get(why, 0) + 1
    with open(os.path.join(scope, "recheck_hosts.txt"), "w") as f:
        f.write(f"# written by recheck_targets.py {dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')} "
                f"from snapshot {snap} on base run {base}: {len(hosts)} hosts ("
                + ", ".join(f"{v} {k}" for k, v in sorted(counts.items())) + ")\n")
        f.write("".join(h + "\n" for h in hosts))
    with open(os.path.join(scope, "recheck_base.txt"), "w") as f:
        f.write(base + "\n")
    print(f"recheck targets: {len(hosts)} hosts (" + ", ".join(f"{v} {k}" for k, v in sorted(counts.items())) + f"); base run {base}, snapshot {snap}")


if __name__ == "__main__":
    main()
