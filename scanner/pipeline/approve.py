#!/usr/bin/env python3
"""approve.py - the human steps before a scan. The UI will call the same functions later.

  approve.py attest APEX --by NAME        record "I own this domain and the systems it points to." for APEX and
                                          print the DNS record that proves control of it (state: pending). The
                                          token in that record is derived from this install's secret
                                          (scope.derive_token); nothing accepts a token from outside.
  approve.py verify APEX                  look the record up at APEX's own nameservers; on a match: verified
  approve.py inventory RUN_ID --by NAME   approve active phases (port scan, TLS scan, nuclei) after reviewing
                                          inventory run RUN_ID. Accepted when that run's recorded inventory covers
                                          at least one domain of the scope (bind_inventory); the approval keeps a
                                          copy of the hosts and addresses that inventory listed, and only those
                                          hosts, under the domains it covered, reach active phases later
                                          (hold_back; a domain added since is held back as a whole).

Scope directory: --scope, else $SCAN_ROOT/scope (default /var/lib/scan/scope). Install secret: --state, else
$SCAN_ROOT/state.
"""
import argparse, ipaddress, json, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import scope as S  # noqa: E402

HOST_CLASSES = ("owned", "cdn_fronted", "third_party", "unverified", "internal", "dead", "excluded")
MAX_INVENTORY_HOSTS = 100000


def attest(scope_dir, apex, by, now=None, state_dir=None):
    """Record the ownership statement. Returns the entry plus the derived "token" (for printing only; the token
    itself is never stored)."""
    ax = S.norm_name(apex)
    if not ax:
        raise S.ScopeError(f"{apex!r} is not a valid domain name")
    if not (by or "").strip():
        raise S.ScopeError("--by NAME is required: the person making the ownership statement")
    secret, _ = S.load_secret(state_dir or S.default_state_dir(scope_dir), create=True)
    entries = S.load_ownership(scope_dir)
    ent = {"apex": ax, "statement": S.OWNERSHIP_STATEMENT, "attested_by": by.strip(),
           "attested_at": S.iso(now or S.now_utc()), "state": "pending", "key_id": S.key_id(secret)}
    entries[ax] = ent
    S.save_ownership(scope_dir, entries)
    return dict(ent, token=S.derive_token(secret, ax))


def verify(scope_dir, apex, lookup=None, now=None, log=print, state_dir=None, secret=None):
    ax = S.norm_name(apex)
    if not ax:
        raise S.ScopeError(f"{apex!r} is not a valid domain name")
    return ax in S.verify_apexes(scope_dir, [ax], lookup=lookup, now=now, log=log, secret=secret,
                                 state_dir=state_dir or S.default_state_dir(scope_dir))


# ---------------------------------------------------------------- inventory approval, bound to scope and hosts
def inventory_record(root, run_id):
    """The inventory a finished run recorded in its manifest (recon.sh phase 9, key "inventory"):
    {"domains": [...], "lab_targets": [...], "hosts": {host: {"ips": [...], "class": "..."}}}, normalized.
    Raises ScopeError (fixed text) when the run is missing, did not finish, or recorded no inventory."""
    if not isinstance(run_id, str) or not run_id or "/" in run_id or run_id.startswith("."):
        raise S.ScopeError("not a valid run id")
    man = os.path.join(root, "runs", run_id, "manifest.json")
    try:
        with open(man) as fh:
            m = json.load(fh)
    except (OSError, ValueError):
        raise S.ScopeError(f"inventory run {run_id} not found (no readable manifest)")
    inv = m.get("inventory") if isinstance(m, dict) else None
    if not isinstance(inv, dict):
        raise S.ScopeError(f"run {run_id} recorded no inventory (it did not finish its inventory phases)")
    if m.get("rc") != 0:
        raise S.ScopeError(f"run {run_id} did not finish cleanly")
    return normalize_inventory(inv)


def normalize_inventory(inv):
    def names(xs):
        if not isinstance(xs, list):
            raise S.ScopeError("inventory record malformed")
        out = set()
        for x in xs:
            n = S.norm_name(x)
            if not n:
                raise S.ScopeError("inventory record malformed")
            out.add(n)
        return sorted(out)
    hosts = inv.get("hosts")
    if not isinstance(hosts, dict) or len(hosts) > MAX_INVENTORY_HOSTS:
        raise S.ScopeError("inventory record malformed")
    hs = {}
    for h, v in hosts.items():
        n = S.norm_name(h)
        if not n or not isinstance(v, dict) or not isinstance(v.get("ips"), list) or v.get("class") not in HOST_CLASSES:
            raise S.ScopeError("inventory record malformed")
        ips = []
        for ip in v["ips"]:
            o = S.parse_ip(ip)
            if o is None:
                raise S.ScopeError("inventory record malformed")
            ips.append(str(o))
        hs[n] = {"ips": sorted(set(ips)), "class": v["class"]}
        if v.get("via_cname") is not None:     # the provider suffix its class came from (classify.py), when by CNAME
            sfx = S.norm_name(v["via_cname"]) if isinstance(v["via_cname"], str) else None
            if not sfx:
                raise S.ScopeError("inventory record malformed")
            hs[n]["via_cname"] = sfx
    return {"domains": names(inv.get("domains", [])), "lab_targets": names(inv.get("lab_targets", [])), "hosts": hs}


def bind_inventory(inv, domains, lab_targets=None):
    """Refuse (ScopeError, fixed text) unless the recorded inventory covers what the job would scan: for a lab job
    every one of its lab targets; otherwise at least one domain of its scope. A scope domain the inventory did not
    cover never gets an active phase (hold_back holds it back), so adding a domain does not stop the scans of the
    domains already approved. A lab inventory never approves a non-lab job and the reverse. Returns the scope's
    domains the inventory did not cover (always [] for a lab job)."""
    if lab_targets:
        missing = set(lab_targets) - set(inv["lab_targets"])
        if missing:
            raise S.ScopeError(f"the approved inventory does not cover {len(missing)} of the job's lab target(s)")
        return []
    if not domains:
        raise S.ScopeError("the job's scope has no domain to approve")
    if not set(domains) & set(inv["domains"]):
        raise S.ScopeError("the approved inventory covers none of the scope's domains")
    return sorted(set(domains) - set(inv["domains"]))


def approval_doc(inventory_run, by, approved_at, inv):
    return {"approved_at": approved_at, "inventory_run": inventory_run, "approved_by": by, "inventory": inv}


def approve_inventory(root, run_id, by, now=None, scope_dir=None, domains=None, lab_targets=None):
    """Bind and write scope/approval.json. domains defaults to the scope's domains.txt."""
    if not (by or "").strip():
        raise S.ScopeError("--by NAME is required")
    sdir = scope_dir or os.path.join(root, "scope")
    inv = inventory_record(root, run_id)
    if domains is None and not lab_targets:
        domains = [d for d in (S.norm_name(x) for x in S.read_list(os.path.join(sdir, "domains.txt"))) if d]
    bind_inventory(inv, domains, lab_targets)
    doc = approval_doc(run_id, by.strip(), S.iso(now or S.now_utc()), inv)
    p = os.path.join(sdir, "approval.json")
    with open(p + ".tmp", "w") as f:
        json.dump(doc, f, indent=1)
    os.replace(p + ".tmp", p)
    return doc


def load_approval(scope_dir, domains=None, lab_targets=None):
    """The approval in effect for this scope, or (None, reason). The approval must carry the inventory it was bound
    to, and that inventory must still cover the scope's domains (or the lab targets) as they are now."""
    try:
        with open(os.path.join(scope_dir, "approval.json")) as fh:
            d = json.load(fh)
    except FileNotFoundError:
        return None, "no scope/approval.json"
    except (OSError, ValueError):
        return None, "scope/approval.json unreadable"
    try:
        if not isinstance(d, dict) or not all(isinstance(d.get(k), str) and d[k].strip() for k in ("approved_at", "inventory_run", "approved_by")):
            raise S.ScopeError("scope/approval.json incomplete")
        if not isinstance(d.get("inventory"), dict):
            raise S.ScopeError("scope/approval.json carries no inventory (approve a finished inventory run again)")
        inv = normalize_inventory(d["inventory"])
        if domains is None and not lab_targets:
            domains = [x for x in (S.norm_name(y) for y in S.read_list(os.path.join(scope_dir, "domains.txt"))) if x]
        bind_inventory(inv, domains, lab_targets)
    except S.ScopeError as e:
        return None, str(e)
    return dict(d, inventory=inv), None


def _nets(paths):
    nets = []
    for p in paths:
        for c in S.read_list(p):
            try:
                nets.append(ipaddress.ip_network(c, strict=False))
            except ValueError:
                raise S.ScopeError(f"{p}: {c!r} is not a CIDR")
    return nets


def domain_summary(scope_dir, run_dir, inv):
    """{"scanned": [...], "held_back": [...], "pending": [...]} for this run's scope domains: verified this run and
    covered by the approved inventory; verified but not covered (inventory tools only, held back); not verified this
    run (nothing is sent to them). Verified this run = listed in <run dir>/apexes.txt (recon.sh phase 0; empty in a
    lab run, which checks no DNS proof, so a lab run's scope domains all count as pending)."""
    domains = {d for d in (S.norm_name(x) for x in S.read_list(os.path.join(scope_dir, "domains.txt"))) if d}
    verified = {d for d in (S.norm_name(x) for x in S.read_list(os.path.join(run_dir, "apexes.txt"))) if d} & domains
    covered = set(inv["domains"]) if inv else set()
    return {"scanned": sorted(verified & covered), "held_back": sorted(verified - covered), "pending": sorted(domains - verified)}


def hold_back(scope_dir, run_dir, config_dir, lab_targets=None):
    """Compare this run's live hosts with the approved inventory and write <run dir>/held_back.json:
      {"inventory_run", "hosts": {host: reason}, "addresses": {host: {"approved": [...], "now": [...]}},
       "domains": {"scanned", "held_back", "pending"}}
    Raises ScopeError (and writes nothing) when there is no valid approval: then no active phase may run at all."""
    doc, why = load_approval(scope_dir, lab_targets=lab_targets)
    if doc is None:
        raise S.ScopeError(f"no valid approval ({why})")
    assets = []
    p = os.path.join(run_dir, "assets.jsonl")
    if os.path.exists(p):
        with open(p, errors="ignore") as fh:
            for line in fh:
                try:
                    a = json.loads(line)
                except ValueError:
                    continue
                if isinstance(a, dict):
                    assets.append(a)
    owned = _nets([os.path.join(scope_dir, "owned_ranges.txt")])
    providers = _nets([os.path.join(config_dir, "third_party_ranges.txt"), os.path.join(scope_dir, "third_party_ranges.txt")])
    inv = doc["inventory"]
    doms = domain_summary(scope_dir, run_dir, inv)
    apexes = sorted(set(doms["scanned"]) | set(doms["held_back"]), key=len, reverse=True)

    def apex_of(h):   # the longest scope domain the host is under (a nested added domain is its own)
        return next((d for d in apexes if h == d or h.endswith("." + d)), None)
    held = S.compute_held_back(inv["hosts"], assets, owned, providers, held_domains=doms["held_back"], apex_of=apex_of)
    addresses = {}
    for a in assets:
        h = S.norm_name(a.get("hostname", ""))
        if h in held:
            now_ips = sorted({str(o) for o in (S.parse_ip(x) for x in a.get("ips") or []) if o is not None})
            addresses[h] = {"approved": list((inv["hosts"].get(h) or {}).get("ips", [])), "now": now_ips}
    out = os.path.join(run_dir, S.HELD_BACK_FILE)
    with open(out + ".tmp", "w") as fh:
        json.dump({"inventory_run": doc["inventory_run"], "hosts": dict(sorted(held.items())),
                   "addresses": dict(sorted(addresses.items())), "domains": doms}, fh, indent=1)
    os.replace(out + ".tmp", out)
    return held


def main(argv=None):
    root = os.environ.get("SCAN_ROOT") or "/var/lib/scan"
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--scope", help="scope directory (default $SCAN_ROOT/scope)")
    ap.add_argument("--root", default=root, help="scan root (default $SCAN_ROOT)")
    ap.add_argument("--state", help="install secret folder (default $SCAN_ROOT/state)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a1 = sub.add_parser("attest"); a1.add_argument("apex"); a1.add_argument("--by", required=True)
    a2 = sub.add_parser("verify"); a2.add_argument("apex")
    a3 = sub.add_parser("inventory"); a3.add_argument("run_id"); a3.add_argument("--by", required=True)
    a4 = sub.add_parser("check-approval", help="exit 0 when scope/approval.json is valid for the scope as it is now")
    a4.add_argument("--lab-targets-file")
    a5 = sub.add_parser("hold-back", help="after phase 5: write <run dir>/held_back.json, the hosts kept from active phases")
    a5.add_argument("--run-dir", required=True); a5.add_argument("--config", required=True); a5.add_argument("--lab-targets-file")
    a = ap.parse_args(argv)
    sdir = a.scope or os.path.join(a.root, "scope")
    state = a.state or os.path.join(a.root, "state")
    try:
        if a.cmd == "attest":
            ent = attest(sdir, a.apex, a.by, state_dir=state)
            name, value = S.record_for(ent["apex"], ent["token"])
            print(f"{S.OWNERSHIP_RULE}\nRecorded for {ent['apex']}: \"{ent['statement']}\" (by {ent['attested_by']}).")
            print(f"Publish this DNS record, then run: approve.py verify {ent['apex']}\n  {name}.  TXT  \"{value}\"")
            return 0
        if a.cmd == "verify":
            return 0 if verify(sdir, a.apex, state_dir=state) else 1
        if a.cmd == "inventory":
            doc = approve_inventory(a.root, a.run_id, a.by, scope_dir=sdir)
            print(f"approved active phases after inventory run {doc['inventory_run']} ({doc['approved_by']}, {doc['approved_at']}); "
                  f"{len(doc['inventory']['hosts'])} host(s) listed")
            return 0
        if a.cmd == "check-approval":
            lab = None
            if a.lab_targets_file:
                lab = sorted({n for n in (S.norm_name(x) for x in S.read_list(a.lab_targets_file)) if n})
            doc, why = load_approval(sdir, lab_targets=lab)
            if doc is None:
                print(f"approval not valid: {why}", file=sys.stderr)
                return 1
            print(doc["inventory_run"])
            return 0
        if a.cmd == "hold-back":
            lab = None
            if a.lab_targets_file:
                lab = sorted({n for n in (S.norm_name(x) for x in S.read_list(a.lab_targets_file)) if n})
            held = hold_back(sdir, a.run_dir, a.config, lab)
            with open(os.path.join(a.run_dir, S.HELD_BACK_FILE)) as fh:
                doms = json.load(fh)["domains"]
            print(f"held back from active phases: {len(held)} host(s)"
                  + (" (" + ", ".join(f"{r} {sum(1 for v in held.values() if v == r)}" for r in sorted(set(held.values()))) + ")" if held else "")
                  + f"; domains scanned {len(doms['scanned'])}, held back {len(doms['held_back'])}, pending {len(doms['pending'])}")
            return 0
    except S.ScopeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    return 1


if __name__ == "__main__":
    sys.exit(main())
