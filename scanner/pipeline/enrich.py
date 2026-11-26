#!/usr/bin/env python3
"""enrich.py - runs on the scanner host in the fingerprint phase. Two passive lookups for the technology inventory:

  asn.json      {ip: {asn, as_name, prefix, cc}} for every public address of a live host (Team Cymru bulk whois,
                whois.cymru.com:43, no key; one TCP session)
  eol/<slug>.json  the endoflife.date cycle list for every product in config/eol_products.txt

  python3 -I -B enrich.py <run_dir> <eol_products.txt>

Both are best effort: a failure leaves the file(s) missing and ingest (ingest.py) falls back to its cache /
CNAME evidence. Nothing here touches a scanned host.
"""
import ipaddress, json, os, socket, sys, urllib.request

CYMRU = ("whois.cymru.com", 43)
EOL_URL = "https://endoflife.date/api/{slug}.json"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """endoflife.date answers the API URL directly; a redirect is refused (an HTTP error), never followed elsewhere."""
    def redirect_request(self, *a, **k):
        return None


EOL_OPENER = urllib.request.build_opener(_NoRedirect)


def public_ips(run_dir):
    out = []
    for line in open(os.path.join(run_dir, "assets.jsonl"), errors="ignore"):
        try:
            a = json.loads(line)
        except Exception:
            continue
        if a.get("class") not in ("owned", "cdn_fronted", "third_party", "unverified"):
            continue
        for ip in a.get("ips") or []:
            try:
                if ipaddress.ip_address(ip).is_global:
                    out.append(ip)
            except ValueError:
                pass
    return sorted(set(out))


def cymru(ips, timeout=120):
    if not ips:
        return {}
    payload = "begin\nverbose\n" + "\n".join(ips) + "\nend\n"
    s = socket.create_connection(CYMRU, timeout=timeout)
    s.sendall(payload.encode())
    chunks = []
    try:
        while True:
            b = s.recv(65536)
            if not b:
                break
            chunks.append(b)
    finally:
        s.close()
    out = {}
    for line in b"".join(chunks).decode(errors="ignore").splitlines():
        if line.lower().startswith("bulk mode") or "|" not in line:
            continue
        f = [x.strip() for x in line.split("|")]
        if len(f) < 7 or not f[1]:
            continue
        out[f[1]] = {"asn": f[0] if f[0] != "NA" else None, "prefix": f[2] or None, "cc": f[3] or None, "as_name": f[6] or None}
    return out


def main():
    run_dir, products = sys.argv[1], sys.argv[2]
    ips = public_ips(run_dir)
    try:
        asn = cymru(ips)
        json.dump(asn, open(os.path.join(run_dir, "asn.json"), "w"), indent=0, sort_keys=True)
        print(f"asn: {len(asn)}/{len(ips)} addresses resolved")
    except Exception as e:
        print(f"asn: lookup failed ({e}); {len(ips)} addresses stay without ASN")
    slugs = [l.split("#", 1)[0].strip() for l in open(products, errors="ignore")]
    slugs = [s for s in slugs if s]
    os.makedirs(os.path.join(run_dir, "eol"), exist_ok=True)
    ok, bad = 0, []
    for slug in slugs:
        try:
            req = urllib.request.Request(EOL_URL.format(slug=slug), headers={"User-Agent": "momus-enrich/0.1.0"})
            with EOL_OPENER.open(req, timeout=30) as r:
                body = r.read()
            json.loads(body)
            open(os.path.join(run_dir, "eol", f"{slug}.json"), "wb").write(body)
            ok += 1
        except Exception as e:
            bad.append(f"{slug} ({str(e)[:40]})")
            if len(bad) >= 5 and ok == 0:
                print("eol: endoflife.date unreachable, giving up")
                break
    print(f"eol: {ok}/{len(slugs)} products" + (f"; failed: {', '.join(bad[:6])}" if bad else ""))


if __name__ == "__main__":
    main()
