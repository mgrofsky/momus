#!/usr/bin/env bash
# run_container_test.sh - the seeder container end to end, offline: build it, run it on an internal Docker network
# (no route off this machine) with the zone-file source and invented names, and check the output file, the status
# file, the user it ran as, that the scanner container can read the seed volume but never write to it, and that the
# seeder, mounted as Compose mounts it, can list or read nothing under a "published" path.
# Needs the scanner image (docker build -t momus-scanner scanner/). No host variable is passed into any container.
#   seeder/tests/run_container_test.sh
set -u
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
P=momus-seedtest-$$
SEED=$P-seed SCOPE=$P-scope PUB=$P-pub NET=$P-net
WORK=$(mktemp -d)
pass=0 fail=0
check(){ if [ "$2" = 0 ]; then pass=$((pass+1)); echo "PASS $1"; else fail=$((fail+1)); echo "FAIL $1${3:+  -- $3}"; fi; }
cleanup(){
  docker volume rm -f "$SEED" "$SCOPE" "$PUB" >/dev/null 2>&1
  docker network rm "$NET" >/dev/null 2>&1
  rm -rf "$WORK"
}
trap cleanup EXIT

docker build -q -f seeder/Dockerfile -t momus-seeder . >/dev/null || { echo "FAIL build"; exit 1; }
docker image inspect momus-scanner >/dev/null 2>&1 || { echo "FAIL the scanner image is missing (docker build -t momus-scanner scanner/)"; exit 1; }
docker volume create "$SEED" >/dev/null && docker volume create "$SCOPE" >/dev/null && docker volume create "$PUB" >/dev/null
docker network create --internal "$NET" >/dev/null

# The same settings as the Compose service (compose.yaml "seeder"), spelled out: no host variable, internal network.
seeder_run(){
  docker run --rm --network "$NET" --user 10002:10002 --read-only --tmpfs /tmp:size=16m,mode=1777 --cap-drop ALL \
    --security-opt no-new-privileges:true -e SEED_ZONE_FILES=1 \
    -v "$SCOPE:/srv/seed-scope:ro" -v "$SEED:/srv/seed" -v "$WORK/zones:/srv/seed-zones:ro" momus-seeder
}
scanner_sh(){   # $1 = mount mode (ro|rw), then a shell command; as the scanner user, no network, no entrypoint
  local mode=$1; shift
  docker run --rm --network none --user 10001:10001 --entrypoint sh -v "$SEED:/srv/seed:$mode" momus-scanner -c "$*"
}

# 1. A fresh seed volume is mounted by the scanner first (read-only, as in Compose): it must still end up owned by the
#    seeder's uid, so the seeder can write it later. Docker fills an empty volume from the image's mount point.
scanner_sh ro 'test -d /srv/seed'
own=$(docker run --rm --network none --user 10001:10001 --entrypoint stat -v "$SEED:/srv/seed:ro" momus-scanner -c '%u:%g %a' /srv/seed)
check "a fresh seed volume first mounted by the scanner is owned by the seeder (10002:10002, 755)" "$([ "$own" = "10002:10002 755" ]; echo $?)" "$own"

# 1b. The same for the verified-domain list's volume, first mounted by the seeder (read-only, as in Compose): it must
#     end up owned by the scanner's uid, so the scanner can write the list later.
docker run --rm --network none --user 10002:10002 --entrypoint true -v "$SCOPE:/srv/seed-scope:ro" momus-seeder
own=$(docker run --rm --network none --user 10001:10001 --entrypoint stat -v "$SCOPE:/srv/seed-scope" momus-scanner -c '%u:%g %a' /srv/seed-scope)
check "a fresh seed_scope volume first mounted by the seeder is owned by the scanner (10001:10001, 755)" "$([ "$own" = "10001:10001 755" ]; echo $?)" "$own"

# 2. The scanner's verified-domain list (one verified domain; the scanner never lists a pending one), written by the
#    scanner's own user, and zone files with invented names.
mkdir -p "$WORK/zones"
cat > "$WORK/zones/example.test.zone" <<'Z'
$ORIGIN example.test.
@     IN SOA ns1 hostmaster ( 2030010101 3600 600 86400 300 )
      IN NS  ns1
ns1   IN A   192.0.2.10
www   IN A   192.0.2.11
app   IN CNAME www
ext   IN CNAME somewhere.else.example.
Z
printf 'portal\nvpn.example.test\n198.51.100.7\nx|id.example.test\nbad name.example.test\n' > "$WORK/zones/example.test.hosts"
printf 'www\nmail\n' > "$WORK/zones/pending.test.hosts"
chmod -R a+rX "$WORK/zones"
docker run --rm --network none --user 10001:10001 --entrypoint python3 -v "$SCOPE:/srv/seed-scope" momus-scanner -I -B -c '
import json
json.dump({"schema": "momus-verified-domains-v1", "updated_at": "2030-01-01T00:00:00Z", "domains": ["example.test"]},
          open("/srv/seed-scope/verified_domains.json", "w"))'

# 3. Run the seeder once.
out=$(seeder_run 2>&1); rc=$?
check "the seeder runs once and exits 0" "$rc" "$out"
got=$(scanner_sh ro 'cat /srv/seed/seed_hosts.txt')
want=$(printf '%s\n' app.example.test example.test ext.example.test ns1.example.test portal.example.test vpn.example.test www.example.test)
check "seed_hosts.txt holds the verified domain's host names only, sorted (no address, no pending domain, no junk)" \
  "$([ "$got" = "$want" ]; echo $?)" "$got"
status=$(scanner_sh ro 'cat /srv/seed/status.json')
python3 -I -B - "$status" <<'PY'; check "status.json: schema, counts per source, no target-derived text" "$?"
import json, sys
s = json.loads(sys.argv[1])
assert s["schema"] == "momus-seed-status-v1" and s["result"] == "written" and s["count"] == 7, s
assert (s["domains_verified"], s["domains_refused"], s["failed_sources"]) == (1, 0, []), s
assert s["sources"]["zonefiles"] == {"enabled": True, "names": 7, "errors": ["zonefile-origin-not-a-verified-domain"]}, s
assert all(not s["sources"][k]["enabled"] for k in ("route53", "axfr", "pdns")), s
text = json.dumps(s)
for absent in ("192.0.2", "198.51.100", "somewhere", "hostmaster", "pending.test", "example.test"):
    assert absent not in text, absent
PY
owner=$(scanner_sh ro 'stat -c "%u:%g %a" /srv/seed/seed_hosts.txt')
check "the file was written by the seeder's own user (uid 10002), mode 644" "$([ "$owner" = "10002:10002 644" ]; echo $?)" "$owner"
user=$(docker image inspect -f '{{.Config.User}}' momus-seeder)
check "the seeder image runs as 10002:10002 (not root)" "$([ "$user" = "10002:10002" ]; echo $?)" "$user"
check "the seeder logged counts, no host name or address" \
  "$(echo "$out" | grep -qE 'example\.test|192\.0\.2|198\.51' && echo 1 || echo 0)" "$out"

# 4. The scanner cannot write to the seed volume: neither through its read-only mount, nor with a writable mount
#    (the files belong to uid 10002, mode 644 and 755).
scanner_sh ro 'echo evil.example.test >> /srv/seed/seed_hosts.txt' 2>/dev/null
check "the scanner cannot append to seed_hosts.txt (read-only mount)" "$([ $? -ne 0 ]; echo $?)"
scanner_sh ro 'touch /srv/seed/new' 2>/dev/null
check "the scanner cannot create a file in the seed volume (read-only mount)" "$([ $? -ne 0 ]; echo $?)"
scanner_sh rw 'echo evil.example.test >> /srv/seed/seed_hosts.txt || touch /srv/seed/new' 2>/dev/null
check "the scanner cannot write even with a writable mount (owner and mode)" "$([ $? -ne 0 ]; echo $?)"
check "seed_hosts.txt is unchanged" "$([ "$(scanner_sh ro 'cat /srv/seed/seed_hosts.txt')" = "$want" ]; echo $?)"

# 5. A run that finds nothing keeps the earlier file.
rm -f "$WORK/zones/"*
seeder_run >/dev/null 2>&1
check "a run that finds nothing keeps the earlier file" "$([ "$(scanner_sh ro 'cat /srv/seed/seed_hosts.txt')" = "$want" ]; echo $?)"
res=$(scanner_sh ro 'cat /srv/seed/status.json' | python3 -I -B -c 'import json,sys; print(json.load(sys.stdin)["result"])')
check "status.json says kept-previous" "$([ "$res" = "kept-previous" ]; echo $?)" "$res"

# 6. Control: the test network really is internal (no route off this machine).
internal=$(docker network inspect -f '{{.Internal}}' "$NET")
check "control: the test network is internal" "$([ "$internal" = "true" ]; echo $?)" "$internal"

# 7. The Compose definition (rendered from a copy in an empty folder, so no .env or seed.env is ever read).
mkdir -p "$WORK/compose" && cp compose.yaml "$WORK/compose/"
(cd "$WORK/compose" && docker compose -p momuscheck config --format json) > "$WORK/plain.json" 2>/dev/null
(cd "$WORK/compose" && docker compose -p momuscheck --profile seed config --format json) > "$WORK/seed.json" 2>/dev/null
(cd "$WORK/compose" && python3 -I -B - "$WORK/plain.json" "$WORK/seed.json") <<'PY2'; check "compose: the seeder is profile-only, unprivileged, mounts seed_scope read-only and no published folder; the brain mounts neither volume; the scanner mounts seed read-only and seed_scope read-write" "$?"
import json, sys
plain, seed = (json.load(open(p)) for p in sys.argv[1:3])
assert "seeder" not in plain["services"], "a plain docker compose up must not start the seeder"
s = seed["services"]["seeder"]
assert s["profiles"] == ["seed"] and s["user"] == "10002:10002" and s["read_only"] is True and s["cap_drop"] == ["ALL"], s
assert s["security_opt"] == ["no-new-privileges:true"] and not s.get("ports") and not s.get("cap_add"), s
assert int(s["mem_limit"]) == 512 * 1024 * 1024 and s["restart"] == "no", (s.get("mem_limit"), s.get("restart"))
assert list(s["networks"]) == ["seed_net"] and not seed["networks"]["seed_net"].get("internal"), "ordinary outbound access"
vols = {v["target"]: v for v in s["volumes"]}
assert all(v.get("source") != "published" and "published" not in v["target"] for v in s["volumes"]), "no published mount"
assert vols["/srv/seed-scope"]["source"] == "seed_scope" and vols["/srv/seed-scope"].get("read_only") is True
assert vols["/srv/seed"]["source"] == "seed" and not vols["/srv/seed"].get("read_only")
assert vols["/srv/seed-zones"].get("read_only") is True
raw = open("compose.yaml").read()           # an optional env_file that is absent is dropped from the rendered config
block = raw[raw.index("\n  seeder:\n"):raw.index("\nnetworks:\n")]
assert "- path: seed.env " in block and "path: .env" not in block, "the seeder reads seed.env, never .env"
sc = {v["target"]: v for v in seed["services"]["scanner"]["volumes"]}
assert sc["/srv/seed"]["source"] == "seed" and sc["/srv/seed"].get("read_only") is True
assert sc["/srv/seed-scope"]["source"] == "seed_scope" and not sc["/srv/seed-scope"].get("read_only")
assert all(v.get("source") not in ("seed", "seed_scope") for v in seed["services"]["brain"]["volumes"]), "the brain mounts neither"
assert "seed_net" not in seed["services"]["scanner"]["networks"] and "seed_net" not in seed["services"]["brain"]["networks"]
PY2

# 8. The seeder, mounted exactly as the rendered Compose definition mounts it (each named volume replaced by a test
#    volume; "published" holds a canary snapshot), can list or read nothing under a "published" path. Control: the
#    same probe with the published folder mounted finds the canary, so the probe can fail.
docker run --rm --network none --user 0:0 --entrypoint sh -v "$PUB:/p" momus-seeder -c \
  'mkdir -p /p/snapshots && echo CANARY-PUBLISHED-SNAPSHOT > /p/snapshots/full-1.sqlite && chmod -R a+rX /p'
mounts=$(python3 -I -B - "$WORK/seed.json" "$SEED" "$SCOPE" "$PUB" "$WORK/zones" <<'PY3'
import json, sys
seed, vol = json.load(open(sys.argv[1])), {"seed": sys.argv[2], "seed_scope": sys.argv[3], "published": sys.argv[4]}
for v in seed["services"]["seeder"]["volumes"]:
    src = vol[v["source"]] if v["type"] == "volume" else sys.argv[5]
    print(f"-v {src}:{v['target']}" + (":ro" if v.get("read_only") else ""))
PY3
)
probe='
import os
hits = []
for root, dirs, files in os.walk("/"):
    dirs[:] = [d for d in dirs if os.path.join(root, d) not in ("/proc", "/sys", "/dev")]
    for name in dirs + files:
        p = os.path.join(root, name)
        if "published" in p.lower():
            hits.append(p)
        elif name in files and p.startswith(("/srv/", "/tmp/")):
            try:
                with open(p, "rb") as fh:
                    if b"CANARY-PUBLISHED" in fh.read(1 << 20):
                        hits.append(p)
            except OSError:
                pass
print("found:", sorted(hits))'
# shellcheck disable=SC2086
seen=$(docker run --rm --network none --user 10002:10002 --read-only --cap-drop ALL $mounts --entrypoint python3 momus-seeder -I -B -c "$probe" 2>&1)
echo "  seeder with the Compose mounts ($(echo $mounts | tr '\n' ' ')): $seen"
check "the seeder cannot list or read anything under a published path" "$([ "$seen" = "found: []" ]; echo $?)" "$seen"
# shellcheck disable=SC2086
ctl=$(docker run --rm --network none --user 10002:10002 --read-only --cap-drop ALL $mounts -v "$PUB:/srv/published:ro" --entrypoint python3 momus-seeder -I -B -c "$probe" 2>&1)
check "control: with the published folder mounted, the same probe finds the canary" "$(echo "$ctl" | grep -q '/srv/published/snapshots/full-1.sqlite'; echo $?)" "$ctl"

echo "SUMMARY: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
