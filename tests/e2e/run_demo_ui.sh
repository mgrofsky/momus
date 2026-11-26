#!/usr/bin/env bash
# run_demo_ui.sh - end-to-end test of the brain with the scanner and the demo target, in lab mode, on internal
# Docker networks only. A driver (tests/e2e/ui_driver.py) runs in a container on the brain's own internal network
# and uses the brain over HTTP like a browser: bootstrap an admin, add the lab targets, queue an inventory job,
# approve the inventory, queue a full job, wait, then check the findings, the analyst (mock provider: a brief, a
# proposal accepted into a mark, no canary in any recorded prompt), the canaries, the escaped script-tag title
# and the audit log. Cleans up everything it created. Run it on its own (not at the same time as run_demo.sh: both
# use the lab range 10.89.47.0/24).
#   tests/e2e/run_demo_ui.sh
set -u
cd "$(dirname "${BASH_SOURCE[0]}")/../.." || exit 2
ROOT=$PWD
PROJECT=momus-labui
WORK=$(mktemp -d "${TMPDIR:-/tmp}/momus-e2e-ui.XXXXXX")
dc(){ docker compose -p "$PROJECT" -f "$ROOT/compose.yaml" -f "$ROOT/compose.lab.yaml" -f "$ROOT/tests/e2e/compose.ui-e2e.yaml" "$@"; }
PASS=0; FAIL=0
check(){ if [ "$2" -eq 0 ]; then PASS=$((PASS+1)); echo "PASS $1"; else FAIL=$((FAIL+1)); echo "FAIL $1${3:+  [$3]}"; fi; }
cleanup(){ docker rm -f momus-e2e-ui-driver >/dev/null 2>&1; dc --profile dev down -v --remove-orphans >/dev/null 2>&1; rm -rf "$WORK"; }
trap cleanup EXIT

echo "== 0. clean state"
cleanup; WORK=$(mktemp -d "${TMPDIR:-/tmp}/momus-e2e-ui.XXXXXX")

echo "== 1. build and start scanner, demo target and brain in lab mode"
t0=$(date +%s)
dc build >"$WORK/build.log" 2>&1; rc=$?
check "1 images build (scanner, demo target, brain) in $(( $(date +%s) - t0 ))s" $rc "$(tail -5 "$WORK/build.log")"
[ $rc -eq 0 ] || { echo "SUMMARY: $PASS passed, $FAIL failed"; exit 1; }
dc up -d >"$WORK/up.log" 2>&1; check "1 the lab stack starts" $? "$(tail -5 "$WORK/up.log")"
BR=$PROJECT-brain-1; SC=$PROJECT-scanner-1
for c in "$BR" "$SC" "$PROJECT-demo-target-1"; do
  nets=$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$c")
  bad=""; for n in $nets; do [ "$(docker network inspect -f '{{.Internal}}' "$n")" = true ] || bad="$bad $n"; done
  check "1 every network attached to $c is internal ($nets)" "$([ -n "$nets" ] && [ -z "$bad" ]; echo $?)" "not internal:$bad"
done
bn=$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$BR")
sn=$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$SC")
shared=""; for n in $bn; do case " $sn " in *" $n "*) shared="$shared $n";; esac; done
check "1 the brain and the scanner share no network" "$([ -z "$shared" ]; echo $?)" "$shared"
check "1 the brain runs as uid 10001 with a read-only root filesystem" \
  "$([ "$(docker exec "$BR" id -u)" = 10001 ] && [ "$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' "$BR")" = true ]; echo $?)"
TOKEN=""; for i in $(seq 1 60); do TOKEN=$(docker logs "$BR" 2>&1 | sed -n 's/^  BOOTSTRAP TOKEN: //p' | tail -1); [ -n "$TOKEN" ] && break; sleep 1; done
check "1 the brain printed a one-time bootstrap token to its log" "$([ -n "$TOKEN" ]; echo $?)"
for i in $(seq 1 30); do docker logs "$SC" 2>&1 | grep -q 'runner: started' && break; sleep 1; done
asset=$(docker exec "$BR" python3 -B -c 'import urllib.request; r = urllib.request.urlopen("http://127.0.0.1:8080/static/vendor/htmx-2.0.7.min.js", timeout=10); body = r.read(); assert len(body) > 10000 and len(body) == int(r.headers.get("Content-Length", "0")) and b"htmx" in body; print(len(body))' 2>&1); rc=$?
check "1 the browser script downloads in full from the non-root brain" "$rc" "$asset"
[ "$rc" -eq 0 ] || { echo "SUMMARY: $PASS passed, $FAIL failed"; exit 1; }

echo "== 2-9. drive the brain over HTTP"
docker run --name momus-e2e-ui-driver --rm --network "${PROJECT}_brain_lab" --read-only --cap-drop ALL --user 10001:10001 \
  -e BOOTSTRAP_TOKEN="$TOKEN" -v "$ROOT/tests/e2e:/e2e:ro" -v "$ROOT/demo/canaries.json:/c/canaries.json:ro" \
  --entrypoint python3 momus-brain -I -B /e2e/ui_driver.py --base http://brain:8080 --canaries /c/canaries.json >"$WORK/driver.log" 2>&1; rc=$?
cat "$WORK/driver.log"
PASS=$((PASS + $(grep -c '^PASS' "$WORK/driver.log"))); FAIL=$((FAIL + $(grep -c '^FAIL' "$WORK/driver.log")))
if [ $rc -ne 0 ] && ! grep -q '^FAIL' "$WORK/driver.log"; then FAIL=$((FAIL+1)); echo "FAIL ui_driver.py exited $rc"; fi

echo "== 10. canaries in the brain's own log and app database; tear down"
docker logs "$BR" >"$WORK/brain.log" 2>&1
docker cp "$BR:/data/brain.sqlite" "$WORK/brain.sqlite" >/dev/null 2>&1
for f in "$BR:/data/brain.sqlite-wal"; do docker cp "$f" "$WORK/brain.sqlite-wal" >/dev/null 2>&1; done
out=$(python3 -I -B - "$ROOT/demo/canaries.json" "$WORK/brain.log" "$WORK/brain.sqlite" "$WORK/brain.sqlite-wal" <<'PY2'
import json, os, sys
canon = json.load(open(sys.argv[1]))
blobs = [open(p, "rb").read().decode("latin-1") for p in sys.argv[2:] if os.path.exists(p)]
print(("PASS" if len(blobs) >= 2 else "FAIL") + f" 10 read the brain's log and app database ({len(blobs)} files)")
for k, v in sorted(canon["secrets"].items()):
    s = "".join(v["parts"])
    print(("PASS" if not any(s in b for b in blobs) else "FAIL") + f" 10 canary {k} is in neither the brain's log nor its app database")
PY2
)
printf '%s\n' "$out"
PASS=$((PASS + $(printf '%s\n' "$out" | grep -c '^PASS'))); FAIL=$((FAIL + $(printf '%s\n' "$out" | grep -c '^FAIL')))
# the analyst ran with the mock provider, which recorded every prompt it would have sent to a model provider
docker exec "$BR" cat /tmp/analyst-prompts.jsonl >"$WORK/prompts.jsonl" 2>/dev/null
out=$(python3 -I -B - "$ROOT/demo/canaries.json" "$WORK/prompts.jsonl" <<'PY3'
import json, sys
canon = json.load(open(sys.argv[1]))
lines = [json.loads(l) for l in open(sys.argv[2], encoding="utf-8") if l.strip()]
blob = "\n".join(d["system"] + "\n" + d["user"] for d in lines)
print(("PASS" if len(lines) >= 3 else "FAIL") + f" 10 the mock provider recorded the analyst's prompts ({len(lines)})")
print(("PASS" if "target.demo.test" in blob and "untrusted" in blob and '"evidence":' in blob else "FAIL")
      + " 10 the prompts hold the scan results: identifiers, and labeled untrusted text including stored evidence")
for k, v in sorted(canon["secrets"].items()):
    s = "".join(v["parts"])
    print(("PASS" if s not in blob and s.lower() not in blob.lower() else "FAIL") + f" 10 canary {k} is in no prompt recorded by the mock provider")
PY3
)
printf '%s\n' "$out"
PASS=$((PASS + $(printf '%s\n' "$out" | grep -c '^PASS'))); FAIL=$((FAIL + $(printf '%s\n' "$out" | grep -c '^FAIL')))
cleanup; trap - EXIT
left=$(docker ps -a --format '{{.Names}}' | grep -E "^($PROJECT-|momus-e2e-ui)"; docker volume ls -q | grep -E "^${PROJECT}_"; docker network ls --format '{{.Name}}' | grep -E "^${PROJECT}_")
check "10 no container, volume or network from this test is left" "$([ -z "$left" ]; echo $?)" "$left"

echo "SUMMARY: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
