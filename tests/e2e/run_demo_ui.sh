#!/usr/bin/env bash
# run_demo_ui.sh - end-to-end test of the brain with the scanner and the demo target. Those three stay on internal
# Docker networks in lab mode. A driver (tests/e2e/ui_driver.py) connects from the host to the localhost browser bridge
# and uses the brain over HTTP like a browser: bootstrap an admin, add the lab targets, queue an inventory job,
# approve the inventory, queue a full job, wait, then check the findings, the analyst (mock provider: a brief, a
# proposal accepted into a mark, no canary in any recorded prompt), the canaries, the escaped script-tag title,
# the audit log, and a domain added last whose DNS proof record the Scope page's live part shows once published. Cleans up everything it created. Run it on its own (not at the same time as run_demo.sh: both
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
cleanup(){ dc --profile dev down -v --remove-orphans >/dev/null 2>&1; rm -rf "$WORK"; }
trap cleanup EXIT

echo "== 0. clean state"
cleanup; WORK=$(mktemp -d "${TMPDIR:-/tmp}/momus-e2e-ui.XXXXXX")

echo "== 1. build and start scanner, demo target and brain in lab mode"
t0=$(date +%s)
dc build >"$WORK/build.log" 2>&1; rc=$?
check "1 images build (scanner, demo target, brain, browser bridge) in $(( $(date +%s) - t0 ))s" $rc "$(tail -5 "$WORK/build.log")"
[ $rc -eq 0 ] || { echo "SUMMARY: $PASS passed, $FAIL failed"; exit 1; }
dc up -d >"$WORK/up.log" 2>&1; check "1 the lab stack starts" $? "$(tail -5 "$WORK/up.log")"
BR=$PROJECT-brain-1; SC=$PROJECT-scanner-1; PX=$PROJECT-ui-proxy-1
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
pn=$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$PX")
check "1 the browser bridge joins only brain_lab and browser_bridge" \
  "$([ "$pn" = "${PROJECT}_brain_lab ${PROJECT}_browser_bridge " ] || [ "$pn" = "${PROJECT}_browser_bridge ${PROJECT}_brain_lab " ]; echo $?)" "$pn"
check "1 the browser bridge has no mounts and a read-only root filesystem" \
  "$([ "$(docker inspect -f '{{len .Mounts}} {{.HostConfig.ReadonlyRootfs}}' "$PX")" = '0 true' ]; echo $?)"
proxy_env=$(docker inspect -f '{{json .Config.Env}}' "$PX" | python3 -I -B -c 'import json,sys; e=json.load(sys.stdin); print(" ".join(x.split("=",1)[0] for x in e if x.startswith(("MOMUS_","SCAN_","SEED_","AWS_","ANTHROPIC_","OPENAI_","GEMINI_"))))')
check "1 the browser bridge has no app or provider environment settings" "$([ -z "$proxy_env" ]; echo $?)" "$proxy_env"
TOKEN=""; for i in $(seq 1 60); do TOKEN=$(docker logs "$BR" 2>&1 | sed -n 's/^  BOOTSTRAP TOKEN: //p' | tail -1); [ -n "$TOKEN" ] && break; sleep 1; done
check "1 the brain printed a one-time bootstrap token to its log" "$([ -n "$TOKEN" ]; echo $?)"
bind=$(docker port "$PX" 8080/tcp 2>/dev/null)
check "1 the lab web UI is published only on the host loopback address" \
  "$([ "$bind" = '127.0.0.1:18081' ]; echo $?)" "$bind"
page=$(python3 -I -B -c 'import sys,urllib.request; r = urllib.request.urlopen("http://" + sys.argv[1] + "/bootstrap", timeout=10); body = r.read(); assert r.status == 200 and b"First run: create the admin account" in body; print(r.status)' "$bind" 2>&1); rc=$?
check "1 a local browser can load the lab's first-run page" "$rc" "$page"
probe=$(python3 -I -B -c 'import http.client,sys; host,port=sys.argv[1].rsplit(":",1); c=http.client.HTTPConnection(host,int(port),timeout=10); c.request("GET","http://example.com/",headers={"Host":sys.argv[1]}); print(c.getresponse().status)' "$bind" 2>&1); rc=$?
check "1 the browser bridge refuses forward-proxy requests" \
  "$([ "$rc" -eq 0 ] && [ "$probe" = 400 ]; echo $?)" "$probe"
probe=$(python3 -I -B -c 'import http.client,sys; host,port=sys.argv[1].rsplit(":",1); c=http.client.HTTPConnection(host,int(port),timeout=10); c.request("GET","/bootstrap",headers={"Host":"unrelated.example"}); print(c.getresponse().status)' "$bind" 2>&1); rc=$?
check "1 the browser bridge refuses nonlocal Host headers" \
  "$([ "$rc" -eq 0 ] && [ "$probe" = 400 ]; echo $?)" "$probe"
for i in $(seq 1 30); do docker logs "$SC" 2>&1 | grep -q 'runner: started' && break; sleep 1; done
asset=$(docker exec "$BR" python3 -B -c 'import urllib.request; r = urllib.request.urlopen("http://127.0.0.1:8080/static/vendor/htmx-2.0.7.min.js", timeout=10); body = r.read(); assert len(body) > 10000 and len(body) == int(r.headers.get("Content-Length", "0")) and b"htmx" in body; print(len(body))' 2>&1); rc=$?
check "1 the browser script downloads in full from the non-root brain" "$rc" "$asset"
[ "$rc" -eq 0 ] || { echo "SUMMARY: $PASS passed, $FAIL failed"; exit 1; }

echo "== 2-9. drive the brain over HTTP"
BOOTSTRAP_TOKEN="$TOKEN" python3 -I -B "$ROOT/tests/e2e/ui_driver.py" \
  --base "http://$bind" --canaries "$ROOT/demo/canaries.json" >"$WORK/driver.log" 2>&1; rc=$?
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
left=$(docker ps -a --format '{{.Names}}' | grep -E "^${PROJECT}-"; docker volume ls -q | grep -E "^${PROJECT}_"; docker network ls --format '{{.Name}}' | grep -E "^${PROJECT}_")
check "10 no container, volume or network from this test is left" "$([ -z "$left" ]; echo $?)" "$left"

echo "SUMMARY: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
