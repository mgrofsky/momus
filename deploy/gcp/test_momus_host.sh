#!/usr/bin/env bash
# test_momus_host.sh - offline checks for momus-host.sh and startup.sh. Nothing here contacts Google Cloud.
#   deploy/gcp/test_momus_host.sh
# 1. bash -n on both scripts, and shellcheck (from the koalaman/shellcheck image) when Docker can provide it.
# 2. The default mode (and --delete without --apply) runs no command: the script runs in a container with no network
#    and no variable from this machine, with a recording stand-in "gcloud" first on PATH, and the stand-in must
#    record nothing. --apply is never passed, not even to the stand-in.
set -u
cd "$(dirname "${BASH_SOURCE[0]}")" || exit 1
pass=0 fail=0
check(){ if [ "$2" = 0 ]; then pass=$((pass+1)); echo "PASS $1"; else fail=$((fail+1)); echo "FAIL $1${3:+  -- $3}"; fi; }

bash -n momus-host.sh; check "bash -n momus-host.sh" $?
bash -n startup.sh; check "bash -n startup.sh" $?
SC_IMAGE=koalaman/shellcheck:v0.10.0
if docker image inspect "$SC_IMAGE" >/dev/null 2>&1 || docker pull -q "$SC_IMAGE" >/dev/null 2>&1; then
  out=$(docker run --rm --network none -v "$PWD:/mnt:ro" "$SC_IMAGE" momus-host.sh startup.sh test_momus_host.sh 2>&1)
  check "shellcheck (no findings)" $? "$out"
else
  echo "SKIP shellcheck: image $SC_IMAGE not available"
fi

out=$(docker run --rm --network none -e HOME=/nonexistent -v "$PWD:/t:ro" bash:5.2 bash -c '
set -u
mkdir -p /tmp/stub
printf "#!/bin/sh\necho \"\$*\" >> /tmp/calls\n" > /tmp/stub/gcloud
chmod +x /tmp/stub/gcloud
export PATH=/tmp/stub:$PATH
: > /tmp/calls
A="--project demo-project-1 --region us-central1 --zone us-central1-a"
echo "== create"; bash /t/momus-host.sh $A; echo "rc=$?"
echo "== arm64"; bash /t/momus-host.sh $A --arch arm64 --name momus-two --disk-gb 100; echo "rc=$?"
echo "== delete"; bash /t/momus-host.sh $A --delete; echo "rc=$?"
echo "== help"; bash /t/momus-host.sh --help; echo "rc=$?"
for bad in "--project X" "--project demo-project-1 --region us-central1 --zone europe-west4-a" "--name bad_name" \
           "--disk-gb 10" "--arch x86" "--range 8.8.8.0/24" "--machine-type e2;id" "--bogus"; do
  echo "== bad $bad"; bash /t/momus-host.sh $A $bad 2>&1; echo "rc=$?"
done
echo "== calls"; wc -l < /tmp/calls
' 2>&1)
check "default mode: exits 0 and prints the create commands" "$(echo "$out" | awk '/^== create/{f=1;next} /^== /{f=0} f' | grep -c '^gcloud compute ' | grep -qx 7; echo $?)" "$out"
check "default mode: the dry-run notice is printed" "$(echo "$out" | grep -q '^# Dry run: nothing was run'; echo $?)"
check "every printed create command names the project" "$(echo "$out" | awk '/^== create/{f=1;next} /^== /{f=0} f' | grep '^gcloud ' | grep -vc -- '--project=demo-project-1' | grep -qx 0; echo $?)"
check "the VM has no external address, OS Login on, project SSH keys blocked, no service account" \
  "$(echo "$out" | grep '^gcloud compute instances create' | head -1 | grep -- '--no-address' | grep -- 'enable-oslogin=TRUE,block-project-ssh-keys=TRUE' | grep -q -- '--no-service-account --no-scopes'; echo $?)"
check "the only inbound rule is TCP 22 from the IAP range to the VM's tag" \
  "$(echo "$out" | grep '^gcloud compute firewall-rules create' | head -1 | grep -- '--rules=tcp:22' | grep -- '--source-ranges=35.235.240.0/20' | grep -q -- '--target-tags=momus'; echo $?)"
check "the static address is Cloud NAT's outbound address" "$(echo "$out" | grep -q -- '--nat-external-ip-pool=momus-egress'; echo $?)"
check "arm64 picks the arm64 image family and machine type" \
  "$(echo "$out" | grep '^gcloud compute instances create momus-two' | grep -- 'ubuntu-2404-lts-arm64' | grep -- 't2a-standard-2' | grep -q -- '--boot-disk-size=100GB'; echo $?)"
check "--delete prints the seven removal commands" "$(echo "$out" | awk '/^== delete/{f=1;next} /^== /{f=0} f' | grep -c '^gcloud compute .* delete ' | grep -qx 7; echo $?)"
help=$(echo "$out" | awk '/^== help/{f=1;next} /^== /{f=0} f')
check "--help prints the header comment only, then exits 0" \
  "$(echo "$help" | grep -v '^rc=0$' | grep -vc '^#' | grep -qx 0 && echo "$help" | grep -q 'Docker and the Compose plugin (startup.sh)' \
     && echo "$help" | grep -qx 'rc=0'; echo $?)" "$help"
check "every invalid value is refused (exit 2)" "$(echo "$out" | grep -A3 '^== bad' | grep -c '^rc=2$' | grep -qx 8; echo $?)" "$out"
check "no command ran in any mode: the stand-in gcloud recorded nothing" "$(echo "$out" | awk '/^== calls/{getline; print}' | tr -d ' ' | grep -qx 0; echo $?)"

echo "SUMMARY: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
