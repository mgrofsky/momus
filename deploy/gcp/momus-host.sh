#!/usr/bin/env bash
# momus-host.sh - one Compute Engine VM for the Momus Compose stack, with no public inbound access.
#
# By default this script only PRINTS the gcloud commands it would run. It runs them only with --apply.
# Written from the Google Cloud documentation (README.md lists every flag with its page).
#
#   deploy/gcp/momus-host.sh --project PROJECT --region REGION --zone ZONE [options]            print the create commands
#   deploy/gcp/momus-host.sh --project PROJECT --region REGION --zone ZONE [options] --apply    run them
#   deploy/gcp/momus-host.sh ... --delete [--apply]                                            print (or run) the removal
#
# Options: --name NAME (default momus; prefix of every resource), --arch amd64|arm64 (default amd64),
#          --machine-type TYPE (default e2-standard-2, or t2a-standard-2 for arm64), --disk-gb N (default 60, 30-1024),
#          --range CIDR (the subnet, default 10.80.0.0/24)
#
# What it creates: a custom-mode VPC network and one subnet (private Google access on); one firewall rule allowing
# TCP 22 only from Identity-Aware Proxy's TCP forwarding range 35.235.240.0/20, to this VM's network tag only; a
# regional static external address used ONLY as Cloud NAT's outbound address (the VM itself has no external address);
# a Cloud Router and Cloud NAT; the VM (Ubuntu 24.04 LTS, shielded VM options on, OS Login on, project-wide SSH keys
# blocked, no service account and no API scopes) with a persistent boot disk, and a startup script that installs
# Docker and the Compose plugin (startup.sh).
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
STARTUP="$HERE/startup.sh"
IAP_RANGE=35.235.240.0/20

project="" region="" zone="" name=momus arch=amd64 machine="" disk_gb=60 range=10.80.0.0/24 apply=0 delete=0
die(){ echo "momus-host: $*" >&2; exit 2; }
need(){ [ $# -ge 2 ] || die "$1 needs a value"; }
while [ $# -gt 0 ]; do
  case "$1" in
    --project) need "$@"; project=$2; shift 2;;
    --region) need "$@"; region=$2; shift 2;;
    --zone) need "$@"; zone=$2; shift 2;;
    --name) need "$@"; name=$2; shift 2;;
    --arch) need "$@"; arch=$2; shift 2;;
    --machine-type) need "$@"; machine=$2; shift 2;;
    --disk-gb) need "$@"; disk_gb=$2; shift 2;;
    --range) need "$@"; range=$2; shift 2;;
    --apply) apply=1; shift;;
    --delete) delete=1; shift;;
    -h|--help) awk 'NR == 1 { next } /^#/ { print; next } { exit }' "${BASH_SOURCE[0]}"; exit 0;;
    *) die "unknown option (see --help)";;
  esac
done

# Every value is checked against a whole-string pattern before it is used in a command.
[[ $project =~ ^[a-z][a-z0-9-]{4,28}[a-z0-9]$ ]] || die "--project: a project id (6-30 characters: lower-case letters, digits, hyphens)"
[[ $region =~ ^[a-z]+-[a-z]+[0-9]{1,2}$ ]] || die "--region: a region such as us-central1"
[[ $zone =~ ^[a-z]+-[a-z]+[0-9]{1,2}-[a-z]$ && $zone == "$region"-? ]] || die "--zone: a zone in --region, such as ${region:-us-central1}-a"
[[ $name =~ ^[a-z][a-z0-9-]{0,30}[a-z0-9]$ ]] || die "--name: 2-32 characters, lower-case letters, digits, hyphens"
[[ $arch =~ ^(amd64|arm64)$ ]] || die "--arch: amd64 or arm64"
if [ -z "$machine" ]; then
  if [ "$arch" = arm64 ]; then machine=t2a-standard-2; else machine=e2-standard-2; fi
fi
[[ $machine =~ ^[a-z][a-z0-9]*-[a-z0-9-]+$ ]] || die "--machine-type: a machine type such as e2-standard-2"
if ! [[ $disk_gb =~ ^[1-9][0-9]{1,3}$ ]] || [ "$disk_gb" -lt 30 ] || [ "$disk_gb" -gt 1024 ]; then die "--disk-gb: 30 to 1024"; fi
[[ $range =~ ^(10|172|192)\.[0-9]{1,3}\.[0-9]{1,3}\.0/(1[6-9]|2[0-8])$ ]] || die "--range: a private IPv4 CIDR from /16 to /28, such as 10.80.0.0/24"
[ -f "$STARTUP" ] || die "startup.sh is missing next to this script"

net=$name-net subnet=$name-subnet fw=$name-allow-iap-ssh addr=$name-egress router=$name-router nat=$name-nat vm=$name
P=(--project="$project")

commands=()
# Each command is kept as one line of shell words: plain words as they are, anything else quoted with printf %q,
# so the printed line can be pasted into a shell and --apply runs exactly the same argument list.
q(){ if [[ $1 =~ ^[A-Za-z0-9_./:=,@+-]+$ ]]; then printf '%s ' "$1"; else printf '%q ' "$1"; fi; }
add(){ local w line=""; for w in "$@"; do line+=$(q "$w"); done; commands+=("$line"); }

if [ "$delete" -eq 0 ]; then
  add gcloud compute networks create "$net" "${P[@]}" --subnet-mode=custom
  add gcloud compute networks subnets create "$subnet" "${P[@]}" --network="$net" --region="$region" --range="$range" \
      --enable-private-ip-google-access
  add gcloud compute firewall-rules create "$fw" "${P[@]}" --network="$net" --direction=INGRESS --action=allow \
      --rules=tcp:22 --source-ranges="$IAP_RANGE" --target-tags="$vm"
  add gcloud compute addresses create "$addr" "${P[@]}" --region="$region"
  add gcloud compute routers create "$router" "${P[@]}" --network="$net" --region="$region"
  add gcloud compute routers nats create "$nat" "${P[@]}" --router="$router" --region="$region" \
      --nat-all-subnet-ip-ranges --nat-external-ip-pool="$addr"
  add gcloud compute instances create "$vm" "${P[@]}" --zone="$zone" --machine-type="$machine" --subnet="$subnet" \
      --no-address --image-family="ubuntu-2404-lts-$arch" --image-project=ubuntu-os-cloud \
      --boot-disk-size="${disk_gb}GB" --boot-disk-type=pd-balanced \
      --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring --tags="$vm" \
      --metadata=enable-oslogin=TRUE,block-project-ssh-keys=TRUE --metadata-from-file=startup-script="$STARTUP" \
      --no-service-account --no-scopes
else
  # reverse order; the VM's boot disk (with the scan data and app database) is deleted with the VM
  add gcloud compute instances delete "$vm" "${P[@]}" --zone="$zone"
  add gcloud compute routers nats delete "$nat" "${P[@]}" --router="$router" --region="$region"
  add gcloud compute routers delete "$router" "${P[@]}" --region="$region"
  add gcloud compute addresses delete "$addr" "${P[@]}" --region="$region"
  add gcloud compute firewall-rules delete "$fw" "${P[@]}"
  add gcloud compute networks subnets delete "$subnet" "${P[@]}" --region="$region"
  add gcloud compute networks delete "$net" "${P[@]}"
fi

if [ "$apply" -eq 0 ]; then
  echo "# Dry run: nothing was run. These are the commands; add --apply to run them in this order."
  for c in "${commands[@]}"; do echo "${c% }"; done
  if [ "$delete" -eq 0 ]; then
    echo "# Afterwards, the UI through Identity-Aware Proxy (README.md):"
    echo "#   gcloud compute ssh $vm --project=$project --zone=$zone --tunnel-through-iap --ssh-flag=\"-L 8080:localhost:8080\""
  fi
  exit 0
fi

echo "momus-host: running ${#commands[@]} commands against project $project" >&2
for c in "${commands[@]}"; do
  echo "+ ${c% }" >&2
  eval "set -- $c"     # each entry was built by add(), so this restores the exact argument list
  "$@"
done
