#!/usr/bin/env bash
# recon.sh - runs in the scanner image as a non-root user. Non-intrusive external attack-surface scan of domains the
# person running it owns. All output goes to $RUN_DIR as JSON/JSONL/XML.
#
# Usage: recon.sh --run-id ID [--inventory-only] [--from-phase N] [--phases 6,8] [--nuclei-passes generic,tech,tp,dns,fp]
#        recon.sh --run-id ID-recheck --recheck BASE_RUN_ID                 daily recheck (see below)
#        SCAN_LAB=1 recon.sh --run-id ID --targets-file FILE --lab-cidr CIDR  lab run against a local target only
#        recon.sh --print-config                                            print the resolved profiles and tool numbers
#
# Scope ($SCAN_ROOT/scope, see pipeline/scope.py): domains.txt (required), exclude.txt, owned_ranges.txt,
# approved_hosts.txt, ownership.json (statement + DNS proof per apex, written by pipeline/approve.py),
# approval.json (inventory approved; without it the run is inventory-only), profile.json (optional profiles).
# Every target list is passed through scope.py immediately before the tool that uses it; rejections are logged to
# scope_rejected.jsonl and the hosts actually handed to each source are written to coverage/<source>.txt.
#
# Profiles: SCAN_CHECK_PROFILE safe (default) | active; SCAN_RATE_PROFILE low (default) | normal | fast.
# scope/profile.json {"check_profile": ..., "rate_profile": ...} takes precedence when present.
# Evidence: SCAN_EVIDENCE minimal (default) | excerpt: what ingest stores of each finding (pipeline/minimize.py);
# recorded in the manifest as "evidence". Raw tool output stays in the run directory (pipeline/retention.py).
#
# Daily recheck (--recheck): no discovery. Phase 1 takes the host list from scope/recheck_hosts.txt (written by
# pipeline/recheck_targets.py from the scan database) and phases 2-8 run on those hosts exactly as in a full run,
# except that nuclei targets are the BASE run's representatives restricted to those hosts. The manifest carries
# recheck/base_run so ingest marks fixed only what was re-tested and carries the rest forward.
#
# Phases:
#   0 start       ownership rule, profiles, scope check, DNS proof re-check of every apex, approval check
#   1 enumerate   seed names ($SCAN_SEED_DIR/seed_hosts.txt, untrusted) + subfinder + assetfinder + crt.sh + dnsrecon
#                 -> name gate -> subdomains.txt
#   2 resolve     dnsx (A/AAAA/CNAME) -> dns.jsonl ; apex MX/TXT/NS/CAA/SOA + _dmarc -> dns_apex.jsonl ;
#                 AXFR attempt per apex nameserver address that passes the address gate -> axfr.json
#   3 probe       httpx-toolkit on hosts whose every address passes the address gate -> httpx.jsonl
#   4 classify    classify.py -> assets.jsonl + target lists (owned / cdn_fronted / unverified / third_party)
#   5 fingerprint whatweb + wafw00f on live URLs + enrich.py (ASN, end-of-life feeds) -> technology inventory
#   --- inventory-only stops here (also when scope/approval.json is missing) ---
#   6 portscan    nmap on addresses that pass scope.portscan_allowed only
#   7 tls         sslscan on every https host
#   8 nuclei      owned+cdn_fronted+unverified: non-intrusive set ; third_party: takeover/misconfig/dns ;
#                 fp: info-level technology-detect templates (inventory only, never a finding)
#   9 manifest    tool versions, profiles, coverage, counts, phase exit codes -> manifest.json ; touch .done
# Critical (abort the run, non-zero exit, before any later tool): scope loading, DNS proof, excluded-tags file,
# enumerate, resolve, classify. Later phases depend on their output, and a half-built target list must never be
# scanned. Probe, fingerprint, portscan, tls and nuclei failures are recorded and the run continues.
# Update checks: subfinder, dnsx, httpx-toolkit and nuclei (one publisher) each check for a newer release at start
# unless told not to; every call here passes -duc. The tools are fixed by the image, so such a check would only be
# traffic to a third party (api.pdtm.sh). assetfinder, dnsrecon, nmap, sslscan, whatweb and wafw00f have no such check.

set -u
set -o pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PIPE=$SCRIPT_DIR/pipeline        # Python pipeline (classify.py, scope.py, ...)
CONF=$SCRIPT_DIR/config          # shipped configuration (exclude_tags.txt, provider lists, eol_products.txt)
# keep the caller's PATH first (the shim tests rely on it); only make sure the standard directories are present
PATH=$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
: "${HOME:?HOME must be set (the nuclei configuration lives under it)}"

BASE=${SCAN_ROOT:-/var/lib/scan}   # scan root: scope/ and runs/ live under it
SCOPE=$BASE/scope
SEED_DIR=${SCAN_SEED_DIR:-/srv/seed}   # the seeder's volume (read-only mount); see pipeline/seed_input.py
EXCLUDE_TAGS_FILE=$CONF/exclude_tags.txt
# Port set for nmap: nmap's own top-100 TCP list plus services that should never be internet-facing.
TOP100_PORTS=7,9,13,21-23,25-26,37,53,79-81,88,106,110-111,113,119,135,139,143-144,179,199,389,427,443-445,465,513-515,543-544,548,554,587,631,646,873,990,993,995,1025-1029,1110,1433,1720,1723,1755,1900,2000-2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000-6001,6646,7070,8000,8008-8009,8080-8081,8443,8888,9100,9999-10000,32768,49152-49157
RISKY_PORTS=137,1434,1521,2375,2376,4369,5901,5984,5985,5986,6379,6443,7001,8088,9000,9042,9090,9200,9300,11211,27017,27018,50070
SCAN_PORTS=$TOP100_PORTS,$RISKY_PORTS

# ---------------------------------------------------------------- rate profiles: every rate, concurrency and timeout
# normal = the reference numbers the other two are derived from; low = about a third (the default: a stranger's network and
# target should never feel this scan); fast = normal x 1.5, capped (nmap --max-rate 300, nuclei -rl 450, -c 75).
# Timeouts and retry counts are the same in every profile: a slower scan must not give up sooner.
RATE_TABLE='
# key                      low   normal  fast   used as
DNSX_THREADS               16    50      75     dnsx -t
DNSX_RETRY                 3     3       3      dnsx -retry (attempts)
HTTPX_RL                   66    200     300    httpx-toolkit -rl (requests/s)
HTTPX_THREADS              26    80      120    httpx-toolkit -t
HTTPX_TIMEOUT              8     8       8      httpx-toolkit -timeout (s)
HTTPX_RETRIES              1     1       1      httpx-toolkit -retries
WHATWEB_THREADS            8     25      37     whatweb --max-threads (25 is its default)
WHATWEB_OPEN_TIMEOUT       15    15      15     whatweb --open-timeout (s, its default)
WHATWEB_READ_TIMEOUT       30    30      30     whatweb --read-timeout (s, its default)
NMAP_CHUNK                 21    64      96     hosts per nmap burst
NMAP_MAX_RATE              66    200     300    nmap --max-rate (packets/s)
NMAP_PARALLELISM           10    32      48     nmap --max-parallelism
NMAP_PAUSE                 15    5       5      seconds between bursts
NMAP_RETRIES               2     2       2      nmap --max-retries
NMAP_HOST_TIMEOUT          10m   10m     10m    nmap --host-timeout
SSLSCAN_PARALLEL           5     16      24     sslscan processes in parallel
SSLSCAN_CONNECT_TIMEOUT    10    10      10     sslscan --connect-timeout (s)
NUC_GENERIC_RL             100   300     450    nuclei generic pass -rl
NUC_GENERIC_C              16    50      75     nuclei generic pass -c
NUC_GENERIC_BS             16    50      75     nuclei generic pass -bs
NUC_TECH_RL                50    150     225    nuclei tech pass -rl
NUC_TECH_C                 8     25      37     nuclei tech pass -c
NUC_TECH_BS                8     25      37     nuclei tech pass -bs
NUC_TP_RL                  33    100     150    nuclei third-party pass -rl
NUC_TP_C                   7     20      30     nuclei third-party pass -c
NUC_TP_BS                  7     20      30     nuclei third-party pass -bs
NUC_DNS_RL                 50    150     225    nuclei dns pass -rl
NUC_DNS_C                  10    30      45     nuclei dns pass -c
NUC_FP_RL                  50    150     225    nuclei fp pass -rl
NUC_FP_C                   10    30      45     nuclei fp pass -c
NUC_FP_BS                  10    30      45     nuclei fp pass -bs
NUC_TIMEOUT                8     8       8      nuclei -timeout (s), http passes
NUC_DNS_TIMEOUT            5     5       5      nuclei -timeout (s), dns pass
NUC_RETRIES                1     1       1      nuclei -retries
DIG_TIME                   5     5       5      dig +timeout (s) for AXFR attempts
'
# Check profiles: the seven tags below run only under "active"; under "safe" they are excluded from every nuclei
# pass. exclude_tags.txt (intrusive, dos, fuzz, ...) is excluded under both. Interactsh is off in both (-ni).
ACTIVE_TAGS=default-login,sqli,rce,lfi,ssrf,xss,injection
GENERIC_TAGS=misconfig,exposure,takeover,config,backup,panel,ssl,dns,headers,token,creds,disclosure,redirect,cors

RUN_ID=""
DOMAINS=$SCOPE/domains.txt
INVENTORY_ONLY=0
INVENTORY_REASON=""
FROM_PHASE=1
PHASES=""           # comma-separated subset to run; empty = all from FROM_PHASE
NUCLEI_PASSES="generic,tech,tp,dns,fp"   # --nuclei-passes: which nuclei passes phase 8 runs
RECHECK_BASE=""     # --recheck BASE: daily recheck on top of runs/BASE (see header)
TARGETS_FILE=""     # --targets-file: lab mode
LAB_CIDR=""
PRINT_CONFIG=0

while [ $# -gt 0 ]; do
  case "$1" in
    --run-id) RUN_ID=$2; shift 2;;
    --domains) DOMAINS=$2; shift 2;;
    --inventory-only) INVENTORY_ONLY=1; INVENTORY_REASON="--inventory-only"; shift;;
    --from-phase) FROM_PHASE=$2; shift 2;;
    --phases) PHASES=$2; shift 2;;
    --nuclei-passes) NUCLEI_PASSES=$2; shift 2;;
    --recheck) RECHECK_BASE=$2; shift 2;;
    --targets-file) TARGETS_FILE=$2; shift 2;;
    --lab-cidr) LAB_CIDR=$2; shift 2;;
    --print-config) PRINT_CONFIG=1; shift;;
    *) echo "unknown arg $1" >&2; exit 2;;
  esac
done

# ---------------------------------------------------------------- profiles (env, then scope/profile.json wins)
CHECK_PROFILE=${SCAN_CHECK_PROFILE:-safe}
RATE_PROFILE=${SCAN_RATE_PROFILE:-low}
PROFILE_SOURCE="environment/default"
if [ -f "$SCOPE/profile.json" ]; then
  pj=$(python3 -I -B - "$SCOPE/profile.json" <<'PY'
import json,sys
try:
    d=json.load(open(sys.argv[1]))
    assert isinstance(d,dict) and set(d) <= {"check_profile","rate_profile"}, "only check_profile and rate_profile are allowed"
except Exception as e:
    print("ERROR",e); sys.exit(0)
print(str(d.get("check_profile",""))+"|"+str(d.get("rate_profile","")))
PY
)
  case "$pj" in ERROR*) echo "scope/profile.json unreadable: ${pj#ERROR }" >&2; exit 2;; esac
  IFS='|' read -r pj_check pj_rate <<<"$pj"
  [ -n "${pj_check:-}" ] && CHECK_PROFILE=$pj_check
  [ -n "${pj_rate:-}" ] && RATE_PROFILE=$pj_rate
  PROFILE_SOURCE="scope/profile.json"
fi
case "$CHECK_PROFILE" in safe|active) ;; *) echo "check profile '$CHECK_PROFILE' unknown (safe|active)" >&2; exit 2;; esac
# what ingest stores of each finding's evidence (pipeline/minimize.py); recorded in the manifest
EVIDENCE_LEVEL=${SCAN_EVIDENCE:-minimal}
case "$EVIDENCE_LEVEL" in minimal|excerpt) ;; *) echo "SCAN_EVIDENCE '$EVIDENCE_LEVEL' unknown (minimal|excerpt)" >&2; exit 2;; esac
case "$RATE_PROFILE" in low) RCOL=2;; normal) RCOL=3;; fast) RCOL=4;; *) echo "rate profile '$RATE_PROFILE' unknown (low|normal|fast)" >&2; exit 2;; esac
rate(){ printf '%s\n' "$RATE_TABLE" | awk -v k="$1" -v c="$RCOL" '$1==k{print $c; f=1} END{if(!f) exit 1}' || { echo "rate key $1 missing" >&2; exit 2; }; }
for k in $(printf '%s\n' "$RATE_TABLE" | awk '$1 ~ /^[A-Z_]+$/{print $1}'); do printf -v "$k" '%s' "$(rate "$k")"; done
if [ "$CHECK_PROFILE" = active ]; then NUC_GENERIC_TAGS=$GENERIC_TAGS,$ACTIVE_TAGS; PROFILE_ETAGS=""
else NUC_GENERIC_TAGS=$GENERIC_TAGS; PROFILE_ETAGS=$ACTIVE_TAGS; fi
PROFILE_LINE="profiles: checks=$CHECK_PROFILE rates=$RATE_PROFILE (from $PROFILE_SOURCE). Change: set \"check_profile\": \"active\" or \"rate_profile\": \"normal|fast\" in scope/profile.json, or SCAN_CHECK_PROFILE / SCAN_RATE_PROFILE when that file is absent"

if [ "$PRINT_CONFIG" -eq 1 ]; then
  echo "CHECK_PROFILE=$CHECK_PROFILE"; echo "RATE_PROFILE=$RATE_PROFILE"; echo "PROFILE_SOURCE=$PROFILE_SOURCE"
  echo "NUC_GENERIC_TAGS=$NUC_GENERIC_TAGS"; echo "PROFILE_ETAGS=$PROFILE_ETAGS"; echo "EVIDENCE_LEVEL=$EVIDENCE_LEVEL"
  for k in $(printf '%s\n' "$RATE_TABLE" | awk '$1 ~ /^[A-Z_]+$/{print $1}'); do echo "$k=${!k}"; done
  exit 0
fi

[ -n "$RUN_ID" ] || { echo "--run-id required" >&2; exit 2; }
case "$RUN_ID" in *[!A-Za-z0-9._-]*|.*|"") echo "--run-id may hold letters, digits, . _ - only" >&2; exit 2;; esac

# ---------------------------------------------------------------- lab mode: refuse before anything else happens
LAB=0
if [ -n "$TARGETS_FILE" ] || [ -n "$LAB_CIDR" ]; then
  [ -n "$TARGETS_FILE" ] && [ -n "$LAB_CIDR" ] || { echo "lab mode needs both --targets-file and --lab-cidr" >&2; exit 2; }
  LAB_NET=$(python3 -I -B "$PIPE/scope.py" lab-check --cidr "$LAB_CIDR") || exit 2
  [ -s "$TARGETS_FILE" ] || { echo "lab mode: --targets-file $TARGETS_FILE missing or empty" >&2; exit 2; }
  [ -z "$RECHECK_BASE" ] || { echo "lab mode and --recheck do not combine" >&2; exit 2; }
  LAB=1
fi
# lab mode: the lab network is internal, so the built-in public resolvers of dnsx, httpx and nuclei are unreachable,
# and their fallbacks fail lookups under concurrency ("no address found for host"): a live host or a check silently
# drops out. In lab mode all three ask the container's own resolver instead: the
# first nameserver in /etc/resolv.conf (Docker's 127.0.0.11, which answers the lab names). The one place it is read.
# Outside lab mode every tool keeps its own resolvers.
LAB_NS=""
[ "$LAB" -eq 1 ] && LAB_NS=$(awk '$1=="nameserver"{print $2; exit}' /etc/resolv.conf 2>/dev/null)
if [ -n "$RECHECK_BASE" ]; then
  [ -d "$BASE/runs/$RECHECK_BASE" ] || { echo "--recheck: base run $BASE/runs/$RECHECK_BASE not on this host" >&2; exit 2; }
  [ -s "$SCOPE/recheck_hosts.txt" ] || { echo "--recheck: $SCOPE/recheck_hosts.txt missing or empty (run pipeline/recheck_targets.py first)" >&2; exit 2; }
  [ "$INVENTORY_ONLY" -eq 0 ] || { echo "--recheck and --inventory-only do not combine" >&2; exit 2; }
fi

RUN_DIR=$BASE/runs/$RUN_ID
mkdir -p "$RUN_DIR/coverage"
cd "$RUN_DIR" || exit 2
LOG=$RUN_DIR/recon.log
PHASES_FILE=$RUN_DIR/phases.jsonl
rm -f "$RUN_DIR/.done"
[ "$FROM_PHASE" -le 1 ] && [ -z "$PHASES" ] && : > "$PHASES_FILE"

log(){ printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" | tee -a "$LOG"; }
now(){ date -u +%FT%TZ; }
# grep -c prints 0 and exits 1 for an empty file: without the inner "|| true" this printed "0" twice ("0\n0"), and
# every "[ "$(count f)" -gt 0 ]" on an empty file failed with "integer expected" (false by accident)
count(){ if [ -f "$1" ]; then grep -c . "$1" || true; else echo 0; fi; }

# gate STAGE KIND IN OUT [COVER]: the scope filter, run immediately before the tool that reads OUT.
gate(){
  local stage=$1 kind=$2 in=$3 out=$4 cover=${5:-}
  rm -f "$out"
  python3 -I -B "$PIPE/scope.py" filter --scope "$SCOPE" --run-dir "$RUN_DIR" --stage "$stage" --kind "$kind" \
    --in "$in" --out "$out" ${cover:+--cover "$cover"} || { echo "scope gate $stage failed"; rm -f "$out"; return 1; }
}
cover_reset(){ local s; for s in "$@"; do : > "$RUN_DIR/coverage/$s.txt"; done; }
# the approval must carry the inventory it was bound to, and that inventory must cover every domain in the scope
# as it is now (in lab mode: every lab target); approve.py is the one place that decides
approval_ok(){
  local lab=(); [ "$LAB" -eq 1 ] && lab=(--lab-targets-file "$TARGETS_FILE")
  python3 -I -B "$PIPE/approve.py" --root "$BASE" --scope "$SCOPE" check-approval "${lab[@]}" >/dev/null 2>>"$LOG"
}
exclude_tags(){
  # fail closed: nuclei never runs with an empty excluded-tags list
  [ -r "$EXCLUDE_TAGS_FILE" ] || { echo "excluded-tags file $EXCLUDE_TAGS_FILE missing or unreadable" >&2; return 1; }
  local t; t=$(grep -vE '^\s*(#|$)' "$EXCLUDE_TAGS_FILE" | tr -d ' \r' | paste -sd, -)
  [ -n "$t" ] || { echo "excluded-tags file $EXCLUDE_TAGS_FILE is empty" >&2; return 1; }
  printf '%s' "$t"
}

# run_phase N name -- runs the shell function phase_<name>, records rc. Critical phases abort the run.
CRITICAL_PHASES=",1,2,4,"
run_phase(){
  local n=$1 name=$2
  if [ "$n" -lt "$FROM_PHASE" ]; then log "phase $n $name skipped (--from-phase $FROM_PHASE)"; return 0; fi
  if [ -n "$PHASES" ] && ! printf ',%s,' "$PHASES" | grep -q ",$n,"; then log "phase $n $name skipped (--phases $PHASES)"; return 0; fi
  log "=== phase $n $name start"
  local start rc end
  start=$(now)
  "phase_$name" >>"$LOG" 2>&1; rc=$?
  end=$(now)
  printf '{"phase":%d,"name":"%s","start":"%s","end":"%s","rc":%d}\n' "$n" "$name" "$start" "$end" "$rc" >> "$PHASES_FILE"
  log "=== phase $n $name end rc=$rc"
  if [ "$rc" -ne 0 ] && printf '%s' "$CRITICAL_PHASES" | grep -q ",$n,"; then log "fatal: phase $n $name failed; nothing later runs"; finish 1; fi
  return 0
}

finish(){
  local rc=${1:-0}
  phase_manifest "$rc" >>"$LOG" 2>&1
  touch "$RUN_DIR/.done"
  log "run finished rc=$rc"
  exit "$rc"
}
fatal(){ log "fatal: $*"; finish 1; }

trap 'log "signal received"; finish 130' INT TERM
NUCLEI_TEMPLATES=$(python3 -I -B -c 'import json,os;print(json.load(open(os.path.expanduser("~/.config/nuclei/.templates-config.json")))["nuclei-templates-directory"])' 2>/dev/null || echo "$HOME/.local/nuclei-templates")
APPROVED=0

# ---------------------------------------------------------------- 0 start: rule, profiles, scope, DNS proof, approval
log "rule: $(python3 -I -B -c 'import sys; sys.path.insert(0, sys.argv[1]); import scope; print(scope.OWNERSHIP_RULE)' "$PIPE")"
log "$PROFILE_LINE"
exclude_tags >/dev/null 2>>"$LOG" || fatal "excluded-tags file missing, unreadable or empty: refusing to run (nuclei must never run without it)"
if [ "$LAB" -eq 1 ]; then
  python3 -I -B - "$RUN_DIR" "$LAB_NET" "$TARGETS_FILE" <<'PY' || fatal "lab targets file unreadable"
import json,os,sys
run,cidr,tf=sys.argv[1:4]
hosts=sorted({l.split("#",1)[0].strip().lower().rstrip(".") for l in open(tf) if l.split("#",1)[0].strip()})
json.dump({"cidr":cidr,"hosts":hosts},open(os.path.join(run,"lab.json"),"w"),indent=1)
PY
  log "lab run: targets $(count "$TARGETS_FILE") from $TARGETS_FILE, lab CIDR $LAB_NET; enumeration skipped; names in the targets file need no DNS proof"
else
  rm -f "$RUN_DIR/lab.json"
fi
[ "$DOMAINS" = "$SCOPE/domains.txt" ] || fatal "--domains is not supported: the scope is $SCOPE/domains.txt with its ownership and DNS proof"
python3 -I -B "$PIPE/scope.py" check --scope "$SCOPE" --run-dir "$RUN_DIR" > scope_apexes.txt 2>>"$LOG" || fatal "scope could not be loaded (see above)"
if [ "$LAB" -eq 1 ]; then
  : > apexes.txt
else
  log "dns proof: re-checking $(count scope_apexes.txt) apex(es) at their own nameservers"
  python3 -I -B "$PIPE/scope.py" recheck-dns --scope "$SCOPE" --run-dir "$RUN_DIR" --state "$BASE/state" > apexes.txt 2>>"$LOG" || fatal "DNS proof check failed to run"
  [ "$(count apexes.txt)" -gt 0 ] || fatal "no apex passed the DNS proof check; nothing may be scanned"
  log "dns proof: $(count apexes.txt) of $(count scope_apexes.txt) apex(es) usable: $(paste -sd, - < apexes.txt)"
fi
rm -f "$RUN_DIR/held_back.json"
if approval_ok; then APPROVED=1; fi
if [ "$INVENTORY_ONLY" -eq 0 ] && [ "$APPROVED" -eq 0 ]; then
  [ -z "$RECHECK_BASE" ] || fatal "--recheck runs active phases and needs a valid scope/approval.json (pipeline/approve.py inventory RUN_ID --by NAME)"
  INVENTORY_ONLY=1; INVENTORY_REASON="no valid scope/approval.json"
  log "inventory-only: scope/approval.json is missing or invalid (not bound to an inventory that covers this scope); no port scan, no nuclei. Review this run's inventory, then: approve.py inventory $RUN_ID --by 'Your Name'"
fi
APEXES=$(cat apexes.txt)

# ---------------------------------------------------------------- 1 enumerate
phase_enumerate(){
  if [ "$LAB" -eq 1 ]; then
    gate enumerate names "$TARGETS_FILE" subdomains.txt || return 1
    python3 -I -B -c 'import json,sys; h=[l.strip() for l in open("subdomains.txt") if l.strip()]; json.dump({x:["lab"] for x in h},open("sources.json","w"),indent=0); print("lab targets:",len(h))'
    [ "$(count subdomains.txt)" -gt 0 ]; return $?
  fi
  if [ -n "$RECHECK_BASE" ]; then
    # recheck: the host list is given (and gated like everything else); discovery sources come from the base run
    grep -vE '^\s*(#|$)' "$SCOPE/recheck_hosts.txt" | tr -d '\r' | tr 'A-Z' 'a-z' | sort -u > recheck_hosts_raw.txt
    gate recheck names recheck_hosts_raw.txt recheck_hosts.txt || return 1
    cp recheck_hosts.txt subdomains.txt
    python3 -I -B - "$RUN_DIR" "$BASE/runs/$RECHECK_BASE" <<'PY'
import sys,os,json
run,base=sys.argv[1:3]
hosts=[l.strip() for l in open(os.path.join(run,"recheck_hosts.txt")) if l.strip()]
try: src=json.load(open(os.path.join(base,"sources.json")))
except Exception: src={}
json.dump({h:sorted(src.get(h,["recheck"])) for h in hosts},open(os.path.join(run,"sources.json"),"w"),indent=0)
print("recheck hosts:",len(hosts),"base:",base)
PY
    [ "$(count subdomains.txt)" -gt 0 ]; return $?
  fi
  : > sub_subfinder.txt; : > sub_assetfinder.txt; : > sub_crtsh.txt; : > sub_dnsrecon.txt; : > sub_seed.txt
  # Seed names from the optional seeder container (its own volume, read-only here; nothing in the scope folder).
  # Untrusted input: no symlink, size and line caps, host-name lines only (seed_input.py); the names then pass the
  # name gate below with every other source. A missing or bad file is skipped and discovery goes on without it.
  python3 -I -B "$PIPE/seed_input.py" --seed-dir "$SEED_DIR" --out sub_seed.txt --record seed_read.json \
    || { echo "seed reader failed; passive enumeration only"; : > sub_seed.txt; }
  # Only DNS-verified apexes reach here (phase 0). These tools ask third-party sources about the apex; dnsrecon
  # also asks the apex's nameservers for its standard records, so it runs only for an apex whose every nameserver
  # address passes the DNS proof's address check again now (scope.py ns-check; a failure skips them all).
  python3 -I -B "$PIPE/scope.py" ns-check --scope "$SCOPE" --run-dir "$RUN_DIR" --stage dnsrecon $APEXES > dnsrecon_apexes.txt 2>>"$LOG" \
    || { echo "dnsrecon gate failed; dnsrecon skipped for every apex"; : > dnsrecon_apexes.txt; }
  timeout 20m subfinder -duc -dL apexes.txt -all -silent -o sub_subfinder.txt || echo "subfinder rc=$?"
  for d in $APEXES; do
    timeout 5m assetfinder --subs-only "$d" >> sub_assetfinder.txt 2>/dev/null || echo "assetfinder $d rc=$?"
    curl -sS -m 60 "https://crt.sh/?q=%25.$d&output=json" \
      | python3 -I -B -c 'import sys,json
try: data=json.load(sys.stdin)
except Exception: data=[]
for e in data:
    for n in str(e.get("name_value","")).split("\n"):
        print(n.strip().lower())' >> sub_crtsh.txt 2>/dev/null || echo "crt.sh $d rc=$?"
    if ! grep -qxF "$d" dnsrecon_apexes.txt; then
      echo "dnsrecon $d skipped: a nameserver address failed the address check (scope_rejected.jsonl)"; continue
    fi
    timeout 5m dnsrecon -d "$d" -t std -j "dnsrecon_$d.json" >/dev/null 2>&1 || echo "dnsrecon $d rc=$?"
    python3 -I -B - "dnsrecon_$d.json" >> sub_dnsrecon.txt <<'PY' || true
import sys,json
try: recs=json.load(open(sys.argv[1]))
except Exception: recs=[]
for r in recs:
    for k in ("name","target","exchange","mname"):
        v=r.get(k)
        if v: print(str(v).lower())
PY
  done
  python3 -I -B - "$RUN_DIR" <<'PY' || return 1
import sys,os,re,json
run=sys.argv[1]
apexes=[l.strip() for l in open(os.path.join(run,"apexes.txt")) if l.strip()]
names=set(apexes)
pat=re.compile(r'[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)+')
sources={a:{"apex"} for a in apexes}
for f in ("sub_seed.txt","sub_subfinder.txt","sub_assetfinder.txt","sub_crtsh.txt","sub_dnsrecon.txt"):
    p=os.path.join(run,f)
    if not os.path.exists(p): continue
    src=f[4:-4]
    for line in open(p,errors="ignore"):
        n=line.strip().lower().rstrip(".")
        if n.startswith("*."): n=n[2:]
        if not n or not pat.fullmatch(n): continue
        names.add(n); sources.setdefault(n,set()).add(src)
with open(os.path.join(run,"subdomains_raw.txt"),"w") as out:
    for n in sorted(names): out.write(n+"\n")
json.dump({n:sorted(s) for n,s in sorted(sources.items())},open(os.path.join(run,"sources_raw.json"),"w"),indent=0)
PY
  # the name gate: apex, ownership, DNS proof and exclusions hold from here on, before the first query
  gate enumerate names subdomains_raw.txt subdomains.txt || return 1
  python3 -I -B - "$RUN_DIR" <<'PY' || return 1
import sys,os,json
run=sys.argv[1]
keep={l.strip() for l in open(os.path.join(run,"subdomains.txt")) if l.strip()}
sources={n:s for n,s in json.load(open(os.path.join(run,"sources_raw.json"))).items() if n in keep}
json.dump(sources,open(os.path.join(run,"sources.json"),"w"),indent=0)
per={}; only={}
for n,s in sources.items():
    for x in s: per[x]=per.get(x,0)+1
    if len(s)==1: only[s[0]]=only.get(s[0],0)+1
print("subdomains:",len(keep))
print("per source (total / only this source):",", ".join(f"{k}={per[k]}/{only.get(k,0)}" for k in sorted(per)))
PY
  [ "$(count subdomains.txt)" -gt 0 ]
}

# ---------------------------------------------------------------- 2 resolve
phase_resolve(){
  cover_reset dns
  gate resolve names subdomains.txt dnsx_targets.txt dns || return 1
  [ "$(count dnsx_targets.txt)" -gt 0 ] || { echo "no names left after the scope gate"; return 1; }
  # lab mode: the container's own resolver (LAB_NS, set once at the top)
  local lab_dns=(); [ -n "$LAB_NS" ] && lab_dns=(-r "$LAB_NS")
  dnsx -duc -l dnsx_targets.txt -a -aaaa -cname -resp -json -silent -retry "$DNSX_RETRY" -t "$DNSX_THREADS" "${lab_dns[@]}" -o dns.jsonl || return 1
  [ -f dns.jsonl ] || return 1
  # email / DNS posture of each apex itself (MX, TXT incl. SPF, NS, CAA, SOA) and its _dmarc record
  if [ "$(count apexes.txt)" -gt 0 ]; then
    { cat apexes.txt; sed 's/^/_dmarc./' apexes.txt; } > apex_names_raw.txt
    gate posture names apex_names_raw.txt apex_names.txt dns || return 1
    dnsx -duc -l apex_names.txt -mx -txt -ns -caa -soa -resp -json -silent -retry "$DNSX_RETRY" -o dns_apex.jsonl || echo "dnsx apex posture query failed (non-fatal; posture falls back to nuclei DNS templates)"
    # AXFR attempt against each apex's nameserver addresses that pass the address gate (read-only; success ==
    # misconfiguration). The address is asked directly, so the nameserver name is never re-resolved by dig.
    python3 -I -B - "$RUN_DIR" "$SCOPE" "$PIPE" "$DIG_TIME" <<'PY' || echo "axfr check failed (non-fatal)"
import sys,os,json,subprocess
run,scope_dir,pipe,dig_time=sys.argv[1:5]
sys.path.insert(0,pipe)
import scope as S
sc=S.Scope(scope_dir,run)
def dig(args,timeout=30):
    try: return subprocess.run(["dig"]+args,capture_output=True,text=True,timeout=timeout).stdout
    except Exception as e: return "; error "+str(e)
out=[]
for apex in [l.strip() for l in open(os.path.join(run,"apexes.txt")) if l.strip()]:
    # names from the answer are untrusted: only valid host names are kept (S.nameserver_names), and each goes after
    # -q, so dig never reads one as an option
    ns=S.nameserver_names(dig(["+short","NS",apex]))
    for server in ns:
        addrs=sorted({x for rr in ("A","AAAA") for x in dig(["+short","-t",rr,"-q",server]).split() if S.parse_ip(x) is not None})
        for ip in addrs:
            ok,why=sc.ip_allowed(ip)
            if not ok:
                sc.reject(f"{server} {ip}","axfr",why); continue
            txt=dig(["axfr",apex,"@"+ip,f"+timeout={dig_time}","+tries=1"],timeout=60)
            recs=[l for l in txt.splitlines() if l and not l.startswith(";")]
            ok=("Transfer failed" not in txt) and ("XFR size" in txt or len(recs)>2)
            out.append({"apex":apex,"ns":server,"ns_ip":ip,"success":bool(ok),"records":len(recs) if ok else 0})
json.dump(out,open(os.path.join(run,"axfr.json"),"w"),indent=1)
print("axfr attempts:",len(out),"successes:",sum(1 for o in out if o["success"]))
PY
  fi
  # hosts carried forward: every address passes the address gate (scope.ip_allowed). Names with a non-scannable
  # address are still classified "internal" by classify.py from dns.jsonl, but nothing is sent to them.
  python3 -I -B -c 'import json
hs=set()
for l in open("dns.jsonl"):
    try: d=json.loads(l)
    except Exception: continue
    if (d.get("a") or [])+(d.get("aaaa") or []): hs.add(d.get("host",""))
open("resolved_raw.txt","w").write("".join(h+"\n" for h in sorted(hs) if h))'
  gate resolve-ip hosts resolved_raw.txt resolved_hosts.txt || return 1
  echo "resolved: $(count resolved_hosts.txt) carried forward of $(count resolved_raw.txt) with addresses"
  [ "$(count resolved_hosts.txt)" -gt 0 ]
}

# ---------------------------------------------------------------- 3 probe
phase_probe(){
  cover_reset http
  local lab_args=(-e private-ips); [ "$LAB" -eq 1 ] && lab_args=()
  # lab mode: httpx resolves names itself, and its built-in public resolvers are unreachable on the internal lab
  # network. Its fallback then fails under concurrency ("no address found for host") and a live host silently drops
  # out of the inventory and of every later phase (lab, 20 names: names lost in 90 of 100 runs; with the container's
  # resolver, 0 of 100). So, as dnsx does in lab mode, ask the container's own resolver.
  local lab_dns=(); [ -n "$LAB_NS" ] && lab_dns=(-r "$LAB_NS")
  gate probe hosts resolved_hosts.txt httpx_targets.txt || return 1
  # -fhr: redirects are followed on the same host only; -e private-ips: never a private address (not in lab mode)
  httpx-toolkit -duc -l httpx_targets.txt -silent -json -o httpx.jsonl \
    -sc -title -td -cpe -ip -cname -cdn -favicon -tls-grab -location -server -cl -ct \
    -fhr "${lab_args[@]}" "${lab_dns[@]}" -ports 80,443,8080,8443 -rl "$HTTPX_RL" -t "$HTTPX_THREADS" -timeout "$HTTPX_TIMEOUT" -retries "$HTTPX_RETRIES" >/dev/null || echo "httpx rc=$?"
  [ -f httpx.jsonl ] || : > httpx.jsonl
  # http coverage = the gated hosts httpx actually answered for. A host it got nothing back for (not serving HTTP, or a
  # failed lookup or connection) was not tested: its http findings must not be marked fixed on this run's strength.
  python3 -I -B - "$RUN_DIR" <<'PY' || return 1
import json,os,sys
run=sys.argv[1]
want={l.strip().lower() for l in open(os.path.join(run,"httpx_targets.txt")) if l.strip()}
got=set()
for l in open(os.path.join(run,"httpx.jsonl"),errors="ignore"):
    try: d=json.loads(l)
    except ValueError: continue
    h=(d.get("input") or "").lower().split(":")[0] if isinstance(d,dict) else ""
    if h in want: got.add(h)
with open(os.path.join(run,"coverage","http.txt"),"w") as f: f.write("".join(h+"\n" for h in sorted(got)))
print(f"httpx answered for {len(got)} of {len(want)} gated host(s); the others are not live on 80/443/8080/8443, or the probe failed")
PY
  echo "http endpoints: $(count httpx.jsonl)"
}

# ---------------------------------------------------------------- 4 classify
phase_classify(){
  python3 -I -B "$PIPE/classify.py" --run-dir "$RUN_DIR" --scope "$SCOPE" --config "$CONF" || return 1
  for f in owned_hosts owned_ips cdn_hosts tp_hosts unverified_hosts internal_hosts dead_hosts owned_urls cdn_urls tp_urls unverified_urls https_hosts all_urls; do
    [ -f "$f.txt" ] || : > "$f.txt"
    echo "$f: $(count $f.txt)"
  done
}

# ---------------------------------------------------------------- 5 fingerprint
phase_fingerprint(){
  gate fingerprint urls all_urls.txt fingerprint_urls.txt || return 1
  if [ "$(count fingerprint_urls.txt)" -gt 0 ]; then
    # caps scale with the target count (with fixed floors): about 5 s per URL for whatweb, 3 s per host for wafw00f
    local n cap; n=$(count fingerprint_urls.txt); cap=$(( n / 10 > 40 ? n / 10 : 40 ))
    echo "whatweb: $n urls, cap ${cap}m"
    # --follow-redirect=never: whatweb's other modes include "same-site", which is not "same host"
    timeout "${cap}m" whatweb -a 1 --no-errors -q --follow-redirect=never --max-threads "$WHATWEB_THREADS" \
      --open-timeout "$WHATWEB_OPEN_TIMEOUT" --read-timeout "$WHATWEB_READ_TIMEOUT" --log-json=whatweb.json -i fingerprint_urls.txt || echo "whatweb rc=$?"
    # wafw00f is sequential and slow: probe one URL per host (prefer https) instead of every endpoint
    python3 -I -B -c 'import sys,re
best={}
for u in open("fingerprint_urls.txt"):
    u=u.strip(); h=re.sub(r"^https?://","",u).split("/")[0].split(":")[0]
    if h not in best or (u.startswith("https://") and not best[h].startswith("https://")): best[h]=u
print("\n".join(sorted(best.values())))' > waf_targets_raw.txt
    gate wafw00f urls waf_targets_raw.txt waf_targets.txt || return 1
    n=$(count waf_targets.txt); cap=$(( n / 15 > 30 ? n / 15 : 30 ))
    echo "wafw00f: $n hosts, cap ${cap}m"
    # -r: wafw00f has no same-host option, so redirect following is off
    timeout "${cap}m" wafw00f -r -i waf_targets.txt -o waf.json -f json || echo "wafw00f rc=$?"
  fi
  # passive enrichment: ASN per public address (Team Cymru whois) and endoflife.date cycles; nothing is sent to a target
  timeout 15m python3 -I -B "$PIPE/enrich.py" "$RUN_DIR" "$CONF/eol_products.txt" || echo "enrich rc=$?"
  return 0
}

# ---------------------------------------------------------------- 6 portscan (approved addresses only)
phase_portscan(){
  cover_reset nmap
  approval_ok || { echo "no valid scope/approval.json: port scan refused"; return 1; }
  grep -v ':' owned_ips.txt > owned_ips_v4_raw.txt || true   # nmap needs -6 for IPv6; dual-stack hosts are covered via v4
  gate portscan portscan owned_ips_v4_raw.txt owned_ips_v4.txt nmap || return 1
  if [ "$(count owned_ips_v4.txt)" -eq 0 ]; then echo "no IPv4 addresses approved for port scans; skipping nmap"; return 0; fi
  # Bursts of NMAP_CHUNK hosts with a short pause, so one stuck chunk cannot stall the whole phase. Behind a NAT
  # with a small state table, replies are dropped once the table fills and open ports read as closed: there, use
  # the low rate profile. Connect scan (-sT, no raw sockets), nmap top-100 + risky ports. nmap is handed addresses,
  # so its http library follows a redirect only to that same address (nselib/http.lua redirect_ok_rules).
  mkdir -p nmap_parts; rm -f nmap_parts/*
  split -l "$NMAP_CHUNK" -d -a 3 owned_ips_v4.txt nmap_parts/chunk_
  local i=0 total; total=$(ls nmap_parts/chunk_* | wc -l)
  for c in nmap_parts/chunk_*; do
    i=$((i+1)); echo "nmap burst $i/$total ($(count "$c") hosts)"
    nmap -sT -sV --version-intensity 5 -p "$SCAN_PORTS" -T3 -Pn --open \
      --script=banner,ssl-cert,http-headers,http-title,http-server-header \
      --max-retries "$NMAP_RETRIES" --host-timeout "$NMAP_HOST_TIMEOUT" --max-parallelism "$NMAP_PARALLELISM" --max-rate "$NMAP_MAX_RATE" \
      -iL "$c" -oX "$c.xml" -oN "$c.txt" >/dev/null 2>&1 || echo "nmap burst $i rc=$?"
    sleep "$NMAP_PAUSE"
  done
  python3 -I -B - <<'PY'
import glob, xml.etree.ElementTree as ET
root=None; hosts=0
for f in sorted(glob.glob("nmap_parts/chunk_*.xml")):
    try: r=ET.parse(f).getroot()
    except ET.ParseError: continue
    if root is None:
        root=r
        for h in list(root.findall("host")): root.remove(h)
    for h in r.findall("host"):
        root.append(h); hosts+=1
if root is not None:
    ET.ElementTree(root).write("nmap.xml", encoding="unicode", xml_declaration=True)
open("nmap.txt","w").write("".join(open(f).read() for f in sorted(glob.glob("nmap_parts/chunk_*.txt"))))
print("nmap merged hosts:",hosts)
PY
}

# ---------------------------------------------------------------- 7 tls
phase_tls(){
  cover_reset sslscan
  gate tls hostports https_hosts.txt sslscan_targets.txt sslscan || return 1
  if [ "$(count sslscan_targets.txt)" -eq 0 ]; then echo "no https hosts"; return 0; fi
  # One XML per host, SSLSCAN_PARALLEL at a time; ingest merges sslscan*.xml.
  mkdir -p sslscan; rm -f sslscan/*.xml
  local n cap; n=$(count sslscan_targets.txt); cap=$(( n / 8 > 60 ? n / 8 : 60 ))   # about 7.5 s per host
  echo "sslscan: $n hosts, cap ${cap}m"
  SSLSCAN_CONNECT_TIMEOUT=$SSLSCAN_CONNECT_TIMEOUT timeout "${cap}m" xargs -a sslscan_targets.txt -P "$SSLSCAN_PARALLEL" -I{} \
    sh -c 'sslscan --no-colour --xml="sslscan/$(echo "$1" | tr : _).xml" --connect-timeout="$SSLSCAN_CONNECT_TIMEOUT" "$1" >/dev/null 2>&1' _ {} || echo "sslscan rc=$?"
  python3 -I -B - <<'PY'
import glob,re
parts=[]
for f in sorted(glob.glob("sslscan/*.xml")):
    t=open(f,errors="ignore").read()
    m=re.search(r"<ssltest.*?</ssltest>",t,re.S)
    if m: parts.append(m.group(0))
open("sslscan.xml","w").write('<?xml version="1.0" encoding="UTF-8"?>\n<document title="SSLScan Results">\n'+"\n".join(parts)+"\n</document>\n")
print("sslscan hosts:",len(parts))
PY
  return 0
}

# ---------------------------------------------------------------- 8 nuclei
phase_nuclei(){
  # coverage per pass: a finding is only marked fixed by a pass that could have observed it (ingest.py)
  cover_reset nuclei nuclei_tp nuclei_dns nuclei_fp
  rm -f nuclei_errors_*.jsonl nuclei_failed_passes.txt
  approval_ok || { echo "no valid scope/approval.json: nuclei refused"; return 1; }
  local etags
  etags=$(exclude_tags) || return 1
  etags=$etags${PROFILE_ETAGS:+,$PROFILE_ETAGS}
  local templates=${SCAN_NUCLEI_TEMPLATES:-$NUCLEI_TEMPLATES}
  [ -d "$templates" ] || { echo "nuclei templates directory $templates not found (templates are baked into the image)"; return 1; }
  # options on every pass: no interactsh, no update check, same-host redirects only, never a host dropped for errors
  local common=(-ni -duc -fhr -retries "$NUC_RETRIES" -nmhe -jsonl -silent -stats -si 300)
  [ "$LAB" -eq 1 ] || common+=(-lna)                 # refuse local/private network targets (not in lab mode)
  # lab mode: every pass asks the container's own resolver (LAB_NS). nuclei's -r takes a file, one resolver per line
  # ("-r, -resolvers string  file containing resolver list for nuclei"); it holds exactly that one address.
  rm -f nuclei_resolvers.txt
  if [ -n "$LAB_NS" ]; then
    printf '%s\n' "$LAB_NS" > nuclei_resolvers.txt || return 1
    common+=(-r nuclei_resolvers.txt)
  fi
  local eh; eh=$(python3 -I -B - "$SCOPE" <<'PY'
import sys,os
p=os.path.join(sys.argv[1],"exclude.txt")
items=[l.split("#",1)[0].strip().lower().lstrip(".") for l in open(p)] if os.path.exists(p) else []
print(",".join(x for x in items if x))
PY
)
  [ -n "$eh" ] && common+=(-eh "$eh")
  # One representative URL per distinct application (see dedupe.py); findings are expanded to siblings at ingest.
  if [ -n "$RECHECK_BASE" ]; then
    python3 -I -B - "$RUN_DIR" "$BASE/runs/$RECHECK_BASE" <<'PY'
import sys,os,json
run,base=sys.argv[1:3]
def hostof(u): return u.split("://")[1].split("/")[0].split(":")[0]
hosts={l.strip() for l in open(os.path.join(run,"recheck_hosts.txt")) if l.strip()}
live=set()
for f in ("owned_urls.txt","cdn_urls.txt","unverified_urls.txt"):
    p=os.path.join(run,f)
    if os.path.exists(p): live|={l.strip() for l in open(p) if l.strip()}
try: groups=json.load(open(os.path.join(base,"nuclei_groups.json")))
except Exception: groups={}
keep={rep:urls for rep,urls in groups.items() if hostof(rep) in hosts and rep in live}
open(os.path.join(run,"nuclei_targets_raw.txt"),"w").write("".join(r+"\n" for r in sorted(keep)))
json.dump(keep,open(os.path.join(run,"nuclei_groups.json"),"w"),indent=1)
print(f"recheck nuclei targets: {len(keep)} representatives of {len(groups)} in {os.path.basename(base)}")
PY
  else
    if python3 -I -B "$PIPE/dedupe.py" "$RUN_DIR"; then mv nuclei_targets.txt nuclei_targets_raw.txt
    else cat owned_urls.txt cdn_urls.txt unverified_urls.txt | sort -u > nuclei_targets_raw.txt; fi
  fi
  gate nuclei urls nuclei_targets_raw.txt nuclei_targets.txt nuclei || return 1
  # findings on a representative are expanded to its siblings at ingest: those siblings were covered too
  python3 -I -B - "$RUN_DIR" "$PIPE" "$SCOPE" <<'PY' || return 1
import sys,os,json
run,pipe,scope_dir=sys.argv[1:4]
sys.path.insert(0,pipe)
import scope as S
sc=S.Scope(scope_dir,run)
def hostof(u): return u.split("://")[1].split("/")[0].split(":")[0]
reps={l.strip() for l in open(os.path.join(run,"nuclei_targets.txt")) if l.strip()}
try: groups=json.load(open(os.path.join(run,"nuclei_groups.json")))
except Exception: groups={}
sib={hostof(u) for r in reps for u in groups.get(r,[])}
sib={h for h in sib if sc.name_allowed(h)[0]}
with open(os.path.join(run,"coverage","nuclei.txt"),"a") as f:
    f.write("".join(h+"\n" for h in sorted(sib)))
PY
  local n; n=$(count nuclei_targets.txt)
  want(){ printf ',%s,' "$NUCLEI_PASSES" | grep -q ",$1,"; }
  if [ "$n" -gt 0 ] && want generic; then
    # -nmhe: never drop a host for "too many errors". With a max-host-errors limit, a lossy network path makes
    # nuclei silently skip hosts part-way through a pass, and findings still live on those hosts come back as
    # "fixed". Rates: -rl is the binding throttle; -c and -bs set how many templates/hosts are in flight. To
    # validate a rate, compare each pass's final -stats error share in recon.log with a slower run.
    nuclei -l nuclei_targets.txt -t "$templates" -tags "$NUC_GENERIC_TAGS" \
      -etags "cve,$etags" -severity low,medium,high,critical -rl "$NUC_GENERIC_RL" -c "$NUC_GENERIC_C" -bs "$NUC_GENERIC_BS" -timeout "$NUC_TIMEOUT" \
      "${common[@]}" -elog nuclei_errors_generic.jsonl -o nuclei_owned.jsonl >/dev/null || { rc=$?; echo "nuclei generic rc=$rc"; echo "generic $rc" >> nuclei_failed_passes.txt; }
  fi
  if [ "$n" -gt 0 ] && want tech; then
    # technology-matched checks (CVEs etc.): nuclei fingerprints the stack, then runs only matching templates
    nuclei -l nuclei_targets.txt -t "$templates" -as \
      -etags "$etags" -severity medium,high,critical -rl "$NUC_TECH_RL" -c "$NUC_TECH_C" -bs "$NUC_TECH_BS" -timeout "$NUC_TIMEOUT" \
      "${common[@]}" -elog nuclei_errors_tech.jsonl -o nuclei_tech.jsonl >/dev/null || { rc=$?; echo "nuclei tech rc=$rc"; echo "tech $rc" >> nuclei_failed_passes.txt; }
  fi
  gate nuclei-tp urls tp_urls.txt tp_targets.txt nuclei_tp || return 1
  if [ "$(count tp_targets.txt)" -gt 0 ] && want tp; then
    # third-party hosted: takeover + misconfig only (the vendor owns the stack)
    nuclei -l tp_targets.txt -t "$templates" -tags takeover,misconfig,dns \
      -etags "cve,exposure,$etags" -severity low,medium,high,critical -rl "$NUC_TP_RL" -c "$NUC_TP_C" -bs "$NUC_TP_BS" -timeout "$NUC_TIMEOUT" \
      "${common[@]}" -elog nuclei_errors_tp.jsonl -o nuclei_tp.jsonl >/dev/null || { rc=$?; echo "nuclei tp rc=$rc"; echo "tp $rc" >> nuclei_failed_passes.txt; }
  fi
  # DNS-level takeover/misconfig templates: gated names only (exclusions hold here too)
  gate nuclei-dns names resolved_hosts.txt nuclei_dns_targets.txt nuclei_dns || return 1
  if [ "$(count nuclei_dns_targets.txt)" -gt 0 ] && want dns; then
    nuclei -l nuclei_dns_targets.txt -t "$templates/dns" -etags "$etags" -rl "$NUC_DNS_RL" -c "$NUC_DNS_C" -timeout "$NUC_DNS_TIMEOUT" \
      "${common[@]}" -elog nuclei_errors_dns.jsonl -o nuclei_dns.jsonl >/dev/null || { rc=$?; echo "nuclei dns rc=$rc"; echo "dns $rc" >> nuclei_failed_passes.txt; }
  fi
  if [ "$n" -gt 0 ] && want fp; then
    # technology fingerprint: info-level "tech" templates on every live app; inventory only, never findings
    cat nuclei_targets.txt tp_targets.txt 2>/dev/null | sort -u > fp_targets_raw.txt
    gate nuclei-fp urls fp_targets_raw.txt fp_targets.txt nuclei_fp || return 1
    nuclei -l fp_targets.txt -t "$templates" -tags tech -severity info \
      -etags "cve,$etags" -rl "$NUC_FP_RL" -c "$NUC_FP_C" -bs "$NUC_FP_BS" -timeout "$NUC_TIMEOUT" \
      "${common[@]}" -elog nuclei_errors_fp.jsonl -o nuclei_fp.jsonl >/dev/null || { rc=$?; echo "nuclei fp rc=$rc"; echo "fp $rc" >> nuclei_failed_passes.txt; }
  fi
  for f in nuclei_owned nuclei_tech nuclei_tp nuclei_dns nuclei_fp; do [ -f "$f.jsonl" ] || : > "$f.jsonl"; echo "$f: $(count $f.jsonl)"; done
  # -elog: one line per request nuclei could not complete (timeout, reset, ...), with its host. ingest.py does not
  # mark a nuclei finding fixed on a host that had such an error in the pass that would have observed it.
  for p in generic tech tp dns fp; do [ -f "nuclei_errors_$p.jsonl" ] && echo "nuclei $p errors: $(count "nuclei_errors_$p.jsonl") request(s)"; done
  return 0
}

# ---------------------------------------------------------------- 9 manifest
phase_manifest(){
  local rc=${1:-0}
  python3 -I -B - "$RUN_DIR" "$RUN_ID" "$rc" "$INVENTORY_ONLY" "${SCAN_NUCLEI_TEMPLATES:-$NUCLEI_TEMPLATES}" "$NUCLEI_PASSES" "$RECHECK_BASE" \
    "$CHECK_PROFILE" "$RATE_PROFILE" "$PROFILE_SOURCE" "$INVENTORY_REASON" "$LAB" "${LAB_NET:-}" "$APPROVED" "$BASE" "$EVIDENCE_LEVEL" <<'PY'
import sys,os,json,subprocess,glob,re
run,run_id,rc,inv,tdir,passes,recheck_base,check_p,rate_p,prof_src,inv_reason,lab,lab_net,approved,root,evidence=sys.argv[1:17]
ANSI=re.compile(r"\x1b\[[0-9;]*[A-Za-z]"); VER=re.compile(r"\bv?\d+\.\d+(?:\.\d+)?\b")
def ver(cmd):
    # the ProjectDiscovery tools print banners with colour codes on stderr and the version on a middle line
    try:
        p=subprocess.run(cmd,capture_output=True,text=True,timeout=60)
        text=ANSI.sub("",(p.stdout or "")+"\n"+(p.stderr or ""))
        m=VER.search(text)
        return m.group(0) if m else (text.strip().splitlines() or ["unknown"])[0][:120]
    except Exception: return "unknown"
def cnt(f):
    p=os.path.join(run,f)
    return sum(1 for l in open(p,errors="ignore") if l.strip()) if os.path.exists(p) else 0
def lines(f):
    p=os.path.join(run,f)
    return {l.strip() for l in open(p,errors="ignore") if l.strip()} if os.path.exists(p) else set()
tools={
 "nmap":ver(["nmap","--version"]),
 "subfinder":ver(["subfinder","-version"]),
 "httpx":ver(["httpx-toolkit","-version"]),
 "nuclei":ver(["nuclei","-version"]),
 "dnsx":ver(["dnsx","-version"]),
 "sslscan":ver(["sslscan","--version"]),
 "whatweb":ver(["whatweb","--version"]),
 "os":(open("/etc/os-release").read().split("\n")[0] if os.path.exists("/etc/os-release") else "unknown"),
}
try: tcfg=json.load(open(os.path.join(os.path.expanduser("~"),".config","nuclei",".templates-config.json")))
except Exception: tcfg={}
tcount=len(glob.glob(os.path.join(tdir,"**","*.yaml"),recursive=True))
phases=[json.loads(l) for l in open(os.path.join(run,"phases.jsonl")) if l.strip()] if os.path.exists(os.path.join(run,"phases.jsonl")) else []
byph={}
for p in phases: byph[p["phase"]]=p        # a re-run of a phase supersedes the earlier record
phases=[byph[k] for k in sorted(byph)]
lab_doc=None
if lab=="1":
    try: lab_doc=json.load(open(os.path.join(run,"lab.json")))
    except Exception: lab_doc={}
    lab_doc={"lab":True,"cidr":lab_net,"targets":len(lab_doc.get("hosts",[])),"dns_proof":"not required in lab mode"}
try:
    appr=json.load(open(os.path.join(root,"scope","approval.json"))) if approved=="1" else None
    appr={k:appr.get(k) for k in ("approved_at","inventory_run","approved_by")} if isinstance(appr,dict) else None
except Exception: appr=None
# the inventory this run recorded (approve.py binds an approval to it): domains covered (the apexes that passed the
# DNS proof), lab targets, and every classified host with its addresses, class and, when classed by a CNAME suffix,
# that suffix (via_cname). Only when classify succeeded.
inventory=None
if any(p.get("phase")==4 and p.get("rc")==0 for p in phases) and os.path.exists(os.path.join(run,"assets.jsonl")):
    hosts={}
    for l in open(os.path.join(run,"assets.jsonl"),errors="ignore"):
        try: a=json.loads(l)
        except Exception: continue
        if isinstance(a,dict) and a.get("hostname"):
            hosts[a["hostname"]]={"ips":sorted(set(a.get("ips") or [])),"class":a.get("class")}
            if isinstance(a.get("via_cname"),str) and a.get("class") in ("cdn_fronted","third_party"):
                hosts[a["hostname"]]["via_cname"]=a["via_cname"]   # classed by its CNAME suffix (classify.py)
    labt=[]
    if lab=="1":
        try: labt=sorted(json.load(open(os.path.join(run,"lab.json"))).get("hosts",[]))
        except Exception: labt=[]
    inventory={"domains":sorted(lines("apexes.txt")),"lab_targets":labt,"hosts":hosts}
try: held=json.load(open(os.path.join(run,"held_back.json")))
except Exception: held=None
try: dnsv=json.load(open(os.path.join(run,"dns_verification.json")))
except Exception: dnsv=None
# seed names (seed_input.py): how many lines the seeder's file had, how many were host names, how many passed the gate.
# Lab and recheck runs read no seed file: all zero.
try: sr=json.load(open(os.path.join(run,"seed_read.json")))
except Exception: sr={}
try: src=json.load(open(os.path.join(run,"sources.json")))
except Exception: src={}
seed={"status":sr.get("status","not-read") if isinstance(sr.get("status"),str) else "not-read",
      "lines":int(sr.get("lines") or 0),"read":int(sr.get("kept") or 0),
      "passed_gate":sum(1 for v in src.values() if isinstance(v,list) and "seed" in v) if sr.get("status")=="read" else 0}
m={
 "run_id":run_id,"rc":int(rc),"inventory_only":inv=="1","inventory_only_reason":inv_reason or None,
 "nuclei_passes":passes,
 "check_profile":check_p,"rate_profile":rate_p,"profile_source":prof_src,
 "evidence":evidence,
 "lab":lab_doc,
 "approval":appr,
 "inventory":inventory,
 "held_back":({"inventory_run":held.get("inventory_run"),"count":len(held.get("hosts") or {}),
               "domains":{k:len(v) for k,v in (held.get("domains") or {}).items() if isinstance(v,list)}} if isinstance(held,dict) else None),
 "dns_verification":dnsv,
 "seed":seed,
 "recheck":bool(recheck_base),"base_run":recheck_base or None,"recheck_hosts":cnt("recheck_hosts.txt"),
 "started":phases[0]["start"] if phases else None,
 "finished":phases[-1]["end"] if phases else None,
 "tools":tools,
 "nuclei_templates_version":tcfg.get("nuclei-templates-version"),
 "nuclei_templates_dir":tdir,"nuclei_template_count":tcount,
 "counts":{k:cnt(k+".txt") for k in ("subdomains","resolved_hosts","owned_hosts","cdn_hosts","unverified_hosts","tp_hosts","internal_hosts","dead_hosts","owned_ips","https_hosts","all_urls","nuclei_targets")},
 "coverage":{s:len(lines(os.path.join("coverage",s+".txt"))) for s in ("dns","http","nmap","sslscan","nuclei","nuclei_tp","nuclei_dns","nuclei_fp")},
 "nuclei_errors":{p:cnt(f"nuclei_errors_{p}.jsonl") for p in ("generic","tech","tp","dns","fp") if os.path.exists(os.path.join(run,f"nuclei_errors_{p}.jsonl"))},
 "nuclei_failed_passes":sorted({l.split()[0] for l in lines("nuclei_failed_passes.txt") if l.split()}),
 "scope_rejected":cnt("scope_rejected.jsonl"),
 "findings_raw":{k:cnt(k+".jsonl") for k in ("nuclei_owned","nuclei_tech","nuclei_tp","nuclei_dns","nuclei_fp")},
 "fingerprint_raw":{"whatweb":cnt("whatweb.json"),"waf_targets":cnt("waf_targets.txt"),"fp_targets":cnt("fp_targets.txt")},
 "phases":phases,
}
json.dump(m,open(os.path.join(run,"manifest.json"),"w"),indent=1)
print(json.dumps(m["counts"]), "coverage", json.dumps(m["coverage"]))
PY
}

# ---------------------------------------------------------------- main
log "run $RUN_ID start inventory_only=$INVENTORY_ONLY${INVENTORY_REASON:+ ($INVENTORY_REASON)} recheck=${RECHECK_BASE:-no} lab=$LAB from_phase=$FROM_PHASE phases=${PHASES:-all} templates=${SCAN_NUCLEI_TEMPLATES:-$NUCLEI_TEMPLATES} (baked into the image; update with update-templates.sh)"
run_phase 1 enumerate
run_phase 2 resolve
run_phase 3 probe
run_phase 4 classify
run_phase 5 fingerprint
if [ "$INVENTORY_ONLY" -eq 1 ]; then log "inventory-only ($INVENTORY_REASON): stopping after fingerprint (no port scan, no nuclei)"; finish 0; fi
# Hosts the approved inventory did not list, whose address moved outside the owned and provider ranges (CDN and
# third-party hosts classed by a CNAME still under the same suffix excepted), or under a verified domain the approved
# inventory did not cover, are held back: from here on every scope gate refuses them (held_back.json), so they reach
# no active tool this run.
HB_LAB=(); [ "$LAB" -eq 1 ] && HB_LAB=(--lab-targets-file "$TARGETS_FILE")
python3 -I -B "$PIPE/approve.py" --root "$BASE" --scope "$SCOPE" hold-back --run-dir "$RUN_DIR" --config "$CONF" "${HB_LAB[@]}" >>"$LOG" 2>&1 \
  || fatal "could not decide which hosts the approved inventory covers; no active phase runs"
run_phase 6 portscan
run_phase 7 tls
run_phase 8 nuclei
finish 0
