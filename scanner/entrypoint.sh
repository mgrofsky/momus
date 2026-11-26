#!/bin/bash
# entrypoint.sh - the scanner container's start-up. Runs as root with NET_ADMIN (and SETUID, SETGID, SETPCAP, used
# only for the privilege drop below); every other capability is dropped by the container settings (compose.yaml).
#
#   1. clear proxy variables (HTTP_PROXY, HTTPS_PROXY, ALL_PROXY, NO_PROXY, FTP_PROXY, both cases)
#   2. install the egress firewall for IPv4 and IPv6, in its own chain MOMUS_EGRESS jumped to first from OUTPUT:
#        allow loopback (this carries Docker's resolver at 127.0.0.11) and established traffic;
#        in lab mode (SCAN_LAB=1 and SCAN_LAB_CIDR, a private range no larger than /24) allow that one range;
#        allow DNS (port 53) to the resolvers Docker's own resolver forwards to from inside this container, if any
#        (a resolver that is not globally routable is allowed on port 53 only, and a WARNING says so);
#        IPv6 only: allow neighbour discovery (router solicitation, neighbour solicitation and advertisement) to
#        link-local (fe80::/10) and link-scope multicast (ff02::/16) destinations only;
#        reject every private, loopback, link-local (incl. 169.254.169.254 and fd00:ec2::/32), carrier-grade NAT,
#        multicast, documentation, benchmarking, reserved and other non-global destination; allow the rest
#   3. verify: read every rule back and compare it with what was meant, then try to connect to the cloud metadata
#      address (and its IPv6 form); the attempt must fail, and when the address is routable the reject rule's
#      packet counter must show that the rule stopped it
#   4. drop to uid/gid 10001 with every capability set empty (incl. the bounding set) and no-new-privileges, with a
#      clean environment, and exec the job runner
# Any failure in 1-3 exits non-zero with a FATAL line. There is no switch to skip the firewall.
set -u
umask 022

die(){ echo "entrypoint: FATAL: $*" >&2; exit 70; }
log(){ echo "entrypoint: $*" >&2; }

[ "$(id -u)" = 0 ] || die "must start as root (it installs the firewall, then drops to uid 10001 itself)"
APP=/app/scanner
export HOME=/root

# ---------------------------------------------------------------- 1. proxy variables
for v in HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY FTP_PROXY http_proxy https_proxy all_proxy no_proxy ftp_proxy; do
  unset "$v"
done

# ---------------------------------------------------------------- lab mode settings
LAB_NET=""
if [ "${SCAN_LAB:-}" = 1 ]; then
  [ -n "${SCAN_LAB_CIDR:-}" ] || die "SCAN_LAB=1 needs SCAN_LAB_CIDR (a private range no larger than /24)"
  LAB_NET=$(python3 -I -B -c 'import sys; sys.path.insert(0, sys.argv[1]); import scope
n, why = scope.private_lab_net(sys.argv[2])
print(n if n else "ERROR " + why)' "$APP/pipeline" "$SCAN_LAB_CIDR") || die "lab CIDR check failed to run"
  case "$LAB_NET" in ERROR*) die "lab mode refused: ${LAB_NET#ERROR }";; esac
  log "lab mode: $LAB_NET allowed"
elif [ -n "${SCAN_LAB:-}" ] || [ -n "${SCAN_LAB_CIDR:-}" ]; then
  die "SCAN_LAB must be 1 or unset, and SCAN_LAB_CIDR is only accepted with SCAN_LAB=1"
fi
LAB_FAM=""
case "$LAB_NET" in *:*) LAB_FAM=6;; ?*) LAB_FAM=4;; esac

# ---------------------------------------------------------------- 2. firewall
BLOCK4="0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.0.0.0/24 192.0.2.0/24
192.31.196.0/24 192.52.193.0/24 192.88.99.0/24 192.168.0.0/16 192.175.48.0/24 198.18.0.0/15 198.51.100.0/24
203.0.113.0/24 224.0.0.0/4 240.0.0.0/4"
# 2000::/3 is the only global unicast block; inside it, the special-purpose ranges are rejected as well
BLOCK6_IN_GLOBAL="2001::/23 2001:db8::/32 2002::/16 3fff::/20"

# resolvers Docker's embedded DNS forwards to from this container's namespace (not those marked host(...),
# which it asks from the host's namespace and which never pass this firewall)
EXT_DNS=$(sed -n 's/^# ExtServers: \[\(.*\)\]$/\1/p' /etc/resolv.conf | tr ' ' '\n' | grep -v '^host(' | grep -v '^$' || true)
# A resolver address that is not globally routable (a private or link-local resolver set with --dns, say) gets the
# port-53 exception below like any other: the firewall then allows that one address on port 53, and only there.
for ip in $EXT_DNS; do
  why=$(python3 -I -B -c 'import sys; sys.path.insert(0, sys.argv[1]); import scope
o = scope.parse_ip(sys.argv[2])
print("not an address" if o is None else (scope.non_global_reason(o) or ""))' "$APP/pipeline" "$ip") || die "resolver address check failed to run"
  [ -z "$why" ] || log "WARNING: resolver $ip from the container's DNS configuration is not globally routable ($why): the firewall allows port 53 to it, so that address is reachable on port 53 only (any process here can send port-53 traffic to it)"
done

fw(){ "$@" || die "firewall command failed: $*"; }
EXPECT4=(); EXPECT6=()
rule4(){ EXPECT4+=("-A MOMUS_EGRESS $*"); fw iptables -w 5 -A MOMUS_EGRESS "$@"; }
rule6(){ EXPECT6+=("-A MOMUS_EGRESS $*"); fw ip6tables -w 5 -A MOMUS_EGRESS "$@"; }

for t in iptables ip6tables; do
  command -v "$t" >/dev/null || die "$t not found"
  "$t" -w 5 -S OUTPUT >/dev/null 2>&1 || die "$t cannot read the filter table (is NET_ADMIN granted?)"
  "$t" -w 5 -S MOMUS_EGRESS >/dev/null 2>&1 && die "chain MOMUS_EGRESS already exists in $t; refusing to guess its contents"
  fw "$t" -w 5 -N MOMUS_EGRESS
done

# IPv4 (iptables -S prints rules in this canonical form; the read-back below compares with it)
rule4 -o lo -j ACCEPT
rule4 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
[ "$LAB_FAM" = 4 ] && rule4 -d "$LAB_NET" -j ACCEPT
for ip in $EXT_DNS; do
  case "$ip" in *:*) continue;; esac
  rule4 -d "$ip/32" -p udp -m udp --dport 53 -j ACCEPT
  rule4 -d "$ip/32" -p tcp -m tcp --dport 53 -j ACCEPT
done
for n in $BLOCK4; do rule4 -d "$n" -j REJECT --reject-with icmp-host-prohibited; done
rule4 -j ACCEPT

# IPv6
rule6 -o lo -j ACCEPT
rule6 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
[ "$LAB_FAM" = 6 ] && rule6 -d "$LAB_NET" -j ACCEPT
for ip in $EXT_DNS; do
  case "$ip" in *:*) ;; *) continue;; esac
  rule6 -d "$ip/128" -p udp -m udp --dport 53 -j ACCEPT
  rule6 -d "$ip/128" -p tcp -m tcp --dport 53 -j ACCEPT
done
for ty in 133 135 136; do   # router solicitation, neighbour solicitation and advertisement
  for nd in fe80::/10 ff02::/16; do   # link-local unicast and link-scope multicast destinations only
    rule6 -d "$nd" -p ipv6-icmp -m icmp6 --icmpv6-type "$ty" -j ACCEPT
  done
done
for n in $BLOCK6_IN_GLOBAL; do rule6 -d "$n" -j REJECT --reject-with icmp6-adm-prohibited; done
rule6 ! -d 2000::/3 -j REJECT --reject-with icmp6-adm-prohibited
rule6 -j ACCEPT

fw iptables -w 5 -I OUTPUT 1 -j MOMUS_EGRESS
fw ip6tables -w 5 -I OUTPUT 1 -j MOMUS_EGRESS

# ---------------------------------------------------------------- 3. verify
readback(){   # family tool, then the expected rules
  local t=$1; shift
  local got want
  got=$("$t" -w 5 -S MOMUS_EGRESS 2>&1) || die "$t: cannot list MOMUS_EGRESS"
  want=$(printf '%s\n' "-N MOMUS_EGRESS" "$@")
  [ "$got" = "$want" ] || {
    printf 'expected:\n%s\ngot:\n%s\n' "$want" "$got" >&2; die "$t: rules read back differ from the rules installed"; }
  [ "$("$t" -w 5 -S OUTPUT | sed -n 2p)" = "-A OUTPUT -j MOMUS_EGRESS" ] || die "$t: OUTPUT does not jump to MOMUS_EGRESS first"
}
readback iptables "${EXPECT4[@]}"
readback ip6tables "${EXPECT6[@]}"

probe(){   # tool, address, rule destination: the connection must fail; if the rule saw it, its counter moved
  local t=$1 addr=$2 dest=$3 res before after
  before=$("$t" -w 5 -L MOMUS_EGRESS -v -x -n | awk -v d="$dest" '$3=="REJECT" && $9==d {print $1; exit}')
  [ -n "$before" ] || die "$t: no reject rule for $dest"
  res=$(python3 -I -B - "$addr" <<'PY'
import errno, socket, sys
addr = sys.argv[1]
fam = socket.AF_INET6 if ":" in addr else socket.AF_INET
s = socket.socket(fam, socket.SOCK_STREAM)
s.settimeout(3)
try:
    s.connect((addr, 80))
    print("CONNECTED")
except socket.timeout:
    print("dropped (timeout)")
except OSError as e:
    print(errno.errorcode.get(e.errno, str(e.errno)))
finally:
    s.close()
PY
)
  after=$("$t" -w 5 -L MOMUS_EGRESS -v -x -n | awk -v d="$dest" '$3=="REJECT" && $9==d {print $1; exit}')
  case "$res" in
    CONNECTED|"") die "verification: a connection to $addr was not blocked ($res)";;
  esac
  if [ "$after" -gt "$before" ]; then
    log "verified: connect to $addr refused by the firewall ($res; reject rule for $dest matched $((after - before)) packet(s))"
  elif [ "$res" = ENETUNREACH ]; then
    log "verified: connect to $addr failed ($res: no route from this container, so no packet reached the rules; rules checked by read-back)"
  else
    die "verification: connect to $addr failed ($res) but the reject rule for $dest did not see it"
  fi
}
probe iptables 169.254.169.254 169.254.0.0/16
probe ip6tables fd00:ec2::254 !2000::/3
log "egress firewall installed and verified (IPv4 ${#EXPECT4[@]} rules, IPv6 ${#EXPECT6[@]} rules${LAB_NET:+, lab range $LAB_NET})"

# ---------------------------------------------------------------- 4. drop privileges and run the job runner
# Clean environment: only the variables below reach the runner (and through it, nothing else reaches the tools).
ENVV=(PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/home/scanner LANG=C.UTF-8
      SCAN_ROOT=${SCAN_ROOT:-/var/lib/scan} SCAN_JOBS=${SCAN_JOBS:-/srv/jobs} SCAN_PUBLISHED=${SCAN_PUBLISHED:-/srv/published})
for v in SCAN_LAB SCAN_LAB_CIDR SCAN_KEEP_SNAPSHOTS SCAN_POLL_SECONDS SCAN_EXIT_WHEN_IDLE SCAN_JOB_MAX_AGE_HOURS TZ; do
  [ -n "${!v:-}" ] && ENVV+=("$v=${!v}")
done
exec setpriv --reuid=10001 --regid=10001 --clear-groups \
  --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
  -- env -i "${ENVV[@]}" python3 -I -B "$APP/runner.py"
