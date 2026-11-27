# Scope and authorization

This page lists every control between "I want to scan this domain" and the first packet the scanner sends to a host,
in the order they apply. For each control it says what it does, where it lives in the code, and the test that shows
it. The last section lists what these controls do not stop. The [scan authorization policy diagram](diagrams/scan-policy.md)
shows the same controls in one picture.

The project is meant only for systems the person running it owns. The controls below are there to catch mistakes,
such as a typo in a domain name, a record that points somewhere unexpected, or a host that changed hands. They are
not a lock against the operator.

**DNS verification is a due-care control. Anyone with the source can remove it. It does not make scanning someone else's systems permitted.**

Terms used on this page:

- **scanner**: the scan container. It is the only part that sends packets to targets.
- **brain**: the web application container. It writes jobs and reads results. It never contacts a target.
- **job**: one JSON file the brain writes to `jobs/`. Every job carries a full copy of the scope.
- **scope**: the domains, exclusions, owned ranges, approved hosts, ownership statements, approval, and profiles a job
  carries.
- **domain**: a registered domain (or a subdomain you control) listed in the scope.
- **gate**: a check in `scanner/pipeline/scope.py` that a list of names, addresses, or URLs passes through
  immediately before the tool that reads it. Rejections are written to `scope_rejected.jsonl` in the run folder.
- **published folder**: `published/`, which the scanner writes and the brain reads.
- **recheck**: a run that re-tests hosts already in the scan database, without discovery.
- **version watch**: a job that sends one `GET /` to each listed host and reads the product version from the response
  headers.
- **seeder**: an optional container that lists host names from DNS services you control and hands them to the
  scanner as discovery input.

## 1. The ownership statement

Before a domain can be added on the Scope page, the admin must tick a box that reads exactly:

> I own this domain and the systems it points to.

Without the tick the domain is not added. The brain stores the statement with the admin's name and the time in its
database, and writes an audit log entry (`domain-add`) in the same transaction. The page states that the statement is
recorded "in the audit log and in every job sent to the scanner".

Every job carries the statement for each domain. The scanner rejects a job whose ownership entry is missing a field,
names a domain that is not in the scope, or has any statement other than that exact sentence. The scanner writes the
entries to `ownership.json` in its scope folder. A domain with no ownership entry never passes the name gate
(section 3). At the start of every scan the scanner writes the project's rule to its run log: "This project should
only be run on systems the person running the project explicitly owns."

The brain will not queue a job while any domain lacks the statement.

The tests that show it:
`brain/tests/test_jobs.py::test_domain_without_ownership_statement_cannot_be_queued`,
`scanner/pipeline/test_runner.py::Validation::test_ownership_rules`,
`scanner/pipeline/test_scope.py::Ownership::test_missing_entry`,
`scanner/pipeline/test_scope.py::Ownership::test_malformed_ownership_file`.

## 2. DNS proof

A domain is scanned only after the scanner finds a TXT record that proves control of the domain's DNS.

**The record.** Name `_scan-verify.<domain>`, value `scan-verify=<token>`, where the token is 32 hexadecimal
characters. For example, for `example.com` the record is `_scan-verify.example.com. IN TXT "scan-verify=<token>"`.

**The token.** The scanner makes the token itself: the first 32 hexadecimal characters of HMAC-SHA-256, keyed with
the install secret, over a fixed label and the domain name. The install secret is 32 random bytes that the scanner's
job runner creates on first start. It is stored in the scanner's own data volume at
`/var/lib/scan/state/install_secret` (a container path), in a folder with mode 0700 and a file with mode 0600, owned
by the scanner user. The secret is never published and never sent in a job. The token is not stored; it is derived
again whenever it is needed.

- Tokens come only from the scanner. The scanner rejects a job with a `token` field, or with any verification
  state (`state`, `verified_at`, and so on), in its ownership entries.
- The token is tied to one install and one domain. Publishing the record of a different domain, or one made by a
  different install, proves nothing.
- The scanner publishes, for each domain, the exact record to create in `scope_status.json` in the published folder.
  The Scope page shows it as the separate Type, Name, and Value fields a DNS panel asks for, with the zone-file line
  below them. Right after a domain is added, the page updates on its own every few seconds until the scanner has
  published the record (no reload needed). The record is public once you publish it in DNS; the secret is not.
- If the install secret is lost and replaced, every token changes: each domain goes back to `pending`, and
  `scope_status.json` carries a notice.

**When it is checked.** The proof is checked again, every time, at each of these points:

- At the start of every inventory, full, and recheck run, before any discovery (phase 0 of `scanner/recon.sh`).
- In every scope-sync job. The brain queues one after a domain is added, and when the admin clicks "Check DNS proof
  now". A scope-sync job runs only `dig`; no scan tool runs.
- At the start of every version-watch job, before any probe. If the check cannot run, the job ends as failed
  without probing. Hosts under a domain that failed the check in that job are skipped.
- When an operator runs `scanner/pipeline/approve.py verify <domain>` by hand.

Lab runs skip this check (section 12).

**Which resolvers are asked.** The scanner finds the domain's nameservers through the container's system resolver:
it asks for NS records, walking up from the domain name until a zone answers, then asks for the A and AAAA records of
each nameserver. Every nameserver address must be globally routable. If any is not, the domain is refused and that
server is never asked. The TXT question then goes to each nameserver address directly, with recursion off, so a local
resolver or cache cannot supply the answer. Every server that answers must return the matching record; a server
that does not answer is left out, and if none answers the lookup has failed.

**Outcomes.**

| Result | Meaning | State afterwards | Usable this run |
|---|---|---|---|
| match | every answering nameserver returns the record | `verified` (time of verification refreshed) | yes |
| mismatch | the record is missing or wrong | `pending` | no |
| disagree | nameservers give different answers | `pending` | no |
| unsafe | a nameserver address is not globally routable | `refused` | no |
| failure | no nameserver found, or none answered | see the grace period | see below |

**The grace period.** When the lookup fails (no nameserver found, or none answered), a domain last verified at most 7
days earlier still counts for that run. The 7 days count from the last successful check. Past that, a domain that was
`verified` becomes `lapsed` and is refused. A wrong or missing record is never covered by the grace period: it sets
the domain to `pending` at once.

**A domain that fails** is logged in the run log and in `scope_rejected.jsonl`, and every name under it is refused by
the name gate for the rest of the run. Other domains in the same scope go on. If no domain passes, the run stops
before discovery. A domain refused in a run is never left `verified` on disk.

dnsrecon also talks to a domain's nameservers. Before it runs, the scanner looks the nameserver addresses up again and
runs dnsrecon only for a domain whose every nameserver address still passes the same check.

The tests that show it:
`scanner/pipeline/test_scope.py::DnsProof::test_right_token`,
`scanner/pipeline/test_scope.py::DnsProof::test_wrong_token`,
`scanner/pipeline/test_scope.py::DnsProof::test_nameservers_disagree`,
`scanner/pipeline/test_scope.py::DnsProof::test_nameserver_on_private_address`,
`scanner/pipeline/test_scope.py::DnsProof::test_lookup_failure_inside_grace`,
`scanner/pipeline/test_scope.py::DnsProof::test_lookup_failure_outside_grace`,
`scanner/pipeline/test_scope.py::DnsProof::test_usable_equals_verified_on_disk`,
`scanner/pipeline/test_scope.py::DnsProof::test_real_lookup_never_asks_a_private_nameserver`,
`scanner/pipeline/test_scope.py::Tokens::test_derived_per_install_and_per_domain`,
`scanner/pipeline/test_scope.py::Tokens::test_token_copied_from_another_install_does_not_verify`,
`scanner/pipeline/test_scope.py::Tokens::test_secret_file_permissions_and_refusals`,
`scanner/pipeline/test_scope.py::Tokens::test_lost_secret_returns_every_domain_to_pending`,
`scanner/pipeline/test_scope.py::NameserverGate::test_one_private_address_refuses_the_apex`,
`scanner/pipeline/test_runner.py::Validation::test_token_anywhere_in_ownership_is_rejected`,
`scanner/pipeline/test_runner.py::Validation::test_cannot_set_verification_state`,
`scanner/pipeline/test_runner.py::Scope::test_secret_created_owner_only_and_never_published`,
`scanner/pipeline/test_runner.py::VersionWatchJobs::test_the_dns_proof_of_this_job_runs_first_and_its_failure_stops_the_probe`,
`scanner/pipeline/test_version_watch.py::ScopeGate::test_a_host_under_a_domain_that_did_not_pass_the_proof_in_this_job_is_not_probed`,
`tests/e2e/run_demo.sh` check "1 the runner created its install secret (owner-only, in the scanner's own state folder)".

## 3. The name gate

A host name passes the name gate only when all of these hold:

- It is a valid host name (lower case after normalizing, labels of `a-z`, `0-9`, `-`, `_`, at least two labels).
- It is a domain in the scope, or a name under one, on a label boundary (`www.example.com` is under `example.com`;
  `badexample.com` is not).
- That domain has an ownership statement and its DNS proof state is `verified`.
- It is not excluded.
- It is not held back (section 8).

**Exclusions.** Each exclusion is one of:

- a name, which excludes itself and every name under it;
- `.suffix` or `*.suffix`, which mean the same thing: every name under the suffix;
- a single address;
- a CIDR range.

An exclusion that is none of these makes the scope fail to load, and the run stops before discovery. An empty domain
list is also an error: it never means "allow everything".

A host whose CNAME chain, as the scanner's resolver reports it, reaches an excluded name is refused like the excluded
name itself.

**Where it applies.** `scanner/recon.sh` passes every target list through the gate immediately before the tool that
reads it: names from every discovery source, including the optional seeder's list and a recheck's host list, before
they are resolved; the domain names before the DNS posture query; resolved hosts before the HTTP probe; URLs before
whatweb, wafw00f, and each nuclei pass; host and port pairs before the TLS scan; names before the DNS-template pass;
and addresses before the port scan. The version watch applies the same gate and the same CNAME check before every
probe. The hosts handed to each tool are written to `coverage/<source>.txt` in the run folder.

The tests that show it:
`scanner/pipeline/test_scope.py::NameGate::test_apex_and_label_boundary`,
`scanner/pipeline/test_scope.py::NameGate::test_suffix_exclusions`,
`scanner/pipeline/test_scope.py::NameGate::test_bad_exclusions_fail_closed`,
`scanner/pipeline/test_scope.py::NameGate::test_empty_or_missing_scope_is_an_error`,
`scanner/pipeline/test_scope.py::DnsProof::test_verified_apex_does_not_cover_a_sibling`,
`scanner/pipeline/test_scope.py::CnameChain::test_alias_of_an_excluded_name_is_refused`,
`scanner/pipeline/test_version_watch.py::ScopeGate::test_alias_of_an_excluded_name_is_not_probed`.

## 4. The address gate

The gate checks the addresses the scanner saved from its own DNS lookups (dnsx, in the resolve phase), before any
tool is handed a host. It does not check the address a tool finally connects to: httpx-toolkit, whatweb, wafw00f,
sslscan, and nuclei are given host names and look them up again, and if a record changed in between, the firewall
then allows any public address ([what these controls do not stop](#what-these-controls-do-not-stop)). nmap and the
version watch use the checked addresses themselves. These address classes are always refused:

- unspecified, loopback, multicast, and reserved addresses;
- private addresses (10/8, 172.16/12, 192.168/16, and the other private blocks);
- link-local addresses, 169.254.0.0/16, which includes the cloud metadata address 169.254.169.254;
- carrier-grade NAT, 100.64.0.0/10, and 192.0.0.0/24;
- IPv6 unique-local (fc00::/7, which includes the IPv6 cloud metadata range fd00:ec2::/32) and site-local addresses;
- IPv6 forms that embed or translate an IPv4 address: NAT64 (64:ff9b::/96, 64:ff9b:1::/48), 6to4 (2002::/16), and
  Teredo (2001::/32);
- anything else that is not globally routable.

An IPv4 address written in IPv4-mapped IPv6 form is checked as IPv4. Addresses and ranges in the exclusions are
refused too.

A host is carried past resolution only when every one of its addresses passes. A host with any refused address is
classed `internal` (section 9) and nothing is sent to it.

**Port scans** need more. Every address of the host must pass the gate and either lie in one of the scope's owned
ranges or belong to a host in the approved-hosts list. The brain accepts only public ranges as owned ranges.

**Provider lists in `scanner/config/`.** These files decide a host's class, which decides what it receives
(section 9). They never widen what the address gate allows.

- `cdn_cnames.txt`: CNAME suffixes of CDN and WAF edges. A host with a CNAME under one is `cdn_fronted`.
- `third_party_cnames.txt`: CNAME suffixes of SaaS and hosting providers. A host with a CNAME under one is
  `third_party`.
- `third_party_ranges.txt`: provider address ranges. A host with an address in one is `third_party`. It ships empty.
  These ranges also let a host's address change without a hold-back (section 8).
- `exclude_tags.txt`: nuclei template tags that never run (section 10).
- `own_networks.txt` and `eol_products.txt` only label results; they do not affect scope.

The code also reads files with the same names as the three provider lists from the scanner's scope folder and merges
them with the shipped ones. In a container install that folder is rebuilt from each job, and a job has no field for
these lists, so the shipped files in `scanner/config/` (built into the image) are the only ones in effect.

The tests that show it:
`scanner/pipeline/test_scope.py::AddressGate::test_non_global_classes`,
`scanner/pipeline/test_scope.py::AddressGate::test_global_and_mapped`,
`scanner/pipeline/test_scope.py::AddressGate::test_address_and_cidr_exclusions`,
`scanner/pipeline/test_scope.py::AddressGate::test_ips_allowed_needs_every_address`,
`scanner/pipeline/test_scope.py::PortScan::test_owned_range_or_approved_host`,
`scanner/pipeline/test_scope.py::Filters::test_hosts_need_gated_resolution`,
`scanner/pipeline/test_classify.py::ClassifyTest::test_classes`.

## 5. Tool flags

Each tool is started with options that keep it on the host it was given. From `scanner/recon.sh`:

| Tool | What it is given | Options that limit where it goes |
|---|---|---|
| subfinder | the verified domains | `-duc` (no update check). It asks third-party data sources, not your hosts. |
| assetfinder | each verified domain | It asks third-party data sources, not your hosts. It has no update check. |
| crt.sh (through `curl -sS -m 60`) | each verified domain | A query to the public certificate log. |
| dnsrecon | a verified domain whose nameserver addresses pass the check again | `-t std` (standard records). |
| dnsx | gated names | `-duc`. In lab mode `-r` with the container's resolver. |
| dig (zone transfer attempt) | each nameserver address of a verified domain that passes the address gate | Asked by address (`@address`), so the nameserver name is not resolved again. |
| httpx-toolkit | gated hosts, ports 80, 443, 8080, 8443 | `-fhr` (redirects only on the same host), `-e private-ips` (outside lab mode), `-duc`. |
| whatweb | gated URLs | `--follow-redirect=never`, `-a 1` (one request per target). |
| wafw00f | one gated URL per host | `-r` (no redirects). |
| nmap | gated IPv4 addresses only, never names | `-sT` (connect scan), `-Pn`, a fixed port list, five listed scripts. |
| sslscan | gated host and port pairs | `--connect-timeout`. |
| nuclei, every pass | gated URLs or names | `-fhr` (same-host redirects), `-lna` (refuses local and private network targets; outside lab mode), `-ni` (no interactsh), `-duc`, `-eh` (the exclusion list), `-nmhe`. |

subfinder, dnsx, httpx-toolkit, and nuclei check for a newer release at start unless told not to; every call passes
`-duc`. The version watch uses `curl` with the connection pinned to the address it checked (`--resolve`), proxies off,
and at most three redirects from each scheme's `GET /` (https and http each), each on the same host name.

The tests that show it:
`scanner/tests/shim/driver.py` check "8 httpx: same-host redirects only, private addresses excluded, normal rates",
`scanner/tests/shim/driver.py` check "8 whatweb: redirects off (--follow-redirect=never), threads and timeouts set",
`scanner/tests/shim/driver.py` check "8 wafw00f: redirects off (-r)",
`scanner/tests/shim/driver.py` check "8 nuclei: same-host redirects, local network refused, no update check, rate options",
`scanner/tests/shim/driver.py` check "7 interactsh off in every nuclei invocation",
`scanner/tests/shim/driver.py` check "1 nuclei -eh carries the exclusion list",
`scanner/tests/shim/driver.py` check "U every call of those tools passes -duc (no update check)",
`scanner/tests/shim/driver.py` check "8 nmap: rate options from the table, addresses only",
`scanner/tests/shim/driver.py` check "8 AXFR asked of the checked nameserver address, never a name",
`scanner/tests/shim/driver.py` check "dnsrecon: an apex whose nameserver now sits on a private address never reaches dnsrecon",
`scanner/pipeline/test_version_watch.py::Targets::test_redirects_to_another_host_are_not_followed`,
`scanner/pipeline/test_version_watch.py::ScopeGate::test_out_of_scope_host_is_never_probed_and_curl_is_pinned`.

## 6. The egress firewall

The scanner's start-up script, `scanner/entrypoint.sh`, installs a firewall in the container's own network namespace
before anything else runs. The rules sit on the container's outbound path, so they cover all of its traffic, IPv4
and IPv6, no matter which tool sent it or which address that tool looked up.

**What it allows, IPv4 and IPv6:**

- loopback (this carries Docker's embedded resolver at 127.0.0.11);
- replies on connections already set up;
- in lab mode only, the one lab range (section 12);
- port 53 (UDP and TCP) to each resolver that Docker's embedded resolver forwards to from inside the container, if
  any. A forwarder that is not globally routable is allowed on port 53 only, and the start-up log prints a warning;
- IPv6 only: router solicitation and neighbor solicitation and advertisement, to link-local (fe80::/10) and
  link-scope multicast (ff02::/16) destinations only;
- every other globally routable destination.

**What it rejects:**

- IPv4: 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16 (including 169.254.169.254),
  172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.31.196.0/24, 192.52.193.0/24, 192.88.99.0/24, 192.168.0.0/16,
  192.175.48.0/24, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, and 240.0.0.0/4.
- IPv6: everything outside 2000::/3 (the global unicast block), which includes fd00:ec2::/32, and inside it
  2001::/23, 2001:db8::/32, 2002::/16, and 3fff::/20.

A rejected packet gets an ICMP "prohibited" reply, so the tool fails at once instead of waiting.

**Start-up check.** After installing the rules, the script reads every rule back and compares it with what it meant
to install, and checks that the rules are the first thing outbound traffic meets. It then tries to connect to
169.254.169.254 and to fd00:ec2::254. Each attempt must fail, and when the address is routable the reject rule's
packet counter must show that the rule stopped it. On a network with no route at all the attempt fails before the
rules, and the read-back is what proves them.

**Refusal to start.** The container exits with a fatal message, before any job runs, if it does not start as root,
cannot read or change the firewall (for example, without `NET_ADMIN`), finds the firewall chain already present,
fails any firewall command, reads back rules that differ, connects to a metadata address, or is given an invalid lab
setting. There is no setting that skips the firewall.

**Capabilities and the privilege drop.** `compose.yaml` drops every capability and adds back only `NET_ADMIN` (for
the firewall) and `SETUID`, `SETGID`, and `SETPCAP` (used once, for the drop). The container runs with a read-only
root file system and `no-new-privileges`. The script also clears the proxy variables. It then switches to uid and gid
10001 with every capability set empty (inheritable, ambient, and bounding), with `no-new-privileges`, and with a clean
environment, and starts the job runner. From then on no scanner process can read or change the rules.

The tests that show it:
`tests/e2e/run_demo.sh` check "1 the scanner installed and verified its firewall, then started the runner as uid 10001",
`tests/e2e/run_demo.sh` check "6 the scanner cannot connect to the decoy by address",
`tests/e2e/run_demo.sh` check "6 the runner (PID 1) runs as uid 10001 with every capability set empty and no-new-privileges",
`tests/e2e/run_demo.sh` check "6 after the drop, a scanner process cannot change the rules",
`tests/e2e/run_demo.sh` check "7 without NET_ADMIN the scanner exits non-zero",
`tests/e2e/run_demo.sh` check "7b the entrypoint warns that resolver 10.20.30.40 is reachable on port 53 only, and still starts",
`tests/e2e/run_demo.sh` check "7b IPv6 neighbour discovery is allowed only to fe80::/10 and ff02::/16".

## 7. Inventory first, and approval bound to an inventory

**Inventory.** An inventory is a discovery-only run: enumeration (including dnsrecon and a zone transfer attempt
against the domain's nameservers), DNS resolution, the HTTP probe, classification, and fingerprinting (whatweb,
wafw00f, and passive enrichment). It runs no port scan, no TLS scan, and no nuclei. It is not passive: before any
approval it sends DNS questions to the domain's nameservers, and HTTP and HTTPS requests (with a TLS handshake) and
the whatweb and wafw00f requests to every discovered host whose addresses pass the address gate. A name discovered
under your domain may point at a system you do not own, and those requests reach it before you review the list.

**Approval.** After reviewing an inventory on the Scope page, the admin approves it. Active phases (the port scan,
the TLS scan, and nuclei) run only with a valid approval. A full run without one runs as an inventory and says so in
its log and manifest.

**What an approval covers.** The approval names one finished inventory run. The scanner accepts it only when that run
finished cleanly and recorded its inventory, and only when one or more of the job's domains appear in that
inventory (in lab mode: all of the job's lab targets). An inventory made in lab mode cannot approve a job outside it,
and an inventory made outside lab mode cannot approve a lab job. The scanner keeps a copy of the hosts the inventory listed, with each host's addresses and class. Active phases then
reach only those hosts, under the domains that inventory covered, at the addresses it listed (with the exceptions in
section 8).

**When it is checked.** The scanner binds the approval to the inventory when it receives each full or recheck job,
before it writes the job's scope; a job whose approval does not bind is rejected. The run checks it again at its
start, before the port scan, and before nuclei.

**When it stops being valid:**

- when the admin withdraws it on the Scope page (later jobs carry no approval);
- when the scope contains none of the domains the inventory covered;
- in lab mode, when the scope has a lab target the inventory did not cover.

An approval does not expire. Removing the inventory run's files under the retention policy does not end it: the
scanner keeps its own copy of the approved inventory.

The tests that show it:
`scanner/pipeline/test_scope.py::Approval::test_needs_existing_inventory_run`,
`scanner/pipeline/test_scope.py::Approval::test_approval_naming_another_domains_inventory_is_refused`,
`scanner/pipeline/test_scope.py::Approval::test_lab_and_non_lab_inventories_do_not_approve_each_other`,
`scanner/pipeline/test_scope.py::Approval::test_load_approval_rechecks_the_scope_as_it_is_now`,
`scanner/pipeline/test_runner.py::Scope::test_approval_needs_the_inventory_run`,
`scanner/pipeline/test_runner.py::HeldBackPublished::test_inventory_covering_none_of_the_scope_is_rejected`,
`scanner/pipeline/test_runner.py::HeldBackPublished::test_approval_survives_retention_of_the_inventory_run`,
`scanner/tests/shim/driver.py` check "6 without approval.json the port scanner and nuclei are never invoked",
`tests/e2e/run_demo.sh` check "2b a full job whose approval names an inventory of other targets is rejected".

## 8. Hosts and domains held back

After fingerprinting and before the port scan, a full or recheck run compares the live hosts it found with the
approved inventory. A host that does not match is **held back**: from that point every gate refuses it, so it reaches
no port scan, no TLS scan, and no nuclei pass in that run. Each held-back host has one fixed reason code:

| Reason code | When |
|---|---|
| `new-since-approved-inventory` | The approved inventory did not list the host. |
| `address-changed` | The host has an address the approved inventory did not list, and that address is in neither the owned ranges nor the provider ranges. |
| `domain-not-in-approved-inventory` | The host is under a domain that was added to the scope after the approved inventory, so that inventory did not cover it. Every name under that domain is held back. |

The address check has one exception, for CDN and provider hosts. If the approved inventory put a host in
`cdn_fronted` or `third_party` because of its CNAME suffix, a new address does not hold it back, as long as the host
stays `cdn_fronted` or `third_party` and keeps a CNAME under that suffix. Edge addresses change often, and
neither class is ever port scanned.

Adding a domain does not stop the scans of domains already approved. The new domain gets inventory checks only until
an inventory that covers it is approved.

Held-back hosts have already been through the inventory steps of that run (resolution, the HTTP probe, whatweb, and
wafw00f), because the comparison needs them. The version watch still probes them, because its single `GET /` sends no
more than the inventory does.

The scanner writes the held-back hosts, their reason codes, and their approved and current addresses to
`held_back.json`, and publishes it. The Scope page lists them under "Awaiting approval". A domain that did not pass
its DNS proof in that run is counted as pending: nothing is sent to it. If the held-back list cannot be computed or
read, no active phase runs.

The tests that show it:
`scanner/pipeline/test_scope.py::HeldBack::test_new_host_is_held`,
`scanner/pipeline/test_scope.py::HeldBack::test_address_drift`,
`scanner/pipeline/test_scope.py::HeldBack::test_held_hosts_refused_by_every_gate_and_not_covered`,
`scanner/pipeline/test_scope.py::HeldBack::test_domain_not_in_the_approved_inventory_holds_every_host`,
`scanner/pipeline/test_scope.py::HeldBack::test_cdn_by_cname_is_not_held_for_edge_address_rotation`,
`scanner/pipeline/test_scope.py::HeldBack::test_unreadable_held_back_file_fails_closed`,
`scanner/pipeline/test_runner.py::HeldBackPublished::test_added_domain_does_not_block_the_job_and_is_published_as_held_back`,
`scanner/tests/shim/driver.py` check "H held_back.json names the new host and the moved host with fixed reason codes".

## 9. Host classes and what each receives

Every run sends a gated name to dnsx for resolution, and every resolved host whose addresses all pass the address gate
to the HTTP probe (httpx-toolkit). The scanner then puts each host in one class. The rules are tried in the order of
the table, and the first one that matches decides:

| Order | Class | How a host gets it |
|---|---|---|
| 1 | `excluded` | The name, or one of its addresses, is excluded. |
| 2 | `dead` | The name does not resolve. |
| 3 | `internal` | At least one address the address gate refuses (private, metadata, and so on). |
| 4 | `owned` | An address in the scope's owned ranges, or the host is in the approved-hosts list. |
| 5 | `cdn_fronted` | A CNAME under a CDN suffix. |
| 6 | `third_party` | A CNAME under a SaaS or hosting suffix. |
| 7 | `third_party` | An address in a provider range. |
| 8 | `cdn_fronted` | httpx reports a CDN or WAF edge. |
| 9 | `unverified` | None of the above. Unknown is not owned. |

What each class receives after classification:

| Class | whatweb, wafw00f | Port scan (nmap) | TLS scan (sslscan) | nuclei |
|---|---|---|---|---|
| `owned` | yes | yes, IPv4 addresses that pass the port-scan rule | yes | generic, technology, DNS-template, and fingerprint passes |
| `cdn_fronted` | yes | no | yes | generic, technology, DNS-template, and fingerprint passes |
| `unverified` | yes | no | yes | generic, technology, DNS-template, and fingerprint passes |
| `third_party` | yes | no | yes | third-party pass (takeover, misconfiguration, and DNS tags, without CVE or exposure templates), DNS-template and fingerprint passes |
| `internal` | no | no | no | no |
| `dead` | no | no | no | no |
| `excluded` | no | no | no | no |

Port scans happen only for `owned` hosts, and each address must still pass the port-scan rule in section 4. The
generic and technology passes target one representative URL per distinct application. The DNS-template pass runs
nuclei's DNS templates against the name. The fingerprint pass runs only when at least one `owned`, `cdn_fronted`, or
`unverified` host has a live URL; a scope with only `third_party` hosts gets none. An `internal` host is reported as a finding (a
private address published in public DNS) and is never probed. The approved-hosts list is the way to allow port scans
on an `unverified` host.

The tests that show it:
`scanner/pipeline/test_classify.py::ClassifyTest::test_classes`,
`scanner/pipeline/test_classify.py::ClassifyTest::test_owned_ips_public_only`,
`scanner/pipeline/test_scope.py::PortScan::test_filter_portscan_and_coverage`,
`scanner/tests/shim/driver.py` check "5 www.example.test (no owned range, not approved) never reaches nmap".

## 10. Check profiles: `safe` and `active`

A check profile decides which nuclei templates may run. There are two: `safe` (the default) and `active`.

**The switch.** One setting per scope. On the Scope page, "Turn aggressive checks on" sets the profile to `active`,
and "Turn aggressive checks off" sets it back to `safe`. The change is written to the audit log and applies from the
next job. Each job carries the setting, and the scanner writes it to `profile.json` in its scope folder, which
`scanner/recon.sh` reads. The environment variable `SCAN_CHECK_PROFILE` applies only when `recon.sh` is run by hand
with no `profile.json`; the job runner does not pass it.

**What `active` adds.** Templates tagged `default-login`, `sqli`, `rce`, `lfi`, `ssrf`, `xss`, or `injection`.

- Under `safe`, those seven tags are excluded from every nuclei pass.
- Under `active`, they are added to the generic pass's tag list and removed from the excluded tags of every pass
  (generic, technology, third-party, DNS-template, and fingerprint).
- Under `safe`, a finding from a template with one of those tags is never marked fixed, because a `safe` run did not
  look for it.

**What is the same in both.**

- The tags in `scanner/config/exclude_tags.txt` (`dos`, `fuzz`, `fuzzing`, `intrusive`, `bruteforce`,
  `brute-force`) are excluded from every pass. If that file is missing, unreadable, or empty, the run stops before
  discovery.
- Interactsh (out-of-band callbacks to a third-party server) is off.
- The technology pass runs in both profiles. It detects each application's technology, then runs the matching
  templates of medium severity and above, which include CVE templates.

The tests that show it:
`scanner/pipeline/test_profiles.py::Profiles::test_defaults_are_safe_and_low`,
`scanner/pipeline/test_profiles.py::Profiles::test_active_from_env_and_from_profile_json`,
`scanner/pipeline/test_profiles.py::Profiles::test_invalid_profiles_refused`,
`scanner/pipeline/test_profiles.py::Profiles::test_excluded_tags_file_holds_none_of_the_seven`,
`scanner/pipeline/test_ingest.py::TestFixedEndToEnd::test_skipped_host_and_active_tags`,
`scanner/tests/shim/driver.py` check "7 safe: every nuclei invocation excludes all seven active-only tags",
`scanner/tests/shim/driver.py` check "7 active: no nuclei invocation excludes any of the seven tags",
`scanner/tests/shim/driver.py` check "7 active: the excluded-tags file still applies".

## 11. Rate profiles

A rate profile sets how hard each tool works. There are three: `low` (the default), `normal`, and `fast`. It is set
on the Scope page ("Rate"), carried in each job, and written to `profile.json` like the check profile.

| Setting | low | normal | fast |
|---|---|---|---|
| dnsx threads (`-t`) | 16 | 50 | 75 |
| httpx-toolkit requests per second (`-rl`) | 66 | 200 | 300 |
| httpx-toolkit threads (`-t`) | 26 | 80 | 120 |
| whatweb threads (`--max-threads`) | 8 | 25 | 37 |
| nmap hosts per burst | 21 | 64 | 96 |
| nmap packets per second (`--max-rate`) | 66 | 200 | 300 |
| nmap parallelism (`--max-parallelism`) | 10 | 32 | 48 |
| nmap pause between bursts (seconds) | 15 | 5 | 5 |
| sslscan processes in parallel | 5 | 16 | 24 |
| nuclei generic pass: rate, concurrency, bulk size (`-rl`, `-c`, `-bs`) | 100, 16, 16 | 300, 50, 50 | 450, 75, 75 |
| nuclei technology pass: rate, concurrency, bulk size | 50, 8, 8 | 150, 25, 25 | 225, 37, 37 |
| nuclei third-party pass: rate, concurrency, bulk size | 33, 7, 7 | 100, 20, 20 | 150, 30, 30 |
| nuclei DNS-template pass: rate, concurrency | 50, 10 | 150, 30 | 225, 45 |
| nuclei fingerprint pass: rate, concurrency, bulk size | 50, 10, 10 | 150, 30, 30 | 225, 45, 45 |

Timeouts and retries do not change with the profile, so `low` never gives up earlier than `fast`: dnsx 3
attempts; httpx-toolkit 8 seconds, 1 retry; whatweb 15 seconds to open and 30 to read; nmap 2 retries and 10 minutes
per host; sslscan 10 seconds to connect; nuclei 8 seconds (5 for the DNS-template pass), 1 retry; zone transfer
attempts 5 seconds. `scanner/recon.sh --print-config` prints the numbers in effect.

The tests that show it:
`scanner/pipeline/test_profiles.py::Profiles::test_rate_table`,
`scanner/pipeline/test_profiles.py::Profiles::test_defaults_are_safe_and_low`,
`scanner/tests/shim/driver.py` check "8 low profile: httpx at a third of the normal rate".

## 12. Lab mode

Lab mode runs the scanner against the bundled, deliberately weak demo target on a private test network. It is started
only with the second Compose file:

```
docker compose -f compose.yaml -f compose.lab.yaml up -d --build
```

That file is never loaded by a plain `docker compose up`. It uses its own project name, so lab data is kept apart
from real scan data.

**The fixed lab subnet** is 10.89.47.0/24. The scanner is at 10.89.47.2 and the demo target at 10.89.47.10, with the
names `target.demo.test` and `notice.demo.test`. The scanner, brain, and demo target use internal networks with no route
off the machine. The browser bridge is the only lab service on a host-facing network; it publishes to `127.0.0.1`
and forwards requests only to the brain. Docker's resolver in the scanner answers the lab names itself and sends every other question to
10.89.47.53, an unused lab address, where nothing answers. Any lab range must be private and no larger than a /24.

**What it changes:**

- The firewall allows the lab range.
- Lab targets are named in the job. They need no DNS proof, and the DNS proof check does not run.
- Enumeration is skipped: only the lab targets are scanned.
- Addresses inside the lab range are allowed only for lab target names, and lab target names may reach only
  addresses inside the lab range.
- httpx-toolkit runs without `-e private-ips` and nuclei without `-lna`, because the lab target has a private address.
- dnsx, httpx-toolkit, and nuclei ask the container's own resolver.
- The vulnerability feeds are not fetched after a lab run.
- An approval must cover every lab target, and only an inventory made in lab mode can approve a lab job.

**What stays enforced:** exclusions, the address gate for every name that is not a lab target, the ownership
statement in the brain, the approval and hold-back rules, check and rate profiles, the excluded tags, same-host
redirects, no update checks, and the firewall for every address outside the lab range.

**Why a job or the heartbeat cannot turn it on.** Lab mode comes from the container's start-up environment
(`SCAN_LAB=1` and `SCAN_LAB_CIDR`), which only `compose.lab.yaml` sets.

- The scanner rejects any job with lab fields unless it was started in lab mode, and the job's lab range must equal
  the range it was started with.
- The scope code refuses lab settings unless `SCAN_LAB=1` is in its environment.
- The brain decides lab mode from its own `MOMUS_LAB` setting only. The scanner's heartbeat (`scanner.json` in the
  published folder) reports the scanner's lab mode for display; when it differs from `MOMUS_LAB`, the brain shows a
  warning and keeps its own setting.

The tests that show it:
`scanner/pipeline/test_scope.py::Lab::test_limits`,
`scanner/pipeline/test_scope.py::Lab::test_lab_addresses_only_for_lab_names`,
`scanner/pipeline/test_scope.py::Lab::test_lab_exclusions_still_apply`,
`scanner/pipeline/test_runner.py::Validation::test_lab_fields`,
`scanner/pipeline/test_runner.py::Queue::test_lab_job_refused_without_lab_mode`,
`scanner/pipeline/test_runner.py::Publishing::test_lab_env_from`,
`brain/tests/test_small_items.py::test_lab_mode_comes_only_from_the_brain_setting`,
`scanner/tests/shim/driver.py` check "lab: nuclei does not get -lna (the lab target is private) and still gets -fhr",
`tests/e2e/run_demo.sh` check "8 lab fields without lab mode: the job is rejected",
`tests/e2e/run_demo.sh` check "1 every network attached to".

## What these controls do not stop

- **A host name can point somewhere else by the time a tool connects.** httpx-toolkit, whatweb, wafw00f, sslscan, and
  nuclei receive names and do their own DNS lookups. If the record changes after the scanner resolved and checked it,
  such a tool can connect to a public address that belongs to someone else. The firewall blocks only non-public
  addresses. nmap receives addresses, and the version watch connects to the address it checked, so neither is
  affected.
- **A name under a verified domain may simply point at another party's public address.** Such a host is classed
  `unverified` and still gets web checks and nuclei templates (never a port scan). Use exclusions for names you know
  are hosted by others.
- **The DNS proof relies on the container's resolver to find the nameservers.** Only the TXT question goes to the
  nameservers directly. If that resolver returns false NS or address records, the TXT question goes to the wrong
  server.
- **The 7-day grace period.** While lookups fail, a domain verified in the last 7 days stays in scope, even if its
  owner has changed in the meantime.
- **Docker's resolver may sit outside the firewall.** When Docker answers the container's DNS questions from the host's
  network namespace, those questions (including the nameserver lookups of the DNS proof) are not filtered by the
  container's rules. When it forwards from inside the container to a resolver on a private address, that address is
  open on port 53.
- **Approvals name hosts, and do not expire.** A host in the approved-hosts list may be port scanned at any public
  address it resolves to. An inventory approval holds back a host whose address is new, but a host that keeps an
  address the inventory listed stays in scope even if you have given that address up. An approval lasts until the
  admin withdraws it or the scope's domains change.
- **One provider serves many customers.** A new address inside a provider range does not
  hold a host back. A CDN or provider host whose CNAME points at a different customer's resource at the same
  provider keeps its web checks. Neither kind of host is port scanned.
- **Inventory steps reach hosts the approval does not cover.** New hosts and hosts under newly added domains still
  get resolution, the HTTP probe, whatweb, and wafw00f before they are held back.
- **nuclei's own exclusion list is exact.** The scanner's gates apply suffix exclusions before nuclei runs. The list
  passed to nuclei with `-eh` holds each exclusion as written, minus a leading dot, so a suffix entry there excludes
  only that one name.
- **Nameservers are contacted directly.** For a verified domain, dnsrecon and the zone transfer attempt talk to the
  domain's nameservers, which are often run by a DNS provider. The scanner checks that their addresses are public, not
  that you run them.
- **In lab mode every tool can reach the whole lab range.**
- **The optional seeder is not covered.** It queries the DNS services named in its settings, which can include hosts in
  scope, and it runs outside the scanner's firewall and exclusions. Names it finds still pass the scanner's name gate.
- **Anyone with the source code or root on the host can remove these controls.** The install secret is a file in the
  scanner's data volume; anyone who can read it can make valid tokens for this install.
