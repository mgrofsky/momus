# Security policy

## Reporting a vulnerability

Report a vulnerability privately, through GitHub's vulnerability reporting form at <https://github.com/mgrofsky/momus/security/advisories/new>, or by email to <security@grofsky.com>. Do not open a public issue for it.

Please include what you found, the version or commit you tested, the steps to reproduce it, and what an attacker gains. A proof of concept that runs against the lab demo (`compose.lab.yaml`) is the most useful kind: it needs no real target.

Test only against your own installation. Never test against systems you do not own, and never use a report to justify scanning someone else's systems.

## In scope

- **Scope controls in the scanner:** any way to make the scanner send packets to a host or address the scope does not allow, to skip the DNS proof, to reach a private, link-local, or cloud metadata address, or to get past its egress firewall ([scope and authorization](docs/scope-and-authorization.md)).
- **The boundary between the containers:** any way for a scanned site, a compromised scanner, or a job file to run code in the brain, write its database, read its secrets, or make it contact anything ([threat model](docs/threat-model.md)).
- **The brain's web application:** authentication, sessions, request forgery, script injection through scan data, access to routes without signing in, and the sign-in limits.
- **The analyst:** any way for text from a scanned site to make the analyst do more than [the analyst](docs/analyst.md) says it can, to change a score, mark, or setting without a person, or to send data to anything but the configured provider.
- **Stored data:** a secret or personal data that reaches the scan database, a snapshot, a report, a log, or a model provider in a way [findings and evidence](docs/findings-and-evidence.md) says it should not.
- **The seeder:** any way for a DNS answer or zone file to make the seeder contact a host it was not configured for, or to put something other than host names under verified domains into its output.

## Out of scope

- The limits the documentation already states: the "What it can still do" lists in the [threat model](docs/threat-model.md) and the limits on each feature's page (for example "What these controls do not stop" in [scope and authorization](docs/scope-and-authorization.md#what-these-controls-do-not-stop)), unless you show they are worse than stated.
- Attacks that need Docker access or root on the host. Anyone with either already controls every container.
- Findings in the scan tools themselves (nmap, nuclei, httpx, and the others). Report those to their own projects. A way to misuse them through Momus is in scope.
- Vulnerabilities in the targets you scan. Those belong to the targets' owners.
- The example cloud deployments under `deploy/`, beyond what they create (they are examples to read and adapt).

## What to expect

A report will be acknowledged, checked, and, when it is confirmed, fixed in the open with credit to you unless you ask otherwise.
