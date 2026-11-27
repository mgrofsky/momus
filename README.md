# Momus

Momus scans the internet-facing systems you own for known vulnerabilities and keeps track of what it finds from one scan to the next. It runs as two containers: a scanner built on Kali Linux that runs well-known open-source scan tools, and a web application (the "brain") where you set the scope, approve scans, and read results. An optional AI analyst in the brain summarizes results and proposes marks, and a person must accept each proposal.

## How it works

### Data flow and trust boundaries

What runs in each container, what crosses between them, and every outside service Momus contacts. [Details](docs/diagrams/README.md)

[![Momus: data flow and trust boundaries](docs/diagrams/momus-dataflow.png)](docs/diagrams/README.md)

### Scan authorization policy

Every check a host has to pass before Momus sends it anything, who sets each one, and what happens when a check fails. [Details](docs/diagrams/scan-policy.md)

[![Momus: scan authorization policy](docs/diagrams/momus-scan-policy.png)](docs/diagrams/scan-policy.md)

### AI analyst data lineage

What the optional AI analyst is given, what it can produce, and what a person has to approve before anything changes. [Details](docs/diagrams/ai-lineage.md)

[![Momus: AI analyst data lineage](docs/diagrams/momus-ai-lineage.png)](docs/diagrams/ai-lineage.md)

## Ground rules

**The one rule: only the scanner sends scan probes to targets, and only the brain talks to a model provider.** The one exception is the optional seeder, which sends its own DNS traffic (API calls and zone transfers) to the DNS servers you configure, outside the scanner's exclusions and firewall ([data flows](docs/data-flows.md#sent-by-the-seeder-optional-off-unless-the-seed-profile-is-used)). The two containers share no network. They exchange files through two folders, each written by one side and read by the other.

**Use it only on systems you own.** Before the scanner sends anything to a domain, an administrator must state that they own it, and the scanner must find a DNS record that only your install can produce. If a later lookup of that record fails (rather than finds a wrong value), a domain verified in the last 7 days still counts ([DNS proof](docs/scope-and-authorization.md#2-dns-proof)). These checks help you avoid mistakes. They do not make scanning someone else's systems permitted. Read [responsible use](docs/responsible-use.md) before your first scan.

Momus is for a security engineer or a small team that wants a self-hosted scanner for its own domains, with a record of what was scanned, when, and on whose approval.

License: [MIT](LICENSE). Source: <https://github.com/mgrofsky/momus>.

## Quick start: the lab demo

The lab demo scans a deliberately weak web server that runs in its own container. The scanner, web application, and demo target use internal Docker networks with no route off your machine. A small browser bridge makes the web UI available only at `http://127.0.0.1:8080`; it has no mounted files or configured secrets and forwards requests only to the lab web application. It needs Docker Engine 28.0.0 or newer and Compose 2.24.4 or newer (tested with Docker Desktop 29.9.3 and Compose v5.7.0), about 5 GB of disk for the images, and the private range `10.89.47.0/24` free on your machine. [Older Docker engines can expose localhost-published ports to other machines on the same network](https://docs.docker.com/engine/network/port-publishing/#publishing-ports). It needs no model key and no cloud account. The image builds use the internet to download base images and packages. Stop anything already using port 8080 before starting the lab.

Run these commands in the project folder. The first one builds the images, which takes several minutes.

```sh
docker compose -f compose.yaml -f compose.lab.yaml up -d --build scanner brain demo-target ui-proxy
docker compose -f compose.yaml -f compose.lab.yaml logs brain
```

The log shows a one-time bootstrap token. Open `http://127.0.0.1:8080/bootstrap`, paste the token, and create the first account. Then use the web pages:

1. On **Scope**, add `target.demo.test` and `notice.demo.test` one at a time. Keep **Kind** set to **lab target (demo network only)** and confirm the ownership statement for each. Lab targets need no public DNS record.
2. On **Runs**, queue an **inventory**. It discovers the two lab hosts and does web fingerprinting. Wait for the job to show **done**.
3. On **Scope**, expand **Review inventory** and check the hosts and addresses, then click **Approve after review**. Under **Approved hosts (port scans allowed)**, add `target.demo.test` if you want the full lab check to include port scans of that target.
4. On **Runs**, queue a **full** run and wait for **done**. Open **Findings**, **Assets**, and **Runs** to explore the results and download the report. The lab banner confirms that these are demo results.

The UI bridge publishes to `127.0.0.1` only. The scanner, brain, and demo target have no published ports, and the brain still has no network shared with the scanner. The bridge is the only lab container with a host-facing network; that network has an outbound route, although the bridge only connects to the brain. The optional analyst uses a built-in mock provider and sends nothing to a model service. For an automated walkthrough of the same web flow, run `tests/e2e/run_demo_ui.sh` on a fresh lab; its driver uses HTTP and does not test rendered layout.

When you are done, remove the lab's containers, networks, and volumes:

```sh
docker compose -f compose.yaml -f compose.lab.yaml --profile dev down -v
```

## Using it on your own domains

Two things must be true first:

- **The Docker host must support iptables and ip6tables** in the scanner's network namespace, IPv4 and IPv6 alike. The scanner installs its egress firewall with both at every start, reads the rules back, and exits with an `entrypoint: FATAL:` line in `docker compose logs scanner` if either cannot be installed or verified. There is no switch to skip the firewall.
- **Each domain's authoritative nameservers must have public addresses.** The DNS proof asks them directly; if any nameserver of a domain resolves to a private or other non-public address, the domain is refused and never scanned ([scope and authorization](docs/scope-and-authorization.md#2-dns-proof)).

Start the scanner and the brain (without the lab file):

```sh
cp .env.example .env
docker compose up -d --build
docker compose logs brain
```

The log shows a one-time bootstrap token. Open `http://127.0.0.1:8080`, enter the token, and create the first account. The web pages are published on your machine's loopback address only. To reach them from elsewhere, put a reverse proxy with TLS in front ([operations](docs/operations.md#running-behind-a-reverse-proxy-with-tls)).

Then, in this order:

1. **Set the scope.** On the Scope page, add each domain, and add exclusions, owned address ranges, the check profile, and the rate profile as you need them ([scope and authorization](docs/scope-and-authorization.md)).
2. **State ownership.** Adding a domain requires ticking "I own this domain and the systems it points to." Your name and the time are recorded in the audit log and in every job.
3. **Publish the DNS record.** The scanner makes a token for each domain. A few seconds after you add a domain, the Scope page shows the exact TXT record to publish (Type, Name, and Value), at `_scan-verify.<domain>`; the page updates on its own while it waits for the scanner. After publishing it, click "Check DNS proof now" and wait until the domain shows `verified`.
4. **Run an inventory.** On the Runs page, queue an inventory run. It finds and classifies your hosts. It is not passive: before you approve anything, it sends DNS questions to your domain's nameservers (including a zone-transfer attempt), and HTTP and HTTPS requests with a TLS handshake plus whatweb and wafw00f fingerprinting requests to every live host it finds. It runs no port scan, no TLS scan, and no nuclei templates. A name it discovers under your domain may point at a system you do not own, and these requests reach that system before you review the list; add exclusions on the Scope page first for names you know point elsewhere.
5. **Review and approve the inventory.** On the Scope page, check every host and address before clicking "Approve after review". Active checks use those hosts and addresses, with a few exceptions:
   - A host you add to the approved hosts can be port-scanned at its current public addresses.
   - A new address in your owned ranges or a listed provider range is not held back.
   - A CDN or third-party host identified by its CNAME stays approved while that CNAME stays with the provider. These hosts never get a port scan.

   Other new hosts and changed addresses wait for a newer inventory ([hosts held back](docs/scope-and-authorization.md#8-hosts-and-domains-held-back)). The scanner checks addresses first, but most tools look up host names again. If a DNS record changes in between, a probe could go to another public address ([scope control limits](docs/scope-and-authorization.md#what-these-controls-do-not-stop)).
6. **Run a full scan.** On the Runs page, queue a full run. The Schedules page can queue a daily recheck, a daily version watch, and a monthly full run.
7. **Read the results.** Overview, Findings, Assets, and Domains show the latest snapshot. Each finding has its evidence, score, and history. Mark a finding as a false positive, an accepted risk, or a duplicate when that is the case ([findings and evidence](docs/findings-and-evidence.md)).
8. **Optionally, configure the analyst.** Set a model provider in `.env`, recreate the brain, and confirm on the Settings page what will be sent to the provider ([the analyst](docs/analyst.md)). Everything else works without it.

## Documentation

- [Responsible use](docs/responsible-use.md): who may use this, on what, and what a scan does to a target.
- [Architecture](docs/architecture.md): the containers, the two folders, the two databases, and the life of a job.
- [Scope and authorization](docs/scope-and-authorization.md): every control between your intent and the first packet.
- [Threat model](docs/threat-model.md): each attacker, what the design stops, and what each can still do.
- [Data flows](docs/data-flows.md): everything that leaves the machine, to whom, and how to turn it off.
- [Findings and evidence](docs/findings-and-evidence.md): what is stored, redaction and its limits, retention, scores, and marks.
- [The analyst](docs/analyst.md): what the AI analyst can and cannot do, and how to configure a provider.
- [Version watch](docs/version-watch.md): tracking product versions against the fixed releases you name.
- [Configuration](docs/configuration.md): every setting of every container.
- [Operations](docs/operations.md): first start, backups, upgrades, a reverse proxy, and troubleshooting.
- [Updating the base image](docs/base-image.md).
- Reference: [job file format](docs/reference/job-format.md), [published folder](docs/reference/published-layout.md), [version-watch output](docs/reference/version-watch-schema.md), [HTTP API](docs/reference/http-api.md).
- Cloud examples: [AWS](deploy/aws/README.md) and [Google Cloud](deploy/gcp/README.md).
- [Third-party tools and licenses](THIRD-PARTY-TOOLS.md), [security policy](SECURITY.md), [contributing](CONTRIBUTING.md), [code of conduct](CODE_OF_CONDUCT.md), and [changelog](CHANGELOG.md).

## Limits you should know

- **A clean result is not proof of safety.** The scanner finds what its tools and templates know about. A finding is marked fixed only when a later scan looked for it and did not find it, but a server that answers promptly with an error or block page can still make a finding look fixed.
- **Redaction is best effort.** The scanner stores a minimal, redacted record of each finding, but pattern matching misses secrets without a recognizable shape. Raw tool output stays unredacted on the scanner's disk until a retention job removes it, and nothing removes it automatically. If you turn on the analyst, text from scanned sites (after redaction) and the IP addresses of your hosts go to the model provider you choose.
