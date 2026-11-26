# Architecture

Momus runs as two containers: the **scanner**, which scans, and the **brain**, the web application. They share no network. They exchange files through two folders and nothing else. Only the scanner sends packets to scan targets. An optional third container, the **seeder**, lists host names from DNS services you control.

The data flow diagram, with its trust boundaries and numbered flows, is in [diagrams](diagrams/README.md). Two more diagrams sit beside it: the [scan authorization policy](diagrams/scan-policy.md) and the [AI analyst data lineage](diagrams/ai-lineage.md).

Terms used on this page:

- **Job:** one JSON file the brain writes to the jobs folder, telling the scanner what to do next.
- **Scope:** the domains, exclusions, and settings a job carries. A **domain** is an apex domain in scope.
- **DNS proof:** a TXT record you publish on a domain to show you control it. The scanner derives the record's value and checks it before it scans the domain; a domain that passes is **verified**.
- **Inventory:** a discovery-only run. An **approval** is an admin's approval of one inventory; full runs and rechecks run active checks only on hosts that inventory found.
- **Held back:** hosts or domains kept out of active checks, for example hosts found after the approved inventory.
- **Recheck:** a run that re-tests the hosts of an earlier full run, without discovery.
- **Ingest:** the scanner step that turns a run's raw tool output into rows of the scan database.
- **Snapshot:** a read-only copy of the scan database that the scanner publishes after each ingest.

## The containers

All services are defined in `compose.yaml`. The lab demo target is in `compose.lab.yaml`.

### Scanner

- **Holds:** a Kali-based image you build yourself; it is never published prebuilt. The image holds the recon tools from Kali's own packages (nmap, subfinder, assetfinder, dnsx, dnsrecon, httpx-toolkit, whatweb, wafw00f, sslscan, nuclei), a set of nuclei templates baked in at build time, the scan pipeline, the job runner (`scanner/runner.py`), and the scan database. The pipeline files are owned by root and are read-only to the scanner user.
- **User and capabilities:** the entrypoint (`scanner/entrypoint.sh`) starts as root with four capabilities only: `NET_ADMIN` to install the egress firewall, and `SETUID`, `SETGID`, and `SETPCAP`, used once to drop privileges. It installs the firewall, verifies it, then drops to uid and gid 10001 with every capability set empty (the bounding set included), sets no-new-privileges, and starts the job runner with a clean environment. The runner and every scan tool run with no capabilities. Without `NET_ADMIN` the container exits. nmap runs as a connect scan (`-sT`), which needs no raw sockets.
- **Root filesystem:** read-only. The writable volumes are `scan_data`, `published`, and `seed_scope` (see the mounts below), and `/tmp` is a 1 GiB in-memory filesystem.
- **Network:** its own network, `scanner_egress`. No published port. The egress firewall, for IPv4 and IPv6, allows traffic on the container's own loopback interface (it never leaves the container; Docker's embedded resolver at 127.0.0.11 is reached this way), established connections, and port 53 to the resolvers Docker's own resolver forwards to. On every other interface it rejects every private, loopback, link-local, carrier-grade NAT, multicast, documentation, benchmarking, reserved, and other non-global destination, including the cloud metadata addresses `169.254.169.254` and `fd00:ec2::/32`. IPv6 neighbor discovery to link-local and link-scope multicast addresses is also allowed, and in lab mode the lab range. Everything else is allowed. So, apart from its own loopback interface, those DNS and neighbor-discovery allowances, and the lab range, the scanner reaches public addresses only (a resolver Docker forwards to can itself be a non-public address; see [what these controls do not stop](scope-and-authorization.md#what-these-controls-do-not-stop)). It cannot reach the brain, the seeder, other containers, the host's private networks, or the cloud metadata service. Before dropping privileges, the entrypoint reads every rule back, compares it with what it meant to install, and tries to connect to the metadata address; any difference or a successful connection stops the container. On a network with no default route, the connection attempt fails before any packet reaches the firewall's reject rule; the entrypoint then logs that and relies on the read-back of the rules. There is no switch to skip the firewall.
- **Mounts:**

  | Volume | Path in the container | Access |
  |---|---|---|
  | `scan_data` | `/var/lib/scan` | read-write |
  | `jobs` | `/srv/jobs` | read-only |
  | `published` | `/srv/published` | read-write |
  | `seed` | `/srv/seed` | read-only |
  | `seed_scope` | `/srv/seed-scope` | read-write |

- **Writes:** in `scan_data`: the current scope (written from each job), one folder per run under `runs/` with the raw tool output and the run's logs, the scan database `data/scan.sqlite`, the reports, the templates fetched by an `update-templates` job, and a private `state/` folder. `state/` holds the install secret (`install_secret`, created on first start, readable by the owner only, never published; DNS proof tokens are derived from it), the record of finished jobs, and the inventory kept with the approval in force. In `published`: everything the brain may read (see "The two folders"). In `seed_scope`: `verified_domains.json`, the names of the DNS-verified domains, for the seeder.

### Brain

- **Holds:** the web application (UI and API), the scheduler, the analyst and its model client, and the app database. Python 3.13 slim base image pinned by digest; Python packages installed from exact versions with hashes.
- **User and capabilities:** uid and gid 10001 (the same uid as the scanner, so both can use the shared `jobs` volume whichever container creates it first). All capabilities dropped. No-new-privileges.
- **Root filesystem:** read-only. The writable volumes are `brain_data` at `/data` and `jobs` at `/srv/jobs`, and `/tmp` is a 64 MiB in-memory filesystem.
- **Network:** its own network, `brain_net`, an ordinary bridge network. Port 8080 is published on `127.0.0.1` only. It has no route to the scanner. Docker places no limit on its outbound traffic, so the brain can reach any address the host can. With the analyst off (`MOMUS_ANALYST_PROVIDER=none`, the default) the brain makes no outbound connection. With a provider set, it connects to that provider (see `docs/analyst.md`).
- **Mounts:**

  | Volume | Path in the container | Access |
  |---|---|---|
  | `brain_data` | `/data` | read-write |
  | `jobs` | `/srv/jobs` | read-write |
  | `published` | `/srv/published` | read-only |

- **Writes:** the app database `/data/brain.sqlite` (with SQLite's write-ahead log files beside it), verified copies of scan snapshots in `/data/snapshot-cache/` (at most three), and in the jobs folder: job files, `<job id>.abandoned` markers, and the removal of job files whose job has ended.

### Seeder (optional)

Started only with the Compose profile `seed`. A plain `docker compose up` never starts it.

- **Holds:** `seeder/seed_dns.py` and the AWS SDK (boto3, exact versions with hashes). The same Python base image as the brain, pinned by digest.
- **User and capabilities:** uid and gid 10002, a user of its own. All capabilities dropped. No-new-privileges. Memory capped at 512 MiB. Compose does not restart it.
- **Root filesystem:** read-only. The only writable volume is `seed` at `/srv/seed`, and `/tmp` is a 16 MiB in-memory filesystem.
- **Network:** its own network, `seed_net`, with ordinary outbound access, because it must reach your DNS services, which may be on private addresses. No published port, and no route to the scanner or the brain. The scanner's firewall and exclusions do not apply to it. It contacts only the DNS services you configure. A zone transfer server is usually the zone's own name server, which can be a host in scope.
- **Settings:** from `seed.env` only (a file you create beside `compose.yaml`). It never reads `.env`, so it never receives the brain's settings or the analyst's key.
- **Mounts:** `seed_scope` at `/srv/seed-scope` (read-only), `seed` at `/srv/seed` (read-write), and the host folder `./seed-zones` at `/srv/seed-zones` (read-only; used only with `SEED_ZONE_FILES=1`). It does not mount the published folder.
- **Writes:** `seed_hosts.txt` (host names only, one per line) and `status.json` in the `seed` volume.

### jobctl (developers only)

Compose defines a developer tool, `jobctl` (profile `dev`), a stand-in for the brain used by tests and for debugging (`scanner/jobctl.py`). It runs from the scanner image as uid 10001, with no network at all, all capabilities dropped, no-new-privileges, and a read-only root filesystem. It mounts `jobs` read-write, `published` read-only, and its own `jobctl_state` volume read-write; those two are its only writable volumes. It writes job files the same way the brain does, so while it is in use the brain is not the only writer of the jobs folder.

### Lab mode and the demo target

`compose.lab.yaml` is an extra Compose file, never loaded by the plain `docker compose up`. It runs under its own project name (`momus-lab`), so its volumes and networks are separate from those of a real scanner. Every network in it is internal, with no route off the machine.

- **Demo target** (`demo-target`): a deliberately weak web server (`demo/target/server.py`) on port 80 with invented weaknesses for the scanner to find. It runs as uid 10002 (the image's own user), with a read-only root filesystem, all capabilities dropped, and no-new-privileges. It sits on the internal network `lab` (`10.89.47.0/24`) at `10.89.47.10`, under the names `target.demo.test` and `notice.demo.test`. Its base image is pinned by digest (`demo/target/Dockerfile`).
- **Scanner in lab mode:** moved to the `lab` network at `10.89.47.2`, with `SCAN_LAB=1` and `SCAN_LAB_CIDR=10.89.47.0/24`. The firewall additionally allows that one range. The runner accepts lab fields in a job only in this mode and only with this same range.
- **Brain in lab mode:** on the internal network `brain_lab`, with no published port, `MOMUS_LAB=1`, and the analyst set to the `mock` test provider, overriding anything in `.env`.

## The two folders

The scanner and the brain exchange files only, and each folder has one direction:

- **`jobs/`** (volume `jobs`): the brain writes, the scanner reads. Read-only in the scanner. One JSON file per job, `<job id>.json`, plus `<job id>.abandoned` markers.
- **`published/`** (volume `published`): the scanner writes, the brain reads. Read-only in the brain. It holds:
  - `status/<job id>.json`: each job's state, phase, counts, times, and exit codes;
  - `snapshots/<run id>.sqlite` and `snapshots/latest.json`: the snapshot and the pointer to the newest one;
  - `reports/<run id>/`: the HTML report and CSV files;
  - `scope_status.json`: for each domain, its verification state, the exact TXT record to publish, and the last check;
  - `held_back.json`: hosts the latest full run or recheck kept out of active checks, with reason codes;
  - `version-watch/<watch id>/`: version-watch results;
  - `scanner.json`: the scanner's heartbeat (tool versions, templates, image build date, profiles in effect), written about every 30 seconds while idle, and at every phase change and at least every 30 seconds during a job.

Every writer writes a file under a temporary name starting with a dot in the same folder, then renames it into place. Readers ignore names starting with a dot, so they see only complete files.

The optional seeder adds two more one-way volumes. Neither is mounted by the brain:

- **`seed`**: the seeder writes, the scanner reads (read-only). The scanner reads `seed_hosts.txt` at the start of discovery as untrusted input and passes every name through the same name check as every other source (`scanner/pipeline/seed_input.py`).
- **`seed_scope`**: the scanner writes, the seeder reads (read-only). It holds only `verified_domains.json`: a schema name, a time, and the names of the DNS-verified domains. The scanner rewrites it whenever it publishes `scope_status.json`. The seeder lists hosts only under those domains.

## The two databases

Both are SQLite files on local Docker volumes. Each has exactly one writer, and no database file is open in two containers.

- **Scan database:** `data/scan.sqlite` in the scanner's `scan_data` volume (`/var/lib/scan/data/scan.sqlite`). It holds the scan runs, hosts and their observations, findings and their observations, ports, certificates, TLS settings, DNS records, components, and run summaries. It is written only by the scanner's ingest step (`scanner/pipeline/ingest.py`); other scanner steps read it. The brain never opens it. The brain reads only snapshots, copies the scanner publishes after each ingest.
- **App database:** `brain.sqlite` in the brain's `brain_data` volume (`/data/brain.sqlite`), in SQLite's write-ahead-log (WAL) mode. It holds accounts, sessions, sign-in attempts, the hash of the bootstrap token, the scope (domains with their ownership statements, exclusions, owned ranges, approved hosts, the inventory approval, the profiles), schedules, the jobs the brain wrote (each with a copy of its job document), marks on findings, notes, the analyst's runs, steps, and proposals, version-watch definitions, settings, and the audit log. It is written only by the brain. The host recovery commands (`brain/tools/admin.py`) run inside the brain's container and use the same database code. Its schema is created and upgraded by numbered SQL migrations (`brain/app/migrations/`) each time the brain starts.

## Job life cycle

1. **The brain writes the job.** A person or the scheduler queues a job. Inside one write transaction on the app database, the brain removes job files that have ended, checks that no job is in flight, builds the job from the app database, refuses it if it would be larger than 1 MiB, records the job and its document in the `jobs` table, writes an audit entry, and writes the job file (temporary name, flushed to disk, then renamed to `<job id>.json`). A job is in flight while a job file has no final status, or while the scanner's heartbeat, no older than 180 seconds, says it is busy. Only one job is in flight at a time.
2. **The scanner validates it.** The runner looks at the jobs folder every few seconds (5 by default) and takes job files oldest first. It skips a job id that has an `.abandoned` marker or that it has already finished. Each file is opened without following links and must be a regular file of at most 1 MiB, holding UTF-8 JSON with no duplicate keys that passes the full format check. `created_at` is required: a job created longer ago than `SCAN_JOB_MAX_AGE_HOURS` (72 hours by default, 1 to 8760) or dated more than five minutes ahead of the scanner's clock is refused. An invalid job gets the final status `rejected` with a fixed reason that names the field (the bad value is never repeated) and never runs.
3. **The scanner runs it.** The status moves from `queued` to `running`. The runner writes the job's scope into a new folder and switches to it in one rename. When a full run or a recheck carries an approval, the approval must name an inventory run on this scanner that covers at least one domain of the scope; otherwise the job is rejected before anything runs. A full run without an approval runs as an inventory (discovery only: no port scan, TLS scan, or templates); a recheck cannot be queued without one. The runner then runs the job's steps one at a time, recording the current phase in the status file. Scan jobs end with ingest, the snapshot, and the report.
4. **The scanner publishes the final status.** A job ends as `done`, `failed`, `rejected`, or `interrupted`. The runner first records the final status in its own data volume (`state/finished/<job id>.json`), then publishes it in `status/<job id>.json`. A job id recorded there never runs again, whatever the published folder says. If its job file is still in the jobs folder and its published status is missing or not final, the runner publishes the recorded status again. If the scanner stops during a job, that job is marked `interrupted` (at the stop, or at the next start).
5. **The brain removes finished job files.** When the Runs or Scope page is shown, before each new job is queued, and on the brain's background tick (every 30 seconds), the brain removes each job file whose job has a final status or an abandoned marker. The job's document stays in the app database.
6. **Abandon.** If a job never gets a final status (for example, because its status file was lost), it keeps the queue blocked. After ten minutes the Runs page offers to mark it abandoned (see `docs/operations.md`). The brain writes `<job id>.abandoned` first, then records the change and an audit entry, then removes the job file. The scanner never runs a job id that has this marker.

## The snapshot and its hash check

The brain never reads the scanner's database directly. After each successful ingest, the scanner publishes a snapshot:

- It copies the scan database with SQLite's backup API to a temporary file in `published/snapshots/`, runs SQLite's integrity check on the copy, renames it to `<run id>.sqlite`, computes its SHA-256, and writes `snapshots/latest.json` with the run id, job id, file name, SHA-256, and time. The hash is also recorded in the job's status.
- It keeps the newest `SCAN_KEEP_SNAPSHOTS` snapshots (10 in `compose.yaml`). The one `latest.json` names is always kept.

The brain opens only the file `latest.json` names, and only after these checks:

- `latest.json` must be small and complete, name a file that matches the snapshot name pattern, and carry a 64-character hex SHA-256. Otherwise nothing is opened.
- A file larger than `MOMUS_SNAPSHOT_MAX_MB` (512 by default, 16 to 4096) is refused.
- The brain copies the file into its own cache while hashing it. A copy whose SHA-256 differs from the recorded one is refused. Hashing the copy, not the original, means the file checked is the file opened, even if the scanner replaces files in the published folder at the same moment.
- **Refused schemas:** the copy must hold only plain tables and plain indexes. A view, trigger, virtual table, shadow table, or hidden or generated column causes a refusal, as does a table the brain reads that lacks the columns it reads. A missing table is allowed; its page shows nothing.
- The copy must pass SQLite's quick check within 120 seconds.

Only a copy that passes every check is moved into `/data/snapshot-cache/`; the brain keeps the three newest. It opens the copy read-only and immutable, with an authorizer that allows only reads, `trusted_schema` off, and a query deadline: every request's snapshot queries stop after `MOMUS_SNAPSHOT_QUERY_SECONDS` (2 by default, 1 to 60), and the page says so. The outcome of each check, refusals included, is remembered for that file's path, inode, size, modification time, and recorded hash, so a refused file is not copied and hashed again on every request. The brain shows a fixed message for each kind of refusal and never writes to the published folder.

## What a job file contains

A job file is one JSON object:

- `schema`: `momus-job-v1`;
- `id`: 2 to 64 characters, lowercase letters, digits, and hyphens; it must match the file name;
- `type`: `scope-sync`, `inventory`, `full`, `recheck`, `version-watch`, `update-templates`, or `retention`;
- `created_at`: the time the brain wrote it;
- `scope`: a full copy of the scope from the app database: domains, exclusions, owned ranges, approved hosts, the ownership statement for each domain, the inventory approval, and the check profile, rate profile, and evidence level;
- `lab` (lab mode only): the lab targets and the lab range;
- `options`: `retention_days` for a retention job, the watches for a version-watch job.

A job never carries a DNS proof token; the scanner derives tokens itself, and a job that carries one is rejected. The full format and every rule the scanner checks are in `docs/reference/job-format.md`.
