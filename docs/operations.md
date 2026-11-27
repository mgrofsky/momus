# Operations

How to start Momus the first time, recover access, back it up, upgrade it, put it behind a reverse proxy, and find out why a scan found nothing. `docs/architecture.md` describes the containers, folders, and databases this page refers to.

## First start and the bootstrap token

Start the scanner and the brain:

    docker compose up -d --build

While no account exists, the brain prints a one-time **bootstrap token** to its log at every start:

    docker compose logs brain

The log lines say where to use it: the `/bootstrap` page at the first address in `MOMUS_ALLOWED_ORIGINS` (by default `http://127.0.0.1:8080/bootstrap`). Paste the token there and choose a username and password to create the first account.

- The token has no time limit. It works until it is used or until the brain restarts; each start replaces it with a new one until the first account exists.
- Only its SHA-256 is stored in the app database.
- Once the first account exists, the token is cleared, no new token is printed, and `/bootstrap` tells you to sign in instead.
- Further accounts are created by a signed-in user on the Settings page. Every account has the same admin role.

## Host recovery commands

Two commands help when nobody can sign in. They run inside the brain's container, so only someone with shell access to the host can use them. No web route reaches them, and nothing is sent over the network. Each writes one audit entry with the fixed actor `host-admin`. The code is in `brain/tools/admin.py`.

    docker compose exec brain python -B -m tools.admin clear-login-delays [username]
    docker compose exec brain python -B -m tools.admin reset-password <username>

- **`clear-login-delays`** removes the failed sign-in attempts that the sign-in delay counts (and attempts left pending for more than five minutes). With a username, it clears that username's failures only and reports how many failed attempts remain for other usernames: those can still hold the per-address delay. Without a username, it clears every username and address.
- **`reset-password`** sets a new password for an existing account and ends every session of that account. The password is read from standard input: at a terminal it asks twice without echo; otherwise it reads one line. It is never taken from an argument or an environment variable, and it must pass the same rules as any password (`MOMUS_PASSWORD_MIN_LENGTH`). To pipe it in, add `-T`: `docker compose exec -T brain python -B -m tools.admin reset-password <username>`.

Both commands refuse to run before the brain has created its database (start it once first). Exit codes: 0 done, 1 refused, 2 usage error.

## Backup and restore

The state that matters lives in four Docker volumes:

| Volume | What it holds |
|---|---|
| `brain_data` | the app database (`brain.sqlite` and its write-ahead-log files) and the brain's snapshot cache |
| `scan_data` | the scan database (`data/scan.sqlite`), the current scope, raw run output, reports, fetched templates, and the scanner's `state/` folder with the install secret and the record of finished jobs |
| `published` | job statuses, snapshots, reports, scope status, the heartbeat |
| `jobs` | job files not yet removed |

Compose names them `momus_<volume>`, for example `momus_brain_data`; `docker volume ls` shows them. The seeder's volumes (`seed`, `seed_scope`) need no backup: the scanner rewrites `seed_scope`, and the next seeder run rewrites `seed`.

**Take a consistent copy with both containers stopped.** Both databases are SQLite files. The app database runs in write-ahead-log mode, so copying `brain.sqlite` alone while the brain runs can miss committed changes that are still in the log. Stopping the containers and copying whole volumes avoids that. Write the backup to a folder outside the repository: the archives hold the install secret, password hashes, raw tool output, and scan results, and a folder inside the repository can be committed by mistake or end up in an image build context (`.gitignore` and `.dockerignore` exclude `backup/`, `backups/`, and `*.tar.gz`, but only as a second line of defense). For example, with the existing brain image (it includes `tar`) and no network:

    BACKUP="$HOME/momus-backups/$(date -u +%Y-%m-%d)"      # outside the repository
    docker compose stop
    mkdir -p "$BACKUP" && chmod 700 "$BACKUP"
    for v in brain_data scan_data published jobs; do
      docker run --rm --network none --user 0 -v "momus_$v:/from:ro" -v "$BACKUP:/to" \
        --entrypoint tar momus-brain -C /from -czf "/to/$v.tar.gz" .
    done
    docker compose start

The archives keep file owners and permissions; they are written as root on the host. If you cannot stop the brain, copy the app database only with SQLite's backup API (for example Python's `sqlite3.Connection.backup`), never with a plain file copy. Check a backup by restoring it into a separate Compose project before you rely on it.

**Protect the backup like a credential.** It holds the scanner's install secret (`state/install_secret` in `scan_data`). DNS proof tokens are derived from that secret, so another scanner install holding a copy would derive the same tokens and pass the DNS proof for your domains. The backup also holds the scan results and stored evidence, the audit log, and password hashes.

**Restore all four volumes from the same backup, before starting either container.** They depend on each other: an inventory approval in the app database names an inventory run that must exist on the scanner (otherwise full runs and rechecks are refused), job records in the app database match statuses in `published`, and snapshots in `published` are copies of the scan database. Then start the scanner first and the brain second. At start the scanner marks jobs left running as `interrupted`, and for each job file still in the jobs folder that it has already finished, it publishes the recorded final status again, so the brain sees those jobs as ended on its first read. For example:

    BACKUP="$HOME/momus-backups/<the backup's folder>"      # the backup folder to restore from
    docker compose down                    # keeps the volumes; never add -v here
    docker compose up --no-start           # creates any missing volume
    for v in brain_data scan_data published jobs; do
      docker run --rm --network none --user 0 -v "momus_$v:/to" -v "$BACKUP:/from:ro" \
        --entrypoint sh momus-brain -c "find /to -mindepth 1 -delete && tar -C /to -xzpf /from/$v.tar.gz"
    done
    docker compose start scanner
    docker compose start brain

If `scan_data` is lost and cannot be restored, the scanner creates a new install secret at its next start. Every domain then returns to "pending" with a new token, the Scope page shows the new TXT record to publish, and nothing is scanned on a domain until its new record is in place.

## Storage: local volumes only

Keep every volume on a local disk. Network file shares (NFS, SMB, and the like) are unsupported for the volumes: SQLite's locking is not reliable on them, and write-ahead-log mode requires every process using the database to be on the same host.

## Upgrades and migrations

To upgrade, update your copy of the source and rebuild:

    docker compose up -d --build

- **App database:** at every start, the brain applies any migration in `brain/app/migrations/` that the database has not yet recorded, in number order. Each migration runs in its own transaction together with its version row. If one fails, its changes are not committed and the brain does not start.
- **Scan database:** the scanner's ingest step creates missing tables and adds missing columns each time it runs.
- **Downgrades do not work.** There are no reverse migrations, and an older brain does not check whether the database was migrated by a newer one. Take a backup (above) before every upgrade; to go back, restore that backup together with the older images.

## Updating the base images

The scanner's `FROM` line pins the Kali base image by digest. Kali is a rolling release, so move the pin at least monthly and whenever a security fix lands in a package the scanner uses. The steps are in `docs/base-image.md`. The brain and the seeder pin their Python base image by digest the same way (`brain/Dockerfile`, `seeder/Dockerfile`).

## Updating the nuclei templates

A scan never updates the templates. There are two ways to get newer ones:

- **An `update-templates` job.** On the Runs page, "Update the scanner's templates" queues one. The scanner downloads the template set from the internet through its egress firewall into its data volume, and switches to it only when the download finished and holds more than 1,000 templates; otherwise the job fails and the earlier set stays in use. Once such a job has succeeded, that downloaded set is used in preference to the set baked into the image, also after you rebuild the image; queue another `update-templates` job to refresh it. The Overview page shows the template count, the source ("update-templates job" or "baked into the image"), and the date.
- **A rebuild of the scanner image** without cache (`docker build --no-cache -t momus-scanner scanner/`) bakes in the version pinned in `scanner/Dockerfile`. To bake in a newer set, update both the version and SHA-256 there from the [ProjectDiscovery release](https://github.com/projectdiscovery/nuclei-templates/releases) and its checksum file before rebuilding.

`scanner/update-templates.sh` updates the image's own copy inside a throwaway container with a writable filesystem and network access:

    docker run --rm -it --user 10001 --entrypoint /app/scanner/update-templates.sh momus-scanner

With `--rm`, that update is discarded when the container exits: it changes neither the image nor any volume. It is useful to check that an update works; to keep newer templates, use one of the two ways above.

## Retention

Raw tool output is kept in one folder per run in the scanner's data volume. A **retention** job (Runs page, "Queue retention clean-up", with a number of days from 1 to 3650, 30 by default) removes run folders older than that, except the most recent full run and any run a recheck is based on. It also trims the published snapshots to `SCAN_KEEP_SNAPSHOTS` and removes version-watch folders whose newest result is older than 90 days. Retention never runs on a schedule: it runs only when someone queues it. It does not remove rows from the scan database. What is stored, and for how long, is in `docs/findings-and-evidence.md`.

## Running behind a reverse proxy with TLS

The brain serves plain HTTP on `127.0.0.1:8080`. To reach it from other machines, put a reverse proxy with TLS in front of it and set three settings in `.env` together.

**The three settings:**

- `MOMUS_ALLOWED_ORIGINS`: the public address the browser uses, for example `https://momus.example.internal`. Every state-changing request must carry an `Origin` (or, failing that, a `Referer`) that matches one of these addresses, or it is refused with status 403.
- `MOMUS_COOKIE_SECURE=1`: marks the session cookie `Secure` and gives it the `__Host-` name prefix, so the browser sends it only over HTTPS.
- `MOMUS_TRUSTED_PROXY`: the proxy's one IP address, as the brain sees it.

**Start-up checks:**

- An `https://` address in `MOMUS_ALLOWED_ORIGINS` with `MOMUS_COOKIE_SECURE` off: the brain refuses to start and logs why.
- An `https://` address in `MOMUS_ALLOWED_ORIGINS` with `MOMUS_TRUSTED_PROXY` empty: the brain starts, logs a warning, and shows the same warning on the Settings page.
- A `MOMUS_TRUSTED_PROXY` value that is not one IP address (a name, a range, or a list) leaves the setting off.
- While running, if a request carries `X-Forwarded-For` but does not come from the `MOMUS_TRUSTED_PROXY` address, the brain logs a warning once per start. This is the sign that the proxy's address has changed.

**Which client address the brain uses.** The sign-in limits and the audit log use the client's address. By default that is the address of the connection itself. When the connection comes from exactly the `MOMUS_TRUSTED_PROXY` address, the brain uses the **last** `X-Forwarded-For` entry, taken across all `X-Forwarded-For` header lines, which is the entry the proxy itself appended. Earlier entries are never used. If that last entry is not a bare IP address (brackets, a port, `unknown`), the proxy's own address is used and the brain logs that once per start. From any other connection, `X-Forwarded-For` is ignored. The setting trusts that one address completely: anything that can connect to the brain from it chooses the client address the limits and the audit log see, so make sure only the proxy can.

**When the setting is wrong.** If `MOMUS_TRUSTED_PROXY` is empty, or does not match the proxy's address, every client appears to come from the proxy's address. The sign-in limits then treat all users as one address: after twice `MOMUS_LOGIN_MAX_FAILURES` failed sign-ins (ten by default) from anyone, every further sign-in attempt, from everyone, has to wait, with a delay that doubles up to `MOMUS_LOGIN_MAX_DELAY_SECONDS`. The audit log records the proxy's address for every request. The brain warns about this in its log and on the Settings page; the sign-in page says nothing. The same sharing happens without a proxy when many clients reach the brain from one address, for example behind a NAT: anyone among them who fails ten times (by default) delays sign-in for all of them.

**Give the proxy a fixed address.** Compose gives a container a new address when it is recreated, and the setting must match exactly. `compose.yaml` gives `brain_net` no fixed subnet. `.env.example` shows one way: a `compose.override.yaml` beside `compose.yaml` that gives `brain_net` a fixed subnet and the proxy service a fixed address on it, for example:

    networks:  { brain_net: { ipam: { config: [ { subnet: 172.30.81.0/24 } ] } } }
    services:  { proxy: { networks: { brain_net: { ipv4_address: 172.30.81.10 } } } }

with `MOMUS_TRUSTED_PROXY=172.30.81.10`. The proxy then reaches the brain at `brain:8080` on that network.

**What the proxy must do:**

- Terminate TLS and forward requests to the brain.
- Append the client's address, as a bare IP address, as the last entry of `X-Forwarded-For`.
- Pass the browser's `Origin` and `Referer` headers and the cookies through unchanged.
- Send the sign-in post (`POST /login`) and the first-account post (`POST /bootstrap`) to the brain with a `Content-Length` header and no `Transfer-Encoding` header; it must not re-frame these bodies as chunked. The brain checks this before it reads the body: no `Content-Length`, a value that is not 1 to 7 ASCII digits, or any `Transfer-Encoding` header gets status 411; a body larger than 16 KiB gets status 413.

Put the UI behind a network control as well (a VPN, or an allow-list at the proxy or a firewall), not on the open internet.

## When a scan finds nothing

Check these, in order:

1. **The job's status.** The Runs page shows each job's state, phase, exit codes, and reason. A job that failed or was rejected did not scan.
2. **DNS proof.** The Scope page shows each domain's verification state and the TXT record to publish. The scanner sends nothing to a domain that is not verified. "Check DNS proof now" queues a `scope-sync` job that checks again. When no domain passes the DNS proof, the run stops with "no apex passed the DNS proof check; nothing may be scanned" in the run's `recon.log`.
3. **Approval and held-back hosts.** Without an approved inventory, a full run does discovery and web checks only (no port scan, TLS scan, or templates), and a recheck cannot be queued. Hosts found after the approved inventory, hosts whose address changed after it, and hosts whose domain was added after it are held back from active checks; the Scope page lists them with the reason. Approve a newer inventory to include them.
4. **Scope.** Exclusions remove hosts and addresses. The port scan runs only on addresses inside your owned ranges or on hosts listed as approved hosts. In the run folder, `scope_rejected.jsonl` lists every rejection by the scope checks, and `coverage/<source>.txt` lists the hosts handed to each tool.
5. **Addresses and the firewall.** A host is probed only when every one of its addresses is globally routable and not excluded. A host with even one private or other non-global address is skipped, and the rejection is written to `scope_rejected.jsonl`. The firewall also blocks every non-global destination, except four narrow allowances: traffic on the container's own loopback interface, which never leaves the scanner container; DNS (port 53) to the resolvers Docker's own resolver forwards to, even when one of those is a non-public address; IPv6 neighbor discovery to link-local and link-scope multicast addresses; and, in lab mode only, the lab range ([the egress firewall](scope-and-authorization.md#6-the-egress-firewall)).
6. **Lab mode.** In lab mode (`compose.lab.yaml`) the scanner is on an internal network with no route off the machine, and the brain queues only inventory, full, and version-watch runs of lab targets. Real domains are not scanned in lab mode, and lab targets are scanned only in lab mode.
7. **Check profile.** `safe`, the default, excludes the templates tagged `default-login`, `sqli`, `rce`, `lfi`, `ssrf`, `xss`, and `injection`; only `active` runs them.
8. **Rate profile.** `low`, the default, is the slowest. A target that drops or times out requests can make tools miss responses; compare the error share in `recon.log` with a run at a slower rate. Outside lab mode, dnsx, httpx, and nuclei look names up through their own public resolvers (`docs/data-flows.md`); a host whose lookup fails there, for example under load, drops out of that run's probe.

**Logs to read:**

- `docker compose logs scanner`: the firewall set-up, and one line per job when it starts, is rejected, and ends.
- `docker compose logs brain`: start-up warnings, refused settings, and errors (exception type only).
- The run folder in the scanner's data volume, `/var/lib/scan/runs/<job id>/`: `recon.log` (every phase, with its start, end, and exit code), `runner-<step>.log` for each step, `scope_rejected.jsonl`, `coverage/`, and `manifest.json`. For example:

      docker compose exec -u 10001 scanner tail -n 100 /var/lib/scan/runs/<job id>/recon.log

## Abandoning a stuck job

Only one job is in flight at a time, and a job stays in flight until the scanner publishes its final status. If that status is lost (for example, the `published` volume was replaced), nothing new can be queued. After ten minutes, the Runs page lists such a job under "Jobs with no final status" with a **Mark abandoned** button and a checkbox confirming that the scanner is not running it. The API offers the same action.

The brain refuses when the job already has a final status, when the scanner's heartbeat (no older than 180 seconds) says it is running that job, when the job is already marked abandoned, or when the brain has neither a record nor a job file for that id. Otherwise it writes the marker file `<job id>.abandoned` in the jobs folder, records the change and an audit entry, and removes the job file. The scanner never runs a job id that has this marker, even if its job file is still there.

## The analyst

The analyst is off by default. Its settings, what it sends, and its limits are in `docs/analyst.md`.

**Try a provider first** with the smoke test, `brain/tools/smoke_provider.py`. Put `MOMUS_ANALYST_PROVIDER` and `MOMUS_ANALYST_MODEL` (and, for Bedrock, `MOMUS_ANALYST_REGION`) in `.env`; `docker compose run` gives the brain's settings from `.env` to this one-off container too. Leave `MOMUS_ANALYST_API_KEY` empty, because a key there is used instead of the file. Put the key in a file, `secrets/momus_analyst_api_key` beside `compose.yaml`, with an editor rather than `echo`, so that it never appears on a command line or in your shell history. The brain reads the first line of that file, and the file must be readable by the container's user (uid 10001). Never commit the `secrets` folder. Then run:

    docker compose run --rm --no-deps \
      -v "$PWD/secrets/momus_analyst_api_key:/run/secrets/momus_analyst_api_key:ro" \
      -e MOMUS_ANALYST_API_KEY_FILE=/run/secrets/momus_analyst_api_key \
      --entrypoint python3 brain -B -m tools.smoke_provider

For Bedrock the key is optional; without one, leave out the two lines that name the key file. It checks the model, runs one brief on built-in demo data in a temporary folder (two hosts, three findings, none of your data), and prints the outcome, each step, the token use, and the brief. The demo data and the prompts are sent to the provider. The key is never printed. Exit code 0 means the brief finished.

Run the smoke test once after you configure a provider, before the first real brief.

**Outbound traffic.** Once a provider is set, the brain connects to it from `brain_net`, an ordinary bridge network. Docker cannot limit a container's outbound traffic by destination, so nothing in Compose stops the brain from reaching other destinations. To enforce "the provider only", put an egress proxy or a host firewall rule in front of that network. Two settings limit what leaves:

- `MOMUS_ANALYST_PROXY`: an egress proxy for the provider requests, `http://host:port` or `https://host:port`, with no user name, password, or path. An invalid value stops the analyst; it never falls back to a direct connection. The proxy sees which provider is contacted, not the content; TLS inspection by the proxy is not supported. The proxy is named in the statement an admin confirms on the Settings page.
- `MOMUS_ANALYST_METADATA_ONLY=1`: sends no text taken from scanned sites, no accepted notes, and no reasons people typed for marks. Identifiers, host names, IP addresses, severities, scores, versions, and counts are still sent, as is a chat question as typed.

## The seeder and the cloud examples

**Cloud examples.** `deploy/aws/` (a CloudFormation template) and `deploy/gcp/` (a script for Google Cloud) each set up one scanner host. Each README lists what it creates and how it is checked.

**Seeder limits.** Run it once with `docker compose --profile seed run --rm seeder`, or on an interval with `SEED_INTERVAL_MINUTES` (15 to 10080) and `docker compose --profile seed up -d seeder`. Its settings are in `.env.example` and belong in `seed.env`.

- A zone file larger than 16 MiB is skipped.
- A PowerDNS answer larger than 8 MiB is refused (`pdns-answer-too-large` in `status.json`).
- The container's memory is capped at 512 MiB (`compose.yaml`).
- A zone file is read into memory whole and split into all of its lines at once, so its memory use grows with its size. The largest accepted zone file stays under the memory cap, but with little margin.
- Compose never restarts the seeder (`restart: "no"`). In interval mode, a seeder stopped by the memory cap stays down until you start it again. The time in `status.json` in the `seed` volume shows how old the seed list is.
- At most 50,000 host names are written per run, shared equally among the enabled sources.
