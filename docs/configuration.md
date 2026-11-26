# Configuration

Every setting is an environment variable, read once when its container starts. Each container gets its settings from a different place:

- **brain** (the web application container): an optional file named `.env` next to `compose.yaml`. Compose passes its contents to the brain only. Copy `.env.example` to `.env` and change what you need; every value in `.env.example` is the default. Never commit `.env`.
- **scanner** (the scan container): the `environment:` block of the scanner service in `compose.yaml`, or a `compose.override.yaml` you add. The scanner does not read `.env`. Its start-up script starts the job runner with a cleared environment and passes on only an allow-list (`scanner/entrypoint.sh`): the variables in the scanner section below, the standard `TZ` (the time zone of the generation time printed in the HTML report; unset means UTC, and every other time the scanner writes is in UTC), and `SCAN_EXIT_WHEN_IDLE`, which is on the list but read by nothing and has no effect. No other variable reaches the scanner's code.
- **seeder** (the optional DNS seeding container): an optional file named `seed.env` next to `compose.yaml`. The seeder never reads `.env`, so it never receives the brain's settings or the analyst's key. Never commit `seed.env`.
- **Keys**: give keys as Docker secrets, not as variables. The brain reads the analyst's key from the file named by `MOMUS_ANALYST_API_KEY_FILE`; the seeder reads the PowerDNS key from the file named by `SEED_PDNS_API_KEY_FILE`, and AWS credentials for Route 53 off AWS from the file named by `AWS_SHARED_CREDENTIALS_FILE`. `compose.yaml` holds commented `secrets:` lines for each.

The brain reads its settings once, at start. The Compose files use no `${...}` substitution.

Lab mode (an isolated test setup with a deliberately weak demo target) is started with `compose.lab.yaml`. That file sets the lab variables below and fixes the analyst variables to the built-in mock provider. For the names it lists, its values override `.env`, so a real provider or key in `.env` never reaches the lab brain.

A few terms used below: a **job** is one JSON file the brain writes to the jobs folder to ask the scanner for work; the **published folder** is where the scanner writes its results for the brain to read; a **snapshot** is a read-only copy of the scan database that the scanner publishes after each run; the **scope** is the domains, exclusions, and scan settings a job carries.

## Brain

How invalid values are handled, for every brain setting below unless its row says otherwise:

- **Numbers**: a value outside the range is moved to the nearest bound. A value that is not a whole number (including `2.5`) gives the default.
- **Switches** (on or off): `1`, `true`, `yes`, or `on` turns the setting on. Any other non-empty value turns it off. Empty gives the default.
- The brain refuses one combination of settings at start: `MOMUS_ALLOWED_ORIGINS` holds an `https://` address while `MOMUS_COOKIE_SECURE` is off. It then exits with a message saying so.

### Web access and sign-in

| Name | Default | Allowed values | Effect |
|---|---|---|---|
| `MOMUS_ALLOWED_ORIGINS` | `http://127.0.0.1:8080,http://localhost:8080` | Comma-separated addresses (scheme, host, port). Empty gives the default. | Every state-changing request must come from one of these addresses (Origin check). Behind a reverse proxy, put the public `https://` address here and set `MOMUS_COOKIE_SECURE=1`. |
| `MOMUS_COOKIE_SECURE` | `0` | Switch. | Marks the session cookie Secure and names it with the `__Host-` prefix. Set it when the brain is served over TLS. |
| `MOMUS_TRUSTED_PROXY` | empty (off) | One IP address. A name, range, or list leaves the setting off. | Only for requests whose connection comes from exactly this address, the last `X-Forwarded-For` entry is used as the client address for the sign-in limits and the audit log. From any other address the header is ignored. With an `https://` origin and this setting empty, the brain logs a warning at start and shows it on the Settings page, because all clients would then share the proxy's address for the sign-in limits. |
| `MOMUS_SESSION_IDLE_MINUTES` | `30` | 5 to 1440 | A session ends after this many minutes without a request. |
| `MOMUS_SESSION_MAX_HOURS` | `12` | 1 to 168 | A session ends this many hours after sign-in, whatever its activity. |
| `MOMUS_PASSWORD_MIN_LENGTH` | `12` | 12 to 128 | Minimum password length. |
| `MOMUS_LOGIN_MAX_FAILURES` | `5` | 3 to 50 | Failed sign-ins for one username (twice this many for one client address) before each further attempt has to wait. Failures count for 24 hours. |
| `MOMUS_LOGIN_MAX_DELAY_SECONDS` | `300` | 30 to 3600 | The longest wait between sign-in attempts. The wait doubles with each further failure up to this value. |
| `MOMUS_LOGIN_HASH_CONCURRENCY` | `2` | 1 to 8 | Password hashes computed at once. Each needs 32 MiB of memory. |

The sign-in limits count per username and per client address (an IPv6 client by its /64). There is no limit across all clients: one would make it cheaper to lock everyone out. A flood of attempts from many addresses can keep the hash slots full, and real sign-ins are then told the server is busy until it ends, so keep the user interface behind a network control. A browser that has signed in before gets no exemption from the delay. `clear-login-delays` (`docs/operations.md`, "Host recovery commands") clears it. Above 30 failed sign-ins in one minute, across all clients, the audit log stops writing one entry per attempt for the rest of that minute and writes one summary entry for the minute when it ends.

An expired session is removed from the app database when its cookie is next presented, or when its user signs out or has the password reset; until then its row stays.

### Snapshot, scheduler, paths, and listening

| Name | Default | Allowed values | Effect |
|---|---|---|---|
| `MOMUS_SNAPSHOT_QUERY_SECONDS` | `2` | Whole seconds, 1 to 60 | Every request's queries on the scan snapshot stop after this long; the page then says so. |
| `MOMUS_SNAPSHOT_MAX_MB` | `512` | 16 to 4096 | The largest scan snapshot the brain accepts, in MiB. A larger one is refused. |
| `MOMUS_SCHEDULER` | `1` | Switch. Empty means on. | Whether the brain queues the scheduled jobs (daily recheck, daily version watch, monthly full run). |
| `MOMUS_DATA_DIR` | `/data` | A container path | Where the app database lives. Must match the `brain_data` volume mount in `compose.yaml`. |
| `MOMUS_JOBS_DIR` | `/srv/jobs` | A container path | Where the brain writes job files. Must match the `jobs` volume mount. |
| `MOMUS_PUBLISHED_DIR` | `/srv/published` | A container path | Where the brain reads the scanner's results. Must match the `published` volume mount. |
| `MOMUS_LISTEN_HOST` | `0.0.0.0` | An address | The address the brain listens on inside its container. |
| `MOMUS_PORT` | `8080` | A port number. A value that is not a whole number stops the brain at start. | The port the brain listens on inside its container. `compose.yaml` publishes container port 8080 on `127.0.0.1:8080`; change both together. |

### Lab mode

Set by `compose.lab.yaml`. Leave both empty for real use.

| Name | Default | Allowed values | Effect |
|---|---|---|---|
| `MOMUS_LAB` | `0` (`compose.lab.yaml`: `1`) | Switch. | Lab mode: lab jobs can be queued, only the test providers of the analyst work, and real providers are refused. |
| `MOMUS_LAB_CIDR` | empty (`compose.lab.yaml`: `10.89.47.0/24`) | A CIDR. An invalid value means lab jobs cannot be queued. | The lab range that lab jobs carry. Lab mode and the lab range come from these two settings only. |

### Analyst

The analyst (an optional AI model that reads scan results and suggests changes for a person to accept) is off by default; everything else works without it. [The analyst](analyst.md) explains each setting in full. A wrong analyst setting never stops the brain: the analyst refuses to run, and the analyst's page says why.

| Name | Default | Allowed values | Effect |
|---|---|---|---|
| `MOMUS_ANALYST_PROVIDER` | `none` | `none`, `anthropic`, `openai`, `gemini`, `bedrock`. `mock` and `susceptible` are test providers, refused outside lab mode. Any other value: the analyst refuses to run. | The model provider. |
| `MOMUS_ANALYST_MODEL` | empty | The provider's model id (at most 200 characters). Required for every real provider. | The model the analyst asks. |
| `MOMUS_ANALYST_API_KEY` | empty | The key. When set, it is used instead of the file. | The provider key. Required for `anthropic`, `openai`, and `gemini`. For `bedrock` it is optional and means a Bedrock API key; without it, the default AWS credential chain is used. |
| `MOMUS_ANALYST_API_KEY_FILE` | empty | A path, for example `/run/secrets/momus_analyst_api_key`. The first line is read, at most 16 KiB, without following a link. A file that cannot be read means no key. | A file holding the key (a Docker secret). |
| `MOMUS_ANALYST_REGION` | empty | An AWS region name, for example `us-east-1`. Required for `bedrock`; otherwise the analyst refuses to run. | The Bedrock region. The endpoint is built from it. |
| `MOMUS_ANALYST_PROXY` | empty (direct) | One `http://` or `https://` URL with a host and a port, with no user name, password, or path. An invalid value stops the analyst; it never goes direct instead. | An egress proxy for provider requests. TLS inspection by the proxy is not supported. |
| `MOMUS_ANALYST_METADATA_ONLY` | `0` | Switch. | Leaves out of every prompt the text taken from scanned sites and the accepted notes. The provider then receives identifiers, numbers, and values from fixed lists. |
| `MOMUS_ANALYST_AUTO_BRIEF` | `0` | Switch. | Writes a brief automatically for each new scan snapshot. |
| `MOMUS_ANALYST_TIMEOUT_SECONDS` | `120` | 10 to 600 | One provider request. |
| `MOMUS_ANALYST_MAX_STEPS` | `12` | 1 to 40 | Model calls per run, corrective retries included. |
| `MOMUS_ANALYST_MAX_TOKENS_PER_CALL` | `16000` | 1024 to 64000 | Output tokens per call. |
| `MOMUS_ANALYST_RUN_TOKEN_BUDGET` | `200000` | 1000 to 5000000 | Input and output tokens per run. |
| `MOMUS_ANALYST_DAILY_TOKEN_BUDGET` | `1000000` | 1000 to 100000000 | Input and output tokens per UTC day, all runs together. |
| `MOMUS_ANALYST_RUN_SECONDS` | `300` | 10 to 3600 | Wall-clock time per run. |
| `MOMUS_ANALYST_MAX_PROPOSALS` | `10` | 0 to 50 | Proposals kept per run; more are dropped and recorded. |
| `MOMUS_ANALYST_MAX_INVALID` | `2` | 0 to 5 | Corrective retries for an invalid answer before the run fails. |
| `MOMUS_ANALYST_MEMORY_CHARS` | `4000` | 0 to 20000 | Characters of accepted notes included in each prompt, newest first. |
| `MOMUS_ANALYST_DEBUG` | `0` | Switch. Ignored in lab mode. | Stores each prompt and response with its run, for debugging. |

For `bedrock` without a key, the standard AWS credential variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_PROFILE`, the shared file paths, and the container, web-identity, and instance-metadata variables) keep their usual meaning. At start, the brain removes from its environment the variables a model SDK would read on its own (proxy, CA-bundle, and endpoint variables, `ANTHROPIC_*`, `OPENAI_*`, `GOOGLE_GENAI_*`, and the others [the analyst](analyst.md) lists) and logs their names. Setting them has no effect.

## Scanner

Only these variables have an effect on the scanner. Set them in the scanner service's `environment:` block. The runner gives each scan step a fresh environment of its own, so no other variable reaches the scan tools.

| Name | Default | Allowed values | Effect |
|---|---|---|---|
| `SCAN_JOB_MAX_AGE_HOURS` | `72` (also set in `compose.yaml`) | 1 to 8760. A value outside the range is moved to the nearest bound; a value that is not a whole number gives 72. | The scanner refuses a job whose `created_at` is older than this, with a final status of rejected; nothing runs. A job dated more than five minutes ahead is refused the same way. |
| `SCAN_KEEP_SNAPSHOTS` | `10` (also set in `compose.yaml`) | A whole number, 1 or more; 0 or less counts as 1. A value that is not a whole number stops the scanner at start. | How many snapshots the scanner keeps in the published folder, counting the current one. |
| `SCAN_POLL_SECONDS` | `5` | A whole number, 1 or more; 0 or less counts as 1. A value that is not a whole number stops the scanner at start. | How long the scanner waits before looking at the jobs folder again when there is no work. |
| `SCAN_ROOT` | `/var/lib/scan` | A container path | The scanner's data folder. Must match the `scan_data` volume mount. |
| `SCAN_JOBS` | `/srv/jobs` | A container path | The jobs folder the scanner reads. Must match the `jobs` volume mount. |
| `SCAN_PUBLISHED` | `/srv/published` | A container path | The published folder the scanner writes. Must match the `published` volume mount. |
| `SCAN_LAB` | unset (`compose.lab.yaml`: `1`) | `1` or unset. Any other value stops the scanner at start. | Lab mode: the firewall allows `SCAN_LAB_CIDR`, and lab fields in a job are accepted. |
| `SCAN_LAB_CIDR` | unset (`compose.lab.yaml`: `10.89.47.0/24`) | A private range (inside `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, or `fc00::/7`) no larger than a /24. Required with `SCAN_LAB=1` and refused without it; otherwise the scanner stops at start. | The one range the scanner's firewall allows in lab mode. A lab job's range must equal it. |

The check profile (`safe` or `active`), the rate profile (`low`, `normal`, or `fast`), and the evidence level (`minimal` or `excerpt`) are part of the scope each job carries, set in the brain. They are not environment settings of the scanner.

## Seeder

Set these in `seed.env`. Every source is off until it is set. A value that is not allowed stops the seeder with a configuration error that names the variable, never the value (exit code 2).

| Name | Default | Allowed values | Effect |
|---|---|---|---|
| `SEED_INTERVAL_MINUTES` | `0` | `0` or empty, or a whole number from 15 to 10080 | `0` runs once and exits. Otherwise the seeder runs again that many minutes after the start of each run. |
| `SEED_ROUTE53` | off | `1` (on) or `0` (off) | Reads public hosted zones under verified domains from Route 53, through the default AWS credential chain. Only the standard AWS partition (`arn:aws:`) is supported. |
| `SEED_ROUTE53_ROLE_ARN` | empty | `arn:aws:iam::<12 digits>:role/<name>`. Needs `SEED_ROUTE53=1`. | One IAM role to assume before reading Route 53. |
| `SEED_ROUTE53_REGION` | `us-east-1` | An AWS region name | The region of the endpoint used for the role assumption. Route 53 itself is global. |
| `SEED_ZONE_FILES` | off | `1` (on) or `0` (off) | Reads zone files or plain host lists from `./seed-zones` (mounted read-only at `/srv/seed-zones`). |
| `SEED_AXFR` | empty | `zone@address` pairs separated by spaces or commas, at most 100. The server is an IP address; it is never looked up by name. | Zone transfers from these servers. |
| `SEED_PDNS_URL` | empty | An `http://` or `https://` URL with no user name, password, query, or fragment | The base URL of the PowerDNS HTTP API. With `http://` the API key is sent in clear text; use `https://` unless the path to PowerDNS is a private network you trust. For an `http://` URL whose host is not loopback, the seeder logs a warning at start. |
| `SEED_PDNS_SERVER` | `localhost` | Letters, digits, dot, underscore, and hyphen. Needs `SEED_PDNS_URL`. | The PowerDNS server id. |
| `SEED_PDNS_ZONES` | empty | Host names separated by spaces or commas, 1 to 200. Required with `SEED_PDNS_URL`, refused without it. | The zones read from PowerDNS. |
| `SEED_PDNS_API_KEY_FILE` | `/run/secrets/momus_seed_pdns_api_key` | An absolute path | A file holding the PowerDNS key, normally a Docker secret. A key in a variable is not accepted. |
| `AWS_SHARED_CREDENTIALS_FILE` | `/nonexistent/aws-credentials` (no file) | A path, for example `/run/secrets/momus_seed_aws_credentials` | A static AWS credentials file for Route 53 on a host without an instance role. The AWS SDK honors what the file says, including a `credential_process` line, which would run inside the seeder container. |

The seeder ignores AWS profiles and the AWS configuration file: when it builds a Route 53 client it removes `AWS_PROFILE`, `AWS_DEFAULT_PROFILE`, and `AWS_SDK_LOAD_CONFIG` and points `AWS_CONFIG_FILE` at a file that does not exist. At start it removes the proxy, CA-bundle, endpoint (`AWS_ENDPOINT_URL*`), and plugin variables and logs their names. The standard AWS credential variables keep their usual meaning.

## Files that are settings

The scanner's lists in `scanner/config/` are copied into the image, owned by root, and the scanner's root filesystem is read-only. To change one, edit the file and rebuild the scanner image (`docker compose build scanner`).

| File | Edit it? | What it does |
|---|---|---|
| `scanner/config/own_networks.txt` | Yes | Your own networks and colocation providers: `substring<TAB>label` per line. A host whose AS name contains the substring shows the label in the hosting column. A bad line stops the ingest step with an error naming the file and line. |
| `scanner/config/cdn_cnames.txt` | Yes, to add providers | CNAME suffixes of CDN and WAF edges. A host whose CNAME chain ends in one is classed as CDN-fronted: web checks run, the shared edge addresses are not port scanned. |
| `scanner/config/third_party_cnames.txt` | Yes, to add providers | CNAME suffixes of SaaS and PaaS providers. A host whose CNAME chain ends in one is classed as third party: passive checks, HTTP fingerprint, and takeover and misconfiguration templates only, no port scan. |
| `scanner/config/third_party_ranges.txt` | Yes, to add ranges | Provider address ranges, one CIDR per line. A host whose address falls in one is classed as third party, as above. Shipped empty. |
| `scanner/config/exclude_tags.txt` | Add only | Nuclei template tags that never run (for example `dos`, `fuzz`, `intrusive`). The scan refuses to start when the file is missing, unreadable, or empty. Removing a tag lets those templates run. |
| `scanner/config/eol_products.txt` | No | The end-of-life products tracked. It must list exactly the products the code knows (`scanner/pipeline/fingerprint.py`); editing it alone breaks that match. |
| `scanner/config/policy.json` | Optional; not shipped | Overrides the fix-by days per severity band (`sla_days`, `strict_sla_days`, 1 to 3650 days), the name of the strict-SLA host list (`strict_sla_hosts_file`), and the informational results stored as technology rather than findings (`noise_tags`, `noise_ids`). A file that is not valid JSON, has an unknown key, or has a value of the wrong type stops the steps that read it, so a typo never falls back to the defaults silently. |

For the seeder, `./seed-zones` next to `compose.yaml` holds the zone files or host lists read with `SEED_ZONE_FILES=1`. Never commit it.

The code also reads variables that are not settings (values the containers and the scanner's runner set for themselves, and variables used only by the test suites and developer tools), so they are not listed here.
