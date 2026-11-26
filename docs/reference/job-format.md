# Job file format (`momus-job-v1`)

A job is one JSON file that tells the scanner what to do next. The brain writes job files into the jobs folder, and
the scanner reads them (read-only) and answers with one status file per job in the published folder. This page is
the exact format of both, for anyone who writes jobs by hand, writes a client, or reviews what the scanner accepts.
The validator is `validate_job` in `scanner/runner.py`; where this page and that function disagree, the function is
right and this page is wrong.

## Where job files go and how to write them

- **Folder.** The jobs folder: `/srv/jobs` in both containers (the `jobs` volume). The brain mounts it read-write; the
  scanner mounts it read-only.
- **File name.** `<job id>.json`. The stem must equal the job's `id`.
- **Writing.** Write the JSON to a dot-prefixed temporary name in the jobs folder itself (the brain and
  `scanner/jobctl.py` use `.<job id>.json.tmp-<pid>`), flush and fsync it, then rename it to `<job id>.json`. The
  scanner never reads a name that starts with `.`, so it only ever sees complete files. The brain never overwrites an
  existing job file.
- **What the scanner looks at.** Only names that end in `.json` and do not start with `.`. Everything else in the
  folder is ignored.
- **Order.** One job runs at a time, oldest file first by modification time, then by file name.
- **Who removes job files.** The brain deletes a job file once the scanner has published a final status for it (or
  once the job is marked abandoned). The scanner never deletes anything in the jobs folder.

## Job id

| Rule | Value |
|---|---|
| Pattern (full match) | `[a-z0-9][a-z0-9-]{0,62}[a-z0-9]` |
| Length | 2 to 64 characters |
| Characters | lower-case letters, digits, and `-`; first and last character a letter or digit; a trailing newline is refused |
| Use | the file name stem, the status file name, and, for `inventory`, `full`, and `recheck` jobs, the run id |

The brain names its jobs `<prefix>-<YYYYMMDD>-<HHMMSS>-<6 hex>` (UTC), with prefix `sync`, `inv`, `full`, `recheck`,
`vw`, `tpl`, or `ret` for the seven job types. The scanner does not require this form; any valid id works.

A job id runs at most once on a given scanner. Once a job has a final status (`done`, `failed`, `rejected`, or
`interrupted`), the scanner never runs that id again, even if a new file with the same id appears (see
[Finished jobs](#finished-jobs-and-reused-ids)).

## File rules

These are checked before the JSON content is looked at. Any failure gives the job the state `rejected` with the fixed
reason shown; the job never runs.

| Rule | Reason when it fails |
|---|---|
| The file name is `<valid job id>.json` | `file name: must be <job id>.json with a valid job id` |
| A regular file, not a symbolic link (links are never followed) | `file: a symbolic link (job files are never followed through links)` |
| A regular file, not a FIFO, device, or folder | `file: not a regular file` |
| It can be opened | `file: cannot be opened` |
| At most 1,048,576 bytes (1 MiB), checked with `lstat` and again on the opened file before reading | `file: larger than 1048576 bytes` |
| UTF-8 | `file: not valid UTF-8 JSON (not UTF-8)` |
| JSON with no key twice in any object | `file: not valid UTF-8 JSON (a key appears twice in one object)` |
| Arrays and objects nested at most 32 deep | `file: not valid UTF-8 JSON (nested too deeply)` |
| Small enough to parse in memory | `file: not valid UTF-8 JSON (too large to parse)` |
| Valid JSON | `file: not valid UTF-8 JSON` |
| The top level is an object | `job: must be an object` |

A job file whose name is not a valid id gets its status under the key `invalid-<16 hex>`, where the 16 hex
characters are the start of the SHA-256 of the file name. No status ever repeats the file name or any job content.

## Top level

No other key is allowed (`job: unknown field '<name>'`).

| Key | Type | Required | Allowed values |
|---|---|---|---|
| `schema` | string | yes | exactly `"momus-job-v1"` |
| `id` | string | yes | the job id pattern above; equal to the file name stem |
| `type` | string | yes | `scope-sync`, `inventory`, `full`, `recheck`, `version-watch`, `update-templates`, `retention` |
| `created_at` | string | yes | the time the job was written: `YYYY-MM-DDTHH:MM:SS`, optional `.` and 1 to 6 digits, then `Z` or `+HH:MM` / `-HH:MM`; must be a real date and time. See [Age rule](#age-rule-for-created_at). |
| `scope` | object | yes, every type | see [`scope`](#scope). It is always the full current scope; the scanner replaces its scope with each job's. |
| `lab` | object | no | only on `inventory`, `full`, and `version-watch` jobs, and only when the scanner runs in lab mode. See [`lab`](#lab). |
| `options` | object | depends on type | `retention`: optional. `version-watch`: required. Every other type: absent or `{}`. See [`options`](#options). |

## Age rule for `created_at`

- A job whose `created_at` is older than the scanner's job age limit is rejected with the reason
  `job: created longer ago than the scanner's job age limit (SCAN_JOB_MAX_AGE_HOURS); it was not run. Queue it again if it is still wanted.`
- A job whose `created_at` is more than five minutes ahead of the scanner's clock is rejected with the reason
  `job: dated in the future (more than five minutes ahead of the scanner's clock); it was not run. Check the brain's and the scanner's clocks, then queue it again.`
- A job without `created_at` is rejected with `created_at: required (the time the brain wrote the job)`. A value that
  is not a valid time is rejected with `created_at: not an ISO 8601 UTC time`.
- The limit is `SCAN_JOB_MAX_AGE_HOURS` in the scanner's environment: a whole number of hours, default 72, clamped to
  1 to 8760. A value that is not a number means 72. `compose.yaml` sets 72.
- The age is checked every time the scanner reads the pending job files, until the job starts. A job that waits in the
  folder past the limit (for example behind a long job) is rejected when it is next read.
- These rejections happen before the scanner writes any scope from the job.

## `scope`

No other key is allowed (`scope: unknown field '<name>'`). Every list is optional and defaults to empty. Host names
must already be in the scanner's exact form: lower case, at least two labels of `a-z`, `0-9`, `-`, and `_` (1 to 63
characters each, not starting or ending with `-`), at most 253 characters in all, no trailing dot, and a last label
that is not all digits and has no `_`. A name in any other form is refused, not corrected.

| Key | Type | Limit | Allowed values |
|---|---|---|---|
| `domains` | list of host names | 200 | the domains in scope. Duplicates are removed and the list is sorted. At least one is required for `scope-sync`, `inventory`, `full`, `recheck`, and `version-watch` unless the job has `lab`. `update-templates` and `retention` accept an empty list. |
| `exclude` | list of strings | 1000 | a host name, `.suffix`, `*.suffix`, an IPv4 or IPv6 address, or a CIDR. A name, `.name`, and `*.name` all exclude that name and every name under it. An address is stored as a single-address network. |
| `owned_ranges` | list of strings | 256 | addresses or CIDRs, stored in network form (an address becomes a /32 or /128) |
| `approved_hosts` | list of host names | 5000 | hosts approved for port scans; deduplicated and sorted |
| `strict_sla_hosts` | list of host names | 5000 | deduplicated and sorted. The brain always sends an empty list. |
| `ownership` | list of objects | 200 | see [`scope.ownership[]`](#scopeownership) |
| `approval` | object or `null` | | see [`scope.approval`](#scopeapproval) |
| `check_profile` | string | | `safe` (default) or `active` |
| `rate_profile` | string | | `low` (default), `normal`, or `fast` |
| `evidence` | string | | `minimal` (default) or `excerpt` |

### `scope.ownership[]`

Exactly these four keys, all required:

| Key | Allowed values |
|---|---|
| `apex` | a host name that is in `scope.domains`; at most one entry per apex |
| `statement` | exactly `I own this domain and the systems it points to.` |
| `attested_by` | 1 to 100 characters, no control character and none of `"` `'` `` ` `` `<` `>` `$` `\`; not only spaces. Leading and trailing spaces are removed. |
| `attested_at` | a time in the `created_at` form |

A job can never carry DNS proof tokens or verification state. An ownership entry with the key `token` is rejected with
`scope.ownership: field 'token' not allowed: the scanner derives every DNS proof token itself (see scope_status.json after a scope-sync job)`.
The keys `state`, `verified_at`, `last_checked_at`, `verified`, `last_result`, `key_id`, and `token_reset` are rejected
with `scope.ownership: field '<name>' not allowed: verification state is kept by the scanner and a job can never set it`.
The scanner derives each domain's token from its own install secret and publishes the TXT record to create in
`scope_status.json` (see the published layout reference).

A domain in `scope.domains` with no ownership entry is accepted; the scanner shows it as `no-statement` and sends it
nothing. The brain refuses to queue any job while one of its domains lacks the statement.

### `scope.approval`

`null`, or an object with exactly these three keys:

| Key | Allowed values |
|---|---|
| `approved_at` | a time in the `created_at` form |
| `inventory_run` | a job id: the id of a finished inventory run on this scanner |
| `approved_by` | the same rule as `attested_by` |

Every job type validates the approval's form. Only `full` and `recheck` jobs use it. For those, the scanner checks
the approval before it writes anything:

- The named run must exist on this scanner with a readable manifest, must have finished with exit code 0, and must
  have recorded an inventory. If retention has removed that run's folder, the scanner uses the copy of the inventory
  it kept from the last accepted approval when that copy names the same run. Otherwise the job is rejected with
  `scope.approval.inventory_run: no finished inventory run with that id on this scanner`.
- A job without `lab`: the inventory must cover at least one of `scope.domains`. Otherwise:
  `scope.approval.inventory_run: that inventory covers none of this scope's domains; approve an inventory of this scope`.
- A job with `lab`: the inventory must list every `lab.targets` entry. Otherwise:
  `scope.approval.inventory_run: that inventory does not cover every lab target of this job; approve an inventory of these lab targets`.

A scope domain that the approved inventory did not cover gets no active checks in that job; it is held back (see
`held_back.json` in the published layout reference). Without a valid approval, a `full` job runs the inventory
phases only (no port scan, TLS scan, or templates), and a `recheck` job fails. For `scope-sync`, `inventory`,
`version-watch`, `update-templates`, and `retention` the approval is ignored.

## `lab`

Lab mode is for testing against a private lab network. The scanner accepts `lab` only when it was started with
`SCAN_LAB=1` and `SCAN_LAB_CIDR` set to a private range no larger than a /24; without it the reason is
`lab: lab fields are refused: the scanner was not started in lab mode (SCAN_LAB=1)`.

| Key | Allowed values |
|---|---|
| `targets` | 1 to 64 host names (deduplicated and sorted) |
| `cidr` | exactly the scanner's `SCAN_LAB_CIDR`, compared in network form |

Both keys are required. `lab` is refused on any type other than `inventory`, `full`, and `version-watch`
(`lab: only inventory and full jobs, and version-watch jobs, can be lab runs`). A lab job may have an empty
`scope.domains`.

## `options`

The allowed keys depend on the type. An unknown key is refused (`options: unknown field '<name>'`), and a value that is
not an object is refused (`options: must be an object`).

| Type | Keys |
|---|---|
| `retention` | `retention_days`: optional, a whole number from 1 to 3650 (a boolean is refused), default 30 |
| `version-watch` | `watches`: required, a list of 1 to 20 watch objects (below) |
| every other type | none: `options` is absent or `{}` |

### `options.watches[]`

A missing or empty list is refused with `options.watches: a version-watch job needs at least one watch`. Each watch is
an object with these keys; any other key (for example a pattern, a header name, a path, or a URL) is refused with
`options.watches[<i>]: unknown field`. A job can never tell the scanner how to read a version: that is fixed in code
per product.

| Key | Required | Allowed values (every pattern is a full match) |
|---|---|---|
| `id` | yes | 2 to 32 characters, `[a-z0-9][a-z0-9-]{0,30}[a-z0-9]`; unique within the job; names the results folder |
| `name` | yes | 1 to 80 characters, `[A-Za-z0-9](?:[A-Za-z0-9 ._,-]{0,78}[A-Za-z0-9._])?` |
| `product` | yes | `php`, `nginx`, `apache-httpd`, or `openssl` |
| `cves` | yes | list of 1 to 20 distinct ids, each `CVE-[0-9]{4}-[0-9]{4,7}`; order kept |
| `floors` | yes | object of 1 to 16 entries. Key: a branch `x.y`, pattern `(?:0|[1-9][0-9]{0,3})\.(?:0|[1-9][0-9]{0,3})` (no leading zeros). Value: the lowest fixed patch number on that branch, a whole number from 0 to 99999 (a boolean is refused). For `openssl`, every branch must be 3.0 or newer. |
| `hosts` | no | list of at most 100 host names in the exact form above; duplicates removed, sorted. These hosts still pass the scope's name rules; a watch never widens the scope. |

Error reasons name the field, never the value (for example
`options.watches[0].floors: a branch is not of the form x.y (numbers, no leading zeros)`). The scanner hands the
normalized watches (floors in numeric branch order, hosts sorted) to version watch. The output it produces is
described in the version-watch schema reference.

## What each job type does

| Type | What the scanner does | Needs a domain (outside lab) | `lab` allowed | Uses `approval` |
|---|---|---|---|---|
| `scope-sync` | Writes the scope, checks the DNS proof of every domain that has an ownership entry (DNS lookups only), and publishes `scope_status.json`. Runs no scan tool. | yes | no | no |
| `inventory` | Discovery only: enumerate, resolve, probe, classify, fingerprint; then ingest, snapshot, and report. Records the inventory an approval can name. | yes | yes | no |
| `full` | The inventory phases for every DNS-verified domain; with a valid approval, also port scan, TLS scan, and templates on approved hosts; then ingest, snapshot, report, and `held_back.json`. | yes | yes | yes |
| `recheck` | Re-tests the hosts with open findings, without discovery. Needs a valid approval. Same hold-back rules as `full`. | yes | no | yes |
| `version-watch` | Checks this job's DNS proof first (skipped in lab mode; if the check cannot run, the job fails and nothing is probed), then reads product versions from response headers for each watch and publishes the results. Held-back hosts are still watched. | yes | yes | no |
| `update-templates` | Downloads a new template set and switches to it only when it holds more than 1,000 templates. Needs outbound network. | no | no | no |
| `retention` | Removes run folders older than `retention_days` (never the most recent full run, and never a run that a recheck uses as its base), prunes snapshots, and removes version-watch result folders whose newest result is 90 or more days old. | no | no | no |

Every job, whatever its type, replaces the scanner's scope with the job's `scope` once it starts (after the approval
check for `full` and `recheck`). A job that is rejected before it starts changes no scope.

## Status files the scanner writes back

For every job file it sees, the scanner writes `status/<key>.json` in the published folder, where `<key>` is the job
id or `invalid-<16 hex>`. The file is rewritten at every change. Schema name: `momus-status-v1`. A status never
holds job content or text taken from a scan target.

| Key | Type | When present | Values |
|---|---|---|---|
| `schema` | string | always | `"momus-status-v1"` |
| `job_id` | string | always | the key |
| `state` | string | always | `queued`, `running`, `done`, `failed`, `rejected`, `interrupted` |
| `queued_at` | string | always (see the exception below) | when the scanner first wrote this status |
| `updated_at` | string | always (see the exception below) | the last rewrite |
| `type` | string | once queued or started | the job type |
| `phase` | string or `null` | rejected, running, and finished jobs | the step in progress (below); `null` after `done`, after a rejection, and after a failure from an unexpected runner error; a job that failed in a step, or was interrupted, keeps the phase it stopped in |
| `reason` | string | `rejected`, `interrupted`, and some `failed` | a fixed text (below) |
| `run_id` | string or `null` | once started | the job id for `inventory`, `full`, and `recheck`; otherwise `null` |
| `lab` | boolean | once started | whether the job had `lab` |
| `started_at` | string | once started | |
| `ended_at` | string | final states | |
| `exit_codes` | object | once started | step name to exit code (below) |
| `counts` | object | once started | numbers only (below) |
| `snapshot` | string | scan jobs that reached the snapshot step | the file name in `snapshots/` |
| `snapshot_sha256` | string | as `snapshot` | 64 hex characters |
| `report_files` | integer | scan jobs that published a report | the number of report files |

All times are UTC, `YYYY-MM-DDTHH:MM:SSZ`.

**States.** `queued`: the file passed validation and waits. `running`: the job started. `done`: it finished.
`failed`: a step exited with an error, or the runner hit an unexpected error. `rejected`: the file or its content was
refused, or (for `full` and `recheck`) the approval was refused; the job did nothing. `interrupted`: the scanner
stopped while the job ran. The last four are final.

**Rejected statuses.** A job rejected while its file was read or validated has only `schema`, `job_id`, `queued_at`,
`state`, `reason`, `ended_at`, `phase` (`null`), and `updated_at`, plus `type` if it had been queued before. A `full`
or `recheck` job rejected for its approval was rejected after it started, so its status also has `type`, `run_id`,
`started_at`, `exit_codes` (`{}`), `counts` (`{}`), and `lab`.

**`phase` values.** `scope`, `dns-proof` (`scope-sync`, and the first step of a `version-watch` job outside lab mode),
`recheck-targets`, `recon`, `recon:<n>-<name>` (`n` from 1 to 8: `enumerate`, `resolve`, `probe`, `classify`,
`fingerprint`, `portscan`, `tls`, `nuclei`), `ingest`, `snapshot`, `report`, `publish-report`, `version-watch`,
`retention`, `update-templates`.

**`exit_codes` keys.** `scope_sync`, `recheck_targets`, `recon`, `ingest`, `report`, `dns_proof`, `version_watch`,
`retention`, `update_templates`; and `runner`, holding an exception type name, when the runner itself failed the job.
For `version_watch`: 0 results written; 2 nothing to probe; 3 at least one watch was suspect; 4 the watches or the
scope could not be loaded. A step that exits with anything but 0 ends the job as `failed`, so a version-watch job with
exit code 2 or 3 is `failed` even though result files may have been published.

**`counts` keys** (integers):

| Job type | Keys |
|---|---|
| `inventory`, `full`, `recheck` | `assets` (hosts observed in this run), `findings_observed` (finding observations in this run), `findings_open` and `findings_fixed` (all findings in the scan database with that status after this run), and `band_critical`, `band_high`, `band_medium`, `band_low` for each band observed in this run |
| `full`, `recheck` also | `held_back` (hosts), `domains_scanned` (verified in this run and covered by the approved inventory), `domains_held_back` (verified, not covered: inventory checks only), `domains_pending` (in scope, not verified in this run: nothing was sent) |
| `scope-sync` | `domains`, `verified` |
| `version-watch` | `watches` (in the job), `files_published` (files in `published/version-watch/` after the job) |
| `update-templates` | `templates` |

A `full` or `recheck` run that reached no active phase (no valid approval, or stopped before the port scan) reports
`domains_scanned: 0`, `domains_held_back: 0`, and as pending the scope domains that did not pass this run's DNS
proof. A lab run checks no DNS proof, so all of its scope domains, if any, count as pending.

**Fixed `reason` texts** other than the validation reasons on this page:

| State | Reason |
|---|---|
| `interrupted` | `the scanner stopped during this job` (found `running` when the scanner started) |
| `interrupted` | `the scanner was stopped during this job` (stopped by a signal while it ran) |
| `failed` | `the runner hit an unexpected error during this job` |
| `failed` | `the scanner's record of this job is unreadable` (see below) |
| `rejected` | `file: could not be read or validated` (an unexpected error while reading) |
| `rejected` | `job: could not be validated` (an unexpected error inside the validator) |

Status files are never removed by the scanner.

## Finished jobs and reused ids

Every final status the scanner writes is also kept in its own data volume, at `state/finished/<key>.json` under
`$SCAN_ROOT` (`/var/lib/scan`). This record is never published. Before a job file is queued, and again just before the
job starts, the scanner checks the record:

- If the id has a record, the job never runs. If the published status is missing or not final, the scanner publishes
  the recorded final status again.
- A record that cannot be parsed, or holds no final state, counts as finished: the job does not run, and the
  republished status is `failed` with the reason `the scanner's record of this job is unreadable`. That status has
  only the keys `schema`, `job_id`, `state`, and `reason`.
- The record is opened without following a symbolic link; a link counts as no record.

So losing or restoring the published folder never makes a finished job run again. The scanner also skips any job
whose published status is already final. Records are never removed by the scanner.

## The abandon marker

If a job never reaches a final status (for example because its status file was lost), an admin can mark it abandoned
in the brain, after confirming that the scanner is not running it. The brain then writes `<job id>.abandoned` into the
jobs folder (through a dot-prefixed temporary name and a rename), records the decision, and deletes the job file.

- The marker's content is `{"job_id": "<id>", "abandoned_at": "<time>", "abandoned_by": "<account>"}`. The scanner
  does not read the content: any file, folder, or link with that name counts.
- While the marker exists, the scanner never runs that id and writes no status for it. It checks when it lists the
  jobs folder and again just before the job would start.
- The brain does not count an abandoned job as in flight, so new jobs can be queued.
- The brain refuses to abandon a job that has a final status, or that a fresh scanner heartbeat names as the job it is
  running.
- Markers are never removed.

## How the brain writes jobs

- One job at a time: the brain queues nothing while a job file without a final status exists, or while a fresh
  heartbeat (at most 180 seconds old) says the scanner is busy. More than 1,000 job files in the folder also counts as
  busy.
- Every job carries the full current scope from the brain's database. No job carries a DNS token.
- The brain writes the file with sorted keys and one-space indentation, and keeps a copy of the exact document with
  the job's row in its database.
- The brain refuses to queue a job larger than 1 MiB, the scanner's limit.
- A `version-watch` job carries every watch stored in the brain, sorted by id. The brain checks each watch with the
  same rules as the scanner before storing it.
- `scanner/jobctl.py` is a developer stand-in for the brain that writes job files the same way.

## Examples

The ids, names, times, and CVE ids below are illustrative. Dates are written `YYYY-MM-DD` with only the day filled in. A real job must carry a `created_at` within the age limit
of the moment the scanner reads it, so these exact files would be rejected. With real dates in place of the placeholders, each example passes
`validate_job`; the lab example needs a scanner started with `SCAN_LAB=1` and `SCAN_LAB_CIDR=10.0.0.0/24`.

A scope-sync job with every scope key written out:

```json
{"schema": "momus-job-v1", "id": "sync-20300101-090000-a1b2c3", "type": "scope-sync", "created_at": "YYYY-MM-01T09:00:00Z",
 "scope": {"domains": ["example.test"], "exclude": [], "owned_ranges": [], "approved_hosts": [], "strict_sla_hosts": [],
           "ownership": [{"apex": "example.test", "statement": "I own this domain and the systems it points to.",
                          "attested_by": "Example Owner", "attested_at": "YYYY-MM-01T08:55:00Z"}],
           "approval": null, "check_profile": "safe", "rate_profile": "low", "evidence": "minimal"}}
```

An inventory job (omitted scope keys take their defaults):

```json
{"schema": "momus-job-v1", "id": "inv-20300101-100000-d4e5f6", "type": "inventory", "created_at": "YYYY-MM-01T10:00:00Z",
 "scope": {"domains": ["example.test"], "exclude": ["legacy.example.test", "192.0.2.128/25"],
           "ownership": [{"apex": "example.test", "statement": "I own this domain and the systems it points to.",
                          "attested_by": "Example Owner", "attested_at": "YYYY-MM-01T08:55:00Z"}]}}
```

A full job whose approval names the inventory above:

```json
{"schema": "momus-job-v1", "id": "full-20300102-100000-0a1b2c", "type": "full", "created_at": "YYYY-MM-02T10:00:00Z",
 "scope": {"domains": ["example.test"], "exclude": ["legacy.example.test"], "owned_ranges": ["192.0.2.0/25"],
           "approved_hosts": ["www.example.test"], "strict_sla_hosts": [],
           "ownership": [{"apex": "example.test", "statement": "I own this domain and the systems it points to.",
                          "attested_by": "Example Owner", "attested_at": "YYYY-MM-01T08:55:00Z"}],
           "approval": {"approved_at": "YYYY-MM-01T12:00:00Z", "inventory_run": "inv-20300101-100000-d4e5f6",
                        "approved_by": "Example Owner"},
           "check_profile": "safe", "rate_profile": "normal", "evidence": "minimal"}}
```

A recheck job:

```json
{"schema": "momus-job-v1", "id": "recheck-20300103-100000-3d4e5f", "type": "recheck", "created_at": "YYYY-MM-03T10:00:00Z",
 "scope": {"domains": ["example.test"],
           "ownership": [{"apex": "example.test", "statement": "I own this domain and the systems it points to.",
                          "attested_by": "Example Owner", "attested_at": "YYYY-MM-01T08:55:00Z"}],
           "approval": {"approved_at": "YYYY-MM-01T12:00:00Z", "inventory_run": "inv-20300101-100000-d4e5f6",
                        "approved_by": "Example Owner"}}}
```

A version-watch job with two watches:

```json
{"schema": "momus-job-v1", "id": "vw-20300103-040000-6a7b8c", "type": "version-watch", "created_at": "YYYY-MM-03T04:00:00Z",
 "scope": {"domains": ["example.test"],
           "ownership": [{"apex": "example.test", "statement": "I own this domain and the systems it points to.",
                          "attested_by": "Example Owner", "attested_at": "YYYY-MM-01T08:55:00Z"}]},
 "options": {"watches": [{"id": "php-example", "name": "PHP example", "product": "php",
                          "cves": ["CVE-2099-0001", "CVE-2099-0002"],
                          "floors": {"8.2": 30, "8.3": 20}, "hosts": ["www.example.test"]},
                         {"id": "nginx-example", "name": "nginx example", "product": "nginx",
                          "cves": ["CVE-2099-0003"], "floors": {"1.26": 3}}]}}
```

An update-templates job and a retention job:

```json
{"schema": "momus-job-v1", "id": "tpl-20300104-100000-9d0e1f", "type": "update-templates", "created_at": "YYYY-MM-04T10:00:00Z",
 "scope": {"domains": ["example.test"],
           "ownership": [{"apex": "example.test", "statement": "I own this domain and the systems it points to.",
                          "attested_by": "Example Owner", "attested_at": "YYYY-MM-01T08:55:00Z"}]}}
```

```json
{"schema": "momus-job-v1", "id": "ret-20300105-100000-2a3b4c", "type": "retention", "created_at": "YYYY-MM-05T10:00:00Z",
 "scope": {"domains": ["example.test"],
           "ownership": [{"apex": "example.test", "statement": "I own this domain and the systems it points to.",
                          "attested_by": "Example Owner", "attested_at": "YYYY-MM-01T08:55:00Z"}]},
 "options": {"retention_days": 30}}
```

A lab inventory job (lab mode only; `domains` may be empty):

```json
{"schema": "momus-job-v1", "id": "inv-lab-1", "type": "inventory", "created_at": "YYYY-MM-01T10:00:00Z",
 "scope": {"domains": []},
 "lab": {"targets": ["app.lab.example.test", "web.lab.example.test"], "cidr": "10.0.0.0/24"}}
```

The status of a finished scope-sync job:

```json
{"counts": {"domains": 1, "verified": 1}, "ended_at": "YYYY-MM-01T09:00:14Z", "exit_codes": {"scope_sync": 0},
 "job_id": "sync-20300101-090000-a1b2c3", "lab": false, "phase": null, "queued_at": "YYYY-MM-01T09:00:02Z",
 "run_id": null, "schema": "momus-status-v1", "started_at": "YYYY-MM-01T09:00:02Z", "state": "done",
 "type": "scope-sync", "updated_at": "YYYY-MM-01T09:00:14Z"}
```

The status of a job rejected for its age:

```json
{"ended_at": "YYYY-MM-05T10:00:03Z", "job_id": "ret-20300101-100000-5e6f7a", "phase": null,
 "queued_at": "YYYY-MM-05T10:00:03Z",
 "reason": "job: created longer ago than the scanner's job age limit (SCAN_JOB_MAX_AGE_HOURS); it was not run. Queue it again if it is still wanted.",
 "schema": "momus-status-v1", "state": "rejected", "updated_at": "YYYY-MM-05T10:00:03Z"}
```
