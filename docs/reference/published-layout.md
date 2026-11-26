# Published folder layout

The published folder is the only way results leave the scanner. The scanner writes it, and the brain reads it
read-only; the two containers share no network. This page lists every file and folder in it, who writes each one and
when, its format, the limits the brain applies when reading it, and how long it is kept. It also covers the small
`seed_scope` volume the optional seeder reads, and the scanner's own state that is deliberately never published.
Job files and status files are described in the job format reference.

In the examples on this page, dates are written `YYYY-MM-DD` with only the day filled in.

## Rules for the whole folder

- **Location.** `/srv/published` in both containers (the `published` volume). The scanner mounts it read-write and
  runs as uid 10001; the brain mounts it read-only.
- **Atomic writes.** Every file is written to a temporary name that starts with `.` in the same folder and then
  renamed into place. A report folder is assembled under a dot-prefixed name and renamed as a whole. Readers must
  ignore every name that starts with `.`. When the scanner starts, it deletes leftover temporary files (names that
  start with `.` and contain `.tmp-`) in `status/`, `snapshots/`, `version-watch/`, and each watch folder.
- **Times.** UTC, `YYYY-MM-DDTHH:MM:SSZ`.
- **JSON files** written by the job runner (`scanner.json`, `scope_status.json`, `held_back.json`, `status/*.json`,
  `snapshots/latest.json`) use sorted keys and one-space indentation.
- **Nothing else.** The scanner writes only the paths below. If the folder cannot be written, the job runner stops
  with one log line and exit code 75.
- **How the brain reads it.** Every file is opened without following a symbolic link: each folder below the
  published folder is opened by descriptor, one step at a time, and the file inside it. A file must be a
  regular file, and is size-checked on the open handle before anything is read. A file that is missing, too large,
  half-written, or not valid JSON is treated as absent. Text values are capped and stripped of control characters,
  and each field is checked for type and pattern; a value that fails is dropped or shown as `unknown`. Unpaired
  surrogates in JSON strings become U+FFFD. A folder listing looks at no more than 50,000 entries.

## Contents

| Path | Written when | Format | Brain read limits | Kept |
|---|---|---|---|---|
| `scanner.json` | When idle, about every 30 seconds. When a job starts and ends. While a job runs, at every phase change and at least every 30 seconds. | `momus-scanner-v1`, [below](#scannerjson) | 256 KiB | overwritten |
| `scope_status.json` | When the job runner starts; after a job's scope is written; and when a job ends (a `full` or `recheck` job rejected for its approval writes no scope and does not rewrite it) | `momus-scope-status-v1`, [below](#scope_statusjson) | 1 MiB; first 1,000 domains | overwritten |
| `held_back.json` | After the recon step of every `full` and `recheck` job, whether or not recon succeeded. Absent until the first one. | `momus-held-back-v1`, [below](#held_backjson) | 4 MiB; first 5,000 hosts and 1,000 domains | overwritten |
| `status/<key>.json` | For every job file the scanner sees, at every change of its status. `<key>` is the job id, or `invalid-<16 hex>` for a file whose name is not a valid job id. | `momus-status-v1`, see the job format reference | 64 KiB per file; the newest 300 files (by modification time) for lists; a single job's status is read by its id | never removed |
| `snapshots/<run id>.sqlite` | After the ingest step of every `inventory`, `full`, and `recheck` job | SQLite database: a copy of the scan database made with SQLite's backup API, checked with `PRAGMA integrity_check` before it is renamed into place (a failed check fails the job and publishes nothing); mode 644 | only the file `latest.json` names; at most `MOMUS_SNAPSHOT_MAX_MB` (default 512, allowed 16 to 4096) | the newest `SCAN_KEEP_SNAPSHOTS` files by modification time (default 10, at least 1), always including the one `latest.json` names; pruned after each snapshot and by each `retention` job |
| `snapshots/latest.json` | After each snapshot | `momus-snapshot-v1`, [below](#snapshotslatestjson) | 64 KiB | overwritten |
| `reports/<run id>/<run id>.html` | After the report step of every `inventory`, `full`, and `recheck` job | self-contained HTML report | at most 20 files listed per run; downloads at most 512 MiB, served as attachments | never removed |
| `reports/<run id>/<run id>-<name>.csv` | as above, for each spreadsheet the run produced | CSV. `<name>` is one of `inventory`, `components`, `certificates`, `ports`, `domains`, `endpoints`, `fixlist`. | as above | never removed |
| `version-watch/<watch id>/<YYYY-MM-DD>.json` | After every `version-watch` job, unless its DNS proof step failed (then nothing is probed or published), and after every `retention` job | `version-watch-v1`, see the version-watch schema reference | 4 MiB per file; 50 watch folders; 50 dated files per folder | mirrors the scanner's state folder (below) |
| `version-watch/<watch id>/latest.json` | as above | as above | as above | as above |

`<run id>` is the job id of the scan job. A report folder is replaced as a whole when the same run publishes again.

**Version-watch results.** The `version-watch/` folder is a copy of the scanner's state folder `$SCAN_ROOT/version-watch/`:
only folders whose names are watch ids, and in them only `YYYY-MM-DD.json` and `latest.json` regular files (no links).
A file is rewritten only when its content changed. Anything in the published copy that the state folder does not
hold is removed, so the published copy never holds more than the state folder. The state folder keeps the newest 90
dated files per watch. A watch that is not in the latest version-watch job keeps its folder until its newest dated file is
90 or more days old (or until it has no dated file), and a `retention` job removes every watch folder whose newest
dated file is 90 or more days old. Both remove only file names version watch writes; a folder that also holds
anything else loses those files but stays.

**Not removed.** The scanner never removes status files or report folders from the published folder. They grow by one
per job and one per scan run.

## `scanner.json`

The scanner's heartbeat. The brain treats a heartbeat as stale when its `updated_at` is more than 180 seconds old or
in the future. While a job is running, the tool versions, templates, and build date are the values read when the job
started.

| Key | Type | Values |
|---|---|---|
| `schema` | string | `"momus-scanner-v1"` |
| `updated_at` | string | time of this write |
| `state` | string | `idle` or `busy` |
| `current_job` | string or `null` | the id of the running job |
| `lab_mode` | boolean | the scanner was started with `SCAN_LAB=1` |
| `lab_cidr` | string or `null` | `SCAN_LAB_CIDR` in lab mode |
| `profiles` | object or `null` | `check_profile`, `rate_profile`, `evidence` of the last job started since the scanner started; `null` before the first |
| `image_build_date` | string or `null` | the image's build date, at most 40 characters |
| `tools` | object | Debian package name to installed version, for the scan tools the image ships |
| `templates` | object | `dir`, `count`, `version`, `date`, and `source` (`baked into the image` or `update-templates job`); `source` is absent when no template folder exists |
| `keep_snapshots` | integer | `SCAN_KEEP_SNAPSHOTS` |

The brain decides lab mode from its own `MOMUS_LAB` setting, never from this file; it only shows a warning when the two
disagree.

## `scope_status.json`

The DNS proof state of every domain in the scanner's current scope, and the exact TXT record each domain must
publish. The scanner derives each domain's token from its install secret; the brain only shows this file and never
decides that a domain is verified.

| Key | Type | Values |
|---|---|---|
| `schema` | string | `"momus-scope-status-v1"` |
| `updated_at` | string | time of this write |
| `install_key_id` | string | 16 hex characters: a public fingerprint of the install secret. It reveals nothing about the secret or any token. |
| `notice` | string or `null` | `null`, or this fixed text while any domain has `token_reset`: `The install secret was replaced (the earlier one was lost), so every domain's DNS proof token changed: each affected domain is pending until its new TXT record is published and checked.` |
| `domains` | object | one entry per domain of the current scope, keyed by domain name, including domains without an ownership entry |

Each `domains` entry:

| Key | Type | Values |
|---|---|---|
| `state` | string | `no-statement` (no ownership entry: nothing is sent to it), `pending` (not verified yet), `verified`, `refused` (a nameserver's address failed the scanner's address check), `lapsed` (was verified, then lookups failed with the last verification more than 7 days ago) |
| `txt_name` | string | `_scan-verify.<domain>` |
| `txt_value` | string | `scan-verify=` followed by 32 hex characters |
| `attested_by` | string or `null` | from the ownership entry |
| `attested_at` | string or `null` | from the ownership entry |
| `verified_at` | string or `null` | the last successful check |
| `last_checked_at` | string or `null` | the last check |
| `last_result` | string or `null` | `match` (every answering nameserver returned the record), `mismatch` (the record is missing or wrong), `disagree` (nameservers disagree), `unsafe` (a nameserver's address was refused), `failure` (no nameserver found or none answered), or `null` (never checked) |
| `token_reset` | string or `null` | `"install-secret-replaced"` from the time the install secret changed until the domain verifies again |

Publish the record exactly: `<txt_name>. IN TXT "<txt_value>"`. A lookup failure does not change a `verified` domain
whose last verification is at most 7 days old.

```json
{"domains": {"example.test": {"attested_at": "YYYY-MM-01T08:55:00Z", "attested_by": "Example Owner",
   "last_checked_at": "YYYY-MM-01T09:00:11Z", "last_result": "mismatch", "state": "pending", "token_reset": null,
   "txt_name": "_scan-verify.example.test", "txt_value": "scan-verify=0f1e2d3c4b5a69788796a5b4c3d2e1f0",
   "verified_at": null}},
 "install_key_id": "3f9c0a1b2c3d4e5f", "notice": null, "schema": "momus-scope-status-v1",
 "updated_at": "YYYY-MM-01T09:00:12Z"}
```

## `held_back.json`

The hosts and domains the latest `full` or `recheck` run kept from active checks (port scan, TLS scan, templates),
so an admin can review them and approve a newer inventory.

| Key | Type | Values |
|---|---|---|
| `schema` | string | `"momus-held-back-v1"` |
| `updated_at` | string | time of this write |
| `run_id` | string | the run this file describes |
| `inventory_run` | string or `null` | the approved inventory the run compared against; `null` when the run had no valid approval or stopped before the active phases |
| `hosts` | list | one object per held-back live host, sorted by host name; `[]` when `inventory_run` is `null` |
| `domains` | list | one object per scope domain held back as a whole; `[]` when `inventory_run` is `null` |

Each `hosts` entry: `host` (a host name), `reason` (one of the codes below), `approved_ips` (the addresses the approved
inventory listed for the host; empty when it did not list the host), `current_ips` (the addresses this run saw). Each
address list holds validated IP addresses, sorted, taken from at most the first 64 entries.

| `reason` | Meaning |
|---|---|
| `new-since-approved-inventory` | the approved inventory did not list the host |
| `address-changed` | the host has an address the inventory did not list for it, and that address is in neither the owned ranges nor the provider ranges. Not applied to a host the inventory classed `cdn_fronted` or `third_party` by its CNAME target while it stays in one of those classes with a CNAME under the same provider suffix. |
| `domain-not-in-approved-inventory` | the host's domain is in the scope and DNS-verified, but the approved inventory did not cover it |

Each `domains` entry: `domain` and `reason` (always `domain-not-in-approved-inventory`). Every name under such a domain
is refused by every active phase, whether or not it is listed in `hosts`; only live hosts are listed. The brain shows a
reason it does not know as "unknown reason".

```json
{"domains": [{"domain": "new.example.test", "reason": "domain-not-in-approved-inventory"}],
 "hosts": [{"approved_ips": [], "current_ips": ["192.0.2.20"], "host": "app.example.test", "reason": "new-since-approved-inventory"},
           {"approved_ips": ["192.0.2.7"], "current_ips": ["192.0.2.9"], "host": "shop.example.test", "reason": "address-changed"},
           {"approved_ips": [], "current_ips": ["192.0.2.44"], "host": "www.new.example.test", "reason": "domain-not-in-approved-inventory"}],
 "inventory_run": "inv-20300101-100000-d4e5f6", "run_id": "full-20300102-100000-0a1b2c",
 "schema": "momus-held-back-v1", "updated_at": "YYYY-MM-02T10:41:07Z"}
```

## `snapshots/latest.json`

Points to the newest snapshot.

| Key | Type | Values |
|---|---|---|
| `schema` | string | `"momus-snapshot-v1"` |
| `run_id` | string | the run the snapshot was taken after |
| `job_id` | string | the job that ran it (the same id) |
| `file` | string | `<run id>.sqlite` in `snapshots/` |
| `sha256` | string | 64 lower-case hex characters: the SHA-256 of that file |
| `created_at` | string | time of this write |

The brain opens a snapshot only when `file` matches `<job id>.sqlite` and `sha256` is 64 hex characters. It copies the
file into its own cache while hashing it, and uses the copy only when the hash matches `sha256`, the database holds
only plain tables and indexes (no view, trigger, or virtual table) with the columns the brain reads, and SQLite's
quick check passes. The copy is opened read-only. Nothing is ever written to the published folder.

```json
{"created_at": "YYYY-MM-02T11:02:40Z", "file": "full-20300102-100000-0a1b2c.sqlite",
 "job_id": "full-20300102-100000-0a1b2c", "run_id": "full-20300102-100000-0a1b2c", "schema": "momus-snapshot-v1",
 "sha256": "9b74c9897bac770ffc029102a200c5de9b74c9897bac770ffc029102a200c5de"}
```

## The `seed_scope` volume and `verified_domains.json`

The optional seeder adds host names from DNS sources, and only for domains the scanner has verified. It never mounts
the published folder. Instead, the scanner gives it one small file in a volume of its own.

- **Path.** `/srv/seed-scope/verified_domains.json` (the `seed_scope` volume). The scanner mounts it read-write, the
  seeder read-only, and the brain not at all. The scanner always uses `/srv/seed-scope`.
- **Written.** Every time the scanner writes `scope_status.json`, and only when the folder exists. Atomic write, mode
  644. If the write fails, the scanner logs one line and the job goes on.
- **Content.** Exactly three keys: `schema` (`"momus-verified-domains-v1"`), `updated_at`, and `domains` (the sorted
  names of the domains whose state is `verified`). No token, no other domain's state, no scan data.
- **How the seeder reads it.** Without following a link, as a regular file of at most 1 MiB, with the schema checked
  and every name checked as a host name.

```json
{"domains": ["example.test"], "schema": "momus-verified-domains-v1", "updated_at": "YYYY-MM-01T09:00:12Z"}
```

## What is never published

These stay in the scanner's data volume (`scan_data`, mounted at `/var/lib/scan`, the scanner's `$SCAN_ROOT`). The
brain has no access to them.

| Path under `$SCAN_ROOT` | What it is |
|---|---|
| `state/install_secret` | The install secret: 32 random bytes as hex, created on first start, mode 600 in a folder of mode 700. Every DNS proof token is derived from it. If it is lost, a new one is created and every domain must publish a new TXT record. |
| `state/finished/<key>.json` | The record of every final job status; a job id recorded here never runs again (see the job format reference) |
| `state/approved_inventory.json` | A copy of the inventory named by the last accepted approval, mode 600, so the approval survives retention of that run's folder |
| `scope` | The current scope (a link to a generation under `scope.d/`): the domain, exclusion, range, and host lists, the profiles, the ownership entries with their verification state, and the bound approval |
| `runs/<run id>/` | Raw tool output and logs of each run, including response bodies and tool error logs. Removed by `retention` jobs, except the most recent full run and any run that a recheck uses as its base. |
| `data/scan.sqlite` | The live scan database. Only snapshot copies are published. |
| `reports/` | The report files before they are copied to the published folder |
| `version-watch/` | The version-watch state folder that `published/version-watch/` mirrors |
| `templates/` | Template sets downloaded by `update-templates` jobs |
