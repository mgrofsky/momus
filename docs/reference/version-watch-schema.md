# Version-watch output schema (`version-watch-v1`)

A version-watch job checks which hosts run a product version below the lowest fixed release of its branch. For each
watch, the scanner writes one result file per UTC day plus `latest.json`, and copies them to the published folder,
where the brain reads them for the Version watch pages and the API. This page is the exact format of those files, for
anyone who reads them directly or writes a client. The watch definitions a job carries are described in the job
format reference; `scope_status.json` and `verified_domains.json` are described in the published layout reference.

In the examples on this page, dates are written `YYYY-MM-DD` with only the day filled in.

## Files

| File | Written | Notes |
|---|---|---|
| `$SCAN_ROOT/version-watch/<watch id>/<YYYY-MM-DD>.json` | by `scanner/pipeline/version_watch.py`, once per run for each watch that has at least one target | `<YYYY-MM-DD>` is the UTC date of the run. A second run on the same day replaces that day's file. |
| `$SCAN_ROOT/version-watch/<watch id>/latest.json` | at the same time, with the same content, unless the run was suspect | a suspect run leaves `latest.json` as it was |
| `published/version-watch/<watch id>/...` | by the job runner after the job, and after every `retention` job | a byte-for-byte copy of the state folder; see the published layout reference |

- Every file is written to a dot-prefixed temporary name in the same folder and renamed into place, with mode 644.
- The JSON is UTF-8 with one-space indentation and keys in the order listed below (not sorted), followed by a newline.
- The newest 90 dated files are kept per watch. A watch that is not in the latest job keeps its folder until its
  newest dated file is 90 or more days old; a `retention` job removes any watch folder whose newest dated file is 90
  or more days old.
- A watch with no target that passes the scope writes no file in that run.

## Suspect runs

A run is suspect for a watch when more than half of that watch's hosts are `UNREACHABLE` (exactly half is not
suspect). A suspect file starts with `"suspect": true`, is written as that day's dated file, and never becomes
`latest.json`. Later runs ignore suspect files when they compute `changes`, `history`, and carried hosts.

## Which text came from a target

Exactly one field holds text taken from a scan target: `hosts[].server`. The file says so itself in
`target_derived: ["hosts[].server"]`. Every other value is fixed text from the scanner, a number, a version in the
strict numeric form, an HTTP status parsed as three digits from 100 to 599, a host name that passed the scanner's name
rule, or part of the watch definition from the job (operator input, validated). Treat `hosts[].server` as untrusted
text: show it only as escaped text.

## Top level

Keys appear in this order.

| Key | Type | Values | From a target |
|---|---|---|---|
| `suspect` | boolean | present only when `true` (see above) | no |
| `schema` | string | `"version-watch-v1"` | no |
| `watch` | object | `id` (watch id pattern), `name` (watch name pattern), `product` (`php`, `nginx`, `apache-httpd`, `openssl`), `product_name` (`PHP`, `nginx`, `Apache HTTP Server`, `OpenSSL`) | no (job) |
| `job_id` | string or `null` | the version-watch job's id | no |
| `generated_at` | string | `YYYY-MM-DDTHH:MM:SSZ` | no |
| `date` | string | `YYYY-MM-DD` (UTC); equal to the file name of a dated file | no |
| `cves` | list of strings | the watch's 1 to 20 CVE ids, `CVE-[0-9]{4}-[0-9]{4,7}`, in the job's order | no (job) |
| `floors` | object | 1 to 16 entries: branch `x.y` to the lowest fixed release as text `x.y.z`, in numeric branch order | no (job) |
| `method` | string | fixed text per product: `GET / over https and http (same-host redirects followed, at most 3), response headers only (<headers>); no crafted request`, where `<headers>` is `X-Powered-By, Server` for `php` and `Server` for the others | no |
| `target_derived` | list of strings | exactly `["hosts[].server"]` | no |
| `targets` | object | see [`targets`](#targets) | no |
| `headline` | object | `hosts`, `fail`, `pass`, `unknown`, `unreachable`: integers; `hosts` is the sum of the other four | no |
| `by_version` | list | one object per distinct version found: `version`, `branch` (`x.y`), `verdict` (`PASS` or `FAIL`), `reason` (as in host rows), `hosts` (integer, at least 1). Sorted by host count, highest first, then by version, lowest first. | no |
| `by_domain` | list | one object per domain: `domain`, then `hosts`, `fail`, `pass`, `unknown`, `unreachable` (integers). Sorted by host count, highest first, then by domain name. | no |
| `hosts` | list | one row per host, see [Host rows](#host-rows). Sorted by verdict (`FAIL`, `UNKNOWN`, `UNREACHABLE`, `PASS`), then by host name. | `server` only |
| `changes` | object | `since`: the date of the newest earlier non-suspect dated file, or `null`. `items`: one object per host that was added, is gone, or whose version or verdict changed, sorted by host name: `hostname`, `from_version`, `to_version` (strict versions or `null`), `from_verdict`, `to_verdict` (one of the four verdicts or `null`). | no |
| `history` | list | `{date, hosts, fail, pass, unknown, unreachable}` for each earlier non-suspect dated file, oldest first, then this run; at most 90 entries (the newest) | no |

### `targets`

| Key | Type | Meaning |
|---|---|---|
| `total` | integer | the watch's target hosts, minus those refused by the scope's name gate or CNAME exclusion check (those are left out of the file entirely). It includes hosts reported `UNREACHABLE` without a request. |
| `from_scan_db` | integer | of those, hosts the scan database lists with a present component of this product |
| `from_job` | integer | of those, hosts listed in the watch's `hosts` |
| `carried` | integer | of those, hosts carried from the newest earlier non-suspect file that neither the scan database nor the job names any more |
| `not_probed` | integer | of those, hosts reported `UNREACHABLE` without a request (domain not verified in this job, or CNAME chain could not be looked up) |
| `scan_db_run` | string or `null` | the newest run id in the scan database (pattern `[A-Za-z0-9][A-Za-z0-9._-]{0,127}`), or `null` when there is no readable scan database |

A host can count in both `from_scan_db` and `from_job`. A carried host that was probed and did not answer is taken
as decommissioned: it counts in `total` and `carried` but is left out of `hosts` and `headline`, and shows in
`changes` as gone. A carried host that was not probed stays in `hosts` as `UNREACHABLE`.

## Host rows

Each entry of `hosts` has exactly these keys, in this order:

| Key | Type | Values | From a target |
|---|---|---|---|
| `hostname` | string | a host name in the scanner's form (lower case, labels `a-z 0-9 - _`, at most 253 characters) | no (scan database, job, or earlier file, each checked again) |
| `domain` | string | the longest scope domain the host is under; otherwise its last two labels | no |
| `version` | string or `null` | the version read from the headers, full match of `[0-9]{1,4}\.[0-9]{1,4}(?:\.[0-9]{1,6})?` | parsed into the strict form only |
| `verdict` | string | `FAIL`, `UNKNOWN`, `UNREACHABLE`, or `PASS` | no |
| `reason` | string | fixed text; see [Verdicts and reasons](#verdicts-and-reasons) | no |
| `read_from` | string or `null` | where the version was read: `<https or http> <x-powered-by or server>`, followed by ` (after redirect)` when it came from a same-host redirect target | no |
| `https_status` | integer or `null` | the status of the first https answer, 100 to 599 | parsed |
| `http_status` | integer or `null` | the status of the first http answer, 100 to 599 | parsed |
| `server` | string or `null` | the `Server` header of the first answer (https first, then http), cut to 1,024 characters, control characters and line separators replaced by spaces, then passed through the scanner's redaction and capped at 100 characters | **yes** |
| `scan_db_version` | string or `null` | the scan database's version for this host and product, kept only when it is in the strict version form | parsed into the strict form only |
| `source` | string | `scan_db`, `job`, `both`, or `carried` | no |

## Verdicts and reasons

The probe is one `GET /` per host per run, over https and then http, headers only, following at most three redirects
from each scheme's request (https and http each), and only to the same host name. One request set per host serves every watch that lists the host. The version is read
with a fixed pattern per product from the first 1,024 characters of these headers, in this order:

| `product` | Headers read | Version form read |
|---|---|---|
| `php` | `X-Powered-By`, then `Server` | `PHP/x.y` or `PHP/x.y.z` |
| `nginx` | `Server` | `nginx/x.y.z` |
| `apache-httpd` | `Server` | `Apache/x.y.z` |
| `openssl` | `Server` | `OpenSSL/x.y.z` (the numeric part only) |

A missing patch level counts as 0. The verdicts and their exact `reason` texts (`<v>` is the version, `<x.y>` its
branch):

| Verdict | When | `reason` |
|---|---|---|
| `PASS` | the version's branch has a floor and the version is at or above it | `<v> is at or above <x.y>.<floor>` |
| `PASS` | the version's branch is newer than every branch with a floor | `<v> is newer than the <newest floor branch> branch; released after the fix` |
| `FAIL` | the version's branch has a floor and the version is below it | `<v> is below <x.y>.<floor>` |
| `FAIL` | any other branch | `<v> is on branch <x.y>: no fixed release on this branch` |
| `UNKNOWN` | an answer on https or http, but no version of this product in the headers | `HTTP <https status or -> (https) / <http status or -> (http), no <product name> version in the headers (hidden or not <product name>)` |
| `UNREACHABLE` | no HTTP status on either scheme, or not probed | `no HTTP response on https or http (<cause>)` |

`<cause>` is one of: `the address check refused it`, `timed out`, `no answer`,
`not probed: its CNAME chain could not be looked up`, `not probed: its domain did not pass the DNS proof in this job`.

## Exit codes of the module

These appear as `exit_codes.version_watch` in the job's status file.

| Code | Meaning | Job state |
|---|---|---|
| 0 | results written | `done` |
| 2 | nothing to probe: no watch had a target, or no watch had a target that passed the scope; nothing written | `failed` |
| 3 | at least one watch was suspect (its dated file was written, its `latest.json` left as it was); other watches were written normally | `failed` |
| 4 | the watches file or the scope could not be loaded; nothing written | `failed` |

## How the brain reads these files

The brain reads `published/version-watch/` only, and treats every file as untrusted.

- Folders: at most 50 watch folders (newest by modification time), names that fully match the watch id pattern,
  real directories only (a link is not followed). Dated files: at most 50 per folder (newest by the date in the name).
  Only `latest.json` and the newest dated file are parsed.
- Each file: opened without following a link, at most 4 MiB, checked on the open handle before parsing.
- The whole document is refused when `schema` is not `version-watch-v1` or `watch.id` differs from the folder name.
- Field caps: the first 5,000 `hosts` rows and 5,000 `changes.items`, the last 100 `history` rows, 200 `by_version`
  rows, 1,000 `by_domain` rows, 20 `cves`, 16 `floors`. `reason` is capped at 300 characters and `server` at 100.
- Each field is checked for type and pattern. A host, `by_domain`, or change row whose host or domain is not a host
  name is dropped, and so is a `by_version` row whose version is not in the strict form; a verdict or source outside
  the lists is shown as `unknown`; other failing values are dropped from lists or become `null`.
- `product_name` is taken from the brain's own product table. `method` and `target_derived` are not kept.
  `targets.scan_db_run` is kept only when it matches the job id pattern.
- The brain shows `latest.json` when it is not suspect, or else the newest dated file when that is not suspect. It
  shows a suspect notice when the newest dated file is suspect and newer than the result shown.

## Example

The dated file `published/version-watch/php-example/YYYY-MM-03.json` of a non-suspect run (identical to that run's
`latest.json`). Names, times, and the CVE id are illustrative.

```json
{
 "schema": "version-watch-v1",
 "watch": {"id": "php-example", "name": "PHP example", "product": "php", "product_name": "PHP"},
 "job_id": "vw-20300103-040000-6a7b8c",
 "generated_at": "YYYY-MM-03T04:00:12Z",
 "date": "YYYY-MM-03",
 "cves": ["CVE-2099-0001"],
 "floors": {"8.2": "8.2.30", "8.3": "8.3.20"},
 "method": "GET / over https and http (same-host redirects followed, at most 3), response headers only (X-Powered-By, Server); no crafted request",
 "target_derived": ["hosts[].server"],
 "targets": {"total": 3, "from_scan_db": 2, "from_job": 1, "carried": 1, "not_probed": 1,
             "scan_db_run": "full-20300102-100000-0a1b2c"},
 "headline": {"hosts": 3, "fail": 1, "pass": 0, "unknown": 1, "unreachable": 1},
 "by_version": [{"version": "8.2.12", "branch": "8.2", "verdict": "FAIL", "reason": "8.2.12 is below 8.2.30", "hosts": 1}],
 "by_domain": [{"domain": "example.test", "hosts": 3, "fail": 1, "pass": 0, "unknown": 1, "unreachable": 1}],
 "hosts": [
  {"hostname": "www.example.test", "domain": "example.test", "version": "8.2.12", "verdict": "FAIL",
   "reason": "8.2.12 is below 8.2.30", "read_from": "https x-powered-by", "https_status": 200, "http_status": 200,
   "server": "Apache", "scan_db_version": "8.2.12", "source": "both"},
  {"hostname": "shop.example.test", "domain": "example.test", "version": null, "verdict": "UNKNOWN",
   "reason": "HTTP 200 (https) / 200 (http), no PHP version in the headers (hidden or not PHP)", "read_from": null,
   "https_status": 200, "http_status": 200, "server": "nginx", "scan_db_version": null, "source": "scan_db"},
  {"hostname": "old.example.test", "domain": "example.test", "version": null, "verdict": "UNREACHABLE",
   "reason": "no HTTP response on https or http (not probed: its CNAME chain could not be looked up)", "read_from": null,
   "https_status": null, "http_status": null, "server": null, "scan_db_version": null, "source": "carried"}
 ],
 "changes": {"since": "YYYY-MM-02", "items": [
  {"hostname": "old.example.test", "from_version": "8.3.25", "to_version": null, "from_verdict": "PASS", "to_verdict": "UNREACHABLE"},
  {"hostname": "shop.example.test", "from_version": null, "to_version": null, "from_verdict": null, "to_verdict": "UNKNOWN"}
 ]},
 "history": [
  {"date": "YYYY-MM-02", "hosts": 2, "fail": 1, "pass": 1, "unknown": 0, "unreachable": 0},
  {"date": "YYYY-MM-03", "hosts": 3, "fail": 1, "pass": 0, "unknown": 1, "unreachable": 1}
 ]
}
```

This example was produced by the scanner's own `build_doc` and reformatted; the scanner writes the same keys with
one-space indentation, one key per line.
