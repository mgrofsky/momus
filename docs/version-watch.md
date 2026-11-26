# Version watch

A version watch tells you which of your hosts run a product version below the lowest fixed release of its branch, for the CVEs you care about. You define the watch; the scanner reads the version each host advertises in its response headers and compares it with your floors.

## What the scanner sends

**One `GET /` per host per run, over https and then http, response headers only. From each scheme's `GET /` it follows at most three redirects (so up to three for https and three for http), and only to the same host name; such a redirect may lead to another path or port on that host. It starts no request to any other path, and uses no other method and no request body.** A host listed by several watches is still asked once per run; every watch then judges the same answer.

Before any request, every host must pass four checks, in this order:

1. **The DNS proof of its domain, checked in this job.** A version-watch job starts with the same DNS proof check a scan runs at its start. If that check cannot run at all, the job fails and nothing is probed. A host under a domain whose proof did not pass in that job is not probed, and is reported `UNREACHABLE` with the reason "not probed: its domain did not pass the DNS proof in this job". A lab job skips the DNS proof and probes only its lab targets.
2. **The scope's name gate:** under a domain in scope, and not excluded.
3. **The exclusions through CNAMEs:** every name in the host's CNAME chain must pass the exclusions. A host whose chain cannot be looked up is not probed, and is reported `UNREACHABLE`.
4. **The address check:** every address of the host must be allowed, and the connection is pinned to the address that was checked.

A host that fails the name gate, or whose CNAME chain reaches an excluded name, is left out of the results; the scanner's log names it.

Hosts under a domain that is **held back from active checks** (added after the inventory you approved) are still watched. This probe sends no more than the web inventory already does.

The user agent is `momus-version-watch`, so the requests are easy to find in WAF and access logs.

## Defining a watch

On the Version watch page, an admin adds, edits, or removes watches. Every change is recorded in the audit log. Each `version-watch` job, whether queued by hand or by the daily schedule, carries every current watch.

| Field | Rule |
|---|---|
| Id | 2 to 32 characters: `a-z`, `0-9`, and `-`, starting and ending with a letter or digit. It names the results folder, so it cannot be changed. |
| Name | 1 to 80 characters: letters, digits, spaces, and `. _ , -`, starting with a letter or digit. |
| Product | One of the products in the table below. |
| CVEs | 1 to 20 ids such as `CVE-2099-12345`, each listed once. |
| Floors | 1 to 16 lines, one per branch, each the lowest fixed release of that branch, written `x.y.z`. For example `8.2.35` means "on branch 8.2, 8.2.35 and later are fixed". Branch numbers have up to four digits and no leading zeros; the patch number is 0 to 99999. |
| Extra hosts | Optional, up to 100 host names. They pass the same checks as every other host. A watch never widens the scope. |

A job can never carry a pattern, a header name, a path, or a URL. How a version is read is fixed in code, per product.

Up to 20 watches can be defined.

**Which hosts a watch looks at:**

- every host the scan database lists as running the product;
- the watch's extra hosts;
- every host on the watch's newest earlier result (not a suspect one) that is still answering. A host that starts hiding its version therefore reads `UNKNOWN`, never as fixed. A carried host that no longer answers is dropped, and shows in the result's changes as gone.

## The verdicts

The rule is the same for every product:

| Verdict | Meaning |
|---|---|
| `PASS` | On a branch that has a floor: at or above it. Or on a branch newer than every listed branch. |
| `FAIL` | On a branch that has a floor: below it. On any other branch: "no fixed release on this branch". |
| `UNKNOWN` | The host answered on https or http, but its headers show no version of this product. The version may be hidden, or the host may not run the product. |
| `UNREACHABLE` | No HTTP answer on either scheme, or the host was not probed. The reason says which. |

A version without a patch number (`PHP/8.2`) counts as patch 0.

A run in which more than half of a watch's hosts are `UNREACHABLE` is marked **suspect**. It is kept as a dated file but does not replace the latest result, because a network problem on the scanner's side must not read as a result.

## Products

| Product | Matches scan component | Headers read | Version read | In because |
|---|---|---|---|---|
| PHP (`php`) | `PHP` | `X-Powered-By`, then `Server` | `PHP/x.y` or `PHP/x.y.z` | PHP still advertises its version in `X-Powered-By` by default (`expose_php`), and branch-plus-patch numbering matches the floor rule. |
| nginx (`nginx`) | `nginx` | `Server` | `nginx/x.y.z` | nginx sends `nginx/x.y.z` unless `server_tokens off`. Numbering is numeric. `cloudflare-nginx` and `openresty/...` do not match. |
| Apache HTTP Server (`apache-httpd`) | `Apache` | `Server` | `Apache/x.y.z` | `ServerTokens` defaults to the full version. `Apache-Coyote` (Tomcat) does not match. |
| OpenSSL (`openssl`) | `OpenSSL` | `Server` | `OpenSSL/x.y.z` | Apache with `mod_ssl` adds `OpenSSL/x.y.z` to `Server`. Releases before 3.0 carry a letter (`1.1.1w`). Only the numeric part is read, and floors must be on branch 3.0 or newer, so a lettered 1.x release always lands on a branch without a floor and fails. |

A version with a fourth number (`1.21.4.1`) is not read as its first three parts.

Considered and left out:

- **Microsoft IIS** (`Microsoft-IIS/10.0`): the header carries only the major and minor version. Fixes arrive as Windows updates that do not change it.
- **ASP.NET** (`X-AspNet-Version: 4.0.30319`): the value names the runtime band, not a patch level.
- **Express** (`X-Powered-By: Express`): there is no version in the header.
- **OpenResty** (`openresty/1.21.4.1`): it uses four-part versions, which do not fit the branch-and-patch rule.
- **lighttpd** (`lighttpd/1.4.x`): it fits the rule but is not in the table. Adding it takes one entry in the product table of `scanner/pipeline/version_watch.py`, the same entry in its copy in `brain/app/watches.py`, and a test.
- **Tomcat and Jetty:** they rarely put a full version in the headers of `GET /`.

## Example definition (an example only)

> **This is an example.** It is an example watch for PHP. Its CVE ids (`CVE-2099-0001`, `CVE-2099-0002`) are placeholders, and its floors are only for illustration. For a real watch, use the real CVE ids and confirm the fixed release of every branch against the vendor's advisory. Fixed versions change when new releases come out.

| Field | Value |
|---|---|
| Id | `example-php-watch` |
| Name | `Example PHP watch` |
| Product | PHP |
| CVEs | `CVE-2099-0001`, `CVE-2099-0002` |
| Floors | `8.2.35`, `8.3.36`, `8.4.27`, `8.5.12` |

With these floors, 8.2.34 fails ("8.2.34 is below 8.2.35"), and 8.2.35 and 8.6.0 pass. 8.1.x, and anything older, fails with "no fixed release on this branch".

The same definition as the developer tool `jobctl.py --watches-file` takes it (a list of watches). The API (`POST /api/v1/version-watch/watches`) takes one watch at a time: the object inside the list.

```json
[{"id": "example-php-watch", "name": "Example PHP watch", "product": "php",
  "cves": ["CVE-2099-0001", "CVE-2099-0002"],
  "floors": {"8.2": 35, "8.3": 36, "8.4": 27, "8.5": 12}, "hosts": []}]
```

## Results

Results are written per watch, to `published/version-watch/<watch id>/<YYYY-MM-DD>.json` and `latest.json` (schema `version-watch-v1`). There is one dated file per UTC day; a later run on the same day replaces it. The newest 90 dated files are kept. A watch you remove keeps its results until its newest result is 90 days old; the next version-watch or retention job after that deletes them. After each version-watch and retention job, the published folder is made to match the scanner's own copy, so it does not grow without limit.

Every value in a result is fixed text, a number, a strictly parsed version or HTTP status, a checked host name, or part of your own definition, with one exception: `hosts[].server`, the raw `Server` header. That value comes from the target. It is cut to 100 characters and passed through the scanner's redaction, and the file lists it under `target_derived`. Treat it as untrusted text. The brain shows it as plain text only.
