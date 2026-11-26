# Findings and evidence

This page describes what Momus keeps about each finding, what it deliberately throws away, how long each kind of data lives, how a finding moves between open and fixed, how its score is computed, and what a mark does and does not do. Each safeguard names the test that shows it.

The short version:

- The scan database keeps a small, structured record of each finding. Response bodies, requests, replay (curl) commands, cookie values, authorization header values, and port-scanner script output are never written to it.
- One optional setting adds a short, redacted excerpt of the recorded HTTP response for web findings. Nothing else.
- Every target-derived text field passes through pattern-based redaction before it is stored. Redaction is a second line of defense and misses things. The list of what it misses is below.
- The raw output of every tool stays on the scanner's disk, unredacted, in the run directory until a retention job removes it. Nothing removes it automatically.
- A finding is marked fixed only when a later scan really looked for it and did not find it. A server that answers quickly with an error or block page can still make a finding look fixed.
- Marks and the AI analyst never change a score, verdict, status, or band count.

## Where the data lives

- **Scan database:** `data/scan.sqlite` under the scanner's scan root (the scanner's data volume). Written by `scanner/pipeline/ingest.py` after each scan run.
- **Snapshot:** a read-only copy of the whole scan database that the scanner publishes after each ingest (`published/snapshots/<run id>.sqlite`, named with its SHA-256 in `published/snapshots/latest.json`). The brain reads findings only from the snapshot. Everything below about the scan database applies to the snapshot too.
- **Run directory:** `runs/<run id>/` under the scan root. The raw output of every tool for one run.
- **Reports:** the HTML report and CSV files for each run, under the scan root and copied to `published/reports/<run id>/`.
- **App database:** the brain's own database. It holds marks, proposals, notes, the audit log, and analyst run records. It never holds a copy of the findings.

See [the published folder](reference/published-layout.md) for the exact layout.

## What is stored about a finding

A finding is identified by its finding key: a hash of the host name (lower case), the source tool, the check id, and the port. The IP address is not part of the key, so a host that moves to a new address keeps its findings. The source is one of `nuclei`, `nmap`, `sslscan`, `dns`, or `http`.

The test that shows it: `scanner/pipeline/test_scoring.py::TestScoring::test_key_ignores_ip_and_case`.

### The finding row

One row per finding across all runs (table `findings`): finding key, host name, domain, source, check id, port, title, severity, CVE ids, the first and last run it was seen in, status (`open` or `fixed`), and the run that fixed it.

The check id of a nuclei finding is the template id plus the matcher name. Both are cleaned by the redaction patterns before the key is built, so a secret planted in a matcher name never becomes part of a key. The title is redacted and capped at 300 characters.

### One observation per run

Each run that sees a finding, or carries it forward, writes one row to `finding_observations`:

| Field | What it holds | How it is stored |
|---|---|---|
| `asset_class` | the host class (`owned`, `cdn_fronted`, `third_party`, `unverified`) | fixed vocabulary |
| `matched` | where the finding matched: a URL, `host:port`, or an address | URLs through URL redaction (below); host and port as they are |
| `description` | template text, which can include target text (for example a banner) | redacted, strict, 2,000 characters |
| `remediation` | template text | as it is, capped at 2,000 characters |
| `reference` | template reference links | URL redaction, at most 10 links of 300 characters |
| `tags` | template or normalizer tags | as they are |
| `cvss`, `epss`, `kev` | CVSS score, best EPSS score of the finding's CVEs, whether any CVE is in the KEV list | numbers |
| `impact`, `likelihood`, `score`, `band`, `sla_days` | the score and its parts (see "How scores are computed") | numbers and fixed vocabulary |
| `state` | `new`, `persistent`, or `reopened` in this run | fixed vocabulary |
| `verdict` | the content check's verdict (for example `confirmed`, `names_only`, `empty`, `redirect`, `gone`) | fixed vocabulary |
| `verification` | the content check's short evidence (a redirect target, listed file names) | redacted, strict, 300 characters |
| `exposure` | what triage found the finding exposes (`credential`, `data`, `source`, `config`, `internal`, `names`, `nothing`, and others) | fixed vocabulary |
| `raw_json` | the minimized evidence record (next section) | allowlisted keys, each typed or redacted |

### The minimized evidence record

`scanner/pipeline/minimize.py` builds the `raw_json` record from the raw tool output. Each source has an explicit allowlist of keys. Any key not on the list is dropped, including keys a future tool version adds.

- **nuclei:** template id, template name and URL, request type, host, port, scheme, URL, path, matched location, IP address, timestamp, matcher name and status, extractor name, extracted values, a list of sibling host names (at most 25), and from the template's `info` block: name, severity, tags, references, and classification (CVE ids, CWE ids, CVSS score and vector, EPSS score and percentile, CPE). Extracted values are redacted and kept to at most 10 values of 200 characters each. When there were more, the total count is recorded.
- **nmap:** address, port, protocol, service name, product (redacted, 100 characters), the ids of the scripts that ran, and the list of open ports. The scripts' output is never kept.
- **sslscan:** protocol names, cipher names (kept only when they look like cipher names), and the certificate expiry.
- **dns:** the domain, the name server and its address, whether a zone transfer succeeded, the record count (never the zone data), addresses, and CNAME targets.
- **http and any other source:** nothing.

The stored record is always valid JSON. Above 16,000 characters, whole optional parts are dropped in a fixed order (the excerpt body, the excerpt, extracted values, references, siblings), and the record names what was dropped. A string is never cut in the middle.

The tests that show it: `scanner/pipeline/test_minimize.py::TestNuclei::test_allowlist_and_drops`, `scanner/pipeline/test_minimize.py::TestNuclei::test_extracted_values_capped`, `scanner/pipeline/test_minimize.py::TestOtherSources::test_nmap_drops_script_output`, `scanner/pipeline/test_minimize.py::TestOtherSources::test_sslscan_and_dns`, `scanner/pipeline/test_minimize.py::TestJsonAndLevel::test_always_valid_json_and_bounded`.

### Triage

Triage is the scanner's follow-up look at what a finding exposes. For findings it examines, it writes one row per run to `finding_triage`: exposure, a summary and a suggested fix (each redacted, strict, 600 characters), the items it looked at, the secrets it found, and whether the host is on the strict-SLA host list (column `pci`; see "How scores are computed").

- Each item keeps its URL (URL redaction), HTTP status, size in bytes, a kind, and a note (redacted, 300 characters).
- Each secret keeps only its type, a masked form, where it was found, and the line number. The masked form is a well-known public prefix when the value has one (`AKIA`, `ghp_`, `eyJ`, a PEM header) followed by the length, for example `AKIA...[20 chars]`. A secret that triage noticed without reading its value is stored as `(value not read)`.

The test that shows it: `scanner/pipeline/test_minimize.py::TestRows::test_triage_record`.

### What is never stored

At either evidence level, the scan database, the snapshot, the reports, and the scanner's logs never receive:

- request dumps;
- replay commands (nuclei's curl command);
- cookie values (only cookie names are kept);
- authorization header values;
- port-scanner (nmap) script output;
- interaction and metadata blocks, and template file paths, from nuclei records.

Response bodies and response header values are not stored at the default level. The `excerpt` level adds a short, redacted part of them for nuclei findings only (next section).

Page data outside findings follows the same rule: endpoint rows keep cookie names only, uncommon header names only, and email addresses scraped from a page only as a count and a list of domains. The scanner's own log lines for content checks and triage name the host, check id, and verdict or exposure only, never the evidence or summary text.

The tests that show it: `scanner/pipeline/test_no_secret_reaches_storage.py::TestNoSecretReachesStorage::test_minimal`, `scanner/pipeline/test_minimize.py::TestRows::test_endpoint_row`.

The first of these builds a synthetic run directory with fake secrets planted in every file ingest reads (recorded requests and responses, curl commands, extracted values, matcher names, page titles, cookies, certificates, DNS text records, nmap script output, and the answers of the follow-up checks). It then runs ingest, the report, and the version watch, and checks that no planted value appears, in any common encoding, in the database files, any table, any report file, any version-watch file, or the captured output. It also checks that the useful parts survive.

## Evidence levels

The evidence level decides how much of each finding's evidence is stored. It is part of the scope, set on the Scope page in the brain ("Evidence kept"), and carried by every scan job.

| Level | Default | What it keeps |
|---|---|---|
| `minimal` | yes | the minimized evidence record described above, and nothing from response bodies or response headers |
| `excerpt` | no | everything `minimal` keeps, plus, for nuclei findings with a recorded HTTP response, an excerpt: the status code, every response header **name**, the **values** of 17 non-sensitive headers only, and at most 2,000 characters of the body after strict redaction |

The 17 headers whose values the excerpt keeps are `content-type`, `content-length`, `content-encoding`, `content-language`, `server`, `x-powered-by`, `cache-control`, `date`, `last-modified`, `vary`, `allow`, `accept-ranges`, `strict-transport-security`, `x-frame-options`, `x-content-type-options`, `referrer-policy`, and `x-xss-protection`. Each value is redacted and capped at 200 characters. `Set-Cookie`, `Authorization`, API key headers, and every other header keep their name only.

For the body, the scanner takes the first 20,000 characters, cut back to the last line end so that a value cut in half is dropped with its line, redacts that text, and keeps at most the first 2,000 characters of the result. A body longer than that with no line end in its first 20,000 characters is left out of the excerpt (the body is stored empty). A body of 20,000 characters or fewer is redacted whole.

The level is checked at every step. The scanner refuses a job whose evidence level is not one of the two names, the recon script refuses an unknown value, and ingest stops with one error line rather than guess. The level applied is recorded with the run (`runs.evidence_level`) and shown in the run's report under "Evidence stored".

Changing the level affects runs ingested after the change. It does not rewrite rows already stored, and a recheck copies the previous rows of hosts it did not re-test as they were.

The tests that show it: `scanner/pipeline/test_minimize.py::TestNuclei::test_excerpt`, `scanner/pipeline/test_minimize.py::TestNuclei::test_excerpt_body_with_no_line_end_in_the_read_limit_is_dropped`, `scanner/pipeline/test_minimize.py::TestNuclei::test_unknown_level_refused`, `scanner/pipeline/test_minimize.py::TestJsonAndLevel::test_evidence_level`, `scanner/pipeline/test_no_secret_reaches_storage.py::TestNoSecretReachesStorage::test_excerpt`.

## Redaction

Minimization is the main control: what is not kept cannot leak. Redaction (`scanner/pipeline/redact.py`) is the second line. It is pattern matching applied field by field to what is kept, before anything is written. The cap on each field is applied after redaction, so a cut never exposes the start of a secret.

### What redaction recognizes

Secret patterns (the value is replaced by `<REDACTED type>`):

- private key blocks (RSA, EC, OpenSSH, PKCS#8, PGP), including JSON-escaped forms;
- `Bearer` tokens, `Basic` credentials, and any `Authorization` or `Proxy-Authorization` header value, as a header line, as a quoted JSON pair, or inside a quoted command-line argument;
- `Cookie` and `Set-Cookie` values: every value is masked, while names and attributes such as `Path` are kept;
- JSON Web Tokens;
- signed-URL and session parameters: S3 (`X-Amz-Signature`, `X-Amz-Credential`, `X-Amz-Security-Token`, `AWSAccessKeyId`, `Signature`), Google Cloud Storage (`X-Goog-Signature`, `X-Goog-Credential`, `GoogleAccessId`), Azure SAS (`sig`), CloudFront (`Policy`, `Signature`, `Key-Pair-Id`), and common session cookie names (`PHPSESSID`, `JSESSIONID`, `sid`, `laravel_session`, and others);
- AWS access key ids (any letter case), npm tokens, GitHub tokens, Slack tokens, Stripe live keys, and Google API keys;
- `.npmrc` credentials (`_authToken`, `_auth`, `_password`);
- passwords in URLs (`scheme://user:password@host`) and in connection strings (`Password=...`);
- values under a secret-looking key name (`password`, `secret`, `api_key`, `access_token`, `client_secret`, `private_key`, `credentials`, and similar) in `.env`, INI, YAML, JSON, shell `export`, and PHP `define` forms. A key that is about a secret rather than holding one (`password_reset_url`, `token_ttl`), placeholders (`changeme`, `${VAR}`), file paths, and version numbers are left alone.

Personal data:

- card numbers that pass the Luhn check;
- phone numbers in international (E.164, `+` prefix) format;
- email addresses, reduced to their domain (`<email at example.com>`).

URLs, for every stored URL: user names and passwords in the URL are removed; the values of credential, signature, session, and OAuth parameters (`code`, `access_token`, `id_token`, `token`, `key`, `password`, and the names above) are replaced in the query string and the fragment; `;jsessionid=` path parameters are masked; URLs nested inside a parameter value are redacted in turn; then the secret patterns run over what is left.

High-entropy tokens (strict mode, used for most stored text fields): a token of 20 or more characters that contains upper case letters, lower case letters, and digits, has high entropy, and switches between character classes often is replaced by `<REDACTED high-entropy string>`. A token containing `/` is judged per segment (16 or more characters), so ordinary URL paths survive.

The tests that show it: `scanner/pipeline/test_redact.py::TestFindSecrets::test_patterns`, `scanner/pipeline/test_redact.py::TestRedact::test_values_replaced`, `scanner/pipeline/test_redact.py::TestRedact::test_luhn`, `scanner/pipeline/test_redact.py::TestGaps::test_lowercase_value_under_a_secret_key`, `scanner/pipeline/test_redact.py::TestGaps::test_jwt`, `scanner/pipeline/test_redact.py::TestGaps::test_authorization_headers`, `scanner/pipeline/test_redact.py::TestGaps::test_cookies_keep_names`, `scanner/pipeline/test_redact.py::TestGaps::test_signed_url_parameters`, `scanner/pipeline/test_redact.py::TestGaps::test_redact_url`, `scanner/pipeline/test_redact.py::TestGaps::test_private_key_blocks`, `scanner/pipeline/test_redact.py::TestGaps::test_structured_text_forms`, `scanner/pipeline/test_redact.py::TestFindSecrets::test_references_are_not_secrets`, `scanner/pipeline/test_minimize.py::TestOrdinaryValuesSurvive::test_urls`, `scanner/pipeline/test_minimize.py::TestOrdinaryValuesSurvive::test_random_tokens_still_masked`.

### Which stored fields are redacted

Ingest reads the full raw record in memory for the content check, scoring, and triage, and cleans each value only at the point where it is written.

- **Strict text redaction with a cap:** finding titles (300), descriptions (2,000), content-check evidence (300), triage summary and fix (600 each), triage item notes (300), page titles (200), `Server` headers (100), WAF names (100), generator and powered-by strings (100), nmap product banners (100), technology names, versions, and their evidence (100, 60, 200), host profile labels (100), certificate subject and issuer (200), extracted values (200), and DNS text-type records such as TXT, SPF, DMARC, and DKIM (500).
- **URL redaction:** matched locations, references, endpoint URLs, final URLs and redirect targets, the URLs in the asset inventory, application group URLs, triage item URLs, and certificate URI alternative names.
- **Kept only when they have the expected shape:** host names, addresses, ports, certificate serial numbers and fingerprints (hex only), certificate key type and signature algorithm, cipher and protocol names, and nmap service names. A value without the expected shape is dropped or treated as text.
- **Names only:** cookies and uncommon response headers.
- **Count and domains only:** email addresses scraped from a page.
- **As they are:** check ids after cleaning, tags, CVE and CWE ids, remediation text from the template (capped), and the fixed vocabularies (verdict, exposure, band, state, class).

The tests that show it: `scanner/pipeline/test_minimize.py::TestNuclei::test_matched_location_is_a_redacted_url`, `scanner/pipeline/test_minimize.py::TestNuclei::test_matcher_name_is_cleaned_deterministically`, `scanner/pipeline/test_minimize.py::TestRows::test_certificate_and_dns`, `scanner/pipeline/test_minimize.py::TestOrdinaryValuesSurvive::test_vocabulary`.

The report writes the stored values. Every CSV cell that starts with `=`, `+`, `-`, `@`, a tab, or a carriage return is prefixed with an apostrophe so that a spreadsheet program does not run it as a formula. In the HTML report only `http` and `https` references become links. The HTML report carries no content security policy of its own: opened from disk, it runs outside the brain's policy, and its escaping is what protects it.

The tests that show it: `scanner/pipeline/test_report.py::TestOutputSafety::test_csv_cell`, `scanner/pipeline/test_report.py::TestOutputSafety::test_links_and_escaping`.

### What redaction will still miss

Treat everything the scanner stores as sensitive. Redaction will not catch:

- **Secrets without a recognizable shape or key name.** A password in free text ("the password is hunter2"), a short or simple value next to an unremarkable key (`db_conn_pw2 = x9`), a token under a key name not on the list, and most vendor key formats beyond the ones listed above.
- **Random-looking values the entropy rule skips.** Tokens shorter than 20 characters (16 per path segment), tokens made only of hex digits, only of lower case letters and digits, or only of upper case letters and digits, and tokens whose character classes come in long runs. The same rule masks some harmless values that do look random, such as mixed-case identifiers.
- **Encoded or transformed values.** Base64 (except `Basic` credentials), hex, URL-encoded JSON, compressed or binary content, values split across lines or fields, HTML entities, look-alike Unicode characters, and anything inside an archive.
- **Secrets inside values stored by shape.** Host names, certificate names, PTR names, cookie and header names, file and path names in triage notes, nmap service names, and template ids are kept as they are when they have the expected shape. A secret embedded in a host name label or an ordinary-looking path segment is kept.
- **Credentials in URLs under other names.** A custom parameter name (`?k=...`) or a token in the path (`/download/<token>`) that is not long and random, and URLs without a scheme inside free text.
- **Personal data other than email addresses, card numbers, and international phone numbers.** Names, postal addresses, national identity numbers, and phone numbers in local formats are not detected.
- **Text written by the target that is not a secret.** Page titles, banners, descriptions, file names, internal host names, and versions are stored after redaction and are shown in the brain. If the AI analyst is enabled, they can be sent to the model provider (see [the analyst](analyst.md)).
- **Raw files on disk.** The run directories keep every tool's raw output without any redaction (see "Retention").
- **Rows already stored.** Changing the evidence level does not rewrite earlier rows.

## Retention

| Data | Where | How long | What removes it |
|---|---|---|---|
| Run directories (raw tool output) | `runs/<run id>/` under the scan root | until a retention job removes them; the job's default period is 30 days | a retention job, queued by a person in the brain |
| Scan database | `data/scan.sqlite` under the scan root | indefinitely | nothing (recheck rows are pruned, below) |
| Snapshots | `published/snapshots/` | the newest `SCAN_KEEP_SNAPSHOTS` files (default 10), always including the one `latest.json` names | the scanner, after each publish and each retention job |
| The brain's verified snapshot copies | the brain's cache folder | the newest 3 | the brain |
| Reports | `reports/` under the scan root and `published/reports/<run id>/` | indefinitely | nothing |
| Version-watch files | `version-watch/<watch id>/` under the scan root and in the published folder | the newest 90 dated files per watch; the folder of a watch removed from the brain stays until its newest file is 90 days old | version-watch jobs and retention jobs |
| Brain records | the app database | see below | see below |

**Run directories hold unredacted data.** A run directory holds what each tool wrote: nuclei records with full requests and responses, nmap XML with script output, page data, TLS and DNS output, and the recon log with the tools' error output. Ingest reads these files. Minimization and redaction apply only to what ingest writes. Anyone who can read the scanner's data volume can read them.

**Retention jobs are manual.** Nothing removes run directories on a schedule. A person queues a retention job from the brain ("Queue retention clean-up") with a period from 1 to 3,650 days (default 30). The job runs `scanner/pipeline/retention.py --apply`. A run's age comes from its manifest's finish or start time, or else from the directory's modification time. Run by hand without `--apply`, the script only lists what it would delete.

Kept longer, whatever their age:

- the most recent full run, because the next recheck builds on its results;
- any run that a recheck names as its base, for the same reason;
- the newest run when its manifest is missing or unreadable, because it may be that latest full run.

The script never follows a symbolic link, ignores anything that is not a directory directly under `runs/`, and refuses to run at all when `runs/` is itself a link.

**Scan database.** Ingest keeps every run's rows, with one exception: a recheck run holds a complete copy of the estate (its own rows plus rows carried forward from the previous snapshot) only while it is the latest recheck or the one before it. After that, its carried rows are removed and it keeps only the hosts it re-tested. Full runs are never pruned. The retention job does not touch the database.

**Brain records.** The audit log is append-only: database triggers refuse every update and delete. Marks are never deleted; a withdrawn mark keeps its row with who withdrew it and when. Proposals, accepted notes, analyst run records, and analyst steps are kept. The prompts and responses of analyst runs are stored only when `MOMUS_ANALYST_DEBUG` is on, and never in lab mode. Sign-in attempt rows are deleted once they are older than the 24-hour window the sign-in limits read. Sessions are deleted when they end.

The tests that show it: `scanner/pipeline/test_retention.py::TestRetention::test_plan`, `scanner/pipeline/test_retention.py::TestRetention::test_dry_run_changes_nothing`, `scanner/pipeline/test_retention.py::TestRetention::test_apply_deletes_only_the_planned_runs`, `scanner/pipeline/test_retention.py::TestRetention::test_newest_run_without_manifest_is_kept`, `scanner/pipeline/test_retention.py::TestRetention::test_runs_directory_that_is_a_link_is_refused`, `scanner/pipeline/test_runner.py::Publishing::test_snapshot_latest_and_prune`, `scanner/pipeline/test_runner.py::Publishing::test_retention_and_version_watch_jobs`, `scanner/pipeline/test_version_watch.py::Retention::test_keep_newest`, `scanner/pipeline/test_version_watch.py::Retention::test_a_watch_removed_from_the_job_keeps_its_results_for_the_retention_period`, `brain/tests/test_audit_db.py::test_audit_log_is_append_only`.

## How a finding becomes open, fixed, or reopened

### States

A finding's status is `open` or `fixed`. Each run that sees it records one of three states:

- **new:** seen for the first time;
- **persistent:** seen again while open;
- **reopened:** seen again after a run had marked it fixed. Its status goes back to `open`.

A finding that a run does not see is not automatically fixed. It is marked fixed only when the run is known to have looked for it.

### What "looked for it" means

A run marks an open finding fixed only when every one of these holds:

1. **The host was in this run's reach.** For a full run, the finding's domain passed the DNS proof in this run. For a recheck, the host was on the recheck's list.
2. **The phase that produces the finding ran and exited without error.** For example, a run whose port scan did not run cannot fix a port finding.
3. **For nuclei findings, every pass that can observe findings was configured to run** (the generic, technology, third-party, and DNS passes).
4. **The host was handed to the tool that observes the finding.** The scanner records, per tool and per nuclei pass, which hosts each tool was given. A nuclei finding needs the pass that observed it: a DNS template needs the DNS pass, a finding on a third-party host needs the third-party pass, and anything else needs the generic and technology passes. For HTTP findings, only hosts that answered the HTTP probe count. A host held back from active checks counts as not tested.
5. **For nuclei findings, the pass finished without error and no request the check depends on failed** (next section).
6. **An active-only check is fixed only by a run with the `active` check profile.** A `safe` run does not send those checks, so it cannot fix their findings.

If any condition fails, the finding stays open, and ingest prints how many findings it kept open for each reason.

The tests that show it: `scanner/pipeline/test_ingest.py::TestFixedRule::test_pure_rule`, `scanner/pipeline/test_ingest.py::TestFixedRule::test_load_coverage`, `scanner/pipeline/test_ingest.py::TestFixedEndToEnd::test_skipped_host_and_active_tags`, `scanner/pipeline/test_ingest.py::TestFixedEndToEnd::test_held_back_hosts_are_not_covered`, `scanner/pipeline/test_ingest.py::TestFixedEndToEnd::test_hosts_under_a_held_back_domain_are_not_covered`, `scanner/pipeline/test_ingest.py::TestFixedEndToEnd::test_dns_pass_coverage_does_not_fix_an_http_finding`, `scanner/pipeline/test_ingest.py::TestFixedEndToEnd::test_dns_finding_fixed_by_the_dns_pass_only`.

### The failed-request rule

This rule applies to nuclei findings only. A nuclei check whose request timed out looks to nuclei the same as a check that ran and did not match. So each nuclei pass writes an error log: one line for each request it could not complete, with the template, the URL, the host, and an error kind. A nuclei finding is not marked fixed when, in the pass that observes it, its host had:

- a failed request under the finding's own template id (read from the template file in the run's template folder, or else taken from the file name); or
- a request that got **no answer at all** at the same URL path the finding matched at. "No answer" means one of the error kinds `network-temporary-error`, `network-permanent-error`, or `deadline-error`: a timeout, a refused or closed port, or a failed name lookup.

The path rule exists because nuclei often sends one request for several templates that ask for the same thing, and logs a failure under only one of them. Errors of other kinds (`unknown-error`, or a line with no kind) count only against their own template. Those cover requests that did get an answer the template could not read, and non-HTTP probes, so an unrelated check's error does not hold every finding on the host open.

Two more parts of the rule:

- An error on a representative host counts for its siblings too. The scanner groups hosts that serve the same application and scans one representative, so the siblings' findings depend on the representative's requests.
- A nuclei pass that exits with an error marks nothing it observes as fixed in that run.

The path entry records the path only, not the port. A failed request at `/` on one port therefore also holds open a finding matched at `/` on another port of the same host. This errs toward keeping findings open.

For nmap, sslscan, DNS, and HTTP findings, the conditions in the previous section are the whole test.

The tests that show it: `scanner/pipeline/test_ingest.py::TestFixedEndToEnd::test_failed_requests_keep_the_finding_open`, `scanner/pipeline/test_ingest.py::TestFixedEndToEnd::test_errors_on_a_representative_keep_its_siblings_open`, `scanner/pipeline/test_ingest.py::TestFixedEndToEnd::test_a_clustered_request_failure_is_caught_by_its_path`, `scanner/pipeline/test_ingest.py::TestFixedEndToEnd::test_root_finding_fixed_despite_non_http_errors_and_an_unreadable_answer_at_root`, `scanner/pipeline/test_ingest.py::TestFixedEndToEnd::test_root_finding_open_after_a_no_answer_error_at_root_from_another_template`, `scanner/pipeline/test_ingest.py::TestFixedEndToEnd::test_unknown_error_on_the_findings_own_template_keeps_it_open`, `scanner/pipeline/test_ingest.py::TestFixedEndToEnd::test_a_line_without_a_kind_adds_no_path`, `scanner/pipeline/test_ingest.py::TestFixedEndToEnd::test_a_failed_pass_fixes_nothing_it_would_have_observed`, `scanner/pipeline/test_ingest.py::TestFixedEndToEnd::test_template_id_read_from_the_template_file`.

### The trade-off

On a slow or unreliable site, a finding can stay open for several scans after the issue is gone, until one run reaches the host for that check without a failed request.

The opposite gap remains. A server that answers promptly with the wrong thing, such as an error page, a maintenance page, or a firewall's block page instead of the real content, produces no error. To the scanner this looks the same as "the issue is gone", and that run can mark the finding fixed. If the issue is still there, a later run that gets the real content sees it again and records it as reopened.

A host that still resolves but stops serving HTTP keeps its open HTTP and nuclei findings open: it is never covered again.

### Rechecks

A recheck is a shorter scan of the hosts that still need attention. Its host list is computed from the scan database: every host with an open finding, every host running an end-of-life component, and every host still offering a legacy TLS protocol in the latest snapshot. A host drops off the list once a recheck sees it clean. A recheck builds on the latest full run (it reuses that run's grouping of hosts for nuclei), and ingest refuses a recheck built on anything else. The brain can queue a daily recheck and a monthly full run on a schedule.

A recheck can only mark fixed the findings on hosts it re-tested, under the same conditions as above. For every host it did not re-test, it carries the previous snapshot's rows forward unchanged, so the recheck's rows describe the whole estate. Open findings it has no observation of are carried forward as `persistent`, with their triage.

The test that shows it: `scanner/pipeline/test_ingest.py::TestTriageStorage::test_carry_triage_only_for_carried_keys`.

## How scores are computed

`scanner/pipeline/scoring.py` scores every finding as impact (1 to 5) times likelihood (1 to 5), giving 1 to 25.

| Band | Score | Default fix-by days |
|---|---|---|
| Critical | 20 to 25 | 30 |
| High | 12 to 19 | 90, or 30 on a host in the strict-SLA host list |
| Medium | 6 to 11 | 180 |
| Low | 1 to 5 | 180 |

The fix-by days can be changed with an optional file `scanner/config/policy.json`, built into the scanner image (its format is described at the top of `scanner/pipeline/settings.py`). The strict-SLA host list is part of a job's scope (`strict_sla_hosts`). The brain always sends it empty; another job writer, such as `scanner/jobctl.py` with `--strict-sla-host`, can fill it.

**Impact:**

- a zone transfer (`axfr` tag) is 5;
- otherwise, from the CVSS score when there is one: 9.0 and above is 5, 7.0 and above is 4, 4.0 and above is 3, above 0 is 2;
- otherwise from the reported severity: critical 5, high 4, medium 3, low 2, info 1.

**Likelihood**, first rule that applies:

1. The content check found nothing readable (verdict `names_only`, `empty`, `redirect`, or `gone`): 1.
2. Any of the finding's CVEs is in CISA's Known Exploited Vulnerabilities (KEV) list: 5.
3. The finding has CVEs: from the highest EPSS (Exploit Prediction Scoring System) score among them: 0.4 and above is 4, 0.1 and above is 3, otherwise 2.
4. Severity info without an exposure tag: 1.
5. An exposure tag (such as `exposure`, `config`, `backup`, `default-login`, `takeover`, `rce`, `sqli`): 4 on an `owned` or `cdn_fronted` host, 3 on others.
6. An `owned` or `cdn_fronted` host: 3 for critical, high, or medium severity, otherwise 2.
7. Otherwise 2.

A host of class `unverified` is scored like `owned`.

**Exposure found by triage** raises the parts as floors and never lowers a score, with one exception:

- `credential` or `data` (a readable credential or personal data): impact at least 4 (at least 5 on a strict-SLA host), likelihood at least 4;
- `source` (readable source code): impact at least 3;
- `nothing` on a finding whose content check said `confirmed`: likelihood 1. This is the exception.

The EPSS and KEV feeds are downloaded at ingest, at most once a day. Lab runs use the newest cached copy if there is one and download nothing; without a copy, findings are scored without them.

The tests that show it: `scanner/pipeline/test_scoring.py::TestScoring::test_impact_from_cvss_beats_severity`, `scanner/pipeline/test_scoring.py::TestScoring::test_kev_is_max_likelihood`, `scanner/pipeline/test_scoring.py::TestScoring::test_epss_bands`, `scanner/pipeline/test_scoring.py::TestScoring::test_exposure_owned_vs_third_party`, `scanner/pipeline/test_scoring.py::TestScoring::test_info_is_one`, `scanner/pipeline/test_scoring.py::TestScoring::test_score_bands`, `scanner/pipeline/test_scoring.py::TestScoring::test_fix_by_days_follow_the_sla_policy`, `scanner/pipeline/test_scoring.py::TestScoring::test_verdict_noise_drops_likelihood`, `scanner/pipeline/test_scoring.py::TestScoring::test_exposure_credential_and_data`, `scanner/pipeline/test_scoring.py::TestScoring::test_exposure_never_lowers`, `scanner/pipeline/test_scoring.py::TestScoring::test_exposure_nothing_on_confirmed_drops`.

### Scores are the scanner's alone

Scores, verdicts, statuses, and states are computed by the scanner and stored in the scan database. The brain opens the snapshot read-only, so nothing in the brain can change them: not a mark, not an accepted proposal, and not the analyst. The analyst's tools only read, and its only output is proposals that a person decides on.

The tests that show it: `brain/tests/test_marks.py::test_mark_never_changes_counts_by_band`, `brain/tests/test_snapshot.py::test_snapshot_connection_is_read_only`, `brain/tests/test_analyst_tools.py::test_the_registry_is_exactly_the_read_only_tool_list`, `brain/tests/test_analyst_tools.py::test_every_tool_is_read_only_against_the_databases_and_files`.

## Marks

A mark is a person's judgment about a finding, stored in the brain's app database and joined to the finding by its key.

### Kinds and who can add them

- **False positive**, **Accepted risk**, and **Duplicate.** Each needs a reason of 3 to 2,000 characters.
- Any signed-in user can add or withdraw a mark, on the finding's page or through the API. Every account is an administrator.
- A finding has at most one current mark. A new mark replaces the previous one, which is kept in the mark history as withdrawn.
- Adding, withdrawing, and accepting are each written to the audit log with the person's name.

### What a mark changes

A current mark takes the finding out of the default findings list (open and unmarked), and the list can be filtered by marked or unmarked. That is all. The finding's score, band, verdict, status, and the open-finding counts by band stay exactly as the scanner computed them, and the mark never reaches the scanner.

The tests that show it: `brain/tests/test_marks.py::test_mark_never_changes_counts_by_band`, `brain/tests/test_marks.py::test_marked_finding_leaves_default_list_and_filters`, `brain/tests/test_marks.py::test_mark_needs_reason_and_existing_finding`.

### Binding to the evidence

Each mark records the finding's **evidence fingerprint**: a SHA-256 hash of what the finding's evidence says in its latest run (the matched location, the content check's evidence and verdict, the exposure, the stored evidence record, and triage's items and secrets). Per-run fields (timestamps, IP addresses, EPSS values) are left out, so the same evidence in a later run has the same fingerprint. The mark also records the run it was made against.

The finding page and the API return the fingerprint, and the mark form and the API carry it back. The mark is refused ("The evidence changed since this page was shown. Nothing was saved") unless it equals the finding's fingerprint in the current snapshot. A manual mark is bound to the evidence fingerprint only; accepting an analyst proposal also checks the snapshot's hash (below).

The tests that show it: `brain/tests/test_marks.py::test_mark_records_fingerprint_and_run`, `brain/tests/test_accept_binding.py::test_a_manual_mark_is_refused_for_evidence_the_page_did_not_show`.

### When a mark goes stale

A mark is **stale** when either:

- the finding was recorded as reopened in a run later than the one the mark was made against; or
- the finding's evidence fingerprint in the current snapshot differs from the one stored with the mark.

A stale mark is shown with a warning that says why, and the finding counts as unmarked again: it returns to the default list. A site that changes what it serves can therefore make a mark stale, which puts the finding back in front of a person. It cannot hide a finding that way.

Two limits: a finding that is not in the current snapshot keeps its mark as current, and the reopened check examines at most 5,000 marks.

The tests that show it: `brain/tests/test_marks.py::test_reopened_finding_shows_mark_as_stale`, `brain/tests/test_marks.py::test_changed_evidence_makes_mark_stale`, `brain/tests/test_marks.py::test_same_evidence_in_a_later_run_keeps_mark_current`.

### Marks from analyst proposals

The analyst can propose a mark or a note; it cannot make one. A person accepts or rejects each proposal on its own page. Accepting a mark proposal goes through the same code as a manual mark, with the same reason rules, fingerprint check, and staleness.

An accept is bound to what the person was shown: the page carries both the finding's evidence fingerprint and the SHA-256 of the snapshot it was rendered from, and the accept is refused if either differs at the moment of the click. A proposal whose finding's evidence changed, whose finding reopened, or whose finding is gone is out of date and can only be closed.

The mark's reason is the model's text. It is labeled everywhere as written by the analyst and accepted by the named person, and later analyst runs are not given that reason.

The tests that show it: `brain/tests/test_analyst_proposals.py::test_accepting_creates_the_mark_through_the_manual_path`, `brain/tests/test_accept_binding.py::test_an_accept_from_a_page_of_an_older_snapshot_is_refused_and_works_after_a_new_look`, `brain/tests/test_accept_binding.py::test_the_api_accept_needs_the_values_the_proposal_was_shown_with`, `brain/tests/test_accept_binding.py::test_a_proposal_whose_evidence_changed_is_out_of_date_and_can_only_be_closed`, `brain/tests/test_accept_binding.py::test_a_proposal_on_a_finding_that_reopened_after_it_is_out_of_date`, `brain/tests/test_accept_binding.py::test_two_tabs_still_accept_once`, `brain/tests/test_accept_binding.py::test_an_accepted_reason_is_labeled_as_the_models_and_does_not_reach_later_runs`.
