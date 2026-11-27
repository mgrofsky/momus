# Threat model

This page says who can attack a Momus install, what each attacker controls, what the design stops, the test that shows each control, and what each attacker can still do. The "What it can still do" lists are the part to read first if you are deciding whether to run Momus. How each control behaves, and what an operator has to do about it, is on the page of the feature it belongs to.

Momus has two core containers. The **scanner** sends the scan traffic. The **brain** is the web application: the user interface, the API, the scheduler, and the optional AI **analyst**. The optional **seeder** collects host names from your own DNS services. Lab mode adds a demo target and a small local browser bridge. The scanner and the brain share no network. They exchange files only: the brain writes **jobs** (one JSON file per job) into the `jobs` folder, and the scanner writes results into the **published folder** (`published/`), which the brain reads. The seeder writes a list of host names that the scanner reads; from the scanner it reads only the list of verified domains.

The one rule: only the scanner sends packets to scan targets, and only the brain talks to a model provider. The seeder is the one exception to the first half. It contacts the DNS services you configure, such as a zone's own name server, and that server can be a host in scope.

Terms used below: a **domain** is an apex in scope; a domain is **verified** when the scanner has found its DNS proof record (a TXT record whose value is derived from a secret the scanner creates at install time); an **inventory** is a discovery-only run; an **approval** is an administrator's approval of an inventory, which active checks require; a host is **held back** when it is kept out of active checks; a **snapshot** is the read-only copy of the scan database the scanner publishes after each run; a **mark** is a person's label on a finding (false positive, duplicate, accepted risk); a **proposal** is a mark or note the analyst suggests and a person accepts or rejects.

## A hostile scanned site

A site you scan controls what it serves: bodies, headers, page titles, server banners, certificates, file names, redirects, and the DNS answers for its own names. It can write text aimed at the AI analyst and markup aimed at your browser.

What the design stops, and the test that shows it:

- A name found by enumeration or in a DNS answer reaches a scan tool only if it is under a domain in scope, on a label boundary, and not excluded. Tests: `scanner/pipeline/test_scope.py::NameGate::test_apex_and_label_boundary`, `scanner/pipeline/test_scope.py::NameGate::test_suffix_exclusions`.
- Only domains whose DNS proof holds are usable in a run. Test: `scanner/pipeline/test_scope.py::DnsProof::test_usable_equals_verified_on_disk`.
- A DNS answer that points a name at a private, loopback, link-local, cloud metadata, or other non-public address is refused before any tool uses it. Test: `scanner/pipeline/test_scope.py::AddressGate::test_non_global_classes`.
- The scanner's egress firewall applies to every process and protocol, whatever a tool looked up or was redirected to. It rejects every non-public destination, except four narrow allowances: traffic on the container's own loopback interface, which never leaves the scanner container (Docker's embedded resolver at 127.0.0.11 is reached this way); DNS (port 53) to the resolvers Docker's own resolver forwards to, even when one of those is a non-public address; IPv6 neighbor discovery to link-local and link-scope multicast addresses; and, in lab mode only, the lab range (see `docs/scope-and-authorization.md`, "The egress firewall" and "Lab mode"). Test: `tests/e2e/run_demo.sh` check "the scanner cannot connect to the decoy by address".
- A CNAME alias of an excluded name is treated as excluded. Test: `scanner/pipeline/test_scope.py::CnameChain::test_alias_of_an_excluded_name_is_refused`.
- A domain whose name server sits on a non-public address is not queried directly. Test: `scanner/pipeline/test_scope.py::NameserverGate::test_one_private_address_refuses_the_apex`.
- Follow-up fetches go to the address the scanner checked and follow redirects on that host only. Test: `scanner/pipeline/test_verify.py::TestPinnedFetch::test_redirect_to_another_host_is_refused`.
- httpx and nuclei follow redirects on the same host only, and whatweb and wafw00f follow none. Tests: `scanner/tests/shim/driver.py` check "same-host redirects only, private addresses excluded", `scanner/tests/shim/driver.py` check "nuclei: same-host redirects, local network refused", `scanner/tests/shim/driver.py` check "whatweb: redirects off", `scanner/tests/shim/driver.py` check "wafw00f: redirects off (-r)".
- The version watch follows same-host redirects only, at most three from each scheme's `GET /`. Test: `scanner/pipeline/test_version_watch.py::Targets::test_redirects_to_another_host_are_not_followed`.
- Response bodies, requests, cookie values, and authorization headers are not stored by default, and stored text is redacted. Test: `scanner/pipeline/test_no_secret_reaches_storage.py::TestNoSecretReachesStorage::test_minimal`.
- Every page escapes text from scan data, no template marks a value as safe, and every response carries a strict content security policy that forbids inline script and framing. Test: `brain/tests/test_output_safety.py::test_every_page_escapes_hostile_data`.
- URLs from scan data are shown as text, never as links. Test: `brain/tests/test_output_safety.py::test_links_from_scan_data_are_text`.
- The scanner's own report escapes its output and guards spreadsheet cells against formulas. Test: `scanner/pipeline/test_report.py::TestOutputSafety::test_csv_cell`.
- Text from scanned sites reaches the analyst only in a part of each tool result labeled as untrusted, and the analyst cannot act on it (see "A model that follows hostile instructions"). Test: `brain/tests/test_analyst_tools.py::test_text_from_scanned_sites_is_only_in_the_untrusted_part`.
- Host names from the seeder pass the same name gate as every other name. Test: `scanner/pipeline/test_seed_input.py::SeedThroughTheGate::test_gate_drops_excluded_and_out_of_scope_seed_names`.

What it can still do:

- Change a DNS record between the scanner's check and a tool's own lookup, and so send that tool to someone else's public address.
- Return an error page or a firewall block page instead of its normal content, so that a run marks a finding fixed while the issue remains.
- Hide secrets from redaction, or put them where redaction does not look.
- Put misleading text in front of you: on result pages, on the analyst page through a model that obeys it, and in a downloaded HTML report you open from disk.
- If the analyst is on and metadata-only mode is off, get its text, after redaction, sent to the model provider.

The details are in `docs/scope-and-authorization.md` ("What these controls do not stop"), `docs/findings-and-evidence.md` (redaction and the fixed rule), and `docs/analyst.md`.

## A compromised scanner

Suppose an attacker controls the scanner container. They control everything under `published/`: the snapshots and the file that names the current snapshot and its hash, the reports, the job status files, the heartbeat, the scope status, the held-back list, and the version-watch results. They can read the `jobs` folder, which holds the scope, the ownership statements, the approvals, and the account names in them. They cannot write it.

What the design stops, and the test that shows it:

- The scanner mounts the `jobs` folder read-only (`compose.yaml`). No automated test checks this mount.
- The scanner and the brain share no network. In normal mode the brain's port is published on host loopback; in lab mode the brain has no published port and the browser bridge publishes to loopback only. Tests: `tests/e2e/run_demo_ui.sh` checks "the brain and the scanner share no network" and "the lab web UI is published only on the host loopback address".
- After start-up, every scanner process runs without capabilities and cannot list or change the firewall. Test: `tests/e2e/run_demo.sh` check "after the drop, a scanner process cannot change the rules".
- A snapshot whose bytes do not match its recorded SHA-256 hash is refused, and snapshots are opened read-only. Test: `brain/tests/test_snapshot.py::test_hash_mismatch_is_refused`.
- A snapshot that holds a view, a trigger, a virtual table, a generated column, or an unexpected table shape is refused, and the refusal is remembered. Test: `brain/tests/test_snapshot_safety.py::test_recursive_view_named_as_a_table_the_brain_reads_is_refused`.
- Every request's snapshot queries stop at a deadline (`MOMUS_SNAPSHOT_QUERY_SECONDS`, default 2), the page says so, and the next request is served. Test: `brain/tests/test_snapshot_safety.py::test_a_slow_query_gives_an_error_page_and_the_next_request_is_served`.
- A snapshot over the size cap (`MOMUS_SNAPSHOT_MAX_MB`, default 512) is refused. Test: `brain/tests/test_snapshot_safety.py::test_snapshot_size_cap`.
- Reads of the published folder are bounded: entries looked at per folder, status files read, and bytes per file. Test: `brain/tests/test_bounded_reads.py::test_thousands_of_status_files_are_capped_before_reading`.
- Text from the heartbeat that reaches the audit log is cleaned first. Test: `brain/tests/test_job_file_cleanup.py::test_every_audit_detail_passes_through_clean`.
- Lab mode and the lab address range come only from the brain's own settings, never from the scanner's heartbeat. Test: `brain/tests/test_small_items.py::test_lab_mode_comes_only_from_the_brain_setting`.
- A heartbeat that is stale or dated in the future does not block queueing. Test: `brain/tests/test_bounded_reads.py::test_only_a_fresh_busy_heartbeat_blocks_queueing`.
- The held-back and scope-status files are read strictly: names must parse, and an unknown code is shown as unknown. Test: `brain/tests/test_bounded_reads.py::test_held_back_is_read_strictly`.
- Reports download as attachments, streamed in chunks, under a sandboxing content security policy. Test: `brain/tests/test_bounded_reads.py::test_a_very_large_report_is_streamed_in_chunks`.
- Links are built only from values that fully match strict patterns. Test: `brain/tests/test_small_items.py::test_links_are_built_only_from_strict_values`.

What it can still do:

- Show anything as results: fake findings, hidden real findings, misleading text. The snapshot's hash lets the brain detect a copy that differs from what was published; it cannot tell whether what was published is honest.
- Make every page wait up to the query deadline, and make the brain copy and hash a new snapshot file up to the size cap each time it publishes one.
- Make a page use memory and time beyond the query deadline with one very large value. The deadline stops SQLite's work only; a single cell up to the size cap (for example a finding's evidence) is then decoded and formatted in Python, which the deadline does not stop, and the brain's container has no memory limit.
- Block queueing, and block "mark abandoned" for a job, by claiming in a fresh heartbeat that it is busy with that job.
- Misreport which domains are verified and which hosts are held back.
- Learn the account names written into job files.
- Within the egress firewall, send whatever traffic it likes to public addresses.

## A person on the network who is not signed in

This attacker can send requests to the brain's port, with any username, password, headers (including `X-Forwarded-For`) and any source address they control. By default the port is published on `127.0.0.1` only, so this attacker must already be on the host or reach it through a proxy you set up. In lab mode the browser bridge is the only published port; it binds to `127.0.0.1` and forwards to the internal brain. Docker Engine 28.0.0 or newer is needed for that localhost-only boundary on the host network.

What the design stops, and the test that shows it:

- Every route except sign-in, first-account set-up, and static files needs a session. Test: `brain/tests/test_auth.py::test_every_route_except_login_and_bootstrap_needs_a_session`.
- Every state-changing request needs an allowed `Origin` and an anti-forgery token, the sign-in form included. Tests: `brain/tests/test_csrf.py::test_state_changing_requests_need_token_and_origin`, `brain/tests/test_csrf.py::test_login_needs_pre_session_token_and_origin`.
- Passwords are hashed with scrypt. Test: `brain/tests/test_auth.py::test_password_hash_is_scrypt`.
- After `MOMUS_LOGIN_MAX_FAILURES` failures for a username (default 5), or twice that from one address, every further attempt waits: 15 seconds after the last failure, doubling to `MOMUS_LOGIN_MAX_DELAY_SECONDS` (default 300). Failures count for 24 hours. A refused attempt writes nothing and does not extend the wait. Test: `brain/tests/test_login_limits.py::test_thousands_of_attempts_against_a_delayed_account_add_no_rows`.
- Unknown usernames are counted and delayed by the same rules as real ones, with the one exception listed below. Test: `brain/tests/test_login_limits.py::test_unknown_usernames_are_limited_the_same_way`.
- A parallel burst of attempts gets no more guesses than the limit. Test: `brain/tests/test_login_limits.py::test_a_parallel_burst_gets_no_more_guesses_than_the_limit`.
- `X-Forwarded-For` is ignored unless the connection comes from the one address set in `MOMUS_TRUSTED_PROXY` (off by default), and the per-username delay cannot be dodged by changing it. Tests: `brain/tests/test_auth.py::test_forwarded_for_is_ignored_by_default`, `brain/tests/test_login_limits.py::test_the_account_delay_cannot_be_dodged_by_changing_the_forwarded_address`.
- An unknown username is checked against a dummy password hash, so it costs one hash like a real one. Test: `brain/tests/test_signin_limits.py::test_the_dummy_hash_is_built_at_start_so_the_first_unknown_name_takes_one_hash`.
- An IPv6 client is counted by its /64 network for the limits. Test: `brain/tests/test_signin_limits.py::test_ipv6_clients_are_counted_by_their_64_in_the_limits_only`.
- The sign-in and first-account posts must state a `Content-Length` of at most 16 KiB before the body is read. Test: `brain/tests/test_signin_limits.py::test_public_posts_without_a_small_content_length_are_refused_before_the_body_is_read`.
- The first-account token is random, stored only as a hash, and works once; the set-up page closes once an account exists. Test: `brain/tests/test_auth.py::test_bootstrap_token_works_once`.
- A redirect after sign-in stays on the site. Test: `brain/tests/test_auth.py::test_open_redirect_refused`.
- Session cookies are `HttpOnly` and `SameSite=Strict`. Test: `brain/tests/test_auth.py::test_session_cookie_flags`.
- Only a hash of the session token is stored. Test: `brain/tests/test_auth.py::test_session_token_stored_hashed`.
- A session ends after a period without requests and after a fixed lifetime. Tests: `brain/tests/test_auth.py::test_idle_timeout`, `brain/tests/test_auth.py::test_absolute_timeout`.

What it can still do:

- Guess passwords slowly. The defense is a long password (at least 12 characters by default).
- Keep a username at its failure limit, and so keep that account waiting for as long as they keep retrying.
- Tell a real username from an unknown one in one narrow case: while it holds a username at its failure limit, it sees the effect of the owner's own failed attempts on that name.
- Flood sign-in from many addresses, so that real sign-ins are told the server is busy for as long as the flood lasts.
- Delay sign-in for everyone who shares its address.
- Send a signed-in user a link that makes a page show one of the application's own status sentences, with an identifier or host name of its choosing in it.

## A signed-in user

Every account is an administrator. A signed-in user can change the scope, make ownership statements, approve inventories, queue jobs, set schedules and version watches, mark findings, create accounts, and use the analyst if one is configured. The design does not protect an install from an administrator acting in bad faith. It makes their actions visible and keeps scans tied to domains whose ownership has been proven.

What the design stops, and the test that shows it:

- Each action writes one entry to the audit log, under the signed-in user's name. Tests: `brain/tests/test_audit_db.py::test_each_action_writes_exactly_one_entry`, `brain/tests/test_login_limits.py::test_no_audit_call_takes_its_actor_from_typed_input`.
- The audit log is append-only: the database refuses updates and deletes. Test: `brain/tests/test_audit_db.py::test_audit_log_is_append_only`.
- A domain cannot be queued without the ownership statement, and the scanner scans only domains whose DNS proof record holds. A job cannot supply the proof token. Tests: `brain/tests/test_jobs.py::test_domain_without_ownership_statement_cannot_be_queued`, `scanner/pipeline/test_scope.py::Tokens::test_token_copied_from_another_install_does_not_verify`.
- Active checks need an approved inventory that covered the job's domains. Test: `scanner/pipeline/test_scope.py::Approval::test_approval_naming_another_domains_inventory_is_refused`.
- The five names the application uses for its own audit entries cannot be taken as account names. Test: `brain/tests/test_signin_limits.py::test_actor_names_cannot_be_taken_as_accounts`.
- Lab targets are refused outside lab mode. Test: `brain/tests/test_jobs.py::test_lab_targets_refused_outside_lab_mode`.
- A mark never changes a score, count, verdict, or status, and goes stale when the finding's evidence changes. Tests: `brain/tests/test_marks.py::test_mark_never_changes_counts_by_band`, `brain/tests/test_marks.py::test_changed_evidence_makes_mark_stale`.
- The analyst sends nothing until an administrator confirms a statement of what goes to which provider, and asks again whenever that statement changes. Test: `brain/tests/test_analyst_consent.py::test_a_changed_provider_or_setting_asks_again`.
- The provider key never appears in a log, a page, a database row, or the API. Test: `brain/tests/test_analyst_consent.py::test_no_key_appears_in_logs_pages_rows_or_api`.
- The recovery commands (reset a password, clear sign-in delays) run on the host, through `docker compose exec`, and read a new password from standard input. No web route reaches them. Test: `brain/tests/test_admin_tool.py::test_the_real_invocation_reads_the_password_from_standard_input`.

What it can still do:

- Anything an administrator is meant to do.
- Create an account whose name only looks like one of the application's own audit names.
- Send other users status-banner links as described above.

## A model that follows hostile instructions

Assume the model the analyst uses does whatever a scanned site's text tells it to. It then controls every answer: which tools it calls and with what arguments, the brief, chat answers, proposals and their reasons, and the references it gives. `docs/analyst.md` covers this attacker in full.

What the design stops, and the test that shows it:

- The analyst's tools are a fixed, read-only list. No tool writes anything, reaches the network or a shell, or opens a file of its choosing. The only files they read are the published snapshot and the published version-watch result files, through the brain's bounded readers; the version-watch tool also reads the list of defined watches from the application's records. Tests: `brain/tests/test_analyst_tools.py::test_the_registry_is_exactly_the_read_only_tool_list`, `brain/tests/test_analyst_tools.py::test_every_tool_is_read_only_against_the_databases_and_files`.
- A test model that obeys every instruction it reads stays within these bounds. Test: `brain/tests/test_analyst_susceptible.py::test_the_obedient_model_stays_bounded`.
- A proposal stays pending until a person accepts it on its own page, and each run may make only a limited number (`MOMUS_ANALYST_MAX_PROPOSALS`, default 10). Test: `brain/tests/test_analyst_proposals.py::test_the_cap_on_proposals_per_run`.
- A reference to a finding, host, or run that is not in the run's snapshot is dropped, and the drop is recorded. Test: `brain/tests/test_analyst_proposals.py::test_fabricated_keys_hosts_and_runs_are_dropped_and_recorded`.
- The model's text is shown as escaped plain text, and its references as text, never as links. Test: `brain/tests/test_analyst_pages.py::test_model_text_is_plain_escaped_text`.
- Every count shown as fact is computed by the application; the model's answer format has no field for a number. Test: `brain/tests/test_analyst_pages.py::test_wrong_counts_from_the_model_cannot_change_any_count_shown`.
- Accepting a proposal is bound to the evidence and the snapshot the page showed. Test: `brain/tests/test_accept_binding.py::test_an_accept_from_a_page_of_an_older_snapshot_is_refused_and_works_after_a_new_look`.
- A redirect answer from a provider is not followed, so the key goes nowhere else. Test: `brain/tests/test_analyst_sdk_env.py::test_a_redirect_answer_is_not_followed`.
- A note the model proposes reaches later runs only after a person accepts it. Test: `brain/tests/test_analyst_proposals.py::test_a_note_is_memory_only_after_a_person_accepts_it`.
- Steps, tokens, time, and invalid answers are limited per run and per day. Test: `brain/tests/test_analyst_loop.py::test_each_limit`.

What it can still do:

- Put wrong or misleading text on the analyst page, labeled as the model's.
- Fill the proposal queue with bad proposals, up to the per-run limit. The warning that a text "reads like instructions" is a hint from a word list, not a control.
- Repeat anything it read, including text redaction missed, into answers that are sent back to the provider.
- Spend the run's budget, which may run over by part of one request.

## A hostile or careless job writer

Whoever can write a file into the `jobs` folder controls a job: normally the brain, also the developer tool `scanner/jobctl.py`, and anyone with access to that volume. The scanner treats every job file as untrusted input.

What the design stops, and the test that shows it:

- A job file is opened without following links or blocking. It must be a regular file of at most 1 MiB, checked before it is read. Test: `scanner/pipeline/test_runner.py::JobFiles::test_symlink_fifo_and_dot_files`.
- Deeply nested, invalid, or duplicate-key JSON is rejected without stopping the job runner. Tests: `scanner/pipeline/test_runner.py::Hostile::test_deeply_nested_arrays_and_objects`, `tests/e2e/run_demo.sh` check "the runner was not restarted by the nested file".
- Unknown fields, malformed ids and names, and oversized lists are rejected, and a rejection reason never repeats the offending value. Tests: `scanner/pipeline/test_runner.py::Validation::test_unknown_fields`, `tests/e2e/run_demo.sh` check "no rejection reason echoes the offending value".
- A job cannot supply a DNS proof token or set a domain's verification state. Tests: `scanner/pipeline/test_runner.py::Validation::test_token_anywhere_in_ownership_is_rejected`, `scanner/pipeline/test_runner.py::Validation::test_cannot_set_verification_state`.
- An approval must name a finished inventory of the job's own targets. Test: `tests/e2e/run_demo.sh` check "a full job whose approval names an inventory of other targets is rejected".
- Lab fields are refused unless the scanner was started in lab mode. Test: `tests/e2e/run_demo.sh` check "lab fields without lab mode: the job is rejected".
- The brain refuses to write a job larger than the scanner reads, and deletes only its own job files, by validated name, without following links. Tests: `brain/tests/test_signin_flood_and_job_document.py::test_a_job_larger_than_the_scanner_accepts_is_refused_before_anything_is_written`, `brain/tests/test_job_file_cleanup.py::test_removal_never_follows_a_link_and_skips_names_that_are_not_job_ids`.
- A job must carry its creation time. One older than `SCAN_JOB_MAX_AGE_HOURS` (default 72) or more than five minutes in the future is refused without running. Test: `scanner/pipeline/test_runner.py::FinishedJobs::test_a_job_older_than_the_age_limit_is_refused_before_any_scope_is_written`.
- A finished job id never runs again, even if its published status is lost; the scanner keeps that record in its own volume. Test: `scanner/pipeline/test_runner.py::FinishedJobs::test_the_record_is_kept_in_the_private_state_folder`.
- A job marked abandoned is never run. Test: `scanner/pipeline/test_runner.py::Hostile::test_an_abandoned_job_id_is_never_run`.
- A version watch can carry only an id, a name, a product from a fixed table, CVE ids, version floors, and host names: no pattern, header, path, or URL. Test: `scanner/pipeline/test_version_watch.py::WatchRules::test_no_field_can_carry_a_pattern_path_or_url`.

What it can still do:

- Replace the scope. Every job carries the full scope and replaces the scanner's current one, so a wrong scope changes what is verified and scanned, always within the DNS proof.
- Queue many valid jobs. The scanner runs one at a time.
- Put more than 1,000 files in the `jobs` folder. The brain then treats the scanner as busy and refuses to queue (it fails closed).
- Rely on an old approval, which does not expire.

## Out of scope

- **Anyone with Docker access or root on the host.** They control every container and volume. For example, `docker exec -u 0` into the scanner gets its start-up capabilities and can change the firewall, and anyone who can read the scanner's data volume can read the install secret.
- **An administrator acting in bad faith.** Every account is an administrator; the audit log records what each one does.
- **The scan targets' own security.** Momus reports what it finds; it does not protect the sites it scans.
- **The model provider and the services listed in `docs/data-flows.md`.** What they do with data sent to them is governed by their own terms.
- **The cloud deployment examples** under `deploy/`, beyond what their READMEs state.
