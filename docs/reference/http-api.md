# Brain HTTP API

The brain serves a JSON API under `/api/v1/` with the same accounts, sessions, and data as its web pages. This page
lists every route, how a client signs in, the anti-forgery rules, request bodies, response shapes, status codes, and
error forms, for anyone who writes a script or client against the brain. The routes are defined in
`brain/app/api.py`, `brain/app/jobs.py` (`register_api`), and `brain/app/analyst/web.py`.

## Signing in and the session

There is no API sign-in route and no API key. A client signs in through the same form a browser uses, keeps the
session cookie, and reads the anti-forgery token from the API:

1. `GET /login`. The response sets the pre-session cookie (`momus_pre`) and contains a form whose hidden field `csrf`
   holds the same value.
2. `POST /login` as `application/x-www-form-urlencoded` with the fields `username`, `password`, `next` (a local path
   such as `/`), and `csrf` (the value from the `GET /login` answer), sending the `momus_pre` cookie, an `Origin` header from
   `MOMUS_ALLOWED_ORIGINS`, and a `Content-Length` header of at most 16 KiB (no `Transfer-Encoding`). On success the
   answer is a `303` redirect that sets the session cookie `momus_session`. A wrong name or password gives `400`, too
   many failures give `429`, and a sign-in refused because the server is busy hashing gives `503`; each of these
   answers is an HTML page.
3. `GET /api/v1/me` with the session cookie. The answer holds `csrf_token`, the session's anti-forgery token.
4. Send the session cookie with every request, and with every state-changing request also the headers
   `X-CSRF-Token: <csrf_token>` and `Origin: <an allowed origin>`.

| Item | Value |
|---|---|
| Session cookie | `momus_session`; `__Host-momus_session` when `MOMUS_COOKIE_SECURE=1` |
| Pre-session cookie (sign-in form only) | `momus_pre`; `__Host-momus_pre` when `MOMUS_COOKIE_SECURE=1` |
| Cookie flags | `HttpOnly`, `SameSite=Strict`, `Path=/`, and `Secure` when `MOMUS_COOKIE_SECURE=1` |
| Idle timeout | `MOMUS_SESSION_IDLE_MINUTES`, default 30 (5 to 1,440) |
| Absolute lifetime | `MOMUS_SESSION_MAX_HOURS`, default 12 (1 to 168) |
| Anti-forgery token | one random token per session, returned by `GET /api/v1/me` as `csrf_token` |
| Sign out | `POST /logout` (a page route) with the token and an allowed `Origin`; changing the password signs out every other session |

The brain stores only a hash of the session token. An expired session is deleted when it is next presented. Every
account has the role `admin`; the API has no finer permissions, so any signed-in account can call every route.

## Rules for every request

These are enforced for every path, in this order:

1. **Origin.** Every request whose method is not `GET` or `HEAD` must carry an `Origin` header that equals one of
   `MOMUS_ALLOWED_ORIGINS` (compared without case and without a trailing `/`; default `http://127.0.0.1:8080` and
   `http://localhost:8080`). Without an `Origin` header, the scheme, host, and port of the `Referer` header are used
   instead. Otherwise: `403`.
2. **Session.** Every path except `/login`, `/bootstrap`, and `/static/` needs a valid session cookie. Otherwise, under
   `/api/`: `401` with `{"error": "sign in first"}`.
3. **Anti-forgery token.** Every request whose method is not `GET` or `HEAD` must carry the session's token, in the
   `X-CSRF-Token` header (or, for a form-encoded or multipart body, in a form field named `csrf`). Otherwise: `403`.

API requests with a body send JSON (`Content-Type: application/json`).

## Responses and errors

- **Success.** A JSON object, written compactly, with `<`, `>`, and `&` written as the JSON escapes `\u003c`, `\u003e`, and
  `\u0026`, so no response holds a live HTML tag. Every response has `Cache-Control: no-store` and the brain's security headers
  (`Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and others).
- **Errors.** Every error under `/api/` is `{"error": "<fixed text>"}`. Error texts never repeat what the client sent.

| Status | When | `error` |
|---|---|---|
| `400` | the request was understood but refused (route-specific text in the tables below) | a fixed sentence |
| `401` | no valid session | `sign in first` |
| `403` | `Origin` (or `Referer`) not allowed | `Cross-site request refused: the Origin is not one of this instance's addresses.` |
| `403` | anti-forgery token missing or wrong | `The anti-forgery token is missing or wrong. Reload the page and try again.` |
| `404` | the object does not exist (route-specific), or an unknown path after sign-in | a fixed sentence, or `Not Found` |
| `409` | the action conflicts with the current state (a job is in flight, a proposal was already decided, and so on) | a fixed sentence |
| `422` | a body, path, or query value is missing, has the wrong type, or is out of range | `The request had a missing or invalid value.` |
| `500` | an unexpected server error (its type is logged, nothing else) | `Something went wrong on the server. The error was logged (type only).` |
| `503` | a query on the scan snapshot ran past `MOMUS_SNAPSHOT_QUERY_SECONDS` | `Reading the scan snapshot took longer than <n> seconds, so this request was stopped. ...` |

Read routes that depend on the scan snapshot return a `snapshot` object (`state`, `message`, `run_id`, `created_at`,
`sha256`, `folder`). When there is no usable snapshot, `state` says why (`missing`, `empty`, `none`, `bad-pointer`,
`mismatch`, `too-large`, `refused`, or `unreadable`) and the lists are empty.

## Path parameters

| Parameter | Rule (a value that fails gives `422`) |
|---|---|
| `{key}` (finding key) | `[0-9a-f]{8,64}` |
| `{host}` | `[a-z0-9_.-]{1,253}` |
| `{watch_id}` | `[a-z0-9][a-z0-9-]{0,30}[a-z0-9]` |
| `{agent_run_id}`, `{proposal_id}` | an integer from 1 to 10^12 |

## Routes

The tables list every route. "Body" fields are JSON keys; a field marked optional may be left out. In the Response
column, braces with bare names (such as `{"ok": true, "job_id", "type"}`) list the keys of the response object; they
are not literal JSON. Every route needs a
session; every `POST` also needs `Origin` and `X-CSRF-Token`.

### Account and instance

| Method and path | Body | Response | Route errors |
|---|---|---|---|
| `GET /api/v1/me` | | `{"username", "role", "csrf_token"}` | |
| `GET /api/v1/settings` | | `{"instance": {...}, "analyst": {...}, "sessions": [...]}`. `instance`: the configuration (folders, allowed origins, cookie and session settings, sign-in limits, snapshot limits, trusted proxy, scheduler, lab mode, schema version, folder states, model provider and model). `analyst`: the analyst's configuration, today's usage, the data statement, and its confirmation. `sessions`: this account's sessions, each `{"created_at", "last_seen_at", "address", "user_agent", "id"}`, newest first. | |
| `POST /api/v1/settings/password` | `current` (string, at most 1,024), `new` (string, at most 1,024) | `{"ok": true, "other_sessions_signed_out": <n>}` | `400` wrong current password or the new one breaks the rules |
| `POST /api/v1/settings/accounts` | `username` (1 to 64 characters), `password` (at most 1,024) | `{"ok": true}` | `400` invalid, reserved, or taken name, or a password that breaks the rules |
| `POST /api/v1/settings/sessions/revoke` | `session_id` (exactly 16 characters: an `id` from `GET /api/v1/settings`) | `{"ok": true}` | `400` `Unknown session.` |
| `GET /api/v1/audit` | query: `action` (an audit action name; any other value is ignored), `actor` and `q` (text, first 100 characters used), `before` (integer, at least 1) | `{"entries": [{"id", "at", "actor", "action", "target", "detail", "address"}], "next_before"}`: at most 200 entries, newest first. Pass `next_before` as `before` for older ones; it is `null` on the last page. | |
| `GET /api/v1/openapi.json` | | the OpenAPI document of these routes (request bodies and parameters; it describes no response shapes) | |

### Findings, assets, and domains (from the scan snapshot)

| Method and path | Body or query | Response | Route errors |
|---|---|---|---|
| `GET /api/v1/overview` | | `{"snapshot", "scanner", "counts", "latest", "trend", "top"}`: open findings per band, the latest scored run's summary, the last 20 scored run summaries (the latest included), the top three open findings with their marks, and the scanner heartbeat with `age_seconds` and `stale` | |
| `GET /api/v1/findings` | query: `band` (`Critical`, `High`, `Medium`, `Low`, `Info`), `state` (`open`, `fixed`, `new`, `reopened`, `persistent`), `domain`, `class`, `source` (`dns`, `http`, `nmap`, `sslscan`, `nuclei`), `marked` (`any`, `marked`, `unmarked`), `sort` (`priority` (default), `score`, `host`, `title`, `first_seen`, `last_seen`, `source`), `page` (integer, clamped to 1 to 10,000). An unknown `band`, `state`, or `source` is ignored. | `{"snapshot", "rows", "total", "facets": {"domains", "classes"}, "filters"}`; 100 rows per page, each with its current `mark` | `422` for a `marked` or `sort` value outside the list |
| `GET /api/v1/findings/{key}` | query: `hist_page` (1 to 10,000) | `{"finding", "description", "remediation", "matched", "verification", "tags", "references", "score", "evidence_text", "triage", "history", "history_page", "history_more", "evidence_fp", "mark", "mark_history"}` | `404` `No such finding in the current snapshot.` |
| `POST /api/v1/findings/{key}/mark` | `kind` (`false_positive`, `accepted_risk`, `duplicate`), `reason` (3 to 2,000 characters), `evidence_fp` (1 to 64 characters: the `evidence_fp` from `GET /api/v1/findings/{key}`) | `{"ok": true}` | `400`, for example `The evidence changed since this page was shown. Nothing was saved: review the finding again.` A mark never changes a finding's score, verdict, or status. |
| `POST /api/v1/findings/{key}/unmark` | none | `{"ok": true}` | `400` `That finding has no mark.` |
| `GET /api/v1/assets` | | `{"snapshot", "run_id", "rows"}`: the inventory of the latest run with assets | |
| `GET /api/v1/assets/{host}` | query: `cert_page`, `tls_page` (1 to 10,000) | `{"run_id", "asset", "profile", "components", "certificates", "certificates_page", "certificates_more", "tls", "tls_page", "tls_more", "ports", "endpoints", "dns", "findings"}` | `404` `No such host in the current snapshot.` |
| `GET /api/v1/domains` | | `{"snapshot", "run_id", "rows"}`: email and DNS posture per domain | |

### Runs and jobs

| Method and path | Body or query | Response | Route errors |
|---|---|---|---|
| `GET /api/v1/runs` | query: `runs_page`, `jobs_page` (1 to 10,000) | `{"jobs", "jobs_page", "jobs_more", "scan_runs", "runs_page", "runs_more", "snapshot", "scanner", "abandonable", "queue"}`. `jobs`: 50 per page, from the scanner's status files and the brain's own job rows (a job with no status yet has `state` `written` or `abandoned`). `abandonable`: ids that may be marked abandoned. `queue`: `{"ready", "busy", "why", "forms", "lab", "sync_pending"}`. | |
| `POST /api/v1/jobs` | `type` (`inventory`, `full`, `recheck`, `version-watch`, `retention`, `update-templates`, `scope-sync`), `retention_days` (optional, 1 to 3,650, default 30; used by `retention`) | `{"ok": true, "job_id", "type"}` | `409` when the job cannot be queued, for example `A job is in flight (<job id>). The scanner runs one job at a time; queue this after it ends.` |
| `POST /api/v1/jobs/abandon` | `job_id` (2 to 64 characters), `confirm` (boolean; must be `true`) | `{"ok": true, "job_id"}` | `409`, for example when the job already has a final status, the scanner reports it as running, or `confirm` is not `true` |

### Scope

| Method and path | Body | Response | Route errors |
|---|---|---|---|
| `GET /api/v1/scope` | | `{"domains", "scope_status_at", "notice", "exclusions", "owned_ranges", "approved_hosts", "profile", "approval", "approvable", "inventory_run", "inventory", "awaiting", "held_back", "unverified", "snapshot", "scanner", "sync_pending", "lab", "domain_counts"}`. Each domain carries `published`, the scanner's entry from `scope_status.json` (the TXT record and state). | |
| `POST /api/v1/scope/domains` | `name` (1 to 253 characters), `statement` (boolean; must be `true`, confirming the ownership statement), `kind` (optional: `domain` (default) or `lab`, lab mode only) | `{"ok": true, "name", "scope_sync_pending"}`. Adding a domain queues a `scope-sync` job when the scanner is idle; otherwise `scope_sync_pending` is `true` and the job is queued later. | `400` |
| `POST /api/v1/scope/domains/remove` | `name` (1 to 253 characters) | `{"ok": true}` | `400` |
| `POST /api/v1/scope/check-now` | none | `{"ok": true, "job_id"}`: a `scope-sync` job was queued | `409` when it cannot be queued |
| `POST /api/v1/scope/entries` | `kind` (`exclusion`, `range`, `host`), `value` (1 to 300 characters), `action` (optional: `add` (default) or `remove`) | `{"ok": true, "value"}` (the value as stored) | `400` |
| `POST /api/v1/scope/profile` | `check_profile` (`safe`, `active`), `rate_profile` (`low`, `normal`, `fast`), `evidence` (`minimal`, `excerpt`); each optional | `{"ok": true, "changed", "profile"}` | `400` |
| `POST /api/v1/scope/approve` | `inventory_run` (2 to 64 characters: the job id of a finished inventory run in the same mode, lab or not) | `{"ok": true}` | `400` `Not a finished inventory run of this scope (lab mode must match).` |
| `POST /api/v1/scope/approve/withdraw` | none | `{"ok": true}` | `400` `No approval to withdraw.` |

### Schedules

| Method and path | Body | Response | Route errors |
|---|---|---|---|
| `GET /api/v1/schedules` | | `{"rows", "now"}`. Each row: `kind`, `enabled`, `hour`, `minute`, `day_of_month`, `last_slot`, `last_outcome`, `updated_by`, `updated_at`, `next_run` (`null` when disabled). Times are UTC. | |
| `POST /api/v1/schedules` | `kind` (`daily-recheck`, `monthly-full`, `daily-version-watch`), `enabled` (boolean), `hour` (0 to 23), `minute` (0 to 59), `day_of_month` (optional, 1 to 31, default 1; used by `monthly-full` only) | the same shape as `GET /api/v1/schedules` | `400` |

Schedules queue jobs only when the brain runs with `MOMUS_SCHEDULER=1`.

### Version watch

| Method and path | Body | Response | Route errors |
|---|---|---|---|
| `GET /api/v1/version-watch` | | `{"watches", "retired", "folder", "max_watches", "full", "probe", "products"}`. Each watch is its definition plus `product_name`, `floor_texts`, `latest` (`{"date", "generated_at", "job_id", "headline"}` or `null`), and `suspect`. `retired`: result folders of watches that are not defined. | |
| `GET /api/v1/version-watch/{watch_id}` | | `{"id", "watched", "definition", "folder", "result", "suspect", "dates", "probe", "products"}`. `result` is the checked result document described in the version-watch schema reference. | `404` `No such watch, and no published results under that id.` |
| `POST /api/v1/version-watch/watches` | one watch object: `id`, `name`, `product`, `cves`, `floors`, and optional `hosts`, with exactly the rules of `options.watches[]` in the job format reference. Values are not converted: a number sent as a string is refused. | `{"ok": true, "outcome", "watch"}`; `outcome` is `added`, `edited`, or `unchanged`; `watch` is the normalized watch | `400` with a fixed sentence naming the problem, or when 20 watches exist already; `422` when the body is not a JSON object |
| `POST /api/v1/version-watch/watches/{watch_id}/remove` | `confirm` (must be the JSON boolean `true`) | `{"ok": true}`. The published results stay until the scanner's retention removes them. | `400` `Tick the box to confirm the removal.`; `404` `No such watch.` |

### Analyst

| Method and path | Body | Response | Route errors |
|---|---|---|---|
| `GET /api/v1/analyst` | | `{"state", "brief", "pending", "decided", "chats", "runs", "runs_page", "runs_more"}` | |
| `GET /api/v1/analyst/runs/{agent_run_id}` | | the run row plus `outcome_text`, `steps` (at most 200), `proposals`, and `messages` (at most 200) | `404` `No such analyst run.` |
| `GET /api/v1/analyst/proposals/{proposal_id}` | | `{"proposal", "finding", "evidence_changed", "mark", "shown_evidence_fp", "shown_snapshot_sha256", "out_of_date", "run_instruction_warning", "instruction_warning"}` | `404` `No such proposal.` |
| `POST /api/v1/analyst/brief` | none | `{"agent_run_id"}` | `409` when a run cannot start (fixed sentence) |
| `POST /api/v1/analyst/chat` | `question` (1 to 2,000 characters) | `{"agent_run_id"}` | `409` when a run cannot start |
| `POST /api/v1/analyst/proposals/{proposal_id}/decide` | `decision` (`accept`, `reject`, `close`); for `accept` also `evidence_fp` and `snapshot_sha256` (each at most 64 characters): the `shown_evidence_fp` and `shown_snapshot_sha256` from `GET /api/v1/analyst/proposals/{proposal_id}` | `{"outcome"}`: `mark` or `note` (accepted), `rejected`, or `closed` | `409`, for example when the proposal was already decided, is out of date (it can then only be closed), or the evidence or snapshot changed since it was shown |
| `POST /api/v1/settings/analyst/consent` | `confirm` (must be the JSON boolean `true`) | `{"confirmed": true, "statement"}` | `400` when `confirm` is not `true`; `409` when there is no usable model provider to confirm |

### API documentation page

`GET /api/docs` (outside `/api/v1/`, signed-in users only) is an HTML page that lists every route in the OpenAPI
document with its method, path, and one-line summary. It and `/api/v1/openapi.json` are not themselves listed there.

## Example

Queue an inventory job (the origin, cookie, and token values are placeholders):

```
POST /api/v1/jobs HTTP/1.1
Host: 127.0.0.1:8080
Origin: http://127.0.0.1:8080
Cookie: momus_session=<session token>
X-CSRF-Token: <csrf_token from GET /api/v1/me>
Content-Type: application/json

{"type": "inventory"}
```

```json
{"ok": true, "job_id": "inv-20300101-100000-d4e5f6", "type": "inventory"}
```

The same request while another job has no final status:

```json
{"error": "A job is in flight (sync-20300101-090000-a1b2c3). The scanner runs one job at a time; queue this after it ends."}
```
