# Roadmap

This page lists the work planned after 0.1.0, why each item is on the list, and what "done" means for it. It is a plan, not a promise: nothing here is built until the [changelog](../CHANGELOG.md) says so. Items marked **decision open** wait on a choice by the maintainer; comments on them are welcome in an issue.

The one rule does not change: only the scanner sends packets to targets, and the two containers share no network. One item below (vulnerability lookups) gives the brain a second, optional outbound connection. It is called out where it appears.

## Summary

| # | Item | What changes for a user | Depends on |
|---|---|---|---|
| 1 | [Interface rework](#1-interface-rework) | Pages are easier to read: one type scale, consistent spacing, compact controls, calmer tables | none |
| 2 | [In-app documentation pages](#2-in-app-documentation-pages) | The data flows page shows the diagram and laid-out tables instead of a raw text file | 1 |
| 3 | [Live run view](#3-live-run-view) | While a job runs, you can see the phase, the tool, and its progress, as an animated view with a text equivalent | 1 |
| 4 | [Vulnerability lookups for version watch](#4-vulnerability-lookups-for-version-watch) | Version watch lists the CVEs that affect the versions it reads, instead of only comparing against floors you type in | none |
| 5 | [Test and security tooling](#5-test-and-security-tooling) | Nothing visible; fewer defects reach a release | none |

Items 1, 4, and 5 can start independently. Items 2 and 3 build on the tokens and components of item 1.

## 1. Interface rework

**Problem.** Pages carry too much text at too many sizes. Tables are wide and dense, most of all on Assets. Dropdowns and form rows are tight. Helper paragraphs repeat what the documentation says. The result is hard to scan when the pages hold real data.

**Plan.**

- **Design tokens.** One set of CSS variables for type, spacing, color, and radius, used everywhere; no one-off values in page rules.
- **Type.** System fonts only (no web fonts). A small scale of about six sizes and two weights, with one fixed use for each step: page title, section heading, body, table cell, label, helper text.
- **Spacing.** One spacing scale. The same padding for every card, the same gap between sections, the same gap between a label and its control.
- **Controls.** Inputs, selects, and buttons share one height, padding, border, and focus ring. Selects keep the native arrow.
- **Tables.** Sticky header, no zebra striping, one separator line per row, numbers right-aligned in tabular figures. Long values are cut with an ellipsis and shown in full on the detail page. A row opens its detail page.
- **Assets page.** Fewer columns by default: host, class, addresses, web server, open findings. Everything else moves to the asset's own page. Filters sit in one row above the table.
- **Text.** One short sentence of helper text per section at most, with a link to the documentation for the rest. Empty states are one sentence.
- **Status lines.** Red is used only for an error. A job in progress is shown as a neutral status (already changed on the Runs page, unreleased).

**Constraints kept.** The content security policy stays `script-src 'self'; style-src 'self'`, so there are no inline styles or scripts. No CSS framework, no build step, no new dependency. Light and dark themes both.

**Done means.** Every page uses the tokens; no page rule sets a raw font size or spacing value. The existing tests pass with their wording updated where a page's text changed. Browser tests (item 5) cover Assets, Scope, and Runs at desktop and narrow widths in both themes.

## 2. In-app documentation pages

**Problem.** The three help pages inside the brain (data flows, version watch, the analyst) show the repository's Markdown file as plain text. The data flow diagram in [docs/diagrams](diagrams/README.md) is never shown in the app.

**Plan.**

- Render the pages as HTML: headings, paragraphs, lists, tables, code, and links. The renderer is a small one in this repository that escapes everything and supports only that subset, so there is no new dependency and no raw HTML passes through.
- The data flows page opens with the data flow diagram (the dark or light export, matching the theme), then the numbered flows, then the tables of what is sent to whom and how to turn each flow off.
- The Markdown files stay the single source. The pages are built from them, so the app and the repository cannot drift apart.

**Done means.** No page shows Markdown syntax. A test renders each page from its source file and checks that tables, links, and the diagram are present, and that hostile text in a source file is escaped.

## 3. Live run view

**Problem.** While a job runs, the Runs page shows one phase name, such as `recon:5-fingerprint`. It does not show which tool is running, how far along it is, or what the job has found so far.

**What exists today.** The scanner writes a status file per job with a phase and a timestamp. Inside the scanner, the run folder already holds the phase timeline, per-tool progress lines, and the target lists, but none of that is published to the brain.

**Plan.**

- **Scanner: a `progress` object in the status file.** For each phase: its name, state (waiting, running, done, skipped, failed), start and end time, the tool now running, and counts such as hosts found, hosts resolved, hosts answering, port-scan bursts done out of total, and template passes done out of total. Numbers, fixed phase names, and tool names only.
- **Brain: a live page for a run.** One lane per phase in order, with the tool and counts beside it, updated by polling. The phases that do not apply to a job type (for example the active phases of an inventory) are shown as skipped, with the reason.
- **Sprites.** Each phase has a small animated figure, drawn as inline SVG and animated by a script served from the brain itself. No image files and no library. The figure is decoration: every state is also shown as text, the motion stops when the browser asks for reduced motion, and a control on the page turns it off.
- **Per-domain and per-host progress. Decision open.** The status file's rule today is that it "never holds job content or text taken from a scan target". Showing which domain or host a tool is working on needs host names in the status file. Host names are already published elsewhere (the held-back list, the scope status), so this is a documented exception rather than a new kind of data, but it changes a stated rule and needs a threat-model entry. The first version ships with counts per domain; host names follow once that entry is written.

**Done means.** The job format and published-layout references describe the `progress` object, and the brain validates it as strictly as every other published field (size cap, known keys, numbers clamped). The live page works with scripts disabled as a plain table. A full lab run in the end-to-end test shows each phase move from waiting to done.

## 4. Vulnerability lookups for version watch

**Problem.** A version watch compares the version a host advertises with floors that you look up and type in yourself. It does not tell you which CVEs affect that version.

**Plan.**

- **Lookups against the National Vulnerability Database (NVD).** For each product and version that version watch reads, the brain asks the NVD API which CVEs affect it, and shows them with their severity scores, publication dates, and whether CISA lists them as known to be exploited.
- **Floors stay.** A floor you set remains the verdict rule, because vendors backport fixes and a version number alone can mislead. Lookups add the list of candidate CVEs beside each verdict and suggest floors; they do not replace your judgment. A version below no floor but with CVEs listed is shown as "review", not as a failure.
- **Products.** First the four products version watch reads today (PHP, nginx, Apache HTTP Server, OpenSSL), mapped to the product names NVD uses. Then, as a second step, the components the scan itself detects, where the scan recorded a version.

**The new outbound connection.** This is a change to what leaves the machine, so it follows the same pattern as the analyst:

- **Off by default.** With the setting unset, the brain makes no request to NVD.
- **What is sent:** a product name and a version number, or a CVE id. **Never** a host name, a domain, an address, or anything read from a target beyond that strictly parsed version.
- **What NVD learns:** that an install at your address runs or is interested in those product versions.
- **Confirmed by a person.** As with the analyst, an administrator confirms a plain statement of what will be sent before the first request, and the confirmation is recorded in the audit log.
- **One fixed destination,** no redirects followed, a response size cap, a timeout, and the same optional egress proxy setting the analyst uses.
- **Cached** in the app database and refreshed on a schedule, within NVD's published rate limits, with an optional API key held as a Docker secret.
- **Documented** in [data flows](data-flows.md), the [threat model](threat-model.md), and the Compose file's network comments, with the attribution notice NVD asks of products that use its API.

**To verify during the build.** The request parameters and rate limits will be confirmed against NVD's own documentation before any code depends on them; the response format and the product names have been checked against live responses.

**Alternatives considered.** Running the lookups in the scanner keeps the brain offline but mixes reference-data requests with scan traffic. Downloading NVD's full data feed into the install sends nothing per version, at the cost of a large download and data only as fresh as the last update. The feed remains a possible later option for installs that want no per-version requests.

**Done means.** With the setting off, the test suite proves no connection is attempted. With it on, tests against recorded responses cover matching, version ranges, rate limiting, a failed or malformed response, and the cache. The version-watch documentation explains what a listed CVE does and does not prove.

## 5. Test and security tooling

**Problem.** A defect in 0.1.0 (the Scope page did not show a new domain's DNS record until reloaded) passed every test, because the interface tests drive the pages over HTTP and never run them in a browser. The repository also has no static analysis of its own code and no dynamic scan of its own web application.

**Plan.**

- **Browser tests.** A browser-driven suite against the lab stack, starting with the flows a person follows: first account, add a domain and see its record appear, queue an inventory, approve it, read a finding. Run at desktop and narrow widths, in light and dark themes.
- **Static analysis.** CodeQL and Bandit on the Python code, `shellcheck` on every shell script, and a linter on the Dockerfiles.
- **Dynamic scan.** A baseline web scan of the lab brain in continuous integration, with each accepted alert listed and explained in the repository.
- **Dependencies and images.** A vulnerability scan of the pinned Python dependencies and of the three built images, alongside the existing Dependabot configuration.

**Constraints kept.** Every action and tool is pinned by commit hash or digest. The workflow keeps read-only permissions and uses no secret. Test-only tools never enter the runtime images.

**Done means.** Each check runs on every pull request, fails the run on a new finding, and has a documented way to record an accepted exception with its reason.

## Decisions open

- **Host names in live progress** (item 3).
- **Scope of vulnerability lookups** (item 4): the four version-watch products only, or also every component the scan detects.

## Not planned

- Authenticated scanning, agent-based scanning, or scanning of systems that have not passed the DNS proof.
- Automatic acceptance of anything the analyst proposes.
- A hosted service. Momus stays self-hosted.

## Contributing

The plan for an item is settled in an issue before code is written, because most items touch a documented guarantee. See [contributing](../CONTRIBUTING.md), and report security problems through the [security policy](../SECURITY.md), not a public issue.
