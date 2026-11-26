# Contributing

Thank you for helping. This page says how to set up, how to run every test suite, the rules every change must keep, and how to make the two most common additions: a product for version watch and a DNS source for the seeder.

Report security problems privately, as [SECURITY.md](SECURITY.md) describes, not in a public issue or pull request. Everyone taking part follows the [code of conduct](CODE_OF_CONDUCT.md).

Issues use the forms in `.github/ISSUE_TEMPLATE/`, and pull requests the template in `.github/pull_request_template.md`. Never paste scan results, host names, addresses, tokens, or keys from a real install into either; reproduce with the lab demo instead.

## Set up

You need:

- Docker with the Compose plugin (the `docker compose` command). Tested with Docker Compose v5.7.0. The Compose files use `env_file` entries with `required: false` (Compose 2.24.0 or newer) and the `!override` and `!reset` merge tags (`!override` needs Compose 2.24.4 or newer), so the minimum is Compose 2.24.4; an older Compose cannot parse them. Every suite except the scanner unit tests and the documentation checks runs in a container.
- Python 3.12 or newer on the host, for the scanner unit tests and the documentation checks. They use the standard library only; install nothing.
- A machine that can spare one fixed private range for the lab: `10.89.47.0/24` (and `10.89.48.0/24` for one end-to-end check). Nothing else on the machine may use it.

Get the source (`git clone https://github.com/mgrofsky/momus.git`) and build the images the suites use:

```sh
docker build -t momus-scanner scanner/
```

The other suites build their own images.

## Run the tests

Run the suites one at a time. The two end-to-end scripts and the lab demo share one fixed lab range, so never run two of them at once.

| Suite | Command | What it covers |
|---|---|---|
| Scanner unit tests | `cd scanner/pipeline && python3 -B -m unittest` | The pipeline, the job runner, scope controls, redaction, scoring, retention, version watch. Standard library only, no network. |
| Scanner shim test | `scanner/tests/run_shim_tests.sh` | `scanner/recon.sh` inside the scanner image with no network, every scan tool replaced by a stand-in that records how it was called. Build `momus-scanner` first. |
| Brain tests | `brain/tests/run_tests.sh` | The web application, sign-in, jobs, the analyst with test providers. Runs in the brain's test image with no network, the repository mounted read-only. |
| Seeder unit tests | `seeder/tests/run_tests.sh` | The seeder's sources and limits. Runs in the seeder image with no network. |
| Seeder container test | `seeder/tests/run_container_test.sh` | The seeder container on an internal Docker network, with its Compose mounts. Needs `momus-scanner`. |
| End-to-end, scanner | `tests/e2e/run_demo.sh` | The lab stack: firewall, jobs, an inventory, approval, a full scan, version watch, and job validation against the demo target, on internal networks only. Cleans up after itself. |
| End-to-end, UI | `tests/e2e/run_demo_ui.sh` | The same lab driven through the brain's web pages, including the analyst with the mock provider. |
| AWS example | see "Checks" in [the AWS example](deploy/aws/README.md) | Static checks of the CloudFormation template, offline. |
| Google Cloud example | `deploy/gcp/test_momus_host.sh` | Static checks of the script; a stand-in `gcloud` must record no call. |
| Documentation | `python3 -B -m unittest discover -s tests/docs` | Every link, path, command, variable, and test name in the documentation exists; `docs/configuration.md` and `.env.example` name exactly the settings the code reads. |

Every suite prints a summary line (`Ran N tests ... OK`, `N passed`, or `SUMMARY: N passed, 0 failed`). A change is ready when all of them pass and the tree holds no `__pycache__`, `.pyc`, or `.pytest_cache`.

## Rules a change must keep

- **The one rule.** Only the scanner sends scan probes to targets, and only the brain talks to a model provider. The optional seeder sends its own DNS traffic (API calls and zone transfers) to the DNS servers its operator configures, and nothing else. The scanner and the brain share no network; they exchange files only. Do not add a network path between them.
- **The scanner uses the Python standard library only.** Its pipeline runs on the host for its unit tests, and its image installs no Python package. Shell scripts call tools that Kali's packages install.
- **No new dependency without discussion.** Open an issue first. The brain's and the seeder's packages are pinned with hashes (`brain/requirements.txt`, `seeder/requirements.txt`) and installed with `--require-hashes`; a new one needs its whole dependency tree pinned the same way, and an entry in [THIRD-PARTY-TOOLS.md](THIRD-PARTY-TOOLS.md) with its license read from the package itself.
- **Every Python call passes `-B`,** so no bytecode cache is written into the tree: `python3 -B ...` in scripts, Dockerfiles, Compose files, and documentation alike.
- **Tests never contact a real host or a model provider.** Use reserved names (`example.test`, `example.com`) and documentation addresses (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`). The exception is a test that needs an address to pass the scanner's global-address check: documentation ranges are not globally routable, so the check refuses them, and such tests use real public addresses (for example `scanner/pipeline/test_scope.py`, `scanner/tests/shim/driver.py`, and `brain/tests/test_jobs.py`, where the brain accepts only public owned ranges). Those tests contact nothing: the scanner unit tests replace every lookup with prepared answers, and the shim and brain tests run with no network. The brain's and the seeder's tests run with no network and fail any test that opens an outbound socket. The end-to-end tests use internal Docker networks only.
- **Security controls fail closed.** A check that cannot decide refuses. A setting that cannot be parsed is refused or falls back to the safe default, never to "allow everything".
- **Show the control works.** A change to a control comes with a test that fails without the change. Do not weaken, skip, or delete an existing test; if a test's expectation must change, say why in the pull request.
- **Keep the documentation true.** If a change alters behavior a page describes, change the page in the same pull request. The documentation checks catch missing paths and settings, not wrong sentences.

## Updating Python packages

Dependabot updates the GitHub Actions and the base images (`.github/dependabot.yml`), not the Python packages. The requirements files are kept by hand, because the images install them with `--require-hashes --no-deps` and Dependabot changes one file and one package at a time without re-checking the whole set. To update a package:

1. Choose the new exact version, and pin every package it requires, directly or through another package, exactly as well. With `--no-deps`, pip installs only what the file lists and checks nothing else.
2. Give each pin the hashes the file header names: the CPython 3.13 Linux wheels for amd64 (x86_64) and arm64 (aarch64) from PyPI, or the single `py3-none-any` wheel. Keep the comment line above each pin that says why it is there.
3. If the package is also in `seeder/requirements.txt`, copy the same lines there. The seeder's tests fail when the two files differ for a shared package.
4. Update the version and the license read from the package's own metadata in [THIRD-PARTY-TOOLS.md](THIRD-PARTY-TOOLS.md).
5. Rebuild the images and run the brain tests, the seeder unit tests, and the seeder container test.

## Add a product to version watch

A version watch reads a product's version from the response headers of `GET /` ([version watch](docs/version-watch.md)). A product fits only if its headers carry a full `x.y.z` version by default and its fixes change that number.

1. Add an entry to `PRODUCTS` in `scanner/pipeline/version_watch.py`: the display name, the scan component it matches, the headers to read in order, and the pattern that reads the version. Copy the shape of an existing entry.
2. Add the same product id and display name to `PRODUCTS` in `brain/app/watches.py`, so that the Version watch page and the API accept it.
3. Add tests to `scanner/pipeline/test_version_watch.py`: a header that matches, look-alike headers that must not (for example another product that embeds the name), and a version with a fourth number or a suffix.
4. Add a row to the product table in `docs/version-watch.md`, with the reason the product fits.

## Add a DNS source to the seeder

The seeder (`seeder/seed_dns.py`) lists host names from DNS services you control ([data flows](docs/data-flows.md)). Every source must keep its rules:

- It is off until its own `SEED_*` setting turns it on, and it reads its settings only through the `Config` class.
- It adds names only through a `Batch` bound to one zone, so that only names equal to that zone or under it, and under a DNS-verified domain, are kept, and a unit that fails adds nothing.
- It has a time limit per request and per run, and a size limit on every answer, and it reports a failure as a fixed error code in `status.json`, never as exception text.
- It never contacts anything taken from an answer and never follows a redirect. It removes the proxy, CA-bundle, service-endpoint (`AWS_ENDPOINT_URL*`), and plugin variables at start and gives each client its endpoint explicitly. The standard AWS credential variables keep their usual meaning, including the container and web-identity credential variables, which name where the SDK fetches credentials (see `docs/configuration.md`).
- Credentials come from a file or the AWS SDK's default credential chain, and are never logged or written. A PowerDNS key in a variable is not accepted.

To add one:

1. Add its name to `SOURCES` and its settings to `Config`, with a pattern for each value. Add the settings to `.env.example` and to `docs/configuration.md` (the documentation check fails until you do).
2. Write a `collect_<name>()` function in the shape of `collect_axfr()` or `collect_pdns()`, and call it from `run_once()`.
3. Add tests to the seeder's suite (`seeder/tests/`) with prepared answers only: oversized answers, slow answers, names outside the zone, and names that are not host names.
4. Add a row to the seeder table in `docs/data-flows.md`: what is sent, to whom, with which credential, and how to turn it off.

## Documentation style

Plain prose, American English, the Oxford comma, short sentences. State limits as plainly as features. Name the test that shows a control works, for example `scanner/pipeline/test_scope.py::NameGate::test_apex_and_label_boundary`. No diagrams in Markdown; the data flow diagram lives in `docs/diagrams/`.
