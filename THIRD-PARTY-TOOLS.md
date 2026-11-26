# Third-party tools and libraries

This page lists every external tool the scanner image installs and every pinned or vendored library in the brain and
the seeder: its name, its version, what this project uses it for, its license, and where the license text is found.
Each license below was read from the package's own copyright file inside a built image, or from the installed
package's metadata. It is not legal advice. If you redistribute any of these images, read the license files named
here yourself.

## This project does not redistribute the scan tools

The repository contains no scan tool binaries and no prebuilt image. You build the scanner image yourself
(`docker build -t momus-scanner scanner/`, or `docker compose build scanner`). The build installs the scan tools
from Kali Linux's own package repository with `apt-get install` (`scanner/Dockerfile`), and nuclei downloads its
templates during the same build. Compose builds every image from this repository's Dockerfiles; it pulls no prebuilt
Momus image.

The brain and the seeder install their Python packages from PyPI during your build, with exact versions and hashes
(`pip install --require-hashes`). The repository itself contains two third-party works: htmx, a small JavaScript
library, with its license beside it, and the Comic Shanns font embedded in the data flow diagram (below).

## Comic Shanns font

Both diagram SVGs (`docs/diagrams/momus-dataflow.svg` and `docs/diagrams/momus-dataflow-light.svg`) embed the Comic
Shanns font (Comic Shanns Regular, version 1.3.0, as Excalidraw ships it) as a WOFF2 file inside the SVG, so the text
renders without the font installed. Its license is the MIT License. The license text and the copyright lines are in
the font's own name table (the copyright record, name ID 0), inside each SVG:

    Copyright (c) 2018 Shannon Miwa
    Copyright (c) 2023 Jesus Gonzalez
    Copyright (c) 2023 Rodrigo Batista de Moraes
    Copyright (c) 2024 Fini Jastrow
    Copyright (c) 2024 Kyle Beechly

## Versions

The scanner's base image is pinned by digest, but the Kali packages are not pinned: a build installs whatever version
Kali's repository holds on the day you build. This page therefore gives no versions for them. To see what your image
holds:

```
docker run --rm --network none --entrypoint dpkg-query momus-scanner -W nmap subfinder nuclei
```

The scanner also reports its tool versions in its heartbeat file (`scanner.json` in the published folder).

The brain's and the seeder's Python packages are pinned exactly in their requirements files, so those versions are
the same in every build.

## How to read a license yourself

For a Kali or Debian package, the license is in `/usr/share/doc/<package>/copyright` inside the scanner image. The
image's normal entrypoint installs a firewall, so override it:

```
docker run --rm --network none --entrypoint cat momus-scanner /usr/share/doc/nmap/copyright
```

The license column for a Kali package gives the `License:` field of the `Files: *` paragraph (the paragraph that
covers the program as a whole). Other paragraphs in the same file can name other licenses for individual files.

For a Python package, the license is in the package's `METADATA` file and the license files in its `.dist-info`
folder, under `/usr/local/lib/python3.13/site-packages/` in the brain and seeder images.

## Scanner: scan tools from Kali packages

Installed by `apt-get install` in `scanner/Dockerfile`. "Copyright file" is
`/usr/share/doc/<package>/copyright` in the scanner image.

| Tool (Kali package) | What the scanner uses it for | License (`Files: *`) | License text |
|---|---|---|---|
| nmap | Port scan of in-scope addresses (`scanner/recon.sh`) | NPSL-0.94 | Copyright file (the license text starts at its `License: NPSL-0.94` paragraph); also `/usr/share/doc/nmap/3rd-party-licenses.txt.gz` |
| subfinder | Passive subdomain enumeration (`scanner/recon.sh`) | MIT | Copyright file |
| assetfinder | Passive subdomain enumeration (`scanner/recon.sh`) | Expat | Copyright file |
| dnsx | Resolving discovered names to A, AAAA, and CNAME records (`scanner/recon.sh`) | Expat | Copyright file |
| dnsrecon | Standard DNS record enumeration of each apex (`dnsrecon -t std`), whose names feed the host list (`scanner/recon.sh`) | GPL-2 | Copyright file |
| httpx-toolkit | Probing hosts for live web services (`scanner/recon.sh`) | Expat | Copyright file |
| whatweb | Web technology fingerprinting (`scanner/recon.sh`) | GPL-2.0+ | Copyright file |
| wafw00f | Web application firewall detection (`scanner/recon.sh`) | BSD-3-clause | Copyright file |
| sslscan | TLS configuration checks on HTTPS hosts (`scanner/recon.sh`) | GPL-3.0+ with OpenSSL exception | Copyright file |
| nuclei | Template-based checks (`scanner/recon.sh`); template downloads (`scanner/Dockerfile`, `scanner/runner.py`, `scanner/update-templates.sh`) | Expat | Copyright file |

## Scanner: supporting packages the pipeline calls

| Package | What the scanner uses it for | License (`Files: *`) | License text |
|---|---|---|---|
| bind9-dnsutils (installed as `dnsutils`) | `dig`: looks up each apex's nameservers and tries a zone transfer (AXFR) against them (`scanner/recon.sh`) | MPL-2.0 and ISC and BSD-2-clause and BSD-3-clause | Copyright file |
| curl | Certificate transparency lookups at crt.sh (`scanner/recon.sh`); the version-watch request (`scanner/pipeline/version_watch.py`) | curl | Copyright file |
| ca-certificates | Trusted root certificates for HTTPS connections | No `Files: *` paragraph; `debian/*`, `Makefile`, `mozilla/*`, `sbin/*`: GPL-2+; `mozilla/certdata.txt`: MPL-2.0 | Copyright file |
| python3 (python3.14) | Runs the job runner and the pipeline (`scanner/runner.py`, `scanner/pipeline/`) | Not in machine-readable form; the file's terms section is headed "PYTHON SOFTWARE FOUNDATION LICENSE VERSION 2" | `/usr/share/doc/python3/copyright`, `/usr/share/doc/python3.14/copyright` |
| iptables | `iptables` and `ip6tables`: the egress firewall installed at start-up (`scanner/entrypoint.sh`) | GPL-2 | Copyright file |
| procps | Installed by `scanner/Dockerfile`; no direct call found in the scanner's scripts | LGPL-2.1+ | Copyright file |

The scanner's scripts also call common tools that come with the Kali base image rather than from the Dockerfile's
package list. Their licenses, read the same way:

| Package | Commands used | License (`Files: *`) |
|---|---|---|
| util-linux | `setpriv` (drops privileges at start-up, `scanner/entrypoint.sh`) | GPL-2+ |
| coreutils | `timeout`, `sort`, `wc`, `tr`, `rm`, and others | GPL-3+ |
| bash | runs `scanner/recon.sh` and the other shell scripts | GPL-3+ |
| grep | `grep` | GPL-3+ |
| sed | `sed` | GPL-3+ |
| mawk | `awk` | GPL-2.0-only |
| findutils | `find` | GFDL-NIV-1.3+ or GFDL-NIV-1.3+ (as the file states it) |
| dpkg | `dpkg-query` (tool versions in the heartbeat, `scanner/runner.py`) | GPL-2+ |

The license text for each is in its copyright file in the scanner image.

No `whois` program is installed. The ASN lookup in `scanner/pipeline/enrich.py` opens its own connection to Team
Cymru's whois service.

## Nuclei templates

The nuclei templates are not part of this repository. The scanner image build runs `nuclei -update-templates`, which
downloads the template set with nuclei's own updater into `/home/scanner/.local/nuclei-templates` in the image. The
template set is not pinned: each build downloads whatever version is current that day, so two builds can hold
different templates. A scan
never updates them. An `update-templates` job downloads a newer set into the scanner's data volume
(`$SCAN_ROOT/templates`), and `scanner/update-templates.sh` updates the image's own copy in an interactive container.
Either way, the download is made by your build or your job, from your machine.

The template set carries its own license file, `/home/scanner/.local/nuclei-templates/LICENSE.md` in the image. Its
first line reads "MIT License" and its copyright line names ProjectDiscovery, Inc. The template version in your image
is in `/home/scanner/.config/nuclei/.templates-config.json` and in the scanner's heartbeat.

## Licenses with terms a redistributor should read

These files carry terms beyond a short permissive notice. They are named here without interpretation.

- **Nmap**: `/usr/share/doc/nmap/copyright` in the scanner image. The main program is under the Nmap Public Source
  License, Version 0.94 (`License: NPSL-0.94`); the full text is in the paragraph headed `License: NPSL-0.94`. The
  same file states that nmap is in the non-free section in Kali. Licenses of bundled third-party code are in
  `/usr/share/doc/nmap/3rd-party-licenses.txt.gz`.
- **sslscan**: `/usr/share/doc/sslscan/copyright` (GPL-3.0+ with an OpenSSL exception).
- **dnsrecon**, **whatweb**, **iptables**, and the base-image tools: GPL licenses, in their copyright files.

## Brain: Python packages

Pinned with hashes in `brain/requirements.txt` and installed by `brain/Dockerfile`. Every installed version matches its
pin. The license is read from the package's `METADATA`: the `License-Expression` field where present, otherwise the
`License` field, otherwise the `License ::` classifier. License files are in
`/usr/local/lib/python3.13/site-packages/<package>-<version>.dist-info/` in the `momus-brain` image ("licenses/"
means the `licenses` subfolder there).

Packages this project chose:

| Package | Version | What the brain uses it for | License (metadata) | License files |
|---|---|---|---|---|
| fastapi | 0.165.0 | Web framework: routing and request parsing | MIT | licenses/LICENSE |
| uvicorn | 0.54.0 | The ASGI web server (`brain/run.py`) | BSD-3-Clause | licenses/LICENSE.md |
| jinja2 (Jinja2) | 3.1.6 | Auto-escaping HTML templates | BSD License (classifier only) | licenses/LICENSE.txt |
| python-multipart | 0.0.34 | HTML form parsing | Apache-2.0 | licenses/LICENSE.txt |
| anthropic | 2.14.0 | Analyst: Anthropic model API (imported only by `brain/app/llm/anthropic_client.py`) | Apache-2.0 | licenses/LICENSE, licenses/LICENSE-MIT |
| openai | 3.59.0 | Analyst: OpenAI model API (imported only by `brain/app/llm/openai_client.py`) | Apache-2.0 | licenses/LICENSE |
| google-genai | 3.6.1 | Analyst: Gemini API (imported only by `brain/app/llm/gemini_client.py`) | Apache-2.0 | licenses/LICENSE |
| boto3 | 1.44.11 | Analyst: Amazon Bedrock (imported only by `brain/app/llm/bedrock_client.py`) | Apache-2.0 | LICENSE, NOTICE |

Packages required by those:

| Package | Version | Required by | License (metadata) | License files |
|---|---|---|---|---|
| annotated-doc | 0.0.7 | fastapi | MIT | licenses/LICENSE |
| annotated-types | 0.8.0 | pydantic | MIT | licenses/LICENSE |
| anyio | 4.16.0 | fastapi, starlette | MIT | licenses/LICENSE |
| botocore | 1.44.11 | boto3, s3transfer | Apache-2.0 | LICENSE.txt, NOTICE |
| certifi | 2026.11.20 | requests | MPL-2.0 | licenses/LICENSE |
| cffi | 2.1.1 | cryptography | MIT-0 | licenses/LICENSE |
| charset-normalizer | 3.5.3 | requests | MIT | licenses/LICENSE |
| click | 8.5.1 | uvicorn | BSD-3-Clause | licenses/LICENSE.txt |
| cryptography | 50.0.2 | google-auth | Apache-2.0 OR BSD-3-Clause | licenses/LICENSE, licenses/LICENSE.APACHE, licenses/LICENSE.BSD |
| distro | 1.9.0 | google-genai | Apache License, Version 2.0 | LICENSE |
| docstring-parser | 0.18.0 | anthropic | MIT | licenses/LICENSE.md |
| google-auth | 2.63.1 | google-genai | Apache 2.0 | licenses/LICENSE |
| h11 | 0.16.0 | uvicorn | MIT | licenses/LICENSE.txt |
| httpcore2 | 2.16.2 | httpx2 | BSD-3-Clause | licenses/LICENSE.md |
| httpx2 | 2.16.2 | anthropic, openai, google-genai | BSD-3-Clause | licenses/LICENSE.md |
| idna | 3.20 | anyio | BSD-3-Clause | licenses/LICENSE.md |
| jiter | 0.19.0 | anthropic, openai | MIT | licenses/LICENSE |
| jmespath | 1.1.0 | boto3, botocore | MIT | LICENSE |
| markupsafe (MarkupSafe) | 3.0.4 | jinja2 | BSD-3-Clause | licenses/LICENSE.txt |
| opentelemetry-api | 1.45.2 | fastapi | Apache-2.0 | licenses/LICENSE |
| pyasn1 | 0.6.5 | pyasn1-modules | BSD-2-Clause | licenses/LICENSE.rst |
| pyasn1-modules | 0.4.2 | google-auth | BSD (classifier: BSD License) | licenses/LICENSE.txt |
| pycparser | 3.12 | cffi | BSD-3-Clause | licenses/LICENSE |
| pydantic | 2.14.4 | fastapi | MIT | licenses/LICENSE |
| pydantic-core | 2.50.5 | pydantic | MIT | licenses/LICENSE |
| python-dateutil | 2.9.0.post0 | botocore | "Dual License" (classifiers: BSD License, Apache Software License) | LICENSE |
| requests | 2.34.2 | google-genai, google-auth | Apache-2.0 | licenses/LICENSE, licenses/NOTICE |
| s3transfer | 0.19.3 | boto3 | Apache License 2.0 | LICENSE.txt, NOTICE.txt |
| six | 1.17.0 | python-dateutil | MIT | LICENSE |
| sniffio | 1.3.1 | anthropic, openai, google-genai | MIT OR Apache-2.0 | LICENSE, LICENSE.APACHE2, LICENSE.MIT |
| starlette | 1.10.0 | fastapi | BSD-3-Clause | licenses/LICENSE.md |
| tenacity | 9.1.4 | google-genai | Apache 2.0 | licenses/LICENSE |
| truststore | 0.10.5 | httpx2, httpcore2 | MIT | licenses/LICENSE |
| typing-extensions | 4.16.0 | fastapi, pydantic, pydantic-core, opentelemetry-api | PSF-2.0 | licenses/LICENSE |
| typing-inspection | 0.4.5 | fastapi, pydantic | MIT | licenses/LICENSE |
| urllib3 | 2.8.0 | botocore, requests | MIT | licenses/LICENSE.txt |
| websockets | 17.4 | google-genai | BSD-3-Clause | licenses/LICENSE |

The "Required by" column is taken from the comments in `brain/requirements.txt`.

### Test-only packages

Pinned in `brain/requirements-dev.txt` and installed only in the brain's test image (`momus-brain-test`, the
`test` stage of `brain/Dockerfile`). They are not in the image that runs the brain.

| Package | Version | Use | License (metadata) | License files |
|---|---|---|---|---|
| pytest | 9.2.0 | Test runner | MIT | licenses/LICENSE |
| httpx | 0.28.1 | Transport for the test client | BSD-3-Clause | licenses/LICENSE.md |
| httpcore | 1.0.9 | Required by httpx | BSD-3-Clause | licenses/LICENSE.md |
| iniconfig | 2.3.1 | Required by pytest | MIT | licenses/LICENSE |
| packaging | 26.4 | Required by pytest | Apache-2.0 OR BSD-2-Clause | licenses/LICENSE, licenses/LICENSE.APACHE, licenses/LICENSE.BSD |
| pluggy | 1.7.0 | Required by pytest | MIT | licenses/LICENSE |
| pygments (Pygments) | 2.21.0 | Required by pytest | BSD-2-Clause | licenses/AUTHORS, licenses/LICENSE |

### Vendored file: htmx

| File | Version | Use | License | License text |
|---|---|---|---|---|
| `brain/app/static/vendor/htmx-2.0.7.min.js` | 2.0.7 | Partial page updates in the web interface (loaded by `brain/app/templates/base.html`) | Zero-Clause BSD | `brain/app/static/vendor/htmx-LICENSE.txt` |

The license file's first line says its text is the LICENSE file of the htmx.org 2.0.7 npm package, copied verbatim.
This file is the only third-party code stored in the repository.

## Seeder: Python packages

Pinned with hashes in `seeder/requirements.txt` and installed by `seeder/Dockerfile`. The seeder's only chosen package
is boto3, imported only when the Route 53 source is turned on (`seeder/seed_dns.py`); the rest are packages boto3
requires. Every installed version matches its pin, and the versions are the same as the brain's. License files are in
`/usr/local/lib/python3.13/site-packages/<package>-<version>.dist-info/` in the `momus-seeder` image.

| Package | Version | Use | License (metadata) | License files |
|---|---|---|---|---|
| boto3 | 1.44.11 | Reads host names from Route 53 | Apache-2.0 | LICENSE, NOTICE |
| botocore | 1.44.11 | Required by boto3 | Apache-2.0 | LICENSE.txt, NOTICE |
| jmespath | 1.1.0 | Required by boto3 | MIT | LICENSE |
| python-dateutil | 2.9.0.post0 | Required by botocore | "Dual License" (classifiers: BSD License, Apache Software License) | LICENSE |
| s3transfer | 0.19.3 | Required by boto3 | Apache License 2.0 | LICENSE.txt, NOTICE.txt |
| six | 1.17.0 | Required by python-dateutil | MIT | LICENSE |
| urllib3 | 2.8.0 | Required by botocore | MIT | licenses/LICENSE.txt |

## Base images

| Image | Base | Pinned | Notes |
|---|---|---|---|
| scanner | `kalilinux/kali-rolling` | By digest (`scanner/Dockerfile`) | Kali is a rolling release; the packages installed on top of it are not pinned (see Versions above). |
| brain | `python:3.13-slim` | By digest (`brain/Dockerfile`) | Python's license is at `/usr/local/lib/python3.13/LICENSE.txt` in the image. The base image also brings pip (26.2.2, license MIT per its metadata), which is not in `brain/requirements.txt`. |
| seeder | `python:3.13-slim` | By digest, the same digest as the brain (`seeder/Dockerfile`) | As for the brain. |
| demo target | `python:3.14-slim` | By digest (`demo/target/Dockerfile`) | Used only in lab mode. It installs no packages; it runs `demo/target/server.py` with the standard library. |

The base images' own system packages are not listed here. Each one's license is in `/usr/share/doc/<package>/copyright`
inside that image.
