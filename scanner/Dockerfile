# Scanner image: the recon tools from Kali's own packages, Python 3, the nuclei templates baked in at build time,
# the pipeline, and the job runner. Build it yourself; it is never published prebuilt.
#   docker build -t momus-scanner scanner/        (or: docker compose build scanner)
# Start-up (entrypoint.sh): as root with NET_ADMIN (+ SETUID, SETGID, SETPCAP for the drop itself), install the
# egress firewall, verify it, then drop to uid 10001 with no capabilities and no-new-privileges and run runner.py.
# Base image pinned by digest (the multi-architecture index, so amd64 and arm64 builds both resolve from it), so a
# rebuild never silently picks up a different base. Kali is a rolling release: update the pin at least monthly and
# whenever a security fix lands in a package the scanner uses, as described in docs/base-image.md. The tag is kept
# for readers only; the digest is what Docker uses.
FROM kalilinux/kali-rolling@sha256:69a9a33d98a584a537bd0f7144d20c3b6d23f3bafa9ffcf0cadf4c5f186d02ff

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      nmap subfinder assetfinder dnsx dnsrecon httpx-toolkit whatweb wafw00f sslscan nuclei \
      dnsutils curl ca-certificates python3 procps \
 && rm -rf /var/lib/apt/lists/*

# Non-root user; everything it writes lives under SCAN_ROOT, the published folder, /tmp or its own home.
ENV SCAN_ROOT=/var/lib/scan
RUN useradd --create-home --home-dir /home/scanner --uid 10001 --shell /bin/bash scanner \
 && mkdir -p "$SCAN_ROOT" \
 && chown scanner:scanner "$SCAN_ROOT"

USER scanner
ENV HOME=/home/scanner
WORKDIR /home/scanner
# Templates are part of the image; a scan never updates them. Update with an update-templates job or a rebuild.
# The download sometimes returns nothing (the publisher's rate limit), so it is tried up to three times; the build
# fails unless more than 1000 templates are present.
RUN n=0; for attempt in 1 2 3; do \
      nuclei -update-templates -nc || true; \
      tdir=$(python3 -I -B -c 'import json,os; print(json.load(open(os.path.expanduser("~/.config/nuclei/.templates-config.json")))["nuclei-templates-directory"])' 2>/dev/null || true); \
      n=$(if [ -n "$tdir" ] && [ -d "$tdir" ]; then find "$tdir" -name '*.yaml' | wc -l; else echo 0; fi); \
      echo "nuclei templates: $n in ${tdir:-no folder} (attempt $attempt)"; \
      if [ "$n" -gt 1000 ]; then break; fi; \
      if [ "$attempt" -lt 3 ]; then sleep 20; fi; \
    done; test "$n" -gt 1000

# Firewall tool for the entrypoint (its own layer, so the tool and template layers above stay cached).
USER root
RUN apt-get update \
 && apt-get install -y --no-install-recommends iptables \
 && rm -rf /var/lib/apt/lists/*

# Mount points for the named volumes, owned by the scanner user so a fresh volume inherits that owner
# (the entrypoint has no CHOWN or DAC_OVERRIDE capability and cannot fix ownership later).
#   /var/lib/scan   scan data: scope/, runs/, data/scan.sqlite, reports/ (read-write)
#   /srv/jobs       job files written by the brain (mounted read-only here)
#   /srv/published  status, snapshots, reports, scope status, heartbeat (read-write here, read-only in the brain)
#   /srv/jobctl     state of the developer stand-in for the brain (jobctl.py, compose service "jobctl" only)
#   /srv/seed       the optional seeder's host list (mounted read-only here). Owned by the seeder's uid 10002, not by
#                   the scanner user, exactly as in the seeder image: a fresh volume gets that owner whichever container
#                   mounts it first, so the seeder can write it and the scanner never can.
#   /srv/seed-scope verified_domains.json for the optional seeder (written here; read-only in the seeder). Owned by
#                   the scanner user here AND in the seeder image, so a fresh volume gets that owner either way.
ENV SCAN_JOBS=/srv/jobs SCAN_PUBLISHED=/srv/published SCAN_SEED_DIR=/srv/seed
RUN mkdir -p /srv/jobs /srv/published /srv/jobctl /srv/seed /srv/seed-scope /home/scanner/.cache \
 && chown scanner:scanner /srv/jobs /srv/published /srv/jobctl /srv/seed-scope /home/scanner/.cache \
 && chmod 0755 /srv/seed-scope \
 && chown 10002:10002 /srv/seed && chmod 0755 /srv/seed

# The pipeline, owned by root and read-only to the scanner user. Tests and caches stay out (.dockerignore).
COPY --chown=root:root --chmod=0755 entrypoint.sh recon.sh update-templates.sh runner.py jobctl.py /app/scanner/
COPY --chown=root:root pipeline/ /app/scanner/pipeline/
COPY --chown=root:root config/ /app/scanner/config/
RUN find /app/scanner -type d -exec chmod 0755 {} + \
 && find /app/scanner -type f -name '*.py' ! -name 'test_*' -exec chmod 0644 {} + \
 && chmod 0755 /app/scanner/entrypoint.sh /app/scanner/recon.sh /app/scanner/update-templates.sh \
 && rm -f /app/scanner/pipeline/test_*.py \
 && date -u +%Y-%m-%dT%H:%M:%SZ > /app/scanner/BUILD_DATE

# The entrypoint must start as root to install the firewall; it never runs anything else as root.
WORKDIR /var/lib/scan
ENTRYPOINT ["/app/scanner/entrypoint.sh"]
