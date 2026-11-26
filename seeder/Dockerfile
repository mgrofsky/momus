# Momus seeder (optional; Compose profile "seed"): lists host names from the DNS sources you control, for the
# domains the scanner has DNS-verified, into the "seed" volume. Build from the repository root:
#   docker build -f seeder/Dockerfile -t momus-seeder .        (or: docker compose --profile seed build seeder)
# It runs as uid 10002 (its own user: neither the scanner nor the brain), with a read-only root filesystem, no
# capabilities and no inbound port. /srv/seed is the only place it writes (and /tmp). It never mounts the scanner's
# published folder: the scanner gives it the list of verified domains in a small volume of its own.
# The same base image as the brain, pinned by digest.
FROM python:3.13-slim@sha256:7249d5587b78209a006dc4a3b5340678f84ea729239193aa559962cd8c1fce50
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_ROOT_USER_ACTION=ignore
# boto3 and what it requires, exact versions with hashes (the same pins as the brain's); no other package
COPY seeder/requirements.txt /app/seeder/requirements.txt
RUN pip install --require-hashes --no-deps --only-binary=:all: -r /app/seeder/requirements.txt \
 && groupadd --gid 10002 seeder \
 && useradd --uid 10002 --gid 10002 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin seeder \
 && mkdir -p /srv/seed /srv/seed-scope /srv/seed-zones \
 && chown 10002:10002 /srv/seed && chmod 0755 /srv/seed \
 && chown 10001:10001 /srv/seed-scope && chmod 0755 /srv/seed-scope
# Mount points:
#   /srv/seed        the seed volume: seed_hosts.txt and status.json (written here only; read-only in the scanner).
#                    Owned by uid 10002 in this image AND in the scanner image, so a fresh volume gets that owner
#                    whichever container mounts it first.
#   /srv/seed-scope  the scanner's verified_domains.json, read-only: which domains are DNS-verified. Owned by the
#                    scanner's uid 10001 in this image AND in the scanner image, so a fresh volume gets that owner
#                    whichever container mounts it first, and the scanner can write it.
#   /srv/seed-zones  zone files or host lists (read-only; only with SEED_ZONE_FILES=1)
# The SDK's configuration file is pointed at nothing: no profile, no single sign-on, no credential cache. A
# credentials file can be given as a Docker secret with AWS_SHARED_CREDENTIALS_FILE (see .env.example); it is the
# operator's own and the SDK honors what it says, including a credential_process line, which would run in this
# container.
ENV HOME=/nonexistent AWS_CONFIG_FILE=/nonexistent/aws-config AWS_SHARED_CREDENTIALS_FILE=/nonexistent/aws-credentials
COPY --chown=root:root --chmod=0644 seeder/seed_dns.py /app/seeder/seed_dns.py
USER 10002:10002
WORKDIR /srv/seed
ENTRYPOINT ["python3", "-I", "-B", "/app/seeder/seed_dns.py"]
