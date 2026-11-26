# Momus brain: the web application (UI, API, scheduler). Build from the repository root:
#   docker build -f brain/Dockerfile -t momus-brain .
# It runs as uid 10001 (the same uid as the scanner, so both can use the shared "jobs" volume whichever container
# creates it first), with a read-only root filesystem; /data (app database) and /tmp are the only writable places.
FROM python:3.13-slim@sha256:7249d5587b78209a006dc4a3b5340678f84ea729239193aa559962cd8c1fce50 AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_ROOT_USER_ACTION=ignore
RUN groupadd --gid 10001 brain \
 && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin brain \
 && mkdir -p /data /srv/jobs /srv/published \
 && chown 10001:10001 /data /srv/jobs /srv/published
WORKDIR /opt/brain
COPY brain/requirements.txt ./requirements.txt
RUN pip install --require-hashes --no-deps --only-binary=:all: -r requirements.txt
COPY brain/app ./app
COPY --chmod=0644 brain/app/static/vendor/htmx-2.0.7.min.js ./app/static/vendor/htmx-2.0.7.min.js
COPY brain/run.py ./run.py
# host recovery commands: docker compose exec brain python -B -m tools.admin <command> (run from WORKDIR /opt/brain)
COPY brain/tools ./tools
COPY docs/data-flows.md docs/version-watch.md docs/analyst.md ./docs/
# the analyst's outgoing text passes through the scanner's own redaction module: one source of truth, copied, not forked
COPY scanner/pipeline/redact.py ./shared/redact.py

# test image: the same, plus pytest and httpx (tests are mounted read-only, never copied in)
FROM base AS test
COPY brain/requirements-dev.txt ./requirements-dev.txt
RUN pip install --require-hashes --no-deps --only-binary=:all: -r requirements-dev.txt
USER 10001:10001

FROM base AS runtime
USER 10001:10001
EXPOSE 8080
VOLUME ["/data"]
# -B: no bytecode written; -E -s: no PYTHON* variables and no user site directory
ENTRYPOINT ["python3", "-B", "-E", "-s", "/opt/brain/run.py"]
