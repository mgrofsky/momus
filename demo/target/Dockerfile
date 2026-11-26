# Demo target for lab mode only (see server.py). Build context is demo/ so the shared canaries.json is included:
#   docker build -f demo/target/Dockerfile -t momus-demo-target demo/
# Base image pinned by digest (the multi-architecture index of python:3.14-slim, so amd64 and arm64 builds both resolve
# from it); the tag is kept for readers only. Update it as docs/base-image.md describes for the scanner.
FROM python:3.14-slim@sha256:22eafb370920ad8b429e0aec3fff433e0669968519f5d60469d83729c138b28b
RUN useradd --uid 10002 --no-create-home --shell /usr/sbin/nologin demo && mkdir -m 0755 /srv/demo
COPY --chown=root:root --chmod=0644 target/server.py canaries.json /srv/demo/
USER demo
EXPOSE 80
ENTRYPOINT ["python3", "-I", "-B", "/srv/demo/server.py", "--canaries", "/srv/demo/canaries.json"]
