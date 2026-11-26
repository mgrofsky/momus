#!/bin/bash
# Startup script for the Momus VM (deploy/gcp/momus-host.sh passes it as the "startup-script" metadata key;
# Compute Engine runs it as root at every boot). It installs Docker and the Compose plugin from Ubuntu's own archive
# and nothing else: no repository is cloned and nothing is started. See README.md for the steps after connecting.
# The VM has no external address; packages arrive through Cloud NAT. Safe to run at every boot.
set -eu
exec >>/var/log/momus-startup.log 2>&1
if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  echo "docker and compose present $(date -u +%FT%TZ)"
  exit 0
fi
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends docker.io docker-buildx docker-compose-v2
systemctl enable --now docker
echo "startup done $(date -u +%FT%TZ)"
