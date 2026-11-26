#!/usr/bin/env bash
# Run the shim test inside the scanner image with no network. Builds nothing: build the image first with
#   docker build -t momus-scanner scanner/
# Usage: scanner/tests/run_shim_tests.sh [image]
set -eu
here=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)    # scanner/
image=${1:-momus-scanner}
# The image's entrypoint installs the firewall and runs the job runner; the shim test bypasses it on purpose
# (no network at all here) and runs as the scanner user, as recon.sh does in production.
# The version-watch scenario's names resolve through /etc/hosts (--add-host; no network is needed for that), so a name
# that slipped past a gate would reach the curl shim and the scenario's "never reaches" checks could not pass by accident.
vw_hosts=(--add-host vw.example.test:94.140.14.91 --add-host vwalias.example.test:94.140.14.92 --add-host vwtwo.example.test:94.140.14.93
          --add-host vwx.excluded.example.test:94.140.14.94 --add-host www.unproven.test:94.140.14.95)
exec docker run --rm --network none "${vw_hosts[@]}" --user 10001:10001 --entrypoint python3 -v "$here:/src/scanner:ro" -e PYTHONDONTWRITEBYTECODE=1 \
  "$image" -B /src/scanner/tests/shim/driver.py
