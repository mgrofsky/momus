#!/usr/bin/env bash
# run_tests.sh - the seeder's unit tests, in the seeder image, with no network. Never run them with the host's Python:
# run.py refuses unless MOMUS_SEED_TEST_CONTAINER=1, which only this script sets.
# The repository is mounted read-only, so no bytecode cache can be written into the source tree.
#   seeder/tests/run_tests.sh
set -eu
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
docker build -q -f seeder/Dockerfile -t momus-seeder . >/dev/null
# No DNS source or cloud service can be reached or authenticated from here: no network; no home folder; the AWS
# variables set to obvious dummies and the config and credential files pointed at nothing, as literal values on this
# command line; the instance metadata service off. No variable from the host's environment is passed in.
# run.py sets the same again and adds a guard that fails any test that opens an outbound socket.
exec docker run --rm --network none --read-only --tmpfs /tmp:size=256m,mode=1777 -e TMPDIR=/tmp \
  -e MOMUS_SEED_TEST_CONTAINER=1 -e HOME=/nonexistent -e AWS_CONFIG_FILE=/nonexistent/aws-config \
  -e AWS_SHARED_CREDENTIALS_FILE=/nonexistent/aws-credentials -e AWS_EC2_METADATA_DISABLED=true \
  -e AWS_ACCESS_KEY_ID=dummy-not-a-key -e AWS_SECRET_ACCESS_KEY=dummy-not-a-key -e AWS_SESSION_TOKEN=dummy-not-a-key \
  -v "$PWD:/src:ro" -w /tmp --entrypoint python3 momus-seeder -I -B /src/seeder/tests/run.py
