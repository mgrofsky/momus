#!/usr/bin/env bash
# run_tests.sh - the brain's unit and integration tests, in the brain's test image, with no network.
# The repository is mounted read-only, so no bytecode cache or pytest cache can be written into the source tree.
#   brain/tests/run_tests.sh [pytest args]
set -eu
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
docker build -q -f brain/Dockerfile --target test -t momus-brain-test . >/dev/null
# No provider can be reached or authenticated from here: no network; no home folder (HOME points at
# nothing); the SDKs' standard credential variables are set to obvious dummies; the AWS config and credential files
# point at nothing and the instance metadata service is off. No variable from the host's environment is passed in.
# conftest.py adds a guard that fails any test that opens an outbound socket.
exec docker run --rm --network none --read-only --tmpfs /tmp:size=512m,mode=1777 -e TMPDIR=/tmp -e MOMUS_REPO=/src \
  -e MOMUS_TEST_CONTAINER=1 -e HOME=/nonexistent -e AWS_CONFIG_FILE=/nonexistent/aws-config \
  -e AWS_SHARED_CREDENTIALS_FILE=/nonexistent/aws-credentials -e AWS_EC2_METADATA_DISABLED=true \
  -e ANTHROPIC_API_KEY=dummy-not-a-key -e OPENAI_API_KEY=dummy-not-a-key -e GEMINI_API_KEY=dummy-not-a-key \
  -e GOOGLE_API_KEY=dummy-not-a-key -e AWS_ACCESS_KEY_ID=dummy-not-a-key -e AWS_SECRET_ACCESS_KEY=dummy-not-a-key \
  -e AWS_BEARER_TOKEN_BEDROCK=dummy-not-a-key \
  -v "$PWD:/src:ro" -w /src/brain momus-brain-test \
  python3 -B -m pytest -p no:cacheprovider -q /src/brain/tests "$@"
