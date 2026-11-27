#!/usr/bin/env bash
# The production scanner has a read-only root filesystem. Nuclei must start with only image-baked config.
set -euo pipefail
image=${1:-momus-scanner}
docker run --rm --read-only --tmpfs /tmp:size=64m,mode=1777 --network none \
  --user 10001:10001 --entrypoint nuclei "$image" \
  -validate -t /home/scanner/.local/nuclei-templates/http/exposures/configs/git-config.yaml \
  -duc -ni -nc
