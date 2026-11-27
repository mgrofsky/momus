#!/usr/bin/env bash
# Install one pinned ProjectDiscovery release into the scanner user's home.
# The optional archive path is for the offline installer test; image builds fetch the tagged archive.
set -euo pipefail

if (( $# < 2 || $# > 3 )); then
  echo "usage: install-templates.sh VERSION SHA256 [LOCAL_ARCHIVE]" >&2
  exit 2
fi
version=$1
digest=$2
if [[ ! $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ || ! $digest =~ ^[0-9a-f]{64}$ ]]; then
  echo "template version or SHA-256 is invalid" >&2
  exit 2
fi
: "${HOME:?HOME must be set}"

archive=$(mktemp)
trap 'rm -f "$archive"' EXIT
if (( $# == 3 )); then
  cp -- "$3" "$archive"
else
  curl --fail --location --silent --show-error --retry 5 --retry-all-errors --retry-delay 3 \
    --connect-timeout 15 --max-time 180 \
    "https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/v${version}.tar.gz" \
    --output "$archive"
fi
python3 -I -B - "$archive" "$digest" <<'PY'
import hashlib
import sys

with open(sys.argv[1], "rb") as archive:
    actual = hashlib.file_digest(archive, "sha256").hexdigest()
if actual != sys.argv[2]:
    raise SystemExit("nuclei templates archive SHA-256 mismatch")
PY

templates="$HOME/.local/nuclei-templates"
mkdir -p "$templates" "$HOME/.config/nuclei"
tar -xzf "$archive" -C "$templates" --strip-components=1
count=$(find "$templates" -name '*.yaml' -type f | wc -l)
if (( count <= 1000 )) || [[ ! -f $templates/LICENSE.md ]]; then
  echo "nuclei templates archive is incomplete ($count YAML files)" >&2
  exit 1
fi
python3 -I -B - "$HOME/.config/nuclei/.templates-config.json" "$templates" "$version" <<'PY'
import json
import sys

with open(sys.argv[1], "w") as config:
    json.dump({
        "nuclei-templates-directory": sys.argv[2],
        "nuclei-templates-version": "v" + sys.argv[3],
    }, config)
    config.write("\n")
PY
echo "nuclei templates: $count YAML files from v$version in $templates"
