#!/usr/bin/env bash
# Exercise the image's template installer with local archives; no network or nuclei binary is needed.
set -euo pipefail

scanner=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

make_archive() {
  local count=$1 output=$2
  local src="$tmp/source"
  rm -rf "$src"
  mkdir -p "$src/nuclei-templates-0.0.0/http"
  printf 'MIT License\n' > "$src/nuclei-templates-0.0.0/LICENSE.md"
  python3 -B - "$src/nuclei-templates-0.0.0/http" "$count" <<'PY'
import pathlib, sys
directory = pathlib.Path(sys.argv[1])
for index in range(int(sys.argv[2])):
    (directory / f"template-{index}.yaml").write_text("id: test\n")
PY
  tar -czf "$output" -C "$src" nuclei-templates-0.0.0
}

archive_sha256() {
  python3 -I -B - "$1" <<'PY'
import hashlib, sys
with open(sys.argv[1], "rb") as archive:
    print(hashlib.file_digest(archive, "sha256").hexdigest())
PY
}

archive="$tmp/valid.tar.gz"
make_archive 1001 "$archive"
digest=$(archive_sha256 "$archive")
mkdir -p "$tmp/valid-home" "$tmp/bad-hash-home" "$tmp/short-home"

HOME="$tmp/valid-home" "$scanner/install-templates.sh" 0.0.0 "$digest" "$archive"
python3 -B - "$tmp/valid-home" <<'PY'
import json, pathlib, sys
home = pathlib.Path(sys.argv[1])
config = json.loads((home / ".config/nuclei/.templates-config.json").read_text())
templates = home / ".local/nuclei-templates"
assert config["nuclei-templates-directory"] == str(templates)
assert config["nuclei-templates-version"] == "v0.0.0"
assert len(list(templates.rglob("*.yaml"))) == 1001
assert (templates / "LICENSE.md").read_text() == "MIT License\n"
PY

if HOME="$tmp/bad-hash-home" "$scanner/install-templates.sh" 0.0.0 "$(printf '%064d' 0)" "$archive" > "$tmp/bad-hash.log" 2>&1; then
  echo "installer accepted an archive with the wrong SHA-256" >&2
  exit 1
fi
test ! -e "$tmp/bad-hash-home/.config/nuclei/.templates-config.json"

short="$tmp/short.tar.gz"
make_archive 1 "$short"
short_digest=$(archive_sha256 "$short")
if HOME="$tmp/short-home" "$scanner/install-templates.sh" 0.0.0 "$short_digest" "$short" > "$tmp/short.log" 2>&1; then
  echo "installer accepted an incomplete template archive" >&2
  exit 1
fi
test ! -e "$tmp/short-home/.config/nuclei/.templates-config.json"

echo "template installer: valid archive installed; altered or incomplete archives refused"
