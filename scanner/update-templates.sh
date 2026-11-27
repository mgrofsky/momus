#!/usr/bin/env bash
# update-templates.sh - the explicit way to update the nuclei templates baked into the scanner image.
# A scan never updates templates (recon.sh runs nuclei with -duc). In the running container the image is read-only:
# submit an "update-templates" job instead (runner.py downloads into $SCAN_ROOT/templates and switches to it only
# when the download holds a real template set). This script updates the image's own copy and is meant for an
# interactive container with a writable filesystem and network access:
#   docker run --rm -it --user 10001 --entrypoint /app/scanner/update-templates.sh momus-scanner
# To bake a newer set into the image, update the version and SHA-256 in scanner/Dockerfile, then rebuild.
set -eu
: "${HOME:?HOME must be set}"
nuclei -update-templates -nc
cfg="$HOME/.config/nuclei/.templates-config.json"
tdir=$(python3 -I -B -c 'import json,sys; print(json.load(open(sys.argv[1]))["nuclei-templates-directory"])' "$cfg")
n=$(find "$tdir" -name '*.yaml' | wc -l)
echo "nuclei templates: $n in $tdir"
[ "$n" -gt 1000 ] || { echo "too few templates after the update; something went wrong" >&2; exit 1; }
