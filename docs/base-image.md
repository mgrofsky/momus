# Updating the scanner's base image

`scanner/Dockerfile` starts from `kalilinux/kali-rolling`, pinned by digest:

    FROM kalilinux/kali-rolling@sha256:<digest>

The digest is the image's multi-architecture index (a manifest list), not one platform's manifest, so the same
line builds on amd64 and arm64. With a digest, every rebuild starts from exactly the same base, and a changed or
replaced upstream tag cannot slip into your image unnoticed.

Kali is a rolling distribution, so a pinned base gets old. The packages the scanner installs (`apt-get install`
in the Dockerfile) are still fetched fresh on each no-cache build, but the base layer itself does not move until
you move the pin.

## How often

- At least once a month.
- Whenever a security fix lands in a package from the base image, such as libc, OpenSSL, or Python.
- Before a release.

## How

1. Pull the current tag and read its index digest:

       docker pull kalilinux/kali-rolling:latest
       docker image inspect kalilinux/kali-rolling:latest --format '{{json .RepoDigests}} {{json .Descriptor}}'

   Use the `sha256:...` from `RepoDigests`. Check that `Descriptor.mediaType` is a list or index
   (`application/vnd.docker.distribution.manifest.list.v2+json` or `application/vnd.oci.image.index.v1+json`).
   A single-platform manifest would pin one architecture only. `docker image ls --tree` should list
   `linux/amd64` and `linux/arm64` under it.
2. Replace the digest on the `FROM` line in `scanner/Dockerfile`.
3. Rebuild without cache and run the tests:

       docker build --no-cache -t momus-scanner scanner/
       (cd scanner/pipeline && python3 -B -m unittest)
       scanner/tests/run_shim_tests.sh
       tests/e2e/run_demo.sh

4. Record the old and new digest in the change description.

If the build fails after an update, keep the old pin until the failure is understood. The old digest stays
pullable from the registry.
