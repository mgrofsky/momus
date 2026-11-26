#!/usr/bin/env python3
"""seed_input.py - read the seeder's host list as untrusted input (recon phase 1).

The seeder (an optional, separate container; seeder/seed_dns.py) writes seed_hosts.txt into the "seed" volume, which
the scanner mounts read-only at $SCAN_SEED_DIR (default /srv/seed). This module is the scanner's only reader of it.
It trusts nothing in the file:
  - the file is opened without following a symlink (the folder too), and must be a regular file;
  - more than MAX_BYTES, or more than MAX_LINES lines, and the whole file is skipped;
  - only lines that are exactly a host name (the scanner's host pattern, lower case, no trailing dot, no address)
    are kept; every other line is dropped and counted;
  - the names kept still go through the scope name gate with every other source (recon.sh), so a seed name under an
    excluded suffix, or outside the scope, never reaches a tool.
A missing, oversize or unreadable file is skipped with a fixed-text reason and the run goes on with passive
enumeration. Nothing from the file is ever printed.

  seed_input.py --seed-dir DIR --out sub_seed.txt --record seed_read.json
Writes sub_seed.txt (the names kept, one per line) and seed_read.json:
  {"status": "read" | "absent" | "skipped", "reason": <fixed text or null>, "lines": n, "kept": n, "dropped": n}
Always exits 0 (a seed problem never fails the run).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys

FILE = "seed_hosts.txt"
MAX_BYTES = 16 << 20            # the seeder writes at most 50000 names of at most 253 characters
MAX_LINES = 50000
# the scanner's host name rule (recon.sh, scope.py), applied with fullmatch
HOST_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+")


def is_host(line: str) -> bool:
    if len(line) > 253 or not HOST_RE.fullmatch(line):
        return False
    labels = line.split(".")
    return all(len(x) <= 63 for x in labels) and not labels[-1].isdigit()


def read_seed(seed_dir: str, max_bytes: int = MAX_BYTES, max_lines: int = MAX_LINES) -> tuple[list[str], dict]:
    """(names kept, record). Never raises for anything about the file."""
    rec = {"status": "skipped", "reason": None, "lines": 0, "kept": 0, "dropped": 0}
    try:
        dfd = os.open(seed_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except FileNotFoundError:
        rec.update(status="absent", reason="no seed folder")
        return [], rec
    except OSError:
        rec["reason"] = "the seed folder is not a plain readable folder"
        return [], rec
    try:
        try:
            fd = os.open(FILE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
        except FileNotFoundError:
            rec.update(status="absent", reason="no seed file")
            return [], rec
        except OSError:
            rec["reason"] = "the seed file is a symlink or unreadable"
            return [], rec
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                rec["reason"] = "the seed file is not a regular file"
                return [], rec
            if st.st_size > max_bytes:
                rec["reason"] = "the seed file is over the size limit"
                return [], rec
            raw = b""
            while len(raw) <= max_bytes:
                chunk = os.read(fd, 1 << 20)
                if not chunk:
                    break
                raw += chunk
            if len(raw) > max_bytes:
                rec["reason"] = "the seed file is over the size limit"
                return [], rec
        except OSError:
            rec["reason"] = "the seed file is a symlink or unreadable"
            return [], rec
        finally:
            os.close(fd)
    finally:
        os.close(dfd)
    lines = raw.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    if len(lines) > max_lines:
        rec["reason"] = "the seed file is over the line limit"
        return [], rec
    kept, seen = [], set()
    for b in lines:
        try:
            s = b.decode("ascii")
        except UnicodeDecodeError:
            rec["dropped"] += 1
            continue
        if is_host(s) and s not in seen:
            seen.add(s)
            kept.append(s)
        elif not is_host(s):
            rec["dropped"] += 1
    rec.update(status="read", lines=len(lines), kept=len(kept))
    return kept, rec


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Read the seeder's host list as untrusted input.")
    ap.add_argument("--seed-dir", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--record", required=True)
    a = ap.parse_args(argv)
    names, rec = read_seed(a.seed_dir)
    with open(a.out, "w") as fh:
        fh.write("".join(n + "\n" for n in names))
    with open(a.record, "w") as fh:
        json.dump(rec, fh)
    if rec["status"] == "read":
        print(f"seed hosts: {rec['kept']} read ({rec['dropped']} lines dropped: not a host name)")
    elif rec["status"] == "absent":
        print(f"seed hosts: none ({rec['reason']})")
    else:
        print(f"seed hosts: skipped ({rec['reason']}); passive enumeration only")
    return 0


if __name__ == "__main__":
    sys.exit(main())
