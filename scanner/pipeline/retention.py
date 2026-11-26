#!/usr/bin/env python3
"""retention.py - remove old run directories (raw tool output) after a retention period.

  python3 -I -B scanner/pipeline/retention.py --root "$SCAN_ROOT" [--days 30] [--apply]

Run directories ($SCAN_ROOT/runs/<run id>) hold the raw output of every tool: response bodies, request dumps,
port-scanner script output, captured headers and cookies. The database keeps only the minimized, redacted
evidence (minimize.py), so the raw files are needed for a while (re-ingest, verification by hand) and then go.

Lists every run directory older than --days (default 30; age from the manifest's finished or started time, else
the directory's own modification time). Without --apply it only prints what it would delete. With --apply it
deletes those directories. It never deletes:
  - the most recent full run (not a recheck, not inventory-only), whatever its age;
  - the newest run of all when its manifest is missing or unreadable (it may be that latest full run);
  - any run that a recheck run names as its base (manifest "base_run"): ingest reads the base's assets;
  - anything that is not a directory directly under $SCAN_ROOT/runs, or a symbolic link (never followed);
and it refuses to work at all when $SCAN_ROOT/runs is itself a symbolic link or not a directory.
Exit codes: 0 done (or nothing to do); 2 bad arguments or an unsafe runs directory.
"""
import argparse, datetime as dt, json, os, shutil, stat, sys

DEFAULT_DAYS = 30


def _manifest(path):
    p = os.path.join(path, "manifest.json")
    try:
        if stat.S_ISLNK(os.lstat(p).st_mode):
            return {}
        with open(p, encoding="utf-8") as fh:
            d = json.load(fh)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _when(m, st):
    for k in ("finished", "started"):
        v = m.get(k)
        if isinstance(v, str) and v:
            try:
                t = dt.datetime.fromisoformat(v.replace("Z", "+00:00"))
                return t if t.tzinfo else t.replace(tzinfo=dt.timezone.utc)
            except ValueError:
                pass
    return dt.datetime.fromtimestamp(st.st_mtime, dt.timezone.utc)


def _kind(m):
    if not m:
        return "unknown"
    if m.get("inventory_only"):
        return "inventory"
    return "recheck" if m.get("recheck") else "full"


def runs_dir(root):
    """The real runs directory, or raise ValueError when it is missing, not a directory, or a symbolic link."""
    d = os.path.join(os.path.abspath(root), "runs")
    try:
        st = os.lstat(d)
    except OSError:
        raise ValueError(f"{d} does not exist")
    if stat.S_ISLNK(st.st_mode):
        raise ValueError(f"{d} is a symbolic link; refusing to follow it")
    if not stat.S_ISDIR(st.st_mode):
        raise ValueError(f"{d} is not a directory")
    return d


def plan(root, days=DEFAULT_DAYS, now=None):
    """(delete, keep): delete = [(name, age_days, kind)]; keep = [(name, reason)] for old runs that are protected and
    for entries that are not plain directories."""
    if not isinstance(days, int) or days < 1:
        raise ValueError("--days must be a whole number of days, 1 or more")
    now = now or dt.datetime.now(dt.timezone.utc)
    rd = runs_dir(root)
    runs, keep = [], []
    for name in sorted(os.listdir(rd)):
        path = os.path.join(rd, name)
        st = os.lstat(path)
        if stat.S_ISLNK(st.st_mode):
            keep.append((name, "symbolic link, not followed"))
            continue
        if not stat.S_ISDIR(st.st_mode):
            continue                       # a stray file in runs/ is not a run directory
        m = _manifest(path)
        runs.append({"name": name, "kind": _kind(m), "when": _when(m, st), "base": m.get("base_run") if m.get("recheck") else None})
    protected = {}
    full = [r for r in runs if r["kind"] == "full"]
    if full:
        latest = max(full, key=lambda r: (r["when"], r["name"]))
        protected[latest["name"]] = "most recent full run"
    if runs:
        newest = max(runs, key=lambda r: (r["when"], r["name"]))
        if newest["kind"] == "unknown" and newest["name"] not in protected:
            protected[newest["name"]] = "newest run, manifest missing or unreadable"
    for r in runs:
        if r["base"] and r["base"] not in protected:
            protected[r["base"]] = f"base of recheck {r['name']}"
    delete = []
    for r in runs:
        age = (now - r["when"]).days
        if age < days:
            continue
        if r["name"] in protected:
            keep.append((r["name"], protected[r["name"]]))
            continue
        delete.append((r["name"], age, r["kind"]))
    return delete, keep


def _remove(rd, name):
    path = os.path.join(rd, name)
    real_rd = os.path.realpath(rd)
    if os.path.dirname(os.path.realpath(path)) != real_rd or os.path.basename(path) != name or name in (".", ".."):
        raise ValueError(f"{path} is not directly under {rd}")
    if stat.S_ISLNK(os.lstat(path).st_mode):
        raise ValueError(f"{path} became a symbolic link; not followed")
    # rmtree removes links inside the tree as links (it never follows them) and refuses a top-level link
    shutil.rmtree(path)


def main(argv=None):
    ap = argparse.ArgumentParser(description="List (and with --apply delete) run directories older than --days.")
    ap.add_argument("--root", default=os.environ.get("SCAN_ROOT"), help="scan root (default $SCAN_ROOT)")
    ap.add_argument("--days", type=int, default=DEFAULT_DAYS)
    ap.add_argument("--apply", action="store_true", help="delete; without it nothing is changed")
    a = ap.parse_args(argv)
    if not a.root:
        print("error: --root or SCAN_ROOT is required", file=sys.stderr)
        return 2
    try:
        delete, keep = plan(a.root, a.days)
        rd = runs_dir(a.root)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    for name, why in keep:
        print(f"keep runs/{name}: {why}")
    verb = "deleted" if a.apply else "would delete"
    for name, age, kind in delete:
        if a.apply:
            try:
                _remove(rd, name)
            except (OSError, ValueError) as e:
                print(f"error: runs/{name} not deleted: {e}", file=sys.stderr)
                continue
        print(f"{verb} runs/{name} ({kind} run, {age} days old)")
    if not delete:
        print(f"nothing older than {a.days} days to delete")
    elif not a.apply:
        print(f"{len(delete)} run(s) would be deleted; rerun with --apply to delete")
    return 0


if __name__ == "__main__":
    sys.exit(main())
