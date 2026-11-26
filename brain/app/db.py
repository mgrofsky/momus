"""The app database: SQLite in WAL mode, numbered SQL migrations, a schema-version table. Written only by the brain."""
import datetime as dt
import os
import re
import sqlite3

MIGRATIONS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "migrations")
_MIG_RE = re.compile(r"^(\d{4})_([a-z0-9_]+)\.sql$")


def now():
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def iso(t=None):
    return (t or now()).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(s):
    return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))


def connect(path):
    db = sqlite3.connect(path, timeout=10, isolation_level=None, check_same_thread=False)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    db.execute("PRAGMA busy_timeout=10000")
    db.execute("PRAGMA trusted_schema=OFF")
    return db


def migrations():
    out = []
    for f in sorted(os.listdir(MIGRATIONS)):
        m = _MIG_RE.fullmatch(f)
        if m:
            out.append((int(m.group(1)), m.group(2), os.path.join(MIGRATIONS, f)))
    return out


def migrate(path):
    """Create or upgrade the database. Each migration runs in its own transaction with its version row."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    db = connect(path)
    try:
        mode = db.execute("PRAGMA journal_mode=WAL").fetchone()[0]
        if mode.lower() != "wal":
            raise RuntimeError(f"the app database could not switch to WAL mode (got {mode})")
        db.execute("CREATE TABLE IF NOT EXISTS schema_version(version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)")
        have = {r[0] for r in db.execute("SELECT version FROM schema_version")}
        applied = []
        for ver, name, p in migrations():
            if ver in have:
                continue
            with open(p, encoding="utf-8") as fh:
                sql = fh.read()
            stamp = iso()
            db.executescript(f"BEGIN;\n{sql}\nINSERT INTO schema_version VALUES({ver}, '{name}', '{stamp}');\nCOMMIT;")
            applied.append(ver)
        return applied
    finally:
        db.close()


def schema_version(db):
    r = db.execute("SELECT MAX(version) FROM schema_version").fetchone()
    return r[0] if r else None
