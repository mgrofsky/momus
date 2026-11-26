-- 0004: version-watch definitions (what each version-watch job carries as options.watches) and a daily
-- version-watch schedule. cves, floors and hosts are JSON text in the canonical form (watches.py); the id never
-- changes once created, because it names the watch's results folder (published/version-watch/<id>/).
CREATE TABLE version_watches(
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  product TEXT NOT NULL,
  cves TEXT NOT NULL,
  floors TEXT NOT NULL,
  hosts TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  updated_by TEXT NOT NULL
);

-- the schedules table is rebuilt to allow the new kind (SQLite cannot change a CHECK constraint in place)
CREATE TABLE schedules_new(
  kind TEXT PRIMARY KEY CHECK(kind IN ('daily-recheck', 'monthly-full', 'daily-version-watch')),
  enabled INTEGER NOT NULL DEFAULT 0,
  hour INTEGER NOT NULL CHECK(hour BETWEEN 0 AND 23),
  minute INTEGER NOT NULL CHECK(minute BETWEEN 0 AND 59),
  day_of_month INTEGER CHECK(day_of_month BETWEEN 1 AND 31),
  last_slot TEXT,
  last_outcome TEXT,
  updated_by TEXT,
  updated_at TEXT
);
INSERT INTO schedules_new(kind, enabled, hour, minute, day_of_month, last_slot, last_outcome, updated_by, updated_at)
  SELECT kind, enabled, hour, minute, day_of_month, last_slot, last_outcome, updated_by, updated_at FROM schedules;
DROP TABLE schedules;
ALTER TABLE schedules_new RENAME TO schedules;
-- off by default, like the other schedules
INSERT INTO schedules(kind, enabled, hour, minute, day_of_month) VALUES('daily-version-watch', 0, 4, 0, NULL);
