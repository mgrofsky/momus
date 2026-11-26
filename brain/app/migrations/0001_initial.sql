-- 0001: the app database. Written only by the brain. Times are ISO 8601 UTC text ("...Z").

CREATE TABLE users(
  id INTEGER PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  pw_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'admin' CHECK(role IN ('admin')),
  created_at TEXT NOT NULL,
  password_changed_at TEXT NOT NULL
);

-- server-side sessions: only the SHA-256 of the cookie value is stored
CREATE TABLE sessions(
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf TEXT NOT NULL,
  created_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  address TEXT,
  user_agent TEXT
);
CREATE INDEX sessions_user ON sessions(user_id);

CREATE TABLE login_attempts(
  id INTEGER PRIMARY KEY,
  username TEXT NOT NULL,
  address TEXT NOT NULL,
  at TEXT NOT NULL,
  ok INTEGER NOT NULL
);
CREATE INDEX login_attempts_user ON login_attempts(username, at);
CREATE INDEX login_attempts_addr ON login_attempts(address, at);

-- the one-time bootstrap token (hash only); used_at set once the first admin exists
CREATE TABLE bootstrap(
  id INTEGER PRIMARY KEY CHECK(id = 1),
  token_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  used_at TEXT
);

-- scope. kind 'lab' exists only for lab mode (the demo target). No DNS token is stored here: the scanner mints it.
CREATE TABLE domains(
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  kind TEXT NOT NULL DEFAULT 'domain' CHECK(kind IN ('domain', 'lab')),
  statement TEXT NOT NULL,
  attested_by TEXT NOT NULL,
  attested_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE exclusions(
  id INTEGER PRIMARY KEY,
  value TEXT NOT NULL UNIQUE,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE owned_ranges(
  id INTEGER PRIMARY KEY,
  cidr TEXT NOT NULL UNIQUE,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE approved_hosts(
  id INTEGER PRIMARY KEY,
  hostname TEXT NOT NULL UNIQUE,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL
);
-- approval of active phases after a human reviewed an inventory run; the newest active row is the one jobs carry
CREATE TABLE inventory_approvals(
  id INTEGER PRIMARY KEY,
  inventory_run TEXT NOT NULL,
  approved_by TEXT NOT NULL,
  approved_at TEXT NOT NULL,
  withdrawn_at TEXT,
  withdrawn_by TEXT
);
-- check, rate and evidence profile per scope (one scope per instance in this version: scope = 'default')
CREATE TABLE scope_profiles(
  scope TEXT PRIMARY KEY,
  check_profile TEXT NOT NULL DEFAULT 'safe' CHECK(check_profile IN ('safe', 'active')),
  rate_profile TEXT NOT NULL DEFAULT 'low' CHECK(rate_profile IN ('low', 'normal', 'fast')),
  evidence TEXT NOT NULL DEFAULT 'minimal' CHECK(evidence IN ('minimal', 'excerpt')),
  updated_by TEXT,
  updated_at TEXT
);
INSERT INTO scope_profiles(scope) VALUES('default');

-- schedules: hour and minute in UTC; day_of_month for the monthly run (a month without that day runs on its last day)
CREATE TABLE schedules(
  kind TEXT PRIMARY KEY CHECK(kind IN ('daily-recheck', 'monthly-full')),
  enabled INTEGER NOT NULL DEFAULT 0,
  hour INTEGER NOT NULL CHECK(hour BETWEEN 0 AND 23),
  minute INTEGER NOT NULL CHECK(minute BETWEEN 0 AND 59),
  day_of_month INTEGER CHECK(day_of_month BETWEEN 1 AND 31),
  last_slot TEXT,
  last_outcome TEXT,
  updated_by TEXT,
  updated_at TEXT
);
INSERT INTO schedules(kind, enabled, hour, minute, day_of_month) VALUES('daily-recheck', 0, 2, 0, NULL);
INSERT INTO schedules(kind, enabled, hour, minute, day_of_month) VALUES('monthly-full', 0, 3, 0, 1);

-- every job file the brain wrote
CREATE TABLE jobs(
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  trigger TEXT NOT NULL CHECK(trigger IN ('user', 'schedule', 'scope-change')),
  file_sha256 TEXT NOT NULL,
  summary TEXT
);

-- marks on findings. A mark never changes a score, verdict or status; it records the evidence fingerprint and the
-- run it was made against, so a reopened finding or changed evidence shows the mark as stale.
CREATE TABLE finding_marks(
  id INTEGER PRIMARY KEY,
  finding_key TEXT NOT NULL,
  kind TEXT NOT NULL CHECK(kind IN ('false_positive', 'accepted_risk', 'duplicate')),
  reason TEXT NOT NULL,
  evidence_fp TEXT NOT NULL,
  run_id TEXT NOT NULL,
  run_seq INTEGER NOT NULL,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  withdrawn_at TEXT,
  withdrawn_by TEXT
);
CREATE INDEX finding_marks_key ON finding_marks(finding_key);

CREATE TABLE notes(
  id INTEGER PRIMARY KEY,
  finding_key TEXT,
  body TEXT NOT NULL,
  source TEXT NOT NULL DEFAULT 'human' CHECK(source IN ('human', 'agent')),
  accepted_by TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE settings(
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_by TEXT,
  updated_at TEXT
);

-- append-only: the triggers below refuse every UPDATE and DELETE
CREATE TABLE audit_log(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at TEXT NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT,
  detail TEXT,
  address TEXT
);
CREATE INDEX audit_action ON audit_log(action);
CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_log BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit_log BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;

-- for the analyst step (empty in this version)
CREATE TABLE agent_runs(
  id INTEGER PRIMARY KEY,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  trigger TEXT NOT NULL,
  scan_run_id TEXT,
  provider TEXT,
  model TEXT,
  status TEXT NOT NULL,
  steps INTEGER NOT NULL DEFAULT 0,
  tokens_in INTEGER NOT NULL DEFAULT 0,
  tokens_out INTEGER NOT NULL DEFAULT 0,
  error TEXT
);
CREATE TABLE agent_messages(
  id INTEGER PRIMARY KEY,
  agent_run_id INTEGER NOT NULL REFERENCES agent_runs(id) ON DELETE CASCADE,
  seq INTEGER NOT NULL,
  role TEXT NOT NULL,
  content TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE proposals(
  id INTEGER PRIMARY KEY,
  agent_run_id INTEGER REFERENCES agent_runs(id),
  finding_key TEXT NOT NULL,
  kind TEXT NOT NULL,
  reason TEXT NOT NULL,
  evidence_fp TEXT,
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'accepted', 'rejected')),
  decided_by TEXT,
  decided_at TEXT,
  created_at TEXT NOT NULL
);
