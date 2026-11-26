-- 0003: a sign-in attempt is recorded as pending (ok NULL) before its password is hashed, so a parallel burst
-- counts every attempt in flight. Attempt rows are pruned once no limit reads them; the audit log stays append-only.
CREATE TABLE login_attempts_new(
  id INTEGER PRIMARY KEY,
  username TEXT NOT NULL,
  address TEXT NOT NULL,
  at TEXT NOT NULL,
  ok INTEGER CHECK(ok IS NULL OR ok IN (0, 1))
);
INSERT INTO login_attempts_new(id, username, address, at, ok) SELECT id, username, address, at, ok FROM login_attempts;
DROP TABLE login_attempts;
ALTER TABLE login_attempts_new RENAME TO login_attempts;
CREATE INDEX login_attempts_user ON login_attempts(username, at);
CREATE INDEX login_attempts_addr ON login_attempts(address, at);
