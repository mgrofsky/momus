-- The analyst. agent_runs and notes gain columns; proposals is rebuilt for notes and references (it was an
-- empty placeholder); agent_steps records every step of a run. Prompts and responses go to agent_messages only when
-- MOMUS_ANALYST_DEBUG is on (never in lab mode).

ALTER TABLE agent_runs ADD COLUMN kind TEXT NOT NULL DEFAULT 'brief';            -- brief | chat
ALTER TABLE agent_runs ADD COLUMN requested_by TEXT;                             -- signed-in user, or 'scheduler'
ALTER TABLE agent_runs ADD COLUMN snapshot_sha256 TEXT;
ALTER TABLE agent_runs ADD COLUMN metadata_only INTEGER NOT NULL DEFAULT 0;
ALTER TABLE agent_runs ADD COLUMN outcome TEXT;                                  -- ok, or the limit or failure that ended it
ALTER TABLE agent_runs ADD COLUMN limits_json TEXT;                              -- the limits in force for this run
ALTER TABLE agent_runs ADD COLUMN question TEXT;                                 -- chat: what the person asked
ALTER TABLE agent_runs ADD COLUMN result_json TEXT;                              -- the validated final answer (model text)
ALTER TABLE agent_runs ADD COLUMN facts_json TEXT;                               -- brief: counts and lists computed by the application
ALTER TABLE agent_runs ADD COLUMN dropped_json TEXT;                             -- what the validator dropped, and why
ALTER TABLE agent_runs ADD COLUMN tools_json TEXT;                               -- the tools called, in order
ALTER TABLE agent_runs ADD COLUMN invalid_answers INTEGER NOT NULL DEFAULT 0;
CREATE INDEX agent_runs_started ON agent_runs(started_at);

CREATE TABLE agent_steps(
  id INTEGER PRIMARY KEY,
  agent_run_id INTEGER NOT NULL REFERENCES agent_runs(id) ON DELETE CASCADE,
  step INTEGER NOT NULL,
  kind TEXT NOT NULL CHECK(kind IN ('tool', 'final', 'invalid', 'error')),
  tool TEXT,
  arguments TEXT,            -- the tool call's arguments as the model wrote them (JSON, capped), or NULL: model text,
                             -- not validated when the call was refused (shown labeled as the model's own text)
  result_bytes INTEGER,      -- size of the tool result sent back to the model
  tokens_in INTEGER NOT NULL DEFAULT 0,
  tokens_out INTEGER NOT NULL DEFAULT 0,
  error TEXT,                -- a fixed message, never provider or model text
  created_at TEXT NOT NULL
);
CREATE INDEX agent_steps_run ON agent_steps(agent_run_id, step);

CREATE TABLE proposals_new(
  id INTEGER PRIMARY KEY,
  agent_run_id INTEGER NOT NULL REFERENCES agent_runs(id),
  kind TEXT NOT NULL CHECK(kind IN ('false_positive', 'duplicate', 'accepted_risk', 'note')),
  finding_key TEXT,                               -- required for marks; optional for notes
  reason TEXT NOT NULL,                           -- the model's text (shown escaped, as the model's)
  references_json TEXT NOT NULL DEFAULT '[]',
  evidence_fp TEXT,                               -- the finding's evidence fingerprint when it was proposed
  snapshot_sha256 TEXT,
  instruction_warning INTEGER NOT NULL DEFAULT 0, -- the finding's stored text reads like instructions to an AI (a hint)
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'accepted', 'rejected')),
  decided_by TEXT,
  decided_at TEXT,
  created_at TEXT NOT NULL
);
INSERT INTO proposals_new(id, agent_run_id, kind, finding_key, reason, evidence_fp, status, decided_by, decided_at, created_at)
  SELECT id, agent_run_id, kind, finding_key, reason, evidence_fp, status, decided_by, decided_at, created_at FROM proposals
  WHERE agent_run_id IS NOT NULL AND kind IN ('false_positive', 'duplicate', 'accepted_risk');
DROP TABLE proposals;
ALTER TABLE proposals_new RENAME TO proposals;
CREATE INDEX proposals_status ON proposals(status, id);

ALTER TABLE notes ADD COLUMN agent_run_id INTEGER;
ALTER TABLE notes ADD COLUMN proposal_id INTEGER;
