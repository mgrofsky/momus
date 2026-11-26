-- Marks and proposals bound to the evidence shown; the sign-in flood index. Columns only; nothing is rebuilt.
-- A mark accepted from an analyst proposal records that proposal: its reason is the model's text, accepted by the
-- named person, and is labeled so wherever it is shown; the analyst's existing_marks tool does not return it.
ALTER TABLE finding_marks ADD COLUMN proposal_id INTEGER;            -- NULL: a manual mark, reason typed by a person
-- The finding's last scan run when the proposal was made, so a reopen after it makes the proposal out of date.
ALTER TABLE proposals ADD COLUMN finding_run_id TEXT;
-- Set when a person closed an out-of-date proposal (a rejection with this fixed reason).
ALTER TABLE proposals ADD COLUMN closed_reason TEXT;
-- 1 when any untrusted text a tool returned during the run matched the instruction word list (a hint, not a control).
ALTER TABLE agent_runs ADD COLUMN instruction_seen INTEGER NOT NULL DEFAULT 0;
-- The sign-in flood count reads failed attempts by time across all clients (auth.flooding).
CREATE INDEX login_attempts_at ON login_attempts(at);
