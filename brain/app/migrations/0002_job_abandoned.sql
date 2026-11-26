-- A job whose status file was lost stays "in flight" for ever: the admin can mark it abandoned (Runs page). The brain
-- then writes <job id>.abandoned in the jobs folder (the scanner never runs that id) and removes the job file.
ALTER TABLE jobs ADD COLUMN abandoned_at TEXT;
ALTER TABLE jobs ADD COLUMN abandoned_by TEXT;
