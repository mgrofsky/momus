-- The brain keeps each job's document. Columns only; nothing is rebuilt.
-- The job document the brain wrote, kept in its row: the brain removes the job file once the scanner publishes a
-- final status for it, and the scanner alone writes that status, so without this copy nobody could later compare
-- what was ordered with what the scanner reports. Written with the file at queue time; for a row from before this
-- migration, read from the file just before it is removed, and only when the file still matches file_sha256.
-- Bounded by the largest job file the brain writes (jobs.JOB_MAX_BYTES, the scanner's MAX_JOB_BYTES).
ALTER TABLE jobs ADD COLUMN document TEXT CHECK(document IS NULL OR length(CAST(document AS BLOB)) <= 1048576);
