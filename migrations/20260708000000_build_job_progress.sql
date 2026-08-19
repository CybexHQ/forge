ALTER TABLE james_build_jobs ADD COLUMN progress_percent INTEGER;
ALTER TABLE james_build_jobs ADD COLUMN progress_stage TEXT;
ALTER TABLE james_build_jobs ADD COLUMN progress_message TEXT;
