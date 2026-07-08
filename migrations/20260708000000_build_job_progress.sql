ALTER TABLE forge_build_jobs ADD COLUMN progress_percent INTEGER;
ALTER TABLE forge_build_jobs ADD COLUMN progress_stage TEXT;
ALTER TABLE forge_build_jobs ADD COLUMN progress_message TEXT;
