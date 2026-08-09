ALTER TABLE pulse_build_jobs ADD COLUMN progress_percent INTEGER;
ALTER TABLE pulse_build_jobs ADD COLUMN progress_stage TEXT;
ALTER TABLE pulse_build_jobs ADD COLUMN progress_message TEXT;
