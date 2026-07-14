ALTER TABLE boot_profiles ADD COLUMN sync_generation INTEGER NOT NULL DEFAULT 0;
ALTER TABLE boot_profiles ADD COLUMN sync_operation_id TEXT NOT NULL DEFAULT '';
ALTER TABLE boot_profiles ADD COLUMN sync_state TEXT NOT NULL DEFAULT 'idle';
ALTER TABLE boot_profiles ADD COLUMN sync_progress_percent INTEGER NOT NULL DEFAULT 0;
ALTER TABLE boot_profiles ADD COLUMN sync_bytes_downloaded INTEGER NOT NULL DEFAULT 0;
ALTER TABLE boot_profiles ADD COLUMN sync_total_bytes INTEGER NOT NULL DEFAULT 0;
ALTER TABLE boot_profiles ADD COLUMN sync_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE boot_profiles ADD COLUMN sync_next_attempt_at TEXT;
ALTER TABLE boot_profiles ADD COLUMN sync_error TEXT NOT NULL DEFAULT '';
ALTER TABLE boot_profiles ADD COLUMN sync_started_at TEXT;
ALTER TABLE boot_profiles ADD COLUMN sync_completed_at TEXT;
ALTER TABLE boot_profiles ADD COLUMN sync_failed_at TEXT;

CREATE INDEX IF NOT EXISTS idx_boot_profiles_sync_queue
    ON boot_profiles(sync_state, sync_next_attempt_at, is_default, enabled);
