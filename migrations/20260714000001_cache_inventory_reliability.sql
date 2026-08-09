-- Persist inventory epochs/generations so Manage can distinguish a full current
-- snapshot from a legacy or truncated report. Triggers make every local cache
-- mutation advance the generation automatically.
CREATE TABLE IF NOT EXISTS cache_inventory_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    instance_id TEXT NOT NULL,
    generation INTEGER NOT NULL DEFAULT 0 CHECK (generation >= 0)
);

INSERT OR IGNORE INTO cache_inventory_state (singleton, instance_id, generation)
VALUES (1, lower(hex(randomblob(16))), 0);

CREATE TRIGGER IF NOT EXISTS pulse_cache_inventory_insert
AFTER INSERT ON pulse_cache_artifacts
BEGIN
    UPDATE cache_inventory_state SET generation = generation + 1 WHERE singleton = 1;
END;

CREATE TRIGGER IF NOT EXISTS pulse_cache_inventory_update
AFTER UPDATE ON pulse_cache_artifacts
BEGIN
    UPDATE cache_inventory_state SET generation = generation + 1 WHERE singleton = 1;
END;

CREATE TRIGGER IF NOT EXISTS pulse_cache_inventory_delete
AFTER DELETE ON pulse_cache_artifacts
BEGIN
    UPDATE cache_inventory_state SET generation = generation + 1 WHERE singleton = 1;
END;

CREATE TABLE IF NOT EXISTS managed_cache_protections (
    artifact_type TEXT NOT NULL,
    hash TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (artifact_type, hash)
);

ALTER TABLE pulse_cache_artifacts ADD COLUMN verification_status TEXT NOT NULL DEFAULT 'pending';
ALTER TABLE pulse_cache_artifacts ADD COLUMN last_verified_at TEXT;

ALTER TABLE boot_profiles ADD COLUMN sync_failure_kind TEXT NOT NULL DEFAULT '';
ALTER TABLE boot_profiles ADD COLUMN sync_retryable INTEGER NOT NULL DEFAULT 1;
ALTER TABLE boot_profiles ADD COLUMN sync_last_verified_at TEXT;

CREATE INDEX IF NOT EXISTS idx_pulse_cache_artifacts_verification
    ON pulse_cache_artifacts(last_verified_at, created_at, id);

CREATE INDEX IF NOT EXISTS idx_boot_profiles_sync_verification
    ON boot_profiles(sync_state, sync_last_verified_at, updated_at, id);
