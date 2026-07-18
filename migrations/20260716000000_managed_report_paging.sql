-- Durable Manage acknowledgement and protected-artifact snapshot paging.

CREATE TABLE IF NOT EXISTS managed_build_job_report_acks (
    managed_job_id TEXT PRIMARY KEY,
    acknowledged_at TEXT NOT NULL,
    FOREIGN KEY (managed_job_id) REFERENCES forge_build_jobs(managed_job_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS managed_cache_protection_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    staging_snapshot_id TEXT NOT NULL DEFAULT '',
    staging_next_cursor INTEGER NOT NULL DEFAULT 0 CHECK (staging_next_cursor >= 0),
    staging_total_items INTEGER NOT NULL DEFAULT 0 CHECK (staging_total_items >= 0),
    authoritative INTEGER NOT NULL DEFAULT 0 CHECK (authoritative IN (0, 1)),
    authoritative_snapshot_id TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL
);

INSERT OR IGNORE INTO managed_cache_protection_state (
    singleton, staging_snapshot_id, staging_next_cursor, staging_total_items,
    authoritative, authoritative_snapshot_id, updated_at
) VALUES (1, '', 0, 0, 0, '', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));

CREATE TABLE IF NOT EXISTS managed_cache_protection_staging (
    snapshot_id TEXT NOT NULL,
    position INTEGER NOT NULL CHECK (position >= 0),
    artifact_type TEXT NOT NULL,
    hash TEXT NOT NULL,
    PRIMARY KEY (snapshot_id, position),
    UNIQUE (snapshot_id, artifact_type, hash)
);

CREATE INDEX IF NOT EXISTS idx_managed_build_job_report_acks_time
    ON managed_build_job_report_acks(acknowledged_at DESC);
