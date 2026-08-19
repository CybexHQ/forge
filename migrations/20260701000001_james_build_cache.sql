CREATE TABLE IF NOT EXISTS james_build_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    managed_job_id TEXT UNIQUE,
    requested_artifact_type TEXT NOT NULL,
    build_spec TEXT NOT NULL DEFAULT '{}',
    target TEXT NOT NULL DEFAULT '',
    system TEXT NOT NULL DEFAULT '',
    input_revision TEXT NOT NULL DEFAULT '',
    input_config_hash TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'cancelled')),
    logs TEXT NOT NULL DEFAULT '',
    error TEXT NOT NULL DEFAULT '',
    output_path TEXT NOT NULL DEFAULT '',
    output_sha256 TEXT NOT NULL DEFAULT '',
    output_size_bytes INTEGER NOT NULL DEFAULT 0,
    exit_code INTEGER,
    cache_metadata TEXT NOT NULL DEFAULT '{}',
    started_at TEXT,
    completed_at TEXT,
    cancel_requested_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_james_build_jobs_status_updated
ON james_build_jobs(status, updated_at DESC);

CREATE TABLE IF NOT EXISTS james_cache_artifacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    managed_artifact_id TEXT UNIQUE,
    artifact_type TEXT NOT NULL,
    hash TEXT NOT NULL,
    size_bytes INTEGER NOT NULL DEFAULT 0,
    path TEXT NOT NULL,
    store_path TEXT NOT NULL DEFAULT '',
    narinfo_path TEXT NOT NULL DEFAULT '',
    nar_url TEXT NOT NULL DEFAULT '',
    file_hash TEXT NOT NULL DEFAULT '',
    nar_hash TEXT NOT NULL DEFAULT '',
    nar_size_bytes INTEGER NOT NULL DEFAULT 0,
    closure_size_bytes INTEGER NOT NULL DEFAULT 0,
    compression TEXT NOT NULL DEFAULT '',
    references_json TEXT NOT NULL DEFAULT '[]',
    serving_url TEXT NOT NULL DEFAULT '',
    source_build_job_id TEXT,
    cache_metadata TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (artifact_type, hash)
);

CREATE INDEX IF NOT EXISTS idx_james_cache_artifacts_created
ON james_cache_artifacts(created_at DESC);
