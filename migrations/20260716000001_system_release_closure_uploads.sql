PRAGMA foreign_keys = ON;

-- Durable local acknowledgement prevents repeatedly uploading a potentially
-- large canonical closure on every cache-inventory snapshot. The key is the
-- exact managed artifact/job/digest tuple; replacing an artifact creates a new
-- immutable identity instead of mutating this acknowledgement.
CREATE TABLE managed_system_release_closure_uploads (
    local_artifact_id INTEGER NOT NULL,
    managed_artifact_id TEXT NOT NULL,
    managed_job_id TEXT NOT NULL,
    build_spec_sha256 TEXT NOT NULL,
    closure_sha256 TEXT NOT NULL,
    closure_size_bytes INTEGER NOT NULL
        CHECK (closure_size_bytes BETWEEN 2 AND 16777216),
    uploaded_at TEXT NOT NULL,
    PRIMARY KEY (local_artifact_id, managed_job_id, closure_sha256),
    FOREIGN KEY (local_artifact_id)
        REFERENCES james_cache_artifacts(id) ON DELETE CASCADE
);

CREATE INDEX idx_managed_system_release_closure_upload_identity
    ON managed_system_release_closure_uploads(
        managed_artifact_id,
        managed_job_id,
        closure_sha256
    );
