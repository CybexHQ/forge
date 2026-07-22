-- Durable, non-secret evidence that a legacy build crossed the reusable-input
-- boundary and that its exported static-cache root was withdrawn. Unreferenced
-- closure members are swept while members shared by retained roots remain.
-- The original BuildSpec is represented only by its SHA-256 digest; protected
-- bytes must never be copied into this ledger.
CREATE TABLE protected_build_job_remediations (
    job_id INTEGER PRIMARY KEY
        REFERENCES forge_build_jobs(id) ON DELETE RESTRICT,
    managed_job_id TEXT,
    original_status TEXT NOT NULL
        CHECK (original_status IN ('queued', 'running', 'succeeded', 'failed', 'cancelled')),
    rule TEXT NOT NULL
        CHECK (rule IN (
            'protected_build_spec',
            'protected_cache_metadata',
            'protected_build_spec_and_cache_metadata'
        )),
    build_spec_sha256 TEXT NOT NULL
        CHECK (
            length(build_spec_sha256) = 64
            AND build_spec_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    cache_purge_status TEXT NOT NULL DEFAULT 'pending_purge'
        CHECK (cache_purge_status IN ('pending_purge', 'purged')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    purged_at TEXT
);

CREATE INDEX idx_protected_build_job_remediations_pending
ON protected_build_job_remediations(cache_purge_status, job_id);

-- The identity of an incident record is immutable. Only the bounded cache
-- purge state and its timestamps may advance during idempotent remediation.
CREATE TRIGGER protected_build_job_remediation_identity_immutable
BEFORE UPDATE OF managed_job_id, original_status, rule, build_spec_sha256
ON protected_build_job_remediations
BEGIN
    SELECT RAISE(ABORT, 'protected build remediation identity is immutable');
END;

CREATE TRIGGER protected_build_job_remediation_delete_forbidden
BEFORE DELETE ON protected_build_job_remediations
BEGIN
    SELECT RAISE(ABORT, 'protected build remediation ledger is append-only');
END;
