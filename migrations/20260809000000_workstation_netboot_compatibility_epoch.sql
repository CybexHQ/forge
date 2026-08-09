-- Compatibility epochs are artifact/runtime identity, not an attribute of the
-- currently running Pulse binary. Existing rows predate the explicit field and
-- therefore belong to the legacy epoch-one contract.
ALTER TABLE workstation_netboot_runtime
    ADD COLUMN desired_compatibility_epoch INTEGER NOT NULL DEFAULT 1
    CHECK (desired_compatibility_epoch > 0);

ALTER TABLE workstation_netboot_bundles
    ADD COLUMN compatibility_epoch INTEGER NOT NULL DEFAULT 1
    CHECK (compatibility_epoch > 0);

CREATE TABLE workstation_netboot_watermarks (
    compatibility_epoch INTEGER NOT NULL CHECK (compatibility_epoch > 0),
    key_fingerprint TEXT NOT NULL,
    architecture TEXT NOT NULL,
    runtime_version TEXT NOT NULL,
    descriptor_sha256 TEXT NOT NULL,
    accepted_at TEXT NOT NULL,
    PRIMARY KEY (compatibility_epoch, key_fingerprint, architecture)
);

INSERT INTO workstation_netboot_watermarks
    (compatibility_epoch, key_fingerprint, architecture, runtime_version,
     descriptor_sha256, accepted_at)
SELECT 1, watermark_key_fingerprint, watermark_architecture,
       watermark_runtime_version, watermark_descriptor_sha256, updated_at
FROM workstation_netboot_runtime
WHERE singleton_id = 1 AND watermark_key_fingerprint <> '';

CREATE TABLE workstation_netboot_reconcile_watermarks (
    compatibility_epoch INTEGER PRIMARY KEY CHECK (compatibility_epoch > 0),
    reconcile_generation INTEGER NOT NULL CHECK (reconcile_generation >= 0),
    descriptor_sha256 TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

INSERT INTO workstation_netboot_reconcile_watermarks
    (compatibility_epoch, reconcile_generation, descriptor_sha256, updated_at)
SELECT 1, reconcile_generation, desired_descriptor_sha256, updated_at
FROM workstation_netboot_runtime
WHERE singleton_id = 1 AND desired_descriptor_sha256 <> '';

-- Retry bookkeeping is deliberately separate from authenticated desired state
-- and anti-rollback watermarks. An invalid candidate must not overwrite the
-- last trusted identity merely so repeated polls can be coalesced.
CREATE TABLE workstation_netboot_reconcile_attempts (
    compatibility_epoch INTEGER NOT NULL CHECK (compatibility_epoch > 0),
    reconcile_generation INTEGER NOT NULL CHECK (reconcile_generation >= 0),
    descriptor_sha256 TEXT NOT NULL CHECK (length(descriptor_sha256) = 64),
    failure_kind TEXT NOT NULL,
    attempt_count INTEGER NOT NULL CHECK (attempt_count > 0),
    terminal_hold INTEGER NOT NULL DEFAULT 0 CHECK (terminal_hold IN (0, 1)),
    next_attempt_at INTEGER,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (compatibility_epoch, reconcile_generation, descriptor_sha256)
);
