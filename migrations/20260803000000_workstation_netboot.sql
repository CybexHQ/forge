CREATE TABLE workstation_netboot_runtime (
    singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
    desired_descriptor_json TEXT NOT NULL DEFAULT '',
    desired_descriptor_sha256 TEXT NOT NULL DEFAULT '',
    reconcile_generation INTEGER NOT NULL DEFAULT 0 CHECK (reconcile_generation >= 0),
    state TEXT NOT NULL DEFAULT 'absent' CHECK (state IN ('absent', 'queued', 'downloading', 'verifying', 'extracting', 'ready', 'failed', 'held')),
    progress_percent INTEGER NOT NULL DEFAULT 0 CHECK (progress_percent BETWEEN 0 AND 100),
    bytes_downloaded INTEGER NOT NULL DEFAULT 0 CHECK (bytes_downloaded >= 0),
    total_bytes INTEGER NOT NULL DEFAULT 0 CHECK (total_bytes >= 0),
    failure_kind TEXT NOT NULL DEFAULT '',
    failure_message TEXT NOT NULL DEFAULT '',
    active_bundle_sha256 TEXT NOT NULL DEFAULT '',
    previous_bundle_sha256 TEXT NOT NULL DEFAULT '',
    watermark_key_fingerprint TEXT NOT NULL DEFAULT '',
    watermark_architecture TEXT NOT NULL DEFAULT '',
    watermark_runtime_version TEXT NOT NULL DEFAULT '',
    watermark_descriptor_sha256 TEXT NOT NULL DEFAULT '',
    last_verified_at TEXT,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO workstation_netboot_runtime (singleton_id) VALUES (1);

ALTER TABLE devices ADD COLUMN managed_device_id TEXT;
ALTER TABLE devices ADD COLUMN reinstall_request_id TEXT;

PRAGMA foreign_keys = OFF;

CREATE TABLE boot_profiles_v4 (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    profile_type TEXT NOT NULL CHECK (profile_type IN ('local_disk', 'pulse_installer', 'custom_ipxe')),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    is_default INTEGER NOT NULL DEFAULT 0 CHECK (is_default IN (0, 1)),
    one_time INTEGER NOT NULL DEFAULT 0 CHECK (one_time IN (0, 1)),
    raw_script TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    managed_profile_id TEXT
);

INSERT INTO boot_profiles_v4
    (id, name, description, profile_type, enabled, is_default, one_time,
     raw_script, created_at, updated_at, managed_profile_id)
SELECT id, name, description,
       CASE WHEN profile_type = 'linux_installer' AND managed_profile_id IS NOT NULL
            THEN 'pulse_installer' ELSE profile_type END,
       enabled, is_default, one_time, raw_script, created_at, updated_at,
       managed_profile_id
FROM boot_profiles
WHERE profile_type IN ('local_disk', 'custom_ipxe')
   OR (profile_type = 'linux_installer' AND managed_profile_id IS NOT NULL);

UPDATE devices SET default_profile_id = NULL
WHERE default_profile_id NOT IN (SELECT id FROM boot_profiles_v4);
UPDATE devices SET one_time_profile_id = NULL, one_time_consumed_at = NULL
WHERE one_time_profile_id NOT IN (SELECT id FROM boot_profiles_v4);
UPDATE devices SET last_selected_profile_id = NULL
WHERE last_selected_profile_id NOT IN (SELECT id FROM boot_profiles_v4);
UPDATE boot_events SET selected_profile_id = NULL
WHERE selected_profile_id NOT IN (SELECT id FROM boot_profiles_v4);

DROP TABLE boot_profiles;
ALTER TABLE boot_profiles_v4 RENAME TO boot_profiles;
DROP TABLE iso_assets;

CREATE UNIQUE INDEX idx_boot_profiles_single_default
ON boot_profiles(is_default) WHERE is_default = 1;
CREATE UNIQUE INDEX idx_boot_profiles_managed_profile_id
ON boot_profiles(managed_profile_id) WHERE managed_profile_id IS NOT NULL;

PRAGMA foreign_keys = ON;

CREATE TABLE workstation_netboot_bundles (
    bundle_sha256 TEXT PRIMARY KEY,
    runtime_version TEXT NOT NULL,
    manage_source_revision TEXT NOT NULL,
    nixpkgs_revision TEXT NOT NULL,
    architecture TEXT NOT NULL,
    manifest_sha256 TEXT NOT NULL,
    descriptor_json TEXT NOT NULL,
    root_path TEXT NOT NULL,
    size_bytes INTEGER NOT NULL CHECK (size_bytes > 0),
    retention_state TEXT NOT NULL DEFAULT 'verified' CHECK (retention_state IN ('verified', 'quarantined')),
    verified_at TEXT NOT NULL,
    last_scrubbed_at TEXT,
    last_served_at TEXT,
    retained_until TEXT,
    quarantined_at TEXT,
    quarantine_reason TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE pulse_boot_sessions (
    session_id TEXT PRIMARY KEY,
    nonce_sha256 TEXT NOT NULL UNIQUE,
    normalized_mac TEXT NOT NULL,
    profile_id TEXT,
    managed_device_id TEXT,
    reinstall_request_id TEXT,
    bundle_sha256 TEXT NOT NULL,
    context_path TEXT NOT NULL,
    issued_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    cleanup_after INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_pulse_boot_sessions_cleanup ON pulse_boot_sessions(cleanup_after);
