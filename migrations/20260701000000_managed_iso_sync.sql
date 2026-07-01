ALTER TABLE boot_profiles ADD COLUMN installer_iso_source TEXT NOT NULL DEFAULT 'boot_profile';
ALTER TABLE boot_profiles ADD COLUMN desired_iso_artifact_id TEXT NOT NULL DEFAULT '';
ALTER TABLE boot_profiles ADD COLUMN desired_iso_filename TEXT NOT NULL DEFAULT '';
ALTER TABLE boot_profiles ADD COLUMN desired_iso_size_bytes INTEGER NOT NULL DEFAULT 0;
ALTER TABLE boot_profiles ADD COLUMN desired_iso_sha256 TEXT NOT NULL DEFAULT '';
ALTER TABLE boot_profiles ADD COLUMN desired_iso_built_at TEXT;
ALTER TABLE boot_profiles ADD COLUMN desired_iso_url TEXT NOT NULL DEFAULT '';
ALTER TABLE boot_profiles ADD COLUMN desired_iso_download_url TEXT NOT NULL DEFAULT '';
