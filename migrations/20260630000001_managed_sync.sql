ALTER TABLE boot_profiles ADD COLUMN managed_profile_id TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_boot_profiles_managed_profile_id
ON boot_profiles(managed_profile_id)
WHERE managed_profile_id IS NOT NULL;

ALTER TABLE devices ADD COLUMN managed_client_id TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_managed_client_id
ON devices(managed_client_id)
WHERE managed_client_id IS NOT NULL;
