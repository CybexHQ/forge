-- Avoid re-reading every ISO on each managed heartbeat while retaining a
-- durable identity for change detection and a separate checksum-verification
-- timestamp for bounded periodic integrity checks.
ALTER TABLE iso_assets ADD COLUMN file_device INTEGER;
ALTER TABLE iso_assets ADD COLUMN file_inode INTEGER;
ALTER TABLE iso_assets ADD COLUMN file_mtime_seconds INTEGER;
ALTER TABLE iso_assets ADD COLUMN file_mtime_nanoseconds INTEGER;
ALTER TABLE iso_assets ADD COLUMN file_ctime_seconds INTEGER;
ALTER TABLE iso_assets ADD COLUMN file_ctime_nanoseconds INTEGER;
ALTER TABLE iso_assets ADD COLUMN checksum_verified_at TEXT;

UPDATE iso_assets
SET checksum_verified_at = last_scanned_at
WHERE checksum_verified_at IS NULL;
