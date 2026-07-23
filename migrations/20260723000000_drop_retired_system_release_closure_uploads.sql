PRAGMA foreign_keys = ON;

-- This acknowledgement table belonged to the retired System Releases
-- protocol. No supported Forge runtime reads or writes it. Keep the applied
-- historical migration immutable and remove the obsolete schema only through
-- this forward migration.
DROP TABLE IF EXISTS managed_system_release_closure_uploads;
