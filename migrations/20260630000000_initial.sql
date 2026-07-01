CREATE TABLE IF NOT EXISTS boot_profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    profile_type TEXT NOT NULL CHECK (profile_type IN ('local_disk', 'iso_live', 'linux_installer', 'custom_ipxe')),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    is_default INTEGER NOT NULL DEFAULT 0 CHECK (is_default IN (0, 1)),
    one_time INTEGER NOT NULL DEFAULT 0 CHECK (one_time IN (0, 1)),
    kernel_path TEXT,
    initrd_path TEXT,
    iso_path TEXT,
    cmdline TEXT,
    raw_script TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_boot_profiles_single_default
ON boot_profiles(is_default)
WHERE is_default = 1;

CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac TEXT NOT NULL UNIQUE COLLATE NOCASE,
    hostname TEXT,
    serial_number TEXT UNIQUE,
    last_seen_at TEXT,
    last_selected_profile_id INTEGER REFERENCES boot_profiles(id) ON DELETE SET NULL,
    notes TEXT NOT NULL DEFAULT '',
    tags TEXT NOT NULL DEFAULT '[]',
    default_profile_id INTEGER REFERENCES boot_profiles(id) ON DELETE SET NULL,
    one_time_profile_id INTEGER REFERENCES boot_profiles(id) ON DELETE SET NULL,
    one_time_consumed_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_devices_last_seen
ON devices(last_seen_at);

CREATE INDEX IF NOT EXISTS idx_devices_serial
ON devices(serial_number);

CREATE TABLE IF NOT EXISTS boot_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER REFERENCES devices(id) ON DELETE SET NULL,
    mac TEXT,
    serial_number TEXT,
    ip_address TEXT,
    user_agent TEXT,
    selected_profile_id INTEGER REFERENCES boot_profiles(id) ON DELETE SET NULL,
    selected_profile_name TEXT,
    known_device INTEGER NOT NULL CHECK (known_device IN (0, 1)),
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_boot_events_created
ON boot_events(created_at);

CREATE INDEX IF NOT EXISTS idx_boot_events_mac
ON boot_events(mac);

CREATE TABLE IF NOT EXISTS iso_assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    relative_path TEXT NOT NULL UNIQUE,
    size_bytes INTEGER NOT NULL,
    checksum_sha256 TEXT NOT NULL,
    last_scanned_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

INSERT INTO boot_profiles
    (name, description, profile_type, enabled, is_default, one_time, created_at, updated_at)
SELECT
    'Local disk',
    'Return control to UEFI firmware so the next local boot target can start.',
    'local_disk',
    1,
    1,
    0,
    datetime('now'),
    datetime('now')
WHERE NOT EXISTS (SELECT 1 FROM boot_profiles WHERE profile_type = 'local_disk');
