use std::{collections::HashSet, fs, path::Path, str::FromStr};

use chrono::Utc;
use serde_json::{Value, json};
use sqlx::{
    FromRow, SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
};

use crate::{
    assets::sanitize_relative_path,
    config::AppConfig,
    error::{AppError, AppResult},
    models::{
        BootEvent, BootProfile, BootProfileType, BuildJob, CacheArtifact, CreateBootProfileRequest,
        CreateBuildJobRequest, CreateCacheArtifactRequest, CreateDeviceRequest, Device, IsoAsset,
        NewBootEvent, UpdateBootProfileRequest, UpdateDeviceRequest, clean_optional_string,
        clean_tags, normalize_mac,
    },
};

const MAX_BOOT_EVENTS_RETAINED: i64 = 10_000;
const MAX_AUTO_DISCOVERED_DEVICES_RETAINED: i64 = 2_000;
const MAX_DEVICE_HOSTNAME_CHARS: usize = 253;
const MAX_DEVICE_SERIAL_CHARS: usize = 128;
const MAX_DEVICE_NOTES_CHARS: usize = 2_000;
const MAX_DEVICE_TAGS: usize = 50;
const MAX_DEVICE_TAG_CHARS: usize = 64;
const MAX_PROFILE_DESCRIPTION_CHARS: usize = 2_000;
const MAX_PROFILE_RAW_SCRIPT_BYTES: usize = 64 * 1024;
const MAX_BUILD_LOG_BYTES: usize = 64 * 1024;
const MAX_BUILD_ERROR_CHARS: usize = 2_000;
const MAX_CACHE_METADATA_BYTES: usize = 16 * 1024;
const ALLOWED_BUILD_STATES: &[&str] = &["queued", "running", "succeeded", "failed", "cancelled"];

pub fn ensure_directories(config: &AppConfig) -> std::io::Result<()> {
    fs::create_dir_all(&config.paths.data_dir)?;
    set_private_dir_permissions(&config.paths.data_dir)?;
    fs::create_dir_all(&config.paths.boot_assets_dir)?;
    fs::create_dir_all(&config.paths.iso_dir)?;
    fs::create_dir_all(&config.paths.static_dir)?;
    fs::create_dir_all(&config.paths.tftp_dir)?;
    fs::create_dir_all(&config.build.work_dir)?;
    set_private_dir_permissions(&config.build.work_dir)?;
    fs::create_dir_all(&config.build.output_dir)?;
    set_private_dir_permissions(&config.build.output_dir)?;
    fs::create_dir_all(&config.cache.root_dir)?;
    if let Some(parent) = config.cache.private_key_path.parent() {
        fs::create_dir_all(parent)?;
        set_private_dir_permissions(parent)?;
    }
    if let Some(parent) = config.manage.state_path.parent() {
        fs::create_dir_all(parent)?;
        set_private_dir_permissions(parent)?;
    }
    Ok(())
}

pub async fn connect(config: &AppConfig) -> AppResult<SqlitePool> {
    if let Some(parent) = config.paths.database_path.parent() {
        fs::create_dir_all(parent)?;
        set_private_dir_permissions(parent)?;
    }

    let database_url = format!("sqlite://{}", config.paths.database_path.display());
    connect_with_url(&database_url).await
}

#[cfg(unix)]
fn set_private_dir_permissions(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn set_private_dir_permissions(_path: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}

pub async fn connect_with_url(database_url: &str) -> AppResult<SqlitePool> {
    let options = SqliteConnectOptions::from_str(database_url)
        .map_err(|err| AppError::Config(err.to_string()))?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .foreign_keys(true);

    Ok(SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await?)
}

pub async fn migrate(pool: &SqlitePool) -> AppResult<()> {
    sqlx::migrate!("./migrations")
        .run(pool)
        .await
        .map_err(|err| AppError::Config(err.to_string()))?;
    Ok(())
}

pub fn now_rfc3339() -> String {
    Utc::now().to_rfc3339()
}

#[derive(Debug, FromRow)]
struct DeviceRow {
    id: i64,
    mac: String,
    hostname: Option<String>,
    serial_number: Option<String>,
    last_seen_at: Option<String>,
    last_selected_profile_id: Option<i64>,
    notes: String,
    tags: String,
    default_profile_id: Option<i64>,
    one_time_profile_id: Option<i64>,
    one_time_consumed_at: Option<String>,
    created_at: String,
    updated_at: String,
}

impl From<DeviceRow> for Device {
    fn from(row: DeviceRow) -> Self {
        let tags = serde_json::from_str(&row.tags).unwrap_or_default();
        Self {
            id: row.id,
            mac: row.mac,
            hostname: row.hostname,
            serial_number: row.serial_number,
            last_seen_at: row.last_seen_at,
            last_selected_profile_id: row.last_selected_profile_id,
            notes: row.notes,
            tags,
            default_profile_id: row.default_profile_id,
            one_time_profile_id: row.one_time_profile_id,
            one_time_consumed_at: row.one_time_consumed_at,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

#[derive(Debug, FromRow)]
struct BootProfileRow {
    id: i64,
    managed_profile_id: Option<String>,
    name: String,
    description: String,
    profile_type: String,
    installer_iso_source: String,
    enabled: i64,
    is_default: i64,
    one_time: i64,
    kernel_path: Option<String>,
    initrd_path: Option<String>,
    iso_path: Option<String>,
    cmdline: Option<String>,
    raw_script: Option<String>,
    desired_iso_artifact_id: String,
    desired_iso_filename: String,
    desired_iso_size_bytes: i64,
    desired_iso_sha256: String,
    desired_iso_built_at: Option<String>,
    desired_iso_url: String,
    desired_iso_download_url: String,
    created_at: String,
    updated_at: String,
}

impl TryFrom<BootProfileRow> for BootProfile {
    type Error = AppError;

    fn try_from(row: BootProfileRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: row.id,
            managed_profile_id: row.managed_profile_id,
            name: row.name,
            description: row.description,
            profile_type: BootProfileType::from_str(&row.profile_type)?,
            installer_iso_source: row.installer_iso_source,
            enabled: row.enabled != 0,
            is_default: row.is_default != 0,
            one_time: row.one_time != 0,
            kernel_path: row.kernel_path,
            initrd_path: row.initrd_path,
            iso_path: row.iso_path,
            cmdline: row.cmdline,
            raw_script: row.raw_script,
            desired_iso_artifact_id: row.desired_iso_artifact_id,
            desired_iso_filename: row.desired_iso_filename,
            desired_iso_size_bytes: row.desired_iso_size_bytes,
            desired_iso_sha256: row.desired_iso_sha256,
            desired_iso_built_at: row.desired_iso_built_at,
            desired_iso_url: row.desired_iso_url,
            desired_iso_download_url: row.desired_iso_download_url,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

#[derive(Debug, FromRow)]
struct BootEventRow {
    id: i64,
    device_id: Option<i64>,
    mac: Option<String>,
    serial_number: Option<String>,
    ip_address: Option<String>,
    user_agent: Option<String>,
    selected_profile_id: Option<i64>,
    selected_profile_name: Option<String>,
    known_device: i64,
    created_at: String,
}

impl From<BootEventRow> for BootEvent {
    fn from(row: BootEventRow) -> Self {
        Self {
            id: row.id,
            device_id: row.device_id,
            mac: row.mac,
            serial_number: row.serial_number,
            ip_address: row.ip_address,
            user_agent: row.user_agent,
            selected_profile_id: row.selected_profile_id,
            selected_profile_name: row.selected_profile_name,
            known_device: row.known_device != 0,
            created_at: row.created_at,
        }
    }
}

#[derive(Debug, FromRow)]
struct IsoAssetRow {
    id: i64,
    filename: String,
    relative_path: String,
    size_bytes: i64,
    checksum_sha256: String,
    last_scanned_at: String,
    created_at: String,
    updated_at: String,
}

impl From<IsoAssetRow> for IsoAsset {
    fn from(row: IsoAssetRow) -> Self {
        Self {
            id: row.id,
            filename: row.filename,
            relative_path: row.relative_path,
            size_bytes: row.size_bytes,
            checksum_sha256: row.checksum_sha256,
            last_scanned_at: row.last_scanned_at,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

#[derive(Debug, FromRow)]
struct BuildJobRow {
    id: i64,
    managed_job_id: Option<String>,
    requested_artifact_type: String,
    build_spec: String,
    target: String,
    system: String,
    input_revision: String,
    input_config_hash: String,
    status: String,
    logs: String,
    error: String,
    output_path: String,
    output_sha256: String,
    output_size_bytes: i64,
    exit_code: Option<i64>,
    cache_metadata: String,
    started_at: Option<String>,
    completed_at: Option<String>,
    cancel_requested_at: Option<String>,
    created_at: String,
    updated_at: String,
}

impl TryFrom<BuildJobRow> for BuildJob {
    type Error = AppError;

    fn try_from(row: BuildJobRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: row.id,
            managed_job_id: row.managed_job_id,
            requested_artifact_type: row.requested_artifact_type,
            build_spec: metadata_from_db(&row.build_spec, "build job build_spec")?,
            target: row.target,
            system: row.system,
            input_revision: row.input_revision,
            input_config_hash: row.input_config_hash,
            status: row.status,
            logs: row.logs,
            error: row.error,
            output_path: row.output_path,
            output_sha256: row.output_sha256,
            output_size_bytes: row.output_size_bytes,
            exit_code: row.exit_code,
            cache_metadata: metadata_from_db(&row.cache_metadata, "build job cache_metadata")?,
            started_at: row.started_at,
            completed_at: row.completed_at,
            cancel_requested_at: row.cancel_requested_at,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

#[derive(Debug, FromRow)]
struct CacheArtifactRow {
    id: i64,
    managed_artifact_id: Option<String>,
    artifact_type: String,
    hash: String,
    size_bytes: i64,
    path: String,
    store_path: String,
    narinfo_path: String,
    nar_url: String,
    file_hash: String,
    nar_hash: String,
    nar_size_bytes: i64,
    closure_size_bytes: i64,
    compression: String,
    references_json: String,
    serving_url: String,
    source_build_job_id: Option<String>,
    cache_metadata: String,
    created_at: String,
    updated_at: String,
}

impl TryFrom<CacheArtifactRow> for CacheArtifact {
    type Error = AppError;

    fn try_from(row: CacheArtifactRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: row.id,
            managed_artifact_id: row.managed_artifact_id,
            artifact_type: row.artifact_type,
            hash: row.hash,
            size_bytes: row.size_bytes,
            path: row.path,
            store_path: row.store_path,
            narinfo_path: row.narinfo_path,
            nar_url: row.nar_url,
            file_hash: row.file_hash,
            nar_hash: row.nar_hash,
            nar_size_bytes: row.nar_size_bytes,
            closure_size_bytes: row.closure_size_bytes,
            compression: row.compression,
            references: json_from_db(&row.references_json, "cache artifact references_json")?,
            serving_url: row.serving_url,
            source_build_job_id: row.source_build_job_id,
            cache_metadata: metadata_from_db(&row.cache_metadata, "cache artifact metadata")?,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

pub async fn list_devices(pool: &SqlitePool) -> AppResult<Vec<Device>> {
    let rows = sqlx::query_as::<_, DeviceRow>(
        "SELECT * FROM devices ORDER BY COALESCE(last_seen_at, created_at) DESC, mac ASC",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(Device::from).collect())
}

pub async fn get_device(pool: &SqlitePool, id: i64) -> AppResult<Device> {
    let row = sqlx::query_as::<_, DeviceRow>("SELECT * FROM devices WHERE id = ?")
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(row.into())
}

pub async fn get_device_by_mac(pool: &SqlitePool, mac: &str) -> AppResult<Option<Device>> {
    let mac = normalize_mac(mac)?;
    let row = sqlx::query_as::<_, DeviceRow>("SELECT * FROM devices WHERE mac = ?")
        .bind(mac)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(Device::from))
}

pub async fn get_device_by_serial(pool: &SqlitePool, serial: &str) -> AppResult<Option<Device>> {
    let serial = serial.trim();
    if serial.is_empty() || serial.len() > 128 {
        return Ok(None);
    }
    let row = sqlx::query_as::<_, DeviceRow>("SELECT * FROM devices WHERE serial_number = ?")
        .bind(serial)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(Device::from))
}

pub async fn upsert_seen_device(
    pool: &SqlitePool,
    mac: &str,
    serial_number: Option<&str>,
) -> AppResult<(Device, bool)> {
    upsert_seen_device_with_retention(
        pool,
        mac,
        serial_number,
        MAX_AUTO_DISCOVERED_DEVICES_RETAINED,
    )
    .await
}

async fn upsert_seen_device_with_retention(
    pool: &SqlitePool,
    mac: &str,
    serial_number: Option<&str>,
    max_auto_devices: i64,
) -> AppResult<(Device, bool)> {
    let mac = normalize_mac(mac)?;
    let now = now_rfc3339();
    if let Some(existing) = get_device_by_mac(pool, &mac).await? {
        let serial = seen_device_serial_number(
            pool,
            existing.id,
            existing.serial_number.clone(),
            serial_number,
        )
        .await?;
        sqlx::query(
            "UPDATE devices
             SET last_seen_at = ?, serial_number = ?, updated_at = ?
             WHERE id = ?",
        )
        .bind(&now)
        .bind(serial)
        .bind(&now)
        .bind(existing.id)
        .execute(pool)
        .await?;
        return Ok((get_device(pool, existing.id).await?, true));
    }

    if let Some(serial) = serial_number.and_then(clean_str_ref) {
        if let Some(existing) = get_device_by_serial(pool, &serial).await? {
            sqlx::query("UPDATE devices SET last_seen_at = ?, updated_at = ? WHERE id = ?")
                .bind(&now)
                .bind(&now)
                .bind(existing.id)
                .execute(pool)
                .await?;
            return Ok((get_device(pool, existing.id).await?, true));
        }
    }

    sqlx::query(
        "INSERT INTO devices
         (mac, serial_number, last_seen_at, notes, tags, created_at, updated_at)
         VALUES (?, ?, ?, '', '[]', ?, ?)",
    )
    .bind(&mac)
    .bind(serial_number.and_then(clean_str_ref))
    .bind(&now)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    let device = get_device_by_mac(pool, &mac)
        .await?
        .ok_or(AppError::NotFound)?;
    prune_auto_discovered_devices(pool, max_auto_devices).await?;
    Ok((device, false))
}

async fn seen_device_serial_number(
    pool: &SqlitePool,
    existing_id: i64,
    existing_serial: Option<String>,
    incoming_serial: Option<&str>,
) -> AppResult<Option<String>> {
    match (existing_serial, incoming_serial.and_then(clean_str_ref)) {
        (None, Some(serial)) => {
            if let Some(serial_device) = get_device_by_serial(pool, &serial).await? {
                if serial_device.id != existing_id {
                    return Ok(None);
                }
            }
            Ok(Some(serial))
        }
        (value, _) => Ok(value),
    }
}

async fn prune_auto_discovered_devices(pool: &SqlitePool, max_devices: i64) -> AppResult<()> {
    sqlx::query(
        "DELETE FROM devices
         WHERE managed_client_id IS NULL
           AND last_seen_at IS NOT NULL
           AND hostname IS NULL
           AND default_profile_id IS NULL
           AND one_time_profile_id IS NULL
           AND notes = ''
           AND tags = '[]'
           AND id NOT IN (
               SELECT id FROM devices
               WHERE managed_client_id IS NULL
                 AND last_seen_at IS NOT NULL
                 AND hostname IS NULL
                 AND default_profile_id IS NULL
                 AND one_time_profile_id IS NULL
                 AND notes = ''
                 AND tags = '[]'
               ORDER BY COALESCE(last_seen_at, created_at) DESC, id DESC
               LIMIT ?
           )",
    )
    .bind(max_devices.max(1))
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn touch_device_seen(pool: &SqlitePool, device_id: i64) -> AppResult<Device> {
    let now = now_rfc3339();
    sqlx::query("UPDATE devices SET last_seen_at = ?, updated_at = ? WHERE id = ?")
        .bind(&now)
        .bind(&now)
        .bind(device_id)
        .execute(pool)
        .await?;
    get_device(pool, device_id).await
}

pub async fn create_device(pool: &SqlitePool, input: CreateDeviceRequest) -> AppResult<Device> {
    let mac = normalize_mac(&input.mac)?;
    let now = now_rfc3339();
    let hostname = clean_optional_string(input.hostname);
    let serial_number = clean_optional_string(input.serial_number);
    let notes = input.notes.unwrap_or_default();
    let tags = clean_tags(input.tags.unwrap_or_default());
    validate_device_metadata(hostname.as_deref(), serial_number.as_deref(), &notes, &tags)?;
    let tags = serde_json::to_string(&tags).map_err(|err| AppError::Validation(err.to_string()))?;

    sqlx::query(
        "INSERT INTO devices
         (mac, hostname, serial_number, notes, tags, default_profile_id, one_time_profile_id, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&mac)
    .bind(hostname)
    .bind(serial_number)
    .bind(notes)
    .bind(tags)
    .bind(input.default_profile_id)
    .bind(input.one_time_profile_id)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    get_device_by_mac(pool, &mac)
        .await?
        .ok_or(AppError::NotFound)
}

pub async fn update_device(
    pool: &SqlitePool,
    id: i64,
    input: UpdateDeviceRequest,
) -> AppResult<Device> {
    let current = get_device(pool, id).await?;
    let hostname = input
        .hostname
        .map(clean_optional_string)
        .unwrap_or(current.hostname);
    let serial_number = input
        .serial_number
        .map(clean_optional_string)
        .unwrap_or(current.serial_number);
    let notes = input.notes.unwrap_or(current.notes);
    let tags = input.tags.map(clean_tags).unwrap_or(current.tags);
    validate_device_metadata(hostname.as_deref(), serial_number.as_deref(), &notes, &tags)?;
    let tags_json =
        serde_json::to_string(&tags).map_err(|err| AppError::Validation(err.to_string()))?;
    let default_profile_id = input
        .default_profile_id
        .unwrap_or(current.default_profile_id);
    let one_time_profile_id = input
        .one_time_profile_id
        .unwrap_or(current.one_time_profile_id);
    let now = now_rfc3339();

    sqlx::query(
        "UPDATE devices
         SET hostname = ?, serial_number = ?, notes = ?, tags = ?,
             default_profile_id = ?, one_time_profile_id = ?, updated_at = ?
         WHERE id = ?",
    )
    .bind(hostname)
    .bind(serial_number)
    .bind(notes)
    .bind(tags_json)
    .bind(default_profile_id)
    .bind(one_time_profile_id)
    .bind(&now)
    .bind(id)
    .execute(pool)
    .await?;

    get_device(pool, id).await
}

pub async fn delete_device(pool: &SqlitePool, id: i64) -> AppResult<()> {
    let affected = sqlx::query("DELETE FROM devices WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?
        .rows_affected();
    if affected == 0 {
        return Err(AppError::NotFound);
    }
    Ok(())
}

pub async fn set_device_last_selected(
    pool: &SqlitePool,
    device_id: i64,
    profile_id: i64,
) -> AppResult<()> {
    let now = now_rfc3339();
    sqlx::query("UPDATE devices SET last_selected_profile_id = ?, updated_at = ? WHERE id = ?")
        .bind(profile_id)
        .bind(&now)
        .bind(device_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn consume_one_time_profile(
    pool: &SqlitePool,
    device_id: i64,
    profile_id: i64,
) -> AppResult<()> {
    let now = now_rfc3339();
    sqlx::query(
        "UPDATE devices
         SET one_time_profile_id = NULL,
             one_time_consumed_at = ?,
             last_selected_profile_id = ?,
             updated_at = ?
         WHERE id = ?",
    )
    .bind(&now)
    .bind(profile_id)
    .bind(&now)
    .bind(device_id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn list_profiles(pool: &SqlitePool) -> AppResult<Vec<BootProfile>> {
    profile_rows_to_models(
        sqlx::query_as::<_, BootProfileRow>("SELECT * FROM boot_profiles ORDER BY name ASC")
            .fetch_all(pool)
            .await?,
    )
}

pub async fn list_enabled_profiles(pool: &SqlitePool) -> AppResult<Vec<BootProfile>> {
    profile_rows_to_models(
        sqlx::query_as::<_, BootProfileRow>(
            "SELECT * FROM boot_profiles WHERE enabled = 1 ORDER BY is_default DESC, name ASC",
        )
        .fetch_all(pool)
        .await?,
    )
}

pub async fn get_profile(pool: &SqlitePool, id: i64) -> AppResult<BootProfile> {
    let row = sqlx::query_as::<_, BootProfileRow>("SELECT * FROM boot_profiles WHERE id = ?")
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or(AppError::NotFound)?;
    row.try_into()
}

pub async fn create_profile(
    pool: &SqlitePool,
    input: CreateBootProfileRequest,
) -> AppResult<BootProfile> {
    validate_profile_name(&input.name)?;
    validate_profile_path(input.kernel_path.as_deref(), "kernel_path")?;
    validate_profile_path(input.initrd_path.as_deref(), "initrd_path")?;
    validate_profile_path(input.iso_path.as_deref(), "iso_path")?;
    validate_profile_cmdline(input.cmdline.as_deref())?;
    validate_profile_description(input.description.as_deref())?;
    validate_profile_raw_script(input.raw_script.as_deref())?;
    if input.is_default.unwrap_or(false) {
        clear_default_profiles(pool).await?;
    }

    let now = now_rfc3339();
    let result = sqlx::query(
        "INSERT INTO boot_profiles
         (name, description, profile_type, enabled, is_default, one_time,
          kernel_path, initrd_path, iso_path, cmdline, raw_script, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(input.name.trim())
    .bind(input.description.unwrap_or_default())
    .bind(input.profile_type.as_str())
    .bind(bool_to_i64(input.enabled.unwrap_or(true)))
    .bind(bool_to_i64(input.is_default.unwrap_or(false)))
    .bind(bool_to_i64(input.one_time.unwrap_or(false)))
    .bind(clean_optional_string(input.kernel_path))
    .bind(clean_optional_string(input.initrd_path))
    .bind(clean_optional_string(input.iso_path))
    .bind(clean_optional_string(input.cmdline))
    .bind(clean_optional_string(input.raw_script))
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    get_profile(pool, result.last_insert_rowid()).await
}

pub async fn update_profile(
    pool: &SqlitePool,
    id: i64,
    input: UpdateBootProfileRequest,
) -> AppResult<BootProfile> {
    let current = get_profile(pool, id).await?;
    let name = input.name.unwrap_or(current.name);
    validate_profile_name(&name)?;
    let description = input.description.unwrap_or(current.description);
    let profile_type = input.profile_type.unwrap_or(current.profile_type);
    let enabled = input.enabled.unwrap_or(current.enabled);
    let is_default = input.is_default.unwrap_or(current.is_default);
    let one_time = input.one_time.unwrap_or(current.one_time);
    let kernel_path = input
        .kernel_path
        .map(clean_optional_string)
        .unwrap_or(current.kernel_path);
    let initrd_path = input
        .initrd_path
        .map(clean_optional_string)
        .unwrap_or(current.initrd_path);
    let iso_path = input
        .iso_path
        .map(clean_optional_string)
        .unwrap_or(current.iso_path);
    let cmdline = input
        .cmdline
        .map(clean_optional_string)
        .unwrap_or(current.cmdline);
    let raw_script = input
        .raw_script
        .map(clean_optional_string)
        .unwrap_or(current.raw_script);

    validate_profile_path(kernel_path.as_deref(), "kernel_path")?;
    validate_profile_path(initrd_path.as_deref(), "initrd_path")?;
    validate_profile_path(iso_path.as_deref(), "iso_path")?;
    validate_profile_cmdline(cmdline.as_deref())?;
    validate_profile_description(Some(&description))?;
    validate_profile_raw_script(raw_script.as_deref())?;

    if is_default {
        clear_default_profiles(pool).await?;
    }

    let now = now_rfc3339();
    sqlx::query(
        "UPDATE boot_profiles
         SET name = ?, description = ?, profile_type = ?, enabled = ?, is_default = ?,
             one_time = ?, kernel_path = ?, initrd_path = ?, iso_path = ?, cmdline = ?,
             raw_script = ?, updated_at = ?
         WHERE id = ?",
    )
    .bind(name.trim())
    .bind(description)
    .bind(profile_type.as_str())
    .bind(bool_to_i64(enabled))
    .bind(bool_to_i64(is_default))
    .bind(bool_to_i64(one_time))
    .bind(kernel_path)
    .bind(initrd_path)
    .bind(iso_path)
    .bind(cmdline)
    .bind(raw_script)
    .bind(&now)
    .bind(id)
    .execute(pool)
    .await?;

    get_profile(pool, id).await
}

pub async fn delete_profile(pool: &SqlitePool, id: i64) -> AppResult<()> {
    let affected = sqlx::query("DELETE FROM boot_profiles WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?
        .rows_affected();
    if affected == 0 {
        return Err(AppError::NotFound);
    }
    Ok(())
}

pub async fn insert_boot_event(pool: &SqlitePool, event: NewBootEvent) -> AppResult<BootEvent> {
    insert_boot_event_with_retention(pool, event, MAX_BOOT_EVENTS_RETAINED).await
}

async fn insert_boot_event_with_retention(
    pool: &SqlitePool,
    event: NewBootEvent,
    max_events: i64,
) -> AppResult<BootEvent> {
    let now = now_rfc3339();
    let result = sqlx::query(
        "INSERT INTO boot_events
         (device_id, mac, serial_number, ip_address, user_agent,
          selected_profile_id, selected_profile_name, known_device, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(event.device_id)
    .bind(event.mac)
    .bind(event.serial_number)
    .bind(event.ip_address)
    .bind(event.user_agent)
    .bind(event.selected_profile_id)
    .bind(event.selected_profile_name)
    .bind(bool_to_i64(event.known_device))
    .bind(&now)
    .execute(pool)
    .await?;

    let event = get_boot_event(pool, result.last_insert_rowid()).await?;
    prune_boot_events(pool, max_events).await?;
    Ok(event)
}

async fn prune_boot_events(pool: &SqlitePool, max_events: i64) -> AppResult<()> {
    sqlx::query(
        "DELETE FROM boot_events
         WHERE id NOT IN (
             SELECT id
             FROM (
                 SELECT id FROM boot_events ORDER BY id DESC LIMIT ?
             )
             UNION
             SELECT id
             FROM (
                 SELECT id
                 FROM boot_events
                 WHERE known_device != 0
                   AND selected_profile_id IS NOT NULL
                 ORDER BY id DESC
                 LIMIT ?
             )
         )",
    )
    .bind(max_events.max(1))
    .bind(max_events.max(1))
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn list_boot_events(pool: &SqlitePool, limit: i64) -> AppResult<Vec<BootEvent>> {
    let rows = sqlx::query_as::<_, BootEventRow>(
        "SELECT * FROM boot_events ORDER BY created_at DESC LIMIT ?",
    )
    .bind(limit.clamp(1, 500))
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(BootEvent::from).collect())
}

async fn get_boot_event(pool: &SqlitePool, id: i64) -> AppResult<BootEvent> {
    let row = sqlx::query_as::<_, BootEventRow>("SELECT * FROM boot_events WHERE id = ?")
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(row.into())
}

pub async fn list_iso_assets(pool: &SqlitePool) -> AppResult<Vec<IsoAsset>> {
    let rows = sqlx::query_as::<_, IsoAssetRow>(
        "SELECT * FROM iso_assets ORDER BY filename COLLATE NOCASE ASC",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(IsoAsset::from).collect())
}

pub async fn upsert_iso_asset(
    pool: &SqlitePool,
    filename: &str,
    relative_path: &str,
    size_bytes: i64,
    checksum_sha256: &str,
) -> AppResult<IsoAsset> {
    let now = now_rfc3339();
    sqlx::query(
        "INSERT INTO iso_assets
         (filename, relative_path, size_bytes, checksum_sha256, last_scanned_at, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(relative_path) DO UPDATE SET
             filename = excluded.filename,
             size_bytes = excluded.size_bytes,
             checksum_sha256 = excluded.checksum_sha256,
             last_scanned_at = excluded.last_scanned_at,
             updated_at = excluded.updated_at",
    )
    .bind(filename)
    .bind(relative_path)
    .bind(size_bytes)
    .bind(checksum_sha256)
    .bind(&now)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    let row = sqlx::query_as::<_, IsoAssetRow>("SELECT * FROM iso_assets WHERE relative_path = ?")
        .bind(relative_path)
        .fetch_optional(pool)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(row.into())
}

pub async fn prune_missing_iso_assets(
    pool: &SqlitePool,
    retained_relative_paths: &[String],
) -> AppResult<usize> {
    let retained: HashSet<&str> = retained_relative_paths.iter().map(String::as_str).collect();
    let current = list_iso_assets(pool).await?;
    let mut removed = 0usize;
    for asset in current {
        if retained.contains(asset.relative_path.as_str()) {
            continue;
        }
        sqlx::query("DELETE FROM iso_assets WHERE relative_path = ?")
            .bind(&asset.relative_path)
            .execute(pool)
            .await?;
        removed += 1;
    }
    Ok(removed)
}

pub async fn list_build_jobs(pool: &SqlitePool) -> AppResult<Vec<BuildJob>> {
    let rows = sqlx::query_as::<_, BuildJobRow>(
        "SELECT * FROM forge_build_jobs ORDER BY created_at DESC, id DESC",
    )
    .fetch_all(pool)
    .await?;
    build_job_rows_to_models(rows)
}

pub async fn create_build_job(
    pool: &SqlitePool,
    input: CreateBuildJobRequest,
) -> AppResult<BuildJob> {
    let requested_artifact_type =
        normalize_artifact_type(&input.requested_artifact_type, "requested_artifact_type")?;
    let target = normalize_build_target(input.target.as_deref(), &requested_artifact_type)?;
    let system = normalize_build_system(input.system.as_deref().unwrap_or("x86_64-linux"))?;
    let input_revision = normalize_input_revision(&input.input_revision)?;
    let input_config_hash = normalize_sha256(&input.input_config_hash, "input_config_hash", false)?;
    let build_spec = build_spec_to_string(
        input.build_spec,
        &requested_artifact_type,
        &target,
        &system,
        &input_revision,
        &input_config_hash,
    )?;
    let cache_metadata = metadata_to_string(input.cache_metadata, "cache_metadata")?;
    let now = now_rfc3339();
    let result = sqlx::query(
        "INSERT INTO forge_build_jobs
         (requested_artifact_type, build_spec, target, system, input_revision, input_config_hash, status, cache_metadata, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, 'queued', ?, ?, ?)",
    )
    .bind(requested_artifact_type)
    .bind(build_spec)
    .bind(target)
    .bind(system)
    .bind(input_revision)
    .bind(input_config_hash)
    .bind(cache_metadata)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    get_build_job(pool, result.last_insert_rowid()).await
}

pub async fn upsert_managed_build_job(
    pool: &SqlitePool,
    managed_job_id: &str,
    requested_artifact_type: &str,
    build_spec: Option<Value>,
    target: Option<&str>,
    system: Option<&str>,
    input_revision: &str,
    input_config_hash: &str,
    cache_metadata: Option<Value>,
) -> AppResult<BuildJob> {
    let managed_job_id = normalize_managed_id(managed_job_id, "managed_job_id")?;
    let requested_artifact_type =
        normalize_artifact_type(requested_artifact_type, "requested_artifact_type")?;
    let target = normalize_build_target(target, &requested_artifact_type)?;
    let system = normalize_build_system(system.unwrap_or("x86_64-linux"))?;
    let input_revision = normalize_input_revision(input_revision)?;
    let input_config_hash = normalize_sha256(input_config_hash, "input_config_hash", false)?;
    let build_spec = build_spec_to_string(
        build_spec,
        &requested_artifact_type,
        &target,
        &system,
        &input_revision,
        &input_config_hash,
    )?;
    let cache_metadata = metadata_to_string(cache_metadata, "cache_metadata")?;
    let now = now_rfc3339();
    sqlx::query(
        "INSERT INTO forge_build_jobs
         (managed_job_id, requested_artifact_type, build_spec, target, system, input_revision, input_config_hash, status, cache_metadata, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, 'queued', ?, ?, ?)
         ON CONFLICT(managed_job_id) DO UPDATE SET
             requested_artifact_type = excluded.requested_artifact_type,
             build_spec = CASE
                 WHEN forge_build_jobs.status = 'queued' THEN excluded.build_spec
                 ELSE forge_build_jobs.build_spec
             END,
             target = CASE
                 WHEN forge_build_jobs.status = 'queued' THEN excluded.target
                 ELSE forge_build_jobs.target
             END,
             system = CASE
                 WHEN forge_build_jobs.status = 'queued' THEN excluded.system
                 ELSE forge_build_jobs.system
             END,
             input_revision = excluded.input_revision,
             input_config_hash = excluded.input_config_hash,
             cache_metadata = excluded.cache_metadata,
             updated_at = excluded.updated_at",
    )
    .bind(&managed_job_id)
    .bind(requested_artifact_type)
    .bind(build_spec)
    .bind(target)
    .bind(system)
    .bind(input_revision)
    .bind(input_config_hash)
    .bind(cache_metadata)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    get_build_job_by_managed_id(pool, &managed_job_id).await
}

pub async fn cancel_absent_managed_build_jobs(
    pool: &SqlitePool,
    retained_managed_job_ids: &[String],
) -> AppResult<usize> {
    let retained: HashSet<&str> = retained_managed_job_ids
        .iter()
        .map(String::as_str)
        .collect();
    let current = list_build_jobs(pool).await?;
    let now = now_rfc3339();
    let mut cancelled = 0usize;
    for job in current {
        let Some(managed_job_id) = job.managed_job_id.as_deref() else {
            continue;
        };
        if retained.contains(managed_job_id) || !matches!(job.status.as_str(), "queued" | "running")
        {
            continue;
        }
        sqlx::query(
            "UPDATE forge_build_jobs
             SET status = CASE WHEN status = 'queued' THEN 'cancelled' ELSE status END,
                 cancel_requested_at = CASE WHEN status = 'running' THEN ? ELSE cancel_requested_at END,
                 completed_at = CASE WHEN status = 'queued' THEN ? ELSE completed_at END,
                 updated_at = ?
             WHERE id = ?",
        )
        .bind(&now)
        .bind(&now)
        .bind(&now)
        .bind(job.id)
        .execute(pool)
        .await?;
        cancelled += 1;
    }
    Ok(cancelled)
}

pub async fn cancel_managed_build_jobs(
    pool: &SqlitePool,
    managed_job_ids: &[String],
) -> AppResult<usize> {
    let now = now_rfc3339();
    let mut cancelled = 0usize;
    for managed_job_id in managed_job_ids {
        let managed_job_id = normalize_managed_id(managed_job_id, "managed_job_id")?;
        let affected = sqlx::query(
            "UPDATE forge_build_jobs
             SET status = CASE WHEN status = 'queued' THEN 'cancelled' ELSE status END,
                 cancel_requested_at = CASE WHEN status = 'running' THEN ? ELSE cancel_requested_at END,
                 completed_at = CASE WHEN status = 'queued' THEN ? ELSE completed_at END,
                 updated_at = ?
             WHERE managed_job_id = ? AND status IN ('queued', 'running')",
        )
        .bind(&now)
        .bind(&now)
        .bind(&now)
        .bind(&managed_job_id)
        .execute(pool)
        .await?
        .rows_affected();
        cancelled += affected as usize;
    }
    Ok(cancelled)
}

pub async fn recover_running_build_jobs(pool: &SqlitePool, reason: &str) -> AppResult<usize> {
    let now = now_rfc3339();
    let error = bounded_error_text(reason);
    let affected = sqlx::query(
        "UPDATE forge_build_jobs
         SET status = 'failed',
             error = ?,
             completed_at = ?,
             updated_at = ?
         WHERE status = 'running'",
    )
    .bind(error)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(affected as usize)
}

pub async fn claim_next_build_job(pool: &SqlitePool) -> AppResult<Option<BuildJob>> {
    let now = now_rfc3339();
    let row = sqlx::query_as::<_, BuildJobRow>(
        "UPDATE forge_build_jobs
         SET status = 'running',
             started_at = COALESCE(started_at, ?),
             cancel_requested_at = NULL,
             logs = '',
             error = '',
             updated_at = ?
         WHERE id = (
             SELECT id FROM forge_build_jobs
             WHERE status = 'queued'
             ORDER BY created_at ASC, id ASC
             LIMIT 1
         )
         RETURNING *",
    )
    .bind(&now)
    .bind(&now)
    .fetch_optional(pool)
    .await?;
    row.map(BuildJob::try_from).transpose()
}

pub async fn build_job_cancel_requested(pool: &SqlitePool, id: i64) -> AppResult<bool> {
    let row: Option<(String, Option<String>)> =
        sqlx::query_as("SELECT status, cancel_requested_at FROM forge_build_jobs WHERE id = ?")
            .bind(id)
            .fetch_optional(pool)
            .await?;
    Ok(row
        .map(|(status, cancel_requested_at)| {
            status == "cancelled"
                || cancel_requested_at
                    .as_deref()
                    .is_some_and(|value| !value.is_empty())
        })
        .unwrap_or(true))
}

pub async fn update_build_job_logs(pool: &SqlitePool, id: i64, logs: &str) -> AppResult<()> {
    let now = now_rfc3339();
    sqlx::query(
        "UPDATE forge_build_jobs
         SET logs = ?, updated_at = ?
         WHERE id = ? AND status = 'running'",
    )
    .bind(bounded_log_text(logs))
    .bind(&now)
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn finish_build_job(
    pool: &SqlitePool,
    id: i64,
    status: &str,
    logs: &str,
    error: &str,
    output_path: &str,
    output_sha256: &str,
    output_size_bytes: i64,
    exit_code: Option<i64>,
    cache_metadata: Option<Value>,
) -> AppResult<BuildJob> {
    validate_terminal_build_status(status)?;
    let logs = bounded_log_text(logs);
    let error = bounded_error_text(error);
    let output_path = normalize_optional_absolute_path(output_path, "output_path")?;
    let output_sha256 = normalize_sha256(output_sha256, "output_sha256", true)?;
    validate_non_negative_i64(output_size_bytes, "output_size_bytes")?;
    let cache_metadata = metadata_to_string(cache_metadata, "cache_metadata")?;
    let now = now_rfc3339();
    sqlx::query(
        "UPDATE forge_build_jobs
         SET status = ?,
             logs = ?,
             error = ?,
             output_path = ?,
             output_sha256 = ?,
             output_size_bytes = ?,
             exit_code = ?,
             cache_metadata = ?,
             completed_at = ?,
             updated_at = ?
         WHERE id = ?",
    )
    .bind(status)
    .bind(logs)
    .bind(error)
    .bind(output_path)
    .bind(output_sha256)
    .bind(output_size_bytes)
    .bind(exit_code)
    .bind(cache_metadata)
    .bind(&now)
    .bind(&now)
    .bind(id)
    .execute(pool)
    .await?;
    get_build_job(pool, id).await
}

pub async fn update_build_job_report(
    pool: &SqlitePool,
    managed_job_id: &str,
    status: &str,
    logs: &str,
    error: &str,
    output_path: &str,
    output_sha256: &str,
    output_size_bytes: i64,
    started_at: Option<&str>,
    completed_at: Option<&str>,
    cache_metadata: Option<Value>,
) -> AppResult<BuildJob> {
    let managed_job_id = normalize_managed_id(managed_job_id, "managed_job_id")?;
    validate_build_status(status)?;
    let logs = bounded_log_text(logs);
    let error = bounded_error_text(error);
    let output_path = normalize_optional_absolute_path(output_path, "output_path")?;
    let output_sha256 = normalize_sha256(output_sha256, "output_sha256", true)?;
    validate_non_negative_i64(output_size_bytes, "output_size_bytes")?;
    validate_optional_timestamp(started_at, "started_at")?;
    validate_optional_timestamp(completed_at, "completed_at")?;
    let cache_metadata = metadata_to_string(cache_metadata, "cache_metadata")?;
    let now = now_rfc3339();
    sqlx::query(
        "UPDATE forge_build_jobs
         SET status = ?,
             logs = ?,
             error = ?,
             output_path = ?,
             output_sha256 = ?,
             output_size_bytes = ?,
             started_at = ?,
             completed_at = ?,
             cache_metadata = ?,
             updated_at = ?
         WHERE managed_job_id = ?",
    )
    .bind(status)
    .bind(logs)
    .bind(error)
    .bind(output_path)
    .bind(output_sha256)
    .bind(output_size_bytes)
    .bind(started_at.map(str::to_string))
    .bind(completed_at.map(str::to_string))
    .bind(cache_metadata)
    .bind(&now)
    .bind(&managed_job_id)
    .execute(pool)
    .await?;

    get_build_job_by_managed_id(pool, &managed_job_id).await
}

pub async fn list_cache_artifacts(pool: &SqlitePool) -> AppResult<Vec<CacheArtifact>> {
    let rows = sqlx::query_as::<_, CacheArtifactRow>(
        "SELECT * FROM forge_cache_artifacts ORDER BY created_at DESC, id DESC",
    )
    .fetch_all(pool)
    .await?;
    cache_artifact_rows_to_models(rows)
}

pub async fn delete_cache_artifact(pool: &SqlitePool, id: i64) -> AppResult<()> {
    sqlx::query("DELETE FROM forge_cache_artifacts WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn create_cache_artifact(
    pool: &SqlitePool,
    input: CreateCacheArtifactRequest,
) -> AppResult<CacheArtifact> {
    upsert_cache_artifact(
        pool,
        None,
        &input.artifact_type,
        &input.hash,
        input.size_bytes,
        &input.path,
        input.store_path.as_deref().unwrap_or(""),
        input.narinfo_path.as_deref().unwrap_or(""),
        input.nar_url.as_deref().unwrap_or(""),
        input.file_hash.as_deref().unwrap_or(""),
        input.nar_hash.as_deref().unwrap_or(""),
        input.nar_size_bytes.unwrap_or(0),
        input.closure_size_bytes.unwrap_or(0),
        input.compression.as_deref().unwrap_or(""),
        input.references,
        input.serving_url.as_deref().unwrap_or(""),
        input.source_build_job_id.as_deref(),
        input.cache_metadata,
    )
    .await
}

pub async fn upsert_cache_artifact(
    pool: &SqlitePool,
    managed_artifact_id: Option<&str>,
    artifact_type: &str,
    hash: &str,
    size_bytes: i64,
    path: &str,
    store_path: &str,
    narinfo_path: &str,
    nar_url: &str,
    file_hash: &str,
    nar_hash: &str,
    nar_size_bytes: i64,
    closure_size_bytes: i64,
    compression: &str,
    references: Option<Value>,
    serving_url: &str,
    source_build_job_id: Option<&str>,
    cache_metadata: Option<Value>,
) -> AppResult<CacheArtifact> {
    let managed_artifact_id = managed_artifact_id
        .map(|value| normalize_managed_id(value, "managed_artifact_id"))
        .transpose()?;
    let artifact_type = normalize_artifact_type(artifact_type, "artifact_type")?;
    let hash = normalize_sha256(hash, "hash", false)?;
    validate_non_negative_i64(size_bytes, "size_bytes")?;
    let path = normalize_absolute_path(path, "path")?;
    let store_path = normalize_optional_store_path(store_path, "store_path")?;
    let narinfo_path = normalize_optional_absolute_path(narinfo_path, "narinfo_path")?;
    let nar_url = normalize_cache_relative_path(nar_url, "nar_url")?;
    let file_hash = normalize_optional_nix_hash(file_hash, "file_hash")?;
    let nar_hash = normalize_optional_nix_hash(nar_hash, "nar_hash")?;
    validate_non_negative_i64(nar_size_bytes, "nar_size_bytes")?;
    validate_non_negative_i64(closure_size_bytes, "closure_size_bytes")?;
    let compression = normalize_optional_cache_token(compression, "compression")?;
    let references_json = references_to_string(references)?;
    let serving_url = normalize_optional_url(serving_url, "serving_url")?;
    let source_build_job_id = source_build_job_id
        .map(|value| normalize_managed_id(value, "source_build_job_id"))
        .transpose()?;
    let cache_metadata = metadata_to_string(cache_metadata, "cache_metadata")?;
    let now = now_rfc3339();
    sqlx::query(
        "INSERT INTO forge_cache_artifacts
         (managed_artifact_id, artifact_type, hash, size_bytes, path, store_path, narinfo_path, nar_url, file_hash, nar_hash, nar_size_bytes, closure_size_bytes, compression, references_json, serving_url, source_build_job_id, cache_metadata, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(artifact_type, hash) DO UPDATE SET
             managed_artifact_id = excluded.managed_artifact_id,
             size_bytes = excluded.size_bytes,
             path = excluded.path,
             store_path = excluded.store_path,
             narinfo_path = excluded.narinfo_path,
             nar_url = excluded.nar_url,
             file_hash = excluded.file_hash,
             nar_hash = excluded.nar_hash,
             nar_size_bytes = excluded.nar_size_bytes,
             closure_size_bytes = excluded.closure_size_bytes,
             compression = excluded.compression,
             references_json = excluded.references_json,
             serving_url = excluded.serving_url,
             source_build_job_id = excluded.source_build_job_id,
             cache_metadata = excluded.cache_metadata,
             updated_at = excluded.updated_at",
    )
    .bind(managed_artifact_id)
    .bind(artifact_type)
    .bind(&hash)
    .bind(size_bytes)
    .bind(path)
    .bind(store_path)
    .bind(narinfo_path)
    .bind(nar_url)
    .bind(file_hash)
    .bind(nar_hash)
    .bind(nar_size_bytes)
    .bind(closure_size_bytes)
    .bind(compression)
    .bind(references_json)
    .bind(serving_url)
    .bind(source_build_job_id)
    .bind(cache_metadata)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    get_cache_artifact_by_hash(pool, &hash).await
}

pub async fn get_build_job(pool: &SqlitePool, id: i64) -> AppResult<BuildJob> {
    let row = sqlx::query_as::<_, BuildJobRow>("SELECT * FROM forge_build_jobs WHERE id = ?")
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or(AppError::NotFound)?;
    row.try_into()
}

pub async fn get_build_job_by_managed_id(
    pool: &SqlitePool,
    managed_job_id: &str,
) -> AppResult<BuildJob> {
    let row =
        sqlx::query_as::<_, BuildJobRow>("SELECT * FROM forge_build_jobs WHERE managed_job_id = ?")
            .bind(managed_job_id)
            .fetch_optional(pool)
            .await?
            .ok_or(AppError::NotFound)?;
    row.try_into()
}

async fn get_cache_artifact_by_hash(pool: &SqlitePool, hash: &str) -> AppResult<CacheArtifact> {
    let row =
        sqlx::query_as::<_, CacheArtifactRow>("SELECT * FROM forge_cache_artifacts WHERE hash = ?")
            .bind(hash)
            .fetch_optional(pool)
            .await?
            .ok_or(AppError::NotFound)?;
    row.try_into()
}

fn profile_rows_to_models(rows: Vec<BootProfileRow>) -> AppResult<Vec<BootProfile>> {
    rows.into_iter().map(BootProfile::try_from).collect()
}

fn build_job_rows_to_models(rows: Vec<BuildJobRow>) -> AppResult<Vec<BuildJob>> {
    rows.into_iter().map(BuildJob::try_from).collect()
}

fn cache_artifact_rows_to_models(rows: Vec<CacheArtifactRow>) -> AppResult<Vec<CacheArtifact>> {
    rows.into_iter().map(CacheArtifact::try_from).collect()
}

async fn clear_default_profiles(pool: &SqlitePool) -> AppResult<()> {
    sqlx::query("UPDATE boot_profiles SET is_default = 0")
        .execute(pool)
        .await?;
    Ok(())
}

fn validate_profile_name(name: &str) -> AppResult<()> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(AppError::Validation("profile name is required".to_string()));
    }
    if trimmed.len() > 120 {
        return Err(AppError::Validation(
            "profile name must be 120 characters or fewer".to_string(),
        ));
    }
    if trimmed.chars().any(char::is_control) {
        return Err(AppError::Validation(
            "profile name must not contain control characters".to_string(),
        ));
    }
    Ok(())
}

fn validate_profile_path(value: Option<&str>, field: &str) -> AppResult<()> {
    if let Some(value) = value {
        if !value.trim().is_empty() && sanitize_relative_path(value).is_err() {
            return Err(AppError::Validation(format!(
                "{field} must be a relative path under the boot assets directory"
            )));
        }
    }
    Ok(())
}

fn validate_profile_cmdline(value: Option<&str>) -> AppResult<()> {
    if value
        .map(|value| value.chars().any(char::is_control))
        .unwrap_or(false)
    {
        return Err(AppError::Validation(
            "profile cmdline must not contain control characters".to_string(),
        ));
    }
    Ok(())
}

fn validate_profile_description(value: Option<&str>) -> AppResult<()> {
    if value
        .map(|value| value.chars().count() > MAX_PROFILE_DESCRIPTION_CHARS)
        .unwrap_or(false)
    {
        return Err(AppError::Validation(format!(
            "profile description must be {MAX_PROFILE_DESCRIPTION_CHARS} characters or fewer"
        )));
    }
    Ok(())
}

fn validate_profile_raw_script(value: Option<&str>) -> AppResult<()> {
    if value
        .map(|value| value.trim().len() > MAX_PROFILE_RAW_SCRIPT_BYTES)
        .unwrap_or(false)
    {
        return Err(AppError::Validation(format!(
            "profile raw_script must be {MAX_PROFILE_RAW_SCRIPT_BYTES} bytes or fewer"
        )));
    }
    Ok(())
}

fn validate_device_metadata(
    hostname: Option<&str>,
    serial_number: Option<&str>,
    notes: &str,
    tags: &[String],
) -> AppResult<()> {
    validate_limited_optional_text(
        hostname,
        "device hostname",
        MAX_DEVICE_HOSTNAME_CHARS,
        false,
    )?;
    validate_limited_optional_text(
        serial_number,
        "device serial number",
        MAX_DEVICE_SERIAL_CHARS,
        false,
    )?;
    validate_limited_text(notes, "device notes", MAX_DEVICE_NOTES_CHARS, true)?;
    validate_device_tags(tags)?;
    Ok(())
}

fn validate_device_tags(tags: &[String]) -> AppResult<()> {
    if tags.len() > MAX_DEVICE_TAGS {
        return Err(AppError::Validation(format!(
            "device tags must include {MAX_DEVICE_TAGS} entries or fewer"
        )));
    }
    for tag in tags {
        validate_limited_text(tag, "device tag", MAX_DEVICE_TAG_CHARS, false)?;
    }
    Ok(())
}

fn validate_limited_optional_text(
    value: Option<&str>,
    field: &str,
    max_chars: usize,
    allow_control: bool,
) -> AppResult<()> {
    if let Some(value) = value {
        validate_limited_text(value, field, max_chars, allow_control)?;
    }
    Ok(())
}

fn validate_limited_text(
    value: &str,
    field: &str,
    max_chars: usize,
    allow_control: bool,
) -> AppResult<()> {
    if value.chars().count() > max_chars {
        return Err(AppError::Validation(format!(
            "{field} must be {max_chars} characters or fewer"
        )));
    }
    if !allow_control && value.chars().any(char::is_control) {
        return Err(AppError::Validation(format!(
            "{field} must not contain control characters"
        )));
    }
    Ok(())
}

fn normalize_artifact_type(value: &str, field: &str) -> AppResult<String> {
    let value = value.trim().to_ascii_lowercase();
    if !matches!(
        value.as_str(),
        "nixos_closure" | "netboot_artifact" | "desktop_image" | "system_generation"
    ) {
        return Err(AppError::Validation(format!(
            "{field} must be one of nixos_closure, netboot_artifact, desktop_image, system_generation"
        )));
    }
    Ok(value)
}

fn normalize_input_revision(value: &str) -> AppResult<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(AppError::Validation(
            "input_revision is required".to_string(),
        ));
    }
    if value.chars().count() > 256 || value.chars().any(char::is_control) {
        return Err(AppError::Validation(
            "input_revision must be 256 characters or fewer and must not contain control characters"
                .to_string(),
        ));
    }
    Ok(value.to_string())
}

fn normalize_build_target(value: Option<&str>, default: &str) -> AppResult<String> {
    let value = value.unwrap_or(default).trim().to_ascii_lowercase();
    if value.is_empty()
        || value.len() > 64
        || value.starts_with(['-', '.', '_'])
        || value.ends_with(['-', '.', '_'])
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
    {
        return Err(AppError::Validation(
            "target must be a safe build target identifier".to_string(),
        ));
    }
    Ok(value)
}

fn normalize_build_system(value: &str) -> AppResult<String> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 64
        || value.starts_with('-')
        || value.ends_with('-')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(AppError::Validation(
            "system must be a safe Nix system name such as x86_64-linux".to_string(),
        ));
    }
    Ok(value.to_string())
}

fn build_spec_to_string(
    value: Option<Value>,
    requested_artifact_type: &str,
    target: &str,
    system: &str,
    input_revision: &str,
    input_config_hash: &str,
) -> AppResult<String> {
    let mut value = value.unwrap_or_else(|| {
        json!({
            "schema_version": 1,
            "artifact_type": requested_artifact_type,
            "target": target,
            "system": system,
            "input_revision": input_revision,
            "input_config_hash": input_config_hash
        })
    });
    let object = value
        .as_object_mut()
        .ok_or_else(|| AppError::Validation("build_spec must be a JSON object".to_string()))?;
    object.insert("artifact_type".to_string(), json!(requested_artifact_type));
    object.insert("target".to_string(), json!(target));
    object.insert("system".to_string(), json!(system));
    object.insert("input_revision".to_string(), json!(input_revision));
    object.insert("input_config_hash".to_string(), json!(input_config_hash));
    let encoded =
        serde_json::to_string(&value).map_err(|err| AppError::Validation(err.to_string()))?;
    if encoded.len() > MAX_CACHE_METADATA_BYTES {
        return Err(AppError::Validation(
            "build_spec must be 16384 bytes or fewer".to_string(),
        ));
    }
    Ok(encoded)
}

fn normalize_sha256(value: &str, field: &str, allow_empty: bool) -> AppResult<String> {
    let value = value.trim();
    if allow_empty && value.is_empty() {
        return Ok(String::new());
    }
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(AppError::Validation(format!(
            "{field} must be a 64-character SHA-256 hex digest"
        )));
    }
    Ok(value.to_ascii_lowercase())
}

fn normalize_managed_id(value: &str, field: &str) -> AppResult<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(AppError::Validation(format!("{field} is required")));
    }
    if value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(AppError::Validation(format!(
            "{field} must be a safe identifier of 128 characters or fewer"
        )));
    }
    Ok(value.to_string())
}

fn validate_build_status(status: &str) -> AppResult<()> {
    if ALLOWED_BUILD_STATES.contains(&status) {
        Ok(())
    } else {
        Err(AppError::Validation(format!(
            "status must be one of {}",
            ALLOWED_BUILD_STATES.join(", ")
        )))
    }
}

fn validate_terminal_build_status(status: &str) -> AppResult<()> {
    if matches!(status, "succeeded" | "failed" | "cancelled") {
        Ok(())
    } else {
        Err(AppError::Validation(
            "terminal build status must be succeeded, failed, or cancelled".to_string(),
        ))
    }
}

fn bounded_log_text(value: &str) -> String {
    bounded_bytes(value, MAX_BUILD_LOG_BYTES)
}

fn bounded_error_text(value: &str) -> String {
    value.chars().take(MAX_BUILD_ERROR_CHARS).collect()
}

fn bounded_bytes(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }
    let mut end = 0usize;
    for (idx, ch) in value.char_indices() {
        let next = idx + ch.len_utf8();
        if next > max_bytes {
            break;
        }
        end = next;
    }
    value[..end].to_string()
}

fn metadata_to_string(value: Option<Value>, field: &str) -> AppResult<String> {
    let value = value.unwrap_or_else(|| json!({}));
    if !value.is_object() {
        return Err(AppError::Validation(format!(
            "{field} must be a JSON object"
        )));
    }
    let encoded =
        serde_json::to_string(&value).map_err(|err| AppError::Validation(err.to_string()))?;
    if encoded.len() > MAX_CACHE_METADATA_BYTES {
        return Err(AppError::Validation(format!(
            "{field} must be {MAX_CACHE_METADATA_BYTES} bytes or fewer"
        )));
    }
    Ok(encoded)
}

fn metadata_from_db(value: &str, field: &str) -> AppResult<Value> {
    let value: Value =
        serde_json::from_str(value).map_err(|err| AppError::Config(format!("{field}: {err}")))?;
    if value.is_object() {
        Ok(value)
    } else {
        Err(AppError::Config(format!("{field} must be a JSON object")))
    }
}

fn json_from_db(value: &str, field: &str) -> AppResult<Value> {
    serde_json::from_str(value).map_err(|err| AppError::Config(format!("{field}: {err}")))
}

fn validate_non_negative_i64(value: i64, field: &str) -> AppResult<()> {
    if value < 0 {
        Err(AppError::Validation(format!(
            "{field} must be zero or greater"
        )))
    } else {
        Ok(())
    }
}

fn normalize_absolute_path(value: &str, field: &str) -> AppResult<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(AppError::Validation(format!("{field} is required")));
    }
    validate_absolute_path(value, field)?;
    Ok(value.to_string())
}

fn normalize_optional_absolute_path(value: &str, field: &str) -> AppResult<String> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(String::new());
    }
    validate_absolute_path(value, field)?;
    Ok(value.to_string())
}

fn validate_absolute_path(value: &str, field: &str) -> AppResult<()> {
    if value.len() > 4096
        || value
            .chars()
            .any(|ch| ch.is_control() || ch == '"' || ch == '\\')
    {
        return Err(AppError::Validation(format!(
            "{field} contains unsupported characters"
        )));
    }
    let path = Path::new(value);
    if !path.is_absolute() || value == "/" {
        return Err(AppError::Validation(format!(
            "{field} must be an absolute normalized path"
        )));
    }
    for component in path.components() {
        if matches!(
            component,
            std::path::Component::CurDir | std::path::Component::ParentDir
        ) {
            return Err(AppError::Validation(format!(
                "{field} must be an absolute normalized path"
            )));
        }
    }
    Ok(())
}

fn normalize_optional_url(value: &str, field: &str) -> AppResult<String> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(String::new());
    }
    if value.len() > 2048
        || value
            .chars()
            .any(|ch| ch.is_control() || ch.is_ascii_whitespace())
    {
        return Err(AppError::Validation(format!(
            "{field} contains unsupported characters"
        )));
    }
    if !(value.starts_with("http://") || value.starts_with("https://")) {
        return Err(AppError::Validation(format!(
            "{field} must be an http or https URL"
        )));
    }
    Ok(value.trim_end_matches('/').to_string())
}

fn normalize_optional_store_path(value: &str, field: &str) -> AppResult<String> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(String::new());
    }
    validate_absolute_path(value, field)?;
    if !value.starts_with("/nix/store/") {
        return Err(AppError::Validation(format!(
            "{field} must be a /nix/store path"
        )));
    }
    Ok(value.to_string())
}

fn normalize_cache_relative_path(value: &str, field: &str) -> AppResult<String> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(String::new());
    }
    sanitize_relative_path(value).map_err(|_| {
        AppError::Validation(format!(
            "{field} must be a relative cache path without traversal"
        ))
    })?;
    Ok(value.to_string())
}

fn normalize_optional_nix_hash(value: &str, field: &str) -> AppResult<String> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(String::new());
    }
    if value.len() > 160
        || value.bytes().any(|byte| {
            !(byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'-' | b'_' | b'='))
        })
    {
        return Err(AppError::Validation(format!(
            "{field} is not a safe Nix hash"
        )));
    }
    Ok(value.to_string())
}

fn normalize_optional_cache_token(value: &str, field: &str) -> AppResult<String> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(String::new());
    }
    if value.len() > 32
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(AppError::Validation(format!("{field} is invalid")));
    }
    Ok(value.to_string())
}

fn references_to_string(value: Option<Value>) -> AppResult<String> {
    let value = value.unwrap_or_else(|| json!([]));
    let array = value
        .as_array()
        .ok_or_else(|| AppError::Validation("references must be a JSON array".to_string()))?;
    if array.len() > 10_000 {
        return Err(AppError::Validation(
            "references must contain 10000 entries or fewer".to_string(),
        ));
    }
    for item in array {
        let Some(reference) = item.as_str() else {
            return Err(AppError::Validation(
                "references must contain strings only".to_string(),
            ));
        };
        normalize_optional_store_path(reference, "reference")?;
    }
    serde_json::to_string(&value).map_err(|err| AppError::Validation(err.to_string()))
}

fn validate_optional_timestamp(value: Option<&str>, field: &str) -> AppResult<()> {
    if let Some(value) = value {
        if value.chars().count() > 64 || value.chars().any(char::is_control) {
            return Err(AppError::Validation(format!("{field} is invalid")));
        }
    }
    Ok(())
}

fn bool_to_i64(value: bool) -> i64 {
    if value { 1 } else { 0 }
}

fn clean_str_ref(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[cfg(test)]
mod tests {
    use crate::models::{
        CreateBootProfileRequest, CreateBuildJobRequest, CreateCacheArtifactRequest,
        CreateDeviceRequest, UpdateDeviceRequest,
    };

    use super::*;
    use serde_json::json;

    async fn test_pool() -> SqlitePool {
        let pool = connect_with_url("sqlite::memory:").await.unwrap();
        migrate(&pool).await.unwrap();
        pool
    }

    #[cfg(unix)]
    #[test]
    fn private_dir_permissions_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "cybex-forge-private-dir-{}-{unique}",
            std::process::id()
        ));

        std::fs::create_dir_all(&path).unwrap();
        set_private_dir_permissions(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        std::fs::remove_dir_all(&path).unwrap();

        assert_eq!(mode, 0o700);
    }

    #[tokio::test]
    async fn consume_one_time_profile_clears_assignment_and_sets_last_selected() {
        let pool = test_pool().await;
        let profile = create_profile(
            &pool,
            CreateBootProfileRequest {
                name: "Installer".to_string(),
                description: None,
                profile_type: BootProfileType::LinuxInstaller,
                enabled: Some(true),
                is_default: Some(false),
                one_time: Some(true),
                kernel_path: Some("netboot/vmlinuz".to_string()),
                initrd_path: Some("netboot/initrd.img".to_string()),
                iso_path: None,
                cmdline: None,
                raw_script: None,
            },
        )
        .await
        .unwrap();
        let device = create_device(
            &pool,
            CreateDeviceRequest {
                mac: "aa:bb:cc:dd:ee:ff".to_string(),
                hostname: None,
                serial_number: None,
                notes: None,
                tags: None,
                default_profile_id: None,
                one_time_profile_id: Some(profile.id),
            },
        )
        .await
        .unwrap();

        consume_one_time_profile(&pool, device.id, profile.id)
            .await
            .unwrap();
        let updated = get_device(&pool, device.id).await.unwrap();

        assert_eq!(updated.one_time_profile_id, None);
        assert_eq!(updated.last_selected_profile_id, Some(profile.id));
        assert!(updated.one_time_consumed_at.is_some());

        update_device(
            &pool,
            device.id,
            UpdateDeviceRequest {
                notes: Some("ready".to_string()),
                ..UpdateDeviceRequest::default()
            },
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn boot_event_retention_preserves_known_selected_profile_events() {
        let pool = test_pool().await;
        let profile = create_profile(
            &pool,
            CreateBootProfileRequest {
                name: "Installer".to_string(),
                description: None,
                profile_type: BootProfileType::LinuxInstaller,
                enabled: Some(true),
                is_default: Some(false),
                one_time: Some(false),
                kernel_path: Some("netboot/vmlinuz".to_string()),
                initrd_path: None,
                iso_path: None,
                cmdline: None,
                raw_script: None,
            },
        )
        .await
        .unwrap();
        insert_boot_event_with_retention(
            &pool,
            NewBootEvent {
                device_id: None,
                mac: Some("02:00:00:00:30:00".to_string()),
                serial_number: None,
                ip_address: None,
                user_agent: Some("critical".to_string()),
                selected_profile_id: Some(profile.id),
                selected_profile_name: Some("Installer".to_string()),
                known_device: true,
            },
            2,
        )
        .await
        .unwrap();
        for idx in 0..3 {
            insert_boot_event_with_retention(
                &pool,
                NewBootEvent {
                    device_id: None,
                    mac: None,
                    serial_number: Some(format!("noise-{idx}")),
                    ip_address: None,
                    user_agent: Some(format!("noise-{idx}")),
                    selected_profile_id: None,
                    selected_profile_name: None,
                    known_device: false,
                },
                2,
            )
            .await
            .unwrap();
        }

        let rows: Vec<(String,)> =
            sqlx::query_as("SELECT user_agent FROM boot_events ORDER BY id ASC")
                .fetch_all(&pool)
                .await
                .unwrap();
        let user_agents = rows
            .into_iter()
            .map(|(user_agent,)| user_agent)
            .collect::<Vec<_>>();

        assert_eq!(user_agents, vec!["critical", "noise-1", "noise-2"]);
    }

    #[tokio::test]
    async fn boot_event_insert_prunes_oldest_rows() {
        let pool = test_pool().await;

        for idx in 0..3 {
            insert_boot_event_with_retention(
                &pool,
                NewBootEvent {
                    device_id: None,
                    mac: None,
                    serial_number: Some(format!("serial-{idx}")),
                    ip_address: Some("192.0.2.10".to_string()),
                    user_agent: Some(format!("agent-{idx}")),
                    selected_profile_id: None,
                    selected_profile_name: None,
                    known_device: false,
                },
                2,
            )
            .await
            .unwrap();
        }

        let rows: Vec<(String,)> =
            sqlx::query_as("SELECT user_agent FROM boot_events ORDER BY id ASC")
                .fetch_all(&pool)
                .await
                .unwrap();
        let user_agents = rows
            .into_iter()
            .map(|(user_agent,)| user_agent)
            .collect::<Vec<_>>();

        assert_eq!(user_agents, vec!["agent-1", "agent-2"]);
    }

    #[tokio::test]
    async fn auto_discovered_device_insert_prunes_oldest_unmanaged_rows() {
        let pool = test_pool().await;

        for idx in 0..3 {
            let mac = format!("02:00:00:00:00:{idx:02x}");
            upsert_seen_device_with_retention(&pool, &mac, None, 2)
                .await
                .unwrap();
        }

        let rows: Vec<(String,)> = sqlx::query_as("SELECT mac FROM devices ORDER BY id ASC")
            .fetch_all(&pool)
            .await
            .unwrap();
        let macs = rows.into_iter().map(|(mac,)| mac).collect::<Vec<_>>();

        assert_eq!(macs, vec!["02:00:00:00:00:01", "02:00:00:00:00:02"]);
    }

    #[tokio::test]
    async fn seen_device_matches_existing_serial_before_inserting_new_mac() {
        let pool = test_pool().await;
        let known = create_device(
            &pool,
            CreateDeviceRequest {
                mac: "02:00:00:00:03:00".to_string(),
                hostname: None,
                serial_number: Some("serial-known".to_string()),
                notes: None,
                tags: None,
                default_profile_id: None,
                one_time_profile_id: None,
            },
        )
        .await
        .unwrap();

        let (seen, was_known) =
            upsert_seen_device_with_retention(&pool, "02:00:00:00:03:99", Some("serial-known"), 10)
                .await
                .unwrap();
        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM devices")
            .fetch_one(&pool)
            .await
            .unwrap();

        assert!(was_known);
        assert_eq!(seen.id, known.id);
        assert_eq!(seen.mac, "02:00:00:00:03:00");
        assert!(seen.last_seen_at.is_some());
        assert_eq!(rows, 1);
    }

    #[tokio::test]
    async fn seen_device_does_not_attach_serial_from_another_mac() {
        let pool = test_pool().await;
        create_device(
            &pool,
            CreateDeviceRequest {
                mac: "02:00:00:00:04:00".to_string(),
                hostname: None,
                serial_number: Some("serial-owned".to_string()),
                notes: None,
                tags: None,
                default_profile_id: None,
                one_time_profile_id: None,
            },
        )
        .await
        .unwrap();
        let known_mac = create_device(
            &pool,
            CreateDeviceRequest {
                mac: "02:00:00:00:04:99".to_string(),
                hostname: None,
                serial_number: None,
                notes: None,
                tags: None,
                default_profile_id: None,
                one_time_profile_id: None,
            },
        )
        .await
        .unwrap();

        let (seen, was_known) =
            upsert_seen_device_with_retention(&pool, "02:00:00:00:04:99", Some("serial-owned"), 10)
                .await
                .unwrap();

        assert!(was_known);
        assert_eq!(seen.id, known_mac.id);
        assert_eq!(seen.serial_number, None);
    }

    #[tokio::test]
    async fn auto_discovered_device_pruning_preserves_curated_rows() {
        let pool = test_pool().await;
        let (curated, _) = upsert_seen_device_with_retention(&pool, "02:00:00:00:01:00", None, 10)
            .await
            .unwrap();
        update_device(
            &pool,
            curated.id,
            UpdateDeviceRequest {
                notes: Some("keep".to_string()),
                ..UpdateDeviceRequest::default()
            },
        )
        .await
        .unwrap();

        for idx in 1..=3 {
            let mac = format!("02:00:00:00:01:{idx:02x}");
            upsert_seen_device_with_retention(&pool, &mac, None, 2)
                .await
                .unwrap();
        }

        let rows: Vec<(String, String)> =
            sqlx::query_as("SELECT mac, notes FROM devices ORDER BY id ASC")
                .fetch_all(&pool)
                .await
                .unwrap();

        assert_eq!(
            rows,
            vec![
                ("02:00:00:00:01:00".to_string(), "keep".to_string()),
                ("02:00:00:00:01:02".to_string(), String::new()),
                ("02:00:00:00:01:03".to_string(), String::new()),
            ]
        );
    }

    #[tokio::test]
    async fn auto_discovered_device_pruning_preserves_manual_blank_rows() {
        let pool = test_pool().await;
        create_device(
            &pool,
            CreateDeviceRequest {
                mac: "02:00:00:00:02:00".to_string(),
                hostname: None,
                serial_number: None,
                notes: None,
                tags: None,
                default_profile_id: None,
                one_time_profile_id: None,
            },
        )
        .await
        .unwrap();

        for idx in 1..=3 {
            let mac = format!("02:00:00:00:02:{idx:02x}");
            upsert_seen_device_with_retention(&pool, &mac, None, 2)
                .await
                .unwrap();
        }

        let rows: Vec<(String,)> = sqlx::query_as("SELECT mac FROM devices ORDER BY id ASC")
            .fetch_all(&pool)
            .await
            .unwrap();
        let macs = rows.into_iter().map(|(mac,)| mac).collect::<Vec<_>>();

        assert_eq!(
            macs,
            vec![
                "02:00:00:00:02:00",
                "02:00:00:00:02:02",
                "02:00:00:00:02:03",
            ]
        );
    }

    #[tokio::test]
    async fn profile_cmdline_rejects_control_characters() {
        let pool = test_pool().await;
        let err = create_profile(
            &pool,
            CreateBootProfileRequest {
                name: "Installer".to_string(),
                description: None,
                profile_type: BootProfileType::LinuxInstaller,
                enabled: Some(true),
                is_default: Some(false),
                one_time: Some(false),
                kernel_path: Some("netboot/vmlinuz".to_string()),
                initrd_path: None,
                iso_path: None,
                cmdline: Some("auto=true\nshell".to_string()),
                raw_script: None,
            },
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("cmdline"));
    }

    #[tokio::test]
    async fn profile_name_rejects_control_characters() {
        let pool = test_pool().await;
        let err = create_profile(
            &pool,
            CreateBootProfileRequest {
                name: "Installer\nshell".to_string(),
                description: None,
                profile_type: BootProfileType::LinuxInstaller,
                enabled: Some(true),
                is_default: Some(false),
                one_time: Some(false),
                kernel_path: Some("netboot/vmlinuz".to_string()),
                initrd_path: None,
                iso_path: None,
                cmdline: None,
                raw_script: None,
            },
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("profile name"));
    }

    #[tokio::test]
    async fn profile_description_rejects_oversized_values() {
        let pool = test_pool().await;
        let err = create_profile(
            &pool,
            CreateBootProfileRequest {
                name: "Installer".to_string(),
                description: Some("x".repeat(MAX_PROFILE_DESCRIPTION_CHARS + 1)),
                profile_type: BootProfileType::LinuxInstaller,
                enabled: Some(true),
                is_default: Some(false),
                one_time: Some(false),
                kernel_path: Some("netboot/vmlinuz".to_string()),
                initrd_path: None,
                iso_path: None,
                cmdline: None,
                raw_script: None,
            },
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("description"));
    }

    #[tokio::test]
    async fn profile_raw_script_rejects_oversized_values() {
        let pool = test_pool().await;
        let err = create_profile(
            &pool,
            CreateBootProfileRequest {
                name: "Custom".to_string(),
                description: None,
                profile_type: BootProfileType::CustomIpxe,
                enabled: Some(true),
                is_default: Some(false),
                one_time: Some(false),
                kernel_path: None,
                initrd_path: None,
                iso_path: None,
                cmdline: None,
                raw_script: Some("echo x\n".repeat((MAX_PROFILE_RAW_SCRIPT_BYTES / 7) + 1)),
            },
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("raw_script"));
    }

    #[tokio::test]
    async fn prune_missing_iso_assets_removes_unseen_rows() {
        let pool = test_pool().await;
        upsert_iso_asset(&pool, "keep.iso", "keep.iso", 10, &"a".repeat(64))
            .await
            .unwrap();
        upsert_iso_asset(&pool, "stale.iso", "nested/stale.iso", 20, &"b".repeat(64))
            .await
            .unwrap();

        let removed = prune_missing_iso_assets(&pool, &["keep.iso".to_string()])
            .await
            .unwrap();
        let assets = list_iso_assets(&pool).await.unwrap();

        assert_eq!(removed, 1);
        assert_eq!(assets.len(), 1);
        assert_eq!(assets[0].relative_path, "keep.iso");
    }

    #[tokio::test]
    async fn build_job_state_helpers_claim_and_finish_jobs() {
        let pool = test_pool().await;
        let job = create_build_job(
            &pool,
            CreateBuildJobRequest {
                requested_artifact_type: "nixos_closure".to_string(),
                build_spec: None,
                target: Some("desktop_experience".to_string()),
                system: Some("x86_64-linux".to_string()),
                input_revision: "desktop-blueprint-1".to_string(),
                input_config_hash: "a".repeat(64),
                cache_metadata: Some(json!({"signing": "pending"})),
            },
        )
        .await
        .unwrap();

        assert_eq!(job.status, "queued");
        assert_eq!(job.target, "desktop_experience");
        assert_eq!(job.system, "x86_64-linux");
        assert_eq!(job.build_spec["artifact_type"], "nixos_closure");

        let claimed = claim_next_build_job(&pool).await.unwrap().unwrap();
        assert_eq!(claimed.id, job.id);
        assert_eq!(claimed.status, "running");
        assert!(claimed.started_at.is_some());

        update_build_job_logs(&pool, job.id, &"x".repeat(MAX_BUILD_LOG_BYTES + 100))
            .await
            .unwrap();
        let running = get_build_job(&pool, job.id).await.unwrap();
        assert!(running.logs.len() <= MAX_BUILD_LOG_BYTES);

        finish_build_job(
            &pool,
            job.id,
            "succeeded",
            "done",
            "",
            "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-output",
            &"b".repeat(64),
            42,
            Some(0),
            Some(json!({"cache": "exported"})),
        )
        .await
        .unwrap();
        let updated = get_build_job(&pool, job.id).await.unwrap();

        assert_eq!(updated.status, "succeeded");
        assert_eq!(updated.output_size_bytes, 42);
        assert_eq!(updated.exit_code, Some(0));
        assert!(updated.completed_at.is_some());
    }

    #[tokio::test]
    async fn build_job_recovery_and_cancellation_are_transactional() {
        let pool = test_pool().await;
        let first = create_build_job(
            &pool,
            CreateBuildJobRequest {
                requested_artifact_type: "nixos_closure".to_string(),
                build_spec: None,
                target: Some("desktop_experience".to_string()),
                system: Some("x86_64-linux".to_string()),
                input_revision: "rev-1".to_string(),
                input_config_hash: "a".repeat(64),
                cache_metadata: None,
            },
        )
        .await
        .unwrap();
        let second = create_build_job(
            &pool,
            CreateBuildJobRequest {
                requested_artifact_type: "nixos_closure".to_string(),
                build_spec: None,
                target: Some("desktop_experience".to_string()),
                system: Some("x86_64-linux".to_string()),
                input_revision: "rev-2".to_string(),
                input_config_hash: "b".repeat(64),
                cache_metadata: None,
            },
        )
        .await
        .unwrap();

        claim_next_build_job(&pool).await.unwrap().unwrap();
        assert!(!build_job_cancel_requested(&pool, first.id).await.unwrap());

        cancel_managed_build_jobs(&pool, &[]).await.unwrap();
        let recovered = recover_running_build_jobs(&pool, "restart recovery")
            .await
            .unwrap();
        assert_eq!(recovered, 1);
        assert_eq!(
            get_build_job(&pool, first.id).await.unwrap().status,
            "failed"
        );

        sqlx::query("UPDATE forge_build_jobs SET managed_job_id = ? WHERE id = ?")
            .bind("managed-job-2")
            .bind(second.id)
            .execute(&pool)
            .await
            .unwrap();
        claim_next_build_job(&pool).await.unwrap().unwrap();
        cancel_managed_build_jobs(&pool, &["managed-job-2".to_string()])
            .await
            .unwrap();
        assert!(build_job_cancel_requested(&pool, second.id).await.unwrap());
    }

    #[tokio::test]
    async fn build_job_validation_rejects_unsafe_inputs() {
        let pool = test_pool().await;
        let err = create_build_job(
            &pool,
            CreateBuildJobRequest {
                requested_artifact_type: "NixOS Closure".to_string(),
                build_spec: None,
                target: None,
                system: None,
                input_revision: "rev".to_string(),
                input_config_hash: "a".repeat(64),
                cache_metadata: None,
            },
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("requested_artifact_type"));

        let err = create_build_job(
            &pool,
            CreateBuildJobRequest {
                requested_artifact_type: "nixos_closure".to_string(),
                build_spec: None,
                target: None,
                system: None,
                input_revision: "rev".to_string(),
                input_config_hash: "not-a-sha".to_string(),
                cache_metadata: None,
            },
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("input_config_hash"));
    }

    #[tokio::test]
    async fn cache_artifact_validation_rejects_bad_hashes_and_paths() {
        let pool = test_pool().await;
        let err = create_cache_artifact(
            &pool,
            CreateCacheArtifactRequest {
                artifact_type: "nixos_closure".to_string(),
                hash: "not-a-sha".to_string(),
                size_bytes: 1,
                path: "/srv/cybex-forge/cache/artifact".to_string(),
                store_path: None,
                narinfo_path: None,
                nar_url: None,
                file_hash: None,
                nar_hash: None,
                nar_size_bytes: None,
                closure_size_bytes: None,
                compression: None,
                references: None,
                serving_url: Some("http://forge.example/cache/artifact".to_string()),
                source_build_job_id: None,
                cache_metadata: None,
            },
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("hash"));

        let err = create_cache_artifact(
            &pool,
            CreateCacheArtifactRequest {
                artifact_type: "nixos_closure".to_string(),
                hash: "b".repeat(64),
                size_bytes: 1,
                path: "../artifact".to_string(),
                store_path: None,
                narinfo_path: None,
                nar_url: None,
                file_hash: None,
                nar_hash: None,
                nar_size_bytes: None,
                closure_size_bytes: None,
                compression: None,
                references: None,
                serving_url: Some("http://forge.example/cache/artifact".to_string()),
                source_build_job_id: None,
                cache_metadata: None,
            },
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("path"));

        let artifact = create_cache_artifact(
            &pool,
            CreateCacheArtifactRequest {
                artifact_type: "nixos_closure".to_string(),
                hash: "c".repeat(64),
                size_bytes: 4096,
                path: "/srv/cybex-forge/cache/artifact".to_string(),
                store_path: Some("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-output".to_string()),
                narinfo_path: Some(
                    "/srv/cybex-forge/www/cache/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.narinfo"
                        .to_string(),
                ),
                nar_url: Some("nar/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.nar.xz".to_string()),
                file_hash: Some("sha256:abc".to_string()),
                nar_hash: Some("sha256:def".to_string()),
                nar_size_bytes: Some(2048),
                closure_size_bytes: Some(4096),
                compression: Some("xz".to_string()),
                references: Some(json!([
                    "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-output"
                ])),
                serving_url: Some("http://forge.example/cache/artifact".to_string()),
                source_build_job_id: Some("job-1".to_string()),
                cache_metadata: Some(json!({"nix_cache_signing": "pending"})),
            },
        )
        .await
        .unwrap();

        assert_eq!(artifact.hash, "c".repeat(64));
        assert_eq!(
            artifact.store_path,
            "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-output"
        );
        assert_eq!(artifact.nar_size_bytes, 2048);
        assert_eq!(artifact.source_build_job_id.as_deref(), Some("job-1"));
        assert_eq!(artifact.cache_metadata["nix_cache_signing"], "pending");
    }

    #[tokio::test]
    async fn device_metadata_rejects_oversized_values() {
        let pool = test_pool().await;
        let err = create_device(
            &pool,
            CreateDeviceRequest {
                mac: "02:00:00:00:20:00".to_string(),
                hostname: Some("x".repeat(MAX_DEVICE_HOSTNAME_CHARS + 1)),
                serial_number: None,
                notes: None,
                tags: None,
                default_profile_id: None,
                one_time_profile_id: None,
            },
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("hostname"));

        let err = create_device(
            &pool,
            CreateDeviceRequest {
                mac: "02:00:00:00:20:01".to_string(),
                hostname: None,
                serial_number: Some("x".repeat(MAX_DEVICE_SERIAL_CHARS + 1)),
                notes: None,
                tags: None,
                default_profile_id: None,
                one_time_profile_id: None,
            },
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("serial"));

        let err = create_device(
            &pool,
            CreateDeviceRequest {
                mac: "02:00:00:00:20:02".to_string(),
                hostname: None,
                serial_number: None,
                notes: Some("x".repeat(MAX_DEVICE_NOTES_CHARS + 1)),
                tags: None,
                default_profile_id: None,
                one_time_profile_id: None,
            },
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("notes"));
    }

    #[tokio::test]
    async fn device_tags_reject_oversized_or_control_character_values() {
        let pool = test_pool().await;
        let err = create_device(
            &pool,
            CreateDeviceRequest {
                mac: "02:00:00:00:21:00".to_string(),
                hostname: None,
                serial_number: None,
                notes: None,
                tags: Some(
                    (0..=MAX_DEVICE_TAGS)
                        .map(|idx| format!("tag-{idx}"))
                        .collect(),
                ),
                default_profile_id: None,
                one_time_profile_id: None,
            },
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("tags"));

        let err = create_device(
            &pool,
            CreateDeviceRequest {
                mac: "02:00:00:00:21:01".to_string(),
                hostname: None,
                serial_number: None,
                notes: None,
                tags: Some(vec!["rack\n1".to_string()]),
                default_profile_id: None,
                one_time_profile_id: None,
            },
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("tag"));
    }
}
