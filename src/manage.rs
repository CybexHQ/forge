#[cfg(unix)]
use std::os::{
    fd::AsRawFd,
    unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
};
use std::{
    collections::{HashMap, HashSet},
    ffi::OsString,
    fs,
    io::{BufReader, Read, Write},
    path::{Path, PathBuf},
    process::{Command as StdCommand, Stdio},
    str::FromStr,
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::{SecondsFormat, Utc};
use ed25519_dalek::{Signer, SigningKey};
use rand::{RngCore, rngs::OsRng};
use reqwest::{
    Client, Method,
    header::{CONTENT_RANGE, CONTENT_TYPE, IF_RANGE, RANGE},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, Sqlite, SqlitePool, Transaction};
use tokio::time::sleep;
use tokio::{
    fs as tokio_fs,
    io::{AsyncReadExt, AsyncWriteExt},
};
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::{
    AppState, RuntimeSettings, assets,
    config::{
        AppConfig, ManageConfig, normalize_absolute_config_path, normalize_bootloader_filename,
        normalize_http_url, normalize_listen_addr, validate_menu_timeout_ms,
    },
    db,
    models::{BootProfileType, BuildJob, CacheArtifact, clean_tags, normalize_mac},
    redact::redact_sensitive_key_values,
    updater::{ForgeUpdateStatusReport, ManagedUpdateRequest},
};

const CAPABILITY_BOOT_V1: &str = "boot_v1";
const CAPABILITY_BUILDER_V1: &str = "builder_v1";
const CAPABILITY_BLUEPRINT_BUILDER_V2: &str = "blueprint_builder_v2";
const CAPABILITY_CACHE_V1: &str = "cache_v1";
const CAPABILITY_UPDATER_V1: &str = "updater_v1";
const FORGE_REPORT_SCOPE_UPDATE_ONLY: &str = "update_only";
const CYBEX_COMPONENT_PROTOCOL_VERSION: u32 = 3;
const CYBEX_MINIMUM_MANAGE_PROTOCOL_VERSION: u32 = 1;
const CYBEX_MAXIMUM_MANAGE_PROTOCOL_VERSION: u32 = 3;
const PXE_MENU_BACKGROUND_ASSET: &[u8] = include_bytes!("../assets/pxe-menu.png");
const PXE_MENU_BACKGROUND_FILENAME: &str = "pxe-menu.png";
const MAX_MANAGED_PROFILES: usize = 1_000;
const MAX_DELETED_MANAGED_PROFILES: usize = 2_000;
const MAX_MANAGED_CLIENTS: usize = 2_000;
const MAX_DELETED_MANAGED_CLIENTS: usize = 2_000;
const MAX_MANAGED_BUILD_JOBS: usize = 500;
const MAX_REPORT_CLIENTS: usize = 2_000;
const MAX_REPORT_ASSETS: usize = 2_000;
const MAX_REPORT_EVENTS: i64 = 500;
const MAX_REPORT_BUILD_JOBS: usize = 500;
const MAX_REPORT_CACHE_ARTIFACTS: usize = 2_000;
const MAX_MANAGED_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_BOOT_REPORT_BODY_BYTES: usize = 3 * 1024 * 1024;
// Closure-bearing cache metadata is bounded to 24 MiB. Leave
// room for the remainder of the authenticated node report so a verified
// manifest is never silently dropped solely because the transport cap is
// smaller than the persistence contract.
const MAX_FORGE_REPORT_BODY_BYTES: usize = 32 * 1024 * 1024;
const MAX_DEVICE_HOSTNAME_CHARS: usize = 253;
const MAX_DEVICE_SERIAL_CHARS: usize = 128;
const MAX_DEVICE_NOTES_CHARS: usize = 2_000;
const MAX_DEVICE_TAGS: usize = 50;
const MAX_DEVICE_TAG_CHARS: usize = 64;
const MAX_PROFILE_DESCRIPTION_CHARS: usize = 2_000;
const MAX_PROFILE_RAW_SCRIPT_BYTES: usize = 64 * 1024;
const BOOT_PROFILE_ISO_SOURCE_BOOT_PROFILE: &str = "boot_profile";
const BOOT_PROFILE_ISO_SOURCE_ENROLLMENT: &str = "enrollment";
const RELIABILITY_STATE_PATH: &str = "/var/lib/cybex-forge/reliability-state.json";
const MAX_RELIABILITY_STATE_BYTES: usize = 16 * 1024;
const FORGE_SERVICE_UNIT: &str = include_str!("../systemd/cybex-forge.service");
const FORGE_CONTROL_SLICE_UNIT: &str = include_str!("../systemd/cybex-forge-control.slice");
const FORGE_BUILD_SLICE_UNIT: &str = include_str!("../systemd/cybex-forge-build.slice");
const FORGE_SENTINEL_SERVICE_UNIT: &str = include_str!("../systemd/cybex-forge-sentinel.service");
const FORGE_SENTINEL_TIMER_UNIT: &str = include_str!("../systemd/cybex-forge-sentinel.timer");
const FORGE_CHECK_SCRIPT: &str = include_str!("../install/cybex-forge-check");
const FORGE_SENTINEL_SCRIPT: &str = include_str!("../install/cybex-forge-sentinel");
const RESOLVER_RECOVERY_DROPIN: &str = r#"[Unit]
StartLimitIntervalSec=0

[Service]
Restart=always
RestartSec=2s
Slice=cybex-forge-control.slice
CPUWeight=1000
IOWeight=1000
OOMScoreAdjust=-750
"#;
const NIX_DAEMON_RESOURCE_DROPIN: &str = r#"[Unit]
StartLimitIntervalSec=0

[Service]
Restart=always
RestartSec=3s
Slice=cybex-forge-build.slice
CPUWeight=25
IOWeight=25
OOMScoreAdjust=250
"#;
const NGINX_AVAILABILITY_DROPIN: &str = r#"[Unit]
StartLimitIntervalSec=0

[Service]
Restart=always
RestartSec=2s
Slice=cybex-forge-control.slice
CPUWeight=1000
IOWeight=1000
OOMScoreAdjust=-500
"#;
const TFTP_AVAILABILITY_DROPIN: &str = NGINX_AVAILABILITY_DROPIN;

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
struct ManagedState {
    private_key_b64: Option<String>,
    public_key_b64: Option<String>,
    public_key_fingerprint: Option<String>,
    enrollment_id: Option<String>,
    enrollment_secret: Option<String>,
    pairing_code: Option<String>,
    device_id: Option<String>,
    managed_token: Option<String>,
    last_reported_event_id: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct EnrollmentResponse {
    enrollment_id: String,
    pairing_code: String,
    status: String,
    enrollment_secret: Option<String>,
}

#[derive(Debug, Deserialize)]
struct EnrollmentStatusResponse {
    status: String,
    device_id: Option<String>,
    managed_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ComponentCompatibilityContract {
    protocol_version: u32,
    minimum_forge_protocol: u32,
    maximum_forge_protocol: u32,
    manage_version: String,
    manage_release: String,
}

#[derive(Debug, Deserialize)]
struct AgentBootConfigResponse {
    #[serde(default)]
    compatibility: Option<ComponentCompatibilityContract>,
    settings: ManagedBootSettings,
    profiles: Vec<ManagedBootProfile>,
    #[serde(default)]
    profiles_complete: bool,
    #[serde(default)]
    deleted_profile_ids: Vec<String>,
    clients: Vec<ManagedBootClient>,
    #[serde(default)]
    deleted_client_ids: Vec<String>,
    #[serde(default)]
    clients_complete: bool,
}

#[derive(Debug, Deserialize)]
struct AgentForgeConfigResponse {
    #[serde(default)]
    compatibility: Option<ComponentCompatibilityContract>,
    #[serde(default)]
    build_jobs: Vec<ManagedBuildJob>,
    #[serde(default)]
    deleted_build_job_ids: Vec<String>,
    #[serde(default)]
    build_jobs_complete: bool,
    #[serde(default)]
    deleted_cache_artifacts: Vec<ManagedDeletedCacheArtifact>,
    #[serde(default)]
    protected_cache_artifacts: Vec<ManagedProtectedCacheArtifact>,
    #[serde(default)]
    protected_cache_artifacts_complete: bool,
    #[serde(default)]
    update: Option<ManagedUpdateRequest>,
}

#[derive(Debug, Deserialize)]
struct ForgeReportResponse {
    #[serde(default)]
    update: bool,
}

#[derive(Debug, Deserialize)]
struct ForgeUpdateOnlyReportResponse {
    status: String,
    update: bool,
    report_scope: String,
    persisted_update: ForgePersistedUpdateAcknowledgement,
}

#[derive(Debug, Deserialize)]
struct ForgePersistedUpdateAcknowledgement {
    status: String,
    attempt_id: String,
    reported_at: String,
}

#[derive(Debug, Deserialize)]
struct ManagedDeletedCacheArtifact {
    artifact_type: String,
    hash: String,
}

#[derive(Debug, Deserialize)]
struct ManagedProtectedCacheArtifact {
    artifact_type: String,
    hash: String,
}

#[derive(Debug, Deserialize)]
struct ManagedBuildJob {
    id: String,
    requested_artifact_type: String,
    #[serde(default)]
    build_spec: Option<Value>,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    system: Option<String>,
    input_revision: String,
    input_config_hash: String,
    #[serde(default)]
    cache_metadata: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct ManagedBootSettings {
    #[serde(default)]
    public_base_url: String,
    #[serde(default)]
    listen_addr: String,
    #[serde(default)]
    tftp_root: String,
    #[serde(default)]
    http_root: String,
    #[serde(default)]
    bootloader_filename: String,
    #[serde(default)]
    menu_timeout_ms: u32,
}

#[derive(Debug, Deserialize)]
struct ManagedBootProfile {
    id: String,
    name: String,
    description: String,
    profile_type: String,
    #[serde(default = "default_installer_iso_source")]
    installer_iso_source: String,
    enabled: bool,
    is_default: bool,
    one_time: bool,
    kernel_path: Option<String>,
    initrd_path: Option<String>,
    iso_path: Option<String>,
    cmdline: Option<String>,
    raw_script: Option<String>,
    #[serde(default)]
    desired_iso_artifact_id: String,
    #[serde(default)]
    desired_iso_filename: String,
    #[serde(default)]
    desired_iso_size_bytes: i64,
    #[serde(default)]
    desired_iso_sha256: String,
    #[serde(default)]
    desired_iso_built_at: Option<String>,
    #[serde(default)]
    desired_iso_url: String,
    #[serde(default)]
    desired_iso_download_url: String,
    #[serde(default)]
    sync_generation: i64,
    #[serde(default)]
    sync_operation_id: String,
}

#[derive(Debug, Deserialize)]
struct ManagedBootClient {
    id: String,
    mac: String,
    hostname: Option<String>,
    serial_number: Option<String>,
    last_seen_at: Option<String>,
    default_profile_id: Option<String>,
    one_time_profile_id: Option<String>,
    notes: String,
    #[serde(default)]
    tags: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
struct BootAgentReportRequest {
    protocol_version: u32,
    settings: BootAgentSettingsReport,
    profile_sync: Vec<BootAgentProfileSyncReport>,
    clients: Vec<BootAgentClientReport>,
    assets: Vec<BootAgentAssetReport>,
    events: Vec<BootAgentEventReport>,
}

#[derive(Clone, Debug, Serialize)]
struct BootAgentSettingsReport {
    public_base_url: String,
    listen_addr: String,
    tftp_root: String,
    http_root: String,
    bootloader_filename: String,
    menu_timeout_ms: u32,
    version: String,
    status: String,
    state: Value,
}

#[derive(Clone, Debug, Serialize)]
struct BootAgentClientReport {
    managed_client_id: Option<String>,
    mac: String,
    hostname: Option<String>,
    serial_number: Option<String>,
    last_seen_at: Option<String>,
    default_profile_id: Option<String>,
    one_time_profile_id: Option<String>,
    notes: String,
    tags: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
struct BootAgentAssetReport {
    filename: String,
    relative_path: String,
    absolute_path: String,
    size_bytes: i64,
    checksum_sha256: String,
    last_scanned_at: String,
    created_at: String,
}

#[derive(Clone, Debug, Serialize)]
struct BootAgentEventReport {
    source_event_id: i64,
    mac: Option<String>,
    serial_number: Option<String>,
    ip_address: Option<String>,
    user_agent: Option<String>,
    selected_profile_id: Option<String>,
    selected_profile_name: Option<String>,
    known_client: bool,
    created_at: String,
}

#[derive(Clone, Debug, Serialize)]
struct BootAgentProfileSyncReport {
    profile_id: String,
    sync_generation: i64,
    sync_operation_id: String,
    state: String,
    progress_percent: Option<i32>,
    bytes_downloaded: Option<i64>,
    total_bytes: Option<i64>,
    artifact_id: Option<String>,
    filename: Option<String>,
    size_bytes: Option<i64>,
    sha256: Option<String>,
    error: Option<String>,
    started_at: Option<chrono::DateTime<Utc>>,
    completed_at: Option<chrono::DateTime<Utc>>,
    failed_at: Option<chrono::DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize)]
struct ForgeAgentReportRequest {
    protocol_version: u32,
    capabilities: Vec<&'static str>,
    cache: crate::cache::CacheStatusReport,
    update: Option<ForgeUpdateStatusReport>,
    build_jobs: Vec<ForgeBuildJobReport>,
    cache_artifacts: Vec<ForgeCacheArtifactReport>,
    cache_inventory_instance_id: String,
    cache_inventory_generation: i64,
    cache_artifacts_complete: bool,
    disk: Option<crate::disk::DiskStats>,
    host: Option<crate::host::HostStats>,
}

#[derive(Clone, Debug, Serialize)]
struct ForgeUpdateOnlyReportRequest {
    protocol_version: u32,
    report_scope: &'static str,
    capabilities: [&'static str; 1],
    update: ForgeUpdateStatusReport,
}

#[derive(Clone, Debug, Serialize)]
struct ForgeBuildJobReport {
    local_id: i64,
    managed_job_id: Option<String>,
    requested_artifact_type: String,
    build_spec: Value,
    target: String,
    system: String,
    input_revision: String,
    input_config_hash: String,
    status: String,
    progress_percent: Option<i32>,
    progress_stage: Option<String>,
    progress_message: Option<String>,
    logs: String,
    error: String,
    output_path: String,
    output_sha256: String,
    output_size_bytes: i64,
    exit_code: Option<i64>,
    cache_metadata: Value,
    started_at: Option<String>,
    completed_at: Option<String>,
    cancel_requested_at: Option<String>,
    created_at: String,
    updated_at: String,
}

#[derive(Clone, Debug, Serialize)]
struct ForgeCacheArtifactReport {
    local_id: i64,
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
    closure_file_size_bytes: i64,
    compression: String,
    references: Value,
    serving_url: String,
    source_build_job_id: Option<String>,
    cache_metadata: Value,
    created_at: String,
    updated_at: String,
}

impl From<BuildJob> for ForgeBuildJobReport {
    fn from(job: BuildJob) -> Self {
        Self {
            local_id: job.id,
            managed_job_id: optional_report_uuid(job.managed_job_id),
            requested_artifact_type: job.requested_artifact_type,
            build_spec: job.build_spec,
            target: job.target,
            system: job.system,
            input_revision: job.input_revision,
            input_config_hash: job.input_config_hash,
            status: job.status,
            progress_percent: job.progress_percent,
            progress_stage: job.progress_stage,
            progress_message: job.progress_message,
            logs: job.logs,
            error: job.error,
            output_path: job.output_path,
            output_sha256: job.output_sha256,
            output_size_bytes: job.output_size_bytes,
            exit_code: job.exit_code,
            cache_metadata: job.cache_metadata,
            started_at: job.started_at,
            completed_at: job.completed_at,
            cancel_requested_at: job.cancel_requested_at,
            created_at: job.created_at,
            updated_at: job.updated_at,
        }
    }
}

impl From<CacheArtifact> for ForgeCacheArtifactReport {
    fn from(artifact: CacheArtifact) -> Self {
        Self {
            local_id: artifact.id,
            managed_artifact_id: optional_report_uuid(artifact.managed_artifact_id),
            artifact_type: artifact.artifact_type,
            hash: artifact.hash,
            size_bytes: artifact.size_bytes,
            path: artifact.path,
            store_path: artifact.store_path,
            narinfo_path: artifact.narinfo_path,
            nar_url: artifact.nar_url,
            file_hash: artifact.file_hash,
            nar_hash: artifact.nar_hash,
            nar_size_bytes: artifact.nar_size_bytes,
            closure_size_bytes: artifact.closure_size_bytes,
            closure_file_size_bytes: artifact.closure_file_size_bytes,
            compression: artifact.compression,
            references: artifact.references,
            serving_url: artifact.serving_url,
            source_build_job_id: optional_report_uuid(artifact.source_build_job_id),
            cache_metadata: artifact.cache_metadata,
            created_at: artifact.created_at,
            updated_at: artifact.updated_at,
        }
    }
}

#[derive(Debug, FromRow)]
struct BootEventReportRow {
    id: i64,
    mac: Option<String>,
    serial_number: Option<String>,
    ip_address: Option<String>,
    user_agent: Option<String>,
    selected_profile_id: Option<String>,
    selected_profile_name: Option<String>,
    known_device: i64,
    created_at: String,
}

#[derive(Debug, FromRow)]
struct ManagedIsoSyncTarget {
    local_id: i64,
    profile_id: String,
    sync_generation: i64,
    sync_operation_id: String,
    sync_state: String,
    sync_progress_percent: i32,
    sync_bytes_downloaded: i64,
    sync_total_bytes: i64,
    sync_attempts: i64,
    sync_next_attempt_at: Option<String>,
    sync_error: String,
    sync_started_at: Option<String>,
    sync_completed_at: Option<String>,
    sync_failed_at: Option<String>,
    sync_last_verified_at: Option<String>,
    profile_type: String,
    desired_iso_artifact_id: String,
    desired_iso_filename: String,
    desired_iso_size_bytes: i64,
    desired_iso_sha256: String,
    desired_iso_download_url: String,
}

#[derive(Debug)]
struct AssetScanReport {
    status: &'static str,
    scanned_count: Option<usize>,
    error: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedUpdateReport {
    pub status: String,
    pub attempt_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SyncOnceUpdaterReport {
    pub status: String,
    pub attempt_id: String,
    pub stage: String,
    pub target_version: String,
    pub current_version: String,
    pub progress_percent: Option<i32>,
}

impl From<&ForgeUpdateStatusReport> for SyncOnceUpdaterReport {
    fn from(status: &ForgeUpdateStatusReport) -> Self {
        Self {
            status: status.status.clone(),
            attempt_id: status.attempt_id.clone(),
            stage: status.stage.clone(),
            target_version: status.target_version.clone(),
            current_version: status.current_version.clone(),
            progress_percent: status.progress_percent,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncOnceDisposition {
    Synced,
    PendingEnrollment,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SyncOnceReport {
    pub schema: &'static str,
    pub outcome: SyncOnceDisposition,
    /// True only after Manage accepted and returned JSON for the signed Forge
    /// report. Boot reports are intentionally not counted here.
    pub report_posted: bool,
    pub update_included: bool,
    pub update_acknowledged: bool,
    pub updater: Option<SyncOnceUpdaterReport>,
}

impl SyncOnceReport {
    fn pending_enrollment() -> Self {
        Self {
            schema: "cybex.forge.sync-once.v1",
            outcome: SyncOnceDisposition::PendingEnrollment,
            report_posted: false,
            update_included: false,
            update_acknowledged: false,
            updater: None,
        }
    }

    fn synced(receipt: ForgeReportReceipt) -> Self {
        Self {
            schema: "cybex.forge.sync-once.v1",
            outcome: SyncOnceDisposition::Synced,
            report_posted: true,
            update_included: receipt.updater.is_some(),
            update_acknowledged: receipt.update_acknowledged,
            updater: receipt.updater,
        }
    }
}

#[derive(Debug)]
struct ForgeReportReceipt {
    update_acknowledged: bool,
    scope_acknowledged: bool,
    persisted_update_acknowledged: bool,
    updater: Option<SyncOnceUpdaterReport>,
}

#[derive(Debug)]
struct NormalizedManagedSettings {
    public_base_url: String,
    listen_addr: String,
    tftp_root: PathBuf,
    http_root: PathBuf,
    bootloader_filename: String,
    menu_timeout_ms: u32,
}

pub fn spawn(state: AppState) {
    let iso_worker_state = state.clone();
    tokio::spawn(async move {
        run_managed_iso_sync_worker(iso_worker_state).await;
    });
    tokio::spawn(async move {
        let mut consecutive_failures: u32 = 0;
        loop {
            let interval = match sync_once_with_outcome(&state).await {
                Ok(report) => {
                    consecutive_failures = 0;
                    let normal_interval =
                        managed_sync_interval_seconds(&state.config.manage, report.outcome);
                    match db::active_build_job_count(&state.db).await {
                        Ok(active_builds) => {
                            active_managed_sync_interval_seconds(normal_interval, active_builds > 0)
                        }
                        Err(err) => {
                            warn!(error = %err, "failed to inspect active Forge builds for managed sync cadence");
                            normal_interval
                        }
                    }
                }
                Err(err) => {
                    consecutive_failures = consecutive_failures.saturating_add(1);
                    let interval =
                        failed_sync_interval_seconds(&state.config.manage, consecutive_failures);
                    warn!(
                        error = %safe_error(&err),
                        consecutive_failures,
                        retry_in_seconds = interval,
                        "managed sync failed"
                    );
                    interval
                }
            };
            sleep(Duration::from_secs(interval)).await;
        }
    });
}

pub async fn enroll_once(state: &AppState) -> Result<()> {
    ensure_manage_enabled(state)?;
    // Enrollment identity, rotated polling credentials, and adoption tokens
    // share one state document. Serialize every read/modify/write cycle across
    // the service and one-shot CLI commands before loading that document.
    let _state_lock = acquire_managed_state_lock(&state.config)?;
    let mut managed = load_managed_state(state)?;
    ensure_key_material(&mut managed)?;
    // The enrollment public key is an idempotency identity. Make it durable
    // before the first HTTP request so response loss cannot create a second
    // pending identity on the next retry.
    save_managed_state(state, &managed)?;
    let enrolled = ensure_enrolled(state, &mut managed).await?;
    save_managed_state(state, &managed)?;
    if enrolled {
        info!("managed enrollment is adopted");
    } else {
        info!("managed enrollment is pending administrator approval");
    }
    Ok(())
}

pub async fn sync_once(state: &AppState) -> Result<SyncOnceReport> {
    sync_once_with_outcome(state).await
}

/// Post one exact updater status without opening the Forge SQLite database or
/// reading/mutating Boot, Build, or Cache state.
///
/// This path exists for qualification while a historical Forge binary is the
/// active service. It deliberately requires an already-adopted signing state,
/// an update-only scope acknowledgement from Manage, and—when supplied—an
/// exact local status/attempt fence.
pub async fn sync_update_report_once(
    config: &AppConfig,
    expected_update: Option<&ExpectedUpdateReport>,
) -> Result<SyncOnceReport> {
    ensure_manage_enabled_config(config)?;
    if !crate::updater::capabilities_enabled(config) {
        bail!("update-only Forge sync requires an enabled updater trust anchor");
    }
    let _state_lock = acquire_managed_state_lock(config)?;
    let managed = load_managed_state_from_config(config)?;
    let device_id = managed_device_id(&managed)?;
    let update = crate::updater::status_report(config)
        .await?
        .ok_or_else(|| {
            anyhow!("update-only Forge sync did not include a local updater status report")
        })?;
    validate_expected_update_report(Some(&update), expected_update)?;

    let updater = SyncOnceUpdaterReport::from(&update);
    let body = ForgeUpdateOnlyReportRequest {
        protocol_version: CYBEX_COMPONENT_PROTOCOL_VERSION,
        report_scope: FORGE_REPORT_SCOPE_UPDATE_ONLY,
        capabilities: [CAPABILITY_UPDATER_V1],
        update,
    };
    let body_bytes =
        serde_json::to_vec(&body).context("serialize update-only Forge report failed")?;
    if body_bytes.len() > MAX_FORGE_REPORT_BODY_BYTES {
        bail!("update-only Forge report exceeded {MAX_FORGE_REPORT_BODY_BYTES} bytes");
    }
    let path = format!("/v1/agent/devices/{device_id}/forge/update-report");
    let response = signed_request_for_config(config, &managed, Method::POST, &path, body_bytes)
        .await?
        .header(CONTENT_TYPE, "application/json")
        .send()
        .await
        .context("report update-only Forge state request failed")?;
    let response = parse_success_json::<ForgeUpdateOnlyReportResponse>(
        response,
        "report update-only Forge state",
    )
    .await?;
    if response.status != "ok" {
        bail!("Manage returned an invalid update-only Forge report status");
    }
    let persisted_update_acknowledged =
        persisted_update_ack_matches(&response.persisted_update, &updater);
    let receipt = ForgeReportReceipt {
        update_acknowledged: response.update,
        scope_acknowledged: response.report_scope == FORGE_REPORT_SCOPE_UPDATE_ONLY,
        persisted_update_acknowledged,
        updater: Some(updater),
    };
    validate_forge_report_receipt(&receipt, true)?;
    let report = SyncOnceReport::synced(receipt);
    validate_update_only_sync_report(&report)?;
    Ok(report)
}

pub async fn apply_runtime_config_once(config: &AppConfig) -> Result<()> {
    ensure_root_supervisor()?;
    let _apply_lock = acquire_runtime_apply_lock()?;
    ensure_manage_enabled_config(config)?;
    let managed = load_managed_state_from_config(config)?;
    if managed
        .device_id
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .is_none()
    {
        info!("managed runtime configuration is pending adoption; skipping apply");
        return Ok(());
    }
    let desired = fetch_boot_config_for_config(config, &managed).await?;
    let settings = normalize_managed_settings(&desired.settings, config)?;
    apply_runtime_settings_to_host(config, &settings)?;
    crate::updater::apply_requested_update(config).await?;
    info!("managed runtime configuration applied");
    Ok(())
}

#[cfg(unix)]
struct AdvisoryFileLock(fs::File);

#[cfg(unix)]
impl Drop for AdvisoryFileLock {
    fn drop(&mut self) {
        // O_CLOEXEC closes an inherited descriptor only once a concurrently
        // forked child reaches exec. Unlock the shared open-file description
        // explicitly so dropping the parent guard releases the lock at once.
        let _ = unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

#[cfg(not(unix))]
type AdvisoryFileLock = fs::File;

#[cfg(unix)]
fn acquire_runtime_apply_lock() -> Result<AdvisoryFileLock> {
    let lock = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open("/run/cybex-forge-runtime-apply.lock")
        .context("open managed runtime apply lock")?;
    let result = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result != 0 {
        bail!("another managed runtime apply is already running");
    }
    Ok(AdvisoryFileLock(lock))
}

#[cfg(not(unix))]
fn acquire_runtime_apply_lock() -> Result<AdvisoryFileLock> {
    fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open("cybex-forge-runtime-apply.lock")
        .context("open managed runtime apply lock")
}

async fn sync_once_with_outcome(state: &AppState) -> Result<SyncOnceReport> {
    ensure_manage_enabled(state)?;
    let _state_lock = acquire_managed_state_lock(&state.config)?;
    let mut managed = load_managed_state(state)?;
    ensure_key_material(&mut managed)?;
    // Keep the signing identity stable across failed submits and restarts.
    save_managed_state(state, &managed)?;
    if !ensure_enrolled(state, &mut managed).await? {
        save_managed_state(state, &managed)?;
        return Ok(SyncOnceReport::pending_enrollment());
    }

    if has_unreported_known_profile_events(&state.db, managed.last_reported_event_id).await? {
        report_boot_state(state, &mut managed, Vec::new()).await?;
        save_managed_state(state, &managed)?;
    }
    let config = fetch_boot_config(state, &managed).await?;
    apply_boot_config(state, &config).await?;
    let profile_sync = current_profile_sync_reports(&state.db).await?;
    report_boot_state(state, &mut managed, profile_sync).await?;
    let forge_report = sync_forge_foundation(state, &managed).await?;
    save_managed_state(state, &managed)?;
    Ok(SyncOnceReport::synced(forge_report))
}

#[derive(Debug, FromRow)]
struct ManagedBootClientReportRow {
    managed_client_id: Option<String>,
    mac: String,
    hostname: Option<String>,
    serial_number: Option<String>,
    last_seen_at: Option<String>,
    default_profile_id: Option<String>,
    one_time_profile_id: Option<String>,
    notes: String,
    tags: String,
}

/// Read the acknowledgement payload from the same committed local rows that
/// serve PXE. The managed IDs prove which Manage client/profile assignments
/// survived validation and the atomic SQLite config transaction.
async fn current_boot_client_reports(pool: &SqlitePool) -> Result<Vec<BootAgentClientReport>> {
    let rows = sqlx::query_as::<_, ManagedBootClientReportRow>(
        r#"SELECT client.managed_client_id,
                  client.mac, client.hostname, client.serial_number,
                  client.last_seen_at,
                  default_profile.managed_profile_id AS default_profile_id,
                  one_time_profile.managed_profile_id AS one_time_profile_id,
                  client.notes, client.tags
           FROM devices client
           LEFT JOIN boot_profiles default_profile
             ON default_profile.id = client.default_profile_id
           LEFT JOIN boot_profiles one_time_profile
             ON one_time_profile.id = client.one_time_profile_id
           ORDER BY CASE WHEN one_time_profile.managed_profile_id IS NOT NULL THEN 0 ELSE 1 END,
                    COALESCE(client.last_seen_at, client.created_at) DESC,
                    client.mac ASC"#,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| BootAgentClientReport {
            managed_client_id: optional_report_uuid(row.managed_client_id),
            mac: row.mac,
            hostname: row.hostname,
            serial_number: row.serial_number,
            last_seen_at: row.last_seen_at,
            default_profile_id: optional_report_uuid(row.default_profile_id),
            one_time_profile_id: optional_report_uuid(row.one_time_profile_id),
            notes: row.notes,
            tags: clean_tags(serde_json::from_str(&row.tags).unwrap_or_default()),
        })
        .collect())
}

async fn ensure_enrolled(state: &AppState, managed: &mut ManagedState) -> Result<bool> {
    if managed
        .device_id
        .as_deref()
        .is_some_and(|id| !id.trim().is_empty())
    {
        return Ok(true);
    }

    if managed.enrollment_id.is_none() || managed.enrollment_secret.is_none() {
        submit_enrollment(state, managed).await?;
        // The submit response can contain a rotated polling credential for an
        // already-adopted idempotent retry. Persist it before polling so a
        // crash cannot lose the only recovery credential.
        save_managed_state(state, managed)?;
    }

    let status = poll_enrollment(state, managed).await?;
    match status.status.as_str() {
        "adopted" => {
            let device_id = status
                .device_id
                .filter(|value| is_safe_path_segment(value))
                .ok_or_else(|| anyhow!("adopted enrollment omitted a safe device id"))?;
            managed.device_id = Some(device_id);
            managed.managed_token = status.managed_token;
            managed.enrollment_id = None;
            managed.enrollment_secret = None;
            managed.pairing_code = None;
            Ok(true)
        }
        "pending" => Ok(false),
        "rejected" | "expired" => {
            managed.enrollment_id = None;
            managed.enrollment_secret = None;
            managed.pairing_code = None;
            Ok(false)
        }
        other => bail!("unknown enrollment status {other}"),
    }
}

async fn submit_enrollment(state: &AppState, managed: &mut ManagedState) -> Result<()> {
    let body = enrollment_body(state, managed)?;
    let body = serde_json::to_vec(&body).context("serialize managed enrollment request")?;
    let timestamp = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    let request_id = random_request_id();
    let endpoint = api_url(state, "/v1/agent/enrollments")?;
    let signed_path = request_path_and_query(&endpoint)?;
    let signature =
        enrollment_request_signature(managed, &signed_path, &timestamp, &request_id, &body)?;
    let response = http_client(state)?
        .post(endpoint)
        .header("x-cybex-organization", organization_header(&state.config)?)
        .header("x-cybex-request-id", request_id)
        .header("x-cybex-timestamp", timestamp)
        .header("x-cybex-signature", signature)
        .header(CONTENT_TYPE, "application/json")
        .body(body)
        .send()
        .await
        .context("submit managed enrollment request failed")?;
    let response: EnrollmentResponse =
        parse_success_json(response, "submit managed enrollment").await?;
    apply_enrollment_response(managed, response)?;
    info!("managed enrollment submitted or recovered; checking approval state");
    Ok(())
}

fn apply_enrollment_response(
    managed: &mut ManagedState,
    response: EnrollmentResponse,
) -> Result<()> {
    if !matches!(response.status.as_str(), "pending" | "adopted") {
        bail!("managed enrollment returned unsupported status");
    }
    if !is_safe_path_segment(&response.enrollment_id) {
        bail!("managed enrollment response contained an unsafe enrollment id");
    }
    if !is_safe_path_segment(&response.pairing_code) {
        bail!("managed enrollment response contained an unsafe pairing code");
    }
    let secret = response
        .enrollment_secret
        .filter(|value| is_valid_header_value(value))
        .ok_or_else(|| anyhow!("managed enrollment response omitted polling secret"))?;
    managed.enrollment_id = Some(response.enrollment_id);
    managed.enrollment_secret = Some(secret);
    managed.pairing_code = Some(response.pairing_code);
    Ok(())
}

async fn poll_enrollment(
    state: &AppState,
    managed: &ManagedState,
) -> Result<EnrollmentStatusResponse> {
    let enrollment_id = managed
        .enrollment_id
        .as_deref()
        .filter(|value| is_safe_path_segment(value))
        .ok_or_else(|| anyhow!("missing safe enrollment id"))?;
    let secret = managed
        .enrollment_secret
        .as_deref()
        .filter(|value| is_valid_header_value(value))
        .ok_or_else(|| anyhow!("missing enrollment polling secret"))?;
    let path = format!("/v1/agent/enrollments/{enrollment_id}/status");
    let timestamp = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    let request_id = random_request_id();
    let endpoint = api_url(state, &path)?;
    let signed_path = request_path_and_query(&endpoint)?;
    let signature = enrollment_status_signature(managed, &signed_path, &timestamp, &request_id)?;
    let response = http_client(state)?
        .get(endpoint)
        .header("x-cybex-organization", organization_header(&state.config)?)
        .header("x-cybex-request-id", request_id)
        .header("x-cybex-timestamp", timestamp)
        .header("x-cybex-signature", signature)
        // Kept during the compatibility window. Manage prioritizes the
        // signed pending-key proof and older releases still accept this token.
        .header("x-cybex-enrollment-token", secret)
        .send()
        .await
        .context("poll managed enrollment request failed")?;
    parse_success_json(response, "poll managed enrollment").await
}

async fn fetch_boot_config(
    state: &AppState,
    managed: &ManagedState,
) -> Result<AgentBootConfigResponse> {
    fetch_boot_config_for_config(&state.config, managed).await
}

async fn fetch_boot_config_for_config(
    config: &AppConfig,
    managed: &ManagedState,
) -> Result<AgentBootConfigResponse> {
    let device_id = managed_device_id(managed)?;
    let path = format!("/v1/agent/devices/{device_id}/boot/config");
    let response = signed_request_for_config(config, managed, Method::GET, &path, Vec::new())
        .await?
        .send()
        .await
        .context("fetch managed boot config request failed")?;
    let mut config: AgentBootConfigResponse =
        parse_success_json(response, "fetch managed boot config").await?;
    validate_component_compatibility(config.compatibility.as_ref())?;
    normalize_legacy_boot_config(&mut config);
    Ok(config)
}

async fn report_boot_state(
    state: &AppState,
    managed: &mut ManagedState,
    profile_sync: Vec<BootAgentProfileSyncReport>,
) -> Result<()> {
    let asset_scan = asset_scan_report(
        assets::scan_iso_dir(&state.config, &state.db)
            .await
            .map(|summary| summary.discovered),
    );
    if let Some(error) = &asset_scan.error {
        warn!(error = %error, "managed ISO asset scan failed");
    }
    let clients = current_boot_client_reports(&state.db).await?;
    let assets = db::list_iso_assets(&state.db).await?;
    let profile_count = db::list_profiles(&state.db).await?.len();
    let events = list_events_after(
        &state.db,
        managed.last_reported_event_id.unwrap_or(0),
        MAX_REPORT_EVENTS,
    )
    .await?;
    let runtime = state.runtime_settings();
    let reliability_state = load_reliability_state();
    let reliability_degraded = reliability_state
        .as_ref()
        .and_then(|state| state.get("status"))
        .and_then(Value::as_str)
        .is_some_and(|status| status != "healthy");
    let reported_status = if asset_scan.error.is_some() || reliability_degraded {
        "warning"
    } else {
        "online"
    };
    let reported_state = boot_report_state(
        profile_count,
        clients.len(),
        assets.len(),
        &asset_scan,
        reliability_state,
    );
    let body = BootAgentReportRequest {
        protocol_version: CYBEX_COMPONENT_PROTOCOL_VERSION,
        settings: BootAgentSettingsReport {
            public_base_url: runtime.public_base_url,
            listen_addr: state.config.server.listen_addr.clone(),
            tftp_root: state.config.paths.tftp_dir.display().to_string(),
            http_root: state.config.paths.boot_assets_dir.display().to_string(),
            bootloader_filename: runtime.bootloader_filename,
            menu_timeout_ms: runtime.menu_timeout_ms,
            version: env!("CARGO_PKG_VERSION").to_string(),
            status: reported_status.to_string(),
            state: reported_state,
        },
        profile_sync,
        clients: clients.into_iter().take(MAX_REPORT_CLIENTS).collect(),
        assets: assets
            .into_iter()
            .take(MAX_REPORT_ASSETS)
            .map(|asset| BootAgentAssetReport {
                absolute_path: state
                    .config
                    .paths
                    .iso_dir
                    .join(&asset.relative_path)
                    .display()
                    .to_string(),
                filename: asset.filename,
                relative_path: asset.relative_path,
                size_bytes: asset.size_bytes,
                checksum_sha256: asset.checksum_sha256,
                last_scanned_at: asset.last_scanned_at,
                created_at: asset.created_at,
            })
            .collect(),
        events: events
            .into_iter()
            .map(|event| BootAgentEventReport {
                source_event_id: event.id,
                mac: event.mac,
                serial_number: event.serial_number,
                ip_address: event.ip_address,
                user_agent: event.user_agent,
                selected_profile_id: optional_report_uuid(event.selected_profile_id),
                selected_profile_name: event.selected_profile_name,
                known_client: event.known_device != 0,
                created_at: event.created_at,
            })
            .collect(),
    };
    let (body, body_bytes) = fit_boot_report_body(body, MAX_BOOT_REPORT_BODY_BYTES)?;
    let max_event_id = body.events.iter().map(|event| event.source_event_id).max();
    let device_id = managed_device_id(managed)?;
    let path = format!("/v1/agent/devices/{device_id}/boot/report");
    let response = signed_request(state, managed, Method::POST, &path, body_bytes)
        .await?
        .header(CONTENT_TYPE, "application/json")
        .send()
        .await
        .context("report managed boot state request failed")?;
    parse_success_json::<Value>(response, "report managed boot state").await?;
    if let Some(max_event_id) = max_event_id {
        managed.last_reported_event_id = Some(max_event_id);
    }
    Ok(())
}

async fn sync_forge_foundation(
    state: &AppState,
    managed: &ManagedState,
) -> Result<ForgeReportReceipt> {
    let desired = fetch_forge_config(state, managed).await?;
    if desired.build_jobs.len() > MAX_MANAGED_BUILD_JOBS {
        bail!("managed forge config returned more than {MAX_MANAGED_BUILD_JOBS} build jobs");
    }

    let mut retained_job_ids = Vec::with_capacity(desired.build_jobs.len());
    for job in desired.build_jobs {
        retained_job_ids.push(job.id.clone());
        db::upsert_managed_build_job(
            &state.db,
            &job.id,
            &job.requested_artifact_type,
            job.build_spec,
            job.target.as_deref(),
            job.system.as_deref(),
            &job.input_revision,
            &job.input_config_hash,
            job.cache_metadata,
        )
        .await
        .with_context(|| format!("sync managed build job {}", job.id))?;
    }
    if desired.build_jobs_complete {
        db::cancel_absent_managed_build_jobs(&state.db, &retained_job_ids).await?;
    }
    db::cancel_managed_build_jobs(&state.db, &desired.deleted_build_job_ids).await?;
    let deletion_keys = desired
        .deleted_cache_artifacts
        .into_iter()
        .map(|artifact| (artifact.artifact_type, artifact.hash))
        .collect::<Vec<_>>();
    crate::cache::remove_artifacts_by_key(&state.db, &state.config, &deletion_keys).await?;
    let protected_keys = desired
        .protected_cache_artifacts
        .into_iter()
        .map(|artifact| (artifact.artifact_type, artifact.hash))
        .collect::<Vec<_>>();
    db::replace_managed_cache_protections(
        &state.db,
        &protected_keys,
        desired.protected_cache_artifacts_complete,
    )
    .await?;
    crate::cache::enforce_retention(&state.db, &state.config).await?;
    crate::updater::store_update_request(&state.config, desired.update).await?;

    report_forge_state(state, managed).await
}

async fn fetch_forge_config(
    state: &AppState,
    managed: &ManagedState,
) -> Result<AgentForgeConfigResponse> {
    let device_id = managed_device_id(managed)?;
    let path = format!("/v1/agent/devices/{device_id}/forge/config");
    let response = signed_request(state, managed, Method::GET, &path, Vec::new())
        .await?
        .send()
        .await
        .context("fetch managed forge config request failed")?;
    let config: AgentForgeConfigResponse =
        parse_success_json(response, "fetch managed forge config").await?;
    validate_component_compatibility(config.compatibility.as_ref())?;
    Ok(config)
}

async fn report_forge_state(
    state: &AppState,
    managed: &ManagedState,
) -> Result<ForgeReportReceipt> {
    let build_jobs = db::list_build_jobs(&state.db).await?;
    if let Err(err) = crate::cache::scrub_cache_artifacts(&state.db, &state.config, 8).await {
        warn!(error = %err, "Forge cache integrity scrub failed");
    }
    let cache_artifacts = db::list_cache_artifacts(&state.db).await?;
    let cache_inventory = db::cache_inventory_state(&state.db).await?;
    let cache_artifacts_complete = cache_artifacts.len() <= MAX_REPORT_CACHE_ARTIFACTS;
    let cache = crate::cache::status_report(&state.config, &state.db).await;
    let update = crate::updater::status_report(&state.config).await?;
    let body = ForgeAgentReportRequest {
        protocol_version: CYBEX_COMPONENT_PROTOCOL_VERSION,
        capabilities: forge_capabilities(&state.config),
        cache,
        update,
        build_jobs: build_jobs
            .into_iter()
            .take(MAX_REPORT_BUILD_JOBS)
            .map(ForgeBuildJobReport::from)
            .collect(),
        cache_artifacts: cache_artifacts
            .into_iter()
            .take(MAX_REPORT_CACHE_ARTIFACTS)
            .map(ForgeCacheArtifactReport::from)
            .collect(),
        cache_inventory_instance_id: cache_inventory.instance_id,
        cache_inventory_generation: cache_inventory.generation,
        cache_artifacts_complete,
        disk: crate::disk::stats(&state.config.cache.root_dir).ok(),
        host: crate::host::sample().await,
    };
    let (body, body_bytes) = fit_forge_report_body(body, MAX_FORGE_REPORT_BODY_BYTES)?;
    let updater = body.update.as_ref().map(SyncOnceUpdaterReport::from);
    let device_id = managed_device_id(managed)?;
    let path = format!("/v1/agent/devices/{device_id}/forge/report");
    let response = signed_request(state, managed, Method::POST, &path, body_bytes)
        .await?
        .header(CONTENT_TYPE, "application/json")
        .send()
        .await
        .context("report managed forge state request failed")?;
    let response =
        parse_success_json::<ForgeReportResponse>(response, "report managed forge state").await?;
    let receipt = ForgeReportReceipt {
        update_acknowledged: response.update,
        scope_acknowledged: false,
        persisted_update_acknowledged: false,
        updater,
    };
    Ok(receipt)
}

fn validate_expected_update_report(
    actual: Option<&ForgeUpdateStatusReport>,
    expected: Option<&ExpectedUpdateReport>,
) -> Result<()> {
    let Some(expected) = expected else {
        return Ok(());
    };
    let actual = actual.ok_or_else(|| {
        anyhow!("fenced Forge sync did not include a local updater status report")
    })?;
    if actual.status != expected.status {
        bail!(
            "fenced Forge sync updater status mismatch: expected {}, got {}",
            expected.status,
            actual.status
        );
    }
    if actual.attempt_id != expected.attempt_id {
        bail!(
            "fenced Forge sync updater attempt mismatch: expected {}, got {}",
            expected.attempt_id,
            actual.attempt_id
        );
    }
    Ok(())
}

fn validate_forge_report_receipt(
    receipt: &ForgeReportReceipt,
    require_update_only: bool,
) -> Result<()> {
    if require_update_only && !receipt.scope_acknowledged {
        bail!("Manage did not acknowledge the update-only Forge report scope");
    }
    if require_update_only && !receipt.update_acknowledged {
        bail!("Manage did not acknowledge the update-only Forge report");
    }
    if require_update_only && !receipt.persisted_update_acknowledged {
        bail!("Manage did not confirm the persisted Forge update status and attempt");
    }
    Ok(())
}

fn persisted_update_ack_matches(
    persisted: &ForgePersistedUpdateAcknowledgement,
    updater: &SyncOnceUpdaterReport,
) -> bool {
    persisted.status == updater.status
        && persisted.attempt_id == updater.attempt_id
        && chrono::DateTime::parse_from_rfc3339(&persisted.reported_at).is_ok()
}

fn validate_update_only_sync_report(report: &SyncOnceReport) -> Result<()> {
    if report.outcome != SyncOnceDisposition::Synced {
        bail!("update-only Forge sync requires an adopted node");
    }
    if !report.report_posted {
        bail!("update-only Forge sync did not post a Forge report");
    }
    if !report.update_included {
        bail!("update-only Forge sync did not include an updater report");
    }
    if !report.update_acknowledged {
        bail!("Manage did not acknowledge the update-only Forge report");
    }
    Ok(())
}

fn fit_forge_report_body(
    mut body: ForgeAgentReportRequest,
    max_bytes: usize,
) -> Result<(ForgeAgentReportRequest, Vec<u8>)> {
    let original_jobs = body.build_jobs.len();
    let original_artifacts = body.cache_artifacts.len();
    let mut body_bytes = serialize_forge_report_body(&body)?;
    if body_bytes.len() <= max_bytes {
        return Ok((body, body_bytes));
    }

    // Logs are diagnostic convenience; the managed job identity, state and
    // cache metadata are the durable evidence that Manage needs. Drop logs
    // first so the newest active and terminal job reports remain intact.
    for job in &mut body.build_jobs {
        job.logs.clear();
    }
    body_bytes = serialize_forge_report_body(&body)?;
    while body_bytes.len() > max_bytes {
        let Some(index) = body
            .build_jobs
            .iter()
            .rposition(|job| matches!(job.status.as_str(), "succeeded" | "failed" | "cancelled"))
        else {
            break;
        };
        // list_build_jobs returns newest first, so rposition removes the
        // oldest terminal evidence while preserving current work and the
        // latest completed Blueprint inventory.
        body.build_jobs.remove(index);
        body_bytes = serialize_forge_report_body(&body)?;
    }

    if body_bytes.len() > max_bytes && !body.cache_artifacts.is_empty() {
        let fitting = max_fitting_prefix_len(body.cache_artifacts.len(), |count| {
            let mut candidate = body.clone();
            candidate.cache_artifacts.truncate(count);
            candidate.cache_artifacts_complete = false;
            serialize_forge_report_body(&candidate).is_ok_and(|bytes| bytes.len() <= max_bytes)
        });
        body.cache_artifacts.truncate(fitting);
        body.cache_artifacts_complete = false;
        body_bytes = serialize_forge_report_body(&body)?;
    }

    if body_bytes.len() > max_bytes {
        bail!("managed forge report base body exceeded {max_bytes} bytes");
    }
    warn!(
        jobs_sent = body.build_jobs.len(),
        jobs_total = original_jobs,
        cache_artifacts_sent = body.cache_artifacts.len(),
        cache_artifacts_total = original_artifacts,
        max_bytes,
        "managed forge report trimmed to fit request budget"
    );
    Ok((body, body_bytes))
}

fn serialize_forge_report_body(body: &ForgeAgentReportRequest) -> Result<Vec<u8>> {
    serde_json::to_vec(body).context("serialize managed forge report")
}

fn fit_boot_report_body(
    mut body: BootAgentReportRequest,
    max_bytes: usize,
) -> Result<(BootAgentReportRequest, Vec<u8>)> {
    let original_clients = body.clients.len();
    let original_assets = body.assets.len();
    let original_events = body.events.len();

    let mut body_bytes = serialize_boot_report_body(&body)?;
    if body_bytes.len() <= max_bytes {
        return Ok((body, body_bytes));
    }

    let clients_len = max_fitting_prefix_len(body.clients.len(), |count| {
        let mut candidate = body.clone();
        candidate.clients.truncate(count);
        boot_report_body_fits(&candidate, max_bytes)
    });
    body.clients.truncate(clients_len);
    body_bytes = serialize_boot_report_body(&body)?;
    if body_bytes.len() > max_bytes {
        let assets_len = max_fitting_prefix_len(body.assets.len(), |count| {
            let mut candidate = body.clone();
            candidate.assets.truncate(count);
            boot_report_body_fits(&candidate, max_bytes)
        });
        body.assets.truncate(assets_len);
        body_bytes = serialize_boot_report_body(&body)?;
    }
    if body_bytes.len() > max_bytes {
        let events_len = max_fitting_prefix_len(body.events.len(), |count| {
            let mut candidate = body.clone();
            candidate.events.truncate(count);
            boot_report_body_fits(&candidate, max_bytes)
        });
        body.events.truncate(events_len);
        body_bytes = serialize_boot_report_body(&body)?;
    }
    if body_bytes.len() > max_bytes {
        bail!("managed boot report base body exceeded {max_bytes} bytes");
    }

    warn!(
        clients_sent = body.clients.len(),
        clients_total = original_clients,
        assets_sent = body.assets.len(),
        assets_total = original_assets,
        events_sent = body.events.len(),
        events_total = original_events,
        max_bytes,
        "managed boot report trimmed to fit request budget"
    );
    Ok((body, body_bytes))
}

fn boot_report_body_fits(body: &BootAgentReportRequest, max_bytes: usize) -> bool {
    serialize_boot_report_body(body)
        .map(|bytes| bytes.len() <= max_bytes)
        .unwrap_or(false)
}

fn serialize_boot_report_body(body: &BootAgentReportRequest) -> Result<Vec<u8>> {
    serde_json::to_vec(body).context("serialize managed boot report")
}

fn max_fitting_prefix_len(len: usize, mut fits: impl FnMut(usize) -> bool) -> usize {
    let mut low = 0usize;
    let mut high = len;
    while low < high {
        let mid = (low + high + 1) / 2;
        if fits(mid) {
            low = mid;
        } else {
            high = mid - 1;
        }
    }
    low
}

async fn apply_boot_config(state: &AppState, config: &AgentBootConfigResponse) -> Result<()> {
    let settings = normalize_managed_settings(&config.settings, &state.config)?;
    validate_boot_config(config)?;
    let mut tx = state.db.begin().await?;
    sync_deleted_profiles(&mut tx, &config.deleted_profile_ids).await?;
    sync_profiles(&mut tx, &config.profiles, config.profiles_complete).await?;
    let profile_map = managed_profile_map(&mut tx).await?;
    sync_deleted_clients(&mut tx, &config.deleted_client_ids).await?;
    sync_clients(
        &mut tx,
        &config.clients,
        &profile_map,
        config.clients_complete,
    )
    .await?;
    tx.commit().await?;
    state.update_runtime_settings(RuntimeSettings {
        public_base_url: settings.public_base_url,
        bootloader_filename: settings.bootloader_filename,
        menu_timeout_ms: settings.menu_timeout_ms,
    });
    Ok(())
}

async fn current_profile_sync_reports(
    pool: &SqlitePool,
) -> Result<Vec<BootAgentProfileSyncReport>> {
    let targets = list_desired_profile_iso_targets(pool).await?;
    let mut reports = Vec::with_capacity(targets.len());
    for target in targets {
        if optional_report_uuid(Some(target.profile_id.clone())).is_none() {
            warn!(
                profile_id = %target.profile_id,
                "skipping managed ISO sync report for non-UUID profile id"
            );
            continue;
        }
        reports.push(profile_sync_report_from_target(&target));
    }
    Ok(reports)
}

async fn run_managed_iso_sync_worker(state: AppState) {
    if let Err(err) = recover_interrupted_profile_syncs(&state.db).await {
        warn!(error = %safe_error(&err), "failed to recover interrupted managed ISO syncs");
    }
    let mut last_gc = None;
    loop {
        match process_next_managed_iso_sync(&state).await {
            Ok(true) => continue,
            Ok(false) => {
                if let Err(err) = verify_next_ready_managed_iso(&state).await {
                    warn!(error = %safe_error(&err), "managed ISO integrity verification failed");
                }
                if last_gc.is_none_or(|last: tokio::time::Instant| {
                    last.elapsed() >= Duration::from_secs(60 * 60)
                }) {
                    if let Err(err) = garbage_collect_managed_isos(&state).await {
                        warn!(error = %safe_error(&err), "managed ISO garbage collection failed");
                    }
                    last_gc = Some(tokio::time::Instant::now());
                }
                sleep(Duration::from_secs(1)).await
            }
            Err(err) => {
                warn!(error = %safe_error(&err), "managed ISO worker iteration failed");
                sleep(Duration::from_secs(5)).await;
            }
        }
    }
}

async fn recover_interrupted_profile_syncs(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        "UPDATE boot_profiles
         SET sync_state = 'queued', sync_next_attempt_at = ?,
             sync_error = 'Forge restarted while synchronizing; retrying'
         WHERE sync_state IN ('preparing', 'downloading', 'verifying')",
    )
    .bind(db::now_rfc3339())
    .execute(pool)
    .await
    .context("recover interrupted managed ISO profile syncs")?;
    Ok(())
}

async fn process_next_managed_iso_sync(state: &AppState) -> Result<bool> {
    let managed = load_managed_state(state)?;
    if managed.device_id.as_deref().is_none_or(str::is_empty)
        || managed.private_key_b64.as_deref().is_none_or(str::is_empty)
    {
        return Ok(false);
    }
    let Some(target) = claim_next_managed_iso_sync(&state.db).await? else {
        return Ok(false);
    };
    let started_at = Utc::now();
    match sync_desired_profile_iso(state, &managed, &target, started_at).await {
        Ok(report) => {
            persist_profile_sync_report(&state.db, target.local_id, &report, None, "", true)
                .await?;
            info!(
                profile_id = %target.profile_id,
                sync_generation = target.sync_generation,
                "managed ISO profile sync completed"
            );
        }
        Err(err) => {
            let retry_delay = managed_iso_retry_delay_seconds(target.sync_attempts);
            let safe = bounded_error_message(safe_error(&err));
            let retryable = managed_iso_error_is_retryable(&safe);
            let failure_kind = managed_iso_failure_kind(&safe);
            let report = profile_sync_failed_report(&target, started_at, err);
            persist_profile_sync_report(
                &state.db,
                target.local_id,
                &report,
                retryable.then_some(retry_delay),
                failure_kind,
                retryable,
            )
            .await?;
            warn!(
                profile_id = %target.profile_id,
                sync_generation = target.sync_generation,
                attempts = target.sync_attempts,
                terminal = !retryable,
                failure_kind,
                retry_in_seconds = retryable.then_some(retry_delay),
                error = %safe,
                "managed ISO profile sync failed"
            );
        }
    }
    Ok(true)
}

async fn claim_next_managed_iso_sync(pool: &SqlitePool) -> Result<Option<ManagedIsoSyncTarget>> {
    let now = db::now_rfc3339();
    for mut target in list_desired_profile_iso_targets(pool).await? {
        if target.sync_state != "queued"
            || target
                .sync_next_attempt_at
                .as_deref()
                .is_some_and(|next| next > now.as_str())
        {
            continue;
        }
        let result = sqlx::query(
            "UPDATE boot_profiles
             SET sync_state = 'downloading', sync_progress_percent = 0,
                 sync_bytes_downloaded = 0, sync_total_bytes = ?,
                 sync_attempts = sync_attempts + 1, sync_next_attempt_at = NULL,
                 sync_error = '', sync_failure_kind = '', sync_retryable = 1,
                 sync_started_at = COALESCE(sync_started_at, ?),
                 sync_completed_at = NULL, sync_failed_at = NULL
             WHERE id = ? AND sync_generation = ? AND sync_operation_id = ?
               AND sync_state = 'queued'",
        )
        .bind(target.desired_iso_size_bytes.max(0))
        .bind(&now)
        .bind(target.local_id)
        .bind(target.sync_generation)
        .bind(&target.sync_operation_id)
        .execute(pool)
        .await
        .context("claim managed ISO profile sync")?;
        if result.rows_affected() == 1 {
            target.sync_state = "downloading".to_string();
            target.sync_attempts = target.sync_attempts.saturating_add(1);
            target.sync_started_at = Some(now);
            return Ok(Some(target));
        }
    }
    Ok(None)
}

fn managed_iso_retry_delay_seconds(attempts: i64) -> i64 {
    let exponent = attempts.saturating_sub(1).clamp(0, 10) as u32;
    5_i64.saturating_mul(1_i64 << exponent).min(3600)
}

fn managed_iso_error_is_retryable(error: &str) -> bool {
    let error = error.to_ascii_lowercase();
    !error.contains("sync generation must not be negative")
        && !error.contains("sync operation id must be a uuid")
        && !error.contains("invalid managed iso profile type")
        && !error.contains("filename must be a simple .iso filename")
        && !error.contains("managed iso size must be positive")
        && !error.contains("checksum must be 64 hex characters")
        && !error.contains("download url must be a manage api path")
}

fn managed_iso_failure_kind(error: &str) -> &'static str {
    let error = error.to_ascii_lowercase();
    if !managed_iso_error_is_retryable(&error) {
        "invalid_desired_state"
    } else if error.contains("checksum") || error.contains("size mismatch") {
        "integrity_mismatch"
    } else if error.contains("no space") || error.contains("headroom") {
        "insufficient_disk_space"
    } else if error.contains("http 401") || error.contains("http 403") {
        "authorization_failed"
    } else if error.contains("http") || error.contains("request") {
        "network_or_server"
    } else {
        "local_io_or_processing"
    }
}

async fn list_desired_profile_iso_targets(pool: &SqlitePool) -> Result<Vec<ManagedIsoSyncTarget>> {
    sqlx::query_as::<_, ManagedIsoSyncTarget>(
        "SELECT id AS local_id,
                managed_profile_id AS profile_id,
                sync_generation,
                sync_operation_id,
                sync_state,
                sync_progress_percent,
                sync_bytes_downloaded,
                sync_total_bytes,
                sync_attempts,
                sync_next_attempt_at,
                sync_error,
                sync_started_at,
                sync_completed_at,
                sync_failed_at,
                sync_last_verified_at,
                profile_type,
                desired_iso_artifact_id,
                desired_iso_filename,
                desired_iso_size_bytes,
                desired_iso_sha256,
                desired_iso_download_url
         FROM boot_profiles
         WHERE managed_profile_id IS NOT NULL
           AND desired_iso_artifact_id <> ''
           AND desired_iso_filename <> ''
           AND desired_iso_size_bytes > 0
           AND desired_iso_sha256 <> ''
           AND desired_iso_download_url <> ''
           AND (
               installer_iso_source = 'enrollment'
               OR profile_type IN ('linux_installer', 'iso_live')
           )
         ORDER BY is_default DESC, enabled DESC, name COLLATE NOCASE ASC",
    )
    .fetch_all(pool)
    .await
    .context("list desired managed ISO profiles")
}

async fn verify_next_ready_managed_iso(state: &AppState) -> Result<bool> {
    let cutoff = Utc::now() - chrono::Duration::hours(6);
    let Some(target) = list_desired_profile_iso_targets(&state.db)
        .await?
        .into_iter()
        .find(|target| {
            target.sync_state == "ready"
                && target
                    .sync_last_verified_at
                    .as_deref()
                    .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
                    .is_none_or(|verified| verified.with_timezone(&Utc) <= cutoff)
        })
    else {
        return Ok(false);
    };
    let filename = managed_iso_filename(&target.desired_iso_filename)?;
    let expected_sha = target.desired_iso_sha256.to_ascii_lowercase();
    let path = state
        .config
        .paths
        .iso_dir
        .join(format!("{expected_sha}-{filename}"));
    let valid = cached_iso_matches(&path, target.desired_iso_size_bytes, &expected_sha)
        .await
        .unwrap_or(false);
    let now = db::now_rfc3339();
    if valid {
        sqlx::query(
            "UPDATE boot_profiles SET sync_last_verified_at = ?, updated_at = ?
             WHERE id = ? AND sync_generation = ? AND sync_operation_id = ? AND sync_state = 'ready'",
        )
        .bind(&now)
        .bind(&now)
        .bind(target.local_id)
        .bind(target.sync_generation)
        .bind(&target.sync_operation_id)
        .execute(&state.db)
        .await?;
    } else {
        tokio_fs::remove_file(&path).await.ok();
        sqlx::query(
            "UPDATE boot_profiles
             SET sync_state = 'queued', sync_progress_percent = 0,
                 sync_bytes_downloaded = 0, sync_attempts = 0,
                 sync_next_attempt_at = ?, sync_error = 'Cached ISO is missing or corrupt; repairing automatically',
                 sync_failure_kind = 'integrity_mismatch', sync_retryable = 1,
                 sync_completed_at = NULL, sync_failed_at = NULL,
                 sync_last_verified_at = ?, updated_at = ?
             WHERE id = ? AND sync_generation = ? AND sync_operation_id = ? AND sync_state = 'ready'",
        )
        .bind(&now)
        .bind(&now)
        .bind(&now)
        .bind(target.local_id)
        .bind(target.sync_generation)
        .bind(&target.sync_operation_id)
        .execute(&state.db)
        .await?;
        warn!(
            profile_id = %target.profile_id,
            sync_generation = target.sync_generation,
            "cached managed ISO is missing or corrupt; queued automatic repair"
        );
    }
    Ok(true)
}

async fn garbage_collect_managed_isos(state: &AppState) -> Result<u64> {
    let targets = list_desired_profile_iso_targets(&state.db).await?;
    let live = targets
        .iter()
        .filter_map(|target| {
            let filename = managed_iso_filename(&target.desired_iso_filename).ok()?;
            valid_sha256(&target.desired_iso_sha256).map(|sha| format!("{sha}-{filename}"))
        })
        .collect::<HashSet<_>>();
    let mut entries = match tokio_fs::read_dir(&state.config.paths.iso_dir).await {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(err) => return Err(err).context("read managed ISO cache directory"),
    };
    let mut removed = 0u64;
    while let Some(entry) = entries.next_entry().await? {
        let name = entry.file_name().to_string_lossy().to_string();
        let final_name = name
            .strip_prefix('.')
            .and_then(|name| name.strip_suffix(".part"));
        let candidate = final_name.unwrap_or(&name);
        let managed = candidate.split_once('-').is_some_and(|(sha, rest)| {
            sha.len() == 64
                && sha.bytes().all(|byte| byte.is_ascii_hexdigit())
                && rest.to_ascii_lowercase().ends_with(".iso")
        });
        if !managed || live.contains(candidate) {
            continue;
        }
        let metadata = entry.metadata().await?;
        let old_enough = metadata
            .modified()
            .ok()
            .and_then(|modified| modified.elapsed().ok())
            .is_some_and(|age| age >= Duration::from_secs(24 * 60 * 60));
        if old_enough && tokio_fs::remove_file(entry.path()).await.is_ok() {
            removed += 1;
        }
    }
    if removed > 0 {
        info!(removed, "garbage-collected unreferenced managed ISO files");
    }
    Ok(removed)
}

async fn sync_desired_profile_iso(
    state: &AppState,
    managed: &ManagedState,
    target: &ManagedIsoSyncTarget,
    started_at: chrono::DateTime<Utc>,
) -> Result<BootAgentProfileSyncReport> {
    validate_managed_iso_target(target, state)?;
    let filename = managed_iso_filename(&target.desired_iso_filename)?;
    let expected_sha = target.desired_iso_sha256.to_ascii_lowercase();
    let local_filename = format!("{expected_sha}-{filename}");
    let relative_path = managed_iso_relative_path(&local_filename);
    let path = state.config.paths.iso_dir.join(&local_filename);

    tokio_fs::create_dir_all(&state.config.paths.iso_dir)
        .await
        .with_context(|| {
            format!(
                "create ISO cache directory {}",
                state.config.paths.iso_dir.display()
            )
        })?;

    let expected_size = target.desired_iso_size_bytes;
    if cached_iso_matches(&path, expected_size, &expected_sha).await? {
        let boot_script = ensure_nixos_netboot_boot_script(state, &path, &expected_sha).await?;
        set_profile_iso_boot_script(&state.db, target, &relative_path, &boot_script).await?;
        return Ok(profile_sync_ready_report(
            target,
            filename,
            expected_size,
            expected_sha,
            started_at,
        ));
    }

    let download_path = managed_iso_download_path(&target.desired_iso_download_url, state)?;
    download_managed_iso(
        state,
        managed,
        &download_path,
        &path,
        expected_size,
        &expected_sha,
        target,
    )
    .await?;
    let boot_script = ensure_nixos_netboot_boot_script(state, &path, &expected_sha).await?;
    set_profile_iso_boot_script(&state.db, target, &relative_path, &boot_script).await?;

    Ok(profile_sync_ready_report(
        target,
        filename,
        expected_size,
        expected_sha,
        started_at,
    ))
}

async fn set_profile_iso_boot_script(
    pool: &SqlitePool,
    target: &ManagedIsoSyncTarget,
    iso_path: &str,
    raw_script: &str,
) -> Result<()> {
    let result = sqlx::query(
        "UPDATE boot_profiles SET iso_path = ?, raw_script = ?, updated_at = ?
         WHERE id = ? AND sync_generation = ? AND sync_operation_id = ?",
    )
    .bind(iso_path)
    .bind(raw_script)
    .bind(db::now_rfc3339())
    .bind(target.local_id)
    .bind(target.sync_generation)
    .bind(&target.sync_operation_id)
    .execute(pool)
    .await
    .context("update managed ISO profile boot script")?;
    if result.rows_affected() != 1 {
        bail!("managed ISO sync operation was superseded before boot script promotion");
    }
    Ok(())
}

const NIXOS_NETBOOT_INITRD_FORMAT: &str = "zstd-combined-newc-v13";
const NIXOS_NETBOOT_SPLIT_INITRD_FORMAT: &str = "zstd-split-squashfs-v14";
const NIXOS_NETBOOT_CAPS_ISO_PATH: &str = "/cybex-netboot-caps.json";
const NIXOS_NETBOOT_INJECTED_CONFIG_ISO_PATH: &str = "/cybex-installer/config.toml";
const NIXOS_NETBOOT_INJECTED_CONFIG_STORE_BASENAME: &str =
    "00000000000000000000000000000000-cybex-forge-netboot-config.toml";

#[derive(Clone, Debug, Deserialize, Serialize)]
struct NixosNetbootManifest {
    iso_sha256: String,
    kernel_iso_path: String,
    initrd_iso_path: String,
    initrd_fstab_path: String,
    cmdline: String,
    kernel_path: String,
    initrd_path: String,
    netboot_cpio_path: String,
    #[serde(default)]
    netboot_initrd_format: String,
    #[serde(default)]
    squashfs_path: String,
    #[serde(default)]
    squashfs_sha256: String,
}

#[derive(Debug, Deserialize)]
struct NixosNetbootCaps {
    #[serde(default)]
    formats: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NixosIsoBootConfig {
    kernel_iso_path: String,
    initrd_iso_path: String,
    cmdline: String,
}

async fn ensure_nixos_netboot_boot_script(
    state: &AppState,
    iso_path: &Path,
    iso_sha256: &str,
) -> Result<String> {
    let boot_assets_dir = state.config.paths.boot_assets_dir.clone();
    let iso_path = iso_path.to_path_buf();
    let iso_sha256 = iso_sha256.to_string();
    let manifest = tokio::task::spawn_blocking(move || {
        ensure_nixos_netboot_artifacts_blocking(&boot_assets_dir, &iso_path, &iso_sha256)
    })
    .await
    .context("join managed ISO netboot preparation")??;
    render_nixos_netboot_script(&manifest, &state.runtime_settings().public_base_url)
}

fn ensure_nixos_netboot_artifacts_blocking(
    boot_assets_dir: &Path,
    iso_path: &Path,
    iso_sha256: &str,
) -> Result<NixosNetbootManifest> {
    let iso_sha256 = valid_sha256(iso_sha256)
        .ok_or_else(|| anyhow!("managed ISO checksum must be 64 hex characters"))?;
    let installers_dir = boot_assets_dir.join("installers");
    let prebuilt_relative_dir = format!("installers/{iso_sha256}-nix-netboot");
    let prebuilt_dir = installers_dir.join(format!("{iso_sha256}-nix-netboot"));
    if let Some(manifest) =
        read_valid_prebuilt_netboot_manifest(&prebuilt_dir, &prebuilt_relative_dir, &iso_sha256)?
    {
        return Ok(manifest);
    }

    fs::create_dir_all(&installers_dir)
        .with_context(|| format!("create {}", installers_dir.display()))?;
    let split_squashfs_capable =
        probe_nixos_netboot_split_squashfs_capability(iso_path, &installers_dir, &iso_sha256)?;

    let artifact_relative_dir = format!("installers/{iso_sha256}");
    let artifact_dir = boot_assets_dir.join("installers").join(&iso_sha256);
    let manifest_path = artifact_dir.join("netboot-manifest.json");
    if let Some(manifest) = read_valid_netboot_manifest(
        &manifest_path,
        &artifact_dir,
        &iso_sha256,
        split_squashfs_capable,
    )? {
        return Ok(manifest);
    }

    let staging_dir = netboot_staging_dir(&installers_dir, &iso_sha256)?;
    if staging_dir.exists() {
        fs::remove_dir_all(&staging_dir)
            .with_context(|| format!("remove stale {}", staging_dir.display()))?;
    }
    fs::create_dir_all(&staging_dir)
        .with_context(|| format!("create {}", staging_dir.display()))?;

    let result = prepare_nixos_netboot_staging(
        iso_path,
        &staging_dir,
        &artifact_relative_dir,
        &iso_sha256,
        split_squashfs_capable,
    );
    if result.is_err() {
        let _ = fs::remove_dir_all(&staging_dir);
    }
    let manifest = result?;

    if artifact_dir.exists() {
        fs::remove_dir_all(&artifact_dir)
            .with_context(|| format!("remove stale {}", artifact_dir.display()))?;
    }
    fs::rename(&staging_dir, &artifact_dir).with_context(|| {
        format!(
            "publish managed ISO netboot artifacts {} -> {}",
            staging_dir.display(),
            artifact_dir.display()
        )
    })?;
    Ok(manifest)
}

fn read_valid_netboot_manifest(
    manifest_path: &Path,
    artifact_dir: &Path,
    iso_sha256: &str,
    split_squashfs_capable: bool,
) -> Result<Option<NixosNetbootManifest>> {
    let Ok(raw) = fs::read(manifest_path) else {
        return Ok(None);
    };
    let manifest = serde_json::from_slice::<NixosNetbootManifest>(&raw)
        .with_context(|| format!("parse {}", manifest_path.display()))?;
    if manifest.iso_sha256 != iso_sha256 {
        return Ok(None);
    }
    let expected_format = if split_squashfs_capable {
        NIXOS_NETBOOT_SPLIT_INITRD_FORMAT
    } else {
        NIXOS_NETBOOT_INITRD_FORMAT
    };
    if manifest.netboot_initrd_format != expected_format {
        return Ok(None);
    }
    if !manifest.netboot_cpio_path.trim().is_empty() {
        return Ok(None);
    }
    if split_squashfs_capable {
        if assets::sanitize_relative_path(&manifest.squashfs_path).is_err() {
            return Ok(None);
        }
        if manifest.squashfs_path != format!("installers/{iso_sha256}/nix-store.squashfs") {
            return Ok(None);
        }
        if valid_sha256(&manifest.squashfs_sha256).is_none() {
            return Ok(None);
        }
        let squashfs_path = artifact_dir.join("nix-store.squashfs");
        if !squashfs_path.is_file() {
            return Ok(None);
        }
        if fs::metadata(&squashfs_path)
            .with_context(|| format!("stat {}", squashfs_path.display()))?
            .len()
            == 0
        {
            return Ok(None);
        }
    } else if !manifest.squashfs_path.trim().is_empty()
        || !manifest.squashfs_sha256.trim().is_empty()
    {
        return Ok(None);
    }
    for filename in ["bzImage", "initrd"] {
        let path = artifact_dir.join(filename);
        if !path.is_file() {
            return Ok(None);
        }
        if fs::metadata(&path)
            .with_context(|| format!("stat {}", path.display()))?
            .len()
            == 0
        {
            return Ok(None);
        }
    }
    Ok(Some(manifest))
}

fn read_valid_prebuilt_netboot_manifest(
    artifact_dir: &Path,
    artifact_relative_dir: &str,
    iso_sha256: &str,
) -> Result<Option<NixosNetbootManifest>> {
    let kernel_path = artifact_dir.join("bzImage");
    let initrd_path = artifact_dir.join("initrd");
    let ipxe_path = artifact_dir.join("netboot.ipxe");
    for path in [&kernel_path, &initrd_path, &ipxe_path] {
        if !path.is_file() {
            return Ok(None);
        }
        if fs::metadata(path)
            .with_context(|| format!("stat {}", path.display()))?
            .len()
            == 0
        {
            return Ok(None);
        }
    }
    let cmdline = parse_nixos_netboot_ipxe_cmdline(&fs::read_to_string(&ipxe_path)?)
        .with_context(|| format!("parse {}", ipxe_path.display()))?;
    Ok(Some(NixosNetbootManifest {
        iso_sha256: iso_sha256.to_string(),
        kernel_iso_path: String::new(),
        initrd_iso_path: String::new(),
        initrd_fstab_path: String::new(),
        cmdline,
        kernel_path: format!("{artifact_relative_dir}/bzImage"),
        initrd_path: format!("{artifact_relative_dir}/initrd"),
        netboot_cpio_path: String::new(),
        netboot_initrd_format: "prebuilt-single-initrd".to_string(),
        squashfs_path: String::new(),
        squashfs_sha256: String::new(),
    }))
}

fn probe_nixos_netboot_split_squashfs_capability(
    iso_path: &Path,
    scratch_dir: &Path,
    iso_sha256: &str,
) -> Result<bool> {
    let caps_path = temp_path(
        scratch_dir,
        &format!("{iso_sha256}.cybex-netboot-caps.json"),
    )?;
    let result = (|| -> Result<bool> {
        if !try_extract_iso_file(iso_path, NIXOS_NETBOOT_CAPS_ISO_PATH, &caps_path)? {
            debug!("managed ISO has no netboot capability marker");
            return Ok(false);
        }
        let raw = fs::read(&caps_path).with_context(|| format!("read {}", caps_path.display()))?;
        match parse_nixos_netboot_split_squashfs_capability(&raw) {
            Ok(capable) => Ok(capable),
            Err(error) => {
                debug!(%error, "managed ISO netboot capability marker was malformed");
                Ok(false)
            }
        }
    })();
    let _ = fs::remove_file(&caps_path);
    result
}

fn parse_nixos_netboot_split_squashfs_capability(raw: &[u8]) -> Result<bool> {
    let caps = serde_json::from_slice::<NixosNetbootCaps>(raw)
        .context("parse managed ISO netboot capability marker")?;
    Ok(caps
        .formats
        .iter()
        .any(|format| format == NIXOS_NETBOOT_SPLIT_INITRD_FORMAT))
}

fn prepare_nixos_netboot_staging(
    iso_path: &Path,
    staging_dir: &Path,
    artifact_relative_dir: &str,
    iso_sha256: &str,
    split_squashfs_capable: bool,
) -> Result<NixosNetbootManifest> {
    let isolinux_cfg = staging_dir.join("isolinux.cfg");
    extract_iso_file(iso_path, "/isolinux/isolinux.cfg", &isolinux_cfg)?;
    let boot_config = parse_isolinux_boot_config(&fs::read_to_string(&isolinux_cfg)?)
        .context("parse NixOS ISO boot config")?;

    let kernel_path = staging_dir.join("bzImage");
    let initrd_path = staging_dir.join("initrd");
    let squashfs_path = staging_dir.join("nix-store.squashfs");
    let injected_config_path = staging_dir.join("cybex-installer-config.toml");
    extract_iso_file(iso_path, &boot_config.kernel_iso_path, &kernel_path)?;
    extract_iso_file(iso_path, &boot_config.initrd_iso_path, &initrd_path)?;
    extract_iso_file(iso_path, "/nix-store.squashfs", &squashfs_path)?;
    let injected_config = if try_extract_iso_file(
        iso_path,
        NIXOS_NETBOOT_INJECTED_CONFIG_ISO_PATH,
        &injected_config_path,
    )? {
        Some(injected_config_path.as_path())
    } else {
        None
    };

    let initrd_fstab_path = find_initrd_fstab_path(&initrd_path)?;
    patch_nixos_netboot_squashfs(&squashfs_path, injected_config)?;
    let squashfs_for_initrd = if split_squashfs_capable {
        None
    } else {
        Some(squashfs_path.as_path())
    };
    rebuild_zstd_initrd_with_netboot_files(&initrd_path, squashfs_for_initrd, &initrd_fstab_path)?;
    let squashfs_sha256 = if split_squashfs_capable {
        ensure_nonempty_file(&squashfs_path)?;
        set_public_artifact_permissions(&squashfs_path)?;
        sha256_file_blocking(&squashfs_path)?
    } else {
        fs::remove_file(&squashfs_path)
            .with_context(|| format!("remove temporary {}", squashfs_path.display()))?;
        String::new()
    };
    let _ = fs::remove_file(&injected_config_path);

    ensure_nonempty_file(&kernel_path)?;
    ensure_nonempty_file(&initrd_path)?;
    set_public_artifact_permissions(&kernel_path)?;
    set_public_artifact_permissions(&initrd_path)?;

    let manifest = NixosNetbootManifest {
        iso_sha256: iso_sha256.to_string(),
        kernel_iso_path: boot_config.kernel_iso_path,
        initrd_iso_path: boot_config.initrd_iso_path,
        initrd_fstab_path,
        cmdline: boot_config.cmdline,
        kernel_path: format!("{artifact_relative_dir}/bzImage"),
        initrd_path: format!("{artifact_relative_dir}/initrd"),
        netboot_cpio_path: String::new(),
        netboot_initrd_format: if split_squashfs_capable {
            NIXOS_NETBOOT_SPLIT_INITRD_FORMAT
        } else {
            NIXOS_NETBOOT_INITRD_FORMAT
        }
        .to_string(),
        squashfs_path: if split_squashfs_capable {
            format!("{artifact_relative_dir}/nix-store.squashfs")
        } else {
            String::new()
        },
        squashfs_sha256,
    };
    fs::write(
        staging_dir.join("netboot-manifest.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )
    .with_context(|| {
        format!(
            "write {}",
            staging_dir.join("netboot-manifest.json").display()
        )
    })?;
    Ok(manifest)
}

fn parse_isolinux_boot_config(config: &str) -> Result<NixosIsoBootConfig> {
    let mut in_boot = false;
    let mut kernel = None;
    let mut initrd = None;
    let mut cmdline = None;

    for line in config.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let upper = line.to_ascii_uppercase();
        if let Some(label) = upper.strip_prefix("LABEL ") {
            in_boot = label.split_whitespace().next() == Some("BOOT");
            continue;
        }
        if !in_boot {
            continue;
        }
        if upper.starts_with("MENU ") {
            continue;
        }
        if let Some(value) = line.strip_prefix("LINUX ") {
            kernel = Some(normalize_iso_member_path(value)?);
        } else if let Some(value) = line.strip_prefix("INITRD ") {
            initrd = Some(normalize_iso_member_path(value)?);
        } else if let Some(value) = line.strip_prefix("APPEND ") {
            cmdline = Some(normalize_kernel_cmdline(value)?);
        }
    }

    Ok(NixosIsoBootConfig {
        kernel_iso_path: kernel.ok_or_else(|| anyhow!("NixOS ISO boot entry omitted LINUX"))?,
        initrd_iso_path: initrd.ok_or_else(|| anyhow!("NixOS ISO boot entry omitted INITRD"))?,
        cmdline: cmdline.ok_or_else(|| anyhow!("NixOS ISO boot entry omitted APPEND"))?,
    })
}

fn parse_nixos_netboot_ipxe_cmdline(script: &str) -> Result<String> {
    for line in script.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("kernel ") else {
            continue;
        };
        let rest = rest.trim();
        let cmdline = rest
            .strip_prefix("bzImage")
            .ok_or_else(|| anyhow!("NixOS netboot iPXE kernel line must load bzImage"))?
            .trim();
        let cmdline = cmdline.replace("${cmdline}", "");
        let cmdline = normalize_kernel_cmdline(&cmdline)?;
        let cmdline = cmdline
            .split_whitespace()
            .filter(|token| !token.starts_with("initrd="))
            .collect::<Vec<_>>()
            .join(" ");
        return Ok(cmdline);
    }
    bail!("NixOS netboot iPXE script omitted kernel line");
}

fn normalize_iso_member_path(value: &str) -> Result<String> {
    let path = value.trim();
    if path.is_empty()
        || path.contains('\\')
        || path.contains("..")
        || path.chars().any(char::is_control)
    {
        bail!("NixOS ISO boot path is invalid");
    }
    Ok(format!("/{}", path.trim_start_matches('/')))
}

fn normalize_kernel_cmdline(value: &str) -> Result<String> {
    if value.chars().any(char::is_control) {
        bail!("NixOS ISO kernel command line contains control characters");
    }
    Ok(value.split_whitespace().collect::<Vec<_>>().join(" "))
}

fn render_nixos_netboot_script(
    manifest: &NixosNetbootManifest,
    public_base_url: &str,
) -> Result<String> {
    let kernel_url = assets::asset_url(public_base_url, &manifest.kernel_path)?;
    let initrd_url = assets::asset_url(public_base_url, &manifest.initrd_path)?;
    let mut cmdline = manifest.cmdline.clone();
    if manifest.netboot_initrd_format == NIXOS_NETBOOT_SPLIT_INITRD_FORMAT {
        let squashfs_url = assets::asset_url(public_base_url, &manifest.squashfs_path)?;
        if valid_sha256(&manifest.squashfs_sha256).is_none() {
            bail!("managed ISO netboot squashfs checksum must be 64 hex characters");
        }
        cmdline = format!(
            "{cmdline} cybex.squashfs_url={squashfs_url} cybex.squashfs_sha256={}",
            manifest.squashfs_sha256
        );
    }
    validate_cmdline(Some(&cmdline))?;
    if manifest.netboot_cpio_path.trim().is_empty() {
        return Ok(format!(
            "#!ipxe\n\
             echo Cybex Forge: Default Enrollment\n\
             kernel {kernel_url} initrd=initrd {cmdline}\n\
             initrd --name initrd {initrd_url}\n\
             boot\n",
            cmdline = cmdline
        ));
    }
    let cpio_url = assets::asset_url(public_base_url, &manifest.netboot_cpio_path)?;
    Ok(format!(
        "#!ipxe\n\
         echo Cybex Forge: Default Enrollment\n\
         kernel {kernel_url} initrd=initrd initrd=nixos-netboot.cpio {cmdline}\n\
         initrd --name initrd {initrd_url}\n\
         initrd --name nixos-netboot.cpio {cpio_url}\n\
         boot\n",
        cmdline = cmdline
    ))
}

fn extract_iso_file(iso_path: &Path, source_path: &str, destination: &Path) -> Result<()> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let output = StdCommand::new("xorriso")
        .arg("-osirrox")
        .arg("on")
        .arg("-indev")
        .arg(iso_path)
        .arg("-extract")
        .arg(source_path)
        .arg(destination)
        .output()
        .with_context(|| "run xorriso to extract managed ISO boot artifact")?;
    ensure_command_success(output, "xorriso extract managed ISO boot artifact")
}

fn try_extract_iso_file(iso_path: &Path, source_path: &str, destination: &Path) -> Result<bool> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let output = StdCommand::new("xorriso")
        .arg("-osirrox")
        .arg("on")
        .arg("-indev")
        .arg(iso_path)
        .arg("-extract")
        .arg(source_path)
        .arg(destination)
        .output()
        .with_context(|| "run xorriso to extract optional managed ISO artifact")?;
    if output.status.success() {
        return Ok(true);
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("Cannot determine attributes")
        && stderr.contains(source_path)
        && stderr.contains("No such file or directory")
    {
        let _ = fs::remove_file(destination);
        return Ok(false);
    }
    ensure_command_success(output, "xorriso extract optional managed ISO artifact")?;
    Ok(true)
}

fn patch_nixos_netboot_squashfs(
    squashfs_path: &Path,
    injected_config_path: Option<&Path>,
) -> Result<()> {
    let parent = squashfs_path
        .parent()
        .ok_or_else(|| anyhow!("{} has no parent directory", squashfs_path.display()))?;
    let extract_dir = temp_path(parent, "nix-store.squashfs-root")?;
    let patched_path = temp_path(parent, "nix-store.squashfs")?;
    let _ = fs::remove_dir_all(&extract_dir);
    let _ = fs::remove_file(&patched_path);

    let result = (|| -> Result<()> {
        let output = StdCommand::new("unsquashfs")
            .arg("-f")
            .arg("-d")
            .arg(&extract_dir)
            .arg(squashfs_path)
            .output()
            .with_context(|| "run unsquashfs to extract managed ISO Nix store")?;
        ensure_command_success(output, "unsquashfs extract managed ISO Nix store")?;
        patch_nixos_netboot_squashfs_fstab(&extract_dir)?;
        if let Some(injected_config_path) = injected_config_path {
            patch_nixos_netboot_squashfs_injected_config(&extract_dir, injected_config_path)?;
        }
        patch_nixos_netboot_squashfs_graphical_kiosk(&extract_dir)?;

        let output = StdCommand::new("mksquashfs")
            .arg(&extract_dir)
            .arg(&patched_path)
            .arg("-noappend")
            .arg("-all-root")
            .arg("-no-recovery")
            .arg("-no-progress")
            .arg("-processors")
            .arg("1")
            .arg("-b")
            .arg("1048576")
            .arg("-comp")
            .arg("zstd")
            .arg("-Xcompression-level")
            .arg("6")
            .output()
            .with_context(|| "run mksquashfs to rebuild managed ISO Nix store")?;
        ensure_command_success(output, "mksquashfs rebuild managed ISO Nix store")?;
        ensure_nonempty_file(&patched_path)?;
        fs::rename(&patched_path, squashfs_path)
            .with_context(|| format!("publish patched {}", squashfs_path.display()))?;
        Ok(())
    })();

    if extract_dir.exists() {
        let _ = run_command_os(
            "chmod",
            [
                OsString::from("-R"),
                OsString::from("u+w"),
                extract_dir.as_os_str().to_os_string(),
            ],
        );
        let _ = fs::remove_dir_all(&extract_dir);
    }
    let _ = fs::remove_file(&patched_path);
    result
}

fn patch_nixos_netboot_squashfs_injected_config(
    squashfs_root: &Path,
    injected_config_path: &Path,
) -> Result<()> {
    ensure_nonempty_file(injected_config_path)?;
    let store_relative = NIXOS_NETBOOT_INJECTED_CONFIG_STORE_BASENAME;
    let store_absolute = format!("/nix/store/{store_relative}");
    let target = squashfs_root.join(store_relative);
    fs::copy(injected_config_path, &target).with_context(|| {
        format!(
            "copy injected installer config {} -> {}",
            injected_config_path.display(),
            target.display()
        )
    })?;
    set_file_mode(&target, 0o444)?;

    let patched_units = patch_nixos_netboot_installer_config_units(squashfs_root, &store_absolute)?;
    if patched_units == 0 {
        bail!("managed ISO Nix store omitted cybex-installer-config.service");
    }
    Ok(())
}

fn patch_nixos_netboot_squashfs_graphical_kiosk(squashfs_root: &Path) -> Result<()> {
    let patched_units = patch_nixos_netboot_installer_kiosk_units(squashfs_root)?;
    if patched_units == 0 {
        bail!("managed ISO Nix store omitted cybex-installer-kiosk.service");
    }
    Ok(())
}

fn patch_nixos_netboot_installer_kiosk_units(squashfs_root: &Path) -> Result<usize> {
    let mut patched = 0usize;
    for entry in
        fs::read_dir(squashfs_root).with_context(|| format!("read {}", squashfs_root.display()))?
    {
        let entry = entry.with_context(|| format!("read {}", squashfs_root.display()))?;
        let unit_dir = entry.path();
        if !unit_dir.is_dir() {
            continue;
        }
        for relative in [
            Path::new("cybex-installer-kiosk.service"),
            Path::new("multi-user.target.wants/cybex-installer-kiosk.service"),
        ] {
            let unit_path = unit_dir.join(relative);
            if !unit_path.is_file() {
                continue;
            }
            let text = fs::read_to_string(&unit_path)
                .with_context(|| format!("read {}", unit_path.display()))?;
            if !text.contains("cybex-installer-kiosk") || !text.contains("[Service]") {
                continue;
            }
            let updated = rewrite_nixos_netboot_kiosk_unit(&text)?;
            set_file_mode(&unit_path, 0o644)?;
            fs::write(&unit_path, updated)
                .with_context(|| format!("write {}", unit_path.display()))?;
            set_file_mode(&unit_path, 0o444)?;
            patched += 1;
        }
    }
    Ok(patched)
}

fn rewrite_nixos_netboot_kiosk_unit(unit: &str) -> Result<String> {
    let updated = upsert_systemd_service_line(unit, "PAMName=", "PAMName=login", true)?;
    let updated = upsert_systemd_service_line(
        &updated,
        "RuntimeDirectoryMode=",
        "RuntimeDirectoryMode=0700",
        true,
    )?;
    let updated =
        upsert_systemd_service_line(&updated, "TTYVTDisallocate=", "TTYVTDisallocate=true", true)?;
    let updated =
        upsert_systemd_service_line(&updated, "UtmpIdentifier=", "UtmpIdentifier=tty1", true)?;
    upsert_systemd_service_line(&updated, "UtmpMode=", "UtmpMode=user", true)
}

fn upsert_systemd_service_line(
    unit: &str,
    prefix: &str,
    replacement: &str,
    insert_if_missing: bool,
) -> Result<String> {
    let mut output = Vec::new();
    let mut in_service = false;
    let mut saw_service = false;
    let mut wrote_line = false;

    for current in unit.lines() {
        if current.starts_with('[') {
            if in_service && insert_if_missing && !wrote_line {
                output.push(replacement.to_string());
                wrote_line = true;
            }
            in_service = current == "[Service]";
            saw_service |= in_service;
            output.push(current.to_string());
            continue;
        }
        if in_service && current.starts_with(prefix) {
            if !wrote_line {
                output.push(replacement.to_string());
                wrote_line = true;
            }
            continue;
        }
        output.push(current.to_string());
    }

    if in_service && insert_if_missing && !wrote_line {
        output.push(replacement.to_string());
        wrote_line = true;
    }
    if !saw_service {
        bail!("systemd unit omitted [Service] section");
    }
    if !wrote_line {
        bail!("systemd unit omitted {prefix} line");
    }

    let mut updated = output.join("\n");
    updated.push('\n');
    Ok(updated)
}

fn patch_nixos_netboot_installer_config_units(
    squashfs_root: &Path,
    injected_config_store_path: &str,
) -> Result<usize> {
    let mut patched = 0usize;
    for entry in
        fs::read_dir(squashfs_root).with_context(|| format!("read {}", squashfs_root.display()))?
    {
        let entry = entry.with_context(|| format!("read {}", squashfs_root.display()))?;
        let unit_dir = entry.path();
        if !unit_dir.is_dir() {
            continue;
        }
        let unit_path = unit_dir.join("cybex-installer-config.service");
        if !unit_path.is_file() {
            continue;
        }
        let text = fs::read_to_string(&unit_path)
            .with_context(|| format!("read {}", unit_path.display()))?;
        if !text.contains("cybex-installer-config") || !text.contains("[Service]") {
            continue;
        }
        let updated = inject_systemd_environment_line(
            &text,
            &format!("CYBEX_INJECTED_CONFIG={injected_config_store_path}"),
        )?;
        set_file_mode(&unit_path, 0o644)?;
        fs::write(&unit_path, updated).with_context(|| format!("write {}", unit_path.display()))?;
        set_file_mode(&unit_path, 0o444)?;
        patched += 1;
    }
    Ok(patched)
}

fn inject_systemd_environment_line(unit: &str, environment: &str) -> Result<String> {
    let line = format!("Environment=\"{environment}\"");
    let mut output = Vec::new();
    let mut inserted = false;
    let mut replaced = false;
    for current in unit.lines() {
        if current.starts_with("Environment=\"CYBEX_INJECTED_CONFIG=") {
            if !replaced {
                output.push(line.clone());
                replaced = true;
                inserted = true;
            }
            continue;
        }
        output.push(current.to_string());
        if current == "[Service]" && !inserted {
            output.push(line.clone());
            inserted = true;
        }
    }
    if !inserted {
        bail!("systemd unit omitted [Service] section");
    }
    let mut updated = output.join("\n");
    updated.push('\n');
    Ok(updated)
}

fn patch_nixos_netboot_squashfs_fstab(squashfs_root: &Path) -> Result<()> {
    let mut patched = 0usize;
    for entry in
        fs::read_dir(squashfs_root).with_context(|| format!("read {}", squashfs_root.display()))?
    {
        let entry = entry.with_context(|| format!("read {}", squashfs_root.display()))?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !name.ends_with("-etc-fstab") {
            continue;
        }
        let text = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        if !text.contains("/dev/disk/by-label/") && !text.contains("/sysroot/iso/") {
            continue;
        }
        set_file_mode(&path, 0o644)?;
        fs::write(&path, nixos_netboot_fstab())
            .with_context(|| format!("write {}", path.display()))?;
        set_file_mode(&path, 0o444)?;
        patched += 1;
    }
    if patched == 0 {
        bail!("managed ISO Nix store omitted generated etc-fstab with ISO mounts");
    }
    Ok(())
}

fn find_initrd_fstab_path(initrd_path: &Path) -> Result<String> {
    let mut child = StdCommand::new("zstd")
        .arg("-dc")
        .arg(initrd_path)
        .stdout(Stdio::piped())
        .spawn()
        .with_context(|| "run zstd to inspect managed ISO initrd")?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("zstd stdout was not captured"))?;
    let mut reader = BufReader::new(stdout);
    let path = find_newc_entry_by_suffix(&mut reader, "-initrd-fstab")?;
    let status = child.wait().with_context(|| "wait for zstd")?;
    if !status.success() {
        bail!("zstd failed while inspecting managed ISO initrd");
    }
    path.ok_or_else(|| anyhow!("managed ISO initrd omitted initrd fstab"))
}

fn find_newc_entry_by_suffix<R: Read>(reader: &mut R, suffix: &str) -> Result<Option<String>> {
    let mut found = None;
    loop {
        let Some(header) = read_newc_header(reader)? else {
            return Ok(found);
        };
        if header.name == "TRAILER!!!" {
            return Ok(found);
        }
        if found.is_none() && header.name.ends_with(suffix) {
            found = Some(header.name.clone());
        }
        skip_exact(reader, header.file_size)?;
        skip_padding(reader, header.file_size)?;
    }
}

#[derive(Debug)]
struct NewcHeader {
    name: String,
    file_size: u64,
}

fn read_newc_header<R: Read>(reader: &mut R) -> Result<Option<NewcHeader>> {
    let mut header = [0u8; 110];
    let mut read = 0usize;
    while read < header.len() {
        let count = reader
            .read(&mut header[read..])
            .context("read initrd cpio header")?;
        if count == 0 {
            if read == 0 {
                return Ok(None);
            }
            bail!("truncated initrd cpio header");
        }
        read += count;
    }
    if &header[..6] != b"070701" && &header[..6] != b"070702" {
        bail!("unsupported initrd cpio format");
    }
    let file_size = parse_newc_hex(&header[54..62])?;
    let name_size = parse_newc_hex(&header[94..102])?;
    if name_size == 0 || name_size > 4096 {
        bail!("invalid initrd cpio name size");
    }
    let mut name = vec![0u8; name_size as usize];
    reader
        .read_exact(&mut name)
        .context("read initrd cpio name")?;
    skip_padding(reader, 110 + name_size)?;
    if name.last() == Some(&0) {
        name.pop();
    }
    let name = String::from_utf8(name).context("initrd cpio name is not utf-8")?;
    Ok(Some(NewcHeader { name, file_size }))
}

fn parse_newc_hex(input: &[u8]) -> Result<u64> {
    let text = std::str::from_utf8(input).context("newc header field was not utf-8")?;
    u64::from_str_radix(text, 16).context("newc header field was not hex")
}

fn rebuild_zstd_initrd_with_netboot_files(
    initrd_path: &Path,
    squashfs_path: Option<&Path>,
    initrd_fstab_path: &str,
) -> Result<()> {
    let decoded_path = initrd_path.with_extension("decoded.cpio.tmp");
    let rebuilt_path = initrd_path.with_extension("rebuilt.cpio.tmp");
    let compressed_path = initrd_path.with_extension("zst.tmp");
    for path in [&decoded_path, &rebuilt_path, &compressed_path] {
        let _ = fs::remove_file(path);
    }

    let result = (|| -> Result<()> {
        decompress_zstd_to_file(initrd_path, &decoded_path)?;
        rewrite_newc_archive_with_netboot_files(
            &decoded_path,
            &rebuilt_path,
            squashfs_path,
            initrd_fstab_path,
        )?;
        compress_file_to_zstd(&rebuilt_path, &compressed_path)?;
        fs::rename(&compressed_path, initrd_path)
            .with_context(|| format!("publish recompressed {}", initrd_path.display()))?;
        set_public_artifact_permissions(initrd_path)?;
        Ok(())
    })();

    for path in [&decoded_path, &rebuilt_path, &compressed_path] {
        let _ = fs::remove_file(path);
    }
    result
}

fn decompress_zstd_to_file(source: &Path, destination: &Path) -> Result<()> {
    let output_file = fs::File::create(destination)
        .with_context(|| format!("create {}", destination.display()))?;
    let output = StdCommand::new("zstd")
        .arg("-dc")
        .arg(source)
        .stdout(Stdio::from(output_file))
        .output()
        .with_context(|| "run zstd to decompress managed ISO initrd")?;
    ensure_command_success(output, "zstd decompress managed ISO initrd")?;
    ensure_nonempty_file(destination)?;
    Ok(())
}

fn rewrite_newc_archive_with_netboot_files(
    source: &Path,
    destination: &Path,
    squashfs_path: Option<&Path>,
    initrd_fstab_path: &str,
) -> Result<()> {
    let input = fs::File::open(source).with_context(|| format!("open {}", source.display()))?;
    let mut reader = BufReader::new(input);
    let mut output = fs::File::create(destination)
        .with_context(|| format!("create {}", destination.display()))?;
    let mut replaced_fstab = false;
    let mut next_ino = 1_000_000u32;

    loop {
        let Some(entry) = read_newc_entry_start(&mut reader)? else {
            bail!("managed ISO initrd cpio omitted TRAILER!!!");
        };
        if entry.name == "TRAILER!!!" {
            break;
        }
        if entry.name == initrd_fstab_path {
            replaced_fstab = true;
            skip_exact(&mut reader, entry.file_size)?;
            skip_padding(&mut reader, entry.file_size)?;
            continue;
        }
        output.write_all(&entry.header)?;
        output.write_all(&entry.name_bytes)?;
        output.write_all(&entry.name_padding)?;
        copy_exact(&mut reader, &mut output, entry.file_size)?;
        copy_exact(&mut reader, &mut output, newc_padding_len(entry.file_size))?;
    }
    if !replaced_fstab {
        bail!("managed ISO initrd omitted expected fstab entry {initrd_fstab_path}");
    }

    write_newc_file_from_bytes(
        &mut output,
        initrd_fstab_path,
        nixos_netboot_fstab().as_bytes(),
        0o100644,
        next_ino,
    )?;
    next_ino += 1;
    if let Some(squashfs_path) = squashfs_path {
        write_newc_file_from_path(
            &mut output,
            "nix-store.squashfs",
            squashfs_path,
            0o100644,
            next_ino,
        )?;
    }
    write_newc_trailer(&mut output)?;
    output
        .sync_all()
        .with_context(|| format!("sync {}", destination.display()))?;
    ensure_nonempty_file(destination)?;
    Ok(())
}

struct NewcEntryStart {
    header: [u8; 110],
    name: String,
    name_bytes: Vec<u8>,
    name_padding: Vec<u8>,
    file_size: u64,
}

fn read_newc_entry_start<R: Read>(reader: &mut R) -> Result<Option<NewcEntryStart>> {
    let mut header = [0u8; 110];
    let mut read = 0usize;
    while read < header.len() {
        let count = reader
            .read(&mut header[read..])
            .context("read initrd cpio header")?;
        if count == 0 {
            if read == 0 {
                return Ok(None);
            }
            bail!("truncated initrd cpio header");
        }
        read += count;
    }
    if &header[..6] != b"070701" && &header[..6] != b"070702" {
        bail!("unsupported initrd cpio format");
    }
    let file_size = parse_newc_hex(&header[54..62])?;
    let name_size = parse_newc_hex(&header[94..102])?;
    if name_size == 0 || name_size > 4096 {
        bail!("invalid initrd cpio name size");
    }
    let mut name_bytes = vec![0u8; name_size as usize];
    reader
        .read_exact(&mut name_bytes)
        .context("read initrd cpio name")?;
    let mut name = name_bytes.clone();
    if name.last() == Some(&0) {
        name.pop();
    }
    let name = String::from_utf8(name).context("initrd cpio name is not utf-8")?;
    let name_padding_len = newc_padding_len(110 + name_size);
    let mut name_padding = vec![0u8; name_padding_len as usize];
    reader
        .read_exact(&mut name_padding)
        .context("read initrd cpio name padding")?;
    Ok(Some(NewcEntryStart {
        header,
        name,
        name_bytes,
        name_padding,
        file_size,
    }))
}

fn compress_file_to_zstd(source: &Path, destination: &Path) -> Result<()> {
    let output = StdCommand::new("zstd")
        .arg("-q")
        .arg("-f")
        .arg("-T0")
        .arg(source)
        .arg("-o")
        .arg(destination)
        .output()
        .with_context(|| "run zstd to recompress managed ISO initrd")?;
    ensure_command_success(output, "zstd recompress managed ISO initrd")?;
    ensure_nonempty_file(destination)?;
    Ok(())
}

fn set_public_artifact_permissions(path: &Path) -> Result<()> {
    set_file_mode(path, 0o644)
}

fn set_file_mode(path: &Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        let permissions = fs::Permissions::from_mode(mode);
        fs::set_permissions(path, permissions)
            .with_context(|| format!("set permissions on {}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        let mut permissions = fs::metadata(path)
            .with_context(|| format!("stat {}", path.display()))?
            .permissions();
        permissions.set_readonly(false);
        fs::set_permissions(path, permissions)
            .with_context(|| format!("set permissions on {}", path.display()))?;
    }
    Ok(())
}

fn nixos_netboot_fstab() -> String {
    [
        "tmpfs / tmpfs x-initrd.mount,mode=0755 0 0",
        "/nix-store.squashfs /nix/.ro-store squashfs x-initrd.mount,loop,threads=multi 0 0",
        "tmpfs /nix/.rw-store tmpfs x-initrd.mount,mode=0755 0 0",
        "overlay /nix/store overlay lowerdir=/sysroot/nix/.ro-store,upperdir=/sysroot/nix/.rw-store/store,workdir=/sysroot/nix/.rw-store/work,x-initrd.mount,x-systemd.requires-mounts-for=/sysroot/nix/.ro-store,x-systemd.requires-mounts-for=/sysroot/nix/.rw-store/store,x-systemd.requires-mounts-for=/sysroot/nix/.rw-store/work 0 0",
        "",
    ]
    .join("\n")
}

fn write_newc_file_from_path(
    out: &mut fs::File,
    name: &str,
    source: &Path,
    mode: u32,
    ino: u32,
) -> Result<()> {
    let mut file = fs::File::open(source).with_context(|| format!("open {}", source.display()))?;
    let size = file
        .metadata()
        .with_context(|| format!("stat {}", source.display()))?
        .len();
    write_newc_header(out, name, mode, size, ino)?;
    std::io::copy(&mut file, out).with_context(|| format!("copy {}", source.display()))?;
    write_zero_padding(out, size)?;
    Ok(())
}

fn write_newc_file_from_bytes(
    out: &mut fs::File,
    name: &str,
    bytes: &[u8],
    mode: u32,
    ino: u32,
) -> Result<()> {
    write_newc_header(out, name, mode, bytes.len() as u64, ino)?;
    out.write_all(bytes)?;
    write_zero_padding(out, bytes.len() as u64)?;
    Ok(())
}

fn write_newc_trailer(out: &mut fs::File) -> Result<()> {
    write_newc_header(out, "TRAILER!!!", 0, 0, 3)
}

fn write_newc_header(
    out: &mut fs::File,
    name: &str,
    mode: u32,
    file_size: u64,
    ino: u32,
) -> Result<()> {
    if name.is_empty() || name.starts_with('/') || name.as_bytes().contains(&0) {
        bail!("invalid cpio entry name");
    }
    if file_size > u32::MAX as u64 {
        bail!("cpio entry is too large");
    }
    let name_size = name.len() as u64 + 1;
    write!(
        out,
        "070701{ino:08x}{mode:08x}{uid:08x}{gid:08x}{nlink:08x}{mtime:08x}{file_size:08x}{dev_major:08x}{dev_minor:08x}{rdev_major:08x}{rdev_minor:08x}{name_size:08x}{check:08x}",
        uid = 0,
        gid = 0,
        nlink = 1,
        mtime = 0,
        dev_major = 0,
        dev_minor = 0,
        rdev_major = 0,
        rdev_minor = 0,
        check = 0,
    )?;
    out.write_all(name.as_bytes())?;
    out.write_all(&[0])?;
    write_zero_padding(out, 110 + name_size)?;
    Ok(())
}

fn write_zero_padding(out: &mut fs::File, len: u64) -> Result<()> {
    let padding = newc_padding_len(len);
    if padding > 0 {
        out.write_all(&vec![0u8; padding as usize])?;
    }
    Ok(())
}

fn skip_padding<R: Read>(reader: &mut R, len: u64) -> Result<()> {
    skip_exact(reader, newc_padding_len(len))
}

fn skip_exact<R: Read>(reader: &mut R, len: u64) -> Result<()> {
    let mut remaining = len;
    let mut buffer = [0u8; 8192];
    while remaining > 0 {
        let chunk = remaining.min(buffer.len() as u64) as usize;
        reader
            .read_exact(&mut buffer[..chunk])
            .context("skip initrd cpio data")?;
        remaining -= chunk as u64;
    }
    Ok(())
}

fn copy_exact<R: Read, W: Write>(reader: &mut R, writer: &mut W, len: u64) -> Result<()> {
    let mut remaining = len;
    let mut buffer = [0u8; 8192];
    while remaining > 0 {
        let chunk = remaining.min(buffer.len() as u64) as usize;
        reader
            .read_exact(&mut buffer[..chunk])
            .context("read initrd cpio data")?;
        writer
            .write_all(&buffer[..chunk])
            .context("write initrd cpio data")?;
        remaining -= chunk as u64;
    }
    Ok(())
}

fn newc_padding_len(len: u64) -> u64 {
    (4 - (len % 4)) % 4
}

fn ensure_nonempty_file(path: &Path) -> Result<()> {
    let metadata = fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    if !metadata.is_file() || metadata.len() == 0 {
        bail!("{} is not a non-empty file", path.display());
    }
    Ok(())
}

fn sha256_file_blocking(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 128];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("read {}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn ensure_command_success(output: std::process::Output, context: &str) -> Result<()> {
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    bail!(
        "{context} failed: {}",
        bounded_error_message(format!("{stderr} {stdout}"))
    )
}

fn netboot_staging_dir(parent: &Path, iso_sha256: &str) -> Result<PathBuf> {
    let mut random = [0u8; 8];
    OsRng.fill_bytes(&mut random);
    Ok(parent.join(format!(
        ".{iso_sha256}.{}.{}.tmp",
        std::process::id(),
        hex::encode(random)
    )))
}

async fn cached_iso_matches(path: &Path, expected_size: i64, expected_sha: &str) -> Result<bool> {
    let Ok(metadata) = tokio_fs::metadata(path).await else {
        return Ok(false);
    };
    if !metadata.is_file() || metadata.len() != expected_size as u64 {
        return Ok(false);
    }
    Ok(sha256_file(path).await? == expected_sha)
}

async fn download_managed_iso(
    state: &AppState,
    managed: &ManagedState,
    download_path: &str,
    path: &Path,
    expected_size: i64,
    expected_sha: &str,
    target: &ManagedIsoSyncTarget,
) -> Result<()> {
    crate::disk::ensure_headroom(path, expected_size.max(0) as u64, "managed ISO download")?;
    let partial_path = managed_iso_partial_path(path)?;
    let mut resume_from = match tokio_fs::metadata(&partial_path).await {
        Ok(metadata) if metadata.is_file() && metadata.len() <= expected_size as u64 => {
            metadata.len()
        }
        Ok(_) => {
            tokio_fs::remove_file(&partial_path).await.ok();
            0
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => 0,
        Err(err) => return Err(err).context("inspect partial managed ISO download"),
    };
    if resume_from == expected_size as u64 {
        if sha256_file(&partial_path).await? == expected_sha {
            promote_managed_iso_download(state, target, &partial_path, path).await?;
            return Ok(());
        }
        tokio_fs::remove_file(&partial_path).await.ok();
        resume_from = 0;
    }

    let mut request = signed_download_request(state, managed, download_path).await?;
    if resume_from > 0 {
        request = request
            .header(RANGE, format!("bytes={resume_from}-"))
            .header(IF_RANGE, format!("\"{expected_sha}\""));
    }
    let mut response = request
        .send()
        .await
        .context("download managed ISO request failed")?;
    let status = response.status();
    if !status.is_success() {
        bail!("download managed ISO failed with HTTP {status}");
    }
    if resume_from > 0 {
        if status == reqwest::StatusCode::PARTIAL_CONTENT {
            let content_range = response
                .headers()
                .get(CONTENT_RANGE)
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default();
            if !content_range.starts_with(&format!("bytes {resume_from}-")) {
                bail!("managed ISO resume response had an invalid Content-Range");
            }
            tracing::info!(
                profile_id = %target.profile_id,
                sync_generation = target.sync_generation,
                resume_from_bytes = resume_from,
                "resuming managed ISO download"
            );
        } else if status == reqwest::StatusCode::OK {
            tokio_fs::remove_file(&partial_path).await.ok();
            resume_from = 0;
        } else {
            bail!("managed ISO resume failed with HTTP {status}");
        }
    }
    if response
        .content_length()
        .is_some_and(|len| len.saturating_add(resume_from) > expected_size as u64)
    {
        bail!("download managed ISO response exceeded expected size");
    }

    download_managed_iso_to_partial(
        &state.db,
        target,
        &mut response,
        &partial_path,
        resume_from,
        expected_size,
        expected_sha,
    )
    .await?;
    promote_managed_iso_download(state, target, &partial_path, path).await
}

async fn promote_managed_iso_download(
    state: &AppState,
    target: &ManagedIsoSyncTarget,
    partial_path: &Path,
    path: &Path,
) -> Result<()> {
    if !profile_sync_operation_is_current(&state.db, target).await? {
        tokio_fs::remove_file(partial_path).await.ok();
        bail!("managed ISO sync operation was superseded before artifact promotion");
    }
    tokio_fs::rename(partial_path, path)
        .await
        .with_context(|| format!("replace managed ISO {}", path.display()))?;
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("managed ISO path has no parent"))?
        .to_path_buf();
    tokio::task::spawn_blocking(move || {
        fs::File::open(&parent)
            .and_then(|directory| directory.sync_all())
            .with_context(|| format!("sync managed ISO directory {}", parent.display()))
    })
    .await
    .context("join managed ISO directory sync")??;
    Ok(())
}

async fn profile_sync_operation_is_current(
    pool: &SqlitePool,
    target: &ManagedIsoSyncTarget,
) -> Result<bool> {
    let matches: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM boot_profiles
         WHERE id = ? AND sync_generation = ? AND sync_operation_id = ?",
    )
    .bind(target.local_id)
    .bind(target.sync_generation)
    .bind(&target.sync_operation_id)
    .fetch_one(pool)
    .await
    .context("verify managed ISO sync operation")?;
    Ok(matches == 1)
}

async fn download_managed_iso_to_partial(
    pool: &SqlitePool,
    target: &ManagedIsoSyncTarget,
    response: &mut reqwest::Response,
    partial_path: &Path,
    resume_from: u64,
    expected_size: i64,
    expected_sha: &str,
) -> Result<()> {
    let mut file = tokio_fs::OpenOptions::new()
        .write(true)
        .create(true)
        .append(resume_from > 0)
        .truncate(resume_from == 0)
        .open(partial_path)
        .await
        .with_context(|| format!("open partial ISO {}", partial_path.display()))?;
    let mut hasher = Sha256::new();
    if resume_from > 0 {
        let mut existing = tokio_fs::File::open(partial_path)
            .await
            .context("open existing partial managed ISO")?;
        let mut buffer = vec![0u8; 1024 * 128];
        loop {
            let read = existing
                .read(&mut buffer)
                .await
                .context("hash existing partial managed ISO")?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
    }
    let mut downloaded = resume_from as i64;
    let mut next_progress_update = downloaded.saturating_add(16 * 1024 * 1024);

    while let Some(chunk) = response
        .chunk()
        .await
        .context("read managed ISO download response")?
    {
        downloaded = downloaded
            .checked_add(chunk.len() as i64)
            .ok_or_else(|| anyhow!("managed ISO download size overflow"))?;
        if downloaded > expected_size {
            bail!("managed ISO download exceeded expected size");
        }
        hasher.update(&chunk);
        file.write_all(&chunk)
            .await
            .context("write managed ISO download")?;
        if downloaded >= next_progress_update {
            update_profile_sync_progress(pool, target, "downloading", downloaded).await?;
            next_progress_update = downloaded.saturating_add(16 * 1024 * 1024);
        }
    }
    file.sync_all().await.context("sync managed ISO download")?;
    drop(file);

    if downloaded != expected_size {
        bail!("managed ISO download size mismatch");
    }
    update_profile_sync_progress(pool, target, "verifying", downloaded).await?;
    let actual_sha = hex::encode(hasher.finalize());
    if actual_sha != expected_sha {
        tokio_fs::remove_file(partial_path).await.ok();
        bail!("managed ISO checksum mismatch");
    }
    Ok(())
}

async fn update_profile_sync_progress(
    pool: &SqlitePool,
    target: &ManagedIsoSyncTarget,
    state: &str,
    downloaded: i64,
) -> Result<()> {
    let progress = if target.desired_iso_size_bytes > 0 {
        downloaded
            .saturating_mul(100)
            .checked_div(target.desired_iso_size_bytes)
            .unwrap_or(0)
            .clamp(0, 99) as i32
    } else {
        0
    };
    let result = sqlx::query(
        "UPDATE boot_profiles
         SET sync_state = ?, sync_progress_percent = ?, sync_bytes_downloaded = ?,
             sync_total_bytes = ?, updated_at = ?
         WHERE id = ? AND sync_generation = ? AND sync_operation_id = ?",
    )
    .bind(state)
    .bind(progress)
    .bind(downloaded.max(0))
    .bind(target.desired_iso_size_bytes.max(0))
    .bind(db::now_rfc3339())
    .bind(target.local_id)
    .bind(target.sync_generation)
    .bind(&target.sync_operation_id)
    .execute(pool)
    .await
    .context("update managed ISO sync progress")?;
    if result.rows_affected() != 1 {
        bail!("managed ISO sync operation was superseded during download");
    }
    Ok(())
}

async fn sha256_file(path: &Path) -> Result<String> {
    let mut file = tokio_fs::File::open(path)
        .await
        .with_context(|| format!("open ISO {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 128];
    loop {
        let read = file
            .read(&mut buffer)
            .await
            .with_context(|| format!("read ISO {}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn profile_sync_ready_report(
    target: &ManagedIsoSyncTarget,
    filename: String,
    size_bytes: i64,
    sha256: String,
    started_at: chrono::DateTime<Utc>,
) -> BootAgentProfileSyncReport {
    BootAgentProfileSyncReport {
        profile_id: target.profile_id.clone(),
        sync_generation: target.sync_generation,
        sync_operation_id: target.sync_operation_id.clone(),
        state: "ready".to_string(),
        progress_percent: Some(100),
        bytes_downloaded: Some(size_bytes),
        total_bytes: Some(size_bytes),
        artifact_id: Some(target.desired_iso_artifact_id.clone()),
        filename: Some(filename),
        size_bytes: Some(size_bytes),
        sha256: Some(sha256),
        error: None,
        started_at: Some(started_at),
        completed_at: Some(Utc::now()),
        failed_at: None,
    }
}

fn profile_sync_report_from_target(target: &ManagedIsoSyncTarget) -> BootAgentProfileSyncReport {
    BootAgentProfileSyncReport {
        profile_id: target.profile_id.clone(),
        sync_generation: target.sync_generation,
        sync_operation_id: target.sync_operation_id.clone(),
        state: target.sync_state.clone(),
        progress_percent: Some(target.sync_progress_percent.clamp(0, 100)),
        bytes_downloaded: Some(target.sync_bytes_downloaded.max(0)),
        total_bytes: Some(
            target
                .sync_total_bytes
                .max(target.desired_iso_size_bytes)
                .max(0),
        ),
        artifact_id: Some(target.desired_iso_artifact_id.clone()),
        filename: Some(target.desired_iso_filename.clone()),
        size_bytes: Some(target.desired_iso_size_bytes.max(0)),
        sha256: valid_sha256(&target.desired_iso_sha256),
        error: (!target.sync_error.is_empty()).then(|| target.sync_error.clone()),
        started_at: parse_sync_timestamp(target.sync_started_at.as_deref()),
        completed_at: parse_sync_timestamp(target.sync_completed_at.as_deref()),
        failed_at: parse_sync_timestamp(target.sync_failed_at.as_deref()),
    }
}

fn parse_sync_timestamp(value: Option<&str>) -> Option<chrono::DateTime<Utc>> {
    value
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&Utc))
}

async fn persist_profile_sync_report(
    pool: &SqlitePool,
    local_id: i64,
    report: &BootAgentProfileSyncReport,
    retry_after_seconds: Option<i64>,
    failure_kind: &str,
    retryable: bool,
) -> Result<bool> {
    let now = Utc::now();
    let state = if retry_after_seconds.is_some() {
        "queued"
    } else {
        report.state.as_str()
    };
    let next_attempt_at = retry_after_seconds
        .map(|seconds| (now + chrono::Duration::seconds(seconds.max(1))).to_rfc3339());
    let completed_at = report.completed_at.map(|value| value.to_rfc3339());
    let failed_at = if state == "failed" {
        Some(report.failed_at.unwrap_or(now).to_rfc3339())
    } else {
        None
    };
    let result = sqlx::query(
        "UPDATE boot_profiles
         SET sync_state = ?, sync_progress_percent = ?, sync_bytes_downloaded = ?,
             sync_total_bytes = ?, sync_next_attempt_at = ?, sync_error = ?,
             sync_completed_at = ?, sync_failed_at = ?,
             sync_failure_kind = ?, sync_retryable = ?,
             sync_last_verified_at = CASE WHEN ? = 'ready' THEN ? ELSE sync_last_verified_at END,
             updated_at = ?
         WHERE id = ? AND sync_generation = ? AND sync_operation_id = ?",
    )
    .bind(state)
    .bind(report.progress_percent.unwrap_or(0).clamp(0, 100))
    .bind(report.bytes_downloaded.unwrap_or(0).max(0))
    .bind(report.total_bytes.unwrap_or(0).max(0))
    .bind(next_attempt_at)
    .bind(report.error.clone().unwrap_or_default())
    .bind(completed_at)
    .bind(failed_at)
    .bind(failure_kind)
    .bind(i64::from(retryable))
    .bind(state)
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .bind(local_id)
    .bind(report.sync_generation)
    .bind(&report.sync_operation_id)
    .execute(pool)
    .await
    .context("persist managed ISO profile sync result")?;
    Ok(result.rows_affected() == 1)
}

fn profile_sync_failed_report(
    target: &ManagedIsoSyncTarget,
    started_at: chrono::DateTime<Utc>,
    err: anyhow::Error,
) -> BootAgentProfileSyncReport {
    BootAgentProfileSyncReport {
        profile_id: target.profile_id.clone(),
        sync_generation: target.sync_generation,
        sync_operation_id: target.sync_operation_id.clone(),
        state: "failed".to_string(),
        progress_percent: Some(0),
        bytes_downloaded: Some(0),
        total_bytes: Some(target.desired_iso_size_bytes.max(0)),
        artifact_id: Some(target.desired_iso_artifact_id.clone()),
        filename: Some(clean_string(&target.desired_iso_filename)),
        size_bytes: Some(target.desired_iso_size_bytes.max(0)),
        sha256: valid_sha256(&target.desired_iso_sha256),
        error: Some(bounded_error_message(safe_error(&err))),
        started_at: Some(started_at),
        completed_at: None,
        failed_at: Some(Utc::now()),
    }
}

fn validate_managed_iso_target(target: &ManagedIsoSyncTarget, state: &AppState) -> Result<()> {
    if target.sync_generation < 0 {
        bail!("managed ISO sync generation must not be negative");
    }
    Uuid::parse_str(target.sync_operation_id.trim())
        .context("managed ISO sync operation id must be a UUID")?;
    BootProfileType::from_str(&target.profile_type)
        .map_err(|err| anyhow!("invalid managed ISO profile type: {err}"))?;
    managed_iso_filename(&target.desired_iso_filename)?;
    if target.desired_iso_size_bytes <= 0 {
        bail!("managed ISO size must be positive");
    }
    if valid_sha256(&target.desired_iso_sha256).is_none() {
        bail!("managed ISO checksum must be 64 hex characters");
    }
    managed_iso_download_path(&target.desired_iso_download_url, state)?;
    Ok(())
}

fn managed_iso_filename(value: &str) -> Result<String> {
    let filename = clean_string(value);
    if filename.is_empty()
        || filename == "."
        || filename == ".."
        || filename.starts_with('.')
        || filename.contains('/')
        || filename.contains('\\')
        || filename.chars().any(char::is_control)
        || !filename.to_ascii_lowercase().ends_with(".iso")
        || filename.chars().count() > 255
    {
        bail!("managed ISO filename must be a simple .iso filename");
    }
    Ok(filename)
}

fn managed_iso_relative_path(filename: &str) -> String {
    format!("isos/{filename}")
}

fn managed_iso_partial_path(path: &Path) -> Result<PathBuf> {
    let filename = path
        .file_name()
        .ok_or_else(|| anyhow!("managed ISO path has no filename"))?
        .to_string_lossy();
    Ok(path.with_file_name(format!(".{filename}.part")))
}

fn managed_iso_download_path(value: &str, state: &AppState) -> Result<String> {
    managed_iso_download_path_with_base(value, Some(state.config.manage.api_url.trim()))
}

fn managed_iso_download_path_with_base(value: &str, api_base: Option<&str>) -> Result<String> {
    let trimmed = value.trim();
    let path = if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        let base = api_base.unwrap_or_default().trim().trim_end_matches('/');
        trimmed
            .strip_prefix(base)
            .filter(|path| path.starts_with('/'))
            .map(ToString::to_string)
            .ok_or_else(|| anyhow!("managed ISO download URL must be a Manage API path"))?
    };
    if !path.starts_with("/v1/agent/devices/")
        || !path.contains("/boot/profiles/")
        || !path.ends_with("/iso/download")
        || path.chars().any(char::is_control)
        || path.contains('"')
        || path.contains('\\')
    {
        bail!("managed ISO download URL must be an agent profile ISO download path");
    }
    Ok(path)
}

type ExistingManagedProfileRow = (i64, Option<String>, Option<String>, i64, String, String);

async fn sync_profiles(
    tx: &mut Transaction<'_, Sqlite>,
    profiles: &[ManagedBootProfile],
    profiles_complete: bool,
) -> Result<()> {
    clear_synced_default_profiles(tx).await?;

    let desired: HashSet<String> = profiles.iter().map(|profile| profile.id.clone()).collect();
    for profile in profiles {
        let profile_type = BootProfileType::from_str(&profile.profile_type)
            .map_err(|err| anyhow!("invalid managed profile type: {err}"))?;
        let now = db::now_rfc3339();
        let existing: Option<ExistingManagedProfileRow> = sqlx::query_as(
            "SELECT id, iso_path, raw_script, sync_generation, sync_operation_id,
                    desired_iso_artifact_id
             FROM boot_profiles WHERE managed_profile_id = ?",
        )
        .bind(&profile.id)
        .fetch_optional(&mut **tx)
        .await?;
        if let Some((
            id,
            existing_iso_path,
            existing_raw_script,
            existing_generation,
            existing_operation_id,
            existing_artifact_id,
        )) = existing
        {
            let sync_intent_changed = existing_generation != profile.sync_generation
                || existing_operation_id != profile.sync_operation_id
                || existing_artifact_id != profile.desired_iso_artifact_id;
            let raw_script = managed_profile_raw_script(profile, existing_raw_script.as_deref());
            let iso_path = managed_profile_iso_path(
                profile,
                existing_iso_path.as_deref(),
                raw_script.as_deref(),
            )?;
            sqlx::query(
                "UPDATE boot_profiles
                 SET name = ?, description = ?, profile_type = ?, installer_iso_source = ?,
                     enabled = ?, is_default = ?, one_time = ?, kernel_path = ?, initrd_path = ?,
                     iso_path = ?, cmdline = ?, raw_script = ?, desired_iso_artifact_id = ?,
                     desired_iso_filename = ?, desired_iso_size_bytes = ?, desired_iso_sha256 = ?,
                     desired_iso_built_at = ?, desired_iso_url = ?, desired_iso_download_url = ?,
                     sync_generation = ?, sync_operation_id = ?,
                     updated_at = ?
                 WHERE id = ?",
            )
            .bind(profile.name.trim())
            .bind(&profile.description)
            .bind(profile_type.as_str())
            .bind(normalized_installer_iso_source(
                &profile.installer_iso_source,
            ))
            .bind(bool_to_i64(profile.enabled))
            .bind(bool_to_i64(profile.is_default))
            .bind(bool_to_i64(profile.one_time))
            .bind(clean_optional(profile.kernel_path.clone()))
            .bind(clean_optional(profile.initrd_path.clone()))
            .bind(iso_path.clone())
            .bind(clean_optional(profile.cmdline.clone()))
            .bind(raw_script)
            .bind(clean_string(&profile.desired_iso_artifact_id))
            .bind(clean_string(&profile.desired_iso_filename))
            .bind(profile.desired_iso_size_bytes.max(0))
            .bind(clean_string(&profile.desired_iso_sha256).to_ascii_lowercase())
            .bind(clean_optional(profile.desired_iso_built_at.clone()))
            .bind(clean_string(&profile.desired_iso_url))
            .bind(clean_string(&profile.desired_iso_download_url))
            .bind(profile.sync_generation.max(0))
            .bind(clean_string(&profile.sync_operation_id))
            .bind(&now)
            .bind(id)
            .execute(&mut **tx)
            .await?;
            if sync_intent_changed {
                reset_profile_sync_state(tx, id, profile).await?;
            }
        } else {
            let raw_script = managed_profile_raw_script(profile, None);
            let iso_path = managed_profile_iso_path(profile, None, raw_script.as_deref())?;
            sqlx::query(
                "INSERT INTO boot_profiles
                 (managed_profile_id, name, description, profile_type, installer_iso_source,
                  enabled, is_default, one_time, kernel_path, initrd_path, iso_path, cmdline,
                  raw_script, desired_iso_artifact_id, desired_iso_filename,
                  desired_iso_size_bytes, desired_iso_sha256, desired_iso_built_at,
                  desired_iso_url, desired_iso_download_url, sync_generation,
                  sync_operation_id, sync_state, sync_total_bytes, created_at, updated_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(&profile.id)
            .bind(profile.name.trim())
            .bind(&profile.description)
            .bind(profile_type.as_str())
            .bind(normalized_installer_iso_source(
                &profile.installer_iso_source,
            ))
            .bind(bool_to_i64(profile.enabled))
            .bind(bool_to_i64(profile.is_default))
            .bind(bool_to_i64(profile.one_time))
            .bind(clean_optional(profile.kernel_path.clone()))
            .bind(clean_optional(profile.initrd_path.clone()))
            .bind(iso_path)
            .bind(clean_optional(profile.cmdline.clone()))
            .bind(raw_script)
            .bind(clean_string(&profile.desired_iso_artifact_id))
            .bind(clean_string(&profile.desired_iso_filename))
            .bind(profile.desired_iso_size_bytes.max(0))
            .bind(clean_string(&profile.desired_iso_sha256).to_ascii_lowercase())
            .bind(clean_optional(profile.desired_iso_built_at.clone()))
            .bind(clean_string(&profile.desired_iso_url))
            .bind(clean_string(&profile.desired_iso_download_url))
            .bind(profile.sync_generation.max(0))
            .bind(clean_string(&profile.sync_operation_id))
            .bind(if managed_profile_needs_iso_sync(profile) {
                "queued"
            } else {
                "idle"
            })
            .bind(profile.desired_iso_size_bytes.max(0))
            .bind(&now)
            .bind(&now)
            .execute(&mut **tx)
            .await?;
        }
    }
    if profiles_complete {
        let existing: Vec<(i64, String)> = sqlx::query_as(
            "SELECT id, managed_profile_id FROM boot_profiles WHERE managed_profile_id IS NOT NULL",
        )
        .fetch_all(&mut **tx)
        .await?;
        for (id, remote_id) in existing {
            if !desired.contains(&remote_id) {
                sqlx::query("DELETE FROM boot_profiles WHERE id = ?")
                    .bind(id)
                    .execute(&mut **tx)
                    .await?;
            }
        }
    }
    prune_seeded_local_disk_profile(tx, profiles).await?;
    Ok(())
}

async fn reset_profile_sync_state(
    tx: &mut Transaction<'_, Sqlite>,
    profile_id: i64,
    profile: &ManagedBootProfile,
) -> Result<()> {
    let state = if managed_profile_needs_iso_sync(profile) {
        "queued"
    } else {
        "idle"
    };
    sqlx::query(
        "UPDATE boot_profiles
         SET sync_state = ?, sync_progress_percent = 0, sync_bytes_downloaded = 0,
             sync_total_bytes = ?, sync_attempts = 0, sync_next_attempt_at = NULL,
             sync_error = '', sync_started_at = NULL, sync_completed_at = NULL,
             sync_failed_at = NULL, sync_failure_kind = '', sync_retryable = 1,
             sync_last_verified_at = NULL
         WHERE id = ?",
    )
    .bind(state)
    .bind(profile.desired_iso_size_bytes.max(0))
    .bind(profile_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn sync_deleted_profiles(
    tx: &mut Transaction<'_, Sqlite>,
    deleted_profile_ids: &[String],
) -> Result<()> {
    let mut seen = HashSet::new();
    for remote_id in deleted_profile_ids {
        if !seen.insert(remote_id) {
            continue;
        }
        sqlx::query("DELETE FROM boot_profiles WHERE managed_profile_id = ?")
            .bind(remote_id)
            .execute(&mut **tx)
            .await?;
    }
    Ok(())
}

async fn clear_synced_default_profiles(tx: &mut Transaction<'_, Sqlite>) -> Result<()> {
    sqlx::query("UPDATE boot_profiles SET is_default = 0")
        .execute(&mut **tx)
        .await?;
    Ok(())
}

async fn prune_seeded_local_disk_profile(
    tx: &mut Transaction<'_, Sqlite>,
    profiles: &[ManagedBootProfile],
) -> Result<()> {
    if !profiles
        .iter()
        .any(|profile| profile.profile_type == BootProfileType::LocalDisk.as_str())
    {
        return Ok(());
    }

    sqlx::query(
        "DELETE FROM boot_profiles
         WHERE managed_profile_id IS NULL
           AND profile_type = 'local_disk'
           AND name = 'Local disk'
           AND description = 'Return control to UEFI firmware so the next local boot target can start.'
           AND is_default = 0
           AND NOT EXISTS (
               SELECT 1 FROM devices
               WHERE devices.default_profile_id = boot_profiles.id
                  OR devices.one_time_profile_id = boot_profiles.id
                  OR devices.last_selected_profile_id = boot_profiles.id
           )",
    )
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn sync_clients(
    tx: &mut Transaction<'_, Sqlite>,
    clients: &[ManagedBootClient],
    profile_map: &HashMap<String, i64>,
    clients_complete: bool,
) -> Result<()> {
    let desired: HashSet<String> = clients.iter().map(|client| client.id.clone()).collect();
    for client in clients {
        let mac = normalize_mac(&client.mac)?;
        let default_profile_id =
            local_profile_id(client.default_profile_id.as_deref(), profile_map)?;
        let one_time_profile_id =
            local_profile_id(client.one_time_profile_id.as_deref(), profile_map)?;
        let tags = serde_json::to_string(&clean_tags(client.tags.clone()))?;
        let now = db::now_rfc3339();
        let existing: Option<i64> = sqlx::query_scalar(
            "SELECT id FROM devices
             WHERE managed_client_id = ? OR lower(mac) = lower(?)
             ORDER BY CASE WHEN managed_client_id = ? THEN 0 ELSE 1 END
             LIMIT 1",
        )
        .bind(&client.id)
        .bind(&mac)
        .bind(&client.id)
        .fetch_optional(&mut **tx)
        .await?;
        if let Some(id) = existing {
            sqlx::query(
                "UPDATE devices
                 SET managed_client_id = ?, mac = ?, hostname = ?, serial_number = ?,
                     last_seen_at = COALESCE(?, last_seen_at), notes = ?, tags = ?,
                     default_profile_id = ?, one_time_profile_id = ?, updated_at = ?
                 WHERE id = ?",
            )
            .bind(&client.id)
            .bind(&mac)
            .bind(clean_optional(client.hostname.clone()))
            .bind(clean_optional(client.serial_number.clone()))
            .bind(&client.last_seen_at)
            .bind(&client.notes)
            .bind(&tags)
            .bind(default_profile_id)
            .bind(one_time_profile_id)
            .bind(&now)
            .bind(id)
            .execute(&mut **tx)
            .await?;
        } else {
            sqlx::query(
                "INSERT INTO devices
                 (managed_client_id, mac, hostname, serial_number, last_seen_at, notes, tags,
                  default_profile_id, one_time_profile_id, created_at, updated_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(&client.id)
            .bind(&mac)
            .bind(clean_optional(client.hostname.clone()))
            .bind(clean_optional(client.serial_number.clone()))
            .bind(&client.last_seen_at)
            .bind(&client.notes)
            .bind(&tags)
            .bind(default_profile_id)
            .bind(one_time_profile_id)
            .bind(&now)
            .bind(&now)
            .execute(&mut **tx)
            .await?;
        }
    }
    if clients_complete {
        let existing: Vec<(i64, String)> = sqlx::query_as(
            "SELECT id, managed_client_id FROM devices WHERE managed_client_id IS NOT NULL",
        )
        .fetch_all(&mut **tx)
        .await?;
        for (id, remote_id) in existing {
            if !desired.contains(&remote_id) {
                sqlx::query("DELETE FROM devices WHERE id = ?")
                    .bind(id)
                    .execute(&mut **tx)
                    .await?;
            }
        }
    }
    Ok(())
}

async fn sync_deleted_clients(
    tx: &mut Transaction<'_, Sqlite>,
    deleted_client_ids: &[String],
) -> Result<()> {
    let mut seen = HashSet::new();
    for remote_id in deleted_client_ids {
        if !seen.insert(remote_id) {
            continue;
        }
        sqlx::query("DELETE FROM devices WHERE managed_client_id = ?")
            .bind(remote_id)
            .execute(&mut **tx)
            .await?;
    }
    Ok(())
}

async fn managed_profile_map(tx: &mut Transaction<'_, Sqlite>) -> Result<HashMap<String, i64>> {
    let rows: Vec<(i64, String)> = sqlx::query_as(
        "SELECT id, managed_profile_id FROM boot_profiles WHERE managed_profile_id IS NOT NULL",
    )
    .fetch_all(&mut **tx)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, remote_id)| (remote_id, id))
        .collect())
}

async fn has_unreported_known_profile_events(
    pool: &SqlitePool,
    last_reported_event_id: Option<i64>,
) -> Result<bool> {
    let has_events: i64 = sqlx::query_scalar(
        "SELECT EXISTS (
             SELECT 1
             FROM boot_events
             WHERE id > ?
               AND known_device != 0
               AND selected_profile_id IS NOT NULL
         )",
    )
    .bind(last_reported_event_id.unwrap_or(0))
    .fetch_one(pool)
    .await?;
    Ok(has_events != 0)
}

async fn list_events_after(
    pool: &SqlitePool,
    last_reported_event_id: i64,
    limit: i64,
) -> Result<Vec<BootEventReportRow>> {
    let rows = sqlx::query_as::<_, BootEventReportRow>(
        "SELECT boot_events.id, boot_events.mac, boot_events.serial_number, boot_events.ip_address,
                boot_events.user_agent, boot_profiles.managed_profile_id AS selected_profile_id,
                boot_events.selected_profile_name, boot_events.known_device, boot_events.created_at
         FROM boot_events
         LEFT JOIN boot_profiles ON boot_profiles.id = boot_events.selected_profile_id
         WHERE boot_events.id > ?
         ORDER BY boot_events.id ASC
         LIMIT ?",
    )
    .bind(last_reported_event_id)
    .bind(limit.clamp(1, MAX_REPORT_EVENTS))
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

async fn signed_request(
    state: &AppState,
    managed: &ManagedState,
    method: Method,
    path: &str,
    body: Vec<u8>,
) -> Result<reqwest::RequestBuilder> {
    signed_request_for_config(&state.config, managed, method, path, body).await
}

async fn signed_request_for_config(
    config: &AppConfig,
    managed: &ManagedState,
    method: Method,
    path: &str,
    body: Vec<u8>,
) -> Result<reqwest::RequestBuilder> {
    let signing = signing_key(managed)?;
    let device_id = managed_device_id(managed)?;
    let timestamp = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    let request_id = random_request_id();
    let body_sha256 = sha256_hex(&body);
    let endpoint = api_url_for_config(config, path)?;
    let signed_path = request_path_and_query(&endpoint)?;
    let canonical = canonical_agent_payload(
        method.as_str(),
        &signed_path,
        &timestamp,
        &request_id,
        &body_sha256,
    );
    let signature = URL_SAFE_NO_PAD.encode(signing.sign(canonical.as_bytes()).to_bytes());
    let request = http_client_for_config(config)?
        .request(method, endpoint)
        .header("x-cybex-organization", organization_header(config)?)
        .header("x-cybex-device-id", device_id)
        .header("x-cybex-request-id", request_id)
        .header("x-cybex-timestamp", timestamp)
        .header("x-cybex-signature", signature);
    Ok(if body.is_empty() {
        request
    } else {
        request.body(body)
    })
}

async fn signed_download_request(
    state: &AppState,
    managed: &ManagedState,
    path: &str,
) -> Result<reqwest::RequestBuilder> {
    let signing = signing_key(managed)?;
    let device_id = managed_device_id(managed)?;
    let timestamp = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    let request_id = random_request_id();
    let body_sha256 = sha256_hex([]);
    let endpoint = api_url(state, path)?;
    let signed_path = request_path_and_query(&endpoint)?;
    let canonical =
        canonical_agent_payload("GET", &signed_path, &timestamp, &request_id, &body_sha256);
    let signature = URL_SAFE_NO_PAD.encode(signing.sign(canonical.as_bytes()).to_bytes());
    Ok(http_download_client(state)?
        .get(endpoint)
        .header("x-cybex-organization", organization_header(&state.config)?)
        .header("x-cybex-device-id", device_id)
        .header("x-cybex-request-id", request_id)
        .header("x-cybex-timestamp", timestamp)
        .header("x-cybex-signature", signature))
}

fn enrollment_body(state: &AppState, managed: &ManagedState) -> Result<Value> {
    let public_key = managed
        .public_key_b64
        .as_deref()
        .ok_or_else(|| anyhow!("missing public key"))?;
    let public_key_fingerprint = managed
        .public_key_fingerprint
        .as_deref()
        .ok_or_else(|| anyhow!("missing public key fingerprint"))?;
    let hostname = hostname();
    let machine_id_hash = machine_id_hash(&hostname);
    Ok(json!({
        "organization_id": organization_id(&state.config)?,
        "forge_install_code": forge_install_code(&state.config)?,
        "hostname": hostname,
        "machine_id_hash": machine_id_hash,
        "agent_version": env!("CARGO_PKG_VERSION"),
        "os_name": "Cybex Forge",
        "os_version": env!("CARGO_PKG_VERSION"),
        "kernel_version": kernel_version(),
        "virtualization": virtualization(),
        "device_kind": "cybex-forge",
        "capabilities": forge_capabilities(&state.config),
        "unsupported_capabilities": [],
        "public_key": public_key,
        "public_key_fingerprint": public_key_fingerprint,
        "hardware_fingerprint": machine_id_hash.clone(),
        "hardware_fingerprint_candidates": [machine_id_hash.clone()],
        "hardware_fingerprint_sources": [
            "machine_id_hash",
            "public_key_fingerprint",
        ],
        "facts": {
            "service": "cybex-forge",
            "public_base_url": state.config.public_base_url(),
            "listen_addr": state.config.server.listen_addr.clone(),
            "tftp_root": state.config.paths.tftp_dir.display().to_string(),
            "http_root": state.config.paths.boot_assets_dir.display().to_string(),
            "bootloader_filename": state.config.boot.bootloader_filename.clone(),
            "menu_timeout_ms": state.config.boot.menu_timeout_ms,
            "capabilities": forge_capabilities(&state.config),
        }
    }))
}

fn forge_capabilities(config: &AppConfig) -> Vec<&'static str> {
    let mut capabilities = vec![
        CAPABILITY_BOOT_V1,
        CAPABILITY_BUILDER_V1,
        CAPABILITY_BLUEPRINT_BUILDER_V2,
        CAPABILITY_CACHE_V1,
    ];
    if crate::updater::capabilities_enabled(config) {
        capabilities.push(CAPABILITY_UPDATER_V1);
    }
    capabilities
}

fn optional_report_uuid(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        Uuid::parse_str(trimmed)
            .ok()
            .map(|uuid| uuid.hyphenated().to_string())
    })
}

fn ensure_key_material(state: &mut ManagedState) -> Result<()> {
    let signing = match state.private_key_b64.as_deref() {
        Some(value) => signing_key_from_b64(value)?,
        None => {
            let mut rng = OsRng;
            let signing = SigningKey::generate(&mut rng);
            state.private_key_b64 = Some(STANDARD.encode(signing.to_bytes()));
            signing
        }
    };
    let public = signing.verifying_key().to_bytes();
    state.public_key_b64 = Some(STANDARD.encode(public));
    state.public_key_fingerprint = Some(sha256_hex(public));
    Ok(())
}

fn signing_key(state: &ManagedState) -> Result<SigningKey> {
    let private_key = state
        .private_key_b64
        .as_deref()
        .ok_or_else(|| anyhow!("missing private key"))?;
    signing_key_from_b64(private_key)
}

fn signing_key_from_b64(value: &str) -> Result<SigningKey> {
    let bytes = STANDARD
        .decode(value)
        .context("managed private key is not valid base64")?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("managed private key has invalid length"))?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn load_managed_state(state: &AppState) -> Result<ManagedState> {
    load_managed_state_from_config(&state.config)
}

fn load_managed_state_from_config(config: &AppConfig) -> Result<ManagedState> {
    let path = &config.manage.state_path;
    if !path.exists() {
        return Ok(ManagedState::default());
    }
    let raw = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_slice(&raw).with_context(|| format!("failed to parse {}", path.display()))
}

fn managed_state_lock_path(config: &AppConfig) -> Result<PathBuf> {
    let file_name = config
        .manage
        .state_path
        .file_name()
        .ok_or_else(|| anyhow!("managed state path must include a file name"))?;
    let mut lock_name = OsString::from(file_name);
    lock_name.push(".lock");
    Ok(config.manage.state_path.with_file_name(lock_name))
}

#[cfg(unix)]
fn acquire_managed_state_lock(config: &AppConfig) -> Result<AdvisoryFileLock> {
    let path = managed_state_lock_path(config)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create managed state directory {}", parent.display()))?;
    }
    let lock = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)
        .with_context(|| format!("open managed state lock {}", path.display()))?;
    let metadata = lock
        .metadata()
        .with_context(|| format!("inspect managed state lock {}", path.display()))?;
    if !metadata.file_type().is_file() {
        bail!("managed state lock is not a regular file");
    }
    if metadata.nlink() != 1 {
        bail!("managed state lock must not have hard links");
    }
    if metadata.uid() != unsafe { libc::geteuid() } {
        bail!("managed state lock is owned by an unexpected user");
    }
    lock.set_permissions(fs::Permissions::from_mode(0o600))
        .with_context(|| format!("secure managed state lock {}", path.display()))?;
    let result = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result != 0 {
        bail!("another managed enrollment or sync process is already running");
    }
    Ok(AdvisoryFileLock(lock))
}

#[cfg(not(unix))]
fn acquire_managed_state_lock(config: &AppConfig) -> Result<AdvisoryFileLock> {
    let path = managed_state_lock_path(config)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(path)
        .context("open managed state lock")
}

fn save_managed_state(state: &AppState, managed: &ManagedState) -> Result<()> {
    write_secure_json(&state.config.manage.state_path, managed)
}

fn write_secure_json(path: &Path, value: &ManagedState) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = secure_json_tmp_path(path)?;
    let result = write_secure_json_via_tmp(path, &tmp, value);
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

fn secure_json_tmp_path(path: &Path) -> Result<PathBuf> {
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow!("managed state path must include a file name"))?;
    let mut random = [0u8; 8];
    OsRng.fill_bytes(&mut random);

    let mut tmp_name = OsString::from(".");
    tmp_name.push(file_name);
    tmp_name.push(format!(
        ".{}.{}.tmp",
        std::process::id(),
        hex::encode(random)
    ));

    Ok(path.with_file_name(tmp_name))
}

fn write_secure_json_via_tmp(path: &Path, tmp: &Path, value: &ManagedState) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(tmp)
        .with_context(|| format!("failed to create temporary {}", tmp.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(&serde_json::to_vec_pretty(value)?)?;
    file.write_all(b"\n")?;
    file.sync_all()
        .with_context(|| format!("failed to sync temporary {}", tmp.display()))?;
    drop(file);

    fs::rename(tmp, path).with_context(|| {
        format!(
            "failed to replace managed state {} with {}",
            path.display(),
            tmp.display()
        )
    })?;
    sync_parent_dir(path)?;
    Ok(())
}

#[cfg(unix)]
fn sync_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        let dir = fs::File::open(parent)
            .with_context(|| format!("failed to open directory {}", parent.display()))?;
        dir.sync_all()
            .with_context(|| format!("failed to sync directory {}", parent.display()))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn sync_parent_dir(_path: &Path) -> Result<()> {
    Ok(())
}

async fn parse_success_json<T: DeserializeOwned>(
    mut response: reqwest::Response,
    context: &str,
) -> Result<T> {
    let status = response.status();
    if !status.is_success() {
        let detail = match read_bounded_response_body(&mut response, context).await {
            Ok(body) => managed_api_error_detail(&body),
            Err(_) => None,
        };
        if let Some(detail) = detail {
            bail!("{context} failed with HTTP {status}: {detail}");
        }
        bail!("{context} failed with HTTP {status}");
    }
    let body = read_bounded_response_body(&mut response, context).await?;
    serde_json::from_slice::<T>(&body).with_context(|| format!("parse {context} response failed"))
}

fn managed_api_error_detail(body: &[u8]) -> Option<String> {
    let value = serde_json::from_slice::<Value>(body).ok()?;
    let object = value.as_object()?;
    let error_code = object
        .get("error_code")
        .and_then(Value::as_str)
        .filter(|value| is_safe_path_segment(value));
    let error = object
        .get("error")
        .and_then(Value::as_str)
        .map(|value| bounded_error_message(redact_sensitive_key_values(value)));
    match (error_code, error.filter(|value| !value.is_empty())) {
        (Some(code), Some(error)) => Some(format!("{code}: {error}")),
        (Some(code), None) => Some(code.to_string()),
        (None, Some(error)) => Some(error),
        (None, None) => None,
    }
}

async fn read_bounded_response_body(
    response: &mut reqwest::Response,
    context: &str,
) -> Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|len| len > MAX_MANAGED_RESPONSE_BYTES as u64)
    {
        bail!("{context} response exceeded {MAX_MANAGED_RESPONSE_BYTES} bytes");
    }

    let mut body = Vec::with_capacity(
        response
            .content_length()
            .unwrap_or_default()
            .min(MAX_MANAGED_RESPONSE_BYTES as u64) as usize,
    );
    while let Some(chunk) = response
        .chunk()
        .await
        .with_context(|| format!("read {context} response failed"))?
    {
        append_bounded_response_chunk(&mut body, &chunk, context)?;
    }
    Ok(body)
}

fn append_bounded_response_chunk(body: &mut Vec<u8>, chunk: &[u8], context: &str) -> Result<()> {
    append_bounded_response_chunk_with_limit(body, chunk, MAX_MANAGED_RESPONSE_BYTES, context)
}

fn append_bounded_response_chunk_with_limit(
    body: &mut Vec<u8>,
    chunk: &[u8],
    max_bytes: usize,
    context: &str,
) -> Result<()> {
    let next_len = body
        .len()
        .checked_add(chunk.len())
        .ok_or_else(|| anyhow!("{context} response exceeded {max_bytes} bytes"))?;
    if next_len > max_bytes {
        bail!("{context} response exceeded {max_bytes} bytes");
    }
    body.extend_from_slice(chunk);
    Ok(())
}

fn http_client(state: &AppState) -> Result<Client> {
    http_client_for_config(&state.config)
}

fn http_client_for_config(config: &AppConfig) -> Result<Client> {
    let timeout = Duration::from_secs(bounded_http_timeout_seconds(
        config.manage.http_timeout_seconds,
    ));
    Client::builder()
        .timeout(timeout)
        .connect_timeout(timeout.min(Duration::from_secs(10)))
        .build()
        .context("failed to build managed HTTP client")
}

fn http_download_client(state: &AppState) -> Result<Client> {
    let connect_timeout = Duration::from_secs(bounded_http_timeout_seconds(
        state.config.manage.http_timeout_seconds,
    ))
    .min(Duration::from_secs(10));
    // No overall timeout: multi-GB ISO downloads legitimately run long. The
    // read timeout still fails a stalled transfer, which would otherwise hang
    // the single sync loop indefinitely.
    Client::builder()
        .connect_timeout(connect_timeout)
        .read_timeout(Duration::from_secs(60))
        .build()
        .context("failed to build managed ISO download HTTP client")
}

fn bounded_http_timeout_seconds(value: u64) -> u64 {
    value.clamp(1, 300)
}

fn managed_sync_interval_seconds(config: &ManageConfig, outcome: SyncOnceDisposition) -> u64 {
    match outcome {
        SyncOnceDisposition::Synced => config.sync_interval_seconds.clamp(5, 3600),
        SyncOnceDisposition::PendingEnrollment => config.enrollment_poll_seconds.clamp(1, 300),
    }
}

fn active_managed_sync_interval_seconds(normal_interval: u64, has_active_builds: bool) -> u64 {
    if has_active_builds {
        normal_interval.min(5)
    } else {
        normal_interval
    }
}

/// Exponential backoff after failed syncs: retry quickly at first (a
/// transient blip should not cost a full sync interval), never slower than
/// the normal cadence.
fn failed_sync_interval_seconds(config: &ManageConfig, consecutive_failures: u32) -> u64 {
    let normal = config.sync_interval_seconds.clamp(5, 3600);
    let exponent = consecutive_failures.saturating_sub(1).min(10);
    let backoff = 5u64.saturating_mul(1u64 << exponent);
    backoff.clamp(5, normal.max(5))
}

fn api_url(state: &AppState, path: &str) -> Result<String> {
    api_url_for_config(&state.config, path)
}

fn api_url_for_config(config: &AppConfig, path: &str) -> Result<String> {
    let base = config.manage.api_url.trim().trim_end_matches('/');
    if base.is_empty() {
        bail!("manage.api_url is required when managed mode is enabled");
    }
    Ok(format!("{base}{path}"))
}

fn request_path_and_query(endpoint: &str) -> Result<String> {
    let endpoint = reqwest::Url::parse(endpoint).context("parse managed request URL")?;
    if endpoint.fragment().is_some() {
        bail!("manage.api_url must not contain a URL fragment");
    }
    let mut path = endpoint.path().to_string();
    if let Some(query) = endpoint.query() {
        path.push('?');
        path.push_str(query);
    }
    Ok(path)
}

fn organization_header(config: &AppConfig) -> Result<String> {
    if !config.manage.organization_id.trim().is_empty() {
        return Ok(config.manage.organization_id.trim().to_string());
    }
    let slug = config.manage.organization_slug.trim();
    if !slug.is_empty() {
        return Ok(slug.to_string());
    }
    bail!("manage.organization_id is required when managed mode is enabled");
}

fn organization_id(config: &AppConfig) -> Result<String> {
    let organization_id = config.manage.organization_id.trim();
    if organization_id.is_empty() {
        bail!("manage.organization_id is required for Forge install enrollment");
    }
    Ok(organization_id.to_string())
}

fn forge_install_code(config: &AppConfig) -> Result<String> {
    let code = config.manage.forge_install_code.trim();
    if code.is_empty() {
        bail!("manage.forge_install_code is required for Forge install enrollment");
    }
    Ok(code.to_string())
}

fn ensure_manage_enabled(state: &AppState) -> Result<()> {
    ensure_manage_enabled_config(&state.config)
}

fn ensure_manage_enabled_config(config: &AppConfig) -> Result<()> {
    if !config.manage.enabled {
        bail!("managed mode is disabled");
    }
    Ok(())
}

fn managed_device_id(state: &ManagedState) -> Result<&str> {
    state
        .device_id
        .as_deref()
        .filter(|value| is_safe_path_segment(value))
        .ok_or_else(|| anyhow!("missing managed device id"))
}

fn canonical_agent_payload(
    method: &str,
    path_and_query: &str,
    timestamp: &str,
    request_id: &str,
    body_sha256: &str,
) -> String {
    format!(
        "CYBEX-AGENT-V1\n{}\n{}\n{}\n{}\n{}",
        method.to_uppercase(),
        path_and_query,
        timestamp,
        request_id,
        body_sha256
    )
}

fn enrollment_request_signature(
    managed: &ManagedState,
    path: &str,
    timestamp: &str,
    request_id: &str,
    body: &[u8],
) -> Result<String> {
    let canonical = canonical_agent_payload("POST", path, timestamp, request_id, &sha256_hex(body));
    Ok(URL_SAFE_NO_PAD.encode(signing_key(managed)?.sign(canonical.as_bytes()).to_bytes()))
}

fn enrollment_status_signature(
    managed: &ManagedState,
    path: &str,
    timestamp: &str,
    request_id: &str,
) -> Result<String> {
    let canonical = canonical_agent_payload("GET", path, timestamp, request_id, &sha256_hex([]));
    Ok(URL_SAFE_NO_PAD.encode(signing_key(managed)?.sign(canonical.as_bytes()).to_bytes()))
}

fn random_request_id() -> String {
    let mut bytes = [0_u8; 16];
    OsRng.fill_bytes(&mut bytes);
    format!("req_{}", hex::encode(bytes))
}

fn sha256_hex(bytes: impl AsRef<[u8]>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes.as_ref());
    hex::encode(hasher.finalize())
}

fn hostname() -> String {
    fs::read_to_string("/etc/hostname")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "cybex-forge".to_string())
}

fn machine_id_hash(hostname: &str) -> String {
    let raw = fs::read_to_string("/etc/machine-id")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| hostname.to_string());
    sha256_hex(raw.as_bytes())
}

fn kernel_version() -> String {
    StdCommand::new("uname")
        .arg("-r")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

fn virtualization() -> Option<String> {
    fs::read_to_string("/run/systemd/container")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn validate_profile(profile: &ManagedBootProfile) -> Result<()> {
    validate_managed_id(&profile.id, "managed boot profile id")?;
    if profile.sync_generation < 0 {
        bail!("managed boot profile sync_generation must not be negative");
    }
    Uuid::parse_str(profile.sync_operation_id.trim())
        .context("managed boot profile sync_operation_id must be a UUID")?;
    if profile.name.trim().is_empty() {
        bail!("managed boot profile name is required");
    }
    if profile.name.trim().len() > 120 {
        bail!("managed boot profile name must be 120 characters or fewer");
    }
    if profile.name.trim().chars().any(char::is_control) {
        bail!("managed boot profile name must not contain control characters");
    }
    if profile.description.chars().count() > MAX_PROFILE_DESCRIPTION_CHARS {
        bail!(
            "managed boot profile description must be {MAX_PROFILE_DESCRIPTION_CHARS} characters or fewer"
        );
    }
    if profile
        .raw_script
        .as_deref()
        .map(|value| value.trim().len() > MAX_PROFILE_RAW_SCRIPT_BYTES)
        .unwrap_or(false)
    {
        bail!(
            "managed boot profile raw_script must be {MAX_PROFILE_RAW_SCRIPT_BYTES} bytes or fewer"
        );
    }
    BootProfileType::from_str(&profile.profile_type)
        .map_err(|err| anyhow!("invalid managed profile type: {err}"))?;
    validate_installer_iso_source(&profile.installer_iso_source)?;
    validate_relative_path(profile.kernel_path.as_deref(), "kernel_path")?;
    validate_relative_path(profile.initrd_path.as_deref(), "initrd_path")?;
    validate_relative_path(profile.iso_path.as_deref(), "iso_path")?;
    validate_cmdline(profile.cmdline.as_deref())?;
    validate_desired_iso_metadata(profile)?;
    Ok(())
}

fn validate_boot_config(config: &AgentBootConfigResponse) -> Result<()> {
    if config.profiles.len() > MAX_MANAGED_PROFILES {
        bail!("managed boot config includes too many profiles; max is {MAX_MANAGED_PROFILES}");
    }
    if config.deleted_profile_ids.len() > MAX_DELETED_MANAGED_PROFILES {
        bail!(
            "managed boot config includes too many deleted profiles; max is {MAX_DELETED_MANAGED_PROFILES}"
        );
    }
    if config.clients.len() > MAX_MANAGED_CLIENTS {
        bail!("managed boot config includes too many clients; max is {MAX_MANAGED_CLIENTS}");
    }
    if config.deleted_client_ids.len() > MAX_DELETED_MANAGED_CLIENTS {
        bail!(
            "managed boot config includes too many deleted clients; max is {MAX_DELETED_MANAGED_CLIENTS}"
        );
    }

    let mut profiles_by_id = HashMap::new();
    let mut default_profile_count = 0usize;
    for profile in &config.profiles {
        validate_profile(profile)?;
        if profiles_by_id.insert(profile.id.clone(), profile).is_some() {
            bail!("duplicate managed boot profile id");
        }
        if profile.is_default {
            default_profile_count += 1;
            if default_profile_count > 1 {
                bail!("managed boot config includes multiple default profiles");
            }
            validate_assignable_profile(profile, "managed default boot profile")?;
        }
    }

    let mut deleted_profile_ids = HashSet::new();
    for remote_id in &config.deleted_profile_ids {
        validate_managed_id(remote_id, "deleted managed boot profile id")?;
        if !deleted_profile_ids.insert(remote_id) {
            bail!("duplicate deleted managed boot profile id");
        }
    }

    let mut client_ids = HashSet::new();
    let mut client_macs = HashSet::new();
    for client in &config.clients {
        validate_managed_id(&client.id, "managed boot client id")?;
        if !client_ids.insert(client.id.clone()) {
            bail!("duplicate managed boot client id");
        }
        let mac = normalize_mac(&client.mac)?;
        if !client_macs.insert(mac) {
            bail!("duplicate managed boot client mac");
        }
        validate_client_metadata(client)?;
        validate_client_profile_reference(client.default_profile_id.as_deref(), &profiles_by_id)?;
        validate_client_profile_reference(client.one_time_profile_id.as_deref(), &profiles_by_id)?;
        serde_json::to_string(&clean_tags(client.tags.clone()))?;
    }

    let mut deleted_client_ids = HashSet::new();
    for remote_id in &config.deleted_client_ids {
        validate_managed_id(remote_id, "deleted managed boot client id")?;
        if !deleted_client_ids.insert(remote_id) {
            bail!("duplicate deleted managed boot client id");
        }
    }

    Ok(())
}

fn validate_component_compatibility(
    contract: Option<&ComponentCompatibilityContract>,
) -> Result<()> {
    let Some(contract) = contract else {
        // Absence is the protocol-v1 wire shape. This compatibility window is
        // intentional so Forge can be upgraded before or after Manage.
        return Ok(());
    };
    if !(CYBEX_MINIMUM_MANAGE_PROTOCOL_VERSION..=CYBEX_MAXIMUM_MANAGE_PROTOCOL_VERSION)
        .contains(&contract.protocol_version)
        || !(contract.minimum_forge_protocol..=contract.maximum_forge_protocol)
            .contains(&CYBEX_COMPONENT_PROTOCOL_VERSION)
    {
        bail!(
            "incompatible Manage protocol {} (Forge protocol {}, supported Forge range {} through {}, Manage version {}, release {})",
            contract.protocol_version,
            CYBEX_COMPONENT_PROTOCOL_VERSION,
            contract.minimum_forge_protocol,
            contract.maximum_forge_protocol,
            clean_string(&contract.manage_version),
            clean_string(&contract.manage_release),
        );
    }
    Ok(())
}

fn normalize_legacy_boot_config(config: &mut AgentBootConfigResponse) {
    if config.compatibility.is_some() {
        return;
    }
    // Protocol-v1 Manage did not provide operation UUIDs. A nil UUID keeps
    // local durable state coherent during a rolling upgrade; protocol-v2
    // Manage will replace it with the authoritative fenced operation.
    for profile in &mut config.profiles {
        if profile.sync_operation_id.trim().is_empty() {
            profile.sync_operation_id = Uuid::nil().to_string();
        }
    }
}

fn validate_client_metadata(client: &ManagedBootClient) -> Result<()> {
    validate_limited_optional_text(
        client.hostname.as_deref(),
        "managed boot client hostname",
        MAX_DEVICE_HOSTNAME_CHARS,
        false,
    )?;
    validate_limited_optional_text(
        client.serial_number.as_deref(),
        "managed boot client serial number",
        MAX_DEVICE_SERIAL_CHARS,
        false,
    )?;
    validate_limited_text(
        &client.notes,
        "managed boot client notes",
        MAX_DEVICE_NOTES_CHARS,
        true,
    )?;
    let tags = clean_tags(client.tags.clone());
    validate_client_tags(&tags)?;
    Ok(())
}

fn validate_client_tags(tags: &[String]) -> Result<()> {
    if tags.len() > MAX_DEVICE_TAGS {
        bail!("managed boot client tags must include {MAX_DEVICE_TAGS} entries or fewer");
    }
    for tag in tags {
        validate_limited_text(tag, "managed boot client tag", MAX_DEVICE_TAG_CHARS, false)?;
    }
    Ok(())
}

fn validate_limited_optional_text(
    value: Option<&str>,
    field: &str,
    max_chars: usize,
    allow_control: bool,
) -> Result<()> {
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
) -> Result<()> {
    if value.chars().count() > max_chars {
        bail!("{field} must be {max_chars} characters or fewer");
    }
    if !allow_control && value.chars().any(char::is_control) {
        bail!("{field} must not contain control characters");
    }
    Ok(())
}

fn normalize_managed_settings(
    settings: &ManagedBootSettings,
    config: &AppConfig,
) -> Result<NormalizedManagedSettings> {
    let public_base_url = if settings.public_base_url.trim().is_empty() {
        config.public_base_url().to_string()
    } else {
        normalize_http_url(
            "managed boot settings public_base_url",
            &settings.public_base_url,
        )?
    };
    if public_base_url.is_empty() {
        bail!("managed boot settings public_base_url is required");
    }
    let listen_addr = if settings.listen_addr.trim().is_empty() {
        config.server.listen_addr.clone()
    } else {
        normalize_listen_addr(&settings.listen_addr)?
    };
    validate_managed_listen_addr(&listen_addr)?;
    let tftp_root = normalize_managed_runtime_root(
        "managed boot settings tftp_root",
        &settings.tftp_root,
        &config.paths.tftp_dir,
    )?;
    let http_root = normalize_managed_runtime_root(
        "managed boot settings http_root",
        &settings.http_root,
        &config.paths.boot_assets_dir,
    )?;
    if tftp_root == http_root {
        bail!("managed boot settings tftp_root and http_root must be different");
    }
    if tftp_root.starts_with(&http_root) || http_root.starts_with(&tftp_root) {
        bail!("managed boot settings tftp_root and http_root must not overlap");
    }
    let bootloader_filename = if settings.bootloader_filename.trim().is_empty() {
        config.boot.bootloader_filename.clone()
    } else {
        normalize_bootloader_filename(&settings.bootloader_filename)?
    };
    let menu_timeout_ms = settings.menu_timeout_ms;
    validate_menu_timeout_ms(menu_timeout_ms)?;

    Ok(NormalizedManagedSettings {
        public_base_url,
        listen_addr,
        tftp_root,
        http_root,
        bootloader_filename,
        menu_timeout_ms,
    })
}

fn validate_managed_listen_addr(value: &str) -> Result<()> {
    let parsed: std::net::SocketAddr = value
        .parse()
        .with_context(|| format!("managed boot settings listen_addr {value} is invalid"))?;
    if !parsed.ip().is_loopback() {
        bail!("managed boot settings listen_addr must be loopback-only");
    }
    Ok(())
}

fn managed_update_health_url(listen_addr: &str) -> Result<String> {
    let parsed: std::net::SocketAddr = listen_addr
        .parse()
        .with_context(|| format!("managed boot settings listen_addr {listen_addr} is invalid"))?;
    let host = if parsed.ip().is_unspecified() {
        "127.0.0.1".to_string()
    } else if parsed.ip().is_ipv6() {
        format!("[{}]", parsed.ip())
    } else {
        parsed.ip().to_string()
    };
    Ok(format!("http://{host}:{}/healthz", parsed.port()))
}

fn normalize_managed_runtime_root(field: &str, value: &str, fallback: &Path) -> Result<PathBuf> {
    let raw = if value.trim().is_empty() {
        fallback.to_path_buf()
    } else {
        PathBuf::from(value.trim())
    };
    let path = normalize_absolute_config_path(field, &raw)?;
    if path
        .as_os_str()
        .to_string_lossy()
        .bytes()
        .any(|byte| byte.is_ascii_whitespace())
    {
        bail!("{field} must not contain whitespace");
    }
    if !path
        .as_os_str()
        .to_string_lossy()
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-'))
    {
        bail!("{field} contains unsupported characters");
    }
    let forge_root = Path::new("/srv/cybex-forge");
    if !path.starts_with(forge_root) {
        bail!("{field} must be under /srv/cybex-forge");
    }
    if path == forge_root {
        bail!(
            "{field} must be below {}, not {} itself",
            forge_root.display(),
            forge_root.display()
        );
    }
    Ok(path)
}

#[cfg(unix)]
fn ensure_root_supervisor() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("apply-runtime-config must run as root");
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_root_supervisor() -> Result<()> {
    Ok(())
}

fn apply_runtime_settings_to_host(
    config: &AppConfig,
    settings: &NormalizedManagedSettings,
) -> Result<()> {
    ensure_runtime_directories(config, settings)?;
    let runtime_files = runtime_managed_files(config, settings)?;
    let backups = capture_runtime_file_backups(&runtime_files)?;
    let apply_result = apply_runtime_managed_files(settings, &runtime_files);
    if let Err(err) = apply_result {
        if let Err(rollback_err) = rollback_runtime_files(&runtime_files, &backups) {
            return Err(err).context(format!(
                "runtime configuration failed and rollback also failed: {rollback_err:#}"
            ));
        }
        return Err(err).context("runtime configuration failed; previous files were restored");
    }
    Ok(())
}

struct RuntimeManagedFile {
    path: &'static str,
    contents: String,
    mode: &'static str,
    owner: &'static str,
    group: &'static str,
    component: &'static str,
}

fn runtime_managed_files(
    config: &AppConfig,
    settings: &NormalizedManagedSettings,
) -> Result<Vec<RuntimeManagedFile>> {
    Ok(vec![
        RuntimeManagedFile {
            path: "/etc/systemd/system/cybex-forge.service",
            contents: FORGE_SERVICE_UNIT.to_string(),
            mode: "0644",
            owner: "root",
            group: "root",
            component: "systemd-boot",
        },
        RuntimeManagedFile {
            path: "/etc/systemd/system/cybex-forge-control.slice",
            contents: FORGE_CONTROL_SLICE_UNIT.to_string(),
            mode: "0644",
            owner: "root",
            group: "root",
            component: "systemd",
        },
        RuntimeManagedFile {
            path: "/etc/systemd/system/cybex-forge-build.slice",
            contents: FORGE_BUILD_SLICE_UNIT.to_string(),
            mode: "0644",
            owner: "root",
            group: "root",
            component: "systemd",
        },
        RuntimeManagedFile {
            path: "/etc/systemd/system/cybex-forge-sentinel.service",
            contents: FORGE_SENTINEL_SERVICE_UNIT.to_string(),
            mode: "0644",
            owner: "root",
            group: "root",
            component: "sentinel",
        },
        RuntimeManagedFile {
            path: "/etc/systemd/system/cybex-forge-sentinel.timer",
            contents: FORGE_SENTINEL_TIMER_UNIT.to_string(),
            mode: "0644",
            owner: "root",
            group: "root",
            component: "sentinel",
        },
        RuntimeManagedFile {
            path: "/usr/local/bin/cybex-forge-check",
            contents: FORGE_CHECK_SCRIPT.to_string(),
            mode: "0755",
            owner: "root",
            group: "root",
            component: "checker",
        },
        RuntimeManagedFile {
            path: "/usr/local/bin/cybex-forge-sentinel",
            contents: FORGE_SENTINEL_SCRIPT.to_string(),
            mode: "0755",
            owner: "root",
            group: "root",
            component: "sentinel",
        },
        RuntimeManagedFile {
            path: "/etc/systemd/system/systemd-resolved.service.d/10-cybex-forge-recovery.conf",
            contents: RESOLVER_RECOVERY_DROPIN.to_string(),
            mode: "0644",
            owner: "root",
            group: "root",
            component: "resolver",
        },
        RuntimeManagedFile {
            path: "/etc/systemd/system/nix-daemon.service.d/10-cybex-forge-restart.conf",
            contents: NIX_DAEMON_RESOURCE_DROPIN.to_string(),
            mode: "0644",
            owner: "root",
            group: "root",
            component: "systemd",
        },
        RuntimeManagedFile {
            path: "/etc/systemd/system/nginx.service.d/20-cybex-availability.conf",
            contents: NGINX_AVAILABILITY_DROPIN.to_string(),
            mode: "0644",
            owner: "root",
            group: "root",
            component: "systemd-nginx",
        },
        RuntimeManagedFile {
            path: "/etc/systemd/system/tftpd-hpa.service.d/20-cybex-availability.conf",
            contents: TFTP_AVAILABILITY_DROPIN.to_string(),
            mode: "0644",
            owner: "root",
            group: "root",
            component: "systemd-tftp",
        },
        RuntimeManagedFile {
            path: "/etc/cybex-forge/config.toml",
            contents: render_managed_config(config, settings)?,
            mode: "0640",
            owner: "root",
            group: "cybex-forge",
            component: "boot",
        },
        RuntimeManagedFile {
            path: "/etc/nginx/sites-available/cybex-forge",
            contents: render_nginx_config(settings),
            mode: "0644",
            owner: "root",
            group: "root",
            component: "nginx",
        },
        RuntimeManagedFile {
            path: "/etc/default/tftpd-hpa",
            contents: render_tftpd_defaults(settings),
            mode: "0644",
            owner: "root",
            group: "root",
            component: "tftp",
        },
        RuntimeManagedFile {
            path: "/etc/systemd/system/cybex-forge.service.d/40-write-paths.conf",
            contents: render_boot_write_paths_dropin(settings),
            mode: "0644",
            owner: "root",
            group: "root",
            component: "systemd",
        },
        RuntimeManagedFile {
            path: "/etc/systemd/system/nginx.service.d/10-cybex-hardening.conf",
            contents: render_nginx_hardening_dropin(settings),
            mode: "0644",
            owner: "root",
            group: "root",
            component: "systemd",
        },
        RuntimeManagedFile {
            path: "/etc/systemd/system/tftpd-hpa.service.d/10-cybex-hardening.conf",
            contents: render_tftpd_hardening_dropin(settings),
            mode: "0644",
            owner: "root",
            group: "root",
            component: "systemd",
        },
        RuntimeManagedFile {
            path: "/etc/systemd/system/cybex-forge-check.service",
            contents: render_check_service(settings),
            mode: "0644",
            owner: "root",
            group: "root",
            component: "systemd",
        },
    ])
}

fn capture_runtime_file_backups(files: &[RuntimeManagedFile]) -> Result<Vec<Option<Vec<u8>>>> {
    files
        .iter()
        .map(|file| match fs::read(file.path) {
            Ok(contents) => Ok(Some(contents)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err).with_context(|| format!("back up {}", file.path)),
        })
        .collect()
}

fn apply_runtime_managed_files(
    settings: &NormalizedManagedSettings,
    files: &[RuntimeManagedFile],
) -> Result<()> {
    let mut boot_changed = false;
    let mut nginx_changed = false;
    let mut tftp_changed = false;
    let mut daemon_reload = false;
    let mut resolver_changed = false;

    for file in files {
        let changed = install_text_file(
            Path::new(file.path),
            &file.contents,
            file.mode,
            file.owner,
            file.group,
        )?;
        match file.component {
            "boot" => boot_changed |= changed,
            "nginx" => nginx_changed |= changed,
            "tftp" => tftp_changed |= changed,
            "systemd" => daemon_reload |= changed,
            "systemd-boot" => {
                daemon_reload |= changed;
                boot_changed |= changed;
            }
            "systemd-nginx" => {
                daemon_reload |= changed;
                nginx_changed |= changed;
            }
            "systemd-tftp" => {
                daemon_reload |= changed;
                tftp_changed |= changed;
            }
            "resolver" => {
                daemon_reload |= changed;
                resolver_changed |= changed;
            }
            "sentinel" => daemon_reload |= changed,
            _ => {}
        }
    }

    tftp_changed |= ensure_bootloader_artifacts(settings)?;

    if daemon_reload {
        run_command("systemctl", ["daemon-reload"])?;
        boot_changed = true;
        nginx_changed = true;
        tftp_changed = true;
    }
    if nginx_changed {
        run_command("nginx", ["-t"])?;
    }
    if boot_changed {
        run_command("systemctl", ["restart", "cybex-forge.service"])?;
    }
    if nginx_changed {
        run_command("systemctl", ["restart", "nginx.service"])?;
    }
    if tftp_changed {
        run_command("systemctl", ["restart", "tftpd-hpa.service"])?;
    }
    if resolver_changed {
        run_command("systemctl", ["restart", "systemd-resolved.service"])?;
    }
    for unit in ["cybex-forge.service", "nginx.service", "tftpd-hpa.service"] {
        run_command("systemctl", ["is-active", "--quiet", unit])?;
    }
    run_command(
        "curl",
        ["-fsS", "--max-time", "5", "http://127.0.0.1/healthz"],
    )?;
    run_command(
        "curl",
        [
            "-fsS",
            "--max-time",
            "5",
            "http://127.0.0.1/boot.ipxe?cybex_check=1",
        ],
    )?;
    run_command(
        "systemctl",
        ["enable", "--now", "cybex-forge-sentinel.timer"],
    )?;
    Ok(())
}

fn rollback_runtime_files(files: &[RuntimeManagedFile], backups: &[Option<Vec<u8>>]) -> Result<()> {
    for (file, backup) in files.iter().zip(backups) {
        match backup {
            Some(contents) => {
                install_bytes_file(
                    Path::new(file.path),
                    contents,
                    file.mode,
                    file.owner,
                    file.group,
                )?;
            }
            None => match fs::remove_file(file.path) {
                Ok(()) => sync_parent_dir(Path::new(file.path))?,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => return Err(err).with_context(|| format!("remove {}", file.path)),
            },
        }
    }
    run_command("systemctl", ["daemon-reload"])?;
    run_command("nginx", ["-t"])?;
    for unit in [
        "systemd-resolved.service",
        "cybex-forge.service",
        "nginx.service",
        "tftpd-hpa.service",
    ] {
        run_command("systemctl", ["restart", unit])?;
    }
    Ok(())
}

fn ensure_runtime_directories(
    config: &AppConfig,
    settings: &NormalizedManagedSettings,
) -> Result<()> {
    install_dir(Path::new("/etc/cybex-forge"), "0750", "root", "cybex-forge")?;
    install_dir(
        Path::new("/var/lib/cybex-forge"),
        "0700",
        "cybex-forge",
        "cybex-forge",
    )?;
    install_dir(Path::new("/srv/cybex-forge"), "0755", "root", "cybex-forge")?;
    install_dir(&settings.http_root, "0755", "cybex-forge", "cybex-forge")?;
    install_dir(
        &settings.http_root.join("isos"),
        "0755",
        "cybex-forge",
        "cybex-forge",
    )?;
    install_dir(
        &settings.http_root.join("assets"),
        "0755",
        "cybex-forge",
        "cybex-forge",
    )?;
    install_bytes_file(
        &settings
            .http_root
            .join("assets")
            .join(PXE_MENU_BACKGROUND_FILENAME),
        PXE_MENU_BACKGROUND_ASSET,
        "0644",
        "cybex-forge",
        "cybex-forge",
    )?;
    install_dir(
        &settings.http_root.join("cache"),
        "0755",
        "cybex-forge",
        "cybex-forge",
    )?;
    install_dir(&config.build.work_dir, "0700", "cybex-forge", "cybex-forge")?;
    install_dir(
        &config.build.output_dir,
        "0700",
        "cybex-forge",
        "cybex-forge",
    )?;
    install_dir(
        &config.update.work_dir,
        "0700",
        "cybex-forge",
        "cybex-forge",
    )?;
    install_dir(&config.update.releases_dir, "0755", "root", "root")?;
    if let Some(parent) = config.cache.private_key_path.parent() {
        install_dir(parent, "0700", "cybex-forge", "cybex-forge")?;
    }
    install_dir(&settings.tftp_root, "0555", "root", "root")?;
    install_dir(
        Path::new("/etc/systemd/system/cybex-forge.service.d"),
        "0755",
        "root",
        "root",
    )?;
    install_dir(
        Path::new("/etc/systemd/system/nginx.service.d"),
        "0755",
        "root",
        "root",
    )?;
    install_dir(
        Path::new("/etc/systemd/system/tftpd-hpa.service.d"),
        "0755",
        "root",
        "root",
    )?;
    Ok(())
}

fn render_managed_config(
    config: &AppConfig,
    settings: &NormalizedManagedSettings,
) -> Result<String> {
    let http_root = settings.http_root.display().to_string();
    let tftp_root = settings.tftp_root.display().to_string();
    let cache_root = settings.http_root.join("cache").display().to_string();
    let build_targets = render_build_target_config(&config.build.targets)?;
    Ok(format!(
        "[server]\n\
         listen_addr = {listen_addr}\n\
         public_base_url = {public_base_url}\n\n\
         [paths]\n\
         data_dir = {data_dir}\n\
         database_path = {database_path}\n\
         boot_assets_dir = {http_root}\n\
         iso_dir = {iso_dir}\n\
         static_dir = {static_dir}\n\
         tftp_dir = {tftp_root}\n\n\
         [boot]\n\
         bootloader_filename = {bootloader_filename}\n\
         menu_timeout_ms = {menu_timeout_ms}\n\n\
         [build]\n\
         enabled = {build_enabled}\n\
         max_concurrent_builds = {max_concurrent_builds}\n\
         timeout_seconds = {build_timeout_seconds}\n\
         cancel_grace_seconds = {cancel_grace_seconds}\n\
         max_log_bytes = {max_log_bytes}\n\
         max_artifact_size_bytes = {max_artifact_size_bytes}\n\
         allowed_systems = {allowed_systems}\n\
         work_dir = {build_work_dir}\n\
         output_dir = {build_output_dir}\n\
         nix_binary = {nix_binary}\n\
         {build_targets}\n\
         [cache]\n\
         enabled = {cache_enabled}\n\
         root_dir = {cache_root}\n\
         signing_key_name = {signing_key_name}\n\
         private_key_path = {cache_private_key_path}\n\
         public_key_path = {cache_public_key_path}\n\
         max_bytes = {cache_max_bytes}\n\
         retain_recent_builds = {cache_retain_recent_builds}\n\n\
         [update]\n\
         enabled = {update_enabled}\n\
         work_dir = {update_work_dir}\n\
         releases_dir = {update_releases_dir}\n\
         binary_path = {update_binary_path}\n\
         config_path = {update_config_path}\n\
         service_name = {update_service_name}\n\
         health_url = {update_health_url}\n\
         max_artifact_size_bytes = {update_max_artifact_size_bytes}\n\
         trusted_public_key = {update_trusted_public_key}\n\n\
         [manage]\n\
         enabled = true\n\
         api_url = {api_url}\n\
         organization_id = {organization_id}\n\
         state_path = {state_path}\n\
         sync_interval_seconds = {sync_interval_seconds}\n\
         enrollment_poll_seconds = {enrollment_poll_seconds}\n\
         http_timeout_seconds = {http_timeout_seconds}\n",
        listen_addr = toml_string(&settings.listen_addr)?,
        public_base_url = toml_string(&settings.public_base_url)?,
        data_dir = toml_string(&config.paths.data_dir.display().to_string())?,
        database_path = toml_string(&config.paths.database_path.display().to_string())?,
        http_root = toml_string(&http_root)?,
        iso_dir = toml_string(&settings.http_root.join("isos").display().to_string())?,
        static_dir = toml_string(&settings.http_root.join("assets").display().to_string())?,
        tftp_root = toml_string(&tftp_root)?,
        bootloader_filename = toml_string(&settings.bootloader_filename)?,
        menu_timeout_ms = settings.menu_timeout_ms,
        build_enabled = config.build.enabled,
        max_concurrent_builds = config.build.max_concurrent_builds,
        build_timeout_seconds = config.build.timeout_seconds,
        cancel_grace_seconds = config.build.cancel_grace_seconds,
        max_log_bytes = config.build.max_log_bytes,
        max_artifact_size_bytes = config.build.max_artifact_size_bytes,
        allowed_systems = toml_string_array(&config.build.allowed_systems)?,
        build_work_dir = toml_string(&config.build.work_dir.display().to_string())?,
        build_output_dir = toml_string(&config.build.output_dir.display().to_string())?,
        nix_binary = toml_string(&config.build.nix_binary)?,
        build_targets = build_targets,
        cache_enabled = config.cache.enabled,
        cache_root = toml_string(&cache_root)?,
        signing_key_name = toml_string(&config.cache.signing_key_name)?,
        cache_private_key_path = toml_string(&config.cache.private_key_path.display().to_string())?,
        cache_public_key_path = toml_string(&config.cache.public_key_path.display().to_string())?,
        cache_max_bytes = config.cache.max_bytes,
        cache_retain_recent_builds = config.cache.retain_recent_builds,
        update_enabled = config.update.enabled,
        update_work_dir = toml_string(&config.update.work_dir.display().to_string())?,
        update_releases_dir = toml_string(&config.update.releases_dir.display().to_string())?,
        update_binary_path = toml_string(&config.update.binary_path.display().to_string())?,
        update_config_path = toml_string(&config.update.config_path.display().to_string())?,
        update_service_name = toml_string(&config.update.service_name)?,
        update_health_url = toml_string(&managed_update_health_url(&settings.listen_addr)?)?,
        update_max_artifact_size_bytes = config.update.max_artifact_size_bytes,
        update_trusted_public_key = toml_string(&config.update.trusted_public_key)?,
        api_url = toml_string(&config.manage.api_url)?,
        organization_id = toml_string(&organization_id(config)?)?,
        state_path = toml_string(&config.manage.state_path.display().to_string())?,
        sync_interval_seconds = config.manage.sync_interval_seconds,
        enrollment_poll_seconds = config.manage.enrollment_poll_seconds,
        http_timeout_seconds = config.manage.http_timeout_seconds,
    ))
}

fn render_nginx_config(settings: &NormalizedManagedSettings) -> String {
    let listen_addr = &settings.listen_addr;
    let http_root = settings.http_root.display();
    format!(
        r#"log_format cybex_forge_safe '$remote_addr [$time_local] "$request_method $uri $server_protocol" $status $body_bytes_sent';

server {{
    listen 80 default_server;
    server_name _;

    root {http_root};

    access_log /var/log/nginx/cybex-forge.access.log cybex_forge_safe;
    error_log  /var/log/nginx/cybex-forge.error.log crit;

    server_tokens off;
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;
    add_header Referrer-Policy no-referrer always;
    add_header Content-Security-Policy "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'" always;

    client_max_body_size 1k;
    client_body_timeout 5s;
    client_header_timeout 5s;
    keepalive_timeout 10s;
    large_client_header_buffers 4 8k;
    send_timeout 60s;

    if ($request_method !~ ^(GET|HEAD)$) {{
        return 405;
    }}

    location = /healthz {{
        proxy_pass http://{listen_addr};
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_hide_header X-Content-Type-Options;
        proxy_hide_header X-Frame-Options;
        proxy_hide_header Referrer-Policy;
        proxy_hide_header Content-Security-Policy;
        proxy_connect_timeout 2s;
        proxy_send_timeout 5s;
        proxy_read_timeout 5s;
    }}

    location = /boot.ipxe {{
        proxy_pass http://{listen_addr};
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_hide_header X-Content-Type-Options;
        proxy_hide_header X-Frame-Options;
        proxy_hide_header Referrer-Policy;
        proxy_hide_header Content-Security-Policy;
        proxy_connect_timeout 2s;
        proxy_send_timeout 10s;
        proxy_read_timeout 30s;
    }}

    location = /boot {{
        proxy_pass http://{listen_addr};
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_hide_header X-Content-Type-Options;
        proxy_hide_header X-Frame-Options;
        proxy_hide_header Referrer-Policy;
        proxy_hide_header Content-Security-Policy;
        proxy_connect_timeout 2s;
        proxy_send_timeout 10s;
        proxy_read_timeout 30s;
    }}

    location /boot/ {{
        proxy_pass http://{listen_addr};
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_hide_header X-Content-Type-Options;
        proxy_hide_header X-Frame-Options;
        proxy_hide_header Referrer-Policy;
        proxy_hide_header Content-Security-Policy;
        proxy_connect_timeout 2s;
        proxy_send_timeout 10s;
        proxy_read_timeout 30s;
    }}

    location /files/ {{
        proxy_pass http://{listen_addr};
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_hide_header X-Content-Type-Options;
        proxy_hide_header X-Frame-Options;
        proxy_hide_header Referrer-Policy;
        proxy_hide_header Content-Security-Policy;
        proxy_connect_timeout 2s;
        proxy_send_timeout 10s;
        proxy_read_timeout 300s;
        proxy_buffering off;
    }}

    location /cache/ {{
        proxy_pass http://{listen_addr};
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_hide_header X-Content-Type-Options;
        proxy_hide_header X-Frame-Options;
        proxy_hide_header Referrer-Policy;
        proxy_hide_header Content-Security-Policy;
        proxy_connect_timeout 2s;
        proxy_send_timeout 10s;
        proxy_read_timeout 300s;
        proxy_buffering off;
    }}

    location = / {{
        return 204;
    }}

    location / {{
        return 404;
    }}
}}
"#
    )
}

fn render_tftpd_defaults(settings: &NormalizedManagedSettings) -> String {
    format!(
        "TFTP_USERNAME=\"cybex-forge\"\n\
         TFTP_DIRECTORY=\"{}\"\n\
         TFTP_ADDRESS=\"0.0.0.0:69\"\n\
         TFTP_OPTIONS=\"--ipv4 --secure\"\n",
        settings.tftp_root.display()
    )
}

fn render_boot_write_paths_dropin(settings: &NormalizedManagedSettings) -> String {
    format!(
        "[Service]\nReadWritePaths=\nReadWritePaths=/var/lib/cybex-forge {}\n",
        settings.http_root.display()
    )
}

fn render_nginx_hardening_dropin(settings: &NormalizedManagedSettings) -> String {
    format!(
        "[Service]\n\
         AmbientCapabilities=\n\
         CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID CAP_DAC_OVERRIDE CAP_KILL\n\
         InaccessiblePaths=/etc/cybex-forge /var/lib/cybex-forge {}\n\
         LockPersonality=true\n\
         NoNewPrivileges=true\n\
         PrivateDevices=true\n\
         PrivateTmp=true\n\
         ProtectControlGroups=true\n\
         ProtectHome=true\n\
         ProtectKernelModules=true\n\
         ProtectKernelTunables=true\n\
         ProtectProc=invisible\n\
         ProtectSystem=strict\n\
         ProcSubset=pid\n\
         ReadOnlyPaths={}\n\
         ReadWritePaths=/run /var/lib/nginx /var/log/nginx\n\
         RemoveIPC=true\n\
         RestrictAddressFamilies=\n\
         RestrictAddressFamilies=AF_INET AF_UNIX\n\
         RestrictNamespaces=true\n\
         RestrictRealtime=true\n\
         RestrictSUIDSGID=true\n\
         UMask=0027\n",
        settings.tftp_root.display(),
        settings.http_root.display()
    )
}

fn render_tftpd_hardening_dropin(settings: &NormalizedManagedSettings) -> String {
    format!(
        "[Service]\n\
         AmbientCapabilities=\n\
         CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID CAP_SYS_CHROOT\n\
         InaccessiblePaths=/etc/cybex-forge /var/lib/cybex-forge {}\n\
         LockPersonality=true\n\
         MemoryDenyWriteExecute=true\n\
         NoNewPrivileges=true\n\
         ReadOnlyPaths={}\n\
         ProtectProc=invisible\n\
         ProcSubset=pid\n\
         RemoveIPC=true\n\
         RestrictAddressFamilies=\n\
         RestrictAddressFamilies=AF_INET AF_UNIX\n\
         RestrictNamespaces=true\n\
         RestrictRealtime=true\n\
         RestrictSUIDSGID=true\n\
         UMask=0077\n",
        settings.http_root.display(),
        settings.tftp_root.display()
    )
}

fn render_check_service(settings: &NormalizedManagedSettings) -> String {
    format!(
        r#"[Unit]
Description=Cybex Forge local health check
Wants=network-online.target
After=network-online.target cybex-forge.service nginx.service tftpd-hpa.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/cybex-forge-check --quiet
Nice=5
IOSchedulingClass=best-effort
IOSchedulingPriority=7
AmbientCapabilities=
CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID
LockPersonality=true
MemoryDenyWriteExecute=true
NoNewPrivileges=true
PrivateDevices=true
PrivateTmp=true
ProtectClock=true
ProtectControlGroups=true
ProtectHome=true
ProtectHostname=true
ProtectKernelLogs=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectProc=invisible
ProtectSystem=strict
ProcSubset=pid
ReadOnlyPaths=/etc/cybex-forge /etc/default/tftpd-hpa /etc/nginx {tftp_root}
ReadWritePaths=/run {http_root} /var/lib/cybex-forge /var/lib/nginx /var/log/nginx
RemoveIPC=true
RestrictAddressFamilies=
RestrictAddressFamilies=AF_INET AF_UNIX AF_NETLINK
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
SystemCallArchitectures=native
UMask=0077
"#,
        tftp_root = settings.tftp_root.display(),
        http_root = settings.http_root.display()
    )
}

fn ensure_bootloader_artifacts(settings: &NormalizedManagedSettings) -> Result<bool> {
    let mut changed = false;
    let bootloader = &settings.bootloader_filename;
    let distro_target = settings.tftp_root.join(format!("debian-{bootloader}"));
    if let Some(source) = distro_bootloader_candidate(bootloader) {
        changed |= install_existing_file_if_different(&source, &distro_target, "0444")?;
    }

    let target = settings.tftp_root.join(bootloader);
    if bootloader_supports_embedded_script(bootloader) {
        if !loader_embeds_boot_url(&target, &settings.public_base_url)? {
            changed |= build_embedded_ipxe_loader(settings)?;
        }
        if !loader_embeds_boot_url(&target, &settings.public_base_url)? {
            bail!(
                "TFTP bootloader {} does not embed {}/boot/${{mac}}",
                target.display(),
                settings.public_base_url
            );
        }
    } else if !target.is_file() {
        bail!("custom TFTP bootloader {} is missing", target.display());
    }

    changed |= prune_tftp_root(settings)?;
    changed |= write_tftp_checksums(settings)?;
    Ok(changed)
}

fn distro_bootloader_candidate(bootloader: &str) -> Option<PathBuf> {
    [
        format!("/usr/lib/ipxe/{bootloader}"),
        format!("/usr/lib/ipxe-qemu/{bootloader}"),
        format!("/usr/share/ipxe/{bootloader}"),
    ]
    .into_iter()
    .map(PathBuf::from)
    .find(|path| path.is_file())
    .or_else(|| {
        ["/usr/lib", "/usr/share"]
            .into_iter()
            .filter_map(|root| {
                find_first_bootloader_candidate(Path::new(root))
                    .ok()
                    .flatten()
            })
            .next()
    })
}

fn find_first_bootloader_candidate(root: &Path) -> Result<Option<PathBuf>> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        for entry in fs::read_dir(&path).with_context(|| format!("read {}", path.display()))? {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                stack.push(path);
            } else if file_type.is_file()
                && path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| matches!(name, "snponly.efi" | "ipxe.efi"))
            {
                return Ok(Some(path));
            }
        }
    }
    Ok(None)
}

fn bootloader_supports_embedded_script(bootloader: &str) -> bool {
    matches!(bootloader, "snponly.efi" | "ipxe.efi")
}

fn loader_embeds_boot_url(path: &Path, public_base_url: &str) -> Result<bool> {
    if !path.is_file() {
        return Ok(false);
    }
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let text = String::from_utf8_lossy(&bytes);
    Ok(text.contains(public_base_url)
        && text.contains("chain --autofree ${boot-url}/boot/${mac} || goto failed")
        && text.contains("exit 1")
        && !text.contains("echo Dropping to iPXE shell."))
}

fn build_embedded_ipxe_loader(settings: &NormalizedManagedSettings) -> Result<bool> {
    let ipxe_dir = Path::new("/usr/local/src/ipxe");
    if !ipxe_dir.join("src").is_dir() {
        install_dir(Path::new("/usr/local/src"), "0755", "root", "root")?;
        run_command(
            "git",
            [
                "clone",
                "--depth",
                "1",
                "https://github.com/ipxe/ipxe.git",
                "/usr/local/src/ipxe",
            ],
        )?;
    }
    let embed_script = temp_path(Path::new("/tmp"), "cybex-forge-embed.ipxe")?;
    fs::write(
        &embed_script,
        render_embedded_ipxe_script(&settings.public_base_url),
    )
    .with_context(|| format!("write {}", embed_script.display()))?;
    let jobs = std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(2)
        .to_string();
    let target_arg = format!("bin-x86_64-efi/{}", settings.bootloader_filename);
    let embed_arg = format!("EMBED={}", embed_script.display());
    let make_result = StdCommand::new("make")
        .current_dir(ipxe_dir.join("src"))
        .arg(format!("-j{jobs}"))
        .arg(&target_arg)
        .arg(&embed_arg)
        .output()
        .context("run make for embedded iPXE loader")?;
    let _ = fs::remove_file(&embed_script);
    if !make_result.status.success() {
        bail!(
            "embedded iPXE loader build failed: {}",
            String::from_utf8_lossy(&make_result.stderr).trim()
        );
    }
    let source = ipxe_dir
        .join("src")
        .join("bin-x86_64-efi")
        .join(&settings.bootloader_filename);
    install_existing_file_if_different(
        &source,
        &settings.tftp_root.join(&settings.bootloader_filename),
        "0444",
    )
}

fn render_embedded_ipxe_script(public_base_url: &str) -> String {
    format!(
        "#!ipxe\n\
         # Embedded chainloader for Cybex Forge UEFI PXE clients.\n\
         isset ${{net0/ip}} || dhcp || goto failed\n\
         set boot-url {public_base_url}\n\
         chain --autofree ${{boot-url}}/boot/${{mac}} || goto failed\n\n\
         :failed\n\
         echo Cybex Forge: failed to load ${{boot-url}}/boot/${{mac}}\n\
         echo Returning failure to UEFI firmware.\n\
         exit 1\n"
    )
}

fn prune_tftp_root(settings: &NormalizedManagedSettings) -> Result<bool> {
    let keep = HashSet::from([
        settings.bootloader_filename.clone(),
        format!("debian-{}", settings.bootloader_filename),
        "SHA256SUMS".to_string(),
    ]);
    let mut changed = false;
    for entry in fs::read_dir(&settings.tftp_root)
        .with_context(|| format!("read {}", settings.tftp_root.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if keep.contains(&name) {
            continue;
        }
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            fs::remove_dir_all(&path).with_context(|| format!("remove {}", path.display()))?;
            changed = true;
        } else {
            fs::remove_file(&path).with_context(|| format!("remove {}", path.display()))?;
            changed = true;
        }
    }
    Ok(changed)
}

fn write_tftp_checksums(settings: &NormalizedManagedSettings) -> Result<bool> {
    let mut lines = Vec::new();
    for name in [
        format!("debian-{}", settings.bootloader_filename),
        settings.bootloader_filename.clone(),
    ] {
        let path = settings.tftp_root.join(&name);
        if path.is_file() {
            let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            lines.push(format!("{}  {}\n", sha256_hex(&bytes), name));
        }
    }
    lines.sort();
    install_text_file(
        &settings.tftp_root.join("SHA256SUMS"),
        &lines.concat(),
        "0444",
        "root",
        "root",
    )
}

fn install_dir(path: &Path, mode: &str, owner: &str, group: &str) -> Result<()> {
    run_command_os(
        "install",
        [
            OsString::from("-d"),
            OsString::from("-m"),
            OsString::from(mode),
            OsString::from("-o"),
            OsString::from(owner),
            OsString::from("-g"),
            OsString::from(group),
            path.as_os_str().to_os_string(),
        ],
    )
}

fn install_text_file(
    path: &Path,
    contents: &str,
    mode: &str,
    owner: &str,
    group: &str,
) -> Result<bool> {
    install_bytes_file(path, contents.as_bytes(), mode, owner, group)
}

fn install_bytes_file(
    path: &Path,
    contents: &[u8],
    mode: &str,
    owner: &str,
    group: &str,
) -> Result<bool> {
    let changed = fs::read(path)
        .map(|current| current != contents)
        .unwrap_or(true);
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("{} has no parent directory", path.display()))?;
    fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    let tmp = temp_path(
        parent,
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("file"),
    )?;
    fs::write(&tmp, contents).with_context(|| format!("write {}", tmp.display()))?;
    let result = run_command_os(
        "install",
        [
            OsString::from("-m"),
            OsString::from(mode),
            OsString::from("-o"),
            OsString::from(owner),
            OsString::from("-g"),
            OsString::from(group),
            tmp.as_os_str().to_os_string(),
            path.as_os_str().to_os_string(),
        ],
    );
    let _ = fs::remove_file(&tmp);
    result?;
    sync_parent_dir(path)?;
    Ok(changed)
}

fn install_existing_file_if_different(source: &Path, target: &Path, mode: &str) -> Result<bool> {
    let bytes = fs::read(source).with_context(|| format!("read {}", source.display()))?;
    install_bytes_file(target, &bytes, mode, "root", "root")
}

fn temp_path(parent: &Path, label: &str) -> Result<PathBuf> {
    let mut random = [0u8; 8];
    OsRng.fill_bytes(&mut random);
    Ok(parent.join(format!(
        ".{label}.{}.{}.tmp",
        std::process::id(),
        hex::encode(random)
    )))
}

fn toml_string(value: &str) -> Result<String> {
    serde_json::to_string(value).context("serialize TOML string")
}

fn toml_string_array(values: &[String]) -> Result<String> {
    let encoded = values
        .iter()
        .map(|value| toml_string(value))
        .collect::<Result<Vec<_>>>()?
        .join(", ");
    Ok(format!("[{encoded}]"))
}

fn render_build_target_config(targets: &[crate::config::BuildTargetConfig]) -> Result<String> {
    let mut rendered = String::new();
    for target in targets {
        rendered.push_str("\n[[build.targets]]\n");
        rendered.push_str(&format!(
            "artifact_type = {}\n",
            toml_string(&target.artifact_type)?
        ));
        rendered.push_str(&format!("target = {}\n", toml_string(&target.target)?));
        rendered.push_str(&format!("system = {}\n", toml_string(&target.system)?));
        rendered.push_str(&format!("flake = {}\n", toml_string(&target.flake)?));
        rendered.push_str(&format!("attr = {}\n", toml_string(&target.attr)?));
    }
    Ok(rendered)
}

fn run_command<const N: usize>(program: &str, args: [&str; N]) -> Result<()> {
    run_command_os(program, args.map(OsString::from))
}

fn run_command_os<const N: usize>(program: &str, args: [OsString; N]) -> Result<()> {
    let output = StdCommand::new(program)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("run {program}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("{program} failed: {}", stderr.trim());
    }
    Ok(())
}

fn validate_managed_id(value: &str, field: &str) -> Result<()> {
    if value.trim().is_empty() {
        bail!("{field} is required");
    }
    if value.trim() != value {
        bail!("{field} must not contain surrounding whitespace");
    }
    Ok(())
}

fn validate_client_profile_reference(
    remote_id: Option<&str>,
    profiles_by_id: &HashMap<String, &ManagedBootProfile>,
) -> Result<()> {
    let Some(remote_id) = remote_id else {
        return Ok(());
    };
    if remote_id.trim().is_empty() {
        return Ok(());
    }
    let Some(profile) = profiles_by_id.get(remote_id) else {
        bail!("managed boot client references an unknown boot profile");
    };
    validate_assignable_profile(profile, "managed boot client profile assignment")
}

fn validate_assignable_profile(profile: &ManagedBootProfile, field: &str) -> Result<()> {
    if !profile.enabled {
        bail!("{field} must target an enabled profile");
    }
    if !managed_profile_has_boot_action(profile) {
        bail!("{field} must target a profile with a runnable boot action");
    }
    Ok(())
}

fn managed_profile_has_boot_action(profile: &ManagedBootProfile) -> bool {
    if profile
        .raw_script
        .as_deref()
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
    {
        return true;
    }
    match profile.profile_type.as_str() {
        "local_disk" => true,
        "linux_installer" | "iso_live"
            if normalized_installer_iso_source(&profile.installer_iso_source)
                == BOOT_PROFILE_ISO_SOURCE_ENROLLMENT =>
        {
            true
        }
        "linux_installer" | "iso_live" => {
            profile
                .kernel_path
                .as_deref()
                .map(|value| !value.trim().is_empty())
                .unwrap_or(false)
                || profile
                    .iso_path
                    .as_deref()
                    .map(|value| !value.trim().is_empty())
                    .unwrap_or(false)
                // A managed-ISO profile whose desired ISO is still syncing
                // becomes runnable once the artifact lands; manage assigns
                // clients to such profiles (network reinstall), so accept
                // the config instead of failing the whole sync.
                || managed_profile_needs_iso_sync(profile)
        }
        "custom_ipxe" => false,
        _ => false,
    }
}

fn validate_relative_path(value: Option<&str>, field: &str) -> Result<()> {
    if let Some(value) = value {
        if !value.trim().is_empty() {
            assets::sanitize_relative_path(value)
                .map_err(|_| anyhow!("{field} must be a relative boot asset path"))?;
        }
    }
    Ok(())
}

fn validate_cmdline(value: Option<&str>) -> Result<()> {
    if value
        .map(|value| value.chars().any(char::is_control))
        .unwrap_or(false)
    {
        bail!("managed boot profile cmdline must not contain control characters");
    }
    Ok(())
}

fn local_profile_id(
    remote_id: Option<&str>,
    profile_map: &HashMap<String, i64>,
) -> Result<Option<i64>> {
    let Some(remote_id) = remote_id else {
        return Ok(None);
    };
    if remote_id.trim().is_empty() {
        return Ok(None);
    }
    profile_map
        .get(remote_id)
        .copied()
        .map(Some)
        .ok_or_else(|| anyhow!("managed client references an unknown boot profile"))
}

fn clean_optional(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn clean_string(value: &str) -> String {
    value.trim().to_string()
}

fn default_installer_iso_source() -> String {
    BOOT_PROFILE_ISO_SOURCE_BOOT_PROFILE.to_string()
}

fn normalized_installer_iso_source(value: &str) -> &str {
    match value.trim() {
        BOOT_PROFILE_ISO_SOURCE_ENROLLMENT => BOOT_PROFILE_ISO_SOURCE_ENROLLMENT,
        _ => BOOT_PROFILE_ISO_SOURCE_BOOT_PROFILE,
    }
}

fn validate_installer_iso_source(value: &str) -> Result<()> {
    match value.trim() {
        BOOT_PROFILE_ISO_SOURCE_BOOT_PROFILE | BOOT_PROFILE_ISO_SOURCE_ENROLLMENT => Ok(()),
        _ => bail!("managed boot profile installer_iso_source is invalid"),
    }
}

fn validate_desired_iso_metadata(profile: &ManagedBootProfile) -> Result<()> {
    if !profile.desired_iso_filename.trim().is_empty() {
        managed_iso_filename(&profile.desired_iso_filename)?;
    }
    if profile.desired_iso_size_bytes < 0 {
        bail!("managed boot profile desired_iso_size_bytes must not be negative");
    }
    if !profile.desired_iso_sha256.trim().is_empty()
        && valid_sha256(&profile.desired_iso_sha256).is_none()
    {
        bail!("managed boot profile desired_iso_sha256 must be 64 hex characters");
    }
    if !profile.desired_iso_download_url.trim().is_empty() {
        managed_iso_download_path_with_base(
            &profile.desired_iso_download_url,
            Some("http://localhost"),
        )?;
    }
    Ok(())
}

fn managed_profile_iso_path(
    profile: &ManagedBootProfile,
    existing_iso_path: Option<&str>,
    raw_script: Option<&str>,
) -> Result<Option<String>> {
    if let Some(iso_path) = clean_optional(profile.iso_path.clone()) {
        return Ok(Some(iso_path));
    }
    if !managed_profile_needs_iso_sync(profile) {
        return Ok(None);
    }
    if raw_script
        .filter(|script| generated_iso_raw_script_can_be_preserved(script))
        .is_none()
    {
        return Ok(None);
    }
    let Some(existing_iso_path) = clean_optional(existing_iso_path.map(ToString::to_string)) else {
        return Ok(None);
    };
    validate_relative_path(Some(&existing_iso_path), "iso_path")?;
    Ok(Some(existing_iso_path))
}

fn managed_profile_raw_script(
    profile: &ManagedBootProfile,
    existing_raw_script: Option<&str>,
) -> Option<String> {
    if let Some(raw_script) = clean_optional(profile.raw_script.clone()) {
        return Some(raw_script);
    }
    if managed_profile_needs_iso_sync(profile) {
        return existing_raw_script
            .and_then(|value| clean_optional(Some(value.to_string())))
            .filter(|script| generated_iso_raw_script_can_be_preserved(script));
    }
    None
}

fn generated_iso_raw_script_can_be_preserved(script: &str) -> bool {
    if !script.contains("echo Cybex Forge: Default Enrollment")
        || !script.contains("/files/installers/")
        || !script.contains("kernel ")
        || !script.contains("initrd --name initrd ")
        || !script.lines().any(|line| line.trim() == "boot")
    {
        return false;
    }
    if script.contains("initrd=nixos-netboot.cpio") {
        return script.contains("initrd --name initrd ")
            && script.contains("initrd --name nixos-netboot.cpio ");
    }
    true
}

fn managed_profile_needs_iso_sync(profile: &ManagedBootProfile) -> bool {
    !profile.desired_iso_artifact_id.trim().is_empty()
        && !profile.desired_iso_filename.trim().is_empty()
        && profile.desired_iso_size_bytes > 0
        && !profile.desired_iso_sha256.trim().is_empty()
        && !profile.desired_iso_download_url.trim().is_empty()
        && (normalized_installer_iso_source(&profile.installer_iso_source)
            == BOOT_PROFILE_ISO_SOURCE_ENROLLMENT
            || matches!(
                profile.profile_type.as_str(),
                "linux_installer" | "iso_live"
            ))
}

fn valid_sha256(value: &str) -> Option<String> {
    let checksum = value.trim().to_ascii_lowercase();
    if checksum.len() == 64 && checksum.chars().all(|ch| ch.is_ascii_hexdigit()) {
        Some(checksum)
    } else {
        None
    }
}

fn bool_to_i64(value: bool) -> i64 {
    if value { 1 } else { 0 }
}

fn asset_scan_report(result: crate::error::AppResult<usize>) -> AssetScanReport {
    match result {
        Ok(count) => AssetScanReport {
            status: "ok",
            scanned_count: Some(count),
            error: None,
        },
        Err(err) => AssetScanReport {
            status: "failed",
            scanned_count: None,
            error: Some(bounded_error_message(err.to_string())),
        },
    }
}

fn boot_report_state(
    profile_count: usize,
    client_count: usize,
    asset_count: usize,
    asset_scan: &AssetScanReport,
    reliability_state: Option<Value>,
) -> Value {
    let mut state = json!({
        "managed": true,
        "profile_count": profile_count,
        "client_count": client_count,
        "asset_count": asset_count,
        "asset_scan_status": asset_scan.status,
    });
    if let Some(object) = state.as_object_mut() {
        if let Some(scanned_count) = asset_scan.scanned_count {
            object.insert("asset_scan_count".to_string(), json!(scanned_count));
        }
        if let Some(error) = &asset_scan.error {
            object.insert("asset_scan_error".to_string(), json!(error));
        }
        if let Some(reliability) = reliability_state {
            object.insert("reliability".to_string(), reliability);
        }
    }
    state
}

fn load_reliability_state() -> Option<Value> {
    let bytes = fs::read(RELIABILITY_STATE_PATH).ok()?;
    if bytes.len() > MAX_RELIABILITY_STATE_BYTES {
        warn!(
            path = RELIABILITY_STATE_PATH,
            bytes = bytes.len(),
            "ignoring oversized Forge reliability state"
        );
        return None;
    }
    match serde_json::from_slice::<Value>(&bytes) {
        Ok(Value::Object(object)) => Some(Value::Object(object)),
        Ok(_) => {
            warn!(
                path = RELIABILITY_STATE_PATH,
                "ignoring non-object Forge reliability state"
            );
            None
        }
        Err(err) => {
            warn!(path = RELIABILITY_STATE_PATH, error = %err, "ignoring invalid Forge reliability state");
            None
        }
    }
}

fn bounded_error_message(message: String) -> String {
    const MAX_ERROR_LEN: usize = 240;
    let cleaned = message.replace(['\n', '\r'], " ");
    let trimmed = cleaned.trim();
    if trimmed.chars().count() <= MAX_ERROR_LEN {
        return trimmed.to_string();
    }
    let truncated = trimmed.chars().take(MAX_ERROR_LEN).collect::<String>();
    format!("{truncated}...")
}

fn is_safe_path_segment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        && !value.contains("..")
}

fn is_valid_header_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value
            .bytes()
            .all(|byte| matches!(byte, 0x21..=0x7e) && byte != b'"' && byte != b'\\')
}

fn safe_error(err: &anyhow::Error) -> String {
    let text = err.to_string();
    for sensitive in ["managed_token", "enrollment_secret", "private_key"] {
        if text.to_ascii_lowercase().contains(sensitive) {
            return "managed sync failed; see service configuration".to_string();
        }
    }
    text
}

#[cfg(test)]
mod tests {
    use super::{
        AgentBootConfigResponse, BootAgentAssetReport, BootAgentClientReport, BootAgentEventReport,
        BootAgentReportRequest, BootAgentSettingsReport, CYBEX_COMPONENT_PROTOCOL_VERSION,
        CYBEX_MINIMUM_MANAGE_PROTOCOL_VERSION, ComponentCompatibilityContract, EnrollmentResponse,
        ExpectedUpdateReport, FORGE_REPORT_SCOPE_UPDATE_ONLY, ForgeReportReceipt,
        MAX_DEVICE_HOSTNAME_CHARS, MAX_DEVICE_NOTES_CHARS, MAX_DEVICE_SERIAL_CHARS,
        MAX_DEVICE_TAGS, MAX_MANAGED_CLIENTS, MAX_MANAGED_PROFILES, MAX_PROFILE_DESCRIPTION_CHARS,
        MAX_PROFILE_RAW_SCRIPT_BYTES, MAX_REPORT_CLIENTS, ManagedBootClient, ManagedBootProfile,
        ManagedBootSettings, ManagedState, NIXOS_NETBOOT_INITRD_FORMAT,
        NIXOS_NETBOOT_SPLIT_INITRD_FORMAT, NixosNetbootManifest, NormalizedManagedSettings,
        SyncOnceDisposition, SyncOnceReport, SyncOnceUpdaterReport, acquire_managed_state_lock,
        active_managed_sync_interval_seconds, api_url_for_config,
        append_bounded_response_chunk_with_limit, apply_enrollment_response, asset_scan_report,
        boot_report_state, bounded_error_message, bounded_http_timeout_seconds,
        canonical_agent_payload, clean_optional, current_boot_client_reports,
        current_profile_sync_reports, enrollment_request_signature, enrollment_status_signature,
        ensure_key_material, failed_sync_interval_seconds, fit_boot_report_body,
        forge_capabilities, generated_iso_raw_script_can_be_preserved,
        has_unreported_known_profile_events, managed_api_error_detail,
        managed_iso_error_is_retryable, managed_iso_retry_delay_seconds, managed_profile_map,
        managed_profile_needs_iso_sync, managed_profile_raw_script, managed_state_lock_path,
        managed_sync_interval_seconds, nixos_netboot_fstab, normalize_legacy_boot_config,
        normalize_managed_settings, optional_report_uuid, parse_nixos_netboot_ipxe_cmdline,
        parse_nixos_netboot_split_squashfs_capability, patch_nixos_netboot_squashfs_fstab,
        patch_nixos_netboot_squashfs_graphical_kiosk, patch_nixos_netboot_squashfs_injected_config,
        read_newc_entry_start, read_valid_netboot_manifest, render_check_service,
        render_managed_config, render_nixos_netboot_script, request_path_and_query,
        rewrite_newc_archive_with_netboot_files, runtime_managed_files, serialize_boot_report_body,
        sha256_hex, signed_request_for_config, skip_padding, sync_clients, sync_deleted_clients,
        sync_deleted_profiles, sync_profiles, sync_update_report_once, validate_boot_config,
        validate_component_compatibility, validate_expected_update_report,
        validate_forge_report_receipt, validate_profile, validate_update_only_sync_report,
        write_newc_file_from_bytes, write_newc_trailer, write_secure_json,
    };
    use crate::error::AppError;
    use crate::{
        AppState, boot,
        config::{AppConfig, ManageConfig},
        db,
        models::{CreateDeviceRequest, NewBootEvent},
    };
    use axum::{Json, Router, body::Bytes, extract::State, http::HeaderMap, routing::post};
    use base64::{
        Engine as _,
        engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    };
    use ed25519_dalek::{Signature, SigningKey, Verifier};
    use rand::{RngCore, rngs::OsRng};
    use reqwest::Method;
    use std::{
        collections::HashMap,
        fs,
        io::{BufReader, Read},
        path::{Path, PathBuf},
        sync::{Arc, Mutex},
    };
    use tokio::{net::TcpListener, sync::oneshot};
    use uuid::Uuid;

    type UpdateOnlyCapture =
        Arc<Mutex<Option<oneshot::Sender<(HeaderMap, Vec<u8>, serde_json::Value)>>>>;

    async fn capture_update_only_report(
        State(capture): State<UpdateOnlyCapture>,
        headers: HeaderMap,
        body: Bytes,
    ) -> Json<serde_json::Value> {
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let status = value["update"]["status"].as_str().unwrap().to_string();
        let attempt_id = value["update"]["attempt_id"].as_str().unwrap().to_string();
        if let Some(sender) = capture.lock().unwrap().take() {
            sender
                .send((headers, body.to_vec(), value))
                .map_err(|_| ())
                .unwrap();
        }
        Json(serde_json::json!({
            "status": "ok",
            "report_scope": "update_only",
            "update": true,
            "persisted_update": {
                "status": status,
                "attempt_id": attempt_id,
                "reported_at": "2026-07-23T10:00:00Z"
            }
        }))
    }

    #[test]
    fn enrollment_request_signature_proves_the_exact_body() {
        let signing = SigningKey::from_bytes(&[7_u8; 32]);
        let managed = ManagedState {
            private_key_b64: Some(STANDARD.encode(signing.to_bytes())),
            ..ManagedState::default()
        };
        let timestamp = "2026-07-22T00:00:00Z";
        let request_id = "req_enrollment_proof";
        let body = br#"{"device_kind":"cybex-forge"}"#;
        let encoded = enrollment_request_signature(
            &managed,
            "/v1/agent/enrollments",
            timestamp,
            request_id,
            body,
        )
        .expect("sign enrollment body");
        let signature = Signature::from_slice(
            &URL_SAFE_NO_PAD
                .decode(encoded)
                .expect("decode enrollment signature"),
        )
        .expect("parse enrollment signature");
        let canonical = canonical_agent_payload(
            "POST",
            "/v1/agent/enrollments",
            timestamp,
            request_id,
            &sha256_hex(body),
        );

        signing
            .verifying_key()
            .verify(canonical.as_bytes(), &signature)
            .expect("signature verifies for exact body");
        let changed = canonical_agent_payload(
            "POST",
            "/v1/agent/enrollments",
            timestamp,
            request_id,
            &sha256_hex(br#"{"device_kind":"nixos"}"#),
        );
        assert!(
            signing
                .verifying_key()
                .verify(changed.as_bytes(), &signature)
                .is_err()
        );
    }

    #[test]
    fn pending_enrollment_status_signature_proves_exact_empty_get() {
        let signing = SigningKey::from_bytes(&[9_u8; 32]);
        let managed = ManagedState {
            private_key_b64: Some(STANDARD.encode(signing.to_bytes())),
            ..ManagedState::default()
        };
        let path = "/v1/agent/enrollments/enrollment-123/status";
        let timestamp = "2026-07-22T00:00:00Z";
        let request_id = "req_pending_status";
        let encoded = enrollment_status_signature(&managed, path, timestamp, request_id)
            .expect("sign pending enrollment status poll");
        let signature = Signature::from_slice(
            &URL_SAFE_NO_PAD
                .decode(encoded)
                .expect("decode enrollment status signature"),
        )
        .expect("parse enrollment status signature");
        let canonical =
            canonical_agent_payload("GET", path, timestamp, request_id, &sha256_hex([]));
        signing
            .verifying_key()
            .verify(canonical.as_bytes(), &signature)
            .expect("signature verifies for exact empty GET");

        let wrong_path = canonical_agent_payload(
            "GET",
            "/v1/agent/enrollments/other/status",
            timestamp,
            request_id,
            &sha256_hex([]),
        );
        assert!(
            signing
                .verifying_key()
                .verify(wrong_path.as_bytes(), &signature)
                .is_err()
        );
    }

    #[tokio::test]
    async fn signed_requests_canonicalize_the_final_prefixed_path_and_query() {
        let signing = SigningKey::from_bytes(&[11_u8; 32]);
        let managed = ManagedState {
            device_id: Some("forge-123".to_string()),
            private_key_b64: Some(STANDARD.encode(signing.to_bytes())),
            ..ManagedState::default()
        };
        let mut config = AppConfig::default();
        config.manage.api_url = "https://manage.example.invalid/api".to_string();
        config.manage.organization_id = "org-123".to_string();
        let relative = "/v1/agent/devices/forge-123/config?cursor=a%2Fb";
        let body = br#"{"status":"ready"}"#.to_vec();
        let request =
            signed_request_for_config(&config, &managed, Method::POST, relative, body.clone())
                .await
                .unwrap()
                .build()
                .unwrap();
        let signed_path = request_path_and_query(request.url().as_str()).unwrap();
        assert_eq!(
            signed_path,
            "/api/v1/agent/devices/forge-123/config?cursor=a%2Fb"
        );
        let timestamp = request.headers()["x-cybex-timestamp"].to_str().unwrap();
        let request_id = request.headers()["x-cybex-request-id"].to_str().unwrap();
        let signature = Signature::from_slice(
            &URL_SAFE_NO_PAD
                .decode(request.headers()["x-cybex-signature"].to_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        let canonical = canonical_agent_payload(
            "POST",
            &signed_path,
            timestamp,
            request_id,
            &sha256_hex(&body),
        );
        signing
            .verifying_key()
            .verify(canonical.as_bytes(), &signature)
            .expect("signature covers the URL prefix and query sent on the wire");
        let unprefixed =
            canonical_agent_payload("POST", relative, timestamp, request_id, &sha256_hex(&body));
        assert!(
            signing
                .verifying_key()
                .verify(unprefixed.as_bytes(), &signature)
                .is_err()
        );

        let enrollment_endpoint = api_url_for_config(&config, "/v1/agent/enrollments").unwrap();
        let enrollment_path = request_path_and_query(&enrollment_endpoint).unwrap();
        assert_eq!(enrollment_path, "/api/v1/agent/enrollments");
        let enrollment_signature = enrollment_request_signature(
            &managed,
            &enrollment_path,
            "2026-07-22T00:00:00Z",
            "req_prefixed_enrollment",
            &body,
        )
        .unwrap();
        let enrollment_signature =
            Signature::from_slice(&URL_SAFE_NO_PAD.decode(enrollment_signature).unwrap()).unwrap();
        let enrollment_canonical = canonical_agent_payload(
            "POST",
            "/api/v1/agent/enrollments",
            "2026-07-22T00:00:00Z",
            "req_prefixed_enrollment",
            &sha256_hex(&body),
        );
        signing
            .verifying_key()
            .verify(enrollment_canonical.as_bytes(), &enrollment_signature)
            .expect("enrollment signature covers the configured API prefix");

        let status_path = "/api/v1/agent/enrollments/enrollment-123/status";
        let status_signature = enrollment_status_signature(
            &managed,
            status_path,
            "2026-07-22T00:00:00Z",
            "req_prefixed_status",
        )
        .unwrap();
        let status_signature =
            Signature::from_slice(&URL_SAFE_NO_PAD.decode(status_signature).unwrap()).unwrap();
        let status_canonical = canonical_agent_payload(
            "GET",
            status_path,
            "2026-07-22T00:00:00Z",
            "req_prefixed_status",
            &sha256_hex([]),
        );
        signing
            .verifying_key()
            .verify(status_canonical.as_bytes(), &status_signature)
            .expect("pending status signature covers the configured API prefix");
    }

    #[cfg(unix)]
    #[test]
    fn managed_state_lock_is_adjacent_and_exclusive() {
        use std::os::unix::fs::PermissionsExt;

        let root = temp_state_dir();
        let mut config = AppConfig::default();
        config.manage.state_path = root.join("manage-state.json");
        assert_eq!(
            managed_state_lock_path(&config).unwrap(),
            root.join("manage-state.json.lock")
        );

        let lock_path = managed_state_lock_path(&config).unwrap();
        fs::write(&lock_path, []).unwrap();
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o666)).unwrap();
        let first = acquire_managed_state_lock(&config).expect("acquire first state lock");
        assert_eq!(
            fs::metadata(&lock_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        // Model the descriptor copy that exists briefly between a concurrent
        // fork and exec. Dropping the guard must explicitly unlock even while
        // that inherited open-file description is still alive.
        let inherited = first
            .0
            .try_clone()
            .expect("duplicate state lock descriptor");
        assert!(acquire_managed_state_lock(&config).is_err());
        drop(first);
        let second = acquire_managed_state_lock(&config)
            .expect("state lock guard explicitly releases inherited descriptors");
        drop(inherited);
        assert!(acquire_managed_state_lock(&config).is_err());
        drop(second);
        acquire_managed_state_lock(&config).expect("state lock releases with file handle");
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn managed_state_lock_rejects_symlinks_and_nonregular_paths() {
        use std::{
            ffi::CString,
            os::unix::{
                ffi::OsStrExt,
                fs::{PermissionsExt, symlink},
            },
            time::{Duration, Instant},
        };

        let root = temp_state_dir();
        let mut config = AppConfig::default();
        config.manage.state_path = root.join("manage-state.json");
        fs::create_dir_all(&root).unwrap();
        let lock_path = managed_state_lock_path(&config).unwrap();
        let target = root.join("unrelated-target");
        fs::write(&target, []).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
        symlink(&target, &lock_path).unwrap();

        assert!(acquire_managed_state_lock(&config).is_err());
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o644,
            "a rejected symlink must never chmod its target"
        );

        fs::remove_file(&lock_path).unwrap();
        fs::create_dir(&lock_path).unwrap();
        assert!(acquire_managed_state_lock(&config).is_err());

        fs::remove_dir(&lock_path).unwrap();
        let fifo = CString::new(lock_path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let started = Instant::now();
        assert!(acquire_managed_state_lock(&config).is_err());
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "opening a hostile FIFO must not block before metadata validation"
        );

        fs::remove_file(&lock_path).unwrap();
        let hard_link_target = root.join("hard-link-target");
        fs::write(&hard_link_target, []).unwrap();
        fs::hard_link(&hard_link_target, &lock_path).unwrap();
        assert!(acquire_managed_state_lock(&config).is_err());
        let _ = fs::remove_dir_all(root);
    }

    fn sample_netboot_manifest(
        iso_sha256: &str,
        format: &str,
        squashfs_path: &str,
        squashfs_sha256: &str,
    ) -> NixosNetbootManifest {
        NixosNetbootManifest {
            iso_sha256: iso_sha256.to_string(),
            kernel_iso_path: "/boot/kernel".to_string(),
            initrd_iso_path: "/boot/initrd".to_string(),
            initrd_fstab_path: "nix/store/example-initrd-fstab".to_string(),
            cmdline: "root=fstab quiet".to_string(),
            kernel_path: "installers/example/bzImage".to_string(),
            initrd_path: "installers/example/initrd".to_string(),
            netboot_cpio_path: String::new(),
            netboot_initrd_format: format.to_string(),
            squashfs_path: squashfs_path.to_string(),
            squashfs_sha256: squashfs_sha256.to_string(),
        }
    }

    fn read_newc_archive_entries(path: &Path) -> Vec<(String, Vec<u8>)> {
        let input = fs::File::open(path).unwrap();
        let mut reader = BufReader::new(input);
        let mut entries = Vec::new();
        loop {
            let entry = read_newc_entry_start(&mut reader).unwrap().unwrap();
            if entry.name == "TRAILER!!!" {
                break;
            }
            let mut data = vec![0u8; entry.file_size as usize];
            reader.read_exact(&mut data).unwrap();
            skip_padding(&mut reader, entry.file_size).unwrap();
            entries.push((entry.name, data));
        }
        entries
    }

    #[test]
    fn failed_sync_backoff_grows_and_caps_at_normal_interval() {
        let config = ManageConfig {
            sync_interval_seconds: 30,
            ..ManageConfig::default()
        };

        assert_eq!(failed_sync_interval_seconds(&config, 1), 5);
        assert_eq!(failed_sync_interval_seconds(&config, 2), 10);
        assert_eq!(failed_sync_interval_seconds(&config, 3), 20);
        assert_eq!(failed_sync_interval_seconds(&config, 4), 30);
        assert_eq!(failed_sync_interval_seconds(&config, 100), 30);
    }

    #[test]
    fn active_builds_accelerate_managed_status_sync() {
        assert_eq!(active_managed_sync_interval_seconds(30, true), 5);
        assert_eq!(active_managed_sync_interval_seconds(5, true), 5);
        assert_eq!(active_managed_sync_interval_seconds(30, false), 30);
    }

    #[test]
    fn asset_scan_success_is_reported_as_ok() {
        let scan = asset_scan_report(Ok(4));
        let state = boot_report_state(2, 3, 4, &scan, None);

        assert_eq!(scan.status, "ok");
        assert_eq!(
            state.pointer("/asset_scan_status").and_then(|v| v.as_str()),
            Some("ok")
        );
        assert_eq!(
            state.pointer("/asset_scan_count").and_then(|v| v.as_u64()),
            Some(4)
        );
        assert!(state.pointer("/asset_scan_error").is_none());
    }

    #[test]
    fn asset_scan_failure_is_reported_without_dropping_asset_count() {
        let scan = asset_scan_report(Err(AppError::Config("scan\nfailed".to_string())));
        let state = boot_report_state(2, 3, 7, &scan, None);

        assert_eq!(scan.status, "failed");
        assert_eq!(
            state.pointer("/asset_scan_status").and_then(|v| v.as_str()),
            Some("failed")
        );
        assert_eq!(
            state.pointer("/asset_count").and_then(|v| v.as_u64()),
            Some(7)
        );
        assert_eq!(
            state.pointer("/asset_scan_error").and_then(|v| v.as_str()),
            Some("configuration error: scan failed")
        );
        assert!(state.pointer("/asset_scan_count").is_none());
    }

    #[test]
    fn reliability_incident_is_included_in_managed_report_state() {
        let scan = asset_scan_report(Ok(1));
        let reliability = serde_json::json!({
            "status": "degraded",
            "last_component": "dns",
            "total_repairs": 2
        });
        let state = boot_report_state(1, 0, 1, &scan, Some(reliability));

        assert_eq!(
            state
                .pointer("/reliability/status")
                .and_then(|value| value.as_str()),
            Some("degraded")
        );
        assert_eq!(
            state
                .pointer("/reliability/total_repairs")
                .and_then(|value| value.as_u64()),
            Some(2)
        );
    }

    #[test]
    fn bounded_error_message_removes_line_breaks_and_caps_length() {
        let message = format!("{}\n{}", "x".repeat(300), "tail");
        let bounded = bounded_error_message(message);

        assert_eq!(bounded.chars().count(), 243);
        assert!(bounded.ends_with("..."));
        assert!(!bounded.contains('\n'));
    }

    #[test]
    fn managed_api_error_detail_is_bounded_and_redacts_secrets() {
        let body = serde_json::to_vec(&serde_json::json!({
            "error_code": "invalid_request",
            "error": format!("invalid report token=top-secret\n{}", "x".repeat(300)),
        }))
        .unwrap();

        let detail = managed_api_error_detail(&body).unwrap();

        assert!(detail.starts_with("invalid_request: invalid report token=[REDACTED]"));
        assert!(detail.ends_with("..."));
        assert!(!detail.contains("top-secret"));
        assert!(!detail.contains('\n'));
    }

    #[test]
    fn managed_api_error_detail_ignores_unstructured_bodies() {
        assert_eq!(managed_api_error_detail(b"not json"), None);
        assert_eq!(managed_api_error_detail(br#"{"error":42}"#), None);
    }

    #[test]
    fn nixos_netboot_script_declares_each_initrd_for_uefi() {
        let script = render_nixos_netboot_script(
            &NixosNetbootManifest {
                iso_sha256: "a".repeat(64),
                kernel_iso_path: "/boot/kernel".to_string(),
                initrd_iso_path: "/boot/initrd".to_string(),
                initrd_fstab_path: "nix/store/example-initrd-fstab".to_string(),
                cmdline: "root=fstab quiet".to_string(),
                kernel_path: "installers/example/bzImage".to_string(),
                initrd_path: "installers/example/initrd".to_string(),
                netboot_cpio_path: "installers/example/nixos-netboot.cpio".to_string(),
                netboot_initrd_format: String::new(),
                squashfs_path: String::new(),
                squashfs_sha256: String::new(),
            },
            "http://boot.example",
        )
        .unwrap();

        assert!(script.contains(
            "kernel http://boot.example/files/installers/example/bzImage initrd=initrd initrd=nixos-netboot.cpio root=fstab quiet"
        ));
        assert!(
            script.contains(
                "initrd --name initrd http://boot.example/files/installers/example/initrd"
            )
        );
        assert!(script.contains(
            "initrd --name nixos-netboot.cpio http://boot.example/files/installers/example/nixos-netboot.cpio"
        ));
        assert!(!script.contains("/initrd initrd"));
        assert!(!script.contains("/nixos-netboot.cpio nixos-netboot.cpio"));
    }

    #[test]
    fn prebuilt_nixos_netboot_script_declares_single_initrd_for_uefi() {
        let script = render_nixos_netboot_script(
            &NixosNetbootManifest {
                iso_sha256: "a".repeat(64),
                kernel_iso_path: String::new(),
                initrd_iso_path: String::new(),
                initrd_fstab_path: String::new(),
                cmdline: "root=fstab quiet".to_string(),
                kernel_path: "installers/example-nix-netboot/bzImage".to_string(),
                initrd_path: "installers/example-nix-netboot/initrd".to_string(),
                netboot_cpio_path: String::new(),
                netboot_initrd_format: "prebuilt-single-initrd".to_string(),
                squashfs_path: String::new(),
                squashfs_sha256: String::new(),
            },
            "http://boot.example",
        )
        .unwrap();

        assert!(script.contains(
            "kernel http://boot.example/files/installers/example-nix-netboot/bzImage initrd=initrd root=fstab quiet"
        ));
        assert!(script.contains(
            "initrd --name initrd http://boot.example/files/installers/example-nix-netboot/initrd"
        ));
        assert!(!script.contains("initrd=nixos-netboot.cpio"));
    }

    #[test]
    fn netboot_caps_json_detects_split_squashfs_format() {
        assert!(
            parse_nixos_netboot_split_squashfs_capability(
                br#"{"initrd_squashfs_fetch":true,"formats":["zstd-split-squashfs-v14","zstd-combined-newc-v13"]}"#
            )
            .unwrap()
        );
        assert!(
            !parse_nixos_netboot_split_squashfs_capability(br#"{"initrd_squashfs_fetch":true}"#)
                .unwrap()
        );
        assert!(parse_nixos_netboot_split_squashfs_capability(b"{").is_err());
    }

    #[test]
    fn split_nixos_netboot_script_adds_squashfs_cmdline_params() {
        let script = render_nixos_netboot_script(
            &NixosNetbootManifest {
                iso_sha256: "a".repeat(64),
                kernel_iso_path: "/boot/kernel".to_string(),
                initrd_iso_path: "/boot/initrd".to_string(),
                initrd_fstab_path: "nix/store/example-initrd-fstab".to_string(),
                cmdline: "root=fstab quiet".to_string(),
                kernel_path: "installers/example/bzImage".to_string(),
                initrd_path: "installers/example/initrd".to_string(),
                netboot_cpio_path: String::new(),
                netboot_initrd_format: NIXOS_NETBOOT_SPLIT_INITRD_FORMAT.to_string(),
                squashfs_path: "installers/example/nix-store.squashfs".to_string(),
                squashfs_sha256: "b".repeat(64),
            },
            "http://boot.example",
        )
        .unwrap();

        assert!(script.contains(
            "kernel http://boot.example/files/installers/example/bzImage initrd=initrd root=fstab quiet cybex.squashfs_url=http://boot.example/files/installers/example/nix-store.squashfs cybex.squashfs_sha256="
        ));
        assert!(script.contains(&"b".repeat(64)));
        assert!(
            script.contains(
                "initrd --name initrd http://boot.example/files/installers/example/initrd"
            )
        );
        assert!(!script.contains("initrd=nixos-netboot.cpio"));
    }

    #[test]
    fn netboot_manifest_validation_tracks_iso_split_capability() {
        let mut random = [0u8; 8];
        OsRng.fill_bytes(&mut random);
        let dir =
            std::env::temp_dir().join(format!("cybex-forge-manifest-test-{}", hex::encode(random)));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("bzImage"), b"kernel").unwrap();
        fs::write(dir.join("initrd"), b"initrd").unwrap();
        fs::write(dir.join("nix-store.squashfs"), b"squashfs").unwrap();
        let manifest_path = dir.join("netboot-manifest.json");
        let iso_sha256 = "a".repeat(64);

        let mut manifest = sample_netboot_manifest(
            &iso_sha256,
            NIXOS_NETBOOT_SPLIT_INITRD_FORMAT,
            &format!("installers/{iso_sha256}/nix-store.squashfs"),
            &"b".repeat(64),
        );
        fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        assert!(
            read_valid_netboot_manifest(&manifest_path, &dir, &iso_sha256, true)
                .unwrap()
                .is_some()
        );
        assert!(
            read_valid_netboot_manifest(&manifest_path, &dir, &iso_sha256, false)
                .unwrap()
                .is_none()
        );

        manifest.squashfs_sha256 = "not-a-sha".to_string();
        fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        assert!(
            read_valid_netboot_manifest(&manifest_path, &dir, &iso_sha256, true)
                .unwrap()
                .is_none()
        );

        manifest = sample_netboot_manifest(&iso_sha256, NIXOS_NETBOOT_INITRD_FORMAT, "", "");
        fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        assert!(
            read_valid_netboot_manifest(&manifest_path, &dir, &iso_sha256, false)
                .unwrap()
                .is_some()
        );
        assert!(
            read_valid_netboot_manifest(&manifest_path, &dir, &iso_sha256, true)
                .unwrap()
                .is_none()
        );

        fs::remove_file(dir.join("nix-store.squashfs")).unwrap();
        manifest = sample_netboot_manifest(
            &iso_sha256,
            NIXOS_NETBOOT_SPLIT_INITRD_FORMAT,
            &format!("installers/{iso_sha256}/nix-store.squashfs"),
            &"b".repeat(64),
        );
        fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        assert!(
            read_valid_netboot_manifest(&manifest_path, &dir, &iso_sha256, true)
                .unwrap()
                .is_none()
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn prebuilt_nixos_netboot_cmdline_strips_ipxe_initrd_token() {
        let cmdline = parse_nixos_netboot_ipxe_cmdline(
            "#!ipxe\n\
             kernel bzImage init=/nix/store/example-system/init initrd=initrd quiet root=fstab ${cmdline}\n\
             initrd initrd\n\
             boot\n",
        )
        .unwrap();

        assert_eq!(
            cmdline,
            "init=/nix/store/example-system/init quiet root=fstab"
        );
    }

    #[test]
    fn netboot_squashfs_fstab_patch_removes_iso_mounts() {
        let mut random = [0u8; 8];
        OsRng.fill_bytes(&mut random);
        let dir =
            std::env::temp_dir().join(format!("cybex-forge-fstab-test-{}", hex::encode(random)));
        fs::create_dir_all(&dir).unwrap();
        let fstab_path = dir.join("abc123-etc-fstab");
        fs::write(
            &fstab_path,
            "# generated\n\
             tmpfs / tmpfs x-initrd.mount,mode=0755 0 0\n\
             /dev/disk/by-label/nixos-minimal-26.05-x86_64 /iso iso9660 x-initrd.mount 0 0\n\
             /sysroot/iso/nix-store.squashfs /nix/.ro-store squashfs x-initrd.mount,loop,threads=multi 0 0\n\
             tmpfs /nix/.rw-store tmpfs x-initrd.mount,mode=0755 0 0\n",
        )
        .unwrap();

        patch_nixos_netboot_squashfs_fstab(&dir).unwrap();
        let rewritten = fs::read_to_string(&fstab_path).unwrap();

        assert_eq!(rewritten, nixos_netboot_fstab());
        assert!(!rewritten.contains("/dev/disk/by-label/"));
        assert!(!rewritten.contains("/sysroot/iso/"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn newc_rewrite_without_squashfs_replaces_fstab_only() {
        let mut random = [0u8; 8];
        OsRng.fill_bytes(&mut random);
        let dir =
            std::env::temp_dir().join(format!("cybex-forge-newc-test-{}", hex::encode(random)));
        fs::create_dir_all(&dir).unwrap();
        let source = dir.join("source.cpio");
        let destination = dir.join("destination.cpio");
        {
            let mut file = fs::File::create(&source).unwrap();
            write_newc_file_from_bytes(&mut file, "keep-me", b"unchanged", 0o100644, 1).unwrap();
            write_newc_file_from_bytes(
                &mut file,
                "nix/store/example-initrd-fstab",
                b"old fstab",
                0o100644,
                2,
            )
            .unwrap();
            write_newc_trailer(&mut file).unwrap();
        }

        rewrite_newc_archive_with_netboot_files(
            &source,
            &destination,
            None,
            "nix/store/example-initrd-fstab",
        )
        .unwrap();

        let entries = read_newc_archive_entries(&destination);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0], ("keep-me".to_string(), b"unchanged".to_vec()));
        assert_eq!(
            entries[1],
            (
                "nix/store/example-initrd-fstab".to_string(),
                nixos_netboot_fstab().into_bytes()
            )
        );
        assert!(
            entries
                .iter()
                .all(|(name, _)| name.as_str() != "nix-store.squashfs")
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn netboot_squashfs_injected_config_patch_updates_service() {
        let mut random = [0u8; 8];
        OsRng.fill_bytes(&mut random);
        let dir =
            std::env::temp_dir().join(format!("cybex-forge-config-test-{}", hex::encode(random)));
        let unit_dir = dir.join("abc123-unit-cybex-installer-config.service");
        fs::create_dir_all(&unit_dir).unwrap();
        let unit_path = unit_dir.join("cybex-installer-config.service");
        fs::write(
            &unit_path,
            "[Unit]\n\
             Description=Prepare Cybex injected installer configuration\n\
             \n\
             [Service]\n\
             Environment=\"PATH=/nix/store/example/bin\"\n\
             ExecStart=/nix/store/example-cybex-installer-config/bin/cybex-installer-config\n",
        )
        .unwrap();
        let config_path = dir.join("config.toml");
        fs::write(
            &config_path,
            "api_url = \"https://dev.cybex.net\"\norganization_slug = \"default\"\n",
        )
        .unwrap();

        patch_nixos_netboot_squashfs_injected_config(&dir, &config_path).unwrap();

        let store_path = dir.join(super::NIXOS_NETBOOT_INJECTED_CONFIG_STORE_BASENAME);
        assert_eq!(
            fs::read_to_string(&store_path).unwrap(),
            fs::read_to_string(&config_path).unwrap()
        );
        let unit = fs::read_to_string(&unit_path).unwrap();
        assert!(unit.contains("Environment=\"CYBEX_INJECTED_CONFIG=/nix/store/"));
        assert!(unit.contains(super::NIXOS_NETBOOT_INJECTED_CONFIG_STORE_BASENAME));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn netboot_squashfs_graphical_kiosk_patch_adds_session_settings() {
        let mut random = [0u8; 8];
        OsRng.fill_bytes(&mut random);
        let dir =
            std::env::temp_dir().join(format!("cybex-forge-kiosk-test-{}", hex::encode(random)));
        let system_units_dir = dir.join("abc123-system-units");
        let wants_dir = system_units_dir.join("multi-user.target.wants");
        let unit_store_dir = dir.join("def456-unit-cybex-installer-kiosk.service");
        fs::create_dir_all(&wants_dir).unwrap();
        fs::create_dir_all(&unit_store_dir).unwrap();
        let unit = "[Unit]\n\
                    Description=Cybex graphical installer kiosk\n\
                    \n\
                    [Service]\n\
                    Environment=CYBEX_RUNTIME_DIR=/run/cybex-installer\n\
                    ExecStart=/nix/store/ghi789-cybex-installer-kiosk/bin/cybex-installer-kiosk\n\
                    Restart=on-failure\n\
                    StandardInput=tty\n\
                    StandardOutput=journal\n\
                    TTYPath=/dev/tty1\n\
                    \n\
                    [Install]\n\
                    WantedBy=multi-user.target\n";
        let system_unit = system_units_dir.join("cybex-installer-kiosk.service");
        let wanted_unit = wants_dir.join("cybex-installer-kiosk.service");
        let store_unit = unit_store_dir.join("cybex-installer-kiosk.service");
        fs::write(&system_unit, unit).unwrap();
        fs::write(&wanted_unit, unit).unwrap();
        fs::write(&store_unit, unit).unwrap();

        patch_nixos_netboot_squashfs_graphical_kiosk(&dir).unwrap();

        for unit_path in [system_unit, wanted_unit, store_unit] {
            let rewritten = fs::read_to_string(unit_path).unwrap();
            assert!(rewritten.contains(
                "ExecStart=/nix/store/ghi789-cybex-installer-kiosk/bin/cybex-installer-kiosk"
            ));
            assert!(rewritten.contains("PAMName=login"));
            assert!(rewritten.contains("RuntimeDirectoryMode=0700"));
            assert!(rewritten.contains("TTYVTDisallocate=true"));
            assert!(rewritten.contains("UtmpIdentifier=tty1"));
            assert!(rewritten.contains("UtmpMode=user"));
            assert!(rewritten.contains("StandardOutput=journal"));
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn managed_response_chunk_limit_allows_exact_size() {
        let mut body = b"1234".to_vec();

        append_bounded_response_chunk_with_limit(&mut body, b"56", 6, "test response").unwrap();

        assert_eq!(body, b"123456");
    }

    #[test]
    fn managed_response_chunk_limit_rejects_oversized_body() {
        let mut body = b"1234".to_vec();

        let err = append_bounded_response_chunk_with_limit(&mut body, b"567", 6, "test response")
            .unwrap_err();

        assert!(err.to_string().contains("exceeded 6 bytes"));
        assert_eq!(body, b"1234");
    }

    #[test]
    fn boot_report_body_fitter_trims_inventory_before_events() {
        let settings = BootAgentSettingsReport {
            public_base_url: "http://127.0.0.1".to_string(),
            listen_addr: "127.0.0.1:8080".to_string(),
            tftp_root: "/srv/cybex-forge/tftp".to_string(),
            http_root: "/srv/cybex-forge/www".to_string(),
            bootloader_filename: "snponly.efi".to_string(),
            menu_timeout_ms: 8000,
            version: "test".to_string(),
            status: "online".to_string(),
            state: serde_json::json!({"client_count": 2, "asset_count": 2}),
        };
        let clients = (0..2)
            .map(|idx| BootAgentClientReport {
                managed_client_id: None,
                mac: format!("02:00:00:00:30:{idx:02x}"),
                hostname: Some(format!("node-{idx}")),
                serial_number: None,
                last_seen_at: None,
                default_profile_id: None,
                one_time_profile_id: None,
                notes: "n".repeat(1024),
                tags: vec!["rack-a".to_string()],
            })
            .collect::<Vec<_>>();
        let assets = (0..2)
            .map(|idx| BootAgentAssetReport {
                filename: format!("installer-{idx}.iso"),
                relative_path: format!("isos/installer-{idx}-{}", "x".repeat(512)),
                absolute_path: format!(
                    "/srv/cybex-forge/www/isos/installer-{idx}-{}",
                    "x".repeat(512)
                ),
                size_bytes: 1024,
                checksum_sha256: "a".repeat(64),
                last_scanned_at: "2026-07-01T00:00:00Z".to_string(),
                created_at: "2026-07-01T00:00:00Z".to_string(),
            })
            .collect::<Vec<_>>();
        let events = (1..=2)
            .map(|source_event_id| BootAgentEventReport {
                source_event_id,
                mac: Some("02:00:00:00:30:ff".to_string()),
                serial_number: None,
                ip_address: None,
                user_agent: None,
                selected_profile_id: Some("profile-1".to_string()),
                selected_profile_name: Some("Installer".to_string()),
                known_client: true,
                created_at: "2026-07-01T00:00:00Z".to_string(),
            })
            .collect::<Vec<_>>();
        let body = BootAgentReportRequest {
            protocol_version: CYBEX_COMPONENT_PROTOCOL_VERSION,
            settings,
            profile_sync: Vec::new(),
            clients,
            assets,
            events,
        };
        let mut fitting_shape = body.clone();
        fitting_shape.clients.clear();
        fitting_shape.assets.truncate(1);
        let max_bytes = serialize_boot_report_body(&fitting_shape).unwrap().len();

        let (fitted, body_bytes) = fit_boot_report_body(body, max_bytes).unwrap();

        assert!(body_bytes.len() <= max_bytes);
        assert!(fitted.clients.is_empty());
        assert_eq!(fitted.assets.len(), 1);
        assert_eq!(
            fitted
                .events
                .iter()
                .map(|event| event.source_event_id)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
    }

    #[test]
    fn managed_profile_rejects_control_characters_in_cmdline() {
        let profile = ManagedBootProfile {
            id: "profile-1".to_string(),
            name: "Installer".to_string(),
            description: String::new(),
            profile_type: "linux_installer".to_string(),
            installer_iso_source: "boot_profile".to_string(),
            enabled: true,
            is_default: false,
            one_time: false,
            kernel_path: Some("netboot/vmlinuz".to_string()),
            initrd_path: None,
            iso_path: None,
            cmdline: Some("auto=true\nshell".to_string()),
            raw_script: None,
            desired_iso_artifact_id: String::new(),
            desired_iso_filename: String::new(),
            desired_iso_size_bytes: 0,
            desired_iso_sha256: String::new(),
            desired_iso_built_at: None,
            desired_iso_url: String::new(),
            desired_iso_download_url: String::new(),
            sync_generation: 1,
            sync_operation_id: "00000000-0000-4000-8000-000000000001".to_string(),
        };

        let err = validate_profile(&profile).unwrap_err();

        assert!(err.to_string().contains("cmdline"));
    }

    #[test]
    fn managed_profile_rejects_control_characters_in_name() {
        let mut profile = sample_profile("profile-1");
        profile.name = "Installer\nshell".to_string();

        let err = validate_profile(&profile).unwrap_err();

        assert!(err.to_string().contains("profile name"));
    }

    #[test]
    fn managed_profile_rejects_names_over_local_limit() {
        let mut profile = sample_profile("profile-1");
        profile.name = "x".repeat(121);

        let err = validate_profile(&profile).unwrap_err();

        assert!(err.to_string().contains("120 characters"));
    }

    #[test]
    fn managed_profile_rejects_oversized_description() {
        let mut profile = sample_profile("profile-1");
        profile.description = "x".repeat(MAX_PROFILE_DESCRIPTION_CHARS + 1);

        let err = validate_profile(&profile).unwrap_err();

        assert!(err.to_string().contains("description"));
    }

    #[test]
    fn managed_profile_rejects_oversized_raw_script() {
        let mut profile = sample_profile("profile-1");
        profile.profile_type = "custom_ipxe".to_string();
        profile.kernel_path = None;
        profile.raw_script = Some("echo x\n".repeat((MAX_PROFILE_RAW_SCRIPT_BYTES / 7) + 1));

        let err = validate_profile(&profile).unwrap_err();

        assert!(err.to_string().contains("raw_script"));
    }

    #[test]
    fn managed_settings_are_normalized_and_clamped() {
        let mut app_config = AppConfig::default();
        app_config.server.public_base_url = "http://fallback.example".to_string();
        let settings = ManagedBootSettings {
            public_base_url: " http://boot.example/// ".to_string(),
            listen_addr: "127.0.0.1:9080".to_string(),
            tftp_root: "/srv/cybex-forge/tftp-managed".to_string(),
            http_root: "/srv/cybex-forge/www-managed".to_string(),
            bootloader_filename: " ipxe.efi ".to_string(),
            menu_timeout_ms: 1_000,
        };

        let normalized = normalize_managed_settings(&settings, &app_config).unwrap();

        assert_eq!(normalized.public_base_url, "http://boot.example");
        assert_eq!(normalized.listen_addr, "127.0.0.1:9080");
        assert_eq!(
            normalized.tftp_root,
            PathBuf::from("/srv/cybex-forge/tftp-managed")
        );
        assert_eq!(
            normalized.http_root,
            PathBuf::from("/srv/cybex-forge/www-managed")
        );
        assert_eq!(normalized.bootloader_filename, "ipxe.efi");
        assert_eq!(normalized.menu_timeout_ms, 1_000);
    }

    #[test]
    fn managed_settings_use_local_public_base_url_when_blank() {
        let mut app_config = AppConfig::default();
        app_config.server.public_base_url = "http://fallback.example".to_string();
        let settings = ManagedBootSettings {
            public_base_url: "   ".to_string(),
            listen_addr: String::new(),
            tftp_root: String::new(),
            http_root: String::new(),
            bootloader_filename: String::new(),
            menu_timeout_ms: 0,
        };

        let normalized = normalize_managed_settings(&settings, &app_config).unwrap();

        assert_eq!(normalized.public_base_url, "http://fallback.example");
        assert_eq!(normalized.listen_addr, app_config.server.listen_addr);
        assert_eq!(normalized.tftp_root, app_config.paths.tftp_dir);
        assert_eq!(normalized.http_root, app_config.paths.boot_assets_dir);
        assert_eq!(
            normalized.bootloader_filename,
            app_config.boot.bootloader_filename
        );
        assert_eq!(normalized.menu_timeout_ms, app_config.boot.menu_timeout_ms);
    }

    #[test]
    fn managed_settings_reject_overlapping_runtime_roots() {
        let app_config = AppConfig::default();
        let nested_http = ManagedBootSettings {
            public_base_url: "http://boot.example".to_string(),
            listen_addr: "127.0.0.1:8080".to_string(),
            tftp_root: "/srv/cybex-forge/tftp".to_string(),
            http_root: "/srv/cybex-forge/tftp/www".to_string(),
            bootloader_filename: "snponly.efi".to_string(),
            menu_timeout_ms: 10_000,
        };
        let nested_tftp = ManagedBootSettings {
            public_base_url: "http://boot.example".to_string(),
            listen_addr: "127.0.0.1:8080".to_string(),
            tftp_root: "/srv/cybex-forge/www/tftp".to_string(),
            http_root: "/srv/cybex-forge/www".to_string(),
            bootloader_filename: "snponly.efi".to_string(),
            menu_timeout_ms: 10_000,
        };

        for settings in [nested_http, nested_tftp] {
            assert!(
                normalize_managed_settings(&settings, &app_config)
                    .unwrap_err()
                    .to_string()
                    .contains("must not overlap")
            );
        }
    }

    #[test]
    fn managed_check_service_uses_runtime_roots() {
        let settings = NormalizedManagedSettings {
            public_base_url: "http://boot.example".to_string(),
            listen_addr: "127.0.0.1:8080".to_string(),
            tftp_root: PathBuf::from("/srv/cybex-forge/tftp-managed"),
            http_root: PathBuf::from("/srv/cybex-forge/www-managed"),
            bootloader_filename: "snponly.efi".to_string(),
            menu_timeout_ms: 10_000,
        };

        let service = render_check_service(&settings);

        assert!(service.contains(
            "ReadOnlyPaths=/etc/cybex-forge /etc/default/tftpd-hpa /etc/nginx /srv/cybex-forge/tftp-managed"
        ));
        assert!(service.contains(
            "ReadWritePaths=/run /srv/cybex-forge/www-managed /var/lib/cybex-forge /var/lib/nginx /var/log/nginx"
        ));
        assert!(service.contains("ExecStart=/usr/local/bin/cybex-forge-check --quiet"));
    }

    #[test]
    fn managed_runtime_apply_carries_self_healing_units_for_existing_nodes() {
        let mut config = AppConfig::default();
        config.manage.organization_id = "00000000-0000-0000-0000-000000000001".to_string();
        let settings = NormalizedManagedSettings {
            public_base_url: "http://boot.example".to_string(),
            listen_addr: "127.0.0.1:8080".to_string(),
            tftp_root: PathBuf::from("/srv/cybex-forge/tftp-managed"),
            http_root: PathBuf::from("/srv/cybex-forge/www-managed"),
            bootloader_filename: "snponly.efi".to_string(),
            menu_timeout_ms: 10_000,
        };

        let files = runtime_managed_files(&config, &settings).unwrap();
        let by_path = files
            .iter()
            .map(|file| (file.path, file))
            .collect::<HashMap<_, _>>();

        assert!(
            by_path["/etc/systemd/system/cybex-forge.service"]
                .contents
                .contains("WatchdogSec=30s")
        );
        assert!(
            by_path["/usr/local/bin/cybex-forge-sentinel"]
                .contents
                .contains("reliability-state.json")
        );
        assert!(
            by_path["/usr/local/bin/cybex-forge-check"]
                .contents
                .contains("check_systemd_value cybex-forge Type notify")
        );
        assert_eq!(by_path["/usr/local/bin/cybex-forge-check"].mode, "0755");
        assert!(by_path.contains_key("/etc/systemd/system/cybex-forge-sentinel.timer"));
        assert!(by_path.contains_key(
            "/etc/systemd/system/systemd-resolved.service.d/10-cybex-forge-recovery.conf"
        ));
        assert!(
            by_path.contains_key(
                "/etc/systemd/system/nix-daemon.service.d/10-cybex-forge-restart.conf"
            )
        );
    }

    #[test]
    fn managed_config_derives_update_health_url_from_listen_addr() {
        let mut config = AppConfig::default();
        config.manage.organization_id = "org-1".to_string();
        let settings = NormalizedManagedSettings {
            public_base_url: "http://boot.example".to_string(),
            listen_addr: "127.0.0.1:9181".to_string(),
            tftp_root: PathBuf::from("/srv/cybex-forge/tftp-managed"),
            http_root: PathBuf::from("/srv/cybex-forge/www-managed"),
            bootloader_filename: "snponly.efi".to_string(),
            menu_timeout_ms: 10_000,
        };

        let rendered = render_managed_config(&config, &settings).unwrap();

        assert!(rendered.contains("health_url = \"http://127.0.0.1:9181/healthz\""));
    }

    #[test]
    fn managed_settings_reject_invalid_runtime_values() {
        let app_config = AppConfig::default();
        let invalid_url = ManagedBootSettings {
            public_base_url: "http://boot.example/path?debug=true".to_string(),
            listen_addr: "127.0.0.1:8080".to_string(),
            tftp_root: "/srv/cybex-forge/tftp".to_string(),
            http_root: "/srv/cybex-forge/www".to_string(),
            bootloader_filename: "snponly.efi".to_string(),
            menu_timeout_ms: 10_000,
        };
        let invalid_loader = ManagedBootSettings {
            public_base_url: "http://boot.example".to_string(),
            listen_addr: "127.0.0.1:8080".to_string(),
            tftp_root: "/srv/cybex-forge/tftp".to_string(),
            http_root: "/srv/cybex-forge/www".to_string(),
            bootloader_filename: "../snponly.efi".to_string(),
            menu_timeout_ms: 10_000,
        };
        let invalid_path = ManagedBootSettings {
            public_base_url: "http://boot.example".to_string(),
            listen_addr: "127.0.0.1:8080".to_string(),
            tftp_root: "/tmp/tftp".to_string(),
            http_root: "/srv/cybex-forge/www".to_string(),
            bootloader_filename: "snponly.efi".to_string(),
            menu_timeout_ms: 10_000,
        };
        let invalid_rendered_path = ManagedBootSettings {
            public_base_url: "http://boot.example".to_string(),
            listen_addr: "127.0.0.1:8080".to_string(),
            tftp_root: "/srv/cybex-forge/tftp".to_string(),
            http_root: "/srv/cybex-forge/www;include/tmp/bad".to_string(),
            bootloader_filename: "snponly.efi".to_string(),
            menu_timeout_ms: 10_000,
        };
        let invalid_listener = ManagedBootSettings {
            public_base_url: "http://boot.example".to_string(),
            listen_addr: "0.0.0.0:8080".to_string(),
            tftp_root: "/srv/cybex-forge/tftp".to_string(),
            http_root: "/srv/cybex-forge/www".to_string(),
            bootloader_filename: "snponly.efi".to_string(),
            menu_timeout_ms: 10_000,
        };

        assert!(
            normalize_managed_settings(&invalid_url, &app_config)
                .unwrap_err()
                .to_string()
                .contains("public_base_url")
        );
        assert!(
            normalize_managed_settings(&invalid_loader, &app_config)
                .unwrap_err()
                .to_string()
                .contains("bootloader_filename")
        );
        assert!(
            normalize_managed_settings(&invalid_path, &app_config)
                .unwrap_err()
                .to_string()
                .contains("tftp_root")
        );
        assert!(
            normalize_managed_settings(&invalid_rendered_path, &app_config)
                .unwrap_err()
                .to_string()
                .contains("http_root")
        );
        assert!(
            normalize_managed_settings(&invalid_listener, &app_config)
                .unwrap_err()
                .to_string()
                .contains("listen_addr")
        );
    }

    #[test]
    fn managed_config_rejects_duplicate_profile_ids() {
        let mut config = sample_boot_config();
        config.profiles.push(sample_profile("profile-1"));

        let err = validate_boot_config(&config).unwrap_err();

        assert!(
            err.to_string()
                .contains("duplicate managed boot profile id")
        );
    }

    #[test]
    fn managed_config_rejects_multiple_default_profiles() {
        let mut config = sample_boot_config();
        let mut first = sample_local_disk_profile("default-1");
        first.is_default = true;
        let mut second = sample_local_disk_profile("default-2");
        second.is_default = true;
        config.profiles = vec![first, second];
        config.clients.clear();

        let err = validate_boot_config(&config).unwrap_err();

        assert!(err.to_string().contains("multiple default profiles"));
    }

    #[test]
    fn managed_config_rejects_unknown_client_profile_reference() {
        let mut config = sample_boot_config();
        config.clients[0].default_profile_id = Some("missing-profile".to_string());

        let err = validate_boot_config(&config).unwrap_err();

        assert!(err.to_string().contains("unknown boot profile"));
    }

    #[test]
    fn managed_config_rejects_unassignable_client_profile_reference() {
        let mut config = sample_boot_config();
        config.profiles[0].enabled = false;

        let err = validate_boot_config(&config).unwrap_err();

        assert!(err.to_string().contains("enabled profile"));

        let mut config = sample_boot_config();
        config.profiles[0].profile_type = "iso_live".to_string();
        config.profiles[0].kernel_path = None;

        let err = validate_boot_config(&config).unwrap_err();

        assert!(err.to_string().contains("runnable boot action"));
    }

    #[test]
    fn managed_config_rejects_unassignable_default_profile() {
        let mut config = sample_boot_config();
        config.clients[0].default_profile_id = None;
        config.profiles[0].is_default = true;
        config.profiles[0].enabled = false;

        let err = validate_boot_config(&config).unwrap_err();

        assert!(err.to_string().contains("enabled profile"));

        let mut config = sample_boot_config();
        config.clients[0].default_profile_id = None;
        config.profiles[0].is_default = true;
        config.profiles[0].profile_type = "custom_ipxe".to_string();
        config.profiles[0].kernel_path = None;
        config.profiles[0].raw_script = None;

        let err = validate_boot_config(&config).unwrap_err();

        assert!(err.to_string().contains("runnable boot action"));
    }

    #[test]
    fn managed_config_accepts_pending_iso_sync_client_assignments() {
        // A network-reinstall profile: linux_installer with no boot assets
        // yet, but a desired ISO queued for sync.
        let mut config = sample_boot_config();
        config.profiles[0].profile_type = "linux_installer".to_string();
        config.profiles[0].kernel_path = None;
        config.profiles[0].iso_path = None;
        config.profiles[0].raw_script = None;
        config.profiles[0].desired_iso_artifact_id = "installer:abc:1".to_string();
        config.profiles[0].desired_iso_filename = "cybex-nixos-installer.iso".to_string();
        config.profiles[0].desired_iso_size_bytes = 1024;
        config.profiles[0].desired_iso_sha256 = "a".repeat(64);
        config.profiles[0].desired_iso_download_url =
            "/v1/agent/devices/dev_boot/boot/profiles/profile-1/iso/download".to_string();

        validate_boot_config(&config)
            .expect("client assignment to a pending managed-ISO profile should be accepted");
    }

    #[test]
    fn managed_config_accepts_enrollment_iso_assignments_before_sync_metadata() {
        let mut config = sample_boot_config();
        config.profiles[0].profile_type = "iso_live".to_string();
        config.profiles[0].installer_iso_source = "enrollment".to_string();
        config.profiles[0].kernel_path = None;
        config.profiles[0].cmdline = None;

        validate_boot_config(&config).unwrap();
    }

    #[test]
    fn managed_config_rejects_oversized_client_metadata() {
        let mut config = sample_boot_config();
        config.clients[0].hostname = Some("x".repeat(MAX_DEVICE_HOSTNAME_CHARS + 1));

        let err = validate_boot_config(&config).unwrap_err();

        assert!(err.to_string().contains("hostname"));

        let mut config = sample_boot_config();
        config.clients[0].serial_number = Some("x".repeat(MAX_DEVICE_SERIAL_CHARS + 1));

        let err = validate_boot_config(&config).unwrap_err();

        assert!(err.to_string().contains("serial"));

        let mut config = sample_boot_config();
        config.clients[0].notes = "x".repeat(MAX_DEVICE_NOTES_CHARS + 1);

        let err = validate_boot_config(&config).unwrap_err();

        assert!(err.to_string().contains("notes"));
    }

    #[test]
    fn managed_config_rejects_oversized_or_control_character_client_tags() {
        let mut config = sample_boot_config();
        config.clients[0].tags = (0..=MAX_DEVICE_TAGS)
            .map(|idx| format!("tag-{idx}"))
            .collect();

        let err = validate_boot_config(&config).unwrap_err();

        assert!(err.to_string().contains("tags"));

        let mut config = sample_boot_config();
        config.clients[0].tags = vec!["rack\n1".to_string()];

        let err = validate_boot_config(&config).unwrap_err();

        assert!(err.to_string().contains("tag"));
    }

    #[test]
    fn managed_config_rejects_too_many_profiles() {
        let mut config = sample_boot_config();
        config.profiles = (0..=MAX_MANAGED_PROFILES)
            .map(|idx| sample_profile(&format!("profile-{idx}")))
            .collect();

        let err = validate_boot_config(&config).unwrap_err();

        assert!(err.to_string().contains("too many profiles"));
    }

    #[test]
    fn managed_config_rejects_duplicate_client_ids() {
        let mut config = sample_boot_config();
        config
            .clients
            .push(sample_client("client-1", "02:00:00:00:00:02", "profile-1"));

        let err = validate_boot_config(&config).unwrap_err();

        assert!(err.to_string().contains("duplicate managed boot client id"));
    }

    #[test]
    fn managed_config_rejects_too_many_clients() {
        let mut config = sample_boot_config();
        config.clients = (0..=MAX_MANAGED_CLIENTS)
            .map(|idx| {
                sample_client(
                    &format!("client-{idx}"),
                    &format!(
                        "02:00:{:02x}:{:02x}:{:02x}:{:02x}",
                        (idx >> 24) & 0xff,
                        (idx >> 16) & 0xff,
                        (idx >> 8) & 0xff,
                        idx & 0xff
                    ),
                    "profile-1",
                )
            })
            .collect();

        let err = validate_boot_config(&config).unwrap_err();

        assert!(err.to_string().contains("too many clients"));
    }

    #[test]
    fn managed_config_rejects_duplicate_client_macs() {
        let mut config = sample_boot_config();
        config
            .clients
            .push(sample_client("client-2", "02-00-00-00-00-01", "profile-1"));

        let err = validate_boot_config(&config).unwrap_err();

        assert!(
            err.to_string()
                .contains("duplicate managed boot client mac")
        );
    }

    #[test]
    fn managed_config_accepts_valid_profile_and_client_references() {
        let config = sample_boot_config();

        validate_boot_config(&config).unwrap();
    }

    #[tokio::test]
    async fn managed_sync_detects_unreported_known_profile_events() {
        let pool = managed_test_pool().await;
        let managed_profile = sample_profile("profile-1");
        let mut tx = pool.begin().await.unwrap();
        sync_profiles(&mut tx, &[managed_profile], true)
            .await
            .unwrap();
        tx.commit().await.unwrap();

        let profile_id: i64 = sqlx::query_scalar(
            "SELECT id FROM boot_profiles WHERE managed_profile_id = 'profile-1'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let unknown = db::insert_boot_event(
            &pool,
            NewBootEvent {
                device_id: None,
                mac: Some("02:00:00:00:00:01".to_string()),
                serial_number: None,
                ip_address: None,
                user_agent: None,
                selected_profile_id: Some(profile_id),
                selected_profile_name: Some("Installer".to_string()),
                known_device: false,
            },
        )
        .await
        .unwrap();

        assert!(
            !has_unreported_known_profile_events(&pool, None)
                .await
                .unwrap()
        );
        assert!(
            !has_unreported_known_profile_events(&pool, Some(unknown.id))
                .await
                .unwrap()
        );
        let known = db::insert_boot_event(
            &pool,
            NewBootEvent {
                device_id: None,
                mac: Some("02:00:00:00:00:01".to_string()),
                serial_number: None,
                ip_address: None,
                user_agent: None,
                selected_profile_id: Some(profile_id),
                selected_profile_name: Some("Installer".to_string()),
                known_device: true,
            },
        )
        .await
        .unwrap();

        assert!(
            has_unreported_known_profile_events(&pool, Some(unknown.id))
                .await
                .unwrap()
        );
        assert!(
            !has_unreported_known_profile_events(&pool, Some(known.id))
                .await
                .unwrap()
        );
    }

    #[test]
    fn enrollment_submit_recovery_accepts_pending_or_adopted_with_safe_polling_state() {
        for status in ["pending", "adopted"] {
            let mut managed = ManagedState::default();
            apply_enrollment_response(
                &mut managed,
                EnrollmentResponse {
                    enrollment_id: "enrollment-123".to_string(),
                    pairing_code: "123456".to_string(),
                    status: status.to_string(),
                    enrollment_secret: Some("rotated-secret".to_string()),
                },
            )
            .unwrap();
            assert_eq!(managed.enrollment_id.as_deref(), Some("enrollment-123"));
            assert_eq!(managed.enrollment_secret.as_deref(), Some("rotated-secret"));
        }

        for response in [
            EnrollmentResponse {
                enrollment_id: "../unsafe".to_string(),
                pairing_code: "123456".to_string(),
                status: "adopted".to_string(),
                enrollment_secret: Some("secret".to_string()),
            },
            EnrollmentResponse {
                enrollment_id: "enrollment-123".to_string(),
                pairing_code: "123456".to_string(),
                status: "rejected".to_string(),
                enrollment_secret: Some("secret".to_string()),
            },
            EnrollmentResponse {
                enrollment_id: "enrollment-123".to_string(),
                pairing_code: "123456".to_string(),
                status: "pending".to_string(),
                enrollment_secret: Some("bad\nsecret".to_string()),
            },
        ] {
            assert!(apply_enrollment_response(&mut ManagedState::default(), response).is_err());
        }
    }

    #[test]
    fn enrollment_signing_identity_survives_persistence_before_submit() {
        let root = temp_state_dir();
        let path = root.join("managed-state.json");
        let mut managed = ManagedState::default();
        ensure_key_material(&mut managed).unwrap();
        write_secure_json(&path, &managed).unwrap();

        let restored: ManagedState = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(restored.private_key_b64, managed.private_key_b64);
        assert_eq!(
            restored.public_key_fingerprint,
            managed.public_key_fingerprint
        );
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn armed_one_time_assignments_are_reported_before_the_client_cap() {
        let pool = managed_test_pool().await;
        let default_id = "00000000-0000-4000-8000-000000000101";
        let one_time_id = "00000000-0000-4000-8000-000000000102";
        let mut one_time = sample_profile(one_time_id);
        one_time.one_time = true;
        let mut tx = pool.begin().await.unwrap();
        sync_profiles(&mut tx, &[sample_profile(default_id), one_time], true)
            .await
            .unwrap();
        let profile_map = managed_profile_map(&mut tx).await.unwrap();
        let target_index = MAX_REPORT_CLIENTS;
        let clients = (0..=target_index)
            .map(|index| {
                let id = format!("00000000-0000-4000-8000-{index:012x}");
                let mac = format!(
                    "02:00:{:02x}:{:02x}:{:02x}:{:02x}",
                    (index >> 24) & 0xff,
                    (index >> 16) & 0xff,
                    (index >> 8) & 0xff,
                    index & 0xff,
                );
                let mut client = sample_client(&id, &mac, default_id);
                client.last_seen_at = Some(if index == target_index {
                    "2020-01-01T00:00:00Z".to_string()
                } else {
                    "2026-07-22T00:00:00Z".to_string()
                });
                if index == target_index {
                    client.one_time_profile_id = Some(one_time_id.to_string());
                }
                client
            })
            .collect::<Vec<_>>();
        sync_clients(&mut tx, &clients, &profile_map, true)
            .await
            .unwrap();
        tx.commit().await.unwrap();

        let reports = current_boot_client_reports(&pool).await.unwrap();
        let target_id = format!("00000000-0000-4000-8000-{target_index:012x}");
        assert_eq!(reports.len(), MAX_REPORT_CLIENTS + 1);
        assert_eq!(
            reports[0].managed_client_id.as_deref(),
            Some(target_id.as_str())
        );
        assert!(reports.into_iter().take(MAX_REPORT_CLIENTS).any(|report| {
            report.managed_client_id.as_deref() == Some(target_id.as_str())
                && report.one_time_profile_id.as_deref() == Some(one_time_id)
        }));
    }

    #[tokio::test]
    async fn boot_client_report_echoes_committed_managed_assignment_ids() {
        let pool = managed_test_pool().await;
        let client_id = "00000000-0000-4000-8000-000000000101".to_string();
        let default_profile_id = "00000000-0000-4000-8000-000000000102".to_string();
        let one_time_profile_id = "00000000-0000-4000-8000-000000000103".to_string();
        let mut client = sample_client(&client_id, "02:00:00:00:10:01", &default_profile_id);
        client.one_time_profile_id = Some(one_time_profile_id.clone());
        let profiles = vec![
            sample_profile(&default_profile_id),
            sample_profile(&one_time_profile_id),
        ];
        let mut tx = pool.begin().await.unwrap();
        sync_profiles(&mut tx, &profiles, true).await.unwrap();
        let profile_map = managed_profile_map(&mut tx).await.unwrap();
        sync_clients(&mut tx, &[client], &profile_map, true)
            .await
            .unwrap();
        tx.commit().await.unwrap();

        let reports = current_boot_client_reports(&pool).await.unwrap();

        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].managed_client_id.as_deref(), Some(&*client_id));
        assert_eq!(
            reports[0].default_profile_id.as_deref(),
            Some(&*default_profile_id)
        );
        assert_eq!(
            reports[0].one_time_profile_id.as_deref(),
            Some(&*one_time_profile_id)
        );
    }

    #[tokio::test]
    async fn managed_sync_clears_stale_default_when_control_plane_has_none() {
        let pool = managed_test_pool().await;
        let profile = sample_profile("profile-1");
        let mut tx = pool.begin().await.unwrap();

        sync_profiles(&mut tx, &[profile], true).await.unwrap();
        tx.commit().await.unwrap();

        let default_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM boot_profiles WHERE is_default = 1")
                .fetch_one(&pool)
                .await
                .unwrap();

        assert_eq!(default_count, 0);
    }

    #[tokio::test]
    async fn managed_sync_keeps_iso_profile_non_bootable_until_raw_script_is_ready() {
        let pool = managed_test_pool().await;
        let mut profile = sample_iso_sync_profile("profile-1");
        profile.is_default = true;

        let mut tx = pool.begin().await.unwrap();
        sync_profiles(&mut tx, &[profile], true).await.unwrap();
        tx.commit().await.unwrap();

        let profile = db::list_profiles(&pool)
            .await
            .unwrap()
            .into_iter()
            .find(|profile| profile.managed_profile_id.as_deref() == Some("profile-1"))
            .unwrap();

        assert_eq!(profile.iso_path, None);
        assert_eq!(profile.raw_script, None);
        assert!(!boot::profile_has_boot_action(&profile));
    }

    #[tokio::test]
    async fn managed_sync_preserves_generated_iso_raw_script_until_resync() {
        let pool = managed_test_pool().await;
        let profile = sample_iso_sync_profile("profile-1");

        let mut tx = pool.begin().await.unwrap();
        sync_profiles(&mut tx, &[sample_iso_sync_profile("profile-1")], true)
            .await
            .unwrap();
        tx.commit().await.unwrap();

        let generated_script = render_nixos_netboot_script(
            &NixosNetbootManifest {
                iso_sha256: "a".repeat(64),
                kernel_iso_path: "boot/bzImage".to_string(),
                initrd_iso_path: "boot/initrd".to_string(),
                initrd_fstab_path: "/nix/.ro-store".to_string(),
                cmdline: "root=fstab quiet".to_string(),
                kernel_path: "installers/example/bzImage".to_string(),
                initrd_path: "installers/example/initrd".to_string(),
                netboot_cpio_path: "installers/example/nixos-netboot.cpio".to_string(),
                netboot_initrd_format: NIXOS_NETBOOT_INITRD_FORMAT.to_string(),
                squashfs_path: String::new(),
                squashfs_sha256: String::new(),
            },
            "http://boot.example",
        )
        .unwrap();
        assert!(generated_iso_raw_script_can_be_preserved(&generated_script));
        sqlx::query(
            "UPDATE boot_profiles SET iso_path = ?, raw_script = ? WHERE managed_profile_id = ?",
        )
        .bind("isos/installer.iso")
        .bind(&generated_script)
        .bind("profile-1")
        .execute(&pool)
        .await
        .unwrap();
        let pre_sync_raw_script: Option<String> = sqlx::query_scalar(
            "SELECT raw_script FROM boot_profiles WHERE managed_profile_id = 'profile-1'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            pre_sync_raw_script.as_deref(),
            Some(generated_script.as_str())
        );
        assert!(managed_profile_needs_iso_sync(&profile));
        let cleaned_existing_script = clean_optional(pre_sync_raw_script.clone());
        let cleaned_generated_script = generated_script.trim().to_string();
        assert_eq!(
            cleaned_existing_script.as_deref(),
            Some(cleaned_generated_script.as_str())
        );
        assert!(generated_iso_raw_script_can_be_preserved(
            cleaned_existing_script.as_deref().unwrap()
        ));
        assert_eq!(
            managed_profile_raw_script(&profile, pre_sync_raw_script.as_deref()).as_deref(),
            Some(cleaned_generated_script.as_str())
        );

        let mut tx = pool.begin().await.unwrap();
        sync_profiles(&mut tx, &[profile], true).await.unwrap();
        tx.commit().await.unwrap();

        let raw_script: Option<String> = sqlx::query_scalar(
            "SELECT raw_script FROM boot_profiles WHERE managed_profile_id = 'profile-1'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let iso_path: Option<String> = sqlx::query_scalar(
            "SELECT iso_path FROM boot_profiles WHERE managed_profile_id = 'profile-1'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();

        assert_eq!(
            raw_script.as_deref(),
            Some(cleaned_generated_script.as_str())
        );
        assert_eq!(iso_path.as_deref(), Some("isos/installer.iso"));
    }

    #[tokio::test]
    async fn managed_sync_clears_stale_custom_raw_script_during_iso_sync() {
        let pool = managed_test_pool().await;
        let profile = sample_iso_sync_profile("profile-1");

        let mut tx = pool.begin().await.unwrap();
        sync_profiles(&mut tx, &[sample_iso_sync_profile("profile-1")], true)
            .await
            .unwrap();
        tx.commit().await.unwrap();

        sqlx::query(
            "UPDATE boot_profiles SET iso_path = ?, raw_script = ? WHERE managed_profile_id = ?",
        )
        .bind("isos/installer.iso")
        .bind("#!ipxe\necho stale local script\nboot\n")
        .bind("profile-1")
        .execute(&pool)
        .await
        .unwrap();

        let mut tx = pool.begin().await.unwrap();
        sync_profiles(&mut tx, &[profile], true).await.unwrap();
        tx.commit().await.unwrap();

        let (iso_path, raw_script): (Option<String>, Option<String>) = sqlx::query_as(
            "SELECT iso_path, raw_script FROM boot_profiles WHERE managed_profile_id = 'profile-1'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();

        assert!(iso_path.is_none());
        assert!(raw_script.is_none());
    }

    #[tokio::test]
    async fn managed_sync_clears_stale_generated_iso_raw_script_syntax() {
        let pool = managed_test_pool().await;
        let profile = sample_iso_sync_profile("profile-1");

        let mut tx = pool.begin().await.unwrap();
        sync_profiles(&mut tx, &[sample_iso_sync_profile("profile-1")], true)
            .await
            .unwrap();
        tx.commit().await.unwrap();

        let stale_script = "#!ipxe\n\
            echo Cybex Forge: Default Enrollment\n\
            kernel http://boot.example/files/installers/example-nix-netboot/bzImage init=/nix/store/example/init initrd=initrd root=fstab\n\
            initrd http://boot.example/files/installers/example-nix-netboot/initrd\n\
            boot\n";
        sqlx::query("UPDATE boot_profiles SET raw_script = ? WHERE managed_profile_id = ?")
            .bind(stale_script)
            .bind("profile-1")
            .execute(&pool)
            .await
            .unwrap();

        let mut tx = pool.begin().await.unwrap();
        sync_profiles(&mut tx, &[profile], true).await.unwrap();
        tx.commit().await.unwrap();

        let raw_script: Option<String> = sqlx::query_scalar(
            "SELECT raw_script FROM boot_profiles WHERE managed_profile_id = 'profile-1'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();

        assert!(raw_script.is_none());
    }

    #[tokio::test]
    async fn managed_sync_clears_raw_script_when_iso_sync_no_longer_applies() {
        let pool = managed_test_pool().await;
        let mut profile = sample_iso_sync_profile("profile-1");

        let mut tx = pool.begin().await.unwrap();
        sync_profiles(&mut tx, &[sample_iso_sync_profile("profile-1")], true)
            .await
            .unwrap();
        tx.commit().await.unwrap();

        sqlx::query("UPDATE boot_profiles SET raw_script = ? WHERE managed_profile_id = ?")
            .bind("#!ipxe\necho generated\nboot\n")
            .bind("profile-1")
            .execute(&pool)
            .await
            .unwrap();

        profile.desired_iso_artifact_id.clear();
        profile.desired_iso_filename.clear();
        profile.desired_iso_size_bytes = 0;
        profile.desired_iso_sha256.clear();
        profile.desired_iso_download_url.clear();

        let mut tx = pool.begin().await.unwrap();
        sync_profiles(&mut tx, &[profile], true).await.unwrap();
        tx.commit().await.unwrap();

        let raw_script: Option<String> = sqlx::query_scalar(
            "SELECT raw_script FROM boot_profiles WHERE managed_profile_id = 'profile-1'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();

        assert!(raw_script.is_none());
    }

    #[tokio::test]
    async fn managed_sync_preserves_omitted_profiles_when_window_incomplete() {
        let pool = managed_test_pool().await;
        let profiles = vec![sample_profile("profile-1"), sample_profile("profile-2")];
        let mut tx = pool.begin().await.unwrap();
        sync_profiles(&mut tx, &profiles, true).await.unwrap();
        tx.commit().await.unwrap();

        let mut tx = pool.begin().await.unwrap();
        sync_profiles(&mut tx, &profiles[..1], false).await.unwrap();
        tx.commit().await.unwrap();

        let profile_ids: Vec<String> = sqlx::query_scalar(
            "SELECT managed_profile_id FROM boot_profiles
             WHERE managed_profile_id IS NOT NULL
             ORDER BY managed_profile_id ASC",
        )
        .fetch_all(&pool)
        .await
        .unwrap();

        assert_eq!(profile_ids, vec!["profile-1", "profile-2"]);
    }

    #[tokio::test]
    async fn managed_sync_prunes_omitted_profiles_when_snapshot_complete() {
        let pool = managed_test_pool().await;
        let profiles = vec![sample_profile("profile-1"), sample_profile("profile-2")];
        let mut tx = pool.begin().await.unwrap();
        sync_profiles(&mut tx, &profiles, true).await.unwrap();
        tx.commit().await.unwrap();

        let mut tx = pool.begin().await.unwrap();
        sync_profiles(&mut tx, &profiles[..1], true).await.unwrap();
        tx.commit().await.unwrap();

        let profile_ids: Vec<String> = sqlx::query_scalar(
            "SELECT managed_profile_id FROM boot_profiles
             WHERE managed_profile_id IS NOT NULL
             ORDER BY managed_profile_id ASC",
        )
        .fetch_all(&pool)
        .await
        .unwrap();

        assert_eq!(profile_ids, vec!["profile-1"]);
    }

    #[tokio::test]
    async fn managed_sync_deletes_tombstoned_profiles_when_window_incomplete() {
        let pool = managed_test_pool().await;
        let profiles = vec![sample_profile("profile-1"), sample_profile("profile-2")];
        let mut tx = pool.begin().await.unwrap();
        sync_profiles(&mut tx, &profiles, true).await.unwrap();
        tx.commit().await.unwrap();

        let mut tx = pool.begin().await.unwrap();
        sync_deleted_profiles(&mut tx, &["profile-2".to_string()])
            .await
            .unwrap();
        sync_profiles(&mut tx, &profiles[..1], false).await.unwrap();
        tx.commit().await.unwrap();

        let profile_ids: Vec<String> = sqlx::query_scalar(
            "SELECT managed_profile_id FROM boot_profiles
             WHERE managed_profile_id IS NOT NULL
             ORDER BY managed_profile_id ASC",
        )
        .fetch_all(&pool)
        .await
        .unwrap();

        assert_eq!(profile_ids, vec!["profile-1"]);
    }

    #[tokio::test]
    async fn managed_sync_preserves_omitted_clients_when_window_incomplete() {
        let pool = managed_test_pool().await;
        let managed_profile = sample_profile("profile-1");
        let mut tx = pool.begin().await.unwrap();
        sync_profiles(&mut tx, &[managed_profile], true)
            .await
            .unwrap();
        let profile_map = managed_profile_map(&mut tx).await.unwrap();
        let clients = vec![
            sample_client("client-1", "02:00:00:00:20:01", "profile-1"),
            sample_client("client-2", "02:00:00:00:20:02", "profile-1"),
        ];
        sync_clients(&mut tx, &clients, &profile_map, true)
            .await
            .unwrap();
        tx.commit().await.unwrap();

        let mut tx = pool.begin().await.unwrap();
        let profile_map = managed_profile_map(&mut tx).await.unwrap();
        sync_clients(&mut tx, &clients[..1], &profile_map, false)
            .await
            .unwrap();
        tx.commit().await.unwrap();

        let client_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM devices WHERE managed_client_id IS NOT NULL")
                .fetch_one(&pool)
                .await
                .unwrap();

        assert_eq!(client_count, 2);
    }

    #[tokio::test]
    async fn managed_sync_prunes_omitted_clients_when_snapshot_complete() {
        let pool = managed_test_pool().await;
        let managed_profile = sample_profile("profile-1");
        let mut tx = pool.begin().await.unwrap();
        sync_profiles(&mut tx, &[managed_profile], true)
            .await
            .unwrap();
        let profile_map = managed_profile_map(&mut tx).await.unwrap();
        let clients = vec![
            sample_client("client-1", "02:00:00:00:21:01", "profile-1"),
            sample_client("client-2", "02:00:00:00:21:02", "profile-1"),
        ];
        sync_clients(&mut tx, &clients, &profile_map, true)
            .await
            .unwrap();
        tx.commit().await.unwrap();

        let mut tx = pool.begin().await.unwrap();
        let profile_map = managed_profile_map(&mut tx).await.unwrap();
        sync_clients(&mut tx, &clients[..1], &profile_map, true)
            .await
            .unwrap();
        tx.commit().await.unwrap();

        let client_ids: Vec<String> = sqlx::query_scalar(
            "SELECT managed_client_id FROM devices
             WHERE managed_client_id IS NOT NULL
             ORDER BY managed_client_id ASC",
        )
        .fetch_all(&pool)
        .await
        .unwrap();

        assert_eq!(client_ids, vec!["client-1"]);
    }

    #[tokio::test]
    async fn managed_sync_deletes_tombstoned_clients_when_window_incomplete() {
        let pool = managed_test_pool().await;
        let managed_profile = sample_profile("profile-1");
        let mut tx = pool.begin().await.unwrap();
        sync_profiles(&mut tx, &[managed_profile], true)
            .await
            .unwrap();
        let profile_map = managed_profile_map(&mut tx).await.unwrap();
        let clients = vec![
            sample_client("client-1", "02:00:00:00:22:01", "profile-1"),
            sample_client("client-2", "02:00:00:00:22:02", "profile-1"),
        ];
        sync_clients(&mut tx, &clients, &profile_map, true)
            .await
            .unwrap();
        tx.commit().await.unwrap();

        let mut tx = pool.begin().await.unwrap();
        sync_deleted_clients(&mut tx, &["client-2".to_string()])
            .await
            .unwrap();
        let profile_map = managed_profile_map(&mut tx).await.unwrap();
        sync_clients(&mut tx, &clients[..1], &profile_map, false)
            .await
            .unwrap();
        tx.commit().await.unwrap();

        let client_ids: Vec<String> = sqlx::query_scalar(
            "SELECT managed_client_id FROM devices
             WHERE managed_client_id IS NOT NULL
             ORDER BY managed_client_id ASC",
        )
        .fetch_all(&pool)
        .await
        .unwrap();

        assert_eq!(client_ids, vec!["client-1"]);
    }

    #[test]
    fn managed_config_rejects_duplicate_deleted_client_ids() {
        let mut config = sample_boot_config();
        config.deleted_client_ids = vec!["client-2".to_string(), "client-2".to_string()];

        let err = validate_boot_config(&config).unwrap_err();

        assert!(
            err.to_string()
                .contains("duplicate deleted managed boot client id")
        );
    }

    #[test]
    fn managed_config_rejects_duplicate_deleted_profile_ids() {
        let mut config = sample_boot_config();
        config.deleted_profile_ids = vec!["profile-2".to_string(), "profile-2".to_string()];

        let err = validate_boot_config(&config).unwrap_err();

        assert!(
            err.to_string()
                .contains("duplicate deleted managed boot profile id")
        );
    }

    #[tokio::test]
    async fn managed_sync_prunes_unreferenced_seeded_local_disk_profile() {
        let pool = managed_test_pool().await;
        let managed_local = sample_local_disk_profile("managed-local");
        let mut tx = pool.begin().await.unwrap();

        sync_profiles(&mut tx, &[managed_local], true)
            .await
            .unwrap();
        tx.commit().await.unwrap();

        let seed_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM boot_profiles
             WHERE managed_profile_id IS NULL
               AND profile_type = 'local_disk'
               AND name = 'Local disk'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let managed_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM boot_profiles
             WHERE managed_profile_id = 'managed-local'
               AND profile_type = 'local_disk'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();

        assert_eq!(seed_count, 0);
        assert_eq!(managed_count, 1);
    }

    #[tokio::test]
    async fn managed_sync_preserves_referenced_seeded_local_disk_profile() {
        let pool = managed_test_pool().await;
        let seed_id: i64 = sqlx::query_scalar(
            "SELECT id FROM boot_profiles
             WHERE managed_profile_id IS NULL
               AND profile_type = 'local_disk'
               AND name = 'Local disk'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        db::create_device(
            &pool,
            CreateDeviceRequest {
                mac: "02:00:00:00:10:00".to_string(),
                hostname: None,
                serial_number: None,
                notes: None,
                tags: None,
                default_profile_id: Some(seed_id),
                one_time_profile_id: None,
            },
        )
        .await
        .unwrap();
        let managed_local = sample_local_disk_profile("managed-local");
        let mut tx = pool.begin().await.unwrap();

        sync_profiles(&mut tx, &[managed_local], true)
            .await
            .unwrap();
        tx.commit().await.unwrap();

        let seed_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM boot_profiles
             WHERE id = ?",
        )
        .bind(seed_id)
        .fetch_one(&pool)
        .await
        .unwrap();

        assert_eq!(seed_count, 1);
    }

    #[test]
    fn managed_http_timeout_is_clamped() {
        assert_eq!(bounded_http_timeout_seconds(0), 1);
        assert_eq!(bounded_http_timeout_seconds(30), 30);
        assert_eq!(bounded_http_timeout_seconds(600), 300);
    }

    #[test]
    fn forge_capabilities_report_build_and_cache() {
        let mut config = AppConfig::default();
        assert_eq!(
            forge_capabilities(&config),
            vec!["boot_v1", "builder_v1", "blueprint_builder_v2", "cache_v1"]
        );

        config.update.trusted_public_key = STANDARD.encode(
            SigningKey::from_bytes(&[13_u8; 32])
                .verifying_key()
                .to_bytes(),
        );
        assert_eq!(
            forge_capabilities(&config),
            vec![
                "boot_v1",
                "builder_v1",
                "blueprint_builder_v2",
                "cache_v1",
                "updater_v1"
            ]
        );
    }

    #[test]
    fn optional_report_uuid_omits_non_uuid_ids() {
        assert_eq!(optional_report_uuid(None), None);
        assert_eq!(optional_report_uuid(Some("profile-1".to_string())), None);
        assert_eq!(
            optional_report_uuid(Some(" 5C3BAAB7-A204-4C21-A024-0F567D8CF41D ".to_string()))
                .as_deref(),
            Some("5c3baab7-a204-4c21-a024-0f567d8cf41d")
        );
    }

    #[tokio::test]
    async fn profile_iso_sync_skips_non_uuid_managed_profile_ids() {
        let pool = managed_test_pool().await;
        let mut tx = pool.begin().await.unwrap();
        sync_profiles(&mut tx, &[sample_iso_sync_profile("profile-1")], true)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        let state = AppState::new(AppConfig::default(), pool);

        let reports = current_profile_sync_reports(&state.db).await.unwrap();

        assert!(reports.is_empty());
    }

    #[test]
    fn pending_enrollment_uses_poll_interval() {
        let config = ManageConfig {
            sync_interval_seconds: 60,
            enrollment_poll_seconds: 2,
            ..ManageConfig::default()
        };

        assert_eq!(
            managed_sync_interval_seconds(&config, SyncOnceDisposition::PendingEnrollment),
            2
        );
        assert_eq!(
            managed_sync_interval_seconds(&config, SyncOnceDisposition::Synced),
            60
        );

        let clamped = ManageConfig {
            sync_interval_seconds: 1,
            enrollment_poll_seconds: 0,
            ..ManageConfig::default()
        };
        assert_eq!(
            managed_sync_interval_seconds(&clamped, SyncOnceDisposition::PendingEnrollment),
            1
        );
        assert_eq!(
            managed_sync_interval_seconds(&clamped, SyncOnceDisposition::Synced),
            5
        );
    }

    #[test]
    fn fenced_update_report_requires_the_exact_status_and_attempt() {
        let attempt_id = "a".repeat(32);
        let expected = ExpectedUpdateReport {
            status: "failed".to_string(),
            attempt_id: attempt_id.clone(),
        };
        let mut actual = crate::updater::ForgeUpdateStatusReport {
            status: "failed".to_string(),
            stage: "failed".to_string(),
            progress_percent: Some(100),
            error: "sensitive diagnostic omitted from sync receipt".to_string(),
            target_version: "0.1.2".to_string(),
            current_version: "0.1.1".to_string(),
            attempt_id,
            started_at: None,
            completed_at: Some("2026-07-23T10:00:00Z".to_string()),
        };

        validate_expected_update_report(Some(&actual), Some(&expected)).unwrap();
        assert!(
            validate_expected_update_report(None, Some(&expected))
                .unwrap_err()
                .to_string()
                .contains("did not include")
        );

        actual.status = "idle".to_string();
        assert!(
            validate_expected_update_report(Some(&actual), Some(&expected))
                .unwrap_err()
                .to_string()
                .contains("status mismatch")
        );
        actual.status = "failed".to_string();
        actual.attempt_id = "b".repeat(32);
        assert!(
            validate_expected_update_report(Some(&actual), Some(&expected))
                .unwrap_err()
                .to_string()
                .contains("attempt mismatch")
        );
    }

    #[tokio::test]
    async fn update_only_sync_posts_exact_scoped_body_without_shared_state() {
        let root = temp_state_dir();
        let shared_data = root.join("shared-data-must-not-exist");
        let shared_boot = root.join("shared-boot-must-not-exist");
        let shared_cache = root.join("shared-cache-must-not-exist");
        let shared_build = root.join("shared-build-must-not-exist");
        let shared_releases = root.join("shared-releases-must-not-exist");
        let state_dir = root.join("signing-state");
        let update_dir = root.join("isolated-update");
        fs::create_dir_all(&state_dir).unwrap();
        fs::create_dir_all(&update_dir).unwrap();

        let signing = SigningKey::from_bytes(&[23_u8; 32]);
        let managed = ManagedState {
            private_key_b64: Some(STANDARD.encode(signing.to_bytes())),
            public_key_b64: Some(STANDARD.encode(signing.verifying_key().to_bytes())),
            public_key_fingerprint: Some(sha256_hex(signing.verifying_key().to_bytes())),
            device_id: Some("forge-update-only-test".to_string()),
            ..ManagedState::default()
        };
        let attempt_id = "a".repeat(32);
        let updater = crate::updater::ForgeUpdateStatusReport {
            status: "failed".to_string(),
            stage: "failed".to_string(),
            progress_percent: Some(100),
            error: "synthetic signature rejection".to_string(),
            target_version: "0.1.2".to_string(),
            current_version: "0.1.1".to_string(),
            attempt_id: attempt_id.clone(),
            started_at: Some("2026-07-23T09:59:00Z".to_string()),
            completed_at: Some("2026-07-23T10:00:00Z".to_string()),
        };

        let (capture_tx, capture_rx) = oneshot::channel();
        let capture: UpdateOnlyCapture = Arc::new(Mutex::new(Some(capture_tx)));
        let app = Router::new()
            .route(
                "/v1/agent/devices/forge-update-only-test/forge/update-report",
                post(capture_update_only_report),
            )
            .with_state(capture);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let mut config = AppConfig::default();
        config.manage.enabled = true;
        config.manage.api_url = format!("http://{address}");
        config.manage.organization_id = "organization-update-only-test".to_string();
        config.manage.state_path = state_dir.join("manage-state.json");
        config.paths.data_dir = shared_data.clone();
        config.paths.database_path = shared_data.join("forge.sqlite");
        config.paths.boot_assets_dir = shared_boot.clone();
        config.paths.iso_dir = shared_boot.join("isos");
        config.paths.static_dir = shared_boot.join("assets");
        config.paths.tftp_dir = shared_boot.join("tftp");
        config.cache.root_dir = shared_cache.clone();
        config.cache.private_key_path = shared_cache.join("private-key");
        config.cache.public_key_path = shared_cache.join("public-key");
        config.build.work_dir = shared_build.join("work");
        config.build.output_dir = shared_build.join("output");
        config.update.enabled = true;
        config.update.work_dir = update_dir.clone();
        config.update.releases_dir = shared_releases.clone();
        config.update.trusted_public_key = STANDARD.encode(signing.verifying_key().to_bytes());
        write_secure_json(&config.manage.state_path, &managed).unwrap();
        fs::write(
            update_dir.join("status.json"),
            serde_json::to_vec(&updater).unwrap(),
        )
        .unwrap();
        let managed_state_before = fs::read(&config.manage.state_path).unwrap();
        let updater_status_before = fs::read(update_dir.join("status.json")).unwrap();

        let report = sync_update_report_once(&config, None).await.unwrap();
        let (headers, raw_body, body) = capture_rx.await.unwrap();
        server.abort();

        let keys = body
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            keys,
            std::collections::BTreeSet::from([
                "capabilities",
                "protocol_version",
                "report_scope",
                "update",
            ])
        );
        assert_eq!(body["protocol_version"], CYBEX_COMPONENT_PROTOCOL_VERSION);
        assert_eq!(body["report_scope"], FORGE_REPORT_SCOPE_UPDATE_ONLY);
        assert_eq!(body["capabilities"], serde_json::json!(["updater_v1"]));
        assert_eq!(body["update"]["status"], "failed");
        assert_eq!(body["update"]["attempt_id"], attempt_id);
        assert_eq!(body["update"]["current_version"], "0.1.1");
        assert!(report.report_posted);
        assert!(report.update_included);
        assert!(report.update_acknowledged);
        assert_eq!(report.updater.as_ref().unwrap().status, "failed");
        assert!(!shared_data.exists());
        assert!(!shared_boot.exists());
        assert!(!shared_cache.exists());
        assert!(!shared_build.exists());
        assert!(!shared_releases.exists());
        assert_eq!(
            fs::read(&config.manage.state_path).unwrap(),
            managed_state_before
        );
        assert_eq!(
            fs::read(update_dir.join("status.json")).unwrap(),
            updater_status_before
        );

        assert_eq!(
            headers["x-cybex-organization"].to_str().unwrap(),
            "organization-update-only-test"
        );
        let timestamp = headers["x-cybex-timestamp"].to_str().unwrap();
        let request_id = headers["x-cybex-request-id"].to_str().unwrap();
        let signature = Signature::from_slice(
            &URL_SAFE_NO_PAD
                .decode(headers["x-cybex-signature"].to_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        let canonical = canonical_agent_payload(
            "POST",
            "/v1/agent/devices/forge-update-only-test/forge/update-report",
            timestamp,
            request_id,
            &sha256_hex(&raw_body),
        );
        signing
            .verifying_key()
            .verify(canonical.as_bytes(), &signature)
            .expect("update-only request signature covers the exact scoped body");
    }

    #[test]
    fn update_only_report_requires_scope_update_and_persistence_acknowledgement() {
        let expected = ExpectedUpdateReport {
            status: "failed".to_string(),
            attempt_id: "a".repeat(32),
        };
        let mut receipt = ForgeReportReceipt {
            update_acknowledged: false,
            scope_acknowledged: false,
            persisted_update_acknowledged: false,
            updater: Some(SyncOnceUpdaterReport {
                status: expected.status.clone(),
                attempt_id: expected.attempt_id.clone(),
                stage: "failed".to_string(),
                target_version: "0.1.2".to_string(),
                current_version: "0.1.1".to_string(),
                progress_percent: Some(100),
            }),
        };

        validate_forge_report_receipt(&receipt, false).unwrap();
        assert!(
            validate_forge_report_receipt(&receipt, true)
                .unwrap_err()
                .to_string()
                .contains("report scope")
        );
        receipt.scope_acknowledged = true;
        assert!(
            validate_forge_report_receipt(&receipt, true)
                .unwrap_err()
                .to_string()
                .contains("did not acknowledge")
        );
        receipt.update_acknowledged = true;
        assert!(
            validate_forge_report_receipt(&receipt, true)
                .unwrap_err()
                .to_string()
                .contains("did not confirm")
        );
        receipt.persisted_update_acknowledged = true;
        validate_forge_report_receipt(&receipt, true).unwrap();
    }

    #[test]
    fn forge_report_response_requires_an_explicit_true_update_ack() {
        let acknowledged: super::ForgeUpdateOnlyReportResponse =
            serde_json::from_str(
                r#"{"status":"ok","report_scope":"update_only","update":true,"persisted_update":{"status":"failed","attempt_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","reported_at":"2026-07-23T10:00:00Z"}}"#,
            )
            .unwrap();
        let legacy: super::ForgeReportResponse =
            serde_json::from_str(r#"{"status":"ok"}"#).unwrap();

        assert_eq!(acknowledged.status, "ok");
        assert!(acknowledged.update);
        assert_eq!(acknowledged.report_scope, "update_only");
        assert_eq!(acknowledged.persisted_update.status, "failed");
        assert!(!legacy.update);
        assert!(
            serde_json::from_str::<super::ForgeUpdateOnlyReportResponse>(
                r#"{"status":"ok","update":"true"}"#
            )
            .is_err()
        );
    }

    #[test]
    fn persisted_update_ack_requires_exact_projection_and_timestamp() {
        let updater = SyncOnceUpdaterReport {
            status: "failed".to_string(),
            attempt_id: "a".repeat(32),
            stage: "failed".to_string(),
            target_version: "0.1.2".to_string(),
            current_version: "0.1.1".to_string(),
            progress_percent: Some(100),
        };
        let mut persisted = super::ForgePersistedUpdateAcknowledgement {
            status: updater.status.clone(),
            attempt_id: updater.attempt_id.clone(),
            reported_at: "2026-07-23T10:00:00Z".to_string(),
        };

        assert!(super::persisted_update_ack_matches(&persisted, &updater));
        persisted.attempt_id = "b".repeat(32);
        assert!(!super::persisted_update_ack_matches(&persisted, &updater));
        persisted.attempt_id = updater.attempt_id.clone();
        persisted.reported_at = "not-a-timestamp".to_string();
        assert!(!super::persisted_update_ack_matches(&persisted, &updater));
    }

    #[test]
    fn sync_once_receipt_is_structured_and_excludes_updater_error_text() {
        let receipt = SyncOnceReport::synced(ForgeReportReceipt {
            update_acknowledged: true,
            scope_acknowledged: true,
            persisted_update_acknowledged: true,
            updater: Some(SyncOnceUpdaterReport {
                status: "failed".to_string(),
                attempt_id: "a".repeat(32),
                stage: "failed".to_string(),
                target_version: "0.1.2".to_string(),
                current_version: "0.1.1".to_string(),
                progress_percent: Some(100),
            }),
        });
        let value = serde_json::to_value(&receipt).unwrap();

        assert_eq!(value["schema"], "cybex.forge.sync-once.v1");
        assert_eq!(value["outcome"], "synced");
        assert_eq!(value["report_posted"], true);
        assert_eq!(value["update_included"], true);
        assert_eq!(value["update_acknowledged"], true);
        assert_eq!(value["updater"]["status"], "failed");
        assert_eq!(value["updater"]["attempt_id"], "a".repeat(32));
        assert!(value["updater"].get("error").is_none());
    }

    #[test]
    fn update_only_sync_rejects_a_pending_or_unreported_outcome() {
        let expected = ExpectedUpdateReport {
            status: "failed".to_string(),
            attempt_id: "a".repeat(32),
        };

        assert!(
            validate_update_only_sync_report(&SyncOnceReport::pending_enrollment())
                .unwrap_err()
                .to_string()
                .contains("adopted")
        );

        let unreported = SyncOnceReport {
            schema: "cybex.forge.sync-once.v1",
            outcome: SyncOnceDisposition::Synced,
            report_posted: false,
            update_included: true,
            update_acknowledged: true,
            updater: Some(SyncOnceUpdaterReport {
                status: expected.status.clone(),
                attempt_id: expected.attempt_id.clone(),
                stage: "failed".to_string(),
                target_version: "0.1.2".to_string(),
                current_version: "0.1.1".to_string(),
                progress_percent: Some(100),
            }),
        };
        assert!(
            validate_update_only_sync_report(&unreported)
                .unwrap_err()
                .to_string()
                .contains("did not post")
        );
    }

    #[test]
    fn secure_json_write_is_owner_only_and_cleans_tmp() {
        let path = temp_state_dir().join("manage-state.json");
        let state = ManagedState {
            device_id: Some("dev_test".to_string()),
            managed_token: Some("token_test".to_string()),
            ..ManagedState::default()
        };

        write_secure_json(&path, &state).unwrap();

        let loaded: ManagedState = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(loaded.device_id.as_deref(), Some("dev_test"));
        assert_eq!(loaded.managed_token.as_deref(), Some("token_test"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        let temp_files = fs::read_dir(path.parent().unwrap())
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
            .count();
        fs::remove_dir_all(path.parent().unwrap()).unwrap();

        assert_eq!(temp_files, 0);
    }

    #[test]
    fn boot_event_report_serializes_source_event_id() {
        let report = BootAgentEventReport {
            source_event_id: 42,
            mac: Some("02:00:00:00:00:01".to_string()),
            serial_number: None,
            ip_address: Some("192.0.2.10".to_string()),
            user_agent: None,
            selected_profile_id: Some("5c3baab7-a204-4c21-a024-0f567d8cf41d".to_string()),
            selected_profile_name: Some("Installer".to_string()),
            known_client: true,
            created_at: "2026-06-30T12:00:00Z".to_string(),
        };

        let value = serde_json::to_value(report).unwrap();

        assert_eq!(value["source_event_id"].as_i64(), Some(42));
        assert_eq!(
            value["selected_profile_id"].as_str(),
            Some("5c3baab7-a204-4c21-a024-0f567d8cf41d")
        );
    }

    fn sample_boot_config() -> AgentBootConfigResponse {
        AgentBootConfigResponse {
            compatibility: Some(ComponentCompatibilityContract {
                protocol_version: CYBEX_COMPONENT_PROTOCOL_VERSION,
                minimum_forge_protocol: 1,
                maximum_forge_protocol: CYBEX_COMPONENT_PROTOCOL_VERSION,
                manage_version: "0.1.0".to_string(),
                manage_release: "test".to_string(),
            }),
            settings: ManagedBootSettings {
                public_base_url: "http://127.0.0.1".to_string(),
                listen_addr: "127.0.0.1:8080".to_string(),
                tftp_root: "/srv/cybex-forge/tftp".to_string(),
                http_root: "/srv/cybex-forge/www".to_string(),
                bootloader_filename: "ipxe.efi".to_string(),
                menu_timeout_ms: 10_000,
            },
            profiles: vec![sample_profile("profile-1")],
            profiles_complete: true,
            deleted_profile_ids: vec![],
            clients: vec![sample_client("client-1", "02:00:00:00:00:01", "profile-1")],
            deleted_client_ids: vec![],
            clients_complete: true,
        }
    }

    #[test]
    fn component_manifest_and_runtime_contract_are_compatible() {
        let manifest: serde_json::Value =
            serde_json::from_str(include_str!("../protocol/compatibility.json")).unwrap();
        assert_eq!(
            manifest["protocol_version"].as_u64(),
            Some(u64::from(CYBEX_COMPONENT_PROTOCOL_VERSION))
        );
        assert_eq!(
            manifest["forge"]["minimum_manage_protocol"].as_u64(),
            Some(u64::from(CYBEX_MINIMUM_MANAGE_PROTOCOL_VERSION))
        );
        let config = sample_boot_config();
        validate_component_compatibility(config.compatibility.as_ref()).unwrap();
        validate_component_compatibility(None).unwrap();

        let incompatible = ComponentCompatibilityContract {
            protocol_version: CYBEX_COMPONENT_PROTOCOL_VERSION + 1,
            minimum_forge_protocol: CYBEX_COMPONENT_PROTOCOL_VERSION + 1,
            maximum_forge_protocol: CYBEX_COMPONENT_PROTOCOL_VERSION + 1,
            manage_version: "future".to_string(),
            manage_release: "future".to_string(),
        };
        assert!(validate_component_compatibility(Some(&incompatible)).is_err());
    }

    #[test]
    fn legacy_manage_config_gets_a_safe_local_operation_fence() {
        let mut config = sample_boot_config();
        config.compatibility = None;
        config.profiles[0].sync_operation_id.clear();

        normalize_legacy_boot_config(&mut config);

        assert_eq!(
            config.profiles[0].sync_operation_id,
            Uuid::nil().to_string()
        );
        validate_boot_config(&config).unwrap();
    }

    #[test]
    fn managed_iso_retry_is_exponential_and_bounded() {
        assert_eq!(managed_iso_retry_delay_seconds(1), 5);
        assert_eq!(managed_iso_retry_delay_seconds(2), 10);
        assert_eq!(managed_iso_retry_delay_seconds(3), 20);
        assert_eq!(managed_iso_retry_delay_seconds(i64::MAX), 3600);
        assert!(managed_iso_error_is_retryable(
            "download managed ISO request failed"
        ));
        assert!(!managed_iso_error_is_retryable(
            "managed ISO checksum must be 64 hex characters"
        ));
    }

    async fn managed_test_pool() -> sqlx::SqlitePool {
        let pool = db::connect_with_url("sqlite::memory:").await.unwrap();
        db::migrate(&pool).await.unwrap();
        pool
    }

    fn temp_state_dir() -> PathBuf {
        let mut random = [0u8; 8];
        OsRng.fill_bytes(&mut random);
        let path = std::env::temp_dir().join(format!(
            "cybex-forge-managed-state-{}-{}",
            std::process::id(),
            hex::encode(random)
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn sample_profile(id: &str) -> ManagedBootProfile {
        ManagedBootProfile {
            id: id.to_string(),
            name: "Installer".to_string(),
            description: String::new(),
            profile_type: "linux_installer".to_string(),
            installer_iso_source: "boot_profile".to_string(),
            enabled: true,
            is_default: false,
            one_time: false,
            kernel_path: Some("netboot/vmlinuz".to_string()),
            initrd_path: None,
            iso_path: None,
            cmdline: Some("auto=true".to_string()),
            raw_script: None,
            desired_iso_artifact_id: String::new(),
            desired_iso_filename: String::new(),
            desired_iso_size_bytes: 0,
            desired_iso_sha256: String::new(),
            desired_iso_built_at: None,
            desired_iso_url: String::new(),
            desired_iso_download_url: String::new(),
            sync_generation: 1,
            sync_operation_id: "00000000-0000-4000-8000-000000000001".to_string(),
        }
    }

    fn sample_iso_sync_profile(id: &str) -> ManagedBootProfile {
        let mut profile = sample_profile(id);
        profile.profile_type = "iso_live".to_string();
        profile.installer_iso_source = "enrollment".to_string();
        profile.kernel_path = None;
        profile.cmdline = None;
        profile.desired_iso_artifact_id = "artifact-1".to_string();
        profile.desired_iso_filename = "installer.iso".to_string();
        profile.desired_iso_size_bytes = 1024;
        profile.desired_iso_sha256 = "a".repeat(64);
        profile.desired_iso_download_url =
            format!("/v1/agent/devices/dev_1/boot/profiles/{id}/iso/download");
        profile
    }

    fn sample_local_disk_profile(id: &str) -> ManagedBootProfile {
        ManagedBootProfile {
            id: id.to_string(),
            name: "Managed Local Disk".to_string(),
            description: "Managed local boot fallback".to_string(),
            profile_type: "local_disk".to_string(),
            installer_iso_source: "boot_profile".to_string(),
            enabled: true,
            is_default: true,
            one_time: false,
            kernel_path: None,
            initrd_path: None,
            iso_path: None,
            cmdline: None,
            raw_script: None,
            desired_iso_artifact_id: String::new(),
            desired_iso_filename: String::new(),
            desired_iso_size_bytes: 0,
            desired_iso_sha256: String::new(),
            desired_iso_built_at: None,
            desired_iso_url: String::new(),
            desired_iso_download_url: String::new(),
            sync_generation: 1,
            sync_operation_id: "00000000-0000-4000-8000-000000000001".to_string(),
        }
    }

    fn sample_client(id: &str, mac: &str, profile_id: &str) -> ManagedBootClient {
        ManagedBootClient {
            id: id.to_string(),
            mac: mac.to_string(),
            hostname: Some("node-1".to_string()),
            serial_number: None,
            last_seen_at: None,
            default_profile_id: Some(profile_id.to_string()),
            one_time_profile_id: None,
            notes: String::new(),
            tags: vec!["rack-a".to_string()],
        }
    }
}
