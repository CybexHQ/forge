#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
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
use reqwest::{Client, Method, header::CONTENT_TYPE};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, Sqlite, SqlitePool, Transaction};
use tokio::time::sleep;
use tokio::{
    fs as tokio_fs,
    io::{AsyncReadExt, AsyncWriteExt},
};
use tracing::{info, warn};
use uuid::Uuid;

use crate::{
    AppState, RuntimeSettings, assets,
    config::{
        AppConfig, ManageConfig, normalize_absolute_config_path, normalize_bootloader_filename,
        normalize_http_url, normalize_listen_addr, validate_menu_timeout_ms,
    },
    db,
    models::{BootProfileType, BuildJob, CacheArtifact, clean_tags, normalize_mac},
};

const CAPABILITY_BOOT_V1: &str = "boot_v1";
const CAPABILITY_BUILDER_V1: &str = "builder_v1";
const CAPABILITY_CACHE_V1: &str = "cache_v1";
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
const MAX_REPORT_BODY_BYTES: usize = 3 * 1024 * 1024;
const MAX_DEVICE_HOSTNAME_CHARS: usize = 253;
const MAX_DEVICE_SERIAL_CHARS: usize = 128;
const MAX_DEVICE_NOTES_CHARS: usize = 2_000;
const MAX_DEVICE_TAGS: usize = 50;
const MAX_DEVICE_TAG_CHARS: usize = 64;
const MAX_PROFILE_DESCRIPTION_CHARS: usize = 2_000;
const MAX_PROFILE_RAW_SCRIPT_BYTES: usize = 64 * 1024;
const BOOT_PROFILE_ISO_SOURCE_BOOT_PROFILE: &str = "boot_profile";
const BOOT_PROFILE_ISO_SOURCE_ENROLLMENT: &str = "enrollment";

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
struct AgentBootConfigResponse {
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
    build_jobs: Vec<ManagedBuildJob>,
    #[serde(default)]
    deleted_build_job_ids: Vec<String>,
    #[serde(default)]
    build_jobs_complete: bool,
    #[serde(default)]
    deleted_cache_artifacts: Vec<ManagedDeletedCacheArtifact>,
}

#[derive(Debug, Deserialize)]
struct ManagedDeletedCacheArtifact {
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
    mac: String,
    hostname: Option<String>,
    serial_number: Option<String>,
    last_seen_at: Option<String>,
    notes: String,
    tags: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
struct BootAgentAssetReport {
    filename: String,
    relative_path: String,
    size_bytes: i64,
    checksum_sha256: String,
    last_scanned_at: String,
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
    capabilities: Vec<&'static str>,
    cache: crate::cache::CacheStatusReport,
    build_jobs: Vec<ForgeBuildJobReport>,
    cache_artifacts: Vec<ForgeCacheArtifactReport>,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SyncOutcome {
    Synced,
    PendingEnrollment,
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
    tokio::spawn(async move {
        loop {
            let outcome = match sync_once_with_outcome(&state).await {
                Ok(outcome) => outcome,
                Err(err) => {
                    warn!(error = %safe_error(&err), "managed sync failed");
                    SyncOutcome::Synced
                }
            };
            let interval = managed_sync_interval_seconds(&state.config.manage, outcome);
            sleep(Duration::from_secs(interval)).await;
        }
    });
}

pub async fn enroll_once(state: &AppState) -> Result<()> {
    ensure_manage_enabled(state)?;
    let mut managed = load_managed_state(state)?;
    ensure_key_material(&mut managed)?;
    let enrolled = ensure_enrolled(state, &mut managed).await?;
    save_managed_state(state, &managed)?;
    if enrolled {
        info!("managed enrollment is adopted");
    } else {
        info!("managed enrollment is pending administrator approval");
    }
    Ok(())
}

pub async fn sync_once(state: &AppState) -> Result<()> {
    sync_once_with_outcome(state).await.map(|_| ())
}

pub async fn apply_runtime_config_once(config: &AppConfig) -> Result<()> {
    ensure_root_supervisor()?;
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
    info!("managed runtime configuration applied");
    Ok(())
}

async fn sync_once_with_outcome(state: &AppState) -> Result<SyncOutcome> {
    ensure_manage_enabled(state)?;
    let mut managed = load_managed_state(state)?;
    ensure_key_material(&mut managed)?;
    if !ensure_enrolled(state, &mut managed).await? {
        save_managed_state(state, &managed)?;
        return Ok(SyncOutcome::PendingEnrollment);
    }

    if has_unreported_known_profile_events(&state.db, managed.last_reported_event_id).await? {
        report_boot_state(state, &mut managed, Vec::new()).await?;
        save_managed_state(state, &managed)?;
    }
    let config = fetch_boot_config(state, &managed).await?;
    apply_boot_config(state, &config).await?;
    let profile_sync = sync_desired_profile_isos(state, &managed).await?;
    report_boot_state(state, &mut managed, profile_sync).await?;
    sync_forge_foundation(state, &managed).await?;
    save_managed_state(state, &managed)?;
    Ok(SyncOutcome::Synced)
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
        return Ok(false);
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
    let endpoint = api_url(state, "/v1/agent/enrollments")?;
    let response = http_client(state)?
        .post(endpoint)
        .header("x-cybex-organization", organization_header(&state.config)?)
        .header(CONTENT_TYPE, "application/json")
        .json(&body)
        .send()
        .await
        .context("submit managed enrollment request failed")?;
    let response: EnrollmentResponse =
        parse_success_json(response, "submit managed enrollment").await?;
    if response.status != "pending" {
        bail!("managed enrollment returned non-pending status");
    }
    let secret = response
        .enrollment_secret
        .filter(|value| is_valid_header_value(value))
        .ok_or_else(|| anyhow!("managed enrollment response omitted polling secret"))?;
    managed.enrollment_id = Some(response.enrollment_id);
    managed.enrollment_secret = Some(secret);
    managed.pairing_code = Some(response.pairing_code);
    info!("managed enrollment submitted; waiting for administrator approval");
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
    let endpoint = api_url(
        state,
        &format!("/v1/agent/enrollments/{enrollment_id}/status"),
    )?;
    let response = http_client(state)?
        .get(endpoint)
        .header("x-cybex-organization", organization_header(&state.config)?)
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
    parse_success_json(response, "fetch managed boot config").await
}

async fn report_boot_state(
    state: &AppState,
    managed: &mut ManagedState,
    profile_sync: Vec<BootAgentProfileSyncReport>,
) -> Result<()> {
    let asset_scan = asset_scan_report(assets::scan_iso_dir(&state.config, &state.db).await);
    if let Some(error) = &asset_scan.error {
        warn!(error = %error, "managed ISO asset scan failed");
    }
    let devices = db::list_devices(&state.db).await?;
    let assets = db::list_iso_assets(&state.db).await?;
    let profile_count = db::list_profiles(&state.db).await?.len();
    let events = list_events_after(
        &state.db,
        managed.last_reported_event_id.unwrap_or(0),
        MAX_REPORT_EVENTS,
    )
    .await?;
    let runtime = state.runtime_settings();
    let reported_status = if asset_scan.error.is_some() {
        "warning"
    } else {
        "online"
    };
    let reported_state = boot_report_state(profile_count, devices.len(), assets.len(), &asset_scan);
    let body = BootAgentReportRequest {
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
        clients: devices
            .into_iter()
            .take(MAX_REPORT_CLIENTS)
            .map(|device| BootAgentClientReport {
                mac: device.mac,
                hostname: device.hostname,
                serial_number: device.serial_number,
                last_seen_at: device.last_seen_at,
                notes: device.notes,
                tags: device.tags,
            })
            .collect(),
        assets: assets
            .into_iter()
            .take(MAX_REPORT_ASSETS)
            .map(|asset| BootAgentAssetReport {
                filename: asset.filename,
                relative_path: asset.relative_path,
                size_bytes: asset.size_bytes,
                checksum_sha256: asset.checksum_sha256,
                last_scanned_at: asset.last_scanned_at,
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
    let (body, body_bytes) = fit_boot_report_body(body, MAX_REPORT_BODY_BYTES)?;
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

async fn sync_forge_foundation(state: &AppState, managed: &ManagedState) -> Result<()> {
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
    parse_success_json(response, "fetch managed forge config").await
}

async fn report_forge_state(state: &AppState, managed: &ManagedState) -> Result<()> {
    let build_jobs = db::list_build_jobs(&state.db).await?;
    let cache_artifacts = db::list_cache_artifacts(&state.db).await?;
    let cache = crate::cache::status_report(&state.config, &state.db).await;
    let body = ForgeAgentReportRequest {
        capabilities: forge_capabilities(),
        cache,
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
    };
    let body_bytes = serialize_forge_report_body(&body)?;
    let device_id = managed_device_id(managed)?;
    let path = format!("/v1/agent/devices/{device_id}/forge/report");
    let response = signed_request(state, managed, Method::POST, &path, body_bytes)
        .await?
        .header(CONTENT_TYPE, "application/json")
        .send()
        .await
        .context("report managed forge state request failed")?;
    parse_success_json::<Value>(response, "report managed forge state").await?;
    Ok(())
}

fn serialize_forge_report_body(body: &ForgeAgentReportRequest) -> Result<Vec<u8>> {
    let body = serde_json::to_vec(body).context("serialize managed forge report")?;
    if body.len() > MAX_REPORT_BODY_BYTES {
        bail!("managed forge report exceeded {MAX_REPORT_BODY_BYTES} bytes");
    }
    Ok(body)
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

async fn sync_desired_profile_isos(
    state: &AppState,
    managed: &ManagedState,
) -> Result<Vec<BootAgentProfileSyncReport>> {
    let targets = list_desired_profile_iso_targets(&state.db).await?;
    let mut reports = Vec::with_capacity(targets.len());
    for target in targets {
        if optional_report_uuid(Some(target.profile_id.clone())).is_none() {
            warn!(
                profile_id = %target.profile_id,
                "skipping managed ISO sync report for non-UUID profile id"
            );
            continue;
        }
        let started_at = Utc::now();
        match sync_desired_profile_iso(state, managed, &target, started_at).await {
            Ok(report) => reports.push(report),
            Err(err) => {
                warn!(
                    profile_id = %target.profile_id,
                    error = %safe_error(&err),
                    "managed ISO profile sync failed"
                );
                reports.push(profile_sync_failed_report(&target, started_at, err));
            }
        }
    }
    Ok(reports)
}

async fn list_desired_profile_iso_targets(pool: &SqlitePool) -> Result<Vec<ManagedIsoSyncTarget>> {
    sqlx::query_as::<_, ManagedIsoSyncTarget>(
        "SELECT id AS local_id,
                managed_profile_id AS profile_id,
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

async fn sync_desired_profile_iso(
    state: &AppState,
    managed: &ManagedState,
    target: &ManagedIsoSyncTarget,
    started_at: chrono::DateTime<Utc>,
) -> Result<BootAgentProfileSyncReport> {
    validate_managed_iso_target(target, state)?;
    let filename = managed_iso_filename(&target.desired_iso_filename)?;
    let relative_path = managed_iso_relative_path(&filename);
    let path = state.config.paths.iso_dir.join(&filename);

    tokio_fs::create_dir_all(&state.config.paths.iso_dir)
        .await
        .with_context(|| {
            format!(
                "create ISO cache directory {}",
                state.config.paths.iso_dir.display()
            )
        })?;

    let expected_size = target.desired_iso_size_bytes;
    let expected_sha = target.desired_iso_sha256.to_ascii_lowercase();
    if cached_iso_matches(&path, expected_size, &expected_sha).await? {
        let boot_script = ensure_nixos_netboot_boot_script(state, &path, &expected_sha).await?;
        set_profile_iso_boot_script(&state.db, target.local_id, &relative_path, &boot_script)
            .await?;
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
    )
    .await?;
    let boot_script = ensure_nixos_netboot_boot_script(state, &path, &expected_sha).await?;
    set_profile_iso_boot_script(&state.db, target.local_id, &relative_path, &boot_script).await?;

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
    profile_id: i64,
    iso_path: &str,
    raw_script: &str,
) -> Result<()> {
    sqlx::query(
        "UPDATE boot_profiles SET iso_path = ?, raw_script = ?, updated_at = ? WHERE id = ?",
    )
    .bind(iso_path)
    .bind(raw_script)
    .bind(db::now_rfc3339())
    .bind(profile_id)
    .execute(pool)
    .await
    .context("update managed ISO profile boot script")?;
    Ok(())
}

const NIXOS_NETBOOT_INITRD_FORMAT: &str = "zstd-combined-newc-v7";

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

    let artifact_relative_dir = format!("installers/{iso_sha256}");
    let artifact_dir = boot_assets_dir.join("installers").join(&iso_sha256);
    let manifest_path = artifact_dir.join("netboot-manifest.json");
    if let Some(manifest) = read_valid_netboot_manifest(&manifest_path, &artifact_dir, &iso_sha256)?
    {
        return Ok(manifest);
    }

    fs::create_dir_all(&installers_dir)
        .with_context(|| format!("create {}", installers_dir.display()))?;
    let staging_dir = netboot_staging_dir(&installers_dir, &iso_sha256)?;
    if staging_dir.exists() {
        fs::remove_dir_all(&staging_dir)
            .with_context(|| format!("remove stale {}", staging_dir.display()))?;
    }
    fs::create_dir_all(&staging_dir)
        .with_context(|| format!("create {}", staging_dir.display()))?;

    let result =
        prepare_nixos_netboot_staging(iso_path, &staging_dir, &artifact_relative_dir, &iso_sha256);
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
) -> Result<Option<NixosNetbootManifest>> {
    let Ok(raw) = fs::read(manifest_path) else {
        return Ok(None);
    };
    let manifest = serde_json::from_slice::<NixosNetbootManifest>(&raw)
        .with_context(|| format!("parse {}", manifest_path.display()))?;
    if manifest.iso_sha256 != iso_sha256 {
        return Ok(None);
    }
    if manifest.netboot_initrd_format != NIXOS_NETBOOT_INITRD_FORMAT {
        return Ok(None);
    }
    if !manifest.netboot_cpio_path.trim().is_empty() {
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
    }))
}

fn prepare_nixos_netboot_staging(
    iso_path: &Path,
    staging_dir: &Path,
    artifact_relative_dir: &str,
    iso_sha256: &str,
) -> Result<NixosNetbootManifest> {
    let isolinux_cfg = staging_dir.join("isolinux.cfg");
    extract_iso_file(iso_path, "/isolinux/isolinux.cfg", &isolinux_cfg)?;
    let boot_config = parse_isolinux_boot_config(&fs::read_to_string(&isolinux_cfg)?)
        .context("parse NixOS ISO boot config")?;

    let kernel_path = staging_dir.join("bzImage");
    let initrd_path = staging_dir.join("initrd");
    let squashfs_path = staging_dir.join("nix-store.squashfs");
    extract_iso_file(iso_path, &boot_config.kernel_iso_path, &kernel_path)?;
    extract_iso_file(iso_path, &boot_config.initrd_iso_path, &initrd_path)?;
    extract_iso_file(iso_path, "/nix-store.squashfs", &squashfs_path)?;

    let initrd_fstab_path = find_initrd_fstab_path(&initrd_path)?;
    rebuild_zstd_initrd_with_netboot_files(&initrd_path, &squashfs_path, &initrd_fstab_path)?;
    fs::remove_file(&squashfs_path)
        .with_context(|| format!("remove temporary {}", squashfs_path.display()))?;

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
        netboot_initrd_format: NIXOS_NETBOOT_INITRD_FORMAT.to_string(),
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
    validate_cmdline(Some(&manifest.cmdline))?;
    if manifest.netboot_cpio_path.trim().is_empty() {
        return Ok(format!(
            "#!ipxe\n\
             echo Cybex Forge: Default Enrollment\n\
             kernel {kernel_url} initrd=initrd {cmdline}\n\
             initrd --name initrd {initrd_url}\n\
             boot\n",
            cmdline = manifest.cmdline
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
        cmdline = manifest.cmdline
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
    squashfs_path: &Path,
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
    squashfs_path: &Path,
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
    write_newc_file_from_path(
        &mut output,
        "nix-store.squashfs",
        squashfs_path,
        0o100644,
        next_ino,
    )?;
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
) -> Result<()> {
    let mut response = signed_download_request(state, managed, download_path)
        .await?
        .send()
        .await
        .context("download managed ISO request failed")?;
    let status = response.status();
    if !status.is_success() {
        bail!("download managed ISO failed with HTTP {status}");
    }
    if response
        .content_length()
        .is_some_and(|len| len > expected_size as u64)
    {
        bail!("download managed ISO response exceeded expected size");
    }

    let tmp = managed_iso_tmp_path(path)?;
    let download_result =
        download_managed_iso_to_tmp(&mut response, &tmp, expected_size, expected_sha).await;
    if download_result.is_err() {
        let _ = tokio_fs::remove_file(&tmp).await;
    }
    download_result?;
    tokio_fs::rename(&tmp, path)
        .await
        .with_context(|| format!("replace managed ISO {}", path.display()))?;
    Ok(())
}

async fn download_managed_iso_to_tmp(
    response: &mut reqwest::Response,
    tmp: &Path,
    expected_size: i64,
    expected_sha: &str,
) -> Result<()> {
    let mut file = tokio_fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(tmp)
        .await
        .with_context(|| format!("create temporary ISO {}", tmp.display()))?;
    let mut hasher = Sha256::new();
    let mut downloaded = 0i64;

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
    }
    file.sync_all().await.context("sync managed ISO download")?;
    drop(file);

    if downloaded != expected_size {
        bail!("managed ISO download size mismatch");
    }
    let actual_sha = hex::encode(hasher.finalize());
    if actual_sha != expected_sha {
        bail!("managed ISO checksum mismatch");
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

fn profile_sync_failed_report(
    target: &ManagedIsoSyncTarget,
    started_at: chrono::DateTime<Utc>,
    err: anyhow::Error,
) -> BootAgentProfileSyncReport {
    BootAgentProfileSyncReport {
        profile_id: target.profile_id.clone(),
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

fn managed_iso_tmp_path(path: &Path) -> Result<PathBuf> {
    let filename = path
        .file_name()
        .ok_or_else(|| anyhow!("managed ISO path has no filename"))?
        .to_string_lossy();
    let mut random = [0u8; 8];
    OsRng.fill_bytes(&mut random);
    Ok(path.with_file_name(format!(
        ".{filename}.{}.{}.tmp",
        std::process::id(),
        hex::encode(random)
    )))
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
        let existing: Option<(i64, Option<String>, Option<String>)> = sqlx::query_as(
            "SELECT id, iso_path, raw_script FROM boot_profiles WHERE managed_profile_id = ?",
        )
        .bind(&profile.id)
        .fetch_optional(&mut **tx)
        .await?;
        if let Some((id, existing_iso_path, existing_raw_script)) = existing {
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
            .bind(&now)
            .bind(id)
            .execute(&mut **tx)
            .await?;
        } else {
            let raw_script = managed_profile_raw_script(profile, None);
            let iso_path = managed_profile_iso_path(profile, None, raw_script.as_deref())?;
            sqlx::query(
                "INSERT INTO boot_profiles
                 (managed_profile_id, name, description, profile_type, installer_iso_source,
                  enabled, is_default, one_time, kernel_path, initrd_path, iso_path, cmdline,
                  raw_script, desired_iso_artifact_id, desired_iso_filename,
                  desired_iso_size_bytes, desired_iso_sha256, desired_iso_built_at,
                  desired_iso_url, desired_iso_download_url, created_at, updated_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
    let canonical =
        canonical_agent_payload(method.as_str(), path, &timestamp, &request_id, &body_sha256);
    let signature = URL_SAFE_NO_PAD.encode(signing.sign(canonical.as_bytes()).to_bytes());
    let endpoint = api_url_for_config(config, path)?;
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
    let canonical = canonical_agent_payload("GET", path, &timestamp, &request_id, &body_sha256);
    let signature = URL_SAFE_NO_PAD.encode(signing.sign(canonical.as_bytes()).to_bytes());
    let endpoint = api_url(state, path)?;
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
        "capabilities": forge_capabilities(),
        "unsupported_capabilities": [],
        "public_key": public_key,
        "public_key_fingerprint": public_key_fingerprint,
        "hardware_fingerprint": machine_id_hash.clone(),
        "hardware_fingerprint_candidates": [machine_id_hash.clone()],
        "hardware_fingerprint_sources": {
            "machine_id_hash": machine_id_hash,
            "public_key_fingerprint": public_key_fingerprint,
        },
        "facts": {
            "service": "cybex-forge",
            "public_base_url": state.config.public_base_url(),
            "listen_addr": state.config.server.listen_addr.clone(),
            "tftp_root": state.config.paths.tftp_dir.display().to_string(),
            "http_root": state.config.paths.boot_assets_dir.display().to_string(),
            "bootloader_filename": state.config.boot.bootloader_filename.clone(),
            "menu_timeout_ms": state.config.boot.menu_timeout_ms,
            "capabilities": forge_capabilities(),
        }
    }))
}

fn forge_capabilities() -> Vec<&'static str> {
    vec![
        CAPABILITY_BOOT_V1,
        CAPABILITY_BUILDER_V1,
        CAPABILITY_CACHE_V1,
    ]
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
        bail!("{context} failed with HTTP {status}");
    }
    let body = read_bounded_response_body(&mut response, context).await?;
    serde_json::from_slice::<T>(&body).with_context(|| format!("parse {context} response failed"))
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
    Client::builder()
        .connect_timeout(connect_timeout)
        .build()
        .context("failed to build managed ISO download HTTP client")
}

fn bounded_http_timeout_seconds(value: u64) -> u64 {
    value.clamp(1, 300)
}

fn managed_sync_interval_seconds(config: &ManageConfig, outcome: SyncOutcome) -> u64 {
    match outcome {
        SyncOutcome::Synced => config.sync_interval_seconds.clamp(5, 3600),
        SyncOutcome::PendingEnrollment => config.enrollment_poll_seconds.clamp(1, 300),
    }
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
    let menu_timeout_ms = if settings.menu_timeout_ms == 0 {
        config.boot.menu_timeout_ms
    } else {
        settings.menu_timeout_ms
    };
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
    let mut boot_changed = false;
    let mut nginx_changed = false;
    let mut tftp_changed = false;
    let mut daemon_reload = false;

    boot_changed |= install_text_file(
        Path::new("/etc/cybex-forge/config.toml"),
        &render_managed_config(config, settings)?,
        "0640",
        "root",
        "cybex-forge",
    )?;
    nginx_changed |= install_text_file(
        Path::new("/etc/nginx/sites-available/cybex-forge"),
        &render_nginx_config(settings),
        "0644",
        "root",
        "root",
    )?;
    tftp_changed |= install_text_file(
        Path::new("/etc/default/tftpd-hpa"),
        &render_tftpd_defaults(settings),
        "0644",
        "root",
        "root",
    )?;

    daemon_reload |= install_text_file(
        Path::new("/etc/systemd/system/cybex-forge.service.d/40-write-paths.conf"),
        &render_boot_write_paths_dropin(settings),
        "0644",
        "root",
        "root",
    )?;
    daemon_reload |= install_text_file(
        Path::new("/etc/systemd/system/nginx.service.d/10-cybex-hardening.conf"),
        &render_nginx_hardening_dropin(settings),
        "0644",
        "root",
        "root",
    )?;
    daemon_reload |= install_text_file(
        Path::new("/etc/systemd/system/tftpd-hpa.service.d/10-cybex-hardening.conf"),
        &render_tftpd_hardening_dropin(settings),
        "0644",
        "root",
        "root",
    )?;
    daemon_reload |= install_text_file(
        Path::new("/etc/systemd/system/cybex-forge-check.service"),
        &render_check_service(settings),
        "0644",
        "root",
        "root",
    )?;

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
ExecStart=/usr/local/sbin/cybex-forge-check --quiet
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
                "TFTP bootloader {} does not embed {}/boot.ipxe",
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
        && text.contains("chain --autofree ${boot-url}/boot.ipxe || goto failed"))
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
         chain --autofree ${{boot-url}}/boot.ipxe || goto failed\n\n\
         :failed\n\
         echo Cybex Forge: failed to load ${{boot-url}}/boot.ipxe\n\
         echo Dropping to iPXE shell.\n\
         shell\n"
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
            managed_profile_needs_iso_sync(profile)
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
    }
    state
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
        BootAgentReportRequest, BootAgentSettingsReport, MAX_DEVICE_HOSTNAME_CHARS,
        MAX_DEVICE_NOTES_CHARS, MAX_DEVICE_SERIAL_CHARS, MAX_DEVICE_TAGS, MAX_MANAGED_CLIENTS,
        MAX_MANAGED_PROFILES, MAX_PROFILE_DESCRIPTION_CHARS, MAX_PROFILE_RAW_SCRIPT_BYTES,
        ManagedBootClient, ManagedBootProfile, ManagedBootSettings, ManagedState,
        NIXOS_NETBOOT_INITRD_FORMAT, NixosNetbootManifest, NormalizedManagedSettings, SyncOutcome,
        append_bounded_response_chunk_with_limit, asset_scan_report, boot_report_state,
        bounded_error_message, bounded_http_timeout_seconds, clean_optional, fit_boot_report_body,
        forge_capabilities, generated_iso_raw_script_can_be_preserved,
        has_unreported_known_profile_events, managed_profile_map, managed_profile_needs_iso_sync,
        managed_profile_raw_script, managed_sync_interval_seconds, normalize_managed_settings,
        optional_report_uuid, parse_nixos_netboot_ipxe_cmdline, render_check_service,
        render_nixos_netboot_script, serialize_boot_report_body, sync_clients,
        sync_deleted_clients, sync_deleted_profiles, sync_desired_profile_isos, sync_profiles,
        validate_boot_config, validate_profile, write_secure_json,
    };
    use crate::error::AppError;
    use crate::{
        AppState, boot,
        config::{AppConfig, ManageConfig},
        db,
        models::{CreateDeviceRequest, NewBootEvent},
    };
    use rand::{RngCore, rngs::OsRng};
    use std::{fs, path::PathBuf};

    #[test]
    fn asset_scan_success_is_reported_as_ok() {
        let scan = asset_scan_report(Ok(4));
        let state = boot_report_state(2, 3, 4, &scan);

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
        let state = boot_report_state(2, 3, 7, &scan);

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
    fn bounded_error_message_removes_line_breaks_and_caps_length() {
        let message = format!("{}\n{}", "x".repeat(300), "tail");
        let bounded = bounded_error_message(message);

        assert_eq!(bounded.chars().count(), 243);
        assert!(bounded.ends_with("..."));
        assert!(!bounded.contains('\n'));
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
                mac: format!("02:00:00:00:30:{idx:02x}"),
                hostname: Some(format!("node-{idx}")),
                serial_number: None,
                last_seen_at: None,
                notes: "n".repeat(1024),
                tags: vec!["rack-a".to_string()],
            })
            .collect::<Vec<_>>();
        let assets = (0..2)
            .map(|idx| BootAgentAssetReport {
                filename: format!("installer-{idx}.iso"),
                relative_path: format!("isos/installer-{idx}-{}", "x".repeat(512)),
                size_bytes: 1024,
                checksum_sha256: "a".repeat(64),
                last_scanned_at: "2026-07-01T00:00:00Z".to_string(),
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
    fn managed_config_rejects_incomplete_enrollment_iso_assignments() {
        let mut config = sample_boot_config();
        config.profiles[0].profile_type = "iso_live".to_string();
        config.profiles[0].installer_iso_source = "enrollment".to_string();
        config.profiles[0].kernel_path = None;
        config.profiles[0].cmdline = None;

        let err = validate_boot_config(&config).unwrap_err();

        assert!(err.to_string().contains("runnable boot action"));
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
        assert_eq!(
            forge_capabilities(),
            vec!["boot_v1", "builder_v1", "cache_v1"]
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

        let reports = sync_desired_profile_isos(&state, &ManagedState::default())
            .await
            .unwrap();

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
            managed_sync_interval_seconds(&config, SyncOutcome::PendingEnrollment),
            2
        );
        assert_eq!(
            managed_sync_interval_seconds(&config, SyncOutcome::Synced),
            60
        );

        let clamped = ManageConfig {
            sync_interval_seconds: 1,
            enrollment_poll_seconds: 0,
            ..ManageConfig::default()
        };
        assert_eq!(
            managed_sync_interval_seconds(&clamped, SyncOutcome::PendingEnrollment),
            1
        );
        assert_eq!(
            managed_sync_interval_seconds(&clamped, SyncOutcome::Synced),
            5
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
