#[cfg(unix)]
use std::os::{
    fd::AsRawFd,
    unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
};
use std::{
    collections::{HashMap, HashSet},
    ffi::OsString,
    fs,
    io::Write,
    path::{Path, PathBuf},
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
use tracing::{debug, warn};
use uuid::Uuid;

use crate::{
    AppState, RuntimeSettings,
    config::{
        AppConfig, ManageConfig, normalize_bootloader_filename, normalize_http_url,
        validate_menu_timeout_ms,
    },
    db,
    error::AppError,
    models::{BootProfileType, BuildJob, CacheArtifact, clean_tags, normalize_mac},
    redact::redact_sensitive_key_values,
};

const CAPABILITY_BOOT_V1: &str = "boot_v1";
const CAPABILITY_BUILDER_V1: &str = "builder_v1";
const CAPABILITY_BLUEPRINT_BUILDER_V2: &str = "blueprint_builder_v2";
const CAPABILITY_CACHE_V1: &str = "cache_v1";
const CAPABILITY_WORKSTATION_NETBOOT_V1: &str = "workstation_netboot_v1";
const CAPABILITY_PULSE_BOOT_GRANT_V1: &str = "pulse_boot_grant_v1";
const CAPABILITY_APPLIANCE_UPDATE_V1: &str = crate::appliance::APPLIANCE_UPDATE_CAPABILITY;
const CYBEX_COMPONENT_PROTOCOL_VERSION: u32 = 4;
const CYBEX_MINIMUM_MANAGE_PROTOCOL_VERSION: u32 = 4;
const CYBEX_MAXIMUM_MANAGE_PROTOCOL_VERSION: u32 = 4;
const MAX_MANAGED_PROFILES: usize = 1_000;
const MAX_DELETED_MANAGED_PROFILES: usize = 2_000;
const MAX_MANAGED_CLIENTS: usize = 2_000;
const MAX_DELETED_MANAGED_CLIENTS: usize = 2_000;
const MAX_MANAGED_BUILD_JOBS: usize = 500;
const MAX_REPORT_CLIENTS: usize = 2_000;
const MAX_REPORT_EVENTS: i64 = 500;
const MAX_REPORT_BUILD_JOBS: usize = 500;
const MAX_REPORT_CACHE_ARTIFACTS: usize = 2_000;
const MAX_MANAGED_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_BOOT_REPORT_BODY_BYTES: usize = 3 * 1024 * 1024;
// Closure-bearing cache metadata is bounded to 24 MiB. Leave
// room for the remainder of the authenticated node report so a verified
// manifest is never silently dropped solely because the transport cap is
// smaller than the persistence contract.
const MAX_PULSE_REPORT_BODY_BYTES: usize = 32 * 1024 * 1024;
const MAX_DEVICE_HOSTNAME_CHARS: usize = 253;
const MAX_DEVICE_SERIAL_CHARS: usize = 128;
const MAX_DEVICE_NOTES_CHARS: usize = 2_000;
const MAX_DEVICE_TAGS: usize = 50;
const MAX_DEVICE_TAG_CHARS: usize = 64;
const MAX_PROFILE_DESCRIPTION_CHARS: usize = 2_000;
const MAX_PROFILE_RAW_SCRIPT_BYTES: usize = 64 * 1024;
const RELIABILITY_STATE_PATH: &str = "/var/lib/cybex-pulse/reliability-state.json";
const MAX_RELIABILITY_STATE_BYTES: usize = 16 * 1024;

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
struct ManagedState {
    private_key_b64: Option<String>,
    public_key_b64: Option<String>,
    public_key_fingerprint: Option<String>,
    device_id: Option<String>,
    last_reported_event_id: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct ComponentCompatibilityContract {
    protocol_version: u32,
    minimum_pulse_protocol: u32,
    maximum_pulse_protocol: u32,
    manage_version: String,
    manage_release: String,
    #[serde(default)]
    workstation_runtime_epoch: Option<u32>,
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
struct AgentPulseConfigResponse {
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
    appliance_update: Option<crate::appliance::ManagedApplianceUpdate>,
    #[serde(default)]
    network_change: Option<crate::appliance::SignedApplianceNetworkChange>,
    #[serde(default)]
    workstation_netboot: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct PulseReportResponse {
    status: String,
    #[serde(default)]
    workstation_netboot: Option<WorkstationNetbootReportReceipt>,
}

#[derive(Debug, Deserialize)]
struct WorkstationNetbootReportReceipt {
    state: WorkstationNetbootReportReceiptState,
    #[serde(default)]
    error_code: Option<WorkstationNetbootReportReceiptErrorCode>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum WorkstationNetbootReportReceiptState {
    Accepted,
    Rejected,
    Unavailable,
    #[serde(other)]
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
enum WorkstationNetbootReportReceiptErrorCode {
    #[serde(rename = "runtime_report_missing")]
    Missing,
    #[serde(rename = "runtime_report_invalid")]
    Invalid,
    #[serde(rename = "runtime_report_stale")]
    Stale,
    #[serde(rename = "runtime_report_storage_unavailable")]
    StorageUnavailable,
    #[serde(other)]
    Unknown,
}

impl WorkstationNetbootReportReceiptErrorCode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "runtime_report_missing",
            Self::Invalid => "runtime_report_invalid",
            Self::Stale => "runtime_report_stale",
            Self::StorageUnavailable => "runtime_report_storage_unavailable",
            Self::Unknown => "runtime_report_receipt_invalid",
        }
    }
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
    #[allow(dead_code)]
    listen_addr: String,
    #[serde(default)]
    #[allow(dead_code)]
    tftp_root: String,
    #[serde(default)]
    #[allow(dead_code)]
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
    enabled: bool,
    is_default: bool,
    one_time: bool,
    raw_script: Option<String>,
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
    #[serde(default)]
    managed_device_id: Option<String>,
    #[serde(default)]
    reinstall_request_id: Option<String>,
    notes: String,
    #[serde(default)]
    tags: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
struct BootAgentReportRequest {
    protocol_version: u32,
    settings: BootAgentSettingsReport,
    clients: Vec<BootAgentClientReport>,
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
struct PulseAgentReportRequest {
    protocol_version: u32,
    capabilities: Vec<&'static str>,
    cache: crate::cache::CacheStatusReport,
    build_jobs: Vec<PulseBuildJobReport>,
    cache_artifacts: Vec<PulseCacheArtifactReport>,
    cache_inventory_instance_id: String,
    cache_inventory_generation: i64,
    cache_artifacts_complete: bool,
    disk: Option<crate::disk::DiskStats>,
    host: Option<crate::host::HostStats>,
    workstation_netboot: Option<crate::netboot::WorkstationNetbootReport>,
    appliance: Option<crate::appliance::ApplianceReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    appliance_report_error: Option<&'static str>,
}

#[derive(Clone, Debug, Serialize)]
struct PulseBuildJobReport {
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
    /// Enumerated rejection reason, omitted when the job was not refused.
    /// Manage screens reported prose for credential-shaped words and blanks
    /// the whole field, so the reason has to travel as a code to survive.
    #[serde(skip_serializing_if = "Option::is_none")]
    rejection_code: Option<String>,
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
struct PulseCacheArtifactReport {
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

impl From<BuildJob> for PulseBuildJobReport {
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
            rejection_code: (!job.rejection_code.is_empty()).then_some(job.rejection_code),
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

impl From<CacheArtifact> for PulseCacheArtifactReport {
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncOnceDisposition {
    Synced,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SyncOnceReport {
    pub schema: &'static str,
    pub outcome: SyncOnceDisposition,
    /// True only after Manage accepted and returned JSON for the signed Pulse
    /// report. Boot reports are intentionally not counted here.
    pub report_posted: bool,
}

impl SyncOnceReport {
    fn synced(_receipt: PulseReportReceipt) -> Self {
        Self {
            schema: "cybex.pulse.sync-once.v1",
            outcome: SyncOnceDisposition::Synced,
            report_posted: true,
        }
    }
}

#[derive(Debug)]
struct PulseReportReceipt;

#[derive(Clone, Debug)]
struct NormalizedManagedSettings {
    public_base_url: String,
    bootloader_filename: String,
    menu_timeout_ms: u32,
}

pub fn spawn(state: AppState) {
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
                            warn!(error = %err, "failed to inspect active Pulse builds for managed sync cadence");
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

pub async fn sync_once(state: &AppState) -> Result<SyncOnceReport> {
    sync_once_with_outcome(state).await
}

async fn sync_once_with_outcome(state: &AppState) -> Result<SyncOnceReport> {
    ensure_manage_enabled(state)?;
    let _state_lock = acquire_managed_state_lock(&state.config)?;
    let mut managed = load_managed_state(state)?;
    require_activated_identity(&managed)?;

    let mut first_failure = None;
    if let Err(error) = acknowledge_pending_appliance_network_change(state, &managed).await {
        retain_sync_failure(
            &mut first_failure,
            "appliance network acknowledgement",
            error,
        );
    }
    if let Err(error) = sync_boot_foundation(state, &mut managed).await {
        retain_sync_failure(&mut first_failure, "boot configuration and report", error);
    }
    let pulse_report = match sync_pulse_foundation(state, &managed).await {
        Ok(report) => Some(report),
        Err(error) => {
            retain_sync_failure(&mut first_failure, "Pulse configuration and report", error);
            None
        }
    };
    if let Err(error) = save_managed_state(state, &managed) {
        retain_sync_failure(&mut first_failure, "managed state persistence", error);
    }
    if let Some(error) = first_failure {
        return Err(error);
    }
    Ok(SyncOnceReport::synced(pulse_report.expect(
        "successful Pulse sync returns its report receipt",
    )))
}

async fn sync_boot_foundation(state: &AppState, managed: &mut ManagedState) -> Result<()> {
    let mut first_failure = None;
    match has_unreported_known_profile_events(&state.db, managed.last_reported_event_id).await {
        Ok(true) => match report_boot_state(state, managed).await {
            Ok(()) => {
                if let Err(error) = save_managed_state(state, managed) {
                    retain_sync_failure(&mut first_failure, "boot event cursor save", error);
                }
            }
            Err(error) => retain_sync_failure(&mut first_failure, "boot event pre-report", error),
        },
        Ok(false) => {}
        Err(error) => retain_sync_failure(&mut first_failure, "boot event discovery", error),
    }
    match fetch_boot_config(state, managed).await {
        Ok(config) => {
            if let Err(error) = apply_boot_config(state, &config).await {
                retain_sync_failure(&mut first_failure, "boot desired configuration", error);
            }
        }
        Err(error) => retain_sync_failure(
            &mut first_failure,
            "boot desired configuration fetch",
            error,
        ),
    }
    match report_boot_state(state, managed).await {
        Ok(()) => {
            if let Err(error) = save_managed_state(state, managed) {
                retain_sync_failure(&mut first_failure, "boot event cursor save", error);
            }
        }
        Err(error) => retain_sync_failure(&mut first_failure, "boot state report", error),
    }
    first_failure.map_or(Ok(()), Err)
}

fn retain_sync_failure(
    first_failure: &mut Option<anyhow::Error>,
    subsystem: &'static str,
    error: anyhow::Error,
) {
    warn!(
        subsystem,
        error = %safe_error(&error),
        "managed subsystem sync failed; continuing independent reconciliation"
    );
    if first_failure.is_none() {
        *first_failure = Some(error.context(format!("{subsystem} failed")));
    }
}

#[derive(Debug, FromRow)]
struct ManagedBootClientReportRow {
    mac: String,
    hostname: Option<String>,
    serial_number: Option<String>,
    last_seen_at: Option<String>,
    notes: String,
    tags: String,
}

/// Read the inventory payload from the same committed local rows that serve
/// PXE. Desired configuration remains authoritative for profile assignments.
async fn current_boot_client_reports(pool: &SqlitePool) -> Result<Vec<BootAgentClientReport>> {
    let rows = sqlx::query_as::<_, ManagedBootClientReportRow>(
        r#"SELECT client.mac, client.hostname, client.serial_number,
                  client.last_seen_at, client.notes, client.tags
           FROM devices client
           ORDER BY CASE WHEN client.one_time_profile_id IS NOT NULL THEN 0 ELSE 1 END,
                    COALESCE(client.last_seen_at, client.created_at) DESC,
                    client.mac ASC"#,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| BootAgentClientReport {
            mac: row.mac,
            hostname: row.hostname,
            serial_number: row.serial_number,
            last_seen_at: row.last_seen_at,
            notes: row.notes,
            tags: clean_tags(serde_json::from_str(&row.tags).unwrap_or_default()),
        })
        .collect())
}

fn require_activated_identity(managed: &ManagedState) -> Result<()> {
    managed_device_id(managed).context(
        "Pulse has no V2-activated appliance identity; reinstall from personalized media",
    )?;
    signing_key(managed).context("Pulse V2 appliance signing identity is incomplete")?;
    Ok(())
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
    let config: AgentBootConfigResponse =
        parse_success_json(response, "fetch managed boot config").await?;
    validate_component_compatibility(config.compatibility.as_ref())?;
    Ok(config)
}

async fn report_boot_state(state: &AppState, managed: &mut ManagedState) -> Result<()> {
    let clients = current_boot_client_reports(&state.db).await?;
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
    let reported_status = if reliability_degraded {
        "warning"
    } else {
        "online"
    };
    let reported_state = boot_report_state(profile_count, clients.len(), reliability_state);
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
        clients: clients.into_iter().take(MAX_REPORT_CLIENTS).collect(),
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

async fn sync_pulse_foundation(
    state: &AppState,
    managed: &ManagedState,
) -> Result<PulseReportReceipt> {
    let mut first_failure = None;
    let mut peer_runtime_epoch = None;
    match fetch_pulse_config(state, managed).await {
        Ok(desired) => {
            peer_runtime_epoch = desired
                .compatibility
                .as_ref()
                .and_then(|contract| contract.workstation_runtime_epoch);
            apply_pulse_desired(state, desired, &mut first_failure).await;
        }
        Err(error) => retain_sync_failure(
            &mut first_failure,
            "Pulse desired configuration fetch",
            error,
        ),
    }
    let report = match report_pulse_state(state, managed, peer_runtime_epoch.is_some()).await {
        Ok(report) => Some(report),
        Err(error) => {
            retain_sync_failure(&mut first_failure, "Pulse state report", error);
            None
        }
    };
    if let Some(error) = first_failure {
        return Err(error);
    }
    Ok(report.expect("successful Pulse report returns its receipt"))
}

async fn apply_pulse_desired(
    state: &AppState,
    desired: AgentPulseConfigResponse,
    first_failure: &mut Option<anyhow::Error>,
) {
    if let Some(workstation_netboot) = desired.workstation_netboot {
        match crate::netboot::decode_desired(workstation_netboot.clone()) {
            Ok(workstation_netboot) => {
                if !crate::netboot::queue_reconcile_desired(state, workstation_netboot) {
                    debug!(
                        "coalesced the latest workstation runtime desired state behind the in-flight reconciliation"
                    );
                }
            }
            Err(error) => {
                warn!(
                    failure_kind = crate::netboot::safe_failure_kind(&error),
                    safe_detail = %crate::netboot::safe_failure_message(&error),
                    "isolated an unusable workstation netboot desired state"
                );
                if !crate::netboot::queue_desired_decode_failure(state, workstation_netboot, &error)
                {
                    debug!(
                        "coalesced workstation runtime decoding failure behind the in-flight reconciliation"
                    );
                }
            }
        }
    }

    if let Some(update) = desired.appliance_update {
        if !crate::appliance::queue_update_request(update) {
            debug!("coalesced the latest appliance update behind the in-flight download");
        }
    }
    if let Err(error) = crate::appliance::store_network_change(desired.network_change) {
        retain_sync_failure(first_failure, "appliance network desired state", error);
    }

    let build_count_valid = desired.build_jobs.len() <= MAX_MANAGED_BUILD_JOBS;
    if !build_count_valid {
        retain_sync_failure(
            first_failure,
            "managed build desired state",
            anyhow!("managed pulse config returned more than {MAX_MANAGED_BUILD_JOBS} build jobs"),
        );
    }
    let mut build_snapshot_applied = build_count_valid;
    let mut retained_job_ids = Vec::with_capacity(desired.build_jobs.len());
    if build_count_valid {
        for job in desired.build_jobs {
            retained_job_ids.push(job.id.clone());
            let sync = db::upsert_managed_build_job(
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
            .await;
            match sync {
                Ok(_) => {}
                Err(AppError::Validation(reason)) => {
                    warn!(
                        job_id = %job.id,
                        %reason,
                        "rejecting managed build job; reporting it to Manage as failed"
                    );
                    if let Err(error) = db::record_rejected_managed_build_job(
                        &state.db,
                        &job.id,
                        &job.requested_artifact_type,
                        job.target.as_deref(),
                        job.system.as_deref(),
                        &job.input_revision,
                        &job.input_config_hash,
                        &reason,
                    )
                    .await
                    {
                        build_snapshot_applied = false;
                        retain_sync_failure(
                            first_failure,
                            "rejected managed build persistence",
                            anyhow::Error::new(error),
                        );
                    }
                }
                Err(error) => {
                    build_snapshot_applied = false;
                    retain_sync_failure(
                        first_failure,
                        "managed build desired state",
                        anyhow::Error::new(error)
                            .context(format!("sync managed build job {}", job.id)),
                    );
                }
            }
        }
    }
    if desired.build_jobs_complete && build_snapshot_applied {
        if let Err(error) = db::cancel_absent_managed_build_jobs(&state.db, &retained_job_ids).await
        {
            retain_sync_failure(
                first_failure,
                "managed build snapshot cancellation",
                error.into(),
            );
        }
    }
    if let Err(error) =
        db::cancel_managed_build_jobs(&state.db, &desired.deleted_build_job_ids).await
    {
        retain_sync_failure(first_failure, "managed build deletion", error.into());
    }

    let deletion_keys = desired
        .deleted_cache_artifacts
        .into_iter()
        .map(|artifact| (artifact.artifact_type, artifact.hash))
        .collect::<Vec<_>>();
    if let Err(error) =
        crate::cache::remove_artifacts_by_key(&state.db, &state.config, &deletion_keys).await
    {
        retain_sync_failure(first_failure, "managed cache deletion", error);
    }
    let protected_keys = desired
        .protected_cache_artifacts
        .into_iter()
        .map(|artifact| (artifact.artifact_type, artifact.hash))
        .collect::<Vec<_>>();
    let protections_applied = match db::replace_managed_cache_protections(
        &state.db,
        &protected_keys,
        desired.protected_cache_artifacts_complete,
    )
    .await
    {
        Ok(()) => true,
        Err(error) => {
            retain_sync_failure(first_failure, "managed cache protections", error.into());
            false
        }
    };
    if protections_applied {
        match crate::cache::try_enforce_retention(&state.db, &state.config).await {
            Ok(true) => {}
            Ok(false) => {
                debug!("cache mutation is active; deferring retention until the next managed sync")
            }
            Err(error) => retain_sync_failure(first_failure, "managed cache retention", error),
        }
    }
}

async fn acknowledge_pending_appliance_network_change(
    state: &AppState,
    managed: &ManagedState,
) -> Result<()> {
    let Some(pending) = crate::appliance::pending_network_acknowledgement()? else {
        return Ok(());
    };
    let device_id = managed_device_id(managed)?;
    let path = format!(
        "/v1/agent/devices/{device_id}/pulse/network-changes/{}/acknowledge",
        pending.change_id
    );
    let body = serde_json::to_vec(&json!({
        "candidate_sha256": pending.candidate_sha256,
    }))?;
    let response = signed_request(state, managed, Method::POST, &path, body)
        .await?
        .header(CONTENT_TYPE, "application/json")
        .send()
        .await
        .context("acknowledge applied appliance network candidate")?;
    let acknowledgement: crate::appliance::SignedApplianceNetworkAcknowledgement =
        parse_success_json(response, "acknowledge appliance network candidate").await?;
    crate::appliance::accept_network_acknowledgement(&acknowledgement)
}

async fn fetch_pulse_config(
    state: &AppState,
    managed: &ManagedState,
) -> Result<AgentPulseConfigResponse> {
    let device_id = managed_device_id(managed)?;
    let path = format!("/v1/agent/devices/{device_id}/pulse/config");
    let response = signed_request(state, managed, Method::GET, &path, Vec::new())
        .await?
        .send()
        .await
        .context("fetch managed pulse config request failed")?;
    let config: AgentPulseConfigResponse =
        parse_success_json(response, "fetch managed pulse config").await?;
    validate_component_compatibility(config.compatibility.as_ref())?;
    Ok(config)
}

async fn report_pulse_state(
    state: &AppState,
    managed: &ManagedState,
    peer_supports_runtime_fencing: bool,
) -> Result<PulseReportReceipt> {
    let (build_jobs, build_listing_valid) = match db::list_build_jobs(&state.db).await {
        Ok(jobs) => (jobs, true),
        Err(_) => {
            warn!(
                error_code = "build_report_storage_unavailable",
                "could not read build reports; continuing independent Pulse report lanes"
            );
            (Vec::new(), false)
        }
    };
    let cache_scrub_valid = match crate::cache::try_scrub_cache_artifacts(
        &state.db,
        &state.config,
        8,
    )
    .await
    {
        Ok(Some(_)) => true,
        Ok(None) => {
            debug!(
                "cache mutation is active; deferring integrity scrub until the next managed sync"
            );
            true
        }
        Err(err) => {
            warn!(error = %err, "Pulse cache integrity scrub failed");
            false
        }
    };
    let (cache_artifacts, cache_listing_complete, cache_listing_valid) =
        match db::list_cache_artifacts(&state.db).await {
            Ok(artifacts) => {
                let complete = artifacts.len() <= MAX_REPORT_CACHE_ARTIFACTS;
                (artifacts, complete, true)
            }
            Err(_) => {
                warn!(
                    error_code = "cache_artifact_report_storage_unavailable",
                    "could not read cache artifact reports; sending a non-authoritative cache lane"
                );
                (Vec::new(), false, false)
            }
        };
    let (cache_inventory_instance_id, cache_inventory_generation, cache_inventory_valid) =
        match db::cache_inventory_state(&state.db).await {
            Ok(inventory) => (inventory.instance_id, inventory.generation, true),
            Err(_) => {
                warn!(
                    error_code = "cache_inventory_report_storage_unavailable",
                    "could not read cache inventory generation; isolating the cache lane"
                );
                (String::new(), 0, false)
            }
        };
    let cache_inventory_generation = cache_inventory_generation_for_peer(
        cache_inventory_generation,
        cache_listing_valid,
        cache_inventory_valid,
        peer_supports_runtime_fencing,
    );
    let cache_artifacts_complete =
        cache_listing_complete && cache_inventory_valid && cache_scrub_valid;
    let local_cache_build_state_valid =
        build_listing_valid && cache_scrub_valid && cache_listing_valid && cache_inventory_valid;
    let cache = cache_status_for_local_state(
        crate::cache::status_report(&state.config, &state.db).await,
        local_cache_build_state_valid,
    );
    let workstation_netboot = match crate::netboot::report(state).await {
        Ok(report) => Some(runtime_report_for_peer(
            report,
            peer_supports_runtime_fencing,
        )),
        Err(error) => {
            warn!(
                error_code = crate::netboot::ERROR_RUNTIME_REPORT_STORAGE_UNAVAILABLE,
                safe_detail = %crate::netboot::safe_failure_message(&error),
                "workstation runtime report generation failed; sending null without blocking the Pulse report"
            );
            None
        }
    };
    let (appliance, appliance_report_error) = match crate::appliance::report().await {
        Ok(report) => (report, None),
        Err(error) => {
            warn!(
                error = %safe_error(&error),
                "appliance report generation failed; sending null without blocking independent Pulse state"
            );
            (None, Some("local_state_unavailable"))
        }
    };
    let body = PulseAgentReportRequest {
        protocol_version: CYBEX_COMPONENT_PROTOCOL_VERSION,
        capabilities: pulse_capabilities(&state.config),
        cache,
        build_jobs: build_jobs
            .into_iter()
            .take(MAX_REPORT_BUILD_JOBS)
            .map(PulseBuildJobReport::from)
            .collect(),
        cache_artifacts: cache_artifacts
            .into_iter()
            .take(MAX_REPORT_CACHE_ARTIFACTS)
            .map(PulseCacheArtifactReport::from)
            .collect(),
        cache_inventory_instance_id,
        cache_inventory_generation,
        cache_artifacts_complete,
        disk: crate::disk::stats(&state.config.cache.root_dir).ok(),
        host: crate::host::sample().await,
        workstation_netboot,
        appliance,
        appliance_report_error,
    };
    let (_body, body_bytes) = fit_pulse_report_body(body, MAX_PULSE_REPORT_BODY_BYTES)?;
    let device_id = managed_device_id(managed)?;
    let path = format!("/v1/agent/devices/{device_id}/pulse/report");
    let response = signed_request(state, managed, Method::POST, &path, body_bytes)
        .await?
        .header(CONTENT_TYPE, "application/json")
        .send()
        .await
        .context("report managed pulse state request failed")?;
    let response =
        parse_success_json::<PulseReportResponse>(response, "report managed pulse state").await?;
    validate_pulse_report_response(&response)?;
    Ok(PulseReportReceipt)
}

fn validate_pulse_report_response(response: &PulseReportResponse) -> Result<()> {
    if response.status != "ok" {
        bail!("Manage returned an invalid Pulse report status");
    }
    let Some(receipt) = response.workstation_netboot.as_ref() else {
        // Older Manage releases predate isolated runtime receipts.
        return Ok(());
    };
    match (receipt.state, receipt.error_code) {
        (WorkstationNetbootReportReceiptState::Accepted, None) => Ok(()),
        (
            WorkstationNetbootReportReceiptState::Rejected
            | WorkstationNetbootReportReceiptState::Unavailable,
            Some(code),
        ) if code != WorkstationNetbootReportReceiptErrorCode::Unknown => Err(anyhow!(
            "Manage did not accept workstation runtime evidence ({})",
            code.as_str()
        )),
        _ => bail!("Manage returned an invalid workstation runtime report receipt"),
    }
}

fn runtime_report_for_peer(
    mut report: crate::netboot::WorkstationNetbootReport,
    peer_supports_runtime_fencing: bool,
) -> crate::netboot::WorkstationNetbootReport {
    if !peer_supports_runtime_fencing {
        report.compatibility_epoch = None;
        report.reconcile_generation = None;
        // The legacy nested DTO rejects unknown fields and its invariant also
        // rejects failure evidence on a ready runtime. Omit the additive
        // warning during a Manage-first rolling upgrade; new peers receive it.
        report.warning_kind = None;
        report.warning_message = None;
    }
    report
}

fn cache_inventory_generation_for_peer(
    generation: i64,
    cache_listing_valid: bool,
    cache_inventory_valid: bool,
    peer_supports_lane_isolation: bool,
) -> i64 {
    if peer_supports_lane_isolation && (!cache_listing_valid || !cache_inventory_valid) {
        // A negative generation is rejected by Manage's isolated cache lane.
        // This prevents a best-effort empty snapshot (or an independently
        // optimistic cache status report) from refreshing cache health when
        // Pulse could not read its authoritative local inventory.
        -1
    } else {
        generation
    }
}

fn cache_status_for_local_state(
    mut report: crate::cache::CacheStatusReport,
    local_state_valid: bool,
) -> crate::cache::CacheStatusReport {
    if !local_state_valid {
        // `cache::status_report` deliberately stays best-effort and may mask
        // a local database read failure while collecting diagnostics. At the
        // managed report boundary, however, cache and build form one
        // capability and every peer already understands this error shape.
        // Preserve the cache trust identity and measurements while making the
        // unavailable local state explicit.
        report.status = "error".to_string();
        report.error = "local_state_unavailable".to_string();
    }
    report
}

fn fit_pulse_report_body(
    mut body: PulseAgentReportRequest,
    max_bytes: usize,
) -> Result<(PulseAgentReportRequest, Vec<u8>)> {
    let original_jobs = body.build_jobs.len();
    let original_artifacts = body.cache_artifacts.len();
    let mut body_bytes = serialize_pulse_report_body(&body)?;
    if body_bytes.len() <= max_bytes {
        return Ok((body, body_bytes));
    }

    // Logs are diagnostic convenience; the managed job identity, state and
    // cache metadata are the durable evidence that Manage needs. Drop logs
    // first so the newest active and terminal job reports remain intact.
    for job in &mut body.build_jobs {
        job.logs.clear();
    }
    body_bytes = serialize_pulse_report_body(&body)?;
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
        body_bytes = serialize_pulse_report_body(&body)?;
    }

    if body_bytes.len() > max_bytes && !body.cache_artifacts.is_empty() {
        let fitting = max_fitting_prefix_len(body.cache_artifacts.len(), |count| {
            let mut candidate = body.clone();
            candidate.cache_artifacts.truncate(count);
            candidate.cache_artifacts_complete = false;
            serialize_pulse_report_body(&candidate).is_ok_and(|bytes| bytes.len() <= max_bytes)
        });
        body.cache_artifacts.truncate(fitting);
        body.cache_artifacts_complete = false;
        body_bytes = serialize_pulse_report_body(&body)?;
    }

    if body_bytes.len() > max_bytes {
        bail!("managed pulse report base body exceeded {max_bytes} bytes");
    }
    warn!(
        jobs_sent = body.build_jobs.len(),
        jobs_total = original_jobs,
        cache_artifacts_sent = body.cache_artifacts.len(),
        cache_artifacts_total = original_artifacts,
        max_bytes,
        "managed pulse report trimmed to fit request budget"
    );
    Ok((body, body_bytes))
}

fn serialize_pulse_report_body(body: &PulseAgentReportRequest) -> Result<Vec<u8>> {
    serde_json::to_vec(body).context("serialize managed pulse report")
}

fn fit_boot_report_body(
    mut body: BootAgentReportRequest,
    max_bytes: usize,
) -> Result<(BootAgentReportRequest, Vec<u8>)> {
    let original_clients = body.clients.len();
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
        let existing: Option<i64> =
            sqlx::query_scalar("SELECT id FROM boot_profiles WHERE managed_profile_id = ?")
                .bind(&profile.id)
                .fetch_optional(&mut **tx)
                .await?;
        let raw_script = clean_optional(profile.raw_script.clone());
        if let Some(id) = existing {
            sqlx::query(
                "UPDATE boot_profiles
                 SET name = ?, description = ?, profile_type = ?, enabled = ?,
                     is_default = ?, one_time = ?, raw_script = ?, updated_at = ?
                 WHERE id = ?",
            )
            .bind(profile.name.trim())
            .bind(&profile.description)
            .bind(profile_type.as_str())
            .bind(bool_to_i64(profile.enabled))
            .bind(bool_to_i64(profile.is_default))
            .bind(bool_to_i64(profile.one_time))
            .bind(raw_script)
            .bind(&now)
            .bind(id)
            .execute(&mut **tx)
            .await?;
        } else {
            sqlx::query(
                "INSERT INTO boot_profiles
                 (managed_profile_id, name, description, profile_type, enabled,
                  is_default, one_time, raw_script, created_at, updated_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(&profile.id)
            .bind(profile.name.trim())
            .bind(&profile.description)
            .bind(profile_type.as_str())
            .bind(bool_to_i64(profile.enabled))
            .bind(bool_to_i64(profile.is_default))
            .bind(bool_to_i64(profile.one_time))
            .bind(raw_script)
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
                     default_profile_id = ?,
                     one_time_consumed_at = CASE
                       WHEN one_time_profile_id IS NOT ? THEN NULL
                       ELSE one_time_consumed_at
                     END,
                     one_time_profile_id = ?,
                     managed_device_id = ?, reinstall_request_id = ?, updated_at = ?
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
            .bind(one_time_profile_id)
            .bind(clean_optional(client.managed_device_id.clone()))
            .bind(clean_optional(client.reinstall_request_id.clone()))
            .bind(&now)
            .bind(id)
            .execute(&mut **tx)
            .await?;
        } else {
            sqlx::query(
                "INSERT INTO devices
                 (managed_client_id, mac, hostname, serial_number, last_seen_at, notes, tags,
                  default_profile_id, one_time_profile_id, managed_device_id,
                  reinstall_request_id, created_at, updated_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
            .bind(clean_optional(client.managed_device_id.clone()))
            .bind(clean_optional(client.reinstall_request_id.clone()))
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

fn pulse_capabilities(_config: &AppConfig) -> Vec<&'static str> {
    let mut capabilities = vec![
        CAPABILITY_BOOT_V1,
        CAPABILITY_BUILDER_V1,
        CAPABILITY_BLUEPRINT_BUILDER_V2,
        CAPABILITY_CACHE_V1,
        CAPABILITY_WORKSTATION_NETBOOT_V1,
        CAPABILITY_PULSE_BOOT_GRANT_V1,
    ];
    capabilities.push(CAPABILITY_APPLIANCE_UPDATE_V1);
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

pub(crate) struct PulseBootIdentity {
    pub device_id: String,
    pub signing_key: SigningKey,
}

/// Load the already-adopted node identity for short-lived boot-grant signing.
/// This never creates or rotates key material: PXE must fail closed until the
/// same identity Manage has adopted is durable on disk.
pub(crate) fn pulse_boot_identity(config: &AppConfig) -> Result<PulseBootIdentity> {
    let managed = load_managed_state_from_config(config)?;
    let device_id = managed_device_id(&managed)?.to_string();
    let signing_key = signing_key(&managed)?;
    Ok(PulseBootIdentity {
        device_id,
        signing_key,
    })
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
struct AdvisoryFileLock(fs::File);

#[cfg(unix)]
impl Drop for AdvisoryFileLock {
    fn drop(&mut self) {
        let _ = unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

#[cfg(not(unix))]
type AdvisoryFileLock = fs::File;

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

fn http_client_for_config(config: &AppConfig) -> Result<Client> {
    let timeout = Duration::from_secs(bounded_http_timeout_seconds(
        config.manage.http_timeout_seconds,
    ));
    Client::builder()
        .timeout(timeout)
        .connect_timeout(timeout.min(Duration::from_secs(10)))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("failed to build managed HTTP client")
}

fn bounded_http_timeout_seconds(value: u64) -> u64 {
    value.clamp(1, 300)
}

fn managed_sync_interval_seconds(config: &ManageConfig, _outcome: SyncOnceDisposition) -> u64 {
    config.sync_interval_seconds.clamp(5, 3600)
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
    let profile_type = BootProfileType::from_str(&profile.profile_type)
        .map_err(|err| anyhow!("invalid managed profile type: {err}"))?;
    if profile_type != BootProfileType::CustomIpxe
        && profile
            .raw_script
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
    {
        bail!("managed boot profile raw_script is only valid for custom_ipxe");
    }
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
    let contract =
        contract.ok_or_else(|| anyhow!("managed protocol-4 compatibility is required"))?;
    if !(CYBEX_MINIMUM_MANAGE_PROTOCOL_VERSION..=CYBEX_MAXIMUM_MANAGE_PROTOCOL_VERSION)
        .contains(&contract.protocol_version)
        || !(contract.minimum_pulse_protocol..=contract.maximum_pulse_protocol)
            .contains(&CYBEX_COMPONENT_PROTOCOL_VERSION)
        || contract.workstation_runtime_epoch == Some(0)
    {
        bail!(
            "incompatible Manage protocol {} (Pulse protocol {}, supported Pulse range {} through {}, Manage version {}, release {})",
            contract.protocol_version,
            CYBEX_COMPONENT_PROTOCOL_VERSION,
            contract.minimum_pulse_protocol,
            contract.maximum_pulse_protocol,
            clean_string(&contract.manage_version),
            clean_string(&contract.manage_release),
        );
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
    let bootloader_filename = if settings.bootloader_filename.trim().is_empty() {
        config.boot.bootloader_filename.clone()
    } else {
        normalize_bootloader_filename(&settings.bootloader_filename)?
    };
    let menu_timeout_ms = settings.menu_timeout_ms;
    validate_menu_timeout_ms(menu_timeout_ms)?;

    Ok(NormalizedManagedSettings {
        public_base_url,
        bootloader_filename,
        menu_timeout_ms,
    })
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
    match profile.profile_type.as_str() {
        "local_disk" | "pulse_installer" => true,
        "custom_ipxe" => profile
            .raw_script
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty()),
        _ => false,
    }
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

fn bool_to_i64(value: bool) -> i64 {
    if value { 1 } else { 0 }
}

fn boot_report_state(
    profile_count: usize,
    client_count: usize,
    reliability_state: Option<Value>,
) -> Value {
    let mut state = json!({
        "managed": true,
        "profile_count": profile_count,
        "client_count": client_count,
    });
    if let Some(object) = state.as_object_mut() {
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
            "ignoring oversized Pulse reliability state"
        );
        return None;
    }
    match serde_json::from_slice::<Value>(&bytes) {
        Ok(Value::Object(object)) => Some(Value::Object(object)),
        Ok(_) => {
            warn!(
                path = RELIABILITY_STATE_PATH,
                "ignoring non-object Pulse reliability state"
            );
            None
        }
        Err(err) => {
            warn!(path = RELIABILITY_STATE_PATH, error = %err, "ignoring invalid Pulse reliability state");
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

fn safe_error(err: &anyhow::Error) -> String {
    // `{:#}` walks the whole cause chain. Plain Display shows only the
    // outermost context, which named the failing job but never the reason --
    // "sync managed build job <uuid>" repeated for hours with the actual
    // validation error nowhere in the journal.
    let text = format!("{err:#}");
    for sensitive in ["private_key"] {
        if text.to_ascii_lowercase().contains(sensitive) {
            return "managed sync failed; see service configuration".to_string();
        }
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{AppConfig, ManageConfig},
        db,
        models::{CreateDeviceRequest, NewBootEvent},
    };
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use ed25519_dalek::{Signature, SigningKey, Verifier};
    use rand::{RngCore, rngs::OsRng};
    use reqwest::Method;
    use std::{fs, path::PathBuf, time::Duration};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        time::timeout,
    };

    async fn assert_client_does_not_follow_redirect(client: reqwest::Client) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut first, _) = listener.accept().await.unwrap();
            let mut request = vec![0u8; 4096];
            let _ = first.read(&mut request).await.unwrap();
            first
                .write_all(
                    format!(
                        "HTTP/1.1 302 Found\r\nLocation: http://{address}/redirect-target\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            timeout(Duration::from_millis(250), listener.accept())
                .await
                .is_ok()
        });
        let response = client
            .post(format!("http://{address}/enrollment"))
            .body("one-time-enrollment-body")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::FOUND);
        assert!(!server.await.unwrap(), "redirect target was fetched");
    }

    #[tokio::test]
    async fn managed_http_clients_refuse_redirects() {
        let config = AppConfig::default();
        assert_client_does_not_follow_redirect(http_client_for_config(&config).unwrap()).await;
    }

    #[tokio::test]
    async fn signed_requests_canonicalize_the_final_prefixed_path_and_query() {
        let signing = SigningKey::from_bytes(&[11_u8; 32]);
        let managed = ManagedState {
            device_id: Some("pulse-123".to_string()),
            private_key_b64: Some(STANDARD.encode(signing.to_bytes())),
            ..ManagedState::default()
        };
        let mut config = AppConfig::default();
        config.manage.api_url = "https://manage.example.invalid/api".to_string();
        config.manage.organization_id = "org-123".to_string();
        let relative = "/v1/agent/devices/pulse-123/config?cursor=a%2Fb";
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
            "/api/v1/agent/devices/pulse-123/config?cursor=a%2Fb"
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
    fn reliability_incident_is_included_in_managed_report_state() {
        let reliability = serde_json::json!({
            "status": "degraded",
            "last_component": "dns",
            "total_repairs": 2
        });
        let state = boot_report_state(1, 0, Some(reliability));

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
            tftp_root: "/srv/cybex-pulse/tftp-managed".to_string(),
            http_root: "/srv/cybex-pulse/www-managed".to_string(),
            bootloader_filename: " ipxe.efi ".to_string(),
            menu_timeout_ms: 1_000,
        };

        let normalized = normalize_managed_settings(&settings, &app_config).unwrap();

        assert_eq!(normalized.public_base_url, "http://boot.example");
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
        assert_eq!(
            normalized.bootloader_filename,
            app_config.boot.bootloader_filename
        );
        assert_eq!(normalized.menu_timeout_ms, app_config.boot.menu_timeout_ms);
    }

    #[test]
    fn managed_settings_reject_invalid_runtime_values() {
        let app_config = AppConfig::default();
        let invalid_url = ManagedBootSettings {
            public_base_url: "http://boot.example/path?debug=true".to_string(),
            listen_addr: "127.0.0.1:8080".to_string(),
            tftp_root: "/srv/cybex-pulse/tftp".to_string(),
            http_root: "/srv/cybex-pulse/www".to_string(),
            bootloader_filename: "snponly.efi".to_string(),
            menu_timeout_ms: 10_000,
        };
        let invalid_loader = ManagedBootSettings {
            public_base_url: "http://boot.example".to_string(),
            listen_addr: "127.0.0.1:8080".to_string(),
            tftp_root: "/srv/cybex-pulse/tftp".to_string(),
            http_root: "/srv/cybex-pulse/www".to_string(),
            bootloader_filename: "../snponly.efi".to_string(),
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
        config.profiles[0].profile_type = "custom_ipxe".to_string();
        config.profiles[0].raw_script = None;

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
        config.profiles[0].raw_script = None;

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
    async fn armed_one_time_inventory_is_ordered_before_the_client_cap() {
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
        let target_mac = format!(
            "02:00:{:02x}:{:02x}:{:02x}:{:02x}",
            (target_index >> 24) & 0xff,
            (target_index >> 16) & 0xff,
            (target_index >> 8) & 0xff,
            target_index & 0xff,
        );
        assert_eq!(reports.len(), MAX_REPORT_CLIENTS + 1);
        assert_eq!(reports[0].mac, target_mac);
        assert!(
            reports
                .into_iter()
                .take(MAX_REPORT_CLIENTS)
                .any(|report| report.mac == target_mac)
        );
    }

    #[tokio::test]
    async fn boot_client_report_does_not_echo_desired_assignment_state() {
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
        let report = serde_json::to_value(&reports[0]).unwrap();
        assert_eq!(report["mac"], "02:00:00:00:10:01");
        assert!(report.get("managed_client_id").is_none());
        assert!(report.get("default_profile_id").is_none());
        assert!(report.get("one_time_profile_id").is_none());
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
    fn pulse_capabilities_report_build_and_cache() {
        let config = AppConfig::default();
        assert_eq!(
            pulse_capabilities(&config),
            vec![
                "boot_v1",
                "builder_v1",
                "blueprint_builder_v2",
                "cache_v1",
                "workstation_netboot_v1",
                "pulse_boot_grant_v1",
                "appliance_update_v1"
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

    #[test]
    fn secure_json_write_is_owner_only_and_cleans_tmp() {
        let path = temp_state_dir().join("manage-state.json");
        let state = ManagedState {
            device_id: Some("dev_test".to_string()),
            ..ManagedState::default()
        };

        write_secure_json(&path, &state).unwrap();

        let loaded: ManagedState = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(loaded.device_id.as_deref(), Some("dev_test"));

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
                minimum_pulse_protocol: 1,
                maximum_pulse_protocol: CYBEX_COMPONENT_PROTOCOL_VERSION,
                manage_version: "0.1.0".to_string(),
                manage_release: "test".to_string(),
                workstation_runtime_epoch: Some(crate::netboot::COMPATIBILITY_EPOCH),
            }),
            settings: ManagedBootSettings {
                public_base_url: "http://127.0.0.1".to_string(),
                listen_addr: "127.0.0.1:8080".to_string(),
                tftp_root: "/srv/cybex-pulse/tftp".to_string(),
                http_root: "/srv/cybex-pulse/www".to_string(),
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
            manifest["pulse"]["minimum_manage_protocol"].as_u64(),
            Some(u64::from(CYBEX_MINIMUM_MANAGE_PROTOCOL_VERSION))
        );
        #[cfg(not(feature = "resilience-qualification-epoch-2"))]
        assert_eq!(
            manifest["workstation_runtime"]["compatibility_epoch"].as_u64(),
            Some(u64::from(crate::netboot::COMPATIBILITY_EPOCH))
        );
        #[cfg(feature = "resilience-qualification-epoch-2")]
        {
            assert_eq!(
                manifest["workstation_runtime"]["compatibility_epoch"].as_u64(),
                Some(1)
            );
            assert_eq!(crate::netboot::COMPATIBILITY_EPOCH, 2);
        }
        let config = sample_boot_config();
        validate_component_compatibility(config.compatibility.as_ref()).unwrap();
        assert!(validate_component_compatibility(None).is_err());

        let incompatible = ComponentCompatibilityContract {
            protocol_version: CYBEX_COMPONENT_PROTOCOL_VERSION + 1,
            minimum_pulse_protocol: CYBEX_COMPONENT_PROTOCOL_VERSION + 1,
            maximum_pulse_protocol: CYBEX_COMPONENT_PROTOCOL_VERSION + 1,
            manage_version: "future".to_string(),
            manage_release: "future".to_string(),
            workstation_runtime_epoch: Some(crate::netboot::COMPATIBILITY_EPOCH),
        };
        assert!(validate_component_compatibility(Some(&incompatible)).is_err());
    }

    #[test]
    fn runtime_warning_shape_is_negotiated_without_breaking_legacy_manage() {
        let current = crate::netboot::WorkstationNetbootReport {
            compatibility_epoch: Some(crate::netboot::COMPATIBILITY_EPOCH),
            reconcile_generation: Some(7),
            state: "ready".to_string(),
            warning_kind: Some(crate::netboot::FAILURE_INTEGRITY_MISMATCH.to_string()),
            warning_message: Some("previous rollback copy quarantined".to_string()),
            ..Default::default()
        };
        let legacy = runtime_report_for_peer(current.clone(), false);
        let legacy_value = serde_json::to_value(legacy).unwrap();
        assert!(legacy_value.get("compatibility_epoch").is_none());
        assert!(legacy_value.get("reconcile_generation").is_none());
        assert!(legacy_value.get("warning_kind").is_none());
        assert!(legacy_value.get("warning_message").is_none());
        assert_eq!(legacy_value["state"], "ready");
        assert_eq!(legacy_value["failure_kind"], "");
        assert_eq!(legacy_value["failure_message"], "");

        let current_value = serde_json::to_value(runtime_report_for_peer(current, true)).unwrap();
        assert_eq!(
            current_value["compatibility_epoch"],
            crate::netboot::COMPATIBILITY_EPOCH
        );
        assert_eq!(current_value["reconcile_generation"], 7);
        assert_eq!(
            current_value["warning_kind"],
            crate::netboot::FAILURE_INTEGRITY_MISMATCH
        );
        assert_eq!(current_value["failure_kind"], "");
    }

    #[test]
    fn pulse_report_receipt_accepts_old_manage_and_retries_isolated_rejections() {
        let legacy: PulseReportResponse = serde_json::from_value(json!({"status": "ok"})).unwrap();
        validate_pulse_report_response(&legacy).unwrap();

        let rejected: PulseReportResponse = serde_json::from_value(json!({
            "status": "ok",
            "workstation_netboot": {
                "state": "rejected",
                "error_code": "runtime_report_stale"
            }
        }))
        .unwrap();
        let error = validate_pulse_report_response(&rejected).unwrap_err();
        assert_eq!(
            error.to_string(),
            "Manage did not accept workstation runtime evidence (runtime_report_stale)"
        );
    }

    #[test]
    fn boot_sync_defers_lane_errors_until_after_config_and_final_report() {
        let source = include_str!("manage.rs");
        let start = source.find("async fn sync_boot_foundation").unwrap();
        let end = source[start..]
            .find("\nfn retain_sync_failure")
            .map(|offset| start + offset)
            .unwrap();
        let body = &source[start..end];
        let first_report = body.find("report_boot_state").unwrap();
        let config = body.find("fetch_boot_config").unwrap();
        let final_report = body.rfind("report_boot_state").unwrap();
        assert!(first_report < config && config < final_report);
        assert_eq!(body.matches("report_boot_state").count(), 2);
        assert!(body.contains("first_failure.map_or(Ok(()), Err)"));
    }

    #[test]
    fn pulse_report_inventory_failures_do_not_suppress_independent_lanes() {
        let source = include_str!("manage.rs");
        let start = source.find("async fn report_pulse_state").unwrap();
        let end = source[start..]
            .find("\nfn validate_pulse_report_response")
            .map(|offset| start + offset)
            .unwrap();
        let body = &source[start..end];
        assert!(body.contains("let (build_jobs, build_listing_valid)"));
        assert!(body.contains("match db::list_cache_artifacts"));
        assert!(body.contains("match db::cache_inventory_state"));
        assert!(body.contains("let cache_scrub_valid"));
        assert!(body.contains("(Vec::new(), false, false)"));
        assert!(body.contains("cache_inventory_generation_for_peer("));
        assert!(body.contains("cache_status_for_local_state("));
        assert!(
            body.contains("cache_listing_complete && cache_inventory_valid && cache_scrub_valid")
        );
        assert!(body.contains(
            "build_listing_valid && cache_scrub_valid && cache_listing_valid && cache_inventory_valid"
        ));
        assert!(body.contains("crate::netboot::report(state).await"));
        assert!(body.contains("crate::appliance::report().await"));
    }

    #[test]
    fn cache_inventory_read_failures_invalidate_only_fencing_capable_peer_lane() {
        assert_eq!(
            cache_inventory_generation_for_peer(41, true, true, true),
            41
        );
        assert_eq!(
            cache_inventory_generation_for_peer(41, false, true, true),
            -1,
            "an unreadable artifact list must not refresh cache health"
        );
        assert_eq!(
            cache_inventory_generation_for_peer(41, true, false, true),
            -1,
            "an unreadable inventory watermark must not refresh cache health"
        );

        assert_eq!(
            cache_inventory_generation_for_peer(41, false, true, false),
            41,
            "legacy Manage receives its existing non-authoritative incomplete shape"
        );
        assert_eq!(
            cache_inventory_generation_for_peer(0, true, false, false),
            0,
            "legacy Manage does not receive the isolated-lane sentinel"
        );
    }

    #[test]
    fn legacy_cache_report_marks_local_cache_or_build_state_unavailable_without_losing_identity() {
        let report = crate::cache::CacheStatusReport {
            enabled: true,
            status: "ready".to_string(),
            public_key: "cache.example-1:public-key".to_string(),
            public_key_fingerprint: "sha256:fingerprint".to_string(),
            base_url: "https://pulse.example/cache".to_string(),
            total_size_bytes: 1234,
            artifact_count: 3,
            error: String::new(),
        };

        let degraded = cache_status_for_local_state(report.clone(), false);
        assert_eq!(degraded.enabled, report.enabled);
        assert_eq!(degraded.status, "error");
        assert_eq!(degraded.error, "local_state_unavailable");
        assert_eq!(degraded.public_key, report.public_key);
        assert_eq!(
            degraded.public_key_fingerprint,
            report.public_key_fingerprint
        );
        assert_eq!(degraded.base_url, report.base_url);
        assert_eq!(degraded.total_size_bytes, report.total_size_bytes);
        assert_eq!(degraded.artifact_count, report.artifact_count);
        assert_eq!(
            cache_inventory_generation_for_peer(41, false, true, false),
            41,
            "legacy peers rely on the cache error instead of the isolated-lane sentinel"
        );

        let unchanged = cache_status_for_local_state(report.clone(), true);
        assert_eq!(unchanged.status, report.status);
        assert_eq!(unchanged.error, report.error);
    }

    #[test]
    fn workstation_runtime_shape_is_isolated_from_the_pulse_config_envelope() {
        let config: AgentPulseConfigResponse = serde_json::from_value(json!({
            "workstation_netboot": {
                "future_runtime_contract": true
            }
        }))
        .unwrap();

        let runtime = config
            .workstation_netboot
            .expect("raw runtime desired state");
        assert!(crate::netboot::decode_desired(runtime).is_err());
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
            "cybex-pulse-managed-state-{}-{}",
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
            profile_type: "pulse_installer".to_string(),
            enabled: true,
            is_default: false,
            one_time: false,
            raw_script: None,
        }
    }

    fn sample_local_disk_profile(id: &str) -> ManagedBootProfile {
        ManagedBootProfile {
            id: id.to_string(),
            name: "Managed Local Disk".to_string(),
            description: "Managed local boot fallback".to_string(),
            profile_type: "local_disk".to_string(),
            enabled: true,
            is_default: true,
            one_time: false,
            raw_script: None,
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
            managed_device_id: None,
            reinstall_request_id: None,
            notes: String::new(),
            tags: vec!["rack-a".to_string()],
        }
    }
}
