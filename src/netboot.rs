use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    sync::Mutex,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail};
use axum::{
    extract::{Path as AxumPath, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use rand::{RngCore, rngs::OsRng};
use reqwest::Url;
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::{fs as tokio_fs, io::AsyncWriteExt};
use tracing::warn;

use crate::{
    AppState, assets,
    error::{AppError, AppResult},
    manage_source, release_transport,
};

pub const DESCRIPTOR_SCHEMA: &str = "cybex.james.workstation-netboot.v1";
pub const MANIFEST_SCHEMA: &str = "cybex.james.workstation-netboot-manifest.v1";
pub const SIGNATURE_DOMAIN: &str = "CYBEX-JAMES-WORKSTATION-NETBOOT-V1";
pub const ARCHITECTURE: &str = "x86_64-linux";
pub const FORMAT: &str = "split-squashfs-v1";
pub const REQUIRED_JAMES_PROTOCOL: u32 = 4;
#[cfg(not(feature = "resilience-qualification-epoch-2"))]
pub const COMPATIBILITY_EPOCH: u32 = 1;
#[cfg(feature = "resilience-qualification-epoch-2")]
pub const COMPATIBILITY_EPOCH: u32 = 2;
pub const MAX_BUNDLE_BYTES: u64 = 8 * 1024 * 1024 * 1024;
pub const FAILURE_INVALID_DESCRIPTOR: &str = "invalid_descriptor";
pub const FAILURE_COMPATIBILITY_EPOCH_UNSUPPORTED: &str = "compatibility_epoch_unsupported";
pub const FAILURE_INTEGRITY_MISMATCH: &str = "integrity_mismatch";
pub const FAILURE_INSUFFICIENT_DISK_SPACE: &str = "insufficient_disk_space";
pub const FAILURE_NETWORK_OR_SERVER: &str = "network_or_server";
pub const FAILURE_LOCAL_IO_OR_PROCESSING: &str = "local_io_or_processing";
pub const FAILURE_UNKNOWN: &str = "unknown";
pub const ERROR_RUNTIME_REPORT_STORAGE_UNAVAILABLE: &str = "runtime_report_storage_unavailable";
const MAX_MANIFEST_BYTES: u64 = 256 * 1024;
const FAILURE_MESSAGE_MAX_CHARS: usize = 512;
const BOOT_GRANT_LIFETIME_SECONDS: i64 = 10 * 60;
const BOOT_SESSION_RETENTION_SECONDS: i64 = 24 * 60 * 60;
const BOOT_CONTEXT_MAX_BYTES: usize = 64 * 1024;
const BUNDLE_RETENTION_SECONDS: i64 = 7 * 24 * 60 * 60;
const SCRUB_INTERVAL_SECONDS: i64 = 24 * 60 * 60;
const MAINTENANCE_INTERVAL_SECONDS: u64 = 60 * 60;
const RECONCILE_RETRY_BASE_SECONDS: i64 = 30;
const RECONCILE_RETRY_MAX_SECONDS: i64 = 30 * 60;
const MAX_RECONCILE_ATTEMPT_ROWS: i64 = 128;
// Progress is durable, but it must not turn a fast multi-GiB download into a
// continuous SQLite writer. Persist each newly reached percentage and also a
// heartbeat for very slow links; a forced exact checkpoint follows fsync.
const DOWNLOAD_PROGRESS_MAX_INTERVAL: Duration = Duration::from_secs(5);
const BOOT_GRANT_DOMAIN: &str = "CYBEX-JAMES-BOOT-GRANT-V1";
const COMPONENT_NAMES: [&str; 3] = ["bzImage", "initrd", "nix-store.squashfs"];
static RECONCILE_QUEUE: Mutex<RuntimeReconcileQueue> = Mutex::new(RuntimeReconcileQueue::new());

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ComponentDescriptor {
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ComponentDescriptors {
    #[serde(rename = "bzImage")]
    pub bz_image: ComponentDescriptor,
    pub initrd: ComponentDescriptor,
    #[serde(rename = "nix-store.squashfs")]
    pub nix_store_squashfs: ComponentDescriptor,
}

impl ComponentDescriptors {
    fn get(&self, name: &str) -> Option<&ComponentDescriptor> {
        match name {
            "bzImage" => Some(&self.bz_image),
            "initrd" => Some(&self.initrd),
            "nix-store.squashfs" => Some(&self.nix_store_squashfs),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WorkstationNetbootDescriptor {
    pub schema: String,
    pub runtime_version: String,
    pub manage_source_revision: String,
    pub nixpkgs_revision: String,
    pub architecture: String,
    pub format: String,
    pub required_james_protocol: u32,
    pub url: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub manifest_sha256: String,
    pub components: ComponentDescriptors,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WorkstationNetbootManifest {
    schema: String,
    runtime_version: String,
    architecture: String,
    format: String,
    required_james_protocol: u32,
    manage_source_revision: String,
    nixpkgs_revision: String,
    source_date_epoch: u64,
    toplevel: String,
    kernel_cmdline_template: String,
    components: ComponentDescriptors,
    provenance: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct BootGrantClaims {
    pub schema: &'static str,
    pub james_device_id: String,
    pub organization_id: String,
    pub organization_slug: String,
    pub manage_api_url: String,
    pub bundle_sha256: String,
    pub profile_id: Option<String>,
    pub mac: String,
    pub managed_device_id: Option<String>,
    pub reinstall_request_id: Option<String>,
    pub issued_at: i64,
    pub expires_at: i64,
    pub nonce: String,
}

#[derive(Clone, Debug, Serialize)]
struct JamesBootGrant {
    claims: BootGrantClaims,
    signature: String,
}

#[derive(Clone, Debug, Serialize)]
struct BootContext {
    schema: &'static str,
    api_url: String,
    organization_slug: String,
    bundle_sha256: String,
    profile_id: Option<String>,
    james_boot_grant: JamesBootGrant,
}

#[derive(Clone, Debug, Serialize)]
pub struct BootSessionLaunch {
    pub schema: &'static str,
    pub bundle_sha256: String,
    pub kernel_url: String,
    pub initrd_url: String,
    pub context_url: String,
    pub squashfs_url: String,
    pub command_line: String,
    pub expires_at: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DesiredWorkstationNetboot {
    #[serde(default = "default_compatibility_epoch")]
    pub compatibility_epoch: u32,
    pub descriptor: WorkstationNetbootDescriptor,
    pub reconcile_generation: i64,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct WorkstationNetbootReport {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compatibility_epoch: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reconcile_generation: Option<i64>,
    pub state: String,
    pub progress_percent: i64,
    pub bytes_downloaded: i64,
    pub total_bytes: i64,
    pub failure_kind: String,
    pub failure_message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning_message: Option<String>,
    pub desired_bundle_sha256: String,
    pub active_bundle_sha256: String,
    pub previous_bundle_sha256: String,
    pub runtime_version: String,
    pub last_verified_at: Option<String>,
}

const fn default_compatibility_epoch() -> u32 {
    // A missing field is the legacy epoch-one envelope. It must never inherit
    // the current binary's epoch, otherwise an epoch upgrade would silently
    // relabel desired state sent by an older Manage.
    1
}

enum RuntimeReconcileRequest {
    Desired {
        state: AppState,
        desired: Box<DesiredWorkstationNetboot>,
    },
    DecodeFailure {
        state: AppState,
        value: serde_json::Value,
        failure_kind: &'static str,
        failure_message: String,
    },
}

struct RuntimeReconcileQueue {
    worker_running: bool,
    pending: Option<RuntimeReconcileRequest>,
}

impl RuntimeReconcileQueue {
    const fn new() -> Self {
        Self {
            worker_running: false,
            pending: None,
        }
    }

    fn enqueue(&mut self, request: RuntimeReconcileRequest) -> bool {
        self.pending = Some(request);
        if self.worker_running {
            false
        } else {
            self.worker_running = true;
            true
        }
    }
}

#[derive(Debug)]
struct CodedRuntimeFailure {
    code: &'static str,
    detail: String,
}

#[derive(Debug)]
struct DownloadProgressCheckpoint {
    progress_percent: i64,
    bytes_downloaded: u64,
    persisted_at: Instant,
}

impl DownloadProgressCheckpoint {
    fn new(persisted_at: Instant) -> Self {
        Self {
            // import_bundle has already persisted the initial 1%/zero-byte
            // state immediately before entering the downloader.
            progress_percent: 1,
            bytes_downloaded: 0,
            persisted_at,
        }
    }

    fn due(&self, progress_percent: i64, bytes_downloaded: u64, now: Instant, force: bool) -> bool {
        force
            || (bytes_downloaded > self.bytes_downloaded
                && (progress_percent > self.progress_percent
                    || now.saturating_duration_since(self.persisted_at)
                        >= DOWNLOAD_PROGRESS_MAX_INTERVAL))
    }

    fn commit(&mut self, progress_percent: i64, bytes_downloaded: u64, now: Instant) {
        self.progress_percent = progress_percent;
        self.bytes_downloaded = bytes_downloaded;
        self.persisted_at = now;
    }
}

impl std::fmt::Display for CodedRuntimeFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.detail)
    }
}

impl std::error::Error for CodedRuntimeFailure {}

fn coded_runtime_failure(code: &'static str, detail: impl Into<String>) -> anyhow::Error {
    CodedRuntimeFailure {
        code,
        detail: detail.into(),
    }
    .into()
}

fn validate_compatibility_epoch(compatibility_epoch: u32) -> Result<()> {
    if compatibility_epoch != COMPATIBILITY_EPOCH {
        return Err(coded_runtime_failure(
            FAILURE_COMPATIBILITY_EPOCH_UNSUPPORTED,
            format!(
                "workstation runtime compatibility epoch {compatibility_epoch} is unsupported; this James supports epoch {COMPATIBILITY_EPOCH}"
            ),
        ));
    }
    Ok(())
}

/// Read and validate the compatibility envelope before deserializing the
/// signed descriptor. This lets a newer desired-state shape fail with the
/// stable epoch code instead of being mistaken for a malformed v1 descriptor.
pub fn decode_desired(value: serde_json::Value) -> Result<DesiredWorkstationNetboot> {
    let compatibility_epoch = value
        .get("compatibility_epoch")
        .map(|value| {
            serde_json::from_value::<u32>(value.clone()).map_err(|error| {
                coded_runtime_failure(
                    FAILURE_INVALID_DESCRIPTOR,
                    format!("parse workstation runtime compatibility epoch: {error}"),
                )
            })
        })
        .transpose()?
        .unwrap_or_else(default_compatibility_epoch);
    validate_compatibility_epoch(compatibility_epoch)?;
    serde_json::from_value(value).map_err(|error| {
        coded_runtime_failure(
            FAILURE_INVALID_DESCRIPTOR,
            format!("parse workstation runtime desired state: {error}"),
        )
    })
}

pub fn signature_message(descriptor: &WorkstationNetbootDescriptor) -> String {
    format!(
        "{SIGNATURE_DOMAIN}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
        descriptor.runtime_version,
        descriptor.manage_source_revision,
        descriptor.nixpkgs_revision,
        descriptor.architecture,
        descriptor.format,
        descriptor.required_james_protocol,
        descriptor.components.bz_image.size_bytes,
        descriptor.components.bz_image.sha256,
        descriptor.components.initrd.size_bytes,
        descriptor.components.initrd.sha256,
        descriptor.components.nix_store_squashfs.size_bytes,
        descriptor.components.nix_store_squashfs.sha256,
        descriptor.manifest_sha256,
        descriptor.size_bytes,
        descriptor.sha256,
        descriptor.url,
    )
}

pub fn validate_descriptor(
    descriptor: &WorkstationNetbootDescriptor,
    trusted_public_key: &str,
) -> Result<()> {
    validate_descriptor_with_policy(descriptor, trusted_public_key, false)
}

fn validate_descriptor_with_policy(
    descriptor: &WorkstationNetbootDescriptor,
    trusted_public_key: &str,
    allow_private_release_urls: bool,
) -> Result<()> {
    if descriptor.schema != DESCRIPTOR_SCHEMA {
        bail!("workstation netboot descriptor schema is unsupported");
    }
    Version::parse(&descriptor.runtime_version)
        .context("workstation netboot runtime version is not canonical SemVer")?;
    validate_revision(&descriptor.manage_source_revision, "Manage source revision")?;
    validate_revision(&descriptor.nixpkgs_revision, "nixpkgs revision")?;
    if descriptor.architecture != ARCHITECTURE
        || descriptor.format != FORMAT
        || descriptor.required_james_protocol != REQUIRED_JAMES_PROTOCOL
    {
        bail!("workstation netboot descriptor target contract is incompatible");
    }
    validate_sha256(&descriptor.sha256, "bundle SHA-256")?;
    validate_sha256(&descriptor.manifest_sha256, "manifest SHA-256")?;
    if descriptor.size_bytes == 0 || descriptor.size_bytes > MAX_BUNDLE_BYTES {
        bail!("workstation netboot bundle size is outside its bound");
    }
    for name in COMPONENT_NAMES {
        let component = descriptor.components.get(name).expect("fixed component");
        validate_sha256(&component.sha256, "component SHA-256")?;
        if component.size_bytes == 0 || component.size_bytes > MAX_BUNDLE_BYTES {
            bail!("workstation netboot component size is outside its bound");
        }
    }
    let parsed_url = Url::parse(&descriptor.url).context("parse workstation netboot URL")?;
    if (!allow_private_release_urls && parsed_url.scheme() != "https")
        || (allow_private_release_urls && !matches!(parsed_url.scheme(), "http" | "https"))
        || parsed_url.host_str().is_none()
        || !parsed_url.username().is_empty()
        || parsed_url.password().is_some()
        || parsed_url.fragment().is_some()
    {
        bail!("workstation netboot URL must be an uncredentialed public HTTPS URL");
    }
    let expected_name = format!(
        "cybex-workstation-netboot-{}-{}-{ARCHITECTURE}.tar.zst",
        descriptor.runtime_version,
        &descriptor.manage_source_revision[..12]
    );
    if parsed_url
        .path_segments()
        .and_then(Iterator::last)
        .is_none_or(|name| name != expected_name)
    {
        bail!("workstation netboot URL does not bind the canonical filename");
    }

    // This flag is available only for an explicitly configured development
    // appliance. Integrity and compatibility checks above remain active, but
    // the PoC path does not require an offline release-signing ceremony.
    if allow_private_release_urls {
        return Ok(());
    }

    let key_bytes = STANDARD
        .decode(trusted_public_key.trim())
        .context("decode workstation netboot trusted public key")?;
    let key_array: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| anyhow!("workstation netboot trusted public key must be 32 bytes"))?;
    let key = VerifyingKey::from_bytes(&key_array).context("parse workstation netboot key")?;
    if key.is_weak() {
        bail!("workstation netboot trusted public key must not be weak");
    }
    let signature_bytes = STANDARD
        .decode(descriptor.signature.trim())
        .context("decode workstation netboot signature")?;
    if STANDARD.encode(&signature_bytes) != descriptor.signature {
        bail!("workstation netboot signature is not canonical Base64");
    }
    let signature =
        Signature::from_slice(&signature_bytes).context("parse workstation netboot signature")?;
    key.verify(signature_message(descriptor).as_bytes(), &signature)
        .context("verify workstation netboot signature")?;
    Ok(())
}

/// Queue independent runtime reconciliation without holding up the managed
/// Build/Cache/report loop. While an import is running, replace the one pending
/// request so the worker converges directly to the newest desired state rather
/// than building a stale retry backlog.
pub fn queue_reconcile_desired(state: &AppState, desired: DesiredWorkstationNetboot) -> bool {
    queue_runtime_reconciliation(RuntimeReconcileRequest::Desired {
        state: state.clone(),
        desired: Box::new(desired),
    })
}

pub fn queue_desired_decode_failure(
    state: &AppState,
    value: serde_json::Value,
    error: &anyhow::Error,
) -> bool {
    queue_runtime_reconciliation(RuntimeReconcileRequest::DecodeFailure {
        state: state.clone(),
        value,
        failure_kind: safe_failure_kind(error),
        failure_message: safe_failure_message(error),
    })
}

fn queue_runtime_reconciliation(request: RuntimeReconcileRequest) -> bool {
    let start_worker = RECONCILE_QUEUE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .enqueue(request);
    if start_worker {
        tokio::spawn(drain_runtime_reconcile_queue());
    }
    start_worker
}

async fn drain_runtime_reconcile_queue() {
    loop {
        let request = {
            let mut queue = RECONCILE_QUEUE
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            match queue.pending.take() {
                Some(request) => request,
                None => {
                    queue.worker_running = false;
                    return;
                }
            }
        };
        match request {
            RuntimeReconcileRequest::Desired { state, desired } => {
                if let Err(error) = reconcile_desired(&state, &desired).await {
                    warn!(
                        failure_kind = safe_failure_kind(&error),
                        safe_detail = %safe_failure_message(&error),
                        "workstation netboot reconciliation failed"
                    );
                }
            }
            RuntimeReconcileRequest::DecodeFailure {
                state,
                value,
                failure_kind,
                failure_message,
            } => {
                if let Err(error) =
                    record_desired_decode_failure(&state, &value, failure_kind, &failure_message)
                        .await
                {
                    warn!(
                        error_code = ERROR_RUNTIME_REPORT_STORAGE_UNAVAILABLE,
                        safe_detail = %safe_failure_message(&error),
                        "could not persist workstation runtime desired-state decoding failure"
                    );
                }
            }
        }
    }
}

/// Persist a desired-state decoding failure. The caller serializes this with
/// valid reconciliation so an older import cannot overwrite a newer failure
/// (or vice versa). When the envelope still contains a valid v1 descriptor,
/// retain its identity for attribution; otherwise clear the stale identity.
async fn record_desired_decode_failure(
    state: &AppState,
    value: &serde_json::Value,
    failure_kind: &'static str,
    failure_message: &str,
) -> Result<()> {
    let desired = serde_json::from_value::<DesiredWorkstationNetboot>(value.clone()).ok();
    let parsed_epoch = match value.get("compatibility_epoch") {
        None => Some(default_compatibility_epoch()),
        Some(value) => value
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .filter(|value| *value > 0),
    };
    let desired_epoch = parsed_epoch.unwrap_or_else(default_compatibility_epoch);
    let desired_generation = value
        .get("reconcile_generation")
        .and_then(serde_json::Value::as_i64)
        .filter(|value| *value >= 0);

    if let (Some(attempted_epoch), Some(attempted_generation), Some(raw_descriptor)) =
        (parsed_epoch, desired_generation, value.get("descriptor"))
    {
        let attempted_descriptor = serde_json::to_vec(raw_descriptor)?;
        let attempted_descriptor_sha256 = sha256_bytes(&attempted_descriptor);
        if !reconcile_attempt_is_due(
            state,
            attempted_epoch,
            attempted_generation,
            &attempted_descriptor_sha256,
        )
        .await?
        {
            return Ok(());
        }
        record_reconcile_attempt(
            state,
            attempted_epoch,
            attempted_generation,
            &attempted_descriptor_sha256,
            failure_kind,
        )
        .await?;
        if failure_kind == FAILURE_INVALID_DESCRIPTOR {
            // An unauthenticated descriptor is retry bookkeeping only. Do not
            // relabel or fail the last trusted runtime row to make it visible.
            return Ok(());
        }
    }

    if let Some(desired) = desired.filter(|desired| desired.reconcile_generation >= 0) {
        if validate_descriptor_with_policy(
            &desired.descriptor,
            &state.config.update.trusted_public_key,
            state.config.workstation_netboot.allow_private_release_urls,
        )
        .is_ok()
        {
            let descriptor_json = serde_json::to_string(&desired.descriptor)?;
            let descriptor_sha256 = sha256_bytes(descriptor_json.as_bytes());
            sqlx::query(
                "UPDATE workstation_netboot_runtime
                 SET desired_compatibility_epoch = ?, desired_descriptor_json = ?,
                     desired_descriptor_sha256 = ?, reconcile_generation = ?,
                     state = 'failed', progress_percent = 0, bytes_downloaded = 0, total_bytes = ?,
                     failure_kind = ?, failure_message = ?, updated_at = ?
                 WHERE singleton_id = 1",
            )
            .bind(desired.compatibility_epoch)
            .bind(descriptor_json)
            .bind(descriptor_sha256)
            .bind(desired.reconcile_generation)
            .bind(i64::try_from(desired.descriptor.size_bytes).unwrap_or(i64::MAX))
            .bind(failure_kind)
            .bind(failure_message)
            .bind(now())
            .execute(&state.db)
            .await?;
            return Ok(());
        }
    }

    sqlx::query(
        "UPDATE workstation_netboot_runtime
         SET desired_compatibility_epoch = ?, desired_descriptor_json = '',
             desired_descriptor_sha256 = '',
             reconcile_generation = COALESCE(?, reconcile_generation),
             state = 'failed', progress_percent = 0, bytes_downloaded = 0, total_bytes = 0,
             failure_kind = ?, failure_message = ?, updated_at = ?
         WHERE singleton_id = 1",
    )
    .bind(desired_epoch)
    .bind(desired_generation)
    .bind(failure_kind)
    .bind(failure_message)
    .bind(now())
    .execute(&state.db)
    .await?;
    Ok(())
}

pub async fn reconcile_desired(
    state: &AppState,
    desired: &DesiredWorkstationNetboot,
) -> Result<()> {
    let descriptor_json = serde_json::to_string(&desired.descriptor)?;
    let descriptor_sha256 = sha256_bytes(descriptor_json.as_bytes());
    if !reconcile_attempt_is_due(
        state,
        desired.compatibility_epoch,
        desired.reconcile_generation,
        &descriptor_sha256,
    )
    .await?
    {
        return Ok(());
    }
    let result = reconcile_desired_inner(state, desired).await;
    if let Err(error) = &result {
        let failure_kind = classify_failure(error);
        if let Err(storage_error) = record_reconcile_attempt(
            state,
            desired.compatibility_epoch,
            desired.reconcile_generation,
            &descriptor_sha256,
            failure_kind,
        )
        .await
        {
            warn!(
                error_code = ERROR_RUNTIME_REPORT_STORAGE_UNAVAILABLE,
                safe_detail = %safe_failure_message(&storage_error),
                "could not persist workstation runtime retry state"
            );
        }
        if let Err(storage_error) = record_failure_for_attempt(
            state,
            desired.compatibility_epoch,
            desired.reconcile_generation,
            &descriptor_sha256,
            failure_kind,
            &safe_failure_message(error),
        )
        .await
        {
            warn!(
                error_code = ERROR_RUNTIME_REPORT_STORAGE_UNAVAILABLE,
                safe_detail = %safe_failure_message(&storage_error),
                "could not persist workstation runtime failure state"
            );
        }
    } else if let Err(storage_error) = clear_reconcile_attempt(
        state,
        desired.compatibility_epoch,
        desired.reconcile_generation,
        &descriptor_sha256,
    )
    .await
    {
        warn!(
            error_code = ERROR_RUNTIME_REPORT_STORAGE_UNAVAILABLE,
            safe_detail = %safe_failure_message(&storage_error),
            "could not clear workstation runtime retry state"
        );
    }
    result
}

async fn reconcile_attempt_is_due(
    state: &AppState,
    compatibility_epoch: u32,
    reconcile_generation: i64,
    descriptor_sha256: &str,
) -> Result<bool> {
    let attempt: Option<(i64, Option<i64>)> = sqlx::query_as(
        "SELECT terminal_hold, next_attempt_at
         FROM workstation_netboot_reconcile_attempts
         WHERE compatibility_epoch = ? AND reconcile_generation = ?
           AND descriptor_sha256 = ?",
    )
    .bind(compatibility_epoch)
    .bind(reconcile_generation)
    .bind(descriptor_sha256)
    .fetch_optional(&state.db)
    .await?;
    Ok(match attempt {
        None => true,
        Some((terminal_hold, _)) if terminal_hold != 0 => false,
        Some((_, next_attempt_at)) => next_attempt_at.is_none_or(|at| at <= Utc::now().timestamp()),
    })
}

async fn record_reconcile_attempt(
    state: &AppState,
    compatibility_epoch: u32,
    reconcile_generation: i64,
    descriptor_sha256: &str,
    failure_kind: &str,
) -> Result<()> {
    // A signed descriptor that cannot be validated is deterministic and must
    // wait for a new desired identity. Artifact integrity failures are not:
    // an interrupted proxy/CDN response can hash incorrectly even though the
    // immutable origin becomes readable again. Back those failures off just
    // like transport errors so an unchanged desired state can self-heal.
    let terminal_hold = failure_kind == FAILURE_INVALID_DESCRIPTOR;
    let timestamp = now();
    let now_epoch = Utc::now().timestamp();
    sqlx::query(
        "INSERT INTO workstation_netboot_reconcile_attempts
           (compatibility_epoch, reconcile_generation, descriptor_sha256,
            failure_kind, attempt_count, terminal_hold, next_attempt_at, updated_at)
         VALUES (?, ?, ?, ?, 1, ?, ?, ?)
         ON CONFLICT(compatibility_epoch, reconcile_generation, descriptor_sha256) DO UPDATE SET
           failure_kind = excluded.failure_kind,
           attempt_count = workstation_netboot_reconcile_attempts.attempt_count + 1,
           terminal_hold = excluded.terminal_hold,
           next_attempt_at = CASE WHEN excluded.terminal_hold = 1 THEN NULL ELSE
             ? + MIN(?, ? * (1 << MIN(workstation_netboot_reconcile_attempts.attempt_count, 6)))
           END,
           updated_at = excluded.updated_at",
    )
    .bind(compatibility_epoch)
    .bind(reconcile_generation)
    .bind(descriptor_sha256)
    .bind(failure_kind)
    .bind(i64::from(terminal_hold))
    .bind((!terminal_hold).then_some(now_epoch + RECONCILE_RETRY_BASE_SECONDS))
    .bind(&timestamp)
    .bind(now_epoch)
    .bind(RECONCILE_RETRY_MAX_SECONDS)
    .bind(RECONCILE_RETRY_BASE_SECONDS)
    .execute(&state.db)
    .await?;
    sqlx::query(
        "DELETE FROM workstation_netboot_reconcile_attempts
         WHERE rowid IN (
           SELECT rowid FROM workstation_netboot_reconcile_attempts
           ORDER BY updated_at DESC, rowid DESC LIMIT -1 OFFSET ?
         )",
    )
    .bind(MAX_RECONCILE_ATTEMPT_ROWS)
    .execute(&state.db)
    .await?;
    Ok(())
}

async fn clear_reconcile_attempt(
    state: &AppState,
    compatibility_epoch: u32,
    reconcile_generation: i64,
    descriptor_sha256: &str,
) -> Result<()> {
    sqlx::query(
        "DELETE FROM workstation_netboot_reconcile_attempts
         WHERE compatibility_epoch = ? AND reconcile_generation = ?
           AND descriptor_sha256 = ?",
    )
    .bind(compatibility_epoch)
    .bind(reconcile_generation)
    .bind(descriptor_sha256)
    .execute(&state.db)
    .await?;
    Ok(())
}

async fn reconcile_desired_inner(
    state: &AppState,
    desired: &DesiredWorkstationNetboot,
) -> Result<()> {
    validate_compatibility_epoch(desired.compatibility_epoch)?;
    if desired.reconcile_generation < 0 {
        bail!("workstation netboot reconcile generation must not be negative");
    }
    validate_descriptor_with_policy(
        &desired.descriptor,
        &state.config.update.trusted_public_key,
        state.config.workstation_netboot.allow_private_release_urls,
    )?;
    let allow_private_manage_source = state.config.workstation_netboot.allow_private_release_urls
        && state.config.build.manage_source_url_template
            != manage_source::MANAGE_SOURCE_URL_TEMPLATE;
    manage_source::verify_revision(
        &state.config.build.manage_source_url_template,
        &desired.descriptor.manage_source_revision,
        allow_private_manage_source,
    )
    .context("verify packaged Manage source for workstation runtime")?;
    let descriptor_json = serde_json::to_string(&desired.descriptor)?;
    let descriptor_sha256 = sha256_bytes(descriptor_json.as_bytes());
    admit_reconcile_identity(
        state,
        &desired.descriptor,
        &descriptor_sha256,
        desired.compatibility_epoch,
        desired.reconcile_generation,
    )
    .await?;

    let already_ready: (i64,) = sqlx::query_as(
        "SELECT EXISTS(
             SELECT 1 FROM workstation_netboot_runtime runtime
             JOIN workstation_netboot_bundles bundle
               ON bundle.bundle_sha256 = runtime.active_bundle_sha256
             WHERE runtime.singleton_id = 1
               AND runtime.desired_compatibility_epoch = ?
               AND runtime.desired_descriptor_sha256 = ?
               AND runtime.reconcile_generation = ?
               AND runtime.state = 'ready'
               AND runtime.active_bundle_sha256 = ?
               AND bundle.compatibility_epoch = ?
         )",
    )
    .bind(desired.compatibility_epoch)
    .bind(&descriptor_sha256)
    .bind(desired.reconcile_generation)
    .bind(&desired.descriptor.sha256)
    .bind(desired.compatibility_epoch)
    .fetch_one(&state.db)
    .await?;
    if already_ready.0 != 0 {
        return Ok(());
    }

    sqlx::query(
        "UPDATE workstation_netboot_runtime
         SET desired_compatibility_epoch = ?, desired_descriptor_json = ?,
             desired_descriptor_sha256 = ?, reconcile_generation = ?,
             state = 'queued', progress_percent = 0, bytes_downloaded = 0, total_bytes = ?,
             failure_kind = '', failure_message = '', updated_at = ?
         WHERE singleton_id = 1",
    )
    .bind(desired.compatibility_epoch)
    .bind(&descriptor_json)
    .bind(&descriptor_sha256)
    .bind(desired.reconcile_generation)
    .bind(i64::try_from(desired.descriptor.size_bytes).unwrap_or(i64::MAX))
    .bind(now())
    .execute(&state.db)
    .await?;

    if crate::maintenance::lease_active()? {
        set_runtime_state(state, "held", 0, 0, desired.descriptor.size_bytes).await?;
        return Ok(());
    }

    let existing_ready: Option<(String,)> = sqlx::query_as(
        "SELECT bundle_sha256 FROM workstation_netboot_bundles
         WHERE bundle_sha256 = ? AND compatibility_epoch = ?
           AND retention_state = 'verified'",
    )
    .bind(&desired.descriptor.sha256)
    .bind(desired.compatibility_epoch)
    .fetch_optional(&state.db)
    .await?;
    if existing_ready.is_some() {
        promote_existing(
            state,
            &desired.descriptor,
            &descriptor_json,
            &descriptor_sha256,
            desired.compatibility_epoch,
            desired.reconcile_generation,
        )
        .await?;
        return Ok(());
    }

    let imported = import_bundle(state, &desired.descriptor, desired.compatibility_epoch).await?;
    if !imported {
        return Ok(());
    }
    promote_existing(
        state,
        &desired.descriptor,
        &descriptor_json,
        &descriptor_sha256,
        desired.compatibility_epoch,
        desired.reconcile_generation,
    )
    .await
}

async fn admit_reconcile_identity(
    state: &AppState,
    descriptor: &WorkstationNetbootDescriptor,
    descriptor_sha256: &str,
    compatibility_epoch: u32,
    generation: i64,
) -> Result<()> {
    let key_fingerprint = sha256_bytes(
        &STANDARD
            .decode(state.config.update.trusted_public_key.trim())
            .context("decode workstation netboot trust key")?,
    );
    // Acquire SQLite's writer reservation before reading the causal ledgers.
    // This bounded metadata-only transaction then cannot fail later while
    // upgrading a stale DEFERRED snapshot under concurrent James writers.
    let mut transaction = state.db.begin_with("BEGIN IMMEDIATE").await?;
    let stored_generation: Option<(i64, String)> = sqlx::query_as(
        "SELECT reconcile_generation, descriptor_sha256
         FROM workstation_netboot_reconcile_watermarks
         WHERE compatibility_epoch = ?",
    )
    .bind(compatibility_epoch)
    .fetch_optional(&mut *transaction)
    .await?;
    validate_reconcile_generation_precedence(
        stored_generation.as_ref(),
        generation,
        descriptor_sha256,
    )?;

    let artifact_watermark: Option<(String, String)> = sqlx::query_as(
        "SELECT runtime_version, descriptor_sha256
         FROM workstation_netboot_watermarks
         WHERE compatibility_epoch = ? AND key_fingerprint = ? AND architecture = ?",
    )
    .bind(compatibility_epoch)
    .bind(&key_fingerprint)
    .bind(&descriptor.architecture)
    .fetch_optional(&mut *transaction)
    .await?;
    if let Some((accepted_version, accepted_descriptor_sha256)) = artifact_watermark {
        enforce_watermark_precedence(
            &accepted_version,
            &accepted_descriptor_sha256,
            &descriptor.runtime_version,
            descriptor_sha256,
        )?;
    }

    if stored_generation
        .as_ref()
        .is_none_or(|(stored, _)| generation > *stored)
    {
        sqlx::query(
            "INSERT INTO workstation_netboot_reconcile_watermarks
             (compatibility_epoch, reconcile_generation, descriptor_sha256, updated_at)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(compatibility_epoch) DO UPDATE SET
               reconcile_generation = excluded.reconcile_generation,
               descriptor_sha256 = excluded.descriptor_sha256,
               updated_at = excluded.updated_at",
        )
        .bind(compatibility_epoch)
        .bind(generation)
        .bind(descriptor_sha256)
        .bind(now())
        .execute(&mut *transaction)
        .await?;
    }
    transaction.commit().await?;
    Ok(())
}

fn validate_reconcile_generation_precedence(
    stored: Option<&(i64, String)>,
    generation: i64,
    descriptor_sha256: &str,
) -> Result<()> {
    if let Some((stored_generation, stored_descriptor)) = stored {
        if generation < *stored_generation {
            bail!("workstation netboot stale reconcile generation was rejected");
        }
        if generation == *stored_generation && stored_descriptor != descriptor_sha256 {
            bail!("workstation netboot descriptor changed at the accepted reconcile generation");
        }
    }
    Ok(())
}

#[cfg(test)]
async fn accept_reconcile_generation(
    state: &AppState,
    compatibility_epoch: u32,
    generation: i64,
    descriptor_sha256: &str,
) -> Result<()> {
    let mut transaction = state.db.begin_with("BEGIN IMMEDIATE").await?;
    let stored: Option<(i64, String)> = sqlx::query_as(
        "SELECT reconcile_generation, descriptor_sha256
         FROM workstation_netboot_reconcile_watermarks
         WHERE compatibility_epoch = ?",
    )
    .bind(compatibility_epoch)
    .fetch_optional(&mut *transaction)
    .await?;
    validate_reconcile_generation_precedence(stored.as_ref(), generation, descriptor_sha256)?;
    if let Some((stored_generation, _)) = stored {
        if generation == stored_generation {
            transaction.commit().await?;
            return Ok(());
        }
    }
    sqlx::query(
        "INSERT INTO workstation_netboot_reconcile_watermarks
         (compatibility_epoch, reconcile_generation, descriptor_sha256, updated_at)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(compatibility_epoch) DO UPDATE SET
           reconcile_generation = excluded.reconcile_generation,
           descriptor_sha256 = excluded.descriptor_sha256,
           updated_at = excluded.updated_at",
    )
    .bind(compatibility_epoch)
    .bind(generation)
    .bind(descriptor_sha256)
    .bind(now())
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(())
}

async fn import_bundle(
    state: &AppState,
    descriptor: &WorkstationNetbootDescriptor,
    compatibility_epoch: u32,
) -> Result<bool> {
    let existing_epoch: Option<(i64,)> = sqlx::query_as(
        "SELECT compatibility_epoch FROM workstation_netboot_bundles WHERE bundle_sha256 = ?",
    )
    .bind(&descriptor.sha256)
    .fetch_optional(&state.db)
    .await?;
    if existing_epoch.is_some_and(|(stored,)| stored != i64::from(compatibility_epoch)) {
        return Err(coded_runtime_failure(
            FAILURE_INVALID_DESCRIPTOR,
            "workstation netboot bundle identity was already verified under another compatibility epoch",
        ));
    }

    let private_root = state.config.paths.data_dir.join("netboot");
    let staging_root = private_root.join("staging");
    let public_root = state.config.paths.boot_assets_dir.join("netboot");
    let extraction_root = public_root.join(".staging");
    tokio_fs::create_dir_all(&staging_root).await?;
    tokio_fs::create_dir_all(&public_root).await?;
    tokio_fs::create_dir_all(&extraction_root).await?;
    let expanded_bytes = expected_expanded_runtime_bytes(descriptor)?;
    if fs::metadata(&private_root)?.dev() == fs::metadata(&public_root)?.dev() {
        let peak_bytes = descriptor
            .size_bytes
            .checked_add(expanded_bytes)
            .ok_or_else(|| anyhow!("workstation netboot import size overflow"))?;
        crate::disk::ensure_headroom(&private_root, peak_bytes, "workstation netboot import")?;
    } else {
        crate::disk::ensure_headroom(
            &private_root,
            descriptor.size_bytes,
            "workstation netboot download",
        )?;
        crate::disk::ensure_headroom(
            &public_root,
            expanded_bytes,
            "workstation netboot extraction",
        )?;
    }

    set_runtime_state(state, "downloading", 1, 0, descriptor.size_bytes).await?;
    let part = staging_root.join(format!("{}.tar.zst.part", descriptor.sha256));
    download_bundle(state, descriptor, &part).await?;
    set_runtime_state(
        state,
        "verifying",
        70,
        descriptor.size_bytes,
        descriptor.size_bytes,
    )
    .await?;
    let actual = sha256_file(part.clone()).await?;
    if actual != descriptor.sha256 {
        tokio_fs::remove_file(&part).await.ok();
        bail!("workstation netboot bundle SHA-256 mismatch");
    }

    set_runtime_state(
        state,
        "extracting",
        80,
        descriptor.size_bytes,
        descriptor.size_bytes,
    )
    .await?;
    if crate::maintenance::lease_active()? {
        set_runtime_state(
            state,
            "held",
            80,
            descriptor.size_bytes,
            descriptor.size_bytes,
        )
        .await?;
        return Ok(false);
    }
    // systemd exposes the private data and served roots as separate writable
    // bind mounts. Keep extraction on the served filesystem so the final
    // promotion remains an atomic rename; this dot-directory is outside every
    // routed HTTP namespace.
    let stage = extraction_root.join(format!("{}.{}", descriptor.sha256, uuid::Uuid::new_v4()));
    let part_for_extract = part.clone();
    let stage_for_extract = stage.clone();
    let descriptor_for_extract = descriptor.clone();
    let extraction = tokio::task::spawn_blocking(move || {
        extract_and_verify(
            &part_for_extract,
            &stage_for_extract,
            &descriptor_for_extract,
        )
    })
    .await;
    let extraction = match extraction {
        Ok(result) => result,
        Err(error) => {
            fs::remove_dir_all(&stage).ok();
            tokio_fs::remove_file(&part).await.ok();
            return Err(error).context("join workstation netboot extraction");
        }
    };
    if let Err(error) = extraction {
        fs::remove_dir_all(&stage).ok();
        tokio_fs::remove_file(&part).await.ok();
        return Err(error);
    }

    if crate::maintenance::lease_active()? {
        fs::remove_dir_all(&stage).context("remove held netboot staging tree")?;
        set_runtime_state(
            state,
            "held",
            90,
            descriptor.size_bytes,
            descriptor.size_bytes,
        )
        .await?;
        return Ok(false);
    }

    let final_root = public_root.join(&descriptor.sha256);
    publish_verified_stage(&stage, &final_root, &public_root, descriptor)?;
    tokio_fs::remove_file(&part).await.ok();

    let verified_at = now();
    sqlx::query(
        "INSERT INTO workstation_netboot_bundles
         (bundle_sha256, compatibility_epoch, runtime_version, manage_source_revision, nixpkgs_revision,
          architecture, manifest_sha256, descriptor_json, root_path, size_bytes,
          retention_state, verified_at, last_scrubbed_at, retained_until,
          created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'verified', ?, ?, ?, ?, ?)
         ON CONFLICT(bundle_sha256) DO UPDATE SET
           descriptor_json = excluded.descriptor_json,
           root_path = excluded.root_path,
           retention_state = 'verified',
           verified_at = excluded.verified_at,
           last_scrubbed_at = excluded.last_scrubbed_at,
           retained_until = excluded.retained_until,
           quarantined_at = NULL,
           quarantine_reason = '',
           updated_at = excluded.updated_at
         WHERE workstation_netboot_bundles.compatibility_epoch = excluded.compatibility_epoch",
    )
    .bind(&descriptor.sha256)
    .bind(compatibility_epoch)
    .bind(&descriptor.runtime_version)
    .bind(&descriptor.manage_source_revision)
    .bind(&descriptor.nixpkgs_revision)
    .bind(&descriptor.architecture)
    .bind(&descriptor.manifest_sha256)
    .bind(serde_json::to_string(descriptor)?)
    .bind(final_root.display().to_string())
    .bind(i64::try_from(descriptor.size_bytes).unwrap_or(i64::MAX))
    .bind(&verified_at)
    .bind(&verified_at)
    .bind(retained_until())
    .bind(&verified_at)
    .bind(&verified_at)
    .execute(&state.db)
    .await?;
    Ok(true)
}

fn publish_verified_stage(
    stage: &Path,
    final_root: &Path,
    public_root: &Path,
    descriptor: &WorkstationNetbootDescriptor,
) -> Result<()> {
    match fs::symlink_metadata(final_root) {
        Ok(metadata)
            if metadata.file_type().is_dir()
                && verify_extracted_tree(final_root, descriptor).is_ok() =>
        {
            fs::remove_dir_all(stage).context("remove duplicate verified netboot staging tree")?;
            return Ok(());
        }
        Ok(_) => {
            let quarantine_root = public_root
                .parent()
                .ok_or_else(|| anyhow!("workstation netboot public root has no parent"))?
                .join("netboot-quarantine");
            fs::create_dir_all(&quarantine_root)?;
            fs::set_permissions(&quarantine_root, fs::Permissions::from_mode(0o700))?;
            let identity = final_root
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| anyhow!("workstation netboot final identity is invalid"))?;
            let quarantined =
                quarantine_root.join(format!("{}.{}", identity, uuid::Uuid::new_v4().simple()));
            fs::rename(final_root, &quarantined)
                .context("quarantine pre-existing workstation netboot tree")?;
            sync_directory(&quarantine_root)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    fs::rename(stage, final_root).context("atomically publish workstation netboot")?;
    sync_directory(public_root)?;
    Ok(())
}

fn expected_expanded_runtime_bytes(descriptor: &WorkstationNetbootDescriptor) -> Result<u64> {
    [
        descriptor.components.bz_image.size_bytes,
        descriptor.components.initrd.size_bytes,
        descriptor.components.nix_store_squashfs.size_bytes,
        MAX_MANIFEST_BYTES,
    ]
    .into_iter()
    .try_fold(0_u64, |total, size| {
        total
            .checked_add(size)
            .ok_or_else(|| anyhow!("workstation netboot expanded size overflow"))
    })
}

async fn download_bundle(
    state: &AppState,
    descriptor: &WorkstationNetbootDescriptor,
    part: &Path,
) -> Result<()> {
    let mut progress_checkpoint = DownloadProgressCheckpoint::new(Instant::now());
    let mut offset = match tokio_fs::symlink_metadata(part).await {
        Ok(metadata)
            if metadata.file_type().is_file()
                && metadata.nlink() == 1
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.permissions().mode() & 0o777 == 0o600 =>
        {
            metadata.len()
        }
        Ok(_) => bail!("workstation netboot partial path is not a regular file"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
        Err(error) => return Err(error.into()),
    };
    if offset > descriptor.size_bytes {
        tokio_fs::remove_file(part).await?;
        offset = 0;
    }
    if offset == descriptor.size_bytes {
        persist_download_progress(
            &mut progress_checkpoint,
            state,
            offset,
            descriptor.size_bytes,
            Instant::now(),
            true,
        )
        .await?;
        return Ok(());
    }
    if offset > 0 {
        persist_download_progress(
            &mut progress_checkpoint,
            state,
            offset,
            descriptor.size_bytes,
            Instant::now(),
            true,
        )
        .await?;
    }
    let mut response = send_release_request(
        &descriptor.url,
        state.config.workstation_netboot.allow_private_release_urls,
        offset,
    )
    .await?;
    let restart_from_zero = offset > 0
        && response.status() == StatusCode::OK
        && response.content_length() == Some(descriptor.size_bytes);
    if restart_from_zero {
        offset = 0;
        // The origin ignored Range, so truthfully reset the durable byte count
        // before truncating and restarting rather than showing stale resume
        // progress until the new transfer catches up.
        persist_download_progress(
            &mut progress_checkpoint,
            state,
            0,
            descriptor.size_bytes,
            Instant::now(),
            true,
        )
        .await?;
    }
    let expected_status = if offset > 0 {
        StatusCode::PARTIAL_CONTENT
    } else {
        StatusCode::OK
    };
    if response.status() != expected_status {
        bail!("workstation netboot download returned an unexpected HTTP status");
    }
    let remaining = descriptor.size_bytes - offset;
    if response.content_length() != Some(remaining) {
        bail!("workstation netboot download length did not match the signed descriptor");
    }
    if offset > 0 {
        let expected = format!(
            "bytes {offset}-{}/{}",
            descriptor.size_bytes - 1,
            descriptor.size_bytes
        );
        if response
            .headers()
            .get(header::CONTENT_RANGE)
            .and_then(|value| value.to_str().ok())
            != Some(expected.as_str())
        {
            bail!("workstation netboot resume response had an invalid Content-Range");
        }
    }
    let mut options = tokio_fs::OpenOptions::new();
    options
        .create(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    if offset == 0 {
        options.truncate(true);
    } else {
        options.append(true);
    }
    let mut file = options.open(part).await?;
    let mut downloaded = offset;
    while let Some(chunk) = response
        .chunk()
        .await
        .context("read workstation netboot body")?
    {
        downloaded = downloaded
            .checked_add(chunk.len() as u64)
            .ok_or_else(|| anyhow!("workstation netboot download size overflow"))?;
        if downloaded > descriptor.size_bytes {
            bail!("workstation netboot download exceeded its signed size");
        }
        file.write_all(&chunk).await?;
        persist_download_progress(
            &mut progress_checkpoint,
            state,
            downloaded,
            descriptor.size_bytes,
            Instant::now(),
            false,
        )
        .await?;
    }
    file.flush().await?;
    file.sync_all().await?;
    if downloaded != descriptor.size_bytes {
        bail!("workstation netboot download was truncated");
    }
    // The final exact byte count is durable only after fsync. Force this
    // checkpoint even when the last HTTP chunk already crossed 69%.
    persist_download_progress(
        &mut progress_checkpoint,
        state,
        downloaded,
        descriptor.size_bytes,
        Instant::now(),
        true,
    )
    .await?;
    Ok(())
}

fn download_progress_percent(downloaded: u64, total: u64) -> i64 {
    debug_assert!(total > 0);
    1 + i64::try_from(downloaded.saturating_mul(68) / total).unwrap_or(68)
}

async fn persist_download_progress(
    checkpoint: &mut DownloadProgressCheckpoint,
    state: &AppState,
    downloaded: u64,
    total: u64,
    now: Instant,
    force: bool,
) -> Result<bool> {
    let progress = download_progress_percent(downloaded, total);
    if !checkpoint.due(progress, downloaded, now, force) {
        return Ok(false);
    }
    set_runtime_state(state, "downloading", progress, downloaded, total).await?;
    checkpoint.commit(progress, downloaded, Instant::now());
    Ok(true)
}

async fn send_release_request(
    value: &str,
    allow_private_release_urls: bool,
    offset: u64,
) -> Result<reqwest::Response> {
    release_transport::get(
        value,
        allow_private_release_urls,
        true,
        Duration::from_secs(30 * 60),
        Some(offset),
    )
    .await
    .context("download workstation netboot bundle")
}

fn extract_and_verify(
    archive_path: &Path,
    stage: &Path,
    descriptor: &WorkstationNetbootDescriptor,
) -> Result<()> {
    fs::create_dir(stage).context("create workstation netboot extraction directory")?;
    fs::set_permissions(stage, fs::Permissions::from_mode(0o755))?;
    let file = fs::File::open(archive_path)?;
    let decoder = zstd::Decoder::new(file).context("open workstation netboot zstd stream")?;
    let mut archive = tar::Archive::new(decoder);
    let mut seen = BTreeSet::new();
    let mut ordered_names = Vec::new();
    let mut archive_mtime = None;
    for entry in archive
        .entries()
        .context("read workstation netboot tar entries")?
    {
        let mut entry = entry?;
        if entry.pax_extensions()?.is_some() || entry.header().as_ustar().is_none() {
            bail!("workstation netboot archive extensions are not permitted");
        }
        let path = entry.path()?.into_owned();
        let name = single_component_name(&path)?;
        if !seen.insert(name.clone()) {
            bail!("workstation netboot archive contains a duplicate entry");
        }
        if name != "manifest.json" && !COMPONENT_NAMES.contains(&name.as_str()) {
            bail!("workstation netboot archive contains an unexpected entry");
        }
        if !entry.header().entry_type().is_file()
            || entry.header().uid()? != 0
            || entry.header().gid()? != 0
            || entry.header().mode()? != 0o644
        {
            bail!("workstation netboot archive entry metadata is unsafe");
        }
        let mtime = entry.header().mtime()?;
        if archive_mtime
            .replace(mtime)
            .is_some_and(|previous| previous != mtime)
        {
            bail!("workstation netboot archive timestamps are inconsistent");
        }
        ordered_names.push(name.clone());
        let declared_size = if name == "manifest.json" {
            if entry.size() == 0 || entry.size() > MAX_MANIFEST_BYTES {
                bail!("workstation netboot manifest size is outside its bound");
            }
            entry.size()
        } else {
            let expected = descriptor
                .components
                .get(&name)
                .expect("allowlisted component");
            if entry.size() != expected.size_bytes {
                bail!("workstation netboot archive component size does not match descriptor");
            }
            expected.size_bytes
        };
        let target = stage.join(&name);
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true).mode(0o644);
        let mut output = options.open(&target)?;
        // The service intentionally runs with UMask=0077. Restore the signed
        // public component mode explicitly before checking and publishing it.
        output.set_permissions(fs::Permissions::from_mode(0o644))?;
        let copied = std::io::copy(&mut entry, &mut output)?;
        if copied != declared_size {
            bail!("workstation netboot archive entry was truncated");
        }
        output.sync_all()?;
    }
    let expected_names = BTreeSet::from([
        "manifest.json".to_string(),
        "bzImage".to_string(),
        "initrd".to_string(),
        "nix-store.squashfs".to_string(),
    ]);
    if seen != expected_names {
        bail!("workstation netboot archive did not contain the exact component set");
    }
    if ordered_names != ["bzImage", "initrd", "manifest.json", "nix-store.squashfs"] {
        bail!("workstation netboot archive entries are not sorted");
    }
    let manifest_body = fs::read(stage.join("manifest.json"))?;
    if sha256_bytes(&manifest_body) != descriptor.manifest_sha256 {
        bail!("workstation netboot manifest SHA-256 mismatch");
    }
    let manifest = parse_canonical_manifest(&manifest_body)?;
    validate_manifest(&manifest, descriptor)?;
    if archive_mtime != Some(manifest.source_date_epoch) {
        bail!("workstation netboot archive timestamp does not match its manifest");
    }
    verify_extracted_tree(stage, descriptor)?;
    sync_directory(stage)?;
    Ok(())
}

fn verify_extracted_tree(root: &Path, descriptor: &WorkstationNetbootDescriptor) -> Result<()> {
    let metadata = fs::symlink_metadata(root)?;
    if !metadata.file_type().is_dir() {
        bail!("workstation netboot bundle root is not a directory");
    }
    let mut names = BTreeSet::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow!("workstation netboot bundle filename is not UTF-8"))?;
        if !names.insert(name.clone()) {
            bail!("workstation netboot bundle contains duplicate files");
        }
        if name != "manifest.json" && !COMPONENT_NAMES.contains(&name.as_str()) {
            bail!("workstation netboot bundle contains an unexpected file");
        }
        let metadata = fs::symlink_metadata(entry.path())?;
        if !metadata.file_type().is_file()
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o777 != 0o644
        {
            bail!("workstation netboot bundle file metadata is unsafe");
        }
    }
    let expected_names = BTreeSet::from([
        "manifest.json".to_string(),
        "bzImage".to_string(),
        "initrd".to_string(),
        "nix-store.squashfs".to_string(),
    ]);
    if names != expected_names {
        bail!("workstation netboot bundle does not contain its exact component set");
    }
    let manifest_body = fs::read(root.join("manifest.json"))?;
    if manifest_body.is_empty()
        || manifest_body.len() as u64 > MAX_MANIFEST_BYTES
        || sha256_bytes(&manifest_body) != descriptor.manifest_sha256
    {
        bail!("workstation netboot manifest SHA-256 mismatch");
    }
    let manifest = parse_canonical_manifest(&manifest_body)?;
    validate_manifest(&manifest, descriptor)?;
    for name in COMPONENT_NAMES {
        let expected = descriptor.components.get(name).expect("fixed component");
        let path = root.join(name);
        if fs::metadata(&path)?.len() != expected.size_bytes
            || sha256_regular_file(&path)? != expected.sha256
        {
            bail!("workstation netboot component integrity mismatch");
        }
    }
    Ok(())
}

fn validate_manifest(
    manifest: &WorkstationNetbootManifest,
    descriptor: &WorkstationNetbootDescriptor,
) -> Result<()> {
    if manifest.schema != MANIFEST_SCHEMA
        || manifest.runtime_version != descriptor.runtime_version
        || manifest.architecture != descriptor.architecture
        || manifest.format != descriptor.format
        || manifest.required_james_protocol != descriptor.required_james_protocol
        || manifest.manage_source_revision != descriptor.manage_source_revision
        || manifest.nixpkgs_revision != descriptor.nixpkgs_revision
        || manifest.components != descriptor.components
    {
        bail!("workstation netboot manifest does not match its signed descriptor");
    }
    if !manifest.toplevel.starts_with("/nix/store/")
        || manifest.toplevel.contains(char::is_whitespace)
        || manifest
            .kernel_cmdline_template
            .matches("{squashfs_url}")
            .count()
            != 1
        || {
            let static_cmdline = manifest
                .kernel_cmdline_template
                .replace("{squashfs_url}", "");
            static_cmdline.contains('{') || static_cmdline.contains('}')
        }
        || manifest.provenance.is_empty()
    {
        bail!("workstation netboot manifest runtime metadata is invalid");
    }
    Ok(())
}

fn parse_canonical_manifest(body: &[u8]) -> Result<WorkstationNetbootManifest> {
    let value: serde_json::Value =
        serde_json::from_slice(body).context("parse workstation netboot manifest")?;
    let mut canonical =
        serde_json::to_vec(&value).context("serialize workstation netboot manifest")?;
    canonical.push(b'\n');
    if canonical != body {
        bail!("workstation netboot manifest is not canonical compact sorted JSON");
    }
    serde_json::from_value(value).context("validate workstation netboot manifest")
}

fn single_component_name(path: &Path) -> Result<String> {
    let mut components = path.components();
    let Some(Component::Normal(name)) = components.next() else {
        bail!("workstation netboot archive path is unsafe");
    };
    if components.next().is_some() {
        bail!("workstation netboot archive path is nested");
    }
    let name = name
        .to_str()
        .ok_or_else(|| anyhow!("workstation netboot archive path is not UTF-8"))?;
    if name.is_empty() || name.starts_with('.') {
        bail!("workstation netboot archive path is unsafe");
    }
    Ok(name.to_string())
}

async fn promote_existing(
    state: &AppState,
    descriptor: &WorkstationNetbootDescriptor,
    descriptor_json: &str,
    descriptor_sha256: &str,
    compatibility_epoch: u32,
    generation: i64,
) -> Result<()> {
    let key_fingerprint = sha256_bytes(
        &STANDARD
            .decode(state.config.update.trusted_public_key.trim())
            .context("decode workstation netboot trust key")?,
    );
    let now = now();
    let last_verified_at = runtime_verification_timestamp(Utc::now());
    let candidate: Option<(String,)> = sqlx::query_as(
        "SELECT root_path FROM workstation_netboot_bundles
         WHERE bundle_sha256 = ? AND compatibility_epoch = ?
           AND retention_state = 'verified'",
    )
    .bind(&descriptor.sha256)
    .bind(compatibility_epoch)
    .fetch_optional(&state.db)
    .await?;
    let (root_path,) = candidate
        .ok_or_else(|| anyhow!("workstation netboot candidate is not a verified local bundle"))?;
    let expected_root = state
        .config
        .paths
        .boot_assets_dir
        .join("netboot")
        .join(&descriptor.sha256);
    if Path::new(&root_path) != expected_root || !expected_root.is_dir() {
        bail!("workstation netboot verified bundle path is inconsistent");
    }
    // Promotion is a bounded, metadata-only causal commit. Downloading,
    // hashing, extraction, filesystem validation, fsync, and publication all
    // completed before this writer reservation is acquired.
    let mut transaction = state.db.begin_with("BEGIN IMMEDIATE").await?;
    let accepted_identity: Option<(i64, String)> = sqlx::query_as(
        "SELECT reconcile_generation, descriptor_sha256
         FROM workstation_netboot_reconcile_watermarks
         WHERE compatibility_epoch = ?",
    )
    .bind(compatibility_epoch)
    .fetch_optional(&mut *transaction)
    .await?;
    if accepted_identity.as_ref() != Some(&(generation, descriptor_sha256.to_string())) {
        bail!("workstation netboot promotion lost its accepted reconcile identity");
    }
    let candidate_still_verified: (i64,) = sqlx::query_as(
        "SELECT EXISTS(
             SELECT 1 FROM workstation_netboot_bundles
             WHERE bundle_sha256 = ? AND compatibility_epoch = ?
               AND retention_state = 'verified' AND root_path = ?
         )",
    )
    .bind(&descriptor.sha256)
    .bind(compatibility_epoch)
    .bind(&root_path)
    .fetch_one(&mut *transaction)
    .await?;
    if candidate_still_verified.0 == 0 {
        bail!("workstation netboot candidate changed before its causal promotion");
    }
    let old_active: (String,) = sqlx::query_as(
        "SELECT active_bundle_sha256 FROM workstation_netboot_runtime WHERE singleton_id = 1",
    )
    .fetch_one(&mut *transaction)
    .await?;
    if !old_active.0.is_empty() && old_active.0 != descriptor.sha256 {
        sqlx::query(
            "UPDATE workstation_netboot_bundles
             SET retained_until = ?, updated_at = ?
             WHERE bundle_sha256 = ? AND retention_state = 'verified'",
        )
        .bind(retained_until())
        .bind(&now)
        .bind(&old_active.0)
        .execute(&mut *transaction)
        .await?;
    }
    sqlx::query(
        "UPDATE workstation_netboot_bundles
         SET retained_until = NULL, updated_at = ?
         WHERE bundle_sha256 = ? AND retention_state = 'verified'",
    )
    .bind(&now)
    .bind(&descriptor.sha256)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO workstation_netboot_watermarks
         (compatibility_epoch, key_fingerprint, architecture, runtime_version,
          descriptor_sha256, accepted_at)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(compatibility_epoch, key_fingerprint, architecture) DO UPDATE SET
           runtime_version = excluded.runtime_version,
           descriptor_sha256 = excluded.descriptor_sha256,
           accepted_at = excluded.accepted_at",
    )
    .bind(compatibility_epoch)
    .bind(&key_fingerprint)
    .bind(&descriptor.architecture)
    .bind(&descriptor.runtime_version)
    .bind(descriptor_sha256)
    .bind(&now)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "UPDATE workstation_netboot_runtime
         SET desired_compatibility_epoch = ?, desired_descriptor_json = ?,
             desired_descriptor_sha256 = ?, reconcile_generation = ?,
             state = 'ready', progress_percent = 100, bytes_downloaded = ?, total_bytes = ?,
             failure_kind = '', failure_message = '',
             previous_bundle_sha256 = CASE
                 WHEN active_bundle_sha256 <> '' AND active_bundle_sha256 <> ? THEN active_bundle_sha256
                 ELSE previous_bundle_sha256 END,
             active_bundle_sha256 = ?,
             watermark_key_fingerprint = CASE WHEN ? = 1 THEN ? ELSE watermark_key_fingerprint END,
             watermark_architecture = CASE WHEN ? = 1 THEN ? ELSE watermark_architecture END,
             watermark_runtime_version = CASE WHEN ? = 1 THEN ? ELSE watermark_runtime_version END,
             watermark_descriptor_sha256 = CASE WHEN ? = 1 THEN ? ELSE watermark_descriptor_sha256 END,
             last_verified_at = ?, updated_at = ?
         WHERE singleton_id = 1",
    )
    .bind(compatibility_epoch)
    .bind(descriptor_json)
    .bind(descriptor_sha256)
    .bind(generation)
    .bind(i64::try_from(descriptor.size_bytes).unwrap_or(i64::MAX))
    .bind(i64::try_from(descriptor.size_bytes).unwrap_or(i64::MAX))
    .bind(&descriptor.sha256)
    .bind(&descriptor.sha256)
    .bind(compatibility_epoch)
    .bind(&key_fingerprint)
    .bind(compatibility_epoch)
    .bind(&descriptor.architecture)
    .bind(compatibility_epoch)
    .bind(&descriptor.runtime_version)
    .bind(compatibility_epoch)
    .bind(descriptor_sha256)
    .bind(&last_verified_at)
    .bind(&now)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(())
}

#[cfg(test)]
async fn enforce_watermark(
    state: &AppState,
    descriptor: &WorkstationNetbootDescriptor,
    descriptor_sha256: &str,
    compatibility_epoch: u32,
) -> Result<()> {
    let key_fingerprint = sha256_bytes(
        &STANDARD
            .decode(state.config.update.trusted_public_key.trim())
            .context("decode workstation netboot trust key")?,
    );
    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT runtime_version, descriptor_sha256
         FROM workstation_netboot_watermarks
         WHERE compatibility_epoch = ? AND key_fingerprint = ? AND architecture = ?",
    )
    .bind(compatibility_epoch)
    .bind(&key_fingerprint)
    .bind(&descriptor.architecture)
    .fetch_optional(&state.db)
    .await?;
    let Some((accepted_version, accepted_descriptor_sha256)) = row else {
        return Ok(());
    };
    enforce_watermark_precedence(
        &accepted_version,
        &accepted_descriptor_sha256,
        &descriptor.runtime_version,
        descriptor_sha256,
    )
}

fn enforce_watermark_precedence(
    accepted_version: &str,
    accepted_descriptor_sha256: &str,
    candidate_version: &str,
    candidate_descriptor_sha256: &str,
) -> Result<()> {
    let accepted =
        Version::parse(accepted_version).context("stored netboot watermark is invalid")?;
    let candidate = Version::parse(candidate_version)?;
    if candidate < accepted {
        return Err(coded_runtime_failure(
            FAILURE_INVALID_DESCRIPTOR,
            "workstation netboot signed downgrade was rejected",
        ));
    }
    if candidate == accepted && accepted_descriptor_sha256 != candidate_descriptor_sha256 {
        return Err(coded_runtime_failure(
            FAILURE_INVALID_DESCRIPTOR,
            "workstation netboot descriptor changed at the accepted runtime version",
        ));
    }
    Ok(())
}

pub fn boot_grant_message(claims: &BootGrantClaims) -> String {
    format!(
        "{BOOT_GRANT_DOMAIN}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
        claims.james_device_id,
        claims.organization_id,
        claims.organization_slug,
        claims.manage_api_url,
        claims.bundle_sha256,
        claims.profile_id.as_deref().unwrap_or_default(),
        claims.mac,
        claims.managed_device_id.as_deref().unwrap_or_default(),
        claims.reinstall_request_id.as_deref().unwrap_or_default(),
        claims.issued_at,
        claims.expires_at,
        claims.nonce,
    )
}

pub async fn create_boot_session(
    state: &AppState,
    normalized_mac: &str,
    profile_id: Option<&str>,
    managed_device_id: Option<&str>,
    reinstall_request_id: Option<&str>,
) -> Result<BootSessionLaunch> {
    crate::models::normalize_mac(normalized_mac)
        .map_err(|_| anyhow!("boot session MAC is invalid"))?;
    for (label, value) in [
        ("profile", profile_id),
        ("reinstall request", reinstall_request_id),
    ] {
        if let Some(value) = value {
            uuid::Uuid::parse_str(value)
                .with_context(|| format!("boot session {label} identity is invalid"))?;
        }
    }
    if managed_device_id.is_some_and(|value| !is_safe_control_plane_id(value)) {
        bail!("boot session managed device identity is invalid");
    }
    uuid::Uuid::parse_str(&state.config.manage.organization_id)
        .context("boot session organization identity is invalid")?;
    validate_organization_slug(&state.config.manage.organization_slug)?;

    // Import state describes reconciliation of the newest desired candidate;
    // it does not revoke an independently verified active bundle. Keep serving
    // the active runtime while a replacement is queued, downloading, held, or
    // failed, and fail closed only when there is no verified active bundle.
    let active: Option<(String, String, String)> = sqlx::query_as(
        "SELECT runtime.active_bundle_sha256, bundle.descriptor_json, bundle.root_path
         FROM workstation_netboot_runtime runtime
         JOIN workstation_netboot_bundles bundle
           ON bundle.bundle_sha256 = runtime.active_bundle_sha256
         WHERE runtime.singleton_id = 1 AND bundle.retention_state = 'verified'
           AND bundle.compatibility_epoch = ?",
    )
    .bind(COMPATIBILITY_EPOCH)
    .fetch_optional(&state.db)
    .await?;
    let (bundle_sha256, descriptor_json, root_path) = active
        .ok_or_else(|| anyhow!("workstation netboot runtime has no verified active bundle"))?;
    let descriptor: WorkstationNetbootDescriptor =
        serde_json::from_str(&descriptor_json).context("parse active netboot descriptor")?;
    if descriptor.sha256 != bundle_sha256 {
        bail!("active workstation netboot identity is inconsistent");
    }
    let manifest_body = fs::read(Path::new(&root_path).join("manifest.json"))
        .context("read active workstation netboot manifest")?;
    if sha256_bytes(&manifest_body) != descriptor.manifest_sha256 {
        bail!("active workstation netboot manifest failed its identity check");
    }
    let manifest = parse_canonical_manifest(&manifest_body)?;
    validate_manifest(&manifest, &descriptor)?;

    let identity = crate::manage::james_boot_identity(&state.config)?;
    if !is_safe_control_plane_id(&identity.device_id) {
        bail!("adopted James device identity is invalid");
    }
    let issued_at = Utc::now().timestamp();
    let expires_at = issued_at + BOOT_GRANT_LIFETIME_SECONDS;
    let cleanup_after = issued_at + BOOT_SESSION_RETENTION_SECONDS;
    let mut nonce_bytes = [0_u8; 32];
    let mut session_bytes = [0_u8; 16];
    OsRng.fill_bytes(&mut nonce_bytes);
    OsRng.fill_bytes(&mut session_bytes);
    let nonce = URL_SAFE_NO_PAD.encode(nonce_bytes);
    let session_id = URL_SAFE_NO_PAD.encode(session_bytes);
    let claims = BootGrantClaims {
        schema: "cybex.james.boot-grant.v1",
        james_device_id: identity.device_id,
        organization_id: state.config.manage.organization_id.clone(),
        organization_slug: state.config.manage.organization_slug.clone(),
        manage_api_url: state.config.manage.api_url.clone(),
        bundle_sha256: bundle_sha256.clone(),
        profile_id: profile_id.map(ToOwned::to_owned),
        mac: normalized_mac.to_string(),
        managed_device_id: managed_device_id.map(ToOwned::to_owned),
        reinstall_request_id: reinstall_request_id.map(ToOwned::to_owned),
        issued_at,
        expires_at,
        nonce,
    };
    let signature = identity
        .signing_key
        .sign(boot_grant_message(&claims).as_bytes());
    let context = BootContext {
        schema: "cybex.james.boot-context.v1",
        api_url: claims.manage_api_url.clone(),
        organization_slug: claims.organization_slug.clone(),
        bundle_sha256: bundle_sha256.clone(),
        profile_id: claims.profile_id.clone(),
        james_boot_grant: JamesBootGrant {
            claims,
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        },
    };
    let context_body = serde_json::to_vec(&context).context("serialize James boot context")?;
    let context_archive = newc_context_archive(&context_body, issued_at)?;
    if context_archive.len() > BOOT_CONTEXT_MAX_BYTES {
        bail!("James boot context archive exceeded 64 KiB");
    }

    let sessions_root = state.config.paths.data_dir.join("netboot/sessions");
    let session_root = sessions_root.join(&session_id);
    fs::create_dir_all(&sessions_root).context("create James boot sessions root")?;
    fs::set_permissions(&sessions_root, fs::Permissions::from_mode(0o700))?;
    fs::create_dir(&session_root).context("create James boot session directory")?;
    fs::set_permissions(&session_root, fs::Permissions::from_mode(0o700))?;
    let context_path = session_root.join("context.cpio");
    // iPXE's magic-initrd support wraps this bounded JSON body in the cpio
    // entry named by render_ipxe_launch. Supplying a second standalone cpio
    // after the compressed NixOS initrd is not reliable on the UEFI path.
    let write_result = write_private_file(&context_path, &context_body);
    if let Err(error) = write_result {
        fs::remove_dir_all(&session_root).ok();
        return Err(error);
    }

    let insert_result = sqlx::query(
        "INSERT INTO james_boot_sessions
         (session_id, nonce_sha256, normalized_mac, profile_id, managed_device_id,
          reinstall_request_id, bundle_sha256, context_path, issued_at, expires_at,
          cleanup_after)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&session_id)
    .bind(sha256_bytes(&nonce_bytes))
    .bind(normalized_mac)
    .bind(profile_id)
    .bind(managed_device_id)
    .bind(reinstall_request_id)
    .bind(&bundle_sha256)
    .bind(context_path.display().to_string())
    .bind(issued_at)
    .bind(expires_at)
    .bind(cleanup_after)
    .execute(&state.db)
    .await;
    if let Err(error) = insert_result {
        fs::remove_dir_all(&session_root).ok();
        return Err(error.into());
    }
    sync_directory(&sessions_root)?;

    let public_base = state.config.public_base_url();
    let kernel_url = format!("{public_base}/netboot/{bundle_sha256}/bzImage");
    let initrd_url = format!("{public_base}/netboot/{bundle_sha256}/initrd");
    let squashfs_url = format!("{public_base}/netboot/{bundle_sha256}/nix-store.squashfs");
    let context_url = format!("{public_base}/boot-session/{session_id}/context.cpio");
    let command_line = manifest
        .kernel_cmdline_template
        .replace("{squashfs_url}", &squashfs_url);
    Ok(BootSessionLaunch {
        schema: "cybex.james.kexec.v1",
        bundle_sha256,
        kernel_url,
        initrd_url,
        context_url,
        squashfs_url,
        command_line,
        expires_at,
    })
}

fn is_safe_control_plane_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value == value.trim()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

pub fn render_ipxe_launch(launch: &BootSessionLaunch) -> String {
    format!(
        "#!ipxe\necho Cybex James: loading signed workstation installer runtime\nkernel {} {} || goto failed\ninitrd {} || goto failed\ninitrd --name context.json {} /etc/cybex-installer/boot-context.json mode=600 mkdir=1 || goto failed\nboot || goto failed\n:failed\necho Cybex James could not stage the installer runtime\nsleep 5\nexit 1\n",
        launch.kernel_url, launch.command_line, launch.initrd_url, launch.context_url,
    )
}

pub async fn serve_context(
    State(state): State<AppState>,
    AxumPath(session_id): AxumPath<String>,
    headers: HeaderMap,
) -> AppResult<Response> {
    if !valid_session_id(&session_id) {
        return Err(AppError::NotFound);
    }
    let row: Option<(String, i64)> = sqlx::query_as(
        "SELECT context_path, expires_at FROM james_boot_sessions WHERE session_id = ?",
    )
    .bind(&session_id)
    .fetch_optional(&state.db)
    .await?;
    let (stored_path, expires_at) = row.ok_or(AppError::NotFound)?;
    if expires_at < Utc::now().timestamp() {
        return Err(AppError::NotFound);
    }
    let expected_root = state
        .config
        .paths
        .data_dir
        .join("netboot/sessions")
        .join(&session_id);
    let expected_path = expected_root.join("context.cpio");
    if Path::new(&stored_path) != expected_path {
        return Err(AppError::NotFound);
    }
    let mut response =
        assets::serve_file_from_root(&expected_root, "context.cpio", &headers).await?;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        "application/vnd.cybex.boot-context"
            .parse()
            .map_err(|_| AppError::Config("invalid context content type".to_string()))?,
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        "no-store, max-age=0"
            .parse()
            .map_err(|_| AppError::Config("invalid context cache policy".to_string()))?,
    );
    Ok(response)
}

pub async fn cleanup_expired_sessions(state: &AppState) -> Result<usize> {
    let now_unix = Utc::now().timestamp();
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT session_id, context_path FROM james_boot_sessions
         WHERE cleanup_after < ? ORDER BY cleanup_after LIMIT 256",
    )
    .bind(now_unix)
    .fetch_all(&state.db)
    .await?;
    let sessions_root = state.config.paths.data_dir.join("netboot/sessions");
    let mut removed = 0;
    for (session_id, context_path) in rows {
        if !valid_session_id(&session_id) {
            continue;
        }
        let root = sessions_root.join(&session_id);
        if Path::new(&context_path) != root.join("context.cpio") {
            continue;
        }
        match fs::symlink_metadata(&root) {
            Ok(metadata) if metadata.file_type().is_dir() => {
                fs::remove_dir_all(&root).context("remove expired James boot session")?;
            }
            Ok(_) => continue,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        sqlx::query("DELETE FROM james_boot_sessions WHERE session_id = ? AND cleanup_after < ?")
            .bind(&session_id)
            .bind(now_unix)
            .execute(&state.db)
            .await?;
        removed += 1;
    }
    Ok(removed)
}

pub fn spawn_maintenance(state: AppState) {
    tokio::spawn(async move {
        loop {
            if let Err(error) = maintain_once(&state).await {
                warn!(
                    failure_kind = classify_failure(&error),
                    "workstation netboot maintenance failed"
                );
            }
            tokio::time::sleep(Duration::from_secs(MAINTENANCE_INTERVAL_SECONDS)).await;
        }
    });
}

async fn maintain_once(state: &AppState) -> Result<()> {
    cleanup_expired_sessions(state).await?;
    scrub_due_bundles(state).await?;
    prune_expired_bundles(state).await?;
    Ok(())
}

async fn scrub_due_bundles(state: &AppState) -> Result<usize> {
    let cutoff = (Utc::now() - chrono::Duration::seconds(SCRUB_INTERVAL_SECONDS))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT bundle.bundle_sha256, bundle.descriptor_json, bundle.root_path
         FROM workstation_netboot_bundles bundle
         JOIN workstation_netboot_runtime runtime ON runtime.singleton_id = 1
         WHERE bundle.retention_state = 'verified'
           AND (bundle.bundle_sha256 = runtime.active_bundle_sha256
                OR bundle.bundle_sha256 = runtime.previous_bundle_sha256)
           AND (bundle.last_scrubbed_at IS NULL OR bundle.last_scrubbed_at < ?)
         ORDER BY CASE WHEN bundle.bundle_sha256 = runtime.active_bundle_sha256 THEN 0 ELSE 1 END",
    )
    .bind(cutoff)
    .fetch_all(&state.db)
    .await?;
    let mut scrubbed = 0;
    for (bundle_sha256, descriptor_json, root_path) in rows {
        let verification =
            verify_stored_bundle(state, &bundle_sha256, &descriptor_json, &root_path).await;
        match verification {
            Ok(()) => {
                sqlx::query(
                    "UPDATE workstation_netboot_bundles
                     SET last_scrubbed_at = ?, updated_at = ?
                     WHERE bundle_sha256 = ? AND retention_state = 'verified'",
                )
                .bind(now())
                .bind(now())
                .bind(&bundle_sha256)
                .execute(&state.db)
                .await?;
                scrubbed += 1;
            }
            Err(_) => {
                quarantine_bundle(state, &bundle_sha256, &root_path).await?;
            }
        }
    }
    Ok(scrubbed)
}

async fn verify_stored_bundle(
    state: &AppState,
    bundle_sha256: &str,
    descriptor_json: &str,
    root_path: &str,
) -> Result<()> {
    validate_sha256(bundle_sha256, "stored bundle SHA-256")?;
    let descriptor: WorkstationNetbootDescriptor =
        serde_json::from_str(descriptor_json).context("parse stored workstation descriptor")?;
    if descriptor.sha256 != bundle_sha256 {
        bail!("stored workstation descriptor identity is inconsistent");
    }
    validate_descriptor_with_policy(
        &descriptor,
        &state.config.update.trusted_public_key,
        state.config.workstation_netboot.allow_private_release_urls,
    )?;
    let expected_root = state
        .config
        .paths
        .boot_assets_dir
        .join("netboot")
        .join(bundle_sha256);
    if Path::new(root_path) != expected_root {
        bail!("stored workstation bundle path is inconsistent");
    }
    tokio::task::spawn_blocking(move || verify_extracted_tree(&expected_root, &descriptor))
        .await
        .context("join workstation netboot scrub")?
}

async fn quarantine_bundle(state: &AppState, bundle_sha256: &str, root_path: &str) -> Result<()> {
    validate_sha256(bundle_sha256, "quarantined bundle SHA-256")?;
    let expected_root = state
        .config
        .paths
        .boot_assets_dir
        .join("netboot")
        .join(bundle_sha256);
    if Path::new(root_path) != expected_root {
        bail!("refusing to quarantine an unexpected workstation bundle path");
    }
    let quarantine_root = state
        .config
        .paths
        .boot_assets_dir
        .join("netboot-quarantine");
    fs::create_dir_all(&quarantine_root)?;
    fs::set_permissions(&quarantine_root, fs::Permissions::from_mode(0o700))?;
    let quarantined_path = quarantine_root.join(format!(
        "{}.{}",
        bundle_sha256,
        uuid::Uuid::new_v4().simple()
    ));
    match fs::symlink_metadata(&expected_root) {
        Ok(metadata) if metadata.file_type().is_dir() => {
            fs::rename(&expected_root, &quarantined_path)
                .context("atomically quarantine corrupt workstation bundle")?;
            sync_directory(
                expected_root
                    .parent()
                    .ok_or_else(|| anyhow!("workstation bundle has no parent"))?,
            )?;
            sync_directory(&quarantine_root)?;
        }
        Ok(_) => bail!("corrupt workstation bundle root is not a directory"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let timestamp = now();
    sqlx::query(
        "UPDATE workstation_netboot_bundles
         SET retention_state = 'quarantined', root_path = ?, quarantined_at = ?,
             quarantine_reason = 'integrity_mismatch', updated_at = ?
         WHERE bundle_sha256 = ?",
    )
    .bind(quarantined_path.display().to_string())
    .bind(&timestamp)
    .bind(&timestamp)
    .bind(bundle_sha256)
    .execute(&state.db)
    .await?;

    let runtime: (String, String) = sqlx::query_as(
        "SELECT active_bundle_sha256, previous_bundle_sha256
         FROM workstation_netboot_runtime WHERE singleton_id = 1",
    )
    .fetch_one(&state.db)
    .await?;
    if runtime.0 == bundle_sha256 {
        let fallback = find_verified_fallback(state, bundle_sha256).await?;
        update_runtime_after_active_quarantine(state, fallback, &timestamp).await?;
    } else if runtime.1 == bundle_sha256 {
        update_runtime_after_previous_quarantine(state, &timestamp).await?;
    }
    Ok(())
}

async fn update_runtime_after_active_quarantine(
    state: &AppState,
    fallback: Option<String>,
    timestamp: &str,
) -> Result<()> {
    let active = fallback.unwrap_or_default();
    // A verified fallback remains bootable, but it is not the desired runtime.
    // Report genuine degradation while retaining the LKG identity for service;
    // calling this ready would violate Manage's desired==active invariant.
    sqlx::query(
        "UPDATE workstation_netboot_runtime
         SET state = 'failed', active_bundle_sha256 = ?, previous_bundle_sha256 = '',
             failure_kind = 'integrity_mismatch',
             failure_message = 'active workstation runtime failed integrity verification',
             progress_percent = 0,
             updated_at = ?
         WHERE singleton_id = 1",
    )
    .bind(active)
    .bind(timestamp)
    .execute(&state.db)
    .await?;
    Ok(())
}

async fn update_runtime_after_previous_quarantine(state: &AppState, timestamp: &str) -> Result<()> {
    // Quarantining only the rollback candidate does not change the active
    // runtime's ready state, but the integrity warning remains diagnostic data.
    sqlx::query(
        "UPDATE workstation_netboot_runtime
         SET previous_bundle_sha256 = '', failure_kind = 'integrity_mismatch',
             failure_message = 'previous workstation runtime failed integrity verification',
             updated_at = ? WHERE singleton_id = 1",
    )
    .bind(timestamp)
    .execute(&state.db)
    .await?;
    Ok(())
}

async fn find_verified_fallback(state: &AppState, excluded: &str) -> Result<Option<String>> {
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT bundle.bundle_sha256, bundle.descriptor_json, bundle.root_path
         FROM workstation_netboot_bundles bundle
         JOIN workstation_netboot_runtime runtime ON runtime.singleton_id = 1
         WHERE bundle.retention_state = 'verified' AND bundle.bundle_sha256 <> ?
           AND bundle.compatibility_epoch = ?
         ORDER BY CASE WHEN bundle.bundle_sha256 = runtime.previous_bundle_sha256 THEN 0 ELSE 1 END,
                  bundle.verified_at DESC
         LIMIT 8",
    )
    .bind(excluded)
    .bind(COMPATIBILITY_EPOCH)
    .fetch_all(&state.db)
    .await?;
    for (bundle_sha256, descriptor_json, root_path) in rows {
        if verify_stored_bundle(state, &bundle_sha256, &descriptor_json, &root_path)
            .await
            .is_ok()
        {
            sqlx::query(
                "UPDATE workstation_netboot_bundles
                 SET retained_until = NULL, last_scrubbed_at = ?, updated_at = ?
                 WHERE bundle_sha256 = ?",
            )
            .bind(now())
            .bind(now())
            .bind(&bundle_sha256)
            .execute(&state.db)
            .await?;
            return Ok(Some(bundle_sha256));
        }
        quarantine_tree_only(state, &bundle_sha256, &root_path).await?;
    }
    Ok(None)
}

async fn quarantine_tree_only(
    state: &AppState,
    bundle_sha256: &str,
    root_path: &str,
) -> Result<()> {
    let expected_root = state
        .config
        .paths
        .boot_assets_dir
        .join("netboot")
        .join(bundle_sha256);
    if Path::new(root_path) != expected_root {
        bail!("refusing to quarantine an unexpected workstation fallback path");
    }
    let quarantine_root = state
        .config
        .paths
        .boot_assets_dir
        .join("netboot-quarantine");
    fs::create_dir_all(&quarantine_root)?;
    fs::set_permissions(&quarantine_root, fs::Permissions::from_mode(0o700))?;
    let target = quarantine_root.join(format!(
        "{}.{}",
        bundle_sha256,
        uuid::Uuid::new_v4().simple()
    ));
    match fs::symlink_metadata(&expected_root) {
        Ok(metadata) if metadata.file_type().is_dir() => fs::rename(&expected_root, &target)?,
        Ok(_) => bail!("corrupt workstation fallback root is not a directory"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let timestamp = now();
    sqlx::query(
        "UPDATE workstation_netboot_bundles
         SET retention_state = 'quarantined', root_path = ?, quarantined_at = ?,
             quarantine_reason = 'integrity_mismatch', updated_at = ?
         WHERE bundle_sha256 = ?",
    )
    .bind(target.display().to_string())
    .bind(&timestamp)
    .bind(&timestamp)
    .bind(bundle_sha256)
    .execute(&state.db)
    .await?;
    Ok(())
}

async fn prune_expired_bundles(state: &AppState) -> Result<usize> {
    let now_text = now();
    let now_unix = Utc::now().timestamp();
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT bundle.bundle_sha256, bundle.root_path
         FROM workstation_netboot_bundles bundle
         JOIN workstation_netboot_runtime runtime ON runtime.singleton_id = 1
         WHERE bundle.retention_state = 'verified'
           AND bundle.retained_until IS NOT NULL AND bundle.retained_until < ?
           AND bundle.bundle_sha256 <> runtime.active_bundle_sha256
           AND bundle.bundle_sha256 <> runtime.previous_bundle_sha256
           AND NOT EXISTS (
             SELECT 1 FROM james_boot_sessions session
             WHERE session.bundle_sha256 = bundle.bundle_sha256 AND session.expires_at >= ?
           )
         ORDER BY bundle.retained_until LIMIT 8",
    )
    .bind(&now_text)
    .bind(now_unix)
    .fetch_all(&state.db)
    .await?;
    let public_root = state.config.paths.boot_assets_dir.join("netboot");
    let mut removed = 0;
    for (bundle_sha256, root_path) in rows {
        validate_sha256(&bundle_sha256, "pruned bundle SHA-256")?;
        let root = public_root.join(&bundle_sha256);
        if Path::new(&root_path) != root {
            continue;
        }
        let tombstone = public_root.join(format!(".prune-{}", uuid::Uuid::new_v4().simple()));
        match fs::symlink_metadata(&root) {
            Ok(metadata) if metadata.file_type().is_dir() => {
                fs::rename(&root, &tombstone)?;
                sync_directory(&public_root)?;
            }
            Ok(_) => continue,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let result = sqlx::query(
            "DELETE FROM workstation_netboot_bundles
             WHERE bundle_sha256 = ? AND retention_state = 'verified' AND retained_until < ?",
        )
        .bind(&bundle_sha256)
        .bind(&now_text)
        .execute(&state.db)
        .await;
        match result {
            Ok(result) if result.rows_affected() == 1 => {
                if tombstone.exists() {
                    fs::remove_dir_all(&tombstone)?;
                    sync_directory(&public_root)?;
                }
                removed += 1;
            }
            Ok(_) => {
                if tombstone.exists() {
                    fs::rename(&tombstone, &root)?;
                    sync_directory(&public_root)?;
                }
            }
            Err(error) => {
                if tombstone.exists() {
                    fs::rename(&tombstone, &root)?;
                    sync_directory(&public_root)?;
                }
                return Err(error.into());
            }
        }
    }
    Ok(removed)
}

fn validate_organization_slug(value: &str) -> Result<()> {
    if value.len() < 2
        || value.len() > 64
        || value.starts_with('-')
        || value.ends_with('-')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        bail!("boot session organization slug is invalid");
    }
    Ok(())
}

fn valid_session_id(value: &str) -> bool {
    value.len() == 22
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        && URL_SAFE_NO_PAD
            .decode(value)
            .is_ok_and(|decoded| decoded.len() == 16)
}

fn write_private_file(path: &Path, body: &[u8]) -> Result<()> {
    let temporary = path.with_extension("cpio.tmp");
    let mut options = fs::OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = options.open(&temporary)?;
    std::io::Write::write_all(&mut file, body)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    sync_directory(
        path.parent()
            .ok_or_else(|| anyhow!("context path has no parent"))?,
    )
}

fn newc_context_archive(body: &[u8], mtime: i64) -> Result<Vec<u8>> {
    if mtime < 0 || body.is_empty() {
        bail!("James boot context archive inputs are invalid");
    }
    let mut archive = Vec::with_capacity(body.len() + 512);
    append_newc_entry(
        &mut archive,
        "etc/cybex-installer/boot-context.json",
        0o100600,
        mtime as u32,
        body,
    )?;
    append_newc_entry(&mut archive, "TRAILER!!!", 0, mtime as u32, &[])?;
    while archive.len() % 512 != 0 {
        archive.push(0);
    }
    Ok(archive)
}

fn append_newc_entry(
    archive: &mut Vec<u8>,
    name: &str,
    mode: u32,
    mtime: u32,
    body: &[u8],
) -> Result<()> {
    let name_size = name
        .len()
        .checked_add(1)
        .ok_or_else(|| anyhow!("CPIO name size overflow"))?;
    let file_size = u32::try_from(body.len()).context("CPIO body exceeds u32")?;
    let header = format!(
        "070701{ino:08x}{mode:08x}{uid:08x}{gid:08x}{nlink:08x}{mtime:08x}{file_size:08x}{devmajor:08x}{devminor:08x}{rdevmajor:08x}{rdevminor:08x}{name_size:08x}{check:08x}",
        ino = 1_u32,
        uid = 0_u32,
        gid = 0_u32,
        nlink = 1_u32,
        devmajor = 0_u32,
        devminor = 0_u32,
        rdevmajor = 0_u32,
        rdevminor = 0_u32,
        check = 0_u32,
    );
    if header.len() != 110 {
        bail!("CPIO header length is invalid");
    }
    archive.extend_from_slice(header.as_bytes());
    archive.extend_from_slice(name.as_bytes());
    archive.push(0);
    pad_four(archive);
    archive.extend_from_slice(body);
    pad_four(archive);
    Ok(())
}

fn pad_four(value: &mut Vec<u8>) {
    while value.len() % 4 != 0 {
        value.push(0);
    }
}

async fn set_runtime_state(
    state: &AppState,
    status: &str,
    progress: i64,
    downloaded: u64,
    total: u64,
) -> Result<()> {
    sqlx::query(
        "UPDATE workstation_netboot_runtime
         SET state = ?, progress_percent = ?, bytes_downloaded = ?, total_bytes = ?, updated_at = ?
         WHERE singleton_id = 1",
    )
    .bind(status)
    .bind(progress.clamp(0, 100))
    .bind(i64::try_from(downloaded).unwrap_or(i64::MAX))
    .bind(i64::try_from(total).unwrap_or(i64::MAX))
    .bind(now())
    .execute(&state.db)
    .await?;
    Ok(())
}

async fn record_failure_for_attempt(
    state: &AppState,
    compatibility_epoch: u32,
    reconcile_generation: i64,
    descriptor_sha256: &str,
    kind: &str,
    message: &str,
) -> Result<()> {
    sqlx::query(
        "UPDATE workstation_netboot_runtime
         SET state = 'failed', failure_kind = ?, failure_message = ?, updated_at = ?
         WHERE singleton_id = 1
           AND desired_compatibility_epoch = ?
           AND desired_descriptor_sha256 = ?
           AND reconcile_generation = ?",
    )
    .bind(kind)
    .bind(message)
    .bind(now())
    .bind(compatibility_epoch)
    .bind(descriptor_sha256)
    .bind(reconcile_generation)
    .execute(&state.db)
    .await?;
    Ok(())
}

pub async fn report(state: &AppState) -> Result<WorkstationNetbootReport> {
    #[derive(sqlx::FromRow)]
    struct RuntimeReportRow {
        desired_compatibility_epoch: i64,
        reconcile_generation: i64,
        state: String,
        progress_percent: i64,
        bytes_downloaded: i64,
        total_bytes: i64,
        failure_kind: String,
        failure_message: String,
        desired_descriptor_json: String,
        compatible_active_bundle_sha256: String,
        compatible_previous_bundle_sha256: String,
        last_verified_at: Option<String>,
        active_runtime_version: String,
    }

    let row = sqlx::query_as::<_, RuntimeReportRow>(
        "SELECT runtime.desired_compatibility_epoch, runtime.reconcile_generation,
                    runtime.state, runtime.progress_percent, runtime.bytes_downloaded,
                    runtime.total_bytes, runtime.failure_kind, runtime.failure_message,
                    runtime.desired_descriptor_json,
                    COALESCE(active.bundle_sha256, '') AS compatible_active_bundle_sha256,
                    COALESCE(previous.bundle_sha256, '') AS compatible_previous_bundle_sha256,
                    runtime.last_verified_at,
                    COALESCE(active.runtime_version, '') AS active_runtime_version
             FROM workstation_netboot_runtime runtime
             LEFT JOIN workstation_netboot_bundles active
               ON active.bundle_sha256 = runtime.active_bundle_sha256
              AND active.retention_state = 'verified'
              AND active.compatibility_epoch = ?
             LEFT JOIN workstation_netboot_bundles previous
               ON previous.bundle_sha256 = runtime.previous_bundle_sha256
              AND previous.retention_state = 'verified'
              AND previous.compatibility_epoch = ?
             WHERE runtime.singleton_id = 1",
    )
    .bind(COMPATIBILITY_EPOCH)
    .bind(COMPATIBILITY_EPOCH)
    .fetch_one(&state.db)
    .await?;
    let desired_bundle_sha256 =
        serde_json::from_str::<WorkstationNetbootDescriptor>(&row.desired_descriptor_json)
            .map(|descriptor| descriptor.sha256)
            .unwrap_or_default();
    let incompatible_ready = row.state == "ready" && row.compatible_active_bundle_sha256.is_empty();
    let ready_warning = row.state == "ready"
        && !incompatible_ready
        && !normalize_failure_kind(&row.failure_kind).is_empty();
    Ok(WorkstationNetbootReport {
        compatibility_epoch: Some(
            u32::try_from(row.desired_compatibility_epoch).unwrap_or(default_compatibility_epoch()),
        ),
        reconcile_generation: Some(row.reconcile_generation),
        state: if incompatible_ready {
            "failed".to_string()
        } else {
            row.state
        },
        progress_percent: row.progress_percent,
        bytes_downloaded: row.bytes_downloaded,
        total_bytes: row.total_bytes,
        failure_kind: if incompatible_ready {
            FAILURE_COMPATIBILITY_EPOCH_UNSUPPORTED.to_string()
        } else if ready_warning {
            String::new()
        } else {
            normalize_failure_kind(&row.failure_kind).to_string()
        },
        failure_message: if incompatible_ready {
            "active workstation runtime belongs to another compatibility epoch".to_string()
        } else if ready_warning {
            String::new()
        } else {
            normalize_failure_message(&row.failure_message)
        },
        warning_kind: ready_warning.then(|| normalize_failure_kind(&row.failure_kind).to_string()),
        warning_message: ready_warning.then(|| normalize_failure_message(&row.failure_message)),
        desired_bundle_sha256,
        active_bundle_sha256: row.compatible_active_bundle_sha256,
        previous_bundle_sha256: row.compatible_previous_bundle_sha256,
        last_verified_at: row.last_verified_at,
        runtime_version: row.active_runtime_version,
    })
}

fn normalize_failure_kind(value: &str) -> &str {
    match value {
        "" => "",
        FAILURE_INVALID_DESCRIPTOR => FAILURE_INVALID_DESCRIPTOR,
        FAILURE_INTEGRITY_MISMATCH => FAILURE_INTEGRITY_MISMATCH,
        FAILURE_INSUFFICIENT_DISK_SPACE => FAILURE_INSUFFICIENT_DISK_SPACE,
        FAILURE_NETWORK_OR_SERVER => FAILURE_NETWORK_OR_SERVER,
        FAILURE_LOCAL_IO_OR_PROCESSING => FAILURE_LOCAL_IO_OR_PROCESSING,
        FAILURE_COMPATIBILITY_EPOCH_UNSUPPORTED => FAILURE_COMPATIBILITY_EPOCH_UNSUPPORTED,
        _ => FAILURE_UNKNOWN,
    }
}

pub async fn serve_component(
    State(state): State<AppState>,
    AxumPath((bundle_sha256, component)): AxumPath<(String, String)>,
    headers: HeaderMap,
) -> AppResult<Response> {
    validate_sha256(&bundle_sha256, "bundle SHA-256").map_err(|_| AppError::NotFound)?;
    if !COMPONENT_NAMES.contains(&component.as_str()) {
        return Err(AppError::NotFound);
    }
    let now_unix = Utc::now().timestamp();
    let allowed: (i64,) = sqlx::query_as(
        "SELECT EXISTS(
           SELECT 1 FROM workstation_netboot_bundles bundle
           WHERE bundle.bundle_sha256 = ? AND bundle.retention_state = 'verified'
             AND bundle.compatibility_epoch = ?
             AND (
               EXISTS(
                 SELECT 1 FROM workstation_netboot_runtime
                 WHERE singleton_id = 1
                   AND (bundle.bundle_sha256 = active_bundle_sha256
                        OR bundle.bundle_sha256 = previous_bundle_sha256)
               ) OR EXISTS(
                 SELECT 1 FROM james_boot_sessions session
                 WHERE session.bundle_sha256 = bundle.bundle_sha256 AND session.expires_at >= ?
               )
             )
         )",
    )
    .bind(&bundle_sha256)
    .bind(COMPATIBILITY_EPOCH)
    .bind(now_unix)
    .fetch_one(&state.db)
    .await?;
    if allowed.0 == 0 {
        return Err(AppError::NotFound);
    }
    let root = state
        .config
        .paths
        .boot_assets_dir
        .join("netboot")
        .join(&bundle_sha256);
    let mut response = assets::serve_file_from_root(&root, &component, &headers).await?;
    let content_type = match component.as_str() {
        "bzImage" => "application/vnd.cybex.kernel",
        "initrd" => "application/vnd.cybex.initrd",
        "nix-store.squashfs" => "application/vnd.cybex.squashfs",
        _ => unreachable!("component was allowlisted"),
    };
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        content_type
            .parse()
            .map_err(|_| AppError::Config("invalid netboot content type".to_string()))?,
    );
    response.headers_mut().insert(
        header::ETAG,
        format!("\"{bundle_sha256}-{component}\"")
            .parse()
            .map_err(|_| AppError::Config("invalid netboot ETag".to_string()))?,
    );
    sqlx::query(
        "UPDATE workstation_netboot_bundles SET last_served_at = ?, updated_at = ? WHERE bundle_sha256 = ?",
    )
    .bind(now())
    .bind(now())
    .bind(&bundle_sha256)
    .execute(&state.db)
    .await
    .ok();
    Ok(response)
}

pub async fn readiness(State(state): State<AppState>) -> Response {
    match report(&state).await {
        Ok(report) => (StatusCode::OK, axum::Json(report)).into_response(),
        Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

fn validate_revision(value: &str, label: &str) -> Result<()> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("workstation netboot {label} must be lowercase 40-hex");
    }
    Ok(())
}

fn validate_sha256(value: &str, label: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("workstation netboot {label} must be lowercase 64-hex");
    }
    Ok(())
}

async fn sha256_file(path: PathBuf) -> Result<String> {
    tokio::task::spawn_blocking(move || sha256_regular_file(&path))
        .await
        .context("join workstation netboot hashing")?
}

fn sha256_regular_file(path: &Path) -> Result<String> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        bail!("workstation netboot component is not a regular file");
    }
    let mut options = fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = options.open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn sha256_bytes(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

fn sync_directory(path: &Path) -> Result<()> {
    let directory = fs::File::open(path)?;
    directory.sync_all()?;
    Ok(())
}

fn now() -> String {
    Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn runtime_verification_timestamp(value: DateTime<Utc>) -> String {
    // This evidence crosses the James/Manage boundary. Preserve PostgreSQL's
    // microsecond precision so an older Manage release that still compares it
    // with `desired_changed_at` does not misclassify a same-second successful
    // reconciliation as stale. New Manage releases use causal generation and
    // descriptor identity instead of cross-host wall-clock ordering.
    value.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
}

fn retained_until() -> String {
    (Utc::now() + chrono::Duration::seconds(BUNDLE_RETENTION_SECONDS))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

pub fn safe_failure_message(error: &anyhow::Error) -> String {
    normalize_failure_message(&error.to_string())
}

fn normalize_failure_message(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .take(FAILURE_MESSAGE_MAX_CHARS)
        .collect()
}

fn classify_failure(error: &anyhow::Error) -> &'static str {
    if let Some(failure) = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<CodedRuntimeFailure>())
    {
        return failure.code;
    }
    let message = error.to_string().to_ascii_lowercase();
    if message.contains("signature")
        || message.contains("descriptor")
        || message.contains("watermark")
    {
        FAILURE_INVALID_DESCRIPTOR
    } else if message.contains("sha-256")
        || message.contains("manifest")
        || message.contains("archive")
    {
        FAILURE_INTEGRITY_MISMATCH
    } else if message.contains("disk space") {
        FAILURE_INSUFFICIENT_DISK_SPACE
    } else if message.contains("http")
        || message.contains("resolve")
        || message.contains("download")
    {
        FAILURE_NETWORK_OR_SERVER
    } else {
        FAILURE_LOCAL_IO_OR_PROCESSING
    }
}

pub fn safe_failure_kind(error: &anyhow::Error) -> &'static str {
    classify_failure(error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        task::JoinHandle,
    };

    #[test]
    fn runtime_verification_evidence_preserves_subsecond_precision() {
        let instant = DateTime::parse_from_rfc3339("2026-08-10T12:34:56.123456Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(
            runtime_verification_timestamp(instant),
            "2026-08-10T12:34:56.123456Z"
        );
    }

    #[test]
    fn download_progress_writes_are_bounded_and_keep_slow_link_heartbeats() {
        let started = Instant::now();
        let total = 1_416_000_000_u64;
        let mut checkpoint = DownloadProgressCheckpoint::new(started);
        let mut writes = 0usize;
        for chunk in 1..=100_000_u64 {
            let downloaded = total.saturating_mul(chunk) / 100_000;
            let progress = download_progress_percent(downloaded, total);
            if checkpoint.due(progress, downloaded, started, false) {
                checkpoint.commit(progress, downloaded, started);
                writes += 1;
            }
        }
        // One write per newly reached 2..69% value, rather than one write per
        // HTTP chunk. The forced post-fsync checkpoint is one additional write.
        assert_eq!(writes, 68);
        assert!(checkpoint.due(69, total, started, true));

        let slow = DownloadProgressCheckpoint::new(started);
        let same_percent_bytes = total / 1000;
        assert!(!slow.due(1, same_percent_bytes, started, false));
        assert!(slow.due(
            1,
            same_percent_bytes,
            started + DOWNLOAD_PROGRESS_MAX_INTERVAL,
            false
        ));
    }

    #[test]
    fn boot_context_overlay_is_a_bounded_newc_member() {
        let body = br#"{"schema":"cybex.james.boot-context.v1"}"#;
        let cpio = newc_context_archive(body, 1_700_000_000).unwrap();
        assert!(cpio.len() <= BOOT_CONTEXT_MAX_BYTES);
        assert!(
            cpio.windows(b"etc/cybex-installer/boot-context.json".len())
                .any(|window| window == b"etc/cybex-installer/boot-context.json")
        );
    }

    #[test]
    fn ipxe_launch_uses_magic_initrd_context_injection() {
        let launch = BootSessionLaunch {
            schema: "cybex.james.kexec.v1",
            bundle_sha256: "a".repeat(64),
            kernel_url: "http://james.test/kernel".to_string(),
            initrd_url: "http://james.test/initrd".to_string(),
            context_url: "http://james.test/context.cpio".to_string(),
            squashfs_url: "http://james.test/rootfs".to_string(),
            command_line: "init=/nix/store/system/init".to_string(),
            expires_at: 1_700_000_600,
        };
        let script = render_ipxe_launch(&launch);
        assert!(script.contains("initrd http://james.test/initrd"));
        assert!(script.contains(
            "http://james.test/context.cpio /etc/cybex-installer/boot-context.json mode=600 mkdir=1"
        ));
    }

    #[test]
    fn signature_message_contract_is_exact() {
        let descriptor = fixture_descriptor();
        let message = signature_message(&descriptor);
        assert!(message.starts_with("CYBEX-JAMES-WORKSTATION-NETBOOT-V1\n1.0.0\n"));
        assert!(message.ends_with("https://releases.example.test/cybex-workstation-netboot-1.0.0-aaaaaaaaaaaa-x86_64-linux.tar.zst\n"));
        assert_eq!(message.lines().count(), 17);
    }

    #[test]
    fn development_policy_accepts_unsigned_runtime_after_structural_validation() {
        let mut descriptor = fixture_descriptor();
        assert!(validate_descriptor(&descriptor, "not-a-key").is_err());
        assert!(validate_descriptor_with_policy(&descriptor, "not-a-key", true).is_ok());

        descriptor.components.initrd.size_bytes = 0;
        assert!(validate_descriptor_with_policy(&descriptor, "not-a-key", true).is_err());
    }

    #[test]
    fn missing_runtime_epoch_always_means_legacy_epoch_one() {
        let legacy = serde_json::json!({
            "descriptor": fixture_descriptor(),
            "reconcile_generation": 7
        });
        if COMPATIBILITY_EPOCH == 1 {
            let desired = decode_desired(legacy).unwrap();
            assert_eq!(desired.compatibility_epoch, 1);
        } else {
            let error = decode_desired(legacy).unwrap_err();
            assert_eq!(
                safe_failure_kind(&error),
                FAILURE_COMPATIBILITY_EPOCH_UNSUPPORTED
            );
        }
    }

    #[test]
    fn runtime_report_fencing_fields_can_be_omitted_for_legacy_manage() {
        let legacy = serde_json::to_value(WorkstationNetbootReport::default()).unwrap();
        assert!(legacy.get("compatibility_epoch").is_none());
        assert!(legacy.get("reconcile_generation").is_none());

        let current = serde_json::to_value(WorkstationNetbootReport {
            compatibility_epoch: Some(COMPATIBILITY_EPOCH),
            reconcile_generation: Some(7),
            ..WorkstationNetbootReport::default()
        })
        .unwrap();
        assert_eq!(
            current["compatibility_epoch"].as_u64(),
            Some(u64::from(COMPATIBILITY_EPOCH))
        );
        assert_eq!(current["reconcile_generation"].as_i64(), Some(7));
    }

    #[test]
    fn unsupported_runtime_epoch_has_one_stable_failure_code() {
        validate_compatibility_epoch(COMPATIBILITY_EPOCH).unwrap();
        let error = validate_compatibility_epoch(COMPATIBILITY_EPOCH + 1).unwrap_err();
        assert_eq!(
            safe_failure_kind(&error),
            FAILURE_COMPATIBILITY_EPOCH_UNSUPPORTED
        );
    }

    #[test]
    fn compatibility_epoch_is_checked_before_descriptor_shape() {
        let future = serde_json::json!({
            "compatibility_epoch": COMPATIBILITY_EPOCH + 1,
            "descriptor": { "future_descriptor_contract": true },
            "reconcile_generation": 8
        });
        let error = decode_desired(future).unwrap_err();
        assert_eq!(
            safe_failure_kind(&error),
            FAILURE_COMPATIBILITY_EPOCH_UNSUPPORTED
        );
    }

    #[tokio::test]
    async fn unsupported_runtime_epoch_is_persisted_without_interrupting_the_active_runtime() {
        let fixture = RuntimeFilesystemFixture::new().await;
        let active = fixture.install_bundle("1.0.0", &"a".repeat(64)).await;
        fixture.activate(&active, None).await;
        let candidate = fixture.signed_download_descriptor(
            "2.0.0",
            &"c".repeat(64),
            1,
            "http://127.0.0.1:9".to_string(),
        );
        let raw_desired = serde_json::to_value(DesiredWorkstationNetboot {
            compatibility_epoch: COMPATIBILITY_EPOCH + 1,
            descriptor: candidate.clone(),
            reconcile_generation: 2,
        })
        .unwrap();
        let error = decode_desired(raw_desired.clone()).unwrap_err();

        record_desired_decode_failure(
            &fixture.state,
            &raw_desired,
            safe_failure_kind(&error),
            &safe_failure_message(&error),
        )
        .await
        .unwrap();

        let report = report(&fixture.state).await.unwrap();
        assert_eq!(report.compatibility_epoch, Some(COMPATIBILITY_EPOCH + 1));
        assert_eq!(report.reconcile_generation, Some(2));
        assert_eq!(report.state, "failed");
        assert_eq!(report.failure_kind, FAILURE_COMPATIBILITY_EPOCH_UNSUPPORTED);
        assert!(!report.failure_message.is_empty());
        assert!(report.failure_message.chars().count() <= FAILURE_MESSAGE_MAX_CHARS);
        assert!(
            report
                .failure_message
                .chars()
                .all(|character| !character.is_control())
        );
        assert_eq!(report.desired_bundle_sha256, candidate.sha256);
        assert_eq!(report.active_bundle_sha256, active.sha256);
        assert_eq!(report.runtime_version, active.runtime_version);
        let launch = create_boot_session(&fixture.state, "02:00:00:00:00:01", None, None, None)
            .await
            .unwrap();
        assert_eq!(launch.bundle_sha256, active.sha256);
        fixture.cleanup();
    }

    #[tokio::test]
    async fn malformed_desired_does_not_block_a_corrected_same_generation() {
        let fixture = RuntimeFilesystemFixture::new().await;
        let malformed = serde_json::json!({
            "compatibility_epoch": COMPATIBILITY_EPOCH,
            "descriptor": {"schema": DESCRIPTOR_SCHEMA},
            "reconcile_generation": 7
        });
        record_desired_decode_failure(
            &fixture.state,
            &malformed,
            FAILURE_INVALID_DESCRIPTOR,
            "malformed desired state",
        )
        .await
        .unwrap();

        let watermark_count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM workstation_netboot_reconcile_watermarks
             WHERE compatibility_epoch = ?",
        )
        .bind(COMPATIBILITY_EPOCH)
        .fetch_one(&fixture.state.db)
        .await
        .unwrap();
        assert_eq!(watermark_count.0, 0);

        let corrected = fixture.install_bundle("1.0.0", &"c".repeat(64)).await;
        reconcile_desired(
            &fixture.state,
            &DesiredWorkstationNetboot {
                compatibility_epoch: COMPATIBILITY_EPOCH,
                descriptor: corrected.clone(),
                reconcile_generation: 7,
            },
        )
        .await
        .unwrap();
        let report = report(&fixture.state).await.unwrap();
        assert_eq!(report.state, "ready");
        assert_eq!(report.desired_bundle_sha256, corrected.sha256);
        assert_eq!(report.reconcile_generation, Some(7));
        fixture.cleanup();
    }

    #[test]
    fn runtime_report_failure_kind_is_bounded() {
        for known in [
            FAILURE_INVALID_DESCRIPTOR,
            FAILURE_INTEGRITY_MISMATCH,
            FAILURE_INSUFFICIENT_DISK_SPACE,
            FAILURE_NETWORK_OR_SERVER,
            FAILURE_LOCAL_IO_OR_PROCESSING,
            FAILURE_COMPATIBILITY_EPOCH_UNSUPPORTED,
        ] {
            assert_eq!(normalize_failure_kind(known), known);
        }
        assert_eq!(normalize_failure_kind(""), "");
        assert_eq!(normalize_failure_kind("future_detail"), FAILURE_UNKNOWN);
    }

    #[tokio::test]
    async fn runtime_reconciliation_queue_is_single_worker_and_latest_wins() {
        let fixture = RuntimeFilesystemFixture::new().await;
        let mut queue = RuntimeReconcileQueue::new();
        let desired = |generation| DesiredWorkstationNetboot {
            compatibility_epoch: COMPATIBILITY_EPOCH,
            descriptor: fixture_descriptor(),
            reconcile_generation: generation,
        };
        assert!(queue.enqueue(RuntimeReconcileRequest::Desired {
            state: fixture.state.clone(),
            desired: Box::new(desired(1)),
        }));
        assert!(!queue.enqueue(RuntimeReconcileRequest::Desired {
            state: fixture.state.clone(),
            desired: Box::new(desired(2)),
        }));
        match queue.pending.take().unwrap() {
            RuntimeReconcileRequest::Desired { desired, .. } => {
                assert_eq!(desired.reconcile_generation, 2)
            }
            RuntimeReconcileRequest::DecodeFailure { .. } => panic!("latest request changed kind"),
        }
        fixture.cleanup();
    }

    #[tokio::test]
    async fn candidate_download_failure_keeps_the_verified_active_runtime_bootable() {
        let fixture = RuntimeFilesystemFixture::new().await;
        let active = fixture.install_bundle("1.0.0", &"a".repeat(64)).await;
        fixture.activate(&active, None).await;

        let (url, server) = one_shot_http_response("503 Service Unavailable", Vec::new()).await;
        let candidate = fixture.signed_download_descriptor("2.0.0", &"c".repeat(64), 1, url);
        let error = reconcile_desired(
            &fixture.state,
            &DesiredWorkstationNetboot {
                compatibility_epoch: COMPATIBILITY_EPOCH,
                descriptor: candidate.clone(),
                reconcile_generation: 2,
            },
        )
        .await
        .unwrap_err();
        await_one_shot_server(server).await;

        assert_eq!(safe_failure_kind(&error), FAILURE_NETWORK_OR_SERVER);
        // Fast config polls are durably coalesced until the bounded transient
        // retry time, rather than hammering an unavailable release host.
        reconcile_desired(
            &fixture.state,
            &DesiredWorkstationNetboot {
                compatibility_epoch: COMPATIBILITY_EPOCH,
                descriptor: candidate.clone(),
                reconcile_generation: 2,
            },
        )
        .await
        .unwrap();
        sqlx::query(
            "UPDATE workstation_netboot_reconcile_attempts SET next_attempt_at = 0
             WHERE compatibility_epoch = ? AND reconcile_generation = 2",
        )
        .bind(COMPATIBILITY_EPOCH)
        .execute(&fixture.state.db)
        .await
        .unwrap();
        let retry_error = reconcile_desired(
            &fixture.state,
            &DesiredWorkstationNetboot {
                compatibility_epoch: COMPATIBILITY_EPOCH,
                descriptor: candidate,
                reconcile_generation: 2,
            },
        )
        .await
        .unwrap_err();
        assert_eq!(safe_failure_kind(&retry_error), FAILURE_NETWORK_OR_SERVER);
        fixture
            .assert_failed_candidate_did_not_interrupt_boot(&active)
            .await;
        fixture.cleanup();
    }

    #[tokio::test]
    async fn candidate_verification_failure_keeps_the_verified_active_runtime_bootable() {
        let fixture = RuntimeFilesystemFixture::new().await;
        let active = fixture.install_bundle("1.0.0", &"a".repeat(64)).await;
        fixture.activate(&active, None).await;

        let corrupt_archive = b"not-the-signed-archive".to_vec();
        let (url, server) = one_shot_http_response("200 OK", corrupt_archive.clone()).await;
        let candidate = fixture.signed_download_descriptor(
            "2.0.0",
            &"c".repeat(64),
            corrupt_archive.len() as u64,
            url,
        );
        let error = reconcile_desired(
            &fixture.state,
            &DesiredWorkstationNetboot {
                compatibility_epoch: COMPATIBILITY_EPOCH,
                descriptor: candidate.clone(),
                reconcile_generation: 2,
            },
        )
        .await
        .unwrap_err();
        await_one_shot_server(server).await;

        assert_eq!(safe_failure_kind(&error), FAILURE_INTEGRITY_MISMATCH);
        // A normal config poll is coalesced until the durable retry time, so a
        // bad origin cannot be hammered on every managed sync.
        reconcile_desired(
            &fixture.state,
            &DesiredWorkstationNetboot {
                compatibility_epoch: COMPATIBILITY_EPOCH,
                descriptor: candidate.clone(),
                reconcile_generation: 2,
            },
        )
        .await
        .unwrap();
        let held = report(&fixture.state).await.unwrap();
        assert_eq!(held.state, "failed");
        assert_eq!(held.failure_kind, FAILURE_INTEGRITY_MISMATCH);
        let retry_state: (i64, Option<i64>) = sqlx::query_as(
            "SELECT terminal_hold, next_attempt_at
             FROM workstation_netboot_reconcile_attempts
             WHERE compatibility_epoch = ? AND reconcile_generation = 2",
        )
        .bind(COMPATIBILITY_EPOCH)
        .fetch_one(&fixture.state.db)
        .await
        .unwrap();
        assert_eq!(retry_state.0, 0);
        assert!(retry_state.1.is_some());

        // Once due, the exact same desired identity is retried automatically.
        // This request reaches the now-closed fixture origin and proves the
        // integrity failure did not create a terminal/manual-recovery hold.
        sqlx::query(
            "UPDATE workstation_netboot_reconcile_attempts SET next_attempt_at = 0
             WHERE compatibility_epoch = ? AND reconcile_generation = 2",
        )
        .bind(COMPATIBILITY_EPOCH)
        .execute(&fixture.state.db)
        .await
        .unwrap();
        let retry_error = reconcile_desired(
            &fixture.state,
            &DesiredWorkstationNetboot {
                compatibility_epoch: COMPATIBILITY_EPOCH,
                descriptor: candidate,
                reconcile_generation: 2,
            },
        )
        .await
        .unwrap_err();
        assert_eq!(safe_failure_kind(&retry_error), FAILURE_NETWORK_OR_SERVER);
        fixture
            .assert_failed_candidate_did_not_interrupt_boot(&active)
            .await;
        fixture.cleanup();
    }

    #[tokio::test]
    async fn invalid_candidate_hold_is_separate_from_trusted_runtime_state() {
        let fixture = RuntimeFilesystemFixture::new().await;
        let active = fixture.install_bundle("1.0.0", &"a".repeat(64)).await;
        fixture.activate(&active, None).await;
        let mut invalid = fixture.signed_download_descriptor(
            "2.0.0",
            &"c".repeat(64),
            1,
            "http://127.0.0.1:9".to_string(),
        );
        invalid.schema = "unsupported-development-runtime".to_string();

        let attempt = |generation| DesiredWorkstationNetboot {
            compatibility_epoch: COMPATIBILITY_EPOCH,
            descriptor: invalid.clone(),
            reconcile_generation: generation,
        };
        let error = reconcile_desired(&fixture.state, &attempt(2))
            .await
            .unwrap_err();
        assert_eq!(safe_failure_kind(&error), FAILURE_INVALID_DESCRIPTOR);
        let ledger: (i64, String) = sqlx::query_as(
            "SELECT terminal_hold, failure_kind
             FROM workstation_netboot_reconcile_attempts
             WHERE compatibility_epoch = ? AND reconcile_generation = 2",
        )
        .bind(COMPATIBILITY_EPOCH)
        .fetch_one(&fixture.state.db)
        .await
        .unwrap();
        assert_eq!(ledger, (1, FAILURE_INVALID_DESCRIPTOR.to_string()));

        // Poll replay is held without relabelling the authenticated active row.
        reconcile_desired(&fixture.state, &attempt(2))
            .await
            .unwrap();
        let report = report(&fixture.state).await.unwrap();
        assert_eq!(report.state, "ready");
        assert_eq!(report.active_bundle_sha256, active.sha256);
        assert_eq!(report.reconcile_generation, Some(1));

        // Explicit reconciliation advances generation and releases the hold.
        let retry = reconcile_desired(&fixture.state, &attempt(3))
            .await
            .unwrap_err();
        assert_eq!(safe_failure_kind(&retry), FAILURE_INVALID_DESCRIPTOR);
        fixture.cleanup();
    }

    #[tokio::test]
    async fn downloader_follows_a_bounded_redirect_and_preserves_resume_range() {
        let fixture = RuntimeFilesystemFixture::new().await;
        let body = b"signed-runtime-body".to_vec();
        let offset = 6_u64;

        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target_listener.local_addr().unwrap();
        let target_body = body.clone();
        let target = tokio::spawn(async move {
            let (mut stream, _) = target_listener.accept().await.unwrap();
            let mut request = vec![0_u8; 4096];
            let read = stream.read(&mut request).await.unwrap();
            let request = String::from_utf8_lossy(&request[..read]).to_ascii_lowercase();
            assert!(request.contains(&format!("range: bytes={offset}-")));
            let remaining = &target_body[offset as usize..];
            let response = format!(
                "HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nContent-Range: bytes {offset}-{}/{}\r\nConnection: close\r\n\r\n",
                remaining.len(),
                target_body.len() - 1,
                target_body.len(),
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            stream.write_all(remaining).await.unwrap();
        });

        let redirect_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let redirect_address = redirect_listener.local_addr().unwrap();
        let redirect = tokio::spawn(async move {
            let (mut stream, _) = redirect_listener.accept().await.unwrap();
            let mut request = vec![0_u8; 4096];
            let read = stream.read(&mut request).await.unwrap();
            assert!(
                String::from_utf8_lossy(&request[..read])
                    .to_ascii_lowercase()
                    .contains(&format!("range: bytes={offset}-"))
            );
            let response = format!(
                "HTTP/1.1 302 Found\r\nLocation: http://{target_address}/asset\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });

        let mut descriptor = fixture.signed_download_descriptor(
            "2.0.0",
            &sha256_bytes(&body),
            body.len() as u64,
            format!("http://{redirect_address}"),
        );
        descriptor.sha256 = sha256_bytes(&body);
        fixture.sign_descriptor(&mut descriptor);
        let part = fixture.root.join("redirect-resume.part");
        fs::write(&part, &body[..offset as usize]).unwrap();
        fs::set_permissions(&part, fs::Permissions::from_mode(0o600)).unwrap();

        download_bundle(&fixture.state, &descriptor, &part)
            .await
            .unwrap();
        assert_eq!(fs::read(&part).unwrap(), body);
        await_one_shot_server(redirect).await;
        await_one_shot_server(target).await;
        fixture.cleanup();
    }

    #[tokio::test]
    async fn downloader_restarts_when_a_server_ignores_resume_range() {
        let fixture = RuntimeFilesystemFixture::new().await;
        let body = b"complete-signed-runtime".to_vec();
        let (base_url, server) = one_shot_http_response("200 OK", body.clone()).await;
        let mut descriptor = fixture.signed_download_descriptor(
            "2.0.0",
            &sha256_bytes(&body),
            body.len() as u64,
            base_url,
        );
        descriptor.sha256 = sha256_bytes(&body);
        fixture.sign_descriptor(&mut descriptor);
        let part = fixture.root.join("restart-resume.part");
        fs::write(&part, &body[..5]).unwrap();
        fs::set_permissions(&part, fs::Permissions::from_mode(0o600)).unwrap();

        download_bundle(&fixture.state, &descriptor, &part)
            .await
            .unwrap();
        assert_eq!(fs::read(&part).unwrap(), body);
        await_one_shot_server(server).await;
        fixture.cleanup();
    }

    #[tokio::test]
    async fn runtime_download_does_not_block_build_boot_cache_or_report_lanes() {
        use std::sync::Arc;
        use tokio::sync::Notify;

        let fixture = RuntimeFilesystemFixture::new().await;
        let body = vec![0x5a; 128 * 1024];
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let first_chunk_sent = Arc::new(Notify::new());
        let finish_response = Arc::new(Notify::new());
        let server_body = body.clone();
        let server_first_chunk_sent = first_chunk_sent.clone();
        let server_finish_response = finish_response.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0_u8; 4096];
            let _ = stream.read(&mut request).await.unwrap();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                server_body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            stream.write_all(&server_body[..4096]).await.unwrap();
            stream.flush().await.unwrap();
            server_first_chunk_sent.notify_one();
            server_finish_response.notified().await;
            stream.write_all(&server_body[4096..]).await.unwrap();
        });
        let mut descriptor = fixture.signed_download_descriptor(
            "2.0.0",
            &sha256_bytes(&body),
            body.len() as u64,
            format!("http://{address}"),
        );
        descriptor.sha256 = sha256_bytes(&body);
        fixture.sign_descriptor(&mut descriptor);
        let part = fixture.root.join("concurrent-download.part");
        let download_state = fixture.state.clone();
        let download_part = part.clone();
        let download = tokio::spawn(async move {
            download_bundle(&download_state, &descriptor, &download_part).await
        });

        first_chunk_sent.notified().await;
        tokio::time::timeout(Duration::from_secs(2), async {
            crate::db::record_rejected_managed_build_job(
                &fixture.state.db,
                "11111111-1111-4111-8111-111111111111",
                "nixos_closure",
                Some("blueprint"),
                Some("x86_64-linux"),
                "runtime-contention-probe",
                &"a".repeat(64),
                "deterministic contention probe",
            )
            .await
            .unwrap();
            crate::db::insert_boot_event(
                &fixture.state.db,
                crate::models::NewBootEvent {
                    device_id: None,
                    mac: Some("02:ca:fe:00:04:02".to_string()),
                    serial_number: None,
                    ip_address: Some("192.0.2.30".to_string()),
                    user_agent: Some("contention-probe".to_string()),
                    selected_profile_id: None,
                    selected_profile_name: None,
                    known_device: false,
                },
            )
            .await
            .unwrap();
            let protections = (1..=64_u64)
                .map(|value| ("nixos_closure".to_string(), format!("{value:064x}")))
                .collect::<Vec<_>>();
            crate::db::replace_managed_cache_protections(&fixture.state.db, &protections, true)
                .await
                .unwrap();
            let reports = crate::db::list_build_jobs_report_page(
                &fixture.state.db,
                None,
                None,
                None,
                0,
                8,
                64 * 1024,
            )
            .await
            .unwrap();
            assert_eq!(reports.len(), 1);
        })
        .await
        .expect("a runtime network wait blocked another SQLite evidence lane");
        finish_response.notify_one();
        download.await.unwrap().unwrap();
        server.await.unwrap();
        assert_eq!(fs::read(&part).unwrap(), body);
        fixture.cleanup();
    }

    #[tokio::test]
    async fn corrupt_active_runtime_falls_back_with_the_fallback_runtime_version() {
        let fixture = RuntimeFilesystemFixture::new().await;
        let fallback = fixture.install_bundle("1.0.0", &"b".repeat(64)).await;
        let corrupt = fixture.install_bundle("2.0.0", &"a".repeat(64)).await;
        fixture.activate(&corrupt, Some(&fallback)).await;
        fs::write(fixture.bundle_root(&corrupt).join("bzImage"), b"corrupt").unwrap();

        scrub_due_bundles(&fixture.state).await.unwrap();

        let report = report(&fixture.state).await.unwrap();
        assert_eq!(report.state, "failed");
        assert_eq!(report.active_bundle_sha256, fallback.sha256);
        assert_eq!(report.runtime_version, fallback.runtime_version);
        assert_eq!(report.failure_kind, FAILURE_INTEGRITY_MISMATCH);
        assert!(report.warning_kind.is_none());
        let launch = create_boot_session(&fixture.state, "02:00:00:00:00:01", None, None, None)
            .await
            .unwrap();
        assert_eq!(launch.bundle_sha256, fallback.sha256);
        fixture.cleanup();
    }

    #[tokio::test]
    async fn verified_stage_replaces_a_corrupt_preexisting_publish_tree() {
        let fixture = RuntimeFilesystemFixture::new().await;
        let descriptor = fixture.install_bundle("1.0.0", &"a".repeat(64)).await;
        let final_root = fixture.bundle_root(&descriptor);
        let stage = fixture.root.join("verified-stage");
        fs::create_dir(&stage).unwrap();
        for name in ["manifest.json", "bzImage", "initrd", "nix-store.squashfs"] {
            fs::copy(final_root.join(name), stage.join(name)).unwrap();
            fs::set_permissions(stage.join(name), fs::Permissions::from_mode(0o644)).unwrap();
        }
        verify_extracted_tree(&stage, &descriptor).unwrap();
        fs::write(final_root.join("bzImage"), b"corrupt").unwrap();

        let public_root = final_root.parent().unwrap();
        publish_verified_stage(&stage, &final_root, public_root, &descriptor).unwrap();
        verify_extracted_tree(&final_root, &descriptor).unwrap();
        assert!(!stage.exists());
        let quarantine_root = public_root.parent().unwrap().join("netboot-quarantine");
        assert_eq!(fs::read_dir(quarantine_root).unwrap().count(), 1);
        fixture.cleanup();
    }

    #[tokio::test]
    async fn completed_old_import_cannot_promote_after_a_newer_identity_is_admitted() {
        let fixture = RuntimeFilesystemFixture::new().await;
        let old = fixture.install_bundle("1.0.0", &"a".repeat(64)).await;
        let newer = fixture.install_bundle("2.0.0", &"b".repeat(64)).await;
        let old_json = serde_json::to_string(&old).unwrap();
        let old_identity = sha256_bytes(old_json.as_bytes());
        let newer_json = serde_json::to_string(&newer).unwrap();
        let newer_identity = sha256_bytes(newer_json.as_bytes());
        accept_reconcile_generation(&fixture.state, COMPATIBILITY_EPOCH, 1, &old_identity)
            .await
            .unwrap();
        accept_reconcile_generation(&fixture.state, COMPATIBILITY_EPOCH, 2, &newer_identity)
            .await
            .unwrap();

        let error = promote_existing(
            &fixture.state,
            &old,
            &old_json,
            &old_identity,
            COMPATIBILITY_EPOCH,
            1,
        )
        .await
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("lost its accepted reconcile identity")
        );
        let active: (String,) = sqlx::query_as(
            "SELECT active_bundle_sha256 FROM workstation_netboot_runtime WHERE singleton_id = 1",
        )
        .fetch_one(&fixture.state.db)
        .await
        .unwrap();
        assert!(active.0.is_empty());

        promote_existing(
            &fixture.state,
            &newer,
            &newer_json,
            &newer_identity,
            COMPATIBILITY_EPOCH,
            2,
        )
        .await
        .unwrap();
        let report = report(&fixture.state).await.unwrap();
        assert_eq!(report.active_bundle_sha256, newer.sha256);
        assert_eq!(report.reconcile_generation, Some(2));
        fixture.cleanup();
    }

    #[tokio::test]
    async fn identical_bundle_hash_is_never_relabelled_across_epochs() {
        let fixture = RuntimeFilesystemFixture::new().await;
        let descriptor = fixture.install_bundle("1.0.0", &"a".repeat(64)).await;
        let other_epoch = if COMPATIBILITY_EPOCH == 1 { 2 } else { 1 };
        sqlx::query(
            "UPDATE workstation_netboot_bundles SET compatibility_epoch = ?
             WHERE bundle_sha256 = ?",
        )
        .bind(other_epoch)
        .bind(&descriptor.sha256)
        .execute(&fixture.state.db)
        .await
        .unwrap();

        fixture.activate(&descriptor, None).await;
        assert!(
            create_boot_session(&fixture.state, "02:00:00:00:00:01", None, None, None)
                .await
                .unwrap_err()
                .to_string()
                .contains("no verified active bundle")
        );
        let report = report(&fixture.state).await.unwrap();
        assert_eq!(report.state, "failed");
        assert!(report.active_bundle_sha256.is_empty());
        assert_eq!(report.failure_kind, FAILURE_COMPATIBILITY_EPOCH_UNSUPPORTED);

        let error = import_bundle(&fixture.state, &descriptor, COMPATIBILITY_EPOCH)
            .await
            .unwrap_err();
        assert_eq!(safe_failure_kind(&error), FAILURE_INVALID_DESCRIPTOR);
        assert!(error.to_string().contains("another compatibility epoch"));
        fixture.cleanup();
    }

    #[tokio::test]
    async fn active_integrity_fallback_reports_degraded_with_a_bootable_lkg() {
        let state = runtime_test_state().await;
        let quarantined = "a".repeat(64);
        let fallback = "b".repeat(64);
        sqlx::query(
            "UPDATE workstation_netboot_runtime
             SET state = 'ready', active_bundle_sha256 = ?, previous_bundle_sha256 = ?
             WHERE singleton_id = 1",
        )
        .bind(quarantined)
        .bind(&fallback)
        .execute(&state.db)
        .await
        .unwrap();

        update_runtime_after_active_quarantine(&state, Some(fallback.clone()), &now())
            .await
            .unwrap();

        let row: (String, String, String, String) = sqlx::query_as(
            "SELECT state, active_bundle_sha256, previous_bundle_sha256, failure_kind
             FROM workstation_netboot_runtime WHERE singleton_id = 1",
        )
        .fetch_one(&state.db)
        .await
        .unwrap();
        assert_eq!(row.0, "failed");
        assert_eq!(row.1, fallback);
        assert!(row.2.is_empty());
        assert_eq!(row.3, FAILURE_INTEGRITY_MISMATCH);
        assert_eq!(normalize_failure_kind(&row.3), FAILURE_INTEGRITY_MISMATCH);
        let report = report(&state).await.unwrap();
        assert_eq!(report.state, "failed");
        assert_eq!(report.failure_kind, FAILURE_INTEGRITY_MISMATCH);
        assert!(!report.failure_message.is_empty());
        assert!(report.warning_kind.is_none());
    }

    #[tokio::test]
    async fn previous_bundle_quarantine_keeps_the_active_runtime_ready_with_a_warning() {
        let fixture = RuntimeFilesystemFixture::new().await;
        let active = fixture.install_bundle("2.0.0", &"a".repeat(64)).await;
        let previous = fixture.install_bundle("1.0.0", &"b".repeat(64)).await;
        fixture.activate(&active, Some(&previous)).await;

        update_runtime_after_previous_quarantine(&fixture.state, &now())
            .await
            .unwrap();

        let row: (String, String, String, String) = sqlx::query_as(
            "SELECT state, active_bundle_sha256, previous_bundle_sha256, failure_kind
             FROM workstation_netboot_runtime WHERE singleton_id = 1",
        )
        .fetch_one(&fixture.state.db)
        .await
        .unwrap();
        assert_eq!(row.0, "ready");
        assert_eq!(row.1, active.sha256);
        assert!(row.2.is_empty());
        assert_eq!(row.3, FAILURE_INTEGRITY_MISMATCH);
        assert_eq!(normalize_failure_kind(&row.3), FAILURE_INTEGRITY_MISMATCH);
        let report = report(&fixture.state).await.unwrap();
        assert_eq!(report.state, "ready");
        assert!(report.failure_kind.is_empty());
        assert_eq!(
            report.warning_kind.as_deref(),
            Some(FAILURE_INTEGRITY_MISMATCH)
        );
        fixture.cleanup();
    }

    #[test]
    fn public_address_policy_rejects_special_networks() {
        for value in [
            "127.0.0.1",
            "10.0.0.1",
            "100.64.0.1",
            "169.254.169.254",
            "192.0.0.1",
            "192.0.2.1",
            "198.18.0.1",
            "::1",
            "fc00::1",
            "fe80::1",
            "2001:db8::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(
                !release_transport::public_ip(value.parse().unwrap()),
                "{value}"
            );
        }
        assert!(release_transport::public_ip("8.8.8.8".parse().unwrap()));
        assert!(release_transport::public_ip(
            "2606:4700:4700::1111".parse().unwrap()
        ));
    }

    #[test]
    fn watermark_rejects_downgrade_and_changed_equal_version() {
        enforce_watermark_precedence("1.2.3", &"a".repeat(64), "1.2.2", &"a".repeat(64))
            .unwrap_err();
        enforce_watermark_precedence("1.2.3", &"a".repeat(64), "1.2.3", &"b".repeat(64))
            .unwrap_err();
        enforce_watermark_precedence("1.2.3", &"a".repeat(64), "1.2.3", &"a".repeat(64)).unwrap();
        enforce_watermark_precedence("1.2.3", &"a".repeat(64), "1.3.0", &"b".repeat(64)).unwrap();
    }

    #[tokio::test]
    async fn reconcile_generation_watermark_is_monotonic_per_epoch() {
        let state = runtime_test_state().await;
        accept_reconcile_generation(&state, 1, 5, &"a".repeat(64))
            .await
            .unwrap();
        assert!(
            accept_reconcile_generation(&state, 1, 4, &"a".repeat(64))
                .await
                .unwrap_err()
                .to_string()
                .contains("stale reconcile generation")
        );
        assert!(
            accept_reconcile_generation(&state, 1, 5, &"b".repeat(64))
                .await
                .unwrap_err()
                .to_string()
                .contains("descriptor changed")
        );
        accept_reconcile_generation(&state, 1, 6, &"b".repeat(64))
            .await
            .unwrap();
        // A distinct compatibility epoch has an independent generation line.
        accept_reconcile_generation(&state, 2, 1, &"c".repeat(64))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn artifact_watermarks_remain_independent_across_epoch_round_trips() {
        let fixture = RuntimeFilesystemFixture::new().await;
        let active = fixture.install_bundle("3.0.0", &"a".repeat(64)).await;
        fixture.activate(&active, None).await;
        let key_fingerprint = sha256_bytes(&fixture.signing_key.verifying_key().to_bytes());
        let other_epoch = if COMPATIBILITY_EPOCH == 1 { 2 } else { 1 };
        sqlx::query(
            "INSERT INTO workstation_netboot_watermarks
             (compatibility_epoch, key_fingerprint, architecture, runtime_version,
              descriptor_sha256, accepted_at) VALUES (?, ?, ?, '9.0.0', ?, ?)",
        )
        .bind(other_epoch)
        .bind(&key_fingerprint)
        .bind(ARCHITECTURE)
        .bind("f".repeat(64))
        .bind(now())
        .execute(&fixture.state.db)
        .await
        .unwrap();

        let mut candidate = fixture_descriptor();
        candidate.runtime_version = "2.0.0".to_string();
        let candidate_sha = sha256_bytes(serde_json::to_string(&candidate).unwrap().as_bytes());
        assert!(
            enforce_watermark(
                &fixture.state,
                &candidate,
                &candidate_sha,
                COMPATIBILITY_EPOCH,
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("downgrade")
        );
        let rows: Vec<(i64, String)> = sqlx::query_as(
            "SELECT compatibility_epoch, runtime_version
             FROM workstation_netboot_watermarks ORDER BY compatibility_epoch",
        )
        .fetch_all(&fixture.state.db)
        .await
        .unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().any(|row| row.1 == "3.0.0"));
        assert!(rows.iter().any(|row| row.1 == "9.0.0"));
        fixture.cleanup();
    }

    #[tokio::test]
    async fn generation_and_artifact_watermarks_are_admitted_atomically() {
        let fixture = RuntimeFilesystemFixture::new().await;
        let active = fixture.install_bundle("3.0.0", &"a".repeat(64)).await;
        fixture.activate(&active, None).await;

        let rollback = fixture.signed_download_descriptor(
            "2.0.0",
            &"b".repeat(64),
            1,
            "http://127.0.0.1:9".to_string(),
        );
        let rollback_error = reconcile_desired(
            &fixture.state,
            &DesiredWorkstationNetboot {
                compatibility_epoch: COMPATIBILITY_EPOCH,
                descriptor: rollback,
                reconcile_generation: 2,
            },
        )
        .await
        .unwrap_err();
        assert_eq!(
            safe_failure_kind(&rollback_error),
            FAILURE_INVALID_DESCRIPTOR
        );
        let generation_after_rollback: (i64,) = sqlx::query_as(
            "SELECT reconcile_generation FROM workstation_netboot_reconcile_watermarks
             WHERE compatibility_epoch = ?",
        )
        .bind(COMPATIBILITY_EPOCH)
        .fetch_one(&fixture.state.db)
        .await
        .unwrap();
        assert_eq!(generation_after_rollback.0, 1);

        // The rejected candidate did not consume generation two, so a
        // corrected descriptor at that same generation can converge.
        let corrected = fixture.install_bundle("4.0.0", &"c".repeat(64)).await;
        reconcile_desired(
            &fixture.state,
            &DesiredWorkstationNetboot {
                compatibility_epoch: COMPATIBILITY_EPOCH,
                descriptor: corrected.clone(),
                reconcile_generation: 2,
            },
        )
        .await
        .unwrap();
        let report = report(&fixture.state).await.unwrap();
        assert_eq!(report.state, "ready");
        assert_eq!(report.active_bundle_sha256, corrected.sha256);

        let stale_newer = fixture.install_bundle("5.0.0", &"d".repeat(64)).await;
        let stale_error = reconcile_desired(
            &fixture.state,
            &DesiredWorkstationNetboot {
                compatibility_epoch: COMPATIBILITY_EPOCH,
                descriptor: stale_newer,
                reconcile_generation: 1,
            },
        )
        .await
        .unwrap_err();
        assert!(
            stale_error
                .to_string()
                .contains("stale reconcile generation")
        );
        let artifact_after_stale: (String,) = sqlx::query_as(
            "SELECT runtime_version FROM workstation_netboot_watermarks
             WHERE compatibility_epoch = ?",
        )
        .bind(COMPATIBILITY_EPOCH)
        .fetch_one(&fixture.state.db)
        .await
        .unwrap();
        assert_eq!(artifact_after_stale.0, "4.0.0");
        fixture.cleanup();
    }

    #[test]
    fn manifest_accepts_the_single_squashfs_url_placeholder() {
        let descriptor = fixture_descriptor();
        let manifest = fixture_manifest(&descriptor);
        validate_manifest(&manifest, &descriptor).unwrap();
    }

    #[test]
    fn manifest_rejects_other_cmdline_placeholders() {
        let descriptor = fixture_descriptor();
        let mut manifest = fixture_manifest(&descriptor);
        manifest.kernel_cmdline_template.push_str(" {unexpected}");
        validate_manifest(&manifest, &descriptor).unwrap_err();
    }

    struct RuntimeFilesystemFixture {
        state: AppState,
        root: PathBuf,
        signing_key: SigningKey,
    }

    impl RuntimeFilesystemFixture {
        async fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "cybex-james-netboot-runtime-test-{}",
                uuid::Uuid::new_v4().simple()
            ));
            fs::create_dir_all(&root).unwrap();
            let signing_key = SigningKey::from_bytes(&[23_u8; 32]);
            let mut config = crate::config::AppConfig::default();
            config.server.public_base_url = "http://james.test".to_string();
            config.paths.data_dir = root.join("data");
            config.paths.database_path = root.join("cybex-james.sqlite");
            config.paths.boot_assets_dir = root.join("www");
            config.paths.static_dir = root.join("static");
            config.paths.tftp_dir = root.join("tftp");
            config.manage.api_url = "http://manage.test".to_string();
            config.manage.organization_id = "550e8400-e29b-41d4-a716-446655440000".to_string();
            config.manage.organization_slug = "test-org".to_string();
            config.manage.state_path = root.join("manage-state.json");
            config.workstation_netboot.allow_private_release_urls = true;
            let manage_revision = "a".repeat(40);
            let manage_source_dir = root.join("manage-source");
            fs::create_dir(&manage_source_dir).unwrap();
            fs::set_permissions(&manage_source_dir, fs::Permissions::from_mode(0o755)).unwrap();
            let manage_archive_body = b"deterministic Manage source fixture";
            let manage_archive = manage_source_dir.join(format!("{manage_revision}.tar"));
            fs::write(&manage_archive, manage_archive_body).unwrap();
            fs::set_permissions(&manage_archive, fs::Permissions::from_mode(0o444)).unwrap();
            let manage_metadata = format!(
                "{{\"filename\":\"{manage_revision}.tar\",\"revision\":\"{manage_revision}\",\"schema\":\"cybex.james.manage-source.v1\",\"sha256\":\"{}\",\"size_bytes\":{}}}\n",
                sha256_bytes(manage_archive_body),
                manage_archive_body.len()
            );
            let manage_metadata_path = manage_source_dir.join(format!("{manage_revision}.json"));
            fs::write(&manage_metadata_path, manage_metadata).unwrap();
            fs::set_permissions(&manage_metadata_path, fs::Permissions::from_mode(0o444)).unwrap();
            config.build.manage_source_url_template = format!(
                "tarball+file://{}/{{revision}}.tar",
                manage_source_dir.display()
            );
            config.update.trusted_public_key =
                STANDARD.encode(signing_key.verifying_key().to_bytes());
            fs::write(
                &config.manage.state_path,
                serde_json::to_vec(&serde_json::json!({
                    "private_key_b64": STANDARD.encode(signing_key.to_bytes()),
                    "public_key_b64": STANDARD.encode(signing_key.verifying_key().to_bytes()),
                    "device_id": "james-runtime-test"
                }))
                .unwrap(),
            )
            .unwrap();
            let database_url = format!("sqlite://{}", config.paths.database_path.display());
            let pool = crate::db::connect_with_url(&database_url).await.unwrap();
            crate::db::migrate(&pool).await.unwrap();
            Self {
                state: AppState::new(config, pool),
                root,
                signing_key,
            }
        }

        fn bundle_root(&self, descriptor: &WorkstationNetbootDescriptor) -> PathBuf {
            self.state
                .config
                .paths
                .boot_assets_dir
                .join("netboot")
                .join(&descriptor.sha256)
        }

        async fn install_bundle(
            &self,
            runtime_version: &str,
            bundle_sha256: &str,
        ) -> WorkstationNetbootDescriptor {
            let component_bodies = [
                ("bzImage", b"fixture-kernel".as_slice()),
                ("initrd", b"fixture-initrd".as_slice()),
                ("nix-store.squashfs", b"fixture-store".as_slice()),
            ];
            let components = ComponentDescriptors {
                bz_image: component_descriptor(component_bodies[0].1),
                initrd: component_descriptor(component_bodies[1].1),
                nix_store_squashfs: component_descriptor(component_bodies[2].1),
            };
            let mut descriptor = WorkstationNetbootDescriptor {
                schema: DESCRIPTOR_SCHEMA.to_string(),
                runtime_version: runtime_version.to_string(),
                manage_source_revision: "a".repeat(40),
                nixpkgs_revision: "c".repeat(40),
                architecture: ARCHITECTURE.to_string(),
                format: FORMAT.to_string(),
                required_james_protocol: REQUIRED_JAMES_PROTOCOL,
                url: format!(
                    "http://127.0.0.1:9/cybex-workstation-netboot-{runtime_version}-aaaaaaaaaaaa-{ARCHITECTURE}.tar.zst"
                ),
                sha256: bundle_sha256.to_string(),
                size_bytes: 1,
                manifest_sha256: "0".repeat(64),
                components,
                signature: String::new(),
            };
            let manifest = fixture_manifest(&descriptor);
            let mut manifest_body =
                serde_json::to_vec(&serde_json::to_value(manifest).unwrap()).unwrap();
            manifest_body.push(b'\n');
            descriptor.manifest_sha256 = sha256_bytes(&manifest_body);
            self.sign_descriptor(&mut descriptor);

            let bundle_root = self.bundle_root(&descriptor);
            fs::create_dir_all(&bundle_root).unwrap();
            for (name, body) in component_bodies {
                let path = bundle_root.join(name);
                fs::write(&path, body).unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            }
            let manifest_path = bundle_root.join("manifest.json");
            fs::write(&manifest_path, manifest_body).unwrap();
            fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o644)).unwrap();

            let timestamp = now();
            sqlx::query(
                "INSERT INTO workstation_netboot_bundles
                 (bundle_sha256, compatibility_epoch, runtime_version, manage_source_revision, nixpkgs_revision,
                  architecture, manifest_sha256, descriptor_json, root_path, size_bytes,
                  retention_state, verified_at, created_at, updated_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'verified', ?, ?, ?)",
            )
            .bind(&descriptor.sha256)
            .bind(COMPATIBILITY_EPOCH)
            .bind(&descriptor.runtime_version)
            .bind(&descriptor.manage_source_revision)
            .bind(&descriptor.nixpkgs_revision)
            .bind(&descriptor.architecture)
            .bind(&descriptor.manifest_sha256)
            .bind(serde_json::to_string(&descriptor).unwrap())
            .bind(bundle_root.display().to_string())
            .bind(i64::try_from(descriptor.size_bytes).unwrap())
            .bind(&timestamp)
            .bind(&timestamp)
            .bind(&timestamp)
            .execute(&self.state.db)
            .await
            .unwrap();
            descriptor
        }

        async fn activate(
            &self,
            active: &WorkstationNetbootDescriptor,
            previous: Option<&WorkstationNetbootDescriptor>,
        ) {
            let descriptor_json = serde_json::to_string(active).unwrap();
            let descriptor_sha256 = sha256_bytes(descriptor_json.as_bytes());
            sqlx::query(
                "INSERT OR REPLACE INTO workstation_netboot_watermarks
                 (compatibility_epoch, key_fingerprint, architecture, runtime_version,
                  descriptor_sha256, accepted_at) VALUES (?, ?, ?, ?, ?, ?)",
            )
            .bind(COMPATIBILITY_EPOCH)
            .bind(sha256_bytes(&self.signing_key.verifying_key().to_bytes()))
            .bind(ARCHITECTURE)
            .bind(&active.runtime_version)
            .bind(&descriptor_sha256)
            .bind(now())
            .execute(&self.state.db)
            .await
            .unwrap();
            sqlx::query(
                "INSERT OR REPLACE INTO workstation_netboot_reconcile_watermarks
                 (compatibility_epoch, reconcile_generation, descriptor_sha256, updated_at)
                 VALUES (?, 1, ?, ?)",
            )
            .bind(COMPATIBILITY_EPOCH)
            .bind(&descriptor_sha256)
            .bind(now())
            .execute(&self.state.db)
            .await
            .unwrap();
            sqlx::query(
                "UPDATE workstation_netboot_runtime
                 SET desired_compatibility_epoch = ?, desired_descriptor_json = ?, desired_descriptor_sha256 = ?,
                     reconcile_generation = 1, state = 'ready', progress_percent = 100,
                     active_bundle_sha256 = ?, previous_bundle_sha256 = ?,
                     watermark_key_fingerprint = ?, watermark_architecture = ?,
                     watermark_runtime_version = ?, watermark_descriptor_sha256 = ?,
                     last_verified_at = ?, updated_at = ?
                 WHERE singleton_id = 1",
            )
            .bind(COMPATIBILITY_EPOCH)
            .bind(descriptor_json)
            .bind(&descriptor_sha256)
            .bind(&active.sha256)
            .bind(
                previous
                    .map(|descriptor| descriptor.sha256.as_str())
                    .unwrap_or_default(),
            )
            .bind(sha256_bytes(&self.signing_key.verifying_key().to_bytes()))
            .bind(ARCHITECTURE)
            .bind(&active.runtime_version)
            .bind(&descriptor_sha256)
            .bind(now())
            .bind(now())
            .execute(&self.state.db)
            .await
            .unwrap();
        }

        fn signed_download_descriptor(
            &self,
            runtime_version: &str,
            bundle_sha256: &str,
            size_bytes: u64,
            release_base_url: String,
        ) -> WorkstationNetbootDescriptor {
            let mut descriptor = fixture_descriptor();
            descriptor.runtime_version = runtime_version.to_string();
            descriptor.url = format!(
                "{release_base_url}/cybex-workstation-netboot-{runtime_version}-aaaaaaaaaaaa-{ARCHITECTURE}.tar.zst"
            );
            descriptor.sha256 = bundle_sha256.to_string();
            descriptor.size_bytes = size_bytes;
            self.sign_descriptor(&mut descriptor);
            descriptor
        }

        fn sign_descriptor(&self, descriptor: &mut WorkstationNetbootDescriptor) {
            descriptor.signature.clear();
            descriptor.signature = STANDARD.encode(
                self.signing_key
                    .sign(signature_message(descriptor).as_bytes())
                    .to_bytes(),
            );
        }

        async fn assert_failed_candidate_did_not_interrupt_boot(
            &self,
            active: &WorkstationNetbootDescriptor,
        ) {
            let report = report(&self.state).await.unwrap();
            assert_eq!(report.state, "failed");
            assert_eq!(report.active_bundle_sha256, active.sha256);
            assert_eq!(report.runtime_version, active.runtime_version);
            let launch = create_boot_session(&self.state, "02:00:00:00:00:01", None, None, None)
                .await
                .unwrap();
            assert_eq!(launch.bundle_sha256, active.sha256);
        }

        fn cleanup(self) {
            fs::remove_dir_all(self.root).unwrap();
        }
    }

    fn component_descriptor(body: &[u8]) -> ComponentDescriptor {
        ComponentDescriptor {
            sha256: sha256_bytes(body),
            size_bytes: body.len() as u64,
        }
    }

    async fn one_shot_http_response(
        status: &'static str,
        body: Vec<u8>,
    ) -> (String, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0_u8; 4096];
            let _ = stream.read(&mut request).await.unwrap();
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            stream.write_all(&body).await.unwrap();
        });
        (format!("http://{address}"), server)
    }

    async fn await_one_shot_server(server: JoinHandle<()>) {
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
    }

    fn fixture_manifest(descriptor: &WorkstationNetbootDescriptor) -> WorkstationNetbootManifest {
        WorkstationNetbootManifest {
            schema: MANIFEST_SCHEMA.to_string(),
            runtime_version: descriptor.runtime_version.clone(),
            architecture: descriptor.architecture.clone(),
            format: descriptor.format.clone(),
            required_james_protocol: descriptor.required_james_protocol,
            manage_source_revision: descriptor.manage_source_revision.clone(),
            nixpkgs_revision: descriptor.nixpkgs_revision.clone(),
            source_date_epoch: 1,
            toplevel: "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-system".to_string(),
            kernel_cmdline_template: "init=/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-system/init cybex.squashfs_url={squashfs_url}".to_string(),
            components: descriptor.components.clone(),
            provenance: BTreeMap::from([("agent".to_string(), "f".repeat(64))]),
        }
    }

    async fn runtime_test_state() -> AppState {
        let pool = crate::db::connect_with_url("sqlite::memory:")
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();
        AppState::new(crate::config::AppConfig::default(), pool)
    }

    fn fixture_descriptor() -> WorkstationNetbootDescriptor {
        let component = ComponentDescriptor {
            sha256: "b".repeat(64),
            size_bytes: 1,
        };
        WorkstationNetbootDescriptor {
            schema: DESCRIPTOR_SCHEMA.to_string(),
            runtime_version: "1.0.0".to_string(),
            manage_source_revision: "a".repeat(40),
            nixpkgs_revision: "c".repeat(40),
            architecture: ARCHITECTURE.to_string(),
            format: FORMAT.to_string(),
            required_james_protocol: REQUIRED_JAMES_PROTOCOL,
            url: "https://releases.example.test/cybex-workstation-netboot-1.0.0-aaaaaaaaaaaa-x86_64-linux.tar.zst".to_string(),
            sha256: "d".repeat(64),
            size_bytes: 4,
            manifest_sha256: "e".repeat(64),
            components: ComponentDescriptors {
                bz_image: component.clone(),
                initrd: component.clone(),
                nix_store_squashfs: component,
            },
            signature: String::new(),
        }
    }
}
