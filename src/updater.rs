#[cfg(unix)]
use std::os::{
    fd::AsRawFd,
    unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
};
use std::{
    cmp::Ordering,
    collections::HashSet,
    fs,
    future::Future,
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    pin::Pin,
    process::{Command, Output},
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::{SecondsFormat, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use reqwest::Url;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use tokio::{fs as tokio_fs, io::AsyncWriteExt, time::sleep};

use crate::{config::AppConfig, db};

const REQUEST_FILE: &str = "request.json";
const STATUS_FILE: &str = "status.json";
const LOCK_FILE: &str = "apply.lock";
const APPLY_STATE_FILE: &str = "apply-state.json";
const MEDIA_REBASE_EVENTS_DIR: &str = "media-rebase-events";
const RELEASE_SCHEMA: &str = "cybex.forge.update-request.v1";
const APPLY_LOCK_SCHEMA: &str = "cybex.forge.update-lock.v1";
const APPLY_STATE_SCHEMA: &str = "cybex.forge.apply-state.v1";
const MEDIA_REBASE_SCHEMA: &str = "cybex.forge.media-rebase.v1";
const MEDIA_REBASE_TRANSACTION_FILE: &str = "media-rebase-transaction.json";
const BINARY_RECOVERY_SCHEMA: &str = "cybex.forge.appliance.binary-recovery.v1";
const BINARY_RECOVERY_FILE: &str = "binary-recovery.json";
const INSTALL_ENROLLMENT_STAGE_FILE: &str = ".enrollment-code.staged";
const MAX_INSTALL_ENROLLMENT_STAGE_BYTES: u64 = 512;
const MAX_MEDIA_REBASE_EVENT_BYTES: u64 = 4 * 1024;
pub const MAX_MEDIA_REBASE_EVENTS_PER_REPORT: usize = 16;
pub const UPDATE_ONLY_PROJECTION_SCHEMA: &str = "cybex.forge.update-projection.v1";
const MAX_UPDATE_ONLY_PROJECTION_BYTES: u64 = 4 * 1024;

fn command_output_with_transient_exec_retry(command: &mut Command) -> io::Result<Output> {
    const MAX_ATTEMPTS: usize = 8;

    for attempt in 0..MAX_ATTEMPTS {
        match command.output() {
            Ok(output) => return Ok(output),
            Err(error)
                if error.raw_os_error() == Some(libc::ETXTBSY) && attempt + 1 < MAX_ATTEMPTS =>
            {
                // The update worker can copy a new executable while another
                // service thread forks. CLOEXEC closes that inherited writer
                // only at exec, so retry the resulting short ETXTBSY window.
                std::thread::sleep(Duration::from_millis(1_u64 << attempt.min(6)));
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("command output retry loop returns on its final attempt")
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ManagedUpdateRequest {
    pub version: String,
    pub artifact_url: String,
    pub sha256: String,
    #[serde(default)]
    pub signature: String,
    #[serde(default)]
    pub release_url: String,
    #[serde(default)]
    pub notes_url: String,
    pub requested_at: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MediaRebaseEvidence {
    pub schema: String,
    pub event_id: String,
    pub media_sequence: u64,
    pub mode: String,
    pub resulting_version: String,
    pub previous_request_attempt_id: Option<String>,
    pub previous_target_version: Option<String>,
    pub previous_status: Option<String>,
    pub created_at: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct StoredUpdateRequest {
    schema: String,
    request: ManagedUpdateRequest,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ForgeUpdateStatusReport {
    pub status: String,
    pub stage: String,
    pub progress_percent: Option<i32>,
    pub error: String,
    pub target_version: String,
    pub current_version: String,
    pub attempt_id: String,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateOnlyStatusProjection {
    schema: String,
    status: String,
    attempt_id: String,
    current_version: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct UpdateLockOwner {
    schema: String,
    pid: u32,
    process_start_ticks: u64,
    boot_id: String,
    state: String,
    acquired_at: String,
    released_at: Option<String>,
}

struct UpdateLock {
    file: fs::File,
    owner: UpdateLockOwner,
}

impl Drop for UpdateLock {
    fn drop(&mut self) {
        self.owner.state = "released".to_string();
        self.owner.released_at = Some(now_rfc3339());
        let _ = write_lock_owner(&mut self.file, &self.owner);
        #[cfg(unix)]
        let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ApplyState {
    schema: String,
    attempt_id: String,
    target_version: String,
    backup_filename: String,
    phase: String,
    started_at: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BinaryRecoveryJournal {
    schema: String,
    embedded_version: String,
    reason: String,
}

trait UpdateRuntime {
    fn restart_service(&self, config: &AppConfig) -> Result<()>;

    fn wait_for_health<'a>(
        &'a self,
        config: &'a AppConfig,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;
}

struct SystemUpdateRuntime;

impl UpdateRuntime for SystemUpdateRuntime {
    fn restart_service(&self, config: &AppConfig) -> Result<()> {
        restart_service(config)
    }

    fn wait_for_health<'a>(
        &'a self,
        config: &'a AppConfig,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(wait_for_health(config))
    }
}

pub fn capabilities_enabled(config: &AppConfig) -> bool {
    config.update.enabled && parse_trusted_public_key(&config.update.trusted_public_key).is_ok()
}

pub async fn store_update_request(
    config: &AppConfig,
    request: Option<ManagedUpdateRequest>,
) -> Result<()> {
    if !config.update.enabled {
        return Ok(());
    }
    let Some(request) = request else {
        return Ok(());
    };
    validate_request(&request)?;
    ensure_update_work_dir(config)?;

    let existing = read_status(config).ok().flatten();
    let same_target = existing
        .as_ref()
        .is_some_and(|status| status.target_version == request.version);
    let same_attempt = existing
        .as_ref()
        .is_some_and(|status| status.attempt_id == request_attempt_id(&request));
    let active = existing
        .as_ref()
        .is_some_and(|status| update_status_is_active(&status.status));

    write_json_atomic(
        &request_path(config),
        &StoredUpdateRequest {
            schema: RELEASE_SCHEMA.to_string(),
            request: request.clone(),
        },
    )?;

    if same_target && (active || same_attempt) {
        return Ok(());
    }

    if validate_update_target_version(&request.version).is_err() {
        write_version_policy_status(config, &request)?;
        return Ok(());
    }

    write_status(
        config,
        ForgeUpdateStatusReport {
            status: "requested".to_string(),
            stage: "queued".to_string(),
            progress_percent: Some(0),
            error: String::new(),
            target_version: request.version.clone(),
            current_version: env!("CARGO_PKG_VERSION").to_string(),
            attempt_id: request_attempt_id(&request),
            started_at: None,
            completed_at: None,
        },
    )?;
    Ok(())
}

pub async fn status_report(config: &AppConfig) -> Result<Option<ForgeUpdateStatusReport>> {
    if !config.update.enabled {
        return Ok(None);
    }
    if let Some(status) = read_status(config)? {
        return Ok(Some(status));
    }
    Ok(Some(ForgeUpdateStatusReport {
        status: "idle".to_string(),
        stage: "idle".to_string(),
        progress_percent: None,
        error: String::new(),
        target_version: String::new(),
        current_version: env!("CARGO_PKG_VERSION").to_string(),
        attempt_id: String::new(),
        started_at: None,
        completed_at: None,
    }))
}

/// Return only a durable updater status written by the updater itself.
///
/// Unlike [`status_report`], this never synthesizes an idle projection using
/// the version of the currently executing control binary.
pub fn stored_status_report(config: &AppConfig) -> Result<Option<ForgeUpdateStatusReport>> {
    if !config.update.enabled {
        return Ok(None);
    }
    read_status(config)
}

pub fn media_rebase_events(config: &AppConfig) -> Result<Vec<MediaRebaseEvidence>> {
    let directory = media_rebase_events_path(config);
    let directory_metadata = match fs::symlink_metadata(&directory) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err).with_context(|| format!("inspect {}", directory.display())),
    };
    if !directory_metadata.file_type().is_dir() {
        bail!("Forge media-rebase event queue is not a directory");
    }
    #[cfg(unix)]
    if directory_metadata.uid() != unsafe { libc::geteuid() }
        || directory_metadata.mode() & 0o777 != 0o700
    {
        bail!("Forge media-rebase event queue has unsafe ownership or permissions");
    }

    let mut events = Vec::new();
    for entry in
        fs::read_dir(&directory).with_context(|| format!("read {}", directory.display()))?
    {
        let entry = entry.with_context(|| format!("read entry in {}", directory.display()))?;
        let filename = entry.file_name();
        let filename = filename
            .to_str()
            .ok_or_else(|| anyhow!("Forge media-rebase event filename is not UTF-8"))?;
        if filename.starts_with(".media-rebase.") {
            continue;
        }
        let event_id_from_name = filename
            .strip_suffix(".json")
            .ok_or_else(|| anyhow!("Forge media-rebase event filename is invalid"))?;
        let path = entry.path();
        let metadata =
            fs::symlink_metadata(&path).with_context(|| format!("inspect {}", path.display()))?;
        if !metadata.file_type().is_file() || metadata.len() > MAX_MEDIA_REBASE_EVENT_BYTES {
            bail!("Forge media-rebase event is not a bounded regular file");
        }
        #[cfg(unix)]
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o777 != 0o600
            || metadata.nlink() != 1
        {
            bail!("Forge media-rebase event has unsafe ownership, permissions, or links");
        }
        let mut options = fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let file = options
            .open(&path)
            .with_context(|| format!("open {}", path.display()))?;
        let opened = file
            .metadata()
            .with_context(|| format!("reinspect {}", path.display()))?;
        #[cfg(unix)]
        if opened.dev() != metadata.dev()
            || opened.ino() != metadata.ino()
            || opened.uid() != unsafe { libc::geteuid() }
            || opened.mode() & 0o777 != 0o600
            || opened.nlink() != 1
        {
            bail!("Forge media-rebase event changed while opening");
        }
        let mut bytes = Vec::new();
        file.take(MAX_MEDIA_REBASE_EVENT_BYTES + 1)
            .read_to_end(&mut bytes)
            .with_context(|| format!("read {}", path.display()))?;
        if bytes.len() as u64 > MAX_MEDIA_REBASE_EVENT_BYTES {
            bail!("Forge media-rebase event exceeds its size limit");
        }
        let event: MediaRebaseEvidence =
            serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))?;
        validate_media_rebase_event(&event)?;
        if event.event_id != event_id_from_name {
            bail!("Forge media-rebase event filename does not match its event ID");
        }
        events.push(event);
    }
    events.sort_by(|left, right| {
        left.media_sequence
            .cmp(&right.media_sequence)
            .then_with(|| left.event_id.cmp(&right.event_id))
    });
    let mut distinct = HashSet::new();
    if events
        .iter()
        .any(|event| !distinct.insert(event.event_id.as_str()))
    {
        bail!("Forge media-rebase event IDs are not distinct");
    }
    if events
        .windows(2)
        .any(|pair| pair[0].media_sequence == pair[1].media_sequence)
    {
        bail!("Forge media-rebase event sequences are not distinct");
    }
    events.truncate(MAX_MEDIA_REBASE_EVENTS_PER_REPORT);
    Ok(events)
}

pub fn acknowledge_media_rebase_events(
    config: &AppConfig,
    reported: &[MediaRebaseEvidence],
    acknowledged_event_ids: &[String],
) -> Result<()> {
    if acknowledged_event_ids.len() > reported.len() {
        bail!("Manage acknowledged more media-rebase events than Forge reported");
    }
    let reported_ids = reported
        .iter()
        .map(|event| event.event_id.as_str())
        .collect::<HashSet<_>>();
    let mut acknowledged = HashSet::new();
    for event_id in acknowledged_event_ids {
        validate_media_rebase_event_id(event_id)?;
        if !acknowledged.insert(event_id.as_str()) || !reported_ids.contains(event_id.as_str()) {
            bail!("Manage returned an invalid media-rebase acknowledgement");
        }
    }
    for event_id in acknowledged_event_ids {
        let path = media_rebase_events_path(config).join(format!("{event_id}.json"));
        remove_owned_regular_file_if_exists(&path)?;
        sync_parent_directory(&path)?;
    }
    Ok(())
}

/// Complete any appliance transaction which must be durable before Forge is
/// allowed to start. The NixOS boot-owned reconciliation unit invokes this
/// through the currently installed, governed Forge executable.
pub fn reconcile_appliance_recovery(config: &AppConfig) -> Result<()> {
    config
        .validate_appliance_config()
        .context("refusing appliance reconciliation with unsafe configuration")?;
    scrub_interrupted_install_enrollment_stage(config)?;
    // A media rebase deliberately supersedes every updater projection. Record
    // binary recovery first, then let the journaled rebase atomically replace
    // it with the required idle projection and durable media evidence.
    reconcile_binary_recovery(config)?;
    finalize_media_rebase_transaction(config)
}

/// Remove an interrupted installer staging file before the unprivileged Forge
/// service can start. Current media keeps one Forge-owned persistent copy and
/// atomically renames it from the bootstrap stage to the final path; legacy
/// pre-release media used a second root-owned appliance path. Both fixed paths
/// are rebound by inode before overwrite/unlink, and cleanup is replay-safe.
fn scrub_interrupted_install_enrollment_stage(config: &AppConfig) -> Result<()> {
    // Current media stages beside the final credential so publication is one
    // atomic rename with no second persistent copy. Also reconcile the legacy
    // root-owned appliance path used by pre-release media.
    for path in [
        config
            .paths
            .data_dir
            .join("bootstrap")
            .join(INSTALL_ENROLLMENT_STAGE_FILE),
        appliance_metadata_path(config).join(INSTALL_ENROLLMENT_STAGE_FILE),
    ] {
        scrub_interrupted_install_enrollment_stage_path(&path)?;
    }
    Ok(())
}

fn scrub_interrupted_install_enrollment_stage_path(path: &Path) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err).with_context(|| format!("inspect {}", path.display())),
    };
    if !metadata.file_type().is_file() || metadata.len() > MAX_INSTALL_ENROLLMENT_STAGE_BYTES {
        bail!("interrupted installer enrollment stage must be a bounded regular file");
    }
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("interrupted installer enrollment stage has no parent"))?;
    let parent_metadata =
        fs::symlink_metadata(parent).with_context(|| format!("inspect {}", parent.display()))?;
    if !parent_metadata.file_type().is_dir() {
        bail!("interrupted installer enrollment stage parent is not a directory");
    }
    #[cfg(unix)]
    if metadata.uid() != parent_metadata.uid()
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || parent_metadata.mode() & 0o777 != 0o700
    {
        bail!("interrupted installer enrollment stage parent has unsafe metadata");
    }

    let mut options = fs::OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = options
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    let opened = file
        .metadata()
        .with_context(|| format!("inspect open {}", path.display()))?;
    if !opened.file_type().is_file() || opened.len() > MAX_INSTALL_ENROLLMENT_STAGE_BYTES {
        bail!("interrupted installer enrollment stage changed while opening");
    }
    #[cfg(unix)]
    if opened.dev() != metadata.dev()
        || opened.ino() != metadata.ino()
        || opened.uid() != metadata.uid()
        || opened.mode() != metadata.mode()
        || opened.nlink() != 1
        || opened.len() != metadata.len()
    {
        bail!("interrupted installer enrollment stage changed while opening");
    }

    file.seek(SeekFrom::Start(0))
        .context("seek interrupted installer enrollment stage")?;
    let zeroes = vec![0_u8; opened.len() as usize];
    file.write_all(&zeroes)
        .context("overwrite interrupted installer enrollment stage")?;
    file.set_len(0)
        .context("truncate interrupted installer enrollment stage")?;
    file.sync_all()
        .context("sync interrupted installer enrollment stage")?;
    let erased = file
        .metadata()
        .context("reinspect interrupted installer enrollment stage")?;
    let named =
        fs::symlink_metadata(path).with_context(|| format!("reinspect {}", path.display()))?;
    #[cfg(unix)]
    if erased.dev() != opened.dev()
        || erased.ino() != opened.ino()
        || erased.nlink() != 1
        || named.dev() != erased.dev()
        || named.ino() != erased.ino()
        || !named.file_type().is_file()
    {
        bail!("refusing to unlink a replaced installer enrollment stage");
    }
    drop(file);
    fs::remove_file(path).with_context(|| format!("remove {}", path.display()))?;
    sync_parent_directory(path)
}

fn finalize_media_rebase_transaction(config: &AppConfig) -> Result<()> {
    let journal = appliance_metadata_path(config).join(MEDIA_REBASE_TRANSACTION_FILE);
    let Some(event) = read_protected_json_if_exists::<MediaRebaseEvidence>(
        &journal,
        MAX_MEDIA_REBASE_EVENT_BYTES,
        effective_uid(),
    )?
    else {
        return Ok(());
    };
    validate_media_rebase_event(&event).context("validate media-rebase transaction")?;

    let event_directory = media_rebase_events_path(config);
    let event_directory_metadata = fs::symlink_metadata(&event_directory)
        .with_context(|| format!("inspect {}", event_directory.display()))?;
    if !event_directory_metadata.file_type().is_dir() {
        bail!("Forge media-rebase transaction event queue is not a directory");
    }
    #[cfg(unix)]
    if event_directory_metadata.mode() & 0o777 != 0o700 {
        bail!("Forge media-rebase transaction event queue must have mode 0700");
    }

    // The journal already contains the complete event. Deleting any subset of
    // these exact files is therefore replayable after sudden power loss.
    for path in [
        request_path(config),
        status_path(config),
        apply_state_path(config),
        lock_path(config),
    ] {
        remove_rebase_control_path(&path)?;
    }

    publish_media_rebase_event_noreplace(config, &event, &event_directory_metadata)?;
    remove_rebase_control_path(&journal)?;
    Ok(())
}

fn reconcile_binary_recovery(config: &AppConfig) -> Result<()> {
    let journal = appliance_metadata_path(config).join(BINARY_RECOVERY_FILE);
    let Some(recovery) = read_protected_json_if_exists::<BinaryRecoveryJournal>(
        &journal,
        MAX_MEDIA_REBASE_EVENT_BYTES,
        effective_uid(),
    )?
    else {
        return Ok(());
    };
    if recovery.schema != BINARY_RECOVERY_SCHEMA || recovery.reason != "missing_or_nonexecutable" {
        bail!("Forge appliance binary-recovery journal is invalid");
    }
    parse_semantic_version(&recovery.embedded_version)
        .context("Forge appliance embedded recovery version is invalid")?;
    let actual_version =
        installed_binary_version(config).context("identify restored Forge appliance binary")?;
    if actual_version != recovery.embedded_version {
        bail!("restored Forge appliance binary does not match the journaled embedded version");
    }

    let existing = read_status(config)?;
    let (target_version, attempt_id, started_at) = existing
        .as_ref()
        .map(|status| {
            (
                status.target_version.clone(),
                status.attempt_id.clone(),
                status.started_at.clone(),
            )
        })
        .unwrap_or_default();
    write_status(
        config,
        ForgeUpdateStatusReport {
            status: if target_version.is_empty() {
                "failed".to_string()
            } else {
                "rolled_back".to_string()
            },
            stage: "appliance_binary_recovery".to_string(),
            progress_percent: Some(100),
            error: "appliance_binary_recovered: restored embedded baseline after the live binary was missing or non-executable".to_string(),
            target_version,
            current_version: actual_version,
            attempt_id,
            started_at,
            completed_at: Some(now_rfc3339()),
        },
    )?;
    remove_rebase_control_path(&journal)?;
    Ok(())
}

fn publish_media_rebase_event_noreplace(
    config: &AppConfig,
    event: &MediaRebaseEvidence,
    directory_metadata: &fs::Metadata,
) -> Result<()> {
    let path = media_rebase_events_path(config).join(format!("{}.json", event.event_id));
    if path.exists() || fs::symlink_metadata(&path).is_ok() {
        let existing = read_protected_json_if_exists::<MediaRebaseEvidence>(
            &path,
            MAX_MEDIA_REBASE_EVENT_BYTES,
            metadata_uid(directory_metadata),
        )?
        .ok_or_else(|| anyhow!("published media-rebase event disappeared"))?;
        if existing != *event {
            bail!("media-rebase transaction event ID collides with different evidence");
        }
        return Ok(());
    }

    let directory = path
        .parent()
        .ok_or_else(|| anyhow!("media-rebase event path has no parent"))?;
    let temporary = directory.join(format!(
        ".media-rebase-reconcile-{}-{}.tmp",
        std::process::id(),
        Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    let body = serde_json::to_vec(event).context("serialize media-rebase transaction event")?;
    let result = (|| -> Result<()> {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let mut file = options
            .open(&temporary)
            .with_context(|| format!("create {}", temporary.display()))?;
        #[cfg(unix)]
        align_service_state_owner(&file, directory_metadata)?;
        file.write_all(&body)
            .with_context(|| format!("write {}", temporary.display()))?;
        file.sync_all()
            .with_context(|| format!("sync {}", temporary.display()))?;
        drop(file);
        rename_noreplace(&temporary, &path)
            .with_context(|| format!("publish {}", path.display()))?;
        fs::File::open(directory)
            .with_context(|| format!("open {}", directory.display()))?
            .sync_all()
            .with_context(|| format!("sync {}", directory.display()))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn read_protected_json_if_exists<T: DeserializeOwned>(
    path: &Path,
    maximum_bytes: u64,
    expected_uid: u32,
) -> Result<Option<T>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err).with_context(|| format!("inspect {}", path.display())),
    };
    if !metadata.file_type().is_file() || metadata.len() > maximum_bytes {
        bail!("protected appliance journal is not a bounded regular file");
    }
    #[cfg(unix)]
    if metadata.uid() != expected_uid || metadata.mode() & 0o777 != 0o600 || metadata.nlink() != 1 {
        bail!("protected appliance journal ownership or permissions are unsafe");
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let file = options
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    let opened = file
        .metadata()
        .with_context(|| format!("reinspect {}", path.display()))?;
    #[cfg(unix)]
    if opened.dev() != metadata.dev()
        || opened.ino() != metadata.ino()
        || opened.uid() != expected_uid
        || opened.mode() & 0o777 != 0o600
        || opened.nlink() != 1
        || opened.len() != metadata.len()
    {
        bail!("protected appliance journal changed while opening");
    }
    let mut bytes = Vec::new();
    file.take(maximum_bytes + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {}", path.display()))?;
    if bytes.len() as u64 > maximum_bytes {
        bail!("protected appliance journal exceeds its size limit");
    }
    serde_json::from_slice(&bytes)
        .with_context(|| format!("parse {}", path.display()))
        .map(Some)
}

fn remove_rebase_control_path(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("{} has no parent", path.display()))?;
    let parent_metadata =
        fs::symlink_metadata(parent).with_context(|| format!("inspect {}", parent.display()))?;
    if !parent_metadata.file_type().is_dir() {
        bail!("media-rebase control parent is not a directory");
    }
    #[cfg(unix)]
    if parent_metadata.mode() & 0o022 != 0 {
        bail!("media-rebase control parent is group/other writable");
    }
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err).with_context(|| format!("inspect {}", path.display())),
    };
    if !metadata.file_type().is_symlink() && !metadata.file_type().is_file() {
        bail!(
            "refusing non-file media-rebase control path {}",
            path.display()
        );
    }
    #[cfg(unix)]
    if metadata.file_type().is_file()
        && (metadata.uid() != parent_metadata.uid() || metadata.nlink() != 1)
    {
        bail!("media-rebase control file ownership or links are unsafe");
    }
    fs::remove_file(path).with_context(|| format!("remove {}", path.display()))?;
    fs::File::open(parent)
        .with_context(|| format!("open {}", parent.display()))?
        .sync_all()
        .with_context(|| format!("sync {}", parent.display()))
}

#[cfg(target_os = "linux")]
fn rename_noreplace(source: &Path, destination: &Path) -> io::Result<()> {
    let source = std::ffi::CString::new(source.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "source path contains NUL"))?;
    let destination = std::ffi::CString::new(destination.as_os_str().as_bytes()).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "destination path contains NUL")
    })?;
    // libc does not expose the renameat2 wrapper on every Linux libc target
    // (notably the static musl appliance target), but it does expose the
    // architecture-correct syscall number and variadic syscall entry point.
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "linux"))]
fn rename_noreplace(source: &Path, destination: &Path) -> io::Result<()> {
    fs::hard_link(source, destination)?;
    fs::remove_file(source)
}

#[cfg(unix)]
fn metadata_uid(metadata: &fs::Metadata) -> u32 {
    metadata.uid()
}

#[cfg(not(unix))]
fn metadata_uid(_metadata: &fs::Metadata) -> u32 {
    0
}

#[cfg(unix)]
fn effective_uid() -> u32 {
    unsafe { libc::geteuid() }
}

#[cfg(not(unix))]
fn effective_uid() -> u32 {
    0
}

fn validate_media_rebase_event(event: &MediaRebaseEvidence) -> Result<()> {
    if event.schema != MEDIA_REBASE_SCHEMA {
        bail!("unsupported Forge media-rebase event schema");
    }
    validate_media_rebase_event_id(&event.event_id)?;
    if event.media_sequence == 0 {
        bail!("Forge media-rebase sequence must be positive");
    }
    if !matches!(event.mode.as_str(), "repair" | "recovery") {
        bail!("Forge media-rebase mode is invalid");
    }
    parse_semantic_version(&event.resulting_version)
        .context("Forge media-rebase resulting version is invalid")?;
    if let Some(version) = &event.previous_target_version {
        parse_semantic_version(version)
            .context("Forge media-rebase previous target version is invalid")?;
    }
    if let Some(attempt_id) = &event.previous_request_attempt_id {
        if attempt_id.is_empty()
            || attempt_id.len() > 128
            || !attempt_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            bail!("Forge media-rebase previous attempt ID is invalid");
        }
    }
    if let Some(status) = &event.previous_status {
        if !matches!(
            status.as_str(),
            "idle"
                | "requested"
                | "queued"
                | "waiting"
                | "preflight"
                | "downloading"
                | "verifying"
                | "staged"
                | "applying"
                | "restarting"
                | "health_checking"
                | "succeeded"
                | "failed"
                | "rolled_back"
                | "unsupported"
        ) {
            bail!("Forge media-rebase previous status is invalid");
        }
    }
    chrono::DateTime::parse_from_rfc3339(&event.created_at)
        .context("Forge media-rebase timestamp is invalid")?;
    Ok(())
}

fn validate_media_rebase_event_id(event_id: &str) -> Result<()> {
    let parsed = uuid::Uuid::parse_str(event_id).context("parse Forge media-rebase event ID")?;
    if parsed.is_nil() || parsed.hyphenated().to_string() != event_id {
        bail!("Forge media-rebase event ID is not a canonical nonzero UUID");
    }
    Ok(())
}

/// Read a narrow, non-secret updater projection for an update-only report.
///
/// This qualification input is deliberately distinct from updater-owned
/// `status.json`: it is explicit, bounded, read-only, denies unknown fields,
/// and cannot carry error text or timestamps into a signed report.
pub fn read_update_only_projection(path: &Path) -> Result<ForgeUpdateStatusReport> {
    if !path.is_absolute() {
        bail!("Forge update-only projection path must be absolute");
    }
    let path_metadata =
        fs::symlink_metadata(path).with_context(|| format!("inspect {}", path.display()))?;
    if !path_metadata.file_type().is_file() {
        bail!("Forge update-only projection must be a regular file");
    }
    if path_metadata.len() > MAX_UPDATE_ONLY_PROJECTION_BYTES {
        bail!("Forge update-only projection exceeds its size limit");
    }
    #[cfg(unix)]
    {
        let owner = path_metadata.uid();
        let effective_uid = unsafe { libc::geteuid() };
        if path_metadata.nlink() != 1
            || path_metadata.mode() & 0o022 != 0
            || (owner != 0 && owner != effective_uid)
        {
            bail!("Forge update-only projection ownership or permissions are unsafe");
        }
    }

    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = options
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    let opened_metadata = file
        .metadata()
        .with_context(|| format!("inspect open {}", path.display()))?;
    if !opened_metadata.file_type().is_file() {
        bail!("Forge update-only projection must remain a regular file");
    }
    if opened_metadata.len() > MAX_UPDATE_ONLY_PROJECTION_BYTES {
        bail!("Forge update-only projection exceeds its size limit");
    }
    #[cfg(unix)]
    if opened_metadata.dev() != path_metadata.dev()
        || opened_metadata.ino() != path_metadata.ino()
        || opened_metadata.nlink() != 1
    {
        bail!("Forge update-only projection changed while opening");
    }

    let mut bytes = Vec::with_capacity(
        (opened_metadata.len() + 1).min(MAX_UPDATE_ONLY_PROJECTION_BYTES + 1) as usize,
    );
    std::io::Read::by_ref(&mut file)
        .take(MAX_UPDATE_ONLY_PROJECTION_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {}", path.display()))?;
    if bytes.len() as u64 > MAX_UPDATE_ONLY_PROJECTION_BYTES {
        bail!("Forge update-only projection exceeds its size limit");
    }
    let read_metadata = file
        .metadata()
        .with_context(|| format!("reinspect {}", path.display()))?;
    #[cfg(unix)]
    if read_metadata.dev() != path_metadata.dev()
        || read_metadata.ino() != path_metadata.ino()
        || read_metadata.uid() != path_metadata.uid()
        || read_metadata.mode() != path_metadata.mode()
        || read_metadata.nlink() != path_metadata.nlink()
        || read_metadata.len() != path_metadata.len()
        || read_metadata.mtime() != path_metadata.mtime()
        || read_metadata.mtime_nsec() != path_metadata.mtime_nsec()
    {
        bail!("Forge update-only projection changed while reading");
    }
    #[cfg(not(unix))]
    if read_metadata.len() != path_metadata.len() {
        bail!("Forge update-only projection changed while reading");
    }
    let projection: UpdateOnlyStatusProjection =
        serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))?;
    validate_update_only_projection(&projection)?;

    Ok(ForgeUpdateStatusReport {
        status: projection.status,
        stage: "idle".to_string(),
        progress_percent: None,
        error: String::new(),
        target_version: String::new(),
        current_version: projection.current_version,
        attempt_id: projection.attempt_id,
        started_at: None,
        completed_at: None,
    })
}

pub async fn apply_requested_update(config: &AppConfig) -> Result<()> {
    apply_requested_update_with_runtime(config, &SystemUpdateRuntime).await
}

async fn apply_requested_update_with_runtime(
    config: &AppConfig,
    runtime: &dyn UpdateRuntime,
) -> Result<()> {
    if !config.update.enabled {
        return Ok(());
    }
    ensure_update_dirs(config)?;
    repair_service_status_ownership(config)?;
    let Some(_lock) = try_acquire_lock(config)? else {
        return Ok(());
    };

    if recover_interrupted_apply(config, runtime)? {
        return Ok(());
    }

    let Some(stored) = read_request(config)? else {
        return Ok(());
    };
    if stored.schema != RELEASE_SCHEMA {
        bail!("unsupported Forge update request schema");
    }
    let request = stored.request;
    validate_request(&request)?;

    if let Some(status) = read_status(config)? {
        if status.target_version == request.version
            && status.attempt_id == request_attempt_id(&request)
            && update_status_is_terminal(&status.status)
        {
            if !terminal_status_matches_installed_binary(config, &status, &request)? {
                record_terminal_binary_identity_mismatch(config, status)?;
            }
            return Ok(());
        }
    }
    if validate_update_target_version(&request.version).is_err() {
        write_version_policy_status(config, &request)?;
        return Ok(());
    }

    let started_at = now_rfc3339();
    let attempt_id = request_attempt_id(&request);
    let apply_result =
        apply_requested_update_inner(config, &request, &attempt_id, &started_at, runtime).await;
    prune_stale_update_files(config, &attempt_id, &request.version);
    if let Err(err) = apply_result {
        let message = err.to_string();
        let current_version = installed_binary_version(config).unwrap_or_default();
        write_status(
            config,
            ForgeUpdateStatusReport {
                status: "failed".to_string(),
                stage: "failed".to_string(),
                progress_percent: Some(100),
                error: message.clone(),
                target_version: request.version.clone(),
                current_version,
                attempt_id: attempt_id.clone(),
                started_at: Some(started_at.clone()),
                completed_at: Some(now_rfc3339()),
            },
        )?;
        return Err(anyhow!(message));
    }
    Ok(())
}

fn terminal_status_matches_installed_binary(
    config: &AppConfig,
    status: &ForgeUpdateStatusReport,
    request: &ManagedUpdateRequest,
) -> Result<bool> {
    let actual_version = match installed_binary_version(config) {
        Ok(version) => version,
        Err(_) => return Ok(false),
    };
    if actual_version != status.current_version {
        return Ok(false);
    }
    if status.status == "succeeded" {
        if actual_version != request.version {
            return Ok(false);
        }
        let actual_sha256 = sha256_regular_file(&config.update.binary_path)?;
        if actual_sha256 != request.sha256.to_ascii_lowercase() {
            return Ok(false);
        }
    }
    Ok(true)
}

fn record_terminal_binary_identity_mismatch(
    config: &AppConfig,
    mut status: ForgeUpdateStatusReport,
) -> Result<()> {
    status.status = if status.status == "succeeded" {
        "rolled_back".to_string()
    } else {
        "failed".to_string()
    };
    status.stage = "binary_identity_mismatch".to_string();
    status.progress_percent = Some(100);
    status.error =
        "installed_binary_identity_mismatch: terminal updater state did not match the live executable"
            .to_string();
    status.current_version = installed_binary_version(config).unwrap_or_default();
    status.completed_at = Some(now_rfc3339());
    write_status(config, status)
}

async fn apply_requested_update_inner(
    config: &AppConfig,
    request: &ManagedUpdateRequest,
    attempt_id: &str,
    started_at: &str,
    runtime: &dyn UpdateRuntime,
) -> Result<()> {
    write_progress(config, request, attempt_id, started_at, "preflight", 5, "")?;
    let pool = db::connect(config).await.context("open Forge database")?;
    let active_builds = db::active_build_job_count(&pool)
        .await
        .context("check active Forge builds")?;
    if active_builds > 0 {
        write_progress(
            config,
            request,
            attempt_id,
            started_at,
            "waiting",
            5,
            "waiting for active build jobs to finish",
        )?;
        return Ok(());
    }

    // The signature covers (version, sha256, artifact URL), so verify it
    // before fetching anything: an unsigned request must not trigger a
    // download at all.
    write_progress(config, request, attempt_id, started_at, "verifying", 15, "")?;
    verify_signature(config, request)?;

    write_progress(
        config,
        request,
        attempt_id,
        started_at,
        "downloading",
        30,
        "",
    )?;
    let artifact = download_artifact(config, request).await?;

    let staged = stage_artifact(config, request, &artifact)?;
    write_progress(config, request, attempt_id, started_at, "staged", 70, "")?;
    smoke_test_binary(config, &staged, &request.version)?;

    install_and_activate_candidate(config, request, attempt_id, started_at, &staged, runtime).await
}

async fn install_and_activate_candidate(
    config: &AppConfig,
    request: &ManagedUpdateRequest,
    attempt_id: &str,
    started_at: &str,
    staged: &Path,
    runtime: &dyn UpdateRuntime,
) -> Result<()> {
    let backup = backup_current_binary(config, attempt_id)?;
    let backup_filename = backup
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| anyhow!("update backup filename is invalid"))?
        .to_string();
    let mut state = ApplyState {
        schema: APPLY_STATE_SCHEMA.to_string(),
        attempt_id: attempt_id.to_string(),
        target_version: request.version.clone(),
        backup_filename,
        phase: "backup_ready".to_string(),
        started_at: started_at.to_string(),
    };
    write_apply_state(config, &state)?;

    state.phase = "candidate_installing".to_string();
    write_apply_state(config, &state)?;
    write_progress(config, request, attempt_id, started_at, "applying", 82, "")?;
    if let Err(err) = install_binary(config, staged) {
        return rollback_after_activation_failure(
            config,
            request,
            attempt_id,
            started_at,
            &backup,
            &format!("candidate_install_failed: {err}"),
            runtime,
        );
    }

    state.phase = "candidate_installed".to_string();
    if let Err(err) = write_apply_state(config, &state) {
        return rollback_after_activation_failure(
            config,
            request,
            attempt_id,
            started_at,
            &backup,
            &format!("activation_state_persist_failed: {err}"),
            runtime,
        );
    }
    let activation_result = async {
        write_progress(
            config,
            request,
            attempt_id,
            started_at,
            "restarting",
            88,
            "",
        )?;
        runtime
            .restart_service(config)
            .context("candidate_restart_failed")?;
        write_progress(
            config,
            request,
            attempt_id,
            started_at,
            "health_checking",
            94,
            "",
        )?;
        runtime
            .wait_for_health(config)
            .await
            .context("candidate_health_check_failed")?;
        Result::<()>::Ok(())
    }
    .await;
    if let Err(err) = activation_result {
        return rollback_after_activation_failure(
            config,
            request,
            attempt_id,
            started_at,
            &backup,
            &err.to_string(),
            runtime,
        );
    }

    if let Err(err) = write_status(
        config,
        ForgeUpdateStatusReport {
            status: "succeeded".to_string(),
            stage: "complete".to_string(),
            progress_percent: Some(100),
            error: String::new(),
            target_version: request.version.clone(),
            current_version: request.version.clone(),
            attempt_id: attempt_id.to_string(),
            started_at: Some(started_at.to_string()),
            completed_at: Some(now_rfc3339()),
        },
    ) {
        return rollback_after_activation_failure(
            config,
            request,
            attempt_id,
            started_at,
            &backup,
            &format!("success_status_persist_failed: {err}"),
            runtime,
        );
    }
    if let Err(err) = remove_apply_state(config) {
        tracing::warn!(error = %err, "failed to remove committed Forge update state");
    }
    Ok(())
}

fn rollback_after_activation_failure(
    config: &AppConfig,
    request: &ManagedUpdateRequest,
    attempt_id: &str,
    started_at: &str,
    backup: &Path,
    trigger: &str,
    runtime: &dyn UpdateRuntime,
) -> Result<()> {
    if let Err(err) = restore_binary(config, backup) {
        bail!("rollback_failed: trigger={trigger}; restore_binary={err}");
    }
    let restored_version = installed_binary_version(config)
        .with_context(|| format!("rollback_failed: trigger={trigger}; restored_binary_identity"))?;
    if let Err(err) = runtime.restart_service(config) {
        bail!("rollback_failed: trigger={trigger}; restored_binary_restart={err}");
    }
    write_status(
        config,
        ForgeUpdateStatusReport {
            status: "rolled_back".to_string(),
            stage: "rolled_back".to_string(),
            progress_percent: Some(100),
            error: format!("activation_failed: {trigger}; restored previous binary"),
            target_version: request.version.clone(),
            current_version: restored_version,
            attempt_id: attempt_id.to_string(),
            started_at: Some(started_at.to_string()),
            completed_at: Some(now_rfc3339()),
        },
    )?;
    if let Err(err) = remove_apply_state(config) {
        tracing::warn!(error = %err, "failed to remove rolled-back Forge update state");
    }
    Ok(())
}

fn recover_interrupted_apply(config: &AppConfig, runtime: &dyn UpdateRuntime) -> Result<bool> {
    let Some(state) = read_apply_state(config)? else {
        return Ok(false);
    };
    validate_apply_state(config, &state)?;

    if read_status(config)?.is_some_and(|status| {
        status.attempt_id == state.attempt_id
            && status.target_version == state.target_version
            && matches!(status.status.as_str(), "succeeded" | "rolled_back")
    }) {
        remove_apply_state(config)?;
        return Ok(false);
    }

    if state.phase == "backup_ready" {
        remove_apply_state(config)?;
        return Ok(false);
    }

    let backup = config.update.releases_dir.join(&state.backup_filename);
    if let Err(err) = restore_binary(config, &backup) {
        return Err(record_interrupted_recovery_failure(
            config,
            &state,
            format!("restore_binary={err}"),
        ));
    }
    let restored_version = match installed_binary_version(config) {
        Ok(version) => version,
        Err(err) => {
            return Err(record_interrupted_recovery_failure(
                config,
                &state,
                format!("restored_binary_identity={err}"),
            ));
        }
    };
    if let Err(err) = runtime.restart_service(config) {
        return Err(record_interrupted_recovery_failure(
            config,
            &state,
            format!("restored_binary_restart={err}"),
        ));
    }
    write_status(
        config,
        ForgeUpdateStatusReport {
            status: "rolled_back".to_string(),
            stage: "rolled_back".to_string(),
            progress_percent: Some(100),
            error: format!(
                "interrupted_apply_recovered: restored previous binary from {} phase",
                state.phase
            ),
            target_version: state.target_version,
            current_version: restored_version,
            attempt_id: state.attempt_id,
            started_at: Some(state.started_at),
            completed_at: Some(now_rfc3339()),
        },
    )?;
    if let Err(err) = remove_apply_state(config) {
        tracing::warn!(error = %err, "failed to remove recovered Forge update state");
    }
    Ok(true)
}

fn record_interrupted_recovery_failure(
    config: &AppConfig,
    state: &ApplyState,
    detail: String,
) -> anyhow::Error {
    let message = format!("rollback_failed: trigger=interrupted_apply; {detail}");
    let status_result = write_status(
        config,
        ForgeUpdateStatusReport {
            status: "failed".to_string(),
            stage: "failed".to_string(),
            progress_percent: Some(100),
            error: message.clone(),
            target_version: state.target_version.clone(),
            current_version: installed_binary_version(config).unwrap_or_default(),
            attempt_id: state.attempt_id.clone(),
            started_at: Some(state.started_at.clone()),
            completed_at: Some(now_rfc3339()),
        },
    );
    match status_result {
        Ok(()) => anyhow!(message),
        Err(err) => anyhow!("{message}; failure_status_persist_failed={err}"),
    }
}

async fn download_artifact(config: &AppConfig, request: &ManagedUpdateRequest) -> Result<PathBuf> {
    let parsed = Url::parse(&request.artifact_url).context("parse update artifact URL")?;
    if !matches!(parsed.scheme(), "http" | "https") {
        bail!("update artifact URL must be http:// or https://");
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5 * 60))
        .connect_timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("build update HTTP client")?;
    let mut response = client
        .get(&request.artifact_url)
        .send()
        .await
        .context("download update artifact")?;
    if !response.status().is_success() {
        bail!(
            "update artifact download failed with HTTP {}",
            response.status()
        );
    }
    if response
        .content_length()
        .is_some_and(|len| len > config.update.max_artifact_size_bytes)
    {
        bail!("update artifact exceeds configured size limit");
    }

    crate::disk::ensure_headroom(
        &config.update.releases_dir,
        config.update.max_artifact_size_bytes,
        "Forge update download",
    )?;
    let tmp_path = config.update.releases_dir.join(".artifact.download");
    remove_owned_regular_file_if_exists(&tmp_path)?;
    let mut file = tokio_fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp_path)
        .await
        .with_context(|| format!("create {}", tmp_path.display()))?;
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    while let Some(chunk) = response.chunk().await.context("read update artifact")? {
        total = total
            .checked_add(chunk.len() as u64)
            .ok_or_else(|| anyhow!("update artifact size overflow"))?;
        if total > config.update.max_artifact_size_bytes {
            bail!("update artifact exceeds configured size limit");
        }
        hasher.update(&chunk);
        file.write_all(&chunk)
            .await
            .context("write update artifact")?;
    }
    file.flush().await.context("flush update artifact")?;
    file.sync_all().await.context("sync update artifact")?;
    drop(file);

    let actual = format!("{:x}", hasher.finalize());
    if actual != request.sha256.to_ascii_lowercase() {
        let _ = fs::remove_file(&tmp_path);
        bail!("update artifact sha256 mismatch");
    }
    Ok(tmp_path)
}

fn verify_signature(config: &AppConfig, request: &ManagedUpdateRequest) -> Result<()> {
    let key = parse_trusted_public_key(&config.update.trusted_public_key)?;
    if request.signature.trim().is_empty() {
        bail!("update signature is required");
    }
    let sig_bytes = decode_b64(request.signature.trim()).context("decode update signature")?;
    let signature = Signature::from_slice(&sig_bytes).context("parse update signature")?;
    let message = update_signature_message(request);
    key.verify_strict(message.as_bytes(), &signature)
        .context("verify update signature")
}

fn parse_trusted_public_key(value: &str) -> Result<VerifyingKey> {
    let value = value.trim();
    if value.is_empty() {
        bail!(
            "update.trusted_public_key is not configured; refusing to apply an unverified Forge update (configure the trusted release key or set update.enabled = false)"
        );
    }
    let key_bytes = decode_b64(value).context("decode trusted update public key")?;
    let key_array: [u8; 32] = key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("trusted update public key must be a 32-byte Ed25519 key"))?;
    let verifying_key =
        VerifyingKey::from_bytes(&key_array).context("parse trusted update public key")?;
    if verifying_key.is_weak() {
        bail!("trusted update public key must not be a weak Ed25519 key");
    }
    Ok(verifying_key)
}

fn stage_artifact(
    config: &AppConfig,
    request: &ManagedUpdateRequest,
    artifact: &Path,
) -> Result<PathBuf> {
    let filename = format!("cybex-forge-{}", safe_version_filename(&request.version));
    let staged = config.update.releases_dir.join(filename);
    let staged_tmp = config.update.releases_dir.join(".artifact.staged");
    remove_owned_regular_file_if_exists(&staged_tmp)?;
    fs::copy(artifact, &staged_tmp).with_context(|| format!("stage {}", staged_tmp.display()))?;
    set_executable(&staged_tmp)?;
    sync_regular_file(&staged_tmp)?;
    fs::rename(&staged_tmp, &staged).with_context(|| format!("publish {}", staged.display()))?;
    sync_parent_directory(&staged)?;
    remove_owned_regular_file_if_exists(artifact)?;
    Ok(staged)
}

fn smoke_test_binary(config: &AppConfig, binary: &Path, expected_version: &str) -> Result<()> {
    let actual_version = installed_binary_version_at(binary)
        .with_context(|| format!("read version from staged binary {}", binary.display()))?;
    if actual_version != expected_version {
        bail!("staged binary version does not match the signed update version");
    }

    let mut command = Command::new(binary);
    command
        .arg("--config")
        .arg(&config.update.config_path)
        .arg("print-config");
    let output = command_output_with_transient_exec_retry(&mut command)
        .with_context(|| format!("run smoke test for {}", binary.display()))?;
    if !output.status.success() {
        bail!(
            "staged binary smoke test failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

fn installed_binary_version(config: &AppConfig) -> Result<String> {
    installed_binary_version_at(&config.update.binary_path)
}

fn installed_binary_version_at(binary: &Path) -> Result<String> {
    let mut command = Command::new(binary);
    command.arg("--version");
    let output = command_output_with_transient_exec_retry(&mut command)
        .with_context(|| format!("execute {} --version", binary.display()))?;
    if !output.status.success() || !output.stderr.is_empty() {
        bail!("installed Forge binary identity check failed");
    }
    let stdout = std::str::from_utf8(&output.stdout)
        .context("installed Forge binary version output is not UTF-8")?;
    let version = stdout
        .strip_prefix("cybex-forge ")
        .and_then(|value| value.strip_suffix('\n'))
        .filter(|value| !value.contains('\n'))
        .ok_or_else(|| anyhow!("installed Forge binary version output is not canonical"))?;
    parse_semantic_version(version).context("installed Forge binary version is not canonical")?;
    Ok(version.to_string())
}

fn sha256_regular_file(path: &Path) -> Result<String> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect installed binary {}", path.display()))?;
    if !metadata.file_type().is_file() {
        bail!("installed Forge binary is not a regular file");
    }
    #[cfg(unix)]
    if metadata.nlink() != 1 {
        bail!("installed Forge binary has an unsafe link count");
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = options
        .open(path)
        .with_context(|| format!("open installed binary {}", path.display()))?;
    let opened = file
        .metadata()
        .with_context(|| format!("reinspect installed binary {}", path.display()))?;
    #[cfg(unix)]
    if opened.dev() != metadata.dev()
        || opened.ino() != metadata.ino()
        || opened.nlink() != 1
        || opened.len() != metadata.len()
    {
        bail!("installed Forge binary changed while opening");
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .with_context(|| format!("hash installed binary {}", path.display()))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn backup_current_binary(config: &AppConfig, attempt_id: &str) -> Result<PathBuf> {
    let backup = config
        .update
        .releases_dir
        .join(format!("cybex-forge-backup-{attempt_id}"));
    fs::copy(&config.update.binary_path, &backup)
        .with_context(|| format!("backup {}", config.update.binary_path.display()))?;
    set_executable(&backup)?;
    sync_regular_file(&backup)?;
    sync_parent_directory(&backup)?;
    Ok(backup)
}

fn install_binary(config: &AppConfig, staged: &Path) -> Result<()> {
    let parent = config
        .update
        .binary_path
        .parent()
        .ok_or_else(|| anyhow!("update binary path has no parent"))?;
    let tmp = parent.join(".cybex-forge.update");
    fs::copy(staged, &tmp).with_context(|| format!("install {}", tmp.display()))?;
    set_executable(&tmp)?;
    sync_regular_file(&tmp)?;
    fs::rename(&tmp, &config.update.binary_path)
        .with_context(|| format!("replace {}", config.update.binary_path.display()))?;
    sync_parent_directory(&config.update.binary_path)?;
    Ok(())
}

/// Remove backups and staged release binaries from earlier attempts/versions.
/// The current attempt's backup and the current version's staged binary are
/// kept so a post-restart rollback remains possible; everything older is one
/// full binary copy each and would otherwise accumulate forever.
fn prune_stale_update_files(config: &AppConfig, keep_attempt_id: &str, keep_version: &str) {
    let keep_backup = format!("cybex-forge-backup-{keep_attempt_id}");
    let keep_release = format!("cybex-forge-{}", safe_version_filename(keep_version));
    for (dir, prefix, keep) in [
        (
            &config.update.releases_dir,
            "cybex-forge-backup-",
            &keep_backup,
        ),
        (&config.update.releases_dir, "cybex-forge-", &keep_release),
    ] {
        let entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if !name.starts_with(prefix) || name == keep.as_str() {
                continue;
            }
            // The releases prefix also matches backup names when both dirs
            // coincide; never let the releases pass delete the kept backup.
            if name == keep_backup {
                continue;
            }
            if let Err(err) = fs::remove_file(entry.path()) {
                tracing::warn!(
                    error = %err,
                    path = %entry.path().display(),
                    "failed to prune stale Forge update file"
                );
            }
        }
    }
}

fn restore_binary(config: &AppConfig, backup: &Path) -> Result<()> {
    let parent = config
        .update
        .binary_path
        .parent()
        .ok_or_else(|| anyhow!("update binary path has no parent"))?;
    let tmp = parent.join(".cybex-forge.rollback");
    fs::copy(backup, &tmp).with_context(|| format!("restore {}", tmp.display()))?;
    set_executable(&tmp)?;
    sync_regular_file(&tmp)?;
    fs::rename(&tmp, &config.update.binary_path)
        .with_context(|| format!("rollback {}", config.update.binary_path.display()))?;
    sync_parent_directory(&config.update.binary_path)?;
    Ok(())
}

fn restart_service(config: &AppConfig) -> Result<()> {
    let mut command = Command::new("systemctl");
    command.arg("restart").arg(&config.update.service_name);
    let output =
        command_output_with_transient_exec_retry(&mut command).context("restart Forge service")?;
    if !output.status.success() {
        bail!(
            "restart {} failed: {}",
            config.update.service_name,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

async fn wait_for_health(config: &AppConfig) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .connect_timeout(Duration::from_secs(2))
        .build()
        .context("build health HTTP client")?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
    let mut last_error = String::new();
    while tokio::time::Instant::now() < deadline {
        match client.get(&config.update.health_url).send().await {
            Ok(response) if response.status().is_success() => return Ok(()),
            Ok(response) => last_error = format!("HTTP {}", response.status()),
            Err(err) => last_error = err.to_string(),
        }
        sleep(Duration::from_secs(2)).await;
    }
    bail!("Forge health check did not pass: {last_error}");
}

fn write_progress(
    config: &AppConfig,
    request: &ManagedUpdateRequest,
    attempt_id: &str,
    started_at: &str,
    stage: &str,
    progress: i32,
    error: &str,
) -> Result<()> {
    write_status(
        config,
        ForgeUpdateStatusReport {
            status: stage.to_string(),
            stage: stage.to_string(),
            progress_percent: Some(progress.clamp(0, 100)),
            error: error.to_string(),
            target_version: request.version.clone(),
            current_version: env!("CARGO_PKG_VERSION").to_string(),
            attempt_id: attempt_id.to_string(),
            started_at: Some(started_at.to_string()),
            completed_at: None,
        },
    )
}

fn read_request(config: &AppConfig) -> Result<Option<StoredUpdateRequest>> {
    let path = request_path(config);
    if !path.is_file() {
        return Ok(None);
    }
    let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("parse {}", path.display()))
        .map(Some)
}

fn read_status(config: &AppConfig) -> Result<Option<ForgeUpdateStatusReport>> {
    let path = status_path(config);
    if !path.is_file() {
        return Ok(None);
    }
    let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("parse {}", path.display()))
        .map(Some)
}

fn read_apply_state(config: &AppConfig) -> Result<Option<ApplyState>> {
    let path = apply_state_path(config);
    if !path.is_file() {
        return Ok(None);
    }
    let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("parse {}", path.display()))
        .map(Some)
}

fn write_apply_state(config: &AppConfig, state: &ApplyState) -> Result<()> {
    validate_apply_state(config, state)?;
    write_json_atomic(&apply_state_path(config), state)
}

fn remove_apply_state(config: &AppConfig) -> Result<()> {
    let path = apply_state_path(config);
    match fs::remove_file(&path) {
        Ok(()) => sync_parent_directory(&path),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("remove {}", path.display())),
    }
}

fn validate_apply_state(config: &AppConfig, state: &ApplyState) -> Result<()> {
    if state.schema != APPLY_STATE_SCHEMA {
        bail!("unsupported Forge apply-state schema");
    }
    if state.attempt_id.len() != 32
        || !state
            .attempt_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("Forge apply-state attempt ID is invalid");
    }
    if !matches!(
        state.phase.as_str(),
        "backup_ready" | "candidate_installing" | "candidate_installed"
    ) {
        bail!("Forge apply-state phase is invalid");
    }
    let expected_backup = format!("cybex-forge-backup-{}", state.attempt_id);
    if state.backup_filename != expected_backup
        || Path::new(&state.backup_filename)
            .file_name()
            .and_then(|v| v.to_str())
            != Some(state.backup_filename.as_str())
    {
        bail!("Forge apply-state backup filename is invalid");
    }
    parse_semantic_version(&state.target_version)
        .context("Forge apply-state target version is invalid")?;
    let backup = config.update.releases_dir.join(&state.backup_filename);
    let metadata = fs::symlink_metadata(&backup)
        .with_context(|| format!("inspect Forge apply-state backup {}", backup.display()))?;
    if !metadata.file_type().is_file() {
        bail!("Forge apply-state backup is missing");
    }
    #[cfg(unix)]
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.nlink() != 1 {
        bail!("Forge apply-state backup ownership is invalid");
    }
    Ok(())
}

fn write_status(config: &AppConfig, status: ForgeUpdateStatusReport) -> Result<()> {
    write_service_state_json_atomic(&status_path(config), &status)
}

fn write_service_state_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("{} has no parent", path.display()))?;
    let parent_metadata =
        fs::symlink_metadata(parent).with_context(|| format!("inspect {}", parent.display()))?;
    if !parent_metadata.file_type().is_dir() {
        bail!("Forge update service-state parent must be a directory");
    }
    let tmp = parent.join(format!(
        ".cybex-forge-service-state-{}-{}.tmp",
        std::process::id(),
        Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    let body = serde_json::to_vec_pretty(value).context("serialize update service state")?;
    let result = (|| -> Result<()> {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let mut file = options
            .open(&tmp)
            .with_context(|| format!("create {}", tmp.display()))?;
        #[cfg(unix)]
        align_service_state_owner(&file, &parent_metadata)?;
        file.write_all(&body)
            .with_context(|| format!("write {}", tmp.display()))?;
        file.sync_all()
            .with_context(|| format!("sync {}", tmp.display()))?;
        drop(file);
        fs::rename(&tmp, path).with_context(|| format!("rename {}", path.display()))?;
        sync_parent_directory(path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

#[cfg(unix)]
fn service_state_requires_chown(effective_uid: u32, parent_uid: u32) -> Result<bool> {
    if effective_uid == 0 {
        return Ok(true);
    }
    if effective_uid != parent_uid {
        bail!("Forge update service state must be written by root or the service account");
    }
    Ok(false)
}

#[cfg(unix)]
fn align_service_state_owner(file: &fs::File, parent_metadata: &fs::Metadata) -> Result<()> {
    let effective_uid = unsafe { libc::geteuid() };
    if service_state_requires_chown(effective_uid, parent_metadata.uid())? {
        let result = unsafe {
            libc::fchown(
                file.as_raw_fd(),
                parent_metadata.uid(),
                parent_metadata.gid(),
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error()).context("assign Forge service-state owner");
        }
    }
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .context("secure Forge service state")?;
    let metadata = file.metadata().context("inspect Forge service state")?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.uid() != parent_metadata.uid()
        || metadata.gid() != parent_metadata.gid()
        || metadata.mode() & 0o777 != 0o600
    {
        bail!("Forge update service-state ownership is invalid");
    }
    Ok(())
}

fn repair_service_status_ownership(config: &AppConfig) -> Result<()> {
    let path = status_path(config);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err).with_context(|| format!("inspect {}", path.display())),
    };
    if !metadata.file_type().is_file() {
        bail!("Forge update service status must be a regular file");
    }
    #[cfg(unix)]
    {
        let parent = path
            .parent()
            .ok_or_else(|| anyhow!("{} has no parent", path.display()))?;
        let parent_metadata = fs::symlink_metadata(parent)
            .with_context(|| format!("inspect {}", parent.display()))?;
        let mut options = fs::OpenOptions::new();
        options.read(true).write(true);
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let file = options
            .open(&path)
            .with_context(|| format!("open {}", path.display()))?;
        align_service_state_owner(&file, &parent_metadata)?;
        file.sync_all()
            .with_context(|| format!("sync {}", path.display()))?;
        sync_parent_directory(&path)?;
    }
    Ok(())
}

fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("{} has no parent", path.display()))?;
    fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    let tmp = parent.join(format!(
        ".cybex-forge-update-{}-{}.tmp",
        std::process::id(),
        Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    let body = serde_json::to_vec_pretty(value).context("serialize update state")?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .with_context(|| format!("create {}", tmp.display()))?;
    file.write_all(&body)
        .with_context(|| format!("write {}", tmp.display()))?;
    file.sync_all()
        .with_context(|| format!("sync {}", tmp.display()))?;
    drop(file);
    fs::rename(&tmp, path).with_context(|| format!("rename {}", path.display()))?;
    sync_parent_directory(path)
}

fn try_acquire_lock(config: &AppConfig) -> Result<Option<UpdateLock>> {
    let path = lock_path(config);
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    options
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = options
        .open(&path)
        .with_context(|| format!("open {}", path.display()))?;

    #[cfg(unix)]
    {
        let metadata = file
            .metadata()
            .with_context(|| format!("inspect {}", path.display()))?;
        if !metadata.file_type().is_file()
            || metadata.nlink() != 1
            || metadata.uid() != unsafe { libc::geteuid() }
        {
            bail!("Forge update lock must be a singly-linked file owned by the updater");
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("secure {}", path.display()))?;
    }

    #[cfg(unix)]
    {
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                return Ok(None);
            }
            return Err(err).with_context(|| format!("lock {}", path.display()));
        }
    }

    if let Some(existing) = read_lock_owner(&mut file)? {
        validate_lock_owner_shape(&existing)?;
        if existing.state == "held" && lock_owner_is_live(&existing)? {
            #[cfg(unix)]
            let _ = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
            return Ok(None);
        }
    }

    let owner = current_lock_owner()?;
    write_lock_owner(&mut file, &owner)?;
    sync_parent_directory(&path)?;
    Ok(Some(UpdateLock { file, owner }))
}

fn read_lock_owner(file: &mut fs::File) -> Result<Option<UpdateLockOwner>> {
    file.seek(SeekFrom::Start(0)).context("seek update lock")?;
    let mut body = String::new();
    file.take(16 * 1024)
        .read_to_string(&mut body)
        .context("read update lock")?;
    if body.trim().is_empty() {
        return Ok(None);
    }
    serde_json::from_str(&body)
        .context("parse update lock owner")
        .map(Some)
}

fn write_lock_owner(file: &mut fs::File, owner: &UpdateLockOwner) -> Result<()> {
    let body = serde_json::to_vec_pretty(owner).context("serialize update lock owner")?;
    file.seek(SeekFrom::Start(0)).context("seek update lock")?;
    file.set_len(0).context("truncate update lock")?;
    file.write_all(&body).context("write update lock owner")?;
    file.sync_all().context("sync update lock owner")
}

fn validate_lock_owner_shape(owner: &UpdateLockOwner) -> Result<()> {
    if owner.schema != APPLY_LOCK_SCHEMA {
        bail!("unsupported Forge update-lock schema");
    }
    if owner.pid == 0 || owner.process_start_ticks == 0 {
        bail!("Forge update-lock process identity is invalid");
    }
    if !matches!(owner.state.as_str(), "held" | "released") {
        bail!("Forge update-lock state is invalid");
    }
    if owner.boot_id.len() != 36
        || !owner
            .boot_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
    {
        bail!("Forge update-lock boot identity is invalid");
    }
    Ok(())
}

fn current_lock_owner() -> Result<UpdateLockOwner> {
    let pid = std::process::id();
    let process_start_ticks = process_start_ticks(pid)?
        .ok_or_else(|| anyhow!("current process identity is unavailable"))?;
    Ok(UpdateLockOwner {
        schema: APPLY_LOCK_SCHEMA.to_string(),
        pid,
        process_start_ticks,
        boot_id: current_boot_id()?,
        state: "held".to_string(),
        acquired_at: now_rfc3339(),
        released_at: None,
    })
}

fn lock_owner_is_live(owner: &UpdateLockOwner) -> Result<bool> {
    if owner.state != "held" || owner.boot_id != current_boot_id()? {
        return Ok(false);
    }
    Ok(process_start_ticks(owner.pid)? == Some(owner.process_start_ticks))
}

fn current_boot_id() -> Result<String> {
    let value = fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .context("read Linux boot identity")?;
    let value = value.trim().to_ascii_lowercase();
    if value.len() != 36
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
    {
        bail!("Linux boot identity is invalid");
    }
    Ok(value)
}

fn process_start_ticks(pid: u32) -> Result<Option<u64>> {
    let path = PathBuf::from(format!("/proc/{pid}/stat"));
    let stat = match fs::read_to_string(&path) {
        Ok(value) => value,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err).with_context(|| format!("read {}", path.display())),
    };
    let close = stat
        .rfind(')')
        .ok_or_else(|| anyhow!("{} has an invalid process identity", path.display()))?;
    let start_ticks = stat[close + 1..]
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| anyhow!("{} has no process start time", path.display()))?
        .parse::<u64>()
        .with_context(|| format!("parse {} process start time", path.display()))?;
    if start_ticks == 0 {
        bail!("{} process start time is invalid", path.display());
    }
    Ok(Some(start_ticks))
}

fn sync_parent_directory(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("{} has no parent", path.display()))?;
    fs::File::open(parent)
        .with_context(|| format!("open {}", parent.display()))?
        .sync_all()
        .with_context(|| format!("sync {}", parent.display()))
}

fn sync_regular_file(path: &Path) -> Result<()> {
    fs::File::open(path)
        .with_context(|| format!("open {}", path.display()))?
        .sync_all()
        .with_context(|| format!("sync {}", path.display()))
}

fn ensure_update_dirs(config: &AppConfig) -> Result<()> {
    ensure_update_work_dir(config)?;
    fs::create_dir_all(&config.update.releases_dir)
        .with_context(|| format!("create {}", config.update.releases_dir.display()))?;
    ensure_protected_releases_dir(&config.update.releases_dir)?;
    Ok(())
}

fn ensure_update_work_dir(config: &AppConfig) -> Result<()> {
    fs::create_dir_all(&config.update.work_dir)
        .with_context(|| format!("create {}", config.update.work_dir.display()))?;
    Ok(())
}

fn ensure_protected_releases_dir(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect protected release directory {}", path.display()))?;
    if !metadata.file_type().is_dir() {
        bail!("protected Forge release path must be a directory");
    }
    #[cfg(unix)]
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o022 != 0 {
        bail!(
            "protected Forge release directory must be updater-owned and not group/other writable"
        );
    }
    Ok(())
}

fn remove_owned_regular_file_if_exists(path: &Path) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err).with_context(|| format!("inspect {}", path.display())),
    };
    if !metadata.file_type().is_file() {
        bail!(
            "refusing to replace non-regular Forge update path {}",
            path.display()
        );
    }
    #[cfg(unix)]
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.nlink() != 1 {
        bail!(
            "refusing to replace unowned Forge update path {}",
            path.display()
        );
    }
    fs::remove_file(path).with_context(|| format!("remove {}", path.display()))
}

fn validate_update_only_projection(projection: &UpdateOnlyStatusProjection) -> Result<()> {
    if projection.schema != UPDATE_ONLY_PROJECTION_SCHEMA {
        bail!("unsupported Forge update-only projection schema");
    }
    if projection.status != "idle" {
        bail!("explicit Forge update-only projections are restricted to idle status");
    }
    if !projection.attempt_id.is_empty() {
        bail!("idle Forge update-only projection must have an empty attempt");
    }
    validate_update_projection_version(&projection.current_version, "current")?;
    Ok(())
}

fn validate_update_projection_version(version: &str, field: &str) -> Result<()> {
    if version.is_empty()
        || version.len() > 128
        || version.starts_with('-')
        || version.ends_with(['-', '.'])
        || version.contains("..")
        || !version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+'))
    {
        bail!("Forge update-only projection {field} version is invalid");
    }
    Ok(())
}

fn validate_request(request: &ManagedUpdateRequest) -> Result<()> {
    parse_semantic_version(&request.version)?;
    let url = Url::parse(&request.artifact_url).context("parse update artifact URL")?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        bail!("update artifact URL must be absolute http:// or https://");
    }
    if request.sha256.len() != 64 || !request.sha256.chars().all(|ch| ch.is_ascii_hexdigit()) {
        bail!("update sha256 must be a 64-character hex digest");
    }
    Ok(())
}

fn write_version_policy_status(config: &AppConfig, request: &ManagedUpdateRequest) -> Result<()> {
    write_status(
        config,
        ForgeUpdateStatusReport {
            status: "unsupported".to_string(),
            stage: "version_policy".to_string(),
            progress_percent: Some(100),
            error: "managed update target is not newer than the running Forge version; use appliance recovery for governed rollback".to_string(),
            target_version: request.version.clone(),
            current_version: env!("CARGO_PKG_VERSION").to_string(),
            attempt_id: request_attempt_id(request),
            started_at: None,
            completed_at: Some(now_rfc3339()),
        },
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SemanticVersion {
    major: u64,
    minor: u64,
    patch: u64,
    prerelease: Option<Vec<SemanticIdentifier>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum SemanticIdentifier {
    Numeric(u64),
    Text(String),
}

fn parse_semantic_version(value: &str) -> Result<SemanticVersion> {
    if value.is_empty()
        || value.len() > 128
        || !value.is_ascii()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        bail!("update version must be canonical SemVer");
    }
    let mut build_split = value.split('+');
    let version_and_pre = build_split.next().unwrap_or_default();
    let build = build_split.next();
    if build_split.next().is_some() {
        bail!("update version must be canonical SemVer");
    }
    if let Some(build) = build {
        validate_semantic_identifiers(build, false)?;
    }

    let (core, prerelease_text) = match version_and_pre.split_once('-') {
        Some((core, prerelease)) => (core, Some(prerelease)),
        None => (version_and_pre, None),
    };
    let mut core_parts = core.split('.');
    let major = parse_semantic_numeric(core_parts.next().unwrap_or_default())?;
    let minor = parse_semantic_numeric(core_parts.next().unwrap_or_default())?;
    let patch = parse_semantic_numeric(core_parts.next().unwrap_or_default())?;
    if core_parts.next().is_some() {
        bail!("update version must be canonical SemVer");
    }
    let prerelease = prerelease_text
        .map(|value| validate_semantic_identifiers(value, true))
        .transpose()?;
    Ok(SemanticVersion {
        major,
        minor,
        patch,
        prerelease,
    })
}

fn parse_semantic_numeric(value: &str) -> Result<u64> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        bail!("update version must be canonical SemVer");
    }
    value
        .parse::<u64>()
        .context("update version numeric component is too large")
}

fn validate_semantic_identifiers(value: &str, prerelease: bool) -> Result<Vec<SemanticIdentifier>> {
    value
        .split('.')
        .map(|identifier| {
            if identifier.is_empty()
                || !identifier
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            {
                bail!("update version must be canonical SemVer");
            }
            if prerelease && identifier.bytes().all(|byte| byte.is_ascii_digit()) {
                Ok(SemanticIdentifier::Numeric(parse_semantic_numeric(
                    identifier,
                )?))
            } else {
                Ok(SemanticIdentifier::Text(identifier.to_string()))
            }
        })
        .collect()
}

fn semantic_version_precedence(left: &SemanticVersion, right: &SemanticVersion) -> Ordering {
    let core = (left.major, left.minor, left.patch).cmp(&(right.major, right.minor, right.patch));
    if core != Ordering::Equal {
        return core;
    }
    match (&left.prerelease, &right.prerelease) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (Some(left_ids), Some(right_ids)) => {
            for (left_id, right_id) in left_ids.iter().zip(right_ids) {
                let ordering = match (left_id, right_id) {
                    (SemanticIdentifier::Numeric(left), SemanticIdentifier::Numeric(right)) => {
                        left.cmp(right)
                    }
                    (SemanticIdentifier::Numeric(_), SemanticIdentifier::Text(_)) => Ordering::Less,
                    (SemanticIdentifier::Text(_), SemanticIdentifier::Numeric(_)) => {
                        Ordering::Greater
                    }
                    (SemanticIdentifier::Text(left), SemanticIdentifier::Text(right)) => {
                        left.cmp(right)
                    }
                };
                if ordering != Ordering::Equal {
                    return ordering;
                }
            }
            left_ids.len().cmp(&right_ids.len())
        }
    }
}

fn validate_update_target_version(target: &str) -> Result<()> {
    let target = parse_semantic_version(target)?;
    let current = parse_semantic_version(env!("CARGO_PKG_VERSION"))
        .context("running Forge version is not canonical SemVer")?;
    if semantic_version_precedence(&target, &current) != Ordering::Greater {
        bail!("signed update target must be newer than the running Forge version");
    }
    Ok(())
}

pub fn validate_appliance_media_version(installed: &str, media: &str) -> Result<()> {
    let installed = parse_semantic_version(installed)
        .context("protected installed appliance version is not canonical SemVer")?;
    let media = parse_semantic_version(media)
        .context("replacement appliance media version is not canonical SemVer")?;
    if semantic_version_precedence(&media, &installed) == Ordering::Less {
        bail!("replacement appliance media is older than protected installed state");
    }
    Ok(())
}

fn update_status_is_active(status: &str) -> bool {
    matches!(
        status,
        "requested"
            | "waiting"
            | "preflight"
            | "downloading"
            | "verifying"
            | "staged"
            | "applying"
            | "restarting"
            | "health_checking"
    )
}

fn update_status_is_terminal(status: &str) -> bool {
    matches!(
        status,
        "succeeded" | "failed" | "rolled_back" | "unsupported"
    )
}

fn request_attempt_id(request: &ManagedUpdateRequest) -> String {
    let requested = request.requested_at.as_deref().unwrap_or("manual");
    let mut hasher = Sha256::new();
    hasher.update(request.version.as_bytes());
    hasher.update(b"\n");
    hasher.update(request.sha256.as_bytes());
    hasher.update(b"\n");
    hasher.update(requested.as_bytes());
    format!("{:x}", hasher.finalize())[..32].to_string()
}

fn update_signature_message(request: &ManagedUpdateRequest) -> String {
    format!(
        "{}\n{}\n{}\n",
        request.version,
        request.sha256.to_ascii_lowercase(),
        request.artifact_url
    )
}

fn safe_version_filename(version: &str) -> String {
    version
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-' | '+') {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn decode_b64(value: &str) -> Result<Vec<u8>> {
    STANDARD
        .decode(value)
        .or_else(|_| URL_SAFE_NO_PAD.decode(value))
        .map_err(anyhow::Error::new)
}

fn now_rfc3339() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn request_path(config: &AppConfig) -> PathBuf {
    config.update.work_dir.join(REQUEST_FILE)
}

fn status_path(config: &AppConfig) -> PathBuf {
    config.update.work_dir.join(STATUS_FILE)
}

fn appliance_metadata_path(config: &AppConfig) -> PathBuf {
    config.paths.data_dir.join("appliance")
}

fn media_rebase_events_path(config: &AppConfig) -> PathBuf {
    config.update.work_dir.join(MEDIA_REBASE_EVENTS_DIR)
}

fn lock_path(config: &AppConfig) -> PathBuf {
    config.update.releases_dir.join(LOCK_FILE)
}

fn apply_state_path(config: &AppConfig) -> PathBuf {
    config.update.releases_dir.join(APPLY_STATE_FILE)
}

#[cfg(unix)]
fn set_executable(path: &Path) -> Result<()> {
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_executable(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey, Verifier};
    use std::{
        collections::VecDeque,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };
    use tokio::{io::AsyncReadExt, net::TcpListener, time::timeout};

    const BASELINE_BINARY: &[u8] =
        b"#!/bin/sh\n[ \"$1\" = \"--version\" ] || exit 2\nprintf 'cybex-forge 0.1.1\\n'\n";
    const CANDIDATE_BINARY: &[u8] =
        b"#!/bin/sh\n[ \"$1\" = \"--version\" ] || exit 2\nprintf 'cybex-forge 0.1.3\\n'\n";

    #[derive(Default)]
    struct ScriptedRuntime {
        restart_errors: Mutex<VecDeque<Option<String>>>,
        health_errors: Mutex<VecDeque<Option<String>>>,
        restart_count: AtomicUsize,
        health_count: AtomicUsize,
    }

    impl ScriptedRuntime {
        fn with_results(
            restart_errors: impl IntoIterator<Item = Option<&'static str>>,
            health_errors: impl IntoIterator<Item = Option<&'static str>>,
        ) -> Self {
            Self {
                restart_errors: Mutex::new(
                    restart_errors
                        .into_iter()
                        .map(|value| value.map(str::to_string))
                        .collect(),
                ),
                health_errors: Mutex::new(
                    health_errors
                        .into_iter()
                        .map(|value| value.map(str::to_string))
                        .collect(),
                ),
                restart_count: AtomicUsize::new(0),
                health_count: AtomicUsize::new(0),
            }
        }
    }

    impl UpdateRuntime for ScriptedRuntime {
        fn restart_service(&self, _config: &AppConfig) -> Result<()> {
            self.restart_count.fetch_add(1, Ordering::SeqCst);
            match self.restart_errors.lock().unwrap().pop_front().flatten() {
                Some(error) => Err(anyhow!(error)),
                None => Ok(()),
            }
        }

        fn wait_for_health<'a>(
            &'a self,
            _config: &'a AppConfig,
        ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
            self.health_count.fetch_add(1, Ordering::SeqCst);
            let error = self.health_errors.lock().unwrap().pop_front().flatten();
            Box::pin(async move {
                match error {
                    Some(error) => Err(anyhow!(error)),
                    None => Ok(()),
                }
            })
        }
    }

    fn test_request(requested_at: &str) -> ManagedUpdateRequest {
        ManagedUpdateRequest {
            version: "0.1.3".to_string(),
            artifact_url: "https://example.com/cybex-forge".to_string(),
            sha256: "a".repeat(64),
            signature: String::new(),
            release_url: "https://example.com/releases/v0.1.3".to_string(),
            notes_url: "https://example.com/releases/v0.1.3".to_string(),
            requested_at: Some(requested_at.to_string()),
        }
    }

    fn test_config() -> (AppConfig, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "cybex-forge-updater-test-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let mut config = AppConfig::default();
        config.paths.data_dir = root.join("data");
        config.update.work_dir = root.join("updates");
        config.update.releases_dir = root.join("releases");
        (config, root)
    }

    fn activation_fixture() -> (AppConfig, PathBuf, PathBuf, ManagedUpdateRequest, String) {
        let (mut config, root) = test_config();
        config.update.binary_path = root.join("bin/cybex-forge");
        config.update.config_path = root.join("config.toml");
        fs::create_dir_all(config.update.binary_path.parent().unwrap()).unwrap();
        fs::create_dir_all(&config.update.work_dir).unwrap();
        fs::create_dir_all(&config.update.releases_dir).unwrap();
        fs::write(&config.update.binary_path, BASELINE_BINARY).unwrap();
        set_executable(&config.update.binary_path).unwrap();
        fs::write(&config.update.config_path, b"").unwrap();
        let staged = config.update.releases_dir.join("cybex-forge-0.1.3");
        fs::write(&staged, CANDIDATE_BINARY).unwrap();
        set_executable(&staged).unwrap();
        let request = test_request("2026-07-06T00:00:00Z");
        let attempt_id = request_attempt_id(&request);
        (config, root, staged, request, attempt_id)
    }

    fn write_update_only_projection(root: &Path, value: serde_json::Value) -> PathBuf {
        fs::create_dir_all(root).unwrap();
        let path = root.join("update-projection.json");
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        path
    }

    fn write_media_rebase_event(
        config: &AppConfig,
        event_id: &str,
        media_sequence: u64,
        created_at: &str,
        resulting_version: &str,
    ) {
        let directory = media_rebase_events_path(config);
        fs::create_dir_all(&directory).unwrap();
        #[cfg(unix)]
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.join(format!("{event_id}.json"));
        fs::write(
            &path,
            serde_json::to_vec(&MediaRebaseEvidence {
                schema: MEDIA_REBASE_SCHEMA.to_string(),
                event_id: event_id.to_string(),
                media_sequence,
                mode: "recovery".to_string(),
                resulting_version: resulting_version.to_string(),
                previous_request_attempt_id: Some("a".repeat(64)),
                previous_target_version: Some("0.1.3".to_string()),
                previous_status: Some("succeeded".to_string()),
                created_at: created_at.to_string(),
            })
            .unwrap(),
        )
        .unwrap();
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn appliance_media_version_gate_is_semver_aware_and_never_allows_downgrade() {
        validate_appliance_media_version("1.2.3", "1.2.3").unwrap();
        validate_appliance_media_version("1.2.3", "1.2.4-alpha.1").unwrap();
        validate_appliance_media_version("1.2.3-alpha.1", "1.2.3").unwrap();
        assert!(validate_appliance_media_version("1.2.3", "1.2.2").is_err());
        assert!(validate_appliance_media_version("1.2.3", "1.2.3-rc.1").is_err());
        assert!(validate_appliance_media_version("not-semver", "1.2.3").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn boot_reconciliation_scrubs_current_and_legacy_installer_secret_stages() {
        let (config, root) = test_config();
        let stages = [
            config
                .paths
                .data_dir
                .join("bootstrap")
                .join(INSTALL_ENROLLMENT_STAGE_FILE),
            appliance_metadata_path(&config).join(INSTALL_ENROLLMENT_STAGE_FILE),
        ];
        for (index, stage) in stages.iter().enumerate() {
            let parent = stage.parent().unwrap();
            fs::create_dir_all(parent).unwrap();
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
            fs::write(stage, format!("interrupted-secret-stage-{index}-123")).unwrap();
            fs::set_permissions(stage, fs::Permissions::from_mode(0o600)).unwrap();

            scrub_interrupted_install_enrollment_stage(&config).unwrap();
            assert!(!stage.exists(), "{} survived boot cleanup", stage.display());
            // Cleanup is replay-safe after an interruption which already
            // removed the pathname.
            scrub_interrupted_install_enrollment_stage(&config).unwrap();
        }

        let bootstrap = stages[0].parent().unwrap();
        let protected_target = bootstrap.join("must-survive");
        fs::write(&protected_target, b"not-the-staged-secret").unwrap();
        std::os::unix::fs::symlink(&protected_target, &stages[0]).unwrap();
        let error = scrub_interrupted_install_enrollment_stage(&config).unwrap_err();
        assert!(error.to_string().contains("bounded regular file"));
        assert_eq!(
            fs::read(&protected_target).unwrap(),
            b"not-the-staged-secret"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn boot_reconciliation_rejects_unsafe_config_before_secret_stage_mutation() {
        let (config, root) = test_config();
        let stage = config
            .paths
            .data_dir
            .join("bootstrap")
            .join(INSTALL_ENROLLMENT_STAGE_FILE);
        fs::create_dir_all(stage.parent().unwrap()).unwrap();
        fs::set_permissions(stage.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(&stage, b"interrupted-secret-stage-123456").unwrap();
        fs::set_permissions(&stage, fs::Permissions::from_mode(0o600)).unwrap();

        let error = reconcile_appliance_recovery(&config).unwrap_err();
        assert!(error.to_string().contains("unsafe configuration"));
        assert_eq!(
            fs::read(&stage).unwrap(),
            b"interrupted-secret-stage-123456"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn media_rebase_transaction_replays_partial_deletion_and_publish_interruptions() {
        let (config, root) = test_config();
        let appliance = appliance_metadata_path(&config);
        let event_directory = media_rebase_events_path(&config);
        fs::create_dir_all(&appliance).unwrap();
        fs::create_dir_all(&event_directory).unwrap();
        fs::create_dir_all(&config.update.releases_dir).unwrap();
        #[cfg(unix)]
        {
            fs::set_permissions(&appliance, fs::Permissions::from_mode(0o700)).unwrap();
            fs::set_permissions(&event_directory, fs::Permissions::from_mode(0o700)).unwrap();
        }
        for path in [
            request_path(&config),
            status_path(&config),
            apply_state_path(&config),
            lock_path(&config),
        ] {
            fs::write(path, b"control").unwrap();
        }

        let event = MediaRebaseEvidence {
            schema: MEDIA_REBASE_SCHEMA.to_string(),
            event_id: "32018c33-09e3-4c4a-b1b8-25d0f86cb0a6".to_string(),
            media_sequence: 7,
            mode: "repair".to_string(),
            resulting_version: "0.1.2".to_string(),
            previous_request_attempt_id: Some("a".repeat(32)),
            previous_target_version: Some("0.1.3".to_string()),
            previous_status: Some("applying".to_string()),
            created_at: "2026-07-31T12:00:00Z".to_string(),
        };
        let journal = appliance.join(MEDIA_REBASE_TRANSACTION_FILE);
        fs::write(&journal, serde_json::to_vec(&event).unwrap()).unwrap();
        #[cfg(unix)]
        fs::set_permissions(&journal, fs::Permissions::from_mode(0o600)).unwrap();

        // Simulate power loss after the first control deletion.
        fs::remove_file(request_path(&config)).unwrap();
        finalize_media_rebase_transaction(&config).unwrap();
        for path in [
            request_path(&config),
            status_path(&config),
            apply_state_path(&config),
            lock_path(&config),
            journal.clone(),
        ] {
            assert!(!path.exists(), "{} survived reconciliation", path.display());
        }
        let published = event_directory.join(format!("{}.json", event.event_id));
        let first_bytes = fs::read(&published).unwrap();
        assert_eq!(
            serde_json::from_slice::<MediaRebaseEvidence>(&first_bytes).unwrap(),
            event
        );

        // Simulate power loss after atomic publication but before journal clear.
        fs::write(&journal, serde_json::to_vec(&event).unwrap()).unwrap();
        fs::write(status_path(&config), b"stale-control").unwrap();
        #[cfg(unix)]
        fs::set_permissions(&journal, fs::Permissions::from_mode(0o600)).unwrap();
        finalize_media_rebase_transaction(&config).unwrap();
        assert!(!journal.exists());
        assert!(!status_path(&config).exists());
        assert_eq!(fs::read(&published).unwrap(), first_bytes);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn reboot_recovery_replaces_stale_success_with_restored_binary_truth() {
        let (config, root, _staged, request, attempt_id) = activation_fixture();
        let appliance = appliance_metadata_path(&config);
        fs::create_dir_all(&appliance).unwrap();
        #[cfg(unix)]
        fs::set_permissions(&appliance, fs::Permissions::from_mode(0o700)).unwrap();
        write_status(
            &config,
            ForgeUpdateStatusReport {
                status: "succeeded".to_string(),
                stage: "complete".to_string(),
                progress_percent: Some(100),
                error: String::new(),
                target_version: request.version,
                current_version: "0.1.3".to_string(),
                attempt_id,
                started_at: Some("2026-07-30T00:00:00Z".to_string()),
                completed_at: Some("2026-07-30T00:01:00Z".to_string()),
            },
        )
        .unwrap();
        let journal = appliance.join(BINARY_RECOVERY_FILE);
        fs::write(
            &journal,
            serde_json::to_vec(&BinaryRecoveryJournal {
                schema: BINARY_RECOVERY_SCHEMA.to_string(),
                embedded_version: "0.1.1".to_string(),
                reason: "missing_or_nonexecutable".to_string(),
            })
            .unwrap(),
        )
        .unwrap();
        #[cfg(unix)]
        fs::set_permissions(&journal, fs::Permissions::from_mode(0o600)).unwrap();

        reconcile_binary_recovery(&config).unwrap();

        let recovered = read_status(&config).unwrap().unwrap();
        assert_eq!(recovered.status, "rolled_back");
        assert_eq!(recovered.stage, "appliance_binary_recovery");
        assert_eq!(recovered.current_version, "0.1.1");
        assert!(recovered.error.contains("appliance_binary_recovered"));
        assert!(!journal.exists());
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn terminal_success_never_short_circuits_a_different_live_binary() {
        let (config, root, _staged, request, attempt_id) = activation_fixture();
        write_json_atomic(
            &request_path(&config),
            &StoredUpdateRequest {
                schema: RELEASE_SCHEMA.to_string(),
                request: request.clone(),
            },
        )
        .unwrap();
        write_status(
            &config,
            ForgeUpdateStatusReport {
                status: "succeeded".to_string(),
                stage: "complete".to_string(),
                progress_percent: Some(100),
                error: String::new(),
                target_version: request.version,
                current_version: "0.1.3".to_string(),
                attempt_id,
                started_at: Some("2026-07-30T00:00:00Z".to_string()),
                completed_at: Some("2026-07-30T00:01:00Z".to_string()),
            },
        )
        .unwrap();

        apply_requested_update_with_runtime(
            &config,
            &ScriptedRuntime::with_results(std::iter::empty(), std::iter::empty()),
        )
        .await
        .unwrap();

        let corrected = read_status(&config).unwrap().unwrap();
        assert_eq!(corrected.status, "rolled_back");
        assert_eq!(corrected.stage, "binary_identity_mismatch");
        assert_eq!(corrected.current_version, "0.1.1");
        assert!(
            corrected
                .error
                .contains("installed_binary_identity_mismatch")
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn explicit_idle_projection_preserves_historical_version_without_writes() {
        let (mut config, root) = test_config();
        config.update.enabled = true;
        let projection = write_update_only_projection(
            &root,
            serde_json::json!({
                "schema": UPDATE_ONLY_PROJECTION_SCHEMA,
                "status": "idle",
                "attempt_id": "",
                "current_version": "0.1.0"
            }),
        );
        let before = fs::read(&projection).unwrap();

        let status = read_update_only_projection(&projection).unwrap();

        assert_eq!(status.status, "idle");
        assert_eq!(status.stage, "idle");
        assert!(status.attempt_id.is_empty());
        assert_eq!(status.current_version, "0.1.0");
        assert!(status.target_version.is_empty());
        assert!(status.error.is_empty());
        assert_eq!(status.progress_percent, None);
        assert_eq!(fs::read(&projection).unwrap(), before);
        assert!(stored_status_report(&config).unwrap().is_none());
        assert!(!config.update.work_dir.exists());
        assert!(!config.update.releases_dir.exists());
        assert_eq!(
            fs::read_dir(&root)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect::<Vec<_>>(),
            vec![projection.file_name().unwrap().to_os_string()]
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn media_rebase_events_are_ordered_and_removed_only_after_exact_ack() {
        let (config, root) = test_config();
        let later_id = "22222222-2222-4222-8222-222222222222";
        let earlier_id = "11111111-1111-4111-8111-111111111111";
        write_media_rebase_event(&config, later_id, 2, "2026-07-31T12:00:01Z", "0.1.2");
        write_media_rebase_event(&config, earlier_id, 1, "2026-07-31T12:00:00Z", "0.1.2");

        let reported = media_rebase_events(&config).unwrap();
        assert_eq!(
            reported
                .iter()
                .map(|event| event.event_id.as_str())
                .collect::<Vec<_>>(),
            vec![earlier_id, later_id]
        );
        assert!(
            acknowledge_media_rebase_events(
                &config,
                &reported,
                &["33333333-3333-4333-8333-333333333333".to_string()]
            )
            .is_err()
        );
        assert_eq!(media_rebase_events(&config).unwrap().len(), 2);

        acknowledge_media_rebase_events(&config, &reported, &[earlier_id.to_string()]).unwrap();
        let remaining = media_rebase_events(&config).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].event_id, later_id);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn media_rebase_sequence_survives_a_backward_clock_and_rejects_reuse() {
        let (config, root) = test_config();
        let first_id = "11111111-1111-4111-8111-111111111111";
        let second_id = "22222222-2222-4222-8222-222222222222";
        write_media_rebase_event(&config, first_id, 41, "2026-07-31T12:00:00Z", "0.1.1");
        write_media_rebase_event(&config, second_id, 42, "2024-01-01T00:00:00Z", "0.1.2");

        let events = media_rebase_events(&config).unwrap();
        assert_eq!(
            events
                .iter()
                .map(|event| (event.media_sequence, event.event_id.as_str()))
                .collect::<Vec<_>>(),
            vec![(41, first_id), (42, second_id)]
        );

        let third_id = "33333333-3333-4333-8333-333333333333";
        write_media_rebase_event(&config, third_id, 42, "2027-01-01T00:00:00Z", "0.1.3");
        assert!(
            media_rebase_events(&config)
                .unwrap_err()
                .to_string()
                .contains("sequences are not distinct")
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn explicit_projection_rejects_unknown_or_unsafe_domains() {
        let (_config, root) = test_config();
        let invalid = [
            serde_json::json!({
                "schema": UPDATE_ONLY_PROJECTION_SCHEMA,
                "status": "idle",
                "attempt_id": "",
                "current_version": "0.1.0",
                "error": "must not be accepted"
            }),
            serde_json::json!({
                "schema": "cybex.forge.update-projection.v0",
                "status": "idle",
                "attempt_id": "",
                "current_version": "0.1.0"
            }),
            serde_json::json!({
                "schema": UPDATE_ONLY_PROJECTION_SCHEMA,
                "status": "failed",
                "attempt_id": "a".repeat(32),
                "current_version": "0.1.0"
            }),
            serde_json::json!({
                "schema": UPDATE_ONLY_PROJECTION_SCHEMA,
                "status": "idle",
                "attempt_id": "a".repeat(32),
                "current_version": "0.1.0"
            }),
        ];
        for value in invalid {
            let path = write_update_only_projection(&root, value);
            assert!(read_update_only_projection(&path).is_err());
        }
        for version in ["-0.1.0", "0.1.0-", "0.1.0.", "0..1", "0.1 0"] {
            let path = write_update_only_projection(
                &root,
                serde_json::json!({
                    "schema": UPDATE_ONLY_PROJECTION_SCHEMA,
                    "status": "idle",
                    "attempt_id": "",
                    "current_version": version
                }),
            );
            assert!(read_update_only_projection(&path).is_err());
        }
        assert!(
            read_update_only_projection(Path::new("relative-projection.json"))
                .unwrap_err()
                .to_string()
                .contains("must be absolute")
        );
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn explicit_projection_rejects_mutable_or_indirect_files() {
        let (_config, root) = test_config();
        let projection = write_update_only_projection(
            &root,
            serde_json::json!({
                "schema": UPDATE_ONLY_PROJECTION_SCHEMA,
                "status": "idle",
                "attempt_id": "",
                "current_version": "0.1.0"
            }),
        );
        fs::set_permissions(&projection, fs::Permissions::from_mode(0o620)).unwrap();
        assert!(read_update_only_projection(&projection).is_err());

        fs::set_permissions(&projection, fs::Permissions::from_mode(0o600)).unwrap();
        let symlink = root.join("projection-link.json");
        std::os::unix::fs::symlink(&projection, &symlink).unwrap();
        assert!(read_update_only_projection(&symlink).is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn command_output_retries_a_transient_busy_update_binary() {
        let (_config, root) = test_config();
        fs::create_dir_all(&root).unwrap();
        let executable = root.join("busy-update-binary");
        fs::write(&executable, "#!/bin/sh\nprintf ready\n").unwrap();
        set_executable(&executable).unwrap();
        let executable_writer = fs::OpenOptions::new()
            .write(true)
            .open(&executable)
            .unwrap();
        let release_writer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            drop(executable_writer);
        });

        let output =
            command_output_with_transient_exec_retry(&mut Command::new(&executable)).unwrap();
        release_writer.join().unwrap();

        assert!(output.status.success());
        assert_eq!(output.stdout, b"ready");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn managed_updates_require_a_canonical_strictly_newer_semver() {
        let current = parse_semantic_version(env!("CARGO_PKG_VERSION")).unwrap();
        assert!(validate_update_target_version(env!("CARGO_PKG_VERSION")).is_err());
        let older = if current.patch > 0 {
            format!("{}.{}.{}", current.major, current.minor, current.patch - 1)
        } else if current.minor > 0 {
            format!("{}.{}.0", current.major, current.minor - 1)
        } else {
            "0.0.0-alpha".to_string()
        };
        let current_prerelease = format!(
            "{}.{}.{}-alpha.1",
            current.major, current.minor, current.patch
        );
        let next_prerelease = format!(
            "{}.{}.{}-alpha.1",
            current.major,
            current.minor,
            current.patch.checked_add(1).unwrap()
        );
        assert!(validate_update_target_version(&older).is_err());
        assert!(validate_update_target_version(&current_prerelease).is_err());
        assert!(validate_update_target_version(&next_prerelease).is_ok());
        assert_eq!(
            semantic_version_precedence(
                &parse_semantic_version("1.0.0-alpha.1").unwrap(),
                &parse_semantic_version("1.0.0-alpha.beta").unwrap()
            ),
            std::cmp::Ordering::Less
        );
        assert_eq!(
            semantic_version_precedence(&current, &current),
            std::cmp::Ordering::Equal
        );
        for invalid in [
            "v0.1.3",
            "01.2.3",
            "1.02.3",
            "1.2.03",
            "1.2",
            "1.2.3-alpha.01",
            "1.2.3+",
            "1.2.3 alpha",
        ] {
            assert!(
                parse_semantic_version(invalid).is_err(),
                "accepted {invalid}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn staged_binary_version_must_match_the_signed_request_exactly() {
        let (config, root) = test_config();
        fs::create_dir_all(&root).unwrap();
        let candidate = root.join("candidate");
        fs::write(
            &candidate,
            "#!/bin/sh\ncase \"$1\" in\n  --version) printf 'cybex-forge 0.1.3\\n' ;;\n  --config) printf '{}\\n' ;;\n  *) exit 2 ;;\nesac\n",
        )
        .unwrap();
        set_executable(&candidate).unwrap();

        smoke_test_binary(&config, &candidate, "0.1.3").unwrap();
        let error = smoke_test_binary(&config, &candidate, "0.1.4").unwrap_err();
        assert!(error.to_string().contains("does not match"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn verify_signature_requires_trusted_public_key() {
        let (config, _root) = test_config();
        assert!(config.update.trusted_public_key.trim().is_empty());
        let request = test_request("2026-07-06T00:00:00Z");

        let err = verify_signature(&config, &request).expect_err("must refuse unverified updates");
        assert!(err.to_string().contains("trusted_public_key"));
    }

    #[test]
    fn verify_signature_accepts_the_exact_signed_release_message() {
        let (mut config, root) = test_config();
        let signing_key = SigningKey::from_bytes(&[9_u8; 32]);
        config.update.trusted_public_key = STANDARD.encode(signing_key.verifying_key().to_bytes());
        let mut request = test_request("2026-07-06T00:00:00Z");
        request.signature = STANDARD.encode(
            signing_key
                .sign(update_signature_message(&request).as_bytes())
                .to_bytes(),
        );

        verify_signature(&config, &request).unwrap();
        assert!(capabilities_enabled(&config));

        request.artifact_url.push_str("?changed=1");
        assert!(verify_signature(&config, &request).is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn updater_capability_requires_a_valid_trust_anchor() {
        let (mut config, root) = test_config();
        config.update.enabled = true;
        config.update.trusted_public_key = STANDARD.encode([0_u8; 31]);
        assert!(!capabilities_enabled(&config));
        config.update.trusted_public_key = String::new();
        assert!(!capabilities_enabled(&config));
        config.update.enabled = false;
        config.update.trusted_public_key = STANDARD.encode(
            SigningKey::from_bytes(&[4_u8; 32])
                .verifying_key()
                .to_bytes(),
        );
        assert!(!capabilities_enabled(&config));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn updater_rejects_the_weak_identity_key_and_legacy_forgery() {
        let (mut config, root) = test_config();
        config.update.enabled = true;
        let mut identity = [0_u8; 32];
        identity[0] = 1;
        let weak_key = VerifyingKey::from_bytes(&identity).unwrap();
        assert!(weak_key.is_weak());

        let mut forged_bytes = [0_u8; 64];
        forged_bytes[0] = 1;
        let forged_signature = Signature::from_slice(&forged_bytes).unwrap();
        let mut request = test_request("2026-07-06T00:00:00Z");
        request.signature = STANDARD.encode(forged_bytes);
        assert!(
            weak_key
                .verify(
                    update_signature_message(&request).as_bytes(),
                    &forged_signature,
                )
                .is_ok(),
            "the regression fixture must exercise legacy non-strict verification"
        );

        config.update.trusted_public_key = STANDARD.encode(identity);
        let error = verify_signature(&config, &request).unwrap_err().to_string();
        assert!(error.contains("weak Ed25519 key"));
        assert!(!capabilities_enabled(&config));
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn update_download_refuses_redirects_without_fetching_the_target() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let target_fetches = Arc::new(AtomicUsize::new(0));
        let server_fetches = Arc::clone(&target_fetches);
        let server = tokio::spawn(async move {
            let (mut first, _) = listener.accept().await.unwrap();
            let mut request = vec![0u8; 2048];
            let _ = first.read(&mut request).await.unwrap();
            first
                .write_all(
                    format!(
                        "HTTP/1.1 302 Found\r\nLocation: http://{address}/target\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            if let Ok(Ok((mut redirected, _))) =
                timeout(Duration::from_millis(250), listener.accept()).await
            {
                let mut request = vec![0u8; 2048];
                let read = redirected.read(&mut request).await.unwrap();
                if String::from_utf8_lossy(&request[..read]).contains("GET /target ") {
                    server_fetches.fetch_add(1, Ordering::SeqCst);
                }
                redirected
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody")
                    .await
                    .unwrap();
            }
        });

        let (mut config, root) = test_config();
        fs::create_dir_all(&config.update.releases_dir).unwrap();
        config.update.max_artifact_size_bytes = 1024;
        let mut request = test_request("2026-07-06T00:00:00Z");
        request.artifact_url = format!("http://{address}/redirect");

        let error = download_artifact(&config, &request).await.unwrap_err();
        assert!(error.to_string().contains("HTTP 302"));
        server.await.unwrap();
        assert_eq!(target_fetches.load(Ordering::SeqCst), 0);
        assert!(
            !config
                .update
                .releases_dir
                .join(".artifact.download")
                .exists()
        );
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn successful_activation_commits_candidate_and_clears_recovery_state() {
        let (config, root, staged, request, attempt_id) = activation_fixture();
        let runtime = ScriptedRuntime::with_results([None], [None]);

        install_and_activate_candidate(
            &config,
            &request,
            &attempt_id,
            "2026-07-06T00:00:00Z",
            &staged,
            &runtime,
        )
        .await
        .unwrap();

        assert_eq!(
            fs::read(&config.update.binary_path).unwrap(),
            CANDIDATE_BINARY
        );
        let status = read_status(&config).unwrap().unwrap();
        assert_eq!(status.status, "succeeded");
        assert_eq!(status.current_version, request.version);
        assert!(!apply_state_path(&config).exists());
        assert_eq!(runtime.restart_count.load(Ordering::SeqCst), 1);
        assert_eq!(runtime.health_count.load(Ordering::SeqCst), 1);
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn restart_failure_restores_binary_before_reporting_rolled_back() {
        let (config, root, staged, request, attempt_id) = activation_fixture();
        let runtime = ScriptedRuntime::with_results(
            [Some("candidate restart refused"), None],
            std::iter::empty(),
        );

        install_and_activate_candidate(
            &config,
            &request,
            &attempt_id,
            "2026-07-06T00:00:00Z",
            &staged,
            &runtime,
        )
        .await
        .unwrap();

        assert_eq!(
            fs::read(&config.update.binary_path).unwrap(),
            BASELINE_BINARY
        );
        let status = read_status(&config).unwrap().unwrap();
        assert_eq!(status.status, "rolled_back");
        assert_eq!(status.current_version, "0.1.1");
        assert!(status.error.contains("candidate_restart_failed"));
        assert_eq!(runtime.restart_count.load(Ordering::SeqCst), 2);
        assert_eq!(runtime.health_count.load(Ordering::SeqCst), 0);
        assert!(!apply_state_path(&config).exists());
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn health_failure_restores_binary_and_requires_restart_success() {
        let (config, root, staged, request, attempt_id) = activation_fixture();
        let runtime = ScriptedRuntime::with_results([None, None], [Some("health timeout")]);

        install_and_activate_candidate(
            &config,
            &request,
            &attempt_id,
            "2026-07-06T00:00:00Z",
            &staged,
            &runtime,
        )
        .await
        .unwrap();

        assert_eq!(
            fs::read(&config.update.binary_path).unwrap(),
            BASELINE_BINARY
        );
        let status = read_status(&config).unwrap().unwrap();
        assert_eq!(status.status, "rolled_back");
        assert_eq!(status.current_version, "0.1.1");
        assert!(status.error.contains("candidate_health_check_failed"));
        assert_eq!(runtime.restart_count.load(Ordering::SeqCst), 2);
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn failed_recovery_restart_remains_categorical_and_retryable() {
        let (config, root, staged, request, attempt_id) = activation_fixture();
        let runtime = ScriptedRuntime::with_results(
            [
                Some("candidate restart failed"),
                Some("baseline restart failed"),
            ],
            std::iter::empty(),
        );

        let err = install_and_activate_candidate(
            &config,
            &request,
            &attempt_id,
            "2026-07-06T00:00:00Z",
            &staged,
            &runtime,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("rollback_failed:"));
        assert!(err.to_string().contains("restored_binary_restart"));
        assert_eq!(
            fs::read(&config.update.binary_path).unwrap(),
            BASELINE_BINARY
        );
        assert!(apply_state_path(&config).is_file());

        let recovery_runtime = ScriptedRuntime::with_results([None], std::iter::empty());
        let recovery_error = recover_interrupted_apply(
            &config,
            &ScriptedRuntime::with_results([Some("still unavailable")], std::iter::empty()),
        )
        .unwrap_err();
        assert!(recovery_error.to_string().contains("rollback_failed:"));
        let failed_status = read_status(&config).unwrap().unwrap();
        assert_eq!(failed_status.status, "failed");
        assert_eq!(failed_status.current_version, "0.1.1");
        assert!(failed_status.error.contains("restored_binary_restart"));
        assert!(recover_interrupted_apply(&config, &recovery_runtime).unwrap());
        assert_eq!(read_status(&config).unwrap().unwrap().status, "rolled_back");
        assert!(!apply_state_path(&config).exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn interrupted_candidate_is_restored_from_durable_apply_state() {
        let (config, root, _staged, request, attempt_id) = activation_fixture();
        let backup = backup_current_binary(&config, &attempt_id).unwrap();
        fs::write(&config.update.binary_path, b"interrupted-candidate").unwrap();
        set_executable(&config.update.binary_path).unwrap();
        write_apply_state(
            &config,
            &ApplyState {
                schema: APPLY_STATE_SCHEMA.to_string(),
                attempt_id: attempt_id.clone(),
                target_version: request.version.clone(),
                backup_filename: backup.file_name().unwrap().to_str().unwrap().to_string(),
                phase: "candidate_installed".to_string(),
                started_at: "2026-07-06T00:00:00Z".to_string(),
            },
        )
        .unwrap();
        let runtime = ScriptedRuntime::with_results([None], std::iter::empty());

        assert!(recover_interrupted_apply(&config, &runtime).unwrap());

        assert_eq!(
            fs::read(&config.update.binary_path).unwrap(),
            BASELINE_BINARY
        );
        let status = read_status(&config).unwrap().unwrap();
        assert_eq!(status.status, "rolled_back");
        assert_eq!(status.current_version, "0.1.1");
        assert_ne!(status.current_version, env!("CARGO_PKG_VERSION"));
        assert!(status.error.contains("interrupted_apply_recovered"));
        assert!(!apply_state_path(&config).exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn interrupted_recovery_reports_unknown_when_restored_identity_cannot_be_proven() {
        let (config, root, _staged, request, attempt_id) = activation_fixture();
        let backup = backup_current_binary(&config, &attempt_id).unwrap();
        fs::write(&backup, b"#!/bin/sh\nprintf 'not-a-forge-version\\n'\n").unwrap();
        set_executable(&backup).unwrap();
        fs::write(&config.update.binary_path, CANDIDATE_BINARY).unwrap();
        set_executable(&config.update.binary_path).unwrap();
        write_apply_state(
            &config,
            &ApplyState {
                schema: APPLY_STATE_SCHEMA.to_string(),
                attempt_id,
                target_version: request.version,
                backup_filename: backup.file_name().unwrap().to_str().unwrap().to_string(),
                phase: "candidate_installed".to_string(),
                started_at: "2026-07-06T00:00:00Z".to_string(),
            },
        )
        .unwrap();

        let error = recover_interrupted_apply(
            &config,
            &ScriptedRuntime::with_results(std::iter::empty(), std::iter::empty()),
        )
        .unwrap_err();

        assert!(error.to_string().contains("restored_binary_identity"));
        let status = read_status(&config).unwrap().unwrap();
        assert_eq!(status.status, "failed");
        assert!(status.current_version.is_empty());
        assert!(apply_state_path(&config).is_file());
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn service_status_remains_private_and_readable_by_the_work_dir_owner() {
        let (config, root) = test_config();
        fs::create_dir_all(&config.update.work_dir).unwrap();
        let status = ForgeUpdateStatusReport {
            status: "rolled_back".to_string(),
            stage: "rolled_back".to_string(),
            progress_percent: Some(100),
            error: "synthetic rollback".to_string(),
            target_version: "0.1.2".to_string(),
            current_version: "0.1.1".to_string(),
            attempt_id: "1".repeat(32),
            started_at: Some("2026-07-23T00:00:00Z".to_string()),
            completed_at: Some("2026-07-23T00:00:01Z".to_string()),
        };

        write_status(&config, status).unwrap();

        let parent = fs::metadata(&config.update.work_dir).unwrap();
        let written = fs::metadata(status_path(&config)).unwrap();
        assert_eq!(written.uid(), parent.uid());
        assert_eq!(written.gid(), parent.gid());
        assert_eq!(written.mode() & 0o777, 0o600);
        assert_eq!(read_status(&config).unwrap().unwrap().status, "rolled_back");
        assert!(service_state_requires_chown(0, 4242).unwrap());
        assert!(!service_state_requires_chown(4242, 4242).unwrap());
        assert!(service_state_requires_chown(4343, 4242).is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn update_lock_excludes_a_live_holder_and_reacquires_after_release() {
        let (config, root) = test_config();
        fs::create_dir_all(&config.update.releases_dir).unwrap();

        let first = try_acquire_lock(&config).unwrap().unwrap();
        assert!(try_acquire_lock(&config).unwrap().is_none());
        drop(first);
        assert!(try_acquire_lock(&config).unwrap().is_some());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn update_lock_never_steals_exact_live_process_ownership() {
        let (config, root) = test_config();
        fs::create_dir_all(&config.update.releases_dir).unwrap();
        let owner = current_lock_owner().unwrap();
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path(&config))
            .unwrap();
        write_lock_owner(&mut file, &owner).unwrap();
        drop(file);

        assert!(try_acquire_lock(&config).unwrap().is_none());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn update_lock_recovers_proven_stale_process_identity() {
        let (config, root) = test_config();
        fs::create_dir_all(&config.update.releases_dir).unwrap();
        let mut stale = current_lock_owner().unwrap();
        stale.process_start_ticks = stale.process_start_ticks.saturating_add(1);
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path(&config))
            .unwrap();
        write_lock_owner(&mut file, &stale).unwrap();
        drop(file);

        let recovered = try_acquire_lock(&config).unwrap().unwrap();
        assert_eq!(recovered.owner.pid, std::process::id());
        assert_ne!(
            recovered.owner.process_start_ticks,
            stale.process_start_ticks
        );
        drop(recovered);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn prune_stale_update_files_keeps_current_attempt_and_version() {
        let (config, root) = test_config();
        fs::create_dir_all(&config.update.work_dir).unwrap();
        fs::create_dir_all(&config.update.releases_dir).unwrap();
        let keep_backup = config
            .update
            .releases_dir
            .join("cybex-forge-backup-current");
        let stale_backup = config.update.releases_dir.join("cybex-forge-backup-old");
        let unrelated = config.update.work_dir.join("request.json");
        let keep_release = config.update.releases_dir.join("cybex-forge-v0.1.2");
        let stale_release = config.update.releases_dir.join("cybex-forge-v0.1.1");
        for path in [
            &keep_backup,
            &stale_backup,
            &unrelated,
            &keep_release,
            &stale_release,
        ] {
            fs::write(path, b"x").unwrap();
        }

        prune_stale_update_files(&config, "current", "v0.1.2");

        assert!(keep_backup.exists());
        assert!(unrelated.exists());
        assert!(keep_release.exists());
        assert!(!stale_backup.exists());
        assert!(!stale_release.exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn update_signature_message_is_artifact_scoped() {
        let request = test_request("2026-07-06T00:00:00Z");

        assert_eq!(
            update_signature_message(&request),
            format!(
                "0.1.3\n{}\nhttps://example.com/cybex-forge\n",
                "a".repeat(64)
            )
        );
    }

    #[tokio::test]
    async fn store_update_request_allows_retry_with_new_requested_at() {
        let (config, root) = test_config();
        let first = test_request("2026-07-06T00:00:00Z");
        let second = test_request("2026-07-06T00:01:00Z");

        store_update_request(&config, Some(first.clone()))
            .await
            .unwrap();
        let first_status = read_status(&config).unwrap().unwrap();
        assert_eq!(first_status.status, "requested");
        assert_eq!(first_status.attempt_id, request_attempt_id(&first));

        write_status(
            &config,
            ForgeUpdateStatusReport {
                status: "failed".to_string(),
                stage: "failed".to_string(),
                progress_percent: Some(100),
                error: "simulated failure".to_string(),
                target_version: first.version.clone(),
                current_version: "v0.1.0".to_string(),
                attempt_id: first_status.attempt_id,
                started_at: Some("2026-07-06T00:00:00Z".to_string()),
                completed_at: Some("2026-07-06T00:00:30Z".to_string()),
            },
        )
        .unwrap();

        store_update_request(&config, Some(second.clone()))
            .await
            .unwrap();
        let retry_status = read_status(&config).unwrap().unwrap();
        assert_eq!(retry_status.status, "requested");
        assert_eq!(retry_status.stage, "queued");
        assert_eq!(retry_status.attempt_id, request_attempt_id(&second));
        assert_ne!(retry_status.attempt_id, request_attempt_id(&first));

        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn equal_update_is_reported_as_unsupported_without_artifact_mutation() {
        let (config, root) = test_config();
        let mut request = test_request("2026-07-06T00:00:00Z");
        request.version = env!("CARGO_PKG_VERSION").to_string();

        store_update_request(&config, Some(request.clone()))
            .await
            .unwrap();

        let status = read_status(&config).unwrap().unwrap();
        assert_eq!(status.status, "unsupported");
        assert_eq!(status.stage, "version_policy");
        assert_eq!(status.target_version, request.version);
        assert_eq!(status.attempt_id, request_attempt_id(&request));
        assert!(status.error.contains("not newer"));
        assert!(!config.update.releases_dir.exists());
        assert!(request_path(&config).is_file());
        let _ = fs::remove_dir_all(root);
    }
}
