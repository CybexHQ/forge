#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{
    fs, io,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::{SecondsFormat, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::{fs as tokio_fs, io::AsyncWriteExt, time::sleep};

use crate::{config::AppConfig, db};

const REQUEST_FILE: &str = "request.json";
const STATUS_FILE: &str = "status.json";
const LOCK_FILE: &str = "apply.lock";
const RELEASE_SCHEMA: &str = "cybex.forge.update-request.v1";

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

struct UpdateLock {
    path: PathBuf,
}

impl Drop for UpdateLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

pub fn capabilities_enabled(config: &AppConfig) -> bool {
    config.update.enabled
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
    ensure_update_dirs(config)?;

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

pub async fn apply_requested_update(config: &AppConfig) -> Result<()> {
    if !config.update.enabled {
        return Ok(());
    }
    ensure_update_dirs(config)?;
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
            return Ok(());
        }
    }

    let Some(_lock) = try_acquire_lock(config)? else {
        return Ok(());
    };

    let started_at = now_rfc3339();
    let attempt_id = request_attempt_id(&request);
    let apply_result =
        apply_requested_update_inner(config, &request, &attempt_id, &started_at).await;
    prune_stale_update_files(config, &attempt_id, &request.version);
    if let Err(err) = apply_result {
        write_status(
            config,
            ForgeUpdateStatusReport {
                status: "failed".to_string(),
                stage: "failed".to_string(),
                progress_percent: Some(100),
                error: err.to_string(),
                target_version: request.version,
                current_version: env!("CARGO_PKG_VERSION").to_string(),
                attempt_id,
                started_at: Some(started_at),
                completed_at: Some(now_rfc3339()),
            },
        )?;
    }
    Ok(())
}

async fn apply_requested_update_inner(
    config: &AppConfig,
    request: &ManagedUpdateRequest,
    attempt_id: &str,
    started_at: &str,
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
    smoke_test_binary(config, &staged)?;

    let backup = backup_current_binary(config, attempt_id)?;
    write_progress(config, request, attempt_id, started_at, "applying", 82, "")?;
    install_binary(config, &staged)?;

    write_progress(
        config,
        request,
        attempt_id,
        started_at,
        "restarting",
        88,
        "",
    )?;
    restart_service(config)?;

    write_progress(
        config,
        request,
        attempt_id,
        started_at,
        "health_checking",
        94,
        "",
    )?;
    if let Err(err) = wait_for_health(config).await {
        restore_binary(config, &backup)?;
        let _ = restart_service(config);
        write_status(
            config,
            ForgeUpdateStatusReport {
                status: "rolled_back".to_string(),
                stage: "rolled_back".to_string(),
                progress_percent: Some(100),
                error: format!("health check failed after update; rolled back: {err}"),
                target_version: request.version.clone(),
                current_version: env!("CARGO_PKG_VERSION").to_string(),
                attempt_id: attempt_id.to_string(),
                started_at: Some(started_at.to_string()),
                completed_at: Some(now_rfc3339()),
            },
        )?;
        return Ok(());
    }

    write_status(
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
    )?;
    Ok(())
}

async fn download_artifact(config: &AppConfig, request: &ManagedUpdateRequest) -> Result<PathBuf> {
    let parsed = Url::parse(&request.artifact_url).context("parse update artifact URL")?;
    if !matches!(parsed.scheme(), "http" | "https") {
        bail!("update artifact URL must be http:// or https://");
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5 * 60))
        .connect_timeout(Duration::from_secs(15))
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
        &config.update.work_dir,
        config.update.max_artifact_size_bytes,
        "Forge update download",
    )?;
    let tmp_path = config.update.work_dir.join("artifact.download");
    let mut file = tokio_fs::File::create(&tmp_path)
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
    drop(file);

    let actual = format!("{:x}", hasher.finalize());
    if actual != request.sha256.to_ascii_lowercase() {
        bail!("update artifact sha256 mismatch");
    }
    Ok(tmp_path)
}

fn verify_signature(config: &AppConfig, request: &ManagedUpdateRequest) -> Result<()> {
    if config.update.trusted_public_key.trim().is_empty() {
        bail!(
            "update.trusted_public_key is not configured; refusing to apply an unverified Forge update (configure the trusted release key or set update.enabled = false)"
        );
    }
    if request.signature.trim().is_empty() {
        bail!("update signature is required");
    }
    let key_bytes = decode_b64(config.update.trusted_public_key.trim())
        .context("decode trusted update public key")?;
    let key_array: [u8; 32] = key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("trusted update public key must be Ed25519"))?;
    let key = VerifyingKey::from_bytes(&key_array).context("parse trusted update public key")?;
    let sig_bytes = decode_b64(request.signature.trim()).context("decode update signature")?;
    let signature = Signature::from_slice(&sig_bytes).context("parse update signature")?;
    let message = update_signature_message(request);
    key.verify(message.as_bytes(), &signature)
        .context("verify update signature")
}

fn stage_artifact(
    config: &AppConfig,
    request: &ManagedUpdateRequest,
    artifact: &Path,
) -> Result<PathBuf> {
    let filename = format!("cybex-forge-{}", safe_version_filename(&request.version));
    let staged = config.update.releases_dir.join(filename);
    let staged_tmp = config.update.work_dir.join("artifact.staged");
    fs::copy(artifact, &staged_tmp).with_context(|| format!("stage {}", staged_tmp.display()))?;
    set_executable(&staged_tmp)?;
    fs::rename(&staged_tmp, &staged).with_context(|| format!("publish {}", staged.display()))?;
    Ok(staged)
}

fn smoke_test_binary(config: &AppConfig, binary: &Path) -> Result<()> {
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

fn backup_current_binary(config: &AppConfig, attempt_id: &str) -> Result<PathBuf> {
    let backup = config
        .update
        .work_dir
        .join(format!("cybex-forge-backup-{attempt_id}"));
    fs::copy(&config.update.binary_path, &backup)
        .with_context(|| format!("backup {}", config.update.binary_path.display()))?;
    set_executable(&backup)?;
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
    fs::rename(&tmp, &config.update.binary_path)
        .with_context(|| format!("replace {}", config.update.binary_path.display()))?;
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
        (&config.update.work_dir, "cybex-forge-backup-", &keep_backup),
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
    fs::rename(&tmp, &config.update.binary_path)
        .with_context(|| format!("rollback {}", config.update.binary_path.display()))?;
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

fn write_status(config: &AppConfig, status: ForgeUpdateStatusReport) -> Result<()> {
    write_json_atomic(&status_path(config), &status)
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
    fs::write(&tmp, body).with_context(|| format!("write {}", tmp.display()))?;
    fs::rename(&tmp, path).with_context(|| format!("rename {}", path.display()))?;
    Ok(())
}

fn try_acquire_lock(config: &AppConfig) -> Result<Option<UpdateLock>> {
    let path = lock_path(config);
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
    {
        Ok(_) => Ok(Some(UpdateLock { path })),
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => Ok(None),
        Err(err) => Err(err).with_context(|| format!("create {}", path.display())),
    }
}

fn ensure_update_dirs(config: &AppConfig) -> Result<()> {
    fs::create_dir_all(&config.update.work_dir)
        .with_context(|| format!("create {}", config.update.work_dir.display()))?;
    fs::create_dir_all(&config.update.releases_dir)
        .with_context(|| format!("create {}", config.update.releases_dir.display()))?;
    Ok(())
}

fn validate_request(request: &ManagedUpdateRequest) -> Result<()> {
    if request.version.trim().is_empty()
        || request.version.len() > 128
        || request.version.contains('/')
        || request.version.contains('\\')
        || request
            .version
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace())
    {
        bail!("invalid update version");
    }
    let url = Url::parse(&request.artifact_url).context("parse update artifact URL")?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        bail!("update artifact URL must be absolute http:// or https://");
    }
    if request.sha256.len() != 64 || !request.sha256.chars().all(|ch| ch.is_ascii_hexdigit()) {
        bail!("update sha256 must be a 64-character hex digest");
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

fn lock_path(config: &AppConfig) -> PathBuf {
    config.update.work_dir.join(LOCK_FILE)
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

    fn test_request(requested_at: &str) -> ManagedUpdateRequest {
        ManagedUpdateRequest {
            version: "v0.1.1".to_string(),
            artifact_url: "https://example.com/cybex-forge".to_string(),
            sha256: "a".repeat(64),
            signature: String::new(),
            release_url: "https://example.com/releases/v0.1.1".to_string(),
            notes_url: "https://example.com/releases/v0.1.1".to_string(),
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
        config.update.work_dir = root.join("updates");
        config.update.releases_dir = root.join("releases");
        (config, root)
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
    fn verify_signature_requires_trusted_public_key() {
        let (config, _root) = test_config();
        assert!(config.update.trusted_public_key.trim().is_empty());
        let request = test_request("2026-07-06T00:00:00Z");

        let err = verify_signature(&config, &request).expect_err("must refuse unverified updates");
        assert!(err.to_string().contains("trusted_public_key"));
    }

    #[test]
    fn prune_stale_update_files_keeps_current_attempt_and_version() {
        let (config, root) = test_config();
        fs::create_dir_all(&config.update.work_dir).unwrap();
        fs::create_dir_all(&config.update.releases_dir).unwrap();
        let keep_backup = config.update.work_dir.join("cybex-forge-backup-current");
        let stale_backup = config.update.work_dir.join("cybex-forge-backup-old");
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
                "v0.1.1\n{}\nhttps://example.com/cybex-forge\n",
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
}
