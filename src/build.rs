use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, SecondsFormat, Utc};
use rand::{RngCore, rngs::OsRng};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::Command,
    sync::Mutex,
    time::{sleep, timeout},
};
use tracing::{info, warn};
use uuid::Uuid;

use crate::{
    AppState, cache,
    config::{AppConfig, BuildTargetConfig, pinned_nixpkgs_revision},
    db,
    models::BuildJob,
    redact::{contains_sensitive_key_value, redact_sensitive_key_values},
    system_release::{
        ForgeSystemReleaseProvenanceV1, RenderedSystemReleaseInputs,
        SYSTEM_RELEASE_BUILD_SPEC_SCHEMA_VERSION, SYSTEM_RELEASE_FORGE_PROTOCOL,
        SystemReleaseBuildSpecV3, SystemReleaseClosureManifestV1, SystemReleaseMarkerV3,
        SystemReleaseMaterialBundle, normalize_nar_hash, publish_system_release_evidence,
        render_system_release_inputs, sign_provenance, validate_store_path,
    },
};

const BLUEPRINT_BUILD_INPUT_KIND: &str = "blueprint_nixos_module";
const LEGACY_DESKTOP_EXPERIENCE_BUILD_INPUT_KIND: &str = "desktop_experience_nixos_module";
const MAX_GENERATED_NIX_BYTES: usize = 1024 * 1024;
const MAX_DESKTOP_MODULE_NIX_BYTES: usize = 1024 * 1024;
const MAX_BUILT_RELEASE_MARKER_BYTES: usize = 64 * 1024;
const BUILT_RELEASE_MARKER_RELATIVE_PATH: &str = "etc/cybex/system-release/release-marker.json";
const CAPACITY_ACCOUNTING_TOLERANCE_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildSpec {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    pub artifact_type: String,
    pub target: String,
    pub system: String,
    pub input_revision: String,
    pub input_config_hash: String,
    #[serde(default)]
    #[serde(alias = "desktop_experience_id")]
    pub blueprint_id: Option<String>,
    #[serde(default)]
    #[serde(alias = "desktop_experience_revision_id")]
    pub blueprint_revision_id: Option<String>,
    #[serde(default)]
    #[serde(alias = "desktop_experience_revision_config_hash")]
    pub blueprint_revision_config_hash: Option<String>,
    #[serde(default)]
    pub build_input: Option<BlueprintBuildInput>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlueprintBuildInput {
    pub kind: String,
    pub generated_nix: String,
    #[serde(default)]
    pub desktop_module_nix: Option<String>,
    #[serde(default)]
    pub expected_state: Option<Value>,
    #[serde(default)]
    #[serde(alias = "desktop_experience_name")]
    pub blueprint_name: Option<String>,
    #[serde(default)]
    #[serde(alias = "desktop_experience_revision")]
    pub blueprint_revision: Option<i64>,
}

#[derive(Clone, Debug)]
struct ValidatedBuildSpec {
    artifact_type: String,
    target: String,
    system: String,
    input_revision: String,
    input_config_hash: String,
    blueprint_id: Option<String>,
    blueprint_revision_id: Option<String>,
    blueprint_revision_config_hash: Option<String>,
    build_input: Option<ValidatedBlueprintBuildInput>,
    system_release: Option<SystemReleaseBuildSpecV3>,
}

#[derive(Clone, Debug)]
struct ValidatedBlueprintBuildInput {
    generated_nix: String,
    desktop_module_nix: Option<String>,
    expected_state: Option<Value>,
    blueprint_name: Option<String>,
    blueprint_revision: Option<i64>,
}

#[derive(Clone, Debug)]
struct NixBuildCommand {
    program: String,
    args: Vec<String>,
    out_link: PathBuf,
    input_dir: Option<PathBuf>,
    release_marker_sha256: Option<String>,
}

struct PrivateInputGuard(Option<PathBuf>);

impl PrivateInputGuard {
    fn for_command(command: &NixBuildCommand) -> Self {
        Self(command.input_dir.clone())
    }
}

impl Drop for PrivateInputGuard {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = fs::remove_dir_all(path);
        }
    }
}

#[derive(Clone, Debug)]
struct NixOutputInfo {
    output_path: String,
    output_sha256: String,
    output_size_bytes: i64,
    closure_size_bytes: i64,
}

#[derive(Clone, Debug)]
struct InspectedSystemReleaseOutput {
    closure: SystemReleaseClosureManifestV1,
    canonical_closure: Vec<u8>,
    closure_sha256: String,
    kernel_store_path: String,
    initrd_store_path: String,
    kernel_version: String,
    release_marker_sha256: String,
    nix_version: String,
    observed_nixpkgs_commit: String,
}

#[derive(Clone)]
struct SharedLog {
    inner: Arc<Mutex<SharedLogState>>,
    max_bytes: usize,
}

#[derive(Debug, Default)]
struct SharedLogState {
    text: String,
    redact_following: usize,
}

enum ProcessOutcome {
    Succeeded(i32),
    Failed(i32),
    Cancelled,
    TimedOut,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct BuildCapacity {
    memory_bytes: u64,
    swap_bytes: u64,
}

pub fn spawn(state: AppState) {
    if !state.config.build.enabled {
        return;
    }
    tokio::spawn(async move {
        match db::recover_running_build_jobs(
            &state.db,
            "Forge restarted while this build was running; mark failed for explicit retry.",
        )
        .await
        {
            Ok(count) if count > 0 => {
                warn!(count, "recovered stale running Forge build jobs");
            }
            Ok(_) => {}
            Err(err) => warn!(error = %err, "failed to recover running Forge build jobs"),
        }
        sweep_stale_job_dirs(&state.config).await;

        for worker_index in 0..state.config.build.max_concurrent_builds {
            let worker_state = state.clone();
            tokio::spawn(async move { worker_loop(worker_state, worker_index).await });
        }
    });
}

async fn worker_loop(state: AppState, worker_index: usize) {
    let mut claim_failures: u32 = 0;
    loop {
        match db::claim_next_build_job(&state.db).await {
            Ok(Some(job)) => {
                claim_failures = 0;
                let job_id = job.id;
                info!(job_id, worker_index, "claimed Forge build job");
                if let Err(err) = execute_claimed_job(&state, job).await {
                    warn!(error = %safe_error(&err), worker_index, "Forge build job execution failed");
                }
                cleanup_job_dirs(&state.config, job_id).await;
            }
            Ok(None) => {
                claim_failures = 0;
                sleep(Duration::from_secs(2)).await;
            }
            Err(err) => {
                claim_failures = claim_failures.saturating_add(1);
                let delay = (5u64 << claim_failures.saturating_sub(1).min(5)).min(120);
                warn!(error = %err, worker_index, retry_in_seconds = delay, "failed to claim Forge build job");
                sleep(Duration::from_secs(delay)).await;
            }
        }
    }
}

/// Remove a finished job's output dir (whose `result` out-link is an indirect
/// Nix gcroot pinning the build closure) and its generated flake input dir.
/// The out-link is only needed between build completion and cache export, so
/// once the job reaches a terminal state these must go or `/nix/store` grows
/// without bound.
async fn cleanup_job_dirs(config: &AppConfig, job_id: i64) {
    let job_dir = config.build.output_dir.join(format!("job-{job_id}"));
    let input_dir = config.build.work_dir.join(format!("job-{job_id}-input"));
    for dir in [job_dir, input_dir] {
        match tokio::fs::remove_dir_all(&dir).await {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                warn!(error = %err, path = %dir.display(), "failed to remove Forge build job directory");
            }
        }
    }
}

/// Remove job dirs left behind by earlier Forge runs. Runs once at startup,
/// after stale running jobs have been marked failed and before workers start,
/// so nothing under these names can be live.
async fn sweep_stale_job_dirs(config: &AppConfig) {
    let mut removed = 0usize;
    for (root, prefix, suffix) in [
        (&config.build.output_dir, "job-", ""),
        (&config.build.work_dir, "job-", "-input"),
    ] {
        let mut entries = match tokio::fs::read_dir(root).await {
            Ok(entries) => entries,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => {
                warn!(error = %err, path = %root.display(), "failed to scan Forge build directory");
                continue;
            }
        };
        while let Ok(Some(entry)) = entries.next_entry().await {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some(middle) = name
                .strip_prefix(prefix)
                .and_then(|rest| rest.strip_suffix(suffix))
            else {
                continue;
            };
            if middle.is_empty() || !middle.bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            match tokio::fs::remove_dir_all(entry.path()).await {
                Ok(()) => removed += 1,
                Err(err) => {
                    warn!(error = %err, path = %entry.path().display(), "failed to remove stale Forge build job directory");
                }
            }
        }
    }
    if removed > 0 {
        info!(removed, "removed stale Forge build job directories");
    }
}

async fn execute_claimed_job(state: &AppState, job: BuildJob) -> Result<()> {
    let spec = match validate_build_spec(&state.config, &job) {
        Ok(spec) => spec,
        Err(err) => {
            db::finish_build_job(
                &state.db,
                job.id,
                "failed",
                "",
                &format!("invalid build spec: {}", safe_error(&err)),
                "",
                "",
                0,
                None,
                Some(build_result_metadata(
                    &state.config,
                    &job,
                    None,
                    Some("invalid_build_spec"),
                )),
            )
            .await?;
            return Ok(());
        }
    };
    db::update_build_job_progress(
        &state.db,
        job.id,
        Some(8),
        "validating",
        "Build spec validated",
    )
    .await?;
    let target = match build_target(&state.config, &spec) {
        Ok(target) => target.clone(),
        Err(err) => {
            db::finish_build_job(
                &state.db,
                job.id,
                "failed",
                "",
                &format!("build target is not allowed: {}", safe_error(&err)),
                "",
                "",
                0,
                None,
                Some(build_result_metadata(
                    &state.config,
                    &job,
                    None,
                    Some("target_not_allowed"),
                )),
            )
            .await?;
            return Ok(());
        }
    };

    db::update_build_job_progress(
        &state.db,
        job.id,
        Some(12),
        "preparing",
        "Checking builder capacity and preparing inputs",
    )
    .await?;
    if let Err(err) = crate::disk::ensure_headroom(
        Path::new("/nix/store"),
        state.config.build.max_artifact_size_bytes,
        "Forge build",
    ) {
        db::finish_build_job(
            &state.db,
            job.id,
            "failed",
            "",
            &safe_error(&err),
            "",
            "",
            0,
            None,
            Some(build_result_metadata(
                &state.config,
                &job,
                Some(&target),
                Some("insufficient_disk_space"),
            )),
        )
        .await?;
        return Ok(());
    }
    let capacity = match build_capacity() {
        Ok(capacity) => capacity,
        Err(err) => {
            db::finish_build_job(
                &state.db,
                job.id,
                "failed",
                "",
                &format!(
                    "could not inspect Forge memory capacity: {}",
                    safe_error(&err)
                ),
                "",
                "",
                0,
                None,
                Some(build_result_metadata(
                    &state.config,
                    &job,
                    Some(&target),
                    Some("capacity_check_failed"),
                )),
            )
            .await?;
            return Ok(());
        }
    };
    let capacity_error = if !capacity_meets_minimum(
        capacity.memory_bytes,
        state.config.build.minimum_memory_bytes,
    ) {
        Some((
            "insufficient_memory",
            format!(
                "Forge requires at least {} bytes of memory for Build/Cache; detected {} bytes",
                state.config.build.minimum_memory_bytes, capacity.memory_bytes
            ),
        ))
    } else if !capacity_meets_minimum(capacity.swap_bytes, state.config.build.minimum_swap_bytes) {
        Some((
            "insufficient_swap",
            format!(
                "Forge requires at least {} bytes of emergency swap for Build/Cache; detected {} bytes",
                state.config.build.minimum_swap_bytes, capacity.swap_bytes
            ),
        ))
    } else {
        None
    };
    if let Some((error_kind, error)) = capacity_error {
        db::finish_build_job(
            &state.db,
            job.id,
            "failed",
            "",
            &error,
            "",
            "",
            0,
            None,
            Some(build_result_metadata(
                &state.config,
                &job,
                Some(&target),
                Some(error_kind),
            )),
        )
        .await?;
        return Ok(());
    }
    if let Err(err) = ensure_nix_daemon_available(&state.config).await {
        db::finish_build_job(
            &state.db,
            job.id,
            "failed",
            "",
            &format!("Nix daemon is unavailable: {}", safe_error(&err)),
            "",
            "",
            0,
            None,
            Some(build_result_metadata(
                &state.config,
                &job,
                Some(&target),
                Some("nix_daemon_unavailable"),
            )),
        )
        .await?;
        return Ok(());
    }

    let materials = if let Some(system_release) = spec.system_release.as_ref() {
        db::update_build_job_progress(
            &state.db,
            job.id,
            Some(18),
            "downloading",
            "Downloading content-addressed Blueprint materials",
        )
        .await?;
        match download_system_release_materials(&state.config, system_release).await {
            Ok(materials) => Some(materials),
            Err(err) => {
                db::finish_build_job(
                    &state.db,
                    job.id,
                    "failed",
                    "",
                    &format!("build material download failed: {}", safe_error(&err)),
                    "",
                    "",
                    0,
                    None,
                    Some(build_result_metadata(
                        &state.config,
                        &job,
                        Some(&target),
                        Some("material_download_failed"),
                    )),
                )
                .await?;
                return Ok(());
            }
        }
    } else {
        None
    };

    let command = match nix_build_command(&state.config, &target, &spec, job.id, materials.as_ref())
    {
        Ok(command) => command,
        Err(err) => {
            db::finish_build_job(
                &state.db,
                job.id,
                "failed",
                "",
                &format!("build input preparation failed: {}", safe_error(&err)),
                "",
                "",
                0,
                None,
                Some(build_result_metadata(
                    &state.config,
                    &job,
                    Some(&target),
                    Some("input_preparation_failed"),
                )),
            )
            .await?;
            return Ok(());
        }
    };
    let _private_input_guard = PrivateInputGuard::for_command(&command);
    let log = SharedLog::new(state.config.build.max_log_bytes);
    db::update_build_job_progress(
        &state.db,
        job.id,
        Some(25),
        "building",
        "Building NixOS closure",
    )
    .await?;
    let oom_kills_before = cgroup_oom_kill_count();
    let outcome = run_nix_build(&state.db, &job, &command, &log, &state.config).await?;
    let oom_kills_after = cgroup_oom_kill_count();
    let logs = log.snapshot().await;
    match outcome {
        ProcessOutcome::Succeeded(exit_code) => {
            db::update_build_job_progress(
                &state.db,
                job.id,
                Some(80),
                "inspecting",
                "Inspecting build output",
            )
            .await?;
            let output_info = match inspect_build_output(&state.config, &command).await {
                Ok(info) => info,
                Err(err) => {
                    db::finish_build_job(
                        &state.db,
                        job.id,
                        "failed",
                        &logs,
                        &format!("build output validation failed: {}", safe_error(&err)),
                        "",
                        "",
                        0,
                        Some(exit_code.into()),
                        Some(build_result_metadata(
                            &state.config,
                            &job,
                            Some(&target),
                            Some("output_validation_failed"),
                        )),
                    )
                    .await?;
                    return Ok(());
                }
            };
            if output_info.output_size_bytes as u64 > state.config.build.max_artifact_size_bytes {
                db::finish_build_job(
                    &state.db,
                    job.id,
                    "failed",
                    &logs,
                    "build output exceeded max_artifact_size_bytes",
                    &output_info.output_path,
                    &output_info.output_sha256,
                    output_info.output_size_bytes,
                    Some(exit_code.into()),
                    Some(build_result_metadata(
                        &state.config,
                        &job,
                        Some(&target),
                        Some("artifact_too_large"),
                    )),
                )
                .await?;
                return Ok(());
            }
            let inspected_system_release =
                if let Some(system_release) = spec.system_release.as_ref() {
                    match inspect_system_release_output(
                        &state.config,
                        &command,
                        system_release,
                        &output_info.output_path,
                    )
                    .await
                    {
                        Ok(inspected) => Some(inspected),
                        Err(err) => {
                            db::finish_build_job(
                                &state.db,
                                job.id,
                                "failed",
                                &logs,
                                &format!(
                                    "System Release closure validation failed: {}",
                                    safe_error(&err)
                                ),
                                &output_info.output_path,
                                &output_info.output_sha256,
                                output_info.output_size_bytes,
                                Some(exit_code.into()),
                                Some(build_result_metadata(
                                    &state.config,
                                    &job,
                                    Some(&target),
                                    Some("system_release_closure_invalid"),
                                )),
                            )
                            .await?;
                            return Ok(());
                        }
                    }
                } else {
                    None
                };
            db::update_build_job_progress(
                &state.db,
                job.id,
                Some(90),
                "exporting",
                "Exporting closure to Forge cache",
            )
            .await?;
            let cache_lease = match cache::acquire_mutation_lease(&state.config).await {
                Ok(lease) => lease,
                Err(err) => {
                    db::finish_build_job(
                        &state.db,
                        job.id,
                        "failed",
                        &logs,
                        &format!("cache publication lease failed: {}", safe_error(&err)),
                        &output_info.output_path,
                        &output_info.output_sha256,
                        output_info.output_size_bytes,
                        Some(exit_code.into()),
                        Some(build_result_metadata(
                            &state.config,
                            &job,
                            Some(&target),
                            Some("cache_publication_lease_failed"),
                        )),
                    )
                    .await?;
                    return Ok(());
                }
            };
            if let Some(system_release) = spec.system_release.as_ref() {
                if let Err(err) = cache::ensure_system_release_publication_allowed(
                    &state.config,
                    &system_release.release_id,
                    &cache_lease,
                ) {
                    db::finish_build_job(
                        &state.db,
                        job.id,
                        "failed",
                        &logs,
                        &format!("System Release publication blocked: {}", safe_error(&err)),
                        &output_info.output_path,
                        &output_info.output_sha256,
                        output_info.output_size_bytes,
                        Some(exit_code.into()),
                        Some(build_result_metadata(
                            &state.config,
                            &job,
                            Some(&target),
                            Some("system_release_fault_pending"),
                        )),
                    )
                    .await?;
                    return Ok(());
                }
            }
            let mut cached = match cache::export_output(
                &state.config,
                &job,
                &output_info.output_path,
                &output_info.output_sha256,
                output_info.closure_size_bytes,
                &cache_lease,
            )
            .await
            {
                Ok(artifact) => artifact,
                Err(err) => {
                    db::finish_build_job(
                        &state.db,
                        job.id,
                        "failed",
                        &logs,
                        &format!("cache export failed: {}", safe_error(&err)),
                        &output_info.output_path,
                        &output_info.output_sha256,
                        output_info.output_size_bytes,
                        Some(exit_code.into()),
                        Some(build_result_metadata(
                            &state.config,
                            &job,
                            Some(&target),
                            Some("cache_export_failed"),
                        )),
                    )
                    .await?;
                    return Ok(());
                }
            };
            let system_release_metadata = match (
                spec.system_release.as_ref(),
                inspected_system_release.as_ref(),
            ) {
                (Some(system_release), Some(inspected)) => {
                    match finalize_system_release_artifact(
                        &state.config,
                        &job,
                        system_release,
                        &output_info,
                        inspected,
                        &mut cached,
                        &cache_lease,
                    )
                    .await
                    {
                        Ok(metadata) => Some(metadata),
                        Err(err) => {
                            let _ = cache::sweep_to_recorded_artifacts_under_lease(
                                &state.db,
                                &state.config,
                                &cache_lease,
                            )
                            .await;
                            db::finish_build_job(
                                &state.db,
                                job.id,
                                "failed",
                                &logs,
                                &format!("System Release attestation failed: {}", safe_error(&err)),
                                &output_info.output_path,
                                &output_info.output_sha256,
                                output_info.output_size_bytes,
                                Some(exit_code.into()),
                                Some(build_result_metadata(
                                    &state.config,
                                    &job,
                                    Some(&target),
                                    Some("system_release_attestation_failed"),
                                )),
                            )
                            .await?;
                            return Ok(());
                        }
                    }
                }
                (None, None) => None,
                _ => {
                    let _ = cache::sweep_to_recorded_artifacts_under_lease(
                        &state.db,
                        &state.config,
                        &cache_lease,
                    )
                    .await;
                    db::finish_build_job(
                        &state.db,
                        job.id,
                        "failed",
                        &logs,
                        "System Release inspection state was inconsistent",
                        &output_info.output_path,
                        &output_info.output_sha256,
                        output_info.output_size_bytes,
                        Some(exit_code.into()),
                        Some(build_result_metadata(
                            &state.config,
                            &job,
                            Some(&target),
                            Some("system_release_inspection_inconsistent"),
                        )),
                    )
                    .await?;
                    return Ok(());
                }
            };
            merge_build_metadata(
                &mut cached.metadata,
                &build_result_metadata(&state.config, &job, Some(&target), None),
            );
            if let Some(metadata) = system_release_metadata.as_ref() {
                merge_build_metadata(&mut cached.metadata, metadata);
            }
            db::update_build_job_progress(
                &state.db,
                job.id,
                Some(96),
                "publishing",
                "Publishing cache artifact metadata",
            )
            .await?;
            cache::record_cached_artifact(
                &state.db,
                &state.config,
                &job,
                &spec.artifact_type,
                cached,
                &cache_lease,
            )
            .await?;
            drop(cache_lease);
            cache::enforce_retention(&state.db, &state.config).await?;
            let mut success_metadata = success_result_metadata(&state.config, &job, &target, &spec);
            if let Some(metadata) = system_release_metadata.as_ref() {
                merge_build_metadata(&mut success_metadata, metadata);
            }
            db::finish_build_job(
                &state.db,
                job.id,
                "succeeded",
                &logs,
                "",
                &output_info.output_path,
                &output_info.output_sha256,
                output_info.output_size_bytes,
                Some(exit_code.into()),
                Some(success_metadata),
            )
            .await?;
        }
        ProcessOutcome::Failed(exit_code) => {
            let oom_killed = oom_kills_after > oom_kills_before;
            let (error_kind, error) = classify_nix_build_failure(&logs, oom_killed);
            db::finish_build_job(
                &state.db,
                job.id,
                "failed",
                &logs,
                &error,
                "",
                "",
                0,
                Some(exit_code.into()),
                Some(build_result_metadata(
                    &state.config,
                    &job,
                    Some(&target),
                    Some(error_kind),
                )),
            )
            .await?;
        }
        ProcessOutcome::Cancelled => {
            db::finish_build_job(
                &state.db,
                job.id,
                "cancelled",
                &logs,
                "build cancelled by Manage",
                "",
                "",
                0,
                None,
                Some(build_result_metadata(
                    &state.config,
                    &job,
                    Some(&target),
                    Some("cancelled"),
                )),
            )
            .await?;
        }
        ProcessOutcome::TimedOut => {
            db::finish_build_job(
                &state.db,
                job.id,
                "failed",
                &logs,
                "build exceeded configured timeout",
                "",
                "",
                0,
                None,
                Some(build_result_metadata(
                    &state.config,
                    &job,
                    Some(&target),
                    Some("build_timeout"),
                )),
            )
            .await?;
        }
    }
    Ok(())
}

fn capacity_meets_minimum(actual: u64, minimum: u64) -> bool {
    actual >= minimum.saturating_sub(CAPACITY_ACCOUNTING_TOLERANCE_BYTES)
}

fn validate_build_spec(config: &AppConfig, job: &BuildJob) -> Result<ValidatedBuildSpec> {
    if job.build_spec.get("schema_version").and_then(Value::as_u64)
        == Some(u64::from(SYSTEM_RELEASE_BUILD_SPEC_SCHEMA_VERSION))
    {
        let spec = SystemReleaseBuildSpecV3::parse(job.build_spec.clone())?;
        if spec.artifact_type != job.requested_artifact_type
            || spec.target != job.target
            || spec.system != job.system
            || spec.input_revision != job.input_revision
            || spec.input_config_hash != job.input_config_hash
        {
            bail!("System Release BuildSpec does not match its immutable job row");
        }
        if !config
            .build
            .allowed_systems
            .iter()
            .any(|value| value == &spec.system)
        {
            bail!("System Release system is not allowed on this Forge node");
        }
        return Ok(ValidatedBuildSpec {
            artifact_type: spec.artifact_type.clone(),
            target: spec.target.clone(),
            system: spec.system.clone(),
            input_revision: spec.input_revision.clone(),
            input_config_hash: spec.input_config_hash.clone(),
            blueprint_id: Some(spec.blueprint.blueprint_id.clone()),
            blueprint_revision_id: Some(spec.blueprint.blueprint_revision_id.clone()),
            blueprint_revision_config_hash: Some(spec.blueprint.config_sha256.clone()),
            build_input: None,
            system_release: Some(spec),
        });
    }
    let spec: BuildSpec = serde_json::from_value(job.build_spec.clone())
        .context("build_spec does not match schema")?;
    if spec.schema_version != 1 {
        bail!("unsupported build spec schema_version");
    }
    let artifact_type = normalize_artifact_type(&spec.artifact_type)?;
    let target = normalize_target(&spec.target)?;
    let system = normalize_system(&spec.system)?;
    if !config
        .build
        .allowed_systems
        .iter()
        .any(|value| value == &system)
    {
        bail!("system is not allowed on this Forge node");
    }
    let input_revision = normalize_revision(&spec.input_revision)?;
    let input_config_hash = normalize_sha256(&spec.input_config_hash)?;
    if artifact_type != job.requested_artifact_type {
        bail!("build_spec artifact_type does not match job artifact type");
    }
    if target != job.target || system != job.system {
        bail!("build_spec target/system does not match job row");
    }
    if input_revision != job.input_revision || input_config_hash != job.input_config_hash {
        bail!("build_spec input revision/hash does not match job row");
    }
    let blueprint_id = spec
        .blueprint_id
        .map(|value| normalize_optional_uuidish("blueprint_id", &value))
        .transpose()?;
    let blueprint_revision_id = spec
        .blueprint_revision_id
        .map(|value| normalize_optional_uuidish("blueprint_revision_id", &value))
        .transpose()?;
    let blueprint_revision_config_hash = spec
        .blueprint_revision_config_hash
        .map(|value| normalize_sha256(&value))
        .transpose()?;
    let build_input = spec
        .build_input
        .map(validate_blueprint_build_input)
        .transpose()?;
    if build_input.is_some() && artifact_type != "nixos_closure" {
        bail!("blueprint build_input requires artifact_type nixos_closure");
    }
    Ok(ValidatedBuildSpec {
        artifact_type,
        target,
        system,
        input_revision,
        input_config_hash,
        blueprint_id,
        blueprint_revision_id,
        blueprint_revision_config_hash,
        build_input,
        system_release: None,
    })
}

fn validate_blueprint_build_input(
    input: BlueprintBuildInput,
) -> Result<ValidatedBlueprintBuildInput> {
    let kind = input.kind.trim();
    if !matches!(
        kind,
        BLUEPRINT_BUILD_INPUT_KIND | LEGACY_DESKTOP_EXPERIENCE_BUILD_INPUT_KIND
    ) {
        bail!("unsupported build_input kind");
    }
    if input.generated_nix.trim().is_empty() {
        bail!("build_input.generated_nix is required");
    }
    if input.generated_nix.len() > MAX_GENERATED_NIX_BYTES {
        bail!("build_input.generated_nix is too large");
    }
    if input.generated_nix.bytes().any(|byte| byte == 0) {
        bail!("build_input.generated_nix must not contain NUL bytes");
    }
    if let Some(desktop_module_nix) = input.desktop_module_nix.as_deref() {
        if desktop_module_nix.trim().is_empty() {
            bail!("build_input.desktop_module_nix must not be empty");
        }
        if desktop_module_nix.len() > MAX_DESKTOP_MODULE_NIX_BYTES {
            bail!("build_input.desktop_module_nix is too large");
        }
        if desktop_module_nix.bytes().any(|byte| byte == 0) {
            bail!("build_input.desktop_module_nix must not contain NUL bytes");
        }
        let expected_state = input
            .expected_state
            .as_ref()
            .and_then(Value::as_object)
            .ok_or_else(|| anyhow!("build_input.expected_state must be an object when desktop_module_nix is supplied"))?;
        let expected_state_schema = expected_state.get("schema").and_then(Value::as_str);
        if !matches!(
            expected_state_schema,
            Some(
                "cybex.blueprint.expected-state.v1"
                    | "cybex.blueprint.expected-state.v2"
                    | "cybex.blueprint.expected-state.v3"
            )
        ) {
            bail!(
                "build_input.expected_state schema {expected_state_schema:?} is unsupported; expected an immutable Cybex Blueprint expected-state v1, v2, or v3 artifact"
            );
        }
    } else if input.expected_state.is_some() {
        bail!("build_input.expected_state requires desktop_module_nix");
    }
    Ok(ValidatedBlueprintBuildInput {
        generated_nix: input.generated_nix,
        desktop_module_nix: input.desktop_module_nix,
        expected_state: input.expected_state,
        blueprint_name: input
            .blueprint_name
            .map(|value| bounded_metadata_text(&value, 200))
            .filter(|value| !value.is_empty()),
        blueprint_revision: input.blueprint_revision.filter(|value| *value > 0),
    })
}

fn build_target(config: &AppConfig, spec: &ValidatedBuildSpec) -> Result<BuildTargetConfig> {
    if let Some(system_release) = spec.system_release.as_ref() {
        return Ok(BuildTargetConfig {
            artifact_type: system_release.artifact_type.clone(),
            target: system_release.target.clone(),
            system: system_release.system.clone(),
            flake: format!("github:NixOS/nixpkgs/{}", system_release.nixpkgs_commit),
            attr: "system-release".to_string(),
        });
    }
    config
        .build
        .targets
        .iter()
        .find(|target| {
            target.artifact_type == spec.artifact_type
                && build_target_names_compatible(&target.target, &spec.target)
                && target.system == spec.system
        })
        .cloned()
        .ok_or_else(|| {
            anyhow!("no configured build target matched artifact_type, target, and system")
        })
}

fn build_target_names_compatible(configured: &str, requested: &str) -> bool {
    configured == requested
        || matches!(
            (configured, requested),
            ("desktop_experience", "blueprint") | ("blueprint", "desktop_experience")
        )
}

fn build_capacity() -> Result<BuildCapacity> {
    // Hardened systemd units may use ProcSubset=pid, which intentionally hides
    // /proc/meminfo. LXC virtualizes sysinfo(2), so keep it as the fallback
    // when the cgroup controller reports an unbounded root and procfs omits
    // the host-adjusted totals.
    let sysinfo = kernel_sysinfo_capacity();
    let memory_bytes = read_cgroup_limit("/sys/fs/cgroup/memory.max")?
        .or_else(|| read_meminfo_bytes("MemTotal"))
        .or_else(|| sysinfo.map(|capacity| capacity.memory_bytes))
        .ok_or_else(|| anyhow!("memory limit and MemTotal were unavailable"))?;
    let swap_bytes = read_cgroup_limit("/sys/fs/cgroup/memory.swap.max")?
        .or_else(|| read_meminfo_bytes("SwapTotal"))
        .or_else(|| sysinfo.map(|capacity| capacity.swap_bytes))
        .unwrap_or(0);
    Ok(BuildCapacity {
        memory_bytes,
        swap_bytes,
    })
}

fn kernel_sysinfo_capacity() -> Option<BuildCapacity> {
    let mut info = std::mem::MaybeUninit::<libc::sysinfo>::zeroed();
    // SAFETY: sysinfo(2) initializes the provided libc::sysinfo structure on
    // success, and we only assume initialization after checking its return.
    if unsafe { libc::sysinfo(info.as_mut_ptr()) } != 0 {
        return None;
    }
    let info = unsafe { info.assume_init() };
    Some(capacity_from_sysinfo_values(
        info.totalram,
        info.totalswap,
        u64::from(info.mem_unit),
    ))
}

fn capacity_from_sysinfo_values(totalram: u64, totalswap: u64, mem_unit: u64) -> BuildCapacity {
    BuildCapacity {
        memory_bytes: totalram.saturating_mul(mem_unit),
        swap_bytes: totalswap.saturating_mul(mem_unit),
    }
}

fn read_cgroup_limit(path: &str) -> Result<Option<u64>> {
    match fs::read_to_string(path) {
        Ok(raw) => parse_cgroup_limit(&raw).with_context(|| format!("parse cgroup limit {path}")),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).with_context(|| format!("read cgroup limit {path}")),
    }
}

fn parse_cgroup_limit(raw: &str) -> Result<Option<u64>> {
    let raw = raw.trim();
    if raw == "max" || raw.is_empty() {
        return Ok(None);
    }
    Ok(Some(raw.parse().context("cgroup limit is not an integer")?))
}

fn read_meminfo_bytes(field: &str) -> Option<u64> {
    let raw = fs::read_to_string("/proc/meminfo").ok()?;
    parse_meminfo_bytes(&raw, field)
}

fn parse_meminfo_bytes(raw: &str, field: &str) -> Option<u64> {
    let value_kib = raw.lines().find_map(|line| {
        let (name, rest) = line.split_once(':')?;
        if name != field {
            return None;
        }
        rest.split_whitespace().next()?.parse::<u64>().ok()
    })?;
    value_kib.checked_mul(1024)
}

fn cgroup_oom_kill_count() -> u64 {
    fs::read_to_string("/sys/fs/cgroup/memory.events")
        .ok()
        .and_then(|raw| parse_memory_event(&raw, "oom_kill"))
        .unwrap_or(0)
}

fn parse_memory_event(raw: &str, event: &str) -> Option<u64> {
    raw.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        (fields.next()? == event)
            .then(|| fields.next()?.parse::<u64>().ok())
            .flatten()
    })
}

fn classify_nix_build_failure(logs: &str, oom_killed: bool) -> (&'static str, String) {
    let lower = logs.to_ascii_lowercase();
    if lower.contains("daemon-socket")
        || lower.contains("cannot connect to socket")
        || lower.contains("error connecting to the nix daemon")
    {
        return (
            "nix_daemon_unavailable",
            "The Nix daemon is unavailable; restore nix-daemon.socket and retry".to_string(),
        );
    }
    if oom_killed || lower.contains("out of memory") || lower.contains("oom-kill") {
        return (
            "out_of_memory",
            "Forge exhausted its build memory; increase memory/swap or reduce max_build_cores"
                .to_string(),
        );
    }
    if lower.contains("no space left on device") || lower.contains("disk full") {
        return (
            "insufficient_disk_space",
            "Forge ran out of disk space while building the Nix closure".to_string(),
        );
    }
    if lower.contains("builder for '")
        || lower.contains("failed to build")
        || lower.contains("dependencies of derivation")
    {
        return (
            "package_build_failed",
            "A package in the pinned nixpkgs revision failed to build; inspect the bounded build log"
                .to_string(),
        );
    }
    (
        "nix_build_failed",
        "Nix failed to build the requested closure; inspect the bounded build log".to_string(),
    )
}

async fn ensure_nix_daemon_available(config: &AppConfig) -> Result<()> {
    let output = Command::new(&config.build.nix_binary)
        .args(["store", "ping", "--store", "daemon"])
        .output()
        .await
        .with_context(|| format!("run {} store ping", config.build.nix_binary))?;
    if !output.status.success() {
        bail!(
            "{}",
            String::from_utf8_lossy(&output.stderr)
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        );
    }
    Ok(())
}

fn build_result_metadata(
    config: &AppConfig,
    job: &BuildJob,
    target: Option<&BuildTargetConfig>,
    error_kind: Option<&str>,
) -> Value {
    let mut metadata = job.cache_metadata.as_object().cloned().unwrap_or_default();
    metadata.insert(
        "result_schema".to_string(),
        json!("cybex.forge.build.result.v1"),
    );
    metadata.insert(
        "max_build_cores".to_string(),
        json!(config.build.max_build_cores),
    );
    metadata.insert(
        "minimum_memory_bytes".to_string(),
        json!(config.build.minimum_memory_bytes),
    );
    metadata.insert(
        "minimum_swap_bytes".to_string(),
        json!(config.build.minimum_swap_bytes),
    );
    if let Some(target) = target {
        metadata.insert("nixpkgs_flake".to_string(), json!(target.flake));
        if let Ok(revision) = pinned_nixpkgs_revision(&target.flake) {
            metadata.insert("nixpkgs_revision".to_string(), json!(revision));
        }
    }
    if let Some(error_kind) = error_kind {
        metadata.insert("error_kind".to_string(), json!(error_kind));
    } else {
        metadata.remove("error_kind");
    }
    Value::Object(metadata)
}

fn success_result_metadata(
    config: &AppConfig,
    job: &BuildJob,
    target: &BuildTargetConfig,
    spec: &ValidatedBuildSpec,
) -> Value {
    let mut metadata = build_result_metadata(config, job, Some(target), None);
    let Some(object) = metadata.as_object_mut() else {
        return metadata;
    };
    object.insert("target".to_string(), json!(spec.target));
    object.insert("system".to_string(), json!(spec.system));
    object.insert("input_revision".to_string(), json!(spec.input_revision));
    object.insert(
        "input_config_hash".to_string(),
        json!(spec.input_config_hash),
    );
    object.insert("blueprint_id".to_string(), json!(spec.blueprint_id));
    object.insert(
        "blueprint_revision_id".to_string(),
        json!(spec.blueprint_revision_id),
    );
    object.insert(
        "blueprint_revision_config_hash".to_string(),
        json!(spec.blueprint_revision_config_hash),
    );
    object.insert(
        "build_input_kind".to_string(),
        json!(
            spec.build_input
                .as_ref()
                .map(|_| BLUEPRINT_BUILD_INPUT_KIND)
        ),
    );
    object.insert("cache".to_string(), json!("exported"));
    metadata
}

fn merge_build_metadata(destination: &mut Value, source: &Value) {
    let Some(source) = source.as_object() else {
        return;
    };
    let Some(destination) = destination.as_object_mut() else {
        return;
    };
    for (key, value) in source {
        destination.insert(key.clone(), value.clone());
    }
}

async fn download_system_release_materials(
    config: &AppConfig,
    spec: &SystemReleaseBuildSpecV3,
) -> Result<SystemReleaseMaterialBundle> {
    let compiled_blueprint = crate::manage::download_system_release_material(
        config,
        &spec.blueprint.compiled_module_sha256,
    )
    .await?;
    let asset_digests = spec
        .blueprint
        .asset_manifest
        .get("assets")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("BuildSpec Blueprint asset manifest is malformed"))?
        .iter()
        .map(|asset| {
            asset
                .get("sha256")
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or_else(|| anyhow!("BuildSpec Blueprint asset digest is missing"))
        })
        .collect::<Result<BTreeSet<_>>>()?;
    let extension_digests = spec
        .blueprint
        .extension_manifest
        .get("modules")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("BuildSpec Blueprint extension manifest is malformed"))?
        .iter()
        .map(|module| {
            module
                .get("sha256")
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or_else(|| anyhow!("BuildSpec Blueprint extension digest is missing"))
        })
        .collect::<Result<BTreeSet<_>>>()?;
    let mut assets = BTreeMap::new();
    for digest in asset_digests {
        assets.insert(
            digest.clone(),
            crate::manage::download_system_release_material(config, &digest).await?,
        );
    }
    let mut extensions = BTreeMap::new();
    for digest in extension_digests {
        extensions.insert(
            digest.clone(),
            crate::manage::download_system_release_material(config, &digest).await?,
        );
    }
    Ok(SystemReleaseMaterialBundle {
        compiled_blueprint,
        assets,
        extensions,
    })
}

fn nix_build_command(
    config: &AppConfig,
    target: &BuildTargetConfig,
    spec: &ValidatedBuildSpec,
    job_id: i64,
    materials: Option<&SystemReleaseMaterialBundle>,
) -> Result<NixBuildCommand> {
    if let Some(system_release) = spec.system_release.as_ref() {
        return system_release_nix_build_command(
            config,
            spec,
            system_release,
            job_id,
            materials.ok_or_else(|| anyhow!("System Release material bundle is missing"))?,
        );
    }
    if let Some(build_input) = spec.build_input.as_ref() {
        return blueprint_nix_build_command(config, target, spec, build_input, job_id);
    }
    let job_dir = config.build.output_dir.join(format!("job-{job_id}"));
    let out_link = job_dir.join("result");
    let installable = format!("{}#{}", target.flake, target.attr);
    Ok(NixBuildCommand {
        program: config.build.nix_binary.clone(),
        args: vec![
            "build".to_string(),
            installable,
            "--cores".to_string(),
            config.build.max_build_cores.to_string(),
            "--system".to_string(),
            spec.system.clone(),
            "--out-link".to_string(),
            out_link.display().to_string(),
            "--print-build-logs".to_string(),
            "--no-write-lock-file".to_string(),
        ],
        out_link,
        input_dir: None,
        release_marker_sha256: None,
    })
}

fn system_release_nix_build_command(
    config: &AppConfig,
    spec: &ValidatedBuildSpec,
    system_release: &SystemReleaseBuildSpecV3,
    job_id: i64,
    materials: &SystemReleaseMaterialBundle,
) -> Result<NixBuildCommand> {
    if spec.artifact_type != "system_generation"
        || spec.target != "system_release"
        || spec.system != system_release.system
    {
        bail!("System Release target binding is inconsistent");
    }
    let rendered = render_system_release_inputs(config, system_release, materials)?;
    let input_dir = config.build.work_dir.join(format!("job-{job_id}-input"));
    write_private_job_inputs(&input_dir, &rendered)?;
    let job_dir = config.build.output_dir.join(format!("job-{job_id}"));
    let out_link = job_dir.join("result");
    Ok(NixBuildCommand {
        program: config.build.nix_binary.clone(),
        args: vec![
            "build".to_string(),
            format!("{}#system-release", input_dir.display()),
            "--cores".to_string(),
            config.build.max_build_cores.to_string(),
            "--system".to_string(),
            system_release.system.clone(),
            "--out-link".to_string(),
            out_link.display().to_string(),
            "--print-build-logs".to_string(),
            "--no-write-lock-file".to_string(),
        ],
        out_link,
        input_dir: Some(input_dir),
        release_marker_sha256: Some(rendered.release_marker_sha256),
    })
}

fn write_private_job_inputs(dir: &Path, rendered: &RenderedSystemReleaseInputs) -> Result<()> {
    if let Some(parent) = dir.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create build work directory {}", parent.display()))?;
        let metadata = fs::symlink_metadata(parent)?;
        let effective_uid = unsafe { libc::geteuid() };
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || (metadata.uid() != 0 && metadata.uid() != effective_uid)
            || metadata.permissions().mode() & 0o022 != 0
        {
            bail!("build work directory ownership or mode is unsafe");
        }
    }
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder
        .create(dir)
        .with_context(|| format!("create private build input directory {}", dir.display()))?;
    let result = (|| {
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        for input in &rendered.files {
            atomic_write_job_input(&dir.join(&input.name), &input.bytes, input.mode)?;
        }
        File::open(dir)
            .with_context(|| format!("open private build input directory {}", dir.display()))?
            .sync_all()
            .with_context(|| format!("sync private build input directory {}", dir.display()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(dir);
    }
    result
}

fn atomic_write_job_input(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("build input path has no parent"))?;
    let name = path
        .file_name()
        .ok_or_else(|| anyhow!("build input path has no filename"))?
        .to_string_lossy();
    let mut random = [0u8; 8];
    OsRng.fill_bytes(&mut random);
    let temporary = parent.join(format!(
        ".{name}.{}.{}.tmp",
        std::process::id(),
        hex::encode(random)
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(mode)
            .open(&temporary)
            .with_context(|| format!("create private build input {}", temporary.display()))?;
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        file.write_all(contents)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)
            .with_context(|| format!("publish private build input {}", path.display()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn blueprint_nix_build_command(
    config: &AppConfig,
    target: &BuildTargetConfig,
    spec: &ValidatedBuildSpec,
    build_input: &ValidatedBlueprintBuildInput,
    job_id: i64,
) -> Result<NixBuildCommand> {
    let input_dir = config.build.work_dir.join(format!("job-{job_id}-input"));
    fs::create_dir_all(&input_dir)
        .with_context(|| format!("create build input directory {}", input_dir.display()))?;
    write_job_input_file(input_dir.join("blueprint.nix"), &build_input.generated_nix)?;
    if let Some(desktop_module_nix) = build_input.desktop_module_nix.as_deref() {
        write_job_input_file(input_dir.join("cybex-blueprints.nix"), desktop_module_nix)?;
    }
    if let Some(expected_state) = build_input.expected_state.as_ref() {
        let expected_state = serde_json::to_string_pretty(expected_state)
            .context("serialize Blueprint expected state")?;
        write_job_input_file(input_dir.join("expected-state.json"), &expected_state)?;
    }
    write_job_input_file(
        input_dir.join("cybex-compat-options.nix"),
        blueprint_compat_module(build_input.desktop_module_nix.is_some()),
    )?;
    write_job_input_file(
        input_dir.join("configuration.nix"),
        &forge_nixos_configuration(build_input.desktop_module_nix.is_some()),
    )?;
    write_job_input_file(
        input_dir.join("flake.nix"),
        &forge_nixos_flake(&target.flake, &spec.system, build_input),
    )?;

    let job_dir = config.build.output_dir.join(format!("job-{job_id}"));
    let out_link = job_dir.join("result");
    let installable = format!("{}#{}", input_dir.display(), target.attr);
    Ok(NixBuildCommand {
        program: config.build.nix_binary.clone(),
        args: vec![
            "build".to_string(),
            installable,
            "--cores".to_string(),
            config.build.max_build_cores.to_string(),
            "--out-link".to_string(),
            out_link.display().to_string(),
            "--print-build-logs".to_string(),
            "--no-write-lock-file".to_string(),
        ],
        out_link,
        input_dir: Some(input_dir),
        release_marker_sha256: None,
    })
}

fn write_job_input_file(path: PathBuf, contents: &str) -> Result<()> {
    fs::write(&path, contents).with_context(|| format!("write build input {}", path.display()))
}

fn forge_nixos_flake(
    nixpkgs_flake: &str,
    system: &str,
    build_input: &ValidatedBlueprintBuildInput,
) -> String {
    let name = build_input.blueprint_name.as_deref().unwrap_or("Blueprint");
    let revision = build_input
        .blueprint_revision
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let description = serde_json::to_string(&format!(
        "Cybex Forge Blueprint build: {name} rev {revision}"
    ))
    .unwrap_or_else(|_| "\"Cybex Forge Blueprint build\"".to_string());
    let nixpkgs_flake =
        serde_json::to_string(nixpkgs_flake).unwrap_or_else(|_| "\"nixpkgs\"".to_string());
    format!(
        r#"{{
  description = {description};

  inputs.nixpkgs.url = {nixpkgs_flake};

  outputs = {{ self, nixpkgs }}:
    let
      system = "{system}";
    in {{
      packages.${{system}}.desktop-experience =
        (nixpkgs.lib.nixosSystem {{
          inherit system;
          modules = [
            ./configuration.nix
          ];
        }}).config.system.build.toplevel;
    }};
}}
"#
    )
}

fn forge_nixos_configuration(include_desktop_module: bool) -> String {
    let desktop_module_import = if include_desktop_module {
        "    ./cybex-blueprints.nix\n"
    } else {
        ""
    };
    r#"{ lib, modulesPath, ... }:

{
  imports = [
    ./cybex-compat-options.nix
@DESKTOP_MODULE_IMPORT@
    ./blueprint.nix
  ];

  system.stateVersion = lib.mkDefault lib.trivial.release;
  networking.hostName = lib.mkDefault "cybex-forge-build";
  networking.useDHCP = lib.mkDefault true;

  fileSystems."/" = {
    device = "none";
    fsType = "tmpfs";
  };

  boot.loader.grub.enable = lib.mkDefault false;
  boot.loader.systemd-boot.enable = lib.mkDefault false;
  boot.initrd.enable = lib.mkForce false;
  boot.initrd.systemd.enable = lib.mkDefault false;
  boot.initrd.includeDefaultModules = false;
  boot.initrd.availableKernelModules = lib.mkForce [];
  boot.initrd.kernelModules = lib.mkForce [];
  boot.kernelModules = lib.mkForce [];
  boot.extraModulePackages = lib.mkForce [];
  security.lockKernelModules = lib.mkForce false;
  systemd.services.systemd-udevd.restartTriggers = lib.mkForce [];
}
"#
    .replace("@DESKTOP_MODULE_IMPORT@\n", desktop_module_import)
}

fn blueprint_compat_module(include_desktop_module: bool) -> &'static str {
    if !include_desktop_module {
        return r#"{ lib, ... }:

{
  options.cybex = lib.mkOption {
    type = lib.types.attrsOf lib.types.anything;
    default = {};
    description = "Cybex Blueprint metadata accepted while Forge prebuilds a generic NixOS closure.";
  };

  options.services.cybex-agent = lib.mkOption {
    type = lib.types.attrsOf lib.types.anything;
    default = {};
    description = "Cybex Agent policy accepted while Forge prebuilds a generic NixOS closure.";
  };
}
"#;
    }
    r#"{ lib, ... }:

{
  imports = [
    (lib.mkAliasOptionModule
      [ "cybex" "catalog" "applications" ]
      [ "cybex" "blueprint" "applications" ])
  ];

  options.cybex.desktop.environment = lib.mkOption {
    type = lib.types.str;
    default = "";
    description = "Cybex desktop environment metadata from the assigned Blueprint.";
  };

  options.cybex.blueprint.applications = lib.mkOption {
    type = lib.types.attrsOf (lib.types.submodule {
      options = {
        package = lib.mkOption { type = lib.types.str; default = ""; };
        source = lib.mkOption { type = lib.types.str; default = ""; };
        policy = lib.mkOption { type = lib.types.str; default = ""; };
        channel = lib.mkOption { type = lib.types.str; default = ""; };
        version = lib.mkOption { type = lib.types.nullOr lib.types.str; default = null; };
        pinned = lib.mkOption { type = lib.types.bool; default = false; };
      };
    });
    default = {};
    description = "Cybex application metadata from the assigned Blueprint.";
  };

  options.cybex.security.luks.enable = lib.mkOption {
    type = lib.types.bool;
    default = false;
    description = "Cybex disk-encryption intent metadata.";
  };

  options.services.cybex-agent = lib.mkOption {
    type = lib.types.attrsOf lib.types.anything;
    default = {};
    description = "Cybex Agent policy accepted while Forge prebuilds a generic NixOS closure.";
  };
}
"#
}

async fn run_nix_build(
    pool: &sqlx::SqlitePool,
    job: &BuildJob,
    command: &NixBuildCommand,
    log: &SharedLog,
    config: &AppConfig,
) -> Result<ProcessOutcome> {
    if let Some(parent) = command.out_link.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("create build output directory {}", parent.display()))?;
    }
    tokio::fs::create_dir_all(&config.build.work_dir)
        .await
        .with_context(|| {
            format!(
                "create build work directory {}",
                config.build.work_dir.display()
            )
        })?;
    let mut child = Command::new(&command.program)
        .args(&command.args)
        .current_dir(&config.build.work_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawn {}", command.program))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("nix build stdout was not captured"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow!("nix build stderr was not captured"))?;
    let stdout_log = log.clone();
    let stderr_log = log.clone();
    let stdout_task = tokio::spawn(async move { read_log_stream(stdout, stdout_log).await });
    let stderr_task = tokio::spawn(async move { read_log_stream(stderr, stderr_log).await });
    let started = Instant::now();
    let mut last_log_update = Instant::now();
    let outcome = loop {
        if db::build_job_cancel_requested(pool, job.id).await? {
            terminate_child(&mut child);
            let _ = timeout(
                Duration::from_secs(config.build.cancel_grace_seconds),
                child.wait(),
            )
            .await;
            let _ = child.kill().await;
            break ProcessOutcome::Cancelled;
        }
        if started.elapsed() >= Duration::from_secs(config.build.timeout_seconds) {
            terminate_child(&mut child);
            let _ = timeout(
                Duration::from_secs(config.build.cancel_grace_seconds),
                child.wait(),
            )
            .await;
            let _ = child.kill().await;
            break ProcessOutcome::TimedOut;
        }
        if let Some(status) = child.try_wait().context("poll nix build child")? {
            let code = status.code().unwrap_or(-1);
            break if status.success() {
                ProcessOutcome::Succeeded(code)
            } else {
                ProcessOutcome::Failed(code)
            };
        }
        if last_log_update.elapsed() >= Duration::from_secs(5) {
            db::update_build_job_logs(pool, job.id, &log.snapshot().await).await?;
            last_log_update = Instant::now();
        }
        sleep(Duration::from_millis(500)).await;
    };
    let _ = stdout_task.await;
    let _ = stderr_task.await;
    db::update_build_job_logs(pool, job.id, &log.snapshot().await).await?;
    Ok(outcome)
}

async fn inspect_build_output(
    config: &AppConfig,
    command: &NixBuildCommand,
) -> Result<NixOutputInfo> {
    let output_path = tokio::fs::read_link(&command.out_link)
        .await
        .with_context(|| format!("read build out-link {}", command.out_link.display()))?;
    let output_path = output_path
        .to_str()
        .ok_or_else(|| anyhow!("build output path is not UTF-8"))?
        .to_string();
    if !output_path.starts_with("/nix/store/") {
        bail!("build output path was not in /nix/store");
    }
    let output_sha256 = run_nix_hash(config, &output_path).await?;
    let (output_size_bytes, closure_size_bytes) = run_nix_path_info(config, &output_path).await?;
    Ok(NixOutputInfo {
        output_path,
        output_sha256,
        output_size_bytes,
        closure_size_bytes,
    })
}

async fn inspect_system_release_output(
    config: &AppConfig,
    command: &NixBuildCommand,
    spec: &SystemReleaseBuildSpecV3,
    output_path: &str,
) -> Result<InspectedSystemReleaseOutput> {
    let output = Command::new(&config.build.nix_binary)
        .args(["path-info", "--json", "--recursive", output_path])
        .output()
        .await
        .with_context(|| format!("run {} recursive path-info", config.build.nix_binary))?;
    if !output.status.success() {
        bail!(
            "recursive nix path-info failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let value: Value =
        serde_json::from_slice(&output.stdout).context("parse recursive nix path-info JSON")?;
    let closure = SystemReleaseClosureManifestV1::from_nix_path_info(spec, output_path, &value)?;
    let canonical_closure = closure.canonical_bytes()?;
    let closure_sha256 = sha256_hex(&canonical_closure);
    let (kernel_store_path, initrd_store_path, kernel_version) =
        inspect_system_generation_paths(output_path).await?;
    let release_marker_sha256 = inspect_built_release_marker(output_path, spec, &closure).await?;
    if command.release_marker_sha256.as_deref() != Some(release_marker_sha256.as_str()) {
        bail!("built System Release marker digest differs from the rendered build input");
    }
    let nix_version = observed_nix_version(config).await?;
    let input_dir = command
        .input_dir
        .as_deref()
        .ok_or_else(|| anyhow!("System Release build omitted its private flake input"))?;
    let observed_nixpkgs_commit = observed_nixpkgs_commit(config, input_dir).await?;
    if observed_nixpkgs_commit != spec.nixpkgs_commit {
        bail!("observed nixpkgs revision differs from the BuildSpec pin");
    }
    Ok(InspectedSystemReleaseOutput {
        closure,
        canonical_closure,
        closure_sha256,
        kernel_store_path,
        initrd_store_path,
        kernel_version,
        release_marker_sha256,
        nix_version,
        observed_nixpkgs_commit,
    })
}

fn verify_built_release_marker_bytes(expected: &[u8], bytes: &[u8]) -> Result<String> {
    if bytes.is_empty() || bytes.len() > MAX_BUILT_RELEASE_MARKER_BYTES {
        bail!("built System Release marker has an invalid size");
    }
    if bytes != expected {
        bail!("built System Release marker differs from the exact BuildSpec marker");
    }
    Ok(sha256_hex(bytes))
}

async fn inspect_built_release_marker(
    output_path: &str,
    spec: &SystemReleaseBuildSpecV3,
    closure: &SystemReleaseClosureManifestV1,
) -> Result<String> {
    let marker_path = Path::new(output_path).join(BUILT_RELEASE_MARKER_RELATIVE_PATH);
    let resolved = tokio::fs::canonicalize(&marker_path)
        .await
        .context("resolve built System Release marker")?;
    let marker_store_path = enclosing_store_path(&resolved)?;
    if !closure
        .members
        .iter()
        .any(|member| member.store_path == marker_store_path)
    {
        bail!("built System Release marker is outside the inspected closure");
    }
    let file = tokio::fs::File::open(&resolved)
        .await
        .context("open built System Release marker")?;
    let metadata = file
        .metadata()
        .await
        .context("inspect built System Release marker")?;
    if !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_BUILT_RELEASE_MARKER_BYTES as u64
    {
        bail!("built System Release marker is not a bounded regular file");
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take((MAX_BUILT_RELEASE_MARKER_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .await
        .context("read built System Release marker")?;
    let expected = SystemReleaseMarkerV3::from_spec(spec)?.canonical_bytes()?;
    verify_built_release_marker_bytes(&expected, &bytes)
}

async fn inspect_system_generation_paths(output_path: &str) -> Result<(String, String, String)> {
    let target = Path::new(output_path);
    let kernel = tokio::fs::canonicalize(target.join("kernel"))
        .await
        .context("resolve System Release kernel")?;
    let initrd = tokio::fs::canonicalize(target.join("initrd"))
        .await
        .context("resolve System Release initrd")?;
    let kernel_store_path = enclosing_store_path(&kernel)?;
    let initrd_store_path = enclosing_store_path(&initrd)?;
    let modules = target.join("kernel-modules/lib/modules");
    let mut entries = tokio::fs::read_dir(&modules)
        .await
        .with_context(|| format!("read kernel module directory {}", modules.display()))?;
    let mut versions = Vec::new();
    while let Some(entry) = entries.next_entry().await? {
        if entry.file_type().await?.is_dir() {
            versions.push(
                entry
                    .file_name()
                    .to_str()
                    .ok_or_else(|| anyhow!("kernel version is not UTF-8"))?
                    .to_string(),
            );
        }
    }
    versions.sort();
    if versions.len() != 1
        || versions[0].is_empty()
        || versions[0].len() > 128
        || versions[0].chars().any(char::is_control)
    {
        bail!("System Release output did not contain exactly one safe kernel version");
    }
    Ok((kernel_store_path, initrd_store_path, versions.remove(0)))
}

fn enclosing_store_path(path: &Path) -> Result<String> {
    let relative = path
        .strip_prefix("/nix/store")
        .context("System Release component is outside the Nix store")?;
    let component = relative
        .components()
        .next()
        .ok_or_else(|| anyhow!("System Release component omitted a store object"))?;
    let std::path::Component::Normal(component) = component else {
        bail!("System Release component has an invalid store path");
    };
    let component = component
        .to_str()
        .ok_or_else(|| anyhow!("System Release store component is not UTF-8"))?;
    let store_path = format!("/nix/store/{component}");
    validate_store_path(&store_path)?;
    Ok(store_path)
}

async fn observed_nix_version(config: &AppConfig) -> Result<String> {
    let output = Command::new(&config.build.nix_binary)
        .arg("--version")
        .output()
        .await
        .with_context(|| format!("run {} --version", config.build.nix_binary))?;
    if !output.status.success() {
        bail!("could not observe Nix version");
    }
    let text = String::from_utf8(output.stdout)
        .context("Nix version output is not UTF-8")?
        .trim()
        .to_string();
    let version = text
        .strip_prefix("nix (Nix) ")
        .or_else(|| text.strip_prefix("nix "))
        .ok_or_else(|| anyhow!("Nix version output has an unsupported shape"))?;
    if version.is_empty()
        || version.len() > 128
        || !version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-'))
    {
        bail!("observed Nix version is unsafe");
    }
    Ok(version.to_string())
}

async fn observed_nixpkgs_commit(config: &AppConfig, input_dir: &Path) -> Result<String> {
    let output = Command::new(&config.build.nix_binary)
        .args(["flake", "metadata", "--json", "--no-write-lock-file"])
        .arg(input_dir)
        .output()
        .await
        .with_context(|| format!("inspect System Release flake {}", input_dir.display()))?;
    if !output.status.success() {
        bail!(
            "nix flake metadata failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let value: Value = serde_json::from_slice(&output.stdout).context("parse flake metadata")?;
    let revision = value
        .pointer("/locks/nodes/nixpkgs/locked/rev")
        .or_else(|| value.pointer("/locked/rev"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("flake metadata omitted the locked nixpkgs revision"))?;
    if revision.len() != 40
        || !revision
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("observed nixpkgs revision is not canonical lowercase hexadecimal");
    }
    Ok(revision.to_string())
}

async fn finalize_system_release_artifact(
    config: &AppConfig,
    job: &BuildJob,
    spec: &SystemReleaseBuildSpecV3,
    output: &NixOutputInfo,
    inspected: &InspectedSystemReleaseOutput,
    cached: &mut cache::CachedNixArtifact,
    cache_lease: &cache::CacheMutationLease,
) -> Result<Value> {
    cache::assert_mutation_lease(config, cache_lease)?;
    let managed_job_id = job
        .managed_job_id
        .as_deref()
        .ok_or_else(|| anyhow!("System Release build has no managed job UUID"))?;
    let managed_job_id = Uuid::parse_str(managed_job_id)
        .context("System Release managed job ID is not a UUID")?
        .hyphenated()
        .to_string();
    let artifact_id = Uuid::parse_str(&spec.forge_artifact_id)
        .context("System Release artifact ID is not a UUID")?
        .hyphenated()
        .to_string();
    if cached.store_path != output.output_path {
        bail!("cache export store path differs from the inspected generation");
    }
    let target = inspected.closure.target()?;
    let cached_nar_hash = normalize_nar_hash(&cached.nar_hash)?;
    if cached_nar_hash != target.nar_hash
        || u64::try_from(cached.nar_size_bytes).ok() != Some(target.nar_size_bytes)
    {
        bail!("cache export NAR identity differs from recursive Nix path-info");
    }
    let capability = crate::system_release::capability_context(config)?;
    let attestation = crate::system_release::load_attestation_identity(config)?;
    if capability.attestation_key_id != attestation.key_id {
        bail!("attestation identity changed during the build");
    }
    let cache_identity = cache::signing_identity(config)?;
    let started = canonical_build_time(
        job.started_at
            .as_deref()
            .ok_or_else(|| anyhow!("System Release build has no start time"))?,
    )?;
    let started_time = DateTime::parse_from_rfc3339(&started)?.with_timezone(&Utc);
    let completed = canonical_completion_time_after(started_time).await?;
    let build_spec_sha256 = spec.canonical_sha256()?;
    let mut forge_capabilities = vec![
        "boot_v1".to_string(),
        "builder_v1".to_string(),
        "cache_v1".to_string(),
        "system_release_builder_v3".to_string(),
    ];
    if crate::updater::capabilities_enabled(config) {
        forge_capabilities.push("updater_v1".to_string());
    }
    forge_capabilities.sort();
    let release_marker_sha256 = &inspected.release_marker_sha256;
    let provenance = ForgeSystemReleaseProvenanceV1 {
        schema: crate::system_release::SYSTEM_RELEASE_PROVENANCE_SCHEMA.to_string(),
        organization_id: spec.organization_id.clone(),
        release_id: spec.release_id.clone(),
        variant_id: spec.variant_id.clone(),
        forge_node_id: capability.forge_node_id.clone(),
        forge_build_job_id: managed_job_id.clone(),
        forge_artifact_id: artifact_id.clone(),
        forge_protocol: SYSTEM_RELEASE_FORGE_PROTOCOL,
        forge_version: env!("CARGO_PKG_VERSION").to_string(),
        forge_capabilities,
        nixpkgs_commit: inspected.observed_nixpkgs_commit.clone(),
        nix_version: inspected.nix_version.clone(),
        system: spec.system.clone(),
        baseline_version: spec.baseline_version.clone(),
        compiler_version: spec.compiler_version.clone(),
        input_manifest_sha256: spec.input_manifest_sha256.clone(),
        build_spec_sha256: build_spec_sha256.clone(),
        target_store_path: output.output_path.clone(),
        target_output_sha256: output.output_sha256.clone(),
        target_nar_hash: target.nar_hash.clone(),
        target_nar_size_bytes: target.nar_size_bytes,
        target_kernel_store_path: inspected.kernel_store_path.clone(),
        target_initrd_store_path: inspected.initrd_store_path.clone(),
        target_kernel_version: inspected.kernel_version.clone(),
        release_marker_sha256: release_marker_sha256.clone(),
        closure_digest_sha256: inspected.closure_sha256.clone(),
        closure_manifest_sha256: inspected.closure_sha256.clone(),
        closure_manifest_size_bytes: u64::try_from(inspected.canonical_closure.len())?,
        closure_member_count: u64::try_from(inspected.closure.members.len())?,
        closure_total_size_bytes: inspected.closure.total_nar_size_bytes(),
        cache_key_id: cache_identity.key_id.clone(),
        cache_key_fingerprint: cache_identity.fingerprint.clone(),
        build_started_at: started,
        build_completed_at: completed,
        result: "succeeded".to_string(),
    };
    let provenance_bytes = provenance.canonical_bytes()?;
    let envelope = sign_provenance(&provenance, &attestation.signing_key)?;
    let envelope_bytes = envelope.canonical_bytes()?;
    let envelope_sha256 = sha256_hex(&envelope_bytes);
    let published = publish_system_release_evidence(
        config,
        spec,
        &inspected.canonical_closure,
        &envelope_bytes,
    )?;
    cache::assert_mutation_lease(config, cache_lease)?;
    cached.managed_artifact_id = Some(artifact_id.clone());
    let metadata = json!({
        "system_release": {
            "schema": "cybex.forge.system-release-result.v1",
            "organization_id": spec.organization_id,
            "release_id": spec.release_id,
            "variant_id": spec.variant_id,
            "forge_node_id": capability.forge_node_id,
            "forge_build_job_id": managed_job_id,
            "forge_artifact_id": artifact_id,
            "build_spec_sha256": build_spec_sha256,
            "input_manifest_sha256": spec.input_manifest_sha256,
            "release_marker_sha256": release_marker_sha256,
            "target": {
                "store_path": output.output_path,
                "output_sha256": output.output_sha256,
                "nar_hash": target.nar_hash,
                "nar_size_bytes": target.nar_size_bytes,
                "kernel_store_path": inspected.kernel_store_path,
                "initrd_store_path": inspected.initrd_store_path,
                "kernel_version": inspected.kernel_version,
            },
            "closure": {
                "url": published.closure_url,
                "relative_path": published.closure_relative_path,
                "path": published.closure_path.display().to_string(),
                "sha256": inspected.closure_sha256,
                "digest_sha256": inspected.closure_sha256,
                "size_bytes": inspected.canonical_closure.len(),
                "member_count": inspected.closure.members.len(),
                "total_size_bytes": inspected.closure.total_nar_size_bytes(),
            },
            "provenance": {
                "url": published.provenance_url,
                "relative_path": published.provenance_relative_path,
                "path": published.provenance_path.display().to_string(),
                "canonical_sha256": envelope.canonical_sha256,
                "envelope_sha256": envelope_sha256,
                "canonical_bytes_b64": envelope.canonical_bytes_b64,
                "signature": envelope.signatures[0].signature,
                "envelope": envelope,
                "size_bytes": envelope_bytes.len(),
                "provenance_size_bytes": provenance_bytes.len(),
            },
            "attestation": {
                "public_key": attestation.public_key,
                "key_id": attestation.key_id,
                "fingerprint": capability.attestation_key_id,
            },
            "cache": {
                "public_key": cache_identity.public_key,
                "key_id": cache_identity.key_id,
                "fingerprint": cache_identity.fingerprint,
                "substituter_url": cache::cache_base_url(config),
            },
        }
    });
    Ok(metadata)
}

fn canonical_build_time(value: &str) -> Result<String> {
    let parsed = DateTime::parse_from_rfc3339(value)
        .context("parse System Release build start time")?
        .with_timezone(&Utc);
    Ok(parsed.to_rfc3339_opts(SecondsFormat::Secs, true))
}

async fn canonical_completion_time_after(started: DateTime<Utc>) -> Result<String> {
    let now = Utc::now();
    if now < started {
        bail!("System Release build clock moved behind its recorded start time");
    }
    if now.timestamp() == started.timestamp() {
        let wait_millis = 1_001u64.saturating_sub(u64::from(now.timestamp_subsec_millis()));
        sleep(Duration::from_millis(wait_millis)).await;
    }
    let completed = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    let completed_time = DateTime::parse_from_rfc3339(&completed)?.with_timezone(&Utc);
    if completed_time <= started {
        bail!("System Release build completion time is not after its start time");
    }
    Ok(completed)
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

async fn run_nix_hash(config: &AppConfig, path: &str) -> Result<String> {
    let output = Command::new(&config.build.nix_binary)
        .arg("hash")
        .arg("path")
        .arg("--type")
        .arg("sha256")
        .arg("--base16")
        .arg(path)
        .output()
        .await
        .with_context(|| format!("run {} hash path", config.build.nix_binary))?;
    if !output.status.success() {
        bail!(
            "nix hash path failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let hash = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("nix hash path did not return a SHA-256 hex digest");
    }
    Ok(hash.to_ascii_lowercase())
}

async fn run_nix_path_info(config: &AppConfig, path: &str) -> Result<(i64, i64)> {
    let output = Command::new(&config.build.nix_binary)
        .arg("path-info")
        .arg("--json")
        .arg("--closure-size")
        .arg("--size")
        .arg(path)
        .output()
        .await
        .with_context(|| format!("run {} path-info", config.build.nix_binary))?;
    if !output.status.success() {
        bail!(
            "nix path-info failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let value: Value =
        serde_json::from_slice(&output.stdout).context("parse nix path-info JSON")?;
    let first = nix_path_info_row(&value, path)?;
    let (output_size_bytes, closure_size_bytes) = nix_path_info_sizes(first);
    Ok((output_size_bytes, closure_size_bytes))
}

fn nix_path_info_row<'a>(value: &'a Value, path: &str) -> Result<&'a Value> {
    if let Some(first) = value.as_array().and_then(|array| array.first()) {
        return Ok(first);
    }
    if let Some(object) = value.as_object() {
        if let Some(row) = object.get(path) {
            return Ok(row);
        }
        if let Some(row) = object.values().next() {
            return Ok(row);
        }
    }
    Err(anyhow!("nix path-info returned no rows"))
}

fn nix_path_info_sizes(first: &Value) -> (i64, i64) {
    let closure_size = first
        .get("closureSize")
        .or_else(|| first.get("closure_size"))
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let nar_size = first
        .get("narSize")
        .or_else(|| first.get("size"))
        .and_then(Value::as_i64)
        .unwrap_or(0);
    (closure_size.max(nar_size).max(0), closure_size.max(0))
}

async fn read_log_stream<R>(mut reader: R, log: SharedLog) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut buf = [0u8; 8192];
    loop {
        let read = reader.read(&mut buf).await?;
        if read == 0 {
            break;
        }
        log.append(&String::from_utf8_lossy(&buf[..read])).await;
    }
    Ok(())
}

impl SharedLog {
    fn new(max_bytes: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(SharedLogState::default())),
            max_bytes,
        }
    }

    async fn append(&self, text: &str) {
        let mut inner = self.inner.lock().await;
        let redacted = redact_log_text(text, &mut inner.redact_following);
        inner.text.push_str(&redacted);
        if inner.text.len() > self.max_bytes {
            let marker = "[... earlier build log truncated ...]\n";
            let keep = self.max_bytes.saturating_sub(marker.len());
            let start = utf8_tail_start(&inner.text, keep);
            let tail = inner.text[start..].to_string();
            inner.text = format!("{marker}{tail}");
        }
    }

    async fn snapshot(&self) -> String {
        self.inner.lock().await.text.clone()
    }
}

fn redact_log_text(text: &str, redact_following: &mut usize) -> String {
    text.split_whitespace()
        .map(|token| {
            if *redact_following > 0 {
                *redact_following -= 1;
                return "[REDACTED]".to_string();
            }
            let lower = token.to_ascii_lowercase();
            if lower.contains("authorization:") || lower.contains("private-key") {
                *redact_following = 2;
                "[REDACTED]".to_string()
            } else if contains_sensitive_key_value(token) {
                redact_sensitive_key_values(token)
            } else {
                token.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn utf8_tail_start(value: &str, keep_bytes: usize) -> usize {
    if value.len() <= keep_bytes {
        return 0;
    }
    let mut start = value.len() - keep_bytes;
    while start < value.len() && !value.is_char_boundary(start) {
        start += 1;
    }
    start
}

fn terminate_child(child: &mut tokio::process::Child) {
    #[cfg(unix)]
    if let Some(pid) = child.id() {
        unsafe {
            libc::kill(pid as i32, libc::SIGTERM);
        }
    }
    #[cfg(not(unix))]
    let _ = child.start_kill();
}

fn normalize_artifact_type(value: &str) -> Result<String> {
    let value = value.trim().to_ascii_lowercase();
    match value.as_str() {
        "nixos_closure" | "netboot_artifact" | "desktop_image" | "system_generation" => Ok(value),
        _ => bail!("unsupported artifact_type"),
    }
}

fn normalize_target(value: &str) -> Result<String> {
    let value = value.trim().to_ascii_lowercase();
    if value.is_empty()
        || value.len() > 64
        || value.starts_with(['-', '.', '_'])
        || value.ends_with(['-', '.', '_'])
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
    {
        bail!("invalid target");
    }
    Ok(value)
}

fn normalize_system(value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 64
        || value.starts_with('-')
        || value.ends_with('-')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        bail!("invalid system");
    }
    Ok(value.to_string())
}

fn normalize_revision(value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        bail!("invalid input_revision");
    }
    Ok(value.to_string())
}

fn normalize_sha256(value: &str) -> Result<String> {
    let value = value.trim();
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("input_config_hash must be a SHA-256 hex digest");
    }
    Ok(value.to_ascii_lowercase())
}

fn normalize_optional_uuidish(field: &str, value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        bail!("{field} is invalid");
    }
    Ok(value.to_string())
}

fn bounded_metadata_text(value: &str, max_chars: usize) -> String {
    value
        .replace(['\n', '\r', '\t'], " ")
        .chars()
        .take(max_chars)
        .collect::<String>()
        .trim()
        .to_string()
}

fn default_schema_version() -> u32 {
    1
}

fn safe_error(err: &anyhow::Error) -> String {
    redact_sensitive_key_values(&err.to_string())
        .chars()
        .take(1000)
        .collect()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::config::{AppConfig, BuildTargetConfig};

    use super::*;

    #[tokio::test]
    async fn cleanup_and_sweep_remove_job_dirs() {
        let root = std::env::temp_dir().join(format!(
            "cybex-forge-build-cleanup-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let mut config = AppConfig::default();
        config.build.output_dir = root.join("out");
        config.build.work_dir = root.join("work");
        let finished_out = config.build.output_dir.join("job-7");
        let finished_input = config.build.work_dir.join("job-7-input");
        let stale_out = config.build.output_dir.join("job-3");
        let stale_input = config.build.work_dir.join("job-3-input");
        let unrelated_out = config.build.output_dir.join("job-notanumber");
        let unrelated_work = config.build.work_dir.join("keepme");
        for dir in [
            &finished_out,
            &finished_input,
            &stale_out,
            &stale_input,
            &unrelated_out,
            &unrelated_work,
        ] {
            std::fs::create_dir_all(dir).unwrap();
            std::fs::write(dir.join("result"), b"x").unwrap();
        }

        cleanup_job_dirs(&config, 7).await;
        assert!(!finished_out.exists());
        assert!(!finished_input.exists());
        assert!(stale_out.exists());

        sweep_stale_job_dirs(&config).await;
        assert!(!stale_out.exists());
        assert!(!stale_input.exists());
        assert!(unrelated_out.exists());
        assert!(unrelated_work.exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn private_system_release_inputs_use_strict_modes_and_are_guarded() {
        let root = std::env::temp_dir().join(format!(
            "cybex-forge-private-input-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let work = root.join("work");
        std::fs::create_dir_all(&work).unwrap();
        std::fs::set_permissions(&work, std::fs::Permissions::from_mode(0o700)).unwrap();
        let input = work.join("job-1-input");
        let rendered = RenderedSystemReleaseInputs {
            files: vec![
                crate::system_release::RenderedSystemReleaseFile {
                    name: "configuration.nix".to_string(),
                    bytes: b"{ ... }: {}".to_vec(),
                    mode: 0o600,
                },
                crate::system_release::RenderedSystemReleaseFile {
                    name: "cybex-release-transition.sh".to_string(),
                    bytes: b"#!/bin/sh\nexit 0\n".to_vec(),
                    mode: 0o700,
                },
            ],
            release_marker_sha256: "a".repeat(64),
        };

        write_private_job_inputs(&input, &rendered).unwrap();
        assert_eq!(
            std::fs::metadata(&input).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(input.join("configuration.nix"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(input.join("cybex-release-transition.sh"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );

        let command = NixBuildCommand {
            program: "nix".to_string(),
            args: Vec::new(),
            out_link: root.join("result"),
            input_dir: Some(input.clone()),
            release_marker_sha256: Some("a".repeat(64)),
        };
        drop(PrivateInputGuard::for_command(&command));
        assert!(!input.exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn built_release_marker_digest_requires_exact_output_bytes() {
        let expected = br#"{"schema":"cybex.system-release-marker.v3"}"#;
        assert_eq!(
            verify_built_release_marker_bytes(expected, expected).unwrap(),
            sha256_hex(expected)
        );
        assert!(verify_built_release_marker_bytes(expected, b"{}").is_err());
        let mut newline = expected.to_vec();
        newline.push(b'\n');
        assert!(verify_built_release_marker_bytes(expected, &newline).is_err());
        assert!(verify_built_release_marker_bytes(expected, &[]).is_err());
        assert!(
            verify_built_release_marker_bytes(
                expected,
                &vec![b'x'; MAX_BUILT_RELEASE_MARKER_BYTES + 1]
            )
            .is_err()
        );
    }

    #[test]
    fn provenance_uses_the_marker_inspected_from_the_built_closure() {
        let source = include_str!("build.rs");
        let inspect_start = source
            .find("async fn inspect_system_release_output")
            .expect("System Release output inspector");
        let inspect_end = source[inspect_start..]
            .find("async fn inspect_system_generation_paths")
            .map(|offset| inspect_start + offset)
            .expect("output inspector boundary");
        let inspect = &source[inspect_start..inspect_end];
        assert!(inspect.contains("inspect_built_release_marker(output_path, spec, &closure)"));

        let finalize_start = source
            .find("async fn finalize_system_release_artifact")
            .expect("System Release finalizer");
        let finalize_end = source[finalize_start..]
            .find("fn canonical_build_time")
            .map(|offset| finalize_start + offset)
            .expect("System Release finalizer boundary");
        let finalize = &source[finalize_start..finalize_end];
        assert!(finalize.contains("let release_marker_sha256 = &inspected.release_marker_sha256"));
        assert!(!finalize.contains("command.release_marker_sha256"));
    }

    #[test]
    fn failed_private_input_publication_removes_partial_directory() {
        let root = std::env::temp_dir().join(format!(
            "cybex-forge-private-input-failure-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let work = root.join("work");
        std::fs::create_dir_all(&work).unwrap();
        std::fs::set_permissions(&work, std::fs::Permissions::from_mode(0o700)).unwrap();
        let input = work.join("job-1-input");
        let rendered = RenderedSystemReleaseInputs {
            files: vec![crate::system_release::RenderedSystemReleaseFile {
                name: "missing-parent/configuration.nix".to_string(),
                bytes: b"{ ... }: {}".to_vec(),
                mode: 0o600,
            }],
            release_marker_sha256: "a".repeat(64),
        };

        assert!(write_private_job_inputs(&input, &rendered).is_err());
        assert!(!input.exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn system_release_store_paths_are_strictly_canonical() {
        assert!(
            validate_store_path("/nix/store/0123456789abcdfghijklmnpqrsvwxyz-cybex-system").is_ok()
        );
        assert!(validate_store_path("/nix/store/../../etc/passwd").is_err());
        assert!(validate_store_path("/nix/store/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-system").is_err());
        assert!(
            validate_store_path(&format!(
                "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-{}",
                "a".repeat(4097)
            ))
            .is_err()
        );
        assert!(
            validate_store_path("/nix/store/0123456789abcdfghijklmnpqrsvwxyz-not canonical")
                .is_err()
        );
        assert!(validate_store_path("/tmp/not-store").is_err());
    }

    #[test]
    fn build_spec_rejects_unknown_fields() {
        let value = json!({
            "schema_version": 1,
            "artifact_type": "nixos_closure",
            "target": "desktop_experience",
            "system": "x86_64-linux",
            "input_revision": "rev",
            "input_config_hash": "a".repeat(64),
            "raw_nix": "builtins.currentSystem"
        });
        let parsed = serde_json::from_value::<BuildSpec>(value);
        assert!(parsed.is_err());
    }

    #[test]
    fn sysinfo_capacity_scales_kernel_units_without_overflow() {
        assert_eq!(
            capacity_from_sysinfo_values(32 * 1024 * 1024, 8 * 1024 * 1024, 1024),
            BuildCapacity {
                memory_bytes: 32 * 1024 * 1024 * 1024,
                swap_bytes: 8 * 1024 * 1024 * 1024,
            }
        );
        assert_eq!(
            capacity_from_sysinfo_values(u64::MAX, 1, 4096).memory_bytes,
            u64::MAX
        );
    }

    #[test]
    fn capacity_minimum_allows_only_small_kernel_accounting_rounding() {
        let eight_gib = 8 * 1024 * 1024 * 1024;
        assert!(capacity_meets_minimum(eight_gib, eight_gib));
        assert!(capacity_meets_minimum(eight_gib - 4096, eight_gib));
        assert!(!capacity_meets_minimum(
            eight_gib - CAPACITY_ACCOUNTING_TOLERANCE_BYTES - 1,
            eight_gib
        ));
    }

    #[test]
    fn build_spec_accepts_blueprint_build_input() {
        let value = json!({
            "schema_version": 1,
            "artifact_type": "nixos_closure",
            "target": "blueprint",
            "system": "x86_64-linux",
            "input_revision": "rev",
            "input_config_hash": "a".repeat(64),
            "build_input": {
                "kind": "blueprint_nixos_module",
                "generated_nix": "{ lib, ... }: { networking.hostName = lib.mkDefault \"test\"; }",
                "desktop_module_nix": "{ lib, ... }: { options.cybex.desktop.profile = lib.mkOption { type = lib.types.str; default = \"auto\"; }; }",
                "expected_state": {
                    "schema": "cybex.blueprint.expected-state.v3",
                    "compiler_version": 3,
                    "desktop": {"profile": "gnome"},
                    "checks": []
                },
                "blueprint_name": "Standard Workstation",
                "blueprint_revision": 8
            }
        });
        let parsed = serde_json::from_value::<BuildSpec>(value).unwrap();
        let validated = validate_blueprint_build_input(parsed.build_input.unwrap()).unwrap();
        assert!(validated.desktop_module_nix.is_some());
        assert!(validated.expected_state.is_some());
    }

    #[test]
    fn blueprint_build_input_keeps_immutable_expected_state_v2_buildable() {
        let input = BlueprintBuildInput {
            kind: BLUEPRINT_BUILD_INPUT_KIND.to_string(),
            generated_nix: "{ ... }: {}".to_string(),
            desktop_module_nix: Some("{ ... }: {}".to_string()),
            expected_state: Some(json!({
                "schema": "cybex.blueprint.expected-state.v2",
                "desktop": {"profile": "kde"},
                "checks": []
            })),
            blueprint_name: Some("Immutable v2 Blueprint".to_string()),
            blueprint_revision: Some(2),
        };

        let validated = validate_blueprint_build_input(input).unwrap();

        assert_eq!(
            validated
                .expected_state
                .as_ref()
                .and_then(|value| value.get("schema"))
                .and_then(Value::as_str),
            Some("cybex.blueprint.expected-state.v2")
        );
    }

    #[test]
    fn blueprint_build_input_requires_expected_state_with_real_desktop_module() {
        let input = BlueprintBuildInput {
            kind: BLUEPRINT_BUILD_INPUT_KIND.to_string(),
            generated_nix: "{ ... }: {}".to_string(),
            desktop_module_nix: Some("{ ... }: {}".to_string()),
            expected_state: None,
            blueprint_name: None,
            blueprint_revision: None,
        };

        let err = validate_blueprint_build_input(input).unwrap_err();
        assert!(err.to_string().contains("expected_state must be an object"));
    }

    #[test]
    fn build_spec_accepts_legacy_desktop_experience_aliases() {
        let value = json!({
            "schema_version": 1,
            "artifact_type": "nixos_closure",
            "target": "desktop_experience",
            "system": "x86_64-linux",
            "input_revision": "rev",
            "input_config_hash": "a".repeat(64),
            "desktop_experience_id": "legacy-blueprint",
            "build_input": {
                "kind": "desktop_experience_nixos_module",
                "generated_nix": "{ lib, ... }: { networking.hostName = lib.mkDefault \"test\"; }",
                "desktop_experience_name": "Legacy Workstation",
                "desktop_experience_revision": 7
            }
        });
        let parsed = serde_json::from_value::<BuildSpec>(value).unwrap();
        assert_eq!(parsed.blueprint_id.as_deref(), Some("legacy-blueprint"));
        assert_eq!(
            parsed.build_input.unwrap().blueprint_name.as_deref(),
            Some("Legacy Workstation")
        );
        assert!(build_target_names_compatible(
            "desktop_experience",
            "blueprint"
        ));
    }

    #[test]
    fn nix_build_command_uses_allowlisted_attr() {
        let mut config = AppConfig::default();
        config.build.output_dir = PathBuf::from("/tmp/cybex-forge-test-builds");
        config.build.nix_binary = "nix".to_string();
        let target = BuildTargetConfig {
            artifact_type: "nixos_closure".to_string(),
            target: "blueprint".to_string(),
            system: "x86_64-linux".to_string(),
            flake: "/srv/cybex-forge/build-inputs/cybex".to_string(),
            attr: "packages.x86_64-linux.desktop-experience".to_string(),
        };
        let spec = ValidatedBuildSpec {
            artifact_type: "nixos_closure".to_string(),
            target: "blueprint".to_string(),
            system: "x86_64-linux".to_string(),
            input_revision: "rev".to_string(),
            input_config_hash: "a".repeat(64),
            blueprint_id: None,
            blueprint_revision_id: None,
            blueprint_revision_config_hash: None,
            build_input: None,
            system_release: None,
        };

        let command = nix_build_command(&config, &target, &spec, 42, None).unwrap();

        assert_eq!(command.program, "nix");
        assert_eq!(command.args[0], "build");
        assert!(
            command.args.contains(
                &"/srv/cybex-forge/build-inputs/cybex#packages.x86_64-linux.desktop-experience"
                    .to_string()
            )
        );
        assert!(command.args.contains(&"--out-link".to_string()));
        assert!(command.args.windows(2).any(|args| args == ["--cores", "4"]));
    }

    #[test]
    fn resource_parsers_and_failure_classifier_are_specific() {
        assert_eq!(
            parse_cgroup_limit("8589934592\n").unwrap(),
            Some(8_589_934_592)
        );
        assert_eq!(parse_cgroup_limit("max\n").unwrap(), None);
        assert_eq!(
            parse_meminfo_bytes("MemTotal: 16384 kB\nSwapTotal: 8192 kB\n", "SwapTotal"),
            Some(8 * 1024 * 1024)
        );
        assert_eq!(
            parse_memory_event("oom 3\noom_kill 2\n", "oom_kill"),
            Some(2)
        );
        assert_eq!(
            classify_nix_build_failure("compiler killed", true).0,
            "out_of_memory"
        );
        assert_eq!(
            classify_nix_build_failure("error: builder for '/nix/store/example.drv' failed", false)
                .0,
            "package_build_failed"
        );
        assert_eq!(
            classify_nix_build_failure("No space left on device", false).0,
            "insufficient_disk_space"
        );
        assert_eq!(
            classify_nix_build_failure("cannot connect to socket at daemon-socket", false).0,
            "nix_daemon_unavailable"
        );
    }

    #[test]
    fn nix_build_command_writes_blueprint_flake_input() {
        let root = std::env::temp_dir().join(format!(
            "cybex-forge-build-input-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let mut config = AppConfig::default();
        config.build.work_dir = root.join("work");
        config.build.output_dir = root.join("out");
        config.build.nix_binary = "nix".to_string();
        let target = BuildTargetConfig {
            artifact_type: "nixos_closure".to_string(),
            target: "blueprint".to_string(),
            system: "x86_64-linux".to_string(),
            flake: "/srv/cybex-forge/build-inputs/cybex".to_string(),
            attr: "packages.x86_64-linux.desktop-experience".to_string(),
        };
        let spec = ValidatedBuildSpec {
            artifact_type: "nixos_closure".to_string(),
            target: "blueprint".to_string(),
            system: "x86_64-linux".to_string(),
            input_revision: "rev".to_string(),
            input_config_hash: "a".repeat(64),
            blueprint_id: None,
            blueprint_revision_id: None,
            blueprint_revision_config_hash: None,
            build_input: Some(ValidatedBlueprintBuildInput {
                generated_nix: "{ lib, ... }: { networking.hostName = lib.mkDefault \"test\"; }"
                    .to_string(),
                desktop_module_nix: Some(
                    "{ lib, ... }: { options.cybex.desktop.profile = lib.mkOption { type = lib.types.str; default = \"auto\"; }; }"
                        .to_string(),
                ),
                expected_state: Some(json!({
                    "schema": "cybex.blueprint.expected-state.v1",
                    "desktop": {"profile": "gnome"}
                })),
                blueprint_name: Some("Standard Workstation".to_string()),
                blueprint_revision: Some(8),
            }),
            system_release: None,
        };

        let command = nix_build_command(&config, &target, &spec, 42, None).unwrap();

        assert_eq!(command.program, "nix");
        assert_eq!(command.args[0], "build");
        assert!(
            command
                .args
                .iter()
                .any(|arg| arg.ends_with("#packages.x86_64-linux.desktop-experience"))
        );
        assert!(root.join("work/job-42-input/flake.nix").is_file());
        assert!(root.join("work/job-42-input/blueprint.nix").is_file());
        assert!(
            root.join("work/job-42-input/cybex-blueprints.nix")
                .is_file()
        );
        assert!(root.join("work/job-42-input/expected-state.json").is_file());
        let configuration =
            std::fs::read_to_string(root.join("work/job-42-input/configuration.nix")).unwrap();
        assert!(configuration.contains("./cybex-blueprints.nix"));
        assert!(
            configuration
                .contains("systemd.services.systemd-udevd.restartTriggers = lib.mkForce [];")
        );
        assert!(configuration.contains("boot.initrd.enable = lib.mkForce false;"));
        assert!(configuration.contains("boot.initrd.includeDefaultModules = false;"));
        assert!(configuration.contains("boot.initrd.availableKernelModules = lib.mkForce [];"));
        assert!(configuration.contains("boot.kernelModules = lib.mkForce [];"));
        assert!(configuration.contains("security.lockKernelModules = lib.mkForce false;"));
        let compatibility =
            std::fs::read_to_string(root.join("work/job-42-input/cybex-compat-options.nix"))
                .unwrap();
        assert!(compatibility.contains("options.cybex.blueprint.applications"));
        assert!(compatibility.contains("lib.mkAliasOptionModule"));
        let flake = std::fs::read_to_string(root.join("work/job-42-input/flake.nix")).unwrap();
        assert!(flake.contains(r#"inputs.nixpkgs.url = "/srv/cybex-forge/build-inputs/cybex";"#));
        assert!(!flake.contains("nixos-26.05"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn log_capture_bounds_and_redacts() {
        let log = SharedLog::new(64);
        log.append("token=secret normal password=hunter2 secret-key=/tmp/key\n")
            .await;
        let snapshot = log.snapshot().await;

        assert!(snapshot.contains("[REDACTED]"));
        assert!(!snapshot.contains("hunter2"));
        assert!(snapshot.len() <= 64);
    }

    #[tokio::test]
    async fn log_capture_redacts_authorization_header_value() {
        let log = SharedLog::new(1024);
        log.append("normal Authorization: Bearer top-secret-token done\n")
            .await;
        let snapshot = log.snapshot().await;

        assert!(snapshot.contains("normal"));
        assert!(snapshot.contains("done"));
        assert!(!snapshot.contains("Bearer"));
        assert!(!snapshot.contains("top-secret-token"));
    }

    #[tokio::test]
    async fn log_capture_redacts_authorization_header_value_split_across_appends() {
        let log = SharedLog::new(1024);
        log.append("normal Authorization:").await;
        log.append(" Bearer split-secret done\n").await;
        let snapshot = log.snapshot().await;

        assert!(snapshot.contains("normal"));
        assert!(snapshot.contains("done"));
        assert!(!snapshot.contains("Bearer"));
        assert!(!snapshot.contains("split-secret"));
    }

    #[test]
    fn safe_error_redacts_entire_secret_key_value() {
        let err =
            anyhow!("copy failed for file:///cache?secret-key=/tmp/cache.key&compression=zstd");
        let message = safe_error(&err);

        assert!(message.contains("secret-key=[REDACTED]&compression=zstd"));
        assert!(!message.contains("/tmp/cache.key"));
    }

    #[test]
    fn nix_path_info_parser_accepts_object_or_array_shapes() {
        let object = json!({
            "/nix/store/example": {
                "closureSize": 128,
                "narSize": 64
            }
        });
        let row = nix_path_info_row(&object, "/nix/store/example").unwrap();
        assert_eq!(nix_path_info_sizes(row), (128, 128));

        let array = json!([
            {
                "closureSize": 200,
                "narSize": 300
            }
        ]);
        let row = nix_path_info_row(&array, "/nix/store/other").unwrap();
        assert_eq!(nix_path_info_sizes(row), (300, 200));
    }
}
