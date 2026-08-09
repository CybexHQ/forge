use std::{
    collections::{BTreeMap, HashSet},
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    process::{ExitStatus, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail};
use rand::{RngCore, rngs::OsRng};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, BufReader},
    process::Command,
    sync::Mutex,
    time::{sleep, timeout},
};
use tracing::{info, warn};

use crate::{
    AppState, cache,
    config::{AppConfig, BuildTargetConfig, pinned_nixpkgs_revision},
    db,
    models::BuildJob,
    nix_log::{InternalJsonParser, derivation_display_name},
    protected_material,
    redact::{contains_sensitive_key_value, redact_sensitive_key_values},
};

const BLUEPRINT_BUILD_INPUT_KIND: &str = "blueprint_nixos_module";
const LEGACY_DESKTOP_EXPERIENCE_BUILD_INPUT_KIND: &str = "desktop_experience_nixos_module";
const INSTALLER_TARGET_BUILD_INPUT_KIND: &str = "installer_target_nixos_module";
const INSTALLER_TARGET_BUILD_SCHEMA: &str = "cybex.installer-target.build.v1";
const MAX_GENERATED_NIX_BYTES: usize = 1024 * 1024;
const MAX_DESKTOP_MODULE_NIX_BYTES: usize = 1024 * 1024;
const MAX_HARDWARE_MODULE_NIX_BYTES: usize = 1024 * 1024;
const MAX_TARGET_MODULE_NIX_BYTES: usize = 1024 * 1024;
const MAX_PENDING_LOG_LINE_BYTES: usize = 64 * 1024;
const CAPACITY_ACCOUNTING_TOLERANCE_BYTES: u64 = 1024 * 1024;
/// Progress range reserved for the nix build itself; the phases before
/// (preparing, 12) and after (inspecting, 80) bound it.
const BUILDING_PROGRESS_START: i32 = 25;
const BUILDING_PROGRESS_END: i32 = 79;
// These files are part of the pinned nixpkgs materialization machinery used
// by Pulse's current source lock. A nixpkgs update must deliberately refresh
// the hashes after reviewing the new scripts. Derivation attributes and names
// alone are explicitly not treated as provenance.
const TRUSTED_STDENV_SOURCE_SHA256: &str =
    "fda2f9599062ec0533741844a0b76ea6b5b12be613d8edcb5d445a14876ca809";
const TRUSTED_DEFAULT_BUILDER_SHA256: &str =
    "21c4af68b16048dc99687b414d8d89e980b623cd0ce0f8106de5248f7af75619";
const TRUSTED_SECURITY_WRAPPER_SHA256: &str =
    "5d4752742d2e76e6a4e57dd061320d0ff96f52d65cc1e54c203dce12e8b741dc";
const TRUSTED_LINK_FARM_BUILDER_SHA256: &str =
    "5b6a127611842e04d7cfccf1aefda34824bc01ac0ac300d465b317ea957b7654";
const TRUSTED_SUBSTITUTE_BUILDER_SHA256: &str =
    "57f698eda1384c91aca909f1668331da8ac9928722f0c48ae75b433340a4f7cd";
const TRUSTED_SUBSTITUTE_BUILDER: &str =
    "/nix/store/6n31khdh5axal16074afb98p4839q786-substitute.sh";
const TRUSTED_LINK_FARM_BUILDER: ReviewedStoreOutput = ReviewedStoreOutput {
    path: "/nix/store/b1lyn1hdqrr25d58chjxnbxsrvv64js7-builder.pl",
    drv_path: "/nix/store/jy0p63d0qgl1z5sh8qah512zpbvblqw9-builder.pl.drv",
    output: "out",
};
const TRUSTED_LINK_FARM_PERL: ReviewedStoreOutput = ReviewedStoreOutput {
    path: "/nix/store/k7kxg101ikkm0cyf8jcqhg948vy542af-perl-5.42.0/bin/perl",
    drv_path: "/nix/store/fnbm2l40fm0a6rqhhpgnfl7317d4qyky-perl-5.42.0.drv",
    output: "out",
};
const TRUSTED_STDENV_BASH_BUILDER: &str =
    "/nix/store/zh1ijdhb6gng1509b1zrilb6xlzx60j6-bash-5.3p9/bin/bash";
const TRUSTED_STDENV_BASH_DRV: &str = "/nix/store/g7p7rs03xah2w00a142hzas9h4fkwpck-bash-5.3p9.drv";
const TRUSTED_STDENV_NO_CC: &str = "/nix/store/pr27j8nm0xl52pq4ylncj9kwjw3b84mk-stdenv-linux";
const TRUSTED_STDENV_NO_CC_DRV: &str =
    "/nix/store/bxlz3hzl8k02rnxpgml6krqkrnpird91-stdenv-linux.drv";
const TRUSTED_STDENV_FULL: &str = "/nix/store/xknwpg5yjxxsffmwdmpys269543wpdy5-stdenv-linux";
const TRUSTED_STDENV_FULL_DRV: &str =
    "/nix/store/l0x59a9gpwqh6rxxx2sxbl5nd72r4bc8-stdenv-linux.drv";
const TRUSTED_STDENV_STATIC: &str = "/nix/store/4hy0wmhgfmdh6zq0pjgyfavpa1n5lhbj-stdenv-linux";
const TRUSTED_STDENV_STATIC_DRV: &str =
    "/nix/store/ic3nh1yr6zjlbxwnmxp1r6jhkp816f4l-stdenv-linux.drv";

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
    pub nixpkgs_commit: Option<String>,
    #[serde(default)]
    pub source_lock_sha256: Option<String>,
    #[serde(default)]
    pub software_package_refs: Vec<String>,
    #[serde(default)]
    pub build_input: Option<BlueprintBuildInput>,
    /// When false (the default, including when the field is absent), the build
    /// must come entirely from binary substitution: a pre-flight cache-coverage
    /// check fails the job when the closure would compile real packages from
    /// source (trivial per-system glue derivations are exempt).
    #[serde(default)]
    pub allow_source_builds: bool,
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
    #[serde(default)]
    pub hardware_module_nix: Option<String>,
    #[serde(default)]
    pub target_module_nix: Option<String>,
    #[serde(default)]
    pub manage_source_revision: Option<String>,
    #[serde(default)]
    pub installer_target: Option<Value>,
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
    nixpkgs_commit: Option<String>,
    source_lock_sha256: Option<String>,
    software_package_refs: Vec<String>,
    build_input: Option<ValidatedBlueprintBuildInput>,
    allow_source_builds: bool,
}

#[derive(Clone, Debug)]
struct ValidatedBlueprintBuildInput {
    kind: String,
    generated_nix: String,
    desktop_module_nix: Option<String>,
    expected_state: Option<Value>,
    blueprint_name: Option<String>,
    blueprint_revision: Option<i64>,
    hardware_module_nix: Option<String>,
    target_module_nix: Option<String>,
    manage_source_revision: Option<String>,
    installer_target: Option<Value>,
}

#[derive(Clone, Debug)]
struct NixBuildCommand {
    program: String,
    args: Vec<String>,
    out_link: PathBuf,
    installable: String,
}

#[derive(Clone, Debug)]
struct NixOutputInfo {
    output_path: String,
    output_sha256: String,
    output_size_bytes: i64,
    closure_size_bytes: i64,
    evaluated_derivation: Option<String>,
}

#[derive(Clone)]
struct SharedLog {
    inner: Arc<Mutex<SharedLogState>>,
    max_bytes: usize,
}

#[derive(Debug, Default)]
struct SharedLogState {
    text: String,
    pending: String,
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
            "Pulse restarted while this build was running; mark failed for explicit retry.",
        )
        .await
        {
            Ok(count) if count > 0 => {
                warn!(count, "recovered stale running Pulse build jobs");
            }
            Ok(_) => {}
            Err(err) => warn!(error = %err, "failed to recover running Pulse build jobs"),
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
                info!(job_id, worker_index, "claimed Pulse build job");
                if let Err(err) = execute_claimed_job(&state, job).await {
                    warn!(error = %safe_error(&err), worker_index, "Pulse build job execution failed");
                    recover_failed_job_execution(&state, job_id, worker_index).await;
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
                warn!(error = %err, worker_index, retry_in_seconds = delay, "failed to claim Pulse build job");
                sleep(Duration::from_secs(delay)).await;
            }
        }
    }
}

async fn recover_failed_job_execution(state: &AppState, job_id: i64, worker_index: usize) {
    const RECOVERY_REASON: &str =
        "Pulse stopped the build safely after an internal worker error; retry the build.";
    let mut failures: u32 = 0;
    loop {
        match db::fail_running_build_job_after_worker_error(&state.db, job_id, RECOVERY_REASON)
            .await
        {
            Ok(true) => {
                warn!(job_id, worker_index, "recovered failed Pulse build worker");
                return;
            }
            Ok(false) => return,
            Err(err) => {
                let err = anyhow::Error::new(err);
                failures = failures.saturating_add(1);
                let delay = (2u64 << failures.saturating_sub(1).min(5)).min(60);
                warn!(
                    error = %safe_error(&err),
                    job_id,
                    worker_index,
                    retry_in_seconds = delay,
                    "failed to persist Pulse build worker recovery"
                );
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
                warn!(error = %err, path = %dir.display(), "failed to remove Pulse build job directory");
            }
        }
    }
}

/// Remove job dirs left behind by earlier Pulse runs. Runs once at startup,
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
                warn!(error = %err, path = %root.display(), "failed to scan Pulse build directory");
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
                    warn!(error = %err, path = %entry.path().display(), "failed to remove stale Pulse build job directory");
                }
            }
        }
    }
    if removed > 0 {
        info!(removed, "removed stale Pulse build job directories");
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
        "Pulse build",
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
                    "could not inspect Pulse memory capacity: {}",
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
                "Pulse requires at least {} bytes of memory for Build/Cache; detected {} bytes",
                state.config.build.minimum_memory_bytes, capacity.memory_bytes
            ),
        ))
    } else if !capacity_meets_minimum(capacity.swap_bytes, state.config.build.minimum_swap_bytes) {
        Some((
            "insufficient_swap",
            format!(
                "Pulse requires at least {} bytes of emergency swap for Build/Cache; detected {} bytes",
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

    let command = nix_build_command(&state.config, &target, &spec, job.id)?;
    if !spec.allow_source_builds {
        db::update_build_job_progress(
            &state.db,
            job.id,
            Some(18),
            "checking_cache",
            "Checking binary cache coverage",
        )
        .await?;
        match preflight_source_build_check(&state.config, &command).await {
            Ok(offenders) if !offenders.is_empty() => {
                let mut metadata = build_result_metadata(
                    &state.config,
                    &job,
                    Some(&target),
                    Some("source_build_blocked"),
                );
                if let Some(map) = metadata.as_object_mut() {
                    map.insert("source_build_candidates".to_string(), json!(offenders));
                }
                db::finish_build_job(
                    &state.db,
                    job.id,
                    "failed",
                    "",
                    &source_build_blocked_message(&offenders),
                    "",
                    "",
                    0,
                    None,
                    Some(metadata),
                )
                .await?;
                return Ok(());
            }
            Ok(_) => {}
            Err(err) => {
                let error = format!(
                    "Pulse could not verify binary cache coverage, so this source-disabled build was stopped safely: {}",
                    safe_error(&err)
                );
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
                        Some("source_policy_preflight_failed"),
                    )),
                )
                .await?;
                return Ok(());
            }
        }
    }
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
            let software_inventory = evaluate_software_inventory(&state.config, &spec).await;
            db::update_build_job_progress(
                &state.db,
                job.id,
                Some(90),
                "exporting",
                "Exporting closure to Pulse cache",
            )
            .await?;
            let mut cached = match cache::export_output(
                &state.db,
                &state.config,
                &job,
                &output_info.output_path,
                &output_info.output_sha256,
                output_info.closure_size_bytes,
                output_info.evaluated_derivation.as_deref(),
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
            merge_build_metadata(
                &mut cached.metadata,
                &success_result_metadata(&state.config, &job, &target, &spec, &software_inventory),
            );
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
            )
            .await?;
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
                Some(success_result_metadata(
                    &state.config,
                    &job,
                    &target,
                    &spec,
                    &software_inventory,
                )),
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
    protected_material::validate_build_spec(&job.build_spec)?;
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
        bail!("system is not allowed on this Pulse node");
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
    let nixpkgs_commit = spec
        .nixpkgs_commit
        .map(|value| normalize_nixpkgs_commit(&value))
        .transpose()?;
    let source_lock_sha256 = spec
        .source_lock_sha256
        .map(|value| normalize_sha256(&value))
        .transpose()?;
    if build_input.is_some() && (nixpkgs_commit.is_none() || source_lock_sha256.is_none()) {
        bail!("Blueprint builds require nixpkgs_commit and source_lock_sha256");
    }
    if spec.software_package_refs.len() > 128 {
        bail!("software_package_refs exceeds 128 items");
    }
    let software_package_refs = spec
        .software_package_refs
        .iter()
        .map(|value| normalize_package_ref(value))
        .collect::<Result<Vec<_>>>()?;
    Ok(ValidatedBuildSpec {
        artifact_type,
        target,
        system,
        input_revision,
        input_config_hash,
        blueprint_id,
        blueprint_revision_id,
        blueprint_revision_config_hash,
        nixpkgs_commit,
        source_lock_sha256,
        software_package_refs,
        build_input,
        allow_source_builds: spec.allow_source_builds,
    })
}

fn validate_blueprint_build_input(
    input: BlueprintBuildInput,
) -> Result<ValidatedBlueprintBuildInput> {
    protected_material::validate_generated_nix(&input.generated_nix)?;
    if let Some(desktop_module_nix) = input.desktop_module_nix.as_deref() {
        protected_material::validate_desktop_module_nix(desktop_module_nix)?;
    }
    if let Some(expected_state) = input.expected_state.as_ref() {
        protected_material::validate_expected_state(expected_state)?;
    }
    let kind = input.kind.trim();
    if !matches!(
        kind,
        BLUEPRINT_BUILD_INPUT_KIND
            | LEGACY_DESKTOP_EXPERIENCE_BUILD_INPUT_KIND
            | INSTALLER_TARGET_BUILD_INPUT_KIND
    ) {
        bail!("unsupported build_input kind");
    }
    let installer_target_build = kind == INSTALLER_TARGET_BUILD_INPUT_KIND;
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
        if !matches!(
            expected_state.get("schema").and_then(Value::as_str),
            Some("cybex.blueprint.expected-state.v1" | "cybex.blueprint.expected-state.v2")
        ) {
            bail!("build_input.expected_state has an unsupported schema");
        }
    } else if input.expected_state.is_some() {
        bail!("build_input.expected_state requires desktop_module_nix");
    }
    if installer_target_build {
        let hardware_module_nix = input
            .hardware_module_nix
            .as_deref()
            .ok_or_else(|| anyhow!("installer target requires hardware_module_nix"))?;
        validate_bounded_nix_input(
            "build_input.hardware_module_nix",
            hardware_module_nix,
            MAX_HARDWARE_MODULE_NIX_BYTES,
        )?;
        let target_module_nix = input
            .target_module_nix
            .as_deref()
            .ok_or_else(|| anyhow!("installer target requires target_module_nix"))?;
        validate_bounded_nix_input(
            "build_input.target_module_nix",
            target_module_nix,
            MAX_TARGET_MODULE_NIX_BYTES,
        )?;
        let manage_source_revision = input
            .manage_source_revision
            .as_deref()
            .ok_or_else(|| anyhow!("installer target requires manage_source_revision"))?;
        normalize_nixpkgs_commit(manage_source_revision)
            .context("normalize installer target Manage revision")?;
        validate_installer_target_identity(
            input
                .installer_target
                .as_ref()
                .ok_or_else(|| anyhow!("installer target identity is required"))?,
            manage_source_revision,
        )?;
        if input.desktop_module_nix.is_none() || input.expected_state.is_none() {
            bail!("installer target requires the reviewed desktop module and expected state");
        }
    } else if input.hardware_module_nix.is_some()
        || input.target_module_nix.is_some()
        || input.manage_source_revision.is_some()
        || input.installer_target.is_some()
    {
        bail!("installer target fields require installer_target_nixos_module");
    }
    Ok(ValidatedBlueprintBuildInput {
        kind: kind.to_string(),
        generated_nix: input.generated_nix,
        desktop_module_nix: input.desktop_module_nix,
        expected_state: input.expected_state,
        blueprint_name: input
            .blueprint_name
            .map(|value| bounded_metadata_text(&value, 200))
            .filter(|value| !value.is_empty()),
        blueprint_revision: input.blueprint_revision.filter(|value| *value > 0),
        hardware_module_nix: input.hardware_module_nix,
        target_module_nix: input.target_module_nix,
        manage_source_revision: input.manage_source_revision,
        installer_target: input.installer_target,
    })
}

fn validate_bounded_nix_input(field: &str, value: &str, max_bytes: usize) -> Result<()> {
    if value.trim().is_empty() {
        bail!("{field} must not be empty");
    }
    if value.len() > max_bytes {
        bail!("{field} is too large");
    }
    if value.bytes().any(|byte| byte == 0) {
        bail!("{field} must not contain NUL bytes");
    }
    // The whole BuildSpec has already passed the protected-material scanner;
    // keep this helper focused on the bounded text contract.
    Ok(())
}

fn validate_installer_target_identity(value: &Value, manage_revision: &str) -> Result<()> {
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("installer_target must be an object"))?;
    let expected = [
        "schema",
        "preparation_id",
        "device_id",
        "device_incarnation_id",
        "blueprint_id",
        "blueprint_revision_id",
        "hardware_facts_sha256",
        "hardware_driver_policy",
        "disk_layout_sha256",
        "pulse_device_id",
        "bundle_sha256",
        "profile_id",
        "managed_device_id",
        "reinstall_request_id",
        "manage_source_revision",
        "nixpkgs_revision",
        "source_lock_sha256",
    ]
    .into_iter()
    .collect::<HashSet<_>>();
    let actual = object.keys().map(String::as_str).collect::<HashSet<_>>();
    if actual != expected {
        bail!("installer_target does not match its schema");
    }
    if object.get("schema").and_then(Value::as_str) != Some(INSTALLER_TARGET_BUILD_SCHEMA) {
        bail!("unsupported installer_target schema");
    }
    for field in [
        "preparation_id",
        "device_incarnation_id",
        "blueprint_id",
        "blueprint_revision_id",
        "profile_id",
    ] {
        normalize_optional_uuidish(
            field,
            object
                .get(field)
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("installer_target.{field} is required"))?,
        )?;
    }
    for field in ["managed_device_id", "reinstall_request_id"] {
        if let Some(value) = object.get(field).and_then(Value::as_str) {
            if field == "reinstall_request_id" {
                normalize_optional_uuidish(field, value)?;
            } else {
                normalize_public_identifier(field, value, 160)?;
            }
        } else if !object.get(field).is_some_and(Value::is_null) {
            bail!("installer_target.{field} must be a string or null");
        }
    }
    if object.get("managed_device_id").is_some_and(Value::is_null)
        != object
            .get("reinstall_request_id")
            .is_some_and(Value::is_null)
    {
        bail!("installer_target reinstall bindings must both be present or both be null");
    }
    for field in ["device_id", "pulse_device_id"] {
        normalize_public_identifier(
            field,
            object
                .get(field)
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("installer_target.{field} is required"))?,
            160,
        )?;
    }
    for field in [
        "hardware_facts_sha256",
        "disk_layout_sha256",
        "bundle_sha256",
        "source_lock_sha256",
    ] {
        normalize_sha256(
            object
                .get(field)
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("installer_target.{field} is required"))?,
        )?;
    }
    let identity_manage_revision = object
        .get("manage_source_revision")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("installer_target.manage_source_revision is required"))?;
    if normalize_nixpkgs_commit(identity_manage_revision)? != manage_revision {
        bail!("installer target Manage revision fields do not match");
    }
    normalize_nixpkgs_commit(
        object
            .get("nixpkgs_revision")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("installer_target.nixpkgs_revision is required"))?,
    )?;
    let policy = object
        .get("hardware_driver_policy")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("installer_target.hardware_driver_policy is required"))?;
    if !matches!(
        policy,
        "auto" | "open_graphics" | "nvidia_open" | "nvidia_proprietary" | "disabled"
    ) {
        bail!("installer_target.hardware_driver_policy is invalid");
    }
    Ok(())
}

fn normalize_public_identifier(field: &str, value: &str, max_chars: usize) -> Result<String> {
    if value.is_empty()
        || value != value.trim()
        || value.chars().count() > max_chars
        || value
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace())
    {
        bail!("{field} is invalid");
    }
    Ok(value.to_string())
}

fn build_target<'a>(
    config: &'a AppConfig,
    spec: &ValidatedBuildSpec,
) -> Result<&'a BuildTargetConfig> {
    let target = config
        .build
        .targets
        .iter()
        .find(|target| {
            target.artifact_type == spec.artifact_type
                && build_target_names_compatible(&target.target, &spec.target)
                && target.system == spec.system
        })
        .ok_or_else(|| {
            anyhow!("no configured build target matched artifact_type, target, and system")
        })?;
    if spec.build_input.is_some() {
        let configured_revision = pinned_nixpkgs_revision(&target.flake)
            .context("validate configured Blueprint nixpkgs pin")?;
        if spec.nixpkgs_commit.as_deref() != Some(configured_revision) {
            bail!(
                "Blueprint nixpkgs_commit does not match this Pulse target's reviewed source pin"
            );
        }
    }
    Ok(target)
}

fn build_target_names_compatible(configured: &str, requested: &str) -> bool {
    configured == requested
        || matches!(
            (configured, requested),
            ("desktop_experience", "blueprint")
                | ("blueprint", "desktop_experience")
                | ("blueprint", "installer_target")
                | ("desktop_experience", "installer_target")
        )
}

fn build_capacity() -> Result<BuildCapacity> {
    // Hardened systemd units may hide /proc/meminfo, so retain sysinfo(2) as a
    // fallback when the cgroup controller reports an unbounded root.
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
            "Pulse exhausted its build memory; increase memory/swap or reduce max_build_cores"
                .to_string(),
        );
    }
    if lower.contains("no space left on device") || lower.contains("disk full") {
        return (
            "insufficient_disk_space",
            "Pulse ran out of disk space while building the Nix closure".to_string(),
        );
    }
    if lower.contains("unable to start any build") {
        let candidates: Vec<String> =
            extract_would_build_derivations(logs, SOURCE_BUILD_CANDIDATE_CAP)
                .paths
                .iter()
                .map(|path| derivation_display_name(path))
                .collect();
        return (
            "source_build_blocked",
            source_build_blocked_message(&candidates),
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

const SOURCE_BUILD_CANDIDATE_CAP: usize = 50;
const PREFLIGHT_DRY_RUN_TIMEOUT_SECS: u64 = 600;
const PREFLIGHT_DERIVATION_SHOW_TIMEOUT_SECS: u64 = 120;
const PREFLIGHT_DERIVATION_SHOW_CHUNK: usize = 100;
const PREFLIGHT_WOULD_BUILD_CAP: usize = 4096;
const PREFLIGHT_DRY_RUN_STDOUT_MAX_BYTES: usize = 1024 * 1024;
const PREFLIGHT_DRY_RUN_STDERR_MAX_BYTES: usize = 4 * 1024 * 1024;
const PREFLIGHT_DERIVATION_SHOW_MAX_BYTES: usize = 64 * 1024 * 1024;
const PREFLIGHT_COMMAND_STDERR_MAX_BYTES: usize = 1024 * 1024;
const SOFTWARE_INVENTORY_PROBE_TIMEOUT_SECS: u64 = 15;
const SOFTWARE_INVENTORY_TOTAL_TIMEOUT_SECS: u64 = 120;
const SOFTWARE_INVENTORY_STDOUT_MAX_BYTES: usize = 16 * 1024;
const SOFTWARE_INVENTORY_STDERR_MAX_BYTES: usize = 64 * 1024;
const DISABLE_IFD_NIX_OPTION: [&str; 3] = ["--option", "allow-import-from-derivation", "false"];
const REJECT_FLAKE_CONFIG_NIX_OPTION: [&str; 3] = ["--option", "accept-flake-config", "false"];
const REQUIRE_BUILD_SANDBOX_NIX_OPTION: [&str; 3] = ["--option", "sandbox", "true"];

fn append_source_policy_nix_options(args: &mut Vec<String>, allow_source_builds: bool) {
    // Pulse is a trusted Nix client because it exports and signs closures.
    // Pin the daemon-side sandbox and refuse flake-supplied client settings on
    // every path so a Blueprint cannot use that trust to relax isolation.
    args.extend(
        REJECT_FLAKE_CONFIG_NIX_OPTION
            .iter()
            .map(|value| value.to_string()),
    );
    args.extend(
        REQUIRE_BUILD_SANDBOX_NIX_OPTION
            .iter()
            .map(|value| value.to_string()),
    );
    if !allow_source_builds {
        args.extend(DISABLE_IFD_NIX_OPTION.iter().map(|value| value.to_string()));
    }
}

#[derive(Clone, Copy)]
struct PreflightLimits {
    dry_run_timeout: Duration,
    derivation_show_timeout: Duration,
    dry_run_stdout_max_bytes: usize,
    dry_run_stderr_max_bytes: usize,
    derivation_show_stdout_max_bytes: usize,
    derivation_show_stderr_max_bytes: usize,
}

impl Default for PreflightLimits {
    fn default() -> Self {
        Self {
            dry_run_timeout: Duration::from_secs(PREFLIGHT_DRY_RUN_TIMEOUT_SECS),
            derivation_show_timeout: Duration::from_secs(PREFLIGHT_DERIVATION_SHOW_TIMEOUT_SECS),
            dry_run_stdout_max_bytes: PREFLIGHT_DRY_RUN_STDOUT_MAX_BYTES,
            dry_run_stderr_max_bytes: PREFLIGHT_DRY_RUN_STDERR_MAX_BYTES,
            derivation_show_stdout_max_bytes: PREFLIGHT_DERIVATION_SHOW_MAX_BYTES,
            derivation_show_stderr_max_bytes: PREFLIGHT_COMMAND_STDERR_MAX_BYTES,
        }
    }
}

#[derive(Clone, Copy)]
struct SoftwareInventoryLimits {
    probe_timeout: Duration,
    total_timeout: Duration,
    stdout_max_bytes: usize,
    stderr_max_bytes: usize,
}

impl Default for SoftwareInventoryLimits {
    fn default() -> Self {
        Self {
            probe_timeout: Duration::from_secs(SOFTWARE_INVENTORY_PROBE_TIMEOUT_SECS),
            total_timeout: Duration::from_secs(SOFTWARE_INVENTORY_TOTAL_TIMEOUT_SECS),
            stdout_max_bytes: SOFTWARE_INVENTORY_STDOUT_MAX_BYTES,
            stderr_max_bytes: SOFTWARE_INVENTORY_STDERR_MAX_BYTES,
        }
    }
}

struct BoundedCommandOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

async fn read_bounded_command_stream<R>(
    mut stream: R,
    limit: usize,
    label: &'static str,
) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut output = Vec::with_capacity(limit.min(16 * 1024));
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = stream
            .read(&mut buffer)
            .await
            .with_context(|| format!("read {label}"))?;
        if read == 0 {
            return Ok(output);
        }
        if output.len().saturating_add(read) > limit {
            bail!("{label} exceeded the {limit} byte source-policy limit");
        }
        output.extend_from_slice(&buffer[..read]);
    }
}

/// Capture both pipes concurrently and enforce bounds while bytes arrive. A
/// completed `Command::output` can already have allocated attacker-controlled
/// output, so source-policy subprocesses use this streaming primitive instead.
#[cfg(unix)]
fn command_spawn_is_transient(error: &io::Error) -> bool {
    error.raw_os_error() == Some(libc::ETXTBSY)
}

#[cfg(not(unix))]
fn command_spawn_is_transient(_error: &io::Error) -> bool {
    false
}

async fn spawn_bounded_command(
    command: &mut Command,
    label: &'static str,
) -> Result<tokio::process::Child> {
    const MAX_ATTEMPTS: usize = 8;

    for attempt in 0..MAX_ATTEMPTS {
        match command.spawn() {
            Ok(child) => return Ok(child),
            Err(error) if command_spawn_is_transient(&error) && attempt + 1 < MAX_ATTEMPTS => {
                // CLOEXEC takes effect at exec, so a concurrently forked
                // process can briefly retain a writer for an executable that
                // was just prepared. Retry only Linux/Unix ETXTBSY, with a
                // short bound; all other spawn failures remain fail-closed.
                sleep(Duration::from_millis(1_u64 << attempt.min(6))).await;
            }
            Err(error) => return Err(error).with_context(|| format!("run {label}")),
        }
    }
    unreachable!("bounded command spawn loop returns on its final attempt")
}

async fn run_bounded_command(
    mut command: Command,
    time_limit: Duration,
    stdout_limit: usize,
    stderr_limit: usize,
    label: &'static str,
) -> Result<BoundedCommandOutput> {
    command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    command.process_group(0);
    let mut child = spawn_bounded_command(&mut command, label).await?;
    let process_group = child.id();
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("capture {label} stdout"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow!("capture {label} stderr"))?;
    let mut stdout_capture = Box::pin(read_bounded_command_stream(
        stdout,
        stdout_limit,
        "source-policy command stdout",
    ));
    let mut stderr_capture = Box::pin(read_bounded_command_stream(
        stderr,
        stderr_limit,
        "source-policy command stderr",
    ));
    let deadline = sleep(time_limit);
    tokio::pin!(deadline);
    let mut status = None;
    let mut captured_stdout = None;
    let mut captured_stderr = None;

    enum CaptureEvent {
        Stdout(Result<Vec<u8>>),
        Stderr(Result<Vec<u8>>),
        Exit(std::io::Result<ExitStatus>),
        Timeout,
    }

    loop {
        let event = tokio::select! {
            result = &mut stdout_capture, if captured_stdout.is_none() => {
                CaptureEvent::Stdout(result)
            }
            result = &mut stderr_capture, if captured_stderr.is_none() => {
                CaptureEvent::Stderr(result)
            }
            result = child.wait(), if status.is_none() => CaptureEvent::Exit(result),
            _ = &mut deadline => CaptureEvent::Timeout,
        };
        match event {
            CaptureEvent::Stdout(Ok(output)) => captured_stdout = Some(output),
            CaptureEvent::Stderr(Ok(output)) => captured_stderr = Some(output),
            CaptureEvent::Exit(Ok(exit_status)) => status = Some(exit_status),
            CaptureEvent::Exit(Err(error)) => {
                terminate_bounded_command(&mut child, process_group).await;
                return Err(error).with_context(|| format!("wait for {label}"));
            }
            CaptureEvent::Stdout(Err(error)) | CaptureEvent::Stderr(Err(error)) => {
                terminate_bounded_command(&mut child, process_group).await;
                return Err(error).with_context(|| format!("capture {label}"));
            }
            CaptureEvent::Timeout => {
                terminate_bounded_command(&mut child, process_group).await;
                bail!("{label} timed out");
            }
        }
        if status.is_some() && captured_stdout.is_some() && captured_stderr.is_some() {
            let (Some(status), Some(stdout), Some(stderr)) = (
                status.take(),
                captured_stdout.take(),
                captured_stderr.take(),
            ) else {
                unreachable!("bounded command completion state was checked")
            };
            return Ok(BoundedCommandOutput {
                status,
                stdout,
                stderr,
            });
        }
    }
}

async fn terminate_bounded_command(child: &mut tokio::process::Child, process_group: Option<u32>) {
    #[cfg(unix)]
    if let Some(process_group) = process_group.and_then(|pid| i32::try_from(pid).ok()) {
        // The child is placed in a fresh process group before exec. Kill the
        // whole group so a helper that inherited stdout/stderr cannot outlive
        // a timed-out or overflowing source-policy command.
        unsafe {
            libc::kill(-process_group, libc::SIGKILL);
        }
    }
    let _ = child.start_kill();
    let _ = child.wait().await;
}

#[derive(Debug, Default, PartialEq, Eq)]
struct WouldBuildDerivations {
    paths: Vec<String>,
    marker_seen: bool,
    overflowed: bool,
    expected_count: usize,
    malformed: bool,
}

/// Parse nix's "these N derivations will be built:" block (from `--dry-run`
/// output or a captured build log) into `.drv` store paths, capped.
fn extract_would_build_derivations(text: &str, cap: usize) -> WouldBuildDerivations {
    let mut parsed = WouldBuildDerivations::default();
    let mut in_block = false;
    let mut unique = std::collections::HashSet::new();
    for line in text.lines() {
        let trimmed = line.trim();
        let advertised = if trimmed == "this derivation will be built:" {
            Some(1)
        } else {
            trimmed
                .strip_prefix("these ")
                .and_then(|rest| rest.strip_suffix(" derivations will be built:"))
                .and_then(|count| count.parse::<usize>().ok())
        };
        if let Some(advertised) = advertised {
            in_block = true;
            parsed.marker_seen = true;
            parsed.expected_count = match parsed.expected_count.checked_add(advertised) {
                Some(total) => total,
                None => {
                    parsed.overflowed = true;
                    usize::MAX
                }
            };
            if parsed.expected_count > cap {
                parsed.overflowed = true;
            }
            continue;
        }
        if in_block {
            if trimmed.starts_with("/nix/store/") && trimmed.ends_with(".drv") {
                if !unique.insert(trimmed.to_string()) {
                    parsed.malformed = true;
                } else if parsed.paths.len() < cap {
                    parsed.paths.push(trimmed.to_string());
                } else {
                    parsed.overflowed = true;
                }
                continue;
            }
            in_block = false;
        }
        if trimmed.contains(".drv") {
            parsed.malformed = true;
        }
    }
    if parsed.marker_seen && parsed.expected_count != unique.len() {
        parsed.malformed = true;
    }
    parsed
}

fn source_build_blocked_message(candidates: &[String]) -> String {
    let advice = "Replace source-built software with cache-backed native nixpkgs packages, \
                  or choose a pinned nixpkgs revision with substitutes. If source compilation \
                  is genuinely unavoidable, explicitly enable \"Allow building from source\" \
                  for this Blueprint.";
    if candidates.is_empty() {
        return format!(
            "Blocked: this build requires compiling packages from source, \
             which is not allowed for this Blueprint. {advice}"
        );
    }
    let shown = candidates
        .iter()
        .take(5)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    let suffix = if candidates.len() > 5 {
        format!(" (+{} more)", candidates.len() - 5)
    } else {
        String::new()
    };
    format!(
        "Blocked: {} package(s) are not available from the binary cache and would be \
         compiled from source: {shown}{suffix}. {advice}",
        candidates.len()
    )
}

/// Dry-run the build and return display names of derivations that would be
/// compiled from source. Only structurally constrained NixOS-generated glue
/// and plain, hash-verified downloads are exempt — an empty result means the
/// closure is fully substitutable apart from that bounded local materialization.
async fn preflight_source_build_check(
    config: &AppConfig,
    command: &NixBuildCommand,
) -> Result<Vec<String>> {
    preflight_source_build_check_with_limits(config, command, PreflightLimits::default()).await
}

async fn preflight_source_build_check_with_limits(
    config: &AppConfig,
    command: &NixBuildCommand,
    limits: PreflightLimits,
) -> Result<Vec<String>> {
    tokio::fs::create_dir_all(&config.build.work_dir)
        .await
        .with_context(|| {
            format!(
                "create build work directory {}",
                config.build.work_dir.display()
            )
        })?;
    let mut store_nonce = [0u8; 16];
    OsRng.fill_bytes(&mut store_nonce);
    let store_root = config
        .build
        .work_dir
        .join(format!("source-policy-store-{}", hex::encode(store_nonce)));
    tokio::fs::create_dir(&store_root)
        .await
        .with_context(|| format!("create isolated preflight store {}", store_root.display()))?;
    let result = preflight_source_build_check_in_store(config, command, &store_root, limits).await;
    let cleanup = remove_source_policy_store(&store_root).await;
    match (result, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error)
            .with_context(|| format!("remove isolated preflight store {}", store_root.display())),
    }
}

async fn remove_source_policy_store(store_root: &Path) -> Result<()> {
    let cleanup_path = store_root.to_path_buf();
    let display_path = cleanup_path.display().to_string();
    tokio::task::spawn_blocking(move || {
        make_source_policy_directories_owner_writable(&cleanup_path)?;
        fs::remove_dir_all(&cleanup_path)
    })
    .await
    .context("join isolated source-policy store cleanup")?
    .with_context(|| format!("remove isolated preflight store {display_path}"))
}

#[cfg(unix)]
fn make_source_policy_directories_owner_writable(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "source-policy cleanup root must be a real directory",
        ));
    }
    let mut permissions = metadata.permissions();
    permissions.set_mode(permissions.mode() | 0o700);
    fs::set_permissions(path, permissions)?;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            make_source_policy_directories_owner_writable(&entry.path())?;
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn make_source_policy_directories_owner_writable(path: &Path) -> std::io::Result<()> {
    fs::symlink_metadata(path).and_then(|metadata| {
        if metadata.is_dir() {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "source-policy cleanup root must be a directory",
            ))
        }
    })
}

async fn preflight_source_build_check_in_store(
    config: &AppConfig,
    command: &NixBuildCommand,
    store_root: &Path,
    limits: PreflightLimits,
) -> Result<Vec<String>> {
    let store_url = format!("local?root={}", store_root.display());
    let mut args = vec!["--store".to_string(), store_url.clone()];
    // `nix build --dry-run` may execute import-from-derivation dependencies
    // while evaluating the installable, before it prints the derivations that
    // would be built. Disable IFD at the command-line precedence layer so an
    // unadvertised evaluator-time build cannot bypass the classifier below.
    append_source_policy_nix_options(&mut args, false);
    args.extend([
        "build".to_string(),
        command.installable.clone(),
        "--dry-run".to_string(),
        "--no-write-lock-file".to_string(),
    ]);
    if let Some(position) = command.args.iter().position(|arg| arg == "--system") {
        if let Some(system) = command.args.get(position + 1) {
            args.extend(["--system".to_string(), system.clone()]);
        }
    }
    let mut dry_run = crate::nix_command::tokio_command(&command.program);
    dry_run
        .args(&args)
        .current_dir(&config.build.work_dir)
        .env("LC_ALL", "C")
        .env("LANG", "C");
    let output = run_bounded_command(
        dry_run,
        limits.dry_run_timeout,
        limits.dry_run_stdout_max_bytes,
        limits.dry_run_stderr_max_bytes,
        "nix build --dry-run",
    )
    .await?;
    if !output.status.success() {
        bail!(
            "nix build --dry-run failed: {}",
            bounded_diagnostic_tail(&output.stderr, 500)
        );
    }
    let mut dry_run_listing = String::from_utf8_lossy(&output.stdout).into_owned();
    dry_run_listing.push('\n');
    dry_run_listing.push_str(&String::from_utf8_lossy(&output.stderr));
    let parsed = extract_would_build_derivations(&dry_run_listing, PREFLIGHT_WOULD_BUILD_CAP);
    if parsed.overflowed {
        bail!(
            "nix build --dry-run listed more than {PREFLIGHT_WOULD_BUILD_CAP} local derivations; refusing to truncate source-policy verification"
        );
    }
    if parsed.malformed {
        bail!("nix build --dry-run did not yield the exact advertised set of local derivations");
    }
    let would_build = parsed.paths;
    if would_build.is_empty() {
        return Ok(Vec::new());
    }
    let would_build_set = would_build.iter().cloned().collect::<HashSet<_>>();
    let mut derivations = BTreeMap::<String, Value>::new();
    for chunk in would_build.chunks(PREFLIGHT_DERIVATION_SHOW_CHUNK) {
        let mut derivation_show = crate::nix_command::tokio_command(&command.program);
        derivation_show
            .arg("--store")
            .arg(&store_url)
            .arg("derivation")
            .arg("show")
            .args(chunk)
            .env("LC_ALL", "C")
            .env("LANG", "C");
        let output = run_bounded_command(
            derivation_show,
            limits.derivation_show_timeout,
            limits.derivation_show_stdout_max_bytes,
            limits.derivation_show_stderr_max_bytes,
            "nix derivation show",
        )
        .await?;
        if !output.status.success() {
            bail!(
                "nix derivation show failed: {}",
                bounded_diagnostic_tail(&output.stderr, 500)
            );
        }
        let value: Value =
            serde_json::from_slice(&output.stdout).context("parse nix derivation show JSON")?;
        for path in chunk {
            if let Some(drv) = lookup_derivation(&value, path) {
                derivations.insert(path.clone(), drv.clone());
            }
        }
    }

    // NixOS system closures contain a DAG of small, configuration-only
    // derivations. A reviewed link farm can legitimately consume another
    // reviewed materializer from the same dry-run set (for example the GTK
    // cache consumes the reviewed IBus wrapper). Classify that DAG to a fixed
    // point instead of treating every local dependency as source compilation.
    // A derivation joins the trusted set only after every one of its local
    // input derivations has independently passed the strict grammar below.
    let verify_source = |path: &str, expected: &str| {
        isolated_store_source_matches_sha256(store_root, path, expected)
    };
    let trusted_local = classify_trusted_local_derivations(
        &would_build,
        &derivations,
        &verify_source,
        &would_build_set,
    );

    let mut offenders = would_build
        .iter()
        .filter(|path| !trusted_local.contains(*path))
        .map(|path| derivation_display_name(path))
        .collect::<Vec<_>>();
    offenders.truncate(SOURCE_BUILD_CANDIDATE_CAP);
    Ok(offenders)
}

fn bounded_diagnostic_tail(bytes: &[u8], max_chars: usize) -> String {
    let text = String::from_utf8_lossy(bytes);
    let skip = text.chars().count().saturating_sub(max_chars);
    text.chars().skip(skip).collect()
}

fn classify_trusted_local_derivations<F>(
    would_build: &[String],
    derivations: &BTreeMap<String, Value>,
    verify_source: &F,
    would_build_set: &HashSet<String>,
) -> HashSet<String>
where
    F: Fn(&str, &str) -> bool,
{
    let mut trusted_local = HashSet::<String>::new();
    for _ in 0..would_build.len() {
        let mut changed = false;
        for path in would_build {
            if trusted_local.contains(path) {
                continue;
            }
            if derivation_is_exempt_from_source_policy_with_verifier_and_would_build_and_trusted(
                path,
                derivations.get(path),
                verify_source,
                would_build_set,
                &trusted_local,
            ) {
                changed |= trusted_local.insert(path.clone());
            }
        }
        if !changed {
            break;
        }
    }
    trusted_local
}

fn isolated_store_source_matches_sha256(root: &Path, logical_path: &str, expected: &str) -> bool {
    let Ok(relative) = Path::new(logical_path).strip_prefix("/nix/store") else {
        return false;
    };
    if relative
        .components()
        .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return false;
    }
    let physical = root.join("nix/store").join(relative);
    fs::read(physical).ok().is_some_and(|bytes| {
        let digest = Sha256::digest(bytes);
        hex::encode(digest) == expected
    })
}

/// Find a derivation entry in `nix derivation show` JSON. Older nix keys the
/// top-level object by full store path; nix 2.30+ nests entries under
/// `derivations` keyed by drv basename.
fn lookup_derivation<'value>(value: &'value Value, drv_path: &str) -> Option<&'value Value> {
    let map = value
        .get("derivations")
        .and_then(Value::as_object)
        .or_else(|| value.as_object())?;
    if let Some(entry) = map.get(drv_path) {
        return Some(entry);
    }
    map.get(drv_path.rsplit('/').next().unwrap_or(drv_path))
}

/// Attribute names in a derivation are not provenance. A Blueprint can author
/// its own `runCommand`/`mkDerivation` and set every environment attribute. An
/// exemption therefore needs both pinned nixpkgs materializer bytes and one of
/// the small, non-compiling grammars below.
#[cfg(test)]
fn derivation_is_exempt_from_source_policy(drv_path: &str, drv: Option<&Value>) -> bool {
    derivation_is_exempt_from_source_policy_with_verifier(drv_path, drv, &source_matches_sha256)
}

#[cfg(test)]
fn derivation_is_exempt_from_source_policy_with_verifier<F>(
    drv_path: &str,
    drv: Option<&Value>,
    verify_source: &F,
) -> bool
where
    F: Fn(&str, &str) -> bool,
{
    derivation_is_exempt_from_source_policy_with_verifier_and_would_build(
        drv_path,
        drv,
        verify_source,
        &HashSet::new(),
    )
}

#[cfg(test)]
fn derivation_is_exempt_from_source_policy_with_verifier_and_would_build<F>(
    drv_path: &str,
    drv: Option<&Value>,
    verify_source: &F,
    would_build: &HashSet<String>,
) -> bool
where
    F: Fn(&str, &str) -> bool,
{
    derivation_is_exempt_from_source_policy_with_verifier_and_would_build_and_trusted(
        drv_path,
        drv,
        verify_source,
        would_build,
        &HashSet::new(),
    )
}

fn derivation_is_exempt_from_source_policy_with_verifier_and_would_build_and_trusted<F>(
    drv_path: &str,
    drv: Option<&Value>,
    verify_source: &F,
    would_build: &HashSet<String>,
    trusted_local: &HashSet<String>,
) -> bool
where
    F: Fn(&str, &str) -> bool,
{
    let Some(drv) = drv else {
        return false;
    };
    let attrs = derivation_attributes(drv);
    if [
        "__cybex_conflicting_derivation_attributes",
        "__cybex_invalid_derivation_attributes",
    ]
    .iter()
    .any(|key| attrs.get(*key).and_then(Value::as_bool) == Some(true))
        || !local_input_derivations_are_trusted(drv, would_build, trusted_local)
    {
        return false;
    }
    derivation_is_plain_fixed_output_fetch(drv, &attrs)
        || (stdenv_builder_and_tool_inputs_are_trusted(drv, &attrs, would_build, trusted_local)
            && ((!derivation_has_shell_environment_injection(&attrs)
                && (derivation_is_pinned_nixos_materialization(
                    drv,
                    &attrs,
                    verify_source,
                    would_build,
                    trusted_local,
                ) || derivation_is_reviewed_nixos_generator(
                    drv,
                    &attrs,
                    verify_source,
                    would_build,
                    trusted_local,
                ) || derivation_is_nixos_substitution_glue(
                    drv,
                    &attrs,
                    verify_source,
                    would_build,
                    trusted_local,
                ) || derivation_is_reviewed_low_level_substitution(
                    drv,
                    &attrs,
                    verify_source,
                    would_build,
                    trusted_local,
                )))
                || derivation_is_nixos_security_wrapper(
                    drv_path,
                    drv,
                    &attrs,
                    verify_source,
                    would_build,
                    trusted_local,
                )))
}

#[cfg(test)]
fn source_matches_sha256(path: &str, expected: &str) -> bool {
    if !path.starts_with("/nix/store/") {
        return false;
    }
    fs::read(path).ok().is_some_and(|bytes| {
        let digest = Sha256::digest(bytes);
        hex::encode(digest) == expected
    })
}

fn normalized_script_sha256(script: &str) -> String {
    script_sha256_with_store_path_policy(script, false)
}

fn executable_pinned_script_sha256(script: &str) -> String {
    script_sha256_with_store_path_policy(script, true)
}

fn script_store_item_paths(script: &str) -> Option<HashSet<String>> {
    let bytes = script.as_bytes();
    let mut paths = HashSet::new();
    let mut index = 0;
    const PREFIX: &[u8] = b"/nix/store/";
    while index < bytes.len() {
        if !bytes[index..].starts_with(PREFIX) {
            index += 1;
            continue;
        }
        let path_start = index;
        index += PREFIX.len();
        let hash_end = index.checked_add(32)?;
        if hash_end >= bytes.len()
            || bytes[hash_end] != b'-'
            || !bytes[index..hash_end]
                .iter()
                .all(|byte| b"0123456789abcdfghijklmnpqrsvwxyz".contains(byte))
        {
            return None;
        }
        let name_start = hash_end + 1;
        let mut path_end = name_start;
        while path_end < bytes.len()
            && (bytes[path_end].is_ascii_alphanumeric()
                || matches!(bytes[path_end], b'.' | b'_' | b'+' | b'-'))
        {
            path_end += 1;
        }
        if path_end == name_start {
            return None;
        }
        let path = std::str::from_utf8(&bytes[path_start..path_end])
            .ok()?
            .to_string();
        if !safe_nix_store_path(&path) {
            return None;
        }
        paths.insert(path);
        index = path_end;
    }
    Some(paths)
}

fn script_store_item_paths_are_trusted(
    drv: &Value,
    script: &str,
    would_build: &HashSet<String>,
    trusted_local: &HashSet<String>,
) -> bool {
    script_store_item_paths(script).is_some_and(|paths| {
        !paths.is_empty()
            && paths.iter().all(|path| {
                input_drv_output_reference(drv, path).is_some_and(|reference| {
                    input_derivation_is_nonlocal_or_trusted(
                        &reference.drv_path,
                        would_build,
                        trusted_local,
                    )
                })
            })
    })
}

fn script_sha256_with_store_path_policy(script: &str, preserve_executables: bool) -> String {
    let bytes = script.as_bytes();
    let mut normalized = Vec::with_capacity(bytes.len());
    let mut index = 0;
    const PREFIX: &[u8] = b"/nix/store/";
    while index < bytes.len() {
        if bytes[index..].starts_with(PREFIX) {
            normalized.extend_from_slice(PREFIX);
            index += PREFIX.len();
            let hash_end = index.saturating_add(32);
            if hash_end < bytes.len()
                && bytes[hash_end] == b'-'
                && bytes[index..hash_end]
                    .iter()
                    .all(|byte| b"0123456789abcdfghijklmnpqrsvwxyz".contains(byte))
            {
                let name_start = hash_end + 1;
                let mut store_item_end = name_start;
                while store_item_end < bytes.len()
                    && (bytes[store_item_end].is_ascii_alphanumeric()
                        || matches!(bytes[store_item_end], b'.' | b'_' | b'+' | b'-'))
                {
                    store_item_end += 1;
                }
                let executable_subpath = bytes[store_item_end..].starts_with(b"/bin/")
                    || bytes[store_item_end..].starts_with(b"/sbin/")
                    || bytes[store_item_end..].starts_with(b"/libexec/")
                    || bytes[store_item_end..].starts_with(b"/nix-support/setup-hook");
                if preserve_executables && executable_subpath {
                    normalized.extend_from_slice(&bytes[index..hash_end]);
                } else {
                    normalized.extend_from_slice(b"<hash>");
                }
                index = hash_end;
                continue;
            }
        }
        normalized.push(bytes[index]);
        index += 1;
    }
    hex::encode(Sha256::digest(normalized))
}

/// Nix 2.26 serializes `__structuredAttrs` inside `env.__json`, while newer
/// releases expose `structuredAttrs` directly. Merge both shapes with the
/// ordinary string environment so policy decisions do not depend on the Nix
/// client version installed on Pulse.
fn derivation_attributes(drv: &Value) -> serde_json::Map<String, Value> {
    let mut merged = serde_json::Map::new();
    let mut conflict = false;
    let mut invalid = false;
    if let Some(env_value) = drv.get("env") {
        if let Some(env) = env_value.as_object() {
            if let Some(encoded_value) = env.get("__json") {
                match encoded_value
                    .as_str()
                    .and_then(|encoded| serde_json::from_str::<Value>(encoded).ok())
                {
                    Some(Value::Object(structured)) => {
                        for (key, value) in structured {
                            merge_derivation_attribute(&mut merged, &mut conflict, key, value);
                        }
                    }
                    _ => invalid = true,
                }
            }
            for (key, value) in env.iter().filter(|(key, _)| key.as_str() != "__json") {
                merge_derivation_attribute(&mut merged, &mut conflict, key.clone(), value.clone());
            }
        } else {
            invalid = true;
        }
    }
    if let Some(structured_value) = drv.get("structuredAttrs") {
        if let Some(structured) = structured_value.as_object() {
            for (key, value) in structured {
                merge_derivation_attribute(&mut merged, &mut conflict, key.clone(), value.clone());
            }
        } else {
            invalid = true;
        }
    }
    if conflict {
        merged.insert(
            "__cybex_conflicting_derivation_attributes".to_string(),
            Value::Bool(true),
        );
    }
    if invalid {
        merged.insert(
            "__cybex_invalid_derivation_attributes".to_string(),
            Value::Bool(true),
        );
    }
    merged
}

fn merge_derivation_attribute(
    merged: &mut serde_json::Map<String, Value>,
    conflict: &mut bool,
    key: String,
    value: Value,
) {
    if merged.get(&key).is_some_and(|existing| existing != &value) {
        *conflict = true;
    } else {
        merged.insert(key, value);
    }
}

fn derivation_attr_truthy(attrs: &serde_json::Map<String, Value>, key: &str) -> bool {
    attrs.get(key).is_some_and(|value| {
        value.as_bool() == Some(true) || matches!(value.as_str(), Some("1" | "true"))
    })
}

fn derivation_attr_text<'a>(attrs: &'a serde_json::Map<String, Value>, key: &str) -> &'a str {
    attrs.get(key).and_then(Value::as_str).unwrap_or("")
}

fn derivation_attr_is_empty(attrs: &serde_json::Map<String, Value>, key: &str) -> bool {
    match attrs.get(key) {
        None | Some(Value::Null) => true,
        Some(Value::Bool(value)) => !value,
        Some(Value::String(value)) => value.trim().is_empty(),
        Some(Value::Array(value)) => value.is_empty(),
        Some(Value::Object(value)) => value.is_empty(),
        Some(Value::Number(_)) => false,
    }
}

/// Environment variables interpreted by the shell or an invoked interpreter
/// can execute code before an otherwise reviewed command. Nix derivation
/// attributes become process environment entries, so fail closed on startup
/// hooks, exported functions, loader injection, and interpreter option paths.
fn derivation_has_shell_environment_injection(attrs: &serde_json::Map<String, Value>) -> bool {
    derivation_has_shell_environment_injection_except(attrs, &[])
}

fn derivation_has_shell_environment_injection_except(
    attrs: &serde_json::Map<String, Value>,
    allowed: &[&str],
) -> bool {
    const UNSAFE: &[&str] = &[
        "AR",
        "AS",
        "AWKPATH",
        "BASH_ENV",
        "BASH_LOADABLES_PATH",
        "BASHOPTS",
        "BASH_XTRACEFD",
        "CC",
        "CXX",
        "C_INCLUDE_PATH",
        "CPLUS_INCLUDE_PATH",
        "CLASSPATH",
        "COMPILER_PATH",
        "CONFIG_SHELL",
        "CPATH",
        "ENV",
        "GCC_EXEC_PREFIX",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
        "GOFLAGS",
        "JAVA_TOOL_OPTIONS",
        "JDK_JAVA_OPTIONS",
        "SHELLOPTS",
        "LD_AUDIT",
        "LD",
        "LD_LIBRARY_PATH",
        "LD_PRELOAD",
        "LIBRARY_PATH",
        "LUA_CPATH",
        "LUA_PATH",
        "NM",
        "PATH",
        "NIX_BUILD_SHELL",
        "NIX_ATTRS_JSON_FILE",
        "NIX_ATTRS_SH_FILE",
        "NIX_CFLAGS_COMPILE",
        "NIX_CFLAGS_LINK",
        "NIX_LDFLAGS",
        "NIX_LD",
        "NIX_LD_LIBRARY_PATH",
        "OBJCOPY",
        "OBJC_INCLUDE_PATH",
        "OBJDUMP",
        "PERL5OPT",
        "PERL5LIB",
        "PS4",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "RANLIB",
        "READELF",
        "RUBYLIB",
        "RUBYOPT",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "RUSTFLAGS",
        "SHELL",
        "_HOST_PATH",
        "_PATH",
        "STRIP",
        "NODE_OPTIONS",
    ];
    attrs.iter().any(|(key, value)| {
        !allowed.contains(&key.as_str())
            && (UNSAFE.contains(&key.as_str())
                || key.starts_with("BASH_FUNC_")
                || key.starts_with("CCACHE")
                || key.starts_with("SCCACHE"))
            && !matches!(value, Value::Null)
            && !value.as_str().is_some_and(str::is_empty)
    })
}

fn only_reviewed_phase_hooks(attrs: &serde_json::Map<String, Value>, allowed: &[&str]) -> bool {
    const EXECUTABLE_PHASE_ATTRS: &[&str] = &[
        "buildCommandPath",
        "preHook",
        "addInputsHook",
        "postHook",
        "userHook",
        "failureHook",
        "exitHook",
        "prePhases",
        "postPhases",
        "phases",
        "preUnpack",
        "unpackPhase",
        "postUnpack",
        "prePatch",
        "patchPhase",
        "postPatch",
        "preConfigurePhases",
        "preConfigure",
        "configurePhase",
        "postConfigure",
        "preBuildPhases",
        "preBuild",
        "buildPhase",
        "postBuild",
        "preCheck",
        "checkPhase",
        "postCheck",
        "preInstallPhases",
        "preInstall",
        "installPhase",
        "postInstall",
        "preFixupPhases",
        "preFixup",
        "fixupPhase",
        "postFixup",
        "preInstallCheck",
        "installCheckPhase",
        "postInstallCheck",
        "preDistPhases",
        "preDist",
        "distPhase",
        "postDist",
        "setupHook",
        "setupHooks",
        "shellHook",
    ];
    attrs.iter().all(|(key, _)| {
        let executable = EXECUTABLE_PHASE_ATTRS.contains(&key.as_str())
            || key.ends_with("Hook")
            || key.ends_with("Hooks")
            || key.ends_with("Phases");
        !executable || allowed.contains(&key.as_str()) || derivation_attr_is_empty(attrs, key)
    })
}

fn safe_nix_store_path(value: &str) -> bool {
    let Some(relative) = value.strip_prefix("/nix/store/") else {
        return false;
    };
    let components = relative.split('/').collect::<Vec<_>>();
    if components.is_empty()
        || components.iter().any(|component| component.is_empty())
        || components.iter().skip(1).any(|component| {
            matches!(
                Path::new(component).components().next(),
                Some(std::path::Component::CurDir | std::path::Component::ParentDir)
            ) || Path::new(component).components().count() != 1
        })
    {
        return false;
    }
    let store_item = components[0];
    let Some((hash, name)) = store_item.split_once('-') else {
        return false;
    };
    hash.len() == 32
        && hash
            .bytes()
            .all(|byte| b"0123456789abcdfghijklmnpqrsvwxyz".contains(&byte))
        && !name.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'+' | b'-')
        })
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct InputOutputReference {
    drv_path: String,
    output: String,
}

#[derive(Clone, Copy)]
struct ReviewedStoreOutput {
    path: &'static str,
    drv_path: &'static str,
    output: &'static str,
}

const TRUSTED_STDENV_NO_CC_OUTPUT: ReviewedStoreOutput = ReviewedStoreOutput {
    path: TRUSTED_STDENV_NO_CC,
    drv_path: TRUSTED_STDENV_NO_CC_DRV,
    output: "out",
};

const TRUSTED_STDENV_FULL_OUTPUT: ReviewedStoreOutput = ReviewedStoreOutput {
    path: TRUSTED_STDENV_FULL,
    drv_path: TRUSTED_STDENV_FULL_DRV,
    output: "out",
};

const TRUSTED_STDENV_STATIC_OUTPUT: ReviewedStoreOutput = ReviewedStoreOutput {
    path: TRUSTED_STDENV_STATIC,
    drv_path: TRUSTED_STDENV_STATIC_DRV,
    output: "out",
};

fn input_drv_output_reference(drv: &Value, path: &str) -> Option<InputOutputReference> {
    let mut matching = input_drv_output_references(drv, path)?;
    if matching.len() == 1 {
        matching.pop()
    } else {
        None
    }
}

fn input_drv_output_references(drv: &Value, path: &str) -> Option<Vec<InputOutputReference>> {
    if !safe_nix_store_path(path) {
        return None;
    }
    let store_item = path.strip_prefix("/nix/store/")?.split('/').next()?;
    let mut matching = Vec::new();
    for (input_drv, outputs) in derivation_input_drvs(drv)? {
        let drv_store_item = input_drv.rsplit('/').next()?.strip_suffix(".drv")?;
        let (_, drv_name) = drv_store_item.split_once('-')?;
        for output in outputs {
            let expected_name = if output == "out" {
                drv_name.to_string()
            } else {
                format!("{drv_name}-{output}")
            };
            if store_item
                .split_once('-')
                .is_some_and(|(_, name)| name == expected_name)
            {
                matching.push(InputOutputReference {
                    drv_path: input_drv.clone(),
                    output: output.to_string(),
                });
            }
        }
    }
    Some(matching)
}

/// Nix 2.34's derivation JSON v4 nests inputs and gives each input derivation
/// explicit `outputs` and `dynamicOutputs` metadata. Versions 1-3 use sibling
/// `inputDrvs`/`inputSrcs` fields and encode outputs as an array. Nix 2.26 also
/// emits an unversioned sibling form with the exact v4 metadata object. Parse
/// exactly one complete, internally consistent schema, reject unknown/dynamic
/// metadata, and normalize store basenames before making provenance decisions.
struct NormalizedDerivationInputs {
    drvs: Vec<(String, Vec<String>)>,
    srcs: Vec<String>,
}

fn derivation_inputs(drv: &Value) -> Option<NormalizedDerivationInputs> {
    let version = match drv.get("version") {
        Some(version) => Some(version.as_u64()?),
        None => None,
    };
    let (drv_entries, source_values, structured_metadata) = match (
        drv.get("inputDrvs"),
        drv.get("inputSrcs"),
        drv.get("inputs"),
    ) {
        (Some(drvs), Some(srcs), None)
            if version.is_none_or(|version| (1..=3).contains(&version)) =>
        {
            let drvs = drvs.as_object()?;
            let structured_metadata = if drvs.is_empty() || drvs.values().all(Value::is_array) {
                false
            } else if version.is_none() && drvs.values().all(Value::is_object) {
                true
            } else {
                return None;
            };
            (drvs, srcs.as_array()?, structured_metadata)
        }
        (None, None, Some(inputs)) if version == Some(4) => {
            let inputs = inputs.as_object()?;
            if inputs.len() != 2 || !inputs.contains_key("drvs") || !inputs.contains_key("srcs") {
                return None;
            }
            (
                inputs.get("drvs")?.as_object()?,
                inputs.get("srcs")?.as_array()?,
                true,
            )
        }
        _ => return None,
    };

    let drvs = drv_entries
        .iter()
        .map(|(path, metadata)| {
            let path = normalize_derivation_store_path(path)?;
            let values = if structured_metadata {
                let metadata = metadata.as_object()?;
                if metadata.len() != 2
                    || !metadata
                        .get("dynamicOutputs")
                        .and_then(Value::as_object)
                        .is_some_and(serde_json::Map::is_empty)
                {
                    return None;
                }
                metadata.get("outputs")?.as_array()?
            } else {
                metadata.as_array()?
            };
            let outputs = normalize_derivation_output_names(values)?;
            Some((path, outputs))
        })
        .collect::<Option<Vec<_>>>()?;
    let mut unique_sources = HashSet::new();
    let srcs = source_values
        .iter()
        .map(|value| {
            let path = normalize_store_path(value.as_str()?)?;
            unique_sources.insert(path.clone()).then_some(path)
        })
        .collect::<Option<Vec<_>>>()?;
    Some(NormalizedDerivationInputs { drvs, srcs })
}

fn normalize_store_path(path: &str) -> Option<String> {
    let path = if path.starts_with("/nix/store/") {
        path.to_string()
    } else if !path.contains('/') {
        format!("/nix/store/{path}")
    } else {
        return None;
    };
    safe_nix_store_path(&path).then_some(path)
}

fn normalize_derivation_store_path(path: &str) -> Option<String> {
    let path = normalize_store_path(path)?;
    path.ends_with(".drv").then_some(path)
}

fn normalize_derivation_output_names(values: &[Value]) -> Option<Vec<String>> {
    let mut unique = HashSet::new();
    values
        .iter()
        .map(|value| {
            let output = value.as_str()?;
            if output.is_empty()
                || !output
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'+' | b'-'))
                || !unique.insert(output.to_string())
            {
                return None;
            }
            Some(output.to_string())
        })
        .collect()
}

fn derivation_input_drvs(drv: &Value) -> Option<Vec<(String, Vec<String>)>> {
    Some(derivation_inputs(drv)?.drvs)
}

fn derivation_input_sources(drv: &Value) -> Option<Vec<String>> {
    Some(derivation_inputs(drv)?.srcs)
}

fn store_path_has_matching_input_derivation(drv: &Value, path: &str) -> bool {
    input_drv_output_reference(drv, path).is_some()
}

fn local_input_derivations_are_trusted(
    drv: &Value,
    would_build: &HashSet<String>,
    trusted_local: &HashSet<String>,
) -> bool {
    derivation_input_drvs(drv).is_some_and(|inputs| {
        inputs
            .iter()
            .all(|(path, _)| !would_build.contains(path) || trusted_local.contains(path))
    })
}

fn input_derivation_is_nonlocal_or_trusted(
    drv_path: &str,
    would_build: &HashSet<String>,
    trusted_local: &HashSet<String>,
) -> bool {
    !would_build.contains(drv_path) || trusted_local.contains(drv_path)
}

#[cfg(test)]
fn reviewed_store_output_is_nonlocal(
    drv: &Value,
    actual_path: &str,
    expected: ReviewedStoreOutput,
    would_build: &HashSet<String>,
) -> bool {
    actual_path == expected.path
        && input_drv_output_reference(drv, actual_path).is_some_and(|reference| {
            reference.drv_path == expected.drv_path
                && reference.output == expected.output
                && !would_build.contains(&reference.drv_path)
        })
}

fn reviewed_store_output_is_trusted(
    drv: &Value,
    actual_path: &str,
    expected: ReviewedStoreOutput,
    would_build: &HashSet<String>,
    trusted_local: &HashSet<String>,
) -> bool {
    actual_path == expected.path
        && input_drv_output_reference(drv, actual_path).is_some_and(|reference| {
            reference.drv_path == expected.drv_path
                && reference.output == expected.output
                && input_derivation_is_nonlocal_or_trusted(
                    &reference.drv_path,
                    would_build,
                    trusted_local,
                )
        })
}

fn is_stdenv_tool_input_attribute(key: &str) -> bool {
    matches!(
        key,
        "buildInputs"
            | "nativeBuildInputs"
            | "propagatedBuildInputs"
            | "propagatedNativeBuildInputs"
            | "checkInputs"
            | "nativeCheckInputs"
    ) || key.starts_with("deps")
}

fn parse_stdenv_tool_input_paths(
    attrs: &serde_json::Map<String, Value>,
) -> Option<BTreeMap<String, Vec<String>>> {
    let mut parsed = BTreeMap::new();
    for (key, value) in attrs
        .iter()
        .filter(|(key, _)| is_stdenv_tool_input_attribute(key))
    {
        let paths = match value {
            Value::Null | Value::Bool(false) => Vec::new(),
            Value::String(value) => value
                .split_ascii_whitespace()
                .map(str::to_string)
                .collect::<Vec<_>>(),
            Value::Array(values) => values
                .iter()
                .map(|value| {
                    let path = value.as_str()?;
                    if path.split_ascii_whitespace().count() != 1 {
                        return None;
                    }
                    Some(path.to_string())
                })
                .collect::<Option<Vec<_>>>()?,
            _ => return None,
        };
        let mut unique = HashSet::new();
        if paths.iter().any(|path| {
            !safe_nix_store_path(path)
                || path
                    .strip_prefix("/nix/store/")
                    .is_none_or(|relative| relative.contains('/'))
                || !unique.insert(path.clone())
        }) {
            return None;
        }
        parsed.insert(key.clone(), paths);
    }
    Some(parsed)
}

fn stdenv_tool_inputs_are_empty(attrs: &serde_json::Map<String, Value>) -> bool {
    parse_stdenv_tool_input_paths(attrs).is_some_and(|inputs| inputs.values().all(Vec::is_empty))
}

fn stdenv_builder_and_tool_inputs_are_trusted(
    drv: &Value,
    attrs: &serde_json::Map<String, Value>,
    would_build: &HashSet<String>,
    trusted_local: &HashSet<String>,
) -> bool {
    let builder = drv.get("builder").and_then(Value::as_str).unwrap_or("");
    let Some(builder_reference) = input_drv_output_reference(drv, builder) else {
        return false;
    };
    if builder != TRUSTED_STDENV_BASH_BUILDER
        || builder_reference.drv_path != TRUSTED_STDENV_BASH_DRV
        || builder_reference.output != "out"
        || !input_derivation_is_nonlocal_or_trusted(
            &builder_reference.drv_path,
            would_build,
            trusted_local,
        )
    {
        return false;
    }
    let Some(inputs) = parse_stdenv_tool_input_paths(attrs) else {
        return false;
    };
    inputs.values().flatten().all(|path| {
        input_drv_output_reference(drv, path).is_some_and(|reference| {
            input_derivation_is_nonlocal_or_trusted(&reference.drv_path, would_build, trusted_local)
        })
    })
}

#[derive(Clone, Copy)]
struct ReviewedToolInput {
    attribute: &'static str,
    path: &'static str,
    drv_path: &'static str,
    output: &'static str,
}

const DBUS_GENERATOR_TOOL_INPUTS: &[ReviewedToolInput] = &[
    ReviewedToolInput {
        attribute: "buildInputs",
        path: "/nix/store/165rncxlyi4f9pjf1zk3hmj3mh2v881w-dbus-1.16.2",
        drv_path: "/nix/store/33qh8fiidsm5bg722d1pirdhqwjp8d87-dbus-1.16.2.drv",
        output: "out",
    },
    ReviewedToolInput {
        attribute: "nativeBuildInputs",
        path: "/nix/store/498qnbvjw49sgap3z1fj81mrjm5r2kk8-libxslt-1.1.45-bin",
        drv_path: "/nix/store/2dr63bld5k49y7jzsa9vnjj0s1p98vk4-libxslt-1.1.45.drv",
        output: "bin",
    },
    ReviewedToolInput {
        attribute: "nativeBuildInputs",
        path: "/nix/store/93bjlzpa0w7cg6fmpkgxa7494ac9rwf8-find-xml-catalogs-hook",
        drv_path: "/nix/store/6cgb46lcvnzjasl1qx1rkds76v00kyrl-find-xml-catalogs-hook.drv",
        output: "out",
    },
];

const UDEV_GENERATOR_TOOL_INPUTS: &[ReviewedToolInput] = &[ReviewedToolInput {
    attribute: "nativeBuildInputs",
    path: "/nix/store/rz3ss5filvbbwi9f36g1dw2f95sasqbq-systemd-minimal-260.2",
    drv_path: "/nix/store/6fp0app8kf3sijhh8z6xpgyp39m3pfv0-systemd-minimal-260.2.drv",
    output: "out",
}];

// The current native initrd assembler is also local glue, but it invokes only
// these two pinned cache-backed tools. Keep this descriptor separate so a
// change to either provider requires an explicit source-lock review.
const INITRD_GENERATOR_TOOL_INPUTS: &[ReviewedToolInput] = &[
    ReviewedToolInput {
        attribute: "nativeBuildInputs",
        path: "/nix/store/qi6pv56kjs30bphl10iq4vvs9pbvc5kh-make-initrd-ng-0.1.0",
        drv_path: "/nix/store/v5wn5ka72szkj6f66l03k98i4rj38bq1-make-initrd-ng-0.1.0.drv",
        output: "out",
    },
    ReviewedToolInput {
        attribute: "nativeBuildInputs",
        path: "/nix/store/bbfrw9pncsp5pvybrfp26swb93vy8f9g-cpio-2.15",
        drv_path: "/nix/store/p5gqgqbr9jy12zw97kysdsplg77qilh0-cpio-2.15.drv",
        output: "out",
    },
];

const NIXOS_GENERATE_CONFIG_TOOL_INPUTS: &[ReviewedToolInput] = &[ReviewedToolInput {
    attribute: "nativeBuildInputs",
    path: "/nix/store/4f9rxg7fl8fii4gmhfr2prs475hzz7jx-install-shell-files",
    drv_path: "/nix/store/xk8m6ai5q00gr0h3vm8afc5dk1plpw9i-install-shell-files.drv",
    output: "out",
}];

const BINARY_WRAPPER_TOOL_INPUTS: &[ReviewedToolInput] = &[ReviewedToolInput {
    attribute: "nativeBuildInputs",
    path: "/nix/store/jhidhrz2syhvmk8vxc2jcwi66sncghrp-make-binary-wrapper-hook",
    drv_path: "/nix/store/2i32ilwfs86wl1wgp0f1672l1rj5niqc-make-binary-wrapper-hook.drv",
    output: "out",
}];

const PERL_ENV_LINK_FARM_TOOL_INPUTS: &[ReviewedToolInput] = &[
    ReviewedToolInput {
        attribute: "nativeBuildInputs",
        path: "/nix/store/jhidhrz2syhvmk8vxc2jcwi66sncghrp-make-binary-wrapper-hook",
        drv_path: "/nix/store/2i32ilwfs86wl1wgp0f1672l1rj5niqc-make-binary-wrapper-hook.drv",
        output: "out",
    },
    ReviewedToolInput {
        attribute: "nativeBuildInputs",
        path: "/nix/store/xcnqqnhw9hb4j5rjgds2yjryi8qki5f3-gcc-wrapper-15.2.0",
        drv_path: "/nix/store/bmwhgbaq6jk87imr4nsldixk9ccc1vl4-gcc-wrapper-15.2.0.drv",
        output: "out",
    },
];

const IBUS_LINK_FARM_TOOL_INPUTS: &[ReviewedToolInput] = &[
    ReviewedToolInput {
        attribute: "buildInputs",
        path: "/nix/store/vrhy5h1drqi3fjp6a9yksz0xz2la95bq-ibus-1.5.33-dev",
        drv_path: "/nix/store/kk5gag58ji0f39p8bnraff7aq6h6gh2a-ibus-1.5.33.drv",
        output: "dev",
    },
    ReviewedToolInput {
        attribute: "nativeBuildInputs",
        path: "/nix/store/f16vss2p6m6r7h7a81473x31gqj8j4ha-make-shell-wrapper-hook",
        drv_path: "/nix/store/426mziy0yn9wijy39xhacyajjnbqdngr-make-shell-wrapper-hook.drv",
        output: "out",
    },
];

const GTK_IMMODULE_TOOL_INPUTS: &[ReviewedToolInput] = &[ReviewedToolInput {
    attribute: "buildInputs",
    path: "/nix/store/nc7gb32v570a0q1nb70a4gfqbzl6nfpb-ibus-with-plugins-1.5.33",
    drv_path: "/nix/store/hijbcmvn08z6vxgqidgpflc3vbbna4xv-ibus-with-plugins-1.5.33.drv",
    output: "out",
}];

const SHELL_WRAPPER_TOOL_INPUTS: &[ReviewedToolInput] = &[ReviewedToolInput {
    attribute: "nativeBuildInputs",
    path: "/nix/store/f16vss2p6m6r7h7a81473x31gqj8j4ha-make-shell-wrapper-hook",
    drv_path: "/nix/store/426mziy0yn9wijy39xhacyajjnbqdngr-make-shell-wrapper-hook.drv",
    output: "out",
}];

const FIREFOX_WRAPPER_TOOL_INPUTS: &[ReviewedToolInput] = &[
    ReviewedToolInput {
        attribute: "buildInputs",
        path: "/nix/store/yb5pprzzxvynv57a05axpap57r2kngfx-gtk+3-3.24.52-dev",
        drv_path: "/nix/store/3bfxsr40gsd2gbq5z7az27gj931jm6n1-gtk+3-3.24.52.drv",
        output: "dev",
    },
    ReviewedToolInput {
        attribute: "nativeBuildInputs",
        path: "/nix/store/f16vss2p6m6r7h7a81473x31gqj8j4ha-make-shell-wrapper-hook",
        drv_path: "/nix/store/426mziy0yn9wijy39xhacyajjnbqdngr-make-shell-wrapper-hook.drv",
        output: "out",
    },
    ReviewedToolInput {
        attribute: "nativeBuildInputs",
        path: "/nix/store/ccihqmbbygsvx7jap8apl5jwp8ipy61y-lndir-1.0.5",
        drv_path: "/nix/store/n7ayld0dgrjfmzc7cpawgcfcq70y6hx3-lndir-1.0.5.drv",
        output: "out",
    },
    ReviewedToolInput {
        attribute: "nativeBuildInputs",
        path: "/nix/store/3vavalljj18drsycygl361zqz4rryygd-jq-1.8.1-dev",
        drv_path: "/nix/store/2y8ydpsl3rhv9b5a7w723jw2zznf7n7b-jq-1.8.1.drv",
        output: "dev",
    },
];

const DCONF_GENERATOR_TOOL_INPUTS: &[ReviewedToolInput] = &[ReviewedToolInput {
    attribute: "nativeBuildInputs",
    path: "/nix/store/ajbhgix5hzsr75pr9dhlnpcvhm3kh8pj-dconf-0.49.0",
    drv_path: "/nix/store/gpxwim44mis1367f7cfm8jvdg0rx516c-dconf-0.49.0.drv",
    output: "out",
}];

const JQ_GENERATOR_TOOL_INPUTS: &[ReviewedToolInput] = &[ReviewedToolInput {
    attribute: "nativeBuildInputs",
    path: "/nix/store/3vavalljj18drsycygl361zqz4rryygd-jq-1.8.1-dev",
    drv_path: "/nix/store/2y8ydpsl3rhv9b5a7w723jw2zznf7n7b-jq-1.8.1.drv",
    output: "dev",
}];

const NIXOS_SYSTEM_SETUP_HOOK: ReviewedStoreOutput = ReviewedStoreOutput {
    path: "/nix/store/f16vss2p6m6r7h7a81473x31gqj8j4ha-make-shell-wrapper-hook/nix-support/setup-hook",
    drv_path: "/nix/store/426mziy0yn9wijy39xhacyajjnbqdngr-make-shell-wrapper-hook.drv",
    output: "out",
};

const SYSTEM_PATH_POST_BUILD_TOOLS: &[ReviewedStoreOutput] = &[
    ReviewedStoreOutput {
        path: "/nix/store/c8mrrp6s3rjfbqn47ihlicazjabkji6j-texinfo-7.2/bin/install-info",
        drv_path: "/nix/store/ajdsm2jxfsfwqjv6x1s1r88qk6jb63ch-texinfo-7.2.drv",
        output: "out",
    },
    ReviewedStoreOutput {
        path: "/nix/store/hcgqddzbkw6w3zhk528mmwh3n0jqfas1-shared-mime-info-2.4/bin/update-mime-database",
        drv_path: "/nix/store/i04wr7q7ydgwmc1pg0g9rmg4rj1z1dk1-shared-mime-info-2.4.drv",
        output: "out",
    },
    ReviewedStoreOutput {
        path: "/nix/store/1gl5mj5cpi3j8ajp3wkkmkfl86vpiz6m-desktop-file-utils-0.28/bin/update-desktop-database",
        drv_path: "/nix/store/s22cxhvrbmpcjvdj97nhbp0vyaabjn6g-desktop-file-utils-0.28.drv",
        output: "out",
    },
    ReviewedStoreOutput {
        path: "/nix/store/7c73fgj9w0k8qrpq3j1h8h976bk7gqsp-gtk+3-3.24.52/bin/gtk-update-icon-cache",
        drv_path: "/nix/store/3bfxsr40gsd2gbq5z7az27gj931jm6n1-gtk+3-3.24.52.drv",
        output: "out",
    },
];

const DESKTOP_FILE_VALIDATE: ReviewedStoreOutput = ReviewedStoreOutput {
    path: "/nix/store/1gl5mj5cpi3j8ajp3wkkmkfl86vpiz6m-desktop-file-utils-0.28/bin/desktop-file-validate",
    drv_path: "/nix/store/s22cxhvrbmpcjvdj97nhbp0vyaabjn6g-desktop-file-utils-0.28.drv",
    output: "out",
};

const LOGROTATE_CHECK_INPUTS: &[ReviewedStoreOutput] = &[
    ReviewedStoreOutput {
        path: "/nix/store/sr26flm2nkfa12dkrwj2630kqsfakky4-coreutils-9.11",
        drv_path: "/nix/store/yzawmmja3azkam2gyf3b0z5a8aafja9m-coreutils-9.11.drv",
        output: "out",
    },
    ReviewedStoreOutput {
        path: "/nix/store/ky2583b7y10vd6zfplg5vrmcynhb1myx-logrotate-3.22.0/sbin/logrotate",
        drv_path: "/nix/store/6f0mayqvyhis7mmw6xd771azs0zksg7d-logrotate-3.22.0.drv",
        output: "out",
    },
];

const NIX_CONFIG_CHECK_INPUT: ReviewedStoreOutput = ReviewedStoreOutput {
    path: "/nix/store/b15733bsif8p914l2ps58mkq36k5xsym-nix-2.34.7/bin/nix",
    drv_path: "/nix/store/033lbg2pw9b7xcfvxc22vq54shd2p40f-nix-2.34.7.drv",
    output: "out",
};

const COREDUMP_SOURCE: ReviewedStoreOutput = ReviewedStoreOutput {
    path: "/nix/store/rd05syhv5v5999907a2n1r37sgi19vpd-systemd-260.2/example/sysctl.d/50-coredump.conf",
    drv_path: "/nix/store/4dxvg84cyfibqw5xx3vhcbi24c62yld9-systemd-260.2.drv",
    output: "out",
};

const COREDUMP_SUBSTITUTION_TARGET: ReviewedStoreOutput = ReviewedStoreOutput {
    path: "/nix/store/1rnlk0fgkq8lqds32akkwzm69q6ybl78-systemd",
    drv_path: "/nix/store/rd8x88f6xw7n98n9l1rn2zdg6qczrqfj-systemd.drv",
    output: "out",
};

const SECURITY_WRAPPER_TOOL_INPUTS: &[ReviewedToolInput] = &[ReviewedToolInput {
    attribute: "propagatedBuildInputs",
    path: "/nix/store/w9kkr15qfa6avzxf3v9xx4nqd18jx6c5-linux-headers-static-6.18.7",
    drv_path: "/nix/store/fpmnkyi3g09yf0kmvm33wryasx8gj3xv-linux-headers-static-6.18.7.drv",
    output: "out",
}];

const TRUSTED_SECURITY_WRAPPER_INCLUDE_PATH: &str =
    "/nix/store/iihn636xkv54vlp95abhjamywiw3lmvz-glibc-2.42-67-source-unsecvars";
const TRUSTED_SECURITY_WRAPPER_INCLUDE_DRV: &str =
    "/nix/store/iw8yjjhv5qnbj90n4lkmr2dj3wk8rfz2-glibc-2.42-67-source-unsecvars.drv";

fn reviewed_tool_inputs_match(
    drv: &Value,
    attrs: &serde_json::Map<String, Value>,
    expected: &[ReviewedToolInput],
    would_build: &HashSet<String>,
    trusted_local: &HashSet<String>,
) -> bool {
    let Some(actual) = parse_stdenv_tool_input_paths(attrs) else {
        return false;
    };
    let actual_count = actual.values().map(Vec::len).sum::<usize>();
    if actual_count != expected.len() {
        return false;
    }
    let mut positions = BTreeMap::<&str, usize>::new();
    for descriptor in expected {
        let position = positions.entry(descriptor.attribute).or_default();
        let matches_path = actual
            .get(descriptor.attribute)
            .and_then(|paths| paths.get(*position))
            .is_some_and(|path| path == descriptor.path);
        *position += 1;
        if !matches_path {
            return false;
        }
        let Some(reference) = input_drv_output_reference(drv, descriptor.path) else {
            return false;
        };
        if reference.drv_path != descriptor.drv_path
            || reference.output != descriptor.output
            || !input_derivation_is_nonlocal_or_trusted(
                &reference.drv_path,
                would_build,
                trusted_local,
            )
        {
            return false;
        }
    }
    true
}

// Exact 74cc63f fingerprints for native desktop/NixOS materializers reviewed
// from real source-disabled KDE and Hyprland closures. They only write
// configuration, copy or link cache-backed store inputs, validate udev rules,
// verify wrapper targets, and assemble the final closure. Keep both hashes:
// the second one preserves executable store paths, so changing a tool provider
// cannot ride on the store-normalized hash.
const PINNED_DESKTOP_NIXOS_GENERATOR_FINGERPRINTS: &[(&str, &str)] = &[
    (
        "2b2fc4793476549635b1bc215ceb531bd6136a9e73532a3aeea9804374731d9f",
        "2b2fc4793476549635b1bc215ceb531bd6136a9e73532a3aeea9804374731d9f",
    ),
    (
        "204a759abe8e2b7917a4d7e92ab979b2f3a3909b08a136549c9b3731dea05230",
        "204a759abe8e2b7917a4d7e92ab979b2f3a3909b08a136549c9b3731dea05230",
    ),
    (
        "d4fed03c6c26bde1ab4ecbce4e608db273568927b1a0b23f1b8d3aa0614610fc",
        "b2a896c313f7af137090461b534f7f6ebc6d42272e9e62ef8e62b2b88144854b",
    ),
    (
        "867f11da7012704e437b346716a9845923a334a91942a7ee8fbad12033f68eff",
        "8e70f950ef98f780fc7f24398542506cb1f4ac4ee0a4fb9f6c6b820f38789ef4",
    ),
    (
        "88e4e96d3d47f2439559310bc29f36051c4728d0e3436cf4b50201d399c819b8",
        "e6e13a68184b2c2c618815105932111d8889c88d2da157bbe7d559d4e8338ea4",
    ),
    (
        "749e8872ac9278c1d9108e12361fb7179cb0a55153f0fd151489e23cb8f3b050",
        "e2d74c75220bd550879e4d1110088faa6af4dffdc64241860c21db03147c85b7",
    ),
    (
        "9628a8aedd52690233fda5932b12b00c4ef37ce57d08c762dd3cd88c9a34ba3c",
        "840a0309872b4e1eeb9d2dc2fd6114d27f13dca97fa649bb35f1152af3561d64",
    ),
    (
        "c518c8ef32da2ce4eddc5812ee50a9ce43054202c903356fadbf3a2374958426",
        "8b1e69765e87afc2f299535771301bbd52861a85dba354d9a1616eed6ac4d24c",
    ),
    (
        "6c95edcf4bb40bf57b7dd83d10e2b27cc0b9357c340cf250ddd9687c826f9acf",
        "bf017be7b1499d709f6788fc30237d63d6c4645104f2858e86a0325d21b83340",
    ),
    (
        "1e75c6fe531a9a19269d3a29db10203f7a7dd6b700704f0f218efef6da590396",
        "5bcf9e9dbe1645e0dc5bc0a6cc9c85a28d33cfe08728dbb84208c3e3c7733f1f",
    ),
    (
        "5648261ea9379762bbaee8885dfb1f1f94659f6bff3a193ba61cf43c9c6d0dae",
        "5648261ea9379762bbaee8885dfb1f1f94659f6bff3a193ba61cf43c9c6d0dae",
    ),
    (
        "0931f4d43d76ad5f9f98b6dd94c7d9faa004a5339f537c6ef5b13477b46afe63",
        "0931f4d43d76ad5f9f98b6dd94c7d9faa004a5339f537c6ef5b13477b46afe63",
    ),
    (
        "bc6764aa33e7c94877f7623ca0320af3626854a17ca644645f7f3dbfdafe40d9",
        "b380bafc9053193ff46a0430ed48e2f716929dbbb56b3e95ca016dafcdebc68f",
    ),
    (
        "4cff314a3d512904e440a804d5faae99ff3eb0a085916800dab1c3dd16e26f09",
        "84361dab0fcfdafe2bae018e5d9143bd06141d729355befa12d19cd7d321ba68",
    ),
    (
        "51868134ea8fa6d635d428d9785150cf035d707d42c9ad928071654e44d9a11e",
        "307dc87f1059484c6a136cefa43d67bdbb6633c0fb2e55f751b27e283bc671be",
    ),
    (
        "8a30291d9ee10b834a29c90f85d5b1eac27dd755ea929840b6946173e661bb49",
        "8a30291d9ee10b834a29c90f85d5b1eac27dd755ea929840b6946173e661bb49",
    ),
    (
        "c518c8ef32da2ce4eddc5812ee50a9ce43054202c903356fadbf3a2374958426",
        "4666d1bbec850bf0e780de6e75ca0562c6918c08a7733b67dc62de996997d3a0",
    ),
    // Standard Workstation (Chromium, no Mail) system and user unit link
    // farms plus /etc assembly. These reviewed scripts only copy or link
    // independently trusted store inputs; the executable-pinned digest keeps
    // every configuration-dependent provider identity in the contract.
    (
        "0f4a38129dbc5c3ae0a75b02a15549630eb19f48a18196c2229b5ab50c4eb1b1",
        "936c01fcf78920bf6736d5c9a7461941d6df3d1f8f2dc29f040f59b8102d64e5",
    ),
    (
        "fe12db07a2de4c5d9053a05b139a90ba110e6ad13b6365c2ab9a4efaaec5babe",
        "f21eb14f20b91832619da2515fad5d437a809c9b1936173b0ee6b278cfaf4af5",
    ),
    (
        "3ee4be64b7ae61e457c188845565f35d592ef1f43afd7828c7f9f6f222f44c4b",
        "c1e3714ff277c969f8daf643cc5e8917c5afdee31b149041d651fe93a472f0e6",
    ),
];

const PINNED_NIXOS_TOPLEVEL_GENERATOR_FINGERPRINT: &str =
    "c518c8ef32da2ce4eddc5812ee50a9ce43054202c903356fadbf3a2374958426";

fn reviewed_generator_fingerprints_match(normalized: &str, executable_pinned: &str) -> bool {
    matches!(
        (normalized, executable_pinned),
        (
            "40b682b4d5ba770972e73602a00d9a20fa09fedf1532637ec269beae36e9222c",
            "00161f1592b23d96e52dedcfa41c6f6892f7f60f033ccdf2e4217cf5ddcb5296"
        ) | (
            "4676f84206bed349f6c7a218769918b312ff72a07d72f3ba7b16c3c9e445c4c6",
            "4676f84206bed349f6c7a218769918b312ff72a07d72f3ba7b16c3c9e445c4c6"
        ) | (
            "c8a1f92b51536ac52a31da581b375b0cdfc38bd866fa4e8aba31704571e9951c",
            "1de27a36ff948611e74a447706e54feeee9ede1d62a3d07a91e3eab97d27d888"
        ) | (
            "0420d5a023634df127f1a5db053c5c75ebe9aab49f40998bee7994133602cafb",
            "0420d5a023634df127f1a5db053c5c75ebe9aab49f40998bee7994133602cafb"
        ) | (
            "ce114529adc13141261efde7ba95b910ce63c866dbdcee7c2558a972f7c6e3be",
            "23849171da93df9e8fcab7b9927f142a9080a9a3a4e8fa15356462b570c21a8d"
        ) | (
            "25a6ed5b12ee98254590e9b7f96cf0201d745e0cae5e3397b83a4aa5dc0bd6f9",
            "25a6ed5b12ee98254590e9b7f96cf0201d745e0cae5e3397b83a4aa5dc0bd6f9"
        ) | (
            "d9f66812511d4498ae1ddcfc43103975f3ce3b23e442ea7447f017cde77f12a2",
            "d9f66812511d4498ae1ddcfc43103975f3ce3b23e442ea7447f017cde77f12a2"
        ) | (
            "59f26c16d15861b839afb02ad80574b1d53d9371a52b07de3fb1d5e4006d18b0",
            "6d073685d6995120788b465e189da00ce0722b4a332f0614ab79bacb60d0cfed"
        ) | (
            "d1d2619fd8ae8a62613b56fda4f3416950a8842a37e197ae361ce78e253d77f6",
            "e18ae1db066c7cc415019b22e07cc09570ac3f416fa79636b91345074b2e7aa3"
        ) | (
            "a1f121298ad67c6f711b2d993e39e6fd59452fb6100761d782206dc081b5ed6a",
            "80964d64006e717b3526388de2292508e300abf6731cf0c3163b9de71757f343"
        ) | (
            "acb5b353de414cd3988d256fe53adf60d806084585f72bcddc734d7faebef9e6",
            "acb5b353de414cd3988d256fe53adf60d806084585f72bcddc734d7faebef9e6"
        ) | (
            "64c2c9a5153a9da42e566c21d525bab58e72cbc62064ace52e850ce6de5919de",
            "64c2c9a5153a9da42e566c21d525bab58e72cbc62064ace52e850ce6de5919de"
        ) | (
            "b461f824c2e59def400c695d026a06bc7b4e620dd775310e3dcc4c0a0a659122",
            "d1748170b18dda35ba0b309e3ec309e8a1d504ff1ba3e2fe036616807a3c4e88"
        ) | (
            "1c2082bf51a9da044658c3148fbccfdf3ea9b6d06c2bf4688d44e6d65d5f0a3c",
            "1c2082bf51a9da044658c3148fbccfdf3ea9b6d06c2bf4688d44e6d65d5f0a3c"
        ) | (
            "8e2876a0163080a391c5a2e262fe50c1ce94896b0a59b711300b4591374eb274",
            "cb489083ff04d375e45aa11f27cb09491264489a3154873a00765f9fe76c7fb3"
        ) | (
            "734390098c544326b82013cc64b061fb230f860799e4de5de1cff9f80fac0239",
            "7a39b396ece464831e75f055c3ae8fe5f30f579a003e4e81f2644fdeff88a4bd"
        ) | (
            "51868134ea8fa6d635d428d9785150cf035d707d42c9ad928071654e44d9a11e",
            "644c4e0b7ac44717d335dc1676f3f7945e18922522ae116e9d30ef5e3077e818"
        ) | (
            "3f7791ecb20d5bb1c5b1569d18ecc47e3ecb139e006fb11967418dee604bacf4",
            "dce86d27b0cfa2d76f0618becdf912761f451a0db70787277084a53687566b0d"
        ) | (
            "16e7f4206ba4410770b5a8487fd03ceb865a6f95c722ac0db8d6cddbfcd2a47f",
            "c43b9ba29215cd41ba76fd05a3ceda0b7631a76ad97d46a9b67abef896f38e4e"
        ) | (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ) | (
            "df8f88a3ba834be38513dcf31953f2e9dbd3079f4317aa50f18fecd8da66644c",
            "26557f67d686cc9300815b6751215a50f8862f8e02c301a3b09077494f3ddd75"
        ) | (
            "8a30291d9ee10b834a29c90f85d5b1eac27dd755ea929840b6946173e661bb49",
            "8a30291d9ee10b834a29c90f85d5b1eac27dd755ea929840b6946173e661bb49"
        ) | (
            "dd1a03f2309d59703838fb53178f8701e96766ed4366b7424102d2d16b767187",
            "118615430cffe4d27695d9bfebc05ae2df4dab46a0daa4702e8f7bdca3f44e69"
        ) | (
            "eef541ca127594d1cba6806063b714797a04c993a238e89fc5ec0f5bcfcb5ab9",
            "b16d9e295a5108ea56d1298b862c721befe3ef2f70d141382019bd20c18f91c6"
        ) | (
            "285d9aba044ba011ff28280bad364e574adc01b08c1cf29d5b7dac367c8ca056",
            "285d9aba044ba011ff28280bad364e574adc01b08c1cf29d5b7dac367c8ca056"
        ) | (
            "7f31e03fa62671495df298413ab1f114667049bcd6526192a7b2dbd96e3af9f9",
            "7f31e03fa62671495df298413ab1f114667049bcd6526192a7b2dbd96e3af9f9"
        ) | (
            "194acd910a0964849ebde5d5507047c13eb97ba93d58e7a971b5092f569fca5d",
            "194acd910a0964849ebde5d5507047c13eb97ba93d58e7a971b5092f569fca5d"
        ) | (
            "f44df5d941a4d832d369726837ab2562dd465ef11491122a856ce196a84ebb37",
            "f44df5d941a4d832d369726837ab2562dd465ef11491122a856ce196a84ebb37"
        ) | (
            "c89811dd51623b761819b2b3b6a7065a22786906bd9d0fcc487c9981ca1c738d",
            "c89811dd51623b761819b2b3b6a7065a22786906bd9d0fcc487c9981ca1c738d"
        ) | (
            "3cfd48a3d05164b23d1e2d7d89064fa12797488f3f3fd1a9a79ecd1455aff6f3",
            "3cfd48a3d05164b23d1e2d7d89064fa12797488f3f3fd1a9a79ecd1455aff6f3"
        ) | (
            "065376ecae4278a85a12ebfec1374b3ff7ca72d5a63e63fd070b6e7b9a5497c5",
            "065376ecae4278a85a12ebfec1374b3ff7ca72d5a63e63fd070b6e7b9a5497c5"
        ) | (
            "29010af04cdca69ff89840063ddf07d3c1cb46b08ffff6e4a868efeefa2513af",
            "29010af04cdca69ff89840063ddf07d3c1cb46b08ffff6e4a868efeefa2513af"
        ) | (
            "f9987ea4e2f3e79be4eb17e3f6e68c5ceaac78a1b849f7a6b11c819b5ccc0097",
            "f9987ea4e2f3e79be4eb17e3f6e68c5ceaac78a1b849f7a6b11c819b5ccc0097"
        ) | (
            "d26aeb1aceacb9104eebb7a81ea25dd5008dfa27b81091ef1ccd80a8deef9a61",
            "9ee6c126be9f2f9aa97ab516eb6bfc3976697b5a3b99e796bee5b88323623af8"
        ) | (
            "ac3e3f0f8f366fdd79b5aee4c0b2ae4e74539b1d3abfa3d3ba23ce1ea3b7d46b",
            "ac3e3f0f8f366fdd79b5aee4c0b2ae4e74539b1d3abfa3d3ba23ce1ea3b7d46b"
        ) | (
            "a1246f8806f5d0d94b8b3c4fb87344bc9066862f19b6449b578ccb8b5c850313",
            "a1246f8806f5d0d94b8b3c4fb87344bc9066862f19b6449b578ccb8b5c850313"
        ) | (
            "9092b31b21724b0958c472cfa050c80faeee8f2c4357d51b1205d415c85cad75",
            "9092b31b21724b0958c472cfa050c80faeee8f2c4357d51b1205d415c85cad75"
        ) | (
            "7f0d59ec81ffc600b1b60a88cd4f0844b92594e243df908eed55615fc0b70115",
            "231bc9c621dfb4e83214e7ef70a52c4e1cf30224d7d4096dfbceba696b05155e"
        ) | (
            "6dd723a53e3919ad063c4c18cb8dabb90f91a15d9e67f0e2e62551bd11619eba",
            "2161a0e6e21473f829d1eb09583234c4233aa80af8764728015b97b15ca03009"
        ) | (
            "c518c8ef32da2ce4eddc5812ee50a9ce43054202c903356fadbf3a2374958426",
            "ae215e8cef28fae0aa497d0b9667e374dce0a26ef7619e6cadf5351a7264d496"
        ) | (
            "772f6d9925d49139b03405d5ace988184e0671bcb099e0b6103a0bae20dafbc7",
            "34b3d77b7e96eeb3254a8a4efbba2b6fe41cd114bbc6da8a24f6b48041493b9b"
        ) | (
            "c061170cd0760a05e004a38f9c4014f960d2d96c9985b5c733b034ada5fb144d",
            "f35dbae81e4b9b57eccdeb133e213c8f4b7b399ff50007419c23f32d7c943583"
        ) | (
            "a733046379d65a3d26f7a7c10b082d8afeff67d1464dfeb146ed6e8f499e0dd2",
            "d02cba159178ab1306d99ad65c75ff8c67bdafa27fe91707ad4876e75c23da9f"
        ) | (
            "b8ad9d93841f3878d9002c305c986c6341ed591300917aaf98d64e3b81bcb303",
            "d578d41d33c5ad59159a2d49783fc1715b6737fb4bd5c63efaab7ff257d0fbca"
        ) | (
            "be593d4b624bfdabff2188425bf31da415e943edf7553c6f445242fa0683b8bf",
            "be593d4b624bfdabff2188425bf31da415e943edf7553c6f445242fa0683b8bf"
        ) | (
            "5480bb2c284169db9638f652aee3ff092566a6e7dde15319ce3d9a5a8c3d7151",
            "5480bb2c284169db9638f652aee3ff092566a6e7dde15319ce3d9a5a8c3d7151"
        ) | (
            "ec3c0ea71558ed2553c163b7d6b1d4835891fb1d41c0d98991b90faba413ac31",
            "b4419743eaa9ea0099e298a7ade945231d3da4735efface29cc80c71c6bd35ed"
        )
    ) || PINNED_DESKTOP_NIXOS_GENERATOR_FINGERPRINTS.contains(&(normalized, executable_pinned))
}

fn derivation_is_plain_fixed_output_fetch(
    drv: &Value,
    attrs: &serde_json::Map<String, Value>,
) -> bool {
    let outputs_are_hashed = drv
        .get("outputs")
        .and_then(Value::as_object)
        .is_some_and(|outputs| {
            !outputs.is_empty()
                && outputs.values().all(|output| {
                    output
                        .get("hash")
                        .and_then(Value::as_str)
                        .is_some_and(|hash| !hash.is_empty())
                })
        });
    if !outputs_are_hashed
        || !derivation_attr_is_empty(attrs, "postFetch")
        || !derivation_attr_is_empty(attrs, "buildCommand")
        || !derivation_attr_is_empty(attrs, "buildPhase")
        || !derivation_attr_is_empty(attrs, "installPhase")
        || !derivation_attr_is_empty(attrs, "src")
    {
        return false;
    }
    let has_url = attrs
        .get("urls")
        .and_then(Value::as_array)
        .is_some_and(|urls| !urls.is_empty() && urls.iter().all(|url| url.as_str().is_some()))
        || attrs
            .get("url")
            .and_then(Value::as_str)
            .is_some_and(|url| !url.is_empty());
    if !has_url {
        return false;
    }
    drv.get("builder").and_then(Value::as_str) == Some("builtin:fetchurl")
        && derivation_input_sources(drv).is_some_and(|sources| sources.is_empty())
        && derivation_input_drvs(drv).is_some_and(|inputs| inputs.is_empty())
}

fn has_pinned_stdenv_materializer<F>(
    drv: &Value,
    attrs: &serde_json::Map<String, Value>,
    verify_source: &F,
    expected_stdenv: ReviewedStoreOutput,
    would_build: &HashSet<String>,
    trusted_local: &HashSet<String>,
) -> bool
where
    F: Fn(&str, &str) -> bool,
{
    let Some(sources) = derivation_input_sources(drv) else {
        return false;
    };
    let source_stdenv = sources
        .iter()
        .filter(|path| path.ends_with("-source-stdenv.sh"))
        .collect::<Vec<_>>();
    let builder = sources
        .iter()
        .filter(|path| path.ends_with("-default-builder.sh"))
        .collect::<Vec<_>>();
    let args = drv.get("args").and_then(Value::as_array);
    source_stdenv.len() == 1
        && builder.len() == 1
        && verify_source(source_stdenv[0], TRUSTED_STDENV_SOURCE_SHA256)
        && verify_source(builder[0], TRUSTED_DEFAULT_BUILDER_SHA256)
        && args.is_some_and(|args| {
            args.len() == 3
                && args[0].as_str() == Some("-e")
                && args[1].as_str() == Some(source_stdenv[0].as_str())
                && args[2].as_str() == Some(builder[0].as_str())
        })
        && drv.get("builder").and_then(Value::as_str) == Some(TRUSTED_STDENV_BASH_BUILDER)
        && derivation_attr_is_empty(attrs, "NIX_ATTRS_SH_FILE")
        && derivation_attr_is_empty(attrs, "NIX_ATTRS_JSON_FILE")
        && reviewed_store_output_is_trusted(
            drv,
            derivation_attr_text(attrs, "stdenv"),
            expected_stdenv,
            would_build,
            trusted_local,
        )
}

fn empty_build_tool_attributes(attrs: &serde_json::Map<String, Value>) -> bool {
    stdenv_tool_inputs_are_empty(attrs)
        && [
            "configurePhase",
            "installPhase",
            "src",
            "source",
            "cargoDeps",
            "cargoVendorDir",
            "goModules",
        ]
        .iter()
        .all(|key| derivation_attr_is_empty(attrs, key))
}

const STOCK_WRITE_TEXT_COMMAND: &str = "target=$out$destination\nmkdir -p \"$(dirname \"$target\")\"\n\nif [ -e \"$textPath\" ]; then\n  mv \"$textPath\" \"$target\"\nelse\n  printf \"%s\" \"$text\" > \"$target\"\nfi\n\nif [ -n \"$executable\" ]; then\n  chmod +x \"$target\"\nfi\n\neval \"$checkPhase\"\n";
const STOCK_CONCAT_TEXT_COMMAND: &str = "file=$out$destination\nmkdir -p \"$(dirname \"$file\")\"\ncat $files > \"$file\"\n\nif [ -n \"$executable\" ]; then\n  chmod +x \"$file\"\nfi\n\neval \"$checkPhase\"\n";

fn stock_write_text_check_phase(
    drv: &Value,
    attrs: &serde_json::Map<String, Value>,
    builder: &str,
    would_build: &HashSet<String>,
    trusted_local: &HashSet<String>,
) -> bool {
    let check = derivation_attr_text(attrs, "checkPhase");
    if check.is_empty()
        || (check == format!("{builder} -n -O extglob \"$target\"\n")
            && builder == TRUSTED_STDENV_BASH_BUILDER)
    {
        return true;
    }
    let normalized = normalized_script_sha256(check);
    let executable_pinned = executable_pinned_script_sha256(check);
    let expected_inputs: &[ReviewedStoreOutput] =
        match (normalized.as_str(), executable_pinned.as_str()) {
            (
                "c71bfc17bf52d3624986565626bc02f395d1a945472ea3fc4150b46fe945ee4a",
                "69dbc0809253c5fc97ea9376079ea4972aa2f98968e965918c5897637d946deb",
            ) => std::slice::from_ref(&DESKTOP_FILE_VALIDATE),
            (
                "45adbef1c422d56dd57113f7a605e870e77c59fa21770ffe396e0c46d0a9a57b",
                "99c0d05ddd84682b22aab621673fdf636e6209acfdd6ead417450c51dae02451",
            ) => LOGROTATE_CHECK_INPUTS,
            (
                "b333684bcbe4198fbb46349e9084d4ae61f70c81510164cb59957f052cb4ea1e",
                "c4c11cea94fee4a2c9cbaa6249d417f5f0a55328b3a3f269782d64407f431523",
            ) => std::slice::from_ref(&NIX_CONFIG_CHECK_INPUT),
            _ => return false,
        };
    expected_inputs.iter().all(|input| {
        check.contains(input.path)
            && reviewed_store_output_is_trusted(drv, input.path, *input, would_build, trusted_local)
    })
}

fn stock_unit_materializer(script: &str) -> bool {
    let mut lines = script.lines();
    let Some(name_line) = lines.next() else {
        return false;
    };
    let Some(name) = name_line.strip_prefix("name=") else {
        return false;
    };
    !name.is_empty()
        && name.len() <= 192
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'@'))
        && lines.next() == Some("mkdir -p \"$out/$(dirname -- \"$name\")\"")
        && lines.next() == Some("mv \"$textPath\" \"$out/$name\"")
        && lines.next().is_none()
}

fn derivation_is_pinned_nixos_materialization<F>(
    drv: &Value,
    attrs: &serde_json::Map<String, Value>,
    verify_source: &F,
    would_build: &HashSet<String>,
    trusted_local: &HashSet<String>,
) -> bool
where
    F: Fn(&str, &str) -> bool,
{
    if !derivation_attr_truthy(attrs, "preferLocalBuild")
        || !has_pinned_stdenv_materializer(
            drv,
            attrs,
            verify_source,
            TRUSTED_STDENV_NO_CC_OUTPUT,
            would_build,
            trusted_local,
        )
        || !derivation_attr_is_empty(attrs, "buildPhase")
        || !derivation_attr_is_empty(attrs, "PATH")
    {
        return false;
    }
    let build_command = derivation_attr_text(attrs, "buildCommand");
    if build_command == STOCK_WRITE_TEXT_COMMAND {
        return empty_build_tool_attributes(attrs)
            && only_reviewed_phase_hooks(attrs, &["checkPhase"])
            && stock_write_text_check_phase(
                drv,
                attrs,
                drv.get("builder").and_then(Value::as_str).unwrap_or(""),
                would_build,
                trusted_local,
            );
    }
    if build_command == STOCK_CONCAT_TEXT_COMMAND {
        return empty_build_tool_attributes(attrs) && only_reviewed_phase_hooks(attrs, &[]);
    }
    if stock_unit_materializer(build_command) {
        return empty_build_tool_attributes(attrs) && only_reviewed_phase_hooks(attrs, &[]);
    }
    derivation_is_pinned_link_farm(drv, attrs, verify_source, would_build, trusted_local)
}

fn derivation_is_pinned_link_farm<F>(
    drv: &Value,
    attrs: &serde_json::Map<String, Value>,
    verify_source: &F,
    would_build: &HashSet<String>,
    trusted_local: &HashSet<String>,
) -> bool
where
    F: Fn(&str, &str) -> bool,
{
    let build_command = derivation_attr_text(attrs, "buildCommand");
    let builders = build_command
        .split_whitespace()
        .filter(|source| source.starts_with("/nix/store/") && source.ends_with("-builder.pl"))
        .collect::<Vec<_>>();
    if builders.len() != 1
        || !reviewed_store_output_is_trusted(
            drv,
            builders[0],
            TRUSTED_LINK_FARM_BUILDER,
            would_build,
            trusted_local,
        )
        || (!trusted_local.contains(TRUSTED_LINK_FARM_BUILDER.drv_path)
            && !verify_source(builders[0], TRUSTED_LINK_FARM_BUILDER_SHA256))
        || !only_reviewed_phase_hooks(attrs, &["postBuild"])
        || normalized_script_sha256(build_command)
            != "a6cf60ebc58cc0369cee59040fd37c46b321146b484103ff4aa18b35b8b41b00"
        || executable_pinned_script_sha256(build_command)
            != "99a4422a8e4f1e8438da233af92e5fde1dd815ef5cb8e6d798f71cb70eca85a3"
        || !reviewed_store_output_is_trusted(
            drv,
            TRUSTED_LINK_FARM_PERL.path,
            TRUSTED_LINK_FARM_PERL,
            would_build,
            trusted_local,
        )
    {
        return false;
    }
    let post_build = derivation_attr_text(attrs, "postBuild");
    let normalized = normalized_script_sha256(post_build);
    let executable_pinned = executable_pinned_script_sha256(post_build);
    let expected_tools = match (normalized.as_str(), executable_pinned.as_str()) {
        (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ) => &[],
        (
            "7f86b2e411b93e37acff8e39b860ecbca7ae6d7bc5de52a11d07d8ed58c20bf2",
            "bea12530cb587af0d0682c7dd563f68ff651944056b10514cc8ad957b657eca8",
        )
        | (
            "918614228118dbaf5bf55a905be7d744530df83af7a6f1d91425bc22d1c11283",
            "918614228118dbaf5bf55a905be7d744530df83af7a6f1d91425bc22d1c11283",
        )
        | (
            "992bcd476d3b045a9e19b2bbb991559675ae3e55934a29af45c49a7cc704ce14",
            "992bcd476d3b045a9e19b2bbb991559675ae3e55934a29af45c49a7cc704ce14",
        )
        | (
            "a8eb8749920d22a862141a551e64fcbe9f4f3ac877127b98a11db47246650c2f",
            "a8eb8749920d22a862141a551e64fcbe9f4f3ac877127b98a11db47246650c2f",
        )
        | (
            "e569cbee1cad769627a5bdd399a9680979ee21dbaa32e5a09269ac38f1711b99",
            "e569cbee1cad769627a5bdd399a9680979ee21dbaa32e5a09269ac38f1711b99",
        ) => PERL_ENV_LINK_FARM_TOOL_INPUTS,
        (
            "a239d780414d4aa4bd8fefb39863c6a64abe6d067bac50b6b32c9b35004f5c7f",
            "a239d780414d4aa4bd8fefb39863c6a64abe6d067bac50b6b32c9b35004f5c7f",
        ) => IBUS_LINK_FARM_TOOL_INPUTS,
        (
            "88e1c26fe3f7b058516d0fb1a994bcfae08b4a65423075641322d4345e3d859f",
            "635bcd083f60852265836ba5800762b6ea89ecb8b03cac9a8ef888901d98f7ea",
        ) => {
            if !post_build.starts_with(&format!("source {TRUSTED_STDENV_NO_CC}/setup\n")) {
                return false;
            }
            &[]
        }
        (
            "4969869fb48335b8d774a59ed5d335a19fb0eabfdafd2771b9ef15e648d5f0cf",
            "6a15544ea5c4361d80965ece2094126161bd8413fe80c7f8b91fb68e03e5e931",
        ) => {
            if !SYSTEM_PATH_POST_BUILD_TOOLS.iter().all(|tool| {
                post_build.contains(tool.path)
                    && reviewed_store_output_is_trusted(
                        drv,
                        tool.path,
                        *tool,
                        would_build,
                        trusted_local,
                    )
            }) {
                return false;
            }
            &[]
        }
        _ => return false,
    };
    reviewed_tool_inputs_match(drv, attrs, expected_tools, would_build, trusted_local)
        && link_farm_dynamic_paths_are_trusted(drv, attrs, would_build, trusted_local)
}

fn link_farm_dynamic_paths_are_trusted(
    drv: &Value,
    attrs: &serde_json::Map<String, Value>,
    would_build: &HashSet<String>,
    trusted_local: &HashSet<String>,
) -> bool {
    if !derivation_attr_is_empty(attrs, "paths")
        || !derivation_attr_is_empty(attrs, "extraPathsFrom")
    {
        return false;
    }
    let Some(chosen_outputs) = attrs.get("chosenOutputs").and_then(Value::as_array) else {
        return false;
    };
    chosen_outputs.iter().all(|chosen| {
        chosen
            .get("paths")
            .and_then(Value::as_array)
            .is_some_and(|paths| {
                !paths.is_empty()
                    && paths.iter().all(|path| {
                        let Some(path) = path.as_str() else {
                            return false;
                        };
                        safe_nix_store_path(path)
                            && path
                                .strip_prefix("/nix/store/")
                                .is_some_and(|relative| !relative.contains('/'))
                            && input_drv_output_references(drv, path).is_some_and(|references| {
                                !references.is_empty()
                                    && references.iter().all(|reference| {
                                        input_derivation_is_nonlocal_or_trusted(
                                            &reference.drv_path,
                                            would_build,
                                            trusted_local,
                                        )
                                    })
                            })
                    })
            })
    })
}

fn reviewed_generator_tool_inputs(fingerprint: &str) -> &'static [ReviewedToolInput] {
    match fingerprint {
        "64c2c9a5153a9da42e566c21d525bab58e72cbc62064ace52e850ce6de5919de" => {
            DBUS_GENERATOR_TOOL_INPUTS
        }
        "a1f121298ad67c6f711b2d993e39e6fd59452fb6100761d782206dc081b5ed6a"
        | "8e2876a0163080a391c5a2e262fe50c1ce94896b0a59b711300b4591374eb274"
        | "b8ad9d93841f3878d9002c305c986c6341ed591300917aaf98d64e3b81bcb303"
        | "88e4e96d3d47f2439559310bc29f36051c4728d0e3436cf4b50201d399c819b8"
        | "6c95edcf4bb40bf57b7dd83d10e2b27cc0b9357c340cf250ddd9687c826f9acf" => {
            UDEV_GENERATOR_TOOL_INPUTS
        }
        "acb5b353de414cd3988d256fe53adf60d806084585f72bcddc734d7faebef9e6" => {
            INITRD_GENERATOR_TOOL_INPUTS
        }
        "772f6d9925d49139b03405d5ace988184e0671bcb099e0b6103a0bae20dafbc7" => {
            GTK_IMMODULE_TOOL_INPUTS
        }
        "c061170cd0760a05e004a38f9c4014f960d2d96c9985b5c733b034ada5fb144d" => {
            FIREFOX_WRAPPER_TOOL_INPUTS
        }
        "a733046379d65a3d26f7a7c10b082d8afeff67d1464dfeb146ed6e8f499e0dd2" => {
            SHELL_WRAPPER_TOOL_INPUTS
        }
        "be593d4b624bfdabff2188425bf31da415e943edf7553c6f445242fa0683b8bf"
        | "5480bb2c284169db9638f652aee3ff092566a6e7dde15319ce3d9a5a8c3d7151"
        | "ec3c0ea71558ed2553c163b7d6b1d4835891fb1d41c0d98991b90faba413ac31" => {
            DCONF_GENERATOR_TOOL_INPUTS
        }
        "285d9aba044ba011ff28280bad364e574adc01b08c1cf29d5b7dac367c8ca056" => {
            JQ_GENERATOR_TOOL_INPUTS
        }
        "f9987ea4e2f3e79be4eb17e3f6e68c5ceaac78a1b849f7a6b11c819b5ccc0097" => {
            BINARY_WRAPPER_TOOL_INPUTS
        }
        _ => &[],
    }
}

/// Complex NixOS closure assembly scripts are intentionally not interpreted
/// with a home-grown shell parser. Their exact reviewed, store-hash-normalized
/// bytes are the grammar. Every accepted script also runs through the pinned
/// stdenv/default-builder pair, while executable environment injection is
/// rejected by the caller. Updating nixpkgs therefore requires reviewing and
/// deliberately refreshing these fingerprints.
fn derivation_is_reviewed_nixos_generator<F>(
    drv: &Value,
    attrs: &serde_json::Map<String, Value>,
    verify_source: &F,
    would_build: &HashSet<String>,
    trusted_local: &HashSet<String>,
) -> bool
where
    F: Fn(&str, &str) -> bool,
{
    let build_command = derivation_attr_text(attrs, "buildCommand");
    let fingerprint = normalized_script_sha256(build_command);
    let executable_fingerprint = executable_pinned_script_sha256(build_command);
    let expected_stdenv =
        if fingerprint == "c061170cd0760a05e004a38f9c4014f960d2d96c9985b5c733b034ada5fb144d" {
            TRUSTED_STDENV_FULL_OUTPUT
        } else {
            TRUSTED_STDENV_NO_CC_OUTPUT
        };
    if !has_pinned_stdenv_materializer(
        drv,
        attrs,
        verify_source,
        expected_stdenv,
        would_build,
        trusted_local,
    ) || !derivation_attr_is_empty(attrs, "src")
        || !derivation_attr_is_empty(attrs, "source")
        || !derivation_attr_is_empty(attrs, "cargoDeps")
        || !derivation_attr_is_empty(attrs, "cargoVendorDir")
        || !derivation_attr_is_empty(attrs, "goModules")
        || !derivation_attr_is_empty(attrs, "configurePhase")
        || !derivation_attr_is_empty(attrs, "installPhase")
        || !derivation_attr_is_empty(attrs, "buildPhase")
        || !only_reviewed_phase_hooks(attrs, &[])
    {
        return false;
    }
    let expected_tools = reviewed_generator_tool_inputs(&fingerprint);
    let reviewed_script_inputs = fingerprint
        != "3f7791ecb20d5bb1c5b1569d18ecc47e3ecb139e006fb11967418dee604bacf4"
        || (build_command.contains(NIXOS_SYSTEM_SETUP_HOOK.path)
            && reviewed_store_output_is_trusted(
                drv,
                NIXOS_SYSTEM_SETUP_HOOK.path,
                NIXOS_SYSTEM_SETUP_HOOK,
                would_build,
                trusted_local,
            ));
    let reviewed_fingerprint = if fingerprint == PINNED_NIXOS_TOPLEVEL_GENERATOR_FINGERPRINT {
        // The final NixOS toplevel script has exact, reviewed command bytes,
        // but its executable store hashes legitimately vary with Blueprint
        // configuration. Require every literal store item to be supplied by a
        // substitutable or independently reviewed input instead of enumerating
        // every valid configuration-dependent executable fingerprint.
        build_command.contains(NIXOS_SYSTEM_SETUP_HOOK.path)
            && reviewed_store_output_is_trusted(
                drv,
                NIXOS_SYSTEM_SETUP_HOOK.path,
                NIXOS_SYSTEM_SETUP_HOOK,
                would_build,
                trusted_local,
            )
            && script_store_item_paths_are_trusted(drv, build_command, would_build, trusted_local)
    } else {
        reviewed_generator_fingerprints_match(&fingerprint, &executable_fingerprint)
    };
    reviewed_fingerprint
        && reviewed_script_inputs
        && reviewed_tool_inputs_match(drv, attrs, expected_tools, would_build, trusted_local)
}

/// `substituteAll` has a lower-level fast path for a single file. It runs a
/// pinned nixpkgs helper directly instead of the default stdenv builder. Keep
/// this exemption tied to the exact 74cc helper bytes, source, replacement,
/// stdenv and input providers used for NixOS' coredump sysctl materialization.
fn derivation_is_reviewed_low_level_substitution<F>(
    drv: &Value,
    attrs: &serde_json::Map<String, Value>,
    verify_source: &F,
    would_build: &HashSet<String>,
    trusted_local: &HashSet<String>,
) -> bool
where
    F: Fn(&str, &str) -> bool,
{
    let Some(sources) = derivation_input_sources(drv) else {
        return false;
    };
    let args = drv.get("args").and_then(Value::as_array);
    let source_stdenv = sources
        .iter()
        .find(|path| path.ends_with("-source-stdenv.sh"));
    let exact_sources = source_stdenv.is_some_and(|source_stdenv| {
        sources.len() == 2
            && sources
                .iter()
                .any(|path| path == TRUSTED_SUBSTITUTE_BUILDER)
            && verify_source(source_stdenv, TRUSTED_STDENV_SOURCE_SHA256)
            && verify_source(
                TRUSTED_SUBSTITUTE_BUILDER,
                TRUSTED_SUBSTITUTE_BUILDER_SHA256,
            )
            && args.is_some_and(|args| {
                args.len() == 3
                    && args[0].as_str() == Some("-e")
                    && args[1].as_str() == Some(source_stdenv.as_str())
                    && args[2].as_str() == Some(TRUSTED_SUBSTITUTE_BUILDER)
            })
    });
    exact_sources
        && derivation_attr_truthy(attrs, "preferLocalBuild")
        && reviewed_store_output_is_trusted(
            drv,
            derivation_attr_text(attrs, "stdenv"),
            TRUSTED_STDENV_NO_CC_OUTPUT,
            would_build,
            trusted_local,
        )
        && stdenv_tool_inputs_are_empty(attrs)
        && only_reviewed_phase_hooks(attrs, &[])
        && [
            "buildCommand",
            "buildPhase",
            "configurePhase",
            "installPhase",
            "source",
            "cargoDeps",
            "cargoVendorDir",
            "goModules",
        ]
        .iter()
        .all(|key| derivation_attr_is_empty(attrs, key))
        && derivation_attr_text(attrs, "src") == COREDUMP_SOURCE.path
        && reviewed_store_output_is_trusted(
            drv,
            COREDUMP_SOURCE.path,
            COREDUMP_SOURCE,
            would_build,
            trusted_local,
        )
        && derivation_attr_text(attrs, "substitutions")
            == format!(
                "--replace-fail {} {}",
                COREDUMP_SOURCE
                    .path
                    .strip_suffix("/example/sysctl.d/50-coredump.conf")
                    .unwrap_or(""),
                COREDUMP_SUBSTITUTION_TARGET.path
            )
        && reviewed_store_output_is_trusted(
            drv,
            COREDUMP_SUBSTITUTION_TARGET.path,
            COREDUMP_SUBSTITUTION_TARGET,
            would_build,
            trusted_local,
        )
}

/// `pkgs.substituteAll` is used by NixOS to materialize scripts such as
/// stage-2-init and nixos-generate-config. It copies a pinned store source and
/// substitutes store paths; it does not compile that source. Match the stock
/// phase skeleton and require the exact source to be an input before allowing
/// this second, narrowly defined glue shape.
fn derivation_is_nixos_substitution_glue<F>(
    drv: &Value,
    attrs: &serde_json::Map<String, Value>,
    verify_source: &F,
    would_build: &HashSet<String>,
    trusted_local: &HashSet<String>,
) -> bool
where
    F: Fn(&str, &str) -> bool,
{
    if !derivation_attr_truthy(attrs, "preferLocalBuild")
        || !derivation_attr_truthy(attrs, "dontUnpack")
        || !has_pinned_stdenv_materializer(
            drv,
            attrs,
            verify_source,
            TRUSTED_STDENV_NO_CC_OUTPUT,
            would_build,
            trusted_local,
        )
        || !only_reviewed_phase_hooks(attrs, &["buildPhase", "checkPhase", "postInstall"])
        || !derivation_attr_is_empty(attrs, "buildCommand")
        || !derivation_attr_is_empty(attrs, "configurePhase")
        || !derivation_attr_is_empty(attrs, "installPhase")
    {
        return false;
    }
    let Some(source) = attrs.get("src").and_then(Value::as_str) else {
        return false;
    };
    let source_is_input = source.starts_with("/nix/store/")
        && derivation_input_sources(drv)
            .is_some_and(|sources| sources.iter().any(|candidate| candidate == source));
    let build_phase = derivation_attr_text(attrs, "buildPhase");
    let post_install = derivation_attr_text(attrs, "postInstall");
    let check_phase_hash = normalized_script_sha256(derivation_attr_text(attrs, "checkPhase"));
    let phase_hash = normalized_script_sha256(build_phase);
    let executable_phase_hash = executable_pinned_script_sha256(build_phase);
    let expected_tools = match (phase_hash.as_str(), executable_phase_hash.as_str()) {
        (
            "8cafb28f90f8f504b034abd094be4d6970a2870f34246605ee3471411ce22405",
            "af08e5dd1c31b4da06e919740cb0048bf67feb984cc61cb1267c5292c2679787",
        ) => NIXOS_GENERATE_CONFIG_TOOL_INPUTS,
        (
            "0cf4f12e8ffd17957a7ac7280dfc413236c4fff749e89a00c329e449f7f0d3ed",
            "0cf4f12e8ffd17957a7ac7280dfc413236c4fff749e89a00c329e449f7f0d3ed",
        ) => &[],
        (
            "3c99aab2bba077000b3ee573b684e20b9de792b8213768819cd703ef3e9733b8",
            "3c99aab2bba077000b3ee573b684e20b9de792b8213768819cd703ef3e9733b8",
        ) => &[],
        (
            "7abb6084451f1649b52a1f0503e9d847d665463cabd20d470c16d63092d98169",
            "86239d09efda35dcd8fc1c81fc0470cd022694d30b6fac9c37478fe2fd505438",
        )
        | (
            "765f0d5a997d67fcea0d8dbe896c57016db491d73b0453001519eb58fa1ddf5e",
            "da9a4efc23854364abb9218c2ae25e7cc0f7d0cc19d87fe82cc8dada9fcdc389",
        )
        | (
            "5848971a70c8156aab153adc563cd3353e9c855d1bdb9e6988808494ebfb6b21",
            "44e0fd288c4541f6dd3f16b5a729f5c6f6060cb254f70e8f5f867de5ee189a5d",
        )
        | (
            "3e201cec74c9be02881fce10a5c29dc2a5719be5453566c6fd73ec596129f5cf",
            "a34ed9dceb2bf0f48d29131afece2c02792fc81eb4e68c00f3c776aa6d222b3f",
        )
        | (
            "f18a7b7c27d7028c344b37c24b185fed3fd5a4a23b0aa0d208d7aa50ab7fd0cc",
            "a677a90325d5e32882f560489c044a08b915301969f3ea695c495d27b64adfaa",
        ) => NIXOS_GENERATE_CONFIG_TOOL_INPUTS,
        (
            "3489e136a18e68375d5e57de9d5b9199f407915249c0082cf87763e79c521eff",
            "4bb1e28d9e38c00705275e997fae6b860d4dde2bfe7536f30805ae9fc3f0e551",
        ) => &[],
        _ => return false,
    };
    let approved_phase = source_is_input
        && build_phase.starts_with("runHook preBuild\n\ntarget=$out\n")
        && build_phase.contains("substitute \"$src\" \"$target\"")
        && build_phase.ends_with("runHook postBuild\n")
        && reviewed_tool_inputs_match(drv, attrs, expected_tools, would_build, trusted_local);
    let reviewed_check = matches!(
        check_phase_hash.as_str(),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            | "eb9794c015ed45dee3981591da3f5b6927ca4b9dc4d03829cb196bb96a77fa58"
            | "45bdb470a9145c13f5c931a08f9ea3d8300a8a593c7a067cf6980c7c30733757"
            | "d50c9f65372b25822e7119d3b3931790d1c6dd2992cf8501cb8ff38d9a7b764c"
    );
    let reviewed_post_install = post_install.is_empty()
        || post_install
            .strip_prefix("installManPage ")
            .and_then(|path| path.strip_suffix('\n'))
            .is_some_and(|path| {
                safe_nix_store_path(path)
                    && derivation_input_sources(drv)
                        .is_some_and(|sources| sources.iter().any(|source| source == path))
            });
    approved_phase && reviewed_check && reviewed_post_install
}

/// `security.wrappers` is native NixOS configuration glue. It compiles the
/// pinned nixpkgs wrapper template, not application source. Keep this narrow:
/// the standard wrapper name, generated no-unpack phase, one wrapper.c input,
/// and fixed output filename must all agree.
fn derivation_is_nixos_security_wrapper<F>(
    drv_path: &str,
    drv: &Value,
    attrs: &serde_json::Map<String, Value>,
    verify_source: &F,
    would_build: &HashSet<String>,
    trusted_local: &HashSet<String>,
) -> bool
where
    F: Fn(&str, &str) -> bool,
{
    let name = drv
        .get("name")
        .and_then(Value::as_str)
        .or_else(|| attrs.get("name").and_then(Value::as_str))
        .unwrap_or("");
    let install_phase = derivation_attr_text(attrs, "installPhase");
    let install_lines = install_phase.lines().collect::<Vec<_>>();
    let compile_words = install_lines
        .get(1)
        .map(|line| line.split_whitespace().collect::<Vec<_>>())
        .unwrap_or_default();
    let include_path = compile_words
        .get(3)
        .and_then(|word| word.strip_prefix("-I"))
        .unwrap_or("");
    let cflags = derivation_attr_text(attrs, "CFLAGS");
    let source_program = cflags
        .strip_prefix("-DSOURCE_PROG=\"")
        .and_then(|value| value.strip_suffix("\" -Wall -O2"))
        .unwrap_or("");
    let Some(input_sources) = derivation_input_sources(drv) else {
        return false;
    };
    let wrapper_sources = input_sources
        .iter()
        .filter(|source| source.ends_with("-wrapper.c"))
        .collect::<Vec<_>>();
    let linker_flags = derivation_attr_text(attrs, "NIX_CFLAGS_LINK");
    let expected_tools = if linker_flags == " -static" && name.ends_with("-unknown-linux-musl") {
        SECURITY_WRAPPER_TOOL_INPUTS
    } else {
        return false;
    };
    let include_reference = input_drv_output_reference(drv, include_path);
    drv_path.ends_with(".drv")
        && name.starts_with("security-wrapper-")
        && has_pinned_stdenv_materializer(
            drv,
            attrs,
            verify_source,
            TRUSTED_STDENV_STATIC_OUTPUT,
            would_build,
            trusted_local,
        )
        && !derivation_has_shell_environment_injection_except(attrs, &["NIX_CFLAGS_LINK"])
        && derivation_attr_truthy(attrs, "dontUnpack")
        && derivation_attr_is_empty(attrs, "src")
        && reviewed_tool_inputs_match(drv, attrs, expected_tools, would_build, trusted_local)
        && derivation_attr_is_empty(attrs, "buildPhase")
        && derivation_attr_is_empty(attrs, "configurePhase")
        && derivation_attr_is_empty(attrs, "CC")
        && only_reviewed_phase_hooks(attrs, &["installPhase"])
        && wrapper_sources.len() == 1
        && safe_nix_store_path(wrapper_sources[0])
        && verify_source(wrapper_sources[0], TRUSTED_SECURITY_WRAPPER_SHA256)
        && install_lines.len() == 2
        && install_lines[0] == "mkdir -p $out/bin"
        && compile_words.len() == 6
        && compile_words[0] == "$CC"
        && compile_words[1] == "$CFLAGS"
        && compile_words[2] == wrapper_sources[0]
        && include_path == TRUSTED_SECURITY_WRAPPER_INCLUDE_PATH
        && include_reference.is_some_and(|reference| {
            reference.drv_path == TRUSTED_SECURITY_WRAPPER_INCLUDE_DRV
                && reference.output == "out"
                && input_derivation_is_nonlocal_or_trusted(
                    &reference.drv_path,
                    would_build,
                    trusted_local,
                )
        })
        && compile_words[4] == "-o"
        && compile_words[5] == "$out/bin/security-wrapper"
        && safe_nix_store_path(source_program)
        && store_path_has_matching_input_derivation(drv, source_program)
}

async fn ensure_nix_daemon_available(config: &AppConfig) -> Result<()> {
    let output = crate::nix_command::tokio_command(&config.build.nix_binary)
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
        json!("cybex.pulse.build.result.v1"),
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
    software_inventory: &Value,
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
        json!(spec.build_input.as_ref().map(|input| input.kind.as_str())),
    );
    if let Some(input) = spec.build_input.as_ref() {
        if let Some(revision) = input.manage_source_revision.as_deref() {
            object.insert("manage_source_revision".to_string(), json!(revision));
        }
        if let Some(identity) = input.installer_target.as_ref() {
            object.insert("installer_target".to_string(), identity.clone());
        }
    }
    object.insert("cache".to_string(), json!("exported"));
    if let Some(commit) = spec.nixpkgs_commit.as_deref() {
        object.insert("nixpkgs_revision".to_string(), json!(commit));
        object.insert(
            "nixpkgs_flake".to_string(),
            json!(format!("github:NixOS/nixpkgs/{commit}")),
        );
    }
    object.insert(
        "source_lock_sha256".to_string(),
        json!(spec.source_lock_sha256),
    );
    object.insert("software_inventory".to_string(), software_inventory.clone());
    metadata
}

fn software_inventory_eval_args(installable: &str, allow_source_builds: bool) -> Vec<String> {
    let mut args = Vec::new();
    // Inventory is metadata, but `nix eval` can still realize an
    // import-from-derivation before returning that metadata. Keep it inside
    // the same command-line policy boundary as preflight and the real build.
    append_source_policy_nix_options(&mut args, allow_source_builds);
    args.extend([
        "eval".to_string(),
        "--raw".to_string(),
        "--no-write-lock-file".to_string(),
        installable.to_string(),
    ]);
    args
}

async fn evaluate_software_inventory(config: &AppConfig, spec: &ValidatedBuildSpec) -> Value {
    evaluate_software_inventory_with_limits(config, spec, SoftwareInventoryLimits::default()).await
}

async fn evaluate_software_inventory_with_limits(
    config: &AppConfig,
    spec: &ValidatedBuildSpec,
    limits: SoftwareInventoryLimits,
) -> Value {
    let Some(commit) = spec.nixpkgs_commit.as_deref() else {
        return json!([]);
    };
    let mut refs = vec![(
        "linux-kernel".to_string(),
        "linuxPackages.kernel".to_string(),
    )];
    for package_ref in &spec.software_package_refs {
        if !refs.iter().any(|(_, existing)| existing == package_ref) {
            refs.push((package_ref.clone(), package_ref.clone()));
        }
    }
    let started = Instant::now();
    let mut inventory = Vec::new();
    for (name, package_ref) in refs {
        let remaining = limits.total_timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            break;
        }
        let installable = format!(
            "github:NixOS/nixpkgs/{commit}#legacyPackages.{}.{}.version",
            spec.system, package_ref
        );
        let mut command = crate::nix_command::tokio_command(&config.build.nix_binary);
        command.args(software_inventory_eval_args(
            &installable,
            spec.allow_source_builds,
        ));
        let output = run_bounded_command(
            command,
            limits.probe_timeout.min(remaining),
            limits.stdout_max_bytes,
            limits.stderr_max_bytes,
            "nix software inventory eval",
        )
        .await;
        let Ok(output) = output else {
            continue;
        };
        if !output.status.success() {
            continue;
        }
        let version = String::from_utf8_lossy(&output.stdout)
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        if version.is_empty() || version.len() > 160 {
            continue;
        }
        inventory.push(json!({
            "name": name,
            "package_ref": package_ref,
            "version": version,
        }));
    }
    Value::Array(inventory)
}

fn merge_build_metadata(destination: &mut Value, source: &Value) {
    let Some(source) = source.as_object() else {
        return;
    };
    let Some(destination) = destination.as_object_mut() else {
        return;
    };
    for (key, value) in source {
        // Cache export metadata includes cryptographically verified fields
        // such as the closure manifest and its digest. Managed/request
        // metadata may add context, but must never replace an export result.
        destination
            .entry(key.clone())
            .or_insert_with(|| value.clone());
    }
}

fn nix_build_command(
    config: &AppConfig,
    target: &BuildTargetConfig,
    spec: &ValidatedBuildSpec,
    job_id: i64,
) -> Result<NixBuildCommand> {
    if let Some(build_input) = spec.build_input.as_ref() {
        return blueprint_nix_build_command(config, target, spec, build_input, job_id);
    }
    let job_dir = config.build.output_dir.join(format!("job-{job_id}"));
    let out_link = job_dir.join("result");
    let installable = format!("{}#{}", target.flake, target.attr);
    let mut args = vec!["build".to_string()];
    append_source_policy_nix_options(&mut args, spec.allow_source_builds);
    args.extend([
        installable.clone(),
        "--cores".to_string(),
        config.build.max_build_cores.to_string(),
        "--system".to_string(),
        spec.system.clone(),
        "--out-link".to_string(),
        out_link.display().to_string(),
        "--print-build-logs".to_string(),
        "--log-format".to_string(),
        "internal-json".to_string(),
        "--no-write-lock-file".to_string(),
    ]);
    Ok(NixBuildCommand {
        program: config.build.nix_binary.clone(),
        args,
        out_link,
        installable,
    })
}

fn blueprint_nix_build_command(
    config: &AppConfig,
    target: &BuildTargetConfig,
    spec: &ValidatedBuildSpec,
    build_input: &ValidatedBlueprintBuildInput,
    job_id: i64,
) -> Result<NixBuildCommand> {
    // ValidatedBuildSpec is private, but keep the write boundary independently
    // guarded so future internal call sites cannot materialize protected data.
    protected_material::validate_generated_nix(&build_input.generated_nix)?;
    if let Some(desktop_module_nix) = build_input.desktop_module_nix.as_deref() {
        protected_material::validate_desktop_module_nix(desktop_module_nix)?;
    }
    if let Some(expected_state) = build_input.expected_state.as_ref() {
        protected_material::validate_expected_state(expected_state)?;
    }

    fs::create_dir_all(&config.build.work_dir).with_context(|| {
        format!(
            "create build work directory {}",
            config.build.work_dir.display()
        )
    })?;
    set_private_job_input_dir_permissions(&config.build.work_dir)?;
    let input_dir = config.build.work_dir.join(format!("job-{job_id}-input"));
    fs::create_dir(&input_dir)
        .with_context(|| format!("create build input directory {}", input_dir.display()))?;
    set_private_job_input_dir_permissions(&input_dir)?;
    write_job_input_file(input_dir.join("blueprint.nix"), &build_input.generated_nix)?;
    if let Some(desktop_module_nix) = build_input.desktop_module_nix.as_deref() {
        write_job_input_file(input_dir.join("cybex-blueprints.nix"), desktop_module_nix)?;
    }
    if let Some(expected_state) = build_input.expected_state.as_ref() {
        let expected_state = serde_json::to_string_pretty(expected_state)
            .context("serialize Blueprint expected state")?;
        write_job_input_file(input_dir.join("expected-state.json"), &expected_state)?;
    }
    if let Some(hardware_module_nix) = build_input.hardware_module_nix.as_deref() {
        write_job_input_file(input_dir.join("hardware.nix"), hardware_module_nix)?;
    }
    if let Some(target_module_nix) = build_input.target_module_nix.as_deref() {
        write_job_input_file(input_dir.join("target.nix"), target_module_nix)?;
    }
    let compatibility_module = if build_input.kind == INSTALLER_TARGET_BUILD_INPUT_KIND {
        installer_target_compat_module()
    } else {
        blueprint_compat_module(build_input.desktop_module_nix.is_some())
    };
    write_job_input_file(
        input_dir.join("cybex-compat-options.nix"),
        compatibility_module,
    )?;
    write_job_input_file(
        input_dir.join("configuration.nix"),
        &pulse_nixos_configuration(build_input),
    )?;
    write_job_input_file(
        input_dir.join("flake.nix"),
        &pulse_nixos_flake(
            &format!(
                "github:NixOS/nixpkgs/{}",
                spec.nixpkgs_commit
                    .as_deref()
                    .expect("validated Blueprint source pin")
            ),
            &spec.system,
            build_input,
            &config.build.manage_source_url_template,
        ),
    )?;

    let job_dir = config.build.output_dir.join(format!("job-{job_id}"));
    let out_link = job_dir.join("result");
    let installable = format!("{}#{}", input_dir.display(), target.attr);
    let mut args = vec!["build".to_string()];
    append_source_policy_nix_options(&mut args, spec.allow_source_builds);
    args.extend([
        installable.clone(),
        "--cores".to_string(),
        config.build.max_build_cores.to_string(),
        "--out-link".to_string(),
        out_link.display().to_string(),
        "--print-build-logs".to_string(),
        "--log-format".to_string(),
        "internal-json".to_string(),
        "--no-write-lock-file".to_string(),
    ]);
    Ok(NixBuildCommand {
        program: config.build.nix_binary.clone(),
        args,
        out_link,
        installable,
    })
}

fn write_job_input_file(path: PathBuf, contents: &str) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.mode(0o600);
    }
    let mut file = options
        .open(&path)
        .with_context(|| format!("create build input {}", path.display()))?;
    set_private_job_input_file_permissions(&path)?;
    file.write_all(contents.as_bytes())
        .with_context(|| format!("write build input {}", path.display()))
}

#[cfg(unix)]
fn set_private_job_input_dir_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("restrict build input directory {}", path.display()))
}

#[cfg(not(unix))]
fn set_private_job_input_dir_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_private_job_input_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("restrict build input file {}", path.display()))
}

#[cfg(not(unix))]
fn set_private_job_input_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

fn pulse_nixos_flake(
    nixpkgs_flake: &str,
    system: &str,
    build_input: &ValidatedBlueprintBuildInput,
    manage_source_url_template: &str,
) -> String {
    let name = build_input.blueprint_name.as_deref().unwrap_or("Blueprint");
    let revision = build_input
        .blueprint_revision
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let description = serde_json::to_string(&format!(
        "Cybex Pulse Blueprint build: {name} rev {revision}"
    ))
    .unwrap_or_else(|_| "\"Cybex Pulse Blueprint build\"".to_string());
    let nixpkgs_flake =
        serde_json::to_string(nixpkgs_flake).unwrap_or_else(|_| "\"nixpkgs\"".to_string());
    if build_input.kind == INSTALLER_TARGET_BUILD_INPUT_KIND {
        let manage_revision = build_input
            .manage_source_revision
            .as_deref()
            .expect("validated installer target Manage revision");
        let manage_flake = serde_json::to_string(
            &manage_source_url_template.replace("{revision}", manage_revision),
        )
        .unwrap_or_else(|_| "\"manage\"".to_string());
        return format!(
            r#"{{
  description = {description};

  inputs.nixpkgs.url = {nixpkgs_flake};
  inputs.manage = {{
    url = {manage_flake};
    flake = false;
  }};

  outputs = {{ self, nixpkgs, manage }}:
    let
      system = "{system}";
      pkgs = import nixpkgs {{ inherit system; }};
      cybexAgent = pkgs.rustPlatform.buildRustPackage {{
        pname = "cybex-agent";
        version = "installer-target";
        src = manage + "/agent/cybex-agent";
        cargoLock.lockFile = manage + "/agent/cybex-agent/Cargo.lock";
        doCheck = false;
      }};
    in {{
      packages.${{system}}.desktop-experience =
        (nixpkgs.lib.nixosSystem {{
          inherit system;
          specialArgs = {{
            manageSource = manage;
            inherit cybexAgent;
          }};
          modules = [ ./configuration.nix ];
        }}).config.system.build.toplevel;
    }};
}}
"#
        );
    }
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

fn pulse_nixos_configuration(build_input: &ValidatedBlueprintBuildInput) -> String {
    let include_desktop_module = build_input.desktop_module_nix.is_some();
    if build_input.kind == INSTALLER_TARGET_BUILD_INPUT_KIND {
        return r#"{ ... }:

{
  imports = [
    ./cybex-compat-options.nix
    ./cybex-blueprints.nix
    ./blueprint.nix
    ./hardware.nix
    ./target.nix
  ];
}
"#
        .to_string();
    }
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
  networking.hostName = lib.mkDefault "cybex-pulse-build";
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
    description = "Cybex Blueprint metadata accepted while Pulse prebuilds a generic NixOS closure.";
  };

  options.services.cybex-agent = lib.mkOption {
    type = lib.types.attrsOf lib.types.anything;
    default = {};
    description = "Cybex Agent policy accepted while Pulse prebuilds a generic NixOS closure.";
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
    description = "Cybex Agent policy accepted while Pulse prebuilds a generic NixOS closure.";
  };
}
"#
}

fn installer_target_compat_module() -> &'static str {
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
    let mut child = crate::nix_command::tokio_command(&command.program)
        .args(&command.args)
        .current_dir(&config.build.work_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
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
    let progress = Arc::new(Mutex::new(InternalJsonParser::new()));
    let stderr_progress = progress.clone();
    let stdout_task = tokio::spawn(async move { read_log_stream(stdout, stdout_log).await });
    let stderr_task = tokio::spawn(async move {
        read_internal_json_log_stream(stderr, stderr_log, stderr_progress).await
    });
    let started = Instant::now();
    let mut last_log_update = Instant::now();
    let mut last_progress_sent: Option<(i32, String)> = None;
    let outcome = loop {
        match db::build_job_cancel_requested(pool, job.id).await {
            Ok(true) => {
                terminate_child(&mut child);
                let _ = timeout(
                    Duration::from_secs(config.build.cancel_grace_seconds),
                    child.wait(),
                )
                .await;
                let _ = child.kill().await;
                break ProcessOutcome::Cancelled;
            }
            Ok(false) => {}
            Err(err) => {
                warn!(
                    error = %safe_error(&err.into()),
                    job_id = job.id,
                    "could not check Pulse build cancellation; build supervision will retry"
                );
            }
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
            if let Err(err) = db::update_build_job_logs(pool, job.id, &log.snapshot().await).await {
                warn!(
                    error = %safe_error(&err.into()),
                    job_id = job.id,
                    "could not persist Pulse build logs; build supervision will retry"
                );
            }
            let update = progress
                .lock()
                .await
                .snapshot()
                .progress_update(BUILDING_PROGRESS_START, BUILDING_PROGRESS_END);
            if let Some((mut percent, message)) = update {
                // Keep the reported percentage monotonic even if nix raises
                // its expected-derivation count mid-build.
                if let Some((last_percent, _)) = last_progress_sent.as_ref() {
                    percent = percent.max(*last_percent);
                }
                if last_progress_sent.as_ref() != Some(&(percent, message.clone())) {
                    match db::update_build_job_progress(
                        pool,
                        job.id,
                        Some(percent),
                        "building",
                        &message,
                    )
                    .await
                    {
                        Ok(()) => last_progress_sent = Some((percent, message)),
                        Err(err) => warn!(
                            error = %safe_error(&err.into()),
                            job_id = job.id,
                            "could not persist Pulse build progress; build supervision will retry"
                        ),
                    }
                }
            }
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
    let (output_size_bytes, closure_size_bytes, evaluated_derivation) =
        run_nix_path_info(config, &output_path).await?;
    Ok(NixOutputInfo {
        output_path,
        output_sha256,
        output_size_bytes,
        closure_size_bytes,
        evaluated_derivation,
    })
}

async fn run_nix_hash(config: &AppConfig, path: &str) -> Result<String> {
    let output = crate::nix_command::tokio_command(&config.build.nix_binary)
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

async fn run_nix_path_info(config: &AppConfig, path: &str) -> Result<(i64, i64, Option<String>)> {
    let output = crate::nix_command::tokio_command(&config.build.nix_binary)
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
    let evaluated_derivation = nix_path_info_deriver(first);
    Ok((output_size_bytes, closure_size_bytes, evaluated_derivation))
}

fn nix_path_info_row<'a>(value: &'a Value, path: &str) -> Result<&'a Value> {
    if let Some(array) = value.as_array() {
        if array.len() != 1 {
            bail!("nix path-info returned an unexpected number of rows");
        }
        let first = &array[0];
        if let Some(returned_path) = first.get("path").and_then(Value::as_str) {
            if returned_path != path {
                bail!("nix path-info returned a row for an unexpected store path");
            }
        }
        return Ok(first);
    }
    if let Some(object) = value.as_object() {
        if let Some(row) = object.get(path) {
            return Ok(row);
        }
        bail!("nix path-info omitted the requested store path");
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

fn nix_path_info_deriver(first: &Value) -> Option<String> {
    first
        .get("deriver")
        .and_then(Value::as_str)
        .and_then(normalize_derivation_store_path)
}

async fn read_internal_json_log_stream<R>(
    reader: R,
    log: SharedLog,
    progress: Arc<Mutex<InternalJsonParser>>,
) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut lines = BufReader::new(reader).lines();
    while let Some(line) = lines.next_line().await? {
        let rendered = progress.lock().await.feed_line(&line);
        if let Some(text) = rendered {
            log.append(&format!("{text}\n")).await;
        }
    }
    Ok(())
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
        inner.pending.push_str(text);
        if let Some(last_newline) = inner.pending.rfind('\n') {
            let complete = inner.pending[..=last_newline].to_string();
            inner.pending.drain(..=last_newline);
            let mut redact_following = inner.redact_following;
            let redacted = redact_log_text(&complete, &mut redact_following);
            inner.redact_following = redact_following;
            inner.text.push_str(&redacted);
            bound_captured_log(&mut inner.text, self.max_bytes);
        }
        if inner.pending.len() > MAX_PENDING_LOG_LINE_BYTES {
            inner
                .text
                .push_str("[... oversized unbroken build log line redacted ...]\n");
            inner.pending.clear();
            inner.redact_following = 0;
            bound_captured_log(&mut inner.text, self.max_bytes);
        }
    }

    async fn snapshot(&self) -> String {
        let inner = self.inner.lock().await;
        let mut snapshot = inner.text.clone();
        let mut redact_following = inner.redact_following;
        snapshot.push_str(&redact_log_text(&inner.pending, &mut redact_following));
        bound_captured_log(&mut snapshot, self.max_bytes);
        snapshot
    }
}

fn bound_captured_log(text: &mut String, max_bytes: usize) {
    if text.len() <= max_bytes {
        return;
    }
    let marker = "[... earlier build log truncated ...]\n";
    let keep = max_bytes.saturating_sub(marker.len());
    let start = utf8_tail_start(text, keep);
    let tail = text[start..].to_string();
    *text = format!("{marker}{tail}");
}

fn redact_log_text(text: &str, redact_following: &mut usize) -> String {
    let mut redacted = String::with_capacity(text.len());
    let mut first = true;
    for line in text.split('\n') {
        if !first {
            redacted.push('\n');
        }
        first = false;
        redacted.push_str(&redact_log_line(line, redact_following));
    }
    redacted
}

fn redact_log_line(line: &str, redact_following: &mut usize) -> String {
    let line = redact_sensitive_key_values(line);
    line.split_whitespace()
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

fn normalize_nixpkgs_commit(value: &str) -> Result<String> {
    let value = value.trim().to_ascii_lowercase();
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("nixpkgs_commit must be a lowercase 40-character commit");
    }
    Ok(value)
}

fn normalize_package_ref(value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 192
        || value.starts_with('.')
        || value.ends_with('.')
        || value.split('.').any(|part| part.is_empty())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'+' | b'.'))
    {
        bail!("invalid software package reference");
    }
    Ok(value.to_string())
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

    #[cfg(unix)]
    #[tokio::test]
    async fn nix_daemon_probe_enables_required_features() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "cybex-pulse-nix-daemon-feature-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let fake_nix = root.join("nix");
        std::fs::write(
            &fake_nix,
            r#"#!/bin/sh
set -eu
case "${NIX_CONFIG:-}" in
  *"extra-experimental-features = nix-command flakes"*) ;;
  *) printf '%s\n' 'required Nix features are missing' >&2; exit 64 ;;
esac
[ "$#" -eq 4 ]
[ "$1" = store ]
[ "$2" = ping ]
[ "$3" = --store ]
[ "$4" = daemon ]
"#,
        )
        .unwrap();
        std::fs::set_permissions(&fake_nix, std::fs::Permissions::from_mode(0o700)).unwrap();

        let mut config = AppConfig::default();
        config.build.nix_binary = fake_nix.display().to_string();
        let result = ensure_nix_daemon_available(&config).await;
        std::fs::remove_dir_all(root).unwrap();
        result.unwrap();
    }

    fn valid_installer_target_identity() -> Value {
        json!({
            "schema": INSTALLER_TARGET_BUILD_SCHEMA,
            "preparation_id": "00000000-0000-4000-8000-000000000001",
            "device_id": "device_1",
            "device_incarnation_id": "00000000-0000-4000-8000-000000000002",
            "blueprint_id": "00000000-0000-4000-8000-000000000003",
            "blueprint_revision_id": "00000000-0000-4000-8000-000000000004",
            "hardware_facts_sha256": "11".repeat(32),
            "hardware_driver_policy": "auto",
            "disk_layout_sha256": "22".repeat(32),
            "pulse_device_id": "pulse_1",
            "bundle_sha256": "33".repeat(32),
            "profile_id": "00000000-0000-4000-8000-000000000005",
            "managed_device_id": null,
            "reinstall_request_id": null,
            "manage_source_revision": "4".repeat(40),
            "nixpkgs_revision": "5".repeat(40),
            "source_lock_sha256": "66".repeat(32)
        })
    }

    #[test]
    fn installer_target_identity_is_exact_and_bound_to_manage_source() {
        let valid = valid_installer_target_identity();
        validate_installer_target_identity(&valid, &"4".repeat(40)).unwrap();

        let mut wrong_manage = valid.clone();
        wrong_manage["manage_source_revision"] = json!("7".repeat(40));
        assert!(
            validate_installer_target_identity(&wrong_manage, &"4".repeat(40))
                .unwrap_err()
                .to_string()
                .contains("Manage revision fields do not match")
        );

        let mut one_sided_reinstall = valid.clone();
        one_sided_reinstall["managed_device_id"] = json!("device_1");
        assert!(
            validate_installer_target_identity(&one_sided_reinstall, &"4".repeat(40))
                .unwrap_err()
                .to_string()
                .contains("reinstall bindings")
        );

        let mut unknown = valid;
        unknown["unexpected"] = json!(true);
        assert!(
            validate_installer_target_identity(&unknown, &"4".repeat(40))
                .unwrap_err()
                .to_string()
                .contains("does not match its schema")
        );
    }

    fn import_from_derivation_is_disabled(args: &[String]) -> bool {
        args.windows(DISABLE_IFD_NIX_OPTION.len())
            .any(|window| window.iter().map(String::as_str).eq(DISABLE_IFD_NIX_OPTION))
    }

    fn flake_config_is_rejected(args: &[String]) -> bool {
        args.windows(REJECT_FLAKE_CONFIG_NIX_OPTION.len())
            .any(|window| {
                window
                    .iter()
                    .map(String::as_str)
                    .eq(REJECT_FLAKE_CONFIG_NIX_OPTION)
            })
    }

    fn build_sandbox_is_required(args: &[String]) -> bool {
        args.windows(REQUIRE_BUILD_SANDBOX_NIX_OPTION.len())
            .any(|window| {
                window
                    .iter()
                    .map(String::as_str)
                    .eq(REQUIRE_BUILD_SANDBOX_NIX_OPTION)
            })
    }

    fn software_inventory_test_spec(
        allow_source_builds: bool,
        software_package_refs: Vec<String>,
    ) -> ValidatedBuildSpec {
        ValidatedBuildSpec {
            artifact_type: "nixos_closure".to_string(),
            target: "blueprint".to_string(),
            system: "x86_64-linux".to_string(),
            input_revision: "rev".to_string(),
            input_config_hash: "a".repeat(64),
            blueprint_id: None,
            blueprint_revision_id: None,
            blueprint_revision_config_hash: None,
            nixpkgs_commit: Some("c".repeat(40)),
            source_lock_sha256: Some("d".repeat(64)),
            software_package_refs,
            build_input: None,
            allow_source_builds,
        }
    }

    #[test]
    fn software_inventory_eval_inherits_the_build_source_policy() {
        let installable =
            "github:NixOS/nixpkgs/reviewed#legacyPackages.x86_64-linux.firefox.version";
        let source_disabled = software_inventory_eval_args(installable, false);
        assert!(import_from_derivation_is_disabled(&source_disabled));
        assert!(flake_config_is_rejected(&source_disabled));
        assert!(build_sandbox_is_required(&source_disabled));
        assert_eq!(
            source_disabled.last().map(String::as_str),
            Some(installable)
        );

        let source_enabled = software_inventory_eval_args(installable, true);
        assert!(!import_from_derivation_is_disabled(&source_enabled));
        assert!(flake_config_is_rejected(&source_enabled));
        assert!(build_sandbox_is_required(&source_enabled));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn software_inventory_uses_bounded_source_disabled_eval() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "cybex-pulse-software-inventory-policy-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let fake_nix = root.join("fake-nix");
        std::fs::write(
            &fake_nix,
            r#"#!/bin/sh
set -eu
case " $* " in
  *" --option accept-flake-config false "*) ;;
  *) exit 91 ;;
esac
case " $* " in
  *" --option allow-import-from-derivation false "*) ;;
  *) exit 92 ;;
esac
printf '123.4\n'
"#,
        )
        .unwrap();
        std::fs::set_permissions(&fake_nix, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut config = AppConfig::default();
        config.build.nix_binary = fake_nix.display().to_string();
        let spec = software_inventory_test_spec(false, vec!["firefox".to_string()]);

        let inventory = evaluate_software_inventory_with_limits(
            &config,
            &spec,
            SoftwareInventoryLimits {
                probe_timeout: Duration::from_secs(1),
                total_timeout: Duration::from_secs(2),
                stdout_max_bytes: 1024,
                stderr_max_bytes: 1024,
            },
        )
        .await;

        let inventory = inventory.as_array().unwrap();
        assert_eq!(inventory.len(), 2);
        assert!(
            inventory
                .iter()
                .all(|item| item.get("version") == Some(&json!("123.4")))
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn software_inventory_timeout_kills_the_probe_process_group() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "cybex-pulse-software-inventory-timeout-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let marker = root.join("orphan-survived");
        let fake_nix = root.join("fake-nix");
        std::fs::write(
            &fake_nix,
            format!(
                r#"#!/bin/sh
set -eu
case " $* " in
  *" --option accept-flake-config false "*) ;;
  *) exit 91 ;;
esac
case " $* " in
  *" --option allow-import-from-derivation false "*) ;;
  *) exit 92 ;;
esac
( sleep 0.25; printf survived > '{}' ) &
sleep 5
"#,
                marker.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&fake_nix, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut config = AppConfig::default();
        config.build.nix_binary = fake_nix.display().to_string();
        let spec = software_inventory_test_spec(false, vec!["firefox".to_string()]);
        let started = Instant::now();

        let inventory = evaluate_software_inventory_with_limits(
            &config,
            &spec,
            SoftwareInventoryLimits {
                probe_timeout: Duration::from_millis(50),
                total_timeout: Duration::from_millis(80),
                stdout_max_bytes: 1024,
                stderr_max_bytes: 1024,
            },
        )
        .await;

        assert_eq!(inventory, json!([]));
        assert!(started.elapsed() < Duration::from_secs(1));
        sleep(Duration::from_millis(350)).await;
        assert!(
            !marker.exists(),
            "a timed-out inventory probe left a descendant process running"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn cleanup_and_sweep_remove_job_dirs() {
        let root = std::env::temp_dir().join(format!(
            "cybex-pulse-build-cleanup-test-{}",
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
                    "schema": "cybex.blueprint.expected-state.v2",
                    "compiler_version": 2,
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
    fn blueprint_build_input_requires_expected_state_with_real_desktop_module() {
        let input = BlueprintBuildInput {
            kind: BLUEPRINT_BUILD_INPUT_KIND.to_string(),
            generated_nix: "{ ... }: {}".to_string(),
            desktop_module_nix: Some("{ ... }: {}".to_string()),
            expected_state: None,
            blueprint_name: None,
            blueprint_revision: None,
            hardware_module_nix: None,
            target_module_nix: None,
            manage_source_revision: None,
            installer_target: None,
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
        // Specs from older Manage versions omit allow_source_builds entirely;
        // enforcement must default on.
        assert!(!parsed.allow_source_builds);
        assert!(build_target_names_compatible(
            "desktop_experience",
            "blueprint"
        ));
    }

    #[test]
    fn nix_build_command_uses_allowlisted_attr() {
        let mut config = AppConfig::default();
        config.build.output_dir = PathBuf::from("/tmp/cybex-pulse-test-builds");
        config.build.nix_binary = "nix".to_string();
        let target = BuildTargetConfig {
            artifact_type: "nixos_closure".to_string(),
            target: "blueprint".to_string(),
            system: "x86_64-linux".to_string(),
            flake: "/srv/cybex-pulse/build-inputs/cybex".to_string(),
            attr: "packages.x86_64-linux.desktop-experience".to_string(),
        };
        let mut spec = ValidatedBuildSpec {
            artifact_type: "nixos_closure".to_string(),
            target: "blueprint".to_string(),
            system: "x86_64-linux".to_string(),
            input_revision: "rev".to_string(),
            input_config_hash: "a".repeat(64),
            blueprint_id: None,
            blueprint_revision_id: None,
            blueprint_revision_config_hash: None,
            nixpkgs_commit: None,
            source_lock_sha256: None,
            software_package_refs: Vec::new(),
            build_input: None,
            allow_source_builds: false,
        };

        let command = nix_build_command(&config, &target, &spec, 42).unwrap();

        assert_eq!(command.program, "nix");
        assert_eq!(command.args[0], "build");
        assert!(
            command.args.contains(
                &"/srv/cybex-pulse/build-inputs/cybex#packages.x86_64-linux.desktop-experience"
                    .to_string()
            )
        );
        assert!(command.args.contains(&"--out-link".to_string()));
        assert!(command.args.windows(2).any(|args| args == ["--cores", "4"]));
        assert!(import_from_derivation_is_disabled(&command.args));
        assert!(flake_config_is_rejected(&command.args));
        assert!(build_sandbox_is_required(&command.args));

        spec.allow_source_builds = true;
        let source_enabled = nix_build_command(&config, &target, &spec, 43).unwrap();
        assert!(!import_from_derivation_is_disabled(&source_enabled.args));
        assert!(flake_config_is_rejected(&source_enabled.args));
        assert!(build_sandbox_is_required(&source_enabled.args));
    }

    #[test]
    fn blueprint_build_target_requires_the_reviewed_configured_nixpkgs_pin() {
        let reviewed = "74cc63f702f7d60a557e152a57b40fb1fd0f72ac";
        let mut config = AppConfig::default();
        config.build.targets = vec![BuildTargetConfig {
            artifact_type: "nixos_closure".to_string(),
            target: "blueprint".to_string(),
            system: "x86_64-linux".to_string(),
            flake: format!("github:NixOS/nixpkgs/{reviewed}"),
            attr: "packages.x86_64-linux.desktop-experience".to_string(),
        }];
        let mut spec = ValidatedBuildSpec {
            artifact_type: "nixos_closure".to_string(),
            target: "blueprint".to_string(),
            system: "x86_64-linux".to_string(),
            input_revision: "rev".to_string(),
            input_config_hash: "a".repeat(64),
            blueprint_id: None,
            blueprint_revision_id: None,
            blueprint_revision_config_hash: None,
            nixpkgs_commit: Some(reviewed.to_string()),
            source_lock_sha256: Some("b".repeat(64)),
            software_package_refs: Vec::new(),
            build_input: Some(ValidatedBlueprintBuildInput {
                kind: BLUEPRINT_BUILD_INPUT_KIND.to_string(),
                generated_nix: "{ ... }: {}".to_string(),
                desktop_module_nix: None,
                expected_state: None,
                blueprint_name: None,
                blueprint_revision: None,
                hardware_module_nix: None,
                target_module_nix: None,
                manage_source_revision: None,
                installer_target: None,
            }),
            allow_source_builds: false,
        };
        assert!(build_target(&config, &spec).is_ok());

        spec.nixpkgs_commit = Some("293d6abedf0478e681a4dfcfcb35b30fc796a32f".to_string());
        let error = build_target(&config, &spec).unwrap_err().to_string();
        assert!(error.contains("does not match"));
    }

    #[test]
    fn lookup_derivation_handles_both_show_output_shapes() {
        let full_path = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-users-groups.json.drv";
        // nix >= 2.30: nested under "derivations", keyed by basename.
        let nested = json!({"derivations": {
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-users-groups.json.drv": {
                "name": "users-groups.json",
                "env": {"preferLocalBuild": "1", "text": "{}"}
            }
        }});
        assert!(lookup_derivation(&nested, full_path).is_some());
        // older nix: top-level keyed by full store path.
        let flat = json!({
            full_path: {
                "name": "users-groups.json",
                "env": {"preferLocalBuild": "1", "text": "{}"}
            }
        });
        assert!(lookup_derivation(&flat, full_path).is_some());
        assert!(lookup_derivation(&nested, "/nix/store/bb-unknown.drv").is_none());
    }

    #[test]
    fn nix_store_paths_reject_traversal_and_noncanonical_components() {
        let item = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-package-1.0";
        for valid in [
            item.to_string(),
            format!("{item}/bin/tool"),
            format!("{item}/share/.hidden/file+name_1"),
        ] {
            assert!(safe_nix_store_path(&valid), "expected valid path: {valid}");
        }
        for invalid in [
            format!("{item}/./bin/tool"),
            format!("{item}/../other/bin/tool"),
            format!("{item}//bin/tool"),
            format!("{item}/bin/"),
            "/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-package/bin/tool".to_string(),
            "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-/bin/tool".to_string(),
            "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-package/bin/tool".to_string(),
            "nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-package/bin/tool".to_string(),
            format!("{item}/bin/tool:other"),
        ] {
            assert!(
                !safe_nix_store_path(&invalid),
                "expected invalid path: {invalid}"
            );
        }
    }

    fn synthetic_pinned_source(path: &str, expected: &str) -> bool {
        (path.ends_with("-source-stdenv.sh") && expected == TRUSTED_STDENV_SOURCE_SHA256)
            || (path.ends_with("-default-builder.sh") && expected == TRUSTED_DEFAULT_BUILDER_SHA256)
            || (path.ends_with("-wrapper.c") && expected == TRUSTED_SECURITY_WRAPPER_SHA256)
            || (path.ends_with("-builder.pl") && expected == TRUSTED_LINK_FARM_BUILDER_SHA256)
            || (path == TRUSTED_SUBSTITUTE_BUILDER && expected == TRUSTED_SUBSTITUTE_BUILDER_SHA256)
    }

    fn synthetic_materializer(mut env: Value, extra_sources: Vec<&str>) -> Value {
        let object = env.as_object_mut().unwrap();
        object.entry("preferLocalBuild").or_insert(json!("1"));
        object.entry("buildInputs").or_insert(json!(""));
        object.entry("nativeBuildInputs").or_insert(json!(""));
        object
            .entry("stdenv")
            .or_insert(json!(TRUSTED_STDENV_NO_CC));
        let mut sources = vec![
            "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-source-stdenv.sh",
            "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-default-builder.sh",
        ];
        sources.extend(extra_sources);
        json!({
            "name": "synthetic-materializer",
            "builder": TRUSTED_STDENV_BASH_BUILDER,
            "args": [
                "-e",
                "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-source-stdenv.sh",
                "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-default-builder.sh"
            ],
            "env": env,
            "inputSrcs": sources,
            "inputDrvs": {
                (TRUSTED_STDENV_BASH_DRV): ["out"],
                (TRUSTED_STDENV_NO_CC_DRV): ["out"]
            }
        })
    }

    fn synthetic_derivation_v4(mut drv: Value) -> Value {
        let object = drv.as_object_mut().unwrap();
        let legacy_drvs = object.remove("inputDrvs").unwrap();
        let modern_drvs = legacy_drvs
            .as_object()
            .unwrap()
            .iter()
            .map(|(path, metadata)| {
                (
                    path.strip_prefix("/nix/store/").unwrap().to_string(),
                    json!({"dynamicOutputs": {}, "outputs": metadata}),
                )
            })
            .collect::<serde_json::Map<_, _>>();
        let modern_sources = object
            .remove("inputSrcs")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|path| json!(path.as_str().unwrap().strip_prefix("/nix/store/").unwrap()))
            .collect::<Vec<_>>();
        object.insert(
            "inputs".to_string(),
            json!({"drvs": modern_drvs, "srcs": modern_sources}),
        );
        object.insert("version".to_string(), json!(4));
        drv
    }

    #[test]
    fn source_policy_strictly_normalizes_legacy_and_v4_derivation_inputs() {
        let path = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-etc-hostname.drv";
        let legacy = synthetic_materializer(
            json!({"buildCommand": STOCK_WRITE_TEXT_COMMAND, "checkPhase": ""}),
            vec![],
        );
        let modern = synthetic_derivation_v4(legacy.clone());
        assert!(derivation_is_exempt_from_source_policy_with_verifier(
            path,
            Some(&modern),
            &synthetic_pinned_source,
        ));
        assert_eq!(
            derivation_input_sources(&modern).unwrap(),
            derivation_input_sources(&legacy).unwrap()
        );
        assert!(input_drv_output_reference(&modern, TRUSTED_STDENV_NO_CC).is_some());

        let mut unversioned_structured = legacy.clone();
        for metadata in unversioned_structured["inputDrvs"]
            .as_object_mut()
            .unwrap()
            .values_mut()
        {
            *metadata = json!({
                "dynamicOutputs": {},
                "outputs": metadata.clone(),
            });
        }
        assert!(derivation_is_exempt_from_source_policy_with_verifier(
            path,
            Some(&unversioned_structured),
            &synthetic_pinned_source,
        ));
        assert_eq!(
            derivation_input_sources(&unversioned_structured).unwrap(),
            derivation_input_sources(&legacy).unwrap()
        );
        assert!(
            input_drv_output_reference(&unversioned_structured, TRUSTED_STDENV_NO_CC).is_some()
        );

        let mut mixed_unversioned = unversioned_structured.clone();
        mixed_unversioned["inputDrvs"][TRUSTED_STDENV_NO_CC_DRV] = json!(["out"]);
        assert!(!derivation_is_exempt_from_source_policy_with_verifier(
            path,
            Some(&mixed_unversioned),
            &synthetic_pinned_source,
        ));

        let mut dynamic_unversioned = unversioned_structured.clone();
        dynamic_unversioned["inputDrvs"][TRUSTED_STDENV_NO_CC_DRV]["dynamicOutputs"] =
            json!({"dynamic": {}});
        assert!(!derivation_is_exempt_from_source_policy_with_verifier(
            path,
            Some(&dynamic_unversioned),
            &synthetic_pinned_source,
        ));

        let mut extra_unversioned = unversioned_structured;
        extra_unversioned["inputDrvs"][TRUSTED_STDENV_NO_CC_DRV]["unexpected"] = json!(true);
        assert!(!derivation_is_exempt_from_source_policy_with_verifier(
            path,
            Some(&extra_unversioned),
            &synthetic_pinned_source,
        ));

        let mut version_three = legacy.clone();
        version_three["version"] = json!(3);
        let object = version_three.as_object_mut().unwrap();
        let basename_drvs = object
            .remove("inputDrvs")
            .unwrap()
            .as_object()
            .unwrap()
            .iter()
            .map(|(path, outputs)| {
                (
                    path.strip_prefix("/nix/store/").unwrap().to_string(),
                    outputs.clone(),
                )
            })
            .collect::<serde_json::Map<_, _>>();
        let basename_sources = object
            .remove("inputSrcs")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|path| json!(path.as_str().unwrap().strip_prefix("/nix/store/").unwrap()))
            .collect::<Vec<_>>();
        object.insert("inputDrvs".to_string(), Value::Object(basename_drvs));
        object.insert("inputSrcs".to_string(), Value::Array(basename_sources));
        assert!(derivation_is_exempt_from_source_policy_with_verifier(
            path,
            Some(&version_three),
            &synthetic_pinned_source,
        ));

        let mut mixed = modern.clone();
        mixed["inputDrvs"] = json!({});
        assert!(!derivation_is_exempt_from_source_policy_with_verifier(
            path,
            Some(&mixed),
            &synthetic_pinned_source,
        ));

        let mut traversal = modern.clone();
        let inputs = traversal["inputs"]["drvs"].as_object_mut().unwrap();
        let metadata = inputs
            .remove(
                TRUSTED_STDENV_NO_CC_DRV
                    .strip_prefix("/nix/store/")
                    .unwrap(),
            )
            .unwrap();
        inputs.insert("../forged-stdenv-linux.drv".to_string(), metadata);
        assert!(!derivation_is_exempt_from_source_policy_with_verifier(
            path,
            Some(&traversal),
            &synthetic_pinned_source,
        ));

        let mut legacy_metadata_object = legacy;
        legacy_metadata_object["inputDrvs"][TRUSTED_STDENV_NO_CC_DRV] = json!({"outputs": ["out"]});
        assert!(!derivation_is_exempt_from_source_policy_with_verifier(
            path,
            Some(&legacy_metadata_object),
            &synthetic_pinned_source,
        ));

        let mut dynamic_outputs = modern.clone();
        let stdenv_key = TRUSTED_STDENV_NO_CC_DRV
            .strip_prefix("/nix/store/")
            .unwrap();
        dynamic_outputs["inputs"]["drvs"][stdenv_key]["dynamicOutputs"] = json!({"dynamic": {}});
        assert!(!derivation_is_exempt_from_source_policy_with_verifier(
            path,
            Some(&dynamic_outputs),
            &synthetic_pinned_source,
        ));

        let mut extra_metadata = modern.clone();
        extra_metadata["inputs"]["drvs"][stdenv_key]["unexpected"] = json!(true);
        assert!(!derivation_is_exempt_from_source_policy_with_verifier(
            path,
            Some(&extra_metadata),
            &synthetic_pinned_source,
        ));

        let mut wrong_version = modern.clone();
        wrong_version["version"] = json!(3);
        assert!(!derivation_is_exempt_from_source_policy_with_verifier(
            path,
            Some(&wrong_version),
            &synthetic_pinned_source,
        ));

        let mut unknown_shape = modern;
        unknown_shape["inputs"]["outputs"] = json!({});
        assert!(!derivation_is_exempt_from_source_policy_with_verifier(
            path,
            Some(&unknown_shape),
            &synthetic_pinned_source,
        ));
    }

    #[test]
    fn source_policy_fixed_point_allows_only_acyclic_reviewed_glue_dependencies() {
        let leaf_path = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-leaf.drv";
        let parent_path = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-parent.drv";
        let command = json!({"buildCommand": STOCK_WRITE_TEXT_COMMAND, "checkPhase": ""});
        let leaf = synthetic_materializer(command.clone(), vec![]);
        let mut parent = synthetic_materializer(command.clone(), vec![]);
        parent["inputDrvs"][leaf_path] = json!(["out"]);
        let would_build = vec![parent_path.to_string(), leaf_path.to_string()];
        let would_build_set = would_build.iter().cloned().collect::<HashSet<_>>();
        let derivations = BTreeMap::from([
            (parent_path.to_string(), parent.clone()),
            (leaf_path.to_string(), leaf.clone()),
        ]);
        assert_eq!(
            classify_trusted_local_derivations(
                &would_build,
                &derivations,
                &synthetic_pinned_source,
                &would_build_set,
            ),
            would_build_set,
            "a reviewed parent may depend on a separately reviewed local materializer"
        );

        let mut cycle_leaf = leaf;
        cycle_leaf["inputDrvs"][parent_path] = json!(["out"]);
        let cycle = BTreeMap::from([
            (parent_path.to_string(), parent.clone()),
            (leaf_path.to_string(), cycle_leaf),
        ]);
        assert!(
            classify_trusted_local_derivations(
                &would_build,
                &cycle,
                &synthetic_pinned_source,
                &would_build_set,
            )
            .is_empty(),
            "a dependency cycle must not bootstrap its own trust"
        );

        let malicious = synthetic_materializer(
            json!({"buildCommand": "gcc /nix/store/source.c -o $out"}),
            vec![],
        );
        let tainted = BTreeMap::from([
            (parent_path.to_string(), parent),
            (leaf_path.to_string(), malicious),
        ]);
        assert!(
            classify_trusted_local_derivations(
                &would_build,
                &tainted,
                &synthetic_pinned_source,
                &would_build_set,
            )
            .is_empty(),
            "unreviewed source work must taint every dependent glue derivation"
        );
    }

    #[test]
    fn source_policy_pins_both_desktop_generator_fingerprints() {
        for &(normalized, executable) in PINNED_DESKTOP_NIXOS_GENERATOR_FINGERPRINTS {
            assert!(reviewed_generator_fingerprints_match(
                normalized, executable
            ));
            assert!(!reviewed_generator_fingerprints_match(
                normalized,
                &"0".repeat(64),
            ));
            assert!(!reviewed_generator_fingerprints_match(
                &"0".repeat(64),
                executable,
            ));
        }
    }

    #[test]
    fn source_policy_requires_all_toplevel_script_paths_to_have_trusted_providers() {
        let trusted_path = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-switch-to-configuration";
        let trusted_drv = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-switch-to-configuration.drv";
        let script = format!("{trusted_path}/bin/switch-to-configuration");
        let mut drv = synthetic_materializer(json!({}), vec![]);
        drv["inputDrvs"][trusted_drv] = json!(["out"]);

        assert!(script_store_item_paths_are_trusted(
            &drv,
            &script,
            &HashSet::new(),
            &HashSet::new(),
        ));
        assert!(!script_store_item_paths_are_trusted(
            &drv,
            &script,
            &HashSet::from([trusted_drv.to_string()]),
            &HashSet::new(),
        ));
        assert!(script_store_item_paths_are_trusted(
            &drv,
            &script,
            &HashSet::from([trusted_drv.to_string()]),
            &HashSet::from([trusted_drv.to_string()]),
        ));

        let unreferenced =
            "/nix/store/cccccccccccccccccccccccccccccccc-unreviewed-payload/bin/payload";
        assert!(!script_store_item_paths_are_trusted(
            &drv,
            unreferenced,
            &HashSet::new(),
            &HashSet::new(),
        ));
        assert_eq!(
            script_store_item_paths(&format!("{script}; {script}"))
                .unwrap()
                .len(),
            1,
            "duplicate script references should resolve to one reviewed provider"
        );
        assert!(script_store_item_paths("/nix/store/not-a-store-hash/tool").is_none());
    }

    #[test]
    fn source_policy_pins_developers_udev_generator_provider() {
        let inputs = reviewed_generator_tool_inputs(
            "6c95edcf4bb40bf57b7dd83d10e2b27cc0b9357c340cf250ddd9687c826f9acf",
        );
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0].attribute, UDEV_GENERATOR_TOOL_INPUTS[0].attribute);
        assert_eq!(inputs[0].path, UDEV_GENERATOR_TOOL_INPUTS[0].path);
        assert_eq!(inputs[0].drv_path, UDEV_GENERATOR_TOOL_INPUTS[0].drv_path);
        assert_eq!(inputs[0].output, UDEV_GENERATOR_TOOL_INPUTS[0].output);
    }

    fn synthetic_coredump_substitution() -> Value {
        let source_stdenv = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-source-stdenv.sh";
        json!({
            "name": "50-coredump.conf",
            "builder": TRUSTED_STDENV_BASH_BUILDER,
            "args": ["-e", source_stdenv, TRUSTED_SUBSTITUTE_BUILDER],
            "env": {
                "preferLocalBuild": "1",
                "buildInputs": "",
                "nativeBuildInputs": "",
                "stdenv": TRUSTED_STDENV_NO_CC,
                "src": COREDUMP_SOURCE.path,
                "substitutions": format!(
                    "--replace-fail {} {}",
                    COREDUMP_SOURCE
                        .path
                        .strip_suffix("/example/sysctl.d/50-coredump.conf")
                        .unwrap(),
                    COREDUMP_SUBSTITUTION_TARGET.path,
                ),
            },
            "inputSrcs": [source_stdenv, TRUSTED_SUBSTITUTE_BUILDER],
            "inputDrvs": {
                (TRUSTED_STDENV_BASH_DRV): ["out"],
                (TRUSTED_STDENV_NO_CC_DRV): ["out"],
                (COREDUMP_SOURCE.drv_path): [COREDUMP_SOURCE.output],
                (COREDUMP_SUBSTITUTION_TARGET.drv_path): [COREDUMP_SUBSTITUTION_TARGET.output],
            },
        })
    }

    #[test]
    fn source_policy_pins_low_level_nixos_substitution_recipe() {
        let path = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-50-coredump.conf.drv";
        let valid = synthetic_coredump_substitution();
        assert!(derivation_is_exempt_from_source_policy_with_verifier(
            path,
            Some(&valid),
            &synthetic_pinned_source,
        ));

        let mut injected = valid.clone();
        injected["env"]["substitutions"] = json!(format!(
            "{}; gcc /nix/store/source.c -o $out",
            injected["env"]["substitutions"].as_str().unwrap()
        ));
        assert!(!derivation_is_exempt_from_source_policy_with_verifier(
            path,
            Some(&injected),
            &synthetic_pinned_source,
        ));

        let mut forged_source_provider = valid;
        forged_source_provider["inputDrvs"]
            .as_object_mut()
            .unwrap()
            .remove(COREDUMP_SOURCE.drv_path);
        forged_source_provider["inputDrvs"]["/nix/store/ffffffffffffffffffffffffffffffff-systemd-260.2.drv"] =
            json!(["out"]);
        assert!(!derivation_is_exempt_from_source_policy_with_verifier(
            path,
            Some(&forged_source_provider),
            &synthetic_pinned_source,
        ));
    }

    fn synthetic_link_farm(post_build: &str) -> Value {
        let builder = TRUSTED_LINK_FARM_BUILDER.path;
        let chosen = "/nix/store/dddddddddddddddddddddddddddddddd-payload";
        let mut drv = synthetic_materializer(
            json!({
                "buildCommand": format!(
                    "{} -w {builder}\neval \"$postBuild\"\n",
                    TRUSTED_LINK_FARM_PERL.path
                ),
                "postBuild": post_build,
                "chosenOutputs": [{"paths": [chosen]}],
            }),
            vec![builder],
        );
        drv["inputDrvs"][TRUSTED_LINK_FARM_PERL.drv_path] = json!([TRUSTED_LINK_FARM_PERL.output]);
        drv["inputDrvs"][TRUSTED_LINK_FARM_BUILDER.drv_path] =
            json!([TRUSTED_LINK_FARM_BUILDER.output]);
        drv["inputDrvs"]["/nix/store/ffffffffffffffffffffffffffffffff-payload.drv"] =
            json!(["out"]);
        drv
    }

    fn test_dbus_generator_command() -> String {
        r#"mkdir -p $out

xsltproc --nonet \
  --stringparam serviceDirectories "$serviceDirectories" \
  --stringparam suidHelper "$suidHelper" \
  --stringparam apparmor "$apparmor" \
  /nix/store/n536iaha2b8kzm7dcjiy8b4h8aijbbw6-make-system-conf.xsl /nix/store/165rncxlyi4f9pjf1zk3hmj3mh2v881w-dbus-1.16.2/share/dbus-1/system.conf \
  > $out/system.conf
xsltproc --nonet \
  --stringparam serviceDirectories "$serviceDirectories" \
  --stringparam apparmor "$apparmor" \
  /nix/store/iqfsj1zscjdxrm6dxlsr6yz3560wwlh2-make-session-conf.xsl /nix/store/165rncxlyi4f9pjf1zk3hmj3mh2v881w-dbus-1.16.2/share/dbus-1/session.conf \
  > $out/session.conf

# check if files are empty or only contain space characters
grep -q '[^[:space:]]' "$out/system.conf" || (echo "\"$out/system.conf\" was generated incorrectly and is empty, try building again." && exit 1)
grep -q '[^[:space:]]' "$out/session.conf" || (echo "\"$out/session.conf\" was generated incorrectly and is empty, try building again." && exit 1)
"#
        .to_string()
    }

    fn synthetic_dbus_generator() -> Value {
        let mut drv = synthetic_materializer(
            json!({
                "buildCommand": test_dbus_generator_command(),
                "buildInputs": DBUS_GENERATOR_TOOL_INPUTS[0].path,
                "nativeBuildInputs": format!(
                    "{} {}",
                    DBUS_GENERATOR_TOOL_INPUTS[1].path,
                    DBUS_GENERATOR_TOOL_INPUTS[2].path
                )
            }),
            vec![],
        );
        let inputs = drv["inputDrvs"].as_object_mut().unwrap();
        for descriptor in DBUS_GENERATOR_TOOL_INPUTS {
            inputs.insert(descriptor.drv_path.to_string(), json!([descriptor.output]));
        }
        drv
    }

    #[test]
    fn source_policy_rejects_local_tool_masquerading_inside_reviewed_generator() {
        let path = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-dbus-1.drv";
        let valid = synthetic_dbus_generator();
        let command = test_dbus_generator_command();
        assert_eq!(
            normalized_script_sha256(&command),
            "64c2c9a5153a9da42e566c21d525bab58e72cbc62064ace52e850ce6de5919de"
        );
        assert!(
            derivation_is_exempt_from_source_policy_with_verifier_and_would_build(
                path,
                Some(&valid),
                &synthetic_pinned_source,
                &HashSet::new(),
            )
        );

        // A local writeTextFile-style derivation can advertise a libxslt-like
        // name and `bin` output. Even with the exact reviewed D-Bus command and
        // output path, its exact provider differs and is in the dry-run set.
        let malicious_drv = "/nix/store/dddddddddddddddddddddddddddddddd-libxslt-1.1.45.drv";
        let mut forged = valid.clone();
        let inputs = forged["inputDrvs"].as_object_mut().unwrap();
        inputs.remove(DBUS_GENERATOR_TOOL_INPUTS[1].drv_path);
        inputs.insert(malicious_drv.to_string(), json!(["bin"]));
        let would_build = HashSet::from([malicious_drv.to_string(), path.to_string()]);
        assert!(
            !derivation_is_exempt_from_source_policy_with_verifier_and_would_build(
                path,
                Some(&forged),
                &synthetic_pinned_source,
                &would_build,
            )
        );

        let mut extra_tool = valid;
        extra_tool["env"]["nativeBuildInputs"] = json!(format!(
            "{} /nix/store/ffffffffffffffffffffffffffffffff-extra-hook",
            extra_tool["env"]["nativeBuildInputs"].as_str().unwrap()
        ));
        extra_tool["inputDrvs"]["/nix/store/ffffffffffffffffffffffffffffffff-extra-hook.drv"] =
            json!(["out"]);
        assert!(!derivation_is_exempt_from_source_policy_with_verifier(
            path,
            Some(&extra_tool),
            &synthetic_pinned_source,
        ));
    }

    #[test]
    fn source_policy_rejects_malformed_structured_attribute_shapes() {
        let path = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-etc-hostname.drv";
        let valid = synthetic_materializer(
            json!({"buildCommand": STOCK_WRITE_TEXT_COMMAND, "checkPhase": ""}),
            vec![],
        );
        assert!(derivation_is_exempt_from_source_policy_with_verifier(
            path,
            Some(&valid),
            &synthetic_pinned_source,
        ));

        let mut malformed = Vec::new();
        for encoded in [json!(7), json!("{"), json!("[]"), json!("null")] {
            let mut drv = valid.clone();
            drv["env"]["__json"] = encoded;
            malformed.push(drv);
        }
        for structured in [json!(null), json!("{}"), json!([]), json!(7)] {
            let mut drv = valid.clone();
            drv["structuredAttrs"] = structured;
            malformed.push(drv);
        }
        let mut non_object_env = valid.clone();
        non_object_env["env"] = json!("not-an-object");
        malformed.push(non_object_env);

        for drv in malformed {
            assert!(!derivation_is_exempt_from_source_policy_with_verifier(
                path,
                Some(&drv),
                &synthetic_pinned_source,
            ));
        }
    }

    #[test]
    fn source_policy_exempts_only_constrained_nixos_glue_and_plain_fetches() {
        let glue_path = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-etc-hostname.drv";
        let write_text = synthetic_materializer(
            json!({
                "buildCommand": STOCK_WRITE_TEXT_COMMAND,
                "text": "pulse-host\n",
                "checkPhase": ""
            }),
            vec![],
        );
        let structured = synthetic_materializer(
            json!({
                "__json": serde_json::to_string(&json!({
                    "preferLocalBuild": true,
                    "buildCommand": "mkdir -p $out; ln -s /nix/store/system $out/sw",
                    "buildInputs": [],
                    "nativeBuildInputs": []
                })).unwrap()
            }),
            vec![],
        );
        let fixed_output = json!({
            "name": "wallpaper.jpg",
            "builder": "builtin:fetchurl",
            "env": {"__json": serde_json::to_string(&json!({
                "urls": ["https://example.invalid/wallpaper.jpg"],
                "postFetch": ""
            })).unwrap()},
            "inputSrcs": [],
            "inputDrvs": {},
            "outputs": {"out": {"hash": "abcd", "hashAlgo": "sha256", "path": "/nix/store/out"}}
        });

        assert!(derivation_is_exempt_from_source_policy_with_verifier(
            glue_path,
            Some(&write_text),
            &synthetic_pinned_source,
        ));
        assert!(
            !derivation_is_exempt_from_source_policy_with_verifier_and_would_build(
                glue_path,
                Some(&write_text),
                &synthetic_pinned_source,
                &HashSet::from([TRUSTED_STDENV_BASH_DRV.to_string()]),
            ),
            "a locally built shell provider must never execute an exempt materializer"
        );
        // Arbitrary shell that merely resembles closure assembly is not a
        // materializer exemption; complex stock generators use reviewed
        // fingerprints instead of a permissive shell parser.
        assert!(!derivation_is_exempt_from_source_policy_with_verifier(
            "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-nixos-system-pulse-26.05.drv",
            Some(&structured),
            &synthetic_pinned_source,
        ));
        assert!(derivation_is_exempt_from_source_policy(
            "/nix/store/cccccccccccccccccccccccccccccccc-wallpaper.jpg.drv",
            Some(&fixed_output)
        ));
        assert!(!derivation_is_exempt_from_source_policy(glue_path, None));
    }

    #[test]
    fn source_policy_rejects_stdenv_setup_injection_and_unpinned_stdenv() {
        let path = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-etc-hostname.drv";
        let valid = synthetic_materializer(
            json!({"buildCommand": STOCK_WRITE_TEXT_COMMAND, "checkPhase": ""}),
            vec![],
        );
        assert!(derivation_is_exempt_from_source_policy_with_verifier(
            path,
            Some(&valid),
            &synthetic_pinned_source,
        ));

        for (key, value) in [
            (
                "NIX_ATTRS_SH_FILE",
                json!("/nix/store/ffffffffffffffffffffffffffffffff-malicious-attrs.sh"),
            ),
            (
                "NIX_ATTRS_JSON_FILE",
                json!("/nix/store/ffffffffffffffffffffffffffffffff-malicious-attrs.json"),
            ),
            ("preHook", json!("/nix/store/attacker/bin/payload")),
            ("preHooks", json!(["/nix/store/attacker/bin/payload"])),
            ("addInputsHook", json!("gcc source.c -o $out/payload")),
            ("buildCommandPath", json!("/nix/store/attacker/payload.sh")),
            ("patchPhase", json!("gcc source.c -o $out/payload")),
            ("fixupPhase", json!("gcc source.c -o $out/payload")),
            ("setupHook", json!("/nix/store/attacker/payload.sh")),
        ] {
            let mut forged = valid.clone();
            forged["env"][key] = value;
            assert!(
                !derivation_is_exempt_from_source_policy_with_verifier(
                    path,
                    Some(&forged),
                    &synthetic_pinned_source,
                ),
                "expected setup injection through {key} to be rejected"
            );
        }

        let mut tracing_injection = valid.clone();
        tracing_injection["env"]["NIX_DEBUG"] = json!("6");
        tracing_injection["env"]["PS4"] = json!("$(/nix/store/attacker/bin/payload)");
        assert!(!derivation_is_exempt_from_source_policy_with_verifier(
            path,
            Some(&tracing_injection),
            &synthetic_pinned_source,
        ));

        let forged_stdenv = "/nix/store/ffffffffffffffffffffffffffffffff-stdenv-linux";
        let forged_stdenv_drv = "/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-stdenv-linux.drv";
        let mut forged = valid.clone();
        forged["env"]["stdenv"] = json!(forged_stdenv);
        forged["inputDrvs"][forged_stdenv_drv] = json!(["out"]);
        assert!(!derivation_is_exempt_from_source_policy_with_verifier(
            path,
            Some(&forged),
            &synthetic_pinned_source,
        ));

        let mut forged_provider = valid.clone();
        forged_provider["inputDrvs"]
            .as_object_mut()
            .unwrap()
            .remove(TRUSTED_STDENV_NO_CC_DRV);
        forged_provider["inputDrvs"]["/nix/store/ffffffffffffffffffffffffffffffff-stdenv-linux.drv"] =
            json!(["out"]);
        assert!(!derivation_is_exempt_from_source_policy_with_verifier(
            path,
            Some(&forged_provider),
            &synthetic_pinned_source,
        ));

        assert!(
            !derivation_is_exempt_from_source_policy_with_verifier_and_would_build(
                path,
                Some(&valid),
                &synthetic_pinned_source,
                &HashSet::from([TRUSTED_STDENV_NO_CC_DRV.to_string()]),
            ),
            "the exact stdenv is unsafe when its provider is in the full local-build set"
        );
    }

    #[test]
    fn source_policy_pins_link_farm_interpreters_and_dynamic_inputs() {
        let path = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-link-farm.drv";
        let valid = synthetic_link_farm("");
        assert!(derivation_is_exempt_from_source_policy_with_verifier(
            path,
            Some(&valid),
            &synthetic_pinned_source,
        ));
        assert!(
            !derivation_is_exempt_from_source_policy_with_verifier_and_would_build(
                path,
                Some(&valid),
                &synthetic_pinned_source,
                &HashSet::from([TRUSTED_LINK_FARM_PERL.drv_path.to_string()]),
            ),
            "a locally built Perl must not execute the reviewed link-farm builder"
        );

        let mut empty = valid.clone();
        empty["env"]["chosenOutputs"] = json!([]);
        assert!(link_farm_dynamic_paths_are_trusted(
            &empty,
            &derivation_attributes(&empty),
            &HashSet::new(),
            &HashSet::new(),
        ));

        let mut forged_perl = valid.clone();
        forged_perl["inputDrvs"]
            .as_object_mut()
            .unwrap()
            .remove(TRUSTED_LINK_FARM_PERL.drv_path);
        forged_perl["inputDrvs"]["/nix/store/ffffffffffffffffffffffffffffffff-perl-5.42.0.drv"] =
            json!(["out"]);
        assert!(!derivation_is_exempt_from_source_policy_with_verifier(
            path,
            Some(&forged_perl),
            &synthetic_pinned_source,
        ));

        let local_tool_path = "/nix/store/dddddddddddddddddddddddddddddddd-local-glib";
        let local_tool_drv = "/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-local-glib.drv";
        let mut composed = valid.clone();
        composed["env"]["chosenOutputs"] = json!([{"paths": [local_tool_path]}]);
        composed["inputDrvs"][local_tool_drv] = json!(["out"]);
        assert!(
            !link_farm_dynamic_paths_are_trusted(
                &composed,
                &derivation_attributes(&composed),
                &HashSet::from([local_tool_drv.to_string()]),
                &HashSet::new(),
            ),
            "a local writeText-like output could otherwise supply $out/bin/glib-compile-schemas"
        );

        let same_name_path = "/nix/store/cccccccccccccccccccccccccccccccc-same";
        let first_provider = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-same.drv";
        let second_provider = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-same.drv";
        let mut ambiguous = synthetic_link_farm("");
        ambiguous["env"]["chosenOutputs"] = json!([{"paths": [same_name_path]}]);
        let inputs = ambiguous["inputDrvs"].as_object_mut().unwrap();
        inputs.remove("/nix/store/ffffffffffffffffffffffffffffffff-payload.drv");
        inputs.insert(first_provider.to_string(), json!(["out"]));
        inputs.insert(second_provider.to_string(), json!(["out"]));
        let ambiguous_would_build =
            HashSet::from([first_provider.to_string(), second_provider.to_string()]);
        assert!(!link_farm_dynamic_paths_are_trusted(
            &ambiguous,
            &derivation_attributes(&ambiguous),
            &ambiguous_would_build,
            &HashSet::from([first_provider.to_string()]),
        ));
        assert!(link_farm_dynamic_paths_are_trusted(
            &ambiguous,
            &derivation_attributes(&ambiguous),
            &ambiguous_would_build,
            &ambiguous_would_build,
        ));
    }

    #[test]
    fn source_policy_pins_write_text_check_executable_and_provider() {
        let path = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-desktop-file.drv";
        let check = format!("{} \"$target\"", DESKTOP_FILE_VALIDATE.path);
        let mut valid = synthetic_materializer(
            json!({"buildCommand": STOCK_WRITE_TEXT_COMMAND, "checkPhase": check}),
            vec![],
        );
        valid["inputDrvs"][DESKTOP_FILE_VALIDATE.drv_path] = json!([DESKTOP_FILE_VALIDATE.output]);
        assert!(derivation_is_exempt_from_source_policy_with_verifier(
            path,
            Some(&valid),
            &synthetic_pinned_source,
        ));

        let mut forged_provider = valid.clone();
        forged_provider["inputDrvs"]
            .as_object_mut()
            .unwrap()
            .remove(DESKTOP_FILE_VALIDATE.drv_path);
        forged_provider["inputDrvs"]["/nix/store/ffffffffffffffffffffffffffffffff-desktop-file-utils-0.28.drv"] =
            json!(["out"]);
        assert!(!derivation_is_exempt_from_source_policy_with_verifier(
            path,
            Some(&forged_provider),
            &synthetic_pinned_source,
        ));

        let mut injected = valid;
        injected["env"]["checkPhase"] = json!(format!(
            "{}; gcc /nix/store/source.c -o $out\n",
            injected["env"]["checkPhase"].as_str().unwrap().trim_end()
        ));
        assert!(!derivation_is_exempt_from_source_policy_with_verifier(
            path,
            Some(&injected),
            &synthetic_pinned_source,
        ));
    }

    #[test]
    fn source_policy_pins_sourced_generator_setup_hook_provider() {
        let mut drv = synthetic_materializer(json!({}), vec![]);
        drv["inputDrvs"][NIXOS_SYSTEM_SETUP_HOOK.drv_path] =
            json!([NIXOS_SYSTEM_SETUP_HOOK.output]);
        assert!(reviewed_store_output_is_nonlocal(
            &drv,
            NIXOS_SYSTEM_SETUP_HOOK.path,
            NIXOS_SYSTEM_SETUP_HOOK,
            &HashSet::new(),
        ));
        assert!(!reviewed_store_output_is_nonlocal(
            &drv,
            NIXOS_SYSTEM_SETUP_HOOK.path,
            NIXOS_SYSTEM_SETUP_HOOK,
            &HashSet::from([NIXOS_SYSTEM_SETUP_HOOK.drv_path.to_string()]),
        ));

        let forged_hook = ReviewedStoreOutput {
            path: "/nix/store/ffffffffffffffffffffffffffffffff-make-shell-wrapper-hook/nix-support/setup-hook",
            drv_path: NIXOS_SYSTEM_SETUP_HOOK.drv_path,
            output: "out",
        };
        assert!(!reviewed_store_output_is_nonlocal(
            &drv,
            forged_hook.path,
            NIXOS_SYSTEM_SETUP_HOOK,
            &HashSet::new(),
        ));
    }

    #[test]
    fn source_policy_rejects_forged_glue_attributes_and_compile_commands() {
        let path = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-etc-malicious.drv";
        let prefer_local_only = synthetic_materializer(
            json!({"buildCommand": "$hidden /nix/store/source -o $out"}),
            vec![],
        );
        let forged_run_command = synthetic_materializer(
            json!({"buildCommand": "python -m compileall /nix/store/source -d $out"}),
            vec![],
        );
        let source_derivation = synthetic_materializer(
            json!({
                "src": "/nix/store/fixed-output-source",
                "buildCommand": "mkdir -p $out"
            }),
            vec![],
        );
        let forged_output_hash = json!({
            "name": "payload",
            "env": {
                "outputHash": "sha256-...",
                "urls": ["https://example.invalid/source.tar.gz"]
            }
        });
        let post_fetch_build = json!({
            "name": "payload",
            "builder": "/nix/store/bash/bin/bash",
            "env": {"__json": serde_json::to_string(&json!({
                "urls": ["https://example.invalid/source.tar.gz"],
                "postFetch": "gcc source.c -o $out"
            })).unwrap()},
            "inputSrcs": ["/nix/store/fetchurl-builder.sh"],
            "outputs": {"out": {"hash": "abcd", "path": "/nix/store/out"}}
        });

        for drv in [
            prefer_local_only,
            forged_run_command,
            source_derivation,
            forged_output_hash,
            post_fetch_build,
        ] {
            assert!(!derivation_is_exempt_from_source_policy_with_verifier(
                path,
                Some(&drv),
                &synthetic_pinned_source,
            ));
        }

        for command in [
            "perl /nix/store/source.pl",
            "ld -o $out/payload /nix/store/input.o",
            "nasm /nix/store/input.asm -o $out/payload",
            "zig build --prefix $out",
            "builder=/nix/store/custom/bin/tool; $builder /nix/store/source",
            "case x in x) gcc source.c -o $out/payload;; esac",
            "find source -exec gcc '{}' -o $out/payload ';'",
            "trap 'gcc source.c -o $out/payload' EXIT",
            "runHook preBuild\nmkdir -p $out",
            "sed -n 'e gcc source.c -o $out/payload' input",
            "printf '%s' 'safe | text'; gcc source.c -o $out/payload",
        ] {
            let drv = synthetic_materializer(json!({"buildCommand": command}), vec![]);
            assert!(!derivation_is_exempt_from_source_policy_with_verifier(
                path,
                Some(&drv),
                &synthetic_pinned_source,
            ));
        }

        for injection in [
            ("BASH_ENV", "/nix/store/attacker-hook"),
            ("BASH_FUNC_build%%", "() { gcc source.c -o $out/payload; }"),
            ("LD_PRELOAD", "/nix/store/attacker.so"),
            ("PERL5OPT", "-Mmalicious"),
            ("CC", "/nix/store/attacker/bin/cc"),
            ("CXX", "/nix/store/attacker/bin/c++"),
            ("AR", "/nix/store/attacker/bin/ar"),
            ("LD", "/nix/store/attacker/bin/ld"),
            ("NM", "/nix/store/attacker/bin/nm"),
            ("STRIP", "/nix/store/attacker/bin/strip"),
            ("GCC_EXEC_PREFIX", "/nix/store/attacker/lib/gcc/"),
            ("COMPILER_PATH", "/nix/store/attacker/bin"),
            ("LIBRARY_PATH", "/nix/store/attacker/lib"),
            ("CPATH", "/nix/store/attacker/include"),
            ("C_INCLUDE_PATH", "/nix/store/attacker/include"),
            ("CPLUS_INCLUDE_PATH", "/nix/store/attacker/include"),
            ("NIX_CFLAGS_COMPILE", "-fplugin=/nix/store/attacker.so"),
            ("NIX_LDFLAGS", "-L/nix/store/attacker/lib"),
            ("RUSTC_WRAPPER", "/nix/store/attacker/bin/wrapper"),
            ("CCACHE_PREFIX", "/nix/store/attacker/bin/wrapper"),
            ("SCCACHE_DIR", "/nix/store/attacker/cache"),
            ("CONFIG_SHELL", "/nix/store/attacker/bin/sh"),
            ("SHELL", "/nix/store/attacker/bin/sh"),
            ("NIX_BUILD_SHELL", "/nix/store/attacker/bin/sh"),
        ] {
            let mut drv = synthetic_materializer(
                json!({"buildCommand": STOCK_WRITE_TEXT_COMMAND, "checkPhase": ""}),
                vec![],
            );
            drv["env"][injection.0] = json!(injection.1);
            assert!(!derivation_is_exempt_from_source_policy_with_verifier(
                path,
                Some(&drv),
                &synthetic_pinned_source,
            ));
        }

        for key in ["buildCommand", "PATH", "BASH_ENV"] {
            let mut direct = serde_json::Map::new();
            direct.insert("preferLocalBuild".to_string(), json!("1"));
            direct.insert("buildInputs".to_string(), json!(""));
            direct.insert("nativeBuildInputs".to_string(), json!(""));
            direct.insert("buildCommand".to_string(), json!(STOCK_WRITE_TEXT_COMMAND));
            direct.insert("checkPhase".to_string(), json!(""));
            direct.insert(key.to_string(), json!("gcc source.c -o $out/payload"));
            let structured_value = if key == "buildCommand" {
                json!(STOCK_WRITE_TEXT_COMMAND)
            } else {
                json!("")
            };
            direct.insert(
                "__json".to_string(),
                json!(serde_json::to_string(&json!({ (key): structured_value })).unwrap()),
            );
            let drv = synthetic_materializer(Value::Object(direct), vec![]);
            assert!(!derivation_is_exempt_from_source_policy_with_verifier(
                path,
                Some(&drv),
                &synthetic_pinned_source,
            ));
        }
    }

    #[test]
    fn source_policy_accepts_only_the_native_nixos_security_wrapper_shape() {
        let path = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-wrapper-Hyprland-x86_64-unknown-linux-musl.drv";
        let mut wrapper = synthetic_materializer(
            json!({
                    "preferLocalBuild": "",
                    "name": "security-wrapper-Hyprland-x86_64-unknown-linux-musl",
                    "dontUnpack": "1",
                    "stdenv": TRUSTED_STDENV_STATIC,
                    "NIX_CFLAGS_LINK": " -static",
                    "propagatedBuildInputs": SECURITY_WRAPPER_TOOL_INPUTS[0].path,
                    "CFLAGS": "-DSOURCE_PROG=\"/nix/store/ffffffffffffffffffffffffffffffff-hyprland/bin/Hyprland\" -Wall -O2",
                    "installPhase": format!("mkdir -p $out/bin\n$CC $CFLAGS /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-wrapper.c -I{} -o $out/bin/security-wrapper\n", TRUSTED_SECURITY_WRAPPER_INCLUDE_PATH)
            }),
            vec!["/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-wrapper.c"],
        );
        wrapper["name"] = json!("security-wrapper-Hyprland-x86_64-unknown-linux-musl");
        wrapper["inputDrvs"] = json!({
            "/nix/store/dddddddddddddddddddddddddddddddd-hyprland.drv": ["out"],
            (TRUSTED_SECURITY_WRAPPER_INCLUDE_DRV): ["out"],
            (TRUSTED_STDENV_BASH_DRV): ["out"],
            (TRUSTED_STDENV_STATIC_DRV): ["out"],
            (SECURITY_WRAPPER_TOOL_INPUTS[0].drv_path): [SECURITY_WRAPPER_TOOL_INPUTS[0].output]
        });
        assert!(derivation_is_exempt_from_source_policy_with_verifier(
            path,
            Some(&wrapper),
            &synthetic_pinned_source,
        ));

        let mut forged = wrapper.clone();
        forged["env"]["installPhase"] =
            json!("mkdir -p $out/bin\n$CC payload.c -o $out/bin/payload\n");
        assert!(!derivation_is_exempt_from_source_policy_with_verifier(
            path,
            Some(&forged),
            &synthetic_pinned_source,
        ));

        for (key, value) in [
            (
                "installPhase",
                "mkdir -p $out/bin\n$CC $CFLAGS /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-wrapper.c -I/nix/store/ffffffffffffffffffffffffffffffff-headers;gcc source.c -o $out/payload -o $out/bin/security-wrapper\n",
            ),
            (
                "CFLAGS",
                "-DSOURCE_PROG=\"/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-hyprland/bin/Hyprland\" -fplugin=/nix/store/evil.so -Wall -O2",
            ),
            ("CC", "/nix/store/evil/bin/gcc"),
        ] {
            let mut forged = wrapper.clone();
            forged["env"][key] = json!(value);
            assert!(!derivation_is_exempt_from_source_policy_with_verifier(
                path,
                Some(&forged),
                &synthetic_pinned_source,
            ));
        }
    }

    #[test]
    fn source_policy_allows_only_the_stock_nixos_substitution_phase() {
        let path = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-stage-2-init.sh.drv";
        let stock_phase = "runHook preBuild\n\ntarget=$out\nif test -n \"$dir\"; then\n    target=$out/$dir/$name\n    mkdir -p $out/$dir\nfi\n\nsubstitute \"$src\" \"$target\" --replace-fail @shell@ /nix/store/bash/bin/bash\n\nif test -n \"$isExecutable\"; then\n    chmod +x $target\nfi\n\nrunHook postBuild\n";
        let glue = synthetic_materializer(
            json!({
                    "preferLocalBuild": "1",
                    "dontUnpack": "1",
                    "src": "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-stage-2-init.sh",
                    "buildPhase": stock_phase
            }),
            vec!["/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-stage-2-init.sh"],
        );
        assert!(derivation_is_exempt_from_source_policy_with_verifier(
            path,
            Some(&glue),
            &synthetic_pinned_source,
        ));

        let mut forged = glue.clone();
        forged["env"]["buildPhase"] = json!(stock_phase.replace(
            "runHook postBuild",
            "gcc /nix/store/source/main.c -o $out/payload\nrunHook postBuild"
        ));
        assert!(!derivation_is_exempt_from_source_policy_with_verifier(
            path,
            Some(&forged),
            &synthetic_pinned_source,
        ));

        for hook in ["preBuild", "postBuild", "preInstall", "postFixup"] {
            let mut forged = glue.clone();
            forged["env"][hook] = json!("gcc source.c -o $out/payload");
            assert!(!derivation_is_exempt_from_source_policy_with_verifier(
                path,
                Some(&forged),
                &synthetic_pinned_source,
            ));
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn bounded_command_retries_a_transient_busy_executable() {
        use std::os::unix::fs::PermissionsExt;

        let mut nonce = [0_u8; 8];
        OsRng.fill_bytes(&mut nonce);
        let root = std::env::temp_dir().join(format!(
            "cybex-pulse-bounded-spawn-test-{}-{}",
            std::process::id(),
            hex::encode(nonce)
        ));
        std::fs::create_dir_all(&root).unwrap();
        let executable = root.join("busy-command");
        std::fs::write(&executable, "#!/bin/sh\nprintf ready\n").unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let writer = std::fs::OpenOptions::new()
            .write(true)
            .open(&executable)
            .unwrap();
        let release_writer = tokio::spawn(async move {
            sleep(Duration::from_millis(20)).await;
            drop(writer);
        });

        let output = run_bounded_command(
            Command::new(&executable),
            Duration::from_secs(1),
            1024,
            1024,
            "transient busy executable test",
        )
        .await
        .unwrap();
        release_writer.await.unwrap();

        assert!(output.status.success());
        assert_eq!(output.stdout, b"ready");
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn source_policy_uses_a_fresh_store_even_when_daemon_output_is_already_present() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "cybex-pulse-source-policy-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let fake_nix = root.join("fake-nix");
        std::fs::write(
            &fake_nix,
            r#"#!/bin/sh
set -eu
[ "${LC_ALL:-}" = C ]
case "$*" in
  *" derivation show "*)
    printf '%s\n' '{"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-local-only-source.drv":{"name":"local-only-source","builder":"/nix/store/bash/bin/bash","env":{"preferLocalBuild":"1","buildCommand":"python -m compileall source -d $out"},"inputSrcs":[],"inputDrvs":{}}}'
    ;;
  *" build "*)
    case " $* " in
      *" --option allow-import-from-derivation false "*) ;;
      *) exit 91 ;;
    esac
    # Some Nix wrappers emit the dry-run listing on stdout. It must be
    # verified just as strictly as the usual stderr listing.
    printf '%s\n' 'this derivation will be built:'
    printf '%s\n' '  /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-local-only-source.drv'
    ;;
  *)
    # A normal daemon-store dry run would report nothing because the output is
    # already present. The test only exposes it when an isolated store is used.
    ;;
esac
"#,
        )
        .unwrap();
        std::fs::set_permissions(&fake_nix, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut config = AppConfig::default();
        config.build.work_dir = root.join("work");
        let command = NixBuildCommand {
            program: fake_nix.display().to_string(),
            args: Vec::new(),
            out_link: root.join("result"),
            installable: ".#test".to_string(),
        };

        let offenders = preflight_source_build_check(&config, &command)
            .await
            .unwrap();

        assert_eq!(offenders, vec!["local-only-source"]);
        let leftovers = std::fs::read_dir(&config.build.work_dir)
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("source-policy-store-")
            })
            .count();
        assert_eq!(leftovers, 0);
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn source_policy_disables_ifd_before_dry_run_evaluation() {
        use std::os::unix::fs::PermissionsExt;

        let nix_program = "/usr/bin/nix";
        if !Path::new(nix_program).is_file() {
            return;
        }
        let root = std::env::temp_dir().join(format!(
            "cybex-pulse-source-policy-ifd-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let flake_dir = root.join("flake");
        std::fs::create_dir_all(&flake_dir).unwrap();
        let marker = root.join("hidden-ifd-builder-ran");
        let builder = flake_dir.join("ifd-builder.sh");
        std::fs::write(
            &builder,
            format!(
                "#!/bin/sh\nset -eu\nprintf ran > '{}'\nprintf forced > \"$out\"\n",
                marker.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&builder, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(
            flake_dir.join("flake.nix"),
            r#"{
  nixConfig.allow-import-from-derivation = true;
  outputs = { self }:
    let
      forced = derivation {
        name = "cybex-ifd-regression-leaf";
        system = "x86_64-linux";
        builder = ./ifd-builder.sh;
        args = [];
      };
      payload = builtins.readFile forced;
    in {
      packages.x86_64-linux.default = derivation {
        name = "cybex-ifd-regression-result-${payload}";
        system = "x86_64-linux";
        builder = ./ifd-builder.sh;
        args = [];
      };
    };
}
"#,
        )
        .unwrap();
        let nix_wrapper = root.join("nix-with-features");
        std::fs::write(
            &nix_wrapper,
            format!(
                "#!/bin/sh\nexec {nix_program} --extra-experimental-features 'nix-command flakes' --option sandbox false --accept-flake-config \"$@\"\n"
            ),
        )
        .unwrap();
        std::fs::set_permissions(&nix_wrapper, std::fs::Permissions::from_mode(0o700)).unwrap();

        let mut config = AppConfig::default();
        config.build.work_dir = root.join("work");
        let command = NixBuildCommand {
            program: nix_wrapper.display().to_string(),
            args: vec!["--system".to_string(), "x86_64-linux".to_string()],
            out_link: root.join("result"),
            installable: format!("path:{}#default", flake_dir.display()),
        };
        let error = preflight_source_build_check(&config, &command)
            .await
            .unwrap_err();
        let error = format!("{error:#}");

        assert!(
            error.contains("allow-import-from-derivation") && error.contains("disabled"),
            "forced IFD did not fail through the source-policy option: {error}"
        );
        assert!(
            !marker.exists(),
            "the hidden import-from-derivation builder executed before classification"
        );
        assert_no_source_policy_store_left(&config);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    fn source_policy_test_command(root: &Path, script: &str) -> (AppConfig, NixBuildCommand) {
        use std::os::unix::fs::PermissionsExt;

        let _ = std::fs::remove_dir_all(root);
        std::fs::create_dir_all(root).unwrap();
        let fake_nix = root.join("fake-nix");
        std::fs::write(&fake_nix, script).unwrap();
        std::fs::set_permissions(&fake_nix, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut config = AppConfig::default();
        config.build.work_dir = root.join("work");
        let command = NixBuildCommand {
            program: fake_nix.display().to_string(),
            args: Vec::new(),
            out_link: root.join("result"),
            installable: ".#test".to_string(),
        };
        (config, command)
    }

    #[cfg(unix)]
    fn assert_no_source_policy_store_left(config: &AppConfig) {
        let leftovers = std::fs::read_dir(&config.build.work_dir)
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("source-policy-store-")
            })
            .count();
        assert_eq!(leftovers, 0);
    }

    #[cfg(unix)]
    fn tiny_preflight_limits() -> PreflightLimits {
        PreflightLimits {
            dry_run_timeout: Duration::from_millis(100),
            derivation_show_timeout: Duration::from_millis(100),
            dry_run_stdout_max_bytes: 256,
            dry_run_stderr_max_bytes: 256,
            derivation_show_stdout_max_bytes: 256,
            derivation_show_stderr_max_bytes: 256,
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn source_policy_bounds_dry_run_pipes_and_cleans_isolated_store() {
        let overflow_root = std::env::temp_dir().join(format!(
            "cybex-pulse-source-policy-overflow-test-{}",
            std::process::id()
        ));
        let (config, command) = source_policy_test_command(
            &overflow_root,
            "#!/bin/sh\nset -eu\nwhile :; do printf 'xxxxxxxxxxxxxxxx' >&2; done\n",
        );
        let error =
            preflight_source_build_check_with_limits(&config, &command, tiny_preflight_limits())
                .await
                .unwrap_err();
        let error = format!("{error:#}");
        assert!(error.contains("exceeded"), "unexpected error: {error}");
        assert_no_source_policy_store_left(&config);
        let _ = std::fs::remove_dir_all(&overflow_root);

        let timeout_root = std::env::temp_dir().join(format!(
            "cybex-pulse-source-policy-timeout-test-{}",
            std::process::id()
        ));
        let (config, command) =
            source_policy_test_command(&timeout_root, "#!/bin/sh\nset -eu\nwhile :; do :; done\n");
        let error =
            preflight_source_build_check_with_limits(&config, &command, tiny_preflight_limits())
                .await
                .unwrap_err();
        let error = format!("{error:#}");
        assert!(error.contains("timed out"), "unexpected error: {error}");
        assert_no_source_policy_store_left(&config);
        let _ = std::fs::remove_dir_all(&timeout_root);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn source_policy_timeout_kills_helpers_that_inherit_capture_pipes() {
        let root = std::env::temp_dir().join(format!(
            "cybex-pulse-source-policy-process-group-test-{}",
            std::process::id()
        ));
        let helper_pid = root.join("helper.pid");
        let script = format!(
            "#!/bin/sh\nset -eu\n(while :; do :; done) &\nprintf '%s' \"$!\" > '{}'\nwhile :; do :; done\n",
            helper_pid.display()
        );
        let (config, command) = source_policy_test_command(&root, &script);
        let mut limits = tiny_preflight_limits();
        limits.dry_run_timeout = Duration::from_millis(500);
        let error = preflight_source_build_check_with_limits(&config, &command, limits)
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("timed out"));

        let pid = std::fs::read_to_string(&helper_pid)
            .unwrap()
            .parse::<i32>()
            .unwrap();
        let mut gone = false;
        for _ in 0..50 {
            let alive = unsafe { libc::kill(pid, 0) } == 0;
            if !alive && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
                gone = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            gone,
            "grandchild {pid} survived the bounded-command timeout"
        );
        assert_no_source_policy_store_left(&config);
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn source_policy_bounds_derivation_show_while_reading_and_cleans_store() {
        let root = std::env::temp_dir().join(format!(
            "cybex-pulse-source-policy-show-overflow-test-{}",
            std::process::id()
        ));
        let (config, command) = source_policy_test_command(
            &root,
            r#"#!/bin/sh
set -eu
case "$*" in
  *" derivation show "*) while :; do printf 'xxxxxxxxxxxxxxxx'; done ;;
  *" build "*)
    printf '%s\n' 'this derivation will be built:' >&2
    printf '%s\n' '  /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-local-only.drv' >&2
    ;;
esac
"#,
        );
        let mut limits = tiny_preflight_limits();
        limits.dry_run_stderr_max_bytes = 1024;
        let error = preflight_source_build_check_with_limits(&config, &command, limits)
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("exceeded"));
        assert_no_source_policy_store_left(&config);
        let _ = std::fs::remove_dir_all(root);
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
        let blocked_log = "these 2 derivations will be built:\n  /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-firefox-140.0.drv\n  /nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-vlc-3.0.21.drv\nerror: unable to start any build; either increase '--max-jobs' or enable remote builds";
        let (kind, message) = classify_nix_build_failure(blocked_log, false);
        assert_eq!(kind, "source_build_blocked");
        assert!(message.contains("firefox-140.0"));
        assert!(message.contains("Allow building from source"));
    }

    #[test]
    fn would_build_extraction_and_blocked_message() {
        let dry_run = "evaluating\nthis derivation will be built:\n  /nix/store/cccccccccccccccccccccccccccccccc-pkg-1.0.drv\nthese 3 paths will be fetched (12 MiB download):\n  /nix/store/x\n";
        assert_eq!(
            extract_would_build_derivations(dry_run, 10).paths,
            vec!["/nix/store/cccccccccccccccccccccccccccccccc-pkg-1.0.drv".to_string()]
        );
        assert!(
            extract_would_build_derivations("nothing to do", 10)
                .paths
                .is_empty()
        );
        let overflow = extract_would_build_derivations(
            "these 2 derivations will be built:\n  /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-one.drv\n  /nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-two.drv\n",
            1,
        );
        assert!(overflow.marker_seen);
        assert!(overflow.overflowed);
        assert_eq!(overflow.paths.len(), 1);

        for malformed in [
            "these 2 derivations will be built:\n  /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-one.drv\nwarning: interrupted listing\n  /nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-two.drv\n",
            "these 2 derivations will be built:\n  /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-one.drv\n",
            "these 2 derivations will be built:\n  /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-one.drv\n  /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-one.drv\n",
            "warning: would build /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-hidden.drv\n",
        ] {
            let parsed = extract_would_build_derivations(malformed, 10);
            assert!(
                parsed.malformed,
                "accepted incomplete dry-run output: {malformed}"
            );
        }

        let names: Vec<String> = (0..7).map(|index| format!("pkg-{index}")).collect();
        let message = source_build_blocked_message(&names);
        assert!(message.starts_with("Blocked: 7 package(s)"));
        assert!(message.contains("pkg-4"));
        assert!(!message.contains("pkg-5"));
        assert!(message.contains("(+2 more)"));
        assert!(
            source_build_blocked_message(&[]).contains("requires compiling packages from source")
        );
    }

    #[test]
    fn nix_build_command_writes_blueprint_flake_input() {
        let root = std::env::temp_dir().join(format!(
            "cybex-pulse-build-input-test-{}",
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
            flake: "/srv/cybex-pulse/build-inputs/cybex".to_string(),
            attr: "packages.x86_64-linux.desktop-experience".to_string(),
        };
        let mut spec = ValidatedBuildSpec {
            artifact_type: "nixos_closure".to_string(),
            target: "blueprint".to_string(),
            system: "x86_64-linux".to_string(),
            input_revision: "rev".to_string(),
            input_config_hash: "a".repeat(64),
            blueprint_id: None,
            blueprint_revision_id: None,
            blueprint_revision_config_hash: None,
            nixpkgs_commit: Some("c".repeat(40)),
            source_lock_sha256: Some("d".repeat(64)),
            software_package_refs: vec!["firefox".to_string()],
            build_input: Some(ValidatedBlueprintBuildInput {
                kind: BLUEPRINT_BUILD_INPUT_KIND.to_string(),
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
                hardware_module_nix: None,
                target_module_nix: None,
                manage_source_revision: None,
                installer_target: None,
            }),
            allow_source_builds: false,
        };

        let command = nix_build_command(&config, &target, &spec, 42).unwrap();

        assert_eq!(command.program, "nix");
        assert_eq!(command.args[0], "build");
        assert!(
            command
                .args
                .iter()
                .any(|arg| arg.ends_with("#packages.x86_64-linux.desktop-experience"))
        );
        assert!(import_from_derivation_is_disabled(&command.args));
        assert!(flake_config_is_rejected(&command.args));
        assert!(build_sandbox_is_required(&command.args));
        assert!(root.join("work/job-42-input/flake.nix").is_file());
        assert!(root.join("work/job-42-input/blueprint.nix").is_file());
        assert!(
            root.join("work/job-42-input/cybex-blueprints.nix")
                .is_file()
        );
        assert!(root.join("work/job-42-input/expected-state.json").is_file());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let input_dir = root.join("work/job-42-input");
            assert_eq!(
                std::fs::metadata(&input_dir).unwrap().permissions().mode() & 0o777,
                0o700
            );
            for entry in std::fs::read_dir(&input_dir).unwrap() {
                let entry = entry.unwrap();
                let metadata = entry.metadata().unwrap();
                assert!(metadata.is_file());
                assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
            }
        }
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
        assert!(flake.contains(&format!(
            r#"inputs.nixpkgs.url = "github:NixOS/nixpkgs/{}";"#,
            "c".repeat(40)
        )));
        assert!(!flake.contains("/srv/cybex-pulse/build-inputs/cybex"));

        spec.allow_source_builds = true;
        let source_enabled = nix_build_command(&config, &target, &spec, 43).unwrap();
        assert!(!import_from_derivation_is_disabled(&source_enabled.args));
        assert!(flake_config_is_rejected(&source_enabled.args));
        assert!(build_sandbox_is_required(&source_enabled.args));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn nix_build_command_rejects_protected_material_before_writing_inputs() {
        let sentinel = "CYBEX_PULSE_PROTECTED_SENTINEL_7f922a";
        let root = std::env::temp_dir().join(format!(
            "cybex-pulse-protected-build-input-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let mut config = AppConfig::default();
        config.build.work_dir = root.join("work");
        config.build.output_dir = root.join("out");
        let target = BuildTargetConfig {
            artifact_type: "nixos_closure".to_string(),
            target: "blueprint".to_string(),
            system: "x86_64-linux".to_string(),
            flake: "/srv/cybex-pulse/build-inputs/cybex".to_string(),
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
            nixpkgs_commit: Some("c".repeat(40)),
            source_lock_sha256: Some("d".repeat(64)),
            software_package_refs: Vec::new(),
            build_input: Some(ValidatedBlueprintBuildInput {
                kind: BLUEPRINT_BUILD_INPUT_KIND.to_string(),
                generated_nix: format!(
                    "{{ ... }}: {{ users.users.alice.hashedPassword = \"{sentinel}\"; }}"
                ),
                desktop_module_nix: None,
                expected_state: None,
                blueprint_name: None,
                blueprint_revision: None,
                hardware_module_nix: None,
                target_module_nix: None,
                manage_source_revision: None,
                installer_target: None,
            }),
            allow_source_builds: false,
        };

        let error = nix_build_command(&config, &target, &spec, 99)
            .unwrap_err()
            .to_string();

        assert!(!error.contains(sentinel));
        assert!(!root.join("work/job-99-input").exists());
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

    #[tokio::test]
    async fn log_capture_redacts_spaced_nix_assignments_and_modular_hashes() {
        let sentinel = "CYBEX_PULSE_PROTECTED_SENTINEL_7f922a";
        let password_hash = "$6$rounds=5000$abcdefghijklmnop$uHL2DmwkR2iK6s.wDbxLW3GxvjJT7qW2rEHemZz3oMlKlfj8JwHc99.FNZrTO4drUslZ0MRyYkBDumQxKdL8q/";
        let log = SharedLog::new(4096);
        log.append(&format!(
            "users.users.alice.hashedPassword = \"{sentinel}\"; bare {password_hash}\n"
        ))
        .await;
        let snapshot = log.snapshot().await;

        assert!(snapshot.contains("[REDACTED]"));
        assert!(!snapshot.contains(sentinel));
        assert!(!snapshot.contains(password_hash));
    }

    #[tokio::test]
    async fn log_capture_redacts_assignments_split_across_stream_chunks() {
        let sentinel = "CYBEX_PULSE_PROTECTED_SENTINEL_7f922a";
        let log = SharedLog::new(4096);
        log.append("users.users.alice.hashedPassword = \"CYBEX_PULSE_")
            .await;
        assert!(!log.snapshot().await.contains("CYBEX_PULSE_"));

        log.append("PROTECTED_SENTINEL_7f922a\"; done\n").await;
        let snapshot = log.snapshot().await;

        assert!(snapshot.contains("done"));
        assert!(!snapshot.contains(sentinel));
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
                "narSize": 64,
                "deriver": format!("/nix/store/{}-example.drv", "a".repeat(32))
            }
        });
        let row = nix_path_info_row(&object, "/nix/store/example").unwrap();
        assert_eq!(nix_path_info_sizes(row), (128, 128));
        assert_eq!(
            nix_path_info_deriver(row).as_deref(),
            Some(format!("/nix/store/{}-example.drv", "a".repeat(32)).as_str())
        );

        let array = json!([
            {
                "closureSize": 200,
                "narSize": 300
            }
        ]);
        let row = nix_path_info_row(&array, "/nix/store/other").unwrap();
        assert_eq!(nix_path_info_sizes(row), (300, 200));
        assert_eq!(nix_path_info_deriver(row), None);

        let unrelated_object = json!({
            "/nix/store/unrelated": {
                "deriver": format!("/nix/store/{}-unrelated.drv", "b".repeat(32))
            }
        });
        assert!(
            nix_path_info_row(&unrelated_object, "/nix/store/requested")
                .unwrap_err()
                .to_string()
                .contains("omitted the requested store path")
        );

        let unrelated_array = json!([{
            "path": "/nix/store/unrelated",
            "deriver": format!("/nix/store/{}-unrelated.drv", "b".repeat(32))
        }]);
        assert!(
            nix_path_info_row(&unrelated_array, "/nix/store/requested")
                .unwrap_err()
                .to_string()
                .contains("unexpected store path")
        );
    }

    #[test]
    fn managed_metadata_cannot_replace_verified_cache_export_fields() {
        let mut destination = json!({
            "cache_schema": "cybex.pulse.cache.v1",
            "closure_manifest": {"verified": true},
            "closure_manifest_sha256": "a".repeat(64)
        });
        let source = json!({
            "cache_schema": "untrusted",
            "closure_manifest": {"forged": true},
            "closure_manifest_sha256": "b".repeat(64),
            "target": "blueprint"
        });

        merge_build_metadata(&mut destination, &source);

        assert_eq!(destination["cache_schema"], "cybex.pulse.cache.v1");
        assert_eq!(destination["closure_manifest"], json!({"verified": true}));
        assert_eq!(destination["closure_manifest_sha256"], "a".repeat(64));
        assert_eq!(destination["target"], "blueprint");
    }
}
