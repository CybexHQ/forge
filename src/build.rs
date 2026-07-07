use std::{
    fs,
    path::PathBuf,
    process::Stdio,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::Command,
    sync::Mutex,
    time::{sleep, timeout},
};
use tracing::{info, warn};

use crate::{
    AppState, cache,
    config::{AppConfig, BuildTargetConfig},
    db,
    models::BuildJob,
    redact::{contains_sensitive_key_value, redact_sensitive_key_values},
};

const DESKTOP_EXPERIENCE_BUILD_INPUT_KIND: &str = "desktop_experience_nixos_module";
const MAX_GENERATED_NIX_BYTES: usize = 1024 * 1024;

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
    pub desktop_experience_id: Option<String>,
    #[serde(default)]
    pub desktop_experience_revision_id: Option<String>,
    #[serde(default)]
    pub desktop_experience_revision_config_hash: Option<String>,
    #[serde(default)]
    pub build_input: Option<DesktopExperienceBuildInput>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesktopExperienceBuildInput {
    pub kind: String,
    pub generated_nix: String,
    #[serde(default)]
    pub desktop_experience_name: Option<String>,
    #[serde(default)]
    pub desktop_experience_revision: Option<i64>,
}

#[derive(Clone, Debug)]
struct ValidatedBuildSpec {
    artifact_type: String,
    target: String,
    system: String,
    input_revision: String,
    input_config_hash: String,
    desktop_experience_id: Option<String>,
    desktop_experience_revision_id: Option<String>,
    desktop_experience_revision_config_hash: Option<String>,
    build_input: Option<ValidatedDesktopExperienceBuildInput>,
}

#[derive(Clone, Debug)]
struct ValidatedDesktopExperienceBuildInput {
    generated_nix: String,
    desktop_experience_name: Option<String>,
    desktop_experience_revision: Option<i64>,
}

#[derive(Clone, Debug)]
struct NixBuildCommand {
    program: String,
    args: Vec<String>,
    out_link: PathBuf,
}

#[derive(Clone, Debug)]
struct NixOutputInfo {
    output_path: String,
    output_sha256: String,
    output_size_bytes: i64,
    closure_size_bytes: i64,
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

        for worker_index in 0..state.config.build.max_concurrent_builds {
            let worker_state = state.clone();
            tokio::spawn(async move { worker_loop(worker_state, worker_index).await });
        }
    });
}

async fn worker_loop(state: AppState, worker_index: usize) {
    loop {
        match db::claim_next_build_job(&state.db).await {
            Ok(Some(job)) => {
                info!(job_id = job.id, worker_index, "claimed Forge build job");
                if let Err(err) = execute_claimed_job(&state, job).await {
                    warn!(error = %safe_error(&err), worker_index, "Forge build job execution failed");
                }
            }
            Ok(None) => sleep(Duration::from_secs(2)).await,
            Err(err) => {
                warn!(error = %err, worker_index, "failed to claim Forge build job");
                sleep(Duration::from_secs(5)).await;
            }
        }
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
                Some(json!({"error_kind": "invalid_build_spec"})),
            )
            .await?;
            return Ok(());
        }
    };
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
                Some(json!({"error_kind": "target_not_allowed"})),
            )
            .await?;
            return Ok(());
        }
    };

    let command = nix_build_command(&state.config, &target, &spec, job.id)?;
    let log = SharedLog::new(state.config.build.max_log_bytes);
    let outcome = run_nix_build(&state.db, &job, &command, &log, &state.config).await?;
    let logs = log.snapshot().await;
    match outcome {
        ProcessOutcome::Succeeded(exit_code) => {
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
                        Some(json!({"error_kind": "output_validation_failed"})),
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
                    Some(json!({"error_kind": "artifact_too_large"})),
                )
                .await?;
                return Ok(());
            }
            let cached = match cache::export_output(
                &state.config,
                &job,
                &output_info.output_path,
                &output_info.output_sha256,
                output_info.closure_size_bytes,
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
                        Some(json!({"error_kind": "cache_export_failed"})),
                    )
                    .await?;
                    return Ok(());
                }
            };
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
                Some(json!({
                    "schema": "cybex.forge.build.result.v1",
                    "target": spec.target,
                    "system": spec.system,
                    "input_revision": spec.input_revision,
                    "input_config_hash": spec.input_config_hash,
                    "desktop_experience_id": spec.desktop_experience_id,
                    "desktop_experience_revision_id": spec.desktop_experience_revision_id,
                    "desktop_experience_revision_config_hash": spec.desktop_experience_revision_config_hash,
                    "build_input_kind": spec.build_input.as_ref().map(|_| DESKTOP_EXPERIENCE_BUILD_INPUT_KIND),
                    "cache": "exported"
                })),
            )
            .await?;
        }
        ProcessOutcome::Failed(exit_code) => {
            db::finish_build_job(
                &state.db,
                job.id,
                "failed",
                &logs,
                &format!("nix build exited with status {exit_code}"),
                "",
                "",
                0,
                Some(exit_code.into()),
                Some(json!({"error_kind": "nix_build_failed"})),
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
                Some(json!({"cancelled": true})),
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
                Some(json!({"error_kind": "build_timeout"})),
            )
            .await?;
        }
    }
    Ok(())
}

fn validate_build_spec(config: &AppConfig, job: &BuildJob) -> Result<ValidatedBuildSpec> {
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
    let desktop_experience_id = spec
        .desktop_experience_id
        .map(|value| normalize_optional_uuidish("desktop_experience_id", &value))
        .transpose()?;
    let desktop_experience_revision_id = spec
        .desktop_experience_revision_id
        .map(|value| normalize_optional_uuidish("desktop_experience_revision_id", &value))
        .transpose()?;
    let desktop_experience_revision_config_hash = spec
        .desktop_experience_revision_config_hash
        .map(|value| normalize_sha256(&value))
        .transpose()?;
    let build_input = spec
        .build_input
        .map(validate_desktop_experience_build_input)
        .transpose()?;
    if build_input.is_some() && artifact_type != "nixos_closure" {
        bail!("desktop_experience build_input requires artifact_type nixos_closure");
    }
    Ok(ValidatedBuildSpec {
        artifact_type,
        target,
        system,
        input_revision,
        input_config_hash,
        desktop_experience_id,
        desktop_experience_revision_id,
        desktop_experience_revision_config_hash,
        build_input,
    })
}

fn validate_desktop_experience_build_input(
    input: DesktopExperienceBuildInput,
) -> Result<ValidatedDesktopExperienceBuildInput> {
    let kind = input.kind.trim();
    if kind != DESKTOP_EXPERIENCE_BUILD_INPUT_KIND {
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
    Ok(ValidatedDesktopExperienceBuildInput {
        generated_nix: input.generated_nix,
        desktop_experience_name: input
            .desktop_experience_name
            .map(|value| bounded_metadata_text(&value, 200))
            .filter(|value| !value.is_empty()),
        desktop_experience_revision: input.desktop_experience_revision.filter(|value| *value > 0),
    })
}

fn build_target<'a>(
    config: &'a AppConfig,
    spec: &ValidatedBuildSpec,
) -> Result<&'a BuildTargetConfig> {
    config
        .build
        .targets
        .iter()
        .find(|target| {
            target.artifact_type == spec.artifact_type
                && target.target == spec.target
                && target.system == spec.system
        })
        .ok_or_else(|| {
            anyhow!("no configured build target matched artifact_type, target, and system")
        })
}

fn nix_build_command(
    config: &AppConfig,
    target: &BuildTargetConfig,
    spec: &ValidatedBuildSpec,
    job_id: i64,
) -> Result<NixBuildCommand> {
    if let Some(build_input) = spec.build_input.as_ref() {
        return desktop_experience_nix_build_command(config, target, spec, build_input, job_id);
    }
    let job_dir = config.build.output_dir.join(format!("job-{job_id}"));
    let out_link = job_dir.join("result");
    let installable = format!("{}#{}", target.flake, target.attr);
    Ok(NixBuildCommand {
        program: config.build.nix_binary.clone(),
        args: vec![
            "build".to_string(),
            installable,
            "--system".to_string(),
            spec.system.clone(),
            "--out-link".to_string(),
            out_link.display().to_string(),
            "--print-build-logs".to_string(),
            "--no-write-lock-file".to_string(),
        ],
        out_link,
    })
}

fn desktop_experience_nix_build_command(
    config: &AppConfig,
    target: &BuildTargetConfig,
    spec: &ValidatedBuildSpec,
    build_input: &ValidatedDesktopExperienceBuildInput,
    job_id: i64,
) -> Result<NixBuildCommand> {
    let input_dir = config.build.work_dir.join(format!("job-{job_id}-input"));
    fs::create_dir_all(&input_dir)
        .with_context(|| format!("create build input directory {}", input_dir.display()))?;
    write_job_input_file(
        input_dir.join("desktop-experience.nix"),
        &build_input.generated_nix,
    )?;
    write_job_input_file(
        input_dir.join("cybex-compat-options.nix"),
        desktop_experience_compat_module(),
    )?;
    write_job_input_file(
        input_dir.join("configuration.nix"),
        forge_nixos_configuration(),
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
            "--out-link".to_string(),
            out_link.display().to_string(),
            "--print-build-logs".to_string(),
            "--no-write-lock-file".to_string(),
        ],
        out_link,
    })
}

fn write_job_input_file(path: PathBuf, contents: &str) -> Result<()> {
    fs::write(&path, contents).with_context(|| format!("write build input {}", path.display()))
}

fn forge_nixos_flake(
    nixpkgs_flake: &str,
    system: &str,
    build_input: &ValidatedDesktopExperienceBuildInput,
) -> String {
    let name = build_input
        .desktop_experience_name
        .as_deref()
        .unwrap_or("Desktop Experience");
    let revision = build_input
        .desktop_experience_revision
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let description = serde_json::to_string(&format!(
        "Cybex Forge Desktop Experience build: {name} rev {revision}"
    ))
    .unwrap_or_else(|_| "\"Cybex Forge Desktop Experience build\"".to_string());
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

fn forge_nixos_configuration() -> &'static str {
    r#"{ lib, modulesPath, ... }:

{
  imports = [
    ./cybex-compat-options.nix
    ./desktop-experience.nix
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
}

fn desktop_experience_compat_module() -> &'static str {
    r#"{ lib, ... }:

{
  options.cybex = lib.mkOption {
    type = lib.types.attrsOf lib.types.anything;
    default = {};
    description = "Cybex Desktop Experience metadata accepted while Forge prebuilds a generic NixOS closure.";
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
    fn build_spec_accepts_desktop_experience_build_input() {
        let value = json!({
            "schema_version": 1,
            "artifact_type": "nixos_closure",
            "target": "desktop_experience",
            "system": "x86_64-linux",
            "input_revision": "rev",
            "input_config_hash": "a".repeat(64),
            "build_input": {
                "kind": "desktop_experience_nixos_module",
                "generated_nix": "{ lib, ... }: { networking.hostName = lib.mkDefault \"test\"; }",
                "desktop_experience_name": "Standard Workstation",
                "desktop_experience_revision": 8
            }
        });
        let parsed = serde_json::from_value::<BuildSpec>(value).unwrap();
        assert_eq!(
            parsed.build_input.unwrap().kind,
            DESKTOP_EXPERIENCE_BUILD_INPUT_KIND
        );
    }

    #[test]
    fn nix_build_command_uses_allowlisted_attr() {
        let mut config = AppConfig::default();
        config.build.output_dir = PathBuf::from("/tmp/cybex-forge-test-builds");
        config.build.nix_binary = "nix".to_string();
        let target = BuildTargetConfig {
            artifact_type: "nixos_closure".to_string(),
            target: "desktop_experience".to_string(),
            system: "x86_64-linux".to_string(),
            flake: "/srv/cybex-forge/build-inputs/cybex".to_string(),
            attr: "packages.x86_64-linux.desktop-experience".to_string(),
        };
        let spec = ValidatedBuildSpec {
            artifact_type: "nixos_closure".to_string(),
            target: "desktop_experience".to_string(),
            system: "x86_64-linux".to_string(),
            input_revision: "rev".to_string(),
            input_config_hash: "a".repeat(64),
            desktop_experience_id: None,
            desktop_experience_revision_id: None,
            desktop_experience_revision_config_hash: None,
            build_input: None,
        };

        let command = nix_build_command(&config, &target, &spec, 42).unwrap();

        assert_eq!(command.program, "nix");
        assert_eq!(command.args[0], "build");
        assert!(
            command.args.contains(
                &"/srv/cybex-forge/build-inputs/cybex#packages.x86_64-linux.desktop-experience"
                    .to_string()
            )
        );
        assert!(command.args.contains(&"--out-link".to_string()));
    }

    #[test]
    fn nix_build_command_writes_desktop_experience_flake_input() {
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
            target: "desktop_experience".to_string(),
            system: "x86_64-linux".to_string(),
            flake: "/srv/cybex-forge/build-inputs/cybex".to_string(),
            attr: "packages.x86_64-linux.desktop-experience".to_string(),
        };
        let spec = ValidatedBuildSpec {
            artifact_type: "nixos_closure".to_string(),
            target: "desktop_experience".to_string(),
            system: "x86_64-linux".to_string(),
            input_revision: "rev".to_string(),
            input_config_hash: "a".repeat(64),
            desktop_experience_id: None,
            desktop_experience_revision_id: None,
            desktop_experience_revision_config_hash: None,
            build_input: Some(ValidatedDesktopExperienceBuildInput {
                generated_nix: "{ lib, ... }: { networking.hostName = lib.mkDefault \"test\"; }"
                    .to_string(),
                desktop_experience_name: Some("Standard Workstation".to_string()),
                desktop_experience_revision: Some(8),
            }),
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
        assert!(root.join("work/job-42-input/flake.nix").is_file());
        assert!(
            root.join("work/job-42-input/desktop-experience.nix")
                .is_file()
        );
        let configuration =
            std::fs::read_to_string(root.join("work/job-42-input/configuration.nix")).unwrap();
        assert!(
            configuration
                .contains("systemd.services.systemd-udevd.restartTriggers = lib.mkForce [];")
        );
        assert!(configuration.contains("boot.initrd.enable = lib.mkForce false;"));
        assert!(configuration.contains("boot.initrd.includeDefaultModules = false;"));
        assert!(configuration.contains("boot.initrd.availableKernelModules = lib.mkForce [];"));
        assert!(configuration.contains("boot.kernelModules = lib.mkForce [];"));
        assert!(configuration.contains("security.lockKernelModules = lib.mkForce false;"));
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
