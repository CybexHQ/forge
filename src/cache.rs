use std::{
    collections::{HashMap, HashSet},
    fs::{self, OpenOptions},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use tokio::task;
use uuid::Uuid;

use crate::{config::AppConfig, db, models::BuildJob, redact::redact_sensitive_key_values};

#[derive(Clone, Debug, Serialize)]
pub struct CacheStatusReport {
    pub enabled: bool,
    pub status: String,
    pub public_key: String,
    pub public_key_fingerprint: String,
    pub base_url: String,
    pub total_size_bytes: u64,
    pub artifact_count: usize,
    pub error: String,
}

#[derive(Clone, Debug)]
pub struct CacheSigningIdentity {
    pub public_key: String,
    pub key_id: String,
    pub fingerprint: String,
}

/// Process-external serialization for every mutation of the served cache and
/// its inventory rows. The descriptor owns the advisory `flock`; callers must
/// keep this value alive until filesystem publication and the matching SQLite
/// commit are both complete.
#[derive(Debug)]
pub struct CacheMutationLease {
    file: fs::File,
    path: PathBuf,
}

impl CacheMutationLease {
    fn ensure_matches(&self, config: &AppConfig) -> Result<()> {
        if self.path != config.cache.mutation_lock_path {
            bail!("cache mutation lease does not match configured lock path");
        }
        Ok(())
    }
}

impl Drop for CacheMutationLease {
    fn drop(&mut self) {
        // A crashed process releases the kernel lock automatically. Explicitly
        // unlock on the ordinary path so waiting hook/build processes wake as
        // soon as the guard leaves scope.
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

pub async fn acquire_mutation_lease(config: &AppConfig) -> Result<CacheMutationLease> {
    let lock_path = config.cache.mutation_lock_path.clone();
    let cache_root = config.cache.root_dir.clone();
    task::spawn_blocking(move || acquire_mutation_lease_blocking(&lock_path, &cache_root))
        .await
        .context("join cache mutation lease task")?
}

pub async fn try_acquire_mutation_lease(config: &AppConfig) -> Result<Option<CacheMutationLease>> {
    let lock_path = config.cache.mutation_lock_path.clone();
    let cache_root = config.cache.root_dir.clone();
    task::spawn_blocking(move || {
        acquire_mutation_lease_blocking_inner(&lock_path, &cache_root, true)
    })
    .await
    .context("join non-blocking cache mutation lease task")?
}

pub fn assert_mutation_lease(config: &AppConfig, lease: &CacheMutationLease) -> Result<()> {
    lease.ensure_matches(config)
}

fn acquire_mutation_lease_blocking(
    lock_path: &Path,
    cache_root: &Path,
) -> Result<CacheMutationLease> {
    acquire_mutation_lease_blocking_inner(lock_path, cache_root, false)?
        .ok_or_else(|| anyhow!("blocking cache mutation lease was not acquired"))
}

fn acquire_mutation_lease_blocking_inner(
    lock_path: &Path,
    cache_root: &Path,
    nonblocking: bool,
) -> Result<Option<CacheMutationLease>> {
    fs::create_dir_all(cache_root)
        .with_context(|| format!("create cache root {}", cache_root.display()))?;
    let cache_root_metadata = fs::symlink_metadata(cache_root)
        .with_context(|| format!("stat cache root {}", cache_root.display()))?;
    if !cache_root_metadata.is_dir()
        || cache_root_metadata.file_type().is_symlink()
        || cache_root_metadata.mode() & 0o022 != 0
    {
        bail!("cache root ownership, type, or mode is unsafe for mutation locking");
    }
    let parent = lock_path
        .parent()
        .ok_or_else(|| anyhow!("cache mutation lock path has no parent"))?;
    fs::create_dir_all(parent)
        .with_context(|| format!("create cache mutation lock directory {}", parent.display()))?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(lock_path)
        .with_context(|| format!("open cache mutation lock {}", lock_path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("stat cache mutation lock {}", lock_path.display()))?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o600
        || metadata.uid() != cache_root_metadata.uid()
    {
        bail!("cache mutation lock ownership, type, or mode is unsafe");
    }
    let operation = libc::LOCK_EX | if nonblocking { libc::LOCK_NB } else { 0 };
    let result = unsafe { libc::flock(file.as_raw_fd(), operation) };
    if result != 0 {
        let error = std::io::Error::last_os_error();
        if nonblocking && error.kind() == std::io::ErrorKind::WouldBlock {
            return Ok(None);
        }
        return Err(error).context("acquire cache mutation lease");
    }
    // A waiter can spend an arbitrary amount of time blocked in `flock`.
    // Revalidate the pathname after acquisition so replacing the lock inode
    // while this process waited cannot create two independent mutation
    // domains (one on the unlinked inode and one on its replacement).
    let locked_metadata = file
        .metadata()
        .with_context(|| format!("restat cache mutation lock {}", lock_path.display()))?;
    let path_metadata = fs::symlink_metadata(lock_path)
        .with_context(|| format!("restat cache mutation lock path {}", lock_path.display()))?;
    let current_cache_metadata = fs::symlink_metadata(cache_root)
        .with_context(|| format!("restat cache root {}", cache_root.display()))?;
    if !path_metadata.file_type().is_file()
        || path_metadata.file_type().is_symlink()
        || path_metadata.dev() != locked_metadata.dev()
        || path_metadata.ino() != locked_metadata.ino()
        || locked_metadata.nlink() != 1
        || locked_metadata.mode() & 0o777 != 0o600
        || locked_metadata.uid() != current_cache_metadata.uid()
        || !current_cache_metadata.is_dir()
        || current_cache_metadata.file_type().is_symlink()
        || current_cache_metadata.mode() & 0o022 != 0
    {
        bail!("cache mutation lock or cache root changed while acquiring the lease");
    }
    Ok(Some(CacheMutationLease {
        file,
        path: lock_path.to_path_buf(),
    }))
}

#[derive(Clone, Debug)]
pub struct CachedNixArtifact {
    pub managed_artifact_id: Option<String>,
    pub artifact_hash: String,
    pub size_bytes: i64,
    pub nar_path: PathBuf,
    pub narinfo_path: PathBuf,
    pub nar_url: String,
    pub store_path: String,
    pub file_hash: String,
    pub nar_hash: String,
    pub nar_size_bytes: i64,
    pub closure_size_bytes: i64,
    pub closure_file_size_bytes: i64,
    pub compression: String,
    pub references: Vec<String>,
    pub metadata: Value,
}

#[derive(Debug)]
struct ParsedNarInfo {
    store_path: String,
    url: String,
    compression: String,
    file_hash: String,
    file_size: i64,
    nar_hash: String,
    nar_size: i64,
    references: Vec<String>,
    signatures: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
struct NixCacheInfo {
    store_dir: String,
    want_mass_query: bool,
    priority: Option<u64>,
}

pub async fn status_report(config: &AppConfig, pool: &SqlitePool) -> CacheStatusReport {
    if !config.cache.enabled {
        return CacheStatusReport {
            enabled: false,
            status: "disabled".to_string(),
            public_key: String::new(),
            public_key_fingerprint: String::new(),
            base_url: cache_base_url(config),
            total_size_bytes: 0,
            artifact_count: 0,
            error: String::new(),
        };
    }
    let artifacts = db::list_cache_artifacts(pool).await.unwrap_or_default();
    // Artifact rows only record each export's top-level NAR; the closure NARs
    // written by `nix copy` dominate disk usage, so measure the cache root itself.
    let total_size_bytes = cache_disk_usage(config).await;
    match ensure_signing_key(config).await {
        Ok(public_key) => CacheStatusReport {
            enabled: true,
            status: "ready".to_string(),
            public_key_fingerprint: public_key_fingerprint(&public_key),
            public_key,
            base_url: cache_base_url(config),
            total_size_bytes,
            artifact_count: artifacts.len(),
            error: String::new(),
        },
        Err(err) => CacheStatusReport {
            enabled: true,
            status: "error".to_string(),
            public_key: String::new(),
            public_key_fingerprint: String::new(),
            base_url: cache_base_url(config),
            total_size_bytes,
            artifact_count: artifacts.len(),
            error: sanitize_error(&err),
        },
    }
}

/// Contents written to a fresh cache root. Installers add this cache alongside
/// cache.nixos.org (Priority 40); the lower value prefers the LAN cache when
/// both carry a path.
const NIX_CACHE_INFO_CONTENTS: &str = "StoreDir: /nix/store\nWantMassQuery: 1\nPriority: 30\n";
const RELEASE_TEST_FAULT_SENTINEL_SCHEMA: &str = "cybex.forge-release-test-fault-sentinel.v1";
const RELEASE_TEST_FAULT_PRIVATE_DIR: &str = ".cybex-forge-private";
const RELEASE_TEST_FAULT_SENTINEL_DIR: &str = "release-test-faults";
const RELEASE_TEST_FAULT_SENTINEL_FILE: &str = "pending";
const MAX_RELEASE_TEST_FAULT_SENTINEL_BYTES: u64 = 16 * 1024;

/// Refuse all System Release publication while the root-only acceptance hook
/// has an active cache fault. NARs are shared across releases, so limiting the
/// fence to the named release would allow another build to republish metadata
/// over a deliberately corrupted shared member. The hook creates this
/// non-secret sentinel before touching cache bytes and removes it only after an
/// exact reset, all under the same interprocess lease.
pub fn ensure_system_release_publication_allowed(
    config: &AppConfig,
    _release_id: &str,
    lease: &CacheMutationLease,
) -> Result<()> {
    lease.ensure_matches(config)?;
    let private_dir = config.cache.root_dir.join(RELEASE_TEST_FAULT_PRIVATE_DIR);
    let sentinel_dir = private_dir.join(RELEASE_TEST_FAULT_SENTINEL_DIR);
    let sentinel_path = sentinel_dir.join(RELEASE_TEST_FAULT_SENTINEL_FILE);
    let sentinel_metadata = match fs::symlink_metadata(&sentinel_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "stat release-test fault sentinel {}",
                    sentinel_path.display()
                )
            });
        }
    };
    let cache_metadata = fs::symlink_metadata(&config.cache.root_dir)?;
    for directory in [&private_dir, &sentinel_dir] {
        let metadata = fs::symlink_metadata(directory).with_context(|| {
            format!("stat release-test fault directory {}", directory.display())
        })?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != cache_metadata.uid()
            || metadata.mode() & 0o777 != 0o700
        {
            bail!("release-test fault sentinel directory is unsafe");
        }
    }
    if !sentinel_metadata.file_type().is_file()
        || sentinel_metadata.nlink() != 1
        || sentinel_metadata.len() == 0
        || sentinel_metadata.len() > MAX_RELEASE_TEST_FAULT_SENTINEL_BYTES
        || sentinel_metadata.mode() & 0o777 != 0o644
        || !matches!(sentinel_metadata.uid(), 0) && sentinel_metadata.uid() != cache_metadata.uid()
    {
        bail!("release-test fault sentinel ownership, type, mode, or size is unsafe");
    }
    let raw = fs::read_to_string(&sentinel_path).with_context(|| {
        format!(
            "read release-test fault sentinel {}",
            sentinel_path.display()
        )
    })?;
    validate_release_test_fault_sentinel(&raw)?;
    bail!("an acceptance-test cache fault is pending exact reset");
}

fn validate_release_test_fault_sentinel(raw: &str) -> Result<()> {
    let mut values = HashMap::new();
    for line in raw.lines() {
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| anyhow!("release-test fault sentinel line is invalid"))?;
        if !matches!(
            key,
            "schema"
                | "owner_run_id"
                | "run_id"
                | "acceptance_run_id"
                | "evidence_nonce_sha256"
                | "boot_id"
                | "fault"
                | "release_id"
                | "deployment_id"
                | "attempt_id"
                | "owner_binding_sha256"
                | "consumed"
        ) || values.insert(key, value).is_some()
        {
            bail!("release-test fault sentinel has unknown or duplicate fields");
        }
    }
    let required = |key: &str| {
        values
            .get(key)
            .copied()
            .ok_or_else(|| anyhow!("release-test fault sentinel omitted {key}"))
    };
    if required("schema")? != RELEASE_TEST_FAULT_SENTINEL_SCHEMA
        || required("owner_run_id")? != required("run_id")?
        || !safe_fault_sentinel_id(required("owner_run_id")?)
        || !matches!(
            required("fault")?,
            "corrupt_closure_manifest" | "corrupt_nar" | "invalid_cache_signature"
        )
        || !matches!(required("consumed")?, "true" | "false")
    {
        bail!("release-test fault sentinel identity is invalid");
    }
    for key in [
        "acceptance_run_id",
        "boot_id",
        "release_id",
        "deployment_id",
        "attempt_id",
    ] {
        let value = required(key)?;
        let uuid = Uuid::parse_str(value)
            .with_context(|| format!("release-test fault sentinel {key} is invalid"))?;
        if uuid.is_nil() || uuid.hyphenated().to_string() != value {
            bail!("release-test fault sentinel {key} is not canonical");
        }
    }
    for key in ["evidence_nonce_sha256", "owner_binding_sha256"] {
        if !is_lower_sha256(required(key)?) {
            bail!("release-test fault sentinel {key} is invalid");
        }
    }
    Ok(())
}

fn safe_fault_sentinel_id(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

/// Make the served cache root a valid Nix binary cache before the first build
/// export. `nix copy` only writes `nix-cache-info` as a side effect of an
/// export, so until then installers that were handed this cache as a
/// substituter see "does not appear to be a binary cache" and silently skip
/// substitution. Also pre-generates the signing key pair so the cache reports
/// ready from first boot. Existing files are never modified.
pub async fn initialize(config: &AppConfig) -> Result<()> {
    if !config.cache.enabled {
        return Ok(());
    }
    let lease = acquire_mutation_lease(config).await?;
    let cache_dir = config.cache.root_dir.clone();
    task::spawn_blocking(move || initialize_cache_root_blocking(&cache_dir))
        .await
        .context("join cache init task")??;
    drop(lease);
    ensure_signing_key(config).await?;
    Ok(())
}

pub fn signing_identity(config: &AppConfig) -> Result<CacheSigningIdentity> {
    if !config.cache.enabled {
        bail!("Forge Cache is disabled");
    }
    let private = fs::symlink_metadata(&config.cache.private_key_path).with_context(|| {
        format!(
            "stat cache private key {}",
            config.cache.private_key_path.display()
        )
    })?;
    let public = fs::symlink_metadata(&config.cache.public_key_path).with_context(|| {
        format!(
            "stat cache public key {}",
            config.cache.public_key_path.display()
        )
    })?;
    let effective_uid = unsafe { libc::geteuid() };
    if !private.file_type().is_file()
        || private.nlink() != 1
        || private.uid() != effective_uid
        || private.mode() & 0o777 != 0o600
        || !public.file_type().is_file()
        || public.nlink() != 1
        || public.uid() != effective_uid
        || public.mode() & 0o022 != 0
    {
        bail!("cache signing key ownership or mode is unsafe");
    }
    let public_key = read_public_key(&config.cache.public_key_path)?;
    let fingerprint = public_key_fingerprint(&public_key);
    if fingerprint.is_empty() {
        bail!("cache public key material is invalid");
    }
    Ok(CacheSigningIdentity {
        public_key,
        key_id: fingerprint.clone(),
        fingerprint,
    })
}

fn initialize_cache_root_blocking(cache_dir: &Path) -> Result<()> {
    fs::create_dir_all(cache_dir)
        .with_context(|| format!("create cache directory {}", cache_dir.display()))?;
    let path = cache_dir.join("nix-cache-info");
    if path.exists() {
        // Present means either a previous init or a real `nix copy` wrote it;
        // validate but never clobber metadata nix itself maintains.
        read_nix_cache_info(cache_dir)?;
        return Ok(());
    }
    parse_nix_cache_info(NIX_CACHE_INFO_CONTENTS)
        .context("validate built-in nix-cache-info template")?;
    let staged = cache_dir.join(".nix-cache-info.tmp");
    fs::write(&staged, NIX_CACHE_INFO_CONTENTS)
        .with_context(|| format!("write {}", staged.display()))?;
    fs::rename(&staged, &path).with_context(|| format!("publish {}", path.display()))?;
    Ok(())
}

pub async fn export_output(
    config: &AppConfig,
    job: &BuildJob,
    store_path: &str,
    artifact_hash: &str,
    closure_size_bytes: i64,
    lease: &CacheMutationLease,
) -> Result<CachedNixArtifact> {
    if !config.cache.enabled {
        bail!("Forge Cache is disabled");
    }
    lease.ensure_matches(config)?;
    crate::disk::ensure_headroom(
        &config.cache.root_dir,
        closure_size_bytes.max(0) as u64,
        "Forge cache export",
    )?;
    let public_key = ensure_signing_key(config).await?;
    let cache_dir = config.cache.root_dir.clone();
    let private_key_path = config.cache.private_key_path.clone();
    let nix_binary = config.build.nix_binary.clone();
    let store_path = store_path.to_string();
    let managed_job_id = job.managed_job_id.clone();
    let artifact_hash = artifact_hash.to_string();
    task::spawn_blocking(move || {
        fs::create_dir_all(&cache_dir)
            .with_context(|| format!("create cache directory {}", cache_dir.display()))?;
        let destination = format!(
            "file://{}?secret-key={}",
            cache_dir.display(),
            private_key_path.display()
        );
        let output = Command::new(&nix_binary)
            .arg("copy")
            .arg("--to")
            .arg(&destination)
            .arg(&store_path)
            .output()
            .with_context(|| format!("run {nix_binary} copy to local binary cache"))?;
        if !output.status.success() {
            bail!(
                "nix copy failed: {}",
                bounded_command_error(&output.stderr, &private_key_path)
            );
        }
        let cache_info = read_nix_cache_info(&cache_dir)?;
        let narinfo_name = narinfo_filename_for_store_path(&store_path)?;
        let narinfo_path = cache_dir.join(&narinfo_name);
        let narinfo_raw = fs::read_to_string(&narinfo_path)
            .with_context(|| format!("read generated {}", narinfo_path.display()))?;
        let narinfo = parse_narinfo(&narinfo_raw)?;
        if narinfo.store_path != store_path {
            bail!("generated narinfo StorePath did not match build output path");
        }
        let nar_path = safe_cache_member_path(&cache_dir, &narinfo.url)?;
        let nar_len = fs::metadata(&nar_path)
            .with_context(|| format!("stat generated NAR {}", nar_path.display()))?
            .len();
        if nar_len > i64::MAX as u64 {
            bail!("generated NAR is too large to report");
        }
        let closure_file_size_bytes = closure_file_size_bytes_blocking(&cache_dir, &store_path);
        let metadata = json!({
            "cache_schema": "cybex.forge.cache.v1",
            "public_key_fingerprint": public_key_fingerprint(&public_key),
            "nix_cache_info": cache_info,
            "narinfo": narinfo_name,
            "signatures": narinfo.signatures,
            "file_size": narinfo.file_size,
            "nar_size": narinfo.nar_size,
            "closure_size": closure_size_bytes,
            "closure_file_size": closure_file_size_bytes,
            "source_build_job_id": managed_job_id,
        });
        Ok(CachedNixArtifact {
            managed_artifact_id: None,
            artifact_hash,
            size_bytes: nar_len as i64,
            nar_path,
            narinfo_path,
            nar_url: narinfo.url,
            store_path,
            file_hash: narinfo.file_hash,
            nar_hash: narinfo.nar_hash,
            nar_size_bytes: narinfo.nar_size,
            closure_size_bytes,
            closure_file_size_bytes,
            compression: narinfo.compression,
            references: narinfo.references,
            metadata,
        })
    })
    .await
    .context("join cache export task")?
}

pub async fn record_cached_artifact(
    pool: &SqlitePool,
    config: &AppConfig,
    job: &BuildJob,
    artifact_type: &str,
    artifact: CachedNixArtifact,
    lease: &CacheMutationLease,
) -> Result<()> {
    lease.ensure_matches(config)?;
    let serving_url = format!(
        "{}/{}",
        cache_base_url(config),
        artifact.nar_url.trim_start_matches('/')
    );
    db::upsert_cache_artifact(
        pool,
        artifact.managed_artifact_id.as_deref(),
        artifact_type,
        &artifact.artifact_hash,
        artifact.size_bytes,
        &artifact.nar_path.display().to_string(),
        &artifact.store_path,
        &artifact.narinfo_path.display().to_string(),
        &artifact.nar_url,
        &artifact.file_hash,
        &artifact.nar_hash,
        artifact.nar_size_bytes,
        artifact.closure_size_bytes,
        artifact.closure_file_size_bytes,
        &artifact.compression,
        Some(json!(artifact.references)),
        &serving_url,
        job.managed_job_id.as_deref(),
        Some(artifact.metadata),
    )
    .await
    .map_err(anyhow::Error::from)?;
    Ok(())
}

/// Remove specific artifacts (identified by artifact_type + hash) on request
/// from the management server: delete their rows, then sweep any NAR/narinfo
/// files no longer reachable from the remaining artifacts.
pub async fn remove_artifacts_by_key(
    pool: &SqlitePool,
    config: &AppConfig,
    expected_inventory: &db::CacheInventoryFence,
    keys: &[(String, String)],
) -> Result<db::CacheArtifactRemovalOutcome> {
    let lease = acquire_mutation_lease(config).await?;
    remove_artifacts_by_key_under_lease(pool, config, expected_inventory, keys, &lease).await
}

pub async fn remove_artifacts_by_key_under_lease(
    pool: &SqlitePool,
    config: &AppConfig,
    expected_inventory: &db::CacheInventoryFence,
    keys: &[(String, String)],
    lease: &CacheMutationLease,
) -> Result<db::CacheArtifactRemovalOutcome> {
    lease.ensure_matches(config)?;
    if keys.is_empty() {
        bail!("cache deletion requires at least one inventory-bound artifact key");
    }
    let mut outcome =
        db::remove_cache_artifacts_if_current_and_unprotected(pool, expected_inventory, keys)
            .await?;
    if outcome.inventory_matched && !outcome.deleted.is_empty() {
        // Requery after the deletion transaction while the global lease still
        // excludes publishers. Never sweep from the pre-delete snapshot
        // returned for diagnostics.
        outcome.retained = db::list_cache_artifacts(pool).await?;
        let retained = outcome
            .retained
            .iter()
            .map(RetainedArtifactFiles::from)
            .collect::<Vec<_>>();
        sweep_unreachable_under_lease(config, retained, lease).await?;
    }
    Ok(outcome)
}

pub async fn sweep_to_recorded_artifacts(pool: &SqlitePool, config: &AppConfig) -> Result<u64> {
    let lease = acquire_mutation_lease(config).await?;
    sweep_to_recorded_artifacts_under_lease(pool, config, &lease).await
}

pub async fn sweep_to_recorded_artifacts_under_lease(
    pool: &SqlitePool,
    config: &AppConfig,
    lease: &CacheMutationLease,
) -> Result<u64> {
    lease.ensure_matches(config)?;
    let retained = db::list_cache_artifacts(pool)
        .await?
        .iter()
        .map(RetainedArtifactFiles::from)
        .collect::<Vec<_>>();
    sweep_unreachable_under_lease(config, retained, lease).await
}

pub async fn enforce_retention(pool: &SqlitePool, config: &AppConfig) -> Result<()> {
    let lease = acquire_mutation_lease(config).await?;
    enforce_retention_under_lease(pool, config, &lease).await
}

pub async fn enforce_retention_under_lease(
    pool: &SqlitePool,
    config: &AppConfig,
    lease: &CacheMutationLease,
) -> Result<()> {
    lease.ensure_matches(config)?;
    if config.cache.max_bytes == 0 {
        tracing::warn!(
            "cache.max_bytes is 0: Forge Cache retention is disabled and the cache root can grow without bound"
        );
        return Ok(());
    }
    if !db::managed_cache_protections_authoritative(pool).await? {
        tracing::warn!(
            "cache retention is inhibited until a complete managed protection snapshot is installed"
        );
        return Ok(());
    }
    // Artifact rows only track top-level NARs while `nix copy` stores whole
    // closures, so both the threshold and the reclaim must work on disk state.
    let mut total = cache_disk_usage(config).await;
    if total <= config.cache.max_bytes {
        return Ok(());
    }
    // Evict oldest-first in rounds: pick a batch whose estimated compressed
    // footprint covers the excess, then mark-and-sweep ONCE for the whole
    // batch. Closure sharing can make the estimate optimistic, so re-measure
    // disk usage and run another round while still over budget. This keeps
    // the expensive full-cache walks proportional to rounds (usually one),
    // not to the number of evicted artifacts.
    loop {
        if total <= config.cache.max_bytes {
            break;
        }
        // These are deliberately refreshed for every eviction round under the
        // lease. A complete desired-replica update acquired this same lease,
        // so no stale protection snapshot can be used for deletion.
        let build_jobs = db::list_build_jobs(pool).await?;
        let managed_protections = db::list_managed_cache_protections(pool).await?;
        let mut protected_sources = HashSet::new();
        for job in build_jobs
            .iter()
            .filter(|job| matches!(job.status.as_str(), "queued" | "running"))
            .chain(build_jobs.iter().take(config.cache.retain_recent_builds))
        {
            if let Some(managed_job_id) = job.managed_job_id.as_deref() {
                protected_sources.insert(managed_job_id.to_string());
            }
        }
        let mut candidates = db::list_cache_artifacts(pool).await?;
        candidates.sort_by(|left, right| left.created_at.cmp(&right.created_at));
        if candidates.is_empty() {
            break;
        }
        let excess = total - config.cache.max_bytes;
        let mut estimated_freed: u64 = 0;
        let mut evicted_this_round = false;
        for artifact in &candidates {
            if estimated_freed > excess {
                break;
            }
            if managed_protections
                .contains(&(artifact.artifact_type.clone(), artifact.hash.clone()))
            {
                continue;
            }
            if artifact
                .source_build_job_id
                .as_deref()
                .is_some_and(|id| protected_sources.contains(id))
            {
                continue;
            }
            if !db::delete_cache_artifact_if_unprotected(pool, artifact.id).await? {
                continue;
            }
            evicted_this_round = true;
            let estimate = artifact
                .closure_file_size_bytes
                .max(artifact.size_bytes)
                .max(1) as u64;
            estimated_freed = estimated_freed.saturating_add(estimate);
        }
        if !evicted_this_round {
            break;
        }
        let retained = db::list_cache_artifacts(pool)
            .await?
            .iter()
            .map(RetainedArtifactFiles::from)
            .collect::<Vec<_>>();
        sweep_unreachable_under_lease(config, retained, lease).await?;
        total = cache_disk_usage(config).await;
    }
    Ok(())
}

/// Verify a bounded, oldest-verified-first cache batch. Invalid local rows are
/// removed immediately; the next generation-fenced full inventory makes the
/// loss visible to Manage, whose desired-state controller queues a repair.
pub async fn scrub_cache_artifacts(
    pool: &SqlitePool,
    config: &AppConfig,
    limit: i64,
) -> Result<u64> {
    let lease = acquire_mutation_lease(config).await?;
    scrub_cache_artifacts_under_lease(pool, config, limit, &lease).await
}

pub async fn try_scrub_cache_artifacts(
    pool: &SqlitePool,
    config: &AppConfig,
    limit: i64,
) -> Result<Option<u64>> {
    let Some(lease) = try_acquire_mutation_lease(config).await? else {
        return Ok(None);
    };
    scrub_cache_artifacts_under_lease(pool, config, limit, &lease)
        .await
        .map(Some)
}

async fn scrub_cache_artifacts_under_lease(
    pool: &SqlitePool,
    config: &AppConfig,
    limit: i64,
    lease: &CacheMutationLease,
) -> Result<u64> {
    lease.ensure_matches(config)?;
    let candidates = db::cache_artifacts_due_for_verification(pool, limit).await?;
    if candidates.is_empty() {
        return Ok(0);
    }
    let mut invalid_ids = HashSet::new();
    for artifact in &candidates {
        let valid = verify_cache_artifact(artifact).await.unwrap_or(false);
        if valid {
            db::mark_cache_artifact_verified(pool, artifact.id).await?;
        } else {
            tracing::warn!(
                artifact_id = artifact.id,
                artifact_type = %artifact.artifact_type,
                hash = %artifact.hash,
                "removing missing or corrupt Forge cache artifact for automatic repair"
            );
            db::delete_cache_artifact(pool, artifact.id).await?;
            invalid_ids.insert(artifact.id);
        }
    }
    if !invalid_ids.is_empty() {
        let retained = db::list_cache_artifacts(pool)
            .await?
            .iter()
            .map(RetainedArtifactFiles::from)
            .collect::<Vec<_>>();
        sweep_unreachable_under_lease(config, retained, lease).await?;
    }
    Ok(invalid_ids.len() as u64)
}

async fn verify_cache_artifact(artifact: &crate::models::CacheArtifact) -> Result<bool> {
    let nar_metadata = match tokio::fs::metadata(&artifact.path).await {
        Ok(metadata) if metadata.is_file() => metadata,
        _ => return Ok(false),
    };
    if artifact.size_bytes > 0 && nar_metadata.len() != artifact.size_bytes as u64 {
        return Ok(false);
    }
    let narinfo_raw = match tokio::fs::read_to_string(&artifact.narinfo_path).await {
        Ok(raw) => raw,
        Err(_) => return Ok(false),
    };
    let narinfo = match parse_narinfo(&narinfo_raw) {
        Ok(narinfo) => narinfo,
        Err(_) => return Ok(false),
    };
    Ok(narinfo.store_path == artifact.store_path
        && narinfo.url == artifact.nar_url
        && narinfo.file_hash == artifact.file_hash
        && narinfo.nar_hash == artifact.nar_hash
        && (artifact.nar_size_bytes <= 0 || narinfo.nar_size == artifact.nar_size_bytes))
}

#[derive(Clone, Debug)]
struct RetainedArtifactFiles {
    store_path: String,
    nar_path: PathBuf,
    narinfo_path: PathBuf,
    nar_url: String,
    evidence_relative_paths: Vec<String>,
}

impl From<&crate::models::CacheArtifact> for RetainedArtifactFiles {
    fn from(artifact: &crate::models::CacheArtifact) -> Self {
        let evidence_relative_paths = [
            artifact
                .cache_metadata
                .pointer("/system_release/closure/relative_path"),
            artifact
                .cache_metadata
                .pointer("/system_release/provenance/relative_path"),
        ]
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect();
        Self {
            store_path: artifact.store_path.clone(),
            nar_path: PathBuf::from(&artifact.path),
            narinfo_path: PathBuf::from(&artifact.narinfo_path),
            nar_url: artifact.nar_url.trim_start_matches('/').to_string(),
            evidence_relative_paths,
        }
    }
}

async fn sweep_unreachable_under_lease(
    config: &AppConfig,
    retained: Vec<RetainedArtifactFiles>,
    lease: &CacheMutationLease,
) -> Result<u64> {
    lease.ensure_matches(config)?;
    let cache_root = config.cache.root_dir.clone();
    task::spawn_blocking(move || sweep_unreachable_blocking(&cache_root, &retained))
        .await
        .context("join cache sweep task")?
}

/// Mark-and-sweep over the binary cache directory: walk the narinfo reference
/// graph from every retained artifact's store path, then delete root-level
/// `*.narinfo` files and direct `nar/` members that are no longer reachable.
/// Returns the number of bytes freed.
fn sweep_unreachable_blocking(
    cache_root: &Path,
    retained: &[RetainedArtifactFiles],
) -> Result<u64> {
    let mut live_files: HashSet<PathBuf> = HashSet::new();
    let mut live_nar_urls: HashSet<String> = HashSet::new();
    let mut live_narinfo_hashes: HashSet<String> = HashSet::new();
    let mut retained_narinfo_paths: HashMap<String, PathBuf> = HashMap::new();
    let mut queue: Vec<String> = Vec::new();
    for artifact in retained {
        live_files.insert(artifact.nar_path.clone());
        live_files.insert(artifact.narinfo_path.clone());
        if !artifact.nar_url.is_empty() {
            live_nar_urls.insert(artifact.nar_url.clone());
        }
        if let Some(hash) = store_path_hash(&artifact.store_path) {
            retained_narinfo_paths.insert(hash.clone(), artifact.narinfo_path.clone());
            queue.push(hash);
        }
        for relative in &artifact.evidence_relative_paths {
            live_files.insert(safe_cache_member_path(cache_root, relative)?);
        }
    }
    while let Some(hash) = queue.pop() {
        if !live_narinfo_hashes.insert(hash.clone()) {
            continue;
        }
        let narinfo_path = retained_narinfo_paths
            .get(&hash)
            .cloned()
            .unwrap_or_else(|| cache_root.join(format!("{hash}.narinfo")));
        let contents = fs::read_to_string(&narinfo_path).with_context(|| {
            format!(
                "retained cache closure is missing narinfo {}",
                narinfo_path.display()
            )
        })?;
        for line in contents.lines() {
            if let Some(url) = line.strip_prefix("URL:") {
                live_nar_urls.insert(url.trim().trim_start_matches('/').to_string());
            } else if let Some(references) = line.strip_prefix("References:") {
                for reference in references.split_whitespace() {
                    if let Some(reference_hash) = store_basename_hash(reference) {
                        if !live_narinfo_hashes.contains(&reference_hash) {
                            queue.push(reference_hash);
                        }
                    }
                }
            }
        }
    }
    let mut freed = 0u64;
    if let Ok(entries) = fs::read_dir(cache_root) {
        for entry in entries.flatten() {
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            if !metadata.file_type().is_file() {
                continue;
            }
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let Some(stem) = name.strip_suffix(".narinfo") else {
                continue;
            };
            if live_narinfo_hashes.contains(&stem.to_ascii_lowercase())
                || live_files.contains(&entry.path())
            {
                continue;
            }
            fs::remove_file(entry.path())
                .with_context(|| format!("remove narinfo {}", entry.path().display()))?;
            freed = freed.saturating_add(metadata.len());
        }
    }
    if let Ok(entries) = fs::read_dir(cache_root.join("nar")) {
        for entry in entries.flatten() {
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            if !metadata.file_type().is_file() {
                continue;
            }
            let relative_url = format!("nar/{}", entry.file_name().to_string_lossy());
            if live_nar_urls.contains(&relative_url) || live_files.contains(&entry.path()) {
                continue;
            }
            fs::remove_file(entry.path())
                .with_context(|| format!("remove nar {}", entry.path().display()))?;
            freed = freed.saturating_add(metadata.len());
        }
    }
    let evidence_root = cache_root.join("system-releases");
    let mut directories = Vec::new();
    let mut pending = vec![evidence_root.clone()];
    while let Some(directory) = pending.pop() {
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error).with_context(|| format!("scan {}", directory.display()));
            }
        };
        directories.push(directory.clone());
        for entry in entries {
            let entry = entry?;
            let metadata = fs::symlink_metadata(entry.path())?;
            if metadata.file_type().is_symlink() {
                bail!("System Release cache evidence contains a symlink");
            }
            if metadata.is_dir() {
                pending.push(entry.path());
            } else if metadata.is_file() && !live_files.contains(&entry.path()) {
                fs::remove_file(entry.path()).with_context(|| {
                    format!("remove unreferenced evidence {}", entry.path().display())
                })?;
                freed = freed.saturating_add(metadata.len());
            }
        }
    }
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for directory in directories {
        if directory != evidence_root {
            match fs::remove_dir(&directory) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::DirectoryNotEmpty => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("remove empty {}", directory.display()));
                }
            }
        }
    }
    Ok(freed)
}

/// Sum the compressed bytes (narinfo `FileSize`) of every store path reachable
/// from `store_path` through the cache's narinfo reference graph — the
/// artifact's real on-disk cache footprint, as opposed to `closure_size_bytes`
/// which is the uncompressed installed size. Unreadable narinfos are skipped,
/// so the result is a lower bound on a partially swept cache.
fn closure_file_size_bytes_blocking(cache_root: &Path, store_path: &str) -> i64 {
    let mut visited: HashSet<String> = HashSet::new();
    let mut queue: Vec<String> = store_path_hash(store_path).into_iter().collect();
    let mut total: i64 = 0;
    while let Some(hash) = queue.pop() {
        if !visited.insert(hash.clone()) {
            continue;
        }
        let narinfo_path = cache_root.join(format!("{hash}.narinfo"));
        let Ok(contents) = fs::read_to_string(&narinfo_path) else {
            continue;
        };
        for line in contents.lines() {
            if let Some(file_size) = line.strip_prefix("FileSize:") {
                let parsed = file_size.trim().parse::<i64>().unwrap_or(0);
                total = total.saturating_add(parsed.max(0));
            } else if let Some(references) = line.strip_prefix("References:") {
                for reference in references.split_whitespace() {
                    if let Some(reference_hash) = store_basename_hash(reference) {
                        if !visited.contains(&reference_hash) {
                            queue.push(reference_hash);
                        }
                    }
                }
            }
        }
    }
    total
}

fn store_path_hash(store_path: &str) -> Option<String> {
    store_basename_hash(store_path.rsplit('/').next().unwrap_or(store_path))
}

fn store_basename_hash(basename: &str) -> Option<String> {
    let hash = basename.split('-').next()?;
    (hash.len() == 32 && hash.bytes().all(|byte| byte.is_ascii_alphanumeric()))
        .then(|| hash.to_ascii_lowercase())
}

pub fn cache_base_url(config: &AppConfig) -> String {
    format!("{}/cache", config.public_base_url())
}

async fn cache_disk_usage(config: &AppConfig) -> u64 {
    let root = config.cache.root_dir.clone();
    task::spawn_blocking(move || directory_size_bytes(&root))
        .await
        .unwrap_or(0)
}

fn directory_size_bytes(root: &Path) -> u64 {
    let mut total = 0u64;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            if metadata.file_type().is_dir() {
                stack.push(entry.path());
            } else if metadata.file_type().is_file() {
                total = total.saturating_add(metadata.len());
            }
        }
    }
    total
}

async fn ensure_signing_key(config: &AppConfig) -> Result<String> {
    let private_key = config.cache.private_key_path.clone();
    let public_key = config.cache.public_key_path.clone();
    let key_name = config.cache.signing_key_name.clone();
    task::spawn_blocking(move || ensure_signing_key_blocking(&private_key, &public_key, &key_name))
        .await
        .context("join signing key task")?
}

fn ensure_signing_key_blocking(
    private_key: &Path,
    public_key: &Path,
    key_name: &str,
) -> Result<String> {
    ensure_signing_key_blocking_with_command(
        private_key,
        public_key,
        key_name,
        Path::new("nix-store"),
    )
}

fn ensure_signing_key_blocking_with_command(
    private_key: &Path,
    public_key: &Path,
    key_name: &str,
    nix_store: &Path,
) -> Result<String> {
    if private_key.exists() && public_key.exists() {
        harden_key_permissions(private_key)?;
        return read_public_key(public_key);
    }
    if private_key.exists() || public_key.exists() {
        bail!("cache signing key pair is incomplete");
    }
    let parent = private_key
        .parent()
        .ok_or_else(|| anyhow!("cache private key path has no parent"))?;
    fs::create_dir_all(parent)
        .with_context(|| format!("create cache key directory {}", parent.display()))?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("harden cache key directory {}", parent.display()))?;
    let output = Command::new(nix_store)
        .arg("--generate-binary-cache-key")
        .arg(key_name)
        .arg(private_key)
        .arg(public_key)
        .output()
        .with_context(|| format!("run {} --generate-binary-cache-key", nix_store.display()))?;
    if !output.status.success() {
        bail!(
            "nix-store --generate-binary-cache-key failed: {}",
            bounded_command_error(&output.stderr, private_key)
        );
    }
    harden_key_permissions(private_key)?;
    read_public_key(public_key)
}

fn harden_key_permissions(private_key: &Path) -> Result<()> {
    fs::set_permissions(private_key, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("harden cache private key {}", private_key.display()))
}

fn read_public_key(path: &Path) -> Result<String> {
    let public_key = fs::read_to_string(path)
        .with_context(|| format!("read cache public key {}", path.display()))?
        .trim()
        .to_string();
    if public_key.is_empty()
        || public_key.len() > 512
        || public_key
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace())
    {
        bail!("cache public key has an invalid shape");
    }
    Ok(public_key)
}

fn parse_narinfo(raw: &str) -> Result<ParsedNarInfo> {
    let mut store_path = String::new();
    let mut url = String::new();
    let mut compression = String::new();
    let mut file_hash = String::new();
    let mut file_size = 0i64;
    let mut nar_hash = String::new();
    let mut nar_size = 0i64;
    let mut references = Vec::new();
    let mut signatures = Vec::new();
    for line in raw.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match key {
            "StorePath" => store_path = value.to_string(),
            "URL" => url = value.to_string(),
            "Compression" => compression = value.to_string(),
            "FileHash" => file_hash = value.to_string(),
            "FileSize" => file_size = value.parse().unwrap_or(0),
            "NarHash" => nar_hash = value.to_string(),
            "NarSize" => nar_size = value.parse().unwrap_or(0),
            "References" => {
                references = value
                    .split_whitespace()
                    .map(|reference| {
                        if reference.starts_with("/nix/store/") {
                            reference.to_string()
                        } else {
                            format!("/nix/store/{reference}")
                        }
                    })
                    .collect();
            }
            "Sig" => signatures.push(value.to_string()),
            _ => {}
        }
    }
    if store_path.is_empty()
        || !store_path.starts_with("/nix/store/")
        || url.is_empty()
        || file_hash.is_empty()
        || nar_hash.is_empty()
        || nar_size <= 0
        || signatures.is_empty()
    {
        bail!("generated narinfo omitted required signed cache metadata");
    }
    Ok(ParsedNarInfo {
        store_path,
        url,
        compression,
        file_hash,
        file_size,
        nar_hash,
        nar_size,
        references,
        signatures,
    })
}

fn read_nix_cache_info(cache_dir: &Path) -> Result<NixCacheInfo> {
    let path = cache_dir.join("nix-cache-info");
    let raw =
        fs::read_to_string(&path).with_context(|| format!("read generated {}", path.display()))?;
    parse_nix_cache_info(&raw)
}

fn parse_nix_cache_info(raw: &str) -> Result<NixCacheInfo> {
    let mut store_dir = String::new();
    let mut want_mass_query = None;
    let mut priority = None;

    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            bail!("generated nix-cache-info contains an invalid line");
        };
        let value = value.trim();
        match key {
            "StoreDir" => store_dir = value.to_string(),
            "WantMassQuery" => {
                want_mass_query = Some(match value {
                    "0" => false,
                    "1" => true,
                    _ => bail!("generated nix-cache-info has invalid WantMassQuery"),
                });
            }
            "Priority" => {
                priority = Some(
                    value
                        .parse::<u64>()
                        .context("generated nix-cache-info has invalid Priority")?,
                );
            }
            _ => {}
        }
    }

    if store_dir != "/nix/store" {
        bail!("generated nix-cache-info did not advertise /nix/store");
    }
    Ok(NixCacheInfo {
        store_dir,
        want_mass_query: want_mass_query.unwrap_or(false),
        priority,
    })
}

fn narinfo_filename_for_store_path(store_path: &str) -> Result<String> {
    let name = Path::new(store_path)
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| anyhow!("store path has no safe basename"))?;
    let Some((hash, _rest)) = name.split_once('-') else {
        bail!("store path basename did not include a Nix hash prefix");
    };
    if hash.len() != 32 || !hash.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        bail!("store path basename did not include a safe Nix hash prefix");
    }
    Ok(format!("{hash}.narinfo"))
}

fn safe_cache_member_path(root: &Path, relative: &str) -> Result<PathBuf> {
    if relative.starts_with('/') || relative.contains('\\') {
        bail!("cache member path is not relative");
    }
    let mut out = root.to_path_buf();
    for part in relative.split('/') {
        if part.is_empty() || part == "." || part == ".." {
            bail!("cache member path contains traversal");
        }
        out.push(part);
    }
    Ok(out)
}

fn public_key_fingerprint(public_key: &str) -> String {
    // Cybex Manage validates this as the full 64-char sha256 hex of the
    // decoded ed25519 key material ("name:base64" -> sha256 of the decoded
    // 32 bytes), and rejects the whole forge report when it differs.
    public_key
        .split_once(':')
        .and_then(|(_, material)| BASE64_STANDARD.decode(material).ok())
        .filter(|bytes| bytes.len() == 32)
        .map(|bytes| sha256_hex(&bytes))
        .unwrap_or_default()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn sanitize_error(err: &anyhow::Error) -> String {
    redact_sensitive_key_values(&err.to_string())
        .chars()
        .take(512)
        .collect()
}

fn bounded_command_error(stderr: &[u8], private_key: &Path) -> String {
    redact_sensitive_key_values(&String::from_utf8_lossy(stderr))
        .replace(&private_key.display().to_string(), "[cache-private-key]")
        .chars()
        .take(1000)
        .collect::<String>()
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_temp_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "cybex-forge-cache-{label}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn write_test_cache_artifact(
        cache_root: &Path,
        marker: char,
        name: &str,
        size_bytes: usize,
    ) -> (String, PathBuf, PathBuf) {
        let store_hash = marker.to_string().repeat(32);
        let artifact_hash = marker.to_string().repeat(64);
        let nar_url = format!("nar/{name}.nar.xz");
        let nar_path = cache_root.join(&nar_url);
        let narinfo_path = cache_root.join(format!("{store_hash}.narinfo"));
        fs::create_dir_all(cache_root.join("nar")).unwrap();
        fs::write(&nar_path, vec![marker as u8; size_bytes]).unwrap();
        fs::write(
            &narinfo_path,
            format!(
                "StorePath: /nix/store/{store_hash}-{name}\nURL: {nar_url}\nCompression: xz\nFileHash: sha256:{name}\nFileSize: {size_bytes}\nNarHash: sha256:{name}nar\nNarSize: {size_bytes}\nReferences: \nSig: cybex-forge-cache:test\n"
            ),
        )
        .unwrap();
        (artifact_hash, nar_path, narinfo_path)
    }

    async fn record_test_cache_artifact(
        pool: &SqlitePool,
        cache_root: &Path,
        marker: char,
        name: &str,
        size_bytes: i64,
    ) {
        let store_hash = marker.to_string().repeat(32);
        db::create_cache_artifact(
            pool,
            crate::models::CreateCacheArtifactRequest {
                artifact_type: "nixos_closure".to_string(),
                hash: marker.to_string().repeat(64),
                size_bytes,
                path: cache_root
                    .join(format!("nar/{name}.nar.xz"))
                    .display()
                    .to_string(),
                store_path: Some(format!("/nix/store/{store_hash}-{name}")),
                narinfo_path: Some(
                    cache_root
                        .join(format!("{store_hash}.narinfo"))
                        .display()
                        .to_string(),
                ),
                nar_url: Some(format!("nar/{name}.nar.xz")),
                file_hash: Some(format!("sha256:{name}")),
                nar_hash: Some(format!("sha256:{name}nar")),
                nar_size_bytes: Some(size_bytes),
                closure_size_bytes: Some(size_bytes),
                closure_file_size_bytes: Some(size_bytes),
                compression: Some("xz".to_string()),
                references: Some(json!([])),
                serving_url: Some(format!("https://forge.test/cache/nar/{name}.nar.xz")),
                source_build_job_id: None,
                cache_metadata: None,
            },
        )
        .await
        .unwrap();
    }

    #[test]
    fn closure_file_size_sums_unique_reachable_narinfos() {
        let root = test_temp_dir("closure-file-size");
        let hash_root = "a".repeat(32);
        let hash_dep = "b".repeat(32);
        let hash_shared = "c".repeat(32);
        let hash_missing = "d".repeat(32);
        fs::write(
            root.join(format!("{hash_root}.narinfo")),
            format!(
                "StorePath: /nix/store/{hash_root}-root\nFileSize: 100\nReferences: {hash_dep}-dep {hash_shared}-shared {hash_root}-root\n"
            ),
        )
        .unwrap();
        fs::write(
            root.join(format!("{hash_dep}.narinfo")),
            format!(
                "StorePath: /nix/store/{hash_dep}-dep\nFileSize: 40\nReferences: {hash_shared}-shared {hash_missing}-missing\n"
            ),
        )
        .unwrap();
        fs::write(
            root.join(format!("{hash_shared}.narinfo")),
            format!("StorePath: /nix/store/{hash_shared}-shared\nFileSize: 7\nReferences: \n"),
        )
        .unwrap();

        // Shared dependency counted once, self-reference ignored, missing
        // narinfo skipped: 100 + 40 + 7.
        assert_eq!(
            closure_file_size_bytes_blocking(&root, &format!("/nix/store/{hash_root}-root")),
            147
        );
        assert_eq!(
            closure_file_size_bytes_blocking(&root, "not-a-store-path"),
            0
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn initialize_cache_root_writes_valid_nix_cache_info() {
        let root = test_temp_dir("init-fresh");
        let cache_dir = root.join("cache");

        initialize_cache_root_blocking(&cache_dir).unwrap();

        let parsed = read_nix_cache_info(&cache_dir).unwrap();
        assert_eq!(parsed.store_dir, "/nix/store");
        assert!(parsed.want_mass_query);
        assert_eq!(parsed.priority, Some(30));
        assert!(!cache_dir.join(".nix-cache-info.tmp").exists());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn initialize_cache_root_preserves_existing_nix_cache_info() {
        let root = test_temp_dir("init-existing");
        let existing = "StoreDir: /nix/store\nWantMassQuery: 0\nPriority: 50\n";
        fs::write(root.join("nix-cache-info"), existing).unwrap();

        initialize_cache_root_blocking(&root).unwrap();

        assert_eq!(
            fs::read_to_string(root.join("nix-cache-info")).unwrap(),
            existing
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn initialize_cache_root_rejects_corrupt_existing_nix_cache_info() {
        let root = test_temp_dir("init-corrupt");
        fs::write(root.join("nix-cache-info"), "StoreDir: /tmp/store\n").unwrap();

        let err = initialize_cache_root_blocking(&root).unwrap_err();
        assert!(err.to_string().contains("/nix/store"));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn sanitize_error_redacts_entire_secret_key_value() {
        let err =
            anyhow!("copy failed for file:///cache?secret-key=/tmp/cache.key&compression=zstd");
        let message = sanitize_error(&err);

        assert!(message.contains("secret-key=[REDACTED]&compression=zstd"));
        assert!(!message.contains("/tmp/cache.key"));
    }

    #[test]
    fn bounded_command_error_redacts_secret_key_and_private_key_path() {
        let private_key = PathBuf::from("/tmp/cache.key");
        let message = bounded_command_error(
            b"copy file:///cache?secret-key=/tmp/cache.key&compression=zstd failed /tmp/cache.key",
            &private_key,
        );

        assert!(message.contains("secret-key=[REDACTED]&compression=zstd"));
        assert!(message.contains("[cache-private-key]"));
        assert!(!message.contains("/tmp/cache.key"));
    }

    #[test]
    fn narinfo_parser_requires_signature() {
        let err = parse_narinfo(
            "StorePath: /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-test\n\
             URL: nar/abc.nar.xz\n\
             FileHash: sha256:abc\n\
             NarHash: sha256:def\n\
             NarSize: 42\n",
        )
        .unwrap_err();
        assert!(err.to_string().contains("required signed cache metadata"));
    }

    #[test]
    fn nix_cache_info_requires_nix_store_metadata() {
        let parsed = parse_nix_cache_info(
            "StoreDir: /nix/store\n\
             WantMassQuery: 1\n\
             Priority: 40\n",
        )
        .unwrap();
        assert_eq!(parsed.store_dir, "/nix/store");
        assert!(parsed.want_mass_query);
        assert_eq!(parsed.priority, Some(40));

        let err = parse_nix_cache_info("StoreDir: /tmp/store\nWantMassQuery: 1\n").unwrap_err();
        assert!(err.to_string().contains("/nix/store"));

        let parsed = parse_nix_cache_info("StoreDir: /nix/store\n").unwrap();
        assert!(!parsed.want_mass_query);
        assert_eq!(parsed.priority, None);
    }

    #[test]
    fn signing_key_generation_hardens_private_key_and_reports_public_key() {
        let root = test_temp_dir("signing-key");
        let fake_nix_store = root.join("nix-store");
        fs::write(
            &fake_nix_store,
            "#!/bin/sh\n\
             set -eu\n\
             if [ \"$1\" != \"--generate-binary-cache-key\" ]; then exit 2; fi\n\
             printf '%s\\n' \"$2-secret\" > \"$3\"\n\
             printf '%s\\n' \"$2:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\" > \"$4\"\n",
        )
        .unwrap();
        fs::set_permissions(&fake_nix_store, fs::Permissions::from_mode(0o755)).unwrap();
        let private_key = root.join("keys/cache-priv-key.pem");
        let public_key = root.join("keys/cache-pub-key.pem");

        let public = ensure_signing_key_blocking_with_command(
            &private_key,
            &public_key,
            "cybex-forge-cache",
            &fake_nix_store,
        )
        .unwrap();

        assert!(public.starts_with("cybex-forge-cache:"));
        let fingerprint = public_key_fingerprint(&public);
        assert_eq!(fingerprint.len(), 64);
        assert!(fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(
            fs::metadata(&private_key).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(private_key.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn directory_size_counts_nested_files_and_missing_root_is_zero() {
        let root = test_temp_dir("disk-usage");
        fs::create_dir_all(root.join("nar/deep")).unwrap();
        fs::write(root.join("top.narinfo"), vec![0u8; 10]).unwrap();
        fs::write(root.join("nar/member.nar.xz"), vec![0u8; 100]).unwrap();
        fs::write(root.join("nar/deep/other.nar.xz"), vec![0u8; 1000]).unwrap();

        assert_eq!(directory_size_bytes(&root), 1110);
        assert_eq!(directory_size_bytes(&root.join("does-not-exist")), 0);
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn cache_member_paths_reject_traversal() {
        let root = Path::new("/tmp/cache");
        assert!(safe_cache_member_path(root, "nar/abc.nar.xz").is_ok());
        assert!(safe_cache_member_path(root, "../abc.nar.xz").is_err());
        assert!(safe_cache_member_path(root, "/nar/abc.nar.xz").is_err());
    }

    #[test]
    fn verified_release_retention_keeps_full_closure_and_evidence() {
        let cache_root = test_temp_dir("verified-release-retention");
        fs::create_dir_all(cache_root.join("nar")).unwrap();
        let hash_root = "a".repeat(32);
        let hash_dep = "b".repeat(32);
        let hash_stale = "c".repeat(32);
        let root_store = format!("/nix/store/{hash_root}-system");
        fs::write(
            cache_root.join(format!("{hash_root}.narinfo")),
            format!(
                "StorePath: {root_store}\nURL: nar/root.nar.xz\nReferences: {hash_dep}-dependency\n"
            ),
        )
        .unwrap();
        fs::write(
            cache_root.join(format!("{hash_dep}.narinfo")),
            format!(
                "StorePath: /nix/store/{hash_dep}-dependency\nURL: nar/dependency.nar.xz\nReferences: \n"
            ),
        )
        .unwrap();
        fs::write(
            cache_root.join(format!("{hash_stale}.narinfo")),
            format!(
                "StorePath: /nix/store/{hash_stale}-stale\nURL: nar/stale.nar.xz\nReferences: \n"
            ),
        )
        .unwrap();
        for name in ["root", "dependency", "stale"] {
            fs::write(cache_root.join(format!("nar/{name}.nar.xz")), name).unwrap();
        }
        let evidence_dir = cache_root.join("system-releases/org/release/variant/artifact");
        fs::create_dir_all(&evidence_dir).unwrap();
        fs::write(evidence_dir.join("closure.json"), "closure").unwrap();
        fs::write(evidence_dir.join("provenance-envelope.json"), "provenance").unwrap();
        fs::write(evidence_dir.join("stale.json"), "stale").unwrap();
        let retained = vec![RetainedArtifactFiles {
            store_path: root_store,
            nar_path: cache_root.join("nar/root.nar.xz"),
            narinfo_path: cache_root.join(format!("{hash_root}.narinfo")),
            nar_url: "nar/root.nar.xz".to_string(),
            evidence_relative_paths: vec![
                "system-releases/org/release/variant/artifact/closure.json".to_string(),
                "system-releases/org/release/variant/artifact/provenance-envelope.json".to_string(),
            ],
        }];

        sweep_unreachable_blocking(&cache_root, &retained).unwrap();

        assert!(cache_root.join(format!("{hash_root}.narinfo")).exists());
        assert!(cache_root.join(format!("{hash_dep}.narinfo")).exists());
        assert!(cache_root.join("nar/root.nar.xz").exists());
        assert!(cache_root.join("nar/dependency.nar.xz").exists());
        assert!(evidence_dir.join("closure.json").exists());
        assert!(evidence_dir.join("provenance-envelope.json").exists());
        assert!(!cache_root.join(format!("{hash_stale}.narinfo")).exists());
        assert!(!cache_root.join("nar/stale.nar.xz").exists());
        assert!(!evidence_dir.join("stale.json").exists());
        fs::remove_dir_all(cache_root).unwrap();
    }

    #[test]
    fn verified_release_retention_fails_closed_on_incomplete_or_symlinked_state() {
        let cache_root = test_temp_dir("verified-release-retention-invalid");
        fs::create_dir_all(cache_root.join("nar")).unwrap();
        let hash_root = "a".repeat(32);
        let hash_missing = "b".repeat(32);
        let root_store = format!("/nix/store/{hash_root}-system");
        fs::write(
            cache_root.join(format!("{hash_root}.narinfo")),
            format!(
                "StorePath: {root_store}\nURL: nar/root.nar.xz\nReferences: {hash_missing}-missing\n"
            ),
        )
        .unwrap();
        fs::write(cache_root.join("nar/root.nar.xz"), "root").unwrap();
        let retained = vec![RetainedArtifactFiles {
            store_path: root_store,
            nar_path: cache_root.join("nar/root.nar.xz"),
            narinfo_path: cache_root.join(format!("{hash_root}.narinfo")),
            nar_url: "nar/root.nar.xz".to_string(),
            evidence_relative_paths: Vec::new(),
        }];
        assert!(sweep_unreachable_blocking(&cache_root, &retained).is_err());
        assert!(cache_root.join("nar/root.nar.xz").exists());

        fs::write(
            cache_root.join(format!("{hash_missing}.narinfo")),
            format!(
                "StorePath: /nix/store/{hash_missing}-missing\nURL: nar/missing.nar.xz\nReferences: \n"
            ),
        )
        .unwrap();
        fs::write(cache_root.join("nar/missing.nar.xz"), "missing").unwrap();
        fs::create_dir_all(cache_root.join("system-releases")).unwrap();
        std::os::unix::fs::symlink(
            cache_root.join("nar/root.nar.xz"),
            cache_root.join("system-releases/unsafe"),
        )
        .unwrap();
        assert!(sweep_unreachable_blocking(&cache_root, &retained).is_err());
        fs::remove_dir_all(cache_root).unwrap();
    }

    #[tokio::test]
    async fn status_report_includes_public_signing_key() {
        let pool = db::connect_with_url("sqlite::memory:").await.unwrap();
        db::migrate(&pool).await.unwrap();
        let root = test_temp_dir("status-report");
        let mut config = AppConfig::default();
        config.cache.root_dir = root.join("cache");
        fs::create_dir_all(config.cache.root_dir.join("nar")).unwrap();
        fs::write(config.cache.root_dir.join("nix-cache-info"), vec![0u8; 40]).unwrap();
        fs::write(
            config.cache.root_dir.join("nar/closure-member.nar.xz"),
            vec![0u8; 4096],
        )
        .unwrap();
        config.cache.private_key_path = root.join("cache-priv-key.pem");
        config.cache.public_key_path = root.join("cache-pub-key.pem");
        fs::write(&config.cache.private_key_path, "private").unwrap();
        fs::write(
            &config.cache.public_key_path,
            "cybex-forge-cache:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
        )
        .unwrap();
        fs::set_permissions(
            &config.cache.private_key_path,
            fs::Permissions::from_mode(0o640),
        )
        .unwrap();

        let report = status_report(&config, &pool).await;

        assert_eq!(report.status, "ready");
        assert_eq!(report.total_size_bytes, 4136);
        assert!(report.public_key.starts_with("cybex-forge-cache:"));
        assert_eq!(report.public_key_fingerprint.len(), 64);
        assert_eq!(
            fs::metadata(&config.cache.private_key_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        fs::remove_dir_all(root).ok();
    }

    #[tokio::test]
    async fn retention_sweeps_unreachable_closure_members_and_keeps_shared_ones() {
        let pool = db::connect_with_url("sqlite::memory:").await.unwrap();
        db::migrate(&pool).await.unwrap();
        db::replace_managed_cache_protections(&pool, &[], true)
            .await
            .unwrap();
        let root = test_temp_dir("closure-gc");
        let cache_root = root.join("cache");
        fs::create_dir_all(cache_root.join("nar")).unwrap();
        fs::set_permissions(&cache_root, fs::Permissions::from_mode(0o755)).unwrap();

        let mut config = AppConfig::default();
        config.cache.root_dir = cache_root.clone();
        config.cache.mutation_lock_path = root.join("cache-mutation.lock");
        config.cache.max_bytes = 1;
        config.cache.retain_recent_builds = 1;

        let hash_a = "a".repeat(32);
        let hash_b = "b".repeat(32);
        let hash_shared = "d".repeat(32);
        let hash_unique = "e".repeat(32);
        fs::write(
            cache_root.join(format!("{hash_a}.narinfo")),
            format!(
                "StorePath: /nix/store/{hash_a}-root-a\nURL: nar/root-a.nar.xz\nReferences: {hash_shared}-shared {hash_unique}-unique\n"
            ),
        )
        .unwrap();
        fs::write(
            cache_root.join(format!("{hash_b}.narinfo")),
            format!(
                "StorePath: /nix/store/{hash_b}-root-b\nURL: nar/root-b.nar.xz\nReferences: {hash_shared}-shared\n"
            ),
        )
        .unwrap();
        fs::write(
            cache_root.join(format!("{hash_shared}.narinfo")),
            format!("StorePath: /nix/store/{hash_shared}-shared\nURL: nar/shared.nar.xz\n"),
        )
        .unwrap();
        fs::write(
            cache_root.join(format!("{hash_unique}.narinfo")),
            format!("StorePath: /nix/store/{hash_unique}-unique\nURL: nar/unique.nar.xz\n"),
        )
        .unwrap();
        for nar in ["root-a", "root-b", "shared", "unique"] {
            fs::write(cache_root.join(format!("nar/{nar}.nar.xz")), vec![0u8; 64]).unwrap();
        }

        db::upsert_managed_build_job(
            &pool,
            "active-job",
            "nixos_closure",
            None,
            Some("desktop_experience"),
            Some("x86_64-linux"),
            "revision-1",
            &"a".repeat(64),
            None,
        )
        .await
        .unwrap();

        for (hash, name, source) in [
            (&hash_a, "root-a", None),
            (&hash_b, "root-b", Some("active-job".to_string())),
        ] {
            db::create_cache_artifact(
                &pool,
                crate::models::CreateCacheArtifactRequest {
                    artifact_type: "nixos_closure".to_string(),
                    hash: hash.repeat(2),
                    size_bytes: 64,
                    path: cache_root
                        .join(format!("nar/{name}.nar.xz"))
                        .display()
                        .to_string(),
                    store_path: Some(format!("/nix/store/{hash}-{name}")),
                    narinfo_path: Some(
                        cache_root
                            .join(format!("{hash}.narinfo"))
                            .display()
                            .to_string(),
                    ),
                    nar_url: Some(format!("nar/{name}.nar.xz")),
                    file_hash: Some(format!("sha256:{name}")),
                    nar_hash: Some(format!("sha256:{name}nar")),
                    nar_size_bytes: Some(64),
                    closure_size_bytes: Some(192),
                    closure_file_size_bytes: None,
                    compression: Some("xz".to_string()),
                    references: Some(json!([])),
                    serving_url: Some(format!("http://forge.example/cache/nar/{name}.nar.xz")),
                    source_build_job_id: source,
                    cache_metadata: None,
                },
            )
            .await
            .unwrap();
        }

        enforce_retention(&pool, &config).await.unwrap();

        assert!(!cache_root.join(format!("{hash_a}.narinfo")).exists());
        assert!(!cache_root.join("nar/root-a.nar.xz").exists());
        assert!(!cache_root.join(format!("{hash_unique}.narinfo")).exists());
        assert!(!cache_root.join("nar/unique.nar.xz").exists());
        assert!(cache_root.join(format!("{hash_b}.narinfo")).exists());
        assert!(cache_root.join("nar/root-b.nar.xz").exists());
        assert!(cache_root.join(format!("{hash_shared}.narinfo")).exists());
        assert!(cache_root.join("nar/shared.nar.xz").exists());
        let artifacts = db::list_cache_artifacts(&pool).await.unwrap();
        assert_eq!(artifacts.len(), 1);
        assert_eq!(
            artifacts[0].source_build_job_id.as_deref(),
            Some("active-job")
        );
        fs::remove_dir_all(root).ok();
    }

    #[tokio::test]
    async fn retention_deletes_unprotected_cache_rows_and_files() {
        let pool = db::connect_with_url("sqlite::memory:").await.unwrap();
        db::migrate(&pool).await.unwrap();
        db::replace_managed_cache_protections(&pool, &[], true)
            .await
            .unwrap();
        let root = test_temp_dir("retention");
        let cache_root = root.join("cache");
        fs::create_dir_all(cache_root.join("nar")).unwrap();
        fs::set_permissions(&cache_root, fs::Permissions::from_mode(0o755)).unwrap();

        let mut config = AppConfig::default();
        config.cache.root_dir = cache_root.clone();
        config.cache.mutation_lock_path = root.join("cache-mutation.lock");
        config.cache.max_bytes = 25;
        config.cache.retain_recent_builds = 1;

        db::upsert_managed_build_job(
            &pool,
            "active-job",
            "nixos_closure",
            None,
            Some("desktop_experience"),
            Some("x86_64-linux"),
            "revision-1",
            &"a".repeat(64),
            None,
        )
        .await
        .unwrap();

        let protected_nar = cache_root.join("nar/protected.nar.xz");
        let protected_narinfo = cache_root.join("protected.narinfo");
        let unprotected_nar = cache_root.join("nar/unprotected.nar.xz");
        let unprotected_narinfo = cache_root.join("unprotected.narinfo");
        fs::write(&protected_nar, vec![1u8; 20]).unwrap();
        fs::write(&protected_narinfo, "protected").unwrap();
        fs::write(&unprotected_nar, vec![2u8; 20]).unwrap();
        fs::write(&unprotected_narinfo, "unprotected").unwrap();

        db::create_cache_artifact(
            &pool,
            crate::models::CreateCacheArtifactRequest {
                artifact_type: "nixos_closure".to_string(),
                hash: "b".repeat(64),
                size_bytes: 20,
                path: protected_nar.display().to_string(),
                store_path: Some(
                    "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-protected".to_string(),
                ),
                narinfo_path: Some(protected_narinfo.display().to_string()),
                nar_url: Some("nar/protected.nar.xz".to_string()),
                file_hash: Some("sha256:protected".to_string()),
                nar_hash: Some("sha256:protectednar".to_string()),
                nar_size_bytes: Some(20),
                closure_size_bytes: Some(20),
                closure_file_size_bytes: None,
                compression: Some("xz".to_string()),
                references: Some(json!([
                    "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-protected"
                ])),
                serving_url: Some("http://forge.example/cache/nar/protected.nar.xz".to_string()),
                source_build_job_id: Some("active-job".to_string()),
                cache_metadata: None,
            },
        )
        .await
        .unwrap();
        db::create_cache_artifact(
            &pool,
            crate::models::CreateCacheArtifactRequest {
                artifact_type: "nixos_closure".to_string(),
                hash: "c".repeat(64),
                size_bytes: 20,
                path: unprotected_nar.display().to_string(),
                store_path: Some(
                    "/nix/store/cccccccccccccccccccccccccccccccc-unprotected".to_string(),
                ),
                narinfo_path: Some(unprotected_narinfo.display().to_string()),
                nar_url: Some("nar/unprotected.nar.xz".to_string()),
                file_hash: Some("sha256:unprotected".to_string()),
                nar_hash: Some("sha256:unprotectednar".to_string()),
                nar_size_bytes: Some(20),
                closure_size_bytes: Some(20),
                closure_file_size_bytes: None,
                compression: Some("xz".to_string()),
                references: Some(json!([
                    "/nix/store/cccccccccccccccccccccccccccccccc-unprotected"
                ])),
                serving_url: Some("http://forge.example/cache/nar/unprotected.nar.xz".to_string()),
                source_build_job_id: None,
                cache_metadata: None,
            },
        )
        .await
        .unwrap();

        enforce_retention(&pool, &config).await.unwrap();

        assert!(protected_nar.exists());
        assert!(protected_narinfo.exists());
        assert!(!unprotected_nar.exists());
        assert!(!unprotected_narinfo.exists());
        let artifacts = db::list_cache_artifacts(&pool).await.unwrap();
        assert_eq!(artifacts.len(), 1);
        assert_eq!(
            artifacts[0].source_build_job_id.as_deref(),
            Some("active-job")
        );
        fs::remove_dir_all(root).ok();
    }

    #[tokio::test]
    async fn remove_artifacts_by_key_deletes_rows_and_files() {
        let pool = db::connect_with_url("sqlite::memory:").await.unwrap();
        db::migrate(&pool).await.unwrap();
        db::replace_managed_cache_protections(&pool, &[], true)
            .await
            .unwrap();
        let root = test_temp_dir("remove-by-key");
        let cache_root = root.join("cache");
        fs::create_dir_all(cache_root.join("nar")).unwrap();
        fs::set_permissions(&cache_root, fs::Permissions::from_mode(0o755)).unwrap();

        let mut config = AppConfig::default();
        config.cache.root_dir = cache_root.clone();
        config.cache.mutation_lock_path = root.join("cache-mutation.lock");

        let kept_nar = cache_root.join("nar/kept.nar.xz");
        let kept_narinfo = cache_root.join("kept.narinfo");
        let doomed_nar = cache_root.join("nar/doomed.nar.xz");
        let doomed_narinfo = cache_root.join("doomed.narinfo");
        fs::write(&kept_nar, vec![1u8; 20]).unwrap();
        fs::write(&kept_narinfo, "kept").unwrap();
        fs::write(&doomed_nar, vec![2u8; 20]).unwrap();
        fs::write(&doomed_narinfo, "doomed").unwrap();

        for (hash, name, nar, narinfo) in [
            ("b", "kept", &kept_nar, &kept_narinfo),
            ("c", "doomed", &doomed_nar, &doomed_narinfo),
        ] {
            db::create_cache_artifact(
                &pool,
                crate::models::CreateCacheArtifactRequest {
                    artifact_type: "nixos_closure".to_string(),
                    hash: hash.repeat(64),
                    size_bytes: 20,
                    path: nar.display().to_string(),
                    store_path: Some(format!("/nix/store/{}-{name}", hash.repeat(32))),
                    narinfo_path: Some(narinfo.display().to_string()),
                    nar_url: Some(format!("nar/{name}.nar.xz")),
                    file_hash: Some(format!("sha256:{name}")),
                    nar_hash: Some(format!("sha256:{name}nar")),
                    nar_size_bytes: Some(20),
                    closure_size_bytes: Some(20),
                    closure_file_size_bytes: None,
                    compression: Some("xz".to_string()),
                    references: Some(json!([])),
                    serving_url: Some(format!("http://forge.example/cache/nar/{name}.nar.xz")),
                    source_build_job_id: None,
                    cache_metadata: None,
                },
            )
            .await
            .unwrap();
        }

        let inventory = db::cache_inventory_state(&pool).await.unwrap();
        let outcome = remove_artifacts_by_key(
            &pool,
            &config,
            &db::CacheInventoryFence {
                instance_id: inventory.instance_id,
                generation: inventory.generation,
            },
            &[
                ("nixos_closure".to_string(), "c".repeat(64)),
                ("nixos_closure".to_string(), "f".repeat(64)),
            ],
        )
        .await
        .unwrap();
        assert!(outcome.inventory_matched);
        assert_eq!(outcome.deleted.len(), 1);
        assert_eq!(outcome.missing.len(), 1);

        assert!(kept_nar.exists());
        assert!(kept_narinfo.exists());
        assert!(!doomed_nar.exists());
        assert!(!doomed_narinfo.exists());
        let artifacts = db::list_cache_artifacts(&pool).await.unwrap();
        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].hash, "b".repeat(64));
        fs::remove_dir_all(root).ok();
    }

    #[tokio::test]
    async fn remove_artifacts_by_key_honors_protection_and_inventory_fence() {
        let pool = db::connect_with_url("sqlite::memory:").await.unwrap();
        db::migrate(&pool).await.unwrap();
        let root = test_temp_dir("remove-protected-by-key");
        let cache_root = root.join("cache");
        fs::create_dir_all(cache_root.join("nar")).unwrap();
        fs::set_permissions(&cache_root, fs::Permissions::from_mode(0o755)).unwrap();
        let mut config = AppConfig::default();
        config.cache.root_dir = cache_root.clone();
        config.cache.mutation_lock_path = root.join("cache-mutation.lock");
        let nar = cache_root.join("nar/protected.nar.xz");
        let narinfo = cache_root.join("protected.narinfo");
        fs::write(&nar, vec![7u8; 20]).unwrap();
        fs::write(&narinfo, "protected").unwrap();
        let hash = "d".repeat(64);
        db::create_cache_artifact(
            &pool,
            crate::models::CreateCacheArtifactRequest {
                artifact_type: "nixos_closure".to_string(),
                hash: hash.clone(),
                size_bytes: 20,
                path: nar.display().to_string(),
                store_path: Some(format!("/nix/store/{}-protected", "d".repeat(32))),
                narinfo_path: Some(narinfo.display().to_string()),
                nar_url: Some("nar/protected.nar.xz".to_string()),
                file_hash: Some("sha256:protected".to_string()),
                nar_hash: Some("sha256:protectednar".to_string()),
                nar_size_bytes: Some(20),
                closure_size_bytes: Some(20),
                closure_file_size_bytes: None,
                compression: Some("xz".to_string()),
                references: Some(json!([])),
                serving_url: Some("http://forge.example/cache/nar/protected.nar.xz".to_string()),
                source_build_job_id: None,
                cache_metadata: None,
            },
        )
        .await
        .unwrap();
        db::replace_managed_cache_protections(
            &pool,
            &[("nixos_closure".to_string(), hash.clone())],
            true,
        )
        .await
        .unwrap();
        let current = db::cache_inventory_state(&pool).await.unwrap();
        let stale = db::CacheInventoryFence {
            instance_id: current.instance_id.clone(),
            generation: current.generation - 1,
        };
        let stale_outcome = remove_artifacts_by_key(
            &pool,
            &config,
            &stale,
            &[("nixos_closure".into(), hash.clone())],
        )
        .await
        .unwrap();
        assert!(!stale_outcome.inventory_matched);
        assert!(nar.exists());

        let exact = db::CacheInventoryFence {
            instance_id: current.instance_id,
            generation: current.generation,
        };
        let protected_outcome = remove_artifacts_by_key(
            &pool,
            &config,
            &exact,
            &[("nixos_closure".into(), hash.clone())],
        )
        .await
        .unwrap();
        assert!(protected_outcome.inventory_matched);
        assert_eq!(
            protected_outcome.protected,
            vec![("nixos_closure".into(), hash)]
        );
        assert!(protected_outcome.deleted.is_empty());
        assert!(nar.exists());
        assert!(narinfo.exists());
        assert_eq!(db::list_cache_artifacts(&pool).await.unwrap().len(), 1);
        fs::remove_dir_all(root).ok();
    }

    #[tokio::test]
    async fn sweep_waits_for_publication_inventory_commit() {
        let pool = db::connect_with_url("sqlite::memory:").await.unwrap();
        db::migrate(&pool).await.unwrap();
        let root = test_temp_dir("publication-sweep-lease");
        let cache_root = root.join("cache");
        fs::create_dir_all(&cache_root).unwrap();
        fs::set_permissions(&cache_root, fs::Permissions::from_mode(0o755)).unwrap();
        let mut config = AppConfig::default();
        config.cache.root_dir = cache_root.clone();
        config.cache.mutation_lock_path = root.join("cache-mutation.lock");

        let lease = acquire_mutation_lease(&config).await.unwrap();
        let (_, nar_path, narinfo_path) =
            write_test_cache_artifact(&cache_root, 'a', "publishing", 32);
        let task_pool = pool.clone();
        let task_config = config.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let mut sweep = tokio::spawn(async move {
            started_tx.send(()).unwrap();
            sweep_to_recorded_artifacts(&task_pool, &task_config).await
        });
        started_rx.await.unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), &mut sweep)
                .await
                .is_err(),
            "sweep bypassed the publisher's cache mutation lease"
        );

        record_test_cache_artifact(&pool, &cache_root, 'a', "publishing", 32).await;
        drop(lease);
        tokio::time::timeout(std::time::Duration::from_secs(5), sweep)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(nar_path.exists());
        assert!(narinfo_path.exists());
        fs::remove_dir_all(root).ok();
    }

    #[tokio::test]
    async fn nonblocking_cache_lease_skips_active_publication() {
        let root = test_temp_dir("nonblocking-publication-lease");
        let cache_root = root.join("cache");
        fs::create_dir_all(&cache_root).unwrap();
        fs::set_permissions(&cache_root, fs::Permissions::from_mode(0o755)).unwrap();
        let mut config = AppConfig::default();
        config.cache.root_dir = cache_root;
        config.cache.mutation_lock_path = root.join("cache-mutation.lock");

        let publication = acquire_mutation_lease(&config).await.unwrap();
        assert!(try_acquire_mutation_lease(&config).await.unwrap().is_none());
        drop(publication);
        assert!(try_acquire_mutation_lease(&config).await.unwrap().is_some());
        fs::remove_dir_all(root).ok();
    }

    #[tokio::test]
    async fn retention_requeries_protections_after_waiting_for_publication() {
        let pool = db::connect_with_url("sqlite::memory:").await.unwrap();
        db::migrate(&pool).await.unwrap();
        let root = test_temp_dir("publication-retention-lease");
        let cache_root = root.join("cache");
        fs::create_dir_all(&cache_root).unwrap();
        fs::set_permissions(&cache_root, fs::Permissions::from_mode(0o755)).unwrap();
        let mut config = AppConfig::default();
        config.cache.root_dir = cache_root.clone();
        config.cache.mutation_lock_path = root.join("cache-mutation.lock");
        config.cache.max_bytes = 1;
        config.cache.retain_recent_builds = 0;

        let (_, old_nar, old_narinfo) = write_test_cache_artifact(&cache_root, 'a', "old", 32);
        record_test_cache_artifact(&pool, &cache_root, 'a', "old", 32).await;

        let lease = acquire_mutation_lease(&config).await.unwrap();
        let (new_hash, new_nar, new_narinfo) =
            write_test_cache_artifact(&cache_root, 'b', "protected-new", 32);
        let task_pool = pool.clone();
        let task_config = config.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let mut retention = tokio::spawn(async move {
            started_tx.send(()).unwrap();
            enforce_retention(&task_pool, &task_config).await
        });
        started_rx.await.unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), &mut retention)
                .await
                .is_err(),
            "retention bypassed the publisher's cache mutation lease"
        );

        record_test_cache_artifact(&pool, &cache_root, 'b', "protected-new", 32).await;
        db::replace_managed_cache_protections(
            &pool,
            &[("nixos_closure".to_string(), new_hash)],
            true,
        )
        .await
        .unwrap();
        drop(lease);
        tokio::time::timeout(std::time::Duration::from_secs(5), retention)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(new_nar.exists());
        assert!(new_narinfo.exists());
        assert!(!old_nar.exists());
        assert!(!old_narinfo.exists());
        let artifacts = db::list_cache_artifacts(&pool).await.unwrap();
        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].hash, "b".repeat(64));
        fs::remove_dir_all(root).ok();
    }

    #[tokio::test]
    async fn explicit_removal_rejects_fence_staled_by_waiting_publication() {
        let pool = db::connect_with_url("sqlite::memory:").await.unwrap();
        db::migrate(&pool).await.unwrap();
        let root = test_temp_dir("publication-removal-lease");
        let cache_root = root.join("cache");
        fs::create_dir_all(&cache_root).unwrap();
        fs::set_permissions(&cache_root, fs::Permissions::from_mode(0o755)).unwrap();
        let mut config = AppConfig::default();
        config.cache.root_dir = cache_root.clone();
        config.cache.mutation_lock_path = root.join("cache-mutation.lock");

        let (old_hash, old_nar, old_narinfo) =
            write_test_cache_artifact(&cache_root, 'a', "old", 32);
        record_test_cache_artifact(&pool, &cache_root, 'a', "old", 32).await;
        let inventory = db::cache_inventory_state(&pool).await.unwrap();
        let fence = db::CacheInventoryFence {
            instance_id: inventory.instance_id,
            generation: inventory.generation,
        };

        let lease = acquire_mutation_lease(&config).await.unwrap();
        let (_, new_nar, new_narinfo) = write_test_cache_artifact(&cache_root, 'b', "new", 32);
        let task_pool = pool.clone();
        let task_config = config.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let mut removal = tokio::spawn(async move {
            started_tx.send(()).unwrap();
            remove_artifacts_by_key(
                &task_pool,
                &task_config,
                &fence,
                &[("nixos_closure".to_string(), old_hash)],
            )
            .await
        });
        started_rx.await.unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), &mut removal)
                .await
                .is_err(),
            "explicit removal bypassed the publisher's cache mutation lease"
        );

        record_test_cache_artifact(&pool, &cache_root, 'b', "new", 32).await;
        drop(lease);
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), removal)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(!outcome.inventory_matched);
        assert!(outcome.deleted.is_empty());
        assert!(old_nar.exists());
        assert!(old_narinfo.exists());
        assert!(new_nar.exists());
        assert!(new_narinfo.exists());
        assert_eq!(db::list_cache_artifacts(&pool).await.unwrap().len(), 2);
        fs::remove_dir_all(root).ok();
    }

    #[tokio::test]
    async fn release_fault_sentinel_fails_system_release_publication_closed() {
        let root = test_temp_dir("release-fault-sentinel");
        let cache_root = root.join("cache");
        fs::create_dir_all(&cache_root).unwrap();
        fs::set_permissions(&cache_root, fs::Permissions::from_mode(0o755)).unwrap();
        let mut config = AppConfig::default();
        config.cache.root_dir = cache_root.clone();
        config.cache.mutation_lock_path = root.join("cache-mutation.lock");
        let lease = acquire_mutation_lease(&config).await.unwrap();

        ensure_system_release_publication_allowed(&config, "unused", &lease).unwrap();
        let private_dir = cache_root.join(RELEASE_TEST_FAULT_PRIVATE_DIR);
        let sentinel_dir = private_dir.join(RELEASE_TEST_FAULT_SENTINEL_DIR);
        fs::create_dir(&private_dir).unwrap();
        fs::create_dir(&sentinel_dir).unwrap();
        fs::set_permissions(&private_dir, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&sentinel_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let sentinel = sentinel_dir.join(RELEASE_TEST_FAULT_SENTINEL_FILE);
        let valid = format!(
            "schema={RELEASE_TEST_FAULT_SENTINEL_SCHEMA}\nowner_run_id=bench-owner\nrun_id=bench-owner\nacceptance_run_id=018f6b61-a646-7f7c-a651-7ee13ad42f84\nevidence_nonce_sha256={}\nboot_id=018f6b61-a646-7f7c-a651-7ee13ad42f85\nfault=corrupt_nar\nrelease_id=018f6b61-a646-7f7c-a651-7ee13ad42f86\ndeployment_id=018f6b61-a646-7f7c-a651-7ee13ad42f87\nattempt_id=018f6b61-a646-7f7c-a651-7ee13ad42f88\nowner_binding_sha256={}\nconsumed=true\n",
            "a".repeat(64),
            "b".repeat(64)
        );
        fs::write(&sentinel, valid).unwrap();
        fs::set_permissions(&sentinel, fs::Permissions::from_mode(0o644)).unwrap();
        let error =
            ensure_system_release_publication_allowed(&config, "unused", &lease).unwrap_err();
        assert!(error.to_string().contains("pending exact reset"));

        fs::write(&sentinel, "schema=unknown\n").unwrap();
        assert!(ensure_system_release_publication_allowed(&config, "unused", &lease).is_err());
        fs::remove_file(&sentinel).unwrap();
        std::os::unix::fs::symlink(cache_root.join("nix-cache-info"), &sentinel).unwrap();
        assert!(ensure_system_release_publication_allowed(&config, "unused", &lease).is_err());
        drop(lease);
        fs::remove_dir_all(root).ok();
    }
}
