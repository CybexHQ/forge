use std::{
    collections::HashSet,
    fs, io,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::{Command, Output},
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use tokio::task;

use crate::{config::AppConfig, db, models::BuildJob, redact::redact_sensitive_key_values};

const CACHE_MUTATION_LOCK_FILENAME: &str = ".cybex-cache-mutation.lock";

/// Cross-process lease for the cache filesystem and its artifact inventory.
///
/// A process-local mutex would still let an overlapping Forge process (for
/// example during a service restart) sweep files that `nix copy` is publishing.
/// Keep this descriptor open for the complete filesystem + SQLite mutation so
/// all Forge processes agree on the same serialization boundary.
#[derive(Debug)]
struct CacheMutationLock(fs::File);

impl Drop for CacheMutationLock {
    fn drop(&mut self) {
        let _ = unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

async fn acquire_cache_mutation_lock(config: &AppConfig) -> Result<CacheMutationLock> {
    let cache_root = config.cache.root_dir.clone();
    task::spawn_blocking(move || acquire_cache_mutation_lock_blocking(&cache_root))
        .await
        .context("join cache mutation lock task")?
}

fn acquire_cache_mutation_lock_blocking(cache_root: &Path) -> Result<CacheMutationLock> {
    fs::create_dir_all(cache_root)
        .with_context(|| format!("create cache directory {}", cache_root.display()))?;
    let path = cache_root.join(CACHE_MUTATION_LOCK_FILENAME);
    let lock = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&path)
        .with_context(|| format!("open cache mutation lock {}", path.display()))?;
    let metadata = lock
        .metadata()
        .with_context(|| format!("inspect cache mutation lock {}", path.display()))?;
    if !metadata.file_type().is_file() {
        bail!("cache mutation lock is not a regular file");
    }
    if metadata.nlink() != 1 {
        bail!("cache mutation lock must not have hard links");
    }
    if metadata.uid() != unsafe { libc::geteuid() } {
        bail!("cache mutation lock is owned by an unexpected user");
    }
    lock.set_permissions(fs::Permissions::from_mode(0o600))
        .with_context(|| format!("secure cache mutation lock {}", path.display()))?;
    loop {
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } == 0 {
            return Ok(CacheMutationLock(lock));
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error)
                .with_context(|| format!("lock cache mutation file {}", path.display()));
        }
    }
}

fn command_output_with_transient_exec_retry(command: &mut Command) -> io::Result<Output> {
    const MAX_ATTEMPTS: usize = 8;

    for attempt in 0..MAX_ATTEMPTS {
        match command.output() {
            Ok(output) => return Ok(output),
            Err(error)
                if error.raw_os_error() == Some(libc::ETXTBSY) && attempt + 1 < MAX_ATTEMPTS =>
            {
                // A concurrent fork can briefly inherit an executable's
                // just-closed writer until exec honors CLOEXEC. Retry only
                // that transient kernel error; every other launch failure is
                // returned immediately.
                std::thread::sleep(Duration::from_millis(1_u64 << attempt.min(6)));
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("command output retry loop returns on its final attempt")
}

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

#[derive(Debug)]
pub struct CachedNixArtifact {
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
    // Exported files are not reachable from the SQLite inventory until
    // `record_cached_artifact` finishes. Carry the lease in the returned value
    // so no deletion/sweep can enter during that publication gap.
    _mutation_lock: CacheMutationLock,
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
    let _mutation_lock = acquire_cache_mutation_lock(config).await?;
    let cache_dir = config.cache.root_dir.clone();
    task::spawn_blocking(move || initialize_cache_root_blocking(&cache_dir))
        .await
        .context("join cache init task")??;
    ensure_signing_key(config).await?;
    Ok(())
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
) -> Result<CachedNixArtifact> {
    if !config.cache.enabled {
        bail!("Forge Cache is disabled");
    }
    let mutation_lock = acquire_cache_mutation_lock(config).await?;
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
        let mut command = Command::new(&nix_binary);
        command
            .arg("copy")
            .arg("--to")
            .arg(&destination)
            .arg(&store_path);
        let output = command_output_with_transient_exec_retry(&mut command)
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
            _mutation_lock: mutation_lock,
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
) -> Result<()> {
    let serving_url = format!(
        "{}/{}",
        cache_base_url(config),
        artifact.nar_url.trim_start_matches('/')
    );
    db::upsert_cache_artifact(
        pool,
        None,
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
        Some(json!(&artifact.references)),
        &serving_url,
        job.managed_job_id.as_deref(),
        Some(artifact.metadata.clone()),
    )
    .await
    .map_err(anyhow::Error::from)?;
    let result = enforce_retention_locked(pool, config).await;
    // Make the export-to-inventory lock lifetime explicit. In particular, do
    // not let a future refactor release it before retention sees the new row.
    drop(artifact);
    result
}

/// Remove specific artifacts (identified by artifact_type + hash) on request
/// from the management server: delete their rows, then sweep any NAR/narinfo
/// files no longer reachable from the remaining artifacts.
pub async fn remove_artifacts_by_key(
    pool: &SqlitePool,
    config: &AppConfig,
    keys: &[(String, String)],
) -> Result<()> {
    if keys.is_empty() {
        return Ok(());
    }
    let _mutation_lock = acquire_cache_mutation_lock(config).await?;
    let artifacts = db::list_cache_artifacts(pool).await?;
    let doomed = artifacts
        .iter()
        .filter(|artifact| {
            keys.iter().any(|(artifact_type, hash)| {
                *artifact_type == artifact.artifact_type && *hash == artifact.hash
            })
        })
        .map(|artifact| artifact.id)
        .collect::<HashSet<_>>();
    if doomed.is_empty() {
        return Ok(());
    }
    for id in &doomed {
        db::delete_cache_artifact(pool, *id).await?;
    }
    let retained = artifacts
        .iter()
        .filter(|artifact| !doomed.contains(&artifact.id))
        .map(RetainedArtifactFiles::from)
        .collect::<Vec<_>>();
    sweep_unreachable_locked(config, retained).await?;
    Ok(())
}

pub async fn enforce_retention(pool: &SqlitePool, config: &AppConfig) -> Result<()> {
    if config.cache.max_bytes == 0 {
        return enforce_retention_locked(pool, config).await;
    }
    let _mutation_lock = acquire_cache_mutation_lock(config).await?;
    enforce_retention_locked(pool, config).await
}

async fn enforce_retention_locked(pool: &SqlitePool, config: &AppConfig) -> Result<()> {
    if config.cache.max_bytes == 0 {
        tracing::warn!(
            "cache.max_bytes is 0: Forge Cache retention is disabled and the cache root can grow without bound"
        );
        return Ok(());
    }
    // Artifact rows only track top-level NARs while `nix copy` stores whole
    // closures, so both the threshold and the reclaim must work on disk state.
    let mut total = cache_disk_usage(config).await;
    if total <= config.cache.max_bytes {
        return Ok(());
    }
    let mut candidates = db::list_cache_artifacts(pool).await?;
    candidates.sort_by(|left, right| {
        left.created_at
            .cmp(&right.created_at)
            .then_with(|| left.id.cmp(&right.id))
    });
    // First reclaim files left behind by an interrupted export. The cache
    // mutation lock guarantees that every in-flight successful export is
    // already represented by a row before this sweep can enter.
    let retained = candidates
        .iter()
        .map(RetainedArtifactFiles::from)
        .collect::<Vec<_>>();
    sweep_unreachable_locked(config, retained).await?;
    total = cache_disk_usage(config).await;
    if total <= config.cache.max_bytes {
        return Ok(());
    }

    let build_jobs = db::list_build_jobs(pool).await?;
    let managed_protections = db::list_managed_cache_protections(pool).await?;
    let candidate_sources = candidates
        .iter()
        .filter_map(|artifact| artifact.source_build_job_id.as_deref())
        .collect::<HashSet<_>>();
    let active_sources = build_jobs
        .iter()
        .filter(|job| matches!(job.status.as_str(), "queued" | "running"))
        .filter_map(|job| job.managed_job_id.clone())
        .collect::<HashSet<_>>();
    let recent_terminal_sources = build_jobs
        .iter()
        .filter(|job| !matches!(job.status.as_str(), "queued" | "running"))
        .filter_map(|job| job.managed_job_id.as_deref())
        .filter(|managed_job_id| candidate_sources.contains(managed_job_id))
        .take(config.cache.retain_recent_builds)
        .map(str::to_string)
        .collect::<HashSet<_>>();

    // Manage-desired artifacts and outputs of active jobs are hard fences.
    // Recent terminal outputs are a preference: consider every other artifact
    // first, then use the oldest recent outputs if the cache is still too big.
    let hard_protected = |artifact: &crate::models::CacheArtifact| {
        managed_protections.contains(&(artifact.artifact_type.clone(), artifact.hash.clone()))
            || artifact
                .source_build_job_id
                .as_deref()
                .is_some_and(|id| active_sources.contains(id))
    };
    let mut eviction_order = Vec::with_capacity(candidates.len());
    for evict_recent_terminal in [false, true] {
        eviction_order.extend(
            candidates
                .iter()
                .enumerate()
                .filter(|(_, artifact)| !hard_protected(artifact))
                .filter(|(_, artifact)| {
                    let recent_terminal = artifact
                        .source_build_job_id
                        .as_deref()
                        .is_some_and(|id| recent_terminal_sources.contains(id));
                    recent_terminal == evict_recent_terminal
                })
                .map(|(index, _)| index),
        );
    }
    let mut evicted_ids: HashSet<i64> = HashSet::new();
    // Evict oldest-first in rounds: pick a batch whose estimated compressed
    // footprint covers the excess, then mark-and-sweep ONCE for the whole
    // batch. Closure sharing can make the estimate optimistic, so re-measure
    // disk usage and run another round while still over budget. This keeps
    // the expensive full-cache walks proportional to rounds (usually one),
    // not to the number of evicted artifacts.
    let mut next_index = 0;
    while total > config.cache.max_bytes && next_index < eviction_order.len() {
        let excess = total - config.cache.max_bytes;
        let mut estimated_freed: u64 = 0;
        let mut evicted_this_round = false;
        while next_index < eviction_order.len() && estimated_freed < excess {
            let artifact = &candidates[eviction_order[next_index]];
            next_index += 1;
            db::delete_cache_artifact(pool, artifact.id).await?;
            evicted_ids.insert(artifact.id);
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
        let retained = candidates
            .iter()
            .filter(|candidate| !evicted_ids.contains(&candidate.id))
            .map(RetainedArtifactFiles::from)
            .collect::<Vec<_>>();
        sweep_unreachable_locked(config, retained).await?;
        total = cache_disk_usage(config).await;
    }
    if total > config.cache.max_bytes {
        tracing::warn!(
            total_size_bytes = total,
            max_size_bytes = config.cache.max_bytes,
            "Forge Cache remains above max_bytes after evicting every eligible artifact"
        );
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
    let _mutation_lock = acquire_cache_mutation_lock(config).await?;
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
        sweep_unreachable_locked(config, retained).await?;
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
}

impl From<&crate::models::CacheArtifact> for RetainedArtifactFiles {
    fn from(artifact: &crate::models::CacheArtifact) -> Self {
        Self {
            store_path: artifact.store_path.clone(),
            nar_path: PathBuf::from(&artifact.path),
            narinfo_path: PathBuf::from(&artifact.narinfo_path),
            nar_url: artifact.nar_url.trim_start_matches('/').to_string(),
        }
    }
}

async fn sweep_unreachable_locked(
    config: &AppConfig,
    retained: Vec<RetainedArtifactFiles>,
) -> Result<u64> {
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
    let mut queue: Vec<String> = Vec::new();
    for artifact in retained {
        live_files.insert(artifact.nar_path.clone());
        live_files.insert(artifact.narinfo_path.clone());
        if !artifact.nar_url.is_empty() {
            live_nar_urls.insert(artifact.nar_url.clone());
        }
        if let Some(hash) = store_path_hash(&artifact.store_path) {
            queue.push(hash);
        }
    }
    while let Some(hash) = queue.pop() {
        if !live_narinfo_hashes.insert(hash.clone()) {
            continue;
        }
        let narinfo_path = cache_root.join(format!("{hash}.narinfo"));
        let Ok(contents) = fs::read_to_string(&narinfo_path) else {
            continue;
        };
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
    let mut command = Command::new(nix_store);
    command
        .arg("--generate-binary-cache-key")
        .arg(key_name)
        .arg(private_key)
        .arg(public_key);
    let output = command_output_with_transient_exec_retry(&mut command)
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
    use std::{
        sync::mpsc,
        thread,
        time::{SystemTime, UNIX_EPOCH},
    };

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

    #[test]
    fn pending_cache_artifact_holds_cross_process_mutation_lock_until_dropped() {
        let root = test_temp_dir("mutation-lock");
        let cache_root = root.join("cache");
        let pending = CachedNixArtifact {
            artifact_hash: "a".repeat(64),
            size_bytes: 1,
            nar_path: cache_root.join("nar/output.nar.xz"),
            narinfo_path: cache_root.join(format!("{}.narinfo", "a".repeat(32))),
            nar_url: "nar/output.nar.xz".to_string(),
            store_path: format!("/nix/store/{}-output", "a".repeat(32)),
            file_hash: "sha256:file".to_string(),
            nar_hash: "sha256:nar".to_string(),
            nar_size_bytes: 1,
            closure_size_bytes: 1,
            closure_file_size_bytes: 1,
            compression: "xz".to_string(),
            references: Vec::new(),
            metadata: json!({}),
            _mutation_lock: acquire_cache_mutation_lock_blocking(&cache_root).unwrap(),
        };
        let lock_metadata = fs::metadata(cache_root.join(CACHE_MUTATION_LOCK_FILENAME)).unwrap();
        assert_eq!(lock_metadata.permissions().mode() & 0o777, 0o600);

        let (started_tx, started_rx) = mpsc::channel();
        let (acquired_tx, acquired_rx) = mpsc::channel();
        let contender_root = cache_root.clone();
        let contender = thread::spawn(move || {
            started_tx.send(()).unwrap();
            acquired_tx
                .send(acquire_cache_mutation_lock_blocking(&contender_root))
                .unwrap();
        });
        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(matches!(
            acquired_rx.recv_timeout(Duration::from_millis(50)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));

        drop(pending);
        let acquired = acquired_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap();
        drop(acquired);
        contender.join().unwrap();
        fs::remove_dir_all(root).ok();
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
        let executable_writer = fs::OpenOptions::new()
            .write(true)
            .open(&fake_nix_store)
            .unwrap();
        let release_writer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            drop(executable_writer);
        });
        let private_key = root.join("keys/cache-priv-key.pem");
        let public_key = root.join("keys/cache-pub-key.pem");

        let public = ensure_signing_key_blocking_with_command(
            &private_key,
            &public_key,
            "cybex-forge-cache",
            &fake_nix_store,
        )
        .unwrap();
        release_writer.join().unwrap();

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
        let root = test_temp_dir("closure-gc");
        let cache_root = root.join("cache");
        fs::create_dir_all(cache_root.join("nar")).unwrap();

        let mut config = AppConfig::default();
        config.cache.root_dir = cache_root.clone();
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
        let root = test_temp_dir("retention");
        let cache_root = root.join("cache");
        fs::create_dir_all(cache_root.join("nar")).unwrap();

        let mut config = AppConfig::default();
        config.cache.root_dir = cache_root.clone();
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
    async fn retention_prefers_recent_terminal_artifact_but_evicts_it_to_reach_cap() {
        let pool = db::connect_with_url("sqlite::memory:").await.unwrap();
        db::migrate(&pool).await.unwrap();
        let root = test_temp_dir("retention-recent-soft-limit");
        let cache_root = root.join("cache");
        fs::create_dir_all(cache_root.join("nar")).unwrap();

        let old_hash = "b".repeat(32);
        let recent_hash = "c".repeat(32);
        let old_nar = cache_root.join("nar/old.nar.xz");
        let old_narinfo = cache_root.join(format!("{old_hash}.narinfo"));
        let recent_nar = cache_root.join("nar/recent.nar.xz");
        let recent_narinfo = cache_root.join(format!("{recent_hash}.narinfo"));
        fs::write(&old_nar, vec![1u8; 40]).unwrap();
        fs::write(
            &old_narinfo,
            format!("StorePath: /nix/store/{old_hash}-old\nURL: nar/old.nar.xz\n"),
        )
        .unwrap();
        fs::write(&recent_nar, vec![2u8; 40]).unwrap();
        fs::write(
            &recent_narinfo,
            format!("StorePath: /nix/store/{recent_hash}-recent\nURL: nar/recent.nar.xz\n"),
        )
        .unwrap();
        let old_footprint =
            fs::metadata(&old_nar).unwrap().len() + fs::metadata(&old_narinfo).unwrap().len();
        let recent_footprint =
            fs::metadata(&recent_nar).unwrap().len() + fs::metadata(&recent_narinfo).unwrap().len();

        let recent_job = db::upsert_managed_build_job(
            &pool,
            "recent-terminal-job",
            "nixos_closure",
            None,
            Some("desktop_experience"),
            Some("x86_64-linux"),
            "revision-2",
            &"d".repeat(64),
            None,
        )
        .await
        .unwrap();
        db::finish_build_job(
            &pool,
            recent_job.id,
            "succeeded",
            "",
            "",
            &format!("/nix/store/{recent_hash}-recent"),
            &"e".repeat(64),
            40,
            Some(0),
            None,
        )
        .await
        .unwrap();

        for (hash, name, nar, narinfo, source, footprint) in [
            (
                &old_hash,
                "old",
                &old_nar,
                &old_narinfo,
                None,
                old_footprint,
            ),
            (
                &recent_hash,
                "recent",
                &recent_nar,
                &recent_narinfo,
                Some("recent-terminal-job".to_string()),
                recent_footprint,
            ),
        ] {
            db::create_cache_artifact(
                &pool,
                crate::models::CreateCacheArtifactRequest {
                    artifact_type: "nixos_closure".to_string(),
                    hash: hash.repeat(2),
                    size_bytes: 40,
                    path: nar.display().to_string(),
                    store_path: Some(format!("/nix/store/{hash}-{name}")),
                    narinfo_path: Some(narinfo.display().to_string()),
                    nar_url: Some(format!("nar/{name}.nar.xz")),
                    file_hash: Some(format!("sha256:{name}")),
                    nar_hash: Some(format!("sha256:{name}nar")),
                    nar_size_bytes: Some(40),
                    closure_size_bytes: Some(40),
                    closure_file_size_bytes: Some(footprint as i64),
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

        let mut config = AppConfig::default();
        config.cache.root_dir = cache_root.clone();
        config.cache.max_bytes = recent_footprint;
        config.cache.retain_recent_builds = 10;

        enforce_retention(&pool, &config).await.unwrap();

        let artifacts = db::list_cache_artifacts(&pool).await.unwrap();
        assert_eq!(artifacts.len(), 1);
        assert_eq!(
            artifacts[0].source_build_job_id.as_deref(),
            Some("recent-terminal-job")
        );
        assert!(!old_nar.exists());
        assert!(!old_narinfo.exists());
        assert!(recent_nar.exists());
        assert!(recent_narinfo.exists());

        config.cache.max_bytes = 1;
        enforce_retention(&pool, &config).await.unwrap();

        assert!(db::list_cache_artifacts(&pool).await.unwrap().is_empty());
        assert!(!recent_nar.exists());
        assert!(!recent_narinfo.exists());
        assert!(directory_size_bytes(&cache_root) <= config.cache.max_bytes);
        fs::remove_dir_all(root).ok();
    }

    #[tokio::test]
    async fn remove_artifacts_by_key_deletes_rows_and_files() {
        let pool = db::connect_with_url("sqlite::memory:").await.unwrap();
        db::migrate(&pool).await.unwrap();
        let root = test_temp_dir("remove-by-key");
        let cache_root = root.join("cache");
        fs::create_dir_all(cache_root.join("nar")).unwrap();

        let mut config = AppConfig::default();
        config.cache.root_dir = cache_root.clone();

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

        remove_artifacts_by_key(
            &pool,
            &config,
            &[
                ("nixos_closure".to_string(), "c".repeat(64)),
                ("nixos_closure".to_string(), "f".repeat(64)),
            ],
        )
        .await
        .unwrap();

        assert!(kept_nar.exists());
        assert!(kept_narinfo.exists());
        assert!(!doomed_nar.exists());
        assert!(!doomed_narinfo.exists());
        let artifacts = db::list_cache_artifacts(&pool).await.unwrap();
        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].hash, "b".repeat(64));
        fs::remove_dir_all(root).ok();
    }
}
