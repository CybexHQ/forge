use std::{
    collections::{BTreeSet, HashSet, VecDeque},
    ffi::CString,
    fs,
    io::{self, Read},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use tokio::task;

use crate::{
    config::AppConfig, db, models::BuildJob, protected_material,
    redact::redact_sensitive_key_values,
};

const CACHE_MUTATION_LOCK_FILENAME: &str = ".cybex-cache-mutation.lock";
const CLOSURE_MANIFEST_SCHEMA: &str = "cybex.forge.closure-manifest.v1";
const CLOSURE_MANIFEST_VALIDATION_LEVEL: &str = "compressed_file_hash";
const MAX_NARINFO_BYTES: u64 = 1024 * 1024;
const NIX_BASE32_ALPHABET: &[u8; 32] = b"0123456789abcdfghijklmnpqrsvwxyz";

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

async fn try_acquire_cache_mutation_lock(config: &AppConfig) -> Result<Option<CacheMutationLock>> {
    let cache_root = config.cache.root_dir.clone();
    task::spawn_blocking(move || try_acquire_cache_mutation_lock_blocking(&cache_root))
        .await
        .context("join non-blocking cache mutation lock task")?
}

fn acquire_cache_mutation_lock_blocking(cache_root: &Path) -> Result<CacheMutationLock> {
    let lock = open_cache_mutation_lock(cache_root)?;
    loop {
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } == 0 {
            return Ok(CacheMutationLock(lock));
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error)
                .with_context(|| format!("lock cache mutation file in {}", cache_root.display()));
        }
    }
}

fn try_acquire_cache_mutation_lock_blocking(
    cache_root: &Path,
) -> Result<Option<CacheMutationLock>> {
    let lock = open_cache_mutation_lock(cache_root)?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(Some(CacheMutationLock(lock)));
    }
    let error = io::Error::last_os_error();
    if matches!(error.kind(), io::ErrorKind::WouldBlock) {
        return Ok(None);
    }
    Err(error).with_context(|| format!("try lock cache mutation file in {}", cache_root.display()))
}

fn open_cache_mutation_lock(cache_root: &Path) -> Result<fs::File> {
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
    Ok(lock)
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

#[derive(Clone, Debug)]
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
struct ClosureManifestArtifact {
    store_path: String,
    narinfo_path: String,
    nar_url: String,
    file_hash: String,
    file_size_bytes: u64,
    nar_hash: String,
    nar_size_bytes: u64,
    compression: String,
    references: Vec<String>,
    provenance: String,
}

#[derive(Debug)]
struct VerifiedClosureManifest {
    manifest: Value,
    manifest_sha256: String,
    root_narinfo: ParsedNarInfo,
    root_narinfo_path: PathBuf,
    root_nar_path: PathBuf,
    total_file_size_bytes: u64,
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
    pool: &SqlitePool,
    config: &AppConfig,
    job: &BuildJob,
    store_path: &str,
    artifact_hash: &str,
    closure_size_bytes: i64,
    evaluated_derivation: Option<&str>,
) -> Result<CachedNixArtifact> {
    if !config.cache.enabled {
        bail!("Forge Cache is disabled");
    }
    let mutation_lock = acquire_cache_mutation_lock(config).await?;
    if db::protected_build_job_remediation_exists(pool, job.id).await? {
        bail!("build is quarantined by the protected-material boundary");
    }
    crate::disk::ensure_headroom(
        &config.cache.root_dir,
        closure_size_bytes.max(0) as u64,
        "Forge cache export",
    )?;
    let public_key = ensure_signing_key(config).await?;
    let cache_dir = config.cache.root_dir.clone();
    // Keep quarantined metadata outside the static cache document root. A
    // failed signature/hash check removes the signed discovery record from
    // service; unreferenced NAR bytes are subsequently eligible for sweeping.
    let quarantine_dir = config.paths.data_dir.join("cache-quarantine");
    let private_key_path = config.cache.private_key_path.clone();
    let nix_binary = config.build.nix_binary.clone();
    let store_path = store_path.to_string();
    let evaluated_derivation = evaluated_derivation.map(str::to_string);
    let managed_job_id = job.managed_job_id.clone();
    let artifact_hash = artifact_hash.to_string();
    task::spawn_blocking(move || {
        fs::create_dir_all(&cache_dir)
            .with_context(|| format!("create cache directory {}", cache_dir.display()))?;
        prepare_quarantine_root(&cache_dir, &quarantine_dir)?;
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
        let verified = build_or_quarantine_closure_manifest(
            &cache_dir,
            &quarantine_dir,
            &store_path,
            evaluated_derivation.as_deref(),
            &public_key,
        )?;
        let closure_file_size_bytes = i64::try_from(verified.total_file_size_bytes)
            .context("verified closure compressed size exceeded reporting range")?;
        let nar_len = u64::try_from(verified.root_narinfo.file_size)
            .context("verified root NAR FileSize was negative")?;
        let narinfo_name = verified
            .root_narinfo_path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| anyhow!("verified root NARInfo had no safe filename"))?
            .to_string();
        let narinfo = verified.root_narinfo;
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
            "closure_manifest": verified.manifest,
            "closure_manifest_sha256": verified.manifest_sha256,
        });
        Ok(CachedNixArtifact {
            artifact_hash,
            size_bytes: nar_len as i64,
            nar_path: verified.root_nar_path,
            narinfo_path: verified.root_narinfo_path,
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

fn build_or_quarantine_closure_manifest(
    cache_root: &Path,
    quarantine_root: &Path,
    root_store_path: &str,
    evaluated_derivation: Option<&str>,
    trusted_public_key: &str,
) -> Result<VerifiedClosureManifest> {
    let mut inspected_narinfos = Vec::new();
    match build_closure_manifest(
        cache_root,
        root_store_path,
        evaluated_derivation,
        trusted_public_key,
        &mut inspected_narinfos,
    ) {
        Ok(manifest) => Ok(manifest),
        Err(error) => {
            // The first record is the candidate root and the last record is
            // the member whose validation failed. Unpublish both, but do not
            // quarantine every already-verified shared dependency merely
            // because a later member was bad.
            let mut quarantine_candidates = Vec::new();
            if let Some(root) = inspected_narinfos.first() {
                quarantine_candidates.push(root.clone());
            }
            if let Some(failed) = inspected_narinfos.last() {
                if !quarantine_candidates.contains(failed) {
                    quarantine_candidates.push(failed.clone());
                }
            }
            let quarantined =
                quarantine_narinfo_records(cache_root, quarantine_root, &quarantine_candidates)
                    .context("quarantine invalid closure NARInfo records")?;
            bail!(
                "closure manifest validation failed; quarantined {quarantined} NARInfo record(s): {error}"
            )
        }
    }
}

fn build_closure_manifest(
    cache_root: &Path,
    root_store_path: &str,
    evaluated_derivation: Option<&str>,
    trusted_public_key: &str,
    inspected_narinfos: &mut Vec<PathBuf>,
) -> Result<VerifiedClosureManifest> {
    validate_store_path(root_store_path).context("validate closure root store path")?;
    let evaluated_derivation = evaluated_derivation
        .map(|path| {
            validate_store_path(path).context("validate evaluated derivation store path")?;
            if !path.ends_with(".drv") {
                bail!("evaluated derivation was not a .drv store path");
            }
            Ok(path.to_string())
        })
        .transpose()?;

    let mut queue = VecDeque::from([root_store_path.to_string()]);
    let mut visited = HashSet::new();
    let mut artifacts = Vec::new();
    let mut total_file_size_bytes = 0u64;
    let mut total_nar_size_bytes = 0u64;
    let mut root_narinfo = None;
    let mut root_narinfo_path = None;
    let mut root_nar_path = None;

    while let Some(expected_store_path) = queue.pop_front() {
        validate_store_path(&expected_store_path).context("validate referenced store path")?;
        if !visited.insert(expected_store_path.clone()) {
            continue;
        }

        let narinfo_filename = narinfo_filename_for_store_path(&expected_store_path)?;
        let narinfo_path = cache_root.join(&narinfo_filename);
        inspected_narinfos.push(narinfo_path.clone());
        let narinfo_raw = read_safe_narinfo(cache_root, &narinfo_filename)?;
        let mut narinfo = parse_narinfo_strict(&narinfo_raw)?;
        if narinfo.store_path != expected_store_path {
            bail!("referenced NARInfo StorePath did not match its cache filename");
        }
        validate_store_path(&narinfo.store_path).context("validate NARInfo StorePath")?;
        if narinfo.compression.is_empty()
            || !narinfo
                .compression
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            bail!("NARInfo Compression was missing or invalid");
        }
        let file_size = u64::try_from(narinfo.file_size)
            .ok()
            .filter(|size| *size > 0)
            .ok_or_else(|| anyhow!("NARInfo FileSize was missing or invalid"))?;
        let nar_size = u64::try_from(narinfo.nar_size)
            .ok()
            .filter(|size| *size > 0)
            .ok_or_else(|| anyhow!("NARInfo NarSize was missing or invalid"))?;
        let expected_file_hash = parse_strong_sha256(&narinfo.file_hash, "FileHash")?;
        // Full NarHash verification requires safely decompressing every cache
        // compression format. This increment validates its strong shape but
        // advertises only compressed_file_hash below.
        parse_strong_sha256(&narinfo.nar_hash, "NarHash")?;

        let mut references = BTreeSet::new();
        for reference in &narinfo.references {
            validate_store_path(reference).context("validate NARInfo reference")?;
            references.insert(reference.clone());
        }
        narinfo.references = references.into_iter().collect();
        verify_narinfo_signature(&narinfo, trusted_public_key)?;
        for reference in &narinfo.references {
            if !visited.contains(reference) {
                queue.push_back(reference.clone());
            }
        }

        let (nar_path, actual_file_size, actual_file_hash) =
            hash_safe_cache_member(cache_root, &narinfo.url)?;
        if actual_file_size != file_size {
            bail!("compressed NAR size did not match NARInfo FileSize");
        }
        if actual_file_hash != expected_file_hash {
            bail!("compressed NAR SHA-256 did not match NARInfo FileHash");
        }
        total_file_size_bytes = total_file_size_bytes
            .checked_add(file_size)
            .ok_or_else(|| anyhow!("closure FileSize total overflowed"))?;
        total_nar_size_bytes = total_nar_size_bytes
            .checked_add(nar_size)
            .ok_or_else(|| anyhow!("closure NarSize total overflowed"))?;

        if narinfo.store_path == root_store_path {
            root_narinfo = Some(narinfo.clone());
            root_narinfo_path = Some(narinfo_path.clone());
            root_nar_path = Some(nar_path.clone());
        }
        artifacts.push(ClosureManifestArtifact {
            store_path: narinfo.store_path,
            narinfo_path: narinfo_filename,
            nar_url: narinfo.url,
            file_hash: narinfo.file_hash,
            file_size_bytes: file_size,
            nar_hash: narinfo.nar_hash,
            nar_size_bytes: nar_size,
            compression: narinfo.compression,
            references: narinfo.references,
            provenance: "unknown".to_string(),
        });
    }

    artifacts.sort_by(|left, right| left.store_path.cmp(&right.store_path));
    let artifact_count = artifacts.len();
    let mut manifest = json!({
        "schema": CLOSURE_MANIFEST_SCHEMA,
        "root_store_path": root_store_path,
        "evaluated_derivation": evaluated_derivation,
        "artifacts": artifacts,
        "artifact_count": artifact_count,
        "total_file_size_bytes": total_file_size_bytes,
        "total_nar_size_bytes": total_nar_size_bytes,
        "validation_level": CLOSURE_MANIFEST_VALIDATION_LEVEL,
    });
    protected_material::validate_cache_metadata(&manifest)
        .context("validate closure manifest protected-material boundary")?;
    let manifest_sha256 = sha256_hex(&canonical_json_bytes(&manifest)?);
    manifest
        .as_object_mut()
        .expect("closure manifest is an object")
        .insert("manifest_sha256".to_string(), json!(manifest_sha256));

    Ok(VerifiedClosureManifest {
        manifest,
        manifest_sha256,
        root_narinfo: root_narinfo.ok_or_else(|| anyhow!("closure omitted its root NARInfo"))?,
        root_narinfo_path: root_narinfo_path
            .ok_or_else(|| anyhow!("closure omitted its root NARInfo path"))?,
        root_nar_path: root_nar_path.ok_or_else(|| anyhow!("closure omitted its root NAR path"))?,
        total_file_size_bytes,
    })
}

fn read_safe_narinfo(cache_root: &Path, filename: &str) -> Result<String> {
    if filename.contains('/') || filename.contains('\\') || !filename.ends_with(".narinfo") {
        bail!("NARInfo filename was not a safe cache-root member");
    }
    let path = cache_root.join(filename);
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&path)
        .with_context(|| format!("open generated NARInfo {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect generated NARInfo {}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_NARINFO_BYTES {
        bail!("generated NARInfo was not a bounded regular file");
    }
    let mut raw = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_NARINFO_BYTES + 1)
        .read_to_end(&mut raw)
        .with_context(|| format!("read generated NARInfo {}", path.display()))?;
    if raw.len() as u64 > MAX_NARINFO_BYTES {
        bail!("generated NARInfo exceeded the bounded read limit");
    }
    String::from_utf8(raw).context("generated NARInfo was not UTF-8")
}

fn hash_safe_cache_member(cache_root: &Path, relative: &str) -> Result<(PathBuf, u64, [u8; 32])> {
    let filename = validate_nar_url(relative)?;
    let path = cache_root.join("nar").join(filename);
    let mut file = open_nar_member_at(cache_root, filename)
        .with_context(|| format!("open generated NAR {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect generated NAR {}", path.display()))?;
    if !metadata.file_type().is_file() {
        bail!("generated NAR was not a regular file");
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 128 * 1024];
    let mut bytes_read = 0u64;
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("hash generated NAR {}", path.display()))?;
        if read == 0 {
            break;
        }
        bytes_read = bytes_read
            .checked_add(read as u64)
            .ok_or_else(|| anyhow!("generated NAR size overflowed"))?;
        hasher.update(&buffer[..read]);
    }
    if file
        .metadata()
        .with_context(|| format!("reinspect generated NAR {}", path.display()))?
        .len()
        != bytes_read
    {
        bail!("generated NAR changed while it was being verified");
    }
    Ok((path, bytes_read, hasher.finalize().into()))
}

fn validate_nar_url(relative: &str) -> Result<&str> {
    let filename = relative
        .strip_prefix("nar/")
        .ok_or_else(|| anyhow!("NARInfo URL was outside the nar directory"))?;
    if filename.is_empty()
        || filename.len() > 255
        || filename.contains('/')
        || !filename
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-'))
    {
        bail!("NARInfo URL was not a canonical relative cache URI");
    }
    Ok(filename)
}

fn open_nar_member_at(cache_root: &Path, filename: &str) -> Result<fs::File> {
    let cache_dir = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(cache_root)
        .with_context(|| format!("open cache root {}", cache_root.display()))?;
    let nar_name = CString::new("nar").expect("static directory name contains no NUL");
    let nar_fd = unsafe {
        libc::openat(
            cache_dir.as_raw_fd(),
            nar_name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        )
    };
    if nar_fd < 0 {
        return Err(io::Error::last_os_error()).context("open cache nar directory");
    }
    let nar_dir = unsafe { fs::File::from_raw_fd(nar_fd) };
    let filename = CString::new(filename).context("NAR filename contained NUL")?;
    let nar_fd = unsafe {
        libc::openat(
            nar_dir.as_raw_fd(),
            filename.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if nar_fd < 0 {
        return Err(io::Error::last_os_error()).context("open cache NAR member");
    }
    Ok(unsafe { fs::File::from_raw_fd(nar_fd) })
}

fn parse_strong_sha256(value: &str, field: &str) -> Result<[u8; 32]> {
    let bytes = if let Some(encoded) = value.strip_prefix("sha256-") {
        BASE64_STANDARD
            .decode(encoded)
            .with_context(|| format!("NARInfo {field} had invalid SRI base64"))?
    } else if let Some(encoded) = value.strip_prefix("sha256:") {
        if encoded.len() == 64 && encoded.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            hex::decode(encoded).with_context(|| format!("NARInfo {field} had invalid hex"))?
        } else {
            decode_nix_base32_sha256(encoded)
                .with_context(|| format!("NARInfo {field} had invalid Nix base32"))?
                .to_vec()
        }
    } else {
        bail!("NARInfo {field} was not a strong SHA-256 hash");
    };
    bytes
        .try_into()
        .map_err(|_| anyhow!("NARInfo {field} did not contain a 256-bit digest"))
}

fn verify_narinfo_signature(narinfo: &ParsedNarInfo, public_key: &str) -> Result<()> {
    let (key_name, verifying_key) = parse_cache_public_key(public_key)?;
    let nar_hash = encode_nix_base32_sha256(&parse_strong_sha256(&narinfo.nar_hash, "NarHash")?);
    let fingerprint = format!(
        "1;{};sha256:{};{};{}",
        narinfo.store_path,
        nar_hash,
        narinfo.nar_size,
        narinfo.references.join(",")
    );

    let verified = narinfo.signatures.iter().any(|value| {
        let Some((signature_name, encoded_signature)) = value.split_once(':') else {
            return false;
        };
        if signature_name != key_name {
            return false;
        }
        let Ok(signature_bytes) = BASE64_STANDARD.decode(encoded_signature) else {
            return false;
        };
        let Ok(signature) = Signature::from_slice(&signature_bytes) else {
            return false;
        };
        verifying_key
            .verify_strict(fingerprint.as_bytes(), &signature)
            .is_ok()
    });
    if !verified {
        bail!("NARInfo did not carry a valid signature from the active Forge cache key");
    }
    Ok(())
}

fn parse_cache_public_key(public_key: &str) -> Result<(&str, VerifyingKey)> {
    let (key_name, encoded_key) = public_key
        .split_once(':')
        .filter(|(name, encoded)| !name.is_empty() && !encoded.is_empty())
        .ok_or_else(|| anyhow!("Forge cache public key had an invalid shape"))?;
    let key_bytes = BASE64_STANDARD
        .decode(encoded_key)
        .context("decode Forge cache public key")?;
    let key_bytes: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| anyhow!("Forge cache public key was not 256-bit"))?;
    let verifying_key =
        VerifyingKey::from_bytes(&key_bytes).context("parse Forge cache public key")?;
    if verifying_key.is_weak() {
        bail!("Forge cache public key must not be a weak Ed25519 key");
    }
    Ok((key_name, verifying_key))
}

fn decode_nix_base32_sha256(encoded: &str) -> Result<[u8; 32]> {
    if encoded.len() != 52 {
        bail!("SHA-256 Nix base32 digest must contain 52 characters");
    }
    let mut decoded = [0u8; 32];
    for (position, byte) in encoded.bytes().enumerate() {
        let value = NIX_BASE32_ALPHABET
            .iter()
            .position(|candidate| *candidate == byte)
            .ok_or_else(|| anyhow!("Nix base32 digest contained an invalid character"))?
            as u16;
        let bit = (encoded.len() - 1 - position) * 5;
        let byte_index = bit / 8;
        let shift = bit % 8;
        let shifted = value << shift;
        decoded[byte_index] |= shifted as u8;
        if byte_index + 1 < decoded.len() {
            decoded[byte_index + 1] |= (shifted >> 8) as u8;
        } else if shifted > u8::MAX as u16 {
            bail!("Nix base32 digest had non-canonical high bits");
        }
    }
    Ok(decoded)
}

fn encode_nix_base32_sha256(digest: &[u8; 32]) -> String {
    let mut encoded = [b'0'; 52];
    for position in 0..encoded.len() {
        let bit = position * 5;
        let byte_index = bit / 8;
        let shift = bit % 8;
        let mut value = (digest[byte_index] as u16) >> shift;
        if byte_index + 1 < digest.len() {
            value |= (digest[byte_index + 1] as u16) << (8 - shift);
        }
        encoded[encoded.len() - 1 - position] = NIX_BASE32_ALPHABET[(value & 0x1f) as usize];
    }
    String::from_utf8(encoded.to_vec()).expect("Nix base32 alphabet is ASCII")
}

fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>> {
    fn write_value(value: &Value, output: &mut Vec<u8>) -> serde_json::Result<()> {
        match value {
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
                serde_json::to_writer(output, value)
            }
            Value::Array(values) => {
                output.push(b'[');
                for (index, value) in values.iter().enumerate() {
                    if index > 0 {
                        output.push(b',');
                    }
                    write_value(value, output)?;
                }
                output.push(b']');
                Ok(())
            }
            Value::Object(object) => {
                output.push(b'{');
                let mut keys = object.keys().collect::<Vec<_>>();
                keys.sort_unstable();
                for (index, key) in keys.into_iter().enumerate() {
                    if index > 0 {
                        output.push(b',');
                    }
                    serde_json::to_writer(&mut *output, key)?;
                    output.push(b':');
                    write_value(&object[key], output)?;
                }
                output.push(b'}');
                Ok(())
            }
        }
    }

    let mut output = Vec::new();
    write_value(value, &mut output).context("serialize canonical closure manifest")?;
    Ok(output)
}

fn validate_store_path(value: &str) -> Result<()> {
    let relative = value
        .strip_prefix("/nix/store/")
        .ok_or_else(|| anyhow!("store path was outside /nix/store"))?;
    if relative.contains('/') {
        bail!("store path contained non-canonical components");
    }
    let (hash, name) = relative
        .split_once('-')
        .ok_or_else(|| anyhow!("store path omitted its Nix hash prefix"))?;
    if hash.len() != 32
        || !hash.bytes().all(|byte| NIX_BASE32_ALPHABET.contains(&byte))
        || name.is_empty()
        || !name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'?' | b'=' | b'-')
        })
    {
        bail!("store path was not canonical");
    }
    Ok(())
}

fn quarantine_narinfo_records(
    cache_root: &Path,
    quarantine_root: &Path,
    paths: &[PathBuf],
) -> Result<usize> {
    let mut seen = HashSet::new();
    let candidates = paths
        .iter()
        .filter(|path| path.parent() == Some(cache_root))
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".narinfo") && !name.contains('/'))
        })
        .filter(|path| fs::symlink_metadata(path).is_ok())
        .filter(|path| seen.insert((*path).clone()))
        .cloned()
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        return Ok(0);
    }
    prepare_quarantine_root(cache_root, quarantine_root)?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let quarantine = quarantine_root.join(format!("{}-{nonce}", std::process::id()));
    fs::create_dir(&quarantine)
        .with_context(|| format!("create cache quarantine batch {}", quarantine.display()))?;
    fs::set_permissions(&quarantine, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("secure cache quarantine batch {}", quarantine.display()))?;
    let mut moved = 0usize;
    for (index, path) in candidates.into_iter().enumerate() {
        let destination = quarantine.join(
            path.file_name()
                .expect("quarantine candidates have a filename"),
        );
        // First rename inside the cache filesystem. This atomically removes
        // the public `<hash>.narinfo` name even when the private quarantine
        // lives on another mount. Archival then uses rename where possible or
        // a no-follow copy across filesystems.
        let hidden = cache_root.join(format!(
            ".cybex-quarantine-{}-{nonce}-{index}",
            std::process::id()
        ));
        fs::rename(&path, &hidden).with_context(|| {
            format!(
                "unpublish invalid NARInfo {} before quarantine",
                path.display()
            )
        })?;
        if let Err(rename_error) = fs::rename(&hidden, &destination) {
            if let Err(copy_error) = copy_quarantined_narinfo(&hidden, &destination) {
                return Err(copy_error).with_context(|| {
                    format!("archive unpublished NARInfo after rename failed ({rename_error})")
                });
            }
        }
        moved += 1;
    }
    Ok(moved)
}

fn copy_quarantined_narinfo(source: &Path, destination: &Path) -> Result<()> {
    let mut source_file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(source)
        .with_context(|| format!("open unpublished NARInfo {}", source.display()))?;
    if !source_file
        .metadata()
        .with_context(|| format!("inspect unpublished NARInfo {}", source.display()))?
        .is_file()
    {
        fs::remove_file(source)
            .with_context(|| format!("remove unsafe unpublished NARInfo {}", source.display()))?;
        return Ok(());
    }
    let mut destination_file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(destination)
        .with_context(|| format!("create quarantined NARInfo {}", destination.display()))?;
    io::copy(&mut source_file, &mut destination_file)
        .with_context(|| format!("copy quarantined NARInfo {}", source.display()))?;
    destination_file
        .sync_all()
        .with_context(|| format!("sync quarantined NARInfo {}", destination.display()))?;
    fs::remove_file(source)
        .with_context(|| format!("remove unpublished NARInfo {}", source.display()))?;
    Ok(())
}

fn prepare_quarantine_root(cache_root: &Path, quarantine_root: &Path) -> Result<()> {
    if quarantine_root == cache_root || quarantine_root.starts_with(cache_root) {
        bail!("cache quarantine must be outside the served cache root");
    }
    fs::create_dir_all(quarantine_root)
        .with_context(|| format!("create cache quarantine {}", quarantine_root.display()))?;
    let metadata = fs::symlink_metadata(quarantine_root)
        .with_context(|| format!("inspect cache quarantine {}", quarantine_root.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("cache quarantine was not a private directory");
    }
    let canonical_cache = fs::canonicalize(cache_root)
        .with_context(|| format!("resolve cache root {}", cache_root.display()))?;
    let canonical_quarantine = fs::canonicalize(quarantine_root)
        .with_context(|| format!("resolve cache quarantine {}", quarantine_root.display()))?;
    if canonical_quarantine == canonical_cache || canonical_quarantine.starts_with(&canonical_cache)
    {
        bail!("cache quarantine resolved inside the served cache root");
    }
    fs::set_permissions(quarantine_root, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("secure cache quarantine {}", quarantine_root.display()))?;
    Ok(())
}

/// Finish remediation for legacy jobs whose reusable inputs crossed the
/// protected-material boundary. Database migration has already scrubbed every
/// protected byte before this function runs. Holding the cross-process cache
/// mutation lock prevents an overlapping export or sweep from racing the
/// unpublish/delete sequence.
///
/// `purged` means the signed static binary-cache root publication and its local
/// inventory were removed, and closure members not shared with a retained root
/// were swept. This intentionally does not run `/nix/store` GC; build-store
/// collection remains a separate, governed operation.
pub async fn remediate_protected_build_jobs(
    pool: &SqlitePool,
    config: &AppConfig,
) -> Result<usize> {
    let pending = db::pending_protected_build_job_remediations(pool).await?;
    if pending.is_empty() {
        return Ok(0);
    }

    let _mutation_lock = acquire_cache_mutation_lock(config).await?;
    let quarantine_root = config.paths.data_dir.join("cache-quarantine");
    let mut completed = 0usize;
    for remediation in pending {
        remediate_protected_build_job_locked(pool, config, &quarantine_root, &remediation).await?;
        completed += 1;
    }
    tracing::warn!(
        remediated_jobs = completed,
        "withdrew legacy protected build roots and swept unreferenced members from the Forge static cache; /nix/store GC remains operator-managed"
    );
    Ok(completed)
}

async fn remediate_protected_build_job_locked(
    pool: &SqlitePool,
    config: &AppConfig,
    quarantine_root: &Path,
    remediation: &db::ProtectedBuildJobRemediation,
) -> Result<()> {
    let artifacts = db::list_cache_artifacts(pool).await?;
    let mut doomed_ids = artifacts
        .iter()
        .filter(|artifact| artifact_matches_protected_job(artifact, remediation))
        .map(|artifact| artifact.id)
        .collect::<HashSet<_>>();

    // An upsert can transfer the source job identifier while leaving the same
    // exported root. Treat every row naming that root as affected, and follow
    // aliases to a fixed point before retaining any cache files.
    loop {
        let doomed = artifacts
            .iter()
            .filter(|artifact| doomed_ids.contains(&artifact.id))
            .collect::<Vec<_>>();
        let aliases = artifacts
            .iter()
            .filter(|artifact| !doomed_ids.contains(&artifact.id))
            .filter(|artifact| {
                doomed
                    .iter()
                    .any(|seed| cache_artifact_roots_alias(seed, artifact))
            })
            .map(|artifact| artifact.id)
            .collect::<Vec<_>>();
        if aliases.is_empty() {
            break;
        }
        doomed_ids.extend(aliases);
    }

    let doomed = artifacts
        .iter()
        .filter(|artifact| doomed_ids.contains(&artifact.id))
        .collect::<Vec<_>>();
    let mut root_narinfos = Vec::new();
    for artifact in &doomed {
        if let Some(hash) = store_path_hash(&artifact.store_path) {
            root_narinfos.push(config.cache.root_dir.join(format!("{hash}.narinfo")));
        }
        let recorded = PathBuf::from(&artifact.narinfo_path);
        if recorded.parent() == Some(config.cache.root_dir.as_path()) {
            root_narinfos.push(recorded);
        }
    }

    // Renaming inside the served root atomically removes each discovery name;
    // the existing quarantine helper then archives it into a private 0700/0600
    // location even when the quarantine is on another filesystem.
    quarantine_narinfo_records(&config.cache.root_dir, quarantine_root, &root_narinfos)
        .context("unpublish protected build root NARInfo records")?;

    let retained = artifacts
        .iter()
        .filter(|artifact| !doomed_ids.contains(&artifact.id))
        .map(RetainedArtifactFiles::from)
        .collect::<Vec<_>>();
    sweep_unreachable_locked(config, retained)
        .await
        .context("sweep unreachable protected-build members from static cache")?;

    for narinfo in &root_narinfos {
        if narinfo.parent() == Some(config.cache.root_dir.as_path())
            && fs::symlink_metadata(narinfo).is_ok()
        {
            bail!("protected build root NARInfo remained published after quarantine");
        }
    }

    let artifact_ids = doomed_ids.into_iter().collect::<Vec<_>>();
    db::complete_protected_build_job_cache_purge(pool, remediation, &artifact_ids).await?;
    Ok(())
}

fn artifact_matches_protected_job(
    artifact: &crate::models::CacheArtifact,
    remediation: &db::ProtectedBuildJobRemediation,
) -> bool {
    remediation
        .managed_job_id
        .as_deref()
        .is_some_and(|id| artifact.source_build_job_id.as_deref() == Some(id))
        || (!remediation.output_path.is_empty() && artifact.store_path == remediation.output_path)
}

fn cache_artifact_roots_alias(
    left: &crate::models::CacheArtifact,
    right: &crate::models::CacheArtifact,
) -> bool {
    (!left.store_path.is_empty() && left.store_path == right.store_path)
        || (!left.path.is_empty() && left.path == right.path)
        || (!left.narinfo_path.is_empty() && left.narinfo_path == right.narinfo_path)
        || (!left.nar_url.is_empty() && left.nar_url == right.nar_url)
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

/// Run opportunistic retention without delaying a managed heartbeat behind a
/// cache export or another filesystem mutation. A skipped pass is safe: the
/// next managed sync retries it, while publication and explicit deletions keep
/// using the blocking cross-process lease.
pub async fn try_enforce_retention(pool: &SqlitePool, config: &AppConfig) -> Result<bool> {
    if config.cache.max_bytes == 0 {
        enforce_retention_locked(pool, config).await?;
        return Ok(true);
    }
    let Some(_mutation_lock) = try_acquire_cache_mutation_lock(config).await? else {
        return Ok(false);
    };
    enforce_retention_locked(pool, config).await?;
    Ok(true)
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

/// Verify a bounded, oldest-verified-first cache batch. Healthy roots are due
/// once per day; an invalid root triggers a full safety cascade because a
/// quarantined shared member can invalidate roots outside the normal batch.
/// Invalid local rows are removed immediately; the next generation-fenced full
/// inventory makes the loss visible to Manage, whose desired-state controller
/// queues a repair.
pub async fn scrub_cache_artifacts(
    pool: &SqlitePool,
    config: &AppConfig,
    limit: i64,
) -> Result<u64> {
    let _mutation_lock = acquire_cache_mutation_lock(config).await?;
    scrub_cache_artifacts_locked(pool, config, limit).await
}

async fn scrub_cache_artifacts_locked(
    pool: &SqlitePool,
    config: &AppConfig,
    limit: i64,
) -> Result<u64> {
    let candidates = db::cache_artifacts_due_for_verification(pool, limit).await?;
    if candidates.is_empty() {
        return Ok(0);
    }
    let public_key = ensure_signing_key(config).await?;
    let mut invalid_count = 0u64;
    for artifact in &candidates {
        if scrub_cache_artifact(pool, config, artifact, &public_key).await? {
            invalid_count += 1;
        }
    }

    if invalid_count != 0 {
        // Quarantining a corrupt member can make roots outside the bounded
        // sample incomplete. Corruption is exceptional, so pay the one-time
        // cost of checking every remaining root and withdraw every affected
        // publication before reporting a complete inventory to Manage.
        for artifact in db::list_cache_artifacts(pool).await? {
            if scrub_cache_artifact(pool, config, &artifact, &public_key).await? {
                invalid_count += 1;
            }
        }
        let retained = db::list_cache_artifacts(pool)
            .await?
            .iter()
            .map(RetainedArtifactFiles::from)
            .collect::<Vec<_>>();
        sweep_unreachable_locked(config, retained).await?;
    }
    Ok(invalid_count)
}

/// Run the bounded integrity scrub only when its mutation lease is immediately
/// available. This keeps periodic Manage reports live during a long `nix copy`
/// without weakening the lock used by the scrub itself.
pub async fn try_scrub_cache_artifacts(
    pool: &SqlitePool,
    config: &AppConfig,
    limit: i64,
) -> Result<Option<u64>> {
    let Some(_mutation_lock) = try_acquire_cache_mutation_lock(config).await? else {
        return Ok(None);
    };
    scrub_cache_artifacts_locked(pool, config, limit)
        .await
        .map(Some)
}

async fn scrub_cache_artifact(
    pool: &SqlitePool,
    config: &AppConfig,
    artifact: &crate::models::CacheArtifact,
    public_key: &str,
) -> Result<bool> {
    let verification = verify_cache_artifact(config, artifact, public_key).await;
    if matches!(verification, Ok(true)) {
        db::mark_cache_artifact_verified(pool, artifact.id).await?;
        return Ok(false);
    }

    // Validation can fail before closure traversal reaches a NARInfo (for
    // example, for a malformed inventory store path). Always withdraw both
    // the canonical and recorded root discovery names; the strict verifier
    // already quarantines any corrupt dependency it encountered while walking
    // the closure.
    quarantine_cache_artifact_root(config, artifact).await?;
    let verification_error = verification
        .err()
        .map(|error| sanitize_error(&error))
        .unwrap_or_else(|| "cache inventory did not match verified closure".to_string());
    tracing::warn!(
        artifact_id = artifact.id,
        artifact_type = %artifact.artifact_type,
        hash = %artifact.hash,
        reason = %verification_error,
        "removing missing or corrupt Forge cache artifact for automatic repair"
    );
    db::delete_cache_artifact(pool, artifact.id).await?;
    Ok(true)
}

async fn verify_cache_artifact(
    config: &AppConfig,
    artifact: &crate::models::CacheArtifact,
    public_key: &str,
) -> Result<bool> {
    let cache_root = config.cache.root_dir.clone();
    let quarantine_root = config.paths.data_dir.join("cache-quarantine");
    let artifact = artifact.clone();
    let public_key = public_key.to_string();
    task::spawn_blocking(move || {
        verify_cache_artifact_blocking(&cache_root, &quarantine_root, &artifact, &public_key)
    })
    .await
    .context("join cache artifact verification task")?
}

fn verify_cache_artifact_blocking(
    cache_root: &Path,
    quarantine_root: &Path,
    artifact: &crate::models::CacheArtifact,
    public_key: &str,
) -> Result<bool> {
    let evaluated_derivation = artifact
        .cache_metadata
        .pointer("/closure_manifest/evaluated_derivation")
        .and_then(Value::as_str);
    let verified = build_or_quarantine_closure_manifest(
        cache_root,
        quarantine_root,
        &artifact.store_path,
        evaluated_derivation,
        public_key,
    )?;

    let root = &verified.root_narinfo;
    let expected_references = artifact.references.as_array().and_then(|references| {
        references
            .iter()
            .map(Value::as_str)
            .collect::<Option<Vec<_>>>()
            .map(|references| {
                references
                    .into_iter()
                    .map(str::to_string)
                    .collect::<BTreeSet<_>>()
            })
    });
    let actual_references = root.references.iter().cloned().collect::<BTreeSet<_>>();
    let expected_manifest = artifact.cache_metadata.get("closure_manifest");
    let expected_manifest_sha256 = artifact.cache_metadata.get("closure_manifest_sha256");
    let expected_key_fingerprint = artifact.cache_metadata.get("public_key_fingerprint");
    let inventory_matches = Path::new(&artifact.path) == verified.root_nar_path
        && Path::new(&artifact.narinfo_path) == verified.root_narinfo_path
        && root.store_path == artifact.store_path
        && root.url == artifact.nar_url
        && root.file_hash == artifact.file_hash
        && root.nar_hash == artifact.nar_hash
        && root.compression == artifact.compression
        && (artifact.size_bytes <= 0 || root.file_size == artifact.size_bytes)
        && (artifact.nar_size_bytes <= 0 || root.nar_size == artifact.nar_size_bytes)
        && (artifact.closure_file_size_bytes <= 0
            || verified.total_file_size_bytes == artifact.closure_file_size_bytes as u64)
        && expected_references.as_ref() == Some(&actual_references)
        && expected_manifest.is_none_or(|manifest| manifest == &verified.manifest)
        && expected_manifest_sha256
            .is_none_or(|digest| digest.as_str() == Some(&verified.manifest_sha256))
        && expected_key_fingerprint
            .is_none_or(|digest| digest.as_str() == Some(&public_key_fingerprint(public_key)));

    if !inventory_matches {
        quarantine_narinfo_records(cache_root, quarantine_root, &[verified.root_narinfo_path])?;
    }
    Ok(inventory_matches)
}

async fn quarantine_cache_artifact_root(
    config: &AppConfig,
    artifact: &crate::models::CacheArtifact,
) -> Result<()> {
    let cache_root = config.cache.root_dir.clone();
    let quarantine_root = config.paths.data_dir.join("cache-quarantine");
    let mut candidates = Vec::new();
    if let Ok(filename) = narinfo_filename_for_store_path(&artifact.store_path) {
        candidates.push(cache_root.join(filename));
    }
    candidates.push(PathBuf::from(&artifact.narinfo_path));
    task::spawn_blocking(move || {
        quarantine_narinfo_records(&cache_root, &quarantine_root, &candidates)
    })
    .await
    .context("join cache artifact root quarantine task")??;
    Ok(())
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
#[cfg(test)]
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
    parse_cache_public_key(&public_key)?;
    Ok(public_key)
}

fn parse_narinfo_strict(raw: &str) -> Result<ParsedNarInfo> {
    if !raw.ends_with('\n') {
        bail!("generated NARInfo did not end with a complete record");
    }
    let singleton_fields = [
        "StorePath",
        "URL",
        "Compression",
        "FileHash",
        "FileSize",
        "NarHash",
        "NarSize",
        "References",
    ];
    let mut seen = std::collections::BTreeMap::<&str, usize>::new();
    let mut signatures = 0usize;
    for line in raw.lines() {
        let Some((key, _value)) = line.split_once(": ") else {
            bail!("generated NARInfo contained a malformed line");
        };
        if singleton_fields.contains(&key) {
            let count = seen.entry(key).or_default();
            *count += 1;
            if *count > 1 {
                bail!("generated NARInfo repeated the {key} field");
            }
        } else if key == "Sig" {
            signatures += 1;
        }
    }
    for field in singleton_fields {
        if seen.get(field) != Some(&1) {
            bail!("generated NARInfo omitted the {field} field");
        }
    }
    if signatures == 0 {
        bail!("generated NARInfo omitted a cache signature");
    }
    parse_narinfo(raw)
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
    use ed25519_dalek::{Signer, SigningKey, Verifier};
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

    fn test_store_path(hash_character: char, name: &str) -> String {
        format!(
            "/nix/store/{}-{name}",
            hash_character.to_string().repeat(32)
        )
    }

    fn test_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[0x42; 32])
    }

    fn test_public_key() -> String {
        format!(
            "test-cache:{}",
            BASE64_STANDARD.encode(test_signing_key().verifying_key().as_bytes())
        )
    }

    fn write_manifest_cache_member(
        cache_root: &Path,
        store_path: &str,
        nar_bytes: &[u8],
        references: &[String],
    ) -> (PathBuf, PathBuf) {
        let narinfo_filename = narinfo_filename_for_store_path(store_path).unwrap();
        let hash = store_path_hash(store_path).unwrap();
        let nar_url = format!("nar/{hash}.nar");
        let nar_path = cache_root.join(&nar_url);
        fs::create_dir_all(nar_path.parent().unwrap()).unwrap();
        fs::write(&nar_path, nar_bytes).unwrap();
        let digest_bytes: [u8; 32] = Sha256::digest(nar_bytes).into();
        let digest = hex::encode(digest_bytes);
        let fingerprint_references = references
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join(",");
        let fingerprint = format!(
            "1;{store_path};sha256:{};{};{fingerprint_references}",
            encode_nix_base32_sha256(&digest_bytes),
            nar_bytes.len()
        );
        let signature = test_signing_key().sign(fingerprint.as_bytes());
        let narinfo_path = cache_root.join(narinfo_filename);
        fs::write(
            &narinfo_path,
            format!(
                "StorePath: {store_path}\n\
                 URL: {nar_url}\n\
                 Compression: none\n\
                 FileHash: sha256:{digest}\n\
                 FileSize: {}\n\
                 NarHash: sha256:{digest}\n\
                 NarSize: {}\n\
                 References: {}\n\
                 Sig: test-cache:{}\n",
                nar_bytes.len(),
                nar_bytes.len(),
                references.join(" "),
                BASE64_STANDARD.encode(signature.to_bytes())
            ),
        )
        .unwrap();
        (narinfo_path, nar_path)
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
        assert!(
            try_acquire_cache_mutation_lock_blocking(&cache_root)
                .unwrap()
                .is_none()
        );

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
        let immediate = try_acquire_cache_mutation_lock_blocking(&cache_root)
            .unwrap()
            .expect("non-blocking cache lease should become available after publication");
        drop(immediate);
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
    fn closure_manifest_is_complete_deterministic_and_canonical() {
        let root = test_temp_dir("closure-manifest");
        let root_store = test_store_path('d', "root");
        let dependency_a = test_store_path('a', "dependency-a");
        let dependency_b = test_store_path('b', "dependency-b");
        let shared = test_store_path('c', "shared");
        write_manifest_cache_member(&root, &shared, b"shared-nar", &[]);
        write_manifest_cache_member(
            &root,
            &dependency_a,
            b"dependency-a-nar",
            std::slice::from_ref(&shared),
        );
        write_manifest_cache_member(
            &root,
            &dependency_b,
            b"dependency-b-nar",
            std::slice::from_ref(&shared),
        );
        let (root_narinfo, _) = write_manifest_cache_member(
            &root,
            &root_store,
            b"root-nar",
            &[dependency_b.clone(), dependency_a.clone()],
        );
        let evaluated_derivation = test_store_path('f', "root.drv");

        let mut inspected = Vec::new();
        let first = build_closure_manifest(
            &root,
            &root_store,
            Some(&evaluated_derivation),
            &test_public_key(),
            &mut inspected,
        )
        .unwrap();
        assert_eq!(first.manifest["schema"], CLOSURE_MANIFEST_SCHEMA);
        assert_eq!(
            first
                .manifest
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "artifact_count",
                "artifacts",
                "evaluated_derivation",
                "manifest_sha256",
                "root_store_path",
                "schema",
                "total_file_size_bytes",
                "total_nar_size_bytes",
                "validation_level",
            ])
        );
        assert_eq!(first.manifest["root_store_path"], root_store);
        assert_eq!(first.manifest["evaluated_derivation"], evaluated_derivation);
        assert_eq!(first.manifest["artifact_count"], 4);
        assert_eq!(
            first.manifest["validation_level"],
            CLOSURE_MANIFEST_VALIDATION_LEVEL
        );
        assert_eq!(first.manifest["manifest_sha256"], first.manifest_sha256);
        let artifacts = first.manifest["artifacts"].as_array().unwrap();
        let store_paths = artifacts
            .iter()
            .map(|artifact| artifact["store_path"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            store_paths,
            vec![
                dependency_a.as_str(),
                dependency_b.as_str(),
                shared.as_str(),
                root_store.as_str(),
            ]
        );
        let root_artifact = artifacts
            .iter()
            .find(|artifact| artifact["store_path"] == root_store)
            .unwrap();
        assert_eq!(
            root_artifact
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "compression",
                "file_hash",
                "file_size_bytes",
                "nar_hash",
                "nar_size_bytes",
                "nar_url",
                "narinfo_path",
                "provenance",
                "references",
                "store_path",
            ])
        );
        assert_eq!(root_artifact["provenance"], "unknown");
        assert_eq!(
            root_artifact["references"],
            json!([dependency_a, dependency_b])
        );
        assert_eq!(
            root_artifact["narinfo_path"],
            root_narinfo.file_name().unwrap().to_str().unwrap()
        );
        assert_eq!(
            first.manifest["total_file_size_bytes"],
            (b"shared-nar".len()
                + b"dependency-a-nar".len()
                + b"dependency-b-nar".len()
                + b"root-nar".len()) as u64
        );
        assert_eq!(
            first.manifest["total_nar_size_bytes"],
            first.manifest["total_file_size_bytes"]
        );

        let mut unsigned = first.manifest.clone();
        unsigned.as_object_mut().unwrap().remove("manifest_sha256");
        assert_eq!(
            sha256_hex(&canonical_json_bytes(&unsigned).unwrap()),
            first.manifest_sha256
        );
        protected_material::validate_cache_metadata(&first.manifest).unwrap();
        let encoded = serde_json::to_string(&first.manifest).unwrap();
        assert!(!encoded.contains("CYBEX_FORGE_PROTECTED_SENTINEL"));
        assert!(!encoded.contains("$6$rounds="));

        // Reference ordering in NARInfo must not affect the manifest or its
        // digest.
        write_manifest_cache_member(
            &root,
            &root_store,
            b"root-nar",
            &[dependency_a, dependency_b],
        );
        let second = build_closure_manifest(
            &root,
            &root_store,
            Some(&evaluated_derivation),
            &test_public_key(),
            &mut Vec::new(),
        )
        .unwrap();
        assert_eq!(second.manifest, first.manifest);
        assert_eq!(second.manifest_sha256, first.manifest_sha256);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn closure_manifest_uses_null_for_unknown_derivation() {
        let root = test_temp_dir("closure-manifest-no-deriver");
        let root_store = test_store_path('a', "root");
        write_manifest_cache_member(&root, &root_store, b"root", &[]);

        let manifest = build_closure_manifest(
            &root,
            &root_store,
            None,
            &test_public_key(),
            &mut Vec::new(),
        )
        .unwrap();

        assert!(manifest.manifest["evaluated_derivation"].is_null());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn closure_manifest_rejects_missing_narinfo_and_nar_members() {
        let missing_narinfo_root = test_temp_dir("closure-manifest-missing-narinfo");
        let root_store = test_store_path('a', "root");
        let missing = test_store_path('b', "missing");
        write_manifest_cache_member(
            &missing_narinfo_root,
            &root_store,
            b"root",
            std::slice::from_ref(&missing),
        );
        let error = build_closure_manifest(
            &missing_narinfo_root,
            &root_store,
            None,
            &test_public_key(),
            &mut Vec::new(),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("open generated NARInfo"));

        let missing_nar_root = test_temp_dir("closure-manifest-missing-nar");
        let root_store = test_store_path('c', "root");
        let (_, nar_path) =
            write_manifest_cache_member(&missing_nar_root, &root_store, b"root", &[]);
        fs::remove_file(nar_path).unwrap();
        let error = build_closure_manifest(
            &missing_nar_root,
            &root_store,
            None,
            &test_public_key(),
            &mut Vec::new(),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("open generated NAR"));

        let _ = fs::remove_dir_all(missing_narinfo_root);
        let _ = fs::remove_dir_all(missing_nar_root);
    }

    #[test]
    fn closure_manifest_rejects_traversal_and_weak_nar_hashes() {
        let root = test_temp_dir("closure-manifest-traversal");
        let root_store = test_store_path('a', "root");
        let (narinfo_path, _) = write_manifest_cache_member(&root, &root_store, b"root", &[]);
        let raw = fs::read_to_string(&narinfo_path).unwrap();
        fs::write(&narinfo_path, raw.replace("URL: nar/", "URL: ../")).unwrap();
        let error = build_closure_manifest(
            &root,
            &root_store,
            None,
            &test_public_key(),
            &mut Vec::new(),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("NARInfo URL"));

        let ambiguous_root = test_temp_dir("closure-manifest-ambiguous-url");
        let ambiguous_store = test_store_path('c', "root");
        let (ambiguous_narinfo, _) =
            write_manifest_cache_member(&ambiguous_root, &ambiguous_store, b"root", &[]);
        let raw = fs::read_to_string(&ambiguous_narinfo).unwrap();
        fs::write(
            &ambiguous_narinfo,
            raw.replace(".nar\n", ".nar?download=1\n"),
        )
        .unwrap();
        let error = build_closure_manifest(
            &ambiguous_root,
            &ambiguous_store,
            None,
            &test_public_key(),
            &mut Vec::new(),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("canonical relative cache URI"));

        let weak_root = test_temp_dir("closure-manifest-weak-hash");
        let weak_store = test_store_path('b', "root");
        let (weak_narinfo, _) = write_manifest_cache_member(&weak_root, &weak_store, b"root", &[]);
        let raw = fs::read_to_string(&weak_narinfo).unwrap();
        fs::write(
            &weak_narinfo,
            raw.replace(
                &format!("NarHash: sha256:{}", sha256_hex(b"root")),
                "NarHash: sha256:short",
            ),
        )
        .unwrap();
        let error = build_closure_manifest(
            &weak_root,
            &weak_store,
            None,
            &test_public_key(),
            &mut Vec::new(),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("NarHash"));

        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_dir_all(ambiguous_root);
        let _ = fs::remove_dir_all(weak_root);
    }

    #[test]
    fn closure_manifest_requires_complete_unique_and_authentic_narinfo_fields() {
        let unsigned_root = test_temp_dir("closure-manifest-invalid-signature");
        let unsigned_store = test_store_path('a', "root");
        let (unsigned_narinfo, _) =
            write_manifest_cache_member(&unsigned_root, &unsigned_store, b"root", &[]);
        let raw = fs::read_to_string(&unsigned_narinfo).unwrap();
        let signature_start = raw.find("Sig: test-cache:").unwrap();
        let mut tampered = raw.into_bytes();
        let last_signature_byte = tampered[signature_start..]
            .iter()
            .rposition(|byte| *byte != b'\n' && *byte != b'=')
            .map(|offset| signature_start + offset)
            .unwrap();
        tampered[last_signature_byte] = if tampered[last_signature_byte] == b'A' {
            b'B'
        } else {
            b'A'
        };
        fs::write(&unsigned_narinfo, tampered).unwrap();
        let error = build_closure_manifest(
            &unsigned_root,
            &unsigned_store,
            None,
            &test_public_key(),
            &mut Vec::new(),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("valid signature"));

        let missing_root = test_temp_dir("closure-manifest-missing-references");
        let missing_store = test_store_path('b', "root");
        let (missing_narinfo, _) =
            write_manifest_cache_member(&missing_root, &missing_store, b"root", &[]);
        let raw = fs::read_to_string(&missing_narinfo).unwrap();
        fs::write(&missing_narinfo, raw.replace("References: \n", "")).unwrap();
        let error = build_closure_manifest(
            &missing_root,
            &missing_store,
            None,
            &test_public_key(),
            &mut Vec::new(),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("omitted the References field"));

        let duplicate_root = test_temp_dir("closure-manifest-duplicate-fields");
        let duplicate_store = test_store_path('c', "root");
        let (duplicate_narinfo, _) =
            write_manifest_cache_member(&duplicate_root, &duplicate_store, b"root", &[]);
        let mut raw = fs::read_to_string(&duplicate_narinfo).unwrap();
        raw.push_str("FileSize: 4\n");
        fs::write(&duplicate_narinfo, raw).unwrap();
        let error = build_closure_manifest(
            &duplicate_root,
            &duplicate_store,
            None,
            &test_public_key(),
            &mut Vec::new(),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("repeated the FileSize field"));

        let _ = fs::remove_dir_all(unsigned_root);
        let _ = fs::remove_dir_all(missing_root);
        let _ = fs::remove_dir_all(duplicate_root);
    }

    #[test]
    fn tampered_nar_fails_and_quarantines_signed_narinfo() {
        let root = test_temp_dir("closure-manifest-tampered");
        let cache_root = root.join("cache");
        let quarantine_root = root.join("private-quarantine");
        fs::create_dir_all(&cache_root).unwrap();
        let root_store = test_store_path('a', "root");
        let (narinfo_path, nar_path) =
            write_manifest_cache_member(&cache_root, &root_store, b"root", &[]);
        fs::write(&nar_path, b"evil").unwrap();

        let error = build_or_quarantine_closure_manifest(
            &cache_root,
            &quarantine_root,
            &root_store,
            None,
            &test_public_key(),
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("SHA-256"));
        assert!(error.contains("quarantined 1 NARInfo"));
        assert!(!narinfo_path.exists());
        assert_eq!(
            fs::metadata(&quarantine_root).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let batches = fs::read_dir(&quarantine_root)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(batches.len(), 1);
        assert!(
            batches[0]
                .path()
                .join(narinfo_path.file_name().unwrap())
                .is_file()
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn quarantine_unpublishes_only_the_candidate_root_and_failing_member() {
        let root = test_temp_dir("closure-manifest-selective-quarantine");
        let cache_root = root.join("cache");
        let quarantine_root = root.join("private-quarantine");
        fs::create_dir_all(&cache_root).unwrap();
        let root_store = test_store_path('d', "root");
        let valid_shared = test_store_path('b', "valid-shared");
        let corrupted = test_store_path('a', "corrupted");
        let (corrupt_narinfo, corrupt_nar) =
            write_manifest_cache_member(&cache_root, &corrupted, b"original", &[]);
        let (shared_narinfo, _) = write_manifest_cache_member(
            &cache_root,
            &valid_shared,
            b"shared",
            std::slice::from_ref(&corrupted),
        );
        let (root_narinfo, _) = write_manifest_cache_member(
            &cache_root,
            &root_store,
            b"root",
            std::slice::from_ref(&valid_shared),
        );
        fs::write(corrupt_nar, b"tampered").unwrap();

        let error = build_or_quarantine_closure_manifest(
            &cache_root,
            &quarantine_root,
            &root_store,
            None,
            &test_public_key(),
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("quarantined 2 NARInfo"));
        assert!(!root_narinfo.exists());
        assert!(!corrupt_narinfo.exists());
        assert!(shared_narinfo.exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn quarantine_cannot_be_placed_inside_the_served_cache() {
        let root = test_temp_dir("closure-manifest-served-quarantine");
        let cache_root = root.join("cache");
        let quarantine_root = cache_root.join("quarantine");
        fs::create_dir_all(&cache_root).unwrap();

        let error = prepare_quarantine_root(&cache_root, &quarantine_root)
            .unwrap_err()
            .to_string();

        assert!(error.contains("outside the served cache root"));
        assert!(!quarantine_root.exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn nix_base32_sha256_decoding_matches_nix_hash_output() {
        let decoded =
            decode_nix_base32_sha256("1nf4kwd9jxqdhdciwh1xvmrb4rnqg7jqwvjwc7mxmwcpr2fadkyi")
                .unwrap();

        assert_eq!(
            hex::encode(decoded),
            "d1cfa69cc897f1daeb615c6e8ee579d866b272dd3d401e59830d77991a9fc4d9"
        );
        assert_eq!(
            encode_nix_base32_sha256(&decoded),
            "1nf4kwd9jxqdhdciwh1xvmrb4rnqg7jqwvjwc7mxmwcpr2fadkyi"
        );
    }

    #[test]
    fn nix_generated_narinfo_signature_verifies() {
        let raw = "StorePath: /nix/store/yxi636lafq0dad0kds0cliiwz9pvjhqi-nixpkgs-26.05.drv\n\
URL: nar/1igsxfslfm383dzq03r1a4ihsbiw55xbdnl9n84k8bg0441nq8ca.nar.xz\n\
Compression: xz\n\
FileHash: sha256:1igsxfslfm383dzq03r1a4ihsbiw55xbdnl9n84k8bg0441nq8ca\n\
FileSize: 344\n\
NarHash: sha256:1ikmazsfprwyp4kfg9cgp22if0g08xckkrihiwqmzgqjddk7wxj7\n\
NarSize: 576\n\
References: cvy4yl0j7rbcqnrnpj89rqzd0iq8qyci-nixexprs.tar.xz\n\
Sig: cybex-test:5hs1RwT8NyAcDFKcOYuEufPJXuAVbfMv3XJ7lu9je2cqz0/0QRIFRj2uQPuXkthNe9BNyw2ImzzBOc4EWHSpDQ==\n\
CA: text:sha256:02ip8n5zbxc22shv5832dwhiaci5r9c306882a058savij6rnn7s\n";
        let mut narinfo = parse_narinfo_strict(raw).unwrap();
        narinfo.references.sort();

        verify_narinfo_signature(
            &narinfo,
            "cybex-test:4Cm07ebfb3cchJi1+QERxySdvysSmmX1BihUlu5qfL0=",
        )
        .unwrap();
    }

    #[test]
    fn narinfo_verification_rejects_the_weak_identity_key_and_legacy_forgery() {
        let mut identity = [0_u8; 32];
        identity[0] = 1;
        let weak_key = VerifyingKey::from_bytes(&identity).unwrap();
        assert!(weak_key.is_weak());
        let mut forged_bytes = [0_u8; 64];
        forged_bytes[0] = 1;
        let forged_signature = Signature::from_slice(&forged_bytes).unwrap();
        let narinfo = ParsedNarInfo {
            store_path: test_store_path('a', "weak-key"),
            url: "nar/weak.nar".to_string(),
            compression: "none".to_string(),
            file_hash: format!("sha256:{}", "0".repeat(64)),
            file_size: 1,
            nar_hash: format!("sha256:{}", "0".repeat(64)),
            nar_size: 1,
            references: Vec::new(),
            signatures: vec![format!(
                "weak-cache:{}",
                BASE64_STANDARD.encode(forged_bytes)
            )],
        };
        let nar_hash =
            encode_nix_base32_sha256(&parse_strong_sha256(&narinfo.nar_hash, "NarHash").unwrap());
        let fingerprint = format!(
            "1;{};sha256:{};{};{}",
            narinfo.store_path,
            nar_hash,
            narinfo.nar_size,
            narinfo.references.join(",")
        );
        assert!(
            weak_key
                .verify(fingerprint.as_bytes(), &forged_signature)
                .is_ok(),
            "the regression fixture must exercise legacy non-strict verification"
        );

        let public_key = format!("weak-cache:{}", BASE64_STANDARD.encode(identity));
        let error = verify_narinfo_signature(&narinfo, &public_key)
            .unwrap_err()
            .to_string();
        assert!(error.contains("weak Ed25519 key"));
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
        assert_eq!(validate_nar_url("nar/abc.nar.xz").unwrap(), "abc.nar.xz");
        assert!(validate_nar_url("../abc.nar.xz").is_err());
        assert!(validate_nar_url("/nar/abc.nar.xz").is_err());
        assert!(validate_nar_url("nar/abc.nar.xz?download=1").is_err());
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

    #[tokio::test]
    async fn integrity_scrub_rehashes_closure_members_and_quarantines_tampering() {
        let pool = db::connect_with_url("sqlite::memory:").await.unwrap();
        db::migrate(&pool).await.unwrap();
        let root = test_temp_dir("integrity-scrub-closure");
        let cache_root = root.join("cache");
        let data_root = root.join("data");
        fs::create_dir_all(&cache_root).unwrap();
        fs::create_dir_all(&data_root).unwrap();

        let root_store = test_store_path('a', "scrub-root");
        let second_root_store = test_store_path('c', "second-scrub-root");
        let dependency_store = test_store_path('b', "scrub-dependency");
        let (dependency_narinfo, dependency_nar) =
            write_manifest_cache_member(&cache_root, &dependency_store, &[0x31; 16], &[]);
        let (_root_narinfo, _root_nar) = write_manifest_cache_member(
            &cache_root,
            &root_store,
            &[0x41; 16],
            std::slice::from_ref(&dependency_store),
        );
        let (_second_root_narinfo, _second_root_nar) = write_manifest_cache_member(
            &cache_root,
            &second_root_store,
            &[0x51; 16],
            std::slice::from_ref(&dependency_store),
        );
        let public_key = test_public_key();
        let mut inspected = Vec::new();
        let verified =
            build_closure_manifest(&cache_root, &root_store, None, &public_key, &mut inspected)
                .unwrap();
        let root_narinfo_path = verified.root_narinfo_path.clone();
        let root_nar_path = verified.root_nar_path.clone();
        let mut inspected = Vec::new();
        let second_verified = build_closure_manifest(
            &cache_root,
            &second_root_store,
            None,
            &public_key,
            &mut inspected,
        )
        .unwrap();
        let second_root_narinfo_path = second_verified.root_narinfo_path.clone();
        let second_root_nar_path = second_verified.root_nar_path.clone();

        let mut config = AppConfig::default();
        config.cache.root_dir = cache_root.clone();
        config.paths.data_dir = data_root.clone();
        config.cache.private_key_path = data_root.join("cache-private-key");
        config.cache.public_key_path = data_root.join("cache-public-key");
        fs::write(&config.cache.private_key_path, "test-private-key").unwrap();
        fs::write(&config.cache.public_key_path, &public_key).unwrap();

        for (artifact_hash, verified) in [("c", verified), ("d", second_verified)] {
            let root_narinfo = verified.root_narinfo;
            db::create_cache_artifact(
                &pool,
                crate::models::CreateCacheArtifactRequest {
                    artifact_type: "nixos_closure".to_string(),
                    hash: artifact_hash.repeat(64),
                    size_bytes: root_narinfo.file_size,
                    path: verified.root_nar_path.display().to_string(),
                    store_path: Some(root_narinfo.store_path.clone()),
                    narinfo_path: Some(verified.root_narinfo_path.display().to_string()),
                    nar_url: Some(root_narinfo.url),
                    file_hash: Some(root_narinfo.file_hash),
                    nar_hash: Some(root_narinfo.nar_hash),
                    nar_size_bytes: Some(root_narinfo.nar_size),
                    closure_size_bytes: Some(32),
                    closure_file_size_bytes: Some(verified.total_file_size_bytes as i64),
                    compression: Some(root_narinfo.compression),
                    references: Some(json!(root_narinfo.references)),
                    serving_url: Some(format!(
                        "http://forge.example/cache/{}",
                        root_narinfo.store_path
                    )),
                    source_build_job_id: None,
                    cache_metadata: Some(json!({
                        "cache_schema": "cybex.forge.cache.v1",
                        "public_key_fingerprint": public_key_fingerprint(&public_key),
                        "closure_manifest": verified.manifest,
                        "closure_manifest_sha256": verified.manifest_sha256,
                    })),
                },
            )
            .await
            .unwrap();
        }

        // Preserve the dependency's byte length. A size/metadata-only scrub
        // accepts this corruption; strict closure verification must not.
        fs::write(&dependency_nar, [0x32; 16]).unwrap();

        // Only the first root is in the bounded sample. Once it exposes the
        // shared corrupt member, the scrub must cascade to the second root so
        // Manage cannot continue to report an incomplete closure as ready.
        assert_eq!(scrub_cache_artifacts(&pool, &config, 1).await.unwrap(), 2);
        assert!(db::list_cache_artifacts(&pool).await.unwrap().is_empty());
        assert!(!root_narinfo_path.exists());
        assert!(!second_root_narinfo_path.exists());
        assert!(!dependency_narinfo.exists());
        assert!(!root_nar_path.exists());
        assert!(!second_root_nar_path.exists());
        assert!(!dependency_nar.exists());
        let quarantined = fs::read_dir(data_root.join("cache-quarantine"))
            .unwrap()
            .flat_map(|batch| fs::read_dir(batch.unwrap().path()).unwrap())
            .count();
        assert_eq!(quarantined, 3);
        fs::remove_dir_all(root).ok();
    }

    #[tokio::test]
    async fn startup_remediation_unpublishes_root_and_preserves_shared_members() {
        let pool = db::connect_with_url("sqlite::memory:").await.unwrap();
        db::migrate(&pool).await.unwrap();
        let root = test_temp_dir("protected-upgrade-remediation");
        let cache_root = root.join("cache");
        let data_root = root.join("data");
        fs::create_dir_all(cache_root.join("nar")).unwrap();

        let mut config = AppConfig::default();
        config.cache.root_dir = cache_root.clone();
        config.paths.data_dir = data_root.clone();

        let managed_job_id = "legacy-protected-job";
        let job = db::upsert_managed_build_job(
            &pool,
            managed_job_id,
            "nixos_closure",
            None,
            Some("blueprint"),
            Some("x86_64-linux"),
            "legacy-revision",
            &"f".repeat(64),
            None,
        )
        .await
        .unwrap();
        let sentinel = "$6$rounds=5000$abcdefghijklmnop$protectedmaterial";
        let unsafe_spec = serde_json::to_string(&json!({
            "schema_version": 1,
            "build_input": {
                "kind": "blueprint_nixos_module",
                "generated_nix": format!(
                    "{{ ... }}: {{ users.users.alice.hashedPassword = \"{sentinel}\"; }}"
                )
            }
        }))
        .unwrap();

        let affected_store = test_store_path('a', "protected-system");
        let retained_store = test_store_path('b', "retained-system");
        let shared_store = test_store_path('c', "shared-dependency");
        let affected_nar = cache_root.join("nar/affected.nar.xz");
        let retained_nar = cache_root.join("nar/retained.nar.xz");
        let shared_nar = cache_root.join("nar/shared.nar.xz");
        let affected_narinfo = cache_root.join(format!("{}.narinfo", "a".repeat(32)));
        let retained_narinfo = cache_root.join(format!("{}.narinfo", "b".repeat(32)));
        let shared_narinfo = cache_root.join(format!("{}.narinfo", "c".repeat(32)));
        fs::write(
            &affected_nar,
            format!("legacy affected cache payload {sentinel}"),
        )
        .unwrap();
        fs::write(&retained_nar, b"retained-output").unwrap();
        fs::write(&shared_nar, b"shared-output").unwrap();
        fs::write(
            &affected_narinfo,
            format!(
                "URL: nar/affected.nar.xz\nReferences: {}\nX-Cybex-Legacy-Protected: {sentinel}\n",
                shared_store.trim_start_matches("/nix/store/")
            ),
        )
        .unwrap();
        fs::write(
            &retained_narinfo,
            format!(
                "URL: nar/retained.nar.xz\nReferences: {}\n",
                shared_store.trim_start_matches("/nix/store/")
            ),
        )
        .unwrap();
        fs::write(&shared_narinfo, "URL: nar/shared.nar.xz\nReferences: \n").unwrap();

        db::create_cache_artifact(
            &pool,
            crate::models::CreateCacheArtifactRequest {
                artifact_type: "nixos_closure".to_string(),
                hash: "a".repeat(64),
                size_bytes: fs::metadata(&affected_nar).unwrap().len() as i64,
                path: affected_nar.display().to_string(),
                store_path: Some(affected_store.clone()),
                narinfo_path: Some(affected_narinfo.display().to_string()),
                nar_url: Some("nar/affected.nar.xz".to_string()),
                file_hash: None,
                nar_hash: None,
                nar_size_bytes: None,
                closure_size_bytes: None,
                closure_file_size_bytes: None,
                compression: Some("xz".to_string()),
                references: Some(json!([shared_store])),
                serving_url: None,
                source_build_job_id: Some(managed_job_id.to_string()),
                cache_metadata: None,
            },
        )
        .await
        .unwrap();
        db::create_cache_artifact(
            &pool,
            crate::models::CreateCacheArtifactRequest {
                artifact_type: "nixos_closure".to_string(),
                hash: "b".repeat(64),
                size_bytes: 15,
                path: retained_nar.display().to_string(),
                store_path: Some(retained_store),
                narinfo_path: Some(retained_narinfo.display().to_string()),
                nar_url: Some("nar/retained.nar.xz".to_string()),
                file_hash: None,
                nar_hash: None,
                nar_size_bytes: None,
                closure_size_bytes: None,
                closure_file_size_bytes: None,
                compression: Some("xz".to_string()),
                references: Some(json!([])),
                serving_url: None,
                source_build_job_id: Some("safe-job".to_string()),
                cache_metadata: None,
            },
        )
        .await
        .unwrap();

        sqlx::query(
            "UPDATE forge_build_jobs
             SET build_spec = ?, status = 'succeeded', output_path = ?, logs = ?, error = ?
             WHERE id = ?",
        )
        .bind(&unsafe_spec)
        .bind(&affected_store)
        .bind(format!("legacy log {sentinel}"))
        .bind(format!("legacy error {sentinel}"))
        .bind(job.id)
        .execute(&pool)
        .await
        .unwrap();

        assert_eq!(db::quarantine_protected_build_jobs(&pool).await.unwrap(), 1);
        let ledger: (String, String, String, String) = sqlx::query_as(
            "SELECT original_status, rule, build_spec_sha256, cache_purge_status
             FROM protected_build_job_remediations WHERE job_id = ?",
        )
        .bind(job.id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(ledger.0, "succeeded");
        assert_eq!(ledger.1, "protected_build_spec");
        assert_eq!(ledger.2, sha256_hex(unsafe_spec.as_bytes()));
        assert_eq!(ledger.3, "pending_purge");
        let scrubbed: (String, String, String, String, String) = sqlx::query_as(
            "SELECT build_spec, cache_metadata, status, logs, error
             FROM forge_build_jobs WHERE id = ?",
        )
        .bind(job.id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(scrubbed.0.contains("security_quarantine"));
        assert!(scrubbed.1.contains("pending_purge"));
        assert_eq!(scrubbed.2, "failed");
        assert!(scrubbed.3.is_empty());
        assert!(!scrubbed.4.contains(sentinel));
        assert!(!format!("{scrubbed:?}{ledger:?}").contains(sentinel));

        let mut invalid_config = config.clone();
        invalid_config.paths.data_dir = cache_root.clone();
        let error = remediate_protected_build_jobs(&pool, &invalid_config)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("unpublish protected build root NARInfo"));
        assert!(!error.contains(sentinel));
        assert!(affected_narinfo.exists());
        assert_eq!(db::list_cache_artifacts(&pool).await.unwrap().len(), 2);
        let pending: String = sqlx::query_scalar(
            "SELECT cache_purge_status FROM protected_build_job_remediations WHERE job_id = ?",
        )
        .bind(job.id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(pending, "pending_purge");

        assert_eq!(
            remediate_protected_build_jobs(&pool, &config)
                .await
                .unwrap(),
            1
        );
        assert!(!affected_narinfo.exists());
        assert!(!affected_nar.exists());
        assert!(retained_narinfo.exists());
        assert!(retained_nar.exists());
        assert!(shared_narinfo.exists());
        assert!(shared_nar.exists());
        let mut public_paths = vec![cache_root.clone()];
        while let Some(path) = public_paths.pop() {
            for entry in fs::read_dir(path).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();
                assert!(!path.to_string_lossy().contains(sentinel));
                if entry.file_type().unwrap().is_dir() {
                    public_paths.push(path);
                } else if entry.file_type().unwrap().is_file() {
                    let contents = fs::read(path).unwrap();
                    assert!(
                        !contents
                            .windows(sentinel.len())
                            .any(|window| window == sentinel.as_bytes())
                    );
                }
            }
        }
        let artifacts = db::list_cache_artifacts(&pool).await.unwrap();
        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].hash, "b".repeat(64));
        let purge_status: (String, Option<String>) = sqlx::query_as(
            "SELECT cache_purge_status, purged_at
             FROM protected_build_job_remediations WHERE job_id = ?",
        )
        .bind(job.id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(purge_status.0, "purged");
        assert!(purge_status.1.is_some());
        let metadata: String =
            sqlx::query_scalar("SELECT cache_metadata FROM forge_build_jobs WHERE id = ?")
                .bind(job.id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(metadata.contains("\"status\":\"purged\""));
        assert!(!metadata.contains(sentinel));
        let quarantined_count = fs::read_dir(data_root.join("cache-quarantine"))
            .unwrap()
            .flat_map(|batch| fs::read_dir(batch.unwrap().path()).unwrap())
            .count();
        assert_eq!(quarantined_count, 1);

        assert_eq!(db::quarantine_protected_build_jobs(&pool).await.unwrap(), 0);
        assert_eq!(
            remediate_protected_build_jobs(&pool, &config)
                .await
                .unwrap(),
            0
        );
        assert_eq!(db::list_cache_artifacts(&pool).await.unwrap().len(), 1);
        fs::remove_dir_all(root).ok();
    }
}
