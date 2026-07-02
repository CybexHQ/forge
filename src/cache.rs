use std::{
    collections::HashSet,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, anyhow, bail};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use tokio::task;

use crate::{config::AppConfig, db, models::BuildJob};

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
        let metadata = json!({
            "cache_schema": "cybex.forge.cache.v1",
            "public_key_fingerprint": public_key_fingerprint(&public_key),
            "nix_cache_info": cache_info,
            "narinfo": narinfo_name,
            "signatures": narinfo.signatures,
            "file_size": narinfo.file_size,
            "nar_size": narinfo.nar_size,
            "closure_size": closure_size_bytes,
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
        &artifact.compression,
        Some(json!(artifact.references)),
        &serving_url,
        job.managed_job_id.as_deref(),
        Some(artifact.metadata),
    )
    .await
    .map_err(anyhow::Error::from)?;
    enforce_retention(pool, config).await?;
    Ok(())
}

pub async fn enforce_retention(pool: &SqlitePool, config: &AppConfig) -> Result<()> {
    if config.cache.max_bytes == 0 {
        return Ok(());
    }
    let artifacts = db::list_cache_artifacts(pool).await?;
    let mut total: u64 = artifacts
        .iter()
        .map(|artifact| artifact.size_bytes.max(0) as u64)
        .sum();
    if total <= config.cache.max_bytes {
        return Ok(());
    }
    let build_jobs = db::list_build_jobs(pool).await?;
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
    let mut candidates = artifacts;
    candidates.sort_by(|left, right| left.created_at.cmp(&right.created_at));
    for artifact in candidates {
        if total <= config.cache.max_bytes {
            break;
        }
        if artifact
            .source_build_job_id
            .as_deref()
            .is_some_and(|id| protected_sources.contains(id))
        {
            continue;
        }
        let bytes = artifact.size_bytes.max(0) as u64;
        remove_cache_artifact_files(config, &artifact.path, &artifact.narinfo_path)?;
        db::delete_cache_artifact(pool, artifact.id).await?;
        total = total.saturating_sub(bytes);
    }
    Ok(())
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

fn remove_cache_artifact_files(
    config: &AppConfig,
    nar_path: &str,
    narinfo_path: &str,
) -> Result<()> {
    for path in [nar_path, narinfo_path] {
        let path = Path::new(path);
        if path.as_os_str().is_empty() {
            continue;
        }
        ensure_cache_path(config, path)?;
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                bail!(
                    "refusing to delete symlinked cache artifact {}",
                    path.display()
                );
            }
            Ok(metadata) if metadata.is_file() => {
                fs::remove_file(path)
                    .with_context(|| format!("remove cache artifact {}", path.display()))?;
            }
            Ok(_) => bail!(
                "refusing to delete non-file cache artifact {}",
                path.display()
            ),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(err).with_context(|| format!("stat cache artifact {}", path.display()));
            }
        }
    }
    Ok(())
}

fn ensure_cache_path(config: &AppConfig, path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        bail!("cache artifact path is not normalized");
    }
    if !path.starts_with(&config.cache.root_dir) {
        bail!("cache artifact path is outside cache root");
    }
    Ok(())
}

fn public_key_fingerprint(public_key: &str) -> String {
    sha256_hex(public_key.as_bytes()).chars().take(24).collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn sanitize_error(err: &anyhow::Error) -> String {
    let text = err.to_string();
    text.replace("secret-key=", "secret-key=REDACTED")
        .chars()
        .take(512)
        .collect()
}

fn bounded_command_error(stderr: &[u8], private_key: &Path) -> String {
    String::from_utf8_lossy(stderr)
        .replace(&private_key.display().to_string(), "[cache-private-key]")
        .replace("secret-key=", "secret-key=REDACTED")
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
             printf '%s\\n' \"$2:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcd\" > \"$4\"\n",
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
        assert_eq!(public_key_fingerprint(&public).len(), 24);
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
    fn cache_delete_paths_must_stay_under_root() {
        let mut config = AppConfig::default();
        config.cache.root_dir = PathBuf::from("/srv/cybex-forge/www/cache");

        assert!(ensure_cache_path(&config, Path::new("/srv/cybex-forge/www/cache/nar/a")).is_ok());
        assert!(
            ensure_cache_path(&config, Path::new("/srv/cybex-forge/www/cache/../secret")).is_err()
        );
        assert!(ensure_cache_path(&config, Path::new("/srv/cybex-forge/www/other")).is_err());
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
            "cybex-forge-cache:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcd",
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
        assert_eq!(report.public_key_fingerprint.len(), 24);
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
}
