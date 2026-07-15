use std::{
    collections::HashMap,
    io::SeekFrom,
    os::unix::fs::MetadataExt,
    os::unix::fs::OpenOptionsExt,
    path::{Component, Path, PathBuf},
    pin::Pin,
};

use axum::{
    body::Body,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use tokio::{
    fs::{self, File},
    io::{AsyncRead, AsyncReadExt, AsyncSeekExt},
};
use tokio_util::io::ReaderStream;

use crate::{
    config::AppConfig,
    db::{self, IsoAssetFileIdentity, IsoAssetScanState},
    error::{AppError, AppResult},
};

const ISO_CHECKSUM_REVERIFY_SECONDS: i64 = 6 * 60 * 60;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IsoScanSummary {
    pub discovered: usize,
    pub hashed: usize,
    pub reused: usize,
}

#[derive(Debug)]
struct IsoScanCandidate {
    path: PathBuf,
    filename: String,
    relative_path: String,
    identity: IsoAssetFileIdentity,
    cached: Option<IsoAssetScanState>,
}

pub fn sanitize_relative_path(input: &str) -> AppResult<PathBuf> {
    let trimmed = input.trim();
    if trimmed.starts_with('/') || trimmed.starts_with('\\') {
        return Err(AppError::UnsafePath);
    }
    if trimmed.is_empty() {
        return Err(AppError::UnsafePath);
    }

    let path = Path::new(trimmed);
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => out.push(part),
            Component::CurDir
            | Component::ParentDir
            | Component::RootDir
            | Component::Prefix(_) => return Err(AppError::UnsafePath),
        }
    }

    if out.as_os_str().is_empty() {
        return Err(AppError::UnsafePath);
    }
    Ok(out)
}

pub fn asset_url(public_base_url: &str, relative_path: &str) -> AppResult<String> {
    let safe_path = sanitize_relative_path(relative_path)?;
    let encoded = safe_path
        .components()
        .filter_map(|component| match component {
            Component::Normal(part) => {
                Some(urlencoding::encode(&part.to_string_lossy()).to_string())
            }
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/");
    Ok(format!(
        "{}/files/{}",
        public_base_url.trim_end_matches('/'),
        encoded
    ))
}

pub async fn serve_file_from_root(
    root: &Path,
    requested_path: &str,
    headers: &HeaderMap,
) -> AppResult<Response> {
    let safe_path = sanitize_relative_path(requested_path)?;
    let full_path = root.join(safe_path);
    reject_symlink_components(root, &full_path).await?;
    let root_canonical = fs::canonicalize(root).await?;
    let full_canonical = fs::canonicalize(&full_path).await.map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            AppError::NotFound
        } else {
            AppError::Io(err)
        }
    })?;

    if !full_canonical.starts_with(&root_canonical) {
        return Err(AppError::UnsafePath);
    }

    let file = open_regular_file_no_symlink(&full_canonical).await?;
    let metadata = file.metadata().await?;
    if !metadata.is_file() {
        return Err(AppError::NotFound);
    }

    let file_len = metadata.len();
    let content_type = mime_guess::from_path(&full_canonical)
        .first_or_octet_stream()
        .to_string();
    let range = headers
        .get(header::RANGE)
        .and_then(|value| value.to_str().ok());

    match parse_byte_range(range, file_len) {
        Ok(Some((start, end))) => {
            let mut file = file;
            file.seek(SeekFrom::Start(start)).await?;
            let length = end - start + 1;
            let stream = ReaderStream::new(file.take(length));
            let body = Body::from_stream(stream);
            Response::builder()
                .status(StatusCode::PARTIAL_CONTENT)
                .header(header::CONTENT_TYPE, content_type)
                .header(header::ACCEPT_RANGES, "bytes")
                .header(
                    header::CONTENT_RANGE,
                    format!("bytes {start}-{end}/{file_len}"),
                )
                .header(header::CONTENT_LENGTH, length.to_string())
                .body(body)
                .map_err(|err| AppError::Config(err.to_string()))
        }
        Ok(None) => {
            let stream = ReaderStream::new(file);
            let body = Body::from_stream(stream);
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, content_type)
                .header(header::ACCEPT_RANGES, "bytes")
                .header(header::CONTENT_LENGTH, file_len.to_string())
                .body(body)
                .map_err(|err| AppError::Config(err.to_string()))
        }
        Err(()) => range_not_satisfiable_response(file_len),
    }
}

async fn reject_symlink_components(root: &Path, full_path: &Path) -> AppResult<()> {
    let relative = full_path
        .strip_prefix(root)
        .map_err(|_| AppError::UnsafePath)?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        match component {
            Component::Normal(part) => {
                current.push(part);
                let metadata = fs::symlink_metadata(&current).await.map_err(|err| {
                    if err.kind() == std::io::ErrorKind::NotFound {
                        AppError::NotFound
                    } else {
                        AppError::Io(err)
                    }
                })?;
                if metadata.file_type().is_symlink() {
                    return Err(AppError::UnsafePath);
                }
            }
            _ => return Err(AppError::UnsafePath),
        }
    }
    Ok(())
}

async fn open_regular_file_no_symlink(path: &Path) -> AppResult<File> {
    let path = path.to_path_buf();
    let file = tokio::task::spawn_blocking(move || {
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
    })
    .await
    .map_err(|err| AppError::Config(err.to_string()))?
    .map_err(|err| {
        if err.raw_os_error() == Some(libc::ELOOP) {
            AppError::UnsafePath
        } else if err.kind() == std::io::ErrorKind::NotFound {
            AppError::NotFound
        } else {
            AppError::Io(err)
        }
    })?;
    Ok(File::from_std(file))
}

fn range_not_satisfiable_response(file_len: u64) -> AppResult<Response> {
    Response::builder()
        .status(StatusCode::RANGE_NOT_SATISFIABLE)
        .header(header::ACCEPT_RANGES, "bytes")
        .header(header::CONTENT_RANGE, format!("bytes */{file_len}"))
        .body(Body::empty())
        .map_err(|err| AppError::Config(err.to_string()))
}

fn parse_byte_range(range: Option<&str>, file_len: u64) -> Result<Option<(u64, u64)>, ()> {
    let Some(range) = range.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let Some(spec) = range.strip_prefix("bytes=") else {
        return Err(());
    };
    if spec.contains(',') || file_len == 0 {
        return Err(());
    }
    let Some((start, end)) = spec.split_once('-') else {
        return Err(());
    };
    let start = start.trim();
    let end = end.trim();
    if start.is_empty() {
        let suffix_len = end.parse::<u64>().map_err(|_| ())?;
        if suffix_len == 0 {
            return Err(());
        }
        let start = file_len.saturating_sub(suffix_len);
        return Ok(Some((start, file_len - 1)));
    }

    let start = start.parse::<u64>().map_err(|_| ())?;
    if start >= file_len {
        return Err(());
    }
    let end = if end.is_empty() {
        file_len - 1
    } else {
        end.parse::<u64>().map_err(|_| ())?.min(file_len - 1)
    };
    if end < start {
        return Err(());
    }
    Ok(Some((start, end)))
}

pub async fn scan_iso_dir(config: &AppConfig, pool: &SqlitePool) -> AppResult<IsoScanSummary> {
    let scan_started_at = chrono::Utc::now();
    let checksum_cutoff =
        scan_started_at - chrono::Duration::seconds(ISO_CHECKSUM_REVERIFY_SECONDS);
    let verified_at = scan_started_at.to_rfc3339();
    let mut summary = IsoScanSummary::default();
    let mut scanned_relative_paths = Vec::new();
    let iso_root = config.paths.iso_dir.clone();
    fs::create_dir_all(&iso_root).await?;
    let existing = db::list_iso_asset_scan_states(pool)
        .await?
        .into_iter()
        .map(|asset| (asset.relative_path.clone(), asset))
        .collect::<HashMap<_, _>>();
    let mut candidates = Vec::new();

    let mut pending = vec![iso_root.clone()];
    while let Some(dir) = pending.pop() {
        let mut entries = fs::read_dir(&dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            let file_type = entry.file_type().await?;
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                pending.push(path);
                continue;
            }
            if !file_type.is_file() || !is_iso_path(&path) {
                continue;
            }

            let relative = path
                .strip_prefix(&iso_root)
                .map_err(|err| AppError::Config(err.to_string()))?;
            let relative_path = relative.to_string_lossy().replace('\\', "/");
            sanitize_relative_path(&relative_path)?;
            scanned_relative_paths.push(relative_path.clone());

            let metadata = fs::symlink_metadata(&path).await?;
            if !metadata.file_type().is_file() {
                continue;
            }
            let identity = iso_file_identity(&metadata)?;
            let filename = path
                .file_name()
                .map(|name| name.to_string_lossy().to_string())
                .ok_or_else(|| AppError::Validation("ISO path has no filename".to_string()))?;
            let cached = existing.get(&relative_path).cloned().filter(|asset| {
                asset.file_identity() == Some(identity)
                    && valid_sha256(&asset.checksum_sha256)
                    && asset.checksum_verified_at.is_some()
            });
            candidates.push(IsoScanCandidate {
                path,
                filename,
                relative_path,
                identity,
                cached,
            });
        }
    }
    candidates.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));

    // Bound periodic integrity work to one otherwise unchanged ISO per scan.
    // New or metadata-changed files are always hashed immediately.
    let periodic_reverify = candidates
        .iter()
        .enumerate()
        .filter_map(|(index, candidate)| {
            let cached = candidate.cached.as_ref()?;
            checksum_verification_due(
                cached.checksum_verified_at.as_deref(),
                scan_started_at,
                checksum_cutoff,
            )
            .then_some((
                index,
                parsed_checksum_time(cached.checksum_verified_at.as_deref()),
            ))
        })
        .min_by(|(left_index, left_time), (right_index, right_time)| {
            left_time.cmp(right_time).then_with(|| {
                candidates[*left_index]
                    .relative_path
                    .cmp(&candidates[*right_index].relative_path)
            })
        })
        .map(|(index, _)| index);

    for (index, candidate) in candidates.into_iter().enumerate() {
        let (checksum, identity, checksum_verified_at) = if let Some(cached) = candidate
            .cached
            .as_ref()
            .filter(|_| periodic_reverify != Some(index))
        {
            summary.reused += 1;
            let checksum_verified_at = cached.checksum_verified_at.clone().ok_or_else(|| {
                AppError::Config("cached ISO checksum has no verification timestamp".to_string())
            })?;
            (
                cached.checksum_sha256.clone(),
                candidate.identity,
                checksum_verified_at,
            )
        } else {
            summary.hashed += 1;
            let (checksum, identity) = sha256_file(&candidate.path).await?;
            (checksum, identity, verified_at.clone())
        };
        db::upsert_iso_asset(
            pool,
            &candidate.filename,
            &candidate.relative_path,
            identity,
            &checksum,
            &checksum_verified_at,
        )
        .await?;
        summary.discovered += 1;
    }
    db::prune_missing_iso_assets(pool, &scanned_relative_paths).await?;
    tracing::debug!(
        discovered = summary.discovered,
        hashed = summary.hashed,
        reused = summary.reused,
        "ISO inventory scan completed"
    );

    Ok(summary)
}

fn checksum_verification_due(
    verified_at: Option<&str>,
    now: chrono::DateTime<chrono::Utc>,
    cutoff: chrono::DateTime<chrono::Utc>,
) -> bool {
    parsed_checksum_time(verified_at).is_none_or(|verified| verified <= cutoff || verified > now)
}

fn parsed_checksum_time(value: Option<&str>) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(value?)
        .ok()
        .map(|value| value.with_timezone(&chrono::Utc))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn iso_file_identity(metadata: &std::fs::Metadata) -> AppResult<IsoAssetFileIdentity> {
    let size_bytes = i64::try_from(metadata.len())
        .map_err(|_| AppError::Validation("ISO size exceeds supported range".to_string()))?;
    Ok(IsoAssetFileIdentity {
        size_bytes,
        device: metadata.dev() as i64,
        inode: metadata.ino() as i64,
        mtime_seconds: metadata.mtime(),
        mtime_nanoseconds: metadata.mtime_nsec(),
        ctime_seconds: metadata.ctime(),
        ctime_nanoseconds: metadata.ctime_nsec(),
    })
}

async fn sha256_file(path: &Path) -> AppResult<(String, IsoAssetFileIdentity)> {
    let file = open_regular_file_no_symlink(path).await?;
    let before = iso_file_identity(&file.metadata().await?)?;
    let checksum = sha256_reader(file).await?;
    let path_metadata = fs::symlink_metadata(path).await?;
    if !path_metadata.file_type().is_file() || iso_file_identity(&path_metadata)? != before {
        return Err(AppError::Config(format!(
            "ISO changed while checksumming: {}",
            path.display()
        )));
    }
    Ok((checksum, before))
}

async fn sha256_reader<R>(mut reader: R) -> AppResult<String>
where
    R: AsyncRead + Unpin,
{
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 128];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn is_iso_path(path: &Path) -> bool {
    path.extension()
        .map(|ext| ext.to_string_lossy().eq_ignore_ascii_case("iso"))
        .unwrap_or(false)
}

pub fn redirect_to(location: &str) -> Response {
    (
        StatusCode::SEE_OTHER,
        [(header::LOCATION, location.to_string())],
        Body::empty(),
    )
        .into_response()
}

#[allow(dead_code)]
type BoxedReader = Pin<Box<dyn AsyncRead + Send>>;

#[cfg(test)]
mod tests {
    use super::{asset_url, parse_byte_range, sanitize_relative_path, serve_file_from_root};
    use crate::{config::AppConfig, db};
    use axum::http::{HeaderMap, StatusCode};
    use std::{
        fs,
        os::unix::fs::symlink,
        sync::atomic::{AtomicU64, Ordering},
    };

    #[test]
    fn rejects_path_traversal() {
        assert!(sanitize_relative_path("../secret").is_err());
        assert!(sanitize_relative_path("kernels/../../secret").is_err());
        assert!(sanitize_relative_path("/absolute/path").is_err());
    }

    #[test]
    fn rejects_empty_paths() {
        assert!(sanitize_relative_path("").is_err());
        assert!(sanitize_relative_path("/").is_err());
    }

    #[test]
    fn builds_asset_urls_by_segment() {
        let url = asset_url("http://boot.local:8080", "ubuntu 24/vmlinuz").unwrap();
        assert_eq!(url, "http://boot.local:8080/files/ubuntu%2024/vmlinuz");
    }

    #[test]
    fn parses_byte_ranges() {
        assert_eq!(parse_byte_range(None, 10).unwrap(), None);
        assert_eq!(
            parse_byte_range(Some("bytes=0-3"), 10).unwrap(),
            Some((0, 3))
        );
        assert_eq!(
            parse_byte_range(Some("bytes=4-"), 10).unwrap(),
            Some((4, 9))
        );
        assert_eq!(
            parse_byte_range(Some("bytes=-4"), 10).unwrap(),
            Some((6, 9))
        );
        assert_eq!(
            parse_byte_range(Some("bytes=-20"), 10).unwrap(),
            Some((0, 9))
        );
        assert_eq!(
            parse_byte_range(Some("bytes=8-20"), 10).unwrap(),
            Some((8, 9))
        );
    }

    #[test]
    fn rejects_unsatisfiable_or_unsupported_ranges() {
        assert!(parse_byte_range(Some("bytes=10-12"), 10).is_err());
        assert!(parse_byte_range(Some("bytes=4-3"), 10).is_err());
        assert!(parse_byte_range(Some("bytes=-0"), 10).is_err());
        assert!(parse_byte_range(Some("bytes=0-1,3-4"), 10).is_err());
        assert!(parse_byte_range(Some("items=0-1"), 10).is_err());
        assert!(parse_byte_range(Some("bytes=0-0"), 0).is_err());
    }

    #[tokio::test]
    async fn serve_file_rejects_symlink_components() {
        let root = temp_asset_root();
        fs::write(root.join("real.iso"), b"iso").unwrap();

        let response = serve_file_from_root(&root, "real.iso", &HeaderMap::new())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        symlink(root.join("real.iso"), root.join("link.iso")).unwrap();
        let err = serve_file_from_root(&root, "link.iso", &HeaderMap::new())
            .await
            .unwrap_err();
        assert_eq!(err.code(), "unsafe_path");

        fs::create_dir(root.join("nested")).unwrap();
        fs::write(root.join("nested/inside.iso"), b"iso").unwrap();
        symlink(root.join("nested"), root.join("dirlink")).unwrap();
        let err = serve_file_from_root(&root, "dirlink/inside.iso", &HeaderMap::new())
            .await
            .unwrap_err();
        assert_eq!(err.code(), "unsafe_path");

        fs::remove_dir_all(&root).unwrap();
    }

    #[tokio::test]
    async fn scan_iso_dir_prunes_deleted_assets_after_successful_scan() {
        let root = temp_asset_root();
        fs::write(root.join("present.iso"), b"iso").unwrap();

        let mut config = AppConfig::default();
        config.paths.iso_dir = root.clone();
        let pool = db::connect_with_url("sqlite::memory:").await.unwrap();
        db::migrate(&pool).await.unwrap();
        db::upsert_iso_asset(
            &pool,
            "stale.iso",
            "stale.iso",
            db::IsoAssetFileIdentity {
                size_bytes: 1,
                device: 1,
                inode: 2,
                mtime_seconds: 3,
                mtime_nanoseconds: 4,
                ctime_seconds: 5,
                ctime_nanoseconds: 6,
            },
            &"b".repeat(64),
            "2026-07-15T00:00:00Z",
        )
        .await
        .unwrap();

        let summary = super::scan_iso_dir(&config, &pool).await.unwrap();
        let assets = db::list_iso_assets(&pool).await.unwrap();

        assert_eq!(summary.discovered, 1);
        assert_eq!(summary.hashed, 1);
        assert_eq!(assets.len(), 1);
        assert_eq!(assets[0].relative_path, "present.iso");

        fs::remove_dir_all(&root).unwrap();
    }

    #[tokio::test]
    async fn scan_iso_dir_reuses_unchanged_checksum_and_rehashes_changes() {
        let root = temp_asset_root();
        let path = root.join("present.iso");
        fs::write(&path, b"first").unwrap();

        let mut config = AppConfig::default();
        config.paths.iso_dir = root.clone();
        let pool = db::connect_with_url("sqlite::memory:").await.unwrap();
        db::migrate(&pool).await.unwrap();

        let first = super::scan_iso_dir(&config, &pool).await.unwrap();
        let first_checksum = db::list_iso_assets(&pool).await.unwrap()[0]
            .checksum_sha256
            .clone();
        let unchanged = super::scan_iso_dir(&config, &pool).await.unwrap();

        fs::write(&path, b"other").unwrap();
        let changed = super::scan_iso_dir(&config, &pool).await.unwrap();
        let changed_checksum = db::list_iso_assets(&pool).await.unwrap()[0]
            .checksum_sha256
            .clone();

        assert_eq!(first.hashed, 1);
        assert_eq!(unchanged.hashed, 0);
        assert_eq!(unchanged.reused, 1);
        assert_eq!(changed.hashed, 1);
        assert_ne!(changed_checksum, first_checksum);

        fs::remove_dir_all(&root).unwrap();
    }

    #[tokio::test]
    async fn scan_iso_dir_hashes_legacy_rows_without_file_identity() {
        let root = temp_asset_root();
        fs::write(root.join("present.iso"), b"iso").unwrap();

        let mut config = AppConfig::default();
        config.paths.iso_dir = root.clone();
        let pool = db::connect_with_url("sqlite::memory:").await.unwrap();
        db::migrate(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO iso_assets
             (filename, relative_path, size_bytes, checksum_sha256,
              last_scanned_at, created_at, updated_at)
             VALUES ('present.iso', 'present.iso', 3, ?, ?, ?, ?)",
        )
        .bind("a".repeat(64))
        .bind("2026-07-15T00:00:00Z")
        .bind("2026-07-15T00:00:00Z")
        .bind("2026-07-15T00:00:00Z")
        .execute(&pool)
        .await
        .unwrap();

        let summary = super::scan_iso_dir(&config, &pool).await.unwrap();
        let state = db::list_iso_asset_scan_states(&pool).await.unwrap();

        assert_eq!(summary.hashed, 1);
        assert_eq!(summary.reused, 0);
        assert!(state[0].file_identity().is_some());

        fs::remove_dir_all(&root).unwrap();
    }

    #[tokio::test]
    async fn scan_iso_dir_bounds_periodic_reverification_to_one_unchanged_iso() {
        let root = temp_asset_root();
        fs::write(root.join("one.iso"), b"one").unwrap();
        fs::write(root.join("two.iso"), b"two").unwrap();

        let mut config = AppConfig::default();
        config.paths.iso_dir = root.clone();
        let pool = db::connect_with_url("sqlite::memory:").await.unwrap();
        db::migrate(&pool).await.unwrap();
        super::scan_iso_dir(&config, &pool).await.unwrap();
        sqlx::query("UPDATE iso_assets SET checksum_verified_at = '2000-01-01T00:00:00Z'")
            .execute(&pool)
            .await
            .unwrap();

        let first_due = super::scan_iso_dir(&config, &pool).await.unwrap();
        let second_due = super::scan_iso_dir(&config, &pool).await.unwrap();
        let current = super::scan_iso_dir(&config, &pool).await.unwrap();

        assert_eq!(first_due.hashed, 1);
        assert_eq!(first_due.reused, 1);
        assert_eq!(second_due.hashed, 1);
        assert_eq!(second_due.reused, 1);
        assert_eq!(current.hashed, 0);
        assert_eq!(current.reused, 2);

        fs::remove_dir_all(&root).unwrap();
    }

    fn temp_asset_root() -> std::path::PathBuf {
        static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        for _ in 0..100 {
            let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "cybex-forge-assets-test-{}-{unique}-{id}",
                std::process::id()
            ));
            match fs::create_dir(&root) {
                Ok(()) => return root,
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(err) => panic!("create temp asset root {}: {err}", root.display()),
            }
        }
        panic!("failed to allocate a unique temp asset root");
    }
}
