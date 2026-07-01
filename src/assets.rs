use std::{
    io::SeekFrom,
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
    db,
    error::{AppError, AppResult},
};

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

pub async fn scan_iso_dir(config: &AppConfig, pool: &SqlitePool) -> AppResult<usize> {
    let mut count = 0usize;
    let mut scanned_relative_paths = Vec::new();
    let iso_root = config.paths.iso_dir.clone();
    fs::create_dir_all(&iso_root).await?;

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

            let metadata = fs::metadata(&path).await?;
            let checksum = sha256_file(&path).await?;
            let filename = path
                .file_name()
                .map(|name| name.to_string_lossy().to_string())
                .ok_or_else(|| AppError::Validation("ISO path has no filename".to_string()))?;

            db::upsert_iso_asset(
                pool,
                &filename,
                &relative_path,
                metadata.len() as i64,
                &checksum,
            )
            .await?;
            count += 1;
        }
    }
    db::prune_missing_iso_assets(pool, &scanned_relative_paths).await?;

    Ok(count)
}

async fn sha256_file(path: &Path) -> AppResult<String> {
    let file = File::open(path).await?;
    sha256_reader(file).await
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
    use std::{fs, os::unix::fs::symlink};

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
        db::upsert_iso_asset(&pool, "stale.iso", "stale.iso", 1, &"b".repeat(64))
            .await
            .unwrap();

        let count = super::scan_iso_dir(&config, &pool).await.unwrap();
        let assets = db::list_iso_assets(&pool).await.unwrap();

        assert_eq!(count, 1);
        assert_eq!(assets.len(), 1);
        assert_eq!(assets[0].relative_path, "present.iso");

        fs::remove_dir_all(&root).unwrap();
    }

    fn temp_asset_root() -> std::path::PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "cybex-boot-assets-test-{}-{unique}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        root
    }
}
