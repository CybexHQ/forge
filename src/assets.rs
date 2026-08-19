use std::{
    io::SeekFrom,
    os::unix::fs::OpenOptionsExt,
    path::{Component, Path, PathBuf},
};

use axum::{
    body::Body,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use tokio::{
    fs::{self, File},
    io::{AsyncReadExt, AsyncSeekExt},
};
use tokio_util::io::ReaderStream;

use crate::error::{AppError, AppResult};

const NIX_BASE32_ALPHABET: &[u8] = b"0123456789abcdfghijklmnpqrsvwxyz";
const NAR_COMPRESSION_SUFFIXES: &[&str] = &[".xz", ".bz2", ".zst", ".gz", ".lzip", ".lz4", ".br"];

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

/// Serve only the file layout emitted by a Nix static binary cache. This
/// endpoint is intentionally unauthenticated, so unrelated files must remain
/// unreachable even if an operator accidentally places them below the cache
/// document root.
pub async fn serve_binary_cache_member_from_root(
    root: &Path,
    requested_path: &str,
    headers: &HeaderMap,
) -> AppResult<Response> {
    if !is_binary_cache_member_path(requested_path) {
        return Err(AppError::NotFound);
    }
    serve_file_from_root(root, requested_path, headers).await
}

pub(crate) fn is_binary_cache_member_path(requested_path: &str) -> bool {
    if requested_path.trim() != requested_path
        || requested_path.contains("//")
        || sanitize_relative_path(requested_path).is_err()
    {
        return false;
    };
    let components = requested_path.split('/').collect::<Vec<_>>();
    match components.as_slice() {
        ["nix-cache-info"] => true,
        [filename] => filename
            .strip_suffix(".narinfo")
            .is_some_and(|hash| valid_nix_base32(hash, 32)),
        ["nar", filename] => valid_nar_member_filename(filename),
        _ => false,
    }
}

fn valid_nar_member_filename(filename: &str) -> bool {
    let Some(without_nar) = filename.strip_suffix(".nar").or_else(|| {
        NAR_COMPRESSION_SUFFIXES.iter().find_map(|compression| {
            filename
                .strip_suffix(compression)
                .and_then(|value| value.strip_suffix(".nar"))
        })
    }) else {
        return false;
    };
    valid_nix_base32(without_nar, 52)
}

fn valid_nix_base32(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len
        && value
            .bytes()
            .all(|byte| NIX_BASE32_ALPHABET.contains(&byte))
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

pub fn redirect_to(location: &str) -> Response {
    (
        StatusCode::SEE_OTHER,
        [(header::LOCATION, location.to_string())],
        Body::empty(),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::{
        asset_url, is_binary_cache_member_path, parse_byte_range, sanitize_relative_path,
        serve_binary_cache_member_from_root, serve_file_from_root,
    };
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
    fn binary_cache_member_allowlist_matches_nix_static_cache_layout() {
        let store_hash = "0".repeat(32);
        let file_hash = "1".repeat(52);
        assert!(is_binary_cache_member_path("nix-cache-info"));
        assert!(is_binary_cache_member_path(&format!(
            "{store_hash}.narinfo"
        )));
        for suffix in ["", ".xz", ".bz2", ".zst", ".gz", ".lzip", ".lz4", ".br"] {
            assert!(
                is_binary_cache_member_path(&format!("nar/{file_hash}.nar{suffix}")),
                "expected NAR compression suffix {suffix:?} to be allowed"
            );
        }

        for path in [
            "cache-priv-key.pem",
            "cache-pub-key.pem",
            "manifest.json",
            ".nix-cache-info.tmp",
            "narinfo/00000000000000000000000000000000",
            "nar/secret.txt",
            " nix-cache-info ",
            "nar//1111111111111111111111111111111111111111111111111111.nar.xz",
            "nar/nested/1111111111111111111111111111111111111111111111111111.nar.xz",
            "0000000000000000000000000000000.narinfo",
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee.narinfo",
            "nar/111111111111111111111111111111111111111111111111111.nar.xz",
            "nar/1111111111111111111111111111111111111111111111111111.nar.zip",
        ] {
            assert!(
                !is_binary_cache_member_path(path),
                "unexpected public cache member: {path}"
            );
        }
    }

    #[tokio::test]
    async fn binary_cache_server_refuses_existing_non_cache_files() {
        let root = temp_asset_root();
        let nar_dir = root.join("nar");
        fs::create_dir(&nar_dir).unwrap();
        let store_hash = "0".repeat(32);
        let file_hash = "1".repeat(52);
        fs::write(root.join("nix-cache-info"), b"cache").unwrap();
        fs::write(root.join(format!("{store_hash}.narinfo")), b"narinfo").unwrap();
        fs::write(nar_dir.join(format!("{file_hash}.nar.zst")), b"nar").unwrap();
        fs::write(root.join("cache-priv-key.pem"), b"private").unwrap();

        for path in [
            "nix-cache-info".to_string(),
            format!("{store_hash}.narinfo"),
            format!("nar/{file_hash}.nar.zst"),
        ] {
            let response = serve_binary_cache_member_from_root(&root, &path, &HeaderMap::new())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }
        let error =
            serve_binary_cache_member_from_root(&root, "cache-priv-key.pem", &HeaderMap::new())
                .await
                .unwrap_err();
        assert_eq!(error.code(), "not_found");

        fs::remove_dir_all(&root).unwrap();
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

    fn temp_asset_root() -> std::path::PathBuf {
        static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        for _ in 0..100 {
            let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "cybex-james-assets-test-{}-{unique}-{id}",
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
