use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::Response,
};

use crate::{
    AppState, assets,
    error::{AppError, AppResult},
};

fn is_reserved_boot_namespace(path: &str) -> bool {
    matches!(
        path.trim_start_matches('/').split('/').next(),
        Some("netboot" | "netboot-quarantine")
    )
}

pub async fn boot_file(
    State(state): State<AppState>,
    Path(path): Path<String>,
    headers: HeaderMap,
) -> AppResult<Response> {
    // Workstation runtime files cross a signed/verified authorization boundary
    // in netboot::serve_component. Never let the generic boot-assets route
    // expose active, staging, or quarantined trees by pathname alone.
    if is_reserved_boot_namespace(&path) {
        return Err(AppError::NotFound);
    }
    assets::serve_file_from_root(&state.config.paths.boot_assets_dir, &path, &headers).await
}

pub async fn static_file(
    State(state): State<AppState>,
    Path(path): Path<String>,
    headers: HeaderMap,
) -> AppResult<Response> {
    assets::serve_file_from_root(&state.config.paths.static_dir, &path, &headers).await
}

pub async fn cache_file(
    State(state): State<AppState>,
    Path(path): Path<String>,
    headers: HeaderMap,
) -> AppResult<Response> {
    assets::serve_binary_cache_member_from_root(&state.config.cache.root_dir, &path, &headers).await
}

#[cfg(test)]
mod tests {
    use super::is_reserved_boot_namespace;

    #[test]
    fn generic_files_route_blocks_all_runtime_and_quarantine_namespaces() {
        for path in [
            "netboot/bundle/bzImage",
            "netboot/.staging/candidate/initrd",
            "/netboot/bundle/nix-store.squashfs",
            "netboot-quarantine/bundle/bzImage",
        ] {
            assert!(is_reserved_boot_namespace(path), "{path}");
        }
        for path in ["ipxe.efi", "menus/default.ipxe", "netboot-release.txt"] {
            assert!(!is_reserved_boot_namespace(path), "{path}");
        }
    }
}
