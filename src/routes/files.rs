use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::Response,
};

use crate::{AppState, assets, error::AppResult};

pub async fn boot_file(
    State(state): State<AppState>,
    Path(path): Path<String>,
    headers: HeaderMap,
) -> AppResult<Response> {
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
    assets::serve_file_from_root(&state.config.cache.root_dir, &path, &headers).await
}
