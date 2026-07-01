use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};

use crate::{
    AppState, assets, db,
    error::AppResult,
    models::{
        BootEvent, BootProfile, BuildJob, CacheArtifact, CreateBootProfileRequest,
        CreateBuildJobRequest, CreateCacheArtifactRequest, CreateDeviceRequest, Device, IsoAsset,
        UpdateBootProfileRequest, UpdateDeviceRequest,
    },
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/devices", get(list_devices).post(create_device))
        .route(
            "/devices/:id",
            get(get_device).patch(update_device).delete(delete_device),
        )
        .route("/profiles", get(list_profiles).post(create_profile))
        .route(
            "/profiles/:id",
            get(get_profile)
                .patch(update_profile)
                .delete(delete_profile),
        )
        .route("/boot-events", get(list_boot_events))
        .route("/isos", get(list_iso_assets))
        .route("/isos/scan", post(scan_isos))
        .route("/build/jobs", get(list_build_jobs).post(create_build_job))
        .route(
            "/cache/artifacts",
            get(list_cache_artifacts).post(create_cache_artifact),
        )
}

async fn list_devices(State(state): State<AppState>) -> AppResult<Json<Vec<Device>>> {
    Ok(Json(db::list_devices(&state.db).await?))
}

async fn get_device(State(state): State<AppState>, Path(id): Path<i64>) -> AppResult<Json<Device>> {
    Ok(Json(db::get_device(&state.db, id).await?))
}

async fn create_device(
    State(state): State<AppState>,
    Json(input): Json<CreateDeviceRequest>,
) -> AppResult<(StatusCode, Json<Device>)> {
    let device = db::create_device(&state.db, input).await?;
    Ok((StatusCode::CREATED, Json(device)))
}

async fn update_device(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(input): Json<UpdateDeviceRequest>,
) -> AppResult<Json<Device>> {
    Ok(Json(db::update_device(&state.db, id, input).await?))
}

async fn delete_device(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> AppResult<StatusCode> {
    db::delete_device(&state.db, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_profiles(State(state): State<AppState>) -> AppResult<Json<Vec<BootProfile>>> {
    Ok(Json(db::list_profiles(&state.db).await?))
}

async fn get_profile(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> AppResult<Json<BootProfile>> {
    Ok(Json(db::get_profile(&state.db, id).await?))
}

async fn create_profile(
    State(state): State<AppState>,
    Json(input): Json<CreateBootProfileRequest>,
) -> AppResult<(StatusCode, Json<BootProfile>)> {
    let profile = db::create_profile(&state.db, input).await?;
    Ok((StatusCode::CREATED, Json(profile)))
}

async fn update_profile(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(input): Json<UpdateBootProfileRequest>,
) -> AppResult<Json<BootProfile>> {
    Ok(Json(db::update_profile(&state.db, id, input).await?))
}

async fn delete_profile(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> AppResult<StatusCode> {
    db::delete_profile(&state.db, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
struct EventsQuery {
    limit: Option<i64>,
}

async fn list_boot_events(
    State(state): State<AppState>,
    Query(query): Query<EventsQuery>,
) -> AppResult<Json<Vec<BootEvent>>> {
    Ok(Json(
        db::list_boot_events(&state.db, query.limit.unwrap_or(100)).await?,
    ))
}

async fn list_iso_assets(State(state): State<AppState>) -> AppResult<Json<Vec<IsoAsset>>> {
    Ok(Json(db::list_iso_assets(&state.db).await?))
}

#[derive(Debug, Serialize)]
struct ScanResponse {
    scanned_count: usize,
}

async fn scan_isos(State(state): State<AppState>) -> AppResult<Json<ScanResponse>> {
    let scanned_count = assets::scan_iso_dir(&state.config, &state.db).await?;
    Ok(Json(ScanResponse { scanned_count }))
}

async fn list_build_jobs(State(state): State<AppState>) -> AppResult<Json<Vec<BuildJob>>> {
    Ok(Json(db::list_build_jobs(&state.db).await?))
}

async fn create_build_job(
    State(state): State<AppState>,
    Json(input): Json<CreateBuildJobRequest>,
) -> AppResult<(StatusCode, Json<BuildJob>)> {
    let job = db::create_build_job(&state.db, input).await?;
    Ok((StatusCode::CREATED, Json(job)))
}

async fn list_cache_artifacts(
    State(state): State<AppState>,
) -> AppResult<Json<Vec<CacheArtifact>>> {
    Ok(Json(db::list_cache_artifacts(&state.db).await?))
}

async fn create_cache_artifact(
    State(state): State<AppState>,
    Json(input): Json<CreateCacheArtifactRequest>,
) -> AppResult<(StatusCode, Json<CacheArtifact>)> {
    let artifact = db::create_cache_artifact(&state.db, input).await?;
    Ok((StatusCode::CREATED, Json(artifact)))
}
