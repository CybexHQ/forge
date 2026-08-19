pub mod appliance;
pub mod assets;
pub mod boot;
pub mod build;
pub mod cache;
pub mod config;
pub mod db;
pub mod disk;
pub mod error;
pub mod host;
pub mod maintenance;
pub mod manage;
pub(crate) mod manage_source;
pub mod models;
pub mod netboot;
pub(crate) mod nix_command;
pub mod nix_log;
pub(crate) mod protected_material;
pub mod provisioning;
pub mod readiness;
pub(crate) mod redact;
pub(crate) mod release_transport;
pub mod routes;

use std::sync::{Arc, RwLock};

use axum::Router;
use config::AppConfig;
use sqlx::SqlitePool;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub db: SqlitePool,
    runtime: Arc<RwLock<RuntimeSettings>>,
}

impl AppState {
    pub fn new(config: AppConfig, db: SqlitePool) -> Self {
        let runtime = RuntimeSettings::from_config(&config);
        Self {
            config: Arc::new(config),
            db,
            runtime: Arc::new(RwLock::new(runtime)),
        }
    }

    pub fn runtime_settings(&self) -> RuntimeSettings {
        self.runtime
            .read()
            .map(|settings| settings.clone())
            .unwrap_or_else(|_| RuntimeSettings::from_config(&self.config))
    }

    pub fn update_runtime_settings(&self, settings: RuntimeSettings) {
        if let Ok(mut current) = self.runtime.write() {
            *current = settings;
        }
    }
}

#[derive(Clone, Debug)]
pub struct RuntimeSettings {
    pub public_base_url: String,
    pub bootloader_filename: String,
    pub menu_timeout_ms: u32,
}

impl RuntimeSettings {
    pub fn from_config(config: &AppConfig) -> Self {
        Self {
            public_base_url: config.public_base_url().to_string(),
            bootloader_filename: config.boot.bootloader_filename.clone(),
            menu_timeout_ms: config.boot.menu_timeout_ms,
        }
    }
}

pub fn router(state: AppState) -> Router {
    routes::router(state)
}
