use std::net::SocketAddr;

use anyhow::{Context, bail};
use axum::serve as axum_serve;
use clap::Parser;
use cybex_forge::{
    AppState, assets,
    config::{Cli, Command},
    db, router,
};
use tokio::net::TcpListener;
use tracing::{info, warn};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let cli = Cli::parse();
    let config = cybex_forge::config::AppConfig::load(&cli.config)
        .with_context(|| format!("failed to load config from {}", cli.config.display()))?;

    let command = cli.command.clone().unwrap_or(Command::Serve);

    if matches!(command, Command::PrintConfig) {
        println!(
            "{}",
            toml::to_string_pretty(&config.redacted_for_display())?
        );
        return Ok(());
    }

    ensure_managed_command_is_not_root(&config, &command)?;

    if matches!(command, Command::ApplyRuntimeConfig) {
        return cybex_forge::manage::apply_runtime_config_once(&config).await;
    }

    if !config.manage.enabled && config.auth.admin_token == "change-me" {
        warn!("admin token is still set to the example value");
    }

    db::ensure_directories(&config).context("failed to create service directories")?;
    let pool = db::connect(&config)
        .await
        .context("failed to open database")?;

    match command {
        Command::Serve => {
            db::migrate(&pool)
                .await
                .context("database migration failed")?;
            run_server(config, pool).await
        }
        Command::Migrate => {
            db::migrate(&pool)
                .await
                .context("database migration failed")?;
            info!("database migrations completed");
            Ok(())
        }
        Command::ScanIsos => {
            db::migrate(&pool)
                .await
                .context("database migration failed")?;
            let count = assets::scan_iso_dir(&config, &pool)
                .await
                .context("ISO scan failed")?;
            info!(count, "ISO scan completed");
            Ok(())
        }
        Command::Enroll => {
            db::migrate(&pool)
                .await
                .context("database migration failed")?;
            let state = AppState::new(config, pool);
            cybex_forge::manage::enroll_once(&state).await
        }
        Command::SyncOnce => {
            db::migrate(&pool)
                .await
                .context("database migration failed")?;
            let state = AppState::new(config, pool);
            cybex_forge::manage::sync_once(&state).await
        }
        Command::ApplyRuntimeConfig => {
            unreachable!("apply-runtime-config exits before database setup")
        }
        Command::PrintConfig => unreachable!("print-config exits before database setup"),
    }
}

fn ensure_managed_command_is_not_root(
    config: &cybex_forge::config::AppConfig,
    command: &Command,
) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        if managed_command_requires_service_user(config, command) && effective_uid() == 0 {
            bail!(
                "managed Cybex Forge stateful commands must not run as root; use systemctl for the service or cybex-forge-sync-once for manual sync checks"
            );
        }
    }
    let _ = (config, command);
    Ok(())
}

fn managed_command_requires_service_user(
    config: &cybex_forge::config::AppConfig,
    command: &Command,
) -> bool {
    config.manage.enabled && !matches!(command, Command::PrintConfig | Command::ApplyRuntimeConfig)
}

#[cfg(unix)]
fn effective_uid() -> u32 {
    unsafe { libc::geteuid() }
}

async fn run_server(
    config: cybex_forge::config::AppConfig,
    pool: sqlx::SqlitePool,
) -> anyhow::Result<()> {
    let listen_addr: SocketAddr = config
        .server
        .listen_addr
        .parse()
        .with_context(|| format!("invalid listen address {}", config.server.listen_addr))?;
    let state = AppState::new(config, pool);
    cybex_forge::build::spawn(state.clone());
    if state.config.manage.enabled {
        cybex_forge::manage::spawn(state.clone());
    }
    let app = router(state);

    let listener = TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("failed to bind {listen_addr}"))?;
    info!(%listen_addr, "cybex-forge listening");

    axum_serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .context("server failed")
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl-C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

fn init_tracing() {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("cybex_forge=info,tower_http=info"));
    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer())
        .init();
}

#[cfg(test)]
mod tests {
    use cybex_forge::config::AppConfig;

    use super::{Command, managed_command_requires_service_user};

    #[test]
    fn managed_stateful_commands_require_service_user() {
        let mut config = AppConfig::default();
        config.manage.enabled = true;

        for command in [
            Command::Serve,
            Command::Migrate,
            Command::ScanIsos,
            Command::Enroll,
            Command::SyncOnce,
        ] {
            assert!(managed_command_requires_service_user(&config, &command));
        }
        assert!(!managed_command_requires_service_user(
            &config,
            &Command::PrintConfig
        ));
        assert!(!managed_command_requires_service_user(
            &config,
            &Command::ApplyRuntimeConfig
        ));

        config.manage.enabled = false;
        assert!(!managed_command_requires_service_user(
            &config,
            &Command::SyncOnce
        ));
    }
}
