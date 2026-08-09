use std::net::SocketAddr;

use anyhow::{Context, bail};
use axum::serve as axum_serve;
use clap::Parser;
use cybex_pulse::{
    AppState,
    config::{Cli, Command},
    db, router,
};
use tokio::net::TcpListener;
use tokio::process::Command as TokioCommand;
use tokio::time::{Duration, sleep};
use tracing::{info, warn};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let cli = Cli::parse();
    let command = cli.command.clone().unwrap_or(Command::Serve);
    if matches!(command, Command::VerifyApplianceUpdate) {
        #[cfg(unix)]
        if effective_uid() != 0 {
            anyhow::bail!("appliance package verification must run as root");
        }
        let packages = cybex_pulse::appliance::verify_and_extract_stored_update()?;
        println!("{}", packages.display());
        return Ok(());
    }
    if matches!(command, Command::VerifyApplianceNetworkChange) {
        #[cfg(unix)]
        if effective_uid() != 0 {
            anyhow::bail!("appliance network verification must run as root");
        }
        let candidate = cybex_pulse::appliance::verify_and_materialize_network_change()?;
        println!("{}", candidate.display());
        return Ok(());
    }

    let config = cybex_pulse::config::AppConfig::load(&cli.config)
        .with_context(|| format!("failed to load config from {}", cli.config.display()))?;

    if matches!(command, Command::ValidateApplianceConfig) {
        config.validate_appliance_config()?;
        return Ok(());
    }

    if matches!(command, Command::PrintConfig) {
        println!(
            "{}",
            toml::to_string_pretty(&config.redacted_for_display())?
        );
        return Ok(());
    }

    ensure_managed_command_is_not_root(&config, &command)?;

    if !config.manage.enabled && config.auth.admin_token == "change-me" {
        warn!("admin token is still set to the example value");
    }

    db::ensure_directories(&config).context("failed to create service directories")?;
    let pool = db::connect(&config)
        .await
        .context("failed to open database")?;
    db::migrate(&pool)
        .await
        .context("database migration failed")?;
    cybex_pulse::cache::remediate_protected_build_jobs(&pool, &config)
        .await
        .context("protected build cache remediation failed")?;

    match command {
        Command::Serve => run_server(config, pool).await,
        Command::Migrate => {
            info!("database migrations completed");
            Ok(())
        }
        Command::SyncOnce => {
            let state = AppState::new(config, pool);
            let outcome = cybex_pulse::manage::sync_once(&state).await?;
            println!("{}", serde_json::to_string(&outcome)?);
            Ok(())
        }
        Command::PrintConfig => unreachable!("print-config exits before database setup"),
        Command::ValidateApplianceConfig => {
            unreachable!("validate-appliance-config exits before database setup")
        }
        Command::VerifyApplianceUpdate => {
            unreachable!("appliance update verification exits before config loading")
        }
        Command::VerifyApplianceNetworkChange => {
            unreachable!("appliance network verification exits before config loading")
        }
    }
}

fn ensure_managed_command_is_not_root(
    config: &cybex_pulse::config::AppConfig,
    command: &Command,
) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        if managed_command_requires_service_user(config, command) && effective_uid() == 0 {
            bail!(
                "managed Cybex Pulse stateful commands must not run as root; use systemctl for the service"
            );
        }
    }
    let _ = (config, command);
    Ok(())
}

fn managed_command_requires_service_user(
    config: &cybex_pulse::config::AppConfig,
    command: &Command,
) -> bool {
    config.manage.enabled
        && !matches!(
            command,
            Command::PrintConfig
                | Command::ValidateApplianceConfig
                | Command::VerifyApplianceUpdate
                | Command::VerifyApplianceNetworkChange
        )
}

#[cfg(unix)]
fn effective_uid() -> u32 {
    unsafe { libc::geteuid() }
}

async fn run_server(
    config: cybex_pulse::config::AppConfig,
    pool: sqlx::SqlitePool,
) -> anyhow::Result<()> {
    let listen_addr: SocketAddr = config
        .server
        .listen_addr
        .parse()
        .with_context(|| format!("invalid listen address {}", config.server.listen_addr))?;
    let state = AppState::new(config, pool);
    if let Err(err) = cybex_pulse::cache::initialize(&state.config).await {
        // Degraded, not fatal: exports re-run key setup and `nix copy`
        // rewrites nix-cache-info, so the cache can still heal later.
        warn!(error = %err, "Pulse Cache initialization failed; substituters will reject this cache until resolved");
    }
    cybex_pulse::build::spawn(state.clone());
    cybex_pulse::netboot::spawn_maintenance(state.clone());
    if state.config.manage.enabled {
        cybex_pulse::manage::spawn(state.clone());
    }
    let app = router(state);

    let listener = TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("failed to bind {listen_addr}"))?;
    info!(%listen_addr, "cybex-pulse listening");
    spawn_systemd_watchdog();

    axum_serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .context("server failed")
}

fn spawn_systemd_watchdog() {
    if std::env::var_os("NOTIFY_SOCKET").is_none() {
        return;
    }
    tokio::spawn(async {
        let _ = TokioCommand::new("systemd-notify")
            .arg("--ready")
            .status()
            .await;
        loop {
            sleep(Duration::from_secs(10)).await;
            if TokioCommand::new("systemd-notify")
                .arg("WATCHDOG=1")
                .status()
                .await
                .is_err()
            {
                warn!("failed to notify systemd watchdog");
            }
        }
    });
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
        .unwrap_or_else(|_| EnvFilter::new("cybex_pulse=info,tower_http=info"));
    tracing_subscriber::registry()
        .with(env_filter)
        // Operational logs belong on stderr so one-shot commands can reserve
        // stdout for stable machine-readable results.
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();
}

#[cfg(test)]
mod tests {
    use cybex_pulse::config::AppConfig;

    use super::{Command, managed_command_requires_service_user};

    #[test]
    fn managed_stateful_commands_require_service_user() {
        let mut config = AppConfig::default();
        config.manage.enabled = true;

        for command in [Command::Serve, Command::Migrate, Command::SyncOnce] {
            assert!(managed_command_requires_service_user(&config, &command));
        }
        assert!(!managed_command_requires_service_user(
            &config,
            &Command::PrintConfig
        ));
        assert!(!managed_command_requires_service_user(
            &config,
            &Command::ValidateApplianceConfig
        ));
        config.manage.enabled = false;
        assert!(!managed_command_requires_service_user(
            &config,
            &Command::SyncOnce
        ));
    }
}
