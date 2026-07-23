use std::{net::SocketAddr, path::PathBuf};

use anyhow::{Context, bail};
use axum::serve as axum_serve;
use clap::Parser;
use cybex_forge::{
    AppState, assets,
    config::{Cli, Command},
    db,
    manage::ExpectedUpdateReport,
    router,
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

    if let CommandStartup::UpdateOnly {
        projection_file,
        expected_update,
    } = command_startup(&command)?
    {
        let outcome = cybex_forge::manage::sync_update_report_once(
            &config,
            projection_file.as_deref(),
            expected_update.as_ref(),
        )
        .await?;
        println!("{}", serde_json::to_string(&outcome)?);
        return Ok(());
    }

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
    cybex_forge::cache::remediate_protected_build_jobs(&pool, &config)
        .await
        .context("protected build cache remediation failed")?;

    match command {
        Command::Serve => run_server(config, pool).await,
        Command::Migrate => {
            info!("database migrations completed");
            Ok(())
        }
        Command::ScanIsos => {
            let summary = assets::scan_iso_dir(&config, &pool)
                .await
                .context("ISO scan failed")?;
            info!(
                count = summary.discovered,
                hashed = summary.hashed,
                reused = summary.reused,
                "ISO scan completed"
            );
            Ok(())
        }
        Command::Enroll => {
            let state = AppState::new(config, pool);
            cybex_forge::manage::enroll_once(&state).await
        }
        Command::SyncOnce {
            update_only,
            update_projection_file,
            expect_update_status,
            expect_update_attempt,
            expect_update_current_version,
        } => {
            debug_assert!(
                !update_only
                    && update_projection_file.is_none()
                    && expect_update_status.is_none()
                    && expect_update_attempt.is_none()
                    && expect_update_current_version.is_none()
            );
            let state = AppState::new(config, pool);
            let outcome = cybex_forge::manage::sync_once(&state).await?;
            println!("{}", serde_json::to_string(&outcome)?);
            Ok(())
        }
        Command::ApplyRuntimeConfig => {
            unreachable!("apply-runtime-config exits before database setup")
        }
        Command::PrintConfig => unreachable!("print-config exits before database setup"),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum CommandStartup {
    DatabaseBacked,
    UpdateOnly {
        projection_file: Option<PathBuf>,
        expected_update: Option<ExpectedUpdateReport>,
    },
}

fn command_startup(command: &Command) -> anyhow::Result<CommandStartup> {
    let Command::SyncOnce {
        update_only,
        update_projection_file,
        expect_update_status,
        expect_update_attempt,
        expect_update_current_version,
    } = command
    else {
        return Ok(CommandStartup::DatabaseBacked);
    };
    match (
        *update_only,
        expect_update_status,
        expect_update_attempt,
        expect_update_current_version,
    ) {
        (true, Some(status), Some(attempt_id), Some(current_version)) => {
            if update_projection_file.is_some() && status != "idle" {
                bail!("explicit update-only Forge projections are restricted to idle status");
            }
            if status == "idle" && !attempt_id.is_empty() {
                bail!("idle update-only Forge sync requires an empty expected attempt ID");
            }
            if status != "idle" && attempt_id.is_empty() {
                bail!(
                    "non-idle update-only Forge sync requires a 32-character expected attempt ID"
                );
            }
            Ok(CommandStartup::UpdateOnly {
                projection_file: update_projection_file.clone(),
                expected_update: Some(ExpectedUpdateReport {
                    status: status.clone(),
                    attempt_id: attempt_id.clone(),
                    current_version: current_version.clone(),
                }),
            })
        }
        (true, None, None, None) if update_projection_file.is_none() => {
            Ok(CommandStartup::UpdateOnly {
                projection_file: None,
                expected_update: None,
            })
        }
        (false, None, None, None) if update_projection_file.is_none() => {
            Ok(CommandStartup::DatabaseBacked)
        }
        _ => bail!(
            "update-only Forge sync requires all three update expectation arguments when any is set"
        ),
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
    if let Err(err) = cybex_forge::cache::initialize(&state.config).await {
        // Degraded, not fatal: exports re-run key setup and `nix copy`
        // rewrites nix-cache-info, so the cache can still heal later.
        warn!(error = %err, "Forge Cache initialization failed; substituters will reject this cache until resolved");
    }
    cybex_forge::build::spawn(state.clone());
    if state.config.manage.enabled {
        cybex_forge::manage::spawn(state.clone());
    }
    let app = router(state);

    let listener = TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("failed to bind {listen_addr}"))?;
    info!(%listen_addr, "cybex-forge listening");
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
        .unwrap_or_else(|_| EnvFilter::new("cybex_forge=info,tower_http=info"));
    tracing_subscriber::registry()
        .with(env_filter)
        // Operational logs belong on stderr so one-shot commands can reserve
        // stdout for stable machine-readable results.
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use cybex_forge::config::AppConfig;

    use super::{Command, CommandStartup, command_startup, managed_command_requires_service_user};

    #[test]
    fn managed_stateful_commands_require_service_user() {
        let mut config = AppConfig::default();
        config.manage.enabled = true;

        for command in [
            Command::Serve,
            Command::Migrate,
            Command::ScanIsos,
            Command::Enroll,
            Command::SyncOnce {
                update_only: false,
                update_projection_file: None,
                expect_update_status: None,
                expect_update_attempt: None,
                expect_update_current_version: None,
            },
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
            &Command::SyncOnce {
                update_only: false,
                update_projection_file: None,
                expect_update_status: None,
                expect_update_attempt: None,
                expect_update_current_version: None,
            }
        ));
    }

    #[test]
    fn update_only_sync_uses_the_database_free_startup_path() {
        let command = Command::SyncOnce {
            update_only: true,
            update_projection_file: Some(PathBuf::from("/tmp/update-projection.json")),
            expect_update_status: Some("idle".to_string()),
            expect_update_attempt: Some(String::new()),
            expect_update_current_version: Some("0.1.1".to_string()),
        };

        let startup = command_startup(&command).unwrap();

        assert!(matches!(
            &startup,
            CommandStartup::UpdateOnly {
                projection_file: Some(_),
                expected_update: Some(_),
            }
        ));
        assert_ne!(startup, CommandStartup::DatabaseBacked);
        assert_eq!(
            command_startup(&Command::SyncOnce {
                update_only: false,
                update_projection_file: None,
                expect_update_status: None,
                expect_update_attempt: None,
                expect_update_current_version: None,
            })
            .unwrap(),
            CommandStartup::DatabaseBacked
        );
        assert_eq!(
            command_startup(&Command::SyncOnce {
                update_only: true,
                update_projection_file: None,
                expect_update_status: None,
                expect_update_attempt: None,
                expect_update_current_version: None,
            })
            .unwrap(),
            CommandStartup::UpdateOnly {
                projection_file: None,
                expected_update: None,
            }
        );

        for invalid in [
            Command::SyncOnce {
                update_only: true,
                update_projection_file: Some(PathBuf::from("/tmp/update-projection.json")),
                expect_update_status: None,
                expect_update_attempt: None,
                expect_update_current_version: None,
            },
            Command::SyncOnce {
                update_only: true,
                update_projection_file: Some(PathBuf::from("/tmp/update-projection.json")),
                expect_update_status: Some("failed".to_string()),
                expect_update_attempt: Some("a".repeat(32)),
                expect_update_current_version: Some("0.1.1".to_string()),
            },
            Command::SyncOnce {
                update_only: true,
                update_projection_file: None,
                expect_update_status: Some("idle".to_string()),
                expect_update_attempt: Some("a".repeat(32)),
                expect_update_current_version: Some("0.1.1".to_string()),
            },
            Command::SyncOnce {
                update_only: true,
                update_projection_file: None,
                expect_update_status: Some("failed".to_string()),
                expect_update_attempt: Some(String::new()),
                expect_update_current_version: Some("0.1.1".to_string()),
            },
        ] {
            assert!(command_startup(&invalid).is_err());
        }
    }
}
