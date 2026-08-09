use anyhow::{Result, bail};
use clap::{Parser, Subcommand};
use cybex_forge::provisioning::{
    FinalizeOptions, PrepareOptions, finalize_target, prepare, report_install_stage,
};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "cybex-forge-bootstrap",
    about = "Fail-closed provisioned Ubuntu appliance bootstrap",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Claim this provisioned ISO, wait for approval, and prepare Autoinstall.
    Prepare {
        #[arg(long, default_value = "/cdrom/CYBEX_PROVISIONING.BIN")]
        envelope: PathBuf,
        #[arg(long, default_value = "/cdrom/cybex/provisioning-public-keys")]
        provisioning_keys: PathBuf,
        #[arg(long, default_value = "/cdrom/cybex/release-public-key")]
        release_public_key: PathBuf,
        #[arg(long, default_value = "/autoinstall.yaml")]
        autoinstall: PathBuf,
        #[arg(long, default_value = "/run/cybex-state")]
        state_mount: PathBuf,
    },
    /// Report a late Subiquity stage using the installed device identity.
    Event {
        #[arg(long, default_value = "/run/cybex-state")]
        state_mount: PathBuf,
        #[arg(long)]
        stage: String,
        #[arg(long)]
        status: String,
        #[arg(long)]
        progress_percent: Option<i32>,
        #[arg(long, default_value = "")]
        message: String,
    },
    /// Write plan-bound identity, networking, and SSH trust into /target.
    FinalizeTarget {
        #[arg(long, default_value = "/target")]
        target: PathBuf,
        #[arg(long, default_value = "/run/cybex-state")]
        state_mount: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Prepare {
            envelope,
            provisioning_keys,
            release_public_key,
            autoinstall,
            state_mount,
        } => {
            require_root()?;
            let options = PrepareOptions {
                envelope_path: envelope,
                provisioning_keys_path: provisioning_keys,
                release_public_key_path: release_public_key,
                autoinstall_path: autoinstall,
                state_mount,
                ..PrepareOptions::default()
            };
            prepare(options).await
        }
        Command::Event {
            state_mount,
            stage,
            status,
            progress_percent,
            message,
        } => report_install_stage(&state_mount, &stage, &status, progress_percent, &message).await,
        Command::FinalizeTarget {
            target,
            state_mount,
        } => {
            require_root()?;
            finalize_target(FinalizeOptions {
                target,
                state_mount,
            })
        }
    }
}

fn require_root() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("the provisioned installer must run as root")
    }
    Ok(())
}
