use std::{ffi::OsString, process::Command as StdCommand};

use tokio::process::Command as TokioCommand;

const REQUIRED_EXPERIMENTAL_FEATURES_CONFIG: &str =
    "extra-experimental-features = nix-command flakes";

fn config_with_required_features(existing: Option<OsString>) -> OsString {
    let mut config = existing.unwrap_or_default();
    if !config.is_empty() {
        config.push("\n");
    }
    config.push(REQUIRED_EXPERIMENTAL_FEATURES_CONFIG);
    config
}

fn inherited_config_with_required_features() -> OsString {
    config_with_required_features(std::env::var_os("NIX_CONFIG"))
}

pub(crate) fn tokio_command(program: &str) -> TokioCommand {
    let mut command = TokioCommand::new(program);
    command.env("NIX_CONFIG", inherited_config_with_required_features());
    command
}

pub(crate) fn std_command(program: impl AsRef<std::ffi::OsStr>) -> StdCommand {
    let mut command = StdCommand::new(program);
    command.env("NIX_CONFIG", inherited_config_with_required_features());
    command
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use super::*;

    #[test]
    fn required_features_preserve_existing_nix_settings() {
        assert_eq!(
            config_with_required_features(None),
            OsString::from(REQUIRED_EXPERIMENTAL_FEATURES_CONFIG)
        );
        assert_eq!(
            config_with_required_features(Some(OsString::from(
                "sandbox = true\nsubstituters = https://cache.nixos.org/",
            ))),
            OsString::from(format!(
                "sandbox = true\nsubstituters = https://cache.nixos.org/\n{REQUIRED_EXPERIMENTAL_FEATURES_CONFIG}"
            ))
        );
    }

    #[test]
    fn synchronous_nix_commands_receive_required_features() {
        let command = std_command("nix");
        let nix_config = command
            .get_envs()
            .find_map(|(key, value)| (key == OsStr::new("NIX_CONFIG")).then_some(value))
            .flatten()
            .expect("NIX_CONFIG override");
        assert!(
            nix_config
                .to_string_lossy()
                .contains(REQUIRED_EXPERIMENTAL_FEATURES_CONFIG)
        );
    }
}
