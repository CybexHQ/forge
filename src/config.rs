use std::{fs, net::SocketAddr, path::PathBuf};

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(name = "cybex-boot")]
#[command(about = "UEFI-only PXE/iPXE boot control service")]
pub struct Cli {
    #[arg(
        short,
        long,
        default_value = "/etc/cybex-boot/config.toml",
        env = "CYBEX_BOOT_CONFIG"
    )]
    pub config: PathBuf,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Clone, Debug, Subcommand)]
pub enum Command {
    Serve,
    Migrate,
    ScanIsos,
    Enroll,
    SyncOnce,
    ApplyRuntimeConfig,
    PrintConfig,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub paths: PathsConfig,
    pub auth: AuthConfig,
    pub boot: BootConfig,
    pub manage: ManageConfig,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct ServerConfig {
    pub listen_addr: String,
    pub public_base_url: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct PathsConfig {
    pub data_dir: PathBuf,
    pub database_path: PathBuf,
    pub boot_assets_dir: PathBuf,
    pub iso_dir: PathBuf,
    pub static_dir: PathBuf,
    pub tftp_dir: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct AuthConfig {
    pub admin_token: String,
    pub cookie_name: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct BootConfig {
    pub bootloader_filename: String,
    pub menu_timeout_ms: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct ManageConfig {
    pub enabled: bool,
    pub api_url: String,
    pub organization_id: String,
    #[serde(default)]
    pub boot_install_code: String,
    #[serde(default)]
    pub organization_slug: String,
    pub state_path: PathBuf,
    pub sync_interval_seconds: u64,
    pub enrollment_poll_seconds: u64,
    pub http_timeout_seconds: u64,
}

impl AppConfig {
    pub fn load(path: &PathBuf) -> anyhow::Result<Self> {
        if !path.exists() {
            let mut config = Self::default();
            config.normalize()?;
            return Ok(config);
        }

        let raw = fs::read_to_string(path)?;
        let mut config: Self = toml::from_str(&raw)?;
        config.normalize()?;
        Ok(config)
    }

    pub fn public_base_url(&self) -> &str {
        self.server.public_base_url.trim_end_matches('/')
    }

    pub fn redacted_for_display(&self) -> Self {
        let mut redacted = self.clone();
        redacted.auth.admin_token = redact_secret(&redacted.auth.admin_token);
        redacted
    }

    fn normalize(&mut self) -> anyhow::Result<()> {
        self.server.listen_addr = normalize_listen_addr(&self.server.listen_addr)?;
        self.server.public_base_url =
            normalize_http_url("server.public_base_url", &self.server.public_base_url)?;
        self.paths.data_dir =
            normalize_absolute_config_path("paths.data_dir", &self.paths.data_dir)?;
        self.paths.database_path =
            normalize_absolute_config_path("paths.database_path", &self.paths.database_path)?;
        self.paths.boot_assets_dir =
            normalize_absolute_config_path("paths.boot_assets_dir", &self.paths.boot_assets_dir)?;
        self.paths.iso_dir = normalize_absolute_config_path("paths.iso_dir", &self.paths.iso_dir)?;
        self.paths.static_dir =
            normalize_absolute_config_path("paths.static_dir", &self.paths.static_dir)?;
        self.paths.tftp_dir =
            normalize_absolute_config_path("paths.tftp_dir", &self.paths.tftp_dir)?;
        self.boot.bootloader_filename =
            normalize_bootloader_filename(&self.boot.bootloader_filename)?;
        validate_menu_timeout_ms(self.boot.menu_timeout_ms)?;
        self.manage.api_url = if self.manage.api_url.trim().is_empty() {
            String::new()
        } else {
            normalize_http_url("manage.api_url", &self.manage.api_url)?
        };
        self.manage.organization_id = normalize_organization_id(&self.manage.organization_id)?;
        self.manage.boot_install_code =
            normalize_boot_install_code(&self.manage.boot_install_code)?;
        self.manage.organization_slug =
            normalize_optional_organization_slug(&self.manage.organization_slug)?;
        self.manage.state_path =
            normalize_absolute_config_path("manage.state_path", &self.manage.state_path)?;
        if self.manage.enabled && self.manage.api_url.is_empty() {
            bail!("manage.api_url is required when managed mode is enabled");
        }
        if self.manage.enabled
            && self.manage.organization_id.is_empty()
            && self.manage.organization_slug.is_empty()
        {
            bail!("manage.organization_id is required when managed mode is enabled");
        }
        Ok(())
    }
}

fn redact_secret(value: &str) -> String {
    if value.trim().is_empty() {
        String::new()
    } else {
        "REDACTED".to_string()
    }
}

pub(crate) fn normalize_listen_addr(value: &str) -> anyhow::Result<String> {
    let listen_addr = value.trim();
    if listen_addr.is_empty() {
        bail!("server.listen_addr must not be empty");
    }
    if listen_addr
        .chars()
        .any(|ch| ch.is_control() || ch.is_whitespace() || ch == '"' || ch == '\\')
    {
        bail!("server.listen_addr contains unsupported characters");
    }
    let parsed: SocketAddr = listen_addr.parse().with_context(
        || "server.listen_addr must be an IP socket address such as 127.0.0.1:8080",
    )?;
    if parsed.port() == 0 {
        bail!("server.listen_addr port must be between 1 and 65535");
    }
    Ok(parsed.to_string())
}

pub(crate) fn normalize_http_url(field: &str, value: &str) -> anyhow::Result<String> {
    let url = value.trim().trim_end_matches('/').to_string();
    if url.is_empty() {
        bail!("{field} must not be empty");
    }
    if url
        .chars()
        .any(|ch| ch.is_control() || ch.is_whitespace() || ch == '"' || ch == '\\')
    {
        bail!("{field} contains unsupported characters");
    }
    let parsed = Url::parse(&url)
        .with_context(|| format!("{field} must be an absolute http:// or https:// URL"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        bail!("{field} must be an absolute http:// or https:// URL");
    }
    if parsed.host_str().is_none() {
        bail!("{field} must include a host");
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        bail!("{field} must not include embedded credentials");
    }
    if parsed.query().is_some() {
        bail!("{field} must not include query parameters");
    }
    if parsed.fragment().is_some() {
        bail!("{field} must not include fragments");
    }
    Ok(url)
}

pub(crate) fn normalize_bootloader_filename(value: &str) -> anyhow::Result<String> {
    let filename = value.trim();
    if filename.is_empty() {
        bail!("boot.bootloader_filename must not be empty");
    }
    if filename.starts_with('.')
        || filename.contains('/')
        || filename.contains('\\')
        || filename
            .chars()
            .any(|ch| !(ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-')))
    {
        bail!("boot.bootloader_filename must be a simple filename such as snponly.efi");
    }
    Ok(filename.to_string())
}

pub(crate) fn normalize_absolute_config_path(
    field: &str,
    path: &PathBuf,
) -> anyhow::Result<PathBuf> {
    let raw = path.as_os_str().to_string_lossy();
    if raw.is_empty() {
        bail!("{field} must not be empty");
    }
    if raw
        .chars()
        .any(|ch| ch.is_control() || ch == '"' || ch == '\\')
    {
        bail!("{field} contains unsupported characters");
    }
    if !raw.starts_with('/') {
        bail!("{field} must be an absolute path");
    }
    if raw == "/" {
        bail!("{field} must not be the filesystem root");
    }
    for part in raw.split('/').skip(1) {
        if part.is_empty() || part == "." || part == ".." {
            bail!("{field} must be a normalized absolute path");
        }
    }
    Ok(PathBuf::from(raw.as_ref()))
}

pub(crate) fn validate_menu_timeout_ms(value: u32) -> anyhow::Result<()> {
    if !(1_000..=600_000).contains(&value) {
        bail!("boot.menu_timeout_ms must be between 1000 and 600000");
    }
    Ok(())
}

fn normalize_organization_slug(value: &str) -> anyhow::Result<String> {
    let slug = value.trim().to_ascii_lowercase();
    if slug.len() < 2 || slug.len() > 64 {
        bail!("manage.organization_slug must be 2-64 characters");
    }
    if slug.starts_with('-')
        || slug.ends_with('-')
        || !slug
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
    {
        bail!("manage.organization_slug may contain only lowercase letters, numbers, and hyphens");
    }
    Ok(slug)
}

fn normalize_optional_organization_slug(value: &str) -> anyhow::Result<String> {
    if value.trim().is_empty() {
        Ok(String::new())
    } else {
        normalize_organization_slug(value)
    }
}

fn normalize_organization_id(value: &str) -> anyhow::Result<String> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(String::new());
    }
    Uuid::parse_str(value).map_err(|_| anyhow::anyhow!("manage.organization_id must be a UUID"))?;
    Ok(value.to_string())
}

fn normalize_boot_install_code(value: &str) -> anyhow::Result<String> {
    let code = value.trim();
    if code.is_empty() {
        return Ok(String::new());
    }
    if code.len() > 512
        || code
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        bail!("manage.boot_install_code contains unsupported characters");
    }
    Ok(code.to_string())
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:8080".to_string(),
            public_base_url: "http://CYBEX_BOOT_IP".to_string(),
        }
    }
}

impl Default for PathsConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("/var/lib/cybex-boot"),
            database_path: PathBuf::from("/var/lib/cybex-boot/cybex-boot.sqlite"),
            boot_assets_dir: PathBuf::from("/srv/cybex-boot/www"),
            iso_dir: PathBuf::from("/srv/cybex-boot/www/isos"),
            static_dir: PathBuf::from("/srv/cybex-boot/www/assets"),
            tftp_dir: PathBuf::from("/srv/cybex-boot/tftp"),
        }
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            admin_token: "change-me".to_string(),
            cookie_name: "cybex_admin".to_string(),
        }
    }
}

impl Default for BootConfig {
    fn default() -> Self {
        Self {
            bootloader_filename: "snponly.efi".to_string(),
            menu_timeout_ms: 8000,
        }
    }
}

impl Default for ManageConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            api_url: String::new(),
            organization_id: String::new(),
            boot_install_code: String::new(),
            organization_slug: String::new(),
            state_path: PathBuf::from("/var/lib/cybex-boot/manage-state.json"),
            sync_interval_seconds: 30,
            enrollment_poll_seconds: 10,
            http_timeout_seconds: 30,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn print_config_view_redacts_admin_token() {
        let mut config = AppConfig::default();
        config.auth.admin_token = "secret-token".to_string();
        config.server.public_base_url = "http://boot.example".to_string();

        let redacted = config.redacted_for_display();

        assert_eq!(redacted.auth.admin_token, "REDACTED");
        assert_eq!(redacted.server.public_base_url, "http://boot.example");
        assert_eq!(config.auth.admin_token, "secret-token");
    }

    #[test]
    fn print_config_view_preserves_blank_admin_token() {
        let mut config = AppConfig::default();
        config.auth.admin_token = "   ".to_string();

        assert_eq!(config.redacted_for_display().auth.admin_token, "");
    }

    #[test]
    fn defaults_match_managed_nginx_lxc_layout() {
        let config = AppConfig::default();

        assert_eq!(config.server.listen_addr, "127.0.0.1:8080");
        assert_eq!(config.server.public_base_url, "http://CYBEX_BOOT_IP");
        assert_eq!(
            config.paths.boot_assets_dir,
            PathBuf::from("/srv/cybex-boot/www")
        );
        assert_eq!(
            config.paths.iso_dir,
            PathBuf::from("/srv/cybex-boot/www/isos")
        );
        assert_eq!(
            config.paths.static_dir,
            PathBuf::from("/srv/cybex-boot/www/assets")
        );
        assert_eq!(config.paths.tftp_dir, PathBuf::from("/srv/cybex-boot/tftp"));
        assert_eq!(config.manage.http_timeout_seconds, 30);
    }

    #[test]
    fn missing_config_loads_normalized_defaults() {
        let path = std::env::temp_dir().join(format!(
            "cybex-boot-missing-config-test-{}-{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_file(&path);

        let config = AppConfig::load(&path).unwrap();

        assert_eq!(config.server.listen_addr, "127.0.0.1:8080");
        assert_eq!(config.boot.bootloader_filename, "snponly.efi");
    }

    #[test]
    fn config_load_normalizes_urls_and_managed_identity() {
        let path = write_temp_config(
            r#"
[server]
public_base_url = " http://boot.example/// "

[manage]
enabled = true
api_url = " https://manage.example/api/// "
organization_id = "550e8400-e29b-41d4-a716-446655440000"
boot_install_code = " boot_test "
organization_slug = " Default "
"#,
        );

        let config = AppConfig::load(&path).unwrap();
        let _ = fs::remove_file(&path);

        assert_eq!(config.server.public_base_url, "http://boot.example");
        assert_eq!(config.manage.api_url, "https://manage.example/api");
        assert_eq!(
            config.manage.organization_id,
            "550e8400-e29b-41d4-a716-446655440000"
        );
        assert_eq!(config.manage.boot_install_code, "boot_test");
        assert_eq!(config.manage.organization_slug, "default");
    }

    #[test]
    fn config_load_rejects_invalid_public_base_url() {
        let path = write_temp_config(
            r#"
[server]
public_base_url = "https://"
"#,
        );

        let err = AppConfig::load(&path).unwrap_err();
        let _ = fs::remove_file(&path);

        assert!(err.to_string().contains("server.public_base_url"));
    }

    #[test]
    fn config_load_rejects_invalid_managed_api_url() {
        let path = write_temp_config(
            r#"
[server]
public_base_url = "http://boot.example"

[manage]
enabled = true
api_url = "https://manage.example:70000"
organization_id = "550e8400-e29b-41d4-a716-446655440000"
"#,
        );

        let err = AppConfig::load(&path).unwrap_err();
        let _ = fs::remove_file(&path);

        assert!(err.to_string().contains("manage.api_url"));
    }

    #[test]
    fn config_load_rejects_enabled_managed_mode_without_api_url() {
        let path = write_temp_config(
            r#"
[server]
public_base_url = "http://boot.example"

[manage]
enabled = true
organization_id = "550e8400-e29b-41d4-a716-446655440000"
"#,
        );

        let err = AppConfig::load(&path).unwrap_err();
        let _ = fs::remove_file(&path);

        assert!(err.to_string().contains("manage.api_url is required"));
    }

    #[test]
    fn config_load_rejects_enabled_managed_mode_without_organization_identity() {
        let path = write_temp_config(
            r#"
[server]
public_base_url = "http://boot.example"

[manage]
enabled = true
api_url = "https://manage.example"
"#,
        );

        let err = AppConfig::load(&path).unwrap_err();
        let _ = fs::remove_file(&path);

        assert!(
            err.to_string()
                .contains("manage.organization_id is required")
        );
    }

    #[test]
    fn config_load_rejects_invalid_listen_addr() {
        let path = write_temp_config(
            r#"
[server]
listen_addr = "localhost:8080"
public_base_url = "http://boot.example"
"#,
        );

        let err = AppConfig::load(&path).unwrap_err();
        let _ = fs::remove_file(&path);

        assert!(err.to_string().contains("server.listen_addr"));
    }

    #[test]
    fn config_load_rejects_invalid_bootloader_filename() {
        for bootloader_filename in ["../snponly.efi", "bad name.efi", "snponly.efi:bak"] {
            let path = write_temp_config(&format!(
                r#"
[server]
public_base_url = "http://boot.example"

[boot]
bootloader_filename = "{bootloader_filename}"
"#,
            ));

            let err = AppConfig::load(&path).unwrap_err();
            let _ = fs::remove_file(&path);

            assert!(err.to_string().contains("boot.bootloader_filename"));
        }
    }

    #[test]
    fn config_load_rejects_unsafe_filesystem_paths() {
        for (field, config) in [
            (
                "paths.data_dir",
                r#"
[server]
public_base_url = "http://boot.example"

[paths]
data_dir = "../var/lib/cybex-boot"
"#,
            ),
            (
                "paths.database_path",
                r#"
[server]
public_base_url = "http://boot.example"

[paths]
database_path = "/var/lib/../cybex-boot.sqlite"
"#,
            ),
            (
                "paths.boot_assets_dir",
                r#"
[server]
public_base_url = "http://boot.example"

[paths]
boot_assets_dir = "/srv/cybex-boot//www"
"#,
            ),
            (
                "paths.tftp_dir",
                r#"
[server]
public_base_url = "http://boot.example"

[paths]
tftp_dir = "/"
"#,
            ),
            (
                "manage.state_path",
                r#"
[server]
public_base_url = "http://boot.example"

[manage]
state_path = "/var/lib/cybex-boot/../manage-state.json"
"#,
            ),
        ] {
            let path = write_temp_config(config);
            let err = AppConfig::load(&path).unwrap_err();
            let _ = fs::remove_file(&path);

            assert!(
                err.to_string().contains(field),
                "expected {field} error, got {err}"
            );
        }
    }

    #[test]
    fn config_load_rejects_invalid_menu_timeout() {
        let path = write_temp_config(
            r#"
[server]
public_base_url = "http://boot.example"

[boot]
menu_timeout_ms = 0
"#,
        );

        let err = AppConfig::load(&path).unwrap_err();
        let _ = fs::remove_file(&path);

        assert!(err.to_string().contains("boot.menu_timeout_ms"));
    }

    fn write_temp_config(contents: &str) -> PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "cybex-boot-config-test-{}-{unique}.toml",
            std::process::id()
        ));
        fs::write(&path, contents).unwrap();
        path
    }
}
