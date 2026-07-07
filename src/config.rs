use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(name = "cybex-forge")]
#[command(about = "UEFI-only PXE/iPXE boot control service")]
pub struct Cli {
    #[arg(
        short,
        long,
        default_value = "/etc/cybex-forge/config.toml",
        env = "CYBEX_FORGE_CONFIG"
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
    pub build: BuildConfig,
    pub cache: CacheConfig,
    pub update: UpdateConfig,
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
pub struct BuildConfig {
    pub enabled: bool,
    pub max_concurrent_builds: usize,
    pub timeout_seconds: u64,
    pub cancel_grace_seconds: u64,
    pub max_log_bytes: usize,
    pub max_artifact_size_bytes: u64,
    pub allowed_systems: Vec<String>,
    pub work_dir: PathBuf,
    pub output_dir: PathBuf,
    pub nix_binary: String,
    pub targets: Vec<BuildTargetConfig>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct BuildTargetConfig {
    pub artifact_type: String,
    pub target: String,
    pub system: String,
    pub flake: String,
    pub attr: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct CacheConfig {
    pub enabled: bool,
    pub root_dir: PathBuf,
    pub signing_key_name: String,
    pub private_key_path: PathBuf,
    pub public_key_path: PathBuf,
    pub max_bytes: u64,
    pub retain_recent_builds: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct UpdateConfig {
    pub enabled: bool,
    pub work_dir: PathBuf,
    pub releases_dir: PathBuf,
    pub binary_path: PathBuf,
    pub config_path: PathBuf,
    pub service_name: String,
    pub health_url: String,
    pub max_artifact_size_bytes: u64,
    pub trusted_public_key: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct ManageConfig {
    pub enabled: bool,
    pub api_url: String,
    pub organization_id: String,
    #[serde(default)]
    pub forge_install_code: String,
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
        redacted.manage.forge_install_code = redact_secret(&redacted.manage.forge_install_code);
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
        self.build.max_concurrent_builds = self.build.max_concurrent_builds.clamp(1, 16);
        self.build.timeout_seconds = self.build.timeout_seconds.clamp(30, 24 * 60 * 60);
        self.build.cancel_grace_seconds = self.build.cancel_grace_seconds.clamp(1, 300);
        self.build.max_log_bytes = self.build.max_log_bytes.clamp(1024, 8 * 1024 * 1024);
        self.build.max_artifact_size_bytes = self
            .build
            .max_artifact_size_bytes
            .clamp(1024 * 1024, 64 * 1024 * 1024 * 1024);
        self.build.work_dir =
            normalize_absolute_config_path("build.work_dir", &self.build.work_dir)?;
        self.build.output_dir =
            normalize_absolute_config_path("build.output_dir", &self.build.output_dir)?;
        self.build.nix_binary = normalize_program_name("build.nix_binary", &self.build.nix_binary)?;
        self.build.allowed_systems =
            normalize_allowed_systems(&self.build.allowed_systems, "build.allowed_systems")?;
        for target in &mut self.build.targets {
            normalize_build_target_config(target)?;
        }
        self.cache.root_dir =
            normalize_absolute_config_path("cache.root_dir", &self.cache.root_dir)?;
        self.cache.private_key_path =
            normalize_absolute_config_path("cache.private_key_path", &self.cache.private_key_path)?;
        self.cache.public_key_path =
            normalize_absolute_config_path("cache.public_key_path", &self.cache.public_key_path)?;
        self.cache.signing_key_name =
            normalize_cache_key_name("cache.signing_key_name", &self.cache.signing_key_name)?;
        self.cache.max_bytes = self
            .cache
            .max_bytes
            .clamp(16 * 1024 * 1024, 1024 * 1024 * 1024 * 1024);
        self.cache.retain_recent_builds = self.cache.retain_recent_builds.clamp(1, 10_000);
        self.update.work_dir =
            normalize_absolute_config_path("update.work_dir", &self.update.work_dir)?;
        self.update.releases_dir =
            normalize_absolute_config_path("update.releases_dir", &self.update.releases_dir)?;
        self.update.binary_path =
            normalize_absolute_config_path("update.binary_path", &self.update.binary_path)?;
        self.update.config_path =
            normalize_absolute_config_path("update.config_path", &self.update.config_path)?;
        self.update.service_name =
            normalize_systemd_unit_name("update.service_name", &self.update.service_name)?;
        self.update.health_url = if self.update.health_url.trim().is_empty() {
            local_health_url_from_listen_addr(&self.server.listen_addr)?
        } else {
            normalize_http_url("update.health_url", &self.update.health_url)?
        };
        self.update.max_artifact_size_bytes = self
            .update
            .max_artifact_size_bytes
            .clamp(1024 * 1024, 1024 * 1024 * 1024);
        self.update.trusted_public_key = normalize_optional_public_key_text(
            "update.trusted_public_key",
            &self.update.trusted_public_key,
        )?;
        self.manage.api_url = if self.manage.api_url.trim().is_empty() {
            String::new()
        } else {
            normalize_http_url("manage.api_url", &self.manage.api_url)?
        };
        self.manage.organization_id = normalize_organization_id(&self.manage.organization_id)?;
        self.manage.forge_install_code =
            normalize_forge_install_code(&self.manage.forge_install_code)?;
        self.manage.organization_slug =
            normalize_optional_organization_slug(&self.manage.organization_slug)?;
        self.manage.state_path =
            normalize_absolute_config_path("manage.state_path", &self.manage.state_path)?;
        if self.manage.enabled && self.manage.api_url.is_empty() {
            bail!("manage.api_url is required when managed mode is enabled");
        }
        if self.manage.enabled && self.manage.organization_id.is_empty() {
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
    if url.chars().any(|ch| {
        ch.is_control()
            || ch.is_whitespace()
            || matches!(
                ch,
                '"' | '\\' | ';' | '&' | '|' | '`' | '$' | '<' | '>' | '(' | ')' | '{' | '}' | '@'
            )
    }) {
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

fn local_health_url_from_listen_addr(listen_addr: &str) -> anyhow::Result<String> {
    let parsed: SocketAddr = listen_addr.parse().with_context(
        || "server.listen_addr must be an IP socket address such as 127.0.0.1:8080",
    )?;
    let host = if parsed.ip().is_unspecified() {
        "127.0.0.1".to_string()
    } else if parsed.ip().is_ipv6() {
        format!("[{}]", parsed.ip())
    } else {
        parsed.ip().to_string()
    };
    Ok(format!("http://{host}:{}/healthz", parsed.port()))
}

fn normalize_systemd_unit_name(field: &str, value: &str) -> anyhow::Result<String> {
    let value = value.trim();
    if value.is_empty() {
        bail!("{field} must not be empty");
    }
    if value.len() > 160
        || value.starts_with(['.', '-'])
        || value.contains('/')
        || value.contains('\\')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'@'))
    {
        bail!("{field} must be a safe systemd unit name");
    }
    Ok(value.to_string())
}

fn normalize_optional_public_key_text(field: &str, value: &str) -> anyhow::Result<String> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(String::new());
    }
    if value.len() > 2048
        || value
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace())
    {
        bail!("{field} is invalid");
    }
    Ok(value.to_string())
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

pub(crate) fn normalize_absolute_config_path(field: &str, path: &Path) -> anyhow::Result<PathBuf> {
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
    if value != 0 && !(1_000..=600_000).contains(&value) {
        bail!("boot.menu_timeout_ms must be 0 or between 1000 and 600000");
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

fn normalize_forge_install_code(value: &str) -> anyhow::Result<String> {
    let code = value.trim();
    if code.is_empty() {
        return Ok(String::new());
    }
    if code.len() > 512
        || code
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        bail!("manage.forge_install_code contains unsupported characters");
    }
    Ok(code.to_string())
}

fn normalize_build_target_config(target: &mut BuildTargetConfig) -> anyhow::Result<()> {
    target.artifact_type = normalize_build_artifact_type(&target.artifact_type)?;
    target.target = normalize_safe_identifier("build.targets.target", &target.target, 64)?;
    target.system = normalize_build_system("build.targets.system", &target.system)?;
    target.flake = normalize_build_flake("build.targets.flake", &target.flake)?;
    target.attr = normalize_build_attr("build.targets.attr", &target.attr)?;
    Ok(())
}

fn normalize_allowed_systems(values: &[String], field: &str) -> anyhow::Result<Vec<String>> {
    if values.is_empty() {
        bail!("{field} must include at least one system");
    }
    let mut systems = Vec::with_capacity(values.len());
    for value in values {
        let system = normalize_build_system(field, value)?;
        if !systems.contains(&system) {
            systems.push(system);
        }
    }
    Ok(systems)
}

fn normalize_build_artifact_type(value: &str) -> anyhow::Result<String> {
    let value = value.trim().to_ascii_lowercase();
    match value.as_str() {
        "nixos_closure" | "netboot_artifact" | "desktop_image" | "system_generation" => Ok(value),
        _ => bail!(
            "build artifact type must be one of nixos_closure, netboot_artifact, desktop_image, system_generation"
        ),
    }
}

fn normalize_safe_identifier(field: &str, value: &str, max_len: usize) -> anyhow::Result<String> {
    let value = value.trim().to_ascii_lowercase();
    if value.is_empty()
        || value.len() > max_len
        || value.starts_with(['-', '.', '_'])
        || value.ends_with(['-', '.', '_'])
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
    {
        bail!("{field} must be a safe identifier");
    }
    Ok(value)
}

fn normalize_build_system(field: &str, value: &str) -> anyhow::Result<String> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 64
        || value.starts_with('-')
        || value.ends_with('-')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        bail!("{field} must be a safe Nix system name such as x86_64-linux");
    }
    Ok(value.to_string())
}

fn normalize_build_flake(field: &str, value: &str) -> anyhow::Result<String> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 1024
        || value.chars().any(|ch| {
            ch.is_control() || ch.is_whitespace() || ch == '"' || ch == '\'' || ch == '\\'
        })
    {
        bail!("{field} contains unsupported characters");
    }
    Ok(value.trim_end_matches('#').to_string())
}

fn normalize_build_attr(field: &str, value: &str) -> anyhow::Result<String> {
    let value = value.trim().trim_start_matches('#');
    if value.is_empty()
        || value.len() > 512
        || value.starts_with('.')
        || value.ends_with('.')
        || value.contains("..")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        bail!("{field} must be a safe Nix attribute path");
    }
    Ok(value.to_string())
}

fn normalize_program_name(field: &str, value: &str) -> anyhow::Result<String> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 512
        || value.chars().any(|ch| {
            ch.is_control() || ch.is_whitespace() || ch == '"' || ch == '\'' || ch == '\\'
        })
    {
        bail!("{field} contains unsupported characters");
    }
    Ok(value.to_string())
}

fn normalize_cache_key_name(field: &str, value: &str) -> anyhow::Result<String> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 120
        || value.starts_with('-')
        || value.ends_with('-')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        bail!("{field} must be a safe Nix binary cache key name");
    }
    Ok(value.to_string())
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:8080".to_string(),
            public_base_url: "http://CYBEX_FORGE_IP".to_string(),
        }
    }
}

impl Default for PathsConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("/var/lib/cybex-forge"),
            database_path: PathBuf::from("/var/lib/cybex-forge/cybex-forge.sqlite"),
            boot_assets_dir: PathBuf::from("/srv/cybex-forge/www"),
            iso_dir: PathBuf::from("/srv/cybex-forge/www/isos"),
            static_dir: PathBuf::from("/srv/cybex-forge/www/assets"),
            tftp_dir: PathBuf::from("/srv/cybex-forge/tftp"),
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
            menu_timeout_ms: 0,
        }
    }
}

impl Default for BuildConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_concurrent_builds: 1,
            timeout_seconds: 60 * 60,
            cancel_grace_seconds: 10,
            max_log_bytes: 64 * 1024,
            max_artifact_size_bytes: 16 * 1024 * 1024 * 1024,
            allowed_systems: vec!["x86_64-linux".to_string()],
            work_dir: PathBuf::from("/var/lib/cybex-forge/build"),
            output_dir: PathBuf::from("/var/lib/cybex-forge/build-outputs"),
            nix_binary: "nix".to_string(),
            targets: Vec::new(),
        }
    }
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            root_dir: PathBuf::from("/srv/cybex-forge/www/cache"),
            signing_key_name: "cybex-forge-cache".to_string(),
            private_key_path: PathBuf::from("/var/lib/cybex-forge/cache/cache-priv-key.pem"),
            public_key_path: PathBuf::from("/var/lib/cybex-forge/cache/cache-pub-key.pem"),
            max_bytes: 64 * 1024 * 1024 * 1024,
            retain_recent_builds: 50,
        }
    }
}

impl Default for UpdateConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            work_dir: PathBuf::from("/var/lib/cybex-forge/updates"),
            releases_dir: PathBuf::from("/opt/cybex-forge/releases"),
            binary_path: PathBuf::from("/usr/local/bin/cybex-forge"),
            config_path: PathBuf::from("/etc/cybex-forge/config.toml"),
            service_name: "cybex-forge.service".to_string(),
            health_url: String::new(),
            max_artifact_size_bytes: 128 * 1024 * 1024,
            trusted_public_key: String::new(),
        }
    }
}

impl Default for ManageConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            api_url: String::new(),
            organization_id: String::new(),
            forge_install_code: String::new(),
            organization_slug: String::new(),
            state_path: PathBuf::from("/var/lib/cybex-forge/manage-state.json"),
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
        config.manage.forge_install_code = "install-secret".to_string();
        config.server.public_base_url = "http://boot.example".to_string();

        let redacted = config.redacted_for_display();

        assert_eq!(redacted.auth.admin_token, "REDACTED");
        assert_eq!(redacted.manage.forge_install_code, "REDACTED");
        assert_eq!(redacted.server.public_base_url, "http://boot.example");
        assert_eq!(config.auth.admin_token, "secret-token");
        assert_eq!(config.manage.forge_install_code, "install-secret");
    }

    #[test]
    fn print_config_view_preserves_blank_admin_token() {
        let mut config = AppConfig::default();
        config.auth.admin_token = "   ".to_string();
        config.manage.forge_install_code = "   ".to_string();

        assert_eq!(config.redacted_for_display().auth.admin_token, "");
        assert_eq!(config.redacted_for_display().manage.forge_install_code, "");
    }

    #[test]
    fn defaults_match_managed_nginx_lxc_layout() {
        let config = AppConfig::default();

        assert_eq!(config.server.listen_addr, "127.0.0.1:8080");
        assert_eq!(config.server.public_base_url, "http://CYBEX_FORGE_IP");
        assert_eq!(
            config.paths.boot_assets_dir,
            PathBuf::from("/srv/cybex-forge/www")
        );
        assert_eq!(
            config.paths.iso_dir,
            PathBuf::from("/srv/cybex-forge/www/isos")
        );
        assert_eq!(
            config.paths.static_dir,
            PathBuf::from("/srv/cybex-forge/www/assets")
        );
        assert_eq!(
            config.paths.tftp_dir,
            PathBuf::from("/srv/cybex-forge/tftp")
        );
        assert_eq!(config.manage.http_timeout_seconds, 30);
    }

    #[test]
    fn missing_config_loads_normalized_defaults() {
        let path = std::env::temp_dir().join(format!(
            "cybex-forge-missing-config-test-{}-{}.toml",
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
forge_install_code = " boot_test "
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
        assert_eq!(config.manage.forge_install_code, "boot_test");
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
    fn config_load_rejects_public_base_url_command_metacharacters() {
        let path = write_temp_config(
            r#"
[server]
public_base_url = "http://boot.example/forge;chain"
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
    fn config_load_rejects_enabled_managed_mode_with_only_organization_slug() {
        let path = write_temp_config(
            r#"
[server]
public_base_url = "http://boot.example"

[manage]
enabled = true
api_url = "https://manage.example"
organization_slug = "default"
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
data_dir = "../var/lib/cybex-forge"
"#,
            ),
            (
                "paths.database_path",
                r#"
[server]
public_base_url = "http://boot.example"

[paths]
database_path = "/var/lib/../cybex-forge.sqlite"
"#,
            ),
            (
                "paths.boot_assets_dir",
                r#"
[server]
public_base_url = "http://boot.example"

[paths]
boot_assets_dir = "/srv/cybex-forge//www"
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
state_path = "/var/lib/cybex-forge/../manage-state.json"
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
menu_timeout_ms = 42
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
            "cybex-forge-config-test-{}-{unique}.toml",
            std::process::id()
        ));
        fs::write(&path, contents).unwrap();
        path
    }
}
