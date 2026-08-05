use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, bail};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use clap::{Parser, Subcommand};
use ed25519_dalek::VerifyingKey;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(name = "cybex-forge")]
#[command(about = "UEFI-only PXE/iPXE boot control service")]
#[command(version)]
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
    /// Validate a complete appliance configuration without printing it.
    ValidateApplianceConfig,
    /// Re-verify and extract the currently staged signed Ubuntu package update.
    VerifyApplianceUpdate,
    /// Re-verify and materialize the currently staged signed Netplan change.
    VerifyApplianceNetworkChange,
    SyncOnce,
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
    pub workstation_netboot: WorkstationNetbootConfig,
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
    pub max_build_cores: usize,
    pub minimum_memory_bytes: u64,
    pub minimum_swap_bytes: u64,
    pub timeout_seconds: u64,
    pub cancel_grace_seconds: u64,
    pub max_log_bytes: usize,
    pub max_artifact_size_bytes: u64,
    pub allowed_systems: Vec<String>,
    pub work_dir: PathBuf,
    pub output_dir: PathBuf,
    pub nix_binary: String,
    /// Immutable Manage source used by installer-target builds. The exact
    /// signed revision replaces `{revision}` before Nix evaluates the input.
    pub manage_source_url_template: String,
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

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct UpdateConfig {
    pub trusted_public_key: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct WorkstationNetbootConfig {
    /// Allows isolated test fixtures to use HTTP or non-public addresses.
    /// Production appliances must leave this disabled.
    pub allow_private_release_urls: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ManageConfig {
    pub enabled: bool,
    pub api_url: String,
    pub organization_id: String,
    #[serde(default)]
    pub organization_slug: String,
    pub state_path: PathBuf,
    pub sync_interval_seconds: u64,
    pub http_timeout_seconds: u64,
}

impl AppConfig {
    pub fn load(path: &PathBuf) -> anyhow::Result<Self> {
        if !path.exists() {
            let mut config = Self::default();
            config.normalize()?;
            config.validate_public_cache_boundary(path)?;
            return Ok(config);
        }

        let raw = fs::read_to_string(path)?;
        Self::from_toml_str(&raw, path)
    }

    pub fn from_toml_str(raw: &str, loaded_path: &Path) -> anyhow::Result<Self> {
        let mut config: Self = toml::from_str(raw)?;
        config.normalize()?;
        config.validate_public_cache_boundary(loaded_path)?;
        Ok(config)
    }

    pub fn public_base_url(&self) -> &str {
        self.server.public_base_url.trim_end_matches('/')
    }

    pub fn validate_appliance_config(&self) -> anyhow::Result<()> {
        if self.server.listen_addr != "127.0.0.1:8080" {
            bail!("appliance server.listen_addr must remain 127.0.0.1:8080");
        }

        require_appliance_path(
            "paths.data_dir",
            &self.paths.data_dir,
            "/var/lib/cybex-forge",
        )?;
        require_appliance_path(
            "paths.database_path",
            &self.paths.database_path,
            "/var/lib/cybex-forge/cybex-forge.sqlite",
        )?;
        require_appliance_path(
            "paths.tftp_dir",
            &self.paths.tftp_dir,
            "/srv/cybex-forge/tftp",
        )?;
        for (field, path) in [
            (
                "paths.boot_assets_dir",
                self.paths.boot_assets_dir.as_path(),
            ),
            ("paths.static_dir", self.paths.static_dir.as_path()),
            ("build.work_dir", self.build.work_dir.as_path()),
            ("build.output_dir", self.build.output_dir.as_path()),
            ("cache.root_dir", self.cache.root_dir.as_path()),
        ] {
            require_appliance_srv_path(field, path)?;
        }
        if self.build.nix_binary != "/run/current-system/sw/bin/nix" {
            bail!("appliance build.nix_binary must remain /run/current-system/sw/bin/nix");
        }
        require_appliance_path(
            "cache.private_key_path",
            &self.cache.private_key_path,
            "/var/lib/cybex-forge/cache/cache-priv-key.pem",
        )?;
        require_appliance_path(
            "cache.public_key_path",
            &self.cache.public_key_path,
            "/var/lib/cybex-forge/cache/cache-pub-key.pem",
        )?;

        if self.update.trusted_public_key.is_empty() {
            bail!("appliance update trust key must not be empty");
        }
        normalize_optional_public_key_text(
            "update.trusted_public_key",
            &self.update.trusted_public_key,
        )
        .context("validate appliance update trust key")?;
        if self.workstation_netboot.allow_private_release_urls {
            bail!("appliance workstation netboot fixture URLs must remain disabled");
        }

        if !self.manage.enabled {
            bail!("appliance managed mode must remain enabled");
        }
        let normalized_manage_url = normalize_http_url("manage.api_url", &self.manage.api_url)
            .context("appliance manage.api_url must be an absolute HTTPS URL")?;
        let manage_url = Url::parse(&normalized_manage_url)
            .context("appliance manage.api_url must be an absolute HTTPS URL")?;
        if manage_url.scheme() != "https" {
            bail!("appliance manage.api_url must use HTTPS");
        }
        require_appliance_path(
            "manage.state_path",
            &self.manage.state_path,
            "/var/lib/cybex-forge/state/manage-state.json",
        )?;
        Ok(())
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
        self.paths.static_dir =
            normalize_absolute_config_path("paths.static_dir", &self.paths.static_dir)?;
        self.paths.tftp_dir =
            normalize_absolute_config_path("paths.tftp_dir", &self.paths.tftp_dir)?;
        self.boot.bootloader_filename =
            normalize_bootloader_filename(&self.boot.bootloader_filename)?;
        validate_menu_timeout_ms(self.boot.menu_timeout_ms)?;
        self.build.max_concurrent_builds = self.build.max_concurrent_builds.clamp(1, 16);
        self.build.max_build_cores = self.build.max_build_cores.clamp(1, 128);
        self.build.minimum_memory_bytes = self
            .build
            .minimum_memory_bytes
            .clamp(1024 * 1024 * 1024, 1024 * 1024 * 1024 * 1024);
        self.build.minimum_swap_bytes = self
            .build
            .minimum_swap_bytes
            .clamp(0, 1024 * 1024 * 1024 * 1024);
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
        self.build.manage_source_url_template = normalize_manage_source_url_template(
            &self.build.manage_source_url_template,
            self.workstation_netboot.allow_private_release_urls,
        )?;
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

    /// The cache document root is deliberately unauthenticated so Nix clients
    /// can fetch signed artifacts. Keep it entirely separate from every path
    /// that can hold credentials, mutable state, build inputs, or update
    /// payloads. The HTTP handler also allowlists binary-cache member names,
    /// but a path-layout error must still fail closed at startup.
    fn validate_public_cache_boundary(&self, loaded_config_path: &Path) -> anyhow::Result<()> {
        let cache_root = path_identity_for_overlap(&self.cache.root_dir)
            .context("resolve cache.root_dir for public-cache boundary validation")?;
        let private_paths = [
            ("loaded configuration file", loaded_config_path),
            ("paths.data_dir", self.paths.data_dir.as_path()),
            ("paths.database_path", self.paths.database_path.as_path()),
            ("build.work_dir", self.build.work_dir.as_path()),
            ("build.output_dir", self.build.output_dir.as_path()),
            (
                "cache.private_key_path",
                self.cache.private_key_path.as_path(),
            ),
            (
                "cache.public_key_path",
                self.cache.public_key_path.as_path(),
            ),
            ("manage.state_path", self.manage.state_path.as_path()),
        ];
        for (field, private_path) in private_paths {
            let private_path = path_identity_for_overlap(private_path)
                .with_context(|| format!("resolve {field} for public-cache boundary validation"))?;
            if paths_overlap(&cache_root, &private_path) {
                bail!("cache.root_dir must be path-disjoint from {field}");
            }
        }
        Ok(())
    }
}

fn require_appliance_path(field: &str, actual: &Path, expected: &str) -> anyhow::Result<()> {
    let expected = Path::new(expected);
    if actual != expected {
        bail!("appliance {field} must remain {}", expected.display());
    }
    Ok(())
}

fn require_appliance_srv_path(field: &str, path: &Path) -> anyhow::Result<()> {
    let preserved_root = Path::new("/srv/cybex-forge");
    if path == preserved_root || !path.starts_with(preserved_root) {
        bail!("appliance {field} must be below /srv/cybex-forge");
    }
    Ok(())
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}

/// Resolve every existing path component so symlink aliases cannot bypass an
/// overlap check. If the leaf does not exist yet, retain its normalized suffix
/// beneath the deepest canonicalizable ancestor.
fn path_identity_for_overlap(path: &Path) -> anyhow::Result<PathBuf> {
    let absolute;
    let mut cursor = if path.is_absolute() {
        path
    } else {
        absolute = std::env::current_dir()
            .context("resolve current directory for public-cache boundary validation")?
            .join(path);
        absolute.as_path()
    };
    let mut missing_suffix = Vec::new();
    loop {
        match fs::canonicalize(cursor) {
            Ok(mut canonical) => {
                for component in missing_suffix.iter().rev() {
                    canonical.push(component);
                }
                return Ok(canonical);
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                let filename = cursor.file_name().ok_or_else(|| {
                    anyhow::anyhow!("could not resolve absolute path {}", path.display())
                })?;
                missing_suffix.push(filename.to_os_string());
                cursor = cursor.parent().ok_or_else(|| {
                    anyhow::anyhow!("could not resolve absolute path {}", path.display())
                })?;
            }
            Err(err) => {
                return Err(err).with_context(|| format!("resolve path {}", path.display()));
            }
        }
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

fn normalize_optional_public_key_text(field: &str, value: &str) -> anyhow::Result<String> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(String::new());
    }
    if value.len() > 128
        || value
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace())
    {
        bail!("{field} is invalid");
    }
    let bytes = STANDARD
        .decode(value)
        .or_else(|_| URL_SAFE_NO_PAD.decode(value))
        .with_context(|| format!("{field} must be Base64-encoded"))?;
    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{field} must decode to exactly 32 bytes"))?;
    let verifying_key = VerifyingKey::from_bytes(&key)
        .with_context(|| format!("{field} must be an Ed25519 key"))?;
    if verifying_key.is_weak() {
        bail!("{field} must not be a weak Ed25519 key");
    }
    Ok(STANDARD.encode(key))
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

fn normalize_build_target_config(target: &mut BuildTargetConfig) -> anyhow::Result<()> {
    target.artifact_type = normalize_build_artifact_type(&target.artifact_type)?;
    target.target = normalize_safe_identifier("build.targets.target", &target.target, 64)?;
    target.system = normalize_build_system("build.targets.system", &target.system)?;
    target.flake = normalize_build_flake("build.targets.flake", &target.flake)?;
    if matches!(target.target.as_str(), "blueprint" | "desktop_experience") {
        pinned_nixpkgs_revision(&target.flake)?;
    }
    target.attr = normalize_build_attr("build.targets.attr", &target.attr)?;
    Ok(())
}

fn normalize_manage_source_url_template(
    value: &str,
    allow_private_fixture: bool,
) -> anyhow::Result<String> {
    let value = value.trim();
    if value.is_empty() || value.len() > 2048 || value.chars().any(char::is_control) {
        bail!("build.manage_source_url_template is invalid");
    }
    if value.matches("{revision}").count() != 1 {
        bail!("build.manage_source_url_template must contain exactly one {{revision}} placeholder");
    }
    if value == "github:CybexHQ/manage/{revision}" {
        return Ok(value.to_string());
    }
    let candidate = value.replace("{revision}", &"0".repeat(40));
    let parsed = Url::parse(&candidate)
        .context("build.manage_source_url_template must be an absolute source URL")?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        bail!("build.manage_source_url_template must not contain credentials");
    }
    match parsed.scheme() {
        "https" | "git+https" => {}
        "file" | "git+file" if allow_private_fixture => {}
        _ => bail!(
            "build.manage_source_url_template must use HTTPS; file fixtures require workstation_netboot.allow_private_release_urls"
        ),
    }
    Ok(value.to_string())
}

pub fn pinned_nixpkgs_revision(flake: &str) -> anyhow::Result<&str> {
    let revision = flake.strip_prefix("github:NixOS/nixpkgs/").ok_or_else(|| {
        anyhow::anyhow!(
            "Blueprint build target flake must use github:NixOS/nixpkgs/<40-character-commit>"
        )
    })?;
    if revision.len() != 40 || !revision.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("Blueprint build target flake must pin an immutable 40-character nixpkgs commit");
    }
    Ok(revision)
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
            max_build_cores: 4,
            minimum_memory_bytes: 16 * 1024 * 1024 * 1024,
            minimum_swap_bytes: 8 * 1024 * 1024 * 1024,
            timeout_seconds: 60 * 60,
            cancel_grace_seconds: 10,
            max_log_bytes: 64 * 1024,
            max_artifact_size_bytes: 20 * 1024 * 1024 * 1024,
            allowed_systems: vec!["x86_64-linux".to_string()],
            work_dir: PathBuf::from("/var/lib/cybex-forge/build"),
            output_dir: PathBuf::from("/var/lib/cybex-forge/build-outputs"),
            nix_binary: "nix".to_string(),
            manage_source_url_template: "github:CybexHQ/manage/{revision}".to_string(),
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

impl Default for ManageConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            api_url: String::new(),
            organization_id: String::new(),
            organization_slug: String::new(),
            state_path: PathBuf::from("/var/lib/cybex-forge/state/manage-state.json"),
            sync_interval_seconds: 30,
            http_timeout_seconds: 30,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn appliance_config() -> AppConfig {
        let mut config = AppConfig::default();
        config.build.work_dir = PathBuf::from("/srv/cybex-forge/build-work");
        config.build.output_dir = PathBuf::from("/srv/cybex-forge/build-outputs");
        config.build.nix_binary = "/run/current-system/sw/bin/nix".to_string();
        config.update.trusted_public_key = STANDARD.encode(
            SigningKey::from_bytes(&[7u8; 32])
                .verifying_key()
                .to_bytes(),
        );
        config.manage.enabled = true;
        config.manage.api_url = "https://manage.example".to_string();
        config.manage.organization_id = "550e8400-e29b-41d4-a716-446655440000".to_string();
        config
    }

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
    fn cli_reports_the_exact_package_version() {
        let result = Cli::try_parse_from(["cybex-forge", "--version"]).unwrap_err();

        assert_eq!(result.kind(), clap::error::ErrorKind::DisplayVersion);
        assert!(result.to_string().contains(env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn update_trust_key_is_validated_and_canonicalized() {
        let public_key = SigningKey::from_bytes(&[7_u8; 32])
            .verifying_key()
            .to_bytes();
        let url_safe = URL_SAFE_NO_PAD.encode(public_key);

        assert_eq!(
            normalize_optional_public_key_text("update.trusted_public_key", &url_safe).unwrap(),
            STANDARD.encode(public_key)
        );
        assert!(
            normalize_optional_public_key_text(
                "update.trusted_public_key",
                &STANDARD.encode([0_u8; 31])
            )
            .unwrap_err()
            .to_string()
            .contains("exactly 32 bytes")
        );
        assert!(
            normalize_optional_public_key_text("update.trusted_public_key", "not-base64").is_err()
        );
        let weak_public_keys = include_str!("../trust/ed25519-weak-public-keys.txt")
            .lines()
            .collect::<Vec<_>>();
        assert_eq!(weak_public_keys.len(), 14);
        for value in weak_public_keys {
            let raw = STANDARD.decode(value).unwrap();
            let key: [u8; 32] = raw.try_into().unwrap();
            assert!(VerifyingKey::from_bytes(&key).unwrap().is_weak());
            let error = normalize_optional_public_key_text("update.trusted_public_key", value)
                .unwrap_err()
                .to_string();
            assert!(error.contains("weak Ed25519 key"));
        }
    }

    #[test]
    fn defaults_match_ubuntu_appliance_layout() {
        let config = AppConfig::default();

        assert_eq!(config.server.listen_addr, "127.0.0.1:8080");
        assert_eq!(config.server.public_base_url, "http://CYBEX_FORGE_IP");
        assert_eq!(
            config.paths.boot_assets_dir,
            PathBuf::from("/srv/cybex-forge/www")
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
        assert_eq!(config.build.max_build_cores, 4);
        assert_eq!(config.build.minimum_memory_bytes, 16 * 1024 * 1024 * 1024);
        assert_eq!(config.build.minimum_swap_bytes, 8 * 1024 * 1024 * 1024);
    }

    #[test]
    fn blueprint_build_targets_require_immutable_nixpkgs_commits() {
        assert!(pinned_nixpkgs_revision("github:NixOS/nixpkgs/nixos-unstable").is_err());
        assert!(pinned_nixpkgs_revision("github:NixOS/nixpkgs/abc123").is_err());
        assert_eq!(
            pinned_nixpkgs_revision(
                "github:NixOS/nixpkgs/74cc63f702f7d60a557e152a57b40fb1fd0f72ac"
            )
            .unwrap(),
            "74cc63f702f7d60a557e152a57b40fb1fd0f72ac"
        );
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
        assert_eq!(config.manage.organization_slug, "default");
    }

    #[test]
    fn config_rejects_removed_install_code_and_executable_updater_fields() {
        for raw in [
            "[manage]\nforge_install_code = \"removed\"\n",
            "[manage]\nforge_install_code_file = \"/run/removed\"\n",
            "[update]\nenabled = true\n",
            "[update]\nwork_dir = \"/var/lib/cybex-forge/updates\"\n",
        ] {
            let path = write_temp_config(raw);
            let error = AppConfig::load(&path).unwrap_err();
            let _ = fs::remove_file(&path);
            assert!(error.to_string().contains("unknown field"));
        }
    }

    #[test]
    fn appliance_config_pins_recovery_and_update_invariants() {
        fn rejected(mutate: impl FnOnce(&mut AppConfig), expected_error: &str) {
            let mut config = appliance_config();
            mutate(&mut config);
            let error = config.validate_appliance_config().unwrap_err();
            assert!(
                error.to_string().contains(expected_error),
                "unexpected error: {error:#}"
            );
        }

        rejected(
            |config| config.server.listen_addr = "127.0.0.1:9080".to_string(),
            "listen_addr",
        );
        rejected(
            |config| config.paths.data_dir = PathBuf::from("/srv/cybex-forge/data"),
            "paths.data_dir",
        );
        rejected(
            |config| config.paths.database_path = PathBuf::from("/tmp/forge.sqlite"),
            "paths.database_path",
        );
        rejected(
            |config| config.paths.tftp_dir = PathBuf::from("/srv/cybex-forge/other-tftp"),
            "paths.tftp_dir",
        );
        rejected(
            |config| config.paths.boot_assets_dir = PathBuf::from("/var/www/forge"),
            "paths.boot_assets_dir",
        );
        rejected(
            |config| config.build.work_dir = PathBuf::from("/var/lib/cybex-forge/build"),
            "build.work_dir",
        );
        rejected(
            |config| config.cache.root_dir = PathBuf::from("/var/lib/cybex-forge/cache-public"),
            "cache.root_dir",
        );
        rejected(
            |config| config.build.nix_binary = "/tmp/nix".to_string(),
            "build.nix_binary",
        );
        rejected(
            |config| config.cache.private_key_path = PathBuf::from("/tmp/cache-private-key"),
            "cache.private_key_path",
        );
        rejected(
            |config| config.cache.public_key_path = PathBuf::from("/tmp/cache-public-key"),
            "cache.public_key_path",
        );
        rejected(
            |config| config.update.trusted_public_key.clear(),
            "trust key",
        );
        rejected(|config| config.manage.enabled = false, "managed mode");
        rejected(
            |config| config.manage.api_url = "http://manage.example".to_string(),
            "HTTPS",
        );
        rejected(
            |config| config.manage.state_path = PathBuf::from("/tmp/manage-state.json"),
            "manage.state_path",
        );
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
    fn config_rejects_private_paths_inside_public_cache_root() {
        let root = temp_config_dir("cache-boundary-lexical");
        let cache_root = root.join("public-cache");
        let private_key = cache_root.join("keys/cache-private.pem");
        let public_key = root.join("keys/cache-public.pem");
        let path = write_temp_config(&format!(
            r#"
[server]
public_base_url = "http://boot.example"

[cache]
root_dir = "{}"
private_key_path = "{}"
public_key_path = "{}"
"#,
            cache_root.display(),
            private_key.display(),
            public_key.display(),
        ));

        let err = AppConfig::load(&path).unwrap_err();
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir_all(&root);

        assert!(
            err.to_string()
                .contains("cache.root_dir must be path-disjoint from cache.private_key_path"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn config_rejects_public_cache_nested_in_private_state_root() {
        let root = temp_config_dir("cache-boundary-private-parent");
        let data_dir = root.join("private-state");
        let cache_root = data_dir.join("public-cache");
        let path = write_temp_config(&format!(
            r#"
[server]
public_base_url = "http://boot.example"

[paths]
data_dir = "{}"

[cache]
root_dir = "{}"
"#,
            data_dir.display(),
            cache_root.display(),
        ));

        let err = AppConfig::load(&path).unwrap_err();
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir_all(&root);

        assert!(
            err.to_string()
                .contains("cache.root_dir must be path-disjoint from paths.data_dir"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn config_rejects_public_cache_symlink_alias_of_private_key_directory() {
        use std::os::unix::fs::symlink;

        let root = temp_config_dir("cache-boundary-symlink");
        let real_cache = root.join("real-cache");
        let cache_alias = root.join("cache-alias");
        fs::create_dir_all(&real_cache).unwrap();
        symlink(&real_cache, &cache_alias).unwrap();
        let private_key = real_cache.join("cache-private.pem");
        fs::write(&private_key, "private").unwrap();
        let path = write_temp_config(&format!(
            r#"
[server]
public_base_url = "http://boot.example"

[cache]
root_dir = "{}"
private_key_path = "{}"
"#,
            cache_alias.display(),
            private_key.display(),
        ));

        let err = AppConfig::load(&path).unwrap_err();
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir_all(&root);

        assert!(
            err.to_string()
                .contains("cache.root_dir must be path-disjoint from cache.private_key_path"),
            "unexpected error: {err}"
        );
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

    fn temp_config_dir(label: &str) -> PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "cybex-forge-config-{label}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }
}
